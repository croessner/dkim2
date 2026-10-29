//go:build redisintegration

package redisstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	dkim2 "github.com/croessner/dkim2"
	"github.com/redis/go-redis/v9"
)

const (
	harnessDataUser         = "dkim2-integration-application"
	harnessDataPassword     = "synthetic-application-password-91"
	harnessSentinelUser     = "dkim2-integration-sentinel"
	harnessSentinelPassword = "synthetic-sentinel-password-91"
	harnessMasterName       = "dkim2replay"
	harnessServerName       = "localhost"
	harnessBindLine         = "bind 127.0.0.1"
	harnessNoAppendLine     = "appendonly no"
	harnessAdminUserLine    = "user default on nopass ~* &* +@all"
	harnessAuthGrant        = "+auth"
	harnessHelloGrant       = "+hello"
	harnessPingGrant        = "+ping"
	harnessNoEvictionLine   = "maxmemory-policy noeviction"
	harnessNoSaveLine       = "save \"\""
	harnessCertificateType  = "CERTIFICATE"
)

// harnessDataACL is the documented least-authority data-path ACL. Every
// command the provider sends is granted explicitly: HELLO and AUTH for the
// RESP3 handshake, PING for health, INFO for the startup checks, SET for
// every write, GET because the lease-takeover script calls it, EVAL and
// EVALSHA for that script, SELECT for a non-zero database, and CLUSTER|SLOTS
// for cluster topology discovery.
func harnessDataACL(user, password, prefix string, extra ...string) string {
	rules := []string{
		"user", user, "reset", "on", "sanitize-payload", ">" + password,
		"resetkeys", "resetchannels", "-@all",
		harnessHelloGrant, harnessAuthGrant, harnessPingGrant, "+info", "+set", "+get", "+eval", "+evalsha",
	}
	rules = append(rules, extra...)
	return strings.Join(append(rules, "~"+prefix+"dkim2:replay:*"), " ")
}

// harnessSentinelACL is the documented least-authority Sentinel ACL: master
// discovery, Sentinel enumeration, and the failover notification channels.
func harnessSentinelACL(user, password string, channels bool) string {
	rules := []string{
		"user", user, "reset", "on", ">" + password, "resetchannels", "-@all",
		harnessHelloGrant, harnessAuthGrant, harnessPingGrant, "+sentinel|get-master-addr-by-name",
		"+sentinel|sentinels", "+subscribe",
	}
	if channels {
		rules = append(rules, "&+switch-master", "&+replica-reconf-done")
	}
	return strings.Join(rules, " ")
}

// TestRealRedisHarness proves the production provider against the pinned
// real server in standalone TLS, Sentinel with a forced failover, and a
// three-primary cluster, with the memory provider as the parity baseline.
func TestRealRedisHarness(t *testing.T) {
	harness := newRedisHarness(t)
	t.Run("memory-baseline", func(t *testing.T) {
		store, err := dkim2.NewReplayMemoryStore(dkim2.ReplayMemoryConfig{Clock: dkim2.ReplayClockFunc(time.Now)})
		if err != nil {
			t.Fatal("memory parity store construction failed")
		}
		harness.exerciseParity(t, store, "memory")
		harness.exercisePropagation(t, store, "memory")
		closeHarnessStore(t, store)
	})
	t.Run("standalone-tls", harness.runStandalone)
	t.Run("sentinel-failover", harness.runSentinel)
	t.Run("cluster", harness.runCluster)
}

// redisHarness owns the private work directory, the pinned server binary,
// the authentic test identity, and every spawned server process.
type redisHarness struct {
	server   string
	workdir  string
	identity dkim2.ReplayIdentity
	mu       sync.Mutex
	labels   int
}

// newRedisHarness validates the script-provided server and private directory.
func newRedisHarness(t *testing.T) *redisHarness {
	t.Helper()
	server := os.Getenv("DKIM2_REDIS_SERVER")
	workdir := os.Getenv("DKIM2_REDIS_WORKDIR")
	if !filepath.IsAbs(server) || !filepath.IsAbs(workdir) {
		t.Fatal("mandatory hermetic server binary or work directory is absent")
	}
	info, err := os.Stat(workdir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatal("hermetic work directory is not private")
	}
	return &redisHarness{server: server, workdir: workdir, identity: verifiedTestIdentity(t)}
}

// key derives one fresh distinct first-seen or propagation key.
func (h *redisHarness) key(t *testing.T, propagation bool) dkim2.ReplayKey {
	t.Helper()
	h.mu.Lock()
	h.labels++
	label := "harness-key-" + strconv.Itoa(h.labels)
	h.mu.Unlock()
	derive := (*dkim2.ReplayDeriver).Derive
	if propagation {
		derive = (*dkim2.ReplayDeriver).DerivePropagation
	}
	return deriveReplayKeyWithSecret(t, derive, h.identity, label)
}

// harnessConfig returns the provider defaults tuned for a fast hermetic run.
func harnessConfig() Config {
	config := DefaultConfig("")
	config.TLS = TLSConfig{}
	config.Health = HealthConfig{Interval: time.Second, Timeout: 500 * time.Millisecond, FailureThreshold: 1}
	config.Username = harnessDataUser
	return config
}

// runStandalone proves TLS 1.3 with mutual authentication, server-name
// verification, the documented ACL, and the startup failure classes.
func (h *redisHarness) runStandalone(t *testing.T) {
	material := writeHarnessPKI(t, h.workdir)
	adminPort, tlsPort := freePort(t), freePort(t)
	const prefix = "standalone:"
	lines := []string{
		harnessBindLine, "port " + strconv.Itoa(adminPort), "tls-port " + strconv.Itoa(tlsPort),
		"tls-cert-file " + material.serverCertificate, "tls-key-file " + material.serverKey,
		"tls-ca-cert-file " + material.caFile, "tls-auth-clients yes", "tls-protocols \"TLSv1.2 TLSv1.3\"",
		harnessNoSaveLine, harnessNoAppendLine, harnessNoEvictionLine,
		harnessAdminUserLine,
		harnessDataACL(harnessDataUser, harnessDataPassword, prefix),
		harnessDataACL("missing-info", harnessDataPassword, prefix, "-info"),
		harnessDataACL("missing-get", harnessDataPassword, prefix, "-get"),
		harnessDataACL("missing-hello", harnessDataPassword, prefix, "-hello"),
	}
	h.startServer(t, "standalone", adminPort, lines)
	admin := redis.NewClient(&redis.Options{Addr: harnessAddress(adminPort), DisableIdentity: true})
	t.Cleanup(func() { _ = admin.Close() })

	config := harnessConfig()
	config.StandaloneAddress = harnessAddress(tlsPort)
	config.KeyPrefix = prefix
	config.TLS = TLSConfig{Enabled: true, ServerName: harnessServerName, MinVersion: TLSVersion13}
	secrets := Secrets{
		Password: []byte(harnessDataPassword), RootsDER: [][]byte{material.caDER},
		ClientCertificatePEM: material.clientCertificatePEM, ClientKeyPEM: material.clientKeyPEM,
	}
	store := openHarnessStore(t, config, secrets)
	h.exerciseParity(t, store, "standalone")
	h.exercisePropagation(t, store, "standalone")
	requireHealthy(t, store)
	closeHarnessStore(t, store)

	t.Run("acl-without-info-fails-startup", func(t *testing.T) {
		denied := config
		denied.Username = "missing-info"
		requireStartupReason(t, denied, secrets, StartupPermission)
	})
	t.Run("wrong-password-fails-startup", func(t *testing.T) {
		wrong := secrets
		wrong.Password = []byte("synthetic-wrong-password")
		requireStartupReason(t, config, wrong, StartupAuthentication)
	})
	t.Run("missing-client-certificate-fails-startup", func(t *testing.T) {
		noClient := secrets
		noClient.ClientCertificatePEM, noClient.ClientKeyPEM = nil, nil
		requireStartupReason(t, config, noClient, StartupUnavailable)
	})
	t.Run("wrong-server-name-fails-startup", func(t *testing.T) {
		mismatch := config
		mismatch.TLS.ServerName = "replay.invalid"
		requireStartupReason(t, mismatch, secrets, StartupUnavailable)
	})
	t.Run("eviction-policy-fails-startup", func(t *testing.T) {
		requireAdmin(t, admin.ConfigSet(context.Background(), "maxmemory-policy", "allkeys-lru").Err())
		requireStartupReason(t, config, secrets, StartupEvictionPolicy)
		relaxed := config
		relaxed.RequireNoEviction = false
		closeHarnessStore(t, openHarnessStore(t, relaxed, secrets))
		requireAdmin(t, admin.ConfigSet(context.Background(), "maxmemory-policy", "noeviction").Err())
	})
	t.Run("acl-without-get-breaks-lease-takeover", func(t *testing.T) {
		denied := config
		denied.Username = "missing-get"
		store := openHarnessStore(t, denied, secrets)
		defer closeHarnessStore(t, store)
		key := h.key(t, true)
		retention, lease := harnessRetention(t, 5*time.Second), harnessLease(t)
		requireReservation(t, store, key, retention, lease, dkim2.ReplayPropagationReserved)
		time.Sleep(1100 * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := store.ReservePropagation(ctx, key, retention, lease); err == nil {
			t.Fatal("lease takeover succeeded without +get although the script calls GET")
		}
	})
	t.Run("hello-grant-observation", func(t *testing.T) {
		observed := config
		observed.Username = "missing-hello"
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		store, err := NewStore(ctx, observed, secrets)
		if err == nil {
			t.Log("server admits HELLO without an explicit +hello grant; the documented ACL keeps +hello for Redis compatibility")
			closeHarnessStore(t, store)
			return
		}
		t.Logf("server requires +hello: startup failed with %v", err)
	})
}

// runSentinel proves Sentinel discovery under the least-authority Sentinel
// user, a non-zero database, and correct first-seen and replayed results
// across a forced failover.
func (h *redisHarness) runSentinel(t *testing.T) {
	primaryPort, replicaPort, sentinelPort := freePort(t), freePort(t), freePort(t)
	const prefix = "sentinel:"
	data := func(port int, extra ...string) []string {
		return append([]string{
			harnessBindLine, "port " + strconv.Itoa(port), harnessNoSaveLine, harnessNoAppendLine,
			harnessNoEvictionLine, "replica-announce-ip 127.0.0.1",
			harnessAdminUserLine,
			harnessDataACL(harnessDataUser, harnessDataPassword, prefix, "+select"),
		}, extra...)
	}
	h.startServer(t, "sentinel-primary", primaryPort, data(primaryPort))
	h.startServer(t, "sentinel-replica", replicaPort, data(replicaPort, "replicaof 127.0.0.1 "+strconv.Itoa(primaryPort)))
	h.startServer(t, "sentinel", sentinelPort, []string{
		"sentinel", harnessBindLine, "port " + strconv.Itoa(sentinelPort),
		"sentinel resolve-hostnames no", "sentinel announce-ip 127.0.0.1",
		"sentinel monitor " + harnessMasterName + " 127.0.0.1 " + strconv.Itoa(primaryPort) + " 1",
		"sentinel down-after-milliseconds " + harnessMasterName + " 1000",
		"sentinel failover-timeout " + harnessMasterName + " 10000",
		harnessAdminUserLine,
		harnessSentinelACL(harnessSentinelUser, harnessSentinelPassword, true),
		harnessSentinelACL("sentinel-without-channels", harnessSentinelPassword, false),
	})
	sentinel := redis.NewSentinelClient(&redis.Options{Addr: harnessAddress(sentinelPort), DisableIdentity: true})
	t.Cleanup(func() { _ = sentinel.Close() })
	primaryAdmin := redis.NewClient(&redis.Options{Addr: harnessAddress(primaryPort), DisableIdentity: true})
	t.Cleanup(func() { _ = primaryAdmin.Close() })
	waitFor(t, 30*time.Second, "sentinel sees one healthy replica", func(ctx context.Context) bool {
		replicas, err := sentinel.Replicas(ctx, harnessMasterName).Result()
		return err == nil && len(replicas) == 1 && replicas[0]["flags"] == "slave" &&
			replicas[0]["master-link-status"] == "ok"
	})

	t.Run("sentinel-acl-notification-channels", func(t *testing.T) {
		requireSentinelSubscription(t, sentinelPort, harnessSentinelUser, true)
		requireSentinelSubscription(t, sentinelPort, "sentinel-without-channels", false)
	})

	config := harnessConfig()
	config.Mode = ModeSentinel
	config.SentinelMasterName = harnessMasterName
	config.SentinelAddresses = []string{harnessAddress(sentinelPort)}
	config.SentinelUsername = harnessSentinelUser
	config.DatabaseNumber = 2
	config.KeyPrefix = prefix
	secrets := Secrets{Password: []byte(harnessDataPassword), SentinelPassword: []byte(harnessSentinelPassword)}
	store := openHarnessStore(t, config, secrets)
	defer closeHarnessStore(t, store)
	h.exerciseParity(t, store, "sentinel")

	retention := harnessRetention(t, time.Minute)
	before := make([]dkim2.ReplayKey, 16)
	for index := range before {
		before[index] = h.key(t, false)
		requireCheck(t, store, before[index], retention, dkim2.ReplayCheckFirstSeen)
	}
	waitCtx, cancelWait := context.WithTimeout(context.Background(), 5*time.Second)
	replicated, err := primaryAdmin.Wait(waitCtx, 1, 4000).Result()
	cancelWait()
	if err != nil || replicated < 1 {
		t.Fatalf("pre-failover writes did not reach the replica: %d, %v", replicated, err)
	}

	failoverCtx, cancelFailover := context.WithTimeout(context.Background(), 5*time.Second)
	requireAdmin(t, sentinel.Failover(failoverCtx, harnessMasterName).Err())
	cancelFailover()
	waitFor(t, 30*time.Second, "sentinel promotes the replica", func(ctx context.Context) bool {
		address, err := sentinel.GetMasterAddrByName(ctx, harnessMasterName).Result()
		return err == nil && len(address) == 2 && address[1] == strconv.Itoa(replicaPort)
	})
	probe := h.key(t, false)
	var first dkim2.ReplayCheck
	waitFor(t, 30*time.Second, "provider writes to the promoted primary", func(ctx context.Context) bool {
		check, err := store.CheckAndRemember(ctx, probe, retention)
		if err != nil {
			return false
		}
		first = check
		return true
	})
	if first != dkim2.ReplayCheckFirstSeen {
		t.Fatalf("first post-failover write of a fresh key reported %v", first)
	}
	requireCheck(t, store, probe, retention, dkim2.ReplayCheckReplayed)
	for _, key := range before {
		requireCheck(t, store, key, retention, dkim2.ReplayCheckReplayed)
	}
	requireCheck(t, store, h.key(t, false), retention, dkim2.ReplayCheckFirstSeen)
	h.exercisePropagation(t, store, "sentinel")
	waitFor(t, 10*time.Second, "health probe recovers after failover", func(ctx context.Context) bool {
		return store.Probe(ctx) == nil && store.AuthorityReady()
	})
}

// runCluster forms a three-primary cluster through the client and proves the
// provider across keys owned by every primary.
func (h *redisHarness) runCluster(t *testing.T) {
	const prefix = "cluster:"
	ports := []int{freeClusterPort(t), freeClusterPort(t), freeClusterPort(t)}
	admins := make([]*redis.Client, len(ports))
	for index, port := range ports {
		h.startServer(t, "cluster-"+strconv.Itoa(index), port, []string{
			harnessBindLine, "port " + strconv.Itoa(port), harnessNoSaveLine, harnessNoAppendLine,
			harnessNoEvictionLine, "cluster-enabled yes",
			"cluster-config-file nodes-" + strconv.Itoa(port) + ".conf", "cluster-node-timeout 2000",
			"cluster-announce-ip 127.0.0.1",
			harnessAdminUserLine,
			harnessDataACL(harnessDataUser, harnessDataPassword, prefix, "+cluster|slots"),
			harnessDataACL("missing-cluster-slots", harnessDataPassword, prefix),
		})
		admins[index] = redis.NewClient(&redis.Options{Addr: harnessAddress(port), DisableIdentity: true})
		t.Cleanup(func() { _ = admins[index].Close() })
	}
	ranges := [][2]int{{0, 5460}, {5461, 10922}, {10923, 16383}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	for index, admin := range admins {
		requireAdmin(t, admin.ClusterAddSlotsRange(ctx, ranges[index][0], ranges[index][1]).Err())
	}
	for _, port := range ports[1:] {
		requireAdmin(t, admins[0].ClusterMeet(ctx, "127.0.0.1", strconv.Itoa(port)).Err())
	}
	cancel()
	waitFor(t, 30*time.Second, "cluster converges", func(ctx context.Context) bool {
		for _, admin := range admins {
			info, err := admin.ClusterInfo(ctx).Result()
			if err != nil || !strings.Contains(info, "cluster_state:ok") ||
				!strings.Contains(info, "cluster_known_nodes:3") {
				return false
			}
			shards, err := admin.ClusterShards(ctx).Result()
			if err != nil || len(shards) != 3 {
				return false
			}
		}
		return true
	})

	config := harnessConfig()
	config.Mode = ModeCluster
	config.ClusterAddresses = []string{harnessAddress(ports[0])}
	config.KeyPrefix = prefix
	store := openHarnessStore(t, config, Secrets{Password: []byte(harnessDataPassword)})
	defer closeHarnessStore(t, store)
	h.exerciseParity(t, store, "cluster")
	h.exercisePropagation(t, store, "cluster")

	retention := harnessRetention(t, time.Minute)
	keys := make([]dkim2.ReplayKey, 48)
	for index := range keys {
		keys[index] = h.key(t, false)
		requireCheck(t, store, keys[index], retention, dkim2.ReplayCheckFirstSeen)
	}
	for _, key := range keys {
		requireCheck(t, store, key, retention, dkim2.ReplayCheckReplayed)
	}
	countCtx, cancelCount := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelCount()
	for index, admin := range admins {
		size, err := admin.DBSize(countCtx).Result()
		if err != nil || size == 0 {
			t.Fatalf("primary %d owns no replay keys (size=%d, err=%v)", index, size, err)
		}
	}
	requireHealthy(t, store)

	t.Run("acl-without-cluster-slots-fails-startup", func(t *testing.T) {
		denied := config
		denied.Username = "missing-cluster-slots"
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if store, err := NewStore(ctx, denied, Secrets{Password: []byte(harnessDataPassword)}); err == nil {
			closeHarnessStore(t, store)
			t.Fatal("cluster startup succeeded without +cluster|slots")
		}
	})
}

// exerciseParity proves first-seen, replay, non-extension, expiry, and
// same-key concurrency with exactly one first-seen winner.
func (h *redisHarness) exerciseParity(t *testing.T, store dkim2.ReplayStore, lane string) {
	t.Helper()
	retention := harnessRetention(t, time.Second)
	key := h.key(t, false)
	requireCheck(t, store, key, retention, dkim2.ReplayCheckFirstSeen)
	requireCheck(t, store, key, retention, dkim2.ReplayCheckReplayed)
	time.Sleep(650 * time.Millisecond)
	requireCheck(t, store, key, retention, dkim2.ReplayCheckReplayed)
	time.Sleep(550 * time.Millisecond)
	requireCheck(t, store, key, retention, dkim2.ReplayCheckFirstSeen)
	time.Sleep(1100 * time.Millisecond)

	const callers = 32
	results := make(chan dkim2.ReplayCheck, callers)
	failures := make(chan error, callers)
	var group sync.WaitGroup
	for range callers {
		group.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			check, err := store.CheckAndRemember(ctx, key, retention)
			results <- check
			failures <- err
		})
	}
	group.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatalf("%s same-key call failed: %s", lane, dkim2.ReplayErrorCodeOf(err))
		}
	}
	firstSeen, replayed := 0, 0
	for check := range results {
		switch check {
		case dkim2.ReplayCheckFirstSeen:
			firstSeen++
		case dkim2.ReplayCheckReplayed:
			replayed++
		default:
			t.Fatalf("%s same-key call returned an invalid state", lane)
		}
	}
	if firstSeen != 1 || replayed != callers-1 {
		t.Fatalf("%s same-key parity = %d first-seen, %d replayed", lane, firstSeen, replayed)
	}
}

// exercisePropagation proves reserve, pending, expired-lease takeover,
// monotonic idempotent commit, and unresolved commit of an absent key.
func (h *redisHarness) exercisePropagation(t *testing.T, store dkim2.ReplayStore, lane string) {
	t.Helper()
	propagation, ok := store.(dkim2.ReplayPropagationStore)
	if !ok {
		t.Fatalf("%s provider does not hold the propagation contract", lane)
	}
	retention, lease := harnessRetention(t, 5*time.Second), harnessLease(t)
	key := h.key(t, true)
	requireReservation(t, propagation, key, retention, lease, dkim2.ReplayPropagationReserved)
	requireReservation(t, propagation, key, retention, lease, dkim2.ReplayPropagationPending)
	time.Sleep(1100 * time.Millisecond)
	requireReservation(t, propagation, key, retention, lease, dkim2.ReplayPropagationReserved)
	requireReservation(t, propagation, key, retention, lease, dkim2.ReplayPropagationPending)
	requireCommit(t, propagation, key, dkim2.ReplayPropagationCommitted)
	requireCommit(t, propagation, key, dkim2.ReplayPropagationCommitted)
	requireReservation(t, propagation, key, retention, lease, dkim2.ReplayPropagationAlreadyCommitted)
	time.Sleep(1100 * time.Millisecond)
	requireReservation(t, propagation, key, retention, lease, dkim2.ReplayPropagationAlreadyCommitted)
	requireCommit(t, propagation, h.key(t, true), dkim2.ReplayPropagationCommitUnresolved)
}

// startServer writes one configuration file and runs the pinned server until
// the test ends; readiness is proven by a PING on the plaintext port.
func (h *redisHarness) startServer(t *testing.T, name string, port int, lines []string) {
	t.Helper()
	directory := filepath.Join(h.workdir, name)
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal("server directory creation failed")
	}
	arguments := []string{}
	if len(lines) > 0 && lines[0] == "sentinel" {
		arguments = append(arguments, "--sentinel")
		lines = lines[1:]
	}
	lines = append(lines, "dir \""+directory+"\"", "logfile \""+filepath.Join(directory, "server.log")+"\"",
		"daemonize no", "protected-mode yes")
	configPath := filepath.Join(directory, "server.conf")
	if err := os.WriteFile(configPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal("server configuration write failed")
	}
	command := exec.Command(h.server, append([]string{configPath}, arguments...)...)
	command.Dir = directory
	if err := command.Start(); err != nil {
		t.Fatal("server start failed")
	}
	exited := make(chan struct{})
	go func() {
		_ = command.Wait()
		close(exited)
	}()
	t.Cleanup(func() { stopHarnessProcess(command, exited) })
	client := redis.NewClient(&redis.Options{Addr: harnessAddress(port), DisableIdentity: true, MaxRetries: -1})
	defer func() { _ = client.Close() }()
	waitFor(t, 15*time.Second, name+" accepts connections", func(ctx context.Context) bool {
		select {
		case <-exited:
			t.Fatalf("%s exited during startup", name)
		default:
		}
		return client.Ping(ctx).Err() == nil
	})
}

// stopHarnessProcess terminates one server and reaps it within a bound.
func stopHarnessProcess(command *exec.Cmd, exited <-chan struct{}) {
	_ = command.Process.Signal(syscall.SIGTERM)
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		<-exited
	}
}

// harnessPKI names the generated throwaway CA, server, and client material.
type harnessPKI struct {
	caFile               string
	caDER                []byte
	serverCertificate    string
	serverKey            string
	clientCertificatePEM []byte
	clientKeyPEM         []byte
}

// writeHarnessPKI generates one throwaway CA with a server certificate for
// localhost and 127.0.0.1 and a client certificate for mutual TLS.
func writeHarnessPKI(t *testing.T, workdir string) harnessPKI {
	t.Helper()
	directory := filepath.Join(workdir, "pki")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal("pki directory creation failed")
	}
	now := time.Now()
	caKey := harnessKey(t)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dkim2 harness CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal("harness CA creation failed")
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal("harness CA parse failed")
	}
	leaf := func(serial int64, usage x509.ExtKeyUsage, server bool) ([]byte, []byte) {
		key := harnessKey(t)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "dkim2 harness leaf"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		}
		if server {
			template.DNSNames = []string{harnessServerName}
			template.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal("harness leaf creation failed")
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal("harness key encoding failed")
		}
		return pem.EncodeToMemory(&pem.Block{Type: harnessCertificateType, Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	}
	serverCertificate, serverKey := leaf(2, x509.ExtKeyUsageServerAuth, true)
	clientCertificate, clientKey := leaf(3, x509.ExtKeyUsageClientAuth, false)
	material := harnessPKI{
		caFile: filepath.Join(directory, "ca.pem"), caDER: caDER,
		serverCertificate: filepath.Join(directory, "server.pem"), serverKey: filepath.Join(directory, "server.key"),
		clientCertificatePEM: clientCertificate, clientKeyPEM: clientKey,
	}
	for path, content := range map[string][]byte{
		material.caFile:            pem.EncodeToMemory(&pem.Block{Type: harnessCertificateType, Bytes: caDER}),
		material.serverCertificate: serverCertificate,
		material.serverKey:         serverKey,
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal("pki write failed")
		}
	}
	return material
}

// harnessKey generates one throwaway P-256 key.
func harnessKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("harness key generation failed")
	}
	return key
}

// requireSentinelSubscription proves whether one Sentinel user may subscribe
// to the failover notification channels go-redis listens on.
func requireSentinelSubscription(t *testing.T, port int, user string, allowed bool) {
	t.Helper()
	client := redis.NewSentinelClient(&redis.Options{
		Addr: harnessAddress(port), Username: user, Password: harnessSentinelPassword,
		DisableIdentity: true, Protocol: 3,
	})
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pubsub := client.Subscribe(ctx, "+switch-master", "+replica-reconf-done")
	defer func() { _ = pubsub.Close() }()
	_, err := pubsub.Receive(ctx)
	if allowed && err != nil {
		t.Fatalf("documented Sentinel ACL cannot subscribe to failover channels: %v", err)
	}
	if !allowed && err == nil {
		t.Fatal("Sentinel user without channel grants subscribed; the channel grants are not required")
	}
}

// openHarnessStore constructs one production store and requires readiness.
func openHarnessStore(t *testing.T, config Config, secrets Secrets) *Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, err := NewStore(ctx, config, secrets)
	if err != nil {
		t.Fatalf("NewStore() failed: %v", err)
	}
	if !store.AuthorityReady() || store.State() != dkim2.ReplayStoreReady {
		t.Fatal("constructed store is not authority-ready")
	}
	return store
}

// requireStartupReason proves NewStore fails with one exact startup class.
func requireStartupReason(t *testing.T, config Config, secrets Secrets, want StartupReason) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, err := NewStore(ctx, config, secrets)
	if store != nil {
		closeHarnessStore(t, store)
		t.Fatalf("NewStore() unexpectedly succeeded; want reason %d", want)
	}
	var startup *StartupError
	if !errors.As(err, &startup) || startup.Reason() != want {
		t.Fatalf("NewStore() error = %v; want startup reason %d", err, want)
	}
}

// requireHealthy proves one probe succeeds and readiness holds.
func requireHealthy(t *testing.T, store *Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := store.Probe(ctx); err != nil || !store.AuthorityReady() {
		t.Fatalf("health probe failed: %v", err)
	}
}

// requireCheck requires one exact successful first-seen outcome.
func requireCheck(t *testing.T, store dkim2.ReplayStore, key dkim2.ReplayKey, retention dkim2.ReplayRetention, want dkim2.ReplayCheck) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	check, err := store.CheckAndRemember(ctx, key, retention)
	if err != nil || check != want {
		t.Fatalf("CheckAndRemember() = %v, %v; want %v", check, err, want)
	}
}

// requireReservation requires one exact successful reservation outcome.
func requireReservation(
	t *testing.T,
	store dkim2.ReplayPropagationStore,
	key dkim2.ReplayKey,
	retention dkim2.ReplayRetention,
	lease dkim2.ReplayLease,
	want dkim2.ReplayPropagationReservation,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	reservation, err := store.ReservePropagation(ctx, key, retention, lease)
	if err != nil || reservation != want {
		t.Fatalf("ReservePropagation() = %v, %v; want %v", reservation, err, want)
	}
}

// requireCommit requires one exact successful commit outcome.
func requireCommit(t *testing.T, store dkim2.ReplayPropagationStore, key dkim2.ReplayKey, want dkim2.ReplayPropagationCommit) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	commit, err := store.CommitPropagation(ctx, key)
	if err != nil || commit != want {
		t.Fatalf("CommitPropagation() = %v, %v; want %v", commit, err, want)
	}
}

// requireAdmin fails the test on one administrative command error.
func requireAdmin(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("administrative harness command failed: %v", err)
	}
}

// closeHarnessStore closes one managed provider under a bounded context.
func closeHarnessStore(t *testing.T, store dkim2.ManagedReplayStore) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.Close(ctx); err != nil {
		t.Fatalf("store close failed: %s", dkim2.ReplayErrorCodeOf(err))
	}
}

// harnessRetention constructs one valid retention.
func harnessRetention(t *testing.T, duration time.Duration) dkim2.ReplayRetention {
	t.Helper()
	retention, err := dkim2.NewReplayRetention(duration)
	if err != nil {
		t.Fatal("retention construction failed")
	}
	return retention
}

// harnessLease constructs the one-second propagation lease.
func harnessLease(t *testing.T) dkim2.ReplayLease {
	t.Helper()
	lease, err := dkim2.NewReplayLease(time.Second)
	if err != nil {
		t.Fatal("lease construction failed")
	}
	return lease
}

// waitFor polls one bounded condition every 100ms until it holds.
func waitFor(t *testing.T, limit time.Duration, what string, condition func(context.Context) bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		held := condition(ctx)
		cancel()
		if held {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting until %s", what)
}

// freePort reserves and releases one loopback TCP port.
func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("loopback port reservation failed")
	}
	defer func() { _ = listener.Close() }()
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("loopback port reservation returned a non-TCP address")
	}
	return address.Port
}

// freeClusterPort returns one free port below the ephemeral range whose
// cluster bus port (port+10000) is also free.
func freeClusterPort(t *testing.T) int {
	t.Helper()
	for range 256 {
		offset, err := rand.Int(rand.Reader, big.NewInt(25_000))
		if err != nil {
			t.Fatal("cluster port selection failed")
		}
		port := 20_000 + int(offset.Int64())
		data, err := net.Listen("tcp", harnessAddress(port))
		if err != nil {
			continue
		}
		bus, err := net.Listen("tcp", harnessAddress(port+10000))
		_ = data.Close()
		if err == nil {
			_ = bus.Close()
			return port
		}
	}
	t.Fatal("no loopback port pair for the cluster bus")
	return 0
}

// harnessAddress renders one loopback host:port.
func harnessAddress(port int) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}
