package config

import (
	"crypto/tls"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testRedisMigrationMarker = "redis-removed-secret-marker"
	testSentinelAddresses    = "sentinel-a.internal:26379,sentinel-b.internal:26379"
	testRedisLocalhost       = "localhost"
	duration1ms              = "1ms"
	testSentinelMaster       = "replay-master"
)

// TestLoadRedisStandaloneDefaults proves that redis is the default backend
// and that every replay.redis default matches the reviewed schema.
func TestLoadRedisStandaloneDefaults(t *testing.T) {
	clearStableEnvironment(t)
	snapshot, err := Load([]byte(redisYAML()), FlagValues{})
	if err != nil {
		t.Fatalf("Load() failed with code %s", CodeOf(err))
	}
	if snapshot.Backend() != ReplayRedis || snapshot.Replay().Backend() != ReplayRedis || !snapshot.Replay().Enabled() {
		t.Fatal("Load() did not select the default Redis backend")
	}
	redis, present := snapshot.Replay().Redis()
	if !present {
		t.Fatal("Load() omitted the selected Redis configuration")
	}
	checks := map[string]bool{
		"mode":               redis.Mode() == RedisStandalone && redis.Mode().Label() == "standalone",
		"address":            redis.StandaloneAddress() == testRedisAddress,
		"sentinel empty":     redis.SentinelMasterName() == "" && redis.SentinelAddresses() == nil && redis.SentinelUsername() == "" && redis.SentinelPasswordFile() == "",
		"cluster empty":      redis.ClusterAddresses() == nil,
		"max redirects":      redis.ClusterMaxRedirects() == 8,
		"username":           redis.Username() == "application",
		"password file":      redis.PasswordFile() == "/secure/"+testGeneration+"/redis-password",
		"database":           redis.DatabaseNumber() == 0,
		"key prefix":         redis.KeyPrefix() == "",
		"protocol":           redis.Protocol() == 3,
		"tls enabled":        redis.TLSEnabled(),
		"tls ca":             redis.TLSCAFile() == "/secure/"+testGeneration+"/ca",
		"tls client":         redis.TLSCertificateFile() == "" && redis.TLSKeyFile() == "",
		"tls server name":    redis.TLSServerName() == "replay.example",
		"tls min version":    redis.TLSMinVersion() == tls.VersionTLS12,
		"tls insecure":       !redis.TLSInsecureSkipVerify(),
		"pool size":          redis.PoolSize() == 20,
		"min idle":           redis.MinIdleConnections() == 2,
		"pool timeout":       redis.PoolTimeout() == 2*time.Second,
		"dial timeout":       redis.DialTimeout() == 2*time.Second,
		"read timeout":       redis.ReadTimeout() == 2*time.Second,
		"write timeout":      redis.WriteTimeout() == 2*time.Second,
		"retry attempts":     redis.RetryMaxAttempts() == 3,
		"retry min backoff":  redis.RetryMinBackoff() == 50*time.Millisecond,
		"retry max backoff":  redis.RetryMaxBackoff() == 500*time.Millisecond,
		"health interval":    redis.HealthInterval() == 5*time.Second,
		"health timeout":     redis.HealthTimeout() == 2*time.Second,
		"health threshold":   redis.HealthFailureThreshold() == 3,
		"require noeviction": redis.RequireNoEviction(),
	}
	for name, ok := range checks {
		if !ok {
			t.Errorf("Redis default %s changed", name)
		}
	}
}

// TestLoadRedisExplicitValuesFromYAML proves every replay.redis path is typed
// from YAML at or near its bounds.
func TestLoadRedisExplicitValuesFromYAML(t *testing.T) {
	clearStableEnvironment(t)
	snapshot, err := Load([]byte(redisExplicitClusterYAML()), FlagValues{})
	if err != nil {
		t.Fatalf("Load() failed with code %s", CodeOf(err))
	}
	redis, _ := snapshot.Replay().Redis()
	secure := "/secure/" + testGeneration + "/"
	assertRedisChecks(t, "YAML", map[string]bool{
		"yaml mode":           redis.Mode() == RedisCluster && redis.Mode().Label() == "cluster",
		"yaml addresses":      slices.Equal(redis.ClusterAddresses(), []string{"10.0.0.1:7000", "10.0.0.2:7000", "redis-c.internal:7000"}),
		"yaml redirects":      redis.ClusterMaxRedirects() == 16,
		"yaml username":       redis.Username() == "replay-user",
		"yaml key prefix":     redis.KeyPrefix() == "mailstack:",
		"yaml protocol":       redis.Protocol() == 2,
		"yaml client cert":    redis.TLSCertificateFile() == secure+"client-cert",
		"yaml client key":     redis.TLSKeyFile() == secure+"client-key",
		"yaml min version":    redis.TLSMinVersion() == tls.VersionTLS13,
		"yaml insecure":       redis.TLSInsecureSkipVerify(),
		"yaml pool":           redis.PoolSize() == 64 && redis.MinIdleConnections() == 64,
		"yaml pool timeout":   redis.PoolTimeout() == time.Millisecond,
		"yaml dial timeout":   redis.DialTimeout() == 100*time.Millisecond,
		"yaml read timeout":   redis.ReadTimeout() == 30*time.Second,
		"yaml write timeout":  redis.WriteTimeout() == 3*time.Second,
		"yaml retries":        redis.RetryMaxAttempts() == 10 && redis.RetryMinBackoff() == 5*time.Second && redis.RetryMaxBackoff() == 5*time.Second,
		"yaml health":         redis.HealthInterval() == time.Minute && redis.HealthTimeout() == 59*time.Second && redis.HealthFailureThreshold() == 10,
		"yaml no noeviction":  !redis.RequireNoEviction(),
		"yaml no sentinel":    redis.SentinelAddresses() == nil && redis.StandaloneAddress() == "",
		"yaml database":       redis.DatabaseNumber() == 0,
		"yaml server name":    redis.TLSServerName() == "replay.example",
		"yaml tls enabled":    redis.TLSEnabled(),
		"CA file":             redis.TLSCAFile() == secure+"ca",
		"yaml password file":  redis.PasswordFile() == secure+"redis-password",
		"yaml sentinel files": redis.SentinelPasswordFile() == "" && redis.SentinelUsername() == "",
	})
	// The cluster subtree stays explicit in YAML, so switching the mode to
	// Sentinel through the environment must fail the presence matrix.
	setRedisEnvironment(t, map[string]string{
		pathRedisMode:               valueRedisSentinel,
		pathRedisSentinelMasterName: testSentinelMaster,
		pathRedisSentinelAddresses:  testSentinelAddresses,
	})
	if _, err := Load([]byte(redisExplicitClusterYAML()), FlagValues{}); CodeOf(err) != CodeInvalidMatrix {
		t.Fatalf("environment mode switch with a stale cluster subtree returned code %s", CodeOf(err))
	}
}

// TestLoadRedisEnvironmentOverridesYAML proves every DKIM2D_REPLAY_REDIS_*
// binding is honored, wins over YAML, and keeps layered provenance.
func TestLoadRedisEnvironmentOverridesYAML(t *testing.T) {
	clearStableEnvironment(t)
	secure := "/secure/" + testGeneration + "/"
	setRedisEnvironment(t, map[string]string{
		pathRedisMode:                   valueRedisSentinel,
		pathRedisSentinelMasterName:     testSentinelMaster,
		pathRedisSentinelAddresses:      " sentinel-a.internal:26379 , [2001:db8::1]:26379 ",
		pathRedisSentinelUsername:       "sentinel-user",
		pathRedisSentinelPasswordFile:   secure + "sentinel-password",
		pathRedisAuthUsername:           "env-user",
		pathRedisAuthPasswordFile:       secure + "redis-password",
		pathRedisDatabaseNumber:         "15",
		pathRedisKeyPrefix:              "",
		pathRedisProtocol:               "2",
		pathRedisTLSEnabled:             canonicalTrue,
		pathRedisTLSCAFile:              secure + "ca",
		pathRedisTLSCertificate:         secure + "client-cert",
		pathRedisTLSKey:                 secure + "client-key",
		pathRedisTLSServerName:          testRedisLocalhost,
		pathRedisTLSMinVersion:          valueTLS13,
		pathRedisTLSInsecureSkipVerify:  canonicalTrue,
		pathRedisPoolSize:               "1024",
		pathRedisMinIdleConnections:     "0",
		pathRedisPoolTimeout:            defaultReadTimeout,
		pathRedisDialTimeout:            defaultReadTimeout,
		pathRedisReadTimeout:            defaultAdmissionWait,
		pathRedisWriteTimeout:           defaultAdmissionWait,
		pathRedisRetriesMaxAttempts:     "1",
		pathRedisRetriesMinBackoff:      duration1ms,
		pathRedisRetriesMaxBackoff:      duration1ms,
		pathRedisHealthInterval:         "1s",
		pathRedisHealthTimeout:          defaultAdmissionWait,
		pathRedisHealthFailureThreshold: "1",
		pathRedisRequireNoEviction:      canonicalTrue,
	})
	environmentOnly := redisDocument("    pool_size: 8\n    require_noeviction: false\n")
	snapshot, err := Load([]byte(environmentOnly), FlagValues{})
	if err != nil {
		t.Fatalf("Load() with environment overrides failed with code %s", CodeOf(err))
	}
	redis, _ := snapshot.Replay().Redis()
	assertRedisChecks(t, "environment", map[string]bool{
		"env mode":            redis.Mode() == RedisSentinel,
		"env master":          redis.SentinelMasterName() == testSentinelMaster,
		"env addresses":       slices.Equal(redis.SentinelAddresses(), []string{"sentinel-a.internal:26379", "[2001:db8::1]:26379"}),
		"env sentinel user":   redis.SentinelUsername() == "sentinel-user",
		"env sentinel file":   redis.SentinelPasswordFile() == secure+"sentinel-password",
		"env no cluster":      redis.ClusterAddresses() == nil && redis.ClusterMaxRedirects() == 8,
		"env database":        redis.DatabaseNumber() == 15,
		"env protocol":        redis.Protocol() == 2,
		"env key prefix":      redis.KeyPrefix() == "",
		"env username":        redis.Username() == "env-user",
		"env password file":   redis.PasswordFile() == secure+"redis-password",
		"env server name":     redis.TLSServerName() == testRedisLocalhost,
		"env client identity": redis.TLSCertificateFile() == secure+"client-cert" && redis.TLSKeyFile() == secure+"client-key",
		"env min version":     redis.TLSMinVersion() == tls.VersionTLS13,
		"env insecure":        redis.TLSInsecureSkipVerify(),
		"env health":          redis.HealthInterval() == time.Second && redis.HealthTimeout() == 100*time.Millisecond && redis.HealthFailureThreshold() == 1,
		"env noeviction":      redis.RequireNoEviction(),
		"env retries":         redis.RetryMaxAttempts() == 1 && redis.RetryMinBackoff() == time.Millisecond && redis.RetryMaxBackoff() == time.Millisecond,
		"env pool":            redis.PoolSize() == 1024 && redis.MinIdleConnections() == 0,
		"env timeouts": redis.PoolTimeout() == 30*time.Second && redis.DialTimeout() == 30*time.Second &&
			redis.ReadTimeout() == 100*time.Millisecond && redis.WriteTimeout() == 100*time.Millisecond,
	})
	presence, _ := snapshot.Presence(pathRedisSentinelAddresses)
	if !presence.Environment || presence.YAML || presence.Winner != SourceEnvironment {
		t.Fatal("Sentinel address list lost its environment provenance")
	}
	poolPresence, _ := snapshot.Presence(pathRedisPoolSize)
	if !poolPresence.YAML || !poolPresence.Environment || poolPresence.Winner != SourceEnvironment {
		t.Fatal("pool size lost its layered provenance")
	}
	setRedisEnvironment(t, map[string]string{pathRedisClusterMaxRedirects: "4"})
	if _, err := Load([]byte(environmentOnly), FlagValues{}); CodeOf(err) != CodeInvalidMatrix {
		t.Fatalf("environment cluster key in Sentinel mode returned code %s", CodeOf(err))
	}
}

// assertRedisChecks reports every failed named accessor expectation.
func assertRedisChecks(t *testing.T, source string, checks map[string]bool) {
	t.Helper()
	for name, ok := range checks {
		if !ok {
			t.Errorf("%s Redis value %s changed", source, name)
		}
	}
}

// setRedisEnvironment binds each stable path's own environment variable for
// the test, deriving the variable name from the authoritative schema.
func setRedisEnvironment(t *testing.T, values map[string]string) {
	t.Helper()
	specs, err := indexFieldSpecs(stableFieldSpecs())
	if err != nil {
		t.Fatal("schema index failed")
	}
	for path, value := range values {
		spec, present := specs[path]
		if !present || spec.env == "" {
			t.Fatalf("path %s has no environment binding", path)
		}
		t.Setenv(spec.env, value)
	}
}

// redisExplicitClusterYAML returns one cluster document that sets every
// cluster-compatible replay.redis key explicitly.
func redisExplicitClusterYAML() string {
	return redisDocument(`    mode: cluster
    cluster:
      addresses: "10.0.0.1:7000, 10.0.0.2:7000 ,redis-c.internal:7000"
      max_redirects: 16
    auth:
      username: replay-user
      password_file: /secure/` + testGeneration + `/redis-password
    database_number: 0
    key_prefix: "mailstack:"
    protocol: 2
    tls:
      enabled: true
      ca_file: /secure/` + testGeneration + `/ca
      cert: /secure/` + testGeneration + `/client-cert
      key: /secure/` + testGeneration + `/client-key
      server_name: replay.example
      min_tls_version: TLS1.3
      insecure_skip_verify: true
    pool_size: 64
    min_idle_connections: 64
    pool_timeout: 1ms
    dial_timeout: 100ms
    read_timeout: 30s
    write_timeout: 3s
    retries:
      max_attempts: 10
      min_backoff: 5s
      max_backoff: 5s
    health:
      interval: 60s
      timeout: 59s
      failure_threshold: 10
    require_noeviction: false
`)
}

// TestLoadRedisAddressListsAreParsedOnceAndCloned proves the accessor hands
// out independent copies of the parsed address lists.
func TestLoadRedisAddressListsAreParsedOnceAndCloned(t *testing.T) {
	clearStableEnvironment(t)
	for _, document := range []string{redisSentinelYAML(), redisClusterYAML()} {
		snapshot, err := Load([]byte(document), FlagValues{})
		if err != nil {
			t.Fatalf("Load() failed with code %s", CodeOf(err))
		}
		redis, _ := snapshot.Replay().Redis()
		addresses := redis.SentinelAddresses()
		if redis.Mode() == RedisCluster {
			addresses = redis.ClusterAddresses()
		}
		if len(addresses) < 2 {
			t.Fatal("address list was not parsed")
		}
		original := addresses[0]
		addresses[0] = "mutated.internal:1"
		again := redis.SentinelAddresses()
		if redis.Mode() == RedisCluster {
			again = redis.ClusterAddresses()
		}
		if again[0] != original {
			t.Fatal("address accessor exposed shared backing storage")
		}
	}
}

// TestLoadRedisAddressListFromPlaceholder proves scalar placeholder expansion
// runs before list parsing and validation.
func TestLoadRedisAddressListFromPlaceholder(t *testing.T) {
	clearStableEnvironment(t)
	t.Setenv("TEST_REDIS_SENTINELS", "sentinel-x.internal:26379, sentinel-y.internal:26379")
	document := strings.Replace(redisSentinelYAML(), `"`+testSentinelAddresses+`"`, `"${TEST_REDIS_SENTINELS}"`, 1)
	snapshot, err := Load([]byte(document), FlagValues{})
	if err != nil {
		t.Fatalf("Load() failed with code %s", CodeOf(err))
	}
	redis, _ := snapshot.Replay().Redis()
	if !slices.Equal(redis.SentinelAddresses(), []string{"sentinel-x.internal:26379", "sentinel-y.internal:26379"}) {
		t.Fatal("placeholder-expanded address list was not parsed")
	}
	t.Setenv("TEST_REDIS_SENTINELS", "sentinel-x.internal:26379,,sentinel-y.internal:26379")
	if _, err := Load([]byte(document), FlagValues{}); CodeOf(err) != CodeInvalidField {
		t.Fatalf("expanded empty element returned code %s", CodeOf(err))
	}
}

// TestParseRedisAddressListEdgeCases freezes the comma-separated host:port
// grammar, bounds, trimming, and duplicate rejection.
func TestParseRedisAddressListEdgeCases(t *testing.T) {
	longLabel := strings.Repeat("a", 63)
	longHost := strings.Join([]string{longLabel, longLabel, longLabel, strings.Repeat("b", 56)}, ".")
	accepted := map[string][]string{
		"redis.internal:6379":                   {"redis.internal:6379"},
		" a.internal:1 ,\tb.internal:65535 ":    {"a.internal:1", "b.internal:65535"},
		"127.0.0.1:6379,[::1]:6379":             {"127.0.0.1:6379", "[::1]:6379"},
		"mailstack_valkey:6379":                 {"mailstack_valkey:6379"},
		"valkey:6379":                           {"valkey:6379"},
		"tasks.mailstack-valkey.internal:26379": {"tasks.mailstack-valkey.internal:26379"},
		longHost + ":6379":                      {longHost + ":6379"},
	}
	for input, want := range accepted {
		got, err := parseRedisAddressList(input, maxRedisClusterAddresses)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("parseRedisAddressList(%q) = %q, code %s", input, got, CodeOf(err))
		}
	}
	rejected := []string{
		"", " ", ",", "a.internal:1,", ",a.internal:1", "a.internal:1,,b.internal:2",
		"a.internal:1, a.internal:1", "a.internal:1,a.internal:1",
		"a.internal", "a.internal:", ":6379", "a.internal:0", "a.internal:65536",
		"a.internal:06379", "a.internal:+1", "a.internal:http",
		"Redis.internal:6379", "redis.internal.:6379", "-redis.internal:6379",
		"redis-.internal:6379", "redis..internal:6379", "redis internal:6379",
		"999.1.1.1:6379", "10.0.0:6379", "0.0.0.0:6379", "[::]:6379",
		"224.0.0.1:6379", "[fe80::1%en0]:6379", "[::ffff:192.0.2.1]:6379",
		"[2001:DB8::1]:6379", "2001:db8::1:6379", "[2001:db8:0::1]:6379",
		"redis{tag}.internal:6379", "user@redis.internal:6379",
		"redis://redis.internal:6379", longHost + strings.Repeat("x", 6) + ":6379",
		strings.Repeat("a", 64) + ".internal:6379",
	}
	for _, input := range rejected {
		if got, err := parseRedisAddressList(input, maxRedisClusterAddresses); err == nil || CodeOf(err) != CodeInvalidField {
			t.Fatalf("parseRedisAddressList(%q) accepted %q", input, got)
		}
	}
	elements := func(count int) string {
		values := make([]string, count)
		for index := range values {
			values[index] = "node-" + strconv.Itoa(index) + ".internal:6379"
		}
		return strings.Join(values, ",")
	}
	for _, bounds := range []struct{ maximum int }{{maxRedisSentinelAddresses}, {maxRedisClusterAddresses}} {
		if got, err := parseRedisAddressList(elements(bounds.maximum), bounds.maximum); err != nil || len(got) != bounds.maximum {
			t.Fatalf("list at maximum %d was rejected with code %s", bounds.maximum, CodeOf(err))
		}
		if _, err := parseRedisAddressList(elements(bounds.maximum+1), bounds.maximum); err == nil {
			t.Fatalf("list above maximum %d was accepted", bounds.maximum)
		}
	}
	element255 := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." +
		strings.Repeat("d", 60) + ":10"
	if len(element255) != 255 || !validRedisAddress(element255) {
		t.Fatalf("255-byte element was rejected (len %d)", len(element255))
	}
	if validRedisAddress(element255 + "0") {
		t.Fatal("256-byte element was accepted")
	}
}

// TestLoadRedisModeAndFieldMatrix freezes mode-dependent presence, forbidden
// subtrees, cross-field relations, and typed field bounds.
func TestLoadRedisModeAndFieldMatrix(t *testing.T) {
	clearStableEnvironment(t)
	secure := "/secure/" + testGeneration + "/"
	standalone := "    standalone:\n      address: " + testRedisAddress + "\n"
	sentinel := "    mode: sentinel\n    sentinel:\n      master_name: mymaster\n      addresses: \"" + testSentinelAddresses + "\"\n"
	cluster := "    mode: cluster\n    cluster:\n      addresses: \"10.0.0.1:7000,10.0.0.2:7000\"\n"
	tests := []struct {
		name  string
		block string
		code  Code
	}{
		{"standalone minimal", standalone, ""},
		{"standalone explicit mode", "    mode: standalone\n" + standalone, ""},
		{"standalone missing address", "    mode: standalone\n", CodeInvalidMatrix},
		{"standalone with sentinel subtree", standalone + "    sentinel:\n      master_name: mymaster\n", CodeInvalidMatrix},
		{"standalone with cluster subtree", standalone + "    cluster:\n      max_redirects: 3\n", CodeInvalidMatrix},
		{"standalone list address", "    standalone:\n      address: \"a.internal:1,b.internal:2\"\n", CodeInvalidField},
		{"standalone padded address", "    standalone:\n      address: \" a.internal:1\"\n", CodeInvalidField},
		{"sentinel minimal", sentinel, ""},
		{"sentinel missing master", "    mode: sentinel\n    sentinel:\n      addresses: \"" + testSentinelAddresses + "\"\n", CodeInvalidMatrix},
		{"sentinel missing addresses", "    mode: sentinel\n    sentinel:\n      master_name: mymaster\n", CodeInvalidMatrix},
		{"sentinel with standalone", sentinel + standalone, CodeInvalidMatrix},
		{"sentinel with cluster", sentinel + "    cluster:\n      addresses: \"10.0.0.1:7000\"\n", CodeInvalidMatrix},
		{"sentinel invalid master", "    mode: sentinel\n    sentinel:\n      master_name: \"my master\"\n      addresses: \"" + testSentinelAddresses + "\"\n", CodeInvalidField},
		{"sentinel username without password", "    mode: sentinel\n    sentinel:\n      master_name: mymaster\n      addresses: \"" + testSentinelAddresses + "\"\n      username: watcher\n", CodeInvalidMatrix},
		{"sentinel password without username", "    mode: sentinel\n    sentinel:\n      master_name: mymaster\n      addresses: \"" + testSentinelAddresses + "\"\n      password_file: " + secure + "sentinel-password\n", ""},
		{"sentinel too many addresses", "    mode: sentinel\n    sentinel:\n      master_name: mymaster\n      addresses: \"" + manyRedisAddresses(33) + "\"\n", CodeInvalidField},
		{"cluster minimal", cluster, ""},
		{"cluster explicit database zero", cluster + "    database_number: 0\n", ""},
		{"cluster nonzero database", cluster + "    database_number: 1\n", CodeInvalidField},
		{"cluster with standalone", cluster + standalone, CodeInvalidMatrix},
		{"cluster with sentinel", cluster + "    sentinel:\n      master_name: mymaster\n", CodeInvalidMatrix},
		{"cluster too many addresses", "    mode: cluster\n    cluster:\n      addresses: \"" + manyRedisAddresses(65) + "\"\n", CodeInvalidField},
		{"unknown Redis key", cluster + "    cluster_unused: 1\n", CodeInvalidYAML},
		{"unknown mode", "    mode: replicated\n" + standalone, CodeInvalidField},
		{"auth username without password", standalone + "    auth:\n      username: app\n", CodeInvalidMatrix},
		{"auth password without username", standalone + "    auth:\n      password_file: " + secure + "redis-password\n", ""},
		{"auth username with space", standalone + "    auth:\n      username: \"a b\"\n      password_file: " + secure + "redis-password\n", CodeInvalidField},
		{"database above range", standalone + "    database_number: 16\n", CodeInvalidField},
		{"key prefix brace", standalone + "    key_prefix: \"{tag}\"\n", CodeInvalidField},
		{"key prefix space", standalone + "    key_prefix: \"a b\"\n", CodeInvalidField},
		{"key prefix maximum", standalone + "    key_prefix: \"" + strings.Repeat("k", 64) + "\"\n", ""},
		{"key prefix above maximum", standalone + "    key_prefix: \"" + strings.Repeat("k", 65) + "\"\n", CodeInvalidField},
		{"protocol 4", standalone + "    protocol: 4\n", CodeInvalidField},
		{"protocol 1", standalone + "    protocol: 1\n", CodeInvalidField},
		{"tls cert without key", standalone + "    tls:\n      cert: " + secure + "client-cert\n", CodeInvalidMatrix},
		{"tls key without cert", standalone + "    tls:\n      key: " + secure + "client-key\n", CodeInvalidMatrix},
		{"tls disabled", standalone + "    tls:\n      enabled: false\n", ""},
		{"tls disabled with CA", standalone + "    tls:\n      enabled: false\n      ca_file: " + secure + "ca\n", CodeInvalidMatrix},
		{"tls disabled with insecure", standalone + "    tls:\n      enabled: false\n      insecure_skip_verify: true\n", CodeInvalidMatrix},
		{"tls disabled with server name", standalone + "    tls:\n      enabled: false\n      server_name: replay.example\n", CodeInvalidMatrix},
		{"tls disabled with min version", standalone + "    tls:\n      enabled: false\n      min_tls_version: TLS1.3\n", CodeInvalidMatrix},
		{"tls insecure with tls", standalone + "    tls:\n      insecure_skip_verify: true\n", ""},
		{"tls min version 1.1", standalone + "    tls:\n      min_tls_version: TLS1.1\n", CodeInvalidField},
		{"tls min version lowercase", standalone + "    tls:\n      min_tls_version: tls1.3\n", CodeInvalidField},
		{"tls server name localhost", standalone + "    tls:\n      server_name: localhost\n", ""},
		{"tls server name IP", standalone + "    tls:\n      server_name: 192.0.2.10\n", ""},
		{"tls server name uppercase", standalone + "    tls:\n      server_name: Replay.Example\n", CodeInvalidField},
		{"tls enabled non boolean", standalone + "    tls:\n      enabled: \"yes\"\n", CodeInvalidField},
		{"pool size zero", standalone + "    pool_size: 0\n", CodeInvalidField},
		{"pool size above", standalone + "    pool_size: 1025\n", CodeInvalidField},
		{"min idle above pool", standalone + "    pool_size: 4\n    min_idle_connections: 5\n", CodeInvalidField},
		{"min idle equals pool", standalone + "    pool_size: 4\n    min_idle_connections: 4\n", ""},
		{"backoff inverted", standalone + "    retries:\n      min_backoff: 600ms\n      max_backoff: 500ms\n", CodeInvalidField},
		{"backoff above", standalone + "    retries:\n      max_backoff: 6s\n", CodeInvalidField},
		{"attempts zero", standalone + "    retries:\n      max_attempts: 0\n", CodeInvalidField},
		{"attempts above", standalone + "    retries:\n      max_attempts: 11\n", CodeInvalidField},
		{"health timeout equals interval", standalone + "    health:\n      interval: 2s\n      timeout: 2s\n", CodeInvalidField},
		{"health timeout above interval", standalone + "    health:\n      interval: 2s\n      timeout: 3s\n", CodeInvalidField},
		{"health timeout just below interval", standalone + "    health:\n      interval: 2s\n      timeout: 1999ms\n", ""},
		{"health interval below", standalone + "    health:\n      interval: 999ms\n      timeout: 100ms\n", CodeInvalidField},
		{"health interval above", standalone + "    health:\n      interval: 61s\n", CodeInvalidField},
		{"health timeout below", standalone + "    health:\n      timeout: 99ms\n", CodeInvalidField},
		{"health threshold zero", standalone + "    health:\n      failure_threshold: 0\n", CodeInvalidField},
		{"health threshold above", standalone + "    health:\n      failure_threshold: 11\n", CodeInvalidField},
		{"require noeviction false", standalone + "    require_noeviction: false\n", ""},
		{"dial timeout below", standalone + "    dial_timeout: 99ms\n", CodeInvalidField},
		{"read timeout above", standalone + "    read_timeout: 31s\n", CodeInvalidField},
		{"write timeout weak", standalone + "    write_timeout: 1.5s\n", CodeInvalidField},
		{"pool timeout zero", standalone + "    pool_timeout: 0s\n", CodeInvalidField},
		{"password equals HMAC path", standalone + "    auth:\n      password_file: " + secure + "hmac\n", CodeInvalidField},
		{"password equals capability path", standalone + "    auth:\n      password_file: " + secure + "capability\n", CodeInvalidField},
		{"sentinel password equals redis password", "    mode: sentinel\n    sentinel:\n      master_name: mymaster\n      addresses: \"" + testSentinelAddresses + "\"\n      password_file: " + secure + "same\n    auth:\n      password_file: " + secure + "same\n", CodeInvalidField},
		{"CA equals client key", standalone + "    tls:\n      ca_file: " + secure + "same\n      cert: " + secure + "cert\n      key: " + secure + "same\n", CodeInvalidField},
		{"password outside generation", standalone + "    auth:\n      password_file: /secure/other/redis-password\n", CodeInvalidField},
		{"password relative", standalone + "    auth:\n      password_file: redis-password\n", CodeInvalidField},
		{"CA outside generation", standalone + "    tls:\n      ca_file: /etc/ssl/ca.pem\n", CodeInvalidField},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Load([]byte(redisDocument(test.block)), FlagValues{})
			if test.code == "" {
				if err != nil {
					t.Fatalf("Load() rejected a valid document with code %s", CodeOf(err))
				}
				return
			}
			if CodeOf(err) != test.code {
				t.Fatalf("Load() returned code %s, want %s", CodeOf(err), test.code)
			}
		})
	}
}

// manyRedisAddresses returns count distinct canonical host:port elements.
func manyRedisAddresses(count int) string {
	values := make([]string, count)
	for index := range values {
		values[index] = "node-" + strconv.Itoa(index) + ".internal:6379"
	}
	return strings.Join(values, ",")
}

// TestLoadRedisMissingCommonReplayKeys proves redis keeps the HMAC and epoch
// requirements of the networked backend.
func TestLoadRedisMissingCommonReplayKeys(t *testing.T) {
	clearStableEnvironment(t)
	for _, line := range []string{
		"  hmac_key_file: /secure/" + testGeneration + "/hmac\n",
		"  epoch: 1\n",
	} {
		document := strings.Replace(redisYAML(), line, "", 1)
		if _, err := Load([]byte(document), FlagValues{}); CodeOf(err) != CodeInvalidMatrix {
			t.Fatalf("Load() without %q returned code %s", strings.TrimSpace(line), CodeOf(err))
		}
	}
	explicit := strings.Replace(redisYAML(), "replay:\n", "replay:\n  backend: redis\n", 1)
	if _, err := Load([]byte(explicit), FlagValues{}); err != nil {
		t.Fatalf("explicit redis backend returned code %s", CodeOf(err))
	}
	if _, err := Load([]byte(explicit), NewFlagValues("", false, "", false, "redis", true)); err != nil {
		t.Fatalf("flag-selected redis backend returned code %s", CodeOf(err))
	}
}

// TestRedisSubtreeIsForbiddenWithMemoryAndDisabled proves the non-networked
// backends refuse any explicit replay.redis key from YAML or environment.
func TestRedisSubtreeIsForbiddenWithMemoryAndDisabled(t *testing.T) {
	clearStableEnvironment(t)
	memory := memoryYAML("1", "capability")
	if _, err := Load([]byte(memory), FlagValues{}); err != nil {
		t.Fatalf("memory baseline returned code %s", CodeOf(err))
	}
	for name, document := range map[string]string{
		"memory yaml":   memory + "  redis:\n    pool_size: 4\n",
		"disabled yaml": strings.Replace(disabledYAML(), "  backend: disabled\n", "  backend: disabled\n  redis:\n    tls:\n      enabled: false\n", 1),
	} {
		if _, err := Load([]byte(document), FlagValues{}); CodeOf(err) != CodeInvalidMatrix {
			t.Fatalf("%s returned code %s", name, CodeOf(err))
		}
	}
	t.Run("environment", func(t *testing.T) {
		setRedisEnvironment(t, map[string]string{pathRedisStandaloneAddress: testRedisAddress})
		for _, document := range []string{memory, disabledYAML()} {
			if _, err := Load([]byte(document), FlagValues{}); CodeOf(err) != CodeInvalidMatrix {
				t.Fatalf("environment Redis key returned code %s", CodeOf(err))
			}
		}
	})
	snapshot, err := Load([]byte(memory), FlagValues{})
	if err != nil {
		t.Fatalf("memory returned code %s", CodeOf(err))
	}
	if _, present := snapshot.Replay().Redis(); present {
		t.Fatal("memory backend materialized Redis configuration")
	}
	var zero RedisConfig
	if zero.Mode() != 0 || zero.SentinelAddresses() != nil || zero.ClusterAddresses() != nil ||
		zero.TLSEnabled() || zero.RequireNoEviction() || zero.PoolSize() != 0 || zero.HealthInterval() != 0 ||
		RedisMode(0).Label() != "" {
		t.Fatal("zero RedisConfig exposed non-zero values")
	}
	if _, present := (ReplayConfig{}).Redis(); present {
		t.Fatal("zero ReplayConfig reported a Redis configuration")
	}
}

// TestRemovedValkeyConfigurationFailsWithMigrationGuidance reproduces every
// removed Valkey-provider source: the replay.valkey YAML subtree, its
// DKIM2D_REPLAY_VALKEY_* environment prefix, replay.revalidate_interval, and
// the replay.backend value valkey from YAML, environment, and flag. Each fails
// with CodeRemovedField, points to the migration guide, and never echoes the
// configured value.
func TestRemovedValkeyConfigurationFailsWithMigrationGuidance(t *testing.T) {
	clearStableEnvironment(t)
	assertRedisMigration := func(t *testing.T, err error, name string) {
		t.Helper()
		if CodeOf(err) != CodeRemovedField {
			t.Fatalf("%s returned code %s, want %s", name, CodeOf(err), CodeRemovedField)
		}
		migration, ok := MigrationOf(err)
		if !ok || !strings.Contains(migration, replayRedisMigrationDocument) || strings.Contains(err.Error(), testRedisMigrationMarker) {
			t.Fatalf("%s migration = %q", name, migration)
		}
	}
	yamlCases := map[string]string{
		"valkey subtree": redisYAML() + "  valkey:\n    address: \"" + testRedisMigrationMarker + "\"\n",
		"valkey attestation": strings.Replace(memoryYAML("1", "capability"), "  backend: memory\n",
			"  backend: memory\n  valkey:\n    attestation:\n      shared_epoch: true\n", 1),
		"valkey with disabled": strings.Replace(disabledYAML(), "  backend: disabled\n",
			"  backend: disabled\n  valkey:\n    auditor_password_file: \""+testRedisMigrationMarker+"\"\n", 1),
		"valkey scalar":       redisYAML() + "  valkey: \"" + testRedisMigrationMarker + "\"\n",
		"revalidate interval": redisYAML() + "  revalidate_interval: 30s\n",
		"backend value":       strings.Replace(memoryYAML("1", "capability"), "  backend: memory\n", "  backend: valkey\n", 1),
	}
	for name, document := range yamlCases {
		_, err := Load([]byte(document), FlagValues{})
		assertRedisMigration(t, err, name)
		migration, _ := MigrationOf(err)
		switch name {
		case "revalidate interval":
			if !strings.Contains(migration, "configuration key replay.revalidate_interval") {
				t.Fatalf("%s migration = %q", name, migration)
			}
		case "backend value":
			if !strings.Contains(migration, "configuration value valkey of replay.backend") {
				t.Fatalf("%s migration = %q", name, migration)
			}
		default:
			if !strings.Contains(migration, "configuration key replay.valkey ") {
				t.Fatalf("%s migration = %q", name, migration)
			}
		}
	}
	for _, name := range []string{
		"DKIM2D_REPLAY_VALKEY_ADDRESS",
		"DKIM2D_REPLAY_VALKEY_AUDITOR_PASSWORD_FILE",
		"DKIM2D_REPLAY_VALKEY_ATTESTATION_SHARED_EPOCH",
		"DKIM2D_REPLAY_VALKEY_FUTURE_UNKNOWN",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, testRedisMigrationMarker)
			_, err := Load([]byte(redisYAML()), FlagValues{})
			assertRedisMigration(t, err, name)
			migration, _ := MigrationOf(err)
			if !strings.Contains(migration, "environment variable DKIM2D_REPLAY_VALKEY_* ") || strings.Contains(migration, name) {
				t.Fatalf("%s migration = %q", name, migration)
			}
		})
	}
	t.Run("revalidate environment", func(t *testing.T) {
		t.Setenv("DKIM2D_REPLAY_REVALIDATE_INTERVAL", testRedisMigrationMarker)
		_, err := Load([]byte(memoryYAML("1", "capability")), FlagValues{})
		assertRedisMigration(t, err, "revalidate environment")
	})
	t.Run("backend environment", func(t *testing.T) {
		t.Setenv("DKIM2D_REPLAY_BACKEND", "valkey")
		_, err := Load([]byte(redisYAML()), FlagValues{})
		assertRedisMigration(t, err, "backend environment")
	})
	t.Run("backend flag", func(t *testing.T) {
		_, err := Load([]byte(redisYAML()), NewFlagValues("", false, "", false, "valkey", true))
		assertRedisMigration(t, err, "backend flag")
	})
	t.Run("backend placeholder", func(t *testing.T) {
		t.Setenv("TEST_REPLAY_BACKEND", "valkey")
		document := strings.Replace(memoryYAML("1", "capability"), "  backend: memory\n", "  backend: ${TEST_REPLAY_BACKEND}\n", 1)
		_, err := Load([]byte(document), FlagValues{})
		assertRedisMigration(t, err, "backend placeholder")
	})
	for _, value := range []string{"Valkey", "valkey ", testRedisMigrationMarker} {
		_, err := Load([]byte(redisYAML()), NewFlagValues("", false, "", false, value, true))
		if CodeOf(err) != CodeInvalidField || strings.Contains(err.Error(), testRedisMigrationMarker) {
			t.Fatalf("unknown backend value returned code %s", CodeOf(err))
		}
	}
}

// redisDocument returns one valid Redis-backend document around the given
// replay.redis block, whose lines are indented by four spaces.
func redisDocument(block string) string {
	return `config:
  version: dkim2d-config-v1
protected:
  generation: ` + testGeneration + `
server:
  capability_file: /secure/` + testGeneration + `/capability
replay:
  hmac_key_file: /secure/` + testGeneration + `/hmac
  epoch: 1
  redis:
` + block
}

// redisYAML returns one complete valid standalone Redis document relying on
// the default backend.
func redisYAML() string {
	return redisDocument(`    standalone:
      address: ` + testRedisAddress + `
    auth:
      username: application
      password_file: /secure/` + testGeneration + `/redis-password
    tls:
      ca_file: /secure/` + testGeneration + `/ca
      server_name: replay.example
`)
}

// redisSentinelYAML returns one valid plaintext Sentinel document.
func redisSentinelYAML() string {
	return redisDocument(`    mode: sentinel
    sentinel:
      master_name: mymaster
      addresses: "` + testSentinelAddresses + `"
    tls:
      enabled: false
`)
}

// redisClusterYAML returns one valid TLS cluster document using system roots.
func redisClusterYAML() string {
	return redisDocument(`    mode: cluster
    cluster:
      addresses: "10.0.0.1:7000, 10.0.0.2:7000, 10.0.0.3:7000"
`)
}

// redisProtectedYAML returns one Sentinel document that selects every
// protected Redis role: data password, Sentinel password, CA, client
// certificate, and client key.
func redisProtectedYAML() string {
	return redisDocument(`    mode: sentinel
    sentinel:
      master_name: mymaster
      addresses: "` + testSentinelAddresses + `"
      username: sentinel
      password_file: /secure/` + testGeneration + `/sentinel-password
    auth:
      username: application
      password_file: /secure/` + testGeneration + `/redis-password
    tls:
      ca_file: /secure/` + testGeneration + `/ca
      cert: /secure/` + testGeneration + `/client-cert
      key: /secure/` + testGeneration + `/client-key
      server_name: replay.example
`)
}
