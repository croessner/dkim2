// Command qualify owns the closed Postfix-to-Milter-to-daemon qualification runtime.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	dkim2 "github.com/croessner/dkim2"
)

const (
	generationID          = "0123456789abcdef0123456789abcdef"
	daemonUID             = 2000
	milterUID             = 2001
	postfixUID            = 101
	postfixGID            = 103
	postfixConfig         = "/run/postfix-config"
	milterJail            = "/milter-jail"
	originSocket          = "/milter-jail/run/milter/origin/milter.sock"
	inboundSocket         = "/milter-jail/run/milter/inbound/milter.sock"
	daemonEndpoint        = "http://127.0.0.1:8080"
	inboundDaemonEndpoint = "http://127.0.0.1:8081"
	signingDomain         = "origin.example.test"
	authservID            = "mx.receiver.example.test"
)

var errQualification = errors.New("qualification failed")

// main dispatches one fixed qualification operation.
func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "bootstrap":
		err = bootstrapCapabilities()
	case "daemon":
		err = runDaemon()
	case "stack":
		err = runStack()
	case "health-daemon":
		err = checkDaemonHealth()
	case "health-stack":
		err = checkStackHealth()
	case "success":
		err = runSuccessQualification()
	case "stop-origin-milter":
		err = stopOriginMilter()
	case "milter-failure":
		err = runMilterFailureQualification()
	case "daemon-failure":
		err = runDaemonFailureQualification()
	case "identity":
		err = emitIdentity([]string{"dkim2-milter", "qualify"}, true)
	case "daemon-identity":
		err = emitIdentity([]string{"dkim2d"}, false)
	default:
		os.Exit(2)
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "qualification operation failed")
		os.Exit(1)
	}
}

// bootstrapCapabilities publishes fresh operation-separated capability copies.
func bootstrapCapabilities() error {
	root := "/capabilities"
	if err := os.MkdirAll(root, 0o700); err != nil {
		return errQualification
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return errQualification
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			return errQualification
		}
	}
	for _, operation := range []string{"process", "sign", "revise"} {
		value := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, value); err != nil {
			return errQualification
		}
		for _, owner := range []struct {
			name string
			uid  int
		}{
			{name: "daemon", uid: daemonUID},
			{name: "milter", uid: milterUID},
		} {
			directory := filepath.Join(root, owner.name)
			if err := os.MkdirAll(directory, 0o700); err != nil {
				clear(value)
				return errQualification
			}
			path := filepath.Join(directory, operation)
			if err := os.WriteFile(path, value, 0o600); err != nil ||
				os.Chown(path, owner.uid, ownerGroup(owner.uid)) != nil {
				clear(value)
				return errQualification
			}
		}
		clear(value)
	}
	for _, owner := range []struct {
		name string
		uid  int
	}{
		{name: "daemon", uid: daemonUID},
		{name: "milter", uid: milterUID},
	} {
		directory := filepath.Join(root, owner.name)
		if err := os.Chown(directory, owner.uid, ownerGroup(owner.uid)); err != nil ||
			os.Chmod(directory, 0o500) != nil {
			return errQualification
		}
	}
	return nil
}

// ownerGroup selects the fixed process group for one protected capability copy.
func ownerGroup(uid int) int {
	if uid == milterUID {
		return postfixGID
	}
	return daemonUID
}

// runDaemon prepares one tmpfs generation, local DNS authority, and daemon process.
func runDaemon() error {
	if os.Getuid() != 0 {
		return errQualification
	}
	const jail = "/jail"
	if err := os.Chown(jail, 0, 0); err != nil ||
		os.Chmod(jail, 0o755) != nil ||
		os.MkdirAll(filepath.Join(jail, "run"), 0o755) != nil ||
		os.Chmod(filepath.Join(jail, "run"), 0o755) != nil ||
		os.MkdirAll(filepath.Join(jail, "run", "dkim2"), 0o700) != nil ||
		os.Chown(filepath.Join(jail, "run", "dkim2"), daemonUID, daemonUID) != nil ||
		os.MkdirAll(filepath.Join(jail, "usr", "local", "bin"), 0o755) != nil ||
		os.MkdirAll(filepath.Join(jail, "etc"), 0o755) != nil {
		return errQualification
	}
	if err := copyExecutableFile(
		"/usr/local/bin/dkim2d",
		filepath.Join(jail, "usr", "local", "bin", "dkim2d"),
	); err != nil {
		return err
	}
	if err := os.WriteFile(
		filepath.Join(jail, "etc", "resolv.conf"),
		[]byte("nameserver 127.0.0.1\noptions ndots:1 timeout:1 attempts:1\n"),
		0o644,
	); err != nil {
		return errQualification
	}
	generation := filepath.Join(jail, "run", "dkim2", generationID)
	if err := os.MkdirAll(generation, 0o700); err != nil {
		return errQualification
	}
	for _, operation := range []string{"process", "sign", "revise"} {
		source := filepath.Join("/capabilities/daemon", operation)
		name := map[string]string{
			"process": "capability", "sign": "sign-capability", "revise": "revise-capability",
		}[operation]
		if err := copyProtectedFile(source, filepath.Join(generation, name), 0o600); err != nil {
			return err
		}
	}
	txt, err := writeSigningGeneration(generation)
	if err != nil {
		return err
	}
	if err := bindGenerationOwnership(generation); err != nil ||
		os.Chmod(generation, 0o500) != nil {
		return errQualification
	}
	configPath := filepath.Join(jail, "run", "dkim2", "dkim2d.yaml")
	runtimeGeneration := filepath.Join("/run/dkim2", generationID)
	config := fmt.Sprintf(`config:
  version: dkim2d-config-v1
protected:
  generation: %s
server:
  listen: 127.0.0.1:8080
  capability_file: %s/capability
  sign_capability_file: %s/sign-capability
  revise_capability_file: %s/revise-capability
  read_header_timeout: 5s
  read_timeout: 30s
  write_timeout: 65s
  request_deadline: 60s
  max_in_flight: 2
replay:
  backend: disabled
signing:
  backend: flat_file
  datasource_file: %s/datasource
  private_manifest_file: %s/private-manifest
`, generationID,
		runtimeGeneration,
		runtimeGeneration,
		runtimeGeneration,
		runtimeGeneration,
		runtimeGeneration,
	)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		return errQualification
	}
	if err := os.Chown(configPath, daemonUID, daemonUID); err != nil {
		return errQualification
	}
	if err := syscall.Chroot(jail); err != nil || os.Chdir("/") != nil {
		return errQualification
	}
	dns, err := startDNSAuthority("s1._domainkey."+signingDomain+".", txt)
	if err != nil {
		return err
	}
	defer dns.close()
	if err := syscall.Setgroups([]int{}); err != nil ||
		syscall.Setgid(daemonUID) != nil ||
		syscall.Setuid(daemonUID) != nil {
		return errQualification
	}
	proxy, err := startDaemonInputObserver()
	if err != nil {
		return err
	}
	defer proxy.close()
	return runSupervisedCommand(
		exec.Command(
			"/usr/local/bin/dkim2d",
			"serve",
			"--config",
			"/run/dkim2/dkim2d.yaml",
		),
	)
}

type daemonInputObserver struct {
	server   *http.Server
	listener net.Listener
	received atomic.Int64
}

// startDaemonInputObserver starts a content-free observer before the real daemon boundary.
func startDaemonInputObserver() (*daemonInputObserver, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:8081")
	if err != nil {
		return nil, errQualification
	}
	observer := &daemonInputObserver{listener: listener}
	observer.server = &http.Server{
		Handler:           observer,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() { _ = observer.server.Serve(listener) }()
	return observer, nil
}

// ServeHTTP records only the Milter-submitted Received count and forwards exact JSON bytes.
func (d *daemonInputObserver) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet && request.URL.Path == "/qualification/received-count" {
		writer.Header().Set("Content-Type", "text/plain")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = fmt.Fprintf(writer, "%d\n", d.received.Load())
		return
	}
	if request.Method != http.MethodPost || request.URL.Path != "/v1/process" ||
		request.ContentLength < 1 || request.ContentLength > 5<<20 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, (5<<20)+1))
	if err != nil || len(body) == 0 || len(body) > 5<<20 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	var input struct {
		Message struct {
			RawRFC5322Base64 string `json:"raw_rfc5322_base64"`
		} `json:"message"`
	}
	if json.Unmarshal(body, &input) != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(input.Message.RawRFC5322Base64)
	if err != nil || len(raw) > 4<<20 {
		clear(raw)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	d.received.Store(int64(countHeader(raw, "Received")))
	clear(raw)

	forward, err := http.NewRequestWithContext(
		request.Context(),
		http.MethodPost,
		daemonEndpoint+"/v1/process",
		bytes.NewReader(body),
	)
	if err != nil {
		writer.WriteHeader(http.StatusBadGateway)
		return
	}
	for key, values := range request.Header {
		for _, value := range values {
			forward.Header.Add(key, value)
		}
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Do(forward)
	transport.CloseIdleConnections()
	if err != nil {
		writer.WriteHeader(http.StatusBadGateway)
		return
	}
	defer func() { _ = response.Body.Close() }()
	for key, values := range response.Header {
		for _, value := range values {
			writer.Header().Add(key, value)
		}
	}
	writer.WriteHeader(response.StatusCode)
	_, _ = io.Copy(writer, io.LimitReader(response.Body, 1<<20))
}

// close stops the qualification-only daemon input observer.
func (d *daemonInputObserver) close() {
	if d == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = d.server.Shutdown(ctx)
	_ = d.listener.Close()
}

// bindGenerationOwnership transfers only regular direct children to the daemon identity.
func bindGenerationOwnership(generation string) error {
	entries, err := os.ReadDir(generation)
	if err != nil {
		return errQualification
	}
	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil || !info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 {
			return errQualification
		}
		if err := os.Chown(
			filepath.Join(generation, entry.Name()),
			daemonUID,
			daemonUID,
		); err != nil {
			return errQualification
		}
	}
	if err := os.Chown(generation, daemonUID, daemonUID); err != nil {
		return errQualification
	}
	return nil
}

// writeSigningGeneration creates one synthetic RSA profile and private manifest.
func writeSigningGeneration(generation string) (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return "", errQualification
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", errQualification
	}
	datasource := map[string]any{
		"version": "dkim2-datasource-v1",
		"handles": []any{map[string]any{"id": "origin-key"}},
		"profiles": []any{map[string]any{
			"id": "origin-profile", "domain": signingDomain, "status": "active",
			"credentials": []any{map[string]any{
				"algorithm": "rsa-sha256", "selector": "s1",
				"public_key_spki": base64.StdEncoding.EncodeToString(spki),
				"handle_id":       "origin-key",
			}},
		}},
		"policies": []any{map[string]any{
			"tenant_id": "tenant-a", "domain": signingDomain,
			"use": "originator", "profile_id": "origin-profile",
			"status": "active", "rollout": "enforce",
			"compatibility": "strict",
		}},
	}
	digest := sha256.Sum256(spki)
	manifest := map[string]any{
		"version": "dkim2-private-keys-v1",
		"entries": []any{map[string]any{
			"tenant_id": "tenant-a", "domain": signingDomain,
			"use": "originator", "handle_id": "origin-key",
			"algorithm":          "rsa-sha256",
			"public_spki_sha256": base64.StdEncoding.EncodeToString(digest[:]),
			"private_key_file":   "origin.pem",
		}},
	}
	if err := writeProtectedJSON(filepath.Join(generation, "datasource"), datasource); err != nil {
		return "", err
	}
	if err := writeProtectedJSON(filepath.Join(generation, "private-manifest"), manifest); err != nil {
		return "", err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", errQualification
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	clear(pkcs8)
	if err := os.WriteFile(filepath.Join(generation, "origin.pem"), privatePEM, 0o600); err != nil {
		clear(privatePEM)
		return "", errQualification
	}
	clear(privatePEM)
	dnsKey := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(dnsKey), nil
}

// writeProtectedJSON writes one owner-only compact JSON generation child.
func writeProtectedJSON(path string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return errQualification
	}
	defer clear(encoded)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return errQualification
	}
	return nil
}

// copyProtectedFile copies exact bytes without preserving ambient metadata.
func copyProtectedFile(source, target string, mode os.FileMode) error {
	input, err := os.ReadFile(source)
	if err != nil {
		return errQualification
	}
	defer clear(input)
	if len(input) != 32 {
		return errQualification
	}
	if err := os.WriteFile(target, input, mode); err != nil {
		return errQualification
	}
	return nil
}

// copyExecutableFile copies one fixed build artifact into the tmpfs chroot.
func copyExecutableFile(source, target string) error {
	input, err := os.ReadFile(source)
	if err != nil || len(input) == 0 {
		return errQualification
	}
	if err := os.WriteFile(target, input, 0o555); err != nil {
		return errQualification
	}
	return nil
}

type dnsAuthority struct {
	packet net.PacketConn
	done   chan struct{}
}

// startDNSAuthority starts one exact reserved-name TXT authority on loopback.
func startDNSAuthority(owner, txt string) (*dnsAuthority, error) {
	packet, err := net.ListenPacket("udp4", "127.0.0.1:53")
	if err != nil {
		return nil, errQualification
	}
	authority := &dnsAuthority{packet: packet, done: make(chan struct{})}
	go authority.serve(owner, txt)
	return authority, nil
}

// serve answers one closed TXT owner and NXDOMAINs every other question.
func (d *dnsAuthority) serve(owner, txt string) {
	defer close(d.done)
	buffer := make([]byte, 512)
	for {
		count, address, err := d.packet.ReadFrom(buffer)
		if err != nil {
			return
		}
		response := buildDNSResponse(buffer[:count], owner, txt)
		if len(response) > 0 {
			_, _ = d.packet.WriteTo(response, address)
		}
	}
}

// close stops the fixture DNS authority.
func (d *dnsAuthority) close() {
	if d == nil {
		return
	}
	_ = d.packet.Close()
	<-d.done
}

// buildDNSResponse constructs one bounded DNS TXT response without shared parser code.
func buildDNSResponse(query []byte, owner, txt string) []byte {
	if len(query) < 17 {
		return nil
	}
	offset := 12
	var labels []string
	for {
		if offset >= len(query) {
			return nil
		}
		length := int(query[offset])
		offset++
		if length == 0 {
			break
		}
		if length > 63 || offset+length > len(query) {
			return nil
		}
		labels = append(labels, string(query[offset:offset+length]))
		offset += length
	}
	if offset+4 > len(query) {
		return nil
	}
	questionEnd := offset + 4
	name := strings.ToLower(strings.Join(labels, ".")) + "."
	qtype := binary.BigEndian.Uint16(query[offset : offset+2])
	found := name == strings.ToLower(owner) && qtype == 16
	response := make([]byte, 12, 512)
	copy(response[:2], query[:2])
	flags := uint16(0x8180)
	answerCount := uint16(0)
	if !found {
		flags = 0x8183
	} else {
		answerCount = 1
	}
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], answerCount)
	response = append(response, query[12:questionEnd]...)
	if !found {
		return response
	}
	rdata := encodeDNSTXT(txt)
	response = append(response, 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01)
	response = append(response, 0x00, 0x00, 0x00, 0x3c)
	response = binary.BigEndian.AppendUint16(response, uint16(len(rdata)))
	response = append(response, rdata...)
	return response
}

// encodeDNSTXT splits one TXT value into legal 255-byte character strings.
func encodeDNSTXT(value string) []byte {
	input := []byte(value)
	var output []byte
	for len(input) > 0 {
		count := min(len(input), 255)
		output = append(output, byte(count))
		output = append(output, input[:count]...)
		input = input[count:]
	}
	return output
}

// runStack starts two unprivileged adapters and one alternate-config Postfix instance.
func runStack() error {
	if os.Getuid() != 0 {
		return errQualification
	}
	if err := prepareMilterJail(); err != nil {
		return err
	}
	origin, err := startMilter("origin", "sign", "originator", daemonEndpoint, false)
	if err != nil {
		return err
	}
	defer stopCommand(origin)
	inbound, err := startMilter("inbound", "process", "inbound", inboundDaemonEndpoint, true)
	if err != nil {
		return err
	}
	defer stopCommand(inbound)
	if err := preparePostfix(); err != nil {
		return err
	}
	if err := runCommand("/usr/sbin/postfix", "-c", postfixConfig, "start"); err != nil {
		return err
	}
	defer func() { _ = runCommand("/usr/sbin/postfix", "-c", postfixConfig, "stop") }()
	return waitForTermination()
}

// prepareMilterJail creates one project-scoped local-filesystem root for both adapters.
func prepareMilterJail() error {
	if err := os.Chown(milterJail, 0, 0); err != nil ||
		os.Chmod(milterJail, 0o755) != nil ||
		os.MkdirAll(filepath.Join(milterJail, "usr", "local", "bin"), 0o755) != nil ||
		os.MkdirAll(filepath.Join(milterJail, "run", "milter"), 0o755) != nil {
		return errQualification
	}
	return copyExecutableFile(
		"/usr/local/bin/dkim2-milter",
		filepath.Join(milterJail, "usr", "local", "bin", "dkim2-milter"),
	)
}

// startMilter prepares one route-specific config and starts it as the adapter identity.
func startMilter(
	name, capability, mode, endpoint string,
	authenticationResults bool,
) (*exec.Cmd, error) {
	runtimeRoot := filepath.Join("/run/milter", name)
	root := filepath.Join(milterJail, runtimeRoot)
	protected := filepath.Join(root, "protected")
	if err := os.MkdirAll(protected, 0o700); err != nil {
		return nil, errQualification
	}
	if err := os.Chown(root, milterUID, postfixGID); err != nil ||
		os.Chmod(root, 0o750) != nil ||
		os.Chown(protected, milterUID, postfixGID) != nil {
		return nil, errQualification
	}
	capabilityPath := filepath.Join(protected, "capability")
	if err := copyProtectedFile(
		filepath.Join("/capabilities/milter", capability),
		capabilityPath,
		0o600,
	); err != nil {
		return nil, err
	}
	if err := os.Chown(capabilityPath, milterUID, postfixGID); err != nil ||
		os.Chmod(protected, 0o500) != nil {
		return nil, errQualification
	}
	signing := ""
	if mode != "inbound" {
		signing = "\nsigning:\n  tenant: tenant-a\n  domain: " + signingDomain
	}
	reporting := ""
	if authenticationResults {
		reporting = "\nauthentication_results:\n  enabled: true\n  authserv_id: " + authservID
	}
	config := fmt.Sprintf(`version: dkim2-milter-config-v1
server:
  socket: %s
  socket_mode: "0660"
  shutdown_timeout: 5s
  max_connections: 32
  max_in_flight_messages: 16
  max_buffered_bytes: 67108864
daemon:
  endpoint: %s
  capability_file: %s
  request_timeout: 5s
mode: %s%s%s
failure:
  mode: tempfail
limits:
  message_bytes: 4194304
  header_bytes: 262144
  header_count: 500
  header_field_bytes: 32768
  recipient_count: 100
observability:
  logging:
    level: info
`, filepath.Join(runtimeRoot, "milter.sock"), endpoint,
		filepath.Join(runtimeRoot, "protected", "capability"),
		mode, signing, reporting)
	configPath := filepath.Join(root, "milter.yaml")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil ||
		os.Chown(configPath, milterUID, postfixGID) != nil {
		return nil, errQualification
	}
	command := exec.Command(
		"/usr/local/bin/dkim2-milter",
		"serve",
		"--config",
		filepath.Join(runtimeRoot, "milter.yaml"),
	)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{
		Chroot:     milterJail,
		Credential: &syscall.Credential{Uid: milterUID, Gid: postfixGID},
	}
	if err := command.Start(); err != nil {
		return nil, errQualification
	}
	if err := os.WriteFile(
		filepath.Join(root, "pid"),
		[]byte(strconv.Itoa(command.Process.Pid)),
		0o600,
	); err != nil {
		stopCommand(command)
		return nil, errQualification
	}
	if err := waitForUnixSocket(filepath.Join(root, "milter.sock"), 20*time.Second); err != nil {
		stopCommand(command)
		return nil, err
	}
	return command, nil
}

// preparePostfix copies pinned defaults into tmpfs and applies closed overrides.
func preparePostfix() error {
	if err := copyDirectory("/etc/postfix", postfixConfig); err != nil {
		return err
	}
	queue := "/run/postfix-queue"
	data := "/run/postfix-data"
	if err := os.MkdirAll(queue, 0o755); err != nil ||
		os.MkdirAll(data, 0o755) != nil ||
		os.Chown(data, postfixUID, postfixGID) != nil {
		return errQualification
	}
	settings := []string{
		"compatibility_level=3.11",
		"config_directory=" + postfixConfig,
		"queue_directory=" + queue,
		"data_directory=" + data,
		"inet_interfaces=loopback-only",
		"inet_protocols=ipv4",
		"myhostname=postfix.example.test",
		"myorigin=" + signingDomain,
		"mydestination=",
		"mynetworks=127.0.0.0/8",
		"relay_domains=receiver.example.test",
		"smtpd_relay_restrictions=permit_mynetworks,reject_unauth_destination",
		"smtpd_recipient_restrictions=permit_mynetworks,reject_unauth_destination",
		"smtpd_milters=unix:" + originSocket,
		"non_smtpd_milters=unix:" + originSocket,
		"milter_protocol=6",
		"milter_default_action=tempfail",
		"milter_connect_timeout=2s",
		"milter_command_timeout=5s",
		"milter_content_timeout=5s",
		"default_transport=smtp",
		"relay_transport=smtp",
		"relayhost=[127.0.0.1]:2999",
		"defer_transports=smtp",
		"enable_long_queue_ids=yes",
		"smtputf8_enable=yes",
		"local_header_rewrite_clients=",
		"maillog_file=/dev/stdout",
	}
	arguments := []string{"-c", postfixConfig, "-e"}
	arguments = append(arguments, settings...)
	if err := runCommand("/usr/sbin/postconf", arguments...); err != nil {
		return err
	}
	masterPath := filepath.Join(postfixConfig, "master.cf")
	master, err := os.OpenFile(masterPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return errQualification
	}
	_, writeErr := fmt.Fprintf(master, `
2525 inet n - n - - smtpd
  -o smtpd_milters=unix:%s
  -o milter_protocol=6
  -o milter_default_action=tempfail
  -o milter_connect_timeout=2s
  -o milter_command_timeout=5s
  -o milter_content_timeout=5s
2526 inet n - n - - smtpd
  -o smtpd_milters=unix:%s
  -o milter_protocol=6
  -o milter_default_action=tempfail
  -o milter_connect_timeout=2s
  -o milter_command_timeout=5s
  -o milter_content_timeout=5s
`, originSocket, inboundSocket)
	closeErr := master.Close()
	if writeErr != nil || closeErr != nil {
		return errQualification
	}
	if err := runCommand("/usr/sbin/postfix", "-c", postfixConfig, "check"); err != nil {
		return err
	}
	return nil
}

// copyDirectory copies one fixed configuration tree without following symlinks.
func copyDirectory(source, target string) error {
	if err := os.MkdirAll(target, 0o755); err != nil {
		return errQualification
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return errQualification
	}
	for _, entry := range entries {
		sourcePath := filepath.Join(source, entry.Name())
		targetPath := filepath.Join(target, entry.Name())
		info, infoErr := entry.Info()
		if infoErr != nil || info.Mode()&os.ModeSymlink != 0 {
			return errQualification
		}
		if entry.IsDir() {
			if err := copyDirectory(sourcePath, targetPath); err != nil {
				return err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return errQualification
		}
		input, readErr := os.ReadFile(sourcePath)
		if readErr != nil || os.WriteFile(targetPath, input, info.Mode().Perm()) != nil {
			return errQualification
		}
	}
	return nil
}

// runSuccessQualification proves topology, SMTP/local signing, and inbound verification.
func runSuccessQualification() error {
	if err := checkStackHealth(); err != nil || checkDaemonHealth() != nil {
		return errQualification
	}
	if err := verifyTopology(); err != nil {
		return err
	}
	sender := "<sender@" + signingDomain + ">"
	recipient := "<recipient@receiver.example.test>"
	originMessage := []byte(
		"From: sender@" + signingDomain + "\r\n" +
			"To: recipient@receiver.example.test\r\n" +
			"Subject: smtp origin\r\n" +
			"X-Duplicate: one\r\n" +
			"X-Duplicate: two\r\n\r\n" +
			"binary\xffbody\r\n",
	)
	originID, err := smtpSubmit(2525, sender, []string{recipient}, originMessage, true)
	if err != nil {
		return err
	}
	originRaw, err := queuedMessage(originID)
	if err != nil || validateSignedMessage(originRaw, sender, []string{recipient}) != nil {
		return errQualification
	}
	before, err := queueIDs()
	if err != nil {
		return err
	}
	localMessage := []byte(
		"From: sender@" + signingDomain + "\n" +
			"To: recipient@receiver.example.test\n" +
			"Subject: local origin\n" +
			"X-Local-Submission: yes\n\n",
	)
	if err := submitLocalMessage(localMessage); err != nil {
		return errQualification
	}
	localRaw, err := waitForNewQueuedMessage(before, 10*time.Second)
	if err != nil {
		return errQualification
	}
	if validateSignedMessage(localRaw, sender, []string{recipient}) != nil {
		return errQualification
	}
	receivedBefore := countHeader(originRaw, "Received")
	inboundID, err := smtpSubmit(2526, sender, []string{recipient}, originRaw, true)
	if err != nil {
		return err
	}
	inboundRaw, err := queuedMessage(inboundID)
	observedReceived, observedErr := observedDaemonReceivedCount()
	if err != nil || observedErr != nil ||
		observedReceived != receivedBefore ||
		countHeader(inboundRaw, "Received") != receivedBefore+1 ||
		countHeader(inboundRaw, "Authentication-Results") != 1 ||
		!headerHasExactValue(
			inboundRaw,
			"Authentication-Results",
			authservID+"; dkim2=pass",
		) {
		return errQualification
	}
	return emitCaseFragment([]string{
		"daemon_loopback_topology",
		"inbound_cryptographic_pass",
		"local_sendmail_signing",
		"postfix_received_visibility",
		"smtp_origin_signing",
	})
}

// observedDaemonReceivedCount reads only the content-free qualification observation.
func observedDaemonReceivedCount() (int, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get(inboundDaemonEndpoint + "/qualification/received-count")
	if err != nil {
		return 0, errQualification
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return 0, errQualification
	}
	input, err := io.ReadAll(io.LimitReader(response.Body, 32))
	if err != nil || len(input) == 0 || len(input) >= 32 {
		return 0, errQualification
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(input)))
	if err != nil || value < 0 {
		return 0, errQualification
	}
	return value, nil
}

// submitLocalMessage runs the synthetic non-SMTP intake path within a fixed
// bound so a mutable Postfix process timeout cannot stall qualification.
func submitLocalMessage(message []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		"/usr/sbin/sendmail", "-C", postfixConfig, "-i",
		"-f", "sender@"+signingDomain, "recipient@receiver.example.test",
	)
	command.Stdin = bytes.NewReader(message)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil || ctx.Err() != nil {
		return errQualification
	}
	return nil
}

// validateSignedMessage checks exact field order and independently invokes the public verifier.
func validateSignedMessage(raw []byte, sender string, recipients []string) error {
	headers, err := parseHeaderFields(raw)
	if err != nil {
		return err
	}
	messageIndex := -1
	signatureIndex := -1
	for index, header := range headers {
		switch strings.ToLower(header.name) {
		case "message-instance":
			if messageIndex >= 0 {
				return errQualification
			}
			messageIndex = index
		case "dkim2-signature":
			if signatureIndex >= 0 {
				return errQualification
			}
			signatureIndex = index
		}
	}
	if messageIndex < 0 || signatureIndex != messageIndex+1 {
		return errQualification
	}
	transport, err := dkim2.NewNetTXTTransport(net.DefaultResolver)
	if err != nil {
		return errQualification
	}
	provider, err := dkim2.NewDNSPublicKeyProvider(transport)
	if err != nil {
		return errQualification
	}
	verifier, err := dkim2.NewVerifier(provider)
	if err != nil {
		return errQualification
	}
	forward := make([][]byte, len(recipients))
	for index := range recipients {
		forward[index] = []byte(recipients[index])
	}
	result, err := verifier.Verify(
		context.Background(),
		dkim2.NewVerifyRequest(raw, []byte(sender), forward),
	)
	if err != nil || !result.Valid() || result.State() != dkim2.ResultStatePASS {
		return errQualification
	}
	return nil
}

type parsedHeader struct {
	name  string
	value string
}

// parseHeaderFields independently validates a CRLF header block and folding.
func parseHeaderFields(raw []byte) ([]parsedHeader, error) {
	separator := bytes.Index(raw, []byte("\r\n\r\n"))
	if separator < 0 {
		return nil, errQualification
	}
	lines := bytes.Split(raw[:separator], []byte("\r\n"))
	headers := make([]parsedHeader, 0, len(lines))
	for _, line := range lines {
		if len(line) == 0 {
			return nil, errQualification
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(headers) == 0 {
				return nil, errQualification
			}
			headers[len(headers)-1].value += "\r\n" + string(line)
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 1 {
			return nil, errQualification
		}
		headers = append(headers, parsedHeader{
			name: string(line[:colon]), value: strings.TrimSpace(string(line[colon+1:])),
		})
	}
	return headers, nil
}

// countHeader counts one case-insensitive field name through the independent parser.
func countHeader(raw []byte, name string) int {
	headers, err := parseHeaderFields(raw)
	if err != nil {
		return -1
	}
	count := 0
	for _, header := range headers {
		if strings.EqualFold(header.name, name) {
			count++
		}
	}
	return count
}

// headerHasExactValue checks one unfolded field value without substring matching.
func headerHasExactValue(raw []byte, name, value string) bool {
	headers, err := parseHeaderFields(raw)
	if err != nil {
		return false
	}
	for _, header := range headers {
		if strings.EqualFold(header.name, name) && header.value == value {
			return true
		}
	}
	return false
}

// smtpSubmit drives one explicit SMTP transaction and returns its queue identity.
func smtpSubmit(
	port int,
	sender string,
	recipients []string,
	message []byte,
	wantAccept bool,
) (string, error) {
	connection, err := net.DialTimeout(
		"tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 5*time.Second,
	)
	if err != nil {
		return "", errQualification
	}
	defer func() { _ = connection.Close() }()
	if err := connection.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return "", errQualification
	}
	text := textproto.NewConn(connection)
	defer func() { _ = text.Close() }()
	if _, _, err := text.ReadResponse(220); err != nil {
		return "", errQualification
	}
	if err := text.PrintfLine("EHLO driver.example.test"); err != nil {
		return "", errQualification
	}
	if _, _, err := text.ReadResponse(250); err != nil {
		return "", errQualification
	}
	mailFrom := "MAIL FROM:" + sender
	if bytes.IndexFunc(message, func(value rune) bool { return value >= 0x80 }) >= 0 {
		mailFrom += " BODY=8BITMIME"
	}
	if err := text.PrintfLine("%s", mailFrom); err != nil {
		return "", errQualification
	}
	tempfailed, err := readSMTPResponse(text, 250, !wantAccept)
	if err != nil {
		return "", errQualification
	}
	if tempfailed {
		return "", nil
	}
	for _, recipient := range recipients {
		if err := text.PrintfLine("RCPT TO:%s", recipient); err != nil {
			return "", errQualification
		}
		tempfailed, err = readSMTPResponse(text, 250, !wantAccept)
		if err != nil {
			return "", errQualification
		}
		if tempfailed {
			return "", nil
		}
	}
	if err := text.PrintfLine("DATA"); err != nil {
		return "", errQualification
	}
	tempfailed, err = readSMTPResponse(text, 354, !wantAccept)
	if err != nil {
		return "", errQualification
	}
	if tempfailed {
		return "", nil
	}
	writer := text.DotWriter()
	if _, err := writer.Write(message); err != nil || writer.Close() != nil {
		return "", errQualification
	}
	code, line, responseErr := text.ReadResponse(250)
	_ = text.PrintfLine("QUIT")
	if !wantAccept {
		if responseErr == nil || code != 451 {
			return "", errQualification
		}
		return "", nil
	}
	if responseErr != nil || code != 250 {
		return "", errQualification
	}
	const marker = "queued as "
	index := strings.LastIndex(line, marker)
	if index < 0 {
		return "", errQualification
	}
	queueID := strings.TrimSpace(line[index+len(marker):])
	if !validQueueID(queueID) {
		return "", errQualification
	}
	return queueID, nil
}

// readSMTPResponse accepts only the expected response or the fixed 451
// temporary failure required for a negative qualification transaction.
func readSMTPResponse(
	connection *textproto.Conn,
	expected int,
	allowTempfail bool,
) (bool, error) {
	code, _, err := connection.ReadResponse(expected)
	if err == nil {
		return false, nil
	}
	if allowTempfail && code == 451 {
		return true, nil
	}
	return false, errQualification
}

// validQueueID validates a content-free Postfix long queue identifier.
func validQueueID(value string) bool {
	if len(value) < 10 || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if character >= '0' && character <= '9' ||
			character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' {
			continue
		}
		return false
	}
	return true
}

// queueInventory returns the current project queue identities and queue names.
func queueInventory() (map[string]string, error) {
	command := exec.Command("/usr/sbin/postqueue", "-c", postfixConfig, "-j")
	output, err := command.Output()
	if err != nil {
		return nil, errQualification
	}
	inventory := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		var record struct {
			QueueID   string `json:"queue_id"`
			QueueName string `json:"queue_name"`
		}
		if json.Unmarshal(scanner.Bytes(), &record) != nil ||
			!validQueueID(record.QueueID) ||
			record.QueueName == "" {
			return nil, errQualification
		}
		inventory[record.QueueID] = record.QueueName
	}
	if scanner.Err() != nil {
		return nil, errQualification
	}
	return inventory, nil
}

// queueIDs returns the current project queue identity set.
func queueIDs() (map[string]struct{}, error) {
	inventory, err := queueInventory()
	if err != nil {
		return nil, err
	}
	ids := make(map[string]struct{}, len(inventory))
	for id := range inventory {
		ids[id] = struct{}{}
	}
	return ids, nil
}

// sameQueueIDs proves that a rejected transaction did not replace or add a
// queued message while preserving the same queue length.
func sameQueueIDs(before, after map[string]struct{}) bool {
	if len(before) != len(after) {
		return false
	}
	for id := range before {
		if _, present := after[id]; !present {
			return false
		}
	}
	return true
}

// waitForNewQueuedMessage waits until exactly one new local-submission queue
// identity is both visible and readable across Postfix queue-directory moves.
func waitForNewQueuedMessage(before map[string]struct{}, timeout time.Duration) ([]byte, error) {
	return waitForNewQueuedMessageInQueue(before, "", timeout)
}

// waitForNewQueuedMessageInQueue waits for exactly one readable new message
// and, when requested, requires its exact Postfix queue state.
func waitForNewQueuedMessageInQueue(
	before map[string]struct{},
	queueName string,
	timeout time.Duration,
) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		after, err := queueInventory()
		if err != nil {
			return nil, err
		}
		var added []string
		for id := range after {
			if _, existed := before[id]; !existed {
				added = append(added, id)
			}
		}
		if len(added) == 1 && (queueName == "" || after[added[0]] == queueName) {
			if raw, readErr := readQueuedMessage(added[0]); readErr == nil {
				return raw, nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, errQualification
}

// queuedMessage reads one captured queue message and restores canonical CRLF.
func queuedMessage(queueID string) ([]byte, error) {
	if !validQueueID(queueID) {
		return nil, errQualification
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if output, err := readQueuedMessage(queueID); err == nil {
			return output, nil
		}
		if time.Now().After(deadline) {
			return nil, errQualification
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// readQueuedMessage performs one atomic Postfix queue read and canonicalizes
// only a complete LF-formatted synthetic capture.
func readQueuedMessage(queueID string) ([]byte, error) {
	if !validQueueID(queueID) {
		return nil, errQualification
	}
	command := exec.Command(
		"/usr/sbin/postcat", "-c", postfixConfig, "-qbh", queueID,
	)
	output, err := command.Output()
	if err != nil || len(output) == 0 || bytes.Contains(output, []byte{'\r'}) {
		return nil, errQualification
	}
	output = bytes.ReplaceAll(output, []byte{'\n'}, []byte("\r\n"))
	if !bytes.HasSuffix(output, []byte("\r\n")) {
		output = append(output, '\r', '\n')
	}
	return output, nil
}

// runMilterFailureQualification proves SMTP 451 and an asynchronous maildrop
// hold for non-SMTP submission when the configured Milter is unavailable.
func runMilterFailureQualification() error {
	before, err := queueIDs()
	if err != nil {
		return err
	}
	message := []byte(
		"From: sender@" + signingDomain + "\r\n" +
			"To: recipient@receiver.example.test\r\n" +
			"Subject: unavailable milter\r\n\r\nbody\r\n",
	)
	if _, err := smtpSubmit(
		2525,
		"<sender@"+signingDomain+">",
		[]string{"<recipient@receiver.example.test>"},
		message,
		false,
	); err != nil {
		return err
	}
	afterSMTP, err := queueIDs()
	if err != nil || !sameQueueIDs(before, afterSMTP) {
		return errQualification
	}
	if submitLocalMessage(bytes.ReplaceAll(message, []byte("\r\n"), []byte("\n"))) != nil {
		return errQualification
	}
	localRaw, err := waitForNewQueuedMessageInQueue(before, "maildrop", 5*time.Second)
	if err != nil ||
		countHeader(localRaw, "DKIM2-Signature") != 0 ||
		!headerHasExactValue(localRaw, "Subject", "unavailable milter") {
		return errQualification
	}
	return emitCaseFragment([]string{
		"non_smtp_milter_unavailable_tempfail",
		"smtp_milter_unavailable_tempfail",
	})
}

// runDaemonFailureQualification proves the adapter's fixed 451 and no queue mutation.
func runDaemonFailureQualification() error {
	before, err := queueIDs()
	if err != nil {
		return err
	}
	message := []byte(
		"From: sender@" + signingDomain + "\r\n" +
			"To: recipient@receiver.example.test\r\n" +
			"Subject: unavailable daemon\r\n\r\nbody\r\n",
	)
	if _, err := smtpSubmit(
		2525,
		"<sender@"+signingDomain+">",
		[]string{"<recipient@receiver.example.test>"},
		message,
		false,
	); err != nil {
		return err
	}
	after, err := queueIDs()
	if err != nil || !sameQueueIDs(before, after) {
		return errQualification
	}
	return emitCaseFragment([]string{"daemon_unavailable_fixed_tempfail"})
}

// stopOriginMilter terminates only the owned originator adapter.
func stopOriginMilter() error {
	input, err := os.ReadFile(filepath.Join(milterJail, "run", "milter", "origin", "pid"))
	if err != nil {
		return errQualification
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(input)))
	if err != nil || pid < 2 {
		return errQualification
	}
	process, err := os.FindProcess(pid)
	if err != nil || process.Signal(syscall.SIGTERM) != nil {
		return errQualification
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(originSocket); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errQualification
}

// verifyTopology proves effective loopback, Unix-socket, and Postfix policy facts.
func verifyTopology() error {
	values := map[string]string{
		"milter_protocol":        "6",
		"milter_default_action":  "tempfail",
		"milter_connect_timeout": "2s",
		"milter_command_timeout": "5s",
		"milter_content_timeout": "5s",
		"smtpd_milters":          "unix:" + originSocket,
		"non_smtpd_milters":      "unix:" + originSocket,
	}
	for name, want := range values {
		command := exec.Command("/usr/sbin/postconf", "-c", postfixConfig, "-h", name)
		output, err := command.Output()
		if err != nil || strings.TrimSpace(string(output)) != want {
			return errQualification
		}
	}
	for _, socket := range []string{originSocket, inboundSocket} {
		state, err := os.Lstat(socket)
		if err != nil || state.Mode()&os.ModeSocket == 0 || state.Mode().Perm() != 0o660 {
			return errQualification
		}
	}
	input, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return errQualification
	}
	dockerDNSListeners := 0
	scanner := bufio.NewScanner(bytes.NewReader(input))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[3] != "0A" || fields[1] == "local_address" {
			continue
		}
		address, port, ok := strings.Cut(fields[1], ":")
		if !ok {
			return errQualification
		}
		switch port {
		case "0019", "09DD", "09DE", "1F90", "1F91":
			if address != "0100007F" {
				return errQualification
			}
		default:
			if address != "0B00007F" {
				return errQualification
			}
			dockerDNSListeners++
		}
	}
	if scanner.Err() != nil || dockerDNSListeners != 1 {
		return errQualification
	}
	ipv6, err := os.ReadFile("/proc/net/tcp6")
	if err != nil || hasListeningSocket(ipv6) {
		return errQualification
	}
	return nil
}

// hasListeningSocket reports whether one Linux procfs TCP table has a listener.
func hasListeningSocket(input []byte) bool {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[1] != "local_address" && fields[3] == "0A" {
			return true
		}
	}
	return scanner.Err() != nil
}

// checkDaemonHealth requires the real readiness boundary.
func checkDaemonHealth() error {
	connection, err := net.DialTimeout("tcp4", "127.0.0.1:8080", time.Second)
	if err != nil {
		return errQualification
	}
	defer func() { _ = connection.Close() }()
	request := "GET /readyz HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(connection, request); err != nil {
		return errQualification
	}
	reader := bufio.NewReader(io.LimitReader(connection, 4096))
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP/1.1 200 ") {
		return errQualification
	}
	return nil
}

// checkStackHealth requires both sockets and the running Postfix master.
func checkStackHealth() error {
	for _, path := range []string{originSocket, inboundSocket} {
		state, err := os.Lstat(path)
		if err != nil || state.Mode()&os.ModeSocket == 0 {
			return errQualification
		}
	}
	return runCommand("/usr/sbin/postfix", "-c", postfixConfig, "status")
}

// emitCaseFragment renders sorted content-free successful case identities.
func emitCaseFragment(cases []string) error {
	slices.Sort(cases)
	encoded, err := json.Marshal(struct {
		Schema string   `json:"schema"`
		State  string   `json:"state"`
		Cases  []string `json:"cases"`
	}{
		Schema: "dkim2.postfix-qualification-fragment.v1",
		State:  "pass",
		Cases:  cases,
	})
	if err != nil {
		return errQualification
	}
	_, err = os.Stdout.Write(append(encoded, '\n'))
	return err
}

// emitIdentity renders exact immutable build identities and optional Postfix version.
func emitIdentity(executableNames []string, includePostfix bool) error {
	postfixVersion := ""
	if includePostfix {
		postfix, err := exec.Command("/usr/sbin/postconf", "-h", "mail_version").Output()
		if err != nil {
			return errQualification
		}
		postfixVersion = strings.TrimSpace(string(postfix))
	}
	executables := map[string]string{}
	for _, name := range executableNames {
		path := filepath.Join("/usr/local/bin", name)
		input, readErr := os.ReadFile(path)
		if readErr != nil {
			return errQualification
		}
		digest := sha256.Sum256(input)
		executables[name] = fmt.Sprintf("%x", digest)
	}
	encoded, err := json.Marshal(struct {
		Schema      string            `json:"schema"`
		Postfix     string            `json:"postfix_version,omitempty"`
		Executables map[string]string `json:"executables"`
	}{
		Schema:      "dkim2.postfix-qualification-identity.v1",
		Postfix:     postfixVersion,
		Executables: executables,
	})
	if err != nil {
		return errQualification
	}
	_, err = os.Stdout.Write(append(encoded, '\n'))
	return err
}

// runCommand executes one fixed local command without exposing its diagnostics.
func runCommand(name string, arguments ...string) error {
	command := exec.Command(name, arguments...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return errQualification
	}
	return nil
}

// runSupervisedCommand forwards termination to one long-running child.
func runSupervisedCommand(command *exec.Cmd) error {
	// Avoid os/exec opening /dev/null after the qualification wrapper has
	// entered its deliberately minimal chroot, where no device nodes exist.
	command.Stdin = bytes.NewReader(nil)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		return errQualification
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return errQualification
		}
		return nil
	case <-signals:
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-done:
			if err != nil {
				return errQualification
			}
			return nil
		case <-time.After(10 * time.Second):
			_ = command.Process.Kill()
			return errQualification
		}
	}
}

// waitForTermination blocks the stack supervisor until one termination signal.
func waitForTermination() error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	<-signals
	return nil
}

// waitForUnixSocket waits for one owned public socket to become ready.
func waitForUnixSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state, err := os.Lstat(path)
		if err == nil && state.Mode()&os.ModeSocket != 0 {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errQualification
}

// stopCommand requests bounded termination of one owned child process.
func stopCommand(command *exec.Cmd) {
	if command == nil || command.Process == nil {
		return
	}
	_ = command.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_ = command.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = command.Process.Kill()
		<-done
	}
}
