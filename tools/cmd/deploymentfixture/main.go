// Command deploymentfixture owns the isolated Postfix deployment test fixture.
//
//nolint:goconst // Repeated deployment vocabulary remains explicit at each generated boundary.
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
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	dkim2 "github.com/croessner/dkim2"
	"github.com/croessner/dkim2/tools/internal/artifactpath"
)

const (
	generationID         = "0123456789abcdef0123456789abcdef"
	rotationGenerationID = "fedcba9876543210fedcba9876543210"
	daemonUID            = 2000
	daemonGID            = 2000
	postfixGID           = 103
	originDomain         = "origin.privacy-7f3c9a2d.runtime.example.test"
	transitDomain        = originDomain
	senderDomain         = "sender.privacy-7f3c9a2d.runtime.example.test"
	recipient            = "privacy-recipient-7f3c@" + originDomain
	privacyTenant        = "privacy-tenant-7f3c9a2d"
	privacyMessage       = "privacy-message-7f3c9a2d"
	originSelector       = "s1"
	transitSelector      = "t1"
)

var errFixture = errors.New("deployment_fixture")

type smtpReply struct {
	code     int
	terminal string
}

type publicKeyRecord struct {
	Domain     string `json:"domain"`
	Selector   string `json:"selector"`
	SPKIBase64 string `json:"spki_base64"`
	TXT        string `json:"txt"`
}

type publicKeySet struct {
	Version string            `json:"version"`
	Keys    []publicKeyRecord `json:"keys"`
}

type signingMaterial struct {
	domain       string
	selector     string
	handle       string
	profile      string
	use          string
	privatePEM   []byte
	spki         []byte
	spkiDigest   []byte
	dnsPublicDER []byte
}

type staticProvider struct {
	keys map[string]*rsa.PublicKey
}

type unavailableSigningAuthorizer struct{}

// Authorize is an unreachable callback for revision-verification-only fixtures.
func (unavailableSigningAuthorizer) Authorize(
	context.Context,
	dkim2.SigningAuthorizationQuery,
) (dkim2.SigningAuthorizationResult, error) {
	return dkim2.SigningAuthorizationResult{}, errFixture
}

type unavailablePrivateKeySigner struct{}

// SignDigest is an unreachable callback for revision-verification-only fixtures.
func (unavailablePrivateKeySigner) SignDigest(
	context.Context,
	dkim2.PrivateKeyHandle,
	dkim2.PrivateKeySignRequest,
) (dkim2.PrivateKeySignResult, error) {
	return dkim2.PrivateKeySignResult{}, errFixture
}

// main dispatches one fixed test-only operation.
func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "bootstrap":
		err = bootstrap()
	case "activate-rotation":
		err = selectGeneration(rotationGenerationID)
	case "rollback-rotation":
		err = selectGeneration(generationID)
	case "dns":
		err = serveDNS()
	case "dns-probe":
		err = probeDNS()
	case "verify-originator":
		err = verifyMessage(false)
	case "verify-transit":
		err = verifyMessage(true)
	case "verify-inbound":
		err = verifyInboundMessage()
	case "smtp-inbound":
		err = runSMTPProbe(25, false, 250)
	case "smtp-inbound-file":
		err = runSMTPProbe(25, true, 250)
	case "smtp-transit":
		err = runSMTPProbe(2526, true, 250)
	case "smtp-tempfail":
		err = runSMTPTempfail()
	case "smtp-overload":
		err = runSMTPOverload()
	case "local-submit":
		err = runLocalSubmission()
	default:
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "deployment fixture operation failed: %s\n", os.Args[1])
		os.Exit(1)
	}
}

// runLocalSubmission invokes the real Postfix non-SMTP path with fixed test data.
func runLocalSubmission() error {
	message := []byte(
		"From: sender@" + originDomain + "\n" +
			"To: " + recipient + "\n" +
			"Subject: " + privacyMessage + " local submission\n\n" +
			privacyMessage + " body\n",
	)
	command := exec.Command(
		"/usr/sbin/sendmail",
		"-f", "sender@"+originDomain,
		recipient,
	)
	command.Stdin = bytes.NewReader(message)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return errFixture
	}
	fmt.Println("local submission queue acceptance passed")
	return nil
}

// verifyInboundMessage verifies retained cryptography and one bounded report field.
func verifyInboundMessage() error {
	if err := verifyMessage(true); err != nil {
		return err
	}
	message, err := artifactpath.ReadFile("/verify", "message.eml", 4<<20)
	if err != nil || countHeader(message, "Authentication-Results") != 1 {
		return errFixture
	}
	clear(message)
	fmt.Println("inbound action verification passed")
	return nil
}

// countHeader counts one exact case-insensitive RFC 5322 field before the body.
func countHeader(message []byte, name string) int {
	normalized := bytes.ReplaceAll(message, []byte("\r\n"), []byte("\n"))
	headerEnd := bytes.Index(normalized, []byte("\n\n"))
	if headerEnd < 0 {
		return 0
	}
	count := 0
	prefix := strings.ToLower(name) + ":"
	for _, line := range bytes.Split(normalized[:headerEnd], []byte("\n")) {
		if strings.HasPrefix(strings.ToLower(string(line)), prefix) {
			count++
		}
	}
	return count
}

// runSMTPProbe submits one exact message and requires the selected terminal status.
func runSMTPProbe(port int, fromFile bool, expected int) error {
	message := []byte(
		"From: privacy-envelope-7f3c@" + senderDomain + "\r\n" +
			"To: " + recipient + "\r\n" +
			"Subject: " + privacyMessage + " deployment probe\r\n\r\n" +
			privacyMessage + " body\r\n",
	)
	if fromFile {
		var err error
		message, err = artifactpath.ReadFile("/verify", "message.eml", 4<<20)
		if err != nil || len(message) == 0 {
			return errFixture
		}
	}
	defer clear(message)
	reverseDomain := senderDomain
	if fromFile {
		reverseDomain = originDomain
	}
	reply, err := submitSMTP(port, message, reverseDomain)
	if err != nil || reply.code != expected {
		return errFixture
	}
	if expected != 250 {
		return errFixture
	}
	queueID, ok := queuedID(reply)
	if !ok {
		return errFixture
	}
	fmt.Printf("SMTP queue acceptance passed %s\n", queueID)
	return nil
}

// runSMTPTempfail requires one exact temporary refusal at any SMTP stage.
func runSMTPTempfail() error {
	message := []byte(
		"From: privacy-envelope-7f3c@" + senderDomain + "\r\n" +
			"To: " + recipient + "\r\n\r\n" +
			privacyMessage + " temporary failure probe\r\n",
	)
	reply, err := submitSMTP(25, message, senderDomain)
	if err != nil || (reply.code != 421 && reply.code != 451) {
		return errFixture
	}
	fmt.Println("SMTP temporary failure passed")
	return nil
}

// runSMTPOverload proves bounded concurrent admission completes with refusal.
func runSMTPOverload() error {
	message := bytes.Repeat([]byte("x"), 512<<10)
	message = append(
		[]byte(
			"From: privacy-envelope-7f3c@"+senderDomain+"\r\n"+
				"To: "+recipient+"\r\n\r\n",
		),
		append(message, '\r', '\n')...,
	)
	defer clear(message)
	const attempts = 16
	results := make(chan int, attempts)
	var wait sync.WaitGroup
	wait.Add(attempts)
	for range attempts {
		go func() {
			defer wait.Done()
			reply, err := submitSMTP(25, message, senderDomain)
			if err != nil {
				results <- 0
				return
			}
			if reply.code == 250 {
				if _, ok := queuedID(reply); !ok {
					results <- 0
					return
				}
			}
			results <- reply.code
		}()
	}
	wait.Wait()
	close(results)
	temporary := 0
	for code := range results {
		if code == 421 || code == 451 {
			temporary++
			continue
		}
		if code != 550 {
			return errFixture
		}
	}
	if temporary == 0 {
		return errFixture
	}
	fmt.Println("SMTP overload admission passed")
	return nil
}

// submitSMTP executes one exact SMTP transaction and returns its bounded reply.
func submitSMTP(port int, message []byte, reverseDomain string) (smtpReply, error) {
	if port != 25 && port != 2526 ||
		reverseDomain != originDomain &&
			reverseDomain != senderDomain {
		return smtpReply{}, errFixture
	}
	connection, err := net.DialTimeout(
		"tcp4",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		2*time.Second,
	)
	if err != nil {
		return smtpReply{}, errFixture
	}
	defer func() {
		_ = connection.Close()
	}()
	if err := connection.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		return smtpReply{}, errFixture
	}
	reader := bufio.NewReaderSize(connection, 64<<10)
	reply, err := readSMTPReply(reader)
	if err != nil || reply.code != 220 {
		return reply, err
	}
	for _, step := range []struct {
		command string
		want    int
	}{
		{command: "EHLO " + senderDomain + "\r\n", want: 250},
		{command: "MAIL FROM:<sender@" + reverseDomain + ">\r\n", want: 250},
		{command: "RCPT TO:<" + recipient + ">\r\n", want: 250},
		{command: "DATA\r\n", want: 354},
	} {
		if _, err := io.WriteString(connection, step.command); err != nil {
			return smtpReply{}, errFixture
		}
		reply, err = readSMTPReply(reader)
		if err != nil || reply.code != step.want {
			return reply, err
		}
	}
	framed, err := frameSMTPData(message)
	if err != nil {
		return smtpReply{}, err
	}
	defer clear(framed)
	if _, err := connection.Write(framed); err != nil {
		return smtpReply{}, errFixture
	}
	reply, err = readSMTPReply(reader)
	if err == nil {
		_, _ = io.WriteString(connection, "QUIT\r\n")
		_, _ = readSMTPReply(reader)
	}
	return reply, err
}

// readSMTPReply parses one bounded single-line or multiline SMTP reply.
func readSMTPReply(reader *bufio.Reader) (smtpReply, error) {
	code := 0
	total := 0
	for lineNumber := 0; lineNumber < 100; lineNumber++ {
		line, err := reader.ReadString('\n')
		total += len(line)
		if err != nil || len(line) < 5 || total > 64<<10 ||
			line[len(line)-2:] != "\r\n" {
			return smtpReply{}, errFixture
		}
		current, err := strconv.Atoi(line[:3])
		if err != nil || current < 200 || current > 599 ||
			(line[3] != ' ' && line[3] != '-') {
			return smtpReply{}, errFixture
		}
		if code == 0 {
			code = current
		} else if current != code {
			return smtpReply{}, errFixture
		}
		if line[3] == ' ' {
			return smtpReply{
				code:     code,
				terminal: strings.TrimSuffix(line, "\r\n"),
			}, nil
		}
	}
	return smtpReply{}, errFixture
}

// queuedID extracts one exact Postfix queue acceptance identifier.
func queuedID(reply smtpReply) (string, bool) {
	const prefix = "250 2.0.0 Ok: queued as "
	if reply.code != 250 || !strings.HasPrefix(reply.terminal, prefix) {
		return "", false
	}
	identifier := strings.TrimPrefix(reply.terminal, prefix)
	if len(identifier) < 5 || len(identifier) > 64 {
		return "", false
	}
	for _, value := range identifier {
		if (value < '0' || value > '9') &&
			(value < 'A' || value > 'Z') &&
			(value < 'a' || value > 'z') {
			return "", false
		}
	}
	return identifier, true
}

// frameSMTPData normalizes LF transport framing and applies exact dot stuffing.
func frameSMTPData(message []byte) ([]byte, error) {
	if len(message) == 0 || len(message) > 4<<20 || bytes.IndexByte(message, 0) >= 0 {
		return nil, errFixture
	}
	normalized := bytes.ReplaceAll(message, []byte("\r\n"), []byte("\n"))
	if bytes.IndexByte(normalized, '\r') >= 0 {
		return nil, errFixture
	}
	var output bytes.Buffer
	atLineStart := true
	for _, value := range normalized {
		if atLineStart && value == '.' {
			output.WriteByte('.')
		}
		if value == '\n' {
			output.WriteString("\r\n")
			atLineStart = true
			continue
		}
		output.WriteByte(value)
		atLineStart = false
	}
	if !atLineStart {
		output.WriteString("\r\n")
	}
	output.WriteString(".\r\n")
	return output.Bytes(), nil
}

// bootstrap creates one fresh reserved-test protected deployment generation.
func bootstrap() error {
	if os.Geteuid() != 0 {
		return errFixture
	}
	origin, err := generateSigningMaterial(
		originDomain, originSelector,
		"privacy-origin-key-7f3c", "privacy-origin-profile-7f3c",
		"originator",
	)
	if err != nil {
		return err
	}
	defer origin.clear()
	transit, err := generateSigningMaterial(
		transitDomain, transitSelector,
		"privacy-transit-key-7f3c", "privacy-transit-profile-7f3c",
		"ordinary_transit",
	)
	if err != nil {
		return err
	}
	defer transit.clear()
	if err := prepareRoute("inbound", "inbound", nil); err != nil {
		return err
	}
	if err := prepareRoute("originator", "originator", origin); err != nil {
		return err
	}
	if err := prepareRoute("transit", "ordinary_transit", transit); err != nil {
		return err
	}
	return writePublicKeys(origin, transit)
}

// generateSigningMaterial creates one RSA key and exact public bindings.
func generateSigningMaterial(
	domain, selector, handle, profile, use string,
) (*signingMaterial, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errFixture
	}
	spki, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, errFixture
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, errFixture
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	clear(pkcs8)
	digest := sha256.Sum256(spki)
	return &signingMaterial{
		domain: domain, selector: selector, handle: handle, profile: profile, use: use,
		privatePEM: privatePEM, spki: spki, spkiDigest: bytes.Clone(digest[:]),
		dnsPublicDER: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	}, nil
}

// clear erases retained private material after bootstrap completion.
func (m *signingMaterial) clear() {
	if m == nil {
		return
	}
	clear(m.privatePEM)
	clear(m.spki)
	clear(m.spkiDigest)
	clear(m.dnsPublicDER)
}

// prepareRoute creates one operation-separated daemon, Milter, and socket tree.
func prepareRoute(route, mode string, signing *signingMaterial) error {
	daemonRoot := filepath.Join("/state/daemon", route)
	milterRoot := filepath.Join("/state/milter", route)
	socketRoot := filepath.Join("/state/sockets", route)
	if !emptyDirectory(daemonRoot) || !emptyDirectory(milterRoot) ||
		!emptyDirectory(socketRoot) {
		return errFixture
	}
	generations := []string{generationID, rotationGenerationID}
	for _, identifier := range generations {
		if os.Mkdir(filepath.Join(daemonRoot, identifier), 0o700) != nil {
			return errFixture
		}
	}
	capabilityNames := daemonCapabilityNames(mode)
	capabilities := make(map[string][]byte, len(capabilityNames))
	for _, name := range capabilityNames {
		value, err := routeCapabilityMarker(route, name)
		if err != nil {
			return errFixture
		}
		for _, identifier := range generations {
			if err := os.WriteFile(
				filepath.Join(daemonRoot, identifier, name),
				value,
				0o600,
			); err != nil {
				clear(value)
				return errFixture
			}
		}
		capabilities[name] = value
	}
	defer func() {
		for _, value := range capabilities {
			clear(value)
		}
	}()
	selected := capabilityForMode(mode)
	if selected == "" ||
		os.WriteFile(filepath.Join(milterRoot, "capability"), capabilities[selected], 0o400) != nil {
		return errFixture
	}
	for _, identifier := range generations {
		generation := filepath.Join(daemonRoot, identifier)
		if signing != nil {
			if err := writeSigningFiles(generation, signing); err != nil {
				return err
			}
		}
		if err := bindDaemonGeneration(generation); err != nil {
			return err
		}
	}
	if err := writeDaemonConfig(daemonRoot, generationID, mode, signing != nil); err != nil {
		return err
	}
	if err := writeMilterState(milterRoot, route, mode, signing); err != nil {
		return err
	}
	if err := bindDaemonRootOwnership(daemonRoot); err != nil {
		return err
	}
	if err := bindMilterOwnership(milterRoot, route); err != nil {
		return err
	}
	if os.Chown(socketRoot, daemonUID, postfixGID) != nil ||
		os.Chmod(socketRoot, 0o750) != nil {
		return errFixture
	}
	return nil
}

// routeCapabilityMarker returns one exact route-local protected test
// capability whose bytes can be searched for unauthorized disclosure.
func routeCapabilityMarker(route, name string) ([]byte, error) {
	var marker string
	switch route + "/" + name {
	case "inbound/capability":
		marker = "privacy-cap-inbound-process-0001"
	case "originator/capability":
		marker = "privacy-cap-origin-process-00001"
	case "originator/sign-capability":
		marker = "privacy-cap-origin-signing-00001"
	case "transit/capability":
		marker = "privacy-cap-transit-process-0000"
	case "transit/revise-capability":
		marker = "privacy-cap-transit-revision-000"
	default:
		return nil, errFixture
	}
	if len(marker) != 32 {
		return nil, errFixture
	}
	return []byte(marker), nil
}

// selectGeneration atomically switches every test route to one complete retained generation.
func selectGeneration(identifier string) error {
	if identifier != generationID && identifier != rotationGenerationID {
		return errFixture
	}
	routes := []struct {
		route   string
		mode    string
		signing bool
	}{
		{route: "inbound", mode: "inbound", signing: false},
		{route: "originator", mode: "originator", signing: true},
		{route: "transit", mode: "ordinary_transit", signing: true},
	}
	for _, route := range routes {
		root := filepath.Join("/state/daemon", route.route)
		if err := writeDaemonConfig(root, identifier, route.mode, route.signing); err != nil {
			return err
		}
	}
	return nil
}

// daemonCapabilityNames returns only the route authorities required by daemon config.
func daemonCapabilityNames(mode string) []string {
	switch mode {
	case "inbound":
		return []string{"capability"}
	case "originator":
		return []string{"capability", "sign-capability"}
	case "ordinary_transit":
		return []string{"capability", "revise-capability"}
	default:
		return nil
	}
}

// capabilityForMode selects the only daemon authority copied to one Milter route.
func capabilityForMode(mode string) string {
	switch mode {
	case "inbound":
		return "capability"
	case "originator":
		return "sign-capability"
	case "ordinary_transit":
		return "revise-capability"
	default:
		return ""
	}
}

// emptyDirectory reports whether one existing directory contains no entry.
func emptyDirectory(name string) bool {
	entries, err := os.ReadDir(name)
	return err == nil && len(entries) == 0
}

// writeDaemonConfig atomically writes one strict selector for a complete generation.
func writeDaemonConfig(
	root string,
	identifier string,
	mode string,
	signing bool,
) error {
	signingConfig := ""
	if signing {
		switch mode {
		case "originator":
			signingConfig = fmt.Sprintf(`
  sign_capability_file: /var/lib/dkim2d/%s/sign-capability`, identifier)
		case "ordinary_transit":
			signingConfig = fmt.Sprintf(`
  revise_capability_file: /var/lib/dkim2d/%s/revise-capability`, identifier)
		default:
			return errFixture
		}
	} else if mode != "inbound" {
		return errFixture
	}
	document := fmt.Sprintf(`config:
  version: dkim2d-config-v1
protected:
  generation: %s
server:
  listen: 127.0.0.1:8080
  capability_file: /var/lib/dkim2d/%s/capability%s
  read_header_timeout: 5s
  read_timeout: 30s
  write_timeout: 65s
  request_deadline: 60s
  max_in_flight: 2
replay:
  backend: disabled
observability:
  logging:
    level: info
  tracing:
    exporter: none
`, identifier, identifier, signingConfig)
	if signing {
		document += fmt.Sprintf(`signing:
  backend: flat_file
  datasource_file: /var/lib/dkim2d/%s/datasource
  private_manifest_file: /var/lib/dkim2d/%s/private-manifest
`, identifier, identifier)
	}
	temporary := filepath.Join(root, "config.yaml.new")
	if err := writeOwnedFile(
		temporary,
		[]byte(document),
		daemonUID,
		daemonGID,
		0o600,
	); err != nil {
		return err
	}
	if err := os.Rename(temporary, filepath.Join(root, "config.yaml")); err != nil {
		_ = os.Remove(temporary)
		return errFixture
	}
	return nil
}

// writeSigningFiles creates one flat-file profile and PKCS#8 manifest binding.
func writeSigningFiles(generation string, material *signingMaterial) error {
	datasource := map[string]any{
		"version": "dkim2-datasource-v1",
		"handles": []any{map[string]any{"id": material.handle}},
		"profiles": []any{map[string]any{
			"id": material.profile, "domain": material.domain, "status": "active",
			"credentials": []any{map[string]any{
				"algorithm": "rsa-sha256", "selector": material.selector,
				"public_key_spki": base64.StdEncoding.EncodeToString(material.spki),
				"handle_id":       material.handle,
			}},
		}},
		"policies": []any{map[string]any{
			"tenant_id": privacyTenant, "domain": material.domain,
			"use": material.use, "profile_id": material.profile,
			"status": "active", "rollout": "enforce", "compatibility": "strict",
		}},
	}
	manifest := map[string]any{
		"version": "dkim2-private-keys-v1",
		"entries": []any{map[string]any{
			"tenant_id": privacyTenant, "domain": material.domain,
			"use": material.use, "handle_id": material.handle,
			"algorithm":          "rsa-sha256",
			"public_spki_sha256": base64.StdEncoding.EncodeToString(material.spkiDigest),
			"private_key_file":   material.handle + ".pem",
		}},
	}
	if err := writeJSON(filepath.Join(generation, "datasource"), datasource); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(generation, "private-manifest"), manifest); err != nil {
		return err
	}
	return os.WriteFile(
		filepath.Join(generation, material.handle+".pem"),
		material.privatePEM,
		0o600,
	)
}

// writeJSON writes one compact deterministic protected JSON file.
func writeJSON(name string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return errFixture
	}
	defer clear(encoded)
	if err := os.WriteFile(name, encoded, 0o600); err != nil {
		return errFixture
	}
	return nil
}

// writeMilterState writes one route-specific adapter configuration.
func writeMilterState(
	root, route, mode string,
	signing *signingMaterial,
) error {
	extra := ""
	if signing != nil {
		extra = fmt.Sprintf(`
signing:
  tenant: %s
  domain: %s`, privacyTenant, signing.domain)
		if mode == "originator" {
			extra += fmt.Sprintf("\n  dsn_domain: %s", signing.domain)
		}
	}
	if mode == "inbound" {
		extra = `
authentication_results:
  enabled: true
  authserv_id: mx.privacy-7f3c9a2d.runtime.example.test`
	}
	document := fmt.Sprintf(`version: dkim2-milter-config-v1
server:
  socket: /run/dkim2/milter.sock
  socket_mode: "0660"
  shutdown_timeout: 5s
  max_connections: 8
  max_in_flight_messages: 4
  max_buffered_bytes: 67108864
daemon:
  endpoint: http://127.0.0.1:8080
  capability_file: /etc/dkim2-milter/capability
  request_timeout: 5s
mode: %s%s
failure:
  mode: tempfail
limits:
  message_bytes: 1048576
  header_bytes: 131072
  header_count: 250
  header_field_bytes: 16384
  recipient_count: 50
observability:
  logging:
    level: info
`, mode, extra)
	return writeOwnedFile(
		filepath.Join(root, route+".yaml"),
		[]byte(document),
		daemonUID,
		postfixGID,
		0o400,
	)
}

// bindDaemonGeneration seals one complete protected daemon generation.
func bindDaemonGeneration(generation string) error {
	entries, err := os.ReadDir(generation)
	if err != nil {
		return errFixture
	}
	for _, entry := range entries {
		if entry.IsDir() ||
			os.Chown(filepath.Join(generation, entry.Name()), daemonUID, daemonGID) != nil ||
			os.Chmod(filepath.Join(generation, entry.Name()), 0o600) != nil {
			return errFixture
		}
	}
	if os.Chown(generation, daemonUID, daemonGID) != nil ||
		os.Chmod(generation, 0o500) != nil {
		return errFixture
	}
	return nil
}

// bindDaemonRootOwnership seals the route root after every generation is complete.
func bindDaemonRootOwnership(root string) error {
	if os.Chown(root, daemonUID, daemonGID) != nil ||
		os.Chmod(root, 0o500) != nil {
		return errFixture
	}
	return nil
}

// bindMilterOwnership seals one adapter config and capability directory.
func bindMilterOwnership(root, route string) error {
	for _, name := range []string{"capability", route + ".yaml"} {
		if os.Chown(filepath.Join(root, name), daemonUID, postfixGID) != nil ||
			os.Chmod(filepath.Join(root, name), 0o400) != nil {
			return errFixture
		}
	}
	if os.Chown(root, daemonUID, postfixGID) != nil ||
		os.Chmod(root, 0o500) != nil {
		return errFixture
	}
	return nil
}

// writeOwnedFile writes and binds one regular file to an exact identity.
func writeOwnedFile(name string, content []byte, uid, gid int, mode os.FileMode) error {
	if err := os.WriteFile(name, content, mode); err != nil ||
		os.Chown(name, uid, gid) != nil ||
		os.Chmod(name, mode) != nil {
		return errFixture
	}
	return nil
}

// writePublicKeys publishes only synthetic public DNS and verifier material.
func writePublicKeys(materials ...*signingMaterial) error {
	if !emptyDirectory("/state/dns") {
		return errFixture
	}
	set := publicKeySet{Version: "dkim2-deployment-public-keys-v1"}
	for _, material := range materials {
		set.Keys = append(set.Keys, publicKeyRecord{
			Domain: material.domain, Selector: material.selector,
			SPKIBase64: base64.StdEncoding.EncodeToString(material.spki),
			TXT: "v=DKIM1; k=rsa; p=" +
				base64.StdEncoding.EncodeToString(material.dnsPublicDER),
		})
	}
	if err := writeJSON("/state/dns/public-keys.json", set); err != nil {
		return err
	}
	return os.Chmod("/state/dns/public-keys.json", 0o444)
}

// serveDNS serves the fixed synthetic TXT records over UDP and TCP.
func serveDNS() error {
	set, err := loadPublicKeys("/state/dns/public-keys.json")
	if err != nil {
		return err
	}
	records := make(map[string]string, len(set.Keys))
	for _, key := range set.Keys {
		records[strings.ToLower(key.Selector+"._domainkey."+key.Domain+".")] = key.TXT
	}
	packet, err := net.ListenPacket("udp4", "127.0.0.1:53")
	if err != nil {
		return errFixture
	}
	defer func() {
		_ = packet.Close()
	}()
	listener, err := net.Listen("tcp4", "127.0.0.1:53")
	if err != nil {
		return errFixture
	}
	defer func() {
		_ = listener.Close()
	}()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go serveDNSUDP(ctx, packet, records)
	go serveDNSTCP(ctx, listener, records)
	<-ctx.Done()
	return nil
}

// serveDNSUDP answers bounded UDP DNS queries until shutdown.
func serveDNSUDP(ctx context.Context, packet net.PacketConn, records map[string]string) {
	buffer := make([]byte, 4096)
	for {
		_ = packet.SetReadDeadline(time.Now().Add(time.Second))
		count, address, err := packet.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		response, ok := answerDNS(buffer[:count], records)
		if ok {
			_, _ = packet.WriteTo(response, address)
		}
	}
}

// serveDNSTCP answers bounded length-prefixed TCP DNS queries until shutdown.
func serveDNSTCP(ctx context.Context, listener net.Listener, records map[string]string) {
	for {
		_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		_ = handleDNSTCP(connection, records)
		_ = connection.Close()
	}
}

// handleDNSTCP answers one bounded TCP DNS query.
func handleDNSTCP(connection net.Conn, records map[string]string) error {
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	var lengthBytes [2]byte
	if _, err := io.ReadFull(connection, lengthBytes[:]); err != nil {
		return errFixture
	}
	length := int(binary.BigEndian.Uint16(lengthBytes[:]))
	if length < 12 || length > 4096 {
		return errFixture
	}
	query := make([]byte, length)
	if _, err := io.ReadFull(connection, query); err != nil {
		return errFixture
	}
	response, ok := answerDNS(query, records)
	if !ok || len(response) > 65535 {
		return errFixture
	}
	binary.BigEndian.PutUint16(lengthBytes[:], uint16(len(response)))
	if _, err := connection.Write(lengthBytes[:]); err != nil {
		return errFixture
	}
	_, err := connection.Write(response)
	return err
}

// answerDNS constructs one authoritative TXT answer or bounded NXDOMAIN.
func answerDNS(query []byte, records map[string]string) ([]byte, bool) {
	if len(query) < 12 ||
		binary.BigEndian.Uint16(query[2:4])&0xf800 != 0 ||
		binary.BigEndian.Uint16(query[4:6]) != 1 ||
		binary.BigEndian.Uint16(query[6:8]) != 0 ||
		binary.BigEndian.Uint16(query[8:10]) != 0 ||
		binary.BigEndian.Uint16(query[10:12]) > 1 {
		return nil, false
	}
	name, end, ok := decodeDNSName(query, 12)
	if !ok || end+4 > len(query) {
		return nil, false
	}
	questionEnd := end + 4
	additionalCount := binary.BigEndian.Uint16(query[10:12])
	if additionalCount == 0 && questionEnd != len(query) ||
		additionalCount == 1 && !validEDNSQuery(query, questionEnd) {
		return nil, false
	}
	queryType := binary.BigEndian.Uint16(query[end : end+2])
	queryClass := binary.BigEndian.Uint16(query[end+2 : questionEnd])
	if queryClass != 1 {
		return nil, false
	}
	record, found := records[strings.ToLower(name)]
	response := make([]byte, 12, 512)
	copy(response[0:2], query[0:2])
	flags := uint16(0x8400)
	if !found {
		flags |= 0x0003
	}
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[4:6], 1)
	if found && queryType == 16 {
		binary.BigEndian.PutUint16(response[6:8], 1)
	}
	response = append(response, query[12:questionEnd]...)
	if !found || queryType != 16 {
		return response, true
	}
	if len(record) == 0 || len(record) > 2048 {
		return nil, false
	}
	answer := []byte{0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c}
	chunks := (len(record) + 254) / 255
	rdataLength := len(record) + chunks
	answer = append(answer, byte(rdataLength>>8), byte(rdataLength))
	for len(record) > 0 {
		length := min(len(record), 255)
		answer = append(answer, byte(length))
		answer = append(answer, record[:length]...)
		record = record[length:]
	}
	return append(response, answer...), true
}

// validEDNSQuery accepts one bounded root-owned EDNS version-zero pseudo-record.
func validEDNSQuery(query []byte, offset int) bool {
	if offset < 12 || offset+11 > len(query) || query[offset] != 0 ||
		binary.BigEndian.Uint16(query[offset+1:offset+3]) != 41 ||
		binary.BigEndian.Uint16(query[offset+3:offset+5]) < 512 {
		return false
	}
	ttl := binary.BigEndian.Uint32(query[offset+5 : offset+9])
	if ttl&0xffff0000 != 0 || ttl&0x00007fff != 0 {
		return false
	}
	length := int(binary.BigEndian.Uint16(query[offset+9 : offset+11]))
	if length > 1024 || offset+11+length != len(query) {
		return false
	}
	options := query[offset+11:]
	for len(options) > 0 {
		if len(options) < 4 {
			return false
		}
		optionLength := int(binary.BigEndian.Uint16(options[2:4]))
		if optionLength > len(options)-4 {
			return false
		}
		options = options[4+optionLength:]
	}
	return true
}

// decodeDNSName decodes one uncompressed bounded question owner.
func decodeDNSName(query []byte, offset int) (string, int, bool) {
	var labels []string
	total := 0
	for {
		if offset >= len(query) {
			return "", 0, false
		}
		length := int(query[offset])
		offset++
		if length == 0 {
			return strings.Join(labels, ".") + ".", offset, len(labels) > 0
		}
		if length > 63 || offset+length > len(query) || total+length+1 > 255 {
			return "", 0, false
		}
		labels = append(labels, string(query[offset:offset+length]))
		offset += length
		total += length + 1
	}
}

// probeDNS verifies one exact no-extension query against the local fixture.
func probeDNS() error {
	const identifier = 0x4d32
	query, err := encodeDNSQuery(
		identifier,
		originSelector+"._domainkey."+originDomain+".",
		16,
	)
	if err != nil {
		return err
	}
	connection, err := net.DialTimeout("udp4", "127.0.0.1:53", time.Second)
	if err != nil {
		return errFixture
	}
	defer func() {
		_ = connection.Close()
	}()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return errFixture
	}
	if _, err := connection.Write(query); err != nil {
		return errFixture
	}
	response := make([]byte, 4096)
	count, err := connection.Read(response)
	if err != nil || count <= len(query) {
		return errFixture
	}
	response = response[:count]
	if binary.BigEndian.Uint16(response[0:2]) != identifier ||
		binary.BigEndian.Uint16(response[2:4]) != 0x8400 ||
		binary.BigEndian.Uint16(response[4:6]) != 1 ||
		binary.BigEndian.Uint16(response[6:8]) != 1 ||
		!bytes.Equal(response[12:len(query)], query[12:]) {
		return errFixture
	}
	return nil
}

// encodeDNSQuery constructs one bounded uncompressed IN question.
func encodeDNSQuery(identifier uint16, owner string, queryType uint16) ([]byte, error) {
	if identifier == 0 || queryType == 0 || !strings.HasSuffix(owner, ".") ||
		len(owner) < 2 || len(owner) > 254 {
		return nil, errFixture
	}
	query := make([]byte, 12, 12+len(owner)+4)
	binary.BigEndian.PutUint16(query[0:2], identifier)
	binary.BigEndian.PutUint16(query[4:6], 1)
	labels := strings.Split(strings.TrimSuffix(owner, "."), ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return nil, errFixture
		}
		for _, value := range label {
			if value < 0x21 || value > 0x7e {
				return nil, errFixture
			}
		}
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 0, 0, 1)
	binary.BigEndian.PutUint16(query[len(query)-4:len(query)-2], queryType)
	if len(query) > 512 {
		return nil, errFixture
	}
	return query, nil
}

// verifyMessage cryptographically verifies a captured originator or transit message.
func verifyMessage(expectTransit bool) error {
	message, err := artifactpath.ReadFile("/verify", "message.eml", 4<<20)
	if err != nil || len(message) == 0 || len(message) > 4<<20 {
		return errFixture
	}
	defer clear(message)
	normalized, err := normalizePostcatMessage(message)
	if err != nil {
		return err
	}
	defer clear(normalized)
	set, err := loadPublicKeys("/state/dns/public-keys.json")
	if err != nil {
		return err
	}
	provider, err := newStaticProvider(set)
	if err != nil {
		return err
	}
	verifier, err := dkim2.NewVerifier(provider)
	if err != nil {
		return errFixture
	}
	request := dkim2.NewVerifyRequest(
		normalized,
		[]byte("<sender@"+originDomain+">"),
		[][]byte{[]byte("<" + recipient + ">")},
	)
	result, err := verifier.Verify(context.Background(), request)
	if err != nil || result.State() != dkim2.ResultStatePASS {
		return errFixture
	}
	expectedFields := 1
	if expectTransit {
		expectedFields = 2
	}
	if len(result.SignatureSets()) != 1 ||
		countHeader(normalized, "Message-Instance") != 1 ||
		countHeader(normalized, "DKIM2-Signature") != expectedFields {
		return errFixture
	}
	if !expectTransit {
		signer, signerErr := dkim2.NewSigner(
			provider,
			dkim2.NewRequestRouteAuthority(),
			unavailableSigningAuthorizer{},
			unavailablePrivateKeySigner{},
		)
		if signerErr != nil {
			return errFixture
		}
		revision, capability, revisionErr := signer.VerifyForRevision(
			context.Background(),
			dkim2.NewVerifyRequest(
				normalized,
				[]byte("<sender@"+originDomain+">"),
				[][]byte{[]byte("<" + recipient + ">")},
			),
		)
		if revisionErr != nil ||
			revision.Status() != dkim2.RevisionVerificationVerified ||
			!capability.Valid() {
			fmt.Fprintf(
				os.Stderr,
				"revision preflight failed: %s\n",
				revision.Status(),
			)
			return errFixture
		}
	}
	fmt.Println("public cryptographic verification passed")
	return nil
}

// normalizePostcatMessage restores CRLF after Postfix postcat's LF presentation.
func normalizePostcatMessage(message []byte) ([]byte, error) {
	if len(message) == 0 || bytes.IndexByte(message, '\r') >= 0 {
		return nil, errFixture
	}
	return bytes.ReplaceAll(message, []byte("\n"), []byte("\r\n")), nil
}

// loadPublicKeys reads one bounded strict synthetic public-key set.
func loadPublicKeys(name string) (publicKeySet, error) {
	content, err := artifactpath.ReadFile(
		filepath.Dir(name),
		filepath.Base(name),
		1<<20,
	)
	if err != nil {
		return publicKeySet{}, errFixture
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var set publicKeySet
	if decoder.Decode(&set) != nil || set.Version != "dkim2-deployment-public-keys-v1" ||
		len(set.Keys) != 2 {
		return publicKeySet{}, errFixture
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return publicKeySet{}, errFixture
	}
	return set, nil
}

// newStaticProvider validates and indexes exact RSA SPKI public material.
func newStaticProvider(set publicKeySet) (*staticProvider, error) {
	provider := &staticProvider{keys: make(map[string]*rsa.PublicKey, len(set.Keys))}
	for _, record := range set.Keys {
		der, err := base64.StdEncoding.Strict().DecodeString(record.SPKIBase64)
		if err != nil {
			return nil, errFixture
		}
		keyValue, err := x509.ParsePKIXPublicKey(der)
		clear(der)
		key, ok := keyValue.(*rsa.PublicKey)
		if err != nil || !ok || key.N == nil || key.N.BitLen() < 2048 {
			return nil, errFixture
		}
		dnsKey, err := parseDNSRSAPublicKey(record.TXT)
		if err != nil || dnsKey.N == nil ||
			dnsKey.E != key.E || dnsKey.N.Cmp(key.N) != 0 {
			return nil, errFixture
		}
		identity := record.Selector + "\x00" + record.Domain
		if _, duplicate := provider.keys[identity]; duplicate {
			return nil, errFixture
		}
		provider.keys[identity] = key
	}
	return provider, nil
}

// parseDNSRSAPublicKey decodes the exact synthetic DNS-04 RSA binding.
func parseDNSRSAPublicKey(record string) (*rsa.PublicKey, error) {
	const prefix = "v=DKIM1; k=rsa; p="
	if !strings.HasPrefix(record, prefix) || len(record) <= len(prefix) {
		return nil, errFixture
	}
	der, err := base64.StdEncoding.Strict().DecodeString(record[len(prefix):])
	if err != nil {
		return nil, errFixture
	}
	defer clear(der)
	key, err := x509.ParsePKCS1PublicKey(der)
	if err != nil || key.N == nil || key.N.BitLen() < 2048 {
		return nil, errFixture
	}
	return key, nil
}

// LookupPublicKey returns one exact synthetic public key without diagnostic identity.
func (p *staticProvider) LookupPublicKey(
	ctx context.Context,
	query dkim2.PublicKeyQuery,
) (dkim2.PublicKeyResult, error) {
	if err := ctx.Err(); err != nil {
		return dkim2.PublicKeyResult{}, err
	}
	if p == nil || query.Algorithm() != dkim2.AlgorithmRSASHA256 {
		return dkim2.InvalidPublicKey(query.Algorithm()), nil
	}
	key := p.keys[query.Selector()+"\x00"+query.SigningDomain()]
	if key == nil {
		return dkim2.MissingPublicKey(query.Algorithm()), nil
	}
	return dkim2.FoundRSAPublicKey(key), nil
}
