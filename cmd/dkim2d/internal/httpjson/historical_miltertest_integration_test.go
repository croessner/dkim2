//go:build darwin

package httpjson

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
)

const (
	historicalMiltertestDarwinSHA256 = "b9caf2d3b6c2fe1d76026e554e2c7b6796e651233b162fdfd0605b9d85198c99"
	historicalMiltertestGitCommit    = "a3d5e00ff8cff071f91a485acfc0aaaea81c5feb"
	historicalMiltertestGitTree      = "ba6fa740919c13329ef2842895031924424f08f1"
	historicalMiltertestGitRemote    = "ssh://git@git.roessner-net.de:2222/croessner/miltertest-go.git"
)

type historicalMilterResult struct {
	value app.InboundResult
	err   error
}

type historicalMilterProcessor struct {
	processor *app.InboundProcessor
	results   chan historicalMilterResult
}

// Process delegates to the real inbound pipeline and captures only its typed result.
func (p *historicalMilterProcessor) ProcessInbound(
	ctx context.Context,
	request app.InboundRequest,
) (app.InboundResult, error) {
	result, err := p.processor.ProcessInbound(ctx, request)
	p.results <- historicalMilterResult{value: result, err: err}
	return result, err
}

// TestMiltertestMultiInstanceTestingContinue drives the real Milter executable
// through the generated strict handler for the production-failing m=2 row.
// The external oracle is additional wire evidence only: the normative contract
// is owned by the in-repository mapper and strict-handler tests. Its digest is
// reproducibly built from the private, reviewed commit and tree recorded in
// the retained manifest.
func TestMiltertestMultiInstanceTestingContinue(t *testing.T) {
	miltertestBinary := os.Getenv("DKIM2_MILTERTEST_BIN")
	if miltertestBinary == "" {
		t.Skip("set DKIM2_MILTERTEST_BIN to run the sibling Milter oracle")
	}
	assertHistoricalMiltertestBinary(t, miltertestBinary)
	root, err := os.MkdirTemp("/private/tmp", ".d2-inbound-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err = os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}

	const timestamp = int64(1_700_000_000)
	raw, key := signedMultiInstanceResponseMessage(t, timestamp)
	processor := newHistoricalMilterProcessor(t, key, timestamp)
	capability := bytes.Repeat([]byte{0xa5}, 32)
	wantCapability := base64.RawURLEncoding.EncodeToString(capability)
	var httpCalls atomic.Int32
	var httpStatus atomic.Int32
	adapter, err := newStrictAdapter(&adapterReadinessStub{}, processor)
	if err != nil {
		t.Fatal("historical Milter adapter construction failed")
	}
	capabilityMiddleware := func(
		next generated.StrictHandlerFunc,
		operationID string,
	) generated.StrictHandlerFunc {
		return func(ctx context.Context, writer http.ResponseWriter, request *http.Request, input any) (any, error) {
			if operationID != "ProcessMessage" || request.URL.Path != testProcessPath ||
				request.Header.Get("X-DKIM2-Capability") != wantCapability {
				return nil, &strictAdapterError{class: strictFailureInvalidContract}
			}
			return next(ctx, writer, request, input)
		}
	}
	strict := generated.NewStrictHandler(
		adapter,
		[]generated.StrictMiddlewareFunc{capabilityMiddleware, testWorkingSetMiddleware},
	)
	strictHandler := generated.HandlerFromMux(strict, http.NewServeMux())
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		capture := &historicalHTTPStatusWriter{ResponseWriter: writer, status: http.StatusOK}
		strictHandler.ServeHTTP(capture, request)
		httpCalls.Add(1)
		httpStatus.Store(int32(capture.status))
	}))
	t.Cleanup(server.Close)

	milterBinary := filepath.Join(root, "dkim2-milter")
	build := exec.Command("go", "build", "-o", milterBinary, "../../../../cmd/dkim2-milter")
	if output, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Fatalf("build Milter: %v output=%q", buildErr, output)
	}
	capabilityRoot := filepath.Join(root, "cap")
	if err = os.Mkdir(capabilityRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	capabilityPath := filepath.Join(capabilityRoot, "token")
	if err = os.WriteFile(capabilityPath, capability, 0o400); err != nil {
		t.Fatal(err)
	}
	clear(capability)
	if err = os.Chmod(capabilityRoot, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(capabilityRoot, 0o700) })
	socketPath := filepath.Join(root, "m.sock")
	configPath := filepath.Join(root, "milter.yaml")
	configText := fmt.Sprintf(`version: dkim2-milter-config-v1
server:
  socket: %s
  shutdown_timeout: 1s
daemon:
  endpoint: %s
  capability_file: %s
  request_timeout: 5s
mode: inbound
authentication_results:
  enabled: true
  authserv_id: mx.example.test
failure:
  mode: tempfail
limits:
  message_bytes: 1048576
  header_bytes: 131072
  header_count: 250
  header_field_bytes: 16384
  recipient_count: 50
`, socketPath, server.URL, capabilityPath)
	if err = os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	headers, body, err := splitHistoricalMilterMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	bodyPath := filepath.Join(root, "body")
	if err = os.WriteFile(bodyPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	actionsPath := filepath.Join(root, "actions.json")
	if err = os.WriteFile(actionsPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(root, "inbound.lua")
	scriptText := historicalInboundLua(socketPath, bodyPath, headers)
	if err = os.WriteFile(scriptPath, []byte(scriptText), 0o600); err != nil {
		t.Fatal(err)
	}
	preserveHistoricalMilterArtifacts(t, configPath, scriptPath, bodyPath, milterBinary, miltertestBinary)

	logPath := filepath.Join(root, "milter.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	milter := exec.Command(milterBinary, "serve", "--config", configPath)
	milter.Stdout, milter.Stderr = logFile, logFile
	if err = milter.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if milter.ProcessState == nil {
			_ = milter.Process.Kill()
			_ = milter.Wait()
		}
		_ = logFile.Close()
	})
	waitForHistoricalMilterSocket(t, socketPath, milter, logPath)
	oracle := exec.Command(miltertestBinary, "-s", scriptPath)
	oracle.Env = append(os.Environ(), "MILTERTEST_ACTIONS_FILE="+actionsPath)
	if output, oracleErr := oracle.CombinedOutput(); oracleErr != nil {
		logged, _ := os.ReadFile(logPath)
		t.Fatalf("miltertest: %v output=%q milter_log=%q", oracleErr, output, logged)
	}
	assertHistoricalMilterResult(t, processor.results, actionsPath, httpCalls.Load(), httpStatus.Load())
	stopHistoricalMilter(t, milter)
}

type historicalHTTPStatusWriter struct {
	http.ResponseWriter
	status int
}

// WriteHeader captures the generated strict-handler status unchanged.
func (w *historicalHTTPStatusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// newHistoricalMilterProcessor constructs the exact real daemon pipeline.
func newHistoricalMilterProcessor(t testing.TB, key *rsa.PublicKey, timestamp int64) *historicalMilterProcessor {
	t.Helper()
	verifier, err := dkim2.NewVerifier(
		selectedMatrixProvider{key: key, outcome: selectedProviderFound},
		dkim2.WithVerificationClock(func() time.Time { return time.Unix(timestamp, 0) }),
	)
	if err != nil {
		t.Fatal("historical Milter verifier construction failed")
	}
	domain, err := app.NewDomainProcessor(verifier, config.PolicyTesting)
	if err != nil {
		t.Fatal("historical Milter domain processor construction failed")
	}
	inbound, err := app.NewInboundProcessor(domain, app.NewDisabledReplayCoordinator())
	if err != nil {
		t.Fatal("historical Milter inbound processor construction failed")
	}
	return &historicalMilterProcessor{processor: inbound, results: make(chan historicalMilterResult, 1)}
}

// splitHistoricalMilterMessage preserves exact ordered header callback values and body bytes.
func splitHistoricalMilterMessage(raw []byte) ([][2]string, []byte, error) {
	separator := bytes.Index(raw, []byte("\r\n\r\n"))
	if separator < 0 {
		return nil, nil, fmt.Errorf("missing historical message separator")
	}
	lines := bytes.Split(raw[:separator], []byte("\r\n"))
	fields := make([][2]string, 0, len(lines))
	for _, line := range lines {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if len(fields) == 0 {
				return nil, nil, fmt.Errorf("orphan historical continuation")
			}
			fields[len(fields)-1][1] += "\r\n" + string(line)
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 1 {
			return nil, nil, fmt.Errorf("invalid historical header")
		}
		fields = append(fields, [2]string{string(line[:colon]), string(line[colon+1:])})
	}
	return fields, bytes.Clone(raw[separator+4:]), nil
}

// historicalInboundLua renders the exact synthetic inbound callback sequence.
func historicalInboundLua(socketPath, bodyPath string, headers [][2]string) string {
	var output strings.Builder
	output.WriteString("local json = require(\"json\")\n")
	fmt.Fprintf(&output, "socket_set(\"unix\", %s)\n", historicalLuaLongString(socketPath))
	output.WriteString("negotiate(6, 0xffffffff, 0xffffffff)\n")
	output.WriteString("assert_cap(\"actions\", MILTER.SMFIF_ADDHDR)\n")
	output.WriteString("assert_cap(\"actions\", MILTER.SMFIF_CHGHDRS)\n")
	output.WriteString("connect(\"localhost\", \"127.0.0.1\")\nhelo(\"localhost\")\n")
	output.WriteString("mailfrom(\"<sender@example.test>\")\nrcptto(\"<rcpt@example.test>\")\n")
	for _, header := range headers {
		fmt.Fprintf(&output, "header(%s, %s)\n", historicalLuaLongString(header[0]), historicalLuaLongString(header[1]))
	}
	output.WriteString("eoh()\n")
	fmt.Fprintf(&output, "local file = assert(io.open(%s, \"rb\"))\n", historicalLuaLongString(bodyPath))
	output.WriteString("while true do local chunk = file:read(4096); if not chunk then break end; body(chunk) end\nfile:close()\n")
	output.WriteString("local actions = eom()\n")
	output.WriteString("local actions_path = assert(os.getenv(\"MILTERTEST_ACTIONS_FILE\"))\n")
	output.WriteString("local actions_file = assert(io.open(actions_path, \"wb\"))\n")
	output.WriteString("assert(actions_file:write(json.encode(actions), \"\\n\"))\nassert(actions_file:close())\n")
	output.WriteString("assert_final(actions, \"accept\")\nquit()\n")
	return output.String()
}

// historicalLuaLongString quotes controlled synthetic values without escape interpretation.
func historicalLuaLongString(value string) string {
	for equals := ""; ; equals += "=" {
		closing := "]" + equals + "]"
		if !strings.Contains(value, closing) {
			return "[" + equals + "[" + value + closing
		}
	}
}

// preserveHistoricalMilterArtifacts retains only secret-free executed Lua/YAML and metadata.
func preserveHistoricalMilterArtifacts(
	t testing.TB,
	configPath string,
	scriptPath string,
	bodyPath string,
	milterBinary string,
	miltertestBinary string,
) {
	t.Helper()
	destination := os.Getenv("DKIM2_MILTERTEST_ARTIFACT_DIR")
	if destination == "" {
		return
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	config := mustReadHistoricalArtifact(t, configPath)
	script := mustReadHistoricalArtifact(t, scriptPath)
	body := mustReadHistoricalArtifact(t, bodyPath)
	configDigest := sha256.Sum256(config)
	scriptDigest := sha256.Sum256(script)
	bodyDigest := sha256.Sum256(body)
	manifest := fmt.Sprintf(
		"scenario=dkim2-inbound-m2-testing-continue-report-v1\nconfig_sha256=%x\nlua_sha256=%x\nbody_sha256=%x\nmiltertest_git_remote=%s\nmiltertest_git_commit=%s\nmiltertest_git_tree=%s\nmiltertest_sha256=%s\nmiltertest_go_version=go1.26.6\nmiltertest_build=CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -mod=vendor -buildvcs=false -trimpath -ldflags='-s -w' -o <output> ./cmd/miltertest-go\nexpected_http_status=200\nexpected_terminal=accept\nexpected_mutations=1\nexpected_wire_action=INSHEADER:0:Authentication-Results: mx.example.test; dkim2=pass\nmilter_call=%s serve --config %s\nmiltertest_call=MILTERTEST_ACTIONS_FILE=<ephemeral-0600> %s -s %s\n",
		configDigest, scriptDigest, bodyDigest, historicalMiltertestGitRemote,
		historicalMiltertestGitCommit,
		historicalMiltertestGitTree, historicalMiltertestDarwinSHA256,
		milterBinary, configPath, miltertestBinary, scriptPath,
	)
	for _, artifact := range []struct {
		name string
		data []byte
	}{
		{name: "milter.yaml", data: config},
		{name: "inbound.lua", data: script},
		{name: "body.bin", data: body},
		{name: "manifest.txt", data: []byte(manifest)},
	} {
		if err := os.WriteFile(filepath.Join(destination, artifact.name), artifact.data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// mustReadHistoricalArtifact reads one controlled test artifact.
func mustReadHistoricalArtifact(t testing.TB, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// assertHistoricalMiltertestBinary pins the reviewed Darwin oracle artifact.
func assertHistoricalMiltertestBinary(t testing.TB, path string) {
	t.Helper()
	data := mustReadHistoricalArtifact(t, path)
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != historicalMiltertestDarwinSHA256 {
		t.Fatal("miltertest harness digest did not match reviewed Darwin artifact")
	}
}

// waitForHistoricalMilterSocket waits within one fixed startup bound.
func waitForHistoricalMilterSocket(t testing.TB, path string, process *exec.Cmd, logPath string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		state, err := os.Lstat(path)
		if err == nil && state.Mode()&os.ModeSocket != 0 {
			return
		}
		if process.ProcessState != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	logged, _ := os.ReadFile(logPath)
	t.Fatalf("historical Milter socket not ready output=%q", logged)
}

// assertHistoricalMilterResult proves HTTP 200 and the exact report before accept.
func assertHistoricalMilterResult(
	t testing.TB,
	results <-chan historicalMilterResult,
	actionsPath string,
	httpCalls int32,
	httpStatus int32,
) {
	t.Helper()
	select {
	case outcome := <-results:
		if outcome.err != nil || !outcome.value.Valid() || !outcome.value.Applicable() {
			t.Fatalf("historical inbound result valid=%t applicable=%t error=%v", outcome.value.Valid(), outcome.value.Applicable(), outcome.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("historical inbound processor was not reached")
	}
	if httpCalls != 1 || httpStatus != http.StatusOK {
		t.Fatalf("historical HTTP calls=%d status=%d", httpCalls, httpStatus)
	}
	actions := mustReadHistoricalArtifact(t, actionsPath)
	var decoded []struct {
		Disposition string `json:"disposition"`
		Detail      struct {
			Kind  string `json:"kind"`
			Index uint32 `json:"index"`
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"detail"`
	}
	if err := json.Unmarshal(actions, &decoded); err != nil || len(decoded) != 2 ||
		decoded[0].Detail.Kind != "insert_header" ||
		decoded[0].Detail.Index != 0 ||
		decoded[0].Detail.Name != "Authentication-Results" ||
		decoded[0].Detail.Value != " "+testInboundPassReport ||
		decoded[1].Disposition != testDispositionAccept ||
		(decoded[1].Detail.Kind != "" && decoded[1].Detail.Kind != "none") {
		t.Fatal("historical Milter report action or terminal changed")
	}
}

// stopHistoricalMilter terminates and reaps the isolated real Milter process.
func stopHistoricalMilter(t testing.TB, process *exec.Cmd) {
	t.Helper()
	if err := process.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("historical Milter did not stop")
	}
}
