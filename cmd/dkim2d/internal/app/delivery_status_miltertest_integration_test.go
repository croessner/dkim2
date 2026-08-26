//go:build darwin || linux

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
)

const (
	miltertestHarnessSHA256     = "b9caf2d3b6c2fe1d76026e554e2c7b6796e651233b162fdfd0605b9d85198c99"
	harnessMiddlewareAuthorized = "route_authorized"
)

type deliveryStatusHarnessResult struct {
	raw    []byte
	result OperationResult
	err    error
}

type harnessHTTPStatusWriter struct {
	http.ResponseWriter
	status int
}

// WriteHeader retains the real strict-handler status without changing the response.
func (w *harnessHTTPStatusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

type deliveryStatusHarnessService struct {
	service *SigningService
	result  chan deliveryStatusHarnessResult
	stages  chan string
}

// SignDeliveryStatus executes the real application service behind the strict HTTP boundary.
func (s *deliveryStatusHarnessService) SignDeliveryStatus(
	ctx context.Context,
	request generated.SignDeliveryStatusRequestObject,
) (generated.SignDeliveryStatusResponseObject, error) {
	s.stages <- "entered"
	if request.Body == nil {
		return nil, errors.New("missing harness body")
	}
	rawText, err := request.Body.Message.RawRfc5322Base64.Bytes()
	if err != nil {
		return nil, err
	}
	raw, err := decodeHarnessBase64(rawText)
	if err != nil {
		return nil, err
	}
	s.stages <- "raw"
	reverse, err := request.Body.OuterSmtp.MailFrom.Bytes()
	if err != nil {
		return nil, err
	}
	s.stages <- "reverse"
	recipients := make([][]byte, len(request.Body.OuterSmtp.RcptTo))
	for index := range request.Body.OuterSmtp.RcptTo {
		recipients[index], err = request.Body.OuterSmtp.RcptTo[index].Bytes()
		if err != nil {
			return nil, err
		}
	}
	s.stages <- "recipients"
	appRequest, err := NewPostfixDeliveryStatusRequest(
		raw, reverse, recipients, request.Body.Context.Tenant,
	)
	if err != nil {
		return nil, err
	}
	s.stages <- "mapped"
	result, operationErr := s.service.SignDeliveryStatus(ctx, appRequest)
	s.result <- deliveryStatusHarnessResult{raw: bytes.Clone(raw), result: result, err: operationErr}
	response, err := deliveryStatusHarnessResponse(result, operationErr)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	return generated.SignDeliveryStatus200JSONResponse{
		Body: response,
		Headers: generated.SignDeliveryStatus200ResponseHeaders{
			CacheControl: "no-store", Connection: "close",
			ContentLength:       strconv.Itoa(len(encoded) + 1),
			XContentTypeOptions: "nosniff",
		},
	}, nil
}

// decodeHarnessBase64 decodes the generated wire field into exact message bytes.
func decodeHarnessBase64(encoded []byte) ([]byte, error) {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	count, err := base64.StdEncoding.Decode(decoded, encoded)
	if err != nil {
		clear(decoded)
		return nil, err
	}
	return decoded[:count], nil
}

// GetHealth rejects operations outside the dedicated DSN harness route.
func (*deliveryStatusHarnessService) GetHealth(context.Context, generated.GetHealthRequestObject) (generated.GetHealthResponseObject, error) {
	return nil, errors.New("unexpected harness operation")
}

// HeadHealth rejects operations outside the dedicated DSN harness route.
func (*deliveryStatusHarnessService) HeadHealth(context.Context, generated.HeadHealthRequestObject) (generated.HeadHealthResponseObject, error) {
	return nil, errors.New("unexpected harness operation")
}

// GetMetrics rejects operations outside the dedicated DSN harness route.
func (*deliveryStatusHarnessService) GetMetrics(context.Context, generated.GetMetricsRequestObject) (generated.GetMetricsResponseObject, error) {
	return nil, errors.New("unexpected harness operation")
}

// GetReadiness rejects operations outside the dedicated DSN harness route.
func (*deliveryStatusHarnessService) GetReadiness(context.Context, generated.GetReadinessRequestObject) (generated.GetReadinessResponseObject, error) {
	return nil, errors.New("unexpected harness operation")
}

// HeadReadiness rejects operations outside the dedicated DSN harness route.
func (*deliveryStatusHarnessService) HeadReadiness(context.Context, generated.HeadReadinessRequestObject) (generated.HeadReadinessResponseObject, error) {
	return nil, errors.New("unexpected harness operation")
}

// ProcessMessage rejects operations outside the dedicated DSN harness route.
func (*deliveryStatusHarnessService) ProcessMessage(context.Context, generated.ProcessMessageRequestObject) (generated.ProcessMessageResponseObject, error) {
	return nil, errors.New("unexpected harness operation")
}

// ReviseMessage rejects operations outside the dedicated DSN harness route.
func (*deliveryStatusHarnessService) ReviseMessage(context.Context, generated.ReviseMessageRequestObject) (generated.ReviseMessageResponseObject, error) {
	return nil, errors.New("unexpected harness operation")
}

// SignMessage rejects operations outside the dedicated DSN harness route.
func (*deliveryStatusHarnessService) SignMessage(context.Context, generated.SignMessageRequestObject) (generated.SignMessageResponseObject, error) {
	return nil, errors.New("unexpected harness operation")
}

// TestMiltertestPostfixDSNEndToEnd drives the real Milter executable with the
// sibling Lua MTA oracle and real cryptographic application service.
func TestMiltertestPostfixDSNEndToEnd(t *testing.T) {
	miltertestBinary := os.Getenv("DKIM2_MILTERTEST_BIN")
	if miltertestBinary == "" {
		t.Skip("set DKIM2_MILTERTEST_BIN to run the sibling Milter oracle")
	}
	assertHarnessBinary(t, miltertestBinary)
	root, err := os.MkdirTemp("/private/tmp", ".d2h-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	milterBinary := filepath.Join(root, "dkim2-milter")
	build := exec.Command("go", "build", "-o", milterBinary, "../../../../cmd/dkim2-milter")
	if output, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Fatalf("build Milter: %v output=%q", buildErr, output)
	}

	for _, testCase := range []struct {
		name string
		dual bool
	}{
		{name: "rsa-only"},
		{name: "rsa-ed25519", dual: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newSigningServiceFixtureWithDualCredentials(t, testCase.dual)
			service, serviceErr := NewSigningService(fixture.publicKeys, fixture.runtime, false)
			if serviceErr != nil {
				t.Fatal(serviceErr)
			}
			service.clock = func() time.Time { return time.Unix(1_700_000_000, 0) }
			request := authenticatedDeliveryStatusRequest(t, service)
			request = postfixBounceShapeRequest(t, request, postfixBounceShapeOptions{
				contentDescriptions: true, messageFieldOrder: true,
				recipientFieldOrder: true, diagnosticFold: true, embeddedReturnPath: true,
			})
			runDeliveryStatusMilterHarness(t, root, milterBinary, miltertestBinary, service, request)
			if generator := os.Getenv("DKIM2_POSTFIX_BOUNCE_GENERATOR"); generator != "" && testCase.dual {
				for _, variant := range []struct {
					name string
					args []string
				}{
					{name: "postfix-serialized"},
					{name: "postfix-serialized-no-orcpt-no-envid", args: []string{"full", "no-orcpt", "-"}},
				} {
					t.Run(variant.name, func(t *testing.T) {
						postfixRequest := generateHarnessPostfixBounce(t, root, generator, request, variant.args...)
						runDeliveryStatusMilterHarness(t, root, milterBinary, miltertestBinary, service, postfixRequest)
					})
				}
			}
		})
	}
}

// generateHarnessPostfixBounce invokes an explicitly supplied local Postfix fixture generator.
func generateHarnessPostfixBounce(
	t *testing.T,
	root string,
	generator string,
	request DeliveryStatusRequest,
	arguments ...string,
) DeliveryStatusRequest {
	t.Helper()
	embedded, err := extractHarnessEmbeddedMessage(request.RawMessage())
	if err != nil {
		t.Fatal(err)
	}
	caseRoot, err := os.MkdirTemp(root, "postfix-")
	if err != nil {
		t.Fatal(err)
	}
	originalPath := filepath.Join(caseRoot, "original.eml")
	bouncePath := filepath.Join(caseRoot, "bounce.eml")
	if err := os.WriteFile(originalPath, embedded, 0o600); err != nil {
		t.Fatal(err)
	}
	commandArguments := append([]string{originalPath, bouncePath}, arguments...)
	command := exec.Command(generator, commandArguments...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Postfix bounce generator: %v output=%q", err, output)
	}
	bounce, err := os.ReadFile(bouncePath)
	if err != nil {
		t.Fatal(err)
	}
	postfixRequest, err := NewPostfixDeliveryStatusRequest(
		bounce,
		[]byte("<>"),
		[][]byte{[]byte("<sender@" + signingServiceOriginDomain + ">")},
		signingServiceTestTenant,
	)
	if err != nil {
		t.Fatal(err)
	}
	return postfixRequest
}

// extractHarnessEmbeddedMessage returns the exact synthetic original from the controlled fixture.
func extractHarnessEmbeddedMessage(raw []byte) ([]byte, error) {
	marker := []byte("Content-Type: message/rfc822\r\n\r\n")
	start := bytes.LastIndex(raw, marker)
	if start < 0 {
		return nil, errors.New("missing embedded message")
	}
	start += len(marker)
	end := bytes.LastIndex(raw[start:], []byte("\r\n--dsn--\r\n"))
	if end < 0 {
		return nil, errors.New("missing embedded message boundary")
	}
	return bytes.Clone(raw[start : start+end]), nil
}

// runDeliveryStatusMilterHarness drives one exact Milter callback sequence through the real process.
func runDeliveryStatusMilterHarness(
	t *testing.T,
	root string,
	milterBinary string,
	miltertestBinary string,
	service *SigningService,
	request DeliveryStatusRequest,
) {
	t.Helper()
	harnessService := &deliveryStatusHarnessService{
		service: service, result: make(chan deliveryStatusHarnessResult, 1), stages: make(chan string, 16),
	}
	httpResults := make(chan int, 1)
	middlewareResults := make(chan string, 1)
	capability := bytes.Repeat([]byte{0xa5}, 32)
	wantCapability := base64.RawURLEncoding.EncodeToString(capability)
	middleware := func(next generated.StrictHandlerFunc, operationID string) generated.StrictHandlerFunc {
		return func(ctx context.Context, writer http.ResponseWriter, httpRequest *http.Request, input any) (any, error) {
			reason := harnessMiddlewareAuthorized
			switch {
			case operationID != "SignDeliveryStatus":
				reason = "operation"
			case httpRequest.URL.Path != "/v1/dsn/sign":
				reason = "path"
			case httpRequest.Header.Get("X-DKIM2-DSN-Sign-Capability") != wantCapability:
				reason = "dsn_capability"
			case httpRequest.Header.Get("X-DKIM2-Capability") != "":
				reason = "mixed_capability"
			}
			middlewareResults <- reason
			if reason != harnessMiddlewareAuthorized {
				return nil, errors.New("invalid harness route capability")
			}
			return next(ctx, writer, httpRequest, input)
		}
	}
	strict := generated.NewStrictHandler(harnessService, []generated.StrictMiddlewareFunc{middleware})
	strictHandler := generated.HandlerFromMux(strict, http.NewServeMux())
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		statusWriter := &harnessHTTPStatusWriter{ResponseWriter: writer, status: http.StatusOK}
		strictHandler.ServeHTTP(statusWriter, request)
		httpResults <- statusWriter.status
	}))
	t.Cleanup(server.Close)

	caseRoot, err := os.MkdirTemp(root, "case-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(caseRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	capabilityRoot := filepath.Join(caseRoot, "cap")
	if err := os.Mkdir(capabilityRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	capabilityPath := filepath.Join(capabilityRoot, "token")
	if err := os.WriteFile(capabilityPath, capability, 0o400); err != nil {
		t.Fatal(err)
	}
	clear(capability)
	if err := os.Chmod(capabilityRoot, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(capabilityRoot, 0o700) })
	socketPath := filepath.Join(caseRoot, "m.sock")
	milterConfig := filepath.Join(caseRoot, "milter.yaml")
	config := fmt.Sprintf(`version: dkim2-milter-config-v1
server:
  socket: %s
  shutdown_timeout: 1s
daemon:
  endpoint: %s
  capability_file: %s
  request_timeout: 5s
mode: postfix_dsn
signing:
  tenant: %s
  domain_source: verified_embedded
failure:
  mode: tempfail
limits:
  message_bytes: 1048576
  header_bytes: 131072
  header_count: 250
  header_field_bytes: 16384
  recipient_count: 50
`, socketPath, server.URL, capabilityPath, signingServiceTestTenant)
	if err := os.WriteFile(milterConfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(caseRoot, "milter.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	milter := exec.Command(milterBinary, "serve", "--config", milterConfig)
	milter.Stdout, milter.Stderr = logFile, logFile
	if err := milter.Start(); err != nil {
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
	waitForHarnessSocket(t, socketPath, milter, logPath)

	headerBlock, body, err := splitHarnessMessage(request.RawMessage())
	if err != nil {
		t.Fatal(err)
	}
	bodyPath := filepath.Join(caseRoot, "body")
	if err := os.WriteFile(bodyPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(caseRoot, "dsn.lua")
	script := deliveryStatusLuaScript(t, socketPath, bodyPath, headerBlock)
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	oracle := exec.Command(miltertestBinary, "-s", scriptPath)
	oracleOutput, oracleErr := oracle.CombinedOutput()
	if oracleErr != nil {
		logged, _ := os.ReadFile(logPath)
		t.Fatalf("miltertest: %v output=%q milter_log=%q", oracleErr, oracleOutput, logged)
	}

	assertDeliveryStatusHarnessResult(
		t, harnessService, request, httpResults, middlewareResults, logPath, oracleOutput,
	)
	stopDeliveryStatusHarnessMilter(t, milter)
}

// assertDeliveryStatusHarnessResult verifies exact reconstruction and successful application output.
func assertDeliveryStatusHarnessResult(
	t *testing.T,
	service *deliveryStatusHarnessService,
	request DeliveryStatusRequest,
	httpResults <-chan int,
	middlewareResults <-chan string,
	logPath string,
	oracleOutput []byte,
) {
	t.Helper()
	select {
	case got := <-service.result:
		if !bytes.Equal(got.raw, request.RawMessage()) {
			t.Fatalf("Milter reconstruction differed at offset %d left_len=%d right_len=%d",
				firstDifferentByte(got.raw, request.RawMessage()), len(got.raw), len(request.RawMessage()))
		}
		if got.err != nil || !got.result.Valid() || got.result.Result() != OperationPass ||
			got.result.Disposition() != OperationAccept {
			t.Fatalf("application result valid=%t result=%q disposition=%q error=%v",
				got.result.Valid(), got.result.Result(), got.result.Disposition(), got.err)
		}
	case <-time.After(3 * time.Second):
		logged, _ := os.ReadFile(logPath)
		status := 0
		middlewareResult := "not_reached"
		serviceStage := "not_entered"
		select {
		case status = <-httpResults:
		default:
		}
		select {
		case middlewareResult = <-middlewareResults:
		default:
		}
		for {
			select {
			case serviceStage = <-service.stages:
			default:
				t.Fatalf("strict DSN handler was not called http_status=%d middleware=%s service_stage=%s oracle_output=%q milter_log=%q", status, middlewareResult, serviceStage, oracleOutput, logged)
			}
		}
	}
}

// stopDeliveryStatusHarnessMilter terminates and reaps one isolated test process.
func stopDeliveryStatusHarnessMilter(t *testing.T, milter *exec.Cmd) {
	t.Helper()
	if err := milter.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- milter.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Milter did not stop")
	}
}

// deliveryStatusHarnessResponse maps the domain result through the generated wire contract.
func deliveryStatusHarnessResponse(result OperationResult, operationErr error) (generated.OperationResponse, error) {
	if operationErr != nil || !result.Valid() {
		return generated.OperationResponse{}, errors.New("invalid harness operation result")
	}
	actions := make(generated.ActionPlan, len(result.Fields()))
	for index, field := range result.Fields() {
		name, value, err := projectHarnessField(field.Bytes())
		if err != nil {
			return generated.OperationResponse{}, err
		}
		actions[index] = generated.AddHeaderAction{
			Type: generated.AddHeader, Name: generated.AddHeaderActionName(name), Value: value,
		}
	}
	return generated.OperationResponse{
		ApiVersion: generated.V1, Draft: generated.DraftIetfDkimDkim2Spec05,
		Operation:   generated.DeliveryStatus,
		Result:      generated.OperationResponseResult(result.Result()),
		Disposition: generated.Disposition(result.Disposition()), Actions: actions,
	}, nil
}

// projectHarnessField converts one generated RFC 5322 field into an add-header action.
func projectHarnessField(field []byte) (string, string, error) {
	if !bytes.HasSuffix(field, []byte("\r\n")) {
		return "", "", errors.New("invalid harness field")
	}
	colon := bytes.IndexByte(field, ':')
	if colon < 1 {
		return "", "", errors.New("invalid harness field")
	}
	value := field[colon+1 : len(field)-2]
	value = bytes.ReplaceAll(value, []byte("\r\n"), nil)
	return string(field[:colon]), string(value), nil
}

// splitHarnessMessage preserves ordered headers and the exact body for Milter callbacks.
func splitHarnessMessage(raw []byte) ([][2]string, []byte, error) {
	separator := bytes.Index(raw, []byte("\r\n\r\n"))
	if separator < 0 {
		return nil, nil, errors.New("missing harness header boundary")
	}
	lines := bytes.Split(raw[:separator], []byte("\r\n"))
	fields := make([][2]string, 0, len(lines))
	for _, line := range lines {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if len(fields) == 0 {
				return nil, nil, errors.New("orphan harness continuation")
			}
			fields[len(fields)-1][1] += "\r\n" + string(line)
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 1 {
			return nil, nil, errors.New("invalid harness header")
		}
		fields = append(fields, [2]string{string(line[:colon]), string(line[colon+1:])})
	}
	return fields, bytes.Clone(raw[separator+4:]), nil
}

// deliveryStatusLuaScript renders the exact Postfix DSN callback sequence for the sibling oracle.
func deliveryStatusLuaScript(t *testing.T, socketPath, bodyPath string, headers [][2]string) string {
	t.Helper()
	var output strings.Builder
	fmt.Fprintf(&output, "socket_set(\"unix\", %s)\n", luaLongString(socketPath))
	output.WriteString("negotiate(6, 0xffffffff, 0xffffffff)\n")
	output.WriteString("assert_cap(\"actions\", MILTER.SMFIF_SETSYMLIST)\n")
	output.WriteString("assert_macro_requested(MILTER.SMFIM_EOH, \"{postfix_dsn_origin}\")\n")
	output.WriteString("connect(\"localhost\", \"127.0.0.1\")\nhelo(\"localhost\")\nmailfrom(\"<>\")\n")
	output.WriteString("rcptto(\"<sender@" + signingServiceOriginDomain + ">\")\n")
	for _, header := range headers {
		fmt.Fprintf(&output, "header(%s, %s)\n", luaLongString(header[0]), luaLongString(header[1]))
	}
	output.WriteString("macro(\"N\", { [\"{postfix_dsn_origin}\"] = \"internal\" })\n")
	output.WriteString("eoh()\n")
	fmt.Fprintf(&output, "local file = assert(io.open(%s, \"rb\"))\n", luaLongString(bodyPath))
	output.WriteString("while true do local chunk = file:read(4096); if not chunk then break end; body(chunk) end\nfile:close()\n")
	output.WriteString("local actions = eom()\nassert_added_header(actions, \"Message-Instance\")\nassert_added_header(actions, \"DKIM2-Signature\")\nassert_final(actions, \"accept\")\nquit()\n")
	return output.String()
}

// luaLongString encodes one controlled value without escape interpretation.
func luaLongString(value string) string {
	for equals := ""; ; equals += "=" {
		closing := "]" + equals + "]"
		if !strings.Contains(value, closing) {
			return "[" + equals + "[" + value + closing
		}
	}
}

// assertHarnessBinary pins execution to the independently reviewed oracle artifact.
func assertHarnessBinary(t *testing.T, path string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != miltertestHarnessSHA256 {
		t.Fatal("miltertest harness digest did not match the reviewed artifact")
	}
}

// waitForHarnessSocket waits within a fixed bound for the isolated Milter listener.
func waitForHarnessSocket(t *testing.T, path string, process *exec.Cmd, logPath string) {
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
	t.Fatalf("Milter socket not ready output=%q", logged)
}

// firstDifferentByte returns the first mismatched offset or the shared length.
func firstDifferentByte(left, right []byte) int {
	limit := min(len(left), len(right))
	for index := 0; index < limit; index++ {
		if left[index] != right[index] {
			return index
		}
	}
	return limit
}
