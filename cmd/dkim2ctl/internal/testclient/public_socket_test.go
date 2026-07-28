package testclient

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2ctl/internal/testclient/generated"
)

// TestRuntimePublicSocketSmoke exercises the owned dialer, generated client,
// parsed response metadata, and close lifecycle over a real loopback socket.
func TestRuntimePublicSocketSmoke(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("loopback listeners are unavailable in this test environment")
	}
	defer func() { _ = listener.Close() }()
	serverDone := make(chan error, 1)
	go serveOneHealthResponse(listener, serverDone)

	options := DefaultOptions()
	options.ServerURL = "http://" + listener.Addr().String()
	runtime, err := NewRuntime(options)
	if err != nil {
		t.Fatal("construct public-socket runtime")
	}
	defer func() { _ = runtime.Close() }()
	fact, err := runtime.CallHealth(t.Context())
	if err != nil || fact.Health == nil || fact.Status != http.StatusOK {
		t.Fatal("public-socket generated health call failed")
	}
	select {
	case serverErr := <-serverDone:
		if serverErr != nil {
			t.Fatal("public-socket responder failed")
		}
	case <-time.After(time.Second):
		t.Fatal("public-socket responder did not terminate")
	}
}

// TestIndependentSocketOracleGeneratedOperationMatrix crosses protected files,
// loopback transport, generated DTOs, complete responses, and stable output.
func TestIndependentSocketOracleGeneratedOperationMatrix(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("loopback listeners are unavailable in this test environment")
	}
	processSecret := bytes.Repeat([]byte{0xa5}, 32)
	signSecret := bytes.Repeat([]byte{0xb6}, 32)
	reviseSecret := bytes.Repeat([]byte{0xc7}, 32)
	handler := &conformanceService{
		capabilities: map[string][]byte{
			processPath: processSecret,
			signPath:    signSecret,
			revisePath:  reviseSecret,
		},
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
		<-done
	})

	directory := t.TempDir()
	processCapability := filepath.Join(directory, "process-capability")
	signCapability := filepath.Join(directory, "sign-capability")
	reviseCapability := filepath.Join(directory, "revise-capability")
	for path, value := range map[string][]byte{
		processCapability: processSecret,
		signCapability:    signSecret,
		reviseCapability:  reviseSecret,
	} {
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal("write protected operation capability")
		}
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("fixture source unavailable")
	}
	fixtures := filepath.Join(
		filepath.Dir(filepath.Dir(filepath.Dir(source))),
		"testdata", "fixtures", draftVersion,
	)
	paths := []string{
		filepath.Join(fixtures, "health.json"),
		filepath.Join(fixtures, "process-negative.json"),
		filepath.Join(fixtures, "process-report.json"),
		filepath.Join(fixtures, "process.json"),
		filepath.Join(fixtures, "revise.json"),
		filepath.Join(fixtures, "route-negative.json"),
		filepath.Join(fixtures, "sign.json"),
	}
	options := DefaultOptions()
	options.ServerURL = "http://" + listener.Addr().String()
	options.CapabilityFile = processCapability
	options.SignCapabilityFile = signCapability
	options.ReviseCapabilityFile = reviseCapability
	var output bytes.Buffer
	if err := NewApplication(&output).Run(options, paths); err != nil {
		t.Fatalf(
			"independent oracle fixture matrix failed with %s after %d calls and %d output bytes",
			ExitClassOf(err).String(),
			handler.calls.Load(),
			output.Len(),
		)
	}
	if handler.calls.Load() != 21 {
		t.Fatalf("independent oracle calls = %d, want 21", handler.calls.Load())
	}
	text := output.String()
	for _, marker := range []string{
		operationFixtureDomain, "synthetic", base64.RawURLEncoding.EncodeToString(processSecret),
		base64.RawURLEncoding.EncodeToString(signSecret),
		base64.RawURLEncoding.EncodeToString(reviseSecret),
		operationFixtureMessageBase64,
	} {
		if strings.Contains(text, marker) {
			t.Fatal("independent oracle result leaked protected fixture material")
		}
	}
	if strings.Count(text, "\n") != 21 ||
		!strings.Contains(text, `"operation":"sign","outcome":"match"`) ||
		!strings.Contains(text, `"operation":"revise","outcome":"match"`) {
		t.Fatal("independent oracle results lost deterministic typed outcomes")
	}
}

// conformanceService is one daemon-compatible real-socket oracle.
type conformanceService struct {
	capabilities map[string][]byte
	calls        atomic.Int32
}

// ServeHTTP validates generated requests and emits complete daemon responses.
func (s *conformanceService) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	s.calls.Add(1)
	switch request.URL.Path {
	case healthPath:
		s.writeJSON(writer, http.StatusOK, healthResponseBody, true)
		return
	case "/readyz":
		s.writeJSON(
			writer, http.StatusOK,
			`{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","status":"ready"}`,
			true,
		)
		return
	case processPath, signPath, revisePath:
	default:
		s.writeError(writer, http.StatusNotFound, "not_found")
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		s.writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	expected := s.capabilities[request.URL.Path]
	values := request.Header.Values(capabilityHeader)
	if len(values) != 1 {
		s.writeError(writer, http.StatusForbidden, expectedForbiddenCode)
		return
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(values[0])
	if err != nil || !bytes.Equal(decoded, expected) {
		s.writeError(writer, http.StatusForbidden, expectedForbiddenCode)
		return
	}
	if request.Header.Get("Content-Type") != mediaTypeJSON {
		s.writeError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	if request.URL.RawQuery != "" {
		s.writeError(writer, http.StatusBadRequest, "invalid_contract")
		return
	}
	if request.ContentLength > daemonProcessBodyLimit {
		if _, err := io.CopyN(
			io.Discard,
			request.Body,
			daemonProcessBodyLimit+1,
		); err != nil {
			s.writeError(writer, http.StatusBadRequest, "invalid_contract")
			return
		}
		s.writeError(writer, http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	switch request.URL.Path {
	case processPath:
		s.serveProcess(writer, request)
	case signPath:
		s.serveSign(writer, request)
	case revisePath:
		s.serveRevise(writer, request)
	}
}

// serveProcess returns reporting PASS or the frozen malformed-message result.
func (s *conformanceService) serveProcess(writer http.ResponseWriter, request *http.Request) {
	var input generated.ProcessRequest
	if !decodeGeneratedBody(request, &input) {
		code := expectedInvalidJSONCode
		if request.ContentLength > int64(len(fixedNegativeBody)) {
			code = "invalid_contract"
		}
		s.writeError(writer, http.StatusBadRequest, code)
		return
	}
	if input.Reporting != nil {
		s.writeJSON(writer, http.StatusOK, processReportResponse, false)
		return
	}
	s.writeJSON(writer, http.StatusOK, validProcessResponseBody, false)
}

// serveSign returns accepting or no-mutation originator evidence.
func (s *conformanceService) serveSign(writer http.ResponseWriter, request *http.Request) {
	var input generated.SignRequest
	if !decodeGeneratedBody(request, &input) {
		s.writeError(writer, http.StatusBadRequest, "invalid_json")
		return
	}
	if input.Context.Tenant == "tenant-no-mutation" {
		s.writeJSON(writer, http.StatusOK, signContinueResponse, false)
		return
	}
	s.writeJSON(writer, http.StatusOK, signAcceptResponse, false)
}

// serveRevise returns one- or two-header revision evidence.
func (s *conformanceService) serveRevise(writer http.ResponseWriter, request *http.Request) {
	var input generated.ReviseRequest
	if !decodeGeneratedBody(request, &input) {
		s.writeError(writer, http.StatusBadRequest, "invalid_json")
		return
	}
	if input.Context.Tenant == "tenant-unchanged" {
		s.writeJSON(writer, http.StatusOK, reviseUnchangedResponse, false)
		return
	}
	s.writeJSON(writer, http.StatusOK, reviseChangedResponse, false)
}

// writeError emits one complete request-category OpenAPI error.
func (s *conformanceService) writeError(
	writer http.ResponseWriter,
	status int,
	code string,
) {
	body := `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","code":"` +
		code + `","category":"request"}`
	s.writeJSON(writer, status, body, false)
}

// writeJSON emits exact daemon response metadata and one bounded body.
func (*conformanceService) writeJSON(
	writer http.ResponseWriter,
	status int,
	body string,
	etag bool,
) {
	writer.Header().Set("Cache-Control", cacheNoStore)
	writer.Header().Set("X-Content-Type-Options", contentNoSniff)
	writer.Header().Set("Content-Type", mediaTypeJSON)
	writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
	writer.Header().Set("Connection", connectionClose)
	if etag {
		writer.Header().Set(
			"ETag",
			`"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`,
		)
	}
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, body)
}

// decodeGeneratedBody decodes one exact generated request and closes ownership.
func decodeGeneratedBody(request *http.Request, destination any) bool {
	if request == nil || request.Body == nil {
		return false
	}
	defer func() { _ = request.Body.Close() }()
	decoder := json.NewDecoder(io.LimitReader(request.Body, maxFixtureBytes))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil {
		return false
	}
	var trailing any
	return decoder.Decode(&trailing) == io.EOF
}

const processReportResponse = `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","verification":{"state":"PASS","primary_reason":"none","scope":"current","historical_content":"not_evaluated","historical_signatures":"not_evaluated","custody_structure":"not_present","checks":[{"class":"protocol","reason":"none"}],"signature_sets":[]},"policy":{"mode":"strict","verdict":"accept","primary_reason":"protocol_pass","do_not_modify":"not_evaluated","do_not_explode":"not_evaluated","dns_testing_effective":false,"feedback":{"requested":false,"relay_required":false,"history_coverage":"not_evaluated"},"findings":[{"reason":"protocol_pass","severity":"info"}]},"replay":{"class":"first_seen"},"disposition":"accept","actions":[{"type":"add_header","name":"Authentication-Results","value":"mx.example.test; dkim2=pass"}]}`
const signContinueResponse = `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","operation":"sign","result":"pass","disposition":"continue","actions":[]}`
const reviseUnchangedResponse = `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","operation":"revise","result":"pass","disposition":"accept","actions":[{"type":"add_header","name":"DKIM2-Signature","value":"v=1; a=ed25519-sha256; d=example.test; s=test; b=unchanged"}]}`
const reviseChangedResponse = `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","operation":"revise","result":"pass","disposition":"accept","actions":[{"type":"add_header","name":"Message-Instance","value":"v=1; i=2; h=sha256:synthetic"},{"type":"add_header","name":"DKIM2-Signature","value":"v=1; a=ed25519-sha256; d=example.test; s=test; b=changed"}]}`

// serveOneHealthResponse serves one exact daemon-compatible health response.
func serveOneHealthResponse(listener net.Listener, done chan<- error) {
	connection, err := listener.Accept()
	if err != nil {
		done <- err
		return
	}
	defer func() { _ = connection.Close() }()
	request, err := http.ReadRequest(bufio.NewReader(connection))
	if err != nil || request.Method != http.MethodGet || request.URL.Path != healthPath {
		done <- fmt.Errorf("invalid health request")
		return
	}
	if request.Body != nil {
		_ = request.Body.Close()
	}
	body := healthResponseBody
	response := "HTTP/1.1 200 OK\r\n" +
		"Cache-Control: no-store\r\n" +
		"X-Content-Type-Options: nosniff\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		`ETag: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"` + "\r\n" +
		"Connection: close\r\n\r\n" + body
	_, err = connection.Write([]byte(response))
	done <- err
}
