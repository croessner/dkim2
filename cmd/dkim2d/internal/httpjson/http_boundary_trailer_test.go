package httpjson

import (
	"bytes"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
	"github.com/getkin/kin-openapi/routers"
)

const trailerSecretMarker = "TRAILER-PRIVATE-MARKER"

type trailerAuditRouter struct {
	delegate   routers.Router
	calls      atomic.Int32
	sawTrailer atomic.Bool
}

// FindRoute records whether trailers survived into OpenAPI route selection.
func (r *trailerAuditRouter) FindRoute(request *http.Request) (*routers.Route, map[string]string, error) {
	r.calls.Add(1)
	if request != nil && request.Trailer != nil {
		r.sawTrailer.Store(true)
	}
	return r.delegate.FindRoute(request)
}

type trailerAuditGeneratedHandler struct {
	generated.ServerInterface
	calls      atomic.Int32
	sawTrailer atomic.Bool
}

// ProcessMessage records whether trailers survived into generated/domain dispatch.
func (h *trailerAuditGeneratedHandler) ProcessMessage(writer http.ResponseWriter, request *http.Request) {
	h.calls.Add(1)
	if request != nil && request.Trailer != nil {
		h.sawTrailer.Store(true)
	}
	h.ServerInterface.ProcessMessage(writer, request)
}

type trailerAuditLog struct {
	mu    sync.Mutex
	bytes bytes.Buffer
}

// Write retains test-server diagnostics behind a race-safe lock.
func (l *trailerAuditLog) Write(value []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.bytes.Write(value)
}

// String returns one detached diagnostic snapshot.
func (l *trailerAuditLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.bytes.String()
}

type rawTrailerServer struct {
	address    string
	handler    *HTTPBoundary
	processor  *boundaryProcessor
	router     *trailerAuditRouter
	generated  *trailerAuditGeneratedHandler
	log        *trailerAuditLog
	capability string
}

// startRawTrailerServer starts the production listener and boundary with trailer observers.
func startRawTrailerServer(t *testing.T, readTimeout time.Duration) *rawTrailerServer {
	t.Helper()

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	tracked, err := newTrackedListener(raw, nil)
	if err != nil {
		_ = raw.Close()
		t.Fatalf("newTrackedListener() error = %v", err)
	}
	validator, err := NewRequestValidator()
	if err != nil {
		_ = tracked.Close()
		t.Fatalf("NewRequestValidator() error = %v", err)
	}
	routerAudit := &trailerAuditRouter{delegate: validator.router}
	validator.router = routerAudit

	secret := bytes.Repeat([]byte{0xa5}, 32)
	readiness := &boundaryReadiness{}
	readiness.ready.Store(true)
	processor := &boundaryProcessor{}
	handler, err := NewHTTPBoundary(BoundaryConfig{
		Authority:       raw.Addr().String(),
		RequestDeadline: 15 * time.Second,
		MaxInFlight:     1,
		MaxWaiters:      1,
		AdmissionWait:   10 * time.Millisecond,
	}, &boundaryCapabilityMatcher{value: secret}, readiness, processor,
		&boundaryFatalNotifier{}, validator)
	if err != nil {
		_ = tracked.Close()
		t.Fatalf("NewHTTPBoundary() error = %v", err)
	}
	generatedAudit := &trailerAuditGeneratedHandler{ServerInterface: handler.generated}
	handler.generated = generatedAudit
	errorLog := &trailerAuditLog{}
	server := &http.Server{
		Handler:                      handler,
		ConnContext:                  tracked.ConnContext,
		ErrorLog:                     log.New(errorLog, "", 0),
		ReadTimeout:                  readTimeout,
		WriteTimeout:                 5 * time.Second,
		DisableGeneralOptionsHandler: true,
	}
	serveDone := make(chan struct{})
	go func() {
		_ = server.Serve(tracked)
		close(serveDone)
	}()
	t.Cleanup(func() {
		handler.Close()
		_ = server.Close()
		_ = tracked.Close()
		<-serveDone
	})
	return &rawTrailerServer{
		address:    raw.Addr().String(),
		handler:    handler,
		processor:  processor,
		router:     routerAudit,
		generated:  generatedAudit,
		log:        errorLog,
		capability: base64.RawURLEncoding.EncodeToString(secret),
	}
}

// processTrailerRequest builds one raw chunked process request and trailer block.
func processTrailerRequest(
	server *rawTrailerServer,
	initialFields string,
	declaration string,
	body string,
	trailerBlock string,
) string {
	return "POST /v1/process HTTP/1.1\r\n" +
		"Host: " + server.address + "\r\n" +
		initialFields +
		declaration +
		"Transfer-Encoding: chunked\r\n\r\n" +
		strconv.FormatInt(int64(len(body)), 16) + "\r\n" +
		body + "\r\n0\r\n" +
		trailerBlock + "\r\n"
}

// validTrailerProcessFields returns authenticated JSON request headers.
func validTrailerProcessFields(server *rawTrailerServer) string {
	return testContentTypeJSONField +
		"X-DKIM2-Capability: " + server.capability + "\r\n"
}

// assertTrailerResourcesReleased waits for final tracked-connection ownership and proves exact release.
func assertTrailerResourcesReleased(t *testing.T, server *rawTrailerServer) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if server.handler.admission.Owned() == 0 &&
			len(server.handler.admission.permits) == 0 &&
			len(server.handler.admission.waiters) == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("trailer path retained admission: owned=%d permits=%d waiters=%d",
		server.handler.admission.Owned(),
		len(server.handler.admission.permits),
		len(server.handler.admission.waiters),
	)
}

// assertTrailerSecretsAbsent verifies neither the wire response nor server diagnostics retain trailer values.
func assertTrailerSecretsAbsent(t *testing.T, server *rawTrailerServer, response string, markers ...string) {
	t.Helper()

	diagnostics := server.log.String()
	for _, marker := range markers {
		if strings.Contains(response, marker) || strings.Contains(diagnostics, marker) {
			t.Fatalf("protected trailer value leaked: response_bytes=%d diagnostic_bytes=%d",
				len(response), len(diagnostics))
		}
	}
}

// TestHTTPBoundaryRawTrailerInertMatrix proves valid trailers are discarded before OpenAPI and domain work.
func TestHTTPBoundaryRawTrailerInertMatrix(t *testing.T) {
	protectedTrailers := "X-DKIM2-Capability: " + trailerSecretMarker + "-CAPABILITY-FIRST\r\n" +
		"X-DKIM2-Capability: " + trailerSecretMarker + "-CAPABILITY-SECOND\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Encoding: gzip\r\n" +
		testExpectContinueField +
		"Host: attacker.invalid\r\n" +
		"Range: bytes=0-1\r\n" +
		"If-Match: *\r\n" +
		"If-None-Match: \"" + trailerSecretMarker + "-ETAG\"\r\n" +
		"If-Range: \"" + trailerSecretMarker + "-RANGE\"\r\n" +
		"If-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\n" +
		"If-Unmodified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\n"
	tests := []struct {
		name         string
		declaration  string
		trailerBlock string
	}{
		{
			name:         "declared",
			declaration:  testPrivateTrailerField,
			trailerBlock: "X-Private: " + trailerSecretMarker + "-DECLARED\r\n",
		},
		{
			name:         "undeclared",
			trailerBlock: "X-Private: " + trailerSecretMarker + "-UNDECLARED\r\n",
		},
		{
			name:        "declared without emitted value",
			declaration: testPrivateTrailerField,
		},
		{
			name:        "duplicates",
			declaration: testPrivateTrailerField,
			trailerBlock: "X-Private: " + trailerSecretMarker + "-FIRST\r\n" +
				"X-Private: " + trailerSecretMarker + "-SECOND\r\n",
		},
		{
			name: "declared protected names",
			declaration: "Trailer: X-DKIM2-Capability, Content-Type, Content-Encoding, Expect, Host, " +
				"Range, If-Match, If-None-Match, If-Range, If-Modified-Since, If-Unmodified-Since\r\n",
			trailerBlock: protectedTrailers,
		},
		{
			name:         "undeclared protected names",
			trailerBlock: protectedTrailers,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			server := startRawTrailerServer(t, 2*time.Second)
			response := rawBoundaryExchange(t, server.address, processTrailerRequest(
				server,
				validTrailerProcessFields(server),
				test.declaration,
				validMinimalProcessJSON,
				test.trailerBlock,
			))
			if !strings.HasPrefix(response, "HTTP/1.1 500 Internal Server Error\r\n") ||
				strings.Contains(response, "100 Continue") ||
				server.processor.calls.Load() != 1 ||
				server.router.calls.Load() != 1 ||
				server.router.sawTrailer.Load() ||
				server.generated.calls.Load() != 1 ||
				server.generated.sawTrailer.Load() {
				t.Fatalf("inert trailer outcome: response_bytes=%d domain=%d router=%d/%t generated=%d/%t",
					len(response),
					server.processor.calls.Load(),
					server.router.calls.Load(),
					server.router.sawTrailer.Load(),
					server.generated.calls.Load(),
					server.generated.sawTrailer.Load(),
				)
			}
			assertTrailerResourcesReleased(t, server)
			assertTrailerSecretsAbsent(t, server, response,
				trailerSecretMarker, "attacker.invalid")
		})
	}
}

// TestHTTPBoundaryRawTrailerCannotMutateLexicalContent proves JSON processing uses only framed body bytes.
func TestHTTPBoundaryRawTrailerCannotMutateLexicalContent(t *testing.T) {
	server := startRawTrailerServer(t, 2*time.Second)
	response := rawBoundaryExchange(t, server.address, processTrailerRequest(
		server,
		validTrailerProcessFields(server),
		"Trailer: X-JSON-Repair\r\n",
		"{",
		"X-JSON-Repair: "+trailerSecretMarker+"-LEXICAL\r\n",
	))
	if !strings.HasPrefix(response, testHTTP11BadRequestLine) ||
		!strings.Contains(response, `"code":"invalid_json"`) ||
		server.processor.calls.Load() != 0 ||
		server.router.calls.Load() != 0 ||
		server.generated.calls.Load() != 0 {
		t.Fatalf("lexical trailer outcome: response_bytes=%d domain=%d router=%d generated=%d",
			len(response),
			server.processor.calls.Load(),
			server.router.calls.Load(),
			server.generated.calls.Load(),
		)
	}
	assertTrailerResourcesReleased(t, server)
	assertTrailerSecretsAbsent(t, server, response, trailerSecretMarker)
}

// TestHTTPBoundaryRawTrailerCannotSupplyProtectedHeaders proves trailer values cannot authorize or select media.
func TestHTTPBoundaryRawTrailerCannotSupplyProtectedHeaders(t *testing.T) {
	tests := []struct {
		name          string
		initialFields string
		declaration   string
		trailerBlock  string
		statusLine    string
	}{
		{
			name:          "capability",
			initialFields: testContentTypeJSONField,
			declaration:   "Trailer: X-DKIM2-Capability\r\n",
			trailerBlock:  "X-DKIM2-Capability: supplied-only-in-trailer\r\n",
			statusLine:    "HTTP/1.1 403 Forbidden\r\n",
		},
		{
			name:          "content type",
			initialFields: "X-DKIM2-Capability: ",
			declaration:   "Trailer: Content-Type\r\n",
			trailerBlock:  testContentTypeJSONField,
			statusLine:    "HTTP/1.1 415 Unsupported Media Type\r\n",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			server := startRawTrailerServer(t, 2*time.Second)
			initialFields := test.initialFields
			if test.name == "content type" {
				initialFields += server.capability + "\r\n"
			}
			response := rawBoundaryExchange(t, server.address, processTrailerRequest(
				server,
				initialFields,
				test.declaration,
				validMinimalProcessJSON,
				test.trailerBlock,
			))
			if !strings.HasPrefix(response, test.statusLine) ||
				server.processor.calls.Load() != 0 ||
				server.router.calls.Load() != 0 ||
				server.generated.calls.Load() != 0 {
				t.Fatalf("protected trailer outcome: response_bytes=%d domain=%d router=%d generated=%d",
					len(response),
					server.processor.calls.Load(),
					server.router.calls.Load(),
					server.generated.calls.Load(),
				)
			}
			assertTrailerResourcesReleased(t, server)
			assertTrailerSecretsAbsent(t, server, response,
				trailerSecretMarker, "supplied-only-in-trailer")
		})
	}
}

// TestHTTPBoundaryRawTrailerFailureMatrix proves malformed framing stays bounded and pre-domain.
func TestHTTPBoundaryRawTrailerFailureMatrix(t *testing.T) {
	tests := []struct {
		name         string
		declaration  string
		trailerBlock string
		statusLine   string
		application  bool
	}{
		{
			name:         "prohibited content length declaration",
			declaration:  "Trailer: Content-Length\r\n",
			trailerBlock: "Content-Length: 1\r\n",
			statusLine:   testHTTP11BadRequestLine,
		},
		{
			name:         "prohibited transfer encoding declaration",
			declaration:  "Trailer: Transfer-Encoding\r\n",
			trailerBlock: testChunkedField,
			statusLine:   testHTTP11BadRequestLine,
		},
		{
			name:         "prohibited trailer declaration",
			declaration:  "Trailer: Trailer\r\n",
			trailerBlock: testPrivateTrailerField,
			statusLine:   testHTTP11BadRequestLine,
		},
		{
			name:         transportTestMalformed,
			declaration:  testPrivateTrailerField,
			trailerBlock: "Malformed-" + trailerSecretMarker + "\r\n",
			statusLine:   testHTTP11BadRequestLine,
			application:  true,
		},
		{
			name:         "oversized",
			declaration:  testPrivateTrailerField,
			trailerBlock: "X-Private: " + trailerSecretMarker + strings.Repeat("x", 8*1024) + "\r\n",
			statusLine:   testHTTP11BadRequestLine,
			application:  true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			server := startRawTrailerServer(t, 2*time.Second)
			response := rawBoundaryExchange(t, server.address, processTrailerRequest(
				server,
				validTrailerProcessFields(server),
				test.declaration,
				validMinimalProcessJSON,
				test.trailerBlock,
			))
			if !strings.HasPrefix(response, test.statusLine) ||
				strings.Contains(response, `"code":"invalid_contract"`) != test.application ||
				server.processor.calls.Load() != 0 ||
				server.router.calls.Load() != 0 ||
				server.generated.calls.Load() != 0 {
				t.Fatalf("invalid trailer outcome: response_bytes=%d domain=%d router=%d generated=%d",
					len(response),
					server.processor.calls.Load(),
					server.router.calls.Load(),
					server.generated.calls.Load(),
				)
			}
			assertTrailerResourcesReleased(t, server)
			assertTrailerSecretsAbsent(t, server, response, trailerSecretMarker)
		})
	}
}

// rawPartialTrailerExchange writes an incomplete trailer and optionally closes the client write side.
func rawPartialTrailerExchange(
	t *testing.T,
	address string,
	request string,
	closeWrite bool,
) string {
	t.Helper()

	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = connection.Close() }()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	if closeWrite {
		tcpConnection, ok := connection.(*net.TCPConn)
		if !ok {
			t.Fatal("loopback connection is not TCP")
		}
		if err := tcpConnection.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite() error = %v", err)
		}
	}
	response, _ := io.ReadAll(connection)
	return string(response)
}

// incompleteTrailerRequest builds a valid body followed by an unterminated trailer.
func incompleteTrailerRequest(server *rawTrailerServer) string {
	return "POST /v1/process HTTP/1.1\r\n" +
		"Host: " + server.address + "\r\n" +
		validTrailerProcessFields(server) +
		testPrivateTrailerField +
		"Transfer-Encoding: chunked\r\n\r\n" +
		strconv.FormatInt(int64(len(validMinimalProcessJSON)), 16) + "\r\n" +
		validMinimalProcessJSON + "\r\n0\r\n" +
		"X-Private: " + trailerSecretMarker
}

// TestHTTPBoundaryRawTrailerTimeoutAndDisconnect freezes 408 versus response suppression.
func TestHTTPBoundaryRawTrailerTimeoutAndDisconnect(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		server := startRawTrailerServer(t, 100*time.Millisecond)
		response := rawPartialTrailerExchange(t, server.address, incompleteTrailerRequest(server), false)
		if !strings.HasPrefix(response, "HTTP/1.1 408 Request Timeout\r\n") ||
			!strings.Contains(response, `"code":"request_timeout"`) ||
			server.processor.calls.Load() != 0 ||
			server.router.calls.Load() != 0 ||
			server.router.sawTrailer.Load() ||
			server.generated.calls.Load() != 0 ||
			server.generated.sawTrailer.Load() {
			t.Fatalf("timeout trailer outcome: response_bytes=%d domain=%d router=%d/%t generated=%d/%t",
				len(response),
				server.processor.calls.Load(),
				server.router.calls.Load(),
				server.router.sawTrailer.Load(),
				server.generated.calls.Load(),
				server.generated.sawTrailer.Load(),
			)
		}
		assertTrailerResourcesReleased(t, server)
		assertTrailerSecretsAbsent(t, server, response, trailerSecretMarker)
	})

	t.Run("disconnect", func(t *testing.T) {
		server := startRawTrailerServer(t, 2*time.Second)
		response := rawPartialTrailerExchange(t, server.address, incompleteTrailerRequest(server), true)
		if response != "" ||
			server.processor.calls.Load() != 0 ||
			server.router.calls.Load() != 0 ||
			server.router.sawTrailer.Load() ||
			server.generated.calls.Load() != 0 ||
			server.generated.sawTrailer.Load() {
			t.Fatalf("disconnect trailer outcome: response_bytes=%d domain=%d router=%d/%t generated=%d/%t",
				len(response),
				server.processor.calls.Load(),
				server.router.calls.Load(),
				server.router.sawTrailer.Load(),
				server.generated.calls.Load(),
				server.generated.sawTrailer.Load(),
			)
		}
		assertTrailerResourcesReleased(t, server)
		assertTrailerSecretsAbsent(t, server, response, trailerSecretMarker)
	})
}

type trailerRepeatingReader struct{}

// Read fills the requested chunk without allocating a source body.
func (trailerRepeatingReader) Read(output []byte) (int, error) {
	for index := range output {
		output[index] = 'x'
	}
	return len(output), nil
}

// rawBodyLimitTrailerExchange streams one max-plus-one chunk followed by malformed trailers.
func rawBodyLimitTrailerExchange(t *testing.T, server *rawTrailerServer) string {
	t.Helper()

	connection, err := net.DialTimeout("tcp", server.address, time.Second)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = connection.Close() }()
	_ = connection.SetDeadline(time.Now().Add(20 * time.Second))
	head := "POST /v1/process HTTP/1.1\r\n" +
		"Host: " + server.address + "\r\n" +
		validTrailerProcessFields(server) +
		testPrivateTrailerField +
		"Transfer-Encoding: chunked\r\n\r\n" +
		strconv.FormatInt(maxProcessBodyBytes+1, 16) + "\r\n"
	if _, err := io.WriteString(connection, head); err != nil {
		t.Fatalf("write request head error = %v", err)
	}
	if _, err := io.CopyN(connection, trailerRepeatingReader{}, maxProcessBodyBytes+1); err != nil {
		t.Fatalf("write max-plus-one chunk error = %v", err)
	}
	_, _ = io.WriteString(connection,
		"\r\n0\r\nMalformed-"+trailerSecretMarker+"\r\n\r\n")
	if tcpConnection, ok := connection.(*net.TCPConn); ok {
		_ = tcpConnection.CloseWrite()
	}
	response, _ := io.ReadAll(connection)
	return string(response)
}

// TestHTTPBoundaryRawBodyLimitPrecedesMalformedTrailer freezes the outer 413 race outcome.
func TestHTTPBoundaryRawBodyLimitPrecedesMalformedTrailer(t *testing.T) {
	if testing.Short() {
		t.Skip("max-plus-one raw body integration is not a short test")
	}
	server := startRawTrailerServer(t, 20*time.Second)
	response := rawBodyLimitTrailerExchange(t, server)
	if !strings.HasPrefix(response, "HTTP/1.1 413 Request Entity Too Large\r\n") ||
		!strings.Contains(response, `"code":"request_too_large"`) ||
		strings.Contains(response, `"code":"invalid_contract"`) ||
		server.processor.calls.Load() != 0 ||
		server.router.calls.Load() != 0 ||
		server.generated.calls.Load() != 0 {
		t.Fatalf("body-limit trailer race outcome: response_bytes=%d domain=%d router=%d generated=%d",
			len(response),
			server.processor.calls.Load(),
			server.router.calls.Load(),
			server.generated.calls.Load(),
		)
	}
	assertTrailerResourcesReleased(t, server)
	assertTrailerSecretsAbsent(t, server, response, trailerSecretMarker)
}
