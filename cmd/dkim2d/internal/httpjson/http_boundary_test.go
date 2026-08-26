package httpjson

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
)

const boundaryTestAuthority = "127.0.0.1:8080"

const boundaryNotifierPrivateMarker = "BOUNDARY-NOTIFIER-PRIVATE"

type boundaryCapabilityMatcher struct {
	value []byte
}

type boundaryBlockingWriteConn struct {
	net.Conn
	writeStarted chan struct{}
	allowWrite   chan struct{}
	terminal     chan struct{}
	writeOnce    sync.Once
	closeOnce    sync.Once
}

// newBoundaryBlockingWriteConn constructs one server-side blocked output owner.
func newBoundaryBlockingWriteConn(connection net.Conn) *boundaryBlockingWriteConn {
	return &boundaryBlockingWriteConn{
		Conn:         connection,
		writeStarted: make(chan struct{}),
		allowWrite:   make(chan struct{}),
		terminal:     make(chan struct{}),
	}
}

// Write blocks the first final flush until the test releases socket ownership.
func (c *boundaryBlockingWriteConn) Write(value []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeStarted) })
	<-c.allowWrite
	return c.Conn.Write(value)
}

// Close publishes terminal raw ownership exactly once.
func (c *boundaryBlockingWriteConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { close(c.terminal) })
	return err
}

// startRawBoundaryServer starts the production tracked listener/filter assembly.
func startRawBoundaryServer(t *testing.T) (string, *HTTPBoundary) {
	t.Helper()
	return startRawBoundaryServerWithDate(t, nil)
}

// startRawBoundaryServerWithDate starts the production assembly with one injected Date source.
func startRawBoundaryServerWithDate(
	t *testing.T,
	dateProvider func() (string, bool),
) (string, *HTTPBoundary) {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	tracked, err := newTrackedListener(raw, dateProvider)
	if err != nil {
		_ = raw.Close()
		t.Fatalf("newTrackedListener() error = %v", err)
	}
	validator, err := NewRequestValidator()
	if err != nil {
		_ = tracked.Close()
		t.Fatalf("NewRequestValidator() error = %v", err)
	}
	secret := bytes.Repeat([]byte{0xa5}, 32)
	readiness := &boundaryReadiness{}
	readiness.ready.Store(true)
	handler, err := NewHTTPBoundary(BoundaryConfig{
		Authority:       raw.Addr().String(),
		RequestDeadline: time.Second,
		MaxInFlight:     1,
		MaxWaiters:      1,
		AdmissionWait:   10 * time.Millisecond,
	}, &boundaryCapabilityMatcher{value: secret}, readiness, &boundaryProcessor{},
		&boundaryFatalNotifier{}, validator)
	if err != nil {
		_ = tracked.Close()
		t.Fatalf("NewHTTPBoundary() error = %v", err)
	}
	server := &http.Server{
		Handler:                      handler,
		ConnContext:                  tracked.ConnContext,
		ErrorLog:                     log.New(io.Discard, "", 0),
		DisableGeneralOptionsHandler: true,
		MaxHeaderBytes:               transportServerMaxHeaderBytes,
	}
	go func() { _ = server.Serve(tracked) }()
	t.Cleanup(func() {
		handler.Close()
		_ = server.Close()
		_ = tracked.Close()
	})
	return raw.Addr().String(), handler
}

// rawBoundaryExchange sends one request and reads the one-request-close response.
func rawBoundaryExchange(t *testing.T, address, request string) string {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = connection.Close() }()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	response, _ := io.ReadAll(connection)
	return string(response)
}

// Equal compares one decoded local test capability.
func (m *boundaryCapabilityMatcher) Equal(value []byte) bool {
	return bytes.Equal(m.value, value)
}

type boundaryReadiness struct {
	ready atomic.Bool
}

// Ready returns the current test readiness snapshot.
func (r *boundaryReadiness) Ready() bool { return r != nil && r.ready.Load() }

type boundaryFatalNotifier struct {
	calls      atomic.Int32
	panicValue any
}

// NotifyFatal records one content-free fatal boundary notification.
func (n *boundaryFatalNotifier) NotifyFatal() {
	n.calls.Add(1)
	if n.panicValue != nil {
		panic(n.panicValue)
	}
}

type boundaryProcessor struct {
	calls atomic.Int32
}

type panicGeneratedHandler struct {
	generated.ServerInterface
	commit bool
	value  any
}

type silentGeneratedHandler struct {
	generated.ServerInterface
}

// ProcessMessage returns without committing to expose net/http finishRequest.
func (*silentGeneratedHandler) ProcessMessage(
	writer http.ResponseWriter,
	_ *http.Request,
) {
	writer.Header().Set("Connection", testCloseValue)
}

// ProcessMessage injects one controlled generated-boundary panic.
func (h *panicGeneratedHandler) ProcessMessage(
	writer http.ResponseWriter,
	_ *http.Request,
) {
	if h.commit {
		writer.WriteHeader(http.StatusOK)
	}
	panic(h.value)
}

// Process records domain entry and returns one intentionally invalid test result.
func (p *boundaryProcessor) Process(
	context.Context,
	dkim2.VerifyRequest,
) (app.InboundResult, error) {
	p.calls.Add(1)
	return app.InboundResult{}, nil
}

// newBoundaryFixture constructs one fully generated/runtime-validated handler.
func newBoundaryFixture(
	t *testing.T,
) (*HTTPBoundary, *boundaryReadiness, *boundaryProcessor, []byte) {
	t.Helper()
	validator, err := NewRequestValidator()
	if err != nil {
		t.Fatalf("NewRequestValidator() error = %v", err)
	}
	secret := bytes.Repeat([]byte{0xa5}, 32)
	readiness := &boundaryReadiness{}
	readiness.ready.Store(true)
	processor := &boundaryProcessor{}
	handler, err := NewHTTPBoundary(BoundaryConfig{
		Authority:       boundaryTestAuthority,
		RequestDeadline: time.Minute,
		MaxInFlight:     1,
		MaxWaiters:      1,
		AdmissionWait:   10 * time.Millisecond,
	}, &boundaryCapabilityMatcher{value: secret}, readiness, processor,
		&boundaryFatalNotifier{}, validator)
	if err != nil {
		t.Fatalf("NewHTTPBoundary() error = %v", err)
	}
	return handler, readiness, processor, secret
}

// boundaryRequest installs one real immutable transport-state snapshot.
func boundaryRequest(
	method string,
	target string,
	body string,
	facts transportFacts,
) (*http.Request, *transportState) {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Host = boundaryTestAuthority
	state := newTransportState(nil)
	if facts.protoMajor == 0 {
		facts.protoMajor = 1
		facts.protoMinor = 1
	}
	if facts.hostCount == 0 && facts.hostValue == "" {
		facts.hostCount = 1
		facts.hostValue = boundaryTestAuthority
	}
	state.publishFacts(facts)
	request = request.WithContext(context.WithValue(request.Context(), transportContextKey{}, state))
	return request, state
}

// serveBoundary captures only the intentional net/http abort sentinel in direct tests.
func serveBoundary(
	handler *HTTPBoundary,
	writer http.ResponseWriter,
	request *http.Request,
) (aborted bool) {
	defer func() {
		recovered := recover()
		if recovered == http.ErrAbortHandler {
			aborted = true
		} else if recovered != nil {
			panic(recovered)
		}
	}()
	handler.ServeHTTP(writer, request)
	return false
}

// TestBoundaryAbortSignalHasStablePointerIdentity pins non-zero private storage.
func TestBoundaryAbortSignalHasStablePointerIdentity(t *testing.T) {
	if unsafe.Sizeof(boundaryAbortSignal{}) == 0 {
		t.Fatal("private boundary abort signal has zero-size storage")
	}
}

// TestHTTPBoundaryRequiresFatalNotifier rejects absent and typed-nil shutdown seams.
func TestHTTPBoundaryRequiresFatalNotifier(t *testing.T) {
	validator, err := NewRequestValidator()
	if err != nil {
		t.Fatal("validator construction failed")
	}
	readiness := &boundaryReadiness{}
	readiness.ready.Store(true)
	var typedNil *boundaryFatalNotifier
	for _, notifier := range []FatalNotifier{nil, typedNil} {
		handler, boundaryErr := NewHTTPBoundary(BoundaryConfig{
			Authority:       boundaryTestAuthority,
			RequestDeadline: time.Second,
			MaxInFlight:     1,
			MaxWaiters:      0,
		}, &boundaryCapabilityMatcher{value: bytes.Repeat([]byte{0xa5}, 32)},
			readiness, &boundaryProcessor{}, notifier, validator)
		if handler != nil || !errors.Is(boundaryErr, errHTTPBoundaryConfig) {
			t.Fatal("missing fatal notifier did not fail closed")
		}
	}
}

// TestHTTPBoundaryRequiresTrackedStateAndServesExactHealth proves fail-closed assembly.
func TestHTTPBoundaryRequiresTrackedStateAndServesExactHealth(t *testing.T) {
	handler, _, processor, _ := newBoundaryFixture(t)
	notifier := &boundaryFatalNotifier{}
	handler.fatal = notifier
	untracked := httptest.NewRequest(http.MethodGet, "http://"+boundaryTestAuthority+testHealthPath, nil)
	untrackedRecorder := httptest.NewRecorder()
	if !serveBoundary(handler, untrackedRecorder, untracked) ||
		untrackedRecorder.Body.Len() != 0 || notifier.calls.Load() != 0 {
		t.Fatal("untracked request did not abort without content")
	}

	request, state := boundaryRequest(
		http.MethodGet,
		"http://"+boundaryTestAuthority+testHealthPath,
		"",
		transportFacts{},
	)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.Len() == 0 ||
		recorder.Header().Get("ETag") == "" || recorder.Header().Get("Content-Length") == "" {
		t.Fatal("tracked health response differs")
	}
	if _, _, ok := state.ConsumeHost(); ok || processor.calls.Load() != 0 ||
		notifier.calls.Load() != 0 {
		t.Fatal("Host was not consumed once or health entered domain")
	}
}

// TestHTTPBoundaryFreezesHostTargetAndPrefacePrecedence proves outer route ordering.
func TestHTTPBoundaryFreezesHostTargetAndPrefacePrecedence(t *testing.T) {
	handler, _, _, _ := newBoundaryFixture(t)
	tests := []struct {
		name   string
		method string
		target string
		facts  transportFacts
		status int
	}{
		{
			name:   "missing host before target cap",
			method: http.MethodGet,
			target: "http://" + boundaryTestAuthority + testHealthPath,
			facts: transportFacts{
				protoMajor: 1, protoMinor: 0, requestTargetOverLimit: true,
			},
			status: http.StatusBadRequest,
		},
		{
			name:   "escaped path",
			method: http.MethodGet,
			target: "http://" + boundaryTestAuthority + "/health%7a",
			facts:  transportFacts{},
			status: http.StatusBadRequest,
		},
		{
			name:   "connect origin form",
			method: http.MethodConnect,
			target: "http://" + boundaryTestAuthority + testHealthPath,
			facts:  transportFacts{},
			status: http.StatusBadRequest,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, _ := boundaryRequest(test.method, test.target, "", test.facts)
			if test.name == "missing host before target cap" {
				state, _ := transportStateFromContext(request.Context())
				state.facts.Store(&transportFacts{
					protoMajor: 1, protoMinor: 0, requestTargetOverLimit: true,
				})
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d", recorder.Code, test.status)
			}
		})
	}

	request, _ := boundaryRequest("PRI", "*", "", transportFacts{
		protoMajor: 2,
		protoMinor: 0,
		hostCount:  0,
	})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusHTTPVersionNotSupported ||
		recorder.Header().Get("Content-Length") != "0" ||
		recorder.Header().Get(headerContentType) != "" || recorder.Body.Len() != 0 {
		t.Fatal("explicit PRI 505 shape differs")
	}
}

// TestHTTPBoundaryMapsExpectByVersionAndRoute proves RFC expectation policy.
func TestHTTPBoundaryMapsExpectByVersionAndRoute(t *testing.T) {
	handler, _, _, _ := newBoundaryFixture(t)
	for _, path := range []string{testHealthPath, "*"} {
		for _, expect := range []expectClass{expectContinue, expectUnsupported, expectMalformed} {
			target := "http://" + boundaryTestAuthority + path
			if path == "*" {
				target = "http://" + boundaryTestAuthority + "/"
			}
			request, _ := boundaryRequest(http.MethodGet, target, "", transportFacts{
				expect: expect,
			})
			if path == "*" {
				request.Method = http.MethodOptions
				request.RequestURI = "*"
				request.URL.Path = "*"
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusExpectationFailed {
				t.Fatalf("%s expect %d status = %d", path, expect, recorder.Code)
			}
		}
	}
	request, _ := boundaryRequest(http.MethodGet, "http://"+boundaryTestAuthority+testHealthPath, "", transportFacts{
		protoMajor: 1,
		protoMinor: 0,
		expect:     expectContinue,
	})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("HTTP/1.0 continue status = %d", recorder.Code)
	}
}

// TestHTTPBoundaryRunsGeneratedProcessAfterOASAndMapsCanonicalFailures proves production composition.
func TestHTTPBoundaryRunsGeneratedProcessAfterOASAndMapsCanonicalFailures(t *testing.T) {
	handler, _, processor, secret := newBoundaryFixture(t)
	body := `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-05","message":{"raw_rfc5322_base64":"*"},"smtp":{"mail_from":"","rcpt_to":[""]}}`
	request, _ := boundaryRequest(http.MethodPost, "http://"+boundaryTestAuthority+testProcessPath, body, transportFacts{})
	request.Header.Set(headerContentType, testContentTypeJSON)
	request.Header.Set(localCapabilityHeader, base64.RawURLEncoding.EncodeToString(secret))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest ||
		!strings.Contains(recorder.Body.String(), `"code":"invalid_contract"`) ||
		processor.calls.Load() != 0 {
		t.Fatalf("canonical failure = %d/%q calls=%d", recorder.Code, recorder.Body.String(), processor.calls.Load())
	}
}

// TestHTTPBoundaryRecoverySeparatesPrivateAndDependencyPanics freezes closure.
func TestHTTPBoundaryRecoverySeparatesPrivateAndDependencyPanics(t *testing.T) {
	body := validMinimalProcessJSON
	tests := []struct {
		name          string
		panicValue    any
		commit        bool
		notifierPanic bool
		status        int
		abort         bool
	}{
		{name: "ordinary before commit", panicValue: errors.New("test panic"), status: http.StatusInternalServerError},
		{name: "distinct private type is ordinary", panicValue: &boundaryAbortSignal{tag: 1}, status: http.StatusInternalServerError},
		{name: "public abort sentinel is ordinary", panicValue: http.ErrAbortHandler, status: http.StatusInternalServerError},
		{name: "notifier panic is contained", panicValue: errors.New("test panic"), notifierPanic: true, status: http.StatusInternalServerError},
		{name: "panic after commit", panicValue: errors.New("late test panic"), commit: true, status: http.StatusOK, abort: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			handler, _, _, secret := newBoundaryFixture(t)
			notifier := &boundaryFatalNotifier{}
			if testCase.notifierPanic {
				notifier.panicValue = boundaryNotifierPrivateMarker
			}
			handler.fatal = notifier
			handler.generated = &panicGeneratedHandler{
				ServerInterface: handler.generated,
				commit:          testCase.commit,
				value:           testCase.panicValue,
			}
			request, state := boundaryRequest(
				http.MethodPost,
				"http://"+boundaryTestAuthority+testProcessPath,
				body,
				transportFacts{},
			)
			request.Header.Set(headerContentType, testContentTypeJSON)
			request.Header.Set(
				localCapabilityHeader,
				base64.RawURLEncoding.EncodeToString(secret),
			)
			recorder := httptest.NewRecorder()
			aborted := serveBoundary(handler, recorder, request)
			state.finishTransportOwnership()
			if aborted != testCase.abort || recorder.Code != testCase.status {
				t.Fatalf("recovery = abort %v/status %d, want %v/%d",
					aborted, recorder.Code, testCase.abort, testCase.status)
			}
			if notifier.calls.Load() != 1 ||
				strings.Contains(recorder.Body.String(), boundaryNotifierPrivateMarker) {
				t.Fatal("panic notification count or privacy differs")
			}
			if testCase.commit && strings.Contains(recorder.Body.String(), `"internal_error"`) {
				t.Fatal("late panic appended a second final response")
			}
			if handler.admission.Owned() != 0 {
				t.Fatal("panic path retained process reservation")
			}
		})
	}
}

// TestHTTPBoundaryRawAssemblyFreezesCoreWireShapes proves tracked end-to-end composition.
func TestHTTPBoundaryRawAssemblyFreezesCoreWireShapes(t *testing.T) {
	address, _ := startRawBoundaryServer(t)
	health := rawBoundaryExchange(t, address,
		"GET /healthz HTTP/1.1\r\nHost: "+address+"\r\n\r\n")
	if !strings.HasPrefix(health, testHTTP11OKLine) ||
		!strings.Contains(health, "\r\nConnection: close\r\n") ||
		!strings.Contains(health, `"status":"alive"`) {
		t.Fatalf("health wire response differs: %q", health)
	}
	head := rawBoundaryExchange(t, address,
		"HEAD /healthz HTTP/1.1\r\nHost: "+address+"\r\n\r\n")
	if !strings.HasPrefix(head, testHTTP11OKLine) ||
		strings.Contains(head, `"status":"alive"`) {
		t.Fatalf("HEAD wire response differs: %q", head)
	}
	options := rawBoundaryExchange(t, address,
		"OPTIONS * HTTP/1.1\r\nHost: "+address+"\r\n\r\n")
	if !strings.HasPrefix(options, testHTTP11NoContentLine) ||
		!strings.Contains(options, "Allow: "+testServerAllowMethods+"\r\n") {
		t.Fatalf("OPTIONS wire response differs: %q", options)
	}
	connect := rawBoundaryExchange(t, address,
		"CONNECT "+address+" HTTP/1.1\r\nHost: "+address+"\r\n\r\n")
	if !strings.HasPrefix(connect, testHTTP11NotImplementedLine) ||
		!strings.Contains(connect, "Content-Length: 0\r\n") {
		t.Fatalf("CONNECT wire response differs: %q", connect)
	}
	preface := rawBoundaryExchange(t, address,
		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if !strings.HasPrefix(preface, "HTTP/1.1 505 HTTP Version Not Supported\r\n") ||
		!strings.Contains(preface, "Content-Length: 0\r\n") {
		t.Fatalf("PRI wire response differs: %q", preface)
	}
}

// TestHTTPBoundaryRawExpectEarlyFinalNeverEmitsContinue proves header-first policy.
func TestHTTPBoundaryRawExpectEarlyFinalNeverEmitsContinue(t *testing.T) {
	address, _ := startRawBoundaryServer(t)
	response := rawBoundaryExchange(t, address,
		"POST /v1/process HTTP/1.1\r\n"+
			"Host: "+address+"\r\n"+
			testContentTypeJSONField+
			"Content-Length: 2\r\n"+
			"Expect: 100-continue\r\n\r\n")
	if strings.Contains(response, "100 Continue") ||
		!strings.HasPrefix(response, "HTTP/1.1 403 Forbidden\r\n") {
		t.Fatalf("Expect early-final wire response differs: %q", response)
	}
}

// TestHTTPBoundaryRawContinuePrecedesDomainAndFinal proves the admitted 100 path.
func TestHTTPBoundaryRawContinuePrecedesDomainAndFinal(t *testing.T) {
	address, handler := startRawBoundaryServer(t)
	processor, ok := handler.strict.processor.(*boundaryProcessor)
	if !ok {
		t.Fatal("raw fixture processor type changed")
	}
	capability := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, 32))
	response := rawBoundaryExchange(t, address,
		"POST /v1/process HTTP/1.1\r\n"+
			"Host: "+address+"\r\n"+
			testContentTypeJSONField+
			"X-DKIM2-Capability: "+capability+"\r\n"+
			"Content-Length: "+strconv.Itoa(len(validMinimalProcessJSON))+"\r\n"+
			"Expect: 100-continue\r\n\r\n"+
			validMinimalProcessJSON)
	continueAt := strings.Index(response, "HTTP/1.1 100 Continue\r\n\r\n")
	finalAt := strings.Index(response, "HTTP/1.1 500 Internal Server Error\r\n")
	if continueAt != 0 || finalAt <= continueAt ||
		processor.calls.Load() != 1 {
		t.Fatalf("continue/domain/final response = %q calls=%d",
			response, processor.calls.Load())
	}
	// Reading the connection through EOF proves that the final response reached
	// the socket, not that the serving goroutine has already run its deferred
	// admission release. Synchronize on the reservation itself instead of
	// depending on scheduler timing under the race detector.
	waitBoundaryAdmissionOwned(t, handler.admission, 0)
}

// TestHTTPBoundaryRawContinueSizePrecedesSaturatedAdmission proves the frozen no-100 ordering.
func TestHTTPBoundaryRawContinueSizePrecedesSaturatedAdmission(t *testing.T) {
	address, handler := startRawBoundaryServer(t)
	owner, failure := handler.admission.TryAcquire(context.Background())
	if owner == nil || failure != 0 || handler.admission.Owned() != 1 {
		t.Fatalf("capacity owner = %v/%v owned=%d", owner, failure, handler.admission.Owned())
	}
	defer owner.Release()

	capability := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, 32))
	request := func(contentLength int64) string {
		return "POST /v1/process HTTP/1.1\r\n" +
			"Host: " + address + "\r\n" +
			testContentTypeJSONField +
			"X-DKIM2-Capability: " + capability + "\r\n" +
			"Content-Length: " + strconv.FormatInt(contentLength, 10) + "\r\n" +
			"Expect: 100-continue\r\n\r\n"
	}

	oversized := rawBoundaryExchange(t, address, request(maxProcessBodyBytes+1))
	if strings.Contains(oversized, "100 Continue") ||
		!strings.HasPrefix(oversized, "HTTP/1.1 413 Request Entity Too Large\r\n") ||
		!strings.Contains(oversized, `"code":"request_too_large"`) ||
		handler.admission.Owned() != 1 {
		t.Fatalf("oversized saturated response = %q owned=%d", oversized, handler.admission.Owned())
	}

	otherwiseValid := rawBoundaryExchange(t, address, request(2))
	if strings.Contains(otherwiseValid, "100 Continue") ||
		!strings.HasPrefix(otherwiseValid, "HTTP/1.1 503 Service Unavailable\r\n") ||
		!strings.Contains(otherwiseValid, "Retry-After: 1\r\n") ||
		!strings.Contains(otherwiseValid, `"code":"service_overloaded"`) ||
		handler.admission.Owned() != 1 {
		t.Fatalf("eligible saturated response = %q owned=%d", otherwiseValid, handler.admission.Owned())
	}

	owner.Release()
	oversizedFree := rawBoundaryExchange(t, address, request(maxProcessBodyBytes+1))
	if strings.Contains(oversizedFree, "100 Continue") ||
		!strings.HasPrefix(oversizedFree, "HTTP/1.1 413 Request Entity Too Large\r\n") ||
		handler.admission.Owned() != 0 {
		t.Fatalf("oversized free response = %q owned=%d",
			oversizedFree, handler.admission.Owned())
	}

	blocker, failure := handler.admission.TryAcquire(context.Background())
	if blocker == nil || failure != 0 || handler.admission.Owned() != 1 {
		t.Fatal("failed to restore saturated admission")
	}
	defer blocker.Release()
	ordinaryOversized := rawBoundaryExchange(t, address,
		"POST /v1/process HTTP/1.1\r\n"+
			"Host: "+address+"\r\n"+
			testContentTypeJSONField+
			"X-DKIM2-Capability: "+capability+"\r\n"+
			"Content-Length: "+strconv.FormatInt(maxProcessBodyBytes+1, 10)+"\r\n\r\n")
	if strings.Contains(ordinaryOversized, "100 Continue") ||
		!strings.HasPrefix(ordinaryOversized, "HTTP/1.1 503 Service Unavailable\r\n") ||
		!strings.Contains(ordinaryOversized, `"code":"service_overloaded"`) ||
		handler.admission.Owned() != 1 {
		t.Fatalf("ordinary oversized saturated response = %q owned=%d",
			ordinaryOversized, handler.admission.Owned())
	}
}

// TestHTTPBoundaryRawOptionsRejectsEveryContentLengthOccurrence proves no-framing policy.
func TestHTTPBoundaryRawOptionsRejectsEveryContentLengthOccurrence(t *testing.T) {
	address, _ := startRawBoundaryServer(t)
	tests := []struct {
		name        string
		fields      string
		statusLine  string
		application bool
	}{
		{
			name:       transportTestAbsent,
			statusLine: testHTTP11NoContentLine,
		},
		{
			name:        testZeroName,
			fields:      "Content-Length: 0\r\n",
			statusLine:  testHTTP11BadRequestLine,
			application: true,
		},
		{
			name:        "positive",
			fields:      "Content-Length: 1\r\n",
			statusLine:  testHTTP11BadRequestLine,
			application: true,
		},
		{
			name:        "repeated valid",
			fields:      "Content-Length: 0\r\nContent-Length: 0\r\n",
			statusLine:  testHTTP11BadRequestLine,
			application: true,
		},
		{
			name:       "conflict remains parser owned",
			fields:     "Content-Length: 0\r\nContent-Length: 1\r\n",
			statusLine: testHTTP11BadRequestLine,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			response := rawBoundaryExchange(t, address,
				"OPTIONS * HTTP/1.1\r\nHost: "+address+"\r\n"+
					testCase.fields+"\r\n")
			if !strings.HasPrefix(response, testCase.statusLine) {
				t.Fatalf("response = %q", response)
			}
			hasApplicationError := strings.Contains(response, `"code":"invalid_contract"`)
			if hasApplicationError != testCase.application {
				t.Fatalf("application ownership = %v, want %v: %q",
					hasApplicationError, testCase.application, response)
			}
			if testCase.name == transportTestAbsent &&
				strings.Contains(response, "\r\nContent-Length:") {
				t.Fatalf("204 emitted Content-Length: %q", response)
			}
		})
	}
}

// TestHTTPBoundaryRawIgnoresAccept proves representation negotiation is absent.
func TestHTTPBoundaryRawIgnoresAccept(t *testing.T) {
	address, _ := startRawBoundaryServer(t)
	tests := []struct {
		name   string
		fields string
	}{
		{name: transportTestAbsent},
		{name: "matching", fields: "Accept: application/json\r\n"},
		{name: "nonmatching", fields: "Accept: text/plain\r\n"},
		{name: "wildcard", fields: "Accept: */*\r\n"},
		{name: "malformed semantic", fields: "Accept: ;;;\r\n"},
		{name: "multiple", fields: "Accept: text/plain\r\nAccept: application/json\r\n"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			status := rawBoundaryExchange(t, address,
				"GET /healthz HTTP/1.1\r\nHost: "+address+"\r\n"+
					testCase.fields+"\r\n")
			if !strings.HasPrefix(status, testHTTP11OKLine) ||
				strings.Contains(status, "\r\nVary:") {
				t.Fatalf("status Accept response = %q", status)
			}
			process := rawBoundaryExchange(t, address,
				"POST /v1/process HTTP/1.1\r\nHost: "+address+"\r\n"+
					"Content-Type: application/json\r\nContent-Length: 2\r\n"+
					testCase.fields+"\r\n{}")
			if !strings.HasPrefix(process, "HTTP/1.1 403 Forbidden\r\n") ||
				strings.Contains(process, "\r\nVary:") ||
				strings.Contains(process, "406 Not Acceptable") {
				t.Fatalf("process Accept response = %q", process)
			}
		})
	}
}

// TestHTTPBoundaryRawProcessesOnlyOneRequestPerConnection freezes close policy.
func TestHTTPBoundaryRawProcessesOnlyOneRequestPerConnection(t *testing.T) {
	address, _ := startRawBoundaryServer(t)
	response := rawBoundaryExchange(t, address,
		"GET /healthz HTTP/1.1\r\nHost: "+address+"\r\n\r\n"+
			"GET /readyz HTTP/1.1\r\nHost: "+address+"\r\n\r\n")
	if strings.Count(response, "HTTP/1.1 ") != 1 ||
		!strings.Contains(response, `"status":"alive"`) ||
		strings.Contains(response, `"status":"ready"`) {
		t.Fatalf("connection dispatched more than one request: %q", response)
	}
}

// TestHTTPBoundaryReservationSurvivesHandlerUntilFinalFlush proves finish ownership.
func TestHTTPBoundaryReservationSurvivesHandlerUntilFinalFlush(t *testing.T) {
	handler, _, processor, secret := newBoundaryFixture(t)
	handler.generated = &silentGeneratedHandler{ServerInterface: handler.generated}
	capability := base64.RawURLEncoding.EncodeToString(secret)
	rawRequest := []byte(
		"POST /v1/process HTTP/1.1\r\n" +
			"Host: " + boundaryTestAuthority + "\r\n" +
			testContentTypeJSONField +
			"X-DKIM2-Capability: " + capability + "\r\n" +
			"Content-Length: " + strconv.Itoa(len(validMinimalProcessJSON)) + "\r\n\r\n" +
			validMinimalProcessJSON,
	)
	serverConnection, clientConnection := net.Pipe()
	raw := newBoundaryBlockingWriteConn(serverConnection)
	scripted := newTransportScriptedListener()
	scripted.enqueue(raw)
	tracked, err := newTrackedListener(scripted, nil)
	if err != nil {
		t.Fatal("newTrackedListener() failed")
	}
	handlerReturned := make(chan struct{})
	var returnedOnce sync.Once
	server := &http.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			handler.ServeHTTP(writer, request)
			returnedOnce.Do(func() { close(handlerReturned) })
		}),
		ConnContext:                  tracked.ConnContext,
		ErrorLog:                     log.New(io.Discard, "", 0),
		DisableGeneralOptionsHandler: true,
		MaxHeaderBytes:               transportServerMaxHeaderBytes,
	}
	serveDone := make(chan struct{})
	go func() {
		_ = server.Serve(tracked)
		close(serveDone)
	}()
	t.Cleanup(func() {
		select {
		case <-raw.allowWrite:
		default:
			close(raw.allowWrite)
		}
		handler.Close()
		_ = server.Close()
		_ = tracked.Close()
		_ = clientConnection.Close()
		<-serveDone
	})
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		if _, err := clientConnection.Write(rawRequest); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, clientConnection)
	}()

	select {
	case <-handlerReturned:
	case <-raw.terminal:
		t.Fatal("transport closed before handler entry")
	case <-time.After(time.Second):
		t.Fatal("HTTP boundary did not return")
	}
	select {
	case <-raw.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("finishRequest did not reach the blocked final write")
	}
	if processor.calls.Load() != 0 || handler.admission.Owned() != 1 {
		t.Fatalf("blocked final write calls=%d owned=%d",
			processor.calls.Load(), handler.admission.Owned())
	}
	close(raw.allowWrite)
	select {
	case <-raw.terminal:
	case <-time.After(time.Second):
		t.Fatal("transport did not close after final flush")
	}
	<-clientDone
	waitBoundaryAdmissionOwned(t, handler.admission, 0)
}

// waitBoundaryAdmissionOwned waits only for post-socket scrub completion.
func waitBoundaryAdmissionOwned(
	t testing.TB,
	admission *processAdmission,
	want uint32,
) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		if admission.Owned() == want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("admission ownership = %d, want %d", admission.Owned(), want)
		case <-ticker.C:
		}
	}
}
