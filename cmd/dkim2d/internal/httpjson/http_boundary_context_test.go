package httpjson

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
)

type contextBoundaryServer struct {
	address string
	handler *HTTPBoundary
	tracked *trackedListener
	server  *http.Server
}

type contextCancelReadiness struct {
	calls  atomic.Int32
	cancel context.CancelFunc
}

type contextPanicReadiness struct {
	calls atomic.Int32
}

// Ready cancels only after process admission has attached transport ownership.
func (r *contextCancelReadiness) Ready() bool {
	if r.calls.Add(1) == 2 && r.cancel != nil {
		r.cancel()
	}
	return true
}

// Ready injects one unexpected precommit panic after request-state publication.
func (r *contextPanicReadiness) Ready() bool {
	r.calls.Add(1)
	panic(errors.New(contextPrecommitPanicPrivateMarker))
}

type contextDeadlineProcessor struct {
	calls atomic.Int32
}

type contextCommittedPanicHandler struct {
	generated.ServerInterface
	commitCalled atomic.Int32
}

// ProcessMessage records the buffered commit call before one controlled panic.
func (h *contextCommittedPanicHandler) ProcessMessage(
	writer http.ResponseWriter,
	_ *http.Request,
) {
	writer.WriteHeader(http.StatusOK)
	h.commitCalled.Add(1)
	panic(errors.New("context committed panic"))
}

type contextGoldenCorpus struct {
	Draft       string `json:"draft"`
	RSAModulus  string `json:"rsa_modulus_base64"`
	RSAExponent int    `json:"rsa_exponent"`
	Vectors     map[string]struct {
		Raw     string   `json:"raw_base64"`
		Reverse string   `json:"reverse_path_base64"`
		Forward []string `json:"forward_paths_base64"`
	} `json:"vectors"`
}

type contextGoldenProvider struct {
	key *rsa.PublicKey
}

// LookupPublicKey returns the frozen RSA key for the selected golden vector.
func (p contextGoldenProvider) LookupPublicKey(
	_ context.Context,
	query dkim2.PublicKeyQuery,
) (dkim2.PublicKeyResult, error) {
	if query.Algorithm() != dkim2.AlgorithmRSASHA256 {
		return dkim2.MissingPublicKey(query.Algorithm()), nil
	}
	return dkim2.FoundRSAPublicKey(p.key), nil
}

type contextMutationStore struct {
	calls    atomic.Int32
	cancel   <-chan context.CancelFunc
	deadline bool
}

// CheckAndRemember records possible mutation before triggering terminal context.
func (s *contextMutationStore) CheckAndRemember(
	ctx context.Context,
	_ dkim2.ReplayKey,
	_ dkim2.ReplayRetention,
) (dkim2.ReplayCheck, error) {
	s.calls.Add(1)
	if s.deadline {
		<-ctx.Done()
	} else {
		cancel := <-s.cancel
		cancel()
	}
	return dkim2.ReplayCheckFirstSeen, nil
}

type contextDeadlineError struct{}

const (
	contextEarlyFinalPrivateMarker     = "CONTEXT-EARLY-FINAL-PRIVATE"
	contextDeadlinePrivateMarker       = "CONTEXT-READ-DEADLINE-PRIVATE"
	contextPrecommitPanicPrivateMarker = "CONTEXT-PRECOMMIT-PANIC-PRIVATE"
)

// Error returns one constant content-free deadline diagnostic.
func (contextDeadlineError) Error() string { return "context test deadline" }

// Timeout identifies the scripted terminal read as deadline-owned.
func (contextDeadlineError) Timeout() bool { return true }

// Temporary rejects retry semantics for the scripted read.
func (contextDeadlineError) Temporary() bool { return false }

type contextEarlyFinalConn struct {
	mu sync.Mutex

	request             []byte
	initialLimit        int
	readAt              int
	deadlineAt          int
	written             bytes.Buffer
	deadlineAdvanced    bool
	rejectReadDeadline  bool
	writeBeforeDeadline bool
	readsAfterDeadline  int
	bytesAfterDeadline  int
	waitForClose        bool
	closedSignal        chan struct{}
	closeOnce           sync.Once
	closeCalls          atomic.Int32
	closed              atomic.Bool
}

type contextDiagnosticLog struct {
	mu    sync.Mutex
	bytes bytes.Buffer
}

// Write retains one race-safe diagnostic snapshot for privacy assertions.
func (l *contextDiagnosticLog) Write(value []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.bytes.Write(value)
}

// Contains reports only whether protected spelling reached diagnostics.
func (l *contextDiagnosticLog) Contains(value string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Contains(l.bytes.String(), value)
}

// newContextEarlyFinalConn constructs one deterministic body-close transport.
func newContextEarlyFinalConn(
	request []byte,
	initialLimit int,
	rejectReadDeadline bool,
) *contextEarlyFinalConn {
	if initialLimit < 0 || initialLimit > len(request) {
		initialLimit = len(request)
	}
	return &contextEarlyFinalConn{
		request:            append([]byte(nil), request...),
		initialLimit:       initialLimit,
		rejectReadDeadline: rejectReadDeadline,
		closedSignal:       make(chan struct{}),
	}
}

// Read serves already-available bytes and never invents future client input.
func (c *contextEarlyFinalConn) Read(output []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.mu.Lock()
	if c.deadlineAdvanced {
		c.readsAfterDeadline++
		c.mu.Unlock()
		return 0, contextDeadlineError{}
	}
	if c.readAt < c.initialLimit {
		count := copy(output, c.request[c.readAt:c.initialLimit])
		c.readAt += count
		c.mu.Unlock()
		return count, nil
	}
	waitForClose := c.waitForClose
	closedSignal := c.closedSignal
	c.mu.Unlock()
	if waitForClose {
		<-closedSignal
		return 0, net.ErrClosed
	}
	return 0, io.EOF
}

// Write records whether response commitment followed deadline advancement.
func (c *contextEarlyFinalConn) Write(value []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.deadlineAdvanced {
		c.writeBeforeDeadline = true
	}
	return c.written.Write(value)
}

// Close records exact terminal raw ownership.
func (c *contextEarlyFinalConn) Close() error {
	c.closeCalls.Add(1)
	c.closed.Store(true)
	c.closeOnce.Do(func() { close(c.closedSignal) })
	return nil
}

// LocalAddr returns one content-free local endpoint.
func (*contextEarlyFinalConn) LocalAddr() net.Addr { return transportTestAddr("local") }

// RemoteAddr returns one content-free remote endpoint.
func (*contextEarlyFinalConn) RemoteAddr() net.Addr { return transportTestAddr("remote") }

// SetDeadline delegates the scripted read and write deadline channels.
func (c *contextEarlyFinalConn) SetDeadline(deadline time.Time) error {
	if err := c.SetReadDeadline(deadline); err != nil {
		return err
	}
	return c.SetWriteDeadline(deadline)
}

// SetReadDeadline records or rejects only the application-narrowed deadline.
func (c *contextEarlyFinalConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if deadline.IsZero() || deadline.After(time.Now().Add(time.Second)) {
		return nil
	}
	if c.rejectReadDeadline {
		return errors.New(contextDeadlinePrivateMarker)
	}
	c.deadlineAdvanced = true
	c.deadlineAt = c.readAt
	return nil
}

// SetWriteDeadline accepts the bounded response deadline without widening reads.
func (*contextEarlyFinalConn) SetWriteDeadline(time.Time) error { return nil }

// snapshot returns only content-free counters and terminal facts.
func (c *contextEarlyFinalConn) snapshot() (bool, bool, int, int, int, int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadlineAdvanced,
		c.writeBeforeDeadline,
		c.readsAfterDeadline,
		c.bytesAfterDeadline,
		c.deadlineAt,
		len(c.request) - c.readAt,
		c.written.Len()
}

// writtenContains reports only whether protected spelling reached the wire.
func (c *contextEarlyFinalConn) writtenContains(value string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Contains(c.written.String(), value)
}

// writtenResponseCounts reports only bounded HTTP status-line counts.
func (c *contextEarlyFinalConn) writtenResponseCounts() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	response := c.written.String()
	return strings.Count(response, "HTTP/1.1 "),
		strings.Count(response, "HTTP/1.1 100 Continue\r\n")
}

// Process waits for the boundary-owned deadline and preserves its exact cause.
func (p *contextDeadlineProcessor) Process(
	ctx context.Context,
	_ dkim2.VerifyRequest,
) (app.InboundResult, error) {
	p.calls.Add(1)
	<-ctx.Done()
	return app.InboundResult{}, ctx.Err()
}

// startContextBoundaryServer starts a real tracked listener and one-operation server.
func startContextBoundaryServer(
	t *testing.T,
	deadline time.Duration,
	readiness readinessSource,
	processor inboundProcessService,
	connContext func(context.Context) context.Context,
	configure func(*HTTPBoundary),
) *contextBoundaryServer {
	t.Helper()

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("context listener construction failed")
	}
	tracked, err := newTrackedListener(raw, nil)
	if err != nil {
		_ = raw.Close()
		t.Fatal("tracked context listener construction failed")
	}
	validator, err := NewRequestValidator()
	if err != nil {
		_ = tracked.Close()
		t.Fatal("context validator construction failed")
	}
	secret := bytes.Repeat([]byte{0xa5}, 32)
	handler, err := NewHTTPBoundary(BoundaryConfig{
		Authority:       raw.Addr().String(),
		RequestDeadline: deadline,
		MaxInFlight:     1,
		MaxWaiters:      1,
		AdmissionWait:   10 * time.Millisecond,
	}, &boundaryCapabilityMatcher{value: secret}, readiness, processor,
		&boundaryFatalNotifier{}, validator)
	if err != nil {
		_ = tracked.Close()
		t.Fatal("context boundary construction failed")
	}
	if configure != nil {
		configure(handler)
	}
	server := &http.Server{
		Handler: handler,
		ConnContext: func(ctx context.Context, connection net.Conn) context.Context {
			ctx = tracked.ConnContext(ctx, connection)
			if connContext != nil {
				ctx = connContext(ctx)
			}
			return ctx
		},
		ErrorLog:                     log.New(io.Discard, "", 0),
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
	return &contextBoundaryServer{
		address: raw.Addr().String(),
		handler: handler,
		tracked: tracked,
		server:  server,
	}
}

// contextProcessRequest builds one authenticated complete process request.
func contextProcessRequest(address, body string) string {
	capability := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, 32))
	return "POST /v1/process HTTP/1.1\r\n" +
		"Host: " + address + "\r\n" +
		testContentTypeJSONField +
		"X-DKIM2-Capability: " + capability + "\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" +
		body
}

// contextGoldenInboundProcessor constructs one real PASS-to-replay app pipeline.
func contextGoldenInboundProcessor(
	t *testing.T,
	store dkim2.ReplayStore,
) (*app.InboundProcessor, string) {
	t.Helper()

	corpusBytes, err := os.ReadFile(
		"../../../../lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-04/public-golden.json",
	)
	if err != nil {
		t.Fatal("context golden fixture unavailable")
	}
	var corpus contextGoldenCorpus
	if json.Unmarshal(corpusBytes, &corpus) != nil || corpus.Draft != dkim2.DraftIdentifier {
		t.Fatal("context golden fixture invalid")
	}
	vector, ok := corpus.Vectors["rsa_pass"]
	if !ok {
		t.Fatal("context golden PASS vector unavailable")
	}
	modulus, err := base64.StdEncoding.DecodeString(corpus.RSAModulus)
	if err != nil {
		t.Fatal("context golden RSA modulus invalid")
	}
	verifier, err := dkim2.NewVerifier(
		contextGoldenProvider{key: &rsa.PublicKey{
			N: new(big.Int).SetBytes(modulus),
			E: corpus.RSAExponent,
		}},
		dkim2.WithVerificationClock(func() time.Time {
			return time.Unix(1_700_000_000, 0)
		}),
	)
	if err != nil {
		t.Fatal("context verifier construction failed")
	}
	domain, err := app.NewDomainProcessor(verifier, config.PolicyStrict)
	if err != nil {
		t.Fatal("context domain processor construction failed")
	}
	deriver, err := dkim2.NewReplayDeriver(bytes.Repeat([]byte{0x5a}, 32), 1)
	if err != nil {
		t.Fatal("context replay deriver construction failed")
	}
	t.Cleanup(func() { _ = deriver.Close(context.Background()) })
	replay, err := app.NewEnabledReplayCoordinator(
		deriver,
		store,
		dkim2.DefaultReplayRetention(),
	)
	if err != nil {
		t.Fatal("context replay coordinator construction failed")
	}
	processor, err := app.NewInboundProcessor(domain, replay)
	if err != nil {
		t.Fatal("context inbound processor construction failed")
	}
	reverse, err := base64.StdEncoding.DecodeString(vector.Reverse)
	if err != nil {
		t.Fatal("context reverse-path fixture invalid")
	}
	recipients := make([]string, len(vector.Forward))
	for index, encoded := range vector.Forward {
		value, decodeErr := base64.StdEncoding.DecodeString(encoded)
		if decodeErr != nil {
			t.Fatal("context forward-path fixture invalid")
		}
		recipients[index] = string(value)
	}
	body, err := json.Marshal(map[string]any{
		"api_version": "v1",
		testDraftName: dkim2.DraftIdentifier,
		"message": map[string]any{
			"raw_rfc5322_base64": vector.Raw,
			"fidelity":           "raw_rfc5322",
		},
		"smtp": map[string]any{
			"mail_from": string(reverse),
			"rcpt_to":   recipients,
		},
	})
	if err != nil {
		t.Fatal("context golden request construction failed")
	}
	return processor, string(body)
}

// assertContextResourcesReleased waits for transport scrub and both fixed tokens.
func assertContextResourcesReleased(t *testing.T, server *contextBoundaryServer) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if server.handler.admission.Owned() == 0 &&
			len(server.handler.admission.permits) == 0 &&
			len(server.handler.admission.waiters) == 0 &&
			len(server.tracked.tokens) == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("context resources retained: owned=%d permits=%d waiters=%d connections=%d",
		server.handler.admission.Owned(),
		len(server.handler.admission.permits),
		len(server.handler.admission.waiters),
		len(server.tracked.tokens),
	)
}

// runScriptedContextServer drives one scripted raw connection through the tracked listener.
func runScriptedContextServer(
	t *testing.T,
	raw *contextEarlyFinalConn,
	configure func(*HTTPBoundary),
) (*HTTPBoundary, *trackedListener, *contextDiagnosticLog) {
	t.Helper()

	scripted := newTransportScriptedListener()
	scripted.enqueue(raw)
	tracked, err := newTrackedListener(scripted, nil)
	if err != nil {
		t.Fatal("early-final tracked listener construction failed")
	}
	validator, err := NewRequestValidator()
	if err != nil {
		_ = tracked.Close()
		t.Fatal("early-final validator construction failed")
	}
	readiness := &boundaryReadiness{}
	readiness.ready.Store(true)
	handler, err := NewHTTPBoundary(BoundaryConfig{
		Authority:       scripted.Addr().String(),
		RequestDeadline: time.Second,
		MaxInFlight:     1,
		MaxWaiters:      1,
		AdmissionWait:   10 * time.Millisecond,
	}, &boundaryCapabilityMatcher{value: bytes.Repeat([]byte{0xa5}, 32)},
		readiness, &boundaryProcessor{}, &boundaryFatalNotifier{}, validator)
	if err != nil {
		_ = tracked.Close()
		t.Fatal("scripted context boundary construction failed")
	}
	if configure != nil {
		configure(handler)
	}
	diagnostics := &contextDiagnosticLog{}
	server := &http.Server{
		Handler:                      handler,
		ConnContext:                  tracked.ConnContext,
		ErrorLog:                     log.New(diagnostics, "", 0),
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
	deadline := time.Now().Add(2 * time.Second)
	for raw.closeCalls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if raw.closeCalls.Load() == 0 {
		t.Fatal("scripted context connection did not become terminal")
	}
	return handler, tracked, diagnostics
}

// TestHTTPBoundaryTrackedCancellationAfterReservationSuppressesResponse proves client precedence.
func TestHTTPBoundaryTrackedCancellationAfterReservationSuppressesResponse(t *testing.T) {
	var cancel context.CancelFunc
	notifier := &boundaryFatalNotifier{}
	readiness := &contextCancelReadiness{}
	processor := &boundaryProcessor{}
	server := startContextBoundaryServer(
		t,
		time.Second,
		readiness,
		processor,
		func(ctx context.Context) context.Context {
			ctx, cancel = context.WithCancel(ctx)
			readiness.cancel = cancel
			return ctx
		},
		func(handler *HTTPBoundary) {
			handler.fatal = notifier
		},
	)
	response := rawBoundaryExchange(t, server.address,
		contextProcessRequest(server.address, validMinimalProcessJSON))
	if len(response) != 0 || processor.calls.Load() != 0 ||
		readiness.calls.Load() != 2 || notifier.calls.Load() != 0 {
		t.Fatalf("cancel outcome: response_bytes=%d processor=%d readiness=%d",
			len(response), processor.calls.Load(), readiness.calls.Load())
	}
	assertContextResourcesReleased(t, server)
}

// TestHTTPBoundaryTrackedOwnedDeadlineReturnsExact503 proves local deadline ownership.
func TestHTTPBoundaryTrackedOwnedDeadlineReturnsExact503(t *testing.T) {
	readiness := &boundaryReadiness{}
	readiness.ready.Store(true)
	processor := &contextDeadlineProcessor{}
	server := startContextBoundaryServer(t, 40*time.Millisecond, readiness, processor, nil, nil)
	response := rawBoundaryExchange(t, server.address,
		contextProcessRequest(server.address, validMinimalProcessJSON))
	if !strings.HasPrefix(response, "HTTP/1.1 503 Service Unavailable\r\n") ||
		!strings.Contains(response, "\r\nRetry-After: 1\r\n") ||
		!strings.Contains(response, `"code":"request_deadline"`) ||
		strings.Contains(response, "504 Gateway Timeout") ||
		processor.calls.Load() != 1 {
		t.Fatalf("deadline outcome: response_bytes=%d processor=%d",
			len(response), processor.calls.Load())
	}
	assertContextResourcesReleased(t, server)
}

// TestHTTPBoundaryTrackedPostMutationTerminalContextPreservesHTTP200 proves replay closure.
func TestHTTPBoundaryTrackedPostMutationTerminalContextPreservesHTTP200(t *testing.T) {
	tests := []struct {
		name     string
		deadline time.Duration
		store    func(<-chan context.CancelFunc) *contextMutationStore
	}{
		{
			name:     "client cancellation",
			deadline: time.Second,
			store: func(cancels <-chan context.CancelFunc) *contextMutationStore {
				return &contextMutationStore{cancel: cancels}
			},
		},
		{
			name:     "owned deadline",
			deadline: 50 * time.Millisecond,
			store: func(<-chan context.CancelFunc) *contextMutationStore {
				return &contextMutationStore{deadline: true}
			},
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			cancels := make(chan context.CancelFunc, 1)
			store := testCase.store(cancels)
			processor, body := contextGoldenInboundProcessor(t, store)
			readiness := &boundaryReadiness{}
			readiness.ready.Store(true)
			server := startContextBoundaryServer(
				t,
				testCase.deadline,
				readiness,
				processor,
				func(ctx context.Context) context.Context {
					if testCase.name != "client cancellation" {
						return ctx
					}
					ctx, cancel := context.WithCancel(ctx)
					cancels <- cancel
					return ctx
				},
				nil,
			)
			response := rawBoundaryExchange(t, server.address,
				contextProcessRequest(server.address, body))
			if !strings.HasPrefix(response, testHTTP11OKLine) ||
				!strings.Contains(response, `"class":"indeterminate"`) ||
				!strings.Contains(response, `"disposition":"tempfail"`) ||
				strings.Contains(response, `"request_deadline"`) ||
				store.calls.Load() != 1 {
				t.Fatalf("post-mutation outcome: response_bytes=%d store=%d",
					len(response), store.calls.Load())
			}
			assertContextResourcesReleased(t, server)
		})
	}
}

// earlyFinalHead builds one unauthenticated process request head.
func earlyFinalHead(contentLength int) string {
	return "POST /v1/process HTTP/1.1\r\n" +
		"Host: listener\r\n" +
		testContentTypeJSONField +
		testExpectContinueField +
		"Content-Length: " + strconv.Itoa(contentLength) + "\r\n\r\n"
}

// earlyFinalRequest builds one unauthenticated process request with body bytes.
func earlyFinalRequest(contentLength int, sentBody []byte) []byte {
	head := earlyFinalHead(contentLength)
	request := make([]byte, 0, len(head)+len(sentBody))
	request = append(request, head...)
	return append(request, sentBody...)
}

// TestHTTPBoundaryRawEarlyFinalBoundsBodyClose proves deadline-before-commit containment.
func TestHTTPBoundaryRawEarlyFinalBoundsBodyClose(t *testing.T) {
	t.Run("declared exact limit", testContextEarlyFinalExactLimit)
	t.Run("declared one over limit", testContextEarlyFinalOneOverLimit)
	t.Run("future bytes never waited", testContextEarlyFinalFutureBytes)
}

const contextPostHandlerReadLimit = 256 << 10

// testContextEarlyFinalExactLimit verifies bounded buffered-body draining.
func testContextEarlyFinalExactLimit(t *testing.T) {
	request := earlyFinalRequest(
		contextPostHandlerReadLimit,
		bytes.Repeat([]byte{'x'}, contextPostHandlerReadLimit),
	)
	raw := newContextEarlyFinalConn(request, len(request), false)
	handler, tracked, diagnostics := runScriptedContextServer(t, raw, nil)
	advanced, writeBefore, readsAfter, bytesAfter, deadlineAt, remaining, written := raw.snapshot()
	statuses, continues := raw.writtenResponseCounts()
	bufferedBody := deadlineAt - len(earlyFinalHead(contextPostHandlerReadLimit))
	if !advanced || writeBefore || readsAfter == 0 ||
		bytesAfter != 0 || bufferedBody <= 0 ||
		bufferedBody > contextPostHandlerReadLimit || remaining == 0 || written == 0 ||
		raw.closeCalls.Load() != 1 ||
		handler.admission.Owned() != 0 || len(tracked.tokens) != 0 ||
		raw.writtenContains(contextEarlyFinalPrivateMarker) ||
		diagnostics.Contains(contextEarlyFinalPrivateMarker) ||
		statuses != 1 || continues != 0 {
		t.Fatalf("buffered close outcome: advanced=%t early_write=%t reads=%d raw_after=%d buffered=%d remaining=%d written=%d closes=%d owned=%d connections=%d",
			advanced,
			writeBefore,
			readsAfter,
			bytesAfter,
			bufferedBody,
			remaining,
			written,
			raw.closeCalls.Load(),
			handler.admission.Owned(),
			len(tracked.tokens),
		)
	}
}

// testContextEarlyFinalOneOverLimit verifies immediate closure above the drain bound.
func testContextEarlyFinalOneOverLimit(t *testing.T) {
	contentLength := contextPostHandlerReadLimit + 1
	body := bytes.Repeat([]byte{'y'}, contentLength)
	copy(body, contextEarlyFinalPrivateMarker)
	request := earlyFinalRequest(contentLength, body)
	raw := newContextEarlyFinalConn(request, len(request), false)
	started := time.Now()
	handler, tracked, diagnostics := runScriptedContextServer(t, raw, nil)
	elapsed := time.Since(started)
	advanced, writeBefore, readsAfter, bytesAfter, deadlineAt, remaining, written := raw.snapshot()
	statuses, continues := raw.writtenResponseCounts()
	bufferedBody := deadlineAt - len(earlyFinalHead(contentLength))
	if !advanced || writeBefore || readsAfter != 0 ||
		bytesAfter != 0 || bufferedBody < 0 ||
		bufferedBody > contextPostHandlerReadLimit || remaining == 0 ||
		written == 0 || elapsed >= time.Second ||
		raw.closeCalls.Load() != 1 ||
		handler.admission.Owned() != 0 || len(tracked.tokens) != 0 ||
		raw.writtenContains(contextEarlyFinalPrivateMarker) ||
		diagnostics.Contains(contextEarlyFinalPrivateMarker) ||
		statuses != 1 || continues != 0 {
		t.Fatalf("one-over close outcome: advanced=%t early_write=%t reads=%d raw_after=%d buffered=%d remaining=%d written=%d elapsed_ms=%d closes=%d owned=%d connections=%d",
			advanced,
			writeBefore,
			readsAfter,
			bytesAfter,
			bufferedBody,
			remaining,
			written,
			elapsed.Milliseconds(),
			raw.closeCalls.Load(),
			handler.admission.Owned(),
			len(tracked.tokens),
		)
	}
}

// testContextEarlyFinalFutureBytes verifies the server never waits for unsent body bytes.
func testContextEarlyFinalFutureBytes(t *testing.T) {
	body := bytes.Repeat([]byte{'x'}, 4*1024)
	request := earlyFinalRequest(contextPostHandlerReadLimit, body)
	initialLimit := len(earlyFinalHead(contextPostHandlerReadLimit)) + 1
	raw := newContextEarlyFinalConn(request, initialLimit, false)
	started := time.Now()
	handler, tracked, diagnostics := runScriptedContextServer(t, raw, nil)
	elapsed := time.Since(started)
	advanced, writeBefore, readsAfter, bytesAfter, deadlineAt, remaining, written := raw.snapshot()
	statuses, continues := raw.writtenResponseCounts()
	if !advanced || writeBefore || readsAfter == 0 || bytesAfter != 0 ||
		deadlineAt != initialLimit || remaining != len(body)-1 ||
		written == 0 || elapsed >= time.Second ||
		raw.closeCalls.Load() != 1 ||
		handler.admission.Owned() != 0 || len(tracked.tokens) != 0 ||
		raw.writtenContains(contextEarlyFinalPrivateMarker) ||
		diagnostics.Contains(contextEarlyFinalPrivateMarker) ||
		statuses != 1 || continues != 0 {
		t.Fatalf("future-byte outcome: advanced=%t early_write=%t reads=%d raw_after=%d deadline_at=%d remaining=%d written=%d elapsed_ms=%d closes=%d owned=%d connections=%d",
			advanced,
			writeBefore,
			readsAfter,
			bytesAfter,
			deadlineAt,
			remaining,
			written,
			elapsed.Milliseconds(),
			raw.closeCalls.Load(),
			handler.admission.Owned(),
			len(tracked.tokens),
		)
	}
}

// TestHTTPBoundaryTrackedPrecommitPanicBoundsPartialBody proves panic recovery retains request body state.
func TestHTTPBoundaryTrackedPrecommitPanicBoundsPartialBody(t *testing.T) {
	body := bytes.Repeat([]byte{'x'}, 4*1024)
	copy(body, contextEarlyFinalPrivateMarker)
	request := []byte(contextProcessRequest("listener", string(body)))
	headEnd := bytes.Index(request, []byte("\r\n\r\n")) + len("\r\n\r\n")
	if headEnd < len("\r\n\r\n") || headEnd >= len(request) {
		t.Fatal("precommit panic request head is invalid")
	}
	initialLimit := headEnd + 1
	raw := newContextEarlyFinalConn(request, initialLimit, false)
	readiness := &contextPanicReadiness{}
	notifier := &boundaryFatalNotifier{}
	processor := &boundaryProcessor{}
	started := time.Now()
	handler, tracked, diagnostics := runScriptedContextServer(
		t,
		raw,
		func(handler *HTTPBoundary) {
			handler.readiness = readiness
			handler.strict.readiness = readiness
			handler.strict.processor = processor
			handler.fatal = notifier
		},
	)
	elapsed := time.Since(started)
	advanced, writeBefore, readsAfter, bytesAfter, deadlineAt, remaining, written := raw.snapshot()
	statuses, continues := raw.writtenResponseCounts()
	if !advanced || writeBefore || readsAfter == 0 || bytesAfter != 0 ||
		deadlineAt != initialLimit || remaining != len(body)-1 ||
		written == 0 || elapsed >= time.Second ||
		raw.closeCalls.Load() != 1 ||
		handler.admission.Owned() != 0 || len(tracked.tokens) != 0 ||
		readiness.calls.Load() != 1 || processor.calls.Load() != 0 ||
		notifier.calls.Load() != 1 ||
		!raw.writtenContains("500 Internal Server Error") ||
		!raw.writtenContains(`"code":"internal_error"`) ||
		raw.writtenContains(contextEarlyFinalPrivateMarker) ||
		raw.writtenContains(contextPrecommitPanicPrivateMarker) ||
		diagnostics.Contains(contextEarlyFinalPrivateMarker) ||
		diagnostics.Contains(contextPrecommitPanicPrivateMarker) ||
		statuses != 1 || continues != 0 {
		t.Fatalf("precommit panic outcome: advanced=%t early_write=%t reads=%d raw_after=%d deadline_at=%d remaining=%d written=%d elapsed_ms=%d closes=%d owned=%d connections=%d readiness=%d processor=%d statuses=%d continues=%d",
			advanced,
			writeBefore,
			readsAfter,
			bytesAfter,
			deadlineAt,
			remaining,
			written,
			elapsed.Milliseconds(),
			raw.closeCalls.Load(),
			handler.admission.Owned(),
			len(tracked.tokens),
			readiness.calls.Load(),
			processor.calls.Load(),
			statuses,
			continues,
		)
	}
}

// TestHTTPBoundaryRawEarlyFinalDeadlineFailureSuppressesResponse proves fail-closed control.
func TestHTTPBoundaryRawEarlyFinalDeadlineFailureSuppressesResponse(t *testing.T) {
	raw := newContextEarlyFinalConn(
		earlyFinalRequest(16, bytes.Repeat([]byte{'x'}, 16)),
		len(earlyFinalHead(16))+1,
		true,
	)
	handler, tracked, diagnostics := runScriptedContextServer(t, raw, nil)
	advanced, writeBefore, readsAfter, bytesAfter, _, _, written := raw.snapshot()
	statuses, continues := raw.writtenResponseCounts()
	if advanced || writeBefore || readsAfter != 0 || bytesAfter != 0 || written != 0 ||
		raw.closeCalls.Load() != 1 ||
		handler.admission.Owned() != 0 || len(tracked.tokens) != 0 ||
		raw.writtenContains(contextEarlyFinalPrivateMarker) ||
		diagnostics.Contains(contextEarlyFinalPrivateMarker) ||
		raw.writtenContains(contextDeadlinePrivateMarker) ||
		diagnostics.Contains(contextDeadlinePrivateMarker) ||
		statuses != 0 || continues != 0 {
		t.Fatalf("deadline failure outcome: advanced=%t early_write=%t reads=%d bytes=%d written=%d closes=%d owned=%d connections=%d",
			advanced,
			writeBefore,
			readsAfter,
			bytesAfter,
			written,
			raw.closeCalls.Load(),
			handler.admission.Owned(),
			len(tracked.tokens),
		)
	}
}

// TestHTTPBoundaryTrackedCommittedPanicClosesWithoutSecondResponse proves terminal recovery.
func TestHTTPBoundaryTrackedCommittedPanicClosesWithoutSecondResponse(t *testing.T) {
	processor := &boundaryProcessor{}
	raw := newContextEarlyFinalConn(
		[]byte(contextProcessRequest("listener", validMinimalProcessJSON)),
		len(contextProcessRequest("listener", validMinimalProcessJSON)),
		false,
	)
	raw.waitForClose = true
	panicHandler := &contextCommittedPanicHandler{}
	notifier := &boundaryFatalNotifier{}
	handler, tracked, _ := runScriptedContextServer(
		t,
		raw,
		func(handler *HTTPBoundary) {
			handler.strict.processor = processor
			panicHandler.ServerInterface = handler.generated
			handler.generated = panicHandler
			handler.fatal = notifier
		},
	)
	deadline := time.Now().Add(time.Second)
	for (panicHandler.commitCalled.Load() != 1 ||
		raw.closeCalls.Load() != 1 ||
		handler.admission.Owned() != 0 ||
		len(tracked.tokens) != 0) &&
		time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	statuses, _ := raw.writtenResponseCounts()
	_, _, _, _, _, _, responseBytes := raw.snapshot()
	has500 := raw.writtenContains("500 Internal Server Error")
	hasInternal := raw.writtenContains(`"internal_error"`)
	commitCalls := panicHandler.commitCalled.Load()
	if responseBytes != 0 ||
		statuses != 0 ||
		has500 ||
		hasInternal ||
		commitCalls != 1 ||
		notifier.calls.Load() != 1 ||
		processor.calls.Load() != 0 ||
		raw.closeCalls.Load() != 1 ||
		handler.admission.Owned() != 0 ||
		len(tracked.tokens) != 0 {
		t.Fatalf("committed panic outcome: response_bytes=%d statuses=%d commit=%d processor=%d closes=%d owned=%d connections=%d has500=%t internal=%t",
			responseBytes,
			statuses,
			commitCalls,
			processor.calls.Load(),
			raw.closeCalls.Load(),
			handler.admission.Owned(),
			len(tracked.tokens),
			has500,
			hasInternal,
		)
	}
}
