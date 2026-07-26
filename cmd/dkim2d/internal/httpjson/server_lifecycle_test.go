package httpjson

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type gateContextKey struct{}

type gateTypedNilContext struct{}

type gateActivationAuthority struct {
	allowed  atomic.Bool
	calls    atomic.Int32
	panicVal any
}

type gateClaimActivationAuthority struct {
	state   atomic.Uint32
	claimed chan struct{}
	release chan struct{}
}

const (
	gateActivationArmed uint32 = iota + 1
	gateActivationClaimed
	gateActivationTerminal
)

// AllowHTTPActivation claims one shared activation state before the scripted
// post-claim barrier.
func (a *gateClaimActivationAuthority) AllowHTTPActivation() bool {
	if !a.state.CompareAndSwap(gateActivationArmed, gateActivationClaimed) {
		return false
	}
	close(a.claimed)
	<-a.release
	return true
}

// AllowHTTPActivation returns one scripted no-I/O startup authority.
func (a *gateActivationAuthority) AllowHTTPActivation() bool {
	a.calls.Add(1)
	if a.panicVal != nil {
		panic(a.panicVal)
	}
	return a.allowed.Load()
}

// Deadline reports no deadline for the typed-nil context fixture.
func (*gateTypedNilContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done reports no cancellation channel for the typed-nil context fixture.
func (*gateTypedNilContext) Done() <-chan struct{} { return nil }

// Err reports no cancellation state for the typed-nil context fixture.
func (*gateTypedNilContext) Err() error { return nil }

// Value reports no values for the typed-nil context fixture.
func (*gateTypedNilContext) Value(any) any { return nil }

type gateResponseWriter struct {
	header      http.Header
	writeCalls  int
	headerCalls int
}

type gateCountingConn struct {
	net.Conn
	closeCalls atomic.Int32
}

// Close records exact raw terminalization before closing the scripted peer.
func (c *gateCountingConn) Close() error {
	c.closeCalls.Add(1)
	return c.Conn.Close()
}

type gateCloseErrorConn struct {
	*transportRecordingConn
}

type gatePanicCloseConn struct {
	*transportRecordingConn
}

// Close proves foreign close panics cannot escape the stable server sentinel.
func (c *gatePanicCloseConn) Close() error {
	c.closeCalls.Add(1)
	panic("gate-foreign-close-private-marker")
}

// Close records one uncertain raw close for fail-closed abort coverage.
func (c *gateCloseErrorConn) Close() error {
	c.closeCalls.Add(1)
	c.closed.Store(true)
	return errors.New("gate-close-private-marker")
}

// Header returns the isolated response-header map.
func (w *gateResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

// Write records an attempted response body.
func (w *gateResponseWriter) Write(value []byte) (int, error) {
	w.writeCalls++
	return len(value), nil
}

// WriteHeader records an attempted response status.
func (w *gateResponseWriter) WriteHeader(int) {
	w.headerCalls++
}

type gateMatrixMatcher struct {
	calls atomic.Int32
}

// Equal records capability checks without retaining the candidate.
func (m *gateMatrixMatcher) Equal([]byte) bool {
	m.calls.Add(1)
	return false
}

type gateMatrixReadiness struct {
	calls atomic.Int32
	ready atomic.Bool
}

type gateObservedContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

// Err records that the gate waiter reached its condition-loop context check.
func (c *gateObservedContext) Err() error {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Err()
}

// Ready records no-I/O readiness sampling.
func (r *gateMatrixReadiness) Ready() bool {
	r.calls.Add(1)
	return r.ready.Load()
}

// TestServerListenerPreservesBaseContext proves the narrow server seam.
func TestServerListenerPreservesBaseContext(t *testing.T) {
	t.Parallel()

	raw := newTransportScriptedListener()
	rawConnection := newTransportRecordingConn(nil)
	raw.enqueue(rawConnection)
	listener, err := NewServerListener(raw, nil)
	if err != nil {
		t.Fatal("NewServerListener() failed")
	}
	t.Cleanup(func() { _ = listener.Close() })

	connection, err := listener.Accept()
	if err != nil {
		t.Fatal("ServerListener.Accept() failed")
	}
	deadline := time.Now().Add(time.Minute)
	deadlineContext, cancelDeadline := context.WithDeadline(
		context.WithValue(context.Background(), gateContextKey{}, "base"),
		deadline,
	)
	ctx, cancel := context.WithCancel(deadlineContext)
	serverContext := listener.ConnContext(ctx, connection)
	if serverContext.Value(gateContextKey{}) != "base" {
		t.Fatal("server ConnContext did not preserve BaseContext values")
	}
	if gotDeadline, ok := serverContext.Deadline(); !ok || !gotDeadline.Equal(deadline) {
		t.Fatal("server ConnContext did not preserve BaseContext deadline")
	}
	if state, ok := transportStateFromContext(serverContext); !ok ||
		state.trackedConnection() != connection {
		t.Fatal("tracked transport context did not retain the exact accepted connection")
	}
	if serverContext.Done() != ctx.Done() ||
		serverContext.Done() == context.WithoutCancel(ctx).Done() {
		t.Fatal("server ConnContext detached the instance-owned BaseContext")
	}
	cancel()
	select {
	case <-serverContext.Done():
	case <-time.After(time.Second):
		t.Fatal("server ConnContext detached BaseContext cancellation")
	}
	if !errors.Is(serverContext.Err(), context.Canceled) {
		t.Fatal("server ConnContext changed BaseContext cancellation")
	}
	cancelDeadline()
	if err := connection.Close(); err != nil {
		t.Fatal("server context connection Close() failed")
	}
	if rawConnection.closeCalls.Load() != 1 || len(listener.tracked.tokens) != 0 {
		t.Fatal("server context connection retained ownership")
	}

	nilBaseRaw := newTransportRecordingConn(nil)
	raw.enqueue(nilBaseRaw)
	nilBaseConnection, err := listener.Accept()
	if err != nil {
		t.Fatal("nil-base listener Accept() failed")
	}
	var nilBaseContext context.Context
	if recovered := invokeConnContext(
		nilBaseContext,
		listener.ConnContext,
		nilBaseConnection,
	); recovered != errServerConnContext {
		t.Fatalf("nil incoming ConnContext panic = %v", recovered)
	}
	if nilBaseRaw.closeCalls.Load() != 1 || len(listener.tracked.tokens) != 0 {
		t.Fatal("nil incoming ConnContext did not close and release its cap token")
	}

	typedNilBaseRaw := newTransportRecordingConn(nil)
	raw.enqueue(typedNilBaseRaw)
	typedNilBaseConnection, err := listener.Accept()
	if err != nil {
		t.Fatal("typed-nil-base listener Accept() failed")
	}
	var typedNilBase *gateTypedNilContext
	if recovered := invokeConnContext(
		typedNilBase,
		listener.ConnContext,
		typedNilBaseConnection,
	); recovered != errServerConnContext {
		t.Fatalf("typed-nil incoming ConnContext panic = %v", recovered)
	}
	if typedNilBaseRaw.closeCalls.Load() != 1 ||
		len(listener.tracked.tokens) != 0 {
		t.Fatal("typed-nil incoming ConnContext retained accepted ownership")
	}
	if !IsServerConnContextFailure(errServerConnContext) ||
		IsServerConnContextFailure(errors.New("server connection context failure")) ||
		IsServerConnContextFailure("configured-conn-context-private-marker") ||
		IsServerConnContextFailure(nil) {
		t.Fatal("server ConnContext sentinel recognition leaked or widened identity")
	}
}

// TestServerListenerRejectsNilListener proves fail-closed assembly.
func TestServerListenerRejectsNilListener(t *testing.T) {
	t.Parallel()

	var nilListener *transportScriptedListener
	if listener, err := NewServerListener(nil, nil); err == nil || listener != nil {
		t.Fatal("nil listener was accepted")
	}
	if listener, err := NewServerListener(nilListener, nil); err == nil || listener != nil {
		t.Fatal("typed-nil listener was accepted")
	}
}

// TestServerListenerRejectsForeignConnections proves exact accepted ownership.
func TestServerListenerRejectsForeignConnections(t *testing.T) {
	t.Parallel()

	raw := newTransportScriptedListener()
	listener, err := NewServerListener(raw, nil)
	if err != nil {
		t.Fatal("owner listener construction failed")
	}
	t.Cleanup(func() { _ = listener.Close() })
	connContext := listener.ConnContext

	if recovered := invokeConnContext(
		context.Background(),
		connContext,
		nil,
	); recovered != errServerConnContext {
		t.Fatalf("nil connection panic = %v", recovered)
	}
	var typedNil *trackedConn
	if recovered := invokeConnContext(
		context.Background(),
		connContext,
		typedNil,
	); recovered != errServerConnContext {
		t.Fatalf("typed-nil connection panic = %v", recovered)
	}

	foreignRaw := newTransportRecordingConn(nil)
	if recovered := invokeConnContext(
		context.Background(),
		connContext,
		foreignRaw,
	); recovered != errServerConnContext {
		t.Fatalf("foreign raw connection panic = %v", recovered)
	}
	if foreignRaw.closeCalls.Load() != 1 {
		t.Fatal("foreign raw connection was not closed exactly once")
	}
	panicClose := &gatePanicCloseConn{
		transportRecordingConn: newTransportRecordingConn(nil),
	}
	if recovered := invokeConnContext(
		context.Background(),
		connContext,
		panicClose,
	); recovered != errServerConnContext {
		t.Fatalf("foreign panic-close connection panic = %v", recovered)
	}
	if panicClose.closeCalls.Load() != 1 {
		t.Fatal("foreign panic-close connection was not attempted exactly once")
	}

	forgedRaw := newTransportRecordingConn(nil)
	forgedState := newTransportState(nil)
	forged := newTrackedConn(forgedRaw, forgedState, nil)
	forgedState.connection.Store(forged)
	if recovered := invokeConnContext(
		context.Background(),
		connContext,
		forged,
	); recovered != errServerConnContext {
		t.Fatalf("forged tracked connection panic = %v", recovered)
	}
	if forgedRaw.closeCalls.Load() != 1 {
		t.Fatal("forged tracked connection was not closed exactly once")
	}

	crossRawListener := newTransportScriptedListener()
	crossListener, err := NewServerListener(crossRawListener, nil)
	if err != nil {
		t.Fatal("cross-listener construction failed")
	}
	t.Cleanup(func() { _ = crossListener.Close() })
	crossRaw := newTransportRecordingConn(nil)
	crossRawListener.enqueue(crossRaw)
	crossConnection, err := crossListener.Accept()
	if err != nil {
		t.Fatal("cross-listener Accept() failed")
	}
	if recovered := invokeConnContext(
		context.Background(),
		connContext,
		crossConnection,
	); recovered != errServerConnContext {
		t.Fatalf("cross-listener connection panic = %v", recovered)
	}
	if crossRaw.closeCalls.Load() != 1 ||
		len(crossListener.tracked.tokens) != 0 ||
		len(listener.tracked.tokens) != 0 {
		t.Fatal("cross-listener rejection retained a connection-cap token")
	}

	closedRaw := newTransportRecordingConn(nil)
	raw.enqueue(closedRaw)
	closedConnection, err := listener.Accept()
	if err != nil {
		t.Fatal("same-listener closed Accept() failed")
	}
	if err := closedConnection.Close(); err != nil {
		t.Fatal("same-listener setup Close() failed")
	}
	if recovered := invokeConnContext(
		context.Background(),
		connContext,
		closedConnection,
	); recovered != errServerConnContext {
		t.Fatalf("same-listener closed connection panic = %v", recovered)
	}
	if closedRaw.closeCalls.Load() != 1 || len(listener.tracked.tokens) != 0 {
		t.Fatal("same-listener closed rejection double-closed or retained its token")
	}

	raceRaw := newTransportRecordingConn(nil)
	crossRawListener.enqueue(raceRaw)
	raceConnection, err := crossListener.Accept()
	if err != nil {
		t.Fatal("cross-listener race Accept() failed")
	}
	const attempts = 64
	var workers sync.WaitGroup
	var sentinelCount atomic.Int32
	for range attempts {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if recovered := invokeConnContext(
				context.Background(),
				connContext,
				raceConnection,
			); recovered == errServerConnContext {
				sentinelCount.Add(1)
			}
		}()
	}
	workers.Wait()
	if sentinelCount.Load() != attempts ||
		raceRaw.closeCalls.Load() != 1 ||
		len(crossListener.tracked.tokens) != 0 {
		t.Fatal("concurrent cross-listener rejection leaked ownership")
	}
}

// TestServerListenerBindsConnContextOnce proves terminal one-shot ownership.
func TestServerListenerBindsConnContextOnce(t *testing.T) {
	t.Parallel()

	raw := newTransportScriptedListener()
	listener, err := NewServerListener(raw, nil)
	if err != nil {
		t.Fatal("one-shot listener construction failed")
	}
	t.Cleanup(func() { _ = listener.Close() })
	firstRaw := newTransportRecordingConn(nil)
	raw.enqueue(firstRaw)
	firstConnection, err := listener.Accept()
	if err != nil {
		t.Fatal("one-shot listener Accept() failed")
	}
	if recovered := invokeConnContext(
		context.Background(),
		listener.ConnContext,
		firstConnection,
	); recovered != nil {
		t.Fatalf("first ConnContext binding panic = %v", recovered)
	}
	if recovered := invokeConnContext(
		context.Background(),
		listener.ConnContext,
		firstConnection,
	); recovered != errServerConnContext {
		t.Fatalf("repeated ConnContext binding panic = %v", recovered)
	}
	if firstRaw.closeCalls.Load() != 1 ||
		len(listener.tracked.tokens) != 0 {
		t.Fatal("repeated binding leaked connection ownership")
	}
}

// TestHandlerRegistrationGateStages proves bootstrapping, open, and stopped behavior.
func TestHandlerRegistrationGateStages(t *testing.T) {
	t.Parallel()

	var zero HandlerRegistrationGate
	if zero.Open() {
		t.Fatal("zero-value gate opened")
	}
	zero.Close()
	if err := zero.Wait(context.Background()); !errors.Is(err, errHandlerRegistrationGate) {
		t.Fatalf("zero-value Wait() error = %v", err)
	}
	zeroConnection, zeroRaw := newGateTrackedConnection()
	if recovered := invokeGate(
		&zero,
		&gateResponseWriter{},
		newGateRequest(zeroConnection, http.MethodGet, healthPath),
	); recovered != nil || zeroRaw.closeCalls.Load() != 1 {
		t.Fatal("zero-value gate did not fail closed on its exact tracked connection")
	}

	var calls atomic.Int32
	gate, err := NewHandlerRegistrationGate(http.HandlerFunc(
		func(writer http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			writer.WriteHeader(http.StatusNoContent)
		},
	))
	if err != nil {
		t.Fatal("NewHandlerRegistrationGate() failed")
	}
	if invalid, invalidErr := NewHandlerRegistrationGate(nil); invalidErr == nil || invalid != nil {
		t.Fatal("nil handler was accepted")
	}
	var typedNilHandler *HandlerRegistrationGate
	if invalid, invalidErr := NewHandlerRegistrationGate(typedNilHandler); invalidErr == nil || invalid != nil {
		t.Fatal("typed-nil handler was accepted")
	}
	if err := gate.Wait(context.Background()); !errors.Is(err, errHandlerRegistrationGate) ||
		err.Error() != "handler registration gate state failure" {
		t.Fatalf("pre-close Wait() error = %v", err)
	}

	bootConnection, bootRaw := newGateTrackedConnection()
	bootWriter := &gateResponseWriter{}
	if recovered := invokeGate(
		gate,
		bootWriter,
		newGateRequest(bootConnection, http.MethodGet, healthPath),
	); recovered != nil {
		t.Fatalf("bootstrapping refusal panic = %v", recovered)
	}
	assertGateRefusal(t, bootWriter, bootRaw, 1)
	if calls.Load() != 0 {
		t.Fatal("bootstrapping entry reached the dependency handler")
	}

	if !gate.Open() {
		t.Fatal("open transition failed")
	}
	if !gate.Open() {
		t.Fatal("open transition was not idempotent")
	}
	openConnection, openRaw := newGateTrackedConnection()
	openWriter := &gateResponseWriter{}
	gate.ServeHTTP(openWriter, newGateRequest(openConnection, http.MethodGet, healthPath))
	if calls.Load() != 1 || openWriter.headerCalls != 1 ||
		openRaw.closeCalls.Load() != 0 {
		t.Fatal("open entry did not execute exactly once")
	}

	gate.Close()
	gate.Close()
	if gate.Open() {
		t.Fatal("stopped gate reopened")
	}
	if err := gate.Wait(context.Background()); err != nil {
		t.Fatal("stopped quiescent gate did not join")
	}

	stoppedConnection, stoppedRaw := newGateTrackedConnection()
	stoppedWriter := &gateResponseWriter{}
	if recovered := invokeGate(
		gate,
		stoppedWriter,
		newGateRequest(stoppedConnection, http.MethodGet, healthPath),
	); recovered != nil {
		t.Fatalf("stopped refusal panic = %v", recovered)
	}
	assertGateRefusal(t, stoppedWriter, stoppedRaw, 1)
	if calls.Load() != 1 {
		t.Fatal("stopped entry reached the dependency handler")
	}
}

// TestHandlerRegistrationGatePanicAndBoundedWait prove exact release without waiter leaks.
func TestHandlerRegistrationGatePanicAndBoundedWait(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{})
	release := make(chan struct{})
	panicGate, err := NewHandlerRegistrationGate(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {
			close(entered)
			<-release
			panic("gate-private-panic-marker")
		},
	))
	if err != nil || !panicGate.Open() {
		t.Fatal("panic gate construction/open failed")
	}
	connection, _ := newGateTrackedConnection()
	panicDone := make(chan any, 1)
	go func() {
		defer func() { panicDone <- recover() }()
		panicGate.ServeHTTP(
			&gateResponseWriter{},
			newGateRequest(connection, http.MethodGet, healthPath),
		)
	}()
	<-entered
	panicGate.Close()
	var typedNilWait *gateTypedNilContext
	if err := panicGate.Wait(typedNilWait); !errors.Is(err, errHandlerRegistrationGate) {
		t.Fatalf("typed-nil active Wait() error = %v", err)
	}

	waitContext, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := panicGate.Wait(waitContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("active-handler Wait() error = %v", err)
	}

	const waiterCount = 64
	var waiters sync.WaitGroup
	waitErrors := make(chan error, waiterCount)
	for index := range waiterCount {
		waiters.Add(1)
		go func(cancelImmediately bool) {
			defer waiters.Done()
			waiterContext, cancelWaiter := context.WithTimeout(
				context.Background(),
				20*time.Millisecond,
			)
			if cancelImmediately {
				cancelWaiter()
			} else {
				defer cancelWaiter()
			}
			waitErrors <- panicGate.Wait(waiterContext)
		}(index%2 == 0)
	}
	waiters.Wait()
	close(waitErrors)
	for waitErr := range waitErrors {
		if !errors.Is(waitErr, context.Canceled) &&
			!errors.Is(waitErr, context.DeadlineExceeded) {
			t.Fatalf("concurrent active Wait() error = %v", waitErr)
		}
	}
	close(release)
	if recovered := <-panicDone; recovered != "gate-private-panic-marker" {
		t.Fatal("handler panic was hidden or changed")
	}
	if err := panicGate.Wait(context.Background()); err != nil {
		t.Fatal("panic path retained an active registration")
	}

	for range 64 {
		canceled, cancelWait := context.WithCancel(context.Background())
		cancelWait()
		if err := panicGate.Wait(canceled); err != nil {
			t.Fatal("quiescent gate made canceled wait contexts observable")
		}
	}
}

// TestHandlerRegistrationGateAddCloseRace proves no Add-versus-Wait race exists.
func TestHandlerRegistrationGateAddCloseRace(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	gate, err := NewHandlerRegistrationGate(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {
			calls.Add(1)
		},
	))
	if err != nil || !gate.Open() {
		t.Fatal("race gate construction/open failed")
	}

	const attempts = 256
	start := make(chan struct{})
	var workers sync.WaitGroup
	var refused atomic.Int32
	for range attempts {
		workers.Add(1)
		go func() {
			defer workers.Done()
			connection, raw := newGateTrackedConnection()
			<-start
			recovered := invokeGate(
				gate,
				&gateResponseWriter{},
				newGateRequest(connection, http.MethodPost, processPath),
			)
			if raw.closeCalls.Load() == 1 {
				refused.Add(1)
				if recovered != nil {
					t.Error("tracked refused race entry panicked")
				}
			} else if recovered != nil {
				t.Error("admitted race entry panicked")
			}
		}()
	}
	close(start)
	gate.Close()
	workers.Wait()
	if err := gate.Wait(context.Background()); err != nil {
		t.Fatal("closed gate did not join all admitted handlers")
	}
	if got := calls.Load() + refused.Load(); got != attempts {
		t.Fatalf("classified attempts = %d, want %d", got, attempts)
	}

	var transitionWorkers sync.WaitGroup
	for range attempts {
		transitionWorkers.Add(3)
		go func() {
			defer transitionWorkers.Done()
			gate.Close()
		}()
		go func() {
			defer transitionWorkers.Done()
			if gate.Open() {
				t.Error("concurrent stopped gate reopened")
			}
		}()
		go func() {
			defer transitionWorkers.Done()
			if waitErr := gate.Wait(context.Background()); waitErr != nil {
				t.Error("concurrent stopped gate wait failed")
			}
		}()
	}
	transitionWorkers.Wait()
}

// TestHandlerRegistrationGateQuiescenceWinsCancellation proves join precedence.
func TestHandlerRegistrationGateQuiescenceWinsCancellation(t *testing.T) {
	t.Parallel()

	gate, err := NewHandlerRegistrationGate(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {},
	))
	if err != nil || !gate.Open() {
		t.Fatal("quiescence gate construction/open failed")
	}
	gate.Close()

	gate.mu.Lock()
	gate.active = 1
	gate.mu.Unlock()
	parentContext, cancel := context.WithCancel(context.Background())
	waitContext := &gateObservedContext{
		Context:  parentContext,
		observed: make(chan struct{}),
	}
	waitResult := make(chan error, 1)
	go func() { waitResult <- gate.Wait(waitContext) }()
	<-waitContext.observed
	gate.mu.Lock()
	cancel()
	gate.active = 0
	gate.cond.Broadcast()
	gate.mu.Unlock()
	if waitErr := <-waitResult; waitErr != nil {
		t.Fatalf("proved quiescence lost to cancellation: %v", waitErr)
	}
}

// TestHandlerRegistrationGateUntrackedLateEntryAborts proves no implicit 200 fallback.
func TestHandlerRegistrationGateUntrackedLateEntryAborts(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	gate, err := NewHandlerRegistrationGate(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {
			calls.Add(1)
		},
	))
	if err != nil || !gate.Open() {
		t.Fatal("untracked gate construction/open failed")
	}
	gate.Close()

	contexts := []context.Context{
		context.Background(),
		context.WithValue(
			context.Background(),
			transportContextKey{},
			(*transportState)(nil),
		),
	}
	for index, requestContext := range contexts {
		writer := &gateResponseWriter{}
		request, _ := http.NewRequestWithContext(
			requestContext,
			http.MethodGet,
			"http://listener/healthz",
			nil,
		)
		recovered := invokeGate(gate, writer, request)
		if recovered != http.ErrAbortHandler {
			t.Fatalf("untracked case %d panic = %v", index, recovered)
		}
		if writer.writeCalls != 0 || writer.headerCalls != 0 ||
			len(writer.Header()) != 0 {
			t.Fatalf("untracked case %d fabricated a response", index)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("untracked late entry reached dependency handler")
	}

	closeErrorRaw := &gateCloseErrorConn{
		transportRecordingConn: newTransportRecordingConn(nil),
	}
	closeErrorState := newTransportState(nil)
	closeErrorConnection := newTrackedConn(closeErrorRaw, closeErrorState, nil)
	closeErrorState.connection.Store(closeErrorConnection)
	closeErrorWriter := &gateResponseWriter{}
	if recovered := invokeGate(
		gate,
		closeErrorWriter,
		newGateRequest(closeErrorConnection, http.MethodGet, healthPath),
	); recovered != http.ErrAbortHandler {
		t.Fatalf("uncertain exact-close panic = %v", recovered)
	}
	if closeErrorRaw.closeCalls.Load() != 1 ||
		closeErrorWriter.writeCalls != 0 ||
		closeErrorWriter.headerCalls != 0 ||
		len(closeErrorWriter.Header()) != 0 ||
		calls.Load() != 0 {
		t.Fatal("uncertain exact close wrote a response or touched dependencies")
	}

	raw, listenErr := net.Listen("tcp", "127.0.0.1:0")
	if listenErr != nil {
		t.Fatal("untracked real listener construction failed")
	}
	var diagnostic bytes.Buffer
	server := &http.Server{
		Handler:                      gate,
		ErrorLog:                     log.New(&diagnostic, "", 0),
		DisableGeneralOptionsHandler: true,
	}
	serveDone := make(chan struct{})
	go func() {
		_ = server.Serve(raw)
		close(serveDone)
	}()
	response := rawBoundaryExchange(
		t,
		raw.Addr().String(),
		"GET /healthz HTTP/1.1\r\nHost: "+raw.Addr().String()+"\r\n\r\n",
	)
	_ = server.Close()
	_ = raw.Close()
	<-serveDone
	if response != "" || diagnostic.Len() != 0 || calls.Load() != 0 {
		t.Fatal("untracked real late entry emitted response, diagnostic, or dependency work")
	}
}

// TestHandlerRegistrationGateContainsUncertainTrackedClose proves hostile raw
// close behavior cannot strand transport ownership during late refusal.
func TestHandlerRegistrationGateContainsUncertainTrackedClose(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		closeError bool
		closePanic bool
		wantAbort  bool
		wantFatal  int32
	}{
		{name: observationSuccess},
		{name: "error", closeError: true, wantAbort: true, wantFatal: 1},
		{name: testPanicName, closePanic: true, wantAbort: true, wantFatal: 1},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			recording := newTransportRecordingConn(nil)
			var raw net.Conn = recording
			if testCase.closeError {
				raw = &gateCloseErrorConn{transportRecordingConn: recording}
			}
			if testCase.closePanic {
				raw = &gatePanicCloseConn{transportRecordingConn: recording}
			}
			state := newTransportState(nil)
			var releases atomic.Int32
			connection := newTrackedConn(raw, state, func() {
				releases.Add(1)
			})
			state.connection.Store(connection)
			fatal := &serverTestFatal{}
			gate, err := newHandlerRegistrationGate(
				http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Error("late refusal reached dependency handler")
				}),
				allowHandlerActivation{},
				fatal,
			)
			if err != nil || !gate.Open() {
				t.Fatal("fatal-aware gate construction/open failed")
			}
			gate.Close()
			writer := &gateResponseWriter{}
			recovered := invokeGate(
				gate,
				writer,
				newGateRequest(connection, http.MethodGet, healthPath),
			)
			if (recovered == http.ErrAbortHandler) != testCase.wantAbort ||
				fatal.calls.Load() != testCase.wantFatal ||
				releases.Load() != 1 ||
				connection.contextState.Load() != transportContextClosed ||
				writer.writeCalls != 0 || writer.headerCalls != 0 ||
				len(writer.Header()) != 0 {
				t.Fatal("uncertain tracked close escaped, leaked, or fabricated output")
			}
			if testCase.wantAbort != (connection.closeErr != nil) {
				t.Fatal("tracked close result did not match terminal certainty")
			}
			if strings.Contains(fmt.Sprint(connection.closeErr), "private") ||
				strings.Contains(fmt.Sprint(connection.closeErr), "marker") {
				t.Fatal("uncertain tracked close leaked its raw cause")
			}
		})
	}
}

// TestHandlerRegistrationGateRequiresActivationAuthority proves fatal startup
// facts prevent the one-time gate-open transition.
func TestHandlerRegistrationGateRequiresActivationAuthority(t *testing.T) {
	t.Parallel()

	var typedNil *gateActivationAuthority
	if gate, err := newHandlerRegistrationGate(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		typedNil,
		&serverTestFatal{},
	); err == nil || gate != nil {
		t.Fatal("gate accepted a typed-nil activation authority")
	}

	tests := []struct {
		name       string
		panicValue any
	}{
		{name: "fatal before open"},
		{name: "authority panic", panicValue: "activation-private-panic-marker"},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			activation := &gateActivationAuthority{panicVal: testCase.panicValue}
			fatal := &serverTestFatal{panicVal: "fatal-private-panic-marker"}
			var handlerCalls atomic.Int32
			gate, err := newHandlerRegistrationGate(
				http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					handlerCalls.Add(1)
				}),
				activation,
				fatal,
			)
			if err != nil || gate.Open() {
				t.Fatal("activation-denied gate opened")
			}
			connection, raw := newGateTrackedConnection()
			writer := &gateResponseWriter{}
			if recovered := invokeGate(
				gate,
				writer,
				newGateRequest(connection, http.MethodGet, healthPath),
			); recovered != nil {
				t.Fatalf("ordinary not-ready refusal panic = %v", recovered)
			}
			gate.mu.Lock()
			active := gate.active
			gate.mu.Unlock()
			if activation.calls.Load() != 1 ||
				handlerCalls.Load() != 0 || fatal.calls.Load() != 1 ||
				active != 0 || raw.closeCalls.Load() != 1 ||
				writer.writeCalls != 0 || writer.headerCalls != 0 ||
				len(writer.Header()) != 0 {
				t.Fatal("activation denial admitted or fabricated work")
			}
		})
	}
}

// TestHandlerRegistrationGateDoesNotResampleActivation proves normal route
// registration remains readiness and activation agnostic after opening.
func TestHandlerRegistrationGateDoesNotResampleActivation(t *testing.T) {
	t.Parallel()

	activation := &gateActivationAuthority{}
	activation.allowed.Store(true)
	fatal := &serverTestFatal{}
	var handlerCalls atomic.Int32
	gate, err := newHandlerRegistrationGate(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			handlerCalls.Add(1)
		}),
		activation,
		fatal,
	)
	if err != nil || !gate.Open() {
		t.Fatal("activation-authorized gate construction/open failed")
	}
	activation.allowed.Store(false)
	connection, raw := newGateTrackedConnection()
	defer func() { _ = connection.Close() }()
	writer := &gateResponseWriter{}
	if recovered := invokeGate(
		gate,
		writer,
		newGateRequest(connection, http.MethodGet, healthPath),
	); recovered != nil {
		t.Fatalf("open-gate registration panic = %v", recovered)
	}
	gate.mu.Lock()
	active := gate.active
	gate.mu.Unlock()
	if activation.calls.Load() != 1 || fatal.calls.Load() != 0 ||
		handlerCalls.Load() != 1 || active != 0 ||
		raw.closeCalls.Load() != 0 ||
		writer.writeCalls != 0 || writer.headerCalls != 0 ||
		len(writer.Header()) != 0 {
		t.Fatal("open gate resampled activation or corrupted registration")
	}
}

// TestHandlerRegistrationGateUsesClaimLinearization proves fatal-first denial
// and claim-first activation remain deterministically ordered.
func TestHandlerRegistrationGateUsesClaimLinearization(t *testing.T) {
	t.Parallel()

	t.Run("fatal first", func(t *testing.T) {
		t.Parallel()
		activation := &gateClaimActivationAuthority{
			claimed: make(chan struct{}),
			release: make(chan struct{}),
		}
		activation.state.Store(gateActivationTerminal)
		gate, err := newHandlerRegistrationGate(
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
			activation,
			&serverTestFatal{},
		)
		if err != nil || gate.Open() {
			t.Fatal("fatal-first activation opened the gate")
		}
	})

	t.Run("claim first", func(t *testing.T) {
		t.Parallel()
		activation := &gateClaimActivationAuthority{
			claimed: make(chan struct{}),
			release: make(chan struct{}),
		}
		activation.state.Store(gateActivationArmed)
		gate, err := newHandlerRegistrationGate(
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
			activation,
			&serverTestFatal{},
		)
		if err != nil {
			t.Fatal("claim-first gate construction failed")
		}
		openDone := make(chan bool, 1)
		go func() { openDone <- gate.Open() }()
		<-activation.claimed
		activation.state.Store(gateActivationTerminal)
		close(activation.release)
		if !<-openDone {
			t.Fatal("claimed activation lost after its linearization")
		}
	})
}

// TestHandlerRegistrationGateRejectsTypedNilWriter proves pre-registration validation.
func TestHandlerRegistrationGateRejectsTypedNilWriter(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	gate, err := NewHandlerRegistrationGate(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {
			calls.Add(1)
		},
	))
	if err != nil || !gate.Open() {
		t.Fatal("typed-nil writer gate construction/open failed")
	}
	connection, raw := newGateTrackedConnection()
	var writer *gateResponseWriter
	if recovered := invokeGate(
		gate,
		writer,
		newGateRequest(connection, http.MethodGet, healthPath),
	); recovered != nil {
		t.Fatalf("tracked typed-nil writer panic = %v", recovered)
	}
	if raw.closeCalls.Load() != 1 || calls.Load() != 0 {
		t.Fatal("typed-nil writer did not exact-close before dependency entry")
	}
	gate.Close()
	if err := gate.Wait(context.Background()); err != nil {
		t.Fatal("typed-nil writer retained one handler registration")
	}
}

// TestHandlerRegistrationGateScriptedWireMatrix proves every late route writes zero bytes.
func TestHandlerRegistrationGateScriptedWireMatrix(t *testing.T) {
	t.Parallel()

	gate, err := NewHandlerRegistrationGate(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {
			t.Error("stopped scripted entry reached the dependency handler")
		},
	))
	if err != nil || !gate.Open() {
		t.Fatal("scripted gate construction/open failed")
	}
	gate.Close()

	raw := newTransportScriptedListener()
	listener, err := NewServerListener(raw, nil)
	if err != nil {
		t.Fatal("scripted ServerListener construction failed")
	}
	server := &http.Server{
		Handler:                      gate,
		ConnContext:                  listener.ConnContext,
		ErrorLog:                     log.New(io.Discard, "", 0),
		DisableGeneralOptionsHandler: true,
	}
	serveDone := make(chan struct{})
	go func() {
		_ = server.Serve(listener)
		close(serveDone)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
		<-serveDone
	})

	requests := gateWireRequests("listener")
	for index, request := range requests {
		serverConnection, clientConnection := net.Pipe()
		countedConnection := &gateCountingConn{Conn: serverConnection}
		raw.enqueue(countedConnection)
		_ = clientConnection.SetDeadline(time.Now().Add(time.Second))
		if _, err := io.WriteString(clientConnection, request); err != nil {
			t.Fatalf("scripted request %d write failed", index)
		}
		response, readErr := io.ReadAll(clientConnection)
		_ = clientConnection.Close()
		if len(response) != 0 || readErr != nil {
			t.Fatalf("scripted request %d response = %q/%v", index, response, readErr)
		}
		if countedConnection.closeCalls.Load() != 1 {
			t.Fatalf(
				"scripted request %d raw close count = %d",
				index,
				countedConnection.closeCalls.Load(),
			)
		}
	}
}

// TestHandlerRegistrationGateRealWireMatrix proves open behavior and exact late close.
func TestHandlerRegistrationGateRealWireMatrix(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("real gate listener construction failed")
	}
	listener, err := NewServerListener(raw, nil)
	if err != nil {
		_ = raw.Close()
		t.Fatal("real ServerListener construction failed")
	}
	validator, err := NewRequestValidator()
	if err != nil {
		_ = listener.Close()
		t.Fatal("real gate validator construction failed")
	}
	matcher := &gateMatrixMatcher{}
	readiness := &gateMatrixReadiness{}
	readiness.ready.Store(true)
	processor := &boundaryProcessor{}
	notifier := &boundaryFatalNotifier{}
	boundary, err := NewHTTPBoundary(BoundaryConfig{
		Authority:       raw.Addr().String(),
		RequestDeadline: time.Second,
		MaxInFlight:     1,
		MaxWaiters:      1,
		AdmissionWait:   10 * time.Millisecond,
	}, matcher, readiness, processor, notifier, validator)
	if err != nil {
		_ = listener.Close()
		t.Fatal("real gate boundary construction failed")
	}
	gate, err := NewHandlerRegistrationGate(boundary)
	if err != nil || !gate.Open() {
		_ = listener.Close()
		t.Fatal("real gate construction/open failed")
	}
	server := &http.Server{
		Handler:                      gate,
		ConnContext:                  listener.ConnContext,
		ErrorLog:                     log.New(io.Discard, "", 0),
		DisableGeneralOptionsHandler: true,
		MaxHeaderBytes:               transportServerMaxHeaderBytes,
	}
	serveDone := make(chan struct{})
	go func() {
		_ = server.Serve(listener)
		close(serveDone)
	}()
	t.Cleanup(func() {
		boundary.Close()
		gate.Close()
		_ = server.Close()
		_ = listener.Close()
		<-serveDone
	})

	address := raw.Addr().String()
	openRequests := gateWireRequests(address)
	for index, request := range openRequests {
		response := rawBoundaryExchange(t, address, request)
		if !strings.HasPrefix(response, "HTTP/1.1 ") {
			t.Fatalf("open request %d lacked an HTTP response: %q", index, response)
		}
	}
	if readiness.calls.Load() == 0 {
		t.Fatal("open readiness request did not reach its no-I/O source")
	}

	readiness.ready.Store(false)
	boundary.Close()
	healthWhileNotReady := rawBoundaryExchange(
		t,
		address,
		"GET /healthz HTTP/1.1\r\nHost: "+address+"\r\n\r\n",
	)
	if !strings.HasPrefix(healthWhileNotReady, "HTTP/1.1 200 ") {
		t.Fatalf("health while not ready/closed admission = %q", healthWhileNotReady)
	}
	readinessWhileClosed := rawBoundaryExchange(
		t,
		address,
		"GET /readyz HTTP/1.1\r\nHost: "+address+"\r\n\r\n",
	)
	if !strings.HasPrefix(readinessWhileClosed, "HTTP/1.1 503 ") {
		t.Fatalf("readiness while not ready = %q", readinessWhileClosed)
	}
	openMatcherCalls := matcher.calls.Load()
	openReadinessCalls := readiness.calls.Load()
	openProcessorCalls := processor.calls.Load()
	openNotifierCalls := notifier.calls.Load()

	gate.Close()
	if err := gate.Wait(context.Background()); err != nil {
		t.Fatal("real gate did not join before late matrix")
	}
	for index, request := range openRequests {
		response := rawBoundaryExchange(t, address, request)
		if response != "" {
			t.Fatalf("late request %d received response bytes: %q", index, response)
		}
	}
	if matcher.calls.Load() != openMatcherCalls ||
		readiness.calls.Load() != openReadinessCalls ||
		processor.calls.Load() != openProcessorCalls ||
		notifier.calls.Load() != openNotifierCalls {
		t.Fatal("late matrix touched capability, readiness, processor, or fatal dependencies")
	}
}

// TestServerLifecycleSeamsRejectDiagnosticTraversal proves retained owners stay opaque.
func TestServerLifecycleSeamsRejectDiagnosticTraversal(t *testing.T) {
	t.Parallel()

	raw := newTransportScriptedListener()
	listener, err := NewServerListener(raw, nil)
	if err != nil {
		t.Fatal("privacy listener construction failed")
	}
	t.Cleanup(func() { _ = listener.Close() })
	gate, err := NewHandlerRegistrationGate(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {},
	))
	if err != nil {
		t.Fatal("privacy gate construction failed")
	}
	for _, value := range []any{listener, gate} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if got := fmt.Sprintf(format, value); got != transportRedacted {
				t.Fatalf("format %s = %q", format, got)
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("JSON serialization exposed retained lifecycle state")
		}
		textMarshaler, ok := value.(interface{ MarshalText() ([]byte, error) })
		if !ok {
			t.Fatal("lifecycle owner lacks text serialization refusal")
		}
		if _, err := textMarshaler.MarshalText(); err == nil {
			t.Fatal("text serialization exposed retained lifecycle state")
		}
	}
}

// newGateTrackedConnection constructs one exact-close request transport.
func newGateTrackedConnection() (*trackedConn, *transportRecordingConn) {
	raw := newTransportRecordingConn(nil)
	state := newTransportState(nil)
	connection := newTrackedConn(raw, state, nil)
	state.connection.Store(connection)
	return connection, raw
}

// newGateRequest installs one exact tracked transport context.
func newGateRequest(
	connection *trackedConn,
	method string,
	target string,
) *http.Request {
	request, _ := http.NewRequestWithContext(
		transportConnContext(context.Background(), connection),
		method,
		"http://listener"+target,
		nil,
	)
	return request
}

// assertGateRefusal proves one exact close and zero response writes.
func assertGateRefusal(
	t *testing.T,
	writer *gateResponseWriter,
	raw *transportRecordingConn,
	wantClose int32,
) {
	t.Helper()
	if raw.closeCalls.Load() != wantClose {
		t.Fatalf("connection close count = %d, want %d", raw.closeCalls.Load(), wantClose)
	}
	if writer.writeCalls != 0 || writer.headerCalls != 0 || len(writer.Header()) != 0 {
		t.Fatal("refused gate entry wrote response bytes or headers")
	}
}

// invokeGate captures only the handler-abort sentinel for direct seam tests.
func invokeGate(
	gate *HandlerRegistrationGate,
	writer http.ResponseWriter,
	request *http.Request,
) (recovered any) {
	defer func() { recovered = recover() }()
	gate.ServeHTTP(writer, request)
	return nil
}

// invokeConnContext captures the stable private server-context sentinel.
func invokeConnContext(
	ctx context.Context,
	connContext func(context.Context, net.Conn) context.Context,
	connection net.Conn,
) (recovered any) {
	defer func() { recovered = recover() }()
	_ = connContext(ctx, connection)
	return nil
}

// gateWireRequests returns the required lifecycle route/method matrix.
func gateWireRequests(authority string) []string {
	return []string{
		"GET /healthz HTTP/1.1\r\nHost: " + authority + "\r\n\r\n",
		"HEAD /healthz HTTP/1.1\r\nHost: " + authority + "\r\n\r\n",
		"GET /readyz HTTP/1.1\r\nHost: " + authority + "\r\n\r\n",
		"POST /v1/process HTTP/1.1\r\nHost: " + authority +
			"\r\nContent-Length: 0\r\n\r\n",
		"GET /unknown HTTP/1.1\r\nHost: " + authority + "\r\n\r\n",
		"OPTIONS * HTTP/1.1\r\nHost: " + authority + "\r\n\r\n",
	}
}

var _ http.ResponseWriter = (*gateResponseWriter)(nil)
