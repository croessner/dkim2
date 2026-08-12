package httpjson

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
)

type serverTestListen struct {
	calls    atomic.Int32
	listener net.Listener
	err      error
	panicVal any
}

// Listen records one acquisition and returns the scripted outcome.
func (s *serverTestListen) Listen(network, address string) (net.Listener, error) {
	s.calls.Add(1)
	if network != "tcp" || address != boundaryTestAuthority {
		return nil, errors.New("server-test-authority-marker")
	}
	if s.panicVal != nil {
		panic(s.panicVal)
	}
	return s.listener, s.err
}

type serverTestListener struct {
	accept     func() (net.Conn, error)
	closeCalls atomic.Int32
	closed     chan struct{}
	closeOnce  sync.Once
	closeErr   error
	closePanic any
	address    net.Addr
	addrPanic  any
}

// newServerTestListener constructs one deterministic listener owner.
func newServerTestListener(
	accept func() (net.Conn, error),
) *serverTestListener {
	return &serverTestListener{
		accept: accept,
		closed: make(chan struct{}),
	}
}

// Accept returns the configured transport result.
func (l *serverTestListener) Accept() (net.Conn, error) {
	if l.accept == nil {
		<-l.closed
		return nil, net.ErrClosed
	}
	return l.accept()
}

// Close interrupts blocked acceptance exactly once.
func (l *serverTestListener) Close() error {
	l.closeOnce.Do(func() {
		l.closeCalls.Add(1)
		close(l.closed)
		if l.closePanic != nil {
			panic(l.closePanic)
		}
	})
	return l.closeErr
}

// Addr returns the exact canonical test authority.
func (l *serverTestListener) Addr() net.Addr {
	if l.addrPanic != nil {
		panic(l.addrPanic)
	}
	if l.address != nil {
		return l.address
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
}

type serverTestFatal struct {
	calls    atomic.Int32
	panicVal any
}

type serverTestServeObserver struct {
	calls    atomic.Int32
	panicVal any
	entered  chan struct{}
	release  <-chan struct{}
}

type serverMalformedContext struct {
	deadline      time.Time
	hasDeadline   bool
	done          <-chan struct{}
	err           error
	panicDeadline bool
}

// Deadline returns the scripted hostile deadline observation.
func (c *serverMalformedContext) Deadline() (time.Time, bool) {
	if c.panicDeadline {
		panic("context-private-deadline-marker")
	}
	return c.deadline, c.hasDeadline
}

// Done returns the scripted hostile cancellation channel.
func (c *serverMalformedContext) Done() <-chan struct{} { return c.done }

// Err returns the scripted hostile cancellation state.
func (c *serverMalformedContext) Err() error { return c.err }

// Value returns no retained caller values.
func (*serverMalformedContext) Value(any) any { return nil }

// NotifyServeReturn records one synchronous transport termination handoff.
func (o *serverTestServeObserver) NotifyServeReturn() {
	o.calls.Add(1)
	if o.entered != nil {
		close(o.entered)
	}
	if o.release != nil {
		<-o.release
	}
	if o.panicVal != nil {
		panic(o.panicVal)
	}
}

// TestServerRuntimeHandsOffFatalBeforePublishingTransportTermination freezes defer order.
func TestServerRuntimeHandsOffFatalBeforePublishingTransportTermination(t *testing.T) {
	t.Parallel()
	raw := newServerTestListener(func() (net.Conn, error) {
		return nil, errors.New("serve-private-error-marker")
	})
	runtime := bindServerRuntimeFixture(t, raw, &serverTestFatal{})
	observerEntered := make(chan struct{})
	observerRelease := make(chan struct{})
	observer := &serverTestServeObserver{
		entered: observerEntered,
		release: observerRelease,
	}
	runtime.observer = observer
	result := make(chan error, 1)
	go func() { result <- runtime.Serve() }()
	<-observerEntered
	if runtime.serveReturned.Load() || !runtime.Serving() {
		t.Fatal("transport termination published before app fatal handoff")
	}
	close(observerRelease)
	if err := <-result; !IsServerRuntimeError(err) {
		t.Fatalf("Serve returned %T", err)
	}
	if !runtime.serveReturned.Load() || runtime.Serving() ||
		observer.calls.Load() != 1 {
		t.Fatal("transport termination did not follow the exact observer handoff")
	}
}

// NotifyFatal records one content-free fatal transition.
func (n *serverTestFatal) NotifyFatal() {
	n.calls.Add(1)
	if n.panicVal != nil {
		panic(n.panicVal)
	}
}

// TestServerFactoryAssemblyIsPureAndBindOwnsListen proves acquisition placement.
func TestServerFactoryAssemblyIsPureAndBindOwnsListen(t *testing.T) {
	t.Parallel()

	factory := NewServerFactory()
	if factory == nil {
		t.Fatal("NewServerFactory() returned nil")
	}
	if assembly, err := factory.Assemble(app.HTTPAssemblyInput{}); err == nil || assembly != nil {
		t.Fatal("factory accepted an invalid app assembly input")
	}

	raw := newServerTestListener(nil)
	listen := &serverTestListen{listener: raw}
	baseContext, cancelBase := context.WithCancel(context.Background())
	t.Cleanup(cancelBase)
	assembly := newServerAssemblyFixture(baseContext, t, listen.Listen, &serverTestFatal{})
	if listen.calls.Load() != 0 {
		t.Fatal("pure assembly acquired a listener")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if runtime, err := assembly.Bind(cancelled); err == nil || runtime != nil {
		t.Fatal("canceled Bind() acquired or returned a runtime")
	}
	if listen.calls.Load() != 0 {
		t.Fatal("pre-canceled Bind() called net.Listen")
	}

	raw = newServerTestListener(nil)
	listen = &serverTestListen{listener: raw}
	assembly = newServerAssemblyFixture(baseContext, t, listen.Listen, &serverTestFatal{})
	runtimeValue, err := assembly.Bind(context.Background())
	if err != nil || runtimeValue == nil || listen.calls.Load() != 1 {
		t.Fatal("Bind() did not own exactly one listener acquisition")
	}
	runtime, ok := runtimeValue.(*serverRuntime)
	if !ok || runtime.server == nil || runtime.listener == nil {
		t.Fatal("Bind() returned an incomplete runtime")
	}
	if runtime.ServeStarted() == nil ||
		!IsServerRuntimeError(runtime.Activate()) {
		t.Fatal("runtime forged activation before its serve-loop proof")
	}
	if runtime.server.ReadHeaderTimeout != 5*time.Second ||
		runtime.server.ReadTimeout != 30*time.Second ||
		runtime.server.WriteTimeout != 31*time.Second ||
		runtime.server.MaxHeaderBytes != testServerMaxHeaderBytes ||
		!runtime.server.DisableGeneralOptionsHandler {
		t.Fatal("bound http.Server does not match the exact immutable snapshot")
	}
	if got := runtime.server.BaseContext(runtime.listener); got != baseContext {
		t.Fatal("http.Server BaseContext is not the exact daemon parent")
	}
}

// TestServerAssemblyBindContainsFailures proves stable bind diagnostics.
func TestServerAssemblyBindContainsFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		listen *serverTestListen
	}{
		{
			name:   "raw error",
			listen: &serverTestListen{err: errors.New("bind-private-error-marker")},
		},
		{
			name:   testPanicName,
			listen: &serverTestListen{panicVal: "bind-private-panic-marker"},
		},
		{
			name: "typed nil listener",
			listen: &serverTestListen{
				listener: (*serverTestListener)(nil),
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			assembly := newServerAssemblyFixture(
				context.Background(),
				t,
				testCase.listen.Listen,
				&serverTestFatal{},
			)
			runtime, err := assembly.Bind(context.Background())
			if runtime != nil || !IsServerRuntimeError(err) ||
				stringsContainPrivateMarker(fmt.Sprint(err)) {
				t.Fatal("Bind() leaked or widened its stable failure")
			}
			if testCase.listen.calls.Load() != 1 {
				t.Fatal("Bind() did not attempt exactly one acquisition")
			}
		})
	}
}

// TestServerAssemblyRejectsDivergentListenerFacts proves exact acquisition
// validation and post-listen cancellation rollback.
func TestServerAssemblyRejectsDivergentListenerFacts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		listener *serverTestListener
	}{
		{
			name: "wrong address",
			listener: func() *serverTestListener {
				listener := newServerTestListener(nil)
				listener.address = &net.TCPAddr{
					IP:   net.IPv4(127, 0, 0, 1),
					Port: 8081,
				}
				return listener
			}(),
		},
		{
			name: "address panic",
			listener: func() *serverTestListener {
				listener := newServerTestListener(nil)
				listener.addrPanic = "bind-private-address-marker"
				return listener
			}(),
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			listen := &serverTestListen{listener: testCase.listener}
			assembly := newServerAssemblyFixture(
				context.Background(),
				t,
				listen.Listen,
				&serverTestFatal{},
			)
			runtime, err := assembly.Bind(context.Background())
			if runtime != nil || !IsServerRuntimeError(err) ||
				testCase.listener.closeCalls.Load() != 1 {
				t.Fatal("Bind() did not contain and roll back divergent listener facts")
			}
		})
	}

	var typedNilContext *gateTypedNilContext
	listen := &serverTestListen{listener: newServerTestListener(nil)}
	assembly := newServerAssemblyFixture(
		context.Background(),
		t,
		listen.Listen,
		&serverTestFatal{},
	)
	if runtime, err := assembly.Bind(typedNilContext); runtime != nil ||
		!IsServerRuntimeError(err) || listen.calls.Load() != 0 {
		t.Fatal("Bind() accepted a typed-nil context")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	raw := newServerTestListener(nil)
	assembly = newServerAssemblyFixture(
		context.Background(),
		t,
		func(string, string) (net.Listener, error) {
			cancel()
			return raw, nil
		},
		&serverTestFatal{},
	)
	if runtime, err := assembly.Bind(cancelled); runtime != nil ||
		!IsServerRuntimeError(err) || raw.closeCalls.Load() != 1 {
		t.Fatal("Bind() did not roll back post-acquisition cancellation")
	}
}

// TestServerAssemblyRejectsIPv4MappedIPv6Authority freezes the config-aligned
// canonical loopback rule.
func TestServerAssemblyRejectsIPv4MappedIPv6Authority(t *testing.T) {
	t.Parallel()

	settings := serverSettings{
		authority:         "[::ffff:127.0.0.1]:8080",
		readHeaderTimeout: 5 * time.Second,
		readTimeout:       30 * time.Second,
		writeTimeout:      31 * time.Second,
		requestDeadline:   30 * time.Second,
		shutdownTimeout:   30 * time.Second,
		maxInFlight:       1,
		maxWaiters:        1,
		admissionWait:     10 * time.Millisecond,
	}
	readiness := &boundaryReadiness{}
	readiness.ready.Store(true)
	assembly, err := newServerAssembly(
		context.Background(),
		settings,
		&boundaryCapabilityMatcher{value: bytes.Repeat([]byte{0xa5}, 32)},
		readiness,
		&boundaryProcessor{},
		&serverTestFatal{},
		allowHandlerActivation{},
		&serverTestServeObserver{},
		(&serverTestListen{}).Listen,
	)
	if assembly != nil || !IsServerRuntimeError(err) {
		t.Fatal("assembly accepted an IPv4-mapped IPv6 listener")
	}
}

// TestServerRuntimeContainsServeFailures proves fatal and panic containment.
func TestServerRuntimeContainsServeFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		accept  func() (net.Conn, error)
		corrupt func(*serverRuntime)
	}{
		{
			name: "raw accept error",
			accept: func() (net.Conn, error) {
				return nil, errors.New("serve-private-error-marker")
			},
		},
		{
			name: "toxic accept panic",
			accept: func() (net.Conn, error) {
				panic("serve-private-panic-marker")
			},
		},
		{
			name: "private conn context sentinel",
			accept: func() (net.Conn, error) {
				server, client := net.Pipe()
				_ = client.Close()
				return server, nil
			},
			corrupt: func(runtime *serverRuntime) {
				runtime.listener.tracked.owner = nil
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			fatal := &serverTestFatal{}
			raw := newServerTestListener(testCase.accept)
			runtime := bindServerRuntimeFixture(t, raw, fatal)
			observer := &serverTestServeObserver{}
			if testCase.name == "toxic accept panic" {
				observer.panicVal = "observer-private-panic-marker"
			}
			runtime.observer = observer
			if testCase.corrupt != nil {
				testCase.corrupt(runtime)
			}
			err := runtime.Serve()
			if !IsServerRuntimeError(err) ||
				stringsContainPrivateMarker(fmt.Sprint(err)) {
				t.Fatal("Serve() leaked or widened one fatal outcome")
			}
			if fatal.calls.Load() != 0 || observer.calls.Load() != 1 ||
				raw.closeCalls.Load() != 1 {
				t.Fatal("Serve() classified app state or did not close the listener exactly once")
			}
		})
	}
}

// TestServerRuntimeDoesNotForgeAcceptLoopEntry proves failures before
// net/http's first Accept remain distinguishable from a live serve loop.
func TestServerRuntimeDoesNotForgeAcceptLoopEntry(t *testing.T) {
	t.Parallel()

	runtime := bindServerRuntimeFixture(
		t,
		newServerTestListener(nil),
		&serverTestFatal{},
	)
	observer := &serverTestServeObserver{}
	runtime.observer = observer
	runtime.server.BaseContext = func(net.Listener) context.Context {
		panic("base-context-private-marker")
	}
	if err := runtime.Serve(); !IsServerRuntimeError(err) ||
		observer.calls.Load() != 1 || runtime.Serving() {
		t.Fatal("pre-Accept Serve failure was not contained synchronously")
	}
	select {
	case <-runtime.ServeStarted():
		t.Fatal("pre-Accept Serve failure forged accept-loop entry")
	default:
	}
	if err := runtime.Activate(); !IsServerRuntimeError(err) {
		t.Fatal("Activate() accepted a pre-Accept Serve failure")
	}
}

// TestServerRuntimeContainsStickyListenerCloseFailures proves exact-once close
// behavior remains stable after raw errors and panics.
func TestServerRuntimeContainsStickyListenerCloseFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		closeErr   error
		closePanic any
	}{
		{
			name:     "raw error",
			closeErr: errors.New("close-private-error-marker"),
		},
		{
			name:       testPanicName,
			closePanic: "close-private-panic-marker",
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			raw := newServerTestListener(nil)
			raw.closeErr = testCase.closeErr
			raw.closePanic = testCase.closePanic
			runtime := bindServerRuntimeFixture(t, raw, &serverTestFatal{})
			for range 2 {
				err := runtime.CloseListener()
				if !IsServerRuntimeError(err) ||
					stringsContainPrivateMarker(fmt.Sprint(err)) {
					t.Fatal("CloseListener() did not retain a stable failure")
				}
			}
			if raw.closeCalls.Load() != 1 {
				t.Fatal("CloseListener() repeated the raw close")
			}
		})
	}
}

// TestServerRuntimeServeIsOneShot proves concurrent serve ownership cannot
// create a second net/http loop.
func TestServerRuntimeServeIsOneShot(t *testing.T) {
	t.Parallel()

	acceptStarted := make(chan struct{})
	var raw *serverTestListener
	raw = newServerTestListener(func() (net.Conn, error) {
		select {
		case <-acceptStarted:
		default:
			close(acceptStarted)
		}
		<-raw.closed
		return nil, net.ErrClosed
	})
	runtime := bindServerRuntimeFixture(t, raw, &serverTestFatal{})
	firstDone := make(chan error, 1)
	go func() { firstDone <- runtime.Serve() }()
	<-acceptStarted
	if err := runtime.Serve(); !IsServerRuntimeError(err) {
		t.Fatal("Serve() admitted a second loop")
	}
	if err := runtime.CloseListener(); err != nil {
		t.Fatal("CloseListener() failed")
	}
	if err := <-firstDone; !IsServerRuntimeError(err) {
		t.Fatal("first Serve() did not return its stable terminal result")
	}
	if raw.closeCalls.Load() != 1 {
		t.Fatal("one-shot serve ownership repeated listener close")
	}
}

// TestServerRuntimeStoppedBeforeServeCannotActivate proves startup and stopping
// transitions cannot reopen handler registration.
func TestServerRuntimeStoppedBeforeServeCannotActivate(t *testing.T) {
	t.Parallel()

	acceptStarted := make(chan struct{})
	var raw *serverTestListener
	raw = newServerTestListener(func() (net.Conn, error) {
		select {
		case <-acceptStarted:
		default:
			close(acceptStarted)
		}
		<-raw.closed
		return nil, net.ErrClosed
	})
	runtime := bindServerRuntimeFixture(t, raw, &serverTestFatal{})
	runtime.RejectNewRequests()
	serveDone := make(chan error, 1)
	go func() { serveDone <- runtime.Serve() }()
	<-runtime.ServeStarted()
	if err := runtime.Activate(); !IsServerRuntimeError(err) ||
		runtime.gate.Open() {
		t.Fatal("stopping transition lost to late activation")
	}
	if err := runtime.CloseListener(); err != nil {
		t.Fatal("CloseListener() failed")
	}
	if err := <-serveDone; !IsServerRuntimeError(err) {
		t.Fatal("Serve() did not return its stable terminal result")
	}
}

// TestServerRuntimeCleanStopAndEarlyReturn prove stopping classification.
func TestServerRuntimeCleanStopAndEarlyReturn(t *testing.T) {
	t.Parallel()

	t.Run("clean stop", func(t *testing.T) {
		t.Parallel()
		acceptStarted := make(chan struct{})
		var raw *serverTestListener
		raw = newServerTestListener(func() (net.Conn, error) {
			select {
			case <-acceptStarted:
			default:
				close(acceptStarted)
			}
			<-raw.closed
			return nil, net.ErrClosed
		})
		fatal := &serverTestFatal{}
		runtime := bindServerRuntimeFixture(t, raw, fatal)
		serveDone := make(chan error, 1)
		go func() { serveDone <- runtime.Serve() }()
		<-runtime.ServeStarted()
		if err := runtime.Activate(); err != nil {
			t.Fatal("Activate() rejected a live serve loop")
		}
		<-acceptStarted
		runtime.RejectNewRequests()
		if err := runtime.CloseListener(); err != nil {
			t.Fatal("CloseListener() failed")
		}
		if err := <-serveDone; !IsServerRuntimeError(err) ||
			fatal.calls.Load() != 0 {
			t.Fatal("Serve() did not preserve app-owned stopping classification")
		}
		if runtime.gate.Open() {
			t.Fatal("clean stopped runtime reopened its handler gate")
		}
	})

	t.Run("early close", func(t *testing.T) {
		t.Parallel()
		acceptStarted := make(chan struct{})
		var raw *serverTestListener
		raw = newServerTestListener(func() (net.Conn, error) {
			select {
			case <-acceptStarted:
			default:
				close(acceptStarted)
			}
			<-raw.closed
			return nil, net.ErrClosed
		})
		fatal := &serverTestFatal{}
		runtime := bindServerRuntimeFixture(t, raw, fatal)
		serveDone := make(chan error, 1)
		go func() { serveDone <- runtime.Serve() }()
		<-runtime.ServeStarted()
		if err := runtime.Activate(); err != nil {
			t.Fatal("Activate() rejected a live early-close serve loop")
		}
		<-acceptStarted
		if err := runtime.CloseListener(); err != nil {
			t.Fatal("early CloseListener() failed")
		}
		if err := <-serveDone; !IsServerRuntimeError(err) ||
			fatal.calls.Load() != 0 {
			t.Fatal("Serve() classified pre-stopping listener loss")
		}
		connection, closedRaw := newGateTrackedConnection()
		writer := &gateResponseWriter{}
		if recovered := invokeGate(
			runtime.gate,
			writer,
			newGateRequest(connection, http.MethodGet, healthPath),
		); recovered != nil || closedRaw.closeCalls.Load() != 1 ||
			writer.writeCalls != 0 || writer.headerCalls != 0 {
			t.Fatal("post-return tracked request entered the handler gate")
		}
	})
}

// TestServerRuntimeDelegatesBoundedShutdown proves stable runtime methods.
func TestServerRuntimeDelegatesBoundedShutdown(t *testing.T) {
	t.Parallel()

	acceptStarted := make(chan struct{})
	var raw *serverTestListener
	raw = newServerTestListener(func() (net.Conn, error) {
		select {
		case <-acceptStarted:
		default:
			close(acceptStarted)
		}
		<-raw.closed
		return nil, net.ErrClosed
	})
	runtime := bindServerRuntimeFixture(t, raw, &serverTestFatal{})
	serveDone := make(chan error, 1)
	go func() { serveDone <- runtime.Serve() }()
	<-runtime.ServeStarted()
	if err := runtime.Activate(); err != nil {
		t.Fatal("Activate() rejected a live serve loop")
	}
	<-acceptStarted
	runtime.RejectNewRequests()
	if err := runtime.Activate(); !IsServerRuntimeError(err) {
		t.Fatal("Activate() did not expose the stopped gate")
	}
	if runtime.gate.Open() {
		t.Fatal("Activate() reopened a stopped gate")
	}
	var typedNilContext *gateTypedNilContext
	if err := runtime.Shutdown(typedNilContext); !IsServerRuntimeError(err) {
		t.Fatal("Shutdown() accepted a typed-nil context")
	}
	if err := runtime.WaitHandlers(typedNilContext); !IsServerRuntimeError(err) {
		t.Fatal("WaitHandlers() accepted a typed-nil context")
	}
	if err := runtime.CloseListener(); err != nil {
		t.Fatal("CloseListener() failed")
	}
	if err := runtime.CloseListener(); err != nil || raw.closeCalls.Load() != 1 {
		t.Fatal("CloseListener() was not idempotent")
	}
	if err := <-serveDone; !IsServerRuntimeError(err) {
		t.Fatal("Serve() did not return its stable terminal result")
	}
	if err := runtime.Shutdown(context.Background()); !IsServerRuntimeError(err) {
		t.Fatal("Shutdown() accepted an unbounded context")
	}
	shutdownContext, cancelShutdown := context.WithTimeout(
		context.Background(),
		runtime.shutdownTimeout,
	)
	defer cancelShutdown()
	if err := runtime.Shutdown(shutdownContext); err != nil {
		t.Fatal("Shutdown() failed on a quiescent server")
	}
	forceContext, cancelForce := context.WithTimeout(
		context.Background(),
		20*time.Millisecond,
	)
	defer cancelForce()
	if err := runtime.ForceClose(forceContext); !IsServerRuntimeError(err) {
		t.Fatal("ForceClose() bypassed the unsuccessful-graceful gate")
	}
	waitContext, cancelWait := context.WithTimeout(
		context.Background(),
		serverHandlerJoinTimeout,
	)
	defer cancelWait()
	if err := runtime.WaitHandlers(waitContext); err != nil {
		t.Fatal("WaitHandlers() failed on a quiescent gate")
	}
}

// TestServerRuntimeFreezesHostileContexts proves downstream waits receive only
// one value-free, internally bounded cancellation snapshot.
func TestServerRuntimeFreezesHostileContexts(t *testing.T) {
	t.Parallel()

	openDone := make(chan struct{})
	closedDone := make(chan struct{})
	close(closedDone)
	tests := []struct {
		name    string
		context context.Context
	}{
		{
			name: "nil done",
			context: &serverMalformedContext{
				deadline:    time.Now().Add(time.Second),
				hasDeadline: true,
			},
		},
		{
			name: "closed done without error",
			context: &serverMalformedContext{
				deadline:    time.Now().Add(time.Second),
				hasDeadline: true,
				done:        closedDone,
			},
		},
		{
			name: "deadline panic",
			context: &serverMalformedContext{
				done:          openDone,
				panicDeadline: true,
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			bounded, cancel, err := newBoundedServerContext(
				testCase.context,
				serverHandlerJoinTimeout,
			)
			if cancel != nil {
				cancel()
			}
			if bounded != nil || !IsServerRuntimeError(err) {
				t.Fatal("hostile context reached a downstream wait")
			}
		})
	}

	source, cancelSource := context.WithTimeout(
		context.WithValue(context.Background(), gateContextKey{}, "private-marker"),
		time.Second,
	)
	defer cancelSource()
	bounded, cancel, err := newBoundedServerContext(
		source,
		serverHandlerJoinTimeout,
	)
	if err != nil || bounded == nil || cancel == nil {
		t.Fatal("valid bounded context snapshot failed")
	}
	defer cancel()
	if bounded.Value(gateContextKey{}) != nil {
		t.Fatal("bounded context retained caller values")
	}
}

// TestServerRuntimeBoundsAndJoinsShutdownAndForce proves blocking net/http
// cleanup calls are attempted once and never reported joined prematurely.
func TestServerRuntimeBoundsAndJoinsShutdownAndForce(t *testing.T) {
	t.Parallel()

	t.Run("shutdown remains separately joined", func(t *testing.T) {
		t.Parallel()
		runtime := bindServerRuntimeFixture(
			t,
			newServerTestListener(nil),
			&serverTestFatal{},
		)
		runtime.state = serverRuntimeStopping
		runtime.serveReturned.Store(true)
		shutdownRelease := make(chan struct{})
		shutdownCalls := atomic.Int32{}
		runtime.shutdownServer = func(context.Context) error {
			shutdownCalls.Add(1)
			<-shutdownRelease
			return errors.New("shutdown-private-marker")
		}
		forceCalls := atomic.Int32{}
		runtime.forceServer = func() error {
			forceCalls.Add(1)
			return nil
		}
		shutdownContext, cancelShutdown := context.WithTimeout(
			context.Background(),
			20*time.Millisecond,
		)
		defer cancelShutdown()
		if err := runtime.Shutdown(shutdownContext); !IsServerRuntimeError(err) {
			t.Fatal("blocking Shutdown() escaped its caller bound")
		}
		forceContext, cancelForce := context.WithTimeout(
			context.Background(),
			20*time.Millisecond,
		)
		defer cancelForce()
		if err := runtime.ForceClose(forceContext); !IsServerRuntimeError(err) {
			t.Fatal("ForceClose() falsely proved a blocked shutdown join")
		}
		if shutdownCalls.Load() != 1 || forceCalls.Load() != 1 {
			t.Fatal("bounded cleanup did not attempt each exact owner once")
		}
		close(shutdownRelease)
		retryContext, cancelRetry := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancelRetry()
		if err := runtime.ForceClose(retryContext); err != nil {
			t.Fatal("ForceClose() did not join the already-started attempts")
		}
		if shutdownCalls.Load() != 1 || forceCalls.Load() != 1 {
			t.Fatal("cleanup retry started a second dependency call")
		}
	})

	t.Run("force remains separately joined", func(t *testing.T) {
		t.Parallel()
		runtime := bindServerRuntimeFixture(
			t,
			newServerTestListener(nil),
			&serverTestFatal{},
		)
		runtime.state = serverRuntimeStopping
		runtime.serveReturned.Store(true)
		runtime.shutdownServer = func(context.Context) error {
			return errors.New("shutdown-private-marker")
		}
		shutdownContext, cancelShutdown := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancelShutdown()
		if err := runtime.Shutdown(shutdownContext); !IsServerRuntimeError(err) {
			t.Fatal("scripted graceful failure was not stable")
		}
		forceRelease := make(chan struct{})
		forceCalls := atomic.Int32{}
		runtime.forceServer = func() error {
			forceCalls.Add(1)
			<-forceRelease
			return nil
		}
		forceContext, cancelForce := context.WithTimeout(
			context.Background(),
			20*time.Millisecond,
		)
		defer cancelForce()
		if err := runtime.ForceClose(forceContext); !IsServerRuntimeError(err) {
			t.Fatal("blocking ForceClose() escaped its caller bound")
		}
		close(forceRelease)
		retryContext, cancelRetry := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancelRetry()
		if err := runtime.ForceClose(retryContext); err != nil {
			t.Fatal("ForceClose() did not join its exact existing attempt")
		}
		if forceCalls.Load() != 1 {
			t.Fatal("ForceClose() repeated its dependency call")
		}
	})

	t.Run("nonquiescent graceful result permits force", func(t *testing.T) {
		t.Parallel()
		runtime := bindServerRuntimeFixture(
			t,
			newServerTestListener(nil),
			&serverTestFatal{},
		)
		runtime.state = serverRuntimeStopping
		runtime.serveReturned.Store(true)
		runtime.gate.Close()
		runtime.gate.mu.Lock()
		runtime.gate.active = 1
		runtime.gate.mu.Unlock()
		runtime.shutdownServer = func(context.Context) error { return nil }
		shutdownContext, cancelShutdown := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancelShutdown()
		if err := runtime.Shutdown(shutdownContext); err != nil {
			t.Fatal("scripted graceful shutdown failed")
		}
		if runtime.HandlersQuiescent() {
			t.Fatal("live handler was reported quiescent")
		}
		forceCalls := atomic.Int32{}
		runtime.forceServer = func() error {
			forceCalls.Add(1)
			return nil
		}
		forceContext, cancelForce := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancelForce()
		if err := runtime.ForceClose(forceContext); err != nil ||
			forceCalls.Load() != 1 {
			t.Fatal("nonquiescent graceful result did not permit exact force")
		}
		runtime.gate.mu.Lock()
		runtime.gate.active = 0
		runtime.gate.cond.Broadcast()
		runtime.gate.mu.Unlock()
	})

	t.Run("short waiter cannot fail long owner", func(t *testing.T) {
		t.Parallel()
		runtime := bindServerRuntimeFixture(
			t,
			newServerTestListener(nil),
			&serverTestFatal{},
		)
		runtime.state = serverRuntimeStopping
		runtime.serveReturned.Store(true)
		shutdownEntered := make(chan struct{})
		shutdownRelease := make(chan struct{})
		runtime.shutdownServer = func(context.Context) error {
			close(shutdownEntered)
			<-shutdownRelease
			return nil
		}
		ownerContext, cancelOwner := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancelOwner()
		ownerDone := make(chan error, 1)
		go func() {
			ownerDone <- runtime.Shutdown(ownerContext)
		}()
		<-shutdownEntered
		waiterContext, cancelWaiter := context.WithTimeout(
			context.Background(),
			20*time.Millisecond,
		)
		defer cancelWaiter()
		if err := runtime.Shutdown(waiterContext); !IsServerRuntimeError(err) {
			t.Fatal("short shutdown waiter escaped its own deadline")
		}
		select {
		case <-runtime.forceReady:
			t.Fatal("short waiter failed the still-live graceful owner")
		default:
		}
		close(shutdownRelease)
		if err := <-ownerDone; err != nil {
			t.Fatal("long shutdown owner did not retain its success")
		}
	})
}

// TestServerRuntimeHandsOffOuterDeadlineToForcedClose freezes the composed race.
func TestServerRuntimeHandsOffOuterDeadlineToForcedClose(t *testing.T) {
	t.Parallel()

	runtime := bindServerRuntimeFixture(
		t,
		newServerTestListener(nil),
		&serverTestFatal{},
	)
	runtime.state = serverRuntimeStopping
	runtime.serveReturned.Store(true)
	shutdownEntered := make(chan struct{})
	shutdownRelease := make(chan struct{})
	runtime.shutdownServer = func(context.Context) error {
		close(shutdownEntered)
		<-shutdownRelease
		return errors.New("shutdown-private-marker")
	}
	permitEntered := make(chan struct{})
	permitRelease := make(chan struct{})
	runtime.beforeForcePermit = func() {
		close(permitEntered)
		<-permitRelease
	}
	forceWaitEntered := make(chan struct{})
	runtime.beforeForceWait = func() {
		close(forceWaitEntered)
	}
	var forceCalls atomic.Int32
	runtime.forceServer = func() error {
		forceCalls.Add(1)
		return nil
	}

	shutdownContext, cancelShutdown := context.WithTimeout(
		context.Background(),
		20*time.Millisecond,
	)
	defer cancelShutdown()
	innerShutdown := make(chan error, 1)
	go func() { innerShutdown <- runtime.Shutdown(shutdownContext) }()
	<-shutdownEntered
	<-permitEntered
	select {
	case err := <-innerShutdown:
		t.Fatalf("inner Shutdown returned before permission publication: %v", err)
	case <-shutdownContext.Done():
	}

	forceContext, cancelForce := context.WithTimeout(context.Background(), time.Second)
	defer cancelForce()
	forceResult := make(chan error, 1)
	go func() { forceResult <- runtime.ForceClose(forceContext) }()
	<-forceWaitEntered
	select {
	case err := <-forceResult:
		t.Fatalf("ForceClose refused before owner permission handoff: %v", err)
	default:
	}

	close(permitRelease)
	close(shutdownRelease)
	if err := <-innerShutdown; !IsServerRuntimeError(err) {
		t.Fatalf("timed-out Shutdown returned %T", err)
	}
	if err := <-forceResult; err != nil {
		t.Fatalf("forced close did not consume timeout permission: %v", err)
	}
	if forceCalls.Load() != 1 {
		t.Fatalf("force calls=%d, want 1", forceCalls.Load())
	}
}

// TestServerRuntimeOwnersAreDiagnosticOpaque proves privacy boundaries.
func TestServerRuntimeOwnersAreDiagnosticOpaque(t *testing.T) {
	t.Parallel()

	factory := NewServerFactory()
	assembly := newServerAssemblyFixture(
		context.Background(),
		t,
		(&serverTestListen{listener: newServerTestListener(nil)}).Listen,
		&serverTestFatal{},
	)
	runtimeValue, err := assembly.Bind(context.Background())
	if err != nil {
		t.Fatal("privacy Bind() failed")
	}
	for _, value := range []any{factory, assembly, runtimeValue} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if output := fmt.Sprintf(format, value); output != serverRuntimeRedacted {
				t.Fatalf("format %s = %q", format, output)
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("JSON serialization exposed a server runtime owner")
		}
		textValue, ok := value.(interface{ MarshalText() ([]byte, error) })
		if !ok {
			t.Fatal("server runtime owner lacks text refusal")
		}
		if _, err := textValue.MarshalText(); err == nil {
			t.Fatal("text serialization exposed a server runtime owner")
		}
	}
}

// newServerAssemblyFixture constructs one pure valid internal assembly.
func newServerAssemblyFixture(
	baseContext context.Context,
	t *testing.T,
	listen serverListenFunc,
	fatal app.FatalNotifier,
) *serverAssembly {
	t.Helper()
	readiness := &boundaryReadiness{}
	readiness.ready.Store(true)
	assembly, err := newServerAssembly(
		baseContext,
		serverSettings{
			authority:         boundaryTestAuthority,
			readHeaderTimeout: 5 * time.Second,
			readTimeout:       30 * time.Second,
			writeTimeout:      31 * time.Second,
			requestDeadline:   30 * time.Second,
			shutdownTimeout:   30 * time.Second,
			maxInFlight:       1,
			maxWaiters:        1,
			admissionWait:     10 * time.Millisecond,
		},
		&boundaryCapabilityMatcher{value: bytes.Repeat([]byte{0xa5}, 32)},
		readiness,
		&boundaryProcessor{},
		fatal,
		allowHandlerActivation{},
		&serverTestServeObserver{},
		listen,
	)
	if err != nil {
		t.Fatal("newServerAssembly() failed")
	}
	return assembly
}

// bindServerRuntimeFixture binds one valid runtime to the supplied listener.
func bindServerRuntimeFixture(
	t *testing.T,
	raw net.Listener,
	fatal app.FatalNotifier,
) *serverRuntime {
	t.Helper()
	listen := &serverTestListen{listener: raw}
	assembly := newServerAssemblyFixture(
		context.Background(),
		t,
		listen.Listen,
		fatal,
	)
	runtimeValue, err := assembly.Bind(context.Background())
	if err != nil {
		t.Fatal("runtime fixture Bind() failed")
	}
	runtime, ok := runtimeValue.(*serverRuntime)
	if !ok {
		t.Fatal("runtime fixture returned a foreign implementation")
	}
	return runtime
}

// stringsContainPrivateMarker recognizes every toxic fixture marker.
func stringsContainPrivateMarker(value string) bool {
	return strings.Contains(value, "private") || strings.Contains(value, "marker")
}

var (
	_ net.Listener     = (*serverTestListener)(nil)
	_ app.HTTPFactory  = (*ServerFactory)(nil)
	_ app.HTTPAssembly = (*serverAssembly)(nil)
	_ app.HTTPRuntime  = (*serverRuntime)(nil)
	_ io.Writer        = (*serverErrorSink)(nil)
)
