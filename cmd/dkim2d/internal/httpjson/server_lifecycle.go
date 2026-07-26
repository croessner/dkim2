package httpjson

import (
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
)

var (
	errHandlerRegistrationGate = errors.New("handler registration gate state failure")
	errServerConnContext       = errors.New("server connection context failure")
)

// ServerListener exposes only the tracked listener operations needed by an
// instance-owned HTTP server.
type ServerListener struct {
	tracked       *trackedListener
	acceptEntered chan struct{}
	acceptOnce    sync.Once
}

// NewServerListener constructs the fixed-cap server listener boundary.
func NewServerListener(
	listener net.Listener,
	dateProvider func() (string, bool),
) (*ServerListener, error) {
	tracked, err := newTrackedListener(listener, dateProvider)
	if err != nil {
		return nil, errHTTPBoundaryConfig
	}
	return &ServerListener{
		tracked:       tracked,
		acceptEntered: make(chan struct{}),
	}, nil
}

// Accept returns one connection owned by the tracked transport boundary.
func (l *ServerListener) Accept() (net.Conn, error) {
	if l == nil || l.tracked == nil {
		return nil, net.ErrClosed
	}
	l.acceptOnce.Do(func() {
		close(l.acceptEntered)
	})
	return l.tracked.Accept()
}

// serveStarted returns the one-shot proof that net/http entered its exact
// listener accept loop.
func (l *ServerListener) serveStarted() <-chan struct{} {
	if l == nil {
		return nil
	}
	return l.acceptEntered
}

// Close interrupts accept and closes the tracked listener exactly once.
func (l *ServerListener) Close() error {
	if l == nil || l.tracked == nil {
		return nil
	}
	return l.tracked.Close()
}

// Addr returns the configured listener address without exposing its owner.
func (l *ServerListener) Addr() net.Addr {
	if l == nil || l.tracked == nil {
		return nil
	}
	return l.tracked.Addr()
}

// ConnContext installs private tracked-connection state on the exact
// instance-owned server base context.
func (l *ServerListener) ConnContext(
	ctx context.Context,
	connection net.Conn,
) context.Context {
	if nilInterfaceValue(ctx) {
		failServerConnContext(connection)
	}
	tracked, owned := l.bindOwnedTrackedConnection(connection)
	if !owned {
		failServerConnContext(connection)
	}
	ctx = l.tracked.ConnContext(ctx, connection)
	state, present := transportStateFromContext(ctx)
	if !present || state.trackedConnection() != tracked ||
		state.ResponseTerminal() ||
		tracked.contextState.Load() != transportContextBound {
		failServerConnContext(connection)
	}
	return ctx
}

// bindOwnedTrackedConnection verifies live exact ownership and binds the
// connection context exactly once.
func (l *ServerListener) bindOwnedTrackedConnection(connection net.Conn) (*trackedConn, bool) {
	if l == nil || l.tracked == nil || l.tracked.owner == nil ||
		l.tracked.owner.tag == 0 || nilInterfaceValue(connection) {
		return nil, false
	}
	tracked, ok := connection.(*trackedConn)
	if !ok || tracked == nil || tracked.owner == nil ||
		tracked.owner != l.tracked.owner || tracked.owner.tag == 0 ||
		tracked.state == nil || tracked.state.trackedConnection() != tracked ||
		tracked.state.ResponseTerminal() ||
		!tracked.contextState.CompareAndSwap(transportContextUnbound, transportContextBound) {
		return nil, false
	}
	return tracked, true
}

// failServerConnContext closes one supplied connection when possible and
// propagates only the stable private serve-owner sentinel.
func failServerConnContext(connection net.Conn) {
	if !nilInterfaceValue(connection) {
		closeServerConnContext(connection)
	}
	panic(errServerConnContext)
}

// closeServerConnContext contains arbitrary foreign Close panics.
func closeServerConnContext(connection net.Conn) {
	defer func() {
		_ = recover()
	}()
	_ = connection.Close()
}

// IsServerConnContextFailure reports whether a recovered panic is the private
// content-free connection-context invariant used by the guarded serve owner.
func IsServerConnContextFailure(value any) bool {
	return value == errServerConnContext
}

// String returns a content-free listener representation.
func (*ServerListener) String() string { return transportRedacted }

// GoString returns a content-free Go-syntax listener representation.
func (*ServerListener) GoString() string { return transportRedacted }

// Format prevents formatting verbs from traversing retained listener state.
func (*ServerListener) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, transportRedacted)
}

// MarshalJSON rejects serialization of retained listener state.
func (*ServerListener) MarshalJSON() ([]byte, error) {
	return nil, errors.New(transportMarshalErrorText)
}

// MarshalText rejects diagnostic serialization of retained listener state.
func (*ServerListener) MarshalText() ([]byte, error) {
	return nil, errors.New(transportMarshalErrorText)
}

type handlerRegistrationState uint8

const (
	handlerRegistrationBootstrapping handlerRegistrationState = iota
	handlerRegistrationOpen
	handlerRegistrationStopped
)

// HandlerRegistrationGate linearizes handler entry against instance shutdown.
type HandlerRegistrationGate struct {
	next       http.Handler
	activation activationAuthority
	fatal      FatalNotifier

	mu     sync.Mutex
	cond   *sync.Cond
	state  handlerRegistrationState
	active uint64
}

type activationAuthority interface {
	AllowHTTPActivation() bool
}

type allowHandlerActivation struct{}

// AllowHTTPActivation permits construction-only gate tests without app state.
func (allowHandlerActivation) AllowHTTPActivation() bool { return true }

// NewHandlerRegistrationGate constructs a closed-until-open handler owner.
func NewHandlerRegistrationGate(next http.Handler) (*HandlerRegistrationGate, error) {
	return newHandlerRegistrationGate(next, allowHandlerActivation{}, nil)
}

// newHandlerRegistrationGate constructs a closed-until-open handler owner with
// optional lifecycle notification for unproved late-entry terminalization.
func newHandlerRegistrationGate(
	next http.Handler,
	activation activationAuthority,
	fatal FatalNotifier,
) (*HandlerRegistrationGate, error) {
	if nilInterfaceValue(next) || nilInterfaceValue(activation) {
		return nil, errHTTPBoundaryConfig
	}
	gate := &HandlerRegistrationGate{
		next:       next,
		activation: activation,
		fatal:      fatal,
		state:      handlerRegistrationBootstrapping,
	}
	gate.cond = sync.NewCond(&gate.mu)
	return gate, nil
}

// Open permits handler registration until the monotonic stopped transition.
func (g *HandlerRegistrationGate) Open() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	if g.cond == nil || nilInterfaceValue(g.next) ||
		nilInterfaceValue(g.activation) {
		g.state = handlerRegistrationStopped
		g.mu.Unlock()
		g.notifyFatal()
		return false
	}
	switch g.state {
	case handlerRegistrationBootstrapping:
		allowed, panicked := sampleGateActivation(g.activation)
		if panicked || !allowed {
			g.state = handlerRegistrationStopped
			g.cond.Broadcast()
			g.mu.Unlock()
			g.notifyFatal()
			return false
		}
		g.state = handlerRegistrationOpen
		g.mu.Unlock()
		return true
	case handlerRegistrationOpen:
		g.mu.Unlock()
		return true
	case handlerRegistrationStopped:
		g.mu.Unlock()
		return false
	default:
		g.mu.Unlock()
		return false
	}
}

// sampleGateActivation contains the app-owned no-I/O authority at the exact
// one-time gate-open linearization point.
func sampleGateActivation(
	activation activationAuthority,
) (allowed bool, panicked bool) {
	defer func() {
		if recover() != nil {
			allowed = false
			panicked = true
		}
	}()
	return activation.AllowHTTPActivation(), false
}

// Close stops future registration without waiting for active handlers.
func (g *HandlerRegistrationGate) Close() {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.state != handlerRegistrationStopped {
		g.state = handlerRegistrationStopped
		if g.cond != nil {
			g.cond.Broadcast()
		}
	}
	g.mu.Unlock()
}

// Wait joins active handlers after the stopped transition or returns the
// caller's bounded context state.
func (g *HandlerRegistrationGate) Wait(ctx context.Context) error {
	if g == nil || nilInterfaceValue(ctx) {
		return errHandlerRegistrationGate
	}
	g.mu.Lock()
	if g.cond == nil || nilInterfaceValue(g.next) ||
		g.state != handlerRegistrationStopped {
		g.mu.Unlock()
		return errHandlerRegistrationGate
	}
	if g.active == 0 {
		g.mu.Unlock()
		return nil
	}
	callbackDone := make(chan struct{})
	stopWake := context.AfterFunc(ctx, func() {
		g.mu.Lock()
		g.cond.Broadcast()
		g.mu.Unlock()
		close(callbackDone)
	})
	for g.active != 0 && ctx.Err() == nil {
		g.cond.Wait()
	}
	quiescent := g.active == 0
	err := ctx.Err()
	g.mu.Unlock()
	if !stopWake() {
		<-callbackDone
	}
	if quiescent {
		return nil
	}
	if err != nil {
		return err
	}
	return errHandlerRegistrationGate
}

// Quiescent reports whether registration is closed and no admitted handler
// remains active.
func (g *HandlerRegistrationGate) Quiescent() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.state == handlerRegistrationStopped && g.active == 0
}

// ServeHTTP registers before any boundary or dependency work and releases the
// registration on every ordinary, abort, and panic path.
func (g *HandlerRegistrationGate) ServeHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if g == nil || nilInterfaceValue(writer) || request == nil {
		if !closeRefusedHandlerConnection(request) {
			g.notifyFatal()
			panic(http.ErrAbortHandler)
		}
		return
	}
	if !g.register() {
		if !closeRefusedHandlerConnection(request) {
			g.notifyFatal()
			panic(http.ErrAbortHandler)
		}
		return
	}
	defer g.release()
	g.next.ServeHTTP(writer, request)
}

// notifyFatal contains the optional lifecycle notifier so late-entry abort
// disposition never exposes or replaces its transport outcome.
func (g *HandlerRegistrationGate) notifyFatal() {
	if g == nil || nilInterfaceValue(g.fatal) {
		return
	}
	defer func() {
		_ = recover()
	}()
	g.fatal.NotifyFatal()
}

// register linearizes one entry with the stopped transition.
func (g *HandlerRegistrationGate) register() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cond == nil || nilInterfaceValue(g.next) ||
		g.state != handlerRegistrationOpen {
		return false
	}
	if g.active == ^uint64(0) {
		g.state = handlerRegistrationStopped
		g.cond.Broadcast()
		return false
	}
	g.active++
	return true
}

// release decrements one admitted entry and wakes joined waiters at quiescence.
func (g *HandlerRegistrationGate) release() {
	g.mu.Lock()
	if g.active != 0 {
		g.active--
		if g.active == 0 && g.cond != nil {
			g.cond.Broadcast()
		}
	}
	g.mu.Unlock()
}

// closeRefusedHandlerConnection closes only the exact private request transport
// and reports whether terminalization was proved.
func closeRefusedHandlerConnection(request *http.Request) bool {
	if request == nil {
		return false
	}
	state, ok := transportStateFromContext(request.Context())
	if !ok {
		return false
	}
	return state.Close() == nil
}

// String returns a content-free registration-gate representation.
func (*HandlerRegistrationGate) String() string { return transportRedacted }

// GoString returns a content-free Go-syntax registration-gate representation.
func (*HandlerRegistrationGate) GoString() string { return transportRedacted }

// Format prevents formatting verbs from traversing retained handler state.
func (*HandlerRegistrationGate) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, transportRedacted)
}

// MarshalJSON rejects serialization of retained handler state.
func (*HandlerRegistrationGate) MarshalJSON() ([]byte, error) {
	return nil, errors.New(transportMarshalErrorText)
}

// MarshalText rejects diagnostic serialization of retained handler state.
func (*HandlerRegistrationGate) MarshalText() ([]byte, error) {
	return nil, errors.New(transportMarshalErrorText)
}

var (
	_ net.Listener           = (*ServerListener)(nil)
	_ fmt.Stringer           = (*ServerListener)(nil)
	_ fmt.GoStringer         = (*ServerListener)(nil)
	_ json.Marshaler         = (*ServerListener)(nil)
	_ encoding.TextMarshaler = (*ServerListener)(nil)
	_ http.Handler           = (*HandlerRegistrationGate)(nil)
	_ fmt.Stringer           = (*HandlerRegistrationGate)(nil)
	_ fmt.GoStringer         = (*HandlerRegistrationGate)(nil)
	_ json.Marshaler         = (*HandlerRegistrationGate)(nil)
	_ encoding.TextMarshaler = (*HandlerRegistrationGate)(nil)
)
