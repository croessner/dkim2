package httpjson

import (
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
)

const (
	serverRuntimeErrorText   = "dkim2d HTTP server runtime failure"
	serverHandlerJoinTimeout = 5 * time.Second
)

// serverRuntimeError reports one content-free HTTP server ownership failure.
type serverRuntimeError struct{}

// Error returns the stable content-free runtime diagnostic.
func (*serverRuntimeError) Error() string { return serverRuntimeErrorText }

// Is recognizes the stable HTTP server runtime failure class.
func (*serverRuntimeError) Is(target error) bool {
	_, ok := target.(*serverRuntimeError)
	return ok
}

// IsServerRuntimeError reports whether an error belongs to the stable HTTP
// server ownership class.
func IsServerRuntimeError(err error) bool {
	return errors.Is(err, &serverRuntimeError{})
}

type serverRuntimeState uint8

const (
	serverRuntimeBootstrapping serverRuntimeState = iota
	serverRuntimeActive
	serverRuntimeStopping
)

type serverRuntime struct {
	listener *ServerListener
	server   *http.Server
	boundary *HTTPBoundary
	gate     *HandlerRegistrationGate
	observer app.ServeReturnObserver

	shutdownServer func(context.Context) error
	forceServer    func() error

	shutdownTimeout time.Duration

	stateMu           sync.Mutex
	state             serverRuntimeState
	serveStarted      atomic.Bool
	serveReturned     atomic.Bool
	shutdownAttempted bool
	shutdownCompleted bool
	closeListenerOnce sync.Once
	closeListenerErr  error
	shutdownStartOnce sync.Once
	shutdownDone      chan struct{}
	shutdownErr       error
	forceReadyOnce    sync.Once
	forceReady        chan struct{}
	beforeForcePermit func()
	beforeForceWait   func()
	forceStartOnce    sync.Once
	forceDone         chan struct{}
	forceErr          error
}

// newServerRuntime constructs one exact immutable http.Server owner around the
// previously acquired tracked listener.
func newServerRuntime(
	baseContext context.Context,
	settings serverSettings,
	boundary *HTTPBoundary,
	gate *HandlerRegistrationGate,
	listener *ServerListener,
	observer app.ServeReturnObserver,
) (*serverRuntime, error) {
	if !settings.valid() || boundary == nil || gate == nil ||
		nilInterfaceValue(baseContext) || listener == nil ||
		nilInterfaceValue(listener.tracked) || nilInterfaceValue(observer) {
		return nil, &serverRuntimeError{}
	}
	runtime := &serverRuntime{
		listener:        listener,
		boundary:        boundary,
		gate:            gate,
		observer:        observer,
		shutdownTimeout: settings.shutdownTimeout,
		state:           serverRuntimeBootstrapping,
		shutdownDone:    make(chan struct{}),
		forceReady:      make(chan struct{}),
		forceDone:       make(chan struct{}),
	}
	runtime.server = &http.Server{
		Handler:                      gate,
		ReadHeaderTimeout:            settings.readHeaderTimeout,
		ReadTimeout:                  settings.readTimeout,
		WriteTimeout:                 settings.writeTimeout,
		MaxHeaderBytes:               transportServerMaxHeaderBytes,
		DisableGeneralOptionsHandler: true,
		ErrorLog:                     log.New(&serverErrorSink{}, "", 0),
		BaseContext: func(netListener net.Listener) context.Context {
			if netListener != listener {
				panic(errServerConnContext)
			}
			return baseContext
		},
		ConnContext: listener.ConnContext,
		TLSConfig:   settings.tlsConfig,
	}
	runtime.shutdownServer = runtime.server.Shutdown
	runtime.forceServer = runtime.server.Close
	return runtime, nil
}

// Activate opens handler registration only while the sole serve loop is live.
func (r *serverRuntime) Activate() error {
	if r == nil || r.gate == nil || r.boundary == nil ||
		!r.serveStarted.Load() || !r.acceptLoopEntered() ||
		r.serveReturned.Load() {
		return &serverRuntimeError{}
	}
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	if r.state == serverRuntimeActive {
		if r.serveReturned.Load() {
			return &serverRuntimeError{}
		}
		return nil
	}
	if r.state != serverRuntimeBootstrapping {
		return &serverRuntimeError{}
	}
	if !r.gate.Open() {
		r.state = serverRuntimeStopping
		r.boundary.Close()
		return &serverRuntimeError{}
	}
	if r.serveReturned.Load() {
		r.gate.Close()
		r.state = serverRuntimeStopping
		r.boundary.Close()
		return &serverRuntimeError{}
	}
	r.state = serverRuntimeActive
	return nil
}

// acceptLoopEntered reports only the closed producer-side listener signal.
func (r *serverRuntime) acceptLoopEntered() bool {
	if r == nil || r.listener == nil {
		return false
	}
	started := r.listener.serveStarted()
	if started == nil {
		return false
	}
	select {
	case <-started:
		return true
	default:
		return false
	}
}

// RejectNewRequests closes handler registration before admission and makes the
// transition permanently monotone.
func (r *serverRuntime) RejectNewRequests() {
	if r == nil {
		return
	}
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	if r.state == serverRuntimeStopping {
		return
	}
	r.gate.Close()
	r.state = serverRuntimeStopping
	r.boundary.Close()
}

// Serve owns the only server loop, contains every panic and raw return, and
// closes the exact listener before publishing completion.
func (r *serverRuntime) Serve() (resultErr error) {
	if r == nil || r.server == nil || r.listener == nil ||
		r.listener.serveStarted() == nil ||
		!r.serveStarted.CompareAndSwap(false, true) {
		return &serverRuntimeError{}
	}
	defer func() {
		_ = recover()
		r.notifyServeReturn()
		r.publishServeTermination()
		_ = r.CloseListener()
		resultErr = &serverRuntimeError{}
	}()
	return r.server.Serve(r.listener)
}

// publishServeTermination closes transport state after the app-owned fatal handoff.
func (r *serverRuntime) publishServeTermination() {
	if r == nil {
		return
	}
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	r.serveReturned.Store(true)
	r.state = serverRuntimeStopping
	func() {
		defer func() {
			_ = recover()
		}()
		r.gate.Close()
		r.boundary.Close()
	}()
}

// ServeStarted returns the instance-owned proof that the sole serve goroutine
// crossed its ownership gate before entering net/http.
func (r *serverRuntime) ServeStarted() <-chan struct{} {
	if r == nil {
		return nil
	}
	return r.listener.serveStarted()
}

// Serving reports whether the sole serve invocation has started and has not
// yet reached its synchronous termination handoff.
func (r *serverRuntime) Serving() bool {
	return r != nil && r.serveStarted.Load() && !r.serveReturned.Load()
}

// HandlersQuiescent reports the gate-owned closed-and-zero proof and permits
// forced close after a completed graceful attempt failed to prove quiescence.
func (r *serverRuntime) HandlersQuiescent() bool {
	if r == nil || r.gate == nil {
		return false
	}
	if r.gate.Quiescent() {
		return true
	}
	r.stateMu.Lock()
	permitted := r.state == serverRuntimeStopping && r.serveReturned.Load() &&
		r.shutdownAttempted && r.shutdownCompleted
	r.stateMu.Unlock()
	if permitted {
		r.permitForceClose()
	}
	return false
}

// notifyServeReturn synchronously hands one termination event to the app-owned
// lifecycle arbiter while containing observer failure.
func (r *serverRuntime) notifyServeReturn() {
	if r == nil || nilInterfaceValue(r.observer) {
		return
	}
	defer func() {
		_ = recover()
	}()
	r.observer.NotifyServeReturn()
}

// CloseListener closes the exact tracked listener once without invoking
// http.Server.Close or waiting on net/http listener groups.
func (r *serverRuntime) CloseListener() (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &serverRuntimeError{}
		}
	}()
	if r == nil || r.listener == nil {
		return &serverRuntimeError{}
	}
	r.closeListenerOnce.Do(func() {
		defer func() {
			if recover() != nil {
				r.closeListenerErr = &serverRuntimeError{}
			}
		}()
		if err := r.listener.Close(); err != nil {
			r.closeListenerErr = &serverRuntimeError{}
		}
	})
	return r.closeListenerErr
}

// Shutdown performs one graceful drain only after stopping and serve-loop
// completion have been proven by the lifecycle owner.
func (r *serverRuntime) Shutdown(ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &serverRuntimeError{}
		}
	}()
	if r == nil || r.server == nil || r.shutdownServer == nil {
		return &serverRuntimeError{}
	}
	bounded, cancel, err := newBoundedServerContext(ctx, r.shutdownTimeout)
	if err != nil {
		return &serverRuntimeError{}
	}
	defer cancel()
	r.stateMu.Lock()
	if r.state != serverRuntimeStopping || !r.serveReturned.Load() {
		r.stateMu.Unlock()
		return &serverRuntimeError{}
	}
	r.stateMu.Unlock()
	r.stateMu.Lock()
	r.shutdownAttempted = true
	r.stateMu.Unlock()
	ownsShutdown := false
	r.shutdownStartOnce.Do(func() {
		ownsShutdown = true
		go r.runShutdown(bounded)
	})
	select {
	case <-r.shutdownDone:
		return r.shutdownErr
	case <-bounded.Done():
		select {
		case <-r.shutdownDone:
			return r.shutdownErr
		default:
		}
		if ownsShutdown {
			if r.beforeForcePermit != nil {
				r.beforeForcePermit()
			}
			r.permitForceClose()
		}
		return &serverRuntimeError{}
	}
}

// runShutdown owns the single graceful call and publishes its eventual join;
// forced close may proceed concurrently only after the graceful bound expires.
func (r *serverRuntime) runShutdown(ctx context.Context) {
	defer close(r.shutdownDone)
	defer func() {
		if recover() != nil {
			r.shutdownErr = &serverRuntimeError{}
		}
		r.stateMu.Lock()
		r.shutdownCompleted = true
		failed := r.shutdownErr != nil
		r.stateMu.Unlock()
		if failed {
			r.permitForceClose()
		}
	}()
	if err := r.shutdownServer(ctx); err != nil {
		r.shutdownErr = &serverRuntimeError{}
	}
}

// ForceClose closes active server connections only after an unsuccessful
// graceful drain or handler join and a proven serve-loop join.
func (r *serverRuntime) ForceClose(ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &serverRuntimeError{}
		}
	}()
	if r == nil || r.server == nil || r.forceServer == nil {
		return &serverRuntimeError{}
	}
	bounded, cancel, err := newBoundedServerContext(ctx, serverHandlerJoinTimeout)
	if err != nil {
		return &serverRuntimeError{}
	}
	defer cancel()
	r.stateMu.Lock()
	permitted := r.state == serverRuntimeStopping &&
		r.serveReturned.Load() && r.shutdownAttempted
	r.stateMu.Unlock()
	if !permitted {
		return &serverRuntimeError{}
	}
	if r.beforeForceWait != nil {
		r.beforeForceWait()
	}
	select {
	case <-r.forceReady:
	case <-bounded.Done():
		select {
		case <-r.forceReady:
		default:
			return &serverRuntimeError{}
		}
	}
	r.forceStartOnce.Do(func() {
		go r.runForceClose()
	})
	select {
	case <-r.forceDone:
	case <-bounded.Done():
		select {
		case <-r.forceDone:
		default:
			return &serverRuntimeError{}
		}
	}
	select {
	case <-r.shutdownDone:
		if r.forceErr != nil {
			return r.forceErr
		}
		return nil
	case <-bounded.Done():
		select {
		case <-r.shutdownDone:
			if r.forceErr != nil {
				return r.forceErr
			}
			return nil
		default:
			return &serverRuntimeError{}
		}
	}
}

// runForceClose owns the single potentially blocking http.Server.Close call
// and publishes only its stable joined result.
func (r *serverRuntime) runForceClose() {
	defer close(r.forceDone)
	defer func() {
		if recover() != nil {
			r.forceErr = &serverRuntimeError{}
		}
	}()
	if err := r.forceServer(); err != nil &&
		!errors.Is(err, http.ErrServerClosed) {
		r.forceErr = &serverRuntimeError{}
	}
}

// WaitHandlers joins the closed registration gate within the fixed force-join
// budget and enables forced close when quiescence is not proven.
func (r *serverRuntime) WaitHandlers(ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &serverRuntimeError{}
		}
	}()
	if r == nil || r.gate == nil {
		return &serverRuntimeError{}
	}
	bounded, cancel, err := newBoundedServerContext(ctx, serverHandlerJoinTimeout)
	if err != nil {
		return &serverRuntimeError{}
	}
	defer cancel()
	r.stateMu.Lock()
	permitted := r.state == serverRuntimeStopping &&
		r.serveReturned.Load() && r.shutdownAttempted && r.shutdownCompleted
	r.stateMu.Unlock()
	if !permitted {
		return &serverRuntimeError{}
	}
	if err := waitServerHandlers(bounded, r.gate); err != nil {
		r.permitForceClose()
		return &serverRuntimeError{}
	}
	return nil
}

// permitForceClose publishes the monotone exact-once force-close permission.
func (r *serverRuntime) permitForceClose() {
	if r == nil || r.forceReady == nil {
		return
	}
	r.forceReadyOnce.Do(func() { close(r.forceReady) })
}

// newBoundedServerContext freezes one hostile caller context and derives a
// value-free trusted child whose own deadline bounds all downstream waits.
func newBoundedServerContext(
	ctx context.Context,
	maximum time.Duration,
) (bounded context.Context, cancel context.CancelFunc, resultErr error) {
	defer func() {
		if recover() != nil {
			if cancel != nil {
				cancel()
			}
			bounded = nil
			cancel = nil
			resultErr = &serverRuntimeError{}
		}
	}()
	if nilInterfaceValue(ctx) || maximum <= 0 {
		return nil, nil, &serverRuntimeError{}
	}
	err := ctx.Err()
	deadline, present := ctx.Deadline()
	done := ctx.Done()
	if err != nil || !present || done == nil {
		return nil, nil, &serverRuntimeError{}
	}
	select {
	case <-done:
		return nil, nil, &serverRuntimeError{}
	default:
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > maximum {
		return nil, nil, &serverRuntimeError{}
	}
	bounded, cancel = context.WithDeadline(context.Background(), deadline)
	go cancelBoundedServerContext(done, bounded.Done(), cancel)
	return bounded, cancel, nil
}

// cancelBoundedServerContext relays only the frozen cancellation channel and
// always terminates when the trusted child reaches its own deadline.
func cancelBoundedServerContext(
	callerDone <-chan struct{},
	boundedDone <-chan struct{},
	cancel context.CancelFunc,
) {
	select {
	case <-callerDone:
		cancel()
	case <-boundedDone:
	}
}

// waitServerHandlers contains arbitrary gate corruption and collapses every
// non-quiescent result into the stable server runtime class.
func waitServerHandlers(
	ctx context.Context,
	gate *HandlerRegistrationGate,
) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &serverRuntimeError{}
		}
	}()
	if gate == nil || gate.Wait(ctx) != nil {
		return &serverRuntimeError{}
	}
	return nil
}

// serverErrorSink discards net/http diagnostics without retaining or emitting
// raw transport values.
type serverErrorSink struct{}

// Write discards one already-bounded logging call and reports it consumed.
func (*serverErrorSink) Write(value []byte) (int, error) {
	return len(value), nil
}

// String returns a constant content-free runtime representation.
func (*serverRuntime) String() string { return serverRuntimeRedacted }

// GoString returns a constant content-free runtime representation.
func (*serverRuntime) GoString() string { return serverRuntimeRedacted }

// Format prevents formatting verbs from traversing runtime dependencies.
func (*serverRuntime) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, serverRuntimeRedacted)
}

// MarshalJSON rejects serialization of runtime dependencies.
func (*serverRuntime) MarshalJSON() ([]byte, error) {
	return nil, &serverRuntimeError{}
}

// MarshalText rejects text serialization of runtime dependencies.
func (*serverRuntime) MarshalText() ([]byte, error) {
	return nil, &serverRuntimeError{}
}

var (
	_ app.HTTPRuntime        = (*serverRuntime)(nil)
	_ io.Writer              = (*serverErrorSink)(nil)
	_ fmt.Formatter          = (*serverRuntime)(nil)
	_ json.Marshaler         = (*serverRuntime)(nil)
	_ encoding.TextMarshaler = (*serverRuntime)(nil)
)
