package milter

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const redactedSocketRuntime = "dkim2_milter_socket_runtime{redacted}"

// SocketRuntimeConfig defines bounded Unix-listener lifecycle behavior.
type SocketRuntimeConfig struct {
	Path               string
	Mode               os.FileMode
	ConnectionDeadline time.Duration
	ShutdownTimeout    time.Duration
}

// ConnectionWorker owns one connection and must stop on context or stream closure.
type ConnectionWorker interface {
	Serve(context.Context, io.ReadWriter) error
}

// ConnectionFactory constructs isolated state and must stop when its context ends.
type ConnectionFactory func(context.Context) (ConnectionWorker, error)

// SocketRuntime owns one secure Unix listener and all of its workers.
type SocketRuntime struct {
	state *socketRuntimeState
}

// socketRuntimeState keeps copied runtime holders opaque through one private guard.
type socketRuntimeState struct {
	guard *socketRuntimeGuard
}

// socketRuntimeGuard owns the listener path and every mutable runtime resource.
type socketRuntimeGuard struct {
	config           SocketRuntimeConfig
	admission        *Admission
	factory          ConnectionFactory
	onUnexpectedExit func()

	mu         *sync.Mutex
	started    bool
	closed     bool
	listener   *net.UnixListener
	socket     *ownedSocket
	acceptCtx  context.Context
	stopAccept context.CancelFunc
	runContext context.Context
	cancel     context.CancelFunc
	acceptDone chan struct{}
	active     map[*net.UnixConn]struct{}
	workers    *sync.WaitGroup

	ready     *atomic.Bool
	closeOnce *sync.Once
	closeDone chan struct{}
	closeErr  error
}

// NewSocketRuntime constructs a stopped fail-closed Unix listener runtime.
func NewSocketRuntime(
	config SocketRuntimeConfig,
	admission *Admission,
	factory ConnectionFactory,
) (*SocketRuntime, error) {
	if admission == nil || factory == nil || !validSocketRuntimeConfig(config) {
		return nil, &Error{Class: FailureContract}
	}
	return &SocketRuntime{state: &socketRuntimeState{guard: &socketRuntimeGuard{
		config: config, admission: admission, factory: factory,
		mu: &sync.Mutex{}, workers: &sync.WaitGroup{}, ready: &atomic.Bool{},
		closeOnce: &sync.Once{}, closeDone: make(chan struct{}),
		active: make(map[*net.UnixConn]struct{}),
	}}}, nil
}

// SetUnexpectedExitCallback installs one bounded external-readiness withdrawal.
func (r *SocketRuntime) SetUnexpectedExitCallback(callback func()) error {
	state := r.privateState()
	if state == nil || callback == nil {
		return &Error{Class: FailureContract}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.started || state.closed || state.onUnexpectedExit != nil {
		return &Error{Class: FailureContract}
	}
	state.onUnexpectedExit = callback
	return nil
}

// Start securely binds the socket and waits until the accept loop is live.
func (r *SocketRuntime) Start(ctx context.Context) error {
	state := r.privateState()
	if state == nil || ctx == nil {
		return &Error{Class: FailureContract}
	}
	return state.start(ctx)
}

// privateState returns the mutable socket guard only within this package.
func (r *SocketRuntime) privateState() *socketRuntimeGuard {
	if r == nil || r.state == nil {
		return nil
	}
	return r.state.guard
}

// start binds and activates the listener through the private runtime guard.
func (r *socketRuntimeGuard) start(ctx context.Context) error {
	r.mu.Lock()
	if r.started || r.closed {
		r.mu.Unlock()
		return &Error{Class: FailureContract}
	}
	if err := ctx.Err(); err != nil {
		r.mu.Unlock()
		return &Error{Class: FailureInternal}
	}
	listener, socket, err := openSocketListener(r.config.Path, r.config.Mode)
	if err != nil {
		r.mu.Unlock()
		return err
	}
	r.started = true
	r.listener = listener
	r.socket = socket
	r.acceptCtx, r.stopAccept = context.WithCancel(context.Background())
	r.runContext, r.cancel = context.WithCancel(context.Background())
	r.acceptDone = make(chan struct{})
	acceptLive := make(chan struct{})
	r.mu.Unlock()

	go r.acceptLoop(acceptLive)
	select {
	case <-acceptLive:
		if !r.ready.Load() {
			_ = r.close(context.Background())
			return &Error{Class: FailureInternal}
		}
	case <-ctx.Done():
		_ = r.close(context.Background())
		return &Error{Class: FailureInternal}
	}
	return nil
}

// Ready reports whether the verified listener currently admits connections.
func (r *SocketRuntime) Ready() bool {
	state := r.privateState()
	return state != nil && state.ready.Load()
}

// Close clears readiness, joins cooperative workers within budget, and cleans its inode.
func (r *SocketRuntime) Close(ctx context.Context) error {
	state := r.privateState()
	if state == nil || ctx == nil {
		return &Error{Class: FailureContract}
	}
	return state.close(ctx)
}

// close coalesces every shutdown caller through the private runtime guard.
func (r *socketRuntimeGuard) close(ctx context.Context) error {
	if r == nil || ctx == nil {
		return &Error{Class: FailureContract}
	}
	r.closeOnce.Do(func() {
		r.closeErr = r.closeRuntime(ctx)
		close(r.closeDone)
	})
	<-r.closeDone
	return r.closeErr
}

// acceptLoop admits each connection before constructing or launching its worker.
func (r *socketRuntimeGuard) acceptLoop(live chan<- struct{}) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		close(live)
		close(r.acceptDone)
		return
	}
	r.ready.Store(true)
	r.mu.Unlock()
	close(live)
	unexpected := true
	defer func() {
		_ = recover()
		r.ready.Store(false)
		close(r.acceptDone)
		if unexpected {
			notifyUnexpectedSocketExit(r.onUnexpectedExit)
			go func() { _ = r.close(context.Background()) }()
		}
	}()
	for {
		connection, err := r.listener.AcceptUnix()
		if err != nil {
			r.mu.Lock()
			unexpected = !r.closed
			r.mu.Unlock()
			return
		}
		release, admitted := r.admission.AdmitConnection()
		if !admitted {
			_ = connection.Close()
			continue
		}
		worker, err := r.createConnectionWorker(r.acceptCtx)
		if err != nil || worker == nil {
			release()
			_ = connection.Close()
			continue
		}
		r.mu.Lock()
		r.active[connection] = struct{}{}
		r.workers.Add(1)
		r.mu.Unlock()
		go r.serveConnection(connection, worker, release)
	}
}

// notifyUnexpectedSocketExit contains readiness callback panics.
func notifyUnexpectedSocketExit(callback func()) {
	if callback == nil {
		return
	}
	defer func() { _ = recover() }()
	callback()
}

// createConnectionWorker contains a factory panic before any worker is launched.
func (r *socketRuntimeGuard) createConnectionWorker(
	ctx context.Context,
) (worker ConnectionWorker, resultErr error) {
	defer func() {
		if recover() != nil {
			worker = nil
			resultErr = &Error{Class: FailureInternal}
		}
	}()
	return r.factory(ctx)
}

// serveConnection contains panics and releases every connection owner exactly once.
func (r *socketRuntimeGuard) serveConnection(
	connection *net.UnixConn,
	worker ConnectionWorker,
	release func(),
) {
	defer func() {
		_ = recover()
		_ = connection.Close()
		release()
		r.mu.Lock()
		delete(r.active, connection)
		r.mu.Unlock()
		r.workers.Done()
	}()
	_ = worker.Serve(r.runContext, &deadlineStream{
		connection: connection,
		timeout:    r.config.ConnectionDeadline,
	})
}

// closeRuntime performs the single ordered shutdown and cleanup sequence.
func (r *socketRuntimeGuard) closeRuntime(ctx context.Context) error {
	r.mu.Lock()
	r.closed = true
	r.ready.Store(false)
	r.admission.Stop()
	defer func() { _ = r.admission.CloseObserver() }()
	if !r.started {
		r.mu.Unlock()
		return nil
	}
	listener := r.listener
	acceptDone := r.acceptDone
	r.stopAccept()
	r.mu.Unlock()
	_ = listener.Close()
	<-acceptDone

	workersDone := make(chan struct{})
	go func() {
		r.workers.Wait()
		close(workersDone)
	}()
	shutdownDeadline := time.Now().Add(r.config.ShutdownTimeout)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(shutdownDeadline) {
		shutdownDeadline = callerDeadline
	}
	remaining := max(time.Until(shutdownDeadline), 0)
	graceTimer := time.NewTimer(remaining * 3 / 4)
	joined := false
	select {
	case <-workersDone:
		if !graceTimer.Stop() {
			<-graceTimer.C
		}
		r.cancel()
		return r.socket.cleanup()
	case <-graceTimer.C:
	case <-ctx.Done():
	}
	r.cancelWorkers()
	remaining = time.Until(shutdownDeadline)
	if remaining > 0 {
		finalTimer := time.NewTimer(remaining)
		select {
		case <-workersDone:
			joined = true
			if !finalTimer.Stop() {
				<-finalTimer.C
			}
		case <-finalTimer.C:
		}
	}
	if err := r.socket.cleanup(); err != nil {
		return err
	}
	if !joined {
		return &Error{Class: FailureInternal}
	}
	return nil
}

// cancelWorkers cancels operation contexts and closes every retained socket.
func (r *socketRuntimeGuard) cancelWorkers() {
	r.cancel()
	r.mu.Lock()
	connections := make([]*net.UnixConn, 0, len(r.active))
	for connection := range r.active {
		connections = append(connections, connection)
	}
	r.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

// String returns a content-free socket-runtime diagnostic.
func (SocketRuntime) String() string { return redactedSocketRuntime }

// GoString returns a content-free socket-runtime representation.
func (SocketRuntime) GoString() string { return redactedSocketRuntime }

// Format prevents formatting from traversing the listener path and owners.
func (SocketRuntime) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, redactedSocketRuntime)
}

// MarshalJSON rejects socket-runtime serialization.
func (SocketRuntime) MarshalJSON() ([]byte, error) {
	return nil, &Error{Class: FailureContract}
}

// MarshalText rejects socket-runtime text serialization.
func (SocketRuntime) MarshalText() ([]byte, error) {
	return nil, &Error{Class: FailureContract}
}

// String returns a content-free private socket-state diagnostic.
func (socketRuntimeState) String() string { return redactedSocketRuntime }

// GoString returns a content-free private socket-state representation.
func (socketRuntimeState) GoString() string { return redactedSocketRuntime }

// Format prevents copied state from traversing the private guard.
func (socketRuntimeState) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, redactedSocketRuntime)
}

// MarshalJSON rejects private socket-state serialization.
func (socketRuntimeState) MarshalJSON() ([]byte, error) {
	return nil, &Error{Class: FailureContract}
}

// MarshalText rejects private socket-state text serialization.
func (socketRuntimeState) MarshalText() ([]byte, error) {
	return nil, &Error{Class: FailureContract}
}

// String returns a content-free private socket-guard diagnostic.
func (socketRuntimeGuard) String() string { return redactedSocketRuntime }

// GoString returns a content-free private socket-guard representation.
func (socketRuntimeGuard) GoString() string { return redactedSocketRuntime }

// Format prevents guard dereferencing from traversing the listener path and owners.
func (socketRuntimeGuard) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, redactedSocketRuntime)
}

// MarshalJSON rejects private socket-guard serialization.
func (socketRuntimeGuard) MarshalJSON() ([]byte, error) {
	return nil, &Error{Class: FailureContract}
}

// MarshalText rejects private socket-guard text serialization.
func (socketRuntimeGuard) MarshalText() ([]byte, error) {
	return nil, &Error{Class: FailureContract}
}

// validSocketRuntimeConfig rejects non-Unix paths and unsafe lifecycle bounds.
func validSocketRuntimeConfig(config SocketRuntimeConfig) bool {
	cleanMode := config.Mode.Perm()
	return config.Path != "" && config.Path[0] == '/' &&
		cleanMode == config.Mode && (cleanMode == 0o600 || cleanMode == 0o660) &&
		config.ConnectionDeadline > 0 && config.ShutdownTimeout > 0
}

// deadlineStream refreshes idle read and write deadlines without capping connection lifetime.
type deadlineStream struct {
	connection *net.UnixConn
	timeout    time.Duration
}

// Read refreshes the connection's bounded read deadline before one operation.
func (s *deadlineStream) Read(buffer []byte) (int, error) {
	if s == nil || s.connection == nil {
		return 0, &Error{Class: FailureInternal}
	}
	if err := s.connection.SetReadDeadline(time.Now().Add(s.timeout)); err != nil {
		return 0, &Error{Class: FailureInternal}
	}
	return s.connection.Read(buffer)
}

// Write refreshes the connection's bounded write deadline before one operation.
func (s *deadlineStream) Write(buffer []byte) (int, error) {
	if s == nil || s.connection == nil {
		return 0, &Error{Class: FailureInternal}
	}
	if err := s.connection.SetWriteDeadline(time.Now().Add(s.timeout)); err != nil {
		return 0, &Error{Class: FailureInternal}
	}
	return s.connection.Write(buffer)
}
