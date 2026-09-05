package lmtp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const redactedRuntime = "dkim2_dsn_propagator_lmtp_runtime{redacted}"

// RuntimeConfig defines the bounded Unix-listener lifecycle of the receiver.
type RuntimeConfig struct {
	// Path is the absolute Unix-socket path.
	Path string
	// Mode is the exact requested socket mode.
	Mode os.FileMode
	// MaxConnections bounds concurrently served connections.
	MaxConnections int
	// ConnectionDeadline bounds one idle connection.
	ConnectionDeadline time.Duration
	// ShutdownTimeout bounds the cooperative drain.
	ShutdownTimeout time.Duration
	// Limits bounds each session.
	Limits Limits
}

// valid rejects an incomplete listener policy before binding.
func (c RuntimeConfig) valid() bool {
	return c.Path != "" && c.Mode.Perm() != 0 && c.MaxConnections >= 1 &&
		c.MaxConnections <= 4096 && c.ConnectionDeadline > 0 &&
		c.ShutdownTimeout > 0 && c.Limits.valid()
}

// Runtime owns one secure Unix listener and all of its sessions.
type Runtime struct {
	state *runtimeState
}

// runtimeState keeps copied runtime holders opaque through one private guard.
type runtimeState struct {
	guard *runtimeGuard
}

// runtimeGuard owns the listener and every mutable runtime resource.
type runtimeGuard struct {
	config  RuntimeConfig
	handler Handler

	mu         *sync.Mutex
	started    bool
	closed     bool
	listener   *net.UnixListener
	socket     *ownedSocket
	runContext context.Context
	cancel     context.CancelFunc
	acceptDone chan struct{}
	active     map[net.Conn]struct{}
	workers    *sync.WaitGroup
	slots      chan struct{}

	ready     *atomic.Bool
	closeOnce *sync.Once
	closeDone chan struct{}
	closeErr  error
}

// NewRuntime constructs a stopped fail-closed Unix listener runtime.
func NewRuntime(config RuntimeConfig, handler Handler) (*Runtime, error) {
	if handler == nil || !config.valid() {
		return nil, &Error{}
	}
	return &Runtime{state: &runtimeState{guard: &runtimeGuard{
		config: config, handler: handler,
		mu: &sync.Mutex{}, workers: &sync.WaitGroup{}, ready: &atomic.Bool{},
		closeOnce: &sync.Once{}, closeDone: make(chan struct{}),
		active: make(map[net.Conn]struct{}),
		slots:  make(chan struct{}, config.MaxConnections),
	}}}, nil
}

// privateState returns the mutable runtime guard only within this package.
func (r *Runtime) privateState() *runtimeGuard {
	if r == nil || r.state == nil {
		return nil
	}
	return r.state.guard
}

// Start securely binds the socket and waits until the accept loop is live.
func (r *Runtime) Start(ctx context.Context) error {
	guard := r.privateState()
	if guard == nil || ctx == nil {
		return &Error{}
	}
	guard.mu.Lock()
	if guard.started || guard.closed {
		guard.mu.Unlock()
		return &Error{}
	}
	if err := ctx.Err(); err != nil {
		guard.mu.Unlock()
		return &Error{}
	}
	listener, socket, err := openSocketListener(guard.config.Path, guard.config.Mode)
	if err != nil {
		guard.mu.Unlock()
		return &Error{}
	}
	guard.started = true
	guard.listener = listener
	guard.socket = socket
	guard.runContext, guard.cancel = context.WithCancel(context.Background())
	guard.acceptDone = make(chan struct{})
	live := make(chan struct{})
	guard.mu.Unlock()
	go guard.acceptLoop(live)
	select {
	case <-live:
		if !guard.ready.Load() {
			_ = guard.close(context.Background())
			return &Error{}
		}
	case <-ctx.Done():
		_ = guard.close(context.Background())
		return &Error{}
	}
	return nil
}

// Ready reports whether the verified listener currently admits connections.
func (r *Runtime) Ready() bool {
	guard := r.privateState()
	return guard != nil && guard.ready.Load()
}

// Close clears readiness, drains sessions within budget, and removes its inode.
func (r *Runtime) Close(ctx context.Context) error {
	guard := r.privateState()
	if guard == nil || ctx == nil {
		return &Error{}
	}
	return guard.close(ctx)
}

// close coalesces every shutdown caller through the private runtime guard.
func (r *runtimeGuard) close(ctx context.Context) error {
	r.closeOnce.Do(func() {
		r.closeErr = r.shutdown(ctx)
		close(r.closeDone)
	})
	<-r.closeDone
	return r.closeErr
}

// shutdown performs the single ordered listener and worker release.
func (r *runtimeGuard) shutdown(ctx context.Context) error {
	r.mu.Lock()
	r.closed = true
	r.ready.Store(false)
	listener, socket := r.listener, r.socket
	cancel, acceptDone := r.cancel, r.acceptDone
	connections := make([]net.Conn, 0, len(r.active))
	for connection := range r.active {
		connections = append(connections, connection)
	}
	r.listener, r.socket = nil, nil
	r.mu.Unlock()
	failed := false
	if listener != nil {
		if err := listener.Close(); err != nil {
			failed = true
		}
	}
	if acceptDone != nil {
		select {
		case <-acceptDone:
		case <-ctx.Done():
			failed = true
		}
	}
	drained := make(chan struct{})
	go func() {
		r.workers.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-ctx.Done():
		for _, connection := range connections {
			_ = connection.Close()
		}
		if cancel != nil {
			cancel()
		}
		select {
		case <-drained:
		case <-time.After(r.config.ShutdownTimeout):
			failed = true
		}
	}
	if cancel != nil {
		cancel()
	}
	if socket != nil {
		if err := socket.cleanup(); err != nil {
			failed = true
		}
	}
	if failed {
		return &Error{}
	}
	return nil
}

// acceptLoop admits each connection under the configured connection bound.
func (r *runtimeGuard) acceptLoop(live chan<- struct{}) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		close(live)
		close(r.acceptDone)
		return
	}
	listener := r.listener
	r.ready.Store(true)
	r.mu.Unlock()
	close(live)
	defer func() {
		_ = recover()
		r.ready.Store(false)
		close(r.acceptDone)
	}()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			var netError net.Error
			if errors.As(err, &netError) && netError.Timeout() {
				continue
			}
			return
		}
		if !r.admit(connection) {
			_ = connection.Close()
			continue
		}
		r.workers.Add(1)
		go r.serve(connection)
	}
}

// admit reserves one connection slot and registers the active connection.
func (r *runtimeGuard) admit(connection net.Conn) bool {
	select {
	case r.slots <- struct{}{}:
	default:
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		<-r.slots
		return false
	}
	r.active[connection] = struct{}{}
	return true
}

// serve runs one isolated session and always releases its connection slot.
func (r *runtimeGuard) serve(connection net.Conn) {
	defer func() {
		_ = recover()
		r.mu.Lock()
		delete(r.active, connection)
		r.mu.Unlock()
		_ = connection.Close()
		<-r.slots
		r.workers.Done()
	}()
	_ = connection.SetDeadline(time.Now().Add(r.config.ConnectionDeadline))
	session, err := newSession(
		deadlineStream{connection: connection, idle: r.config.ConnectionDeadline},
		r.config.Limits,
		r.handler,
	)
	if err != nil {
		return
	}
	_ = session.Serve(r.runContext)
}

// deadlineStream refreshes the idle bound on every completed stream operation.
type deadlineStream struct {
	connection net.Conn
	idle       time.Duration
}

// Read refreshes the idle deadline before each bounded read.
func (s deadlineStream) Read(buffer []byte) (int, error) {
	if err := s.connection.SetReadDeadline(time.Now().Add(s.idle)); err != nil {
		return 0, err
	}
	return s.connection.Read(buffer)
}

// Write refreshes the idle deadline before each bounded write.
func (s deadlineStream) Write(buffer []byte) (int, error) {
	if err := s.connection.SetWriteDeadline(time.Now().Add(s.idle)); err != nil {
		return 0, err
	}
	return s.connection.Write(buffer)
}

// String returns a content-free runtime diagnostic.
func (Runtime) String() string { return redactedRuntime }

// GoString returns a content-free runtime representation.
func (r Runtime) GoString() string { return r.String() }

// Format prevents formatting from traversing listener state.
func (r Runtime) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// MarshalJSON rejects runtime serialization.
func (Runtime) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// MarshalText rejects runtime text serialization.
func (Runtime) MarshalText() ([]byte, error) { return nil, &Error{} }

// String returns a content-free private runtime-state diagnostic.
func (runtimeState) String() string { return redactedRuntime }

// GoString returns a content-free private runtime-state representation.
func (r runtimeState) GoString() string { return r.String() }

// Format prevents nested formatting from traversing live runtime resources.
func (r runtimeState) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// MarshalJSON rejects private runtime-state serialization.
func (runtimeState) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// MarshalText rejects private runtime-state text serialization.
func (runtimeState) MarshalText() ([]byte, error) { return nil, &Error{} }

// String returns a content-free private runtime-guard diagnostic.
func (runtimeGuard) String() string { return redactedRuntime }

// GoString returns a content-free private runtime-guard representation.
func (r runtimeGuard) GoString() string { return r.String() }

// Format prevents guard dereferencing from traversing live runtime resources.
func (r runtimeGuard) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// MarshalJSON rejects private runtime-guard serialization.
func (runtimeGuard) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// MarshalText rejects private runtime-guard text serialization.
func (runtimeGuard) MarshalText() ([]byte, error) { return nil, &Error{} }
