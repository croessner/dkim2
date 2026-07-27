package observability

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// metricsListen binds one exact loopback listener within a caller context.
type metricsListen func(context.Context, string, string) (net.Listener, error)

// metricsServer owns the optional loopback HTTP listener lifecycle.
type metricsServer struct {
	authority        string
	handler          http.Handler
	listen           metricsListen
	onUnexpectedExit func()

	mu       sync.Mutex
	listener net.Listener
	server   *http.Server
	workers  sync.WaitGroup

	started atomic.Bool
	stopped atomic.Bool
	running atomic.Bool
}

// newMetricsServer validates but does not acquire the optional listener.
func newMetricsServer(
	authority string,
	registry *Registry,
	listen metricsListen,
) (*metricsServer, error) {
	if authority == "" {
		return nil, nil
	}
	if listen == nil {
		return nil, errConfiguration
	}
	handler, err := MetricsHandler(authority, registry)
	if err != nil {
		return nil, errConfiguration
	}
	return &metricsServer{
		authority: authority,
		handler:   handler,
		listen:    listen,
	}, nil
}

// start binds and begins serving exactly once with complete panic rollback.
func (s *metricsServer) start(ctx context.Context) (resultErr error) {
	if s == nil {
		return nil
	}
	if ctx == nil || s.stopped.Load() || !s.started.CompareAndSwap(false, true) {
		return errConfiguration
	}
	var listener net.Listener
	defer func() {
		if recover() != nil {
			resultErr = errConfiguration
		}
		if resultErr != nil {
			closeMetricsListener(listener)
			s.rollbackStart()
		}
	}()
	var err error
	listener, err = s.listen(ctx, "tcp", s.authority)
	if err != nil || listener == nil {
		return errConfiguration
	}
	address := listener.Addr()
	if address == nil || address.Network() != "tcp" ||
		address.String() != s.authority {
		return errConfiguration
	}
	server := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       2 * time.Second,
		WriteTimeout:      2 * time.Second,
		IdleTimeout:       time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context {
			return context.Background()
		},
		ConnContext: func(context.Context, net.Conn) context.Context {
			return context.Background()
		},
	}
	server.SetKeepAlivesEnabled(false)
	s.mu.Lock()
	s.listener = listener
	s.server = server
	s.running.Store(true)
	s.workers.Add(1)
	s.mu.Unlock()
	go s.serve(server, listener)
	return nil
}

// rollbackStart clears every resource publication after a failed start.
func (s *metricsServer) rollbackStart() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.listener = nil
	s.server = nil
	s.running.Store(false)
	s.mu.Unlock()
}

// serve contains listener and HTTP server panics behind the telemetry boundary.
func (s *metricsServer) serve(server *http.Server, listener net.Listener) {
	defer s.workers.Done()
	unexpected := false
	func() {
		defer func() {
			if recover() != nil {
				unexpected = true
			}
		}()
		serveErr := server.Serve(listener)
		unexpected = serveErr != nil && serveErr != http.ErrServerClosed
	}()
	s.running.Store(false)
	if unexpected && !s.stopped.Load() {
		closeMetricsListener(listener)
		notifyUnexpectedExit(s.onUnexpectedExit)
	}
}

// closeMetricsListener closes a listener while containing hostile seam panics.
func closeMetricsListener(listener net.Listener) {
	if listener == nil {
		return
	}
	defer func() { _ = recover() }()
	_ = listener.Close()
}

// notifyUnexpectedExit contains callback defects behind the server boundary.
func notifyUnexpectedExit(callback func()) {
	if callback == nil {
		return
	}
	defer func() { _ = recover() }()
	callback()
}

// stop terminates serving, closes the listener, and joins its worker.
func (s *metricsServer) stop(ctx context.Context) (resultErr error) {
	if s == nil {
		return nil
	}
	if ctx == nil {
		return errConfiguration
	}
	if !s.stopped.CompareAndSwap(false, true) {
		return nil
	}
	defer func() {
		if recover() != nil {
			resultErr = errConfiguration
		}
	}()
	s.mu.Lock()
	server := s.server
	listener := s.listener
	s.mu.Unlock()
	var shutdownErr error
	if server != nil {
		shutdownErr = server.Shutdown(ctx)
		func() {
			defer func() { _ = recover() }()
			_ = server.Close()
		}()
	}
	closeMetricsListener(listener)
	s.workers.Wait()
	s.running.Store(false)
	if shutdownErr != nil {
		return errConfiguration
	}
	return nil
}

// isRunning reports whether the optional listener is actively serving.
func (s *metricsServer) isRunning() bool {
	return s == nil || s.running.Load()
}
