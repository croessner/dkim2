package inbound

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/ipc"
)

const unixNetwork = "unix"

const defaultMaxConnections = 128

// Processor owns the generated-daemon processing and closed response mapping.
type Processor interface {
	Process(context.Context, adapter.LocalScanRequest) (ipc.Response, error)
}

// EventObserver receives only closed service outcome vocabulary.
type EventObserver interface {
	ObserveInbound(result string, failure string, admission string, failOpen bool)
}

// ServiceConfig constrains one local-scan Unix socket listener.
type ServiceConfig struct {
	Path             string
	Timeout          time.Duration
	MaxConnections   int
	MaxInFlight      int
	MaxBufferedBytes int64
	ReservationBytes int64
	Limits           ipc.RequestLimits
	PeerUID          uint32
	AllowIDs         *adapter.BuildAllowlist
	AuthservID       string
	Observer         EventObserver
	DrainGrace       time.Duration
}

// Service owns bounded one-request-per-connection IPC admission.
type Service struct {
	config    ServiceConfig
	processor Processor
	listener  *net.UnixListener
	peerCheck peerCheck
	socket    *ownedSocket
	slots     chan struct{}
	stopped   chan struct{}
	closed    bool
	mu        *sync.Mutex
	workers   *sync.WaitGroup
	active    map[*net.UnixConn]struct{}
	buffered  int64
	inFlight  int
	runCancel context.CancelFunc
}

// peerCheck admits one local Unix peer before any mail data is read.
type peerCheck func(*net.UnixConn) bool

// NewService validates the fixed local IPC boundary before binding a socket.
func NewService(config ServiceConfig, processor Processor) (*Service, error) {
	if runtime.GOOS != "linux" {
		return nil, adapter.NewError(adapter.FailureContract)
	}
	if config.PeerUID != uint32(os.Geteuid()) {
		return nil, adapter.NewError(adapter.FailureContract)
	}
	return newService(config, processor, func(connection *net.UnixConn) bool {
		return samePeerUID(connection, config.PeerUID)
	})
}

// newService creates a service with an explicit peer checker for isolated tests.
func newService(config ServiceConfig, processor Processor, peerAdmission peerCheck) (*Service, error) {
	if config.MaxConnections == 0 {
		config.MaxConnections = defaultMaxConnections
	}
	if config.MaxInFlight == 0 {
		config.MaxInFlight = config.MaxConnections
	}
	if config.MaxBufferedBytes == 0 {
		config.MaxBufferedBytes = int64(ipc.RequestPayloadBytes)
	}
	if config.ReservationBytes == 0 {
		config.ReservationBytes = int64(ipc.RequestPayloadBytes)
	}
	if config.Limits == (ipc.RequestLimits{}) {
		config.Limits = ipc.DefaultRequestLimits()
	}
	if config.DrainGrace == 0 {
		config.DrainGrace = 2 * time.Second
	}
	if processor == nil || config.AllowIDs == nil || !filepath.IsAbs(config.Path) ||
		config.Timeout <= 0 || config.Timeout > 10*time.Second || peerAdmission == nil {
		return nil, adapter.NewError(adapter.FailureContract)
	}
	if config.MaxConnections < 1 || config.MaxConnections > 4_096 ||
		config.MaxInFlight < 1 || config.MaxInFlight > 1024 ||
		config.MaxInFlight > config.MaxConnections || config.MaxBufferedBytes < 1 ||
		config.MaxBufferedBytes > 1<<34 || config.ReservationBytes < 1 ||
		config.ReservationBytes > config.MaxBufferedBytes || !config.Limits.Valid() {
		return nil, adapter.NewError(adapter.FailureContract)
	}
	if config.DrainGrace < time.Millisecond || config.DrainGrace > 2*time.Second {
		return nil, adapter.NewError(adapter.FailureContract)
	}
	return &Service{
		config: config, processor: processor, peerCheck: peerAdmission,
		slots: make(chan struct{}, config.MaxConnections), stopped: make(chan struct{}),
		active: make(map[*net.UnixConn]struct{}), mu: &sync.Mutex{}, workers: &sync.WaitGroup{},
	}, nil
}

// Start binds the service-owned socket with restrictive permissions.
func (s *Service) Start() error {
	if s == nil {
		return adapter.NewError(adapter.FailureContract)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil || s.closed {
		return adapter.NewError(adapter.FailureContract)
	}
	listener, socket, err := openSocketListener(s.config.Path, 0o600)
	if err != nil {
		return adapter.NewError(adapter.FailureContract)
	}
	s.listener = listener
	s.socket = socket
	return nil
}

// Serve accepts connections until context cancellation or listener closure.
func (s *Service) Serve(ctx context.Context) error {
	return s.serve(ctx, nil)
}

// ServeAsync starts the accept loop and reports when it has entered service ownership.
func (s *Service) ServeAsync(ctx context.Context) (<-chan struct{}, <-chan error, error) {
	if s == nil || ctx == nil {
		return nil, nil, adapter.NewError(adapter.FailureContract)
	}
	live := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- s.serve(ctx, live)
		close(done)
	}()
	return live, done, nil
}

// serve accepts connections until cancellation or listener closure after publishing live state.
func (s *Service) serve(ctx context.Context, live chan<- struct{}) error {
	if s == nil || ctx == nil {
		return adapter.NewError(adapter.FailureContract)
	}
	s.mu.Lock()
	listener := s.listener
	if s.runCancel != nil {
		s.mu.Unlock()
		return adapter.NewError(adapter.FailureContract)
	}
	runContext, runCancel := context.WithCancel(ctx)
	s.runCancel = runCancel
	s.mu.Unlock()
	if listener == nil {
		return adapter.NewError(adapter.FailureContract)
	}
	if live != nil {
		close(live)
	}
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return adapter.NewError(adapter.FailureUnavailable)
		}
		if !s.reserveWorker(runContext, connection) {
			return nil
		}
	}
}

// Close stops admission and removes only the socket owned by this service.
func (s *Service) Close() error {
	return s.CloseContext(context.Background())
}

// CloseContext stops admission, cancels active connections, and removes only the owned socket.
func (s *Service) CloseContext(ctx context.Context) (resultErr error) {
	return s.closeContext(ctx, true)
}

// DrainContext stops admission and joins active work while retaining the owned pathname.
func (s *Service) DrainContext(ctx context.Context) error {
	return s.closeContext(ctx, false)
}

// closeContext drains active work and optionally performs final pathname cleanup.
func (s *Service) closeContext(ctx context.Context, cleanupSocket bool) (resultErr error) {
	if s == nil {
		return nil
	}
	if ctx == nil {
		return adapter.NewError(adapter.FailureContract)
	}
	s.mu.Lock()
	firstClose := !s.closed
	if firstClose {
		s.closed = true
		close(s.stopped)
	}
	listener := s.listener
	s.listener = nil
	socket := s.socket
	if cleanupSocket {
		s.socket = nil
	}
	s.mu.Unlock()
	var closeErr error
	if firstClose && listener != nil {
		closeErr = listener.Close()
	}
	if cleanupSocket && socket != nil {
		defer func() {
			if cleanupErr := socket.cleanup(); cleanupErr != nil && resultErr == nil {
				resultErr = adapter.NewError(adapter.FailureContract)
			}
		}()
	}
	drained := make(chan struct{})
	go func() { s.workers.Wait(); close(drained) }()
	grace := time.NewTimer(s.config.DrainGrace)
	defer grace.Stop()
	select {
	case <-drained:
	case <-grace.C:
		s.forceCancel()
		select {
		case <-drained:
		case <-ctx.Done():
			return adapter.NewError(adapter.FailureUnavailable)
		}
	case <-ctx.Done():
		s.forceCancel()
		select {
		case <-drained:
		default:
			return adapter.NewError(adapter.FailureUnavailable)
		}
	}
	s.releaseRunContext()
	if closeErr != nil {
		return adapter.NewError(adapter.FailureUnavailable)
	}
	return nil
}

// releaseRunContext releases the worker parent only after every worker joined.
func (s *Service) releaseRunContext() {
	if s == nil {
		return
	}
	s.mu.Lock()
	cancel := s.runCancel
	s.runCancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// RemoveSocket removes only the exact retained owned socket after dependent joins.
func (s *Service) RemoveSocket() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	socket := s.socket
	s.socket = nil
	s.mu.Unlock()
	if socket == nil {
		return nil
	}
	if err := socket.cleanup(); err != nil {
		return adapter.NewError(adapter.FailureContract)
	}
	return nil
}

// forceCancel breaks blocked reads and cancels all processor contexts.
func (s *Service) forceCancel() {
	if s == nil {
		return
	}
	s.mu.Lock()
	connections := make([]*net.UnixConn, 0, len(s.active))
	for connection := range s.active {
		connections = append(connections, connection)
	}
	cancel := s.runCancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	for _, connection := range connections {
		_ = connection.Close()
	}
}

// reserveWorker admits one bounded connection or closes it during shutdown.
func (s *Service) reserveWorker(parent context.Context, connection *net.UnixConn) bool {
	if connection == nil {
		return false
	}
	select {
	case <-s.stopped:
		_ = connection.Close()
		return false
	default:
	}
	select {
	case s.slots <- struct{}{}:
	default:
		_ = connection.Close()
		s.observe("failure", "capacity", "connection_limit")
		return true
	case <-s.stopped:
		_ = connection.Close()
		return false
	case <-parent.Done():
		_ = connection.Close()
		return false
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		<-s.slots
		_ = connection.Close()
		return false
	}
	s.workers.Add(1)
	s.active[connection] = struct{}{}
	s.mu.Unlock()
	deadline := time.Now().Add(s.config.Timeout)
	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.active, connection)
			s.mu.Unlock()
			<-s.slots
			s.workers.Done()
		}()
		s.handle(parent, connection, deadline)
	}()
	return true
}

// handle serves one EOF-delimited request and one closed response.
func (s *Service) handle(parent context.Context, connection *net.UnixConn, deadline time.Time) {
	defer closeConnection(connection)
	defer containWorkerPanic()
	if deadline.IsZero() || connection.SetDeadline(deadline) != nil {
		return
	}
	if !s.peerCheck(connection) {
		return
	}
	reserved := int64(0)
	admissionRejected := false
	request, err := ipc.DecodeRequestStreamLimited(connection, s.config.AllowIDs.Allows, s.config.Limits, func(payload uint32) bool {
		if payload == 0 {
			return false
		}
		admitted, admission := s.reserveRequest(s.config.ReservationBytes)
		if !admitted {
			admissionRejected = true
			s.observe("failure", "capacity", admission)
			return false
		}
		reserved = s.config.ReservationBytes
		return true
	})
	defer s.releaseRequest(reserved)
	if err != nil {
		if !admissionRejected {
			s.observe("failure", wireFailure(err), "accepted")
		}
		return
	}
	projected, err := ProjectRequest(request)
	if err != nil {
		return
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	processContext, outcome := adapter.WithOutcome(ctx)
	response, err := s.processor.Process(processContext, projected)
	if err != nil {
		s.observe("failure", adapterFailure(err), "accepted")
		return
	}
	headers := request.Headers()
	eligible := adapter.LocalAuthenticationResultOccurrences(headers, s.config.AuthservID)
	frame, err := ipc.EncodeResponse(response, eligible, uint16(len(headers)))
	clearHeaders(headers)
	clear(eligible)
	if err != nil {
		return
	}
	if writeAll(connection, frame) != nil {
		s.observe("failure", "unavailable", "accepted")
		return
	}
	failure := "none"
	if outcome.FailOpen() {
		failure = "unavailable"
	}
	s.observe("success", failure, "accepted", outcome.FailOpen())
}

// wireFailure maps closed IPC failures to the telemetry allowlist.
func wireFailure(err error) string {
	var wire *ipc.WireError
	if errors.As(err, &wire) && wire.Class() == ipc.FailureResourceLimit {
		return "capacity"
	}
	return "contract"
}

// adapterFailure maps closed processor failures to the telemetry allowlist.
func adapterFailure(err error) string {
	var failure *adapter.Error
	if !errors.As(err, &failure) {
		return "internal"
	}
	switch failure.Class() {
	case adapter.FailureFidelity:
		return "fidelity"
	case adapter.FailureContract, adapter.FailureInvalidRequest:
		return "contract"
	case adapter.FailureResource:
		return "capacity"
	case adapter.FailureUnavailable:
		return "unavailable"
	case adapter.FailureTimeout:
		return "timeout"
	default:
		return "internal"
	}
}

// reserveRequest atomically admits one message slot and its conservative byte budget.
func (s *Service) reserveRequest(size int64) (bool, string) {
	if s == nil || size < 1 {
		return false, "byte_limit"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, "stopping"
	}
	if s.inFlight >= s.config.MaxInFlight {
		return false, "message_limit"
	}
	if size > s.config.MaxBufferedBytes-s.buffered {
		return false, "byte_limit"
	}
	s.buffered += size
	s.inFlight++
	return true, "accepted"
}

// releaseRequest returns one atomic message and byte reservation.
func (s *Service) releaseRequest(size int64) {
	if s == nil || size < 1 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if size > s.buffered {
		s.buffered = 0
	} else {
		s.buffered -= size
	}
	if s.inFlight > 0 {
		s.inFlight--
	}
}

// observe contains observer panics outside service and mail-decision ownership.
func (s *Service) observe(result string, failure string, admission string, failOpen ...bool) {
	if s == nil || s.config.Observer == nil {
		return
	}
	defer func() { _ = recover() }()
	selected := false
	if len(failOpen) == 1 {
		selected = failOpen[0]
	}
	s.config.Observer.ObserveInbound(result, failure, admission, selected)
}

// containWorkerPanic converts dependency panics into a silent closed connection.
func containWorkerPanic() {
	_ = recover()
}

// writeAll completes one bounded response or reports a closed short-write failure.
func writeAll(output interface{ Write([]byte) (int, error) }, frame []byte) error {
	for len(frame) > 0 {
		count, err := output.Write(frame)
		if count < 0 || count > len(frame) || count == 0 {
			return adapter.NewError(adapter.FailureUnavailable)
		}
		frame = frame[count:]
		if err != nil {
			return adapter.NewError(adapter.FailureUnavailable)
		}
	}
	return nil
}

// closeConnection closes one worker connection after all response ownership ends.
func closeConnection(connection *net.UnixConn) {
	if connection == nil {
		return
	}
	if err := connection.Close(); err != nil {
		return
	}
}
