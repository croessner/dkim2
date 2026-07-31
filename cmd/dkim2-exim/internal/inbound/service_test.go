package inbound

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/ipc"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/testsupport"
)

// processorFunc supplies one independently controlled inbound processor.
type processorFunc func(context.Context, adapter.LocalScanRequest) (ipc.Response, error)

// TestNewServiceRejectsPeerUIDDifferentFromOwner proves an unusable 0600 socket never reaches readiness.
func TestNewServiceRejectsPeerUIDDifferentFromOwner(t *testing.T) {
	allowlist, err := adapter.NewBuildAllowlist([]string{strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal("allowlist fixture failed")
	}
	peer := uint32(os.Geteuid()) + 1
	if peer == 0 {
		peer = 1
	}
	processor := processorFunc(func(context.Context, adapter.LocalScanRequest) (ipc.Response, error) {
		return ipc.Response{}, adapter.NewError(adapter.FailureUnavailable)
	})
	if _, err := NewService(ServiceConfig{
		Path: "/run/dkim2-exim/service.sock", Timeout: time.Second,
		PeerUID: peer, AllowIDs: allowlist,
	}, processor); err == nil {
		t.Fatal("peer UID different from service owner accepted")
	}
}

// Process delegates to the independently controlled inbound processor fixture.
func (f processorFunc) Process(ctx context.Context, request adapter.LocalScanRequest) (ipc.Response, error) {
	return f(ctx, request)
}

// shortWriter exposes short and zero writes without a local socket dependency.
type shortWriter struct {
	limit  int
	output bytes.Buffer
}

// Write accepts at most the configured number of bytes for each call.
func (w *shortWriter) Write(value []byte) (int, error) {
	if w.limit == 0 {
		return 0, nil
	}
	if len(value) > w.limit {
		value = value[:w.limit]
	}
	return w.output.Write(value)
}

// TestServiceConnectionBoundsRejectInvalidConfiguration proves connection
// admission is bounded before a listener can bind.
func TestServiceConnectionBoundsRejectInvalidConfiguration(t *testing.T) {
	allowlist, err := adapter.NewBuildAllowlist([]string{strings.Repeat("a", ipc.BuildIDBytes)})
	if err != nil {
		t.Fatal("allowlist construction failed")
	}
	processor := processorFunc(func(context.Context, adapter.LocalScanRequest) (ipc.Response, error) {
		return ipc.Response{}, nil
	})
	if _, err = newService(ServiceConfig{
		Path: "/tmp/dkim2-exim.sock", Timeout: time.Second, MaxConnections: 4_097, AllowIDs: allowlist,
	}, processor, func(*net.UnixConn) bool { return true }); err == nil {
		t.Fatal("unbounded connection configuration accepted")
	}
	service, err := newService(ServiceConfig{
		Path: "/tmp/dkim2-exim.sock", Timeout: time.Second, AllowIDs: allowlist,
	}, processor, func(*net.UnixConn) bool { return true })
	if err != nil || cap(service.slots) != defaultMaxConnections {
		t.Fatal("default connection bound drifted")
	}
}

// TestWriteAllCompletesShortWrites proves a response cannot be truncated by a
// successful partial Unix-socket write.
func TestWriteAllCompletesShortWrites(t *testing.T) {
	writer := &shortWriter{limit: 2}
	if err := writeAll(writer, []byte("closed-response")); err != nil ||
		writer.output.String() != "closed-response" {
		t.Fatal("short response write was not completed")
	}
	if err := writeAll(&shortWriter{}, []byte("x")); err == nil {
		t.Fatal("zero response write was accepted")
	}
}

// TestDrainPreservesGraceThenForceCancels proves the two shutdown phases.
func TestDrainPreservesGraceThenForceCancels(t *testing.T) {
	allowlist, err := adapter.NewBuildAllowlist([]string{strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal("allowlist fixture failed")
	}
	processor := processorFunc(func(context.Context, adapter.LocalScanRequest) (ipc.Response, error) {
		return ipc.Response{}, adapter.NewError(adapter.FailureUnavailable)
	})
	service, err := newService(ServiceConfig{
		Path: "/tmp/service.sock", Timeout: time.Second, DrainGrace: 50 * time.Millisecond,
		AllowIDs: allowlist,
	}, processor, func(*net.UnixConn) bool { return true })
	if err != nil {
		t.Fatal("service fixture failed")
	}
	runContext, cancel := context.WithCancel(context.Background())
	service.runCancel = cancel
	service.workers.Add(1)
	graceCancelled := make(chan bool, 1)
	go func() {
		time.Sleep(10 * time.Millisecond)
		graceCancelled <- runContext.Err() != nil
		service.workers.Done()
	}()
	if err := service.DrainContext(context.Background()); err != nil {
		t.Fatal("graceful drain failed")
	}
	if <-graceCancelled {
		t.Fatal("graceful worker context was cancelled")
	}

	forced, err := newService(ServiceConfig{
		Path: "/tmp/forced.sock", Timeout: time.Second, DrainGrace: time.Millisecond,
		AllowIDs: allowlist,
	}, processor, func(*net.UnixConn) bool { return true })
	if err != nil {
		t.Fatal("forced service fixture failed")
	}
	forcedContext, forcedCancel := context.WithCancel(context.Background())
	forced.runCancel = forcedCancel
	forced.workers.Add(1)
	go func() {
		<-forcedContext.Done()
		forced.workers.Done()
	}()
	shutdown, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := forced.DrainContext(shutdown); err != nil || forcedContext.Err() == nil {
		t.Fatal("forced phase did not cancel and join remainder")
	}
}

// TestRequestAdmissionIsAtomic proves message, byte, and stopping limits form one reservation.
func TestRequestAdmissionIsAtomic(t *testing.T) {
	allowlist, err := adapter.NewBuildAllowlist([]string{strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal("allowlist fixture failed")
	}
	processor := processorFunc(func(context.Context, adapter.LocalScanRequest) (ipc.Response, error) {
		return ipc.Response{}, adapter.NewError(adapter.FailureUnavailable)
	})
	service, err := newService(ServiceConfig{
		Path: "/tmp/admission.sock", Timeout: time.Second,
		MaxConnections: 2, MaxInFlight: 1, MaxBufferedBytes: 128,
		ReservationBytes: 128, AllowIDs: allowlist,
	}, processor, func(*net.UnixConn) bool { return true })
	if err != nil {
		t.Fatal("service fixture failed")
	}
	if admitted, class := service.reserveRequest(128); !admitted || class != "accepted" {
		t.Fatal("exact atomic reservation rejected")
	}
	if admitted, class := service.reserveRequest(1); admitted || class != "message_limit" {
		t.Fatal("one-over concurrent message accepted")
	}
	service.releaseRequest(128)
	service.mu.Lock()
	service.closed = true
	service.mu.Unlock()
	if admitted, class := service.reserveRequest(1); admitted || class != "stopping" {
		t.Fatal("stopping admission accepted")
	}
}

// TestServiceAcceptsOneIndependentPeerFrame proves one actual Unix peer is
// admitted, projected, and returned through independently encoded DXI1 frames.
func TestServiceAcceptsOneIndependentPeerFrame(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-scan service is Linux-only")
	}
	allowlist, err := adapter.NewBuildAllowlist([]string{strings.Repeat("a", ipc.BuildIDBytes)})
	if err != nil {
		t.Fatal("allowlist construction failed")
	}
	parent := testsupport.TrustedTempDirectory(t)
	path := filepath.Join(parent, "service.sock")
	if !unixSocketAvailable(path) {
		t.Skip("local sandbox forbids AF_UNIX binding")
	}
	service, err := newService(ServiceConfig{
		Path: path, Timeout: time.Second, AllowIDs: allowlist, AuthservID: "mx.example.test",
	}, processorFunc(func(_ context.Context, request adapter.LocalScanRequest) (ipc.Response, error) {
		if !bytes.Equal(request.MailFrom(), []byte("<sender@example.test>")) {
			return ipc.Response{}, adapter.NewError(adapter.FailureFidelity)
		}
		return ipc.NewResponse(
			ipc.DecisionAccept, ipc.ReasonNone, []uint16{1}, ipc.AddAuthenticationResults,
			[]byte("mx.example.test; dkim2=pass"), nil, []uint16{1}, 2,
		)
	}), func(*net.UnixConn) bool { return true })
	if err != nil {
		t.Fatal("service construction failed")
	}
	if err = service.Start(); err != nil {
		t.Fatal("service start failed")
	}
	defer func() { _ = service.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- service.Serve(ctx) }()

	request, err := ipc.NewRequest(
		[]byte(strings.Repeat("a", ipc.BuildIDBytes)), ipc.SourceLocalScanObserved, ipc.SessionSMTP,
		[]byte("192.0.2.1"), 25, []byte("helo.example.test"), []byte("esmtp"),
		[]byte("<sender@example.test>"), [][]byte{[]byte("<recipient@example.test>")},
		[][]byte{
			[]byte("Authentication-Results: mx.example.test; dkim=fail\n"),
			[]byte("Subject: independent-peer\n"),
		}, []byte("body\x00\n"),
	)
	if err != nil {
		t.Fatal("request construction failed")
	}
	frame, err := ipc.EncodeRequest(request)
	if err != nil {
		t.Fatal("request encoding failed")
	}
	connection, err := net.DialUnix(unixNetwork, nil, &net.UnixAddr{Name: path, Net: unixNetwork})
	if err != nil {
		t.Fatal("independent peer dial failed")
	}
	defer func() { _ = connection.Close() }()
	if _, err = connection.Write(frame); err != nil {
		t.Fatal("independent peer write failed")
	}
	if err = connection.CloseWrite(); err != nil {
		t.Fatal("independent peer EOF failed")
	}
	responseFrame, err := io.ReadAll(connection)
	if err != nil {
		t.Fatal("independent peer read failed")
	}
	response, err := ipc.DecodeResponse(responseFrame, []uint16{1}, 2)
	if err != nil || response.Decision() != ipc.DecisionAccept ||
		!bytes.Equal(response.AddValue(), []byte("mx.example.test; dkim2=pass")) {
		t.Fatal("service response drifted from independent peer contract")
	}
	if err = service.Close(); err != nil {
		t.Fatal("service close failed")
	}
	if err = <-serveDone; err != nil {
		t.Fatal("service loop close failed")
	}
}

// unixSocketAvailable detects environments where the test sandbox forbids AF_UNIX.
func unixSocketAvailable(path string) bool {
	listener, err := net.ListenUnix(unixNetwork, &net.UnixAddr{Name: path, Net: unixNetwork})
	if err != nil {
		return false
	}
	if closeErr := listener.Close(); closeErr != nil {
		return false
	}
	removeErr := os.Remove(path)
	return removeErr == nil || os.IsNotExist(removeErr)
}
