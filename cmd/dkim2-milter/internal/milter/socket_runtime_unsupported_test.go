//go:build !linux && !darwin

package milter

import (
	"context"
	"io"
	"testing"
	"time"
)

type unsupportedRuntimeWorker struct{}

// Serve is unreachable because unsupported platforms never bind.
func (unsupportedRuntimeWorker) Serve(context.Context, io.ReadWriter) error {
	return nil
}

// TestSocketRuntimeUnsupportedPlatformFailsClosed proves startup cannot bind.
func TestSocketRuntimeUnsupportedPlatformFailsClosed(t *testing.T) {
	t.Parallel()
	admission, err := NewAdmission(1, 1, 1)
	if err != nil {
		t.Fatalf("NewAdmission() error = %v", err)
	}
	runtime, err := NewSocketRuntime(SocketRuntimeConfig{
		Path: "/dkim2-milter.sock", Mode: 0o660,
		ConnectionDeadline: time.Second, ShutdownTimeout: time.Second,
	}, admission, func(context.Context) (ConnectionWorker, error) {
		return unsupportedRuntimeWorker{}, nil
	})
	if err != nil {
		t.Fatalf("NewSocketRuntime() error = %v", err)
	}
	if err := runtime.Start(context.Background()); err == nil {
		t.Fatal("Start() error = nil")
	}
	if runtime.Ready() {
		t.Fatal("Ready() = true")
	}
}
