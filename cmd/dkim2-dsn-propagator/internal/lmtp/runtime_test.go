//go:build linux || darwin

package lmtp

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/testsupport"
)

// testInvalidSocketPath is a placeholder path for policy-refusal fixtures.
const testInvalidSocketPath = "/tmp/x.sock"

// startRuntime binds one listener below repository-owned trusted ancestry.
func startRuntime(t *testing.T, config RuntimeConfig, handler Handler) (*Runtime, string) {
	t.Helper()
	root := testsupport.TrustedTempDirectory(t)
	config.Path = filepath.Join(root, "lmtp.sock")
	runtime, err := NewRuntime(config, handler)
	if err != nil {
		t.Fatalf("runtime construction failed")
	}
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("runtime start failed")
	}
	t.Cleanup(func() {
		stopContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = runtime.Close(stopContext)
	})
	return runtime, config.Path
}

// baseRuntimeConfig returns the bounded listener policy used by runtime tests.
func baseRuntimeConfig(maxConnections int) RuntimeConfig {
	return RuntimeConfig{
		Mode:               0o660,
		MaxConnections:     maxConnections,
		ConnectionDeadline: 5 * time.Second,
		ShutdownTimeout:    5 * time.Second,
		Limits:             Limits{MessageBytes: 65_536, GreetingName: testGreetingName},
	}
}

// TestRuntimeBindsOwnedSocketAndServes proves ownership, mode, and service.
func TestRuntimeBindsOwnedSocketAndServes(t *testing.T) {
	handler := &recordingHandler{reply: ReplyAccepted}
	runtime, path := startRuntime(t, baseRuntimeConfig(4), handler)
	if !runtime.Ready() {
		t.Fatal("runtime did not become ready")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatal("socket inode is not an owned socket")
	}
	if info.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode is %v", info.Mode().Perm())
	}
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal("dial failed")
	}
	defer func() { _ = connection.Close() }()
	reader := bufio.NewReader(connection)
	greeting, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(greeting, "220 mta.example") {
		t.Fatalf("unexpected greeting %q", greeting)
	}
	if _, err := connection.Write([]byte("QUIT\r\n")); err != nil {
		t.Fatal("write failed")
	}
	closing, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(closing, "221 ") {
		t.Fatalf("unexpected closing %q", closing)
	}
}

// TestRuntimeConnectionLimit proves a bounded concurrent connection count.
func TestRuntimeConnectionLimit(t *testing.T) {
	handler := &recordingHandler{reply: ReplyAccepted}
	_, path := startRuntime(t, baseRuntimeConfig(1), handler)
	held, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal("first dial failed")
	}
	defer func() { _ = held.Close() }()
	heldReader := bufio.NewReader(held)
	if _, err := heldReader.ReadString('\n'); err != nil {
		t.Fatal("first greeting failed")
	}
	overflow, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal("second dial failed")
	}
	defer func() { _ = overflow.Close() }()
	if err := overflow.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal("deadline failed")
	}
	buffer := make([]byte, 32)
	if count, err := overflow.Read(buffer); err == nil && count > 0 {
		t.Fatalf("connection beyond the limit was served: %q", string(buffer[:count]))
	}
}

// TestRuntimeCloseRemovesOwnedInode proves shutdown cleans exactly its socket.
func TestRuntimeCloseRemovesOwnedInode(t *testing.T) {
	handler := &recordingHandler{reply: ReplyAccepted}
	runtime, path := startRuntime(t, baseRuntimeConfig(2), handler)
	stopContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runtime.Close(stopContext); err != nil {
		t.Fatal("close failed")
	}
	if runtime.Ready() {
		t.Fatal("readiness survived shutdown")
	}
	if _, err := os.Lstat(path); err == nil {
		t.Fatal("owned socket inode survived shutdown")
	}
	if err := runtime.Close(stopContext); err != nil {
		t.Fatal("second close was not idempotent")
	}
}

// TestRuntimeConcurrentSessions proves isolated state under parallel peers.
func TestRuntimeConcurrentSessions(t *testing.T) {
	handler := &countingHandler{reply: ReplyAccepted}
	_, path := startRuntime(t, baseRuntimeConfig(8), handler)
	var group sync.WaitGroup
	for index := 0; index < 8; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			connection, err := net.Dial("unix", path)
			if err != nil {
				return
			}
			defer func() { _ = connection.Close() }()
			reader := bufio.NewReader(connection)
			_, _ = reader.ReadString('\n')
			script := "LHLO c\r\nMAIL FROM:<>\r\nRCPT TO:<a@local.example>\r\n" +
				"DATA\r\nx\r\n.\r\nQUIT\r\n"
			_, _ = connection.Write([]byte(script))
			for count := 0; count < 12; count++ {
				if _, err := reader.ReadString('\n'); err != nil {
					return
				}
			}
		}()
	}
	group.Wait()
	if handler.count() == 0 {
		t.Fatal("no concurrent delivery completed")
	}
}

// countingHandler counts deliveries without retaining any content.
type countingHandler struct {
	reply     Reply
	mu        sync.Mutex
	delivered int
}

// Handle counts one delivery and returns the configured answer.
func (h *countingHandler) Handle(context.Context, Delivery) Reply {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.delivered++
	return h.reply
}

// count returns the observed delivery count.
func (h *countingHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.delivered
}

// TestRuntimeRejectsInvalidPolicy proves the listener cannot start unbounded.
func TestRuntimeRejectsInvalidPolicy(t *testing.T) {
	handler := &recordingHandler{reply: ReplyAccepted}
	invalid := []RuntimeConfig{
		{Path: testInvalidSocketPath, Mode: 0, MaxConnections: 1, ConnectionDeadline: time.Second, ShutdownTimeout: time.Second, Limits: Limits{MessageBytes: 65_536, GreetingName: "m"}},
		{Path: "", Mode: 0o660, MaxConnections: 1, ConnectionDeadline: time.Second, ShutdownTimeout: time.Second, Limits: Limits{MessageBytes: 65_536, GreetingName: "m"}},
		{Path: testInvalidSocketPath, Mode: 0o660, MaxConnections: 0, ConnectionDeadline: time.Second, ShutdownTimeout: time.Second, Limits: Limits{MessageBytes: 65_536, GreetingName: "m"}},
		{Path: testInvalidSocketPath, Mode: 0o660, MaxConnections: 1, ConnectionDeadline: 0, ShutdownTimeout: time.Second, Limits: Limits{MessageBytes: 65_536, GreetingName: "m"}},
	}
	for _, config := range invalid {
		if _, err := NewRuntime(config, handler); !IsError(err) {
			t.Fatal("invalid listener policy accepted")
		}
	}
	if _, err := NewRuntime(baseRuntimeConfig(1), nil); !IsError(err) {
		t.Fatal("listener without handler accepted")
	}
}

// TestRuntimeRejectsPreexistingSocketPath proves the bind never adopts an inode.
func TestRuntimeRejectsPreexistingSocketPath(t *testing.T) {
	root := testsupport.TrustedTempDirectory(t)
	path := filepath.Join(root, "lmtp.sock")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal("fixture failed")
	}
	config := baseRuntimeConfig(1)
	config.Path = path
	runtime, err := NewRuntime(config, &recordingHandler{reply: ReplyAccepted})
	if err != nil {
		t.Fatal("runtime construction failed")
	}
	if err := runtime.Start(context.Background()); err == nil {
		stopContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = runtime.Close(stopContext)
		cancel()
		t.Fatal("an existing path was adopted as the listener")
	}
}
