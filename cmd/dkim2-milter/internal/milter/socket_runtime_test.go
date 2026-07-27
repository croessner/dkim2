//go:build linux || darwin

package milter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/testsupport"
)

type runtimeWorker struct {
	serve func(context.Context, io.ReadWriter) error
}

// Serve delegates a connection to the test-owned behavior.
func (w runtimeWorker) Serve(ctx context.Context, stream io.ReadWriter) error {
	return w.serve(ctx, stream)
}

// TestSocketRuntimeServesOnlyAfterReadiness proves the public listener is live at readiness.
func TestSocketRuntimeServesOnlyAfterReadiness(t *testing.T) {
	socket := filepath.Join(newSocketTestDir(t), "milter.sock")
	admission, err := NewAdmission(1, 1, testAdmissionBytes)
	if err != nil {
		t.Fatalf("NewAdmission() error = %v", err)
	}
	handled := make(chan struct{})
	runtime, err := NewSocketRuntime(SocketRuntimeConfig{
		Path: socket, Mode: 0o660, ConnectionDeadline: time.Second, ShutdownTimeout: time.Second,
	}, admission, func(context.Context) (ConnectionWorker, error) {
		return runtimeWorker{serve: func(_ context.Context, stream io.ReadWriter) error {
			buffer := make([]byte, 1)
			if _, readErr := io.ReadFull(stream, buffer); readErr != nil {
				return readErr
			}
			if _, writeErr := stream.Write(buffer); writeErr != nil {
				return writeErr
			}
			close(handled)
			return nil
		}}, nil
	})
	if err != nil {
		t.Fatalf("NewSocketRuntime() error = %v", err)
	}
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if !runtime.Ready() {
		t.Fatal("Ready() = false after Start()")
	}
	connection, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		t.Fatalf("DialTimeout() error = %v", err)
	}
	if _, err := connection.Write([]byte{'x'}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	response := make([]byte, 1)
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	_ = connection.Close()
	select {
	case <-handled:
	case <-time.After(time.Second):
		t.Fatal("connection was not handled")
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if runtime.Ready() {
		t.Fatal("Ready() = true after Close()")
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remains after owned cleanup: %v", err)
	}
}

// TestSocketRuntimePlatformPrimitives proves the descriptor-relative bind checks.
func TestSocketRuntimePlatformPrimitives(t *testing.T) {
	path := filepath.Join(newSocketTestDir(t), "milter.sock")
	parent, name, err := openSocketParent(path)
	if err != nil {
		t.Fatalf("openSocketParent() error = %v", err)
	}
	defer func() { _ = unix.Close(parent) }()
	listener, err := bindSocketWithRestrictiveUmask(path, 0o660)
	if err != nil {
		t.Fatalf("bindSocketWithRestrictiveUmask() error = %v", err)
	}
	listener.SetUnlinkOnClose(false)
	defer func() {
		_ = listener.Close()
		_ = os.Remove(path)
	}()
	bound, err := statSocketChild(parent, name)
	if err != nil {
		t.Fatalf("statSocketChild() error = %v", err)
	}
	if !validBoundSocketState(bound, 0o660) {
		t.Fatalf("bound socket state = %#v", bound)
	}
}

// TestSocketRuntimeRejectsUnsafeTargets exercises fail-closed path validation.
func TestSocketRuntimeRejectsUnsafeTargets(t *testing.T) {
	tests := map[string]func(*testing.T) string{
		"relative": func(t *testing.T) string {
			t.Helper()
			return "milter.sock"
		},
		"unsafe_parent": func(t *testing.T) string {
			t.Helper()
			parent := newSocketTestDir(t)
			if err := os.Chmod(parent, 0o777); err != nil {
				t.Fatalf("Chmod() error = %v", err)
			}
			return filepath.Join(parent, "milter.sock")
		},
		"symlink_parent": func(t *testing.T) string {
			t.Helper()
			root := newSocketTestDir(t)
			parent := filepath.Join(root, "real")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatalf("Mkdir() error = %v", err)
			}
			link := filepath.Join(root, "link")
			if err := os.Symlink(parent, link); err != nil {
				t.Fatalf("Symlink() error = %v", err)
			}
			return filepath.Join(link, "milter.sock")
		},
		"symlink_target": func(t *testing.T) string {
			t.Helper()
			parent := newSocketTestDir(t)
			path := filepath.Join(parent, "milter.sock")
			if err := os.Symlink("missing", path); err != nil {
				t.Fatalf("Symlink() error = %v", err)
			}
			return path
		},
		"regular_target": func(t *testing.T) string {
			t.Helper()
			path := filepath.Join(newSocketTestDir(t), "milter.sock")
			if err := os.WriteFile(path, []byte("marker"), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			return path
		},
		"socket_target": func(t *testing.T) string {
			t.Helper()
			path := filepath.Join(newSocketTestDir(t), "milter.sock")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatalf("Listen() error = %v", err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			return path
		},
	}
	for name, fixture := range tests {
		t.Run(name, func(t *testing.T) {
			path := fixture(t)
			admission, err := NewAdmission(2, 2, testAdmissionBytes)
			if err != nil {
				t.Fatalf("NewAdmission() error = %v", err)
			}
			runtime, constructErr := NewSocketRuntime(SocketRuntimeConfig{
				Path: path, Mode: 0o660, ConnectionDeadline: time.Second, ShutdownTimeout: time.Second,
			}, admission, func(context.Context) (ConnectionWorker, error) {
				return runtimeWorker{
					serve: func(context.Context, io.ReadWriter) error { return nil },
				}, nil
			})
			if constructErr != nil {
				return
			}
			if err := runtime.Start(context.Background()); err == nil {
				t.Fatal("Start() error = nil")
			}
			if runtime.Ready() {
				t.Fatal("Ready() = true after rejected startup")
			}
		})
	}
}

// TestSocketRuntimeVerifiesModeAndPreservesReplacement proves inode-bound cleanup.
func TestSocketRuntimeVerifiesModeAndPreservesReplacement(t *testing.T) {
	path := filepath.Join(newSocketTestDir(t), "milter.sock")
	runtime := newTestSocketRuntime(t, path, runtimeWorker{
		serve: func(context.Context, io.ReadWriter) error { return nil },
	}, time.Second, time.Second)
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	state, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}
	if state.Mode()&os.ModeSocket == 0 || state.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %v", state.Mode())
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	replacement, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("replacement Listen() error = %v", err)
	}
	defer func() { _ = replacement.Close() }()
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	replacementState, err := os.Lstat(path)
	if err != nil || replacementState.Mode()&os.ModeSocket == 0 {
		t.Fatalf("replacement removed or changed: state=%v err=%v", replacementState, err)
	}
}

// TestSocketRuntimeCleansOwnedInodeAfterModeChange proves identity is not mode text.
func TestSocketRuntimeCleansOwnedInodeAfterModeChange(t *testing.T) {
	path := filepath.Join(newSocketTestDir(t), "milter.sock")
	runtime := newTestSocketRuntime(t, path, runtimeWorker{
		serve: func(context.Context, io.ReadWriter) error { return nil },
	}, time.Second, time.Second)
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned socket remains after mode change: %v", err)
	}
}

// TestSocketRuntimeNormalizesUnexpectedInheritedGroup proves exact process ownership.
func TestSocketRuntimeNormalizesUnexpectedInheritedGroup(t *testing.T) {
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatalf("Getgroups() error = %v", err)
	}
	alternate := -1
	for _, group := range groups {
		if group != os.Getegid() {
			alternate = group
			break
		}
	}
	if alternate < 0 {
		t.Skip("no alternate supplementary group is available")
	}
	parent := newSocketTestDir(t)
	if err := os.Chown(parent, -1, alternate); err != nil {
		t.Skipf("cannot select supplementary test group: %v", err)
	}
	if err := os.Chmod(parent, os.ModeSetgid|0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	path := filepath.Join(parent, "milter.sock")
	runtime := newTestSocketRuntime(t, path, runtimeWorker{
		serve: func(context.Context, io.ReadWriter) error { return nil },
	}, time.Second, time.Second)
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("Start() rejected normalizable inherited GID: %v", err)
	}
	parentDescriptor, name, err := openSocketParent(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(parentDescriptor) }()
	state, err := statSocketChild(parentDescriptor, name)
	if err != nil || state.gid != uint32(os.Getegid()) {
		t.Fatal("bound socket did not normalize to the effective group")
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestSocketRuntimeAdmitsBeforeWorkerLaunch proves overload does not spawn work.
func TestSocketRuntimeAdmitsBeforeWorkerLaunch(t *testing.T) {
	path := filepath.Join(newSocketTestDir(t), "milter.sock")
	admission, err := NewAdmission(1, 1, testAdmissionBytes)
	if err != nil {
		t.Fatalf("NewAdmission() error = %v", err)
	}
	block := make(chan struct{})
	var launches atomic.Int32
	runtime, err := NewSocketRuntime(SocketRuntimeConfig{
		Path: path, Mode: 0o660, ConnectionDeadline: time.Second, ShutdownTimeout: time.Second,
	}, admission, func(context.Context) (ConnectionWorker, error) {
		launches.Add(1)
		return runtimeWorker{serve: func(context.Context, io.ReadWriter) error {
			<-block
			return nil
		}}, nil
	})
	if err != nil {
		t.Fatalf("NewSocketRuntime() error = %v", err)
	}
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	first, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("first Dial() error = %v", err)
	}
	defer func() { _ = first.Close() }()
	deadline := time.Now().Add(time.Second)
	for launches.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	second, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("second Dial() error = %v", err)
	}
	_ = second.Close()
	time.Sleep(20 * time.Millisecond)
	if got := launches.Load(); got != 1 {
		t.Fatalf("worker launches = %d, want 1", got)
	}
	close(block)
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

// TestSocketRuntimeDeadlineAndShutdownJoin proves deadlines and bounded cancellation.
func TestSocketRuntimeDeadlineAndShutdownJoin(t *testing.T) {
	path := filepath.Join(newSocketTestDir(t), "milter.sock")
	var joined atomic.Bool
	entered := make(chan struct{})
	var once sync.Once
	runtime := newTestSocketRuntime(t, path, runtimeWorker{
		serve: func(_ context.Context, stream io.ReadWriter) error {
			once.Do(func() { close(entered) })
			buffer := make([]byte, 1)
			_, err := stream.Read(buffer)
			joined.Store(true)
			return err
		},
	}, 30*time.Millisecond, 30*time.Millisecond)
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = connection.Close() }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	deadline := time.Now().Add(time.Second)
	for !joined.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !joined.Load() {
		t.Fatal("connection deadline did not release worker")
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

// TestSocketRuntimeDeadlineIsIdleNotLifetime proves active operations refresh it.
func TestSocketRuntimeDeadlineIsIdleNotLifetime(t *testing.T) {
	path := filepath.Join(newSocketTestDir(t), "milter.sock")
	handled := make(chan error, 1)
	runtime := newTestSocketRuntime(t, path, runtimeWorker{
		serve: func(_ context.Context, stream io.ReadWriter) error {
			buffer := make([]byte, 1)
			if _, err := io.ReadFull(stream, buffer); err != nil {
				handled <- err
				return err
			}
			time.Sleep(50 * time.Millisecond)
			_, err := io.ReadFull(stream, buffer)
			handled <- err
			return err
		},
	}, 30*time.Millisecond, time.Second)
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = connection.Close() }()
	if _, err := connection.Write([]byte{'a'}); err != nil {
		t.Fatalf("first Write() error = %v", err)
	}
	time.Sleep(55 * time.Millisecond)
	if _, err := connection.Write([]byte{'b'}); err != nil {
		t.Fatalf("second Write() error = %v", err)
	}
	select {
	case err := <-handled:
		if err != nil {
			t.Fatalf("worker error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not finish")
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

// TestSocketRuntimeCancelsAndJoinsAtShutdownBudget proves stragglers cannot outlive Close.
func TestSocketRuntimeCancelsAndJoinsAtShutdownBudget(t *testing.T) {
	path := filepath.Join(newSocketTestDir(t), "milter.sock")
	entered := make(chan struct{})
	joined := make(chan struct{})
	runtime := newTestSocketRuntime(t, path, runtimeWorker{
		serve: func(ctx context.Context, _ io.ReadWriter) error {
			close(entered)
			<-ctx.Done()
			close(joined)
			return ctx.Err()
		},
	}, time.Second, 30*time.Millisecond)
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = connection.Close() }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	started := time.Now()
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if time.Since(started) < 20*time.Millisecond {
		t.Fatal("Close() canceled before its graceful shutdown budget")
	}
	select {
	case <-joined:
	default:
		t.Fatal("Close() returned before worker join")
	}
}

// TestSocketRuntimeBoundsNonCooperativeWorkerShutdown proves the stop budget is final.
func TestSocketRuntimeBoundsNonCooperativeWorkerShutdown(t *testing.T) {
	path := filepath.Join(newSocketTestDir(t), "milter.sock")
	entered := make(chan struct{})
	release := make(chan struct{})
	joined := make(chan struct{})
	runtime := newTestSocketRuntime(t, path, runtimeWorker{
		serve: func(context.Context, io.ReadWriter) error {
			close(entered)
			<-release
			close(joined)
			return nil
		},
	}, time.Second, 40*time.Millisecond)
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = connection.Close() }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	started := time.Now()
	var adapterError *Error
	if err := runtime.Close(context.Background()); !errors.As(err, &adapterError) ||
		adapterError.Class != FailureInternal {
		t.Fatalf("Close() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("Close() elapsed = %v", elapsed)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remains after bounded shutdown: %v", err)
	}
	close(release)
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("released worker did not finish")
	}
}

// TestSocketRuntimeContainsFactoryPanic proves failed construction releases admission.
func TestSocketRuntimeContainsFactoryPanic(t *testing.T) {
	path := filepath.Join(newSocketTestDir(t), "milter.sock")
	var calls atomic.Int32
	admission, err := NewAdmission(1, 1, testAdmissionBytes)
	if err != nil {
		t.Fatalf("NewAdmission() error = %v", err)
	}
	runtime, err := NewSocketRuntime(SocketRuntimeConfig{
		Path: path, Mode: 0o660, ConnectionDeadline: time.Second, ShutdownTimeout: time.Second,
	}, admission, func(context.Context) (ConnectionWorker, error) {
		if calls.Add(1) == 1 {
			panic("test panic")
		}
		return runtimeWorker{serve: func(context.Context, io.ReadWriter) error { return nil }}, nil
	})
	if err != nil {
		t.Fatalf("NewSocketRuntime() error = %v", err)
	}
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	for index := range 2 {
		connection, dialErr := net.Dial("unix", path)
		if dialErr != nil {
			t.Fatalf("Dial() error = %v", dialErr)
		}
		_ = connection.Close()
		deadline := time.Now().Add(time.Second)
		for calls.Load() < int32(index+1) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("factory calls = %d, want 2", calls.Load())
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

// TestSocketRuntimeCannotStartAfterClose proves lifecycle state cannot reopen.
func TestSocketRuntimeCannotStartAfterClose(t *testing.T) {
	path := filepath.Join(newSocketTestDir(t), "milter.sock")
	runtime := newTestSocketRuntime(t, path, runtimeWorker{
		serve: func(context.Context, io.ReadWriter) error { return nil },
	}, time.Second, time.Second)
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := runtime.Start(context.Background()); err == nil {
		t.Fatal("Start() error = nil after Close()")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("closed runtime created target: %v", err)
	}
}

// TestSocketRuntimeUnexpectedAcceptFailureUsesUnifiedShutdown proves dead loops clean up.
func TestSocketRuntimeUnexpectedAcceptFailureUsesUnifiedShutdown(t *testing.T) {
	path := filepath.Join(newSocketTestDir(t), "milter.sock")
	admission, err := NewAdmission(1, 1, testAdmissionBytes)
	if err != nil {
		t.Fatalf("NewAdmission() error = %v", err)
	}
	runtime, err := NewSocketRuntime(SocketRuntimeConfig{
		Path: path, Mode: 0o660, ConnectionDeadline: time.Second, ShutdownTimeout: time.Second,
	}, admission, func(context.Context) (ConnectionWorker, error) {
		return runtimeWorker{serve: func(context.Context, io.ReadWriter) error { return nil }}, nil
	})
	if err != nil {
		t.Fatalf("NewSocketRuntime() error = %v", err)
	}
	unexpected := make(chan struct{}, 1)
	if err := runtime.SetUnexpectedExitCallback(func() {
		unexpected <- struct{}{}
	}); err != nil {
		t.Fatalf("SetUnexpectedExitCallback() error = %v", err)
	}
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := runtime.privateState().listener.Close(); err != nil {
		t.Fatalf("listener Close() error = %v", err)
	}
	select {
	case <-runtime.privateState().closeDone:
	case <-time.After(time.Second):
		t.Fatal("unexpected accept failure did not finish shutdown")
	}
	select {
	case <-unexpected:
	default:
		t.Fatal("unexpected accept failure did not withdraw external readiness")
	}
	if runtime.Ready() {
		t.Fatal("Ready() = true after accept-loop failure")
	}
	if _, admitted := admission.AdmitConnection(); admitted {
		t.Fatal("admission remained open after accept-loop failure")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remains after accept-loop failure: %v", err)
	}
}

// TestSocketRuntimeUnexpectedExitCallbackIsSingleAssignment proves owner isolation.
func TestSocketRuntimeUnexpectedExitCallbackIsSingleAssignment(t *testing.T) {
	path := filepath.Join(newSocketTestDir(t), "milter.sock")
	runtime := newTestSocketRuntime(t, path, runtimeWorker{
		serve: func(context.Context, io.ReadWriter) error { return nil },
	}, time.Second, time.Second)
	if err := runtime.SetUnexpectedExitCallback(nil); err == nil {
		t.Fatal("nil unexpected-exit callback was accepted")
	}
	if err := runtime.SetUnexpectedExitCallback(func() {}); err != nil {
		t.Fatalf("SetUnexpectedExitCallback() error = %v", err)
	}
	if err := runtime.SetUnexpectedExitCallback(func() {}); err == nil {
		t.Fatal("unexpected-exit callback replacement was accepted")
	}
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := runtime.SetUnexpectedExitCallback(func() {}); err == nil {
		t.Fatal("unexpected-exit callback mutation after Start was accepted")
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

// TestSocketRuntimeCancelsFactoryDuringShutdown proves construction is budget-bound.
func TestSocketRuntimeCancelsFactoryDuringShutdown(t *testing.T) {
	path := filepath.Join(newSocketTestDir(t), "milter.sock")
	entered := make(chan struct{})
	exited := make(chan struct{})
	runtimeAdmission, err := NewAdmission(1, 1, testAdmissionBytes)
	if err != nil {
		t.Fatalf("NewAdmission() error = %v", err)
	}
	runtime, err := NewSocketRuntime(SocketRuntimeConfig{
		Path: path, Mode: 0o660, ConnectionDeadline: time.Second, ShutdownTimeout: time.Second,
	}, runtimeAdmission, func(ctx context.Context) (ConnectionWorker, error) {
		close(entered)
		<-ctx.Done()
		close(exited)
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatalf("NewSocketRuntime() error = %v", err)
	}
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = connection.Close() }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("factory did not start")
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-exited:
	default:
		t.Fatal("Close() returned before factory cancellation")
	}
}

// TestSocketRuntimeNeverRepublishesReadinessDuringClose exercises the startup race.
func TestSocketRuntimeNeverRepublishesReadinessDuringClose(t *testing.T) {
	parent := newSocketTestDir(t)
	for iteration := range 16 {
		path := filepath.Join(parent, "milter-"+string(rune('a'+iteration))+".sock")
		runtime := newTestSocketRuntime(t, path, runtimeWorker{
			serve: func(context.Context, io.ReadWriter) error { return nil },
		}, time.Second, time.Second)
		startDone := make(chan error, 1)
		go func() { startDone <- runtime.Start(context.Background()) }()
		deadline := time.Now().Add(time.Second)
		for {
			state := runtime.privateState()
			state.mu.Lock()
			started := state.started
			state.mu.Unlock()
			if started || time.Now().After(deadline) {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if err := runtime.Close(context.Background()); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		<-startDone
		if runtime.Ready() {
			t.Fatalf("Ready() = true after close in iteration %d", iteration)
		}
	}
}

// TestSocketRuntimeIsStructurallyOpaque freezes every formatting and serialization path.
func TestSocketRuntimeIsStructurallyOpaque(t *testing.T) {
	const marker = "private-socket-runtime-marker"
	admission, err := NewAdmission(1, 1, testAdmissionBytes)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewSocketRuntime(
		SocketRuntimeConfig{
			Path: "/tmp/" + marker + ".sock", Mode: 0o660,
			ConnectionDeadline: time.Second, ShutdownTimeout: time.Second,
		},
		admission,
		func(context.Context) (ConnectionWorker, error) {
			return runtimeWorker{serve: func(context.Context, io.ReadWriter) error {
				return nil
			}}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	subjects := []any{
		runtime,
		*runtime,
		any(runtime),
		runtime.state,
		*runtime.state,
		runtime.state.guard,
		*runtime.state.guard,
		struct{ Value any }{Value: runtime},
		struct{ Value SocketRuntime }{Value: *runtime},
	}
	for _, subject := range subjects {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if output := fmt.Sprintf(format, subject); strings.Contains(output, marker) {
				t.Fatalf("socket runtime format %q exposed its path", format)
			}
		}
		if output, marshalErr := json.Marshal(subject); marshalErr == nil ||
			strings.Contains(string(output), marker) {
			t.Fatal("socket runtime JSON serialization did not fail closed")
		}
		marshaler, ok := subject.(interface{ MarshalText() ([]byte, error) })
		if !ok {
			continue
		}
		if output, marshalErr := marshaler.MarshalText(); marshalErr == nil ||
			strings.Contains(string(output), marker) {
			t.Fatal("socket runtime text serialization did not fail closed")
		}
	}
}

// newTestSocketRuntime constructs a runtime with one test worker.
func newTestSocketRuntime(
	t *testing.T,
	path string,
	worker ConnectionWorker,
	connectionDeadline time.Duration,
	shutdownTimeout time.Duration,
) *SocketRuntime {
	t.Helper()
	admission, err := NewAdmission(2, 2, testAdmissionBytes)
	if err != nil {
		t.Fatalf("NewAdmission() error = %v", err)
	}
	runtime, err := NewSocketRuntime(SocketRuntimeConfig{
		Path: path, Mode: 0o660, ConnectionDeadline: connectionDeadline, ShutdownTimeout: shutdownTimeout,
	}, admission, func(context.Context) (ConnectionWorker, error) { return worker, nil })
	if err != nil {
		t.Fatalf("NewSocketRuntime() error = %v", err)
	}
	return runtime
}

// newSocketTestDir creates a short private parent suitable for Unix path limits.
func newSocketTestDir(t *testing.T) string {
	t.Helper()
	return testsupport.TrustedTempDirectory(t)
}
