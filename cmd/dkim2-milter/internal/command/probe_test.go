package command

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestProbeRejectsNoncanonicalSocket proves the probe cannot select a relative endpoint.
func TestProbeRejectsNoncanonicalSocket(t *testing.T) {
	t.Parallel()
	if !errors.Is(probeSocket("milter.sock"), errCommandRuntime) {
		t.Fatal("relative probe socket did not fail closed")
	}
}

// TestProbeValidatesSocketWithoutConnecting proves health creates no Milter session.
func TestProbeValidatesSocketWithoutConnecting(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "dkim2-probe-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := filepath.Join(directory, "milter.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(socket, 0o660); err != nil {
		t.Fatal(err)
	}
	if err := probeSocket(socket); err != nil {
		t.Fatal(err)
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		t.Fatal("listener is not Unix")
	}
	if err := unixListener.SetDeadline(testImmediateDeadline()); err != nil {
		t.Fatal(err)
	}
	if connection, err := listener.Accept(); err == nil {
		_ = connection.Close()
		t.Fatal("probe opened a Milter session")
	}
}

// TestProbeRejectsRegularFile proves configuration binding cannot authorize other services.
func TestProbeRejectsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(probeSocket(path), errCommandRuntime) {
		t.Fatal("regular file was accepted")
	}
}

// testImmediateDeadline returns a stable expired deadline for nonblocking accept.
func testImmediateDeadline() time.Time {
	return time.Unix(0, 0)
}
