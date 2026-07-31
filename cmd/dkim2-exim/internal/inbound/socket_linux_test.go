//go:build linux

package inbound

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/testsupport"
	"golang.org/x/sys/unix"
)

// TestSocketRejectsUnsafeParentsAndExistingChildren proves trusted bind ancestry.
func TestSocketRejectsUnsafeParentsAndExistingChildren(t *testing.T) {
	root := testsupport.TrustedTempDirectory(t)
	unsafe := filepath.Join(root, "unsafe")
	if os.Mkdir(unsafe, 0o700) != nil || os.Chmod(unsafe, 0o777) != nil {
		t.Fatal("unsafe fixture failed")
	}
	if listener, socket, err := openSocketListener(filepath.Join(unsafe, "service.sock"), 0o600); err == nil {
		_ = listener.Close()
		_ = socket.cleanup()
		t.Fatal("unsafe final parent accepted")
	}
	target := filepath.Join(root, "target")
	if os.Mkdir(target, 0o700) != nil || os.Symlink(target, filepath.Join(root, "link")) != nil {
		t.Fatal("symlink fixture failed")
	}
	if _, _, err := openSocketListener(filepath.Join(root, "link", "service.sock"), 0o600); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
	for _, kind := range []string{"regular", "symlink", "socket"} {
		parent := filepath.Join(root, kind)
		if os.Mkdir(parent, 0o700) != nil {
			t.Fatal("child fixture parent failed")
		}
		path := filepath.Join(parent, "service.sock")
		switch kind {
		case "regular":
			if os.WriteFile(path, []byte("x"), 0o600) != nil {
				t.Fatal("regular fixture failed")
			}
		case "symlink":
			if os.Symlink("/dev/null", path) != nil {
				t.Fatal("symlink fixture failed")
			}
		case "socket":
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal("socket fixture failed")
			}
			listener.SetUnlinkOnClose(false)
			_ = listener.Close()
		}
		if _, _, err := openSocketListener(path, 0o600); err == nil {
			t.Fatal("existing child accepted")
		}
	}
}

// TestSocketExactIdentityAndCleanup proves mode, owner, link count, and unlink ownership.
func TestSocketExactIdentityAndCleanup(t *testing.T) {
	path := filepath.Join(testsupport.TrustedTempDirectory(t), "service.sock")
	listener, socket, err := openSocketListener(path, 0o600)
	if err != nil {
		t.Fatal("valid socket bind failed")
	}
	var state unix.Stat_t
	if unix.Lstat(path, &state) != nil || state.Mode&unix.S_IFMT != unix.S_IFSOCK ||
		state.Mode&0o777 != 0o600 || state.Uid != uint32(os.Geteuid()) ||
		state.Gid != uint32(os.Getegid()) || state.Nlink != 1 {
		t.Fatal("socket identity drifted")
	}
	_ = listener.Close()
	if socket.cleanup() != nil {
		t.Fatal("owned socket cleanup failed")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned socket remained")
	}
}

// TestSocketPostBindFailureRollsBack proves a fallible postcheck leaves no pathname.
func TestSocketPostBindFailureRollsBack(t *testing.T) {
	path := filepath.Join(testsupport.TrustedTempDirectory(t), "service.sock")
	if _, _, err := openSocketListenerObserved(path, 0o600, func() error {
		return errors.New("injected")
	}); err == nil {
		t.Fatal("post-bind validation failure accepted")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed bind left its socket pathname")
	}
}

// TestSocketPostBindParentPermissionMutationPreservesTheSocket proves a hostile
// parent mutation is rejected after the owned bind without unlinking blindly.
func TestSocketPostBindParentPermissionMutationPreservesTheSocket(t *testing.T) {
	parent := testsupport.TrustedTempDirectory(t)
	path := filepath.Join(parent, "service.sock")
	if _, _, err := openSocketListenerObserved(path, 0o600, func() error {
		return os.Chmod(parent, 0o755)
	}); err == nil {
		t.Fatal("post-bind parent permission mutation accepted")
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatal("hostile parent mutation removed the socket unexpectedly")
	}
}

// TestSocketReplacementIsPreserved proves cleanup never unlinks an attacker replacement.
func TestSocketReplacementIsPreserved(t *testing.T) {
	parent := testsupport.TrustedTempDirectory(t)
	path := filepath.Join(parent, "service.sock")
	listener, socket, err := openSocketListener(path, 0o600)
	if err != nil {
		t.Fatal("valid socket bind failed")
	}
	moved := filepath.Join(parent, "moved.sock")
	if os.Rename(path, moved) != nil || os.WriteFile(path, []byte("replacement"), 0o600) != nil {
		t.Fatal("replacement fixture failed")
	}
	_ = listener.Close()
	if socket.cleanup() == nil {
		t.Fatal("replacement cleanup reported success")
	}
	if data, readErr := os.ReadFile(path); readErr != nil || string(data) != "replacement" {
		t.Fatal("replacement was removed")
	}
}
