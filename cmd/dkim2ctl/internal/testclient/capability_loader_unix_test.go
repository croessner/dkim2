//go:build linux || darwin

package testclient

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestLoadCapabilityRejectsFIFOWithoutBlocking freezes nonblocking
// preclassification for attacker-controlled special files.
func TestLoadCapabilityRejectsFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "capability-fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal("create FIFO fixture")
	}
	if _, err := LoadCapability(path); ExitClassOf(err) != ExitCapability {
		t.Fatal("FIFO capability did not fail closed")
	}
}

// TestLoadCapabilityRejectsSpecialPermissionBits freezes exact 0400/0600
// descriptor mode validation.
func TestLoadCapabilityRejectsSpecialPermissionBits(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "capability-special-mode")
	if err := os.WriteFile(path, make([]byte, 32), 0o600); err != nil {
		t.Fatal("write capability fixture")
	}
	if err := os.Chmod(path, 0o4600); err != nil {
		t.Fatal("set special permission bit")
	}
	if _, err := LoadCapability(path); ExitClassOf(err) != ExitCapability {
		t.Fatal("special permission bit was ignored")
	}
}
