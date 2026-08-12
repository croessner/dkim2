//go:build linux || darwin

// Package testsupport owns portable security-sensitive test fixtures.
package testsupport

import (
	"os"
	"path/filepath"
	"testing"
)

// TrustedTempDirectory creates an isolated portable fixture directory.
func TrustedTempDirectory(t testing.TB) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "d2m-")
	if err != nil {
		t.Fatal("create fixture root failed")
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chown(directory, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal("own fixture root failed")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal("protect fixture root failed")
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		t.Fatal("trusted fixture root failed")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		t.Fatal("trusted fixture root failed")
	}
	return resolved
}
