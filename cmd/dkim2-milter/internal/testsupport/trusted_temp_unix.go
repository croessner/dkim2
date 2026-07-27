//go:build linux || darwin

// Package testsupport owns portable security-sensitive test fixtures.
package testsupport

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// TrustedTempDirectory creates a fixture root beneath ancestry accepted by secure loaders.
func TrustedTempDirectory(t testing.TB) string {
	t.Helper()
	base := "."
	if runtime.GOOS == "darwin" {
		base = darwinUserTempDirectory(t)
	}
	directory, err := os.MkdirTemp(base, ".d2m-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	absolute, err := filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

// darwinUserTempDirectory discovers the per-user kernel-managed temporary root.
func darwinUserTempDirectory(t testing.TB) string {
	t.Helper()
	const foldersRoot = "/private/var/folders"
	buckets, err := os.ReadDir(foldersRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, bucket := range buckets {
		if !bucket.IsDir() {
			continue
		}
		bucketPath := filepath.Join(foldersRoot, bucket.Name())
		identities, readErr := os.ReadDir(bucketPath)
		if readErr != nil {
			continue
		}
		for _, identity := range identities {
			if !identity.IsDir() {
				continue
			}
			candidate := filepath.Join(bucketPath, identity.Name(), "T")
			var state unix.Stat_t
			if statErr := unix.Stat(candidate, &state); statErr == nil &&
				state.Uid == uint32(os.Geteuid()) &&
				uint32(state.Mode)&unix.S_IFMT == unix.S_IFDIR &&
				uint32(state.Mode)&0o7777 == 0o700 {
				return candidate
			}
		}
	}
	t.Fatal("trusted Darwin test temporary root unavailable")
	return ""
}
