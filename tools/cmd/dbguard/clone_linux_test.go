//go:build linux

package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestReflinkUnsupportedAdmitsOnlyFilesystemCapabilityErrors keeps the copy fallback closed.
func TestReflinkUnsupportedAdmitsOnlyFilesystemCapabilityErrors(t *testing.T) {
	for _, admitted := range []error{unix.EOPNOTSUPP, unix.EXDEV} {
		if !reflinkUnsupported(admitted) {
			t.Fatalf("reflink capability error %v was not admitted", admitted)
		}
	}
	for _, rejected := range []error{nil, unix.EBADF, unix.EINVAL, unix.EPERM, unix.EIO, unix.ENOSPC} {
		if reflinkUnsupported(rejected) {
			t.Fatalf("error %v selected the copy fallback", rejected)
		}
	}
}

// TestCopyDescriptorBytesRequiresTheExactVerifiedSize rejects truncated and grown sources.
func TestCopyDescriptorBytesRequiresTheExactVerifiedSize(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "source")
	if err := os.WriteFile(sourcePath, []byte("trusted"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = source.Close()
	}()
	if _, err := source.Seek(0, io.SeekEnd); err != nil {
		t.Fatal(err)
	}
	for index, size := range []int64{int64(len("trusted")), int64(len("trusted")) - 1, int64(len("trusted")) + 1} {
		destination, err := os.Create(filepath.Join(root, "target"+string(rune('a'+index))))
		if err != nil {
			t.Fatal(err)
		}
		copyErr := copyDescriptorBytes(destination, source, size)
		if err := destination.Close(); err != nil {
			t.Fatal(err)
		}
		if exact := size == int64(len("trusted")); (copyErr == nil) != exact {
			t.Fatalf("copy of %d bytes from a 7-byte source returned %v", size, copyErr)
		}
	}
	content, err := os.ReadFile(filepath.Join(root, "targeta"))
	if err != nil || string(content) != "trusted" {
		t.Fatal("descriptor copy did not start at offset zero")
	}
}
