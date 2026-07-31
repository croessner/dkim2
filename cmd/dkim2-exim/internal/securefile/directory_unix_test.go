//go:build linux || darwin

package securefile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/testsupport"
)

// TestOpenDirectoryRetainsExactProtectedGeneration proves success, drift rejection, and cleanup.
func TestOpenDirectoryRetainsExactProtectedGeneration(t *testing.T) {
	root := testsupport.TrustedTempDirectory(t)
	handle, err := OpenDirectory(root, DirectoryRules{
		EffectiveUID: uint32(os.Geteuid()), Mode: 0o700,
	})
	if err != nil {
		t.Fatal("exact protected directory was rejected")
	}
	if handle.Descriptor() < 0 || handle.Validate() != nil {
		t.Fatal("retained directory was not valid")
	}
	for _, value := range []any{*handle, handle} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if rendered := fmt.Sprintf(format, value); !strings.Contains(rendered, "redacted") {
				t.Fatal("directory handle formatting escaped")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("directory handle JSON serialization succeeded")
		}
	}
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal("directory mode mutation failed")
	}
	if handle.Validate() == nil {
		t.Fatal("retained directory mode drift was accepted")
	}
	if err := handle.Close(); err != nil {
		t.Fatal("directory close failed")
	}
	if err := handle.Close(); err != nil {
		t.Fatal("directory close was not idempotent")
	}
}

// TestOpenDirectoryRejectsUnsafeAndSymlinkParents proves path and exact-parent policy.
func TestOpenDirectoryRejectsUnsafeAndSymlinkParents(t *testing.T) {
	root := testsupport.TrustedTempDirectory(t)
	unsafe := filepath.Join(root, "unsafe")
	if err := os.Mkdir(unsafe, 0o750); err != nil {
		t.Fatal("unsafe directory setup failed")
	}
	if handle, err := OpenDirectory(unsafe, DirectoryRules{
		EffectiveUID: uint32(os.Geteuid()), Mode: 0o700,
	}); err == nil {
		_ = handle.Close()
		t.Fatal("unsafe final mode was accepted")
	}
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "link")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal("target setup failed")
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal("symlink setup failed")
	}
	if handle, err := OpenDirectory(link, DirectoryRules{
		EffectiveUID: uint32(os.Geteuid()), Mode: 0o700,
	}); err == nil {
		_ = handle.Close()
		t.Fatal("symlink final directory was accepted")
	}
	if handle, err := OpenDirectory("/", DirectoryRules{
		EffectiveUID: uint32(os.Geteuid()), Mode: 0o700,
	}); err == nil {
		_ = handle.Close()
		t.Fatal("root-direct protected directory was accepted")
	}
}
