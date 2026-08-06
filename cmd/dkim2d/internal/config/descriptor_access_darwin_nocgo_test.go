//go:build darwin && !cgo

package config

import (
	"path/filepath"
	"testing"
)

// TestDarwinNoCGOProtectedConfigurationFailsClosed proves protected reads and
// creation remain unavailable when descriptor-native ACL inspection is absent.
func TestDarwinNoCGOProtectedConfigurationFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "protected.yaml")
	if _, err := ReadProtectedDocument(path, 4096); CodeOf(err) != CodeProtectedUnsupported {
		t.Fatal("Darwin protected read without ACL inspection was accepted")
	}
	if err := CreateProtectedDocument(t.Context(), path, []byte("protected\n"), 4096); CodeOf(err) != CodeProtectedUnsupported {
		t.Fatal("Darwin protected creation without ACL inspection was accepted")
	}
}
