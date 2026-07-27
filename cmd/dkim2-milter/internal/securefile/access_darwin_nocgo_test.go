//go:build darwin && !cgo

package securefile

import "testing"

// TestDarwinNoCGOProtectedLoadingFailsClosed proves ACL ambiguity is never bypassed.
func TestDarwinNoCGOProtectedLoadingFailsClosed(t *testing.T) {
	if _, err := descriptorAccessFingerprint(-1, true, 0); err == nil {
		t.Fatal("Darwin protected loading without ACL inspection was accepted")
	}
}
