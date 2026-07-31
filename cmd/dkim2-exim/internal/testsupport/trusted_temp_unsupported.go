//go:build !linux && !darwin

// Package testsupport owns portable security-sensitive test fixtures.
package testsupport

import "testing"

// TrustedTempDirectory returns a generic fixture root on fail-closed platforms.
func TrustedTempDirectory(t testing.TB) string {
	t.Helper()
	return t.TempDir()
}
