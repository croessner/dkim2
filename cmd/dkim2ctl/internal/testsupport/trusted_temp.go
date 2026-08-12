// Package testsupport owns shared test-only infrastructure.
package testsupport

import (
	"fmt"
	"os"
	"runtime"
	"testing"
)

// RunWithTrustedTemp keeps Linux test artifacts below non-shared ancestry so
// production protected-file checks remain enabled and unchanged.
func RunWithTrustedTemp(suite *testing.M) int {
	base := os.TempDir()
	if runtime.GOOS == "linux" {
		home, err := os.UserHomeDir()
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "trusted test temporary root unavailable")
			return 2
		}
		base = home
	}
	root, err := os.MkdirTemp(base, ".dkim2ctl-test-")
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "trusted test temporary root unavailable")
		return 2
	}
	defer func() { _ = os.RemoveAll(root) }()

	previous, present := os.LookupEnv("TMPDIR")
	if err := os.Setenv("TMPDIR", root); err != nil {
		return 2
	}
	defer func() {
		if present {
			_ = os.Setenv("TMPDIR", previous)
		} else {
			_ = os.Unsetenv("TMPDIR")
		}
	}()
	return suite.Run()
}
