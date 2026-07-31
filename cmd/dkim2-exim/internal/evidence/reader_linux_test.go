//go:build linux

package evidence

import (
	"testing"

	"golang.org/x/sys/unix"
)

// testRootFingerprint reads one exact Linux root generation for fixtures.
func testRootFingerprint(t *testing.T, root string) rootFingerprint {
	t.Helper()
	directory, err := unix.Open(
		root,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		t.Fatal("readiness root fixture open failed")
	}
	defer closeFD(directory)
	state, err := inspectRoot(directory)
	if err != nil {
		t.Fatal("readiness root fixture inspection failed")
	}
	return linuxRootFingerprint(state)
}
