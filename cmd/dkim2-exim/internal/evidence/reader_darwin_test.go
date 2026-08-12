//go:build darwin

package evidence

import (
	"testing"

	"golang.org/x/sys/unix"
)

// testRootFingerprint reads one exact Darwin root generation for fixtures.
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
	defer func() { _ = unix.Close(directory) }()
	state, err := inspectDarwinDescriptor(
		directory,
		unix.S_IFDIR,
		0o700,
		0,
		0,
	)
	if err != nil {
		t.Fatal("readiness root fixture inspection failed")
	}
	return darwinRootFingerprint(state)
}
