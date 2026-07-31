//go:build darwin

package integration

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// fixtureRootFingerprint reads one Darwin evidence-root marker fingerprint.
func fixtureRootFingerprint(t *testing.T, root string) [6]uint64 {
	t.Helper()
	var state unix.Stat_t
	if err := unix.Stat(root, &state); err != nil ||
		state.Mode&unix.S_IFMT != unix.S_IFDIR ||
		state.Mode&0o7777 != 0o700 ||
		state.Uid != uint32(os.Geteuid()) {
		t.Fatal("public readiness root inspection failed")
	}
	return [6]uint64{
		uint64(uint32(state.Dev)),
		state.Ino,
		uint64(state.Mtim.Sec),
		uint64(state.Mtim.Nsec),
		uint64(state.Ctim.Sec),
		uint64(state.Ctim.Nsec),
	}
}
