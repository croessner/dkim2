//go:build linux || darwin

package daemon

import "golang.org/x/sys/unix"

// mkfifoCapabilityFixture creates one special-file negative fixture.
func mkfifoCapabilityFixture(path string, mode uint32) error {
	return unix.Mkfifo(path, mode)
}
