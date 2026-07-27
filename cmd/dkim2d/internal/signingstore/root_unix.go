//go:build linux || darwin

package signingstore

import "golang.org/x/sys/unix"

// duplicateRootDescriptor retains the confined generation root.
func duplicateRootDescriptor(rootFD int) (int, error) {
	duplicate, err := unix.FcntlInt(uintptr(rootFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, &Error{}
	}
	return duplicate, nil
}

// closeRootDescriptor releases one retained generation root.
func closeRootDescriptor(rootFD int) error {
	if err := unix.Close(rootFD); err != nil {
		return &Error{}
	}
	return nil
}
