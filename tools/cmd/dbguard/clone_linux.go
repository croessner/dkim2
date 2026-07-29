//go:build linux

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// cloneFile creates one copy-on-write clone from an already-open source descriptor.
func cloneFile(source *os.File, target string) error {
	if source == nil {
		return errors.New("database_clone")
	}
	destination, err := os.OpenFile(
		target,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return errors.New("database_clone")
	}
	cloneErr := unix.IoctlFileClone(int(destination.Fd()), int(source.Fd()))
	syncErr := destination.Sync()
	closeErr := destination.Close()
	if cloneErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(target)
		return errors.New("database_clone")
	}
	return nil
}
