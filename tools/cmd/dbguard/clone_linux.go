//go:build linux

package main

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// cloneFile installs the bytes of an already-open source descriptor into one
// exclusively created target. It prefers a copy-on-write reflink and, only
// when the filesystem reports that reflinks are unsupported, copies exactly
// size bytes from the same descriptor. Both paths consume the descriptor that
// was already verified, never the source path, and the caller re-hashes the
// target before use.
func cloneFile(source *os.File, target string, size int64) error {
	if source == nil || size < 0 {
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
	installErr := unix.IoctlFileClone(int(destination.Fd()), int(source.Fd()))
	if reflinkUnsupported(installErr) {
		installErr = copyDescriptorBytes(destination, source, size)
	}
	syncErr := destination.Sync()
	closeErr := destination.Close()
	if installErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(target)
		return errors.New("database_clone")
	}
	return nil
}

// reflinkUnsupported reports only the FICLONE errors that mean the filesystem
// cannot share extents between these files; every other error fails closed.
func reflinkUnsupported(err error) bool {
	return errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EXDEV)
}

// copyDescriptorBytes copies exactly size bytes from offset zero of the open
// source descriptor and rejects a source that is shorter or longer.
func copyDescriptorBytes(destination *os.File, source *os.File, size int64) error {
	copied, err := io.Copy(destination, io.NewSectionReader(source, 0, size+1))
	if err != nil || copied != size {
		return errors.New("database_clone")
	}
	return nil
}
