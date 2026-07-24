//go:build linux || darwin

package flatfile

import (
	"errors"

	"golang.org/x/sys/unix"
)

// unixFilesystem implements confined descriptor operations on Linux and macOS.
type unixFilesystem struct{}

// newFilesystemOps returns the supported production descriptor implementation.
func newFilesystemOps() (filesystemOps, error) { return unixFilesystem{}, nil }

// duplicateRoot atomically duplicates a borrowed descriptor with close-on-exec.
func (unixFilesystem) duplicateRoot(rootFD int) (int, operationFailure) {
	descriptor, err := unix.FcntlInt(uintptr(rootFD), unix.F_DUPFD_CLOEXEC, 0)
	switch {
	case err == nil:
		return descriptor, operationSucceeded
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.ENOSYS), errors.Is(err, unix.ENOTSUP):
		return -1, operationUnsupported
	default:
		return -1, operationFailed
	}
}

// metadata reads confinement facts from one already-open descriptor.
func (unixFilesystem) metadata(descriptor int) (fileMetadata, operationFailure) {
	var status unix.Stat_t
	if err := unix.Fstat(descriptor, &status); err != nil {
		return fileMetadata{}, operationFailed
	}
	return fileMetadata{
		mode: uint32(status.Mode), uid: status.Uid, links: uint64(status.Nlink),
	}, operationSucceeded
}

// openFile opens one exact child component with all confinement flags atomically.
func (unixFilesystem) openFile(rootFD int, filename string) (int, operationFailure) {
	descriptor, err := unix.Openat(
		rootFD,
		filename,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		0,
	)
	switch {
	case err == nil:
		return descriptor, operationSucceeded
	case errors.Is(err, unix.ENOENT):
		return -1, operationNotFound
	default:
		return -1, operationFailed
	}
}

// read consumes bytes from the same validated file descriptor.
func (unixFilesystem) read(descriptor int, output []byte) (int, operationFailure) {
	count, err := unix.Read(descriptor, output)
	if err != nil {
		return count, operationFailed
	}
	return count, operationSucceeded
}

// close releases one descriptor exactly once without retrying EINTR.
func (unixFilesystem) close(descriptor int) operationFailure {
	if err := unix.Close(descriptor); err != nil {
		return operationFailed
	}
	return operationSucceeded
}

// effectiveUID returns the exact owner expected for confined descriptors.
func (unixFilesystem) effectiveUID() uint32 { return uint32(unix.Geteuid()) }
