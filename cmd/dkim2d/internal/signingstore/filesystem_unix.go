//go:build linux || darwin

package signingstore

import (
	"errors"

	"golang.org/x/sys/unix"
)

type fileState struct {
	device              uint64
	inode               uint64
	mode                uint32
	uid                 uint32
	links               uint64
	size                int64
	mtimeSec, mtimeNsec int64
	ctimeSec, ctimeNsec int64
}

type retainedChild struct {
	fd     int
	before fileState
	data   []byte
}

// openRetainedChild reads and retains one exact generation child descriptor.
func openRetainedChild(
	rootFD int,
	name string,
	maximum int,
	expectedRoot fileState,
) (*retainedChild, error) {
	if rootFD < 0 || !validChildName(name) || maximum <= 0 {
		return nil, &Error{}
	}
	currentRoot, err := descriptorState(rootFD)
	if err != nil || currentRoot != expectedRoot ||
		!validRootState(currentRoot) || !localFilesystem(rootFD) {
		return nil, &Error{}
	}
	fd, err := unix.Openat(
		rootFD,
		name,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, &Error{}
	}
	before, err := descriptorState(fd)
	if err != nil || !validFileState(before, maximum) || !localFilesystem(fd) {
		_ = unix.Close(fd)
		return nil, &Error{}
	}
	output := make([]byte, before.size)
	offset := 0
	for offset < len(output) {
		count, readErr := unix.Read(fd, output[offset:])
		if errors.Is(readErr, unix.EINTR) {
			continue
		}
		if readErr != nil || count <= 0 || count > len(output)-offset {
			clear(output)
			_ = unix.Close(fd)
			return nil, &Error{}
		}
		offset += count
	}
	var extra [1]byte
	for {
		count, readErr := unix.Read(fd, extra[:])
		if errors.Is(readErr, unix.EINTR) {
			continue
		}
		if readErr != nil || count != 0 {
			clear(output)
			_ = unix.Close(fd)
			return nil, &Error{}
		}
		break
	}
	after, err := descriptorState(fd)
	rootAfter, rootErr := descriptorState(rootFD)
	if err != nil || rootErr != nil || after != before || rootAfter != expectedRoot {
		clear(output)
		_ = unix.Close(fd)
		return nil, &Error{}
	}
	return &retainedChild{fd: fd, before: before, data: output}, nil
}

// validateCompoundGeneration rechecks every exact descriptor after all parsing.
func validateCompoundGeneration(
	rootFD int,
	expectedRoot fileState,
	children []*retainedChild,
) error {
	rootAfter, err := descriptorState(rootFD)
	if err != nil || rootAfter != expectedRoot ||
		!validRootState(rootAfter) || !localFilesystem(rootFD) {
		return &Error{}
	}
	for _, child := range children {
		if child == nil || child.fd < 0 {
			return &Error{}
		}
		after, stateErr := descriptorState(child.fd)
		if stateErr != nil || after != child.before || !localFilesystem(child.fd) {
			return &Error{}
		}
	}
	return nil
}

// closeRetainedChild clears bytes and closes one generation descriptor.
func closeRetainedChild(child *retainedChild) error {
	if child == nil {
		return nil
	}
	clear(child.data)
	child.data = nil
	if child.fd >= 0 {
		fd := child.fd
		child.fd = -1
		if err := unix.Close(fd); err != nil {
			return &Error{}
		}
	}
	return nil
}

// descriptorState snapshots the identity and access facts required for
// replacement detection.
func descriptorState(fd int) (fileState, error) {
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil {
		return fileState{}, err
	}
	mtimeSec, mtimeNsec, ctimeSec, ctimeNsec := descriptorTimestamps(status)
	return fileState{
		device:   normalizeFileStateDevice(status.Dev),
		inode:    status.Ino,
		mode:     normalizeFileStateMode(status.Mode),
		uid:      status.Uid,
		links:    normalizeFileStateLinks(status.Nlink),
		size:     status.Size,
		mtimeSec: mtimeSec, mtimeNsec: mtimeNsec,
		ctimeSec: ctimeSec, ctimeNsec: ctimeNsec,
	}, nil
}

// normalizeFileStateDevice widens a platform-dependent device identifier.
func normalizeFileStateDevice[T ~int32 | ~uint32 | ~uint64](value T) uint64 {
	return uint64(value)
}

// normalizeFileStateMode widens platform-dependent stat mode bits.
func normalizeFileStateMode[T ~uint16 | ~uint32](value T) uint32 {
	return uint32(value)
}

// normalizeFileStateLinks widens a platform-dependent hard-link count.
func normalizeFileStateLinks[T ~uint16 | ~uint32 | ~uint64](value T) uint64 {
	return uint64(value)
}

// protectedRootState captures one stable local generation-directory state.
func protectedRootState(rootFD int) (fileState, error) {
	state, err := descriptorState(rootFD)
	if err != nil || !validRootState(state) || !localFilesystem(rootFD) {
		return fileState{}, &Error{}
	}
	return state, nil
}

// validRootState enforces an owned non-writable directory capability.
func validRootState(state fileState) bool {
	const (
		typeMask      = uint32(0170000)
		directoryType = uint32(0040000)
	)
	return state.mode&typeMask == directoryType &&
		state.uid == uint32(unix.Geteuid()) &&
		state.mode&07777 == 0500
}

// validFileState enforces exact private-file ownership and size bounds.
func validFileState(state fileState, maximum int) bool {
	const (
		typeMask    = uint32(0170000)
		regularType = uint32(0100000)
		modeMask    = uint32(07777)
	)
	mode := state.mode & modeMask
	return state.mode&typeMask == regularType &&
		state.uid == uint32(unix.Geteuid()) && state.links == 1 &&
		(mode == 0400 || mode == 0600) &&
		state.size > 0 && state.size <= int64(maximum)
}
