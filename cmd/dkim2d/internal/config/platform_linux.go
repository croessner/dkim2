//go:build linux

package config

import "golang.org/x/sys/unix"

// statDescriptor reads the portable metadata needed for descriptor identity,
// ownership, mode, size, and same-file race checks.
func statDescriptor(fd int) (descriptorMetadata, error) {
	var state unix.Stat_t
	if err := retryDescriptorOperation(func() error { return unix.Fstat(fd, &state) }); err != nil {
		return descriptorMetadata{}, err
	}
	return linuxDescriptorMetadata(state), nil
}

// statAtNoFollow classifies one descriptor-relative child without following a
// final symbolic link.
func statAtNoFollow(dirfd int, name string) (descriptorMetadata, error) {
	var state unix.Stat_t
	if err := retryDescriptorOperation(func() error {
		return unix.Fstatat(dirfd, name, &state, unix.AT_SYMLINK_NOFOLLOW)
	}); err != nil {
		return descriptorMetadata{}, err
	}
	return linuxDescriptorMetadata(state), nil
}

func linuxDescriptorMetadata(state unix.Stat_t) descriptorMetadata {
	return descriptorMetadata{
		device: state.Dev, inode: state.Ino,
		typeBits: state.Mode & unix.S_IFMT, uid: state.Uid,
		modeBits: state.Mode & 0o7777, linkCount: uint64(state.Nlink),
		size:     state.Size,
		mtimeSec: state.Mtim.Sec, mtimeNsec: state.Mtim.Nsec,
		ctimeSec: state.Ctim.Sec, ctimeNsec: state.Ctim.Nsec,
	}
}
