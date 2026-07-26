//go:build darwin

package config

import "golang.org/x/sys/unix"

// statDescriptor returns stable metadata from an already-owned descriptor.
func statDescriptor(fd int) (descriptorMetadata, error) {
	var value unix.Stat_t
	if err := retryDescriptorOperation(func() error {
		return unix.Fstat(fd, &value)
	}); err != nil {
		return descriptorMetadata{}, err
	}
	return metadataFromDarwinStat(value), nil
}

// statAtNoFollow preclassifies a direct child without following its final
// symbolic link.
func statAtNoFollow(dirfd int, name string) (descriptorMetadata, error) {
	var value unix.Stat_t
	if err := retryDescriptorOperation(func() error {
		return unix.Fstatat(dirfd, name, &value, unix.AT_SYMLINK_NOFOLLOW)
	}); err != nil {
		return descriptorMetadata{}, err
	}
	return metadataFromDarwinStat(value), nil
}

// metadataFromDarwinStat converts Darwin kernel metadata into the common
// descriptor-comparison representation.
func metadataFromDarwinStat(value unix.Stat_t) descriptorMetadata {
	return descriptorMetadata{
		device:    uint64(uint32(value.Dev)),
		inode:     value.Ino,
		typeBits:  uint32(value.Mode) & uint32(unix.S_IFMT),
		uid:       value.Uid,
		modeBits:  uint32(value.Mode) & 0o7777,
		linkCount: uint64(value.Nlink),
		size:      value.Size,
		mtimeSec:  value.Mtim.Sec,
		mtimeNsec: value.Mtim.Nsec,
		ctimeSec:  value.Ctim.Sec,
		ctimeNsec: value.Ctim.Nsec,
	}
}
