//go:build linux

package testclient

import "golang.org/x/sys/unix"

const maximumCapabilityXattrBytes = 65_536

// inspectCapabilityAccess accepts only allowlisted local filesystems without xattrs.
func inspectCapabilityAccess(descriptor int) error {
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(descriptor, &filesystem); err != nil {
		return NewExitError(ExitCapability)
	}
	switch int64(filesystem.Type) {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC:
	default:
		return NewExitError(ExitCapability)
	}
	size, err := unix.Flistxattr(descriptor, nil)
	if err != nil || size < 0 || size > maximumCapabilityXattrBytes {
		return NewExitError(ExitCapability)
	}
	if size != 0 {
		return NewExitError(ExitCapability)
	}
	return nil
}
