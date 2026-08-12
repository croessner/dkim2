//go:build linux

package signingstore

import "golang.org/x/sys/unix"

// localFilesystem accepts only the reviewed local filesystem set.
func localFilesystem(fd int) bool {
	var status unix.Statfs_t
	if unix.Fstatfs(fd, &status) != nil {
		return false
	}
	return localLinuxFilesystemType(status.Type)
}

// localLinuxFilesystemType applies the exact closed local-filesystem
// allowlist shared with protected daemon generations.
func localLinuxFilesystemType(filesystemType int64) bool {
	switch filesystemType {
	case unix.EXT4_SUPER_MAGIC,
		unix.XFS_SUPER_MAGIC,
		unix.BTRFS_SUPER_MAGIC,
		unix.TMPFS_MAGIC:
		return true
	default:
		return false
	}
}
