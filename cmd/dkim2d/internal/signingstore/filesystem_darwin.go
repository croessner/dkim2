//go:build darwin

package signingstore

import "golang.org/x/sys/unix"

// localFilesystem accepts only a descriptor whose mount is marked local.
func localFilesystem(fd int) bool {
	var status unix.Statfs_t
	return unix.Fstatfs(fd, &status) == nil &&
		uint64(status.Flags)&uint64(unix.MNT_LOCAL) != 0
}
