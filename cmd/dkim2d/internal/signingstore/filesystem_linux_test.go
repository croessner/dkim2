//go:build linux

package signingstore

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestLocalLinuxFilesystemTypeUsesClosedAllowlist freezes both reviewed local
// types and representative ambiguous, remote, and userspace denials.
func TestLocalLinuxFilesystemTypeUsesClosedAllowlist(t *testing.T) {
	for _, filesystemType := range []int64{
		unix.EXT4_SUPER_MAGIC,
		unix.XFS_SUPER_MAGIC,
		unix.BTRFS_SUPER_MAGIC,
		unix.TMPFS_MAGIC,
	} {
		if !localLinuxFilesystemType(filesystemType) {
			t.Fatalf("reviewed filesystem type %x was rejected", filesystemType)
		}
	}
	for _, filesystemType := range []int64{
		unix.NFS_SUPER_MAGIC,
		unix.FUSE_SUPER_MAGIC,
		unix.OVERLAYFS_SUPER_MAGIC,
		0x7fff_ffff,
	} {
		if localLinuxFilesystemType(filesystemType) {
			t.Fatalf("unreviewed filesystem type %x was accepted", filesystemType)
		}
	}
}
