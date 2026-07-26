//go:build darwin && cgo

package testclient

/*
#include <errno.h>
#include <sys/acl.h>

static int
dkim2ctl_descriptor_has_trivial_acl(int fd)
{
	acl_entry_t entry;
	acl_t acl;
	int cleanup;

	errno = 0;
	acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
	if (acl == NULL) {
		return errno == ENOENT;
	}
	errno = 0;
	int result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
	int terminal = errno;
	cleanup = acl_free(acl);
	return result != 0 && terminal == EINVAL && cleanup == 0;
}
*/
import "C"

import "golang.org/x/sys/unix"

// inspectCapabilityAccess accepts only local APFS/HFS descriptors without extended ACLs.
func inspectCapabilityAccess(descriptor int) error {
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(descriptor, &filesystem); err != nil {
		return NewExitError(ExitCapability)
	}
	name := make([]byte, 0, len(filesystem.Fstypename))
	for _, current := range filesystem.Fstypename {
		if current == 0 {
			break
		}
		name = append(name, current)
	}
	if string(name) != "apfs" && string(name) != "hfs" {
		return NewExitError(ExitCapability)
	}
	if C.dkim2ctl_descriptor_has_trivial_acl(C.int(descriptor)) == 0 {
		return NewExitError(ExitCapability)
	}
	return nil
}
