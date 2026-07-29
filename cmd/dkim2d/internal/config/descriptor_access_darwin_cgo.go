//go:build darwin && cgo

package config

/*
#include <errno.h>
#include <sys/acl.h>

enum {
	dkim2_descriptor_access_trivial = 0,
	dkim2_descriptor_access_unsupported = 1,
	dkim2_descriptor_access_nontrivial = 2,
	dkim2_descriptor_access_continue = 3
};

// dkim2_classify_acl_retrieval accepts only explicit ENOENT as no ACL.
static int
dkim2_classify_acl_retrieval(int is_null, int retrieval_errno)
{
	if (is_null == 0) {
		return dkim2_descriptor_access_continue;
	}
	return retrieval_errno == ENOENT
	    ? dkim2_descriptor_access_trivial
	    : dkim2_descriptor_access_nontrivial;
}

// dkim2_classify_acl_iteration centralizes bounded iteration and cleanup policy.
static int
dkim2_classify_acl_iteration(int entries, int terminal_errno, int hit_bound,
    int cleanup_result)
{
	if (cleanup_result != 0 || hit_bound != 0) {
		return dkim2_descriptor_access_nontrivial;
	}
	if (entries == 0 && terminal_errno == EINVAL) {
		return dkim2_descriptor_access_trivial;
	}
	return dkim2_descriptor_access_nontrivial;
}

// dkim2_inspect_descriptor_access validates one owned Darwin descriptor.
static int
dkim2_inspect_descriptor_access(int fd)
{
	acl_entry_t entry;
	acl_t acl;
	int cleanup_result;
	int entries;
	int entry_id = ACL_FIRST_ENTRY;
	int hit_bound = 1;
	int terminal_errno = 0;

	errno = 0;
	acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
	if (acl == NULL) {
		return dkim2_classify_acl_retrieval(1, errno);
	}

	for (entries = 0; entries < ACL_MAX_ENTRIES; entries++) {
		errno = 0;
		if (acl_get_entry(acl, entry_id, &entry) != 0) {
			terminal_errno = errno;
			hit_bound = 0;
			break;
		}
		entry_id = ACL_NEXT_ENTRY;
	}

	cleanup_result = acl_free(acl);
	return dkim2_classify_acl_iteration(entries, terminal_errno, hit_bound,
	    cleanup_result);
}
*/
import "C"

import (
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/sys/unix"
)

const (
	darwinFilesystemAPFS = 1
	darwinFilesystemHFS  = 2
)

// inspectDescriptorAccess proves that a descriptor uses an allowlisted local
// filesystem and has no Darwin extended ACL entries.
func inspectDescriptorAccess(fd int, directory bool, acceptedMode uint32) error {
	_, err := descriptorAccessFingerprint(fd, directory, acceptedMode)
	return err
}

// inspectTrustedRootAccess applies the standard Darwin root-directory policy.
func inspectTrustedRootAccess(fd int, acceptedMode uint32) error {
	return inspectDescriptorAccess(fd, true, acceptedMode)
}

// inspectTrustedAncestorAccess applies the standard Darwin directory policy.
func inspectTrustedAncestorAccess(fd int, acceptedMode uint32, _ bool) error {
	return inspectDescriptorAccess(fd, true, acceptedMode)
}

// descriptorAccessFingerprint validates and fingerprints the descriptor-native
// Darwin filesystem and extended-ACL state without reopening a pathname.
func descriptorAccessFingerprint(fd int, directory bool, acceptedMode uint32) ([32]byte, error) {
	filesystemKind, err := inspectDarwinFilesystem(fd)
	if err != nil {
		return [32]byte{}, err
	}
	switch C.dkim2_inspect_descriptor_access(C.int(fd)) {
	case C.dkim2_descriptor_access_trivial:
		switch filesystemKind {
		case darwinFilesystemAPFS, darwinFilesystemHFS:
			hash := sha256.New()
			_, _ = hash.Write([]byte("dkim2d-darwin-descriptor-access-v1\x00acl-extended-zero\x00"))
			var fixed [9]byte
			binary.LittleEndian.PutUint32(fixed[:4], uint32(filesystemKind))
			if directory {
				fixed[4] = 1
			}
			binary.LittleEndian.PutUint32(fixed[5:], acceptedMode)
			_, _ = hash.Write(fixed[:])

			var fingerprint [32]byte
			copy(fingerprint[:], hash.Sum(nil))
			return fingerprint, nil
		default:
			return [32]byte{}, newError(CodeProtectedAccess)
		}
	case C.dkim2_descriptor_access_unsupported:
		return [32]byte{}, newError(CodeProtectedUnsupported)
	default:
		return [32]byte{}, newError(CodeProtectedAccess)
	}
}

// inspectDarwinFilesystem obtains and classifies one descriptor-native filesystem name.
func inspectDarwinFilesystem(fd int) (int, error) {
	var state unix.Statfs_t
	if err := retryDescriptorOperation(func() error {
		return unix.Fstatfs(fd, &state)
	}); err != nil {
		return 0, err
	}
	name := make([]byte, 0, len(state.Fstypename))
	for _, character := range state.Fstypename {
		if character == 0 {
			break
		}
		name = append(name, character)
	}
	return classifyDarwinFilesystemName(string(name))
}

// classifyDarwinFilesystemName applies the exact APFS/HFS allowlist.
func classifyDarwinFilesystemName(name string) (int, error) {
	switch name {
	case "apfs":
		return darwinFilesystemAPFS, nil
	case "hfs":
		return darwinFilesystemHFS, nil
	default:
		return 0, newError(CodeProtectedUnsupported)
	}
}

// classifyDarwinACLIteration exercises the same C policy used after libc ACL iteration.
func classifyDarwinACLIteration(
	entries int,
	terminalErrno int,
	hitBound bool,
	cleanupResult int,
) error {
	hit := C.int(0)
	if hitBound {
		hit = 1
	}
	result := C.dkim2_classify_acl_iteration(
		C.int(entries),
		C.int(terminalErrno),
		hit,
		C.int(cleanupResult),
	)
	if result == C.dkim2_descriptor_access_trivial {
		return nil
	}
	return newError(CodeProtectedAccess)
}

// classifyDarwinACLRetrieval exercises the same C retrieval policy used in production.
func classifyDarwinACLRetrieval(isNull bool, retrievalErrno int) error {
	nullValue := C.int(0)
	if isNull {
		nullValue = 1
	}
	result := C.dkim2_classify_acl_retrieval(nullValue, C.int(retrievalErrno))
	switch result {
	case C.dkim2_descriptor_access_continue, C.dkim2_descriptor_access_trivial:
		return nil
	default:
		return newError(CodeProtectedAccess)
	}
}

// darwinACLMaxEntries returns the SDK bound used by the production C loop.
func darwinACLMaxEntries() int {
	return int(C.ACL_MAX_ENTRIES)
}
