//go:build darwin && cgo

package securefile

/*
#include <errno.h>
#include <sys/acl.h>

enum {
	dkim2_securefile_trivial = 0,
	dkim2_securefile_nontrivial = 1,
	dkim2_securefile_continue = 2
};

static int
dkim2_securefile_classify_retrieval(int is_null, int retrieval_errno)
{
	if (is_null == 0) {
		return dkim2_securefile_continue;
	}
	return retrieval_errno == ENOENT
	    ? dkim2_securefile_trivial
	    : dkim2_securefile_nontrivial;
}

static int
dkim2_securefile_classify_iteration(int entries, int terminal_errno,
    int hit_bound, int cleanup_result)
{
	if (cleanup_result != 0 || hit_bound != 0) {
		return dkim2_securefile_nontrivial;
	}
	if (entries == 0 && terminal_errno == EINVAL) {
		return dkim2_securefile_trivial;
	}
	return dkim2_securefile_nontrivial;
}

static int
dkim2_securefile_inspect_acl(int fd)
{
	acl_entry_t entry;
	acl_t acl;
	int entries;
	int entry_id = ACL_FIRST_ENTRY;
	int hit_bound = 1;
	int terminal_errno = 0;

	errno = 0;
	acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
	if (acl == NULL) {
		return dkim2_securefile_classify_retrieval(1, errno);
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
	return dkim2_securefile_classify_iteration(
	    entries, terminal_errno, hit_bound, acl_free(acl));
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

// descriptorAccessFingerprint validates and fingerprints Darwin filesystem and ACL state.
func descriptorAccessFingerprint(fd int, directory bool, acceptedMode uint32) ([32]byte, error) {
	filesystemKind, err := inspectDarwinFilesystem(fd)
	if err != nil {
		return [32]byte{}, err
	}
	if err := inspectDarwinACL(fd); err != nil {
		return [32]byte{}, err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("dkim2-milter-securefile-darwin-access-v1\x00"))
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
}

// rootDescriptorAccessFingerprint applies the standard Darwin root policy.
func rootDescriptorAccessFingerprint(fd int, acceptedMode uint32) ([32]byte, error) {
	return descriptorAccessFingerprint(fd, true, acceptedMode)
}

// ancestryDescriptorAccessFingerprint applies the standard Darwin directory policy.
func ancestryDescriptorAccessFingerprint(fd int, acceptedMode uint32) ([32]byte, error) {
	return descriptorAccessFingerprint(fd, true, acceptedMode)
}

// inspectDarwinACL rejects every extended entry and every ambiguous libc result.
func inspectDarwinACL(fd int) error {
	if C.dkim2_securefile_inspect_acl(C.int(fd)) != C.dkim2_securefile_trivial {
		return &Error{}
	}
	return nil
}

// inspectDarwinFilesystem obtains and classifies one descriptor-native filesystem name.
func inspectDarwinFilesystem(fd int) (int, error) {
	var filesystem unix.Statfs_t
	if err := retryOperation(func() error { return unix.Fstatfs(fd, &filesystem) }); err != nil {
		return 0, err
	}
	name := make([]byte, 0, len(filesystem.Fstypename))
	for _, character := range filesystem.Fstypename {
		if character == 0 {
			break
		}
		name = append(name, character)
	}
	return classifyDarwinFilesystemName(string(name))
}

// classifyDarwinFilesystemName accepts only filesystem access models audited for this loader.
func classifyDarwinFilesystemName(name string) (int, error) {
	switch name {
	case "apfs":
		return darwinFilesystemAPFS, nil
	case "hfs":
		return darwinFilesystemHFS, nil
	default:
		return 0, &Error{}
	}
}

// classifyDarwinACLIteration exposes the production C classifier for regression tests.
func classifyDarwinACLIteration(entries, terminalErrno int, hitBound bool, cleanupResult int) error {
	hit := C.int(0)
	if hitBound {
		hit = 1
	}
	result := C.dkim2_securefile_classify_iteration(
		C.int(entries), C.int(terminalErrno), hit, C.int(cleanupResult),
	)
	if result == C.dkim2_securefile_trivial {
		return nil
	}
	return &Error{}
}

// classifyDarwinACLRetrieval exposes the production C classifier for regression tests.
func classifyDarwinACLRetrieval(isNull bool, retrievalErrno int) error {
	nullValue := C.int(0)
	if isNull {
		nullValue = 1
	}
	result := C.dkim2_securefile_classify_retrieval(nullValue, C.int(retrievalErrno))
	if result == C.dkim2_securefile_continue || result == C.dkim2_securefile_trivial {
		return nil
	}
	return &Error{}
}

// darwinACLMaxEntries returns the SDK bound used by the production C loop.
func darwinACLMaxEntries() int { return int(C.ACL_MAX_ENTRIES) }
