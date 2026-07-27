//go:build darwin && cgo

package securefile

import (
	"syscall"
	"testing"
)

// TestDarwinACLClassifiersRejectEntriesAndAmbiguity freezes libc result policy.
func TestDarwinACLClassifiersRejectEntriesAndAmbiguity(t *testing.T) {
	if darwinACLMaxEntries() != 128 {
		t.Fatalf("ACL_MAX_ENTRIES = %d, want 128", darwinACLMaxEntries())
	}
	if err := classifyDarwinACLRetrieval(true, int(syscall.ENOENT)); err != nil {
		t.Fatal("explicit no-ACL result was rejected")
	}
	for _, errnoValue := range []int{0, int(syscall.EIO), int(syscall.EINVAL)} {
		if err := classifyDarwinACLRetrieval(true, errnoValue); err == nil {
			t.Fatal("ambiguous NULL ACL retrieval was accepted")
		}
	}
	if err := classifyDarwinACLIteration(0, int(syscall.EINVAL), false, 0); err != nil {
		t.Fatal("zero-entry ACL was rejected")
	}
	for _, test := range []struct {
		entries, terminalErrno, cleanup int
		hitBound                        bool
	}{
		{entries: 1, terminalErrno: int(syscall.EINVAL)},
		{terminalErrno: int(syscall.EIO)},
		{entries: 128, hitBound: true},
		{terminalErrno: int(syscall.EINVAL), cleanup: -1},
	} {
		if err := classifyDarwinACLIteration(test.entries, test.terminalErrno, test.hitBound, test.cleanup); err == nil {
			t.Fatal("nontrivial Darwin ACL state was accepted")
		}
	}
}

// TestClassifyDarwinFilesystemNameRejectsUnauditedTypes freezes the allowlist.
func TestClassifyDarwinFilesystemNameRejectsUnauditedTypes(t *testing.T) {
	for _, name := range []string{"apfs", "hfs"} {
		if _, err := classifyDarwinFilesystemName(name); err != nil {
			t.Fatal("allowlisted Darwin filesystem was rejected")
		}
	}
	for _, name := range []string{"APFS", "nfs", "smbfs", "fuse", ""} {
		if _, err := classifyDarwinFilesystemName(name); err == nil {
			t.Fatal("unsupported Darwin filesystem was accepted")
		}
	}
}
