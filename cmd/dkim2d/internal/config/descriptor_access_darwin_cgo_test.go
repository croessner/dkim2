//go:build darwin && cgo

package config

import (
	"syscall"
	"testing"
)

// TestDarwinACLIterationAndCleanupPolicy freezes zero/nonzero/bound/error outcomes.
func TestDarwinACLIterationAndCleanupPolicy(t *testing.T) {
	if darwinACLMaxEntries() != 128 {
		t.Fatalf("ACL_MAX_ENTRIES = %d, want 128", darwinACLMaxEntries())
	}
	tests := []struct {
		name          string
		entries       int
		terminalErrno int
		hitBound      bool
		cleanupResult int
		wantOK        bool
	}{
		{name: "zero extended entries", terminalErrno: int(syscall.EINVAL), wantOK: true},
		{name: "one entry", entries: 1, terminalErrno: int(syscall.EINVAL)},
		{name: "unexpected iteration error", terminalErrno: int(syscall.EIO)},
		{name: "exact bound", entries: 128, hitBound: true},
		{name: "over bound representation", entries: 129, hitBound: true},
		{name: "cleanup failure dominates empty", terminalErrno: int(syscall.EINVAL), cleanupResult: -1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := classifyDarwinACLIteration(
				test.entries,
				test.terminalErrno,
				test.hitBound,
				test.cleanupResult,
			)
			if test.wantOK && err != nil {
				t.Fatalf("trivial ACL rejected with code %s", CodeOf(err))
			}
			if !test.wantOK && CodeOf(err) != CodeProtectedAccess {
				t.Fatalf("nontrivial ACL returned code %s", CodeOf(err))
			}
		})
	}
}

// TestDarwinACLRetrievalPolicy rejects stale or ambiguous NULL results.
func TestDarwinACLRetrievalPolicy(t *testing.T) {
	if err := classifyDarwinACLRetrieval(true, int(syscall.ENOENT)); err != nil {
		t.Fatalf("explicit no-ACL result rejected with code %s", CodeOf(err))
	}
	for _, errnoValue := range []int{0, int(syscall.EIO), int(syscall.EINVAL)} {
		if err := classifyDarwinACLRetrieval(true, errnoValue); CodeOf(err) != CodeProtectedAccess {
			t.Fatalf("ambiguous NULL errno=%d returned code %s", errnoValue, CodeOf(err))
		}
	}
	if err := classifyDarwinACLRetrieval(false, int(syscall.ENOENT)); err != nil {
		t.Fatalf("non-NULL ACL retrieval did not continue: %s", CodeOf(err))
	}
}

// TestDarwinFilesystemNameAllowlist freezes exact case-sensitive local names.
func TestDarwinFilesystemNameAllowlist(t *testing.T) {
	for _, name := range []string{"apfs", "hfs"} {
		if _, err := classifyDarwinFilesystemName(name); err != nil {
			t.Fatalf("allowlisted filesystem %q rejected with code %s", name, CodeOf(err))
		}
	}
	for _, name := range []string{"", "apfsx", "hfs+", "APFS", "nfs", "smbfs", "fuse", "unknown"} {
		if _, err := classifyDarwinFilesystemName(name); CodeOf(err) != CodeProtectedUnsupported {
			t.Fatalf("filesystem %q returned code %s", name, CodeOf(err))
		}
	}
}
