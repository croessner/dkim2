//go:build darwin

package evidence

import (
	"context"
	"testing"

	"golang.org/x/sys/unix"
)

// testRootFingerprint reads one exact Darwin root generation for fixtures.
func testRootFingerprint(t *testing.T, root string) rootFingerprint {
	t.Helper()
	directory, err := unix.Open(
		root,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		t.Fatal("readiness root fixture open failed")
	}
	defer func() { _ = unix.Close(directory) }()
	state, err := inspectDarwinDescriptor(
		directory,
		unix.S_IFDIR,
		0o700,
		0,
		0,
	)
	if err != nil {
		t.Fatal("readiness root fixture inspection failed")
	}
	return darwinRootFingerprint(state)
}

// TestReaderRejectsExtendedRecordAccess proves ACL/xattr-bearing records do
// not satisfy the Darwin descriptor policy used by the public filter proof.
func TestReaderRejectsExtendedRecordAccess(t *testing.T) {
	fixture := newReaderFixture(t)
	if err := unix.Setxattr(
		fixture.recordPath,
		"user.dkim2-test",
		[]byte{1},
		0,
	); err != nil {
		t.Skip("filesystem did not support the xattr fixture")
	}
	reader := openReaderFixture(t, fixture)
	if _, err := reader.LoadContext(
		context.Background(),
		fixture.record.Locator(),
	); err == nil {
		t.Fatal("extended record access metadata was accepted")
	}
}
