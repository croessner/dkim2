//go:build linux

package config

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

type linuxACLTestEntry struct {
	tag        uint16
	permission uint16
	identifier uint32
}

// TestValidateLinuxAccessACL exercises the kernel's fixed-width 28-byte
// version-two base ACL representation and rejects access-extending variants.
func TestValidateLinuxAccessACL(t *testing.T) {
	t.Parallel()

	valid := encodeLinuxACLForTest(
		linuxACLTestEntry{tag: linuxACLUserObject, permission: 0x6, identifier: linuxACLUndefinedID},
		linuxACLTestEntry{tag: linuxACLGroupObject, permission: 0x4, identifier: linuxACLUndefinedID},
		linuxACLTestEntry{tag: linuxACLOther, permission: 0x0, identifier: linuxACLUndefinedID},
	)
	if len(valid) != 28 {
		t.Fatalf("kernel-style ACL length = %d, want 28", len(valid))
	}
	if err := validateLinuxAccessACL(valid, 0o640); err != nil {
		t.Fatalf("valid base ACL rejected with code %q", CodeOf(err))
	}

	tests := []struct {
		name string
		data []byte
		mode uint32
	}{
		{name: "mode mismatch", data: valid, mode: 0o600},
		{
			name: "base identifier",
			data: encodeLinuxACLForTest(
				linuxACLTestEntry{tag: linuxACLUserObject, permission: 0x6, identifier: 42},
				linuxACLTestEntry{tag: linuxACLGroupObject, permission: 0x4, identifier: linuxACLUndefinedID},
				linuxACLTestEntry{tag: linuxACLOther, permission: 0x0, identifier: linuxACLUndefinedID},
			),
			mode: 0o640,
		},
		{
			name: "named user",
			data: encodeLinuxACLForTest(
				linuxACLTestEntry{tag: linuxACLUserObject, permission: 0x6, identifier: linuxACLUndefinedID},
				linuxACLTestEntry{tag: linuxACLUser, permission: 0x4, identifier: 42},
				linuxACLTestEntry{tag: linuxACLGroupObject, permission: 0x4, identifier: linuxACLUndefinedID},
				linuxACLTestEntry{tag: linuxACLOther, permission: 0x0, identifier: linuxACLUndefinedID},
			),
			mode: 0o640,
		},
		{
			name: "mask",
			data: encodeLinuxACLForTest(
				linuxACLTestEntry{tag: linuxACLUserObject, permission: 0x6, identifier: linuxACLUndefinedID},
				linuxACLTestEntry{tag: linuxACLGroupObject, permission: 0x4, identifier: linuxACLUndefinedID},
				linuxACLTestEntry{tag: linuxACLMask, permission: 0x4, identifier: linuxACLUndefinedID},
				linuxACLTestEntry{tag: linuxACLOther, permission: 0x0, identifier: linuxACLUndefinedID},
			),
			mode: 0o640,
		},
		{
			name: "duplicate base entry",
			data: encodeLinuxACLForTest(
				linuxACLTestEntry{tag: linuxACLUserObject, permission: 0x6, identifier: linuxACLUndefinedID},
				linuxACLTestEntry{tag: linuxACLGroupObject, permission: 0x4, identifier: linuxACLUndefinedID},
				linuxACLTestEntry{tag: linuxACLGroupObject, permission: 0x4, identifier: linuxACLUndefinedID},
			),
			mode: 0o640,
		},
		{
			name: "unknown tag",
			data: encodeLinuxACLForTest(
				linuxACLTestEntry{tag: linuxACLUserObject, permission: 0x6, identifier: linuxACLUndefinedID},
				linuxACLTestEntry{tag: 0x40, permission: 0x4, identifier: linuxACLUndefinedID},
				linuxACLTestEntry{tag: linuxACLOther, permission: 0x0, identifier: linuxACLUndefinedID},
			),
			mode: 0o640,
		},
		{
			name: "permission outside mode bits",
			data: encodeLinuxACLForTest(
				linuxACLTestEntry{tag: linuxACLUserObject, permission: 0x8, identifier: linuxACLUndefinedID},
				linuxACLTestEntry{tag: linuxACLGroupObject, permission: 0x4, identifier: linuxACLUndefinedID},
				linuxACLTestEntry{tag: linuxACLOther, permission: 0x0, identifier: linuxACLUndefinedID},
			),
			mode: 0o640,
		},
		{name: "truncated entry", data: valid[:len(valid)-1], mode: 0o640},
		{name: "empty payload", data: valid[:linuxACLHeaderBytes], mode: 0o640},
		{name: "trailing byte", data: append(append([]byte(nil), valid...), 0), mode: 0o640},
	}

	wrongVersion := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint32(wrongVersion[:linuxACLHeaderBytes], linuxACLXattrVersion+1)
	tests = append(tests, struct {
		name string
		data []byte
		mode uint32
	}{name: "unknown version", data: wrongVersion, mode: 0o640})

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := validateLinuxAccessACL(test.data, test.mode); CodeOf(err) != CodeProtectedAccess {
				t.Fatalf("failure code = %q, want %q", CodeOf(err), CodeProtectedAccess)
			}
		})
	}
}

// TestClassifyLinuxXattrNames covers exact name-list framing, system namespace
// policy, and the configured byte and name-count boundaries.
func TestClassifyLinuxXattrNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		data        []byte
		wantAccess  bool
		wantDefault bool
		wantCode    Code
	}{
		{name: "empty"},
		{name: "access", data: []byte(linuxACLAccessName + "\x00"), wantAccess: true},
		{name: "default", data: []byte(linuxACLDefaultName + "\x00"), wantDefault: true},
		{
			name:        "both",
			data:        []byte(linuxACLAccessName + "\x00" + linuxACLDefaultName + "\x00"),
			wantAccess:  true,
			wantDefault: true,
		},
		{name: "user namespace", data: []byte("user.operator-note\x00")},
		{name: "alternate system namespace", data: []byte("system.nfs4_acl\x00"), wantCode: CodeProtectedAccess},
		{name: "duplicate access", data: []byte(linuxACLAccessName + "\x00" + linuxACLAccessName + "\x00"), wantCode: CodeProtectedAccess},
		{name: "duplicate user name", data: []byte("user.one\x00user.one\x00"), wantCode: CodeProtectedAccess},
		{name: "empty element", data: []byte("user.one\x00\x00"), wantCode: CodeProtectedAccess},
		{name: "missing terminator", data: []byte("user.one"), wantCode: CodeProtectedAccess},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			hasAccess, hasDefault, err := classifyLinuxXattrNames(test.data)
			if test.wantCode != "" {
				if CodeOf(err) != test.wantCode {
					t.Fatalf("failure code = %q, want %q", CodeOf(err), test.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("valid list rejected with code %q", CodeOf(err))
			}
			if hasAccess != test.wantAccess || hasDefault != test.wantDefault {
				t.Fatalf("presence = (%t, %t), want (%t, %t)", hasAccess, hasDefault, test.wantAccess, test.wantDefault)
			}
		})
	}

	exactNames := makeLinuxXattrNameListForTest(maxLinuxXattrNames)
	if _, _, err := classifyLinuxXattrNames(exactNames); err != nil {
		t.Fatalf("exact name-count bound rejected with code %q", CodeOf(err))
	}
	tooManyNames := makeLinuxXattrNameListForTest(maxLinuxXattrNames + 1)
	if _, _, err := classifyLinuxXattrNames(tooManyNames); CodeOf(err) != CodeProtectedAccess {
		t.Fatalf("over-name-count failure code = %q, want %q", CodeOf(err), CodeProtectedAccess)
	}

	exactBytes := append([]byte("user."), bytes.Repeat([]byte{'a'}, maxLinuxXattrBytes-len("user.")-1)...)
	exactBytes = append(exactBytes, 0)
	if _, _, err := classifyLinuxXattrNames(exactBytes); err != nil {
		t.Fatalf("exact byte bound rejected with code %q", CodeOf(err))
	}
	overBytes := append(append([]byte(nil), exactBytes...), 0)
	if _, _, err := classifyLinuxXattrNames(overBytes); CodeOf(err) != CodeProtectedAccess {
		t.Fatalf("over-byte-bound failure code = %q, want %q", CodeOf(err), CodeProtectedAccess)
	}
}

// encodeLinuxACLForTest constructs the kernel's little-endian fixed-width
// POSIX ACL xattr representation.
func encodeLinuxACLForTest(entries ...linuxACLTestEntry) []byte {
	data := make([]byte, linuxACLHeaderBytes+len(entries)*linuxACLEntryBytes)
	binary.LittleEndian.PutUint32(data[:linuxACLHeaderBytes], linuxACLXattrVersion)
	offset := linuxACLHeaderBytes
	for _, entry := range entries {
		binary.LittleEndian.PutUint16(data[offset:offset+2], entry.tag)
		binary.LittleEndian.PutUint16(data[offset+2:offset+4], entry.permission)
		binary.LittleEndian.PutUint32(data[offset+4:offset+8], entry.identifier)
		offset += linuxACLEntryBytes
	}
	return data
}

// makeLinuxXattrNameListForTest creates permitted user-namespace names with
// exact NUL framing.
func makeLinuxXattrNameListForTest(count int) []byte {
	var data []byte
	for index := range count {
		data = append(data, []byte("user.x"+strconv.Itoa(index)+"\x00")...)
	}
	return data
}

// TestLinuxFilesystemTypeAllowlist freezes the exact four accepted magic values.
func TestLinuxFilesystemTypeAllowlist(t *testing.T) {
	for _, value := range []int64{
		unix.EXT4_SUPER_MAGIC,
		unix.XFS_SUPER_MAGIC,
		unix.BTRFS_SUPER_MAGIC,
		unix.TMPFS_MAGIC,
	} {
		if _, err := classifyLinuxFilesystemType(value); err != nil {
			t.Fatalf("allowlisted filesystem rejected with code %s", CodeOf(err))
		}
	}
	for _, value := range []int64{
		0,
		unix.NFS_SUPER_MAGIC,
		unix.CIFS_SUPER_MAGIC,
		unix.FUSE_SUPER_MAGIC,
		unix.OVERLAYFS_SUPER_MAGIC,
	} {
		if _, err := classifyLinuxFilesystemType(value); CodeOf(err) != CodeProtectedUnsupported {
			t.Fatalf("unsupported filesystem returned code %s", CodeOf(err))
		}
	}
}

// TestReadLinuxXattrNamesWithProvesProbeReadReprobeBounds covers EINTR and races.
func TestReadLinuxXattrNamesWithProvesProbeReadReprobeBounds(t *testing.T) {
	value := []byte("user.note\x00")
	calls := 0
	got, err := readLinuxXattrNamesWith(func(destination []byte) (int, error) {
		calls++
		if calls == 1 {
			return 0, unix.EINTR
		}
		if destination == nil {
			return len(value), nil
		}
		copy(destination, value)
		return len(value), nil
	})
	if err != nil || !bytes.Equal(got, value) || calls != 4 {
		t.Fatalf("stable EINTR transaction failed: calls=%d code=%s", calls, CodeOf(err))
	}
	tests := []struct {
		name string
		call func([]byte) (int, error)
	}{
		{
			name: "growth",
			call: func() func([]byte) (int, error) {
				call := 0
				return func(destination []byte) (int, error) {
					call++
					if destination != nil {
						copy(destination, value)
						return len(value), nil
					}
					if call > 2 {
						return len(value) + 1, nil
					}
					return len(value), nil
				}
			}(),
		},
		{
			name: "truncated",
			call: func(destination []byte) (int, error) {
				if destination == nil {
					return len(value), nil
				}
				copy(destination, value[:len(value)-1])
				return len(value) - 1, nil
			},
		},
		{
			name: "erange",
			call: func(destination []byte) (int, error) {
				if destination == nil {
					return len(value), nil
				}
				return 0, unix.ERANGE
			},
		},
	}
	for _, test := range tests {
		if _, err := readLinuxXattrNamesWith(test.call); CodeOf(err) != CodeProtectedAccess {
			t.Fatalf("%s returned code %s", test.name, CodeOf(err))
		}
	}
	exact := append(bytes.Repeat([]byte{'a'}, maxLinuxXattrBytes-1), 0)
	step := 0
	got, err = readLinuxXattrNamesWith(func(destination []byte) (int, error) {
		step++
		if destination == nil {
			return len(exact), nil
		}
		copy(destination, exact)
		return len(exact), nil
	})
	if err != nil || len(got) != maxLinuxXattrBytes || step != 3 {
		t.Fatalf("exact xattr byte bound failed with code %s", CodeOf(err))
	}
	if _, err := readLinuxXattrNamesWith(func([]byte) (int, error) {
		return maxLinuxXattrBytes + 1, nil
	}); CodeOf(err) != CodeProtectedAccess {
		t.Fatalf("over xattr byte bound returned code %s", CodeOf(err))
	}
	if _, err := readLinuxXattrNamesWith(func([]byte) (int, error) {
		return -1, nil
	}); CodeOf(err) != CodeProtectedAccess {
		t.Fatalf("negative xattr size returned code %s", CodeOf(err))
	}
}

// TestValidateLinuxAccessACLEntryBound rejects exact nontrivial and over-bound lists safely.
func TestValidateLinuxAccessACLEntryBound(t *testing.T) {
	for _, count := range []int{maxLinuxACLEntries, maxLinuxACLEntries + 1} {
		entries := make([]linuxACLTestEntry, count)
		for index := range entries {
			entries[index] = linuxACLTestEntry{
				tag:        linuxACLUser,
				permission: 0,
				identifier: uint32(index),
			}
		}
		if err := validateLinuxAccessACL(encodeLinuxACLForTest(entries...), 0o600); CodeOf(err) != CodeProtectedAccess {
			t.Fatalf("ACL count %d returned code %s", count, CodeOf(err))
		}
	}
}

// TestReadLinuxACLXattrWithProvesPresenceAndGrowthStability covers ACL races.
func TestReadLinuxACLXattrWithProvesPresenceAndGrowthStability(t *testing.T) {
	value := encodeLinuxACLForTest(
		linuxACLTestEntry{tag: linuxACLUserObject, permission: 0x6, identifier: linuxACLUndefinedID},
		linuxACLTestEntry{tag: linuxACLGroupObject, permission: 0x0, identifier: linuxACLUndefinedID},
		linuxACLTestEntry{tag: linuxACLOther, permission: 0x0, identifier: linuxACLUndefinedID},
	)
	step := 0
	got, present, err := readLinuxACLXattrWith(func(destination []byte) (int, error) {
		step++
		if step == 1 {
			return 0, unix.EINTR
		}
		if destination == nil {
			return len(value), nil
		}
		copy(destination, value)
		return len(value), nil
	})
	if err != nil || !present || !bytes.Equal(got, value) || step != 4 {
		t.Fatalf("stable ACL transaction failed: present=%t step=%d code=%s", present, step, CodeOf(err))
	}
	missingCalls := 0
	got, present, err = readLinuxACLXattrWith(func([]byte) (int, error) {
		missingCalls++
		return 0, unix.ENODATA
	})
	if err != nil || present || got != nil || missingCalls != 2 {
		t.Fatalf("stable absence failed: calls=%d code=%s", missingCalls, CodeOf(err))
	}
	absenceStep := 0
	if _, _, err := readLinuxACLXattrWith(func([]byte) (int, error) {
		absenceStep++
		if absenceStep == 1 {
			return 0, unix.ENODATA
		}
		return len(value), nil
	}); CodeOf(err) != CodeProtectedAccess {
		t.Fatalf("presence change returned code %s", CodeOf(err))
	}
	growthStep := 0
	if _, _, err := readLinuxACLXattrWith(func(destination []byte) (int, error) {
		growthStep++
		if destination != nil {
			copy(destination, value)
			return len(value), nil
		}
		if growthStep > 2 {
			return len(value) + 1, nil
		}
		return len(value), nil
	}); CodeOf(err) != CodeProtectedAccess {
		t.Fatalf("ACL growth returned code %s", CodeOf(err))
	}
}
