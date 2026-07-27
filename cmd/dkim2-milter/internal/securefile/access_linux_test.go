//go:build linux

package securefile

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

type linuxACLTestEntry struct {
	tag        uint16
	permission uint16
	identifier uint32
}

// TestValidateLinuxAccessACLRejectsAccessExtensions freezes the base ACL policy.
func TestValidateLinuxAccessACLRejectsAccessExtensions(t *testing.T) {
	valid := encodeLinuxACLForTest(
		linuxACLTestEntry{linuxACLUserObject, 6, linuxACLUndefinedID},
		linuxACLTestEntry{linuxACLGroupObject, 4, linuxACLUndefinedID},
		linuxACLTestEntry{linuxACLOther, 0, linuxACLUndefinedID},
	)
	if len(valid) != 28 {
		t.Fatalf("kernel ACL bytes = %d, want 28", len(valid))
	}
	if err := validateLinuxAccessACL(valid, 0o640); err != nil {
		t.Fatal("matching base ACL was rejected")
	}
	tests := [][]byte{
		valid[:len(valid)-1],
		encodeLinuxACLForTest(
			linuxACLTestEntry{linuxACLUserObject, 6, linuxACLUndefinedID},
			linuxACLTestEntry{linuxACLUser, 4, 42},
			linuxACLTestEntry{linuxACLGroupObject, 4, linuxACLUndefinedID},
			linuxACLTestEntry{linuxACLOther, 0, linuxACLUndefinedID},
		),
		encodeLinuxACLForTest(
			linuxACLTestEntry{linuxACLUserObject, 6, linuxACLUndefinedID},
			linuxACLTestEntry{linuxACLGroupObject, 4, linuxACLUndefinedID},
			linuxACLTestEntry{linuxACLGroup, 4, 42},
			linuxACLTestEntry{linuxACLOther, 0, linuxACLUndefinedID},
		),
		encodeLinuxACLForTest(
			linuxACLTestEntry{linuxACLUserObject, 6, linuxACLUndefinedID},
			linuxACLTestEntry{linuxACLGroupObject, 4, linuxACLUndefinedID},
			linuxACLTestEntry{linuxACLMask, 4, linuxACLUndefinedID},
			linuxACLTestEntry{linuxACLOther, 0, linuxACLUndefinedID},
		),
	}
	for index, data := range tests {
		if err := validateLinuxAccessACL(data, 0o640); !errorsIsSecure(err) {
			t.Fatalf("access-extending ACL %d was accepted", index)
		}
	}
	if err := validateLinuxAccessACL(valid, 0o600); !errorsIsSecure(err) {
		t.Fatal("mode-mismatching ACL was accepted")
	}
}

// TestClassifyLinuxXattrNamesRejectsAmbiguousSystemState freezes name parsing.
func TestClassifyLinuxXattrNamesRejectsAmbiguousSystemState(t *testing.T) {
	valid := []byte(linuxACLAccessName + "\x00")
	hasAccess, hasDefault, err := classifyLinuxXattrNames(valid)
	if err != nil || !hasAccess || hasDefault {
		t.Fatal("valid access ACL name was rejected")
	}
	for _, data := range [][]byte{
		[]byte("user.note"),
		[]byte(linuxACLAccessName + "\x00" + linuxACLAccessName + "\x00"),
		[]byte("system.nfs4_acl\x00"),
		[]byte("user.note\x00\x00"),
	} {
		if _, _, err := classifyLinuxXattrNames(data); !errorsIsSecure(err) {
			t.Fatal("ambiguous xattr name list was accepted")
		}
	}
	_, hasDefault, err = classifyLinuxXattrNames([]byte(linuxACLDefaultName + "\x00"))
	if err != nil || !hasDefault {
		t.Fatal("default ACL presence was not classified")
	}
}

// TestValidateLinuxACLStateRejectsDefaultAndPresenceDrift freezes reconciliation.
func TestValidateLinuxACLStateRejectsDefaultAndPresenceDrift(t *testing.T) {
	valid := encodeLinuxACLForTest(
		linuxACLTestEntry{linuxACLUserObject, 6, linuxACLUndefinedID},
		linuxACLTestEntry{linuxACLGroupObject, 0, linuxACLUndefinedID},
		linuxACLTestEntry{linuxACLOther, 0, linuxACLUndefinedID},
	)
	if err := validateLinuxACLState(true, false, true, false, valid, 0o600); err != nil {
		t.Fatal("stable base ACL state was rejected")
	}
	for _, test := range []struct {
		hasAccess, hasDefault, accessPresent, defaultPresent bool
	}{
		{hasAccess: true},
		{hasDefault: true, defaultPresent: true},
		{defaultPresent: true},
	} {
		if err := validateLinuxACLState(
			test.hasAccess,
			test.hasDefault,
			test.accessPresent,
			test.defaultPresent,
			valid,
			0o600,
		); !errorsIsSecure(err) {
			t.Fatal("ambiguous or default ACL state was accepted")
		}
	}
}

// TestReadLinuxXattrNamesWithRejectsGrowthAndTruncation freezes exact transactions.
func TestReadLinuxXattrNamesWithRejectsGrowthAndTruncation(t *testing.T) {
	value := []byte("user.note\x00")
	step := 0
	got, err := readLinuxXattrNamesWith(func(destination []byte) (int, error) {
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
	if err != nil || !bytes.Equal(got, value) || step != 4 {
		t.Fatal("stable EINTR transaction failed")
	}
	for _, call := range []func([]byte) (int, error){
		func(destination []byte) (int, error) {
			if destination == nil {
				return len(value), nil
			}
			return len(value) - 1, nil
		},
		func() func([]byte) (int, error) {
			calls := 0
			return func(destination []byte) (int, error) {
				calls++
				if destination != nil {
					copy(destination, value)
					return len(value), nil
				}
				if calls > 2 {
					return len(value) + 1, nil
				}
				return len(value), nil
			}
		}(),
	} {
		if _, err := readLinuxXattrNamesWith(call); !errorsIsSecure(err) {
			t.Fatal("unstable xattr name transaction was accepted")
		}
	}
}

// TestReadLinuxACLXattrWithRejectsAbsenceTransitions freezes ENODATA handling.
func TestReadLinuxACLXattrWithRejectsAbsenceTransitions(t *testing.T) {
	calls := 0
	data, present, err := readLinuxACLXattrWith(func([]byte) (int, error) {
		calls++
		return 0, unix.ENODATA
	})
	if err != nil || present || data != nil || calls != 2 {
		t.Fatal("stable ACL absence was rejected")
	}
	step := 0
	if _, _, err := readLinuxACLXattrWith(func([]byte) (int, error) {
		step++
		if step == 1 {
			return 0, unix.ENODATA
		}
		return 28, nil
	}); !errorsIsSecure(err) {
		t.Fatal("ACL absence transition was accepted")
	}
}

// TestClassifyLinuxFilesystemTypeRejectsRemoteAndOverlay freezes the allowlist.
func TestClassifyLinuxFilesystemTypeRejectsRemoteAndOverlay(t *testing.T) {
	for _, value := range []int64{
		unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC,
	} {
		if _, err := classifyLinuxFilesystemType(value); err != nil {
			t.Fatal("allowlisted filesystem was rejected")
		}
	}
	for _, value := range []int64{unix.NFS_SUPER_MAGIC, unix.CIFS_SUPER_MAGIC, unix.OVERLAYFS_SUPER_MAGIC, 0} {
		if _, err := classifyLinuxFilesystemType(value); !errorsIsSecure(err) {
			t.Fatal("unsupported filesystem was accepted")
		}
	}
}

// encodeLinuxACLForTest creates one kernel-style little-endian ACL value.
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

// errorsIsSecure recognizes the package's content-free error type.
func errorsIsSecure(err error) bool {
	_, ok := err.(*Error)
	return ok
}
