//go:build linux

package securefile

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	linuxACLXattrVersion = 0x0002

	linuxACLUserObject  = 0x0001
	linuxACLUser        = 0x0002
	linuxACLGroupObject = 0x0004
	linuxACLGroup       = 0x0008
	linuxACLMask        = 0x0010
	linuxACLOther       = 0x0020

	linuxACLAccessName  = "system.posix_acl_access"
	linuxACLDefaultName = "system.posix_acl_default"

	maxLinuxXattrBytes  = 65_536
	maxLinuxXattrNames  = 256
	maxLinuxACLEntries  = 256
	linuxACLHeaderBytes = 4
	linuxACLEntryBytes  = 8
	linuxACLUndefinedID = ^uint32(0)
)

// descriptorAccessFingerprint validates and fingerprints Linux filesystem and ACL state.
func descriptorAccessFingerprint(fd int, directory bool, acceptedMode uint32) ([32]byte, error) {
	filesystemType, err := inspectLinuxFilesystem(fd)
	if err != nil {
		return [32]byte{}, err
	}
	names, err := readLinuxXattrNames(fd)
	if err != nil {
		return [32]byte{}, err
	}
	hasAccess, hasDefault, err := classifyLinuxXattrNames(names)
	if err != nil {
		return [32]byte{}, err
	}

	access, accessPresent, err := readLinuxACLXattr(fd, linuxACLAccessName)
	if err != nil {
		return [32]byte{}, err
	}
	defaultACL, defaultPresent, err := readLinuxACLXattr(fd, linuxACLDefaultName)
	if err != nil {
		return [32]byte{}, err
	}
	if err := validateLinuxACLState(
		hasAccess, hasDefault, accessPresent, defaultPresent, access, acceptedMode,
	); err != nil {
		return [32]byte{}, &Error{}
	}

	hash := sha256.New()
	_, _ = hash.Write([]byte("dkim2-milter-securefile-linux-access-v1\x00"))
	var fixed [13]byte
	binary.LittleEndian.PutUint64(fixed[:8], uint64(filesystemType))
	if directory {
		fixed[8] = 1
	}
	binary.LittleEndian.PutUint32(fixed[9:], acceptedMode)
	_, _ = hash.Write(fixed[:])
	writeLinuxFingerprintValue(hash, accessPresent, access)
	writeLinuxFingerprintValue(hash, defaultPresent, defaultACL)

	var fingerprint [32]byte
	copy(fingerprint[:], hash.Sum(nil))
	return fingerprint, nil
}

// validateLinuxACLState reconciles name-list presence and rejects access extensions.
func validateLinuxACLState(
	hasAccess, hasDefault, accessPresent, defaultPresent bool,
	access []byte,
	acceptedMode uint32,
) error {
	if accessPresent != hasAccess || defaultPresent != hasDefault || defaultPresent {
		return &Error{}
	}
	if accessPresent {
		return validateLinuxAccessACL(access, acceptedMode)
	}
	return nil
}

// writeLinuxFingerprintValue adds one framed value to an access fingerprint.
func writeLinuxFingerprintValue(hash interface{ Write([]byte) (int, error) }, present bool, value []byte) {
	var header [5]byte
	if present {
		header[0] = 1
	}
	binary.LittleEndian.PutUint32(header[1:], uint32(len(value)))
	_, _ = hash.Write(header[:])
	_, _ = hash.Write(value)
}

// inspectLinuxFilesystem applies the closed local-filesystem allowlist.
func inspectLinuxFilesystem(fd int) (int64, error) {
	var filesystem unix.Statfs_t
	if err := retryOperation(func() error { return unix.Fstatfs(fd, &filesystem) }); err != nil {
		return 0, err
	}
	return classifyLinuxFilesystemType(int64(filesystem.Type))
}

// classifyLinuxFilesystemType accepts only filesystem access models audited for this loader.
func classifyLinuxFilesystemType(filesystemType int64) (int64, error) {
	switch filesystemType {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC:
		return filesystemType, nil
	default:
		return 0, &Error{}
	}
}

// readLinuxXattrNames obtains one exact bounded descriptor-native name list.
func readLinuxXattrNames(fd int) ([]byte, error) {
	return readLinuxXattrNamesWith(func(destination []byte) (int, error) {
		return unix.Flistxattr(fd, destination)
	})
}

// readLinuxXattrNamesWith performs one probe, read, and reprobe transaction.
func readLinuxXattrNamesWith(call func([]byte) (int, error)) ([]byte, error) {
	size, err := retryLinuxSizeCall(call, nil)
	if err != nil || size < 0 || size > maxLinuxXattrBytes {
		return nil, &Error{}
	}
	if size == 0 {
		confirmed, confirmErr := retryLinuxSizeCall(call, nil)
		if confirmErr != nil || confirmed != 0 {
			return nil, &Error{}
		}
		return nil, nil
	}
	buffer := make([]byte, size+1)
	count, err := retryLinuxSizeCall(call, buffer)
	if err != nil || count != size || count > maxLinuxXattrBytes {
		return nil, &Error{}
	}
	confirmed, err := retryLinuxSizeCall(call, nil)
	if err != nil || confirmed != size {
		return nil, &Error{}
	}
	return buffer[:count], nil
}

// classifyLinuxXattrNames validates framing and rejects unknown system access models.
func classifyLinuxXattrNames(data []byte) (bool, bool, error) {
	if len(data) == 0 {
		return false, false, nil
	}
	if len(data) > maxLinuxXattrBytes || data[len(data)-1] != 0 {
		return false, false, &Error{}
	}
	names := bytes.Split(data[:len(data)-1], []byte{0})
	if len(names) > maxLinuxXattrNames {
		return false, false, &Error{}
	}
	seen := make(map[string]struct{}, len(names))
	var hasAccess, hasDefault bool
	for _, rawName := range names {
		if len(rawName) == 0 {
			return false, false, &Error{}
		}
		name := string(rawName)
		if _, duplicate := seen[name]; duplicate {
			return false, false, &Error{}
		}
		seen[name] = struct{}{}
		switch name {
		case linuxACLAccessName:
			hasAccess = true
		case linuxACLDefaultName:
			hasDefault = true
		default:
			if strings.HasPrefix(name, "system.") {
				return false, false, &Error{}
			}
		}
	}
	return hasAccess, hasDefault, nil
}

// readLinuxACLXattr reads one exact bounded POSIX ACL value.
func readLinuxACLXattr(fd int, name string) ([]byte, bool, error) {
	return readLinuxACLXattrWith(func(destination []byte) (int, error) {
		return unix.Fgetxattr(fd, name, destination)
	})
}

// readLinuxACLXattrWith distinguishes stable absence from one stable value.
func readLinuxACLXattrWith(call func([]byte) (int, error)) ([]byte, bool, error) {
	size, err := retryLinuxSizeCall(call, nil)
	if errors.Is(err, unix.ENODATA) {
		_, confirmedErr := retryLinuxSizeCall(call, nil)
		if !errors.Is(confirmedErr, unix.ENODATA) {
			return nil, false, &Error{}
		}
		return nil, false, nil
	}
	if err != nil || size < 0 || size > maxLinuxXattrBytes {
		return nil, false, &Error{}
	}
	buffer := make([]byte, size+1)
	count, err := retryLinuxSizeCall(call, buffer)
	if err != nil || count != size || count > maxLinuxXattrBytes {
		return nil, false, &Error{}
	}
	confirmed, err := retryLinuxSizeCall(call, nil)
	if err != nil || confirmed != size {
		return nil, false, &Error{}
	}
	return buffer[:count], true, nil
}

// retryLinuxSizeCall retries an interrupted xattr probe or read.
func retryLinuxSizeCall(call func([]byte) (int, error), destination []byte) (int, error) {
	for {
		size, err := call(destination)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return size, err
	}
}

// validateLinuxAccessACL accepts only the three base entries matching acceptedMode.
func validateLinuxAccessACL(data []byte, acceptedMode uint32) error {
	if len(data) < linuxACLHeaderBytes ||
		binary.LittleEndian.Uint32(data[:linuxACLHeaderBytes]) != linuxACLXattrVersion {
		return &Error{}
	}
	payloadBytes := len(data) - linuxACLHeaderBytes
	if payloadBytes%linuxACLEntryBytes != 0 ||
		payloadBytes/linuxACLEntryBytes > maxLinuxACLEntries {
		return &Error{}
	}

	permissions := make(map[uint16]uint16, 3)
	entryCount := 0
	for offset := linuxACLHeaderBytes; offset < len(data); offset += linuxACLEntryBytes {
		if len(data)-offset < linuxACLEntryBytes {
			return &Error{}
		}
		tag := binary.LittleEndian.Uint16(data[offset : offset+2])
		permission := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		identifier := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		if permission > 0x7 {
			return &Error{}
		}
		switch tag {
		case linuxACLUserObject, linuxACLGroupObject, linuxACLOther:
			if identifier != linuxACLUndefinedID {
				return &Error{}
			}
			if _, duplicate := permissions[tag]; duplicate {
				return &Error{}
			}
			permissions[tag] = permission
		case linuxACLUser, linuxACLGroup, linuxACLMask:
			return &Error{}
		default:
			return &Error{}
		}
		entryCount++
	}
	if entryCount != 3 || len(permissions) != 3 ||
		permissions[linuxACLUserObject] != uint16((acceptedMode>>6)&0x7) ||
		permissions[linuxACLGroupObject] != uint16((acceptedMode>>3)&0x7) ||
		permissions[linuxACLOther] != uint16(acceptedMode&0x7) {
		return &Error{}
	}
	return nil
}
