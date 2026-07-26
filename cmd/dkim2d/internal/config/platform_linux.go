//go:build linux

package config

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

// inspectDescriptorAccess proves the descriptor uses an approved local
// filesystem and has no access-granting ACL beyond acceptedMode.
func inspectDescriptorAccess(fd int, directory bool, acceptedMode uint32) error {
	_, err := descriptorAccessFingerprint(fd, directory, acceptedMode)
	return err
}

// statDescriptor reads complete security-relevant metadata from one owned
// descriptor without reopening its pathname.
func statDescriptor(fd int) (descriptorMetadata, error) {
	var state unix.Stat_t
	if err := retryDescriptorOperation(func() error {
		return unix.Fstat(fd, &state)
	}); err != nil {
		return descriptorMetadata{}, err
	}
	return linuxDescriptorMetadata(state), nil
}

// statAtNoFollow classifies one descriptor-relative child without following a
// final symbolic link.
func statAtNoFollow(dirfd int, name string) (descriptorMetadata, error) {
	var state unix.Stat_t
	if err := retryDescriptorOperation(func() error {
		return unix.Fstatat(dirfd, name, &state, unix.AT_SYMLINK_NOFOLLOW)
	}); err != nil {
		return descriptorMetadata{}, err
	}
	return linuxDescriptorMetadata(state), nil
}

// linuxDescriptorMetadata converts Linux stat fields into the common,
// content-free descriptor metadata representation.
func linuxDescriptorMetadata(state unix.Stat_t) descriptorMetadata {
	return descriptorMetadata{
		device:    uint64(state.Dev),
		inode:     state.Ino,
		typeBits:  uint32(state.Mode) & unix.S_IFMT,
		uid:       state.Uid,
		modeBits:  uint32(state.Mode) & 0o7777,
		linkCount: uint64(state.Nlink),
		size:      state.Size,
		mtimeSec:  state.Mtim.Sec,
		mtimeNsec: state.Mtim.Nsec,
		ctimeSec:  state.Ctim.Sec,
		ctimeNsec: state.Ctim.Nsec,
	}
}

// descriptorAccessFingerprint validates descriptor-native filesystem and ACL
// state and returns only a one-way fingerprint for later equality checks.
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
	if accessPresent != hasAccess {
		return [32]byte{}, newError(CodeProtectedAccess)
	}
	if accessPresent {
		if err := validateLinuxAccessACL(access, acceptedMode); err != nil {
			return [32]byte{}, err
		}
	}

	defaultACL, defaultPresent, defaultErr := readLinuxACLXattr(fd, linuxACLDefaultName)
	if defaultErr != nil {
		return [32]byte{}, defaultErr
	}
	if defaultPresent != hasDefault || defaultPresent {
		return [32]byte{}, newError(CodeProtectedAccess)
	}

	hash := sha256.New()
	_, _ = hash.Write([]byte("dkim2d-linux-descriptor-access-v1\x00"))
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

// writeLinuxFingerprintValue adds one unambiguous presence, length, and value
// tuple to a descriptor-access fingerprint.
func writeLinuxFingerprintValue(hash interface{ Write([]byte) (int, error) }, present bool, value []byte) {
	var header [5]byte
	if present {
		header[0] = 1
	}
	binary.LittleEndian.PutUint32(header[1:], uint32(len(value)))
	_, _ = hash.Write(header[:])
	_, _ = hash.Write(value)
}

// inspectLinuxFilesystem rejects descriptors whose local access model is not
// one of the four explicitly supported Linux filesystems and returns its type.
func inspectLinuxFilesystem(fd int) (int64, error) {
	var state unix.Statfs_t
	if err := retryDescriptorOperation(func() error {
		return unix.Fstatfs(fd, &state)
	}); err != nil {
		return 0, err
	}

	filesystemType := int64(state.Type)
	return classifyLinuxFilesystemType(filesystemType)
}

// classifyLinuxFilesystemType applies the exact closed local-filesystem allowlist.
func classifyLinuxFilesystemType(filesystemType int64) (int64, error) {
	switch filesystemType {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC:
		return filesystemType, nil
	default:
		return 0, newError(CodeProtectedUnsupported)
	}
}

// readLinuxXattrNames obtains one exact, bounded descriptor-native extended
// attribute name list and rejects concurrent size changes.
func readLinuxXattrNames(fd int) ([]byte, error) {
	return readLinuxXattrNamesWith(func(destination []byte) (int, error) {
		return unix.Flistxattr(fd, destination)
	})
}

// readLinuxXattrNamesWith performs one exact probe/read/reprobe transaction.
func readLinuxXattrNamesWith(call func([]byte) (int, error)) ([]byte, error) {
	size, err := retryLinuxSizeCall(call, nil)
	if err != nil {
		return nil, newError(CodeProtectedAccess)
	}
	if size < 0 {
		return nil, newError(CodeProtectedAccess)
	}
	if size == 0 {
		confirmedSize, confirmErr := retryLinuxSizeCall(call, nil)
		if confirmErr != nil || confirmedSize != 0 {
			return nil, newError(CodeProtectedAccess)
		}
		return nil, nil
	}
	if size > maxLinuxXattrBytes {
		return nil, newError(CodeProtectedAccess)
	}

	buffer := make([]byte, size+1)
	count, err := retryLinuxSizeCall(call, buffer)
	if err != nil || count != size || count > maxLinuxXattrBytes {
		return nil, newError(CodeProtectedAccess)
	}
	confirmedSize, err := retryLinuxSizeCall(call, nil)
	if err != nil || confirmedSize != size {
		return nil, newError(CodeProtectedAccess)
	}
	return buffer[:count], nil
}

// classifyLinuxXattrNames validates the NUL-separated list, permits at most
// the two POSIX ACL system names, and reports their presence.
func classifyLinuxXattrNames(data []byte) (bool, bool, error) {
	if len(data) == 0 {
		return false, false, nil
	}
	if len(data) > maxLinuxXattrBytes || data[len(data)-1] != 0 {
		return false, false, newError(CodeProtectedAccess)
	}

	var hasAccess bool
	var hasDefault bool
	names := bytes.Split(data[:len(data)-1], []byte{0})
	if len(names) > maxLinuxXattrNames {
		return false, false, newError(CodeProtectedAccess)
	}
	seenNames := make(map[string]struct{}, len(names))
	for _, rawName := range names {
		if len(rawName) == 0 {
			return false, false, newError(CodeProtectedAccess)
		}
		name := string(rawName)
		if _, duplicate := seenNames[name]; duplicate {
			return false, false, newError(CodeProtectedAccess)
		}
		seenNames[name] = struct{}{}
		switch name {
		case linuxACLAccessName:
			hasAccess = true
		case linuxACLDefaultName:
			hasDefault = true
		default:
			if strings.HasPrefix(name, "system.") {
				return false, false, newError(CodeProtectedAccess)
			}
		}
	}
	return hasAccess, hasDefault, nil
}

// readLinuxACLXattr reads one exact, bounded POSIX ACL value and distinguishes
// an absent attribute from an empty or malformed value.
func readLinuxACLXattr(fd int, name string) ([]byte, bool, error) {
	return readLinuxACLXattrWith(func(destination []byte) (int, error) {
		return unix.Fgetxattr(fd, name, destination)
	})
}

// readLinuxACLXattrWith performs one exact ACL probe/read/reprobe transaction.
func readLinuxACLXattrWith(call func([]byte) (int, error)) ([]byte, bool, error) {
	size, err := retryLinuxSizeCall(call, nil)
	if isLinuxMissingXattr(err) {
		_, confirmErr := retryLinuxSizeCall(call, nil)
		if !isLinuxMissingXattr(confirmErr) {
			return nil, false, newError(CodeProtectedAccess)
		}
		return nil, false, nil
	}
	if err != nil || size < 0 || size > maxLinuxXattrBytes {
		return nil, false, newError(CodeProtectedAccess)
	}

	buffer := make([]byte, size+1)
	count, err := retryLinuxSizeCall(call, buffer)
	if err != nil || count != size || count > maxLinuxXattrBytes {
		return nil, false, newError(CodeProtectedAccess)
	}
	confirmedSize, err := retryLinuxSizeCall(call, nil)
	if err != nil || confirmedSize != size {
		return nil, false, newError(CodeProtectedAccess)
	}
	return buffer[:count], true, nil
}

// retryLinuxSizeCall retries one interrupted descriptor-native size/read operation.
func retryLinuxSizeCall(
	call func([]byte) (int, error),
	destination []byte,
) (int, error) {
	for {
		size, err := call(destination)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return size, err
	}
}

// isLinuxMissingXattr reports the Linux no-data result without accepting
// unsupported or ambiguous xattr failures as absence.
func isLinuxMissingXattr(err error) bool {
	return errors.Is(err, unix.ENODATA)
}

// validateLinuxAccessACL accepts only one version-two ACL containing exactly
// the owner, group, and other base entries matching acceptedMode.
func validateLinuxAccessACL(data []byte, acceptedMode uint32) error {
	if len(data) < linuxACLHeaderBytes ||
		binary.LittleEndian.Uint32(data[:linuxACLHeaderBytes]) != linuxACLXattrVersion {
		return newError(CodeProtectedAccess)
	}
	payloadBytes := len(data) - linuxACLHeaderBytes
	if payloadBytes%linuxACLEntryBytes != 0 ||
		payloadBytes/linuxACLEntryBytes > maxLinuxACLEntries {
		return newError(CodeProtectedAccess)
	}

	offset := linuxACLHeaderBytes
	entryCount := 0
	permissions := make(map[uint16]uint16, 3)
	for offset < len(data) {
		if entryCount >= maxLinuxACLEntries || len(data)-offset < linuxACLEntryBytes {
			return newError(CodeProtectedAccess)
		}
		tag := binary.LittleEndian.Uint16(data[offset : offset+2])
		permission := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		identifier := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		if permission > 0x7 {
			return newError(CodeProtectedAccess)
		}

		switch tag {
		case linuxACLUser, linuxACLGroup:
			return newError(CodeProtectedAccess)
		case linuxACLUserObject, linuxACLGroupObject, linuxACLOther:
			if identifier != linuxACLUndefinedID {
				return newError(CodeProtectedAccess)
			}
			if _, duplicate := permissions[tag]; duplicate {
				return newError(CodeProtectedAccess)
			}
			permissions[tag] = permission
		case linuxACLMask:
			return newError(CodeProtectedAccess)
		default:
			return newError(CodeProtectedAccess)
		}
		offset += linuxACLEntryBytes
		entryCount++
	}

	if offset != len(data) || entryCount != 3 || len(permissions) != 3 {
		return newError(CodeProtectedAccess)
	}
	if permissions[linuxACLUserObject] != uint16((acceptedMode>>6)&0x7) ||
		permissions[linuxACLGroupObject] != uint16((acceptedMode>>3)&0x7) ||
		permissions[linuxACLOther] != uint16(acceptedMode&0x7) {
		return newError(CodeProtectedAccess)
	}
	return nil
}
