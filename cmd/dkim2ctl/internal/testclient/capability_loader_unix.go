//go:build linux || darwin

package testclient

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// capabilityMetadata freezes security-relevant descriptor state.
type capabilityMetadata struct {
	device    uint64
	inode     uint64
	mode      uint32
	uid       uint32
	links     uint64
	size      int64
	mtimeSec  int64
	mtimeNsec int64
	ctimeSec  int64
	ctimeNsec int64
}

// LoadCapability opens and validates one protected capability through one descriptor.
func LoadCapability(path string) (*Capability, error) {
	if !validCapabilityPath(path) {
		return nil, NewExitError(ExitCapability)
	}
	descriptor, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, NewExitError(ExitCapability)
	}
	file := os.NewFile(uintptr(descriptor), capabilityRedacted)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, NewExitError(ExitCapability)
	}
	defer func() { _ = file.Close() }()

	before, err := inspectCapabilityDescriptor(descriptor)
	if err != nil {
		return nil, err
	}
	var value [32]byte
	defer func() {
		for index := range value {
			value[index] = 0
		}
	}()
	if _, err := io.ReadFull(file, value[:]); err != nil {
		return nil, NewExitError(ExitCapability)
	}
	var extra [1]byte
	count, readErr := file.Read(extra[:])
	if count != 0 || !errors.Is(readErr, io.EOF) {
		return nil, NewExitError(ExitCapability)
	}
	after, err := inspectCapabilityDescriptor(descriptor)
	if err != nil || before != after {
		return nil, NewExitError(ExitCapability)
	}
	return newCapability(value)
}

// inspectCapabilityDescriptor validates exact ownership, shape, mode, and size.
func inspectCapabilityDescriptor(descriptor int) (capabilityMetadata, error) {
	var state unix.Stat_t
	if err := unix.Fstat(descriptor, &state); err != nil {
		return capabilityMetadata{}, NewExitError(ExitCapability)
	}
	metadata := capabilityMetadataFromStat(state)
	if metadata.mode&unix.S_IFMT != unix.S_IFREG || metadata.uid != uint32(os.Geteuid()) ||
		metadata.links != 1 ||
		(metadata.mode&0o7777) != 0o400 && (metadata.mode&0o7777) != 0o600 ||
		metadata.size != 32 {
		return capabilityMetadata{}, NewExitError(ExitCapability)
	}
	return metadata, nil
}
