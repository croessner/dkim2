//go:build darwin

package evidence

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// readinessReader owns a retained marker-parent descriptor.
type readinessReader struct {
	directory int
	parent    darwinDescriptorState
	child     string
	key       []byte
}

// newReadinessReader opens one retained external marker-parent descriptor.
func newReadinessReader(path string, key []byte) (*readinessReader, error) {
	if !validAbsoluteReaderPath(path) || len(key) != KeyBytes {
		return nil, ErrEvidence
	}
	parentPath, child := filepath.Split(path)
	parentPath = strings.TrimSuffix(parentPath, string(filepath.Separator))
	if parentPath == "" || child == "" || child == "." || child == ".." {
		return nil, ErrEvidence
	}
	directory, err := openTrustedDarwinDirectory(parentPath, 0o700)
	if err != nil {
		return nil, ErrEvidence
	}
	parent, err := inspectDarwinDescriptor(
		directory,
		unix.S_IFDIR,
		0o700,
		0,
		0,
	)
	if err != nil {
		_ = unix.Close(directory)
		return nil, ErrEvidence
	}
	return &readinessReader{
		directory: directory,
		parent:    parent,
		child:     child,
		key:       append([]byte(nil), key...),
	}, nil
}

// read returns one authenticated exact marker generation.
func (r *readinessReader) read() (readinessSnapshot, error) {
	if r == nil || r.directory < 0 || len(r.key) != KeyBytes ||
		r.validateParent() != nil ||
		r.validateManifest() != nil {
		return readinessSnapshot{}, ErrEvidence
	}
	file, err := unix.Openat(
		r.directory,
		r.child,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return readinessSnapshot{}, ErrEvidence
	}
	defer func() { _ = unix.Close(file) }()
	before, err := inspectDarwinDescriptor(
		file,
		unix.S_IFREG,
		0o600,
		1,
		readinessBytes,
	)
	if err != nil || before.size != readinessBytes {
		return readinessSnapshot{}, ErrEvidence
	}
	encoded, err := readDarwinRecord(
		context.Background(),
		file,
		readinessBytes,
	)
	if err != nil {
		return readinessSnapshot{}, ErrEvidence
	}
	defer clear(encoded)
	after, afterErr := inspectDarwinDescriptor(
		file,
		unix.S_IFREG,
		0o600,
		1,
		readinessBytes,
	)
	if afterErr != nil || before != after || r.validateParent() != nil {
		return readinessSnapshot{}, ErrEvidence
	}
	return decodeReadiness(encoded, r.key)
}

// writerLive proves the sole external authority still owns its lifetime lock.
func (r *readinessReader) writerLive() bool {
	if r == nil || r.directory < 0 {
		return false
	}
	err := unix.Flock(r.directory, unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		_ = unix.Flock(r.directory, unix.LOCK_UN)
		return false
	}
	return errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN)
}

// validateManifest rejects stale or arbitrary marker-parent children.
func (r *readinessReader) validateManifest() error {
	duplicate, err := unix.Openat(
		r.directory,
		".",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return ErrEvidence
	}
	file := os.NewFile(uintptr(duplicate), "")
	if file == nil {
		_ = unix.Close(duplicate)
		return ErrEvidence
	}
	defer func() { _ = file.Close() }()
	entries, err := file.ReadDir(4)
	if err != nil && !errors.Is(err, io.EOF) {
		return ErrEvidence
	}
	if len(entries) > 2 {
		return ErrEvidence
	}
	markerSeen := false
	temporarySeen := false
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case name == r.child && !markerSeen:
			markerSeen = true
		case !temporarySeen && validDarwinReadinessTemporary(name):
			temporary, openErr := unix.Openat(
				r.directory,
				name,
				unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
				0,
			)
			if openErr != nil {
				if errors.Is(openErr, unix.ENOENT) {
					continue
				}
				return ErrEvidence
			}
			state, inspectErr := inspectDarwinDescriptor(
				temporary,
				unix.S_IFREG,
				0o600,
				1,
				readinessBytes,
			)
			_ = unix.Close(temporary)
			if inspectErr != nil || state.size > readinessBytes {
				return ErrEvidence
			}
			temporarySeen = true
		default:
			return ErrEvidence
		}
	}
	if !markerSeen {
		return ErrEvidence
	}
	return nil
}

// validDarwinReadinessTemporary accepts one exact random marker temporary.
func validDarwinReadinessTemporary(name string) bool {
	if !strings.HasPrefix(name, readinessTemporaryPrefix) ||
		len(name) != len(readinessTemporaryPrefix)+nonceTextBytes {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(
		name[len(readinessTemporaryPrefix):],
	)
	valid := err == nil && len(decoded) == nonceBytes &&
		base64.RawURLEncoding.EncodeToString(decoded) ==
			name[len(readinessTemporaryPrefix):]
	clear(decoded)
	return valid
}

// validateParent proves the retained marker parent remains protected.
func (r *readinessReader) validateParent() error {
	current, err := inspectDarwinDescriptor(
		r.directory,
		unix.S_IFDIR,
		0o700,
		0,
		0,
	)
	if err != nil || !sameDarwinRootGeneration(r.parent, current) {
		return ErrEvidence
	}
	return nil
}

// close clears and closes one reader authority.
func (r *readinessReader) close() error {
	if r == nil {
		return nil
	}
	clear(r.key)
	r.key = nil
	if r.directory >= 0 {
		_ = unix.Close(r.directory)
		r.directory = -1
	}
	return nil
}
