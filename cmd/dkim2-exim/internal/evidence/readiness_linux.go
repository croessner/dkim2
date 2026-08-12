//go:build linux

package evidence

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// readinessAuthority owns atomic authenticated marker publication.
type readinessAuthority struct {
	mu            sync.Mutex
	directory     int
	parent        descriptorState
	child         string
	key           []byte
	generation    uint64
	beforePublish func(readinessSnapshot) error
	afterPublish  func(readinessSnapshot) error
}

// readinessReader owns a retained marker-parent descriptor.
type readinessReader struct {
	directory int
	parent    descriptorState
	child     string
	key       []byte
}

// newReadinessAuthority opens one dedicated protected external marker parent.
func newReadinessAuthority(path string, key []byte) (*readinessAuthority, error) {
	directory, parent, child, err := openReadinessParent(path)
	if err != nil || len(key) != KeyBytes {
		closeFD(directory)
		return nil, ErrEvidence
	}
	if unix.Flock(directory, unix.LOCK_EX|unix.LOCK_NB) != nil {
		closeFD(directory)
		return nil, ErrNotReady
	}
	authority := &readinessAuthority{
		directory: directory,
		parent:    parent,
		child:     child,
		key:       append([]byte(nil), key...),
	}
	snapshot, readErr := readReadinessAt(
		directory,
		parent,
		child,
		authority.key,
	)
	switch {
	case readErr == nil:
		if validateReadinessParentManifest(
			directory,
			child,
			false,
		) != nil {
			_ = authority.close()
			return nil, ErrNotReady
		}
		if snapshot.generation == ^uint64(0) {
			_ = authority.close()
			return nil, ErrNotReady
		}
		authority.generation = snapshot.generation
	case errors.Is(readErr, unix.ENOENT):
		names, namesErr := readReadinessParentNames(directory)
		if namesErr != nil || len(names) != 0 {
			_ = authority.close()
			return nil, ErrNotReady
		}
	default:
		_ = authority.close()
		return nil, ErrNotReady
	}
	return authority, nil
}

// newReadinessReader opens one retained external marker-parent descriptor.
func newReadinessReader(path string, key []byte) (*readinessReader, error) {
	directory, parent, child, err := openReadinessParent(path)
	if err != nil || len(key) != KeyBytes {
		closeFD(directory)
		return nil, ErrEvidence
	}
	return &readinessReader{
		directory: directory,
		parent:    parent,
		child:     child,
		key:       append([]byte(nil), key...),
	}, nil
}

// write atomically publishes one fsync-complete next generation.
func (a *readinessAuthority) write(
	state byte,
	root rootFingerprint,
	stats Stats,
) error {
	if a == nil {
		return ErrEvidence
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.directory < 0 || len(a.key) != KeyBytes ||
		a.generation == ^uint64(0) ||
		validateRootDescriptor(a.directory, a.parent) != nil {
		return ErrEvidence
	}
	next := a.generation + 1
	snapshot := readinessSnapshot{
		state: state, generation: next, root: root, stats: stats,
	}
	if a.beforePublish != nil && a.beforePublish(snapshot) != nil {
		return ErrEvidence
	}
	encoded, err := encodeReadiness(snapshot, a.key)
	if err != nil {
		return ErrEvidence
	}
	defer clear(encoded)
	temporary, file, err := createReadinessTemporary(a.directory)
	if err != nil {
		return ErrEvidence
	}
	owned := true
	defer func() {
		closeFD(file)
		if owned {
			_ = unix.Unlinkat(a.directory, temporary, 0)
		}
	}()
	if writeReadinessDescriptor(file, encoded) != nil ||
		unix.Fsync(file) != nil {
		return ErrEvidence
	}
	afterWrite, inspectErr := inspectReadinessFile(file)
	if inspectErr != nil || afterWrite.size != readinessBytes {
		return ErrEvidence
	}
	if err = unix.Renameat(a.directory, temporary, a.directory, a.child); err != nil {
		return ErrEvidence
	}
	owned = false
	a.generation = next
	if unix.Fsync(a.directory) != nil ||
		validateRootDescriptor(a.directory, a.parent) != nil ||
		validateReadinessParentManifest(a.directory, a.child, false) != nil {
		return ErrEvidence
	}
	published, err := readReadinessAt(
		a.directory,
		a.parent,
		a.child,
		a.key,
	)
	if err != nil || published != snapshot {
		return ErrEvidence
	}
	if a.afterPublish != nil && a.afterPublish(snapshot) != nil {
		return ErrEvidence
	}
	return nil
}

// read returns one authenticated exact marker generation.
func (r *readinessReader) read() (readinessSnapshot, error) {
	if r == nil || r.directory < 0 || len(r.key) != KeyBytes {
		return readinessSnapshot{}, ErrEvidence
	}
	if validateReadinessParentManifest(r.directory, r.child, true) != nil {
		return readinessSnapshot{}, ErrEvidence
	}
	return readReadinessAt(r.directory, r.parent, r.child, r.key)
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

// close clears and closes one writer authority.
func (a *readinessAuthority) close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	clear(a.key)
	a.key = nil
	_ = unix.Flock(a.directory, unix.LOCK_UN)
	closeFD(a.directory)
	a.directory = -1
	return nil
}

// close clears and closes one reader authority.
func (r *readinessReader) close() error {
	if r == nil {
		return nil
	}
	clear(r.key)
	r.key = nil
	closeFD(r.directory)
	r.directory = -1
	return nil
}

// openReadinessParent opens one exact protected direct marker path.
func openReadinessParent(
	path string,
) (int, descriptorState, string, error) {
	if !validAbsoluteRoot(path) {
		return -1, descriptorState{}, "", ErrEvidence
	}
	parentPath, child := filepath.Split(path)
	parentPath = strings.TrimSuffix(parentPath, string(filepath.Separator))
	if parentPath == "" || child == "" || child == "." || child == ".." {
		return -1, descriptorState{}, "", ErrEvidence
	}
	directory, err := openTrustedDirectory(parentPath, 0o700)
	if err != nil {
		return -1, descriptorState{}, "", ErrEvidence
	}
	parent, err := inspectRoot(directory)
	if err != nil {
		closeFD(directory)
		return -1, descriptorState{}, "", ErrEvidence
	}
	return directory, parent, child, nil
}

// readReadinessAt verifies protected metadata, exact EOF, HMAC, and generation.
func readReadinessAt(
	directory int,
	parent descriptorState,
	child string,
	key []byte,
) (readinessSnapshot, error) {
	if validateRootDescriptor(directory, parent) != nil {
		return readinessSnapshot{}, ErrEvidence
	}
	file, err := unix.Openat(
		directory,
		child,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return readinessSnapshot{}, err
	}
	defer closeFD(file)
	before, err := inspectReadinessFile(file)
	if err != nil {
		return readinessSnapshot{}, ErrEvidence
	}
	encoded, err := readExactReadiness(file)
	if err != nil {
		return readinessSnapshot{}, ErrEvidence
	}
	defer clear(encoded)
	after, afterErr := inspectReadinessFile(file)
	if afterErr != nil || before != after ||
		validateRootDescriptor(directory, parent) != nil {
		return readinessSnapshot{}, ErrEvidence
	}
	return decodeReadiness(encoded, key)
}

// inspectReadinessFile verifies one immutable marker file.
func inspectReadinessFile(file int) (descriptorState, error) {
	state, err := statDescriptor(file)
	if err != nil || state.typeBits != unix.S_IFREG || state.modeBits != 0o600 ||
		state.uid != uint32(os.Geteuid()) || state.linkCount != 1 ||
		state.size != readinessBytes {
		return descriptorState{}, ErrEvidence
	}
	filesystem, err := localFilesystem(file)
	if err != nil || noExtendedAccess(file) != nil {
		return descriptorState{}, ErrEvidence
	}
	state.filesystem = filesystem
	return state, nil
}

// createReadinessTemporary creates one exact private direct child.
func createReadinessTemporary(directory int) (string, int, error) {
	var nonce [nonceBytes]byte
	for attempt := 0; attempt < publicationAttempts; attempt++ {
		if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
			clear(nonce[:])
			return "", -1, ErrEvidence
		}
		name := readinessTemporaryPrefix +
			base64.RawURLEncoding.EncodeToString(nonce[:])
		file, err := unix.Openat(
			directory,
			name,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0o600,
		)
		if err == nil {
			if unix.Fchmod(file, 0o600) != nil {
				closeFD(file)
				_ = unix.Unlinkat(directory, name, 0)
				clear(nonce[:])
				return "", -1, ErrEvidence
			}
			state, inspectErr := inspectReadinessTemporary(file)
			if inspectErr != nil || state.size != 0 {
				closeFD(file)
				_ = unix.Unlinkat(directory, name, 0)
				clear(nonce[:])
				return "", -1, ErrEvidence
			}
			clear(nonce[:])
			return name, file, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			clear(nonce[:])
			return "", -1, ErrEvidence
		}
	}
	clear(nonce[:])
	return "", -1, ErrCapacity
}

// writeReadinessDescriptor writes one complete fixed-width marker.
func writeReadinessDescriptor(file int, encoded []byte) error {
	offset := 0
	for offset < len(encoded) {
		count, err := unix.Write(file, encoded[offset:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || count <= 0 {
			return ErrEvidence
		}
		offset += count
	}
	return nil
}

// readExactReadiness reads one fixed marker followed immediately by EOF.
func readExactReadiness(file int) ([]byte, error) {
	encoded := make([]byte, readinessBytes)
	offset := 0
	for offset < len(encoded) {
		count, err := unix.Read(file, encoded[offset:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || count <= 0 {
			clear(encoded)
			return nil, ErrEvidence
		}
		offset += count
	}
	var extra [1]byte
	count, err := unix.Read(file, extra[:])
	if err != nil || count != 0 {
		clear(encoded)
		return nil, ErrEvidence
	}
	return encoded, nil
}

// readReadinessParentNames snapshots the dedicated marker parent.
func readReadinessParentNames(directory int) ([]string, error) {
	duplicate, err := unix.Openat(
		directory,
		".",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, ErrEvidence
	}
	file := os.NewFile(uintptr(duplicate), "")
	if file == nil {
		closeFD(duplicate)
		return nil, ErrEvidence
	}
	defer func() { _ = file.Close() }()
	entries, err := file.ReadDir(4)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, ErrEvidence
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	return names, nil
}

// validateReadinessParentManifest rejects stale or arbitrary marker siblings.
func validateReadinessParentManifest(
	directory int,
	child string,
	allowLiveTemporary bool,
) error {
	names, err := readReadinessParentNames(directory)
	if err != nil || len(names) > 2 {
		return ErrEvidence
	}
	markerSeen := false
	temporarySeen := false
	for _, name := range names {
		switch {
		case name == child && !markerSeen:
			markerSeen = true
		case allowLiveTemporary && !temporarySeen &&
			validReadinessTemporaryName(name):
			file, openErr := unix.Openat(
				directory,
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
			_, inspectErr := inspectReadinessTemporary(file)
			closeFD(file)
			if inspectErr != nil {
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

// validReadinessTemporaryName accepts one exact random marker temporary.
func validReadinessTemporaryName(name string) bool {
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

// inspectReadinessTemporary verifies one exact private marker temporary.
func inspectReadinessTemporary(file int) (descriptorState, error) {
	state, err := statDescriptor(file)
	if err != nil || state.typeBits != unix.S_IFREG || state.modeBits != 0o600 ||
		state.uid != uint32(os.Geteuid()) || state.linkCount != 1 ||
		state.size < 0 || state.size > readinessBytes {
		return descriptorState{}, ErrEvidence
	}
	filesystem, err := localFilesystem(file)
	if err != nil || noExtendedAccess(file) != nil {
		return descriptorState{}, ErrEvidence
	}
	state.filesystem = filesystem
	return state, nil
}

// linuxRootFingerprint returns one exact mutable directory generation.
func linuxRootFingerprint(state descriptorState) rootFingerprint {
	return rootFingerprint{
		device: uint64(state.device), inode: state.inode, //nolint:unconvert // Keep the persisted identity shape architecture-independent.
		mtimeSec: state.mtimeSec, mtimeNsec: state.mtimeNsec,
		ctimeSec: state.ctimeSec, ctimeNsec: state.ctimeNsec,
	}
}
