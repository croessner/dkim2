//go:build darwin

package evidence

import (
	"context"
	"crypto/subtle"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/securefile"
	"golang.org/x/sys/unix"
)

// darwinDescriptorState freezes security-relevant descriptor metadata.
type darwinDescriptorState struct {
	device    int32
	inode     uint64
	typeBits  uint16
	modeBits  uint16
	uid       uint32
	linkCount uint16
	size      int64
	mtimeSec  int64
	mtimeNsec int64
	ctimeSec  int64
	ctimeNsec int64
}

// darwinReadEntry owns one authenticated read-only manifest member.
type darwinReadEntry struct {
	locator string
	state   darwinDescriptorState
	record  Record
}

// Reader owns a retained, descriptor-confined, mutation-free evidence root.
type Reader struct {
	mu              *sync.Mutex
	leases          *sync.WaitGroup
	directory       int
	root            darwinDescriptorState
	key             []byte
	keyState        darwinDescriptorState
	keyParent       darwinDescriptorState
	readiness       *readinessReader
	now             func() time.Time
	afterFirstRead  func()
	afterTargetOpen func()
	afterValidate   func()
	closing         bool
	closed          bool
}

// ConflictsProtectedIdentity reports whether one protected resource aliases retained evidence authority.
func (r *Reader) ConflictsProtectedIdentity(identity securefile.Identity) bool {
	if r == nil || r.directory < 0 || r.readiness == nil {
		return true
	}
	return identity.MatchesDirectory(uint64(r.keyState.device), r.keyState.inode) ||
		identity.MatchesDirectory(uint64(r.keyParent.device), r.keyParent.inode) ||
		identity.MatchesDirectory(uint64(r.root.device), r.root.inode) ||
		identity.MatchesDirectory(uint64(r.readiness.parent.device), r.readiness.parent.inode)
}

// NewReader opens only the protected key and retained evidence root descriptor.
func NewReader(
	root string,
	keyPath string,
	readinessPath string,
	now func() time.Time,
) (*Reader, error) {
	if !validAbsoluteReaderPath(root) || !validAbsoluteReaderPath(keyPath) ||
		!validAbsoluteReaderPath(readinessPath) ||
		filepath.Dir(keyPath) == root || filepath.Dir(readinessPath) == root ||
		filepath.Dir(readinessPath) == filepath.Dir(keyPath) ||
		readinessPath == keyPath || now == nil {
		return nil, ErrEvidence
	}
	key, keyState, keyParent, err := loadDarwinReaderKeyIdentity(keyPath)
	if err != nil {
		return nil, ErrEvidence
	}
	directory, err := openTrustedDarwinDirectory(root, 0o700)
	if err != nil {
		clear(key)
		return nil, ErrEvidence
	}
	state, err := inspectDarwinDescriptor(directory, unix.S_IFDIR, 0o700, 0, 0)
	if err != nil {
		_ = unix.Close(directory)
		clear(key)
		return nil, ErrEvidence
	}
	readiness, err := newReadinessReader(readinessPath, key)
	if err != nil {
		_ = unix.Close(directory)
		clear(key)
		return nil, ErrEvidence
	}
	if protectedDarwinStatesAlias(keyState, keyParent, state, readiness.parent) {
		_ = readiness.close()
		_ = unix.Close(directory)
		clear(key)
		return nil, ErrEvidence
	}
	return &Reader{
		mu:        &sync.Mutex{},
		leases:    &sync.WaitGroup{},
		directory: directory,
		root:      state,
		key:       key,
		keyState:  keyState,
		keyParent: keyParent,
		readiness: readiness,
		now:       now,
	}, nil
}

// protectedDarwinStatesAlias rejects any retained protected child or parent alias.
func protectedDarwinStatesAlias(states ...darwinDescriptorState) bool {
	for left := range states {
		if states[left].device == 0 || states[left].inode == 0 {
			return true
		}
		for right := left + 1; right < len(states); right++ {
			if states[left].device == states[right].device && states[left].inode == states[right].inode {
				return true
			}
		}
	}
	return false
}

// LoadContext reads one authenticated final record without recovery or mutation.
func (r *Reader) LoadContext(
	ctx context.Context,
	locator string,
) (record Record, err error) {
	defer func() {
		if recover() != nil {
			record = Record{}
			err = ErrEvidence
		}
	}()
	if ctx == nil || !validLocator(locator) {
		return Record{}, ErrEvidence
	}
	release, err := r.begin()
	if err != nil {
		return Record{}, err
	}
	defer release()
	if !r.readiness.writerLive() {
		return Record{}, ErrEvidence
	}
	first, err := r.readiness.read()
	if err != nil || first.state != readinessClean ||
		ctx.Err() != nil || r.validateRoot() != nil {
		return Record{}, ErrEvidence
	}
	rootBefore, err := inspectDarwinDescriptor(
		r.directory, unix.S_IFDIR, 0o700, 0, 0,
	)
	if err != nil || darwinRootFingerprint(rootBefore) != first.root {
		return Record{}, ErrEvidence
	}
	if r.afterFirstRead != nil {
		r.afterFirstRead()
	}
	file, openErr := r.openRecordFile(
		ctx,
		locator+finalSuffix,
	)
	if openErr != nil {
		return Record{}, ErrEvidence
	}
	defer func() { _ = unix.Close(file) }()
	if r.afterTargetOpen != nil {
		r.afterTargetOpen()
	}
	second, markerErr := r.readiness.read()
	rootAuthorized, rootErr := inspectDarwinDescriptor(
		r.directory, unix.S_IFDIR, 0o700, 0, 0,
	)
	if markerErr != nil || second != first || second.state != readinessClean ||
		rootErr != nil || darwinRootFingerprint(rootAuthorized) != first.root {
		return Record{}, ErrEvidence
	}
	if !r.readiness.writerLive() {
		return Record{}, ErrEvidence
	}
	entry, err := r.readRecordFile(
		ctx,
		file,
		locator,
		r.afterValidate,
	)
	if err != nil || entry.locator != locator {
		return Record{}, ErrEvidence
	}
	now, err := r.wallTime()
	if err != nil || now.Before(entry.record.CreatedAt()) ||
		entry.record.Expired(now) ||
		subtle.ConstantTimeCompare(
			[]byte(entry.record.Locator()),
			[]byte(locator),
		) != 1 {
		return Record{}, ErrEvidence
	}
	if r.validateRoot() != nil {
		return Record{}, ErrEvidence
	}
	return entry.record, nil
}

// openRecordFile acquires one exact direct record child.
func (r *Reader) openRecordFile(
	ctx context.Context,
	name string,
) (int, error) {
	if ctx.Err() != nil {
		return -1, ErrEvidence
	}
	file, err := unix.Openat(
		r.directory,
		name,
		unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return -1, err
	}
	return file, nil
}

// readRecordFile authenticates one already-owned Darwin record descriptor.
func (r *Reader) readRecordFile(
	ctx context.Context,
	file int,
	locator string,
	afterValidate func(),
) (darwinReadEntry, error) {
	before, err := inspectDarwinDescriptor(
		file,
		unix.S_IFREG,
		0o600,
		1,
		MaxRecordBytes,
	)
	if err != nil || before.size < recordPrefixBytes+recordMACBytes {
		return darwinReadEntry{}, ErrEvidence
	}
	if afterValidate != nil {
		afterValidate()
	}
	encoded, err := readDarwinRecord(ctx, file, before.size)
	if err != nil {
		return darwinReadEntry{}, ErrEvidence
	}
	defer clear(encoded)
	record, err := decodeAuthenticated(encoded, r.key)
	if err != nil || subtle.ConstantTimeCompare(
		[]byte(record.Locator()),
		[]byte(locator),
	) != 1 {
		return darwinReadEntry{}, ErrEvidence
	}
	after, err := inspectDarwinDescriptor(
		file,
		unix.S_IFREG,
		0o600,
		1,
		MaxRecordBytes,
	)
	if err != nil {
		after, err = inspectDarwinDescriptor(
			file,
			unix.S_IFREG,
			0o600,
			0,
			MaxRecordBytes,
		)
	}
	if err != nil || !sameDarwinReadGeneration(before, after) ||
		r.validateRoot() != nil {
		return darwinReadEntry{}, ErrEvidence
	}
	return darwinReadEntry{locator: locator, state: before, record: record}, nil
}

// sameDarwinReadGeneration permits only the ctime/link transition from unlink.
func sameDarwinReadGeneration(
	before darwinDescriptorState,
	after darwinDescriptorState,
) bool {
	if after.linkCount == 1 {
		return before == after
	}
	return before.linkCount == 1 && after.linkCount == 0 &&
		before.device == after.device && before.inode == after.inode &&
		before.typeBits == after.typeBits && before.modeBits == after.modeBits &&
		before.uid == after.uid && before.size == after.size &&
		before.mtimeSec == after.mtimeSec &&
		before.mtimeNsec == after.mtimeNsec
}

// Close drains active reads, closes the retained root, and clears the key.
func (r *Reader) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closing = true
	r.mu.Unlock()
	r.leases.Wait()
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.key)
	r.key = nil
	if r.readiness != nil {
		_ = r.readiness.close()
		r.readiness = nil
	}
	if r.directory >= 0 {
		_ = unix.Close(r.directory)
		r.directory = -1
	}
	r.now = nil
	r.closed = true
	return nil
}

// begin retains the root and key until one read finishes.
func (r *Reader) begin() (func(), error) {
	if r == nil {
		return nil, ErrEvidence
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing || r.closed || r.directory < 0 || len(r.key) != KeyBytes ||
		r.readiness == nil {
		return nil, ErrClosed
	}
	r.leases.Add(1)
	return r.leases.Done, nil
}

// darwinRootFingerprint returns one exact mutable directory generation.
func darwinRootFingerprint(state darwinDescriptorState) rootFingerprint {
	return rootFingerprint{
		device: uint64(uint32(state.device)), inode: state.inode,
		mtimeSec: state.mtimeSec, mtimeNsec: state.mtimeNsec,
		ctimeSec: state.ctimeSec, ctimeNsec: state.ctimeNsec,
	}
}

// validateRoot proves the retained descriptor still owns the trusted generation.
func (r *Reader) validateRoot() error {
	current, err := inspectDarwinDescriptor(
		r.directory,
		unix.S_IFDIR,
		0o700,
		0,
		0,
	)
	if err != nil || !sameDarwinRootGeneration(r.root, current) {
		return ErrEvidence
	}
	return nil
}

// sameDarwinRootGeneration ignores entry-count metadata changed by sole writer.
func sameDarwinRootGeneration(
	before darwinDescriptorState,
	after darwinDescriptorState,
) bool {
	return before.device == after.device && before.inode == after.inode &&
		before.typeBits == after.typeBits && before.modeBits == after.modeBits &&
		before.uid == after.uid
}

// wallTime invokes the injected clock without trusting panicking callbacks.
func (r *Reader) wallTime() (now time.Time, err error) {
	defer func() {
		if recover() != nil {
			now = time.Time{}
			err = ErrEvidence
		}
	}()
	now = r.now()
	if now.IsZero() {
		return time.Time{}, ErrEvidence
	}
	return now.UTC(), nil
}

// loadDarwinReaderKeyIdentity reads one exact key and retains only descriptor states.
func loadDarwinReaderKeyIdentity(path string) ([]byte, darwinDescriptorState, darwinDescriptorState, error) {
	parentPath, child := filepath.Split(path)
	parentPath = strings.TrimSuffix(parentPath, string(filepath.Separator))
	if parentPath == "" || child == "" || child == "." || child == ".." {
		return nil, darwinDescriptorState{}, darwinDescriptorState{}, ErrEvidence
	}
	parent, err := openTrustedDarwinDirectory(parentPath, 0o500)
	if err != nil {
		return nil, darwinDescriptorState{}, darwinDescriptorState{}, ErrEvidence
	}
	defer func() { _ = unix.Close(parent) }()
	parentBefore, err := inspectDarwinDescriptor(
		parent,
		unix.S_IFDIR,
		0o500,
		0,
		0,
	)
	if err != nil {
		return nil, darwinDescriptorState{}, darwinDescriptorState{}, ErrEvidence
	}
	file, err := unix.Openat(
		parent,
		child,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, darwinDescriptorState{}, darwinDescriptorState{}, ErrEvidence
	}
	defer func() { _ = unix.Close(file) }()
	before, err := inspectDarwinKey(file)
	if err != nil {
		return nil, darwinDescriptorState{}, darwinDescriptorState{}, ErrEvidence
	}
	key, err := readDarwinRecord(context.Background(), file, KeyBytes)
	if err != nil || len(key) != KeyBytes {
		clear(key)
		return nil, darwinDescriptorState{}, darwinDescriptorState{}, ErrEvidence
	}
	after, afterErr := inspectDarwinKey(file)
	parentAfter, parentErr := inspectDarwinDescriptor(
		parent,
		unix.S_IFDIR,
		0o500,
		0,
		0,
	)
	if afterErr != nil || parentErr != nil ||
		before != after || parentBefore != parentAfter {
		clear(key)
		return nil, darwinDescriptorState{}, darwinDescriptorState{}, ErrEvidence
	}
	return key, before, parentBefore, nil
}

// openTrustedDarwinDirectory traverses trusted ancestry and retains the exact final directory.
func openTrustedDarwinDirectory(path string, finalMode uint32) (int, error) {
	// Darwin exposes fixed root-owned compatibility symlinks for /var and /tmp.
	if path == "/var" || strings.HasPrefix(path, "/var/") ||
		path == "/tmp" || strings.HasPrefix(path, "/tmp/") {
		path = "/private" + path
	}
	if !validAbsoluteReaderPath(path) {
		return -1, ErrEvidence
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	if len(parts) < 1 || len(parts) > 64 {
		return -1, ErrEvidence
	}
	current, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, ErrEvidence
	}
	for index, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			_ = unix.Close(current)
			return -1, ErrEvidence
		}
		next, openErr := unix.Openat(current, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(current)
		if openErr != nil {
			return -1, ErrEvidence
		}
		var state unix.Stat_t
		if unix.Fstat(next, &state) != nil || state.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = unix.Close(next)
			return -1, ErrEvidence
		}
		final := index == len(parts)-1
		ancestorSafe := (state.Uid == 0 || state.Uid == uint32(os.Geteuid())) &&
			(state.Mode&0o022 == 0 || state.Uid == 0 && state.Mode&unix.S_ISVTX != 0)
		finalSafe := state.Uid == uint32(os.Geteuid()) && uint32(state.Mode)&0o777 == finalMode
		if final && !finalSafe || !final && !ancestorSafe {
			_ = unix.Close(next)
			return -1, ErrEvidence
		}
		current = next
	}
	return current, nil
}

// inspectDarwinKey verifies one exact protected regular key descriptor.
func inspectDarwinKey(file int) (darwinDescriptorState, error) {
	state, err := inspectDarwinDescriptor(
		file,
		unix.S_IFREG,
		0o400,
		1,
		KeyBytes,
	)
	if err == nil {
		return state, nil
	}
	return inspectDarwinDescriptor(
		file,
		unix.S_IFREG,
		0o600,
		1,
		KeyBytes,
	)
}

// inspectDarwinDescriptor applies portable descriptor metadata policy.
func inspectDarwinDescriptor(
	file int,
	kind uint16,
	mode uint16,
	links uint16,
	maximum int,
) (darwinDescriptorState, error) {
	var stat unix.Stat_t
	if file < 0 || unix.Fstat(file, &stat) != nil {
		return darwinDescriptorState{}, ErrEvidence
	}
	validLinks := stat.Nlink == links || links == 0 && stat.Nlink >= 2
	if stat.Mode&unix.S_IFMT != kind || stat.Mode&0o7777 != mode ||
		stat.Uid != uint32(os.Geteuid()) || !validLinks ||
		stat.Size < 0 || maximum > 0 && stat.Size > int64(maximum) {
		return darwinDescriptorState{}, ErrEvidence
	}
	return darwinDescriptorState{
		device: stat.Dev, inode: stat.Ino,
		typeBits: stat.Mode & unix.S_IFMT, modeBits: stat.Mode & 0o7777,
		uid: stat.Uid, linkCount: stat.Nlink, size: stat.Size,
		mtimeSec: stat.Mtim.Sec, mtimeNsec: stat.Mtim.Nsec,
		ctimeSec: stat.Ctim.Sec, ctimeNsec: stat.Ctim.Nsec,
	}, nil
}

// readDarwinRecord reads one descriptor-declared size and exact EOF.
func readDarwinRecord(ctx context.Context, file int, size int64) ([]byte, error) {
	if ctx == nil || size < 1 || size > MaxRecordBytes {
		return nil, ErrEvidence
	}
	output := make([]byte, int(size))
	offset := 0
	for offset < len(output) {
		if ctx.Err() != nil {
			clear(output)
			return nil, ErrEvidence
		}
		count, err := unix.Read(file, output[offset:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || count <= 0 {
			clear(output)
			return nil, ErrEvidence
		}
		offset += count
	}
	var extra [1]byte
	for {
		count, err := unix.Read(file, extra[:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || count != 0 {
			clear(output)
			return nil, ErrEvidence
		}
		return output, nil
	}
}

// validAbsoluteReaderPath rejects noncanonical and root protected paths.
func validAbsoluteReaderPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path &&
		path != string(filepath.Separator) &&
		!strings.HasSuffix(path, string(filepath.Separator))
}
