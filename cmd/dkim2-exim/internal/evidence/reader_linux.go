//go:build linux

package evidence

import (
	"context"
	"crypto/subtle"
	"path/filepath"
	"sync"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/securefile"
)

// Reader owns a retained, descriptor-confined, mutation-free evidence root.
type Reader struct {
	mu              *sync.Mutex
	leases          *sync.WaitGroup
	directory       int
	root            descriptorState
	key             []byte
	keyState        descriptorState
	keyParent       descriptorState
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
	return identity.MatchesDirectory(r.keyState.device, r.keyState.inode) ||
		identity.MatchesDirectory(r.keyParent.device, r.keyParent.inode) ||
		identity.MatchesDirectory(r.root.device, r.root.inode) ||
		identity.MatchesDirectory(r.readiness.parent.device, r.readiness.parent.inode)
}

// NewReader opens only the protected key and retained evidence root descriptor.
func NewReader(
	root string,
	keyPath string,
	readinessPath string,
	now func() time.Time,
) (*Reader, error) {
	if !validAbsoluteRoot(root) || !validAbsoluteRoot(keyPath) ||
		!validAbsoluteRoot(readinessPath) ||
		filepath.Dir(keyPath) == root || filepath.Dir(readinessPath) == root ||
		filepath.Dir(readinessPath) == filepath.Dir(keyPath) ||
		readinessPath == keyPath || now == nil {
		return nil, ErrEvidence
	}
	key, keyState, keyParent, err := loadKeyFileIdentity(keyPath)
	if err != nil {
		return nil, ErrEvidence
	}
	directory, err := openTrustedDirectory(root, 0o700)
	if err != nil {
		clear(key)
		return nil, ErrEvidence
	}
	state, err := inspectRoot(directory)
	if err != nil {
		closeFD(directory)
		clear(key)
		return nil, ErrEvidence
	}
	readiness, err := newReadinessReader(readinessPath, key)
	if err != nil {
		closeFD(directory)
		clear(key)
		return nil, ErrEvidence
	}
	if protectedStatesAlias(keyState, keyParent, state, readiness.parent) {
		_ = readiness.close()
		closeFD(directory)
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

// protectedStatesAlias rejects any retained protected child or parent alias.
func protectedStatesAlias(states ...descriptorState) bool {
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
		ctx.Err() != nil || validateRootDescriptor(r.directory, r.root) != nil {
		return Record{}, ErrEvidence
	}
	rootBefore, err := inspectRoot(r.directory)
	if err != nil || linuxRootFingerprint(rootBefore) != first.root {
		return Record{}, ErrEvidence
	}
	if r.afterFirstRead != nil {
		r.afterFirstRead()
	}
	openedLocator, file, openErr := openRecordFile(
		ctx,
		nil,
		r.directory,
		locator+finalSuffix,
		manifestFinal,
	)
	if openErr != nil || openedLocator != locator {
		closeFD(file)
		return Record{}, ErrEvidence
	}
	defer closeFD(file)
	if r.afterTargetOpen != nil {
		r.afterTargetOpen()
	}
	second, markerErr := r.readiness.read()
	rootAuthorized, rootErr := inspectRoot(r.directory)
	if markerErr != nil || second != first || second.state != readinessClean ||
		rootErr != nil || linuxRootFingerprint(rootAuthorized) != first.root {
		return Record{}, ErrEvidence
	}
	if !r.readiness.writerLive() {
		return Record{}, ErrEvidence
	}
	entry, err := readRecordFile(
		ctx,
		nil,
		r.directory,
		r.key,
		locator+finalSuffix,
		locator,
		manifestFinal,
		file,
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
	if validateRootDescriptor(r.directory, r.root) != nil {
		return Record{}, ErrEvidence
	}
	return entry.record, nil
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
	closeFD(r.directory)
	r.directory = -1
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
