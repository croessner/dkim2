//go:build linux

package evidence

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/securefile"
	"golang.org/x/sys/unix"
)

var (
	errMissingEvidence    = errors.New("exim evidence missing")
	errOperationCancelled = errors.New("exim evidence operation cancelled")
)

// descriptorState freezes immutable metadata used for replacement detection.
type descriptorState struct {
	device    uint64
	inode     uint64
	typeBits  uint32
	modeBits  uint32
	uid       uint32
	linkCount uint64
	size      int64
	mtimeSec  int64
	mtimeNsec int64
	ctimeSec  int64
	ctimeNsec int64
}

// manifestEntry owns one authenticated startup or sweep snapshot.
type manifestEntry struct {
	name    string
	locator string
	kind    manifestKind
	state   descriptorState
	record  Record
}

// descriptorReader reads without taking ownership of its retained descriptor.
type descriptorReader struct {
	fd int
}

// Read implements io.Reader while retrying interrupted descriptor reads.
func (r descriptorReader) Read(destination []byte) (int, error) {
	for {
		count, err := unix.Read(r.fd, destination)
		if err == unix.EINTR {
			continue
		}
		if count == 0 && err == nil {
			return 0, io.EOF
		}
		return count, err
	}
}

// Store owns one descriptor-confined immutable evidence root.
type Store struct {
	stateMu *sync.Mutex
	writer  *sync.Mutex
	leases  *sync.WaitGroup

	directory     int
	rootIdentity  descriptorState
	keyIdentity   descriptorState
	keyParent     descriptorState
	key           []byte
	now           func() time.Time
	random        io.Reader
	limits        Limits
	stats         Stats
	records       map[string]descriptorState
	readiness     *readinessAuthority
	afterMutation func()
	ready         bool
	closing       bool
	closed        bool
	stop          chan struct{}
	closedDone    chan struct{}
}

// NewStore opens one existing protected evidence root with durable defaults.
func NewStore(root string, key []byte, now func() time.Time) (*Store, error) {
	return NewStoreWithLimits(root, key, now, DefaultLimits())
}

// NewStoreWithLimits opens, validates, and recovers one protected evidence root.
func NewStoreWithLimits(root string, key []byte, now func() time.Time, limits Limits) (store *Store, err error) {
	return newStoreWithLimits(context.Background(), root, key, "", now, limits, descriptorState{}, descriptorState{}, nil)
}

// NewStoreWithReadiness opens a sole-writer store with external readiness.
func NewStoreWithReadiness(
	root string,
	key []byte,
	readinessPath string,
	now func() time.Time,
	limits Limits,
) (*Store, error) {
	if !validAbsoluteRoot(readinessPath) ||
		filepath.Dir(readinessPath) == root {
		return nil, ErrEvidence
	}
	return newStoreWithLimits(context.Background(), root, key, readinessPath, now, limits, descriptorState{}, descriptorState{}, nil)
}

// NewStoreWithReadinessKeyPath retains actual key identity for protected-resource checks.
func NewStoreWithReadinessKeyPath(root string, keyPath string, readinessPath string, now func() time.Time, limits Limits, protected ...securefile.Identity) (*Store, error) {
	return NewStoreWithReadinessKeyPathContext(context.Background(), root, keyPath, readinessPath, now, limits, protected...)
}

// NewStoreWithReadinessKeyPathContext bounds validation and recovery by caller lifetime.
func NewStoreWithReadinessKeyPathContext(ctx context.Context, root string, keyPath string, readinessPath string, now func() time.Time, limits Limits, protected ...securefile.Identity) (*Store, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrEvidence
	}
	key, keyIdentity, keyParent, err := loadKeyFileIdentity(keyPath)
	if err != nil {
		return nil, ErrEvidence
	}
	defer clear(key)
	return newStoreWithLimits(ctx, root, key, readinessPath, now, limits, keyIdentity, keyParent, protected)
}

// ConflictsProtectedIdentity reports whether a protected resource aliases actual store authority.
func (s *Store) ConflictsProtectedIdentity(identity securefile.Identity) bool {
	if s == nil || s.directory < 0 {
		return true
	}
	if identity.MatchesDirectory(s.rootIdentity.device, s.rootIdentity.inode) ||
		identity.MatchesDirectory(s.keyIdentity.device, s.keyIdentity.inode) ||
		identity.MatchesDirectory(s.keyParent.device, s.keyParent.inode) {
		return true
	}
	return s.readiness != nil && identity.MatchesDirectory(s.readiness.parent.device, s.readiness.parent.inode)
}

// newStoreWithLimits opens, recovers, and optionally publishes readiness.
func newStoreWithLimits(
	ctx context.Context,
	root string,
	key []byte,
	readinessPath string,
	now func() time.Time,
	limits Limits,
	keyIdentity descriptorState,
	keyParent descriptorState,
	protected []securefile.Identity,
) (store *Store, err error) {
	defer func() {
		if recover() != nil {
			if store != nil {
				_ = store.Close()
			}
			store = nil
			err = ErrEvidence
		}
	}()
	if ctx == nil || ctx.Err() != nil || !validAbsoluteRoot(root) || len(key) != KeyBytes || now == nil || !limits.Valid() {
		return nil, ErrEvidence
	}
	directory, openErr := openTrustedDirectory(root, 0o700)
	if openErr != nil {
		return nil, ErrEvidence
	}
	rootState, stateErr := inspectRoot(directory)
	if stateErr != nil {
		_ = unix.Close(directory)
		return nil, ErrEvidence
	}
	store = &Store{
		stateMu:      &sync.Mutex{},
		writer:       &sync.Mutex{},
		leases:       &sync.WaitGroup{},
		directory:    directory,
		rootIdentity: rootState,
		keyIdentity:  keyIdentity,
		keyParent:    keyParent,
		key:          append([]byte(nil), key...),
		now:          now,
		random:       rand.Reader,
		limits:       limits,
		records:      make(map[string]descriptorState),
		ready:        true,
		stop:         make(chan struct{}),
		closedDone:   make(chan struct{}),
	}
	if readinessPath != "" {
		store.readiness, err = newReadinessAuthority(readinessPath, key)
		if err != nil {
			store.degrade()
			_ = store.Close()
			return nil, ErrNotReady
		}
		if protectedStatesAliasIfPresent(store.keyIdentity, store.keyParent, store.rootIdentity, store.readiness.parent) ||
			conflictsIdentities(protected, store.keyIdentity, store.keyParent, store.rootIdentity, store.readiness.parent) ||
			store.writeReadiness(readinessDirty) != nil {
			store.degrade()
			_ = store.Close()
			return nil, ErrNotReady
		}
	}
	if probeErr := store.probeNoReplace(ctx); probeErr != nil {
		store.degrade()
		_ = store.Close()
		return nil, ErrNotReady
	}
	if recoveryErr := store.recoverStartup(ctx); recoveryErr != nil {
		store.degrade()
		_ = store.Close()
		return nil, ErrNotReady
	}
	if store.readiness != nil && store.writeReadiness(readinessClean) != nil {
		store.degrade()
		_ = store.Close()
		return nil, ErrNotReady
	}
	return store, nil
}

// protectedStatesAliasIfPresent rejects aliases while permitting raw-key constructors.
func protectedStatesAliasIfPresent(states ...descriptorState) bool {
	present := make([]descriptorState, 0, len(states))
	for _, state := range states {
		if state.device != 0 && state.inode != 0 {
			present = append(present, state)
		}
	}
	return protectedStatesAlias(present...)
}

// conflictsIdentities rejects config or capability aliases before evidence mutation.
func conflictsIdentities(identities []securefile.Identity, states ...descriptorState) bool {
	for _, identity := range identities {
		for _, state := range states {
			if state.device != 0 && identity.MatchesDirectory(state.device, state.inode) {
				return true
			}
		}
	}
	return false
}

// LoadKeyFile descriptor-confines one exact opaque 32-byte protected key child.
func LoadKeyFile(path string) (key []byte, err error) {
	key, _, _, err = loadKeyFileIdentity(path)
	return key, err
}

// loadKeyFileIdentity reads one exact key and retains only its opaque descriptor states.
func loadKeyFileIdentity(path string) (key []byte, fileState descriptorState, parentState descriptorState, err error) {
	defer func() {
		if recover() != nil {
			clear(key)
			key = nil
			fileState = descriptorState{}
			parentState = descriptorState{}
			err = ErrEvidence
		}
	}()
	if !validAbsoluteRoot(path) {
		return nil, descriptorState{}, descriptorState{}, ErrEvidence
	}
	parentPath, child := filepath.Split(path)
	parentPath = strings.TrimSuffix(parentPath, string(filepath.Separator))
	if parentPath == "" {
		parentPath = string(filepath.Separator)
	}
	if child == "" || child == "." || child == ".." {
		return nil, descriptorState{}, descriptorState{}, ErrEvidence
	}
	parent, openErr := openTrustedDirectory(parentPath, 0o500)
	if openErr != nil {
		return nil, descriptorState{}, descriptorState{}, ErrEvidence
	}
	defer closeFD(parent)
	parentBefore, parentErr := inspectProtectedKeyParent(parent)
	if parentErr != nil {
		return nil, descriptorState{}, descriptorState{}, ErrEvidence
	}
	file, fileErr := unix.Openat(
		parent, child, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if fileErr != nil {
		return nil, descriptorState{}, descriptorState{}, ErrEvidence
	}
	defer closeFD(file)
	fileBefore, stateErr := inspectProtectedKey(file)
	if stateErr != nil {
		return nil, descriptorState{}, descriptorState{}, ErrEvidence
	}
	key, err = ReadKey(descriptorReader{fd: file})
	if err != nil {
		return nil, descriptorState{}, descriptorState{}, ErrEvidence
	}
	fileAfter, afterErr := inspectProtectedKey(file)
	parentAfter, parentAfterErr := inspectProtectedKeyParent(parent)
	if afterErr != nil || parentAfterErr != nil ||
		fileBefore != fileAfter || parentBefore != parentAfter {
		clear(key)
		return nil, descriptorState{}, descriptorState{}, ErrEvidence
	}
	return key, fileBefore, parentBefore, nil
}

// openTrustedDirectory traverses one absolute directory path without following links.
func openTrustedDirectory(path string, finalMode uint32) (int, error) {
	if !validAbsoluteRoot(path) {
		return -1, ErrEvidence
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	if len(parts) > 64 {
		return -1, ErrEvidence
	}
	current, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, ErrEvidence
	}
	if len(parts) == 1 && parts[0] == "" {
		_ = unix.Close(current)
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
		safeAncestor := (state.Uid == 0 || state.Uid == uint32(os.Geteuid())) &&
			(state.Mode&0o022 == 0 || state.Uid == 0 && state.Mode&unix.S_ISVTX != 0)
		safeFinal := state.Uid == uint32(os.Geteuid()) && state.Mode&0o777 == finalMode
		if final && !safeFinal || !final && !safeAncestor {
			_ = unix.Close(next)
			return -1, ErrEvidence
		}
		current = next
	}
	return current, nil
}

// Close cancels work, drains descriptor leases, closes the root, and wipes the key.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.stateMu.Lock()
	if s.closed {
		s.stateMu.Unlock()
		return nil
	}
	if s.closing {
		done := s.closedDone
		s.stateMu.Unlock()
		<-done
		return nil
	}
	s.closing = true
	close(s.stop)
	s.stateMu.Unlock()

	s.leases.Wait()
	s.writer.Lock()
	markerCloseErr := error(nil)
	if s.readiness != nil {
		markerCloseErr = s.writeReadiness(readinessClosed)
		if markerCloseErr != nil {
			_ = s.readiness.close()
		}
	}
	s.stateMu.Lock()
	clear(s.key)
	s.key = nil
	clear(s.records)
	s.records = nil
	closeErr := error(nil)
	if s.directory >= 0 {
		closeErr = unix.Close(s.directory)
		s.directory = -1
	}
	if s.readiness != nil {
		_ = s.readiness.close()
		s.readiness = nil
	}
	s.ready = false
	s.closed = true
	s.closing = false
	close(s.closedDone)
	s.stateMu.Unlock()
	s.writer.Unlock()
	if closeErr != nil || markerCloseErr != nil {
		return ErrEvidence
	}
	return nil
}

// readyError reports closed, degraded, or live state without protected detail.
func (s *Store) readyError() error {
	if s == nil {
		return ErrNotReady
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	switch {
	case s.closed || s.closing:
		return ErrClosed
	case !s.ready:
		return ErrNotReady
	default:
		return nil
	}
}

// storeStats returns one exact content-free accounting snapshot.
func (s *Store) storeStats() (Stats, error) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	switch {
	case s.closed || s.closing:
		return Stats{}, ErrClosed
	case !s.ready:
		return Stats{}, ErrNotReady
	}
	return s.stats, nil
}

// publishContext creates one immutable no-replace record under exact accounting.
func (s *Store) publishContext(ctx context.Context, retention time.Duration, incoming adapter.IncomingEvidence) (record Record, err error) {
	defer func() {
		if recover() != nil {
			record = Record{}
			err = ErrEvidence
			s.degrade()
		}
	}()
	if ctx == nil {
		return Record{}, ErrEvidence
	}
	if retention < MinimumRetention || retention > MaximumRetention ||
		retention%time.Second != 0 || !validIncoming(incoming) {
		return Record{}, ErrEvidence
	}
	release, beginErr := s.begin()
	if beginErr != nil {
		return Record{}, beginErr
	}
	defer release()
	s.writer.Lock()
	defer s.writer.Unlock()
	if contextErr(ctx, s.stop) != nil || s.validateRoot() != nil {
		return Record{}, ErrEvidence
	}
	if s.readiness != nil {
		if markerErr := s.writeReadiness(readinessDirty); markerErr != nil {
			s.degrade()
			return Record{}, ErrNotReady
		}
		defer func() {
			if recover() != nil {
				record = Record{}
				err = ErrEvidence
				s.degrade()
				return
			}
			if markerErr := s.finishReadinessMutation(); markerErr != nil {
				record = Record{}
				err = ErrNotReady
			}
		}()
	}
	for attempt := 0; attempt < publicationAttempts; attempt++ {
		if contextErr(ctx, s.stop) != nil {
			return Record{}, ErrEvidence
		}
		now, clockErr := s.wallTime()
		if clockErr != nil {
			s.degrade()
			return Record{}, ErrEvidence
		}
		record, err = NewRecord(now, retention, incoming, s.random)
		if err != nil {
			s.degrade()
			return Record{}, ErrEvidence
		}
		encoded, encodeErr := record.Encode(s.key)
		if encodeErr != nil {
			return Record{}, ErrEvidence
		}
		if !s.capacityAllows(int64(len(encoded))) {
			clear(encoded)
			return Record{}, ErrCapacity
		}
		publishedState, publishErr := s.publishRecord(ctx, record.Locator(), encoded)
		clear(encoded)
		if publishErr == nil {
			if s.afterMutation != nil {
				s.afterMutation()
			}
			size := int64(len(encoded))
			s.stateMu.Lock()
			s.stats.Records++
			s.stats.Bytes += size
			s.records[record.Locator()] = publishedState
			s.stateMu.Unlock()
			return record, nil
		}
		if !errors.Is(publishErr, unix.EEXIST) {
			if errors.Is(publishErr, errOperationCancelled) ||
				errors.Is(publishErr, ErrClosed) {
				return Record{}, ErrEvidence
			}
			s.degrade()
			return Record{}, ErrEvidence
		}
	}
	return Record{}, ErrCapacity
}

// loadContext reads one immutable record through an owned descriptor lease.
func (s *Store) loadContext(ctx context.Context, locator string) (record Record, err error) {
	defer func() {
		if recover() != nil {
			record = Record{}
			err = ErrEvidence
			s.degrade()
		}
	}()
	if ctx == nil || !validLocator(locator) {
		return Record{}, ErrEvidence
	}
	release, beginErr := s.begin()
	if beginErr != nil {
		return Record{}, beginErr
	}
	defer release()
	if contextErr(ctx, s.stop) != nil || s.validateRoot() != nil {
		return Record{}, ErrEvidence
	}
	entry, openErr := s.openRecord(ctx, locator+finalSuffix, manifestFinal)
	if openErr != nil || entry.locator != locator {
		if errors.Is(openErr, errMissingEvidence) {
			return Record{}, ErrEvidence
		}
		if contextErr(ctx, s.stop) != nil {
			return Record{}, ErrEvidence
		}
		s.degrade()
		return Record{}, ErrNotReady
	}
	if !s.expectedRecord(locator, entry.state) {
		s.degrade()
		return Record{}, ErrNotReady
	}
	now, clockErr := s.wallTime()
	if clockErr != nil {
		s.degrade()
		return Record{}, ErrEvidence
	}
	if now.Before(entry.record.CreatedAt()) {
		s.degrade()
		return Record{}, ErrNotReady
	}
	if entry.record.Expired(now) ||
		subtle.ConstantTimeCompare([]byte(entry.record.Locator()), []byte(locator)) != 1 {
		return Record{}, ErrEvidence
	}
	return entry.record, nil
}

// collectContext performs one serialized bounded quarantine-first expiry sweep.
func (s *Store) collectContext(ctx context.Context) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrEvidence
			s.degrade()
		}
	}()
	if ctx == nil {
		return ErrEvidence
	}
	release, beginErr := s.begin()
	if beginErr != nil {
		return beginErr
	}
	defer release()
	s.writer.Lock()
	defer s.writer.Unlock()
	if contextErr(ctx, s.stop) != nil || s.validateRoot() != nil {
		return ErrEvidence
	}
	if s.readiness != nil {
		if markerErr := s.writeReadiness(readinessDirty); markerErr != nil {
			s.degrade()
			return ErrNotReady
		}
		defer func() {
			if recover() != nil {
				err = ErrEvidence
				s.degrade()
				return
			}
			if markerErr := s.finishReadinessMutation(); markerErr != nil {
				err = ErrNotReady
			}
		}()
	}
	entries, listErr := s.readManifestNames()
	if listErr != nil {
		s.degrade()
		return ErrNotReady
	}
	now, clockErr := s.wallTime()
	if clockErr != nil {
		s.degrade()
		return ErrEvidence
	}
	var live Stats
	liveRecords := make(map[string]descriptorState, len(entries))
	scannedBytes := int64(0)
	mutated := false
	for _, child := range entries {
		if contextErr(ctx, s.stop) != nil {
			if mutated {
				s.degrade()
				return ErrNotReady
			}
			return ErrEvidence
		}
		locator, kind, parseErr := parseChildName(child)
		if parseErr != nil || kind != manifestFinal {
			s.degrade()
			return ErrNotReady
		}
		entry, openErr := s.openRecord(ctx, child, kind)
		if openErr != nil || entry.locator != locator {
			if contextErr(ctx, s.stop) != nil {
				return ErrEvidence
			}
			s.degrade()
			return ErrNotReady
		}
		if now.Before(entry.record.CreatedAt()) {
			s.degrade()
			return ErrNotReady
		}
		if !s.expectedRecord(locator, entry.state) {
			s.degrade()
			return ErrNotReady
		}
		if scannedBytes > s.limits.MaxBytes-entry.state.size {
			s.degrade()
			return ErrNotReady
		}
		scannedBytes += entry.state.size
		if entry.record.Expired(now) {
			if gcErr := s.quarantineAndRemove(ctx, entry); gcErr != nil {
				s.degrade()
				return ErrNotReady
			}
			if s.afterMutation != nil {
				s.afterMutation()
			}
			mutated = true
			continue
		}
		if live.Records >= s.limits.MaxRecords ||
			live.Bytes > s.limits.MaxBytes-entry.state.size {
			s.degrade()
			return ErrNotReady
		}
		live.Records++
		live.Bytes += entry.state.size
		liveRecords[locator] = entry.state
	}
	s.stateMu.Lock()
	s.stats = live
	s.records = liveRecords
	s.stateMu.Unlock()
	return nil
}

// begin owns one root/key lease until its returned release is called.
func (s *Store) begin() (func(), error) {
	if s == nil {
		return nil, ErrNotReady
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	switch {
	case s.closed || s.closing:
		return nil, ErrClosed
	case !s.ready || s.directory < 0 || len(s.key) != KeyBytes:
		return nil, ErrNotReady
	default:
		s.leases.Add(1)
		return s.leases.Done, nil
	}
}

// degrade closes readiness without deleting or rewriting unsafe state.
func (s *Store) degrade() {
	if s == nil {
		return
	}
	s.stateMu.Lock()
	s.ready = false
	s.stateMu.Unlock()
	if s.readiness != nil {
		if err := s.writeReadiness(readinessDirty); err != nil {
			_ = s.readiness.close()
		}
	}
}

// finishReadinessMutation publishes clean only for a fully ready fsynced root.
func (s *Store) finishReadinessMutation() error {
	if s == nil || s.readiness == nil {
		return nil
	}
	if s.readyError() != nil || unix.Fsync(s.directory) != nil ||
		s.writeReadiness(readinessClean) != nil {
		s.degrade()
		return ErrNotReady
	}
	return nil
}

// writeReadiness snapshots root generation and informational aggregate state.
func (s *Store) writeReadiness(state byte) error {
	if s == nil || s.readiness == nil || s.directory < 0 {
		return ErrEvidence
	}
	root, err := inspectRoot(s.directory)
	if err != nil {
		return ErrEvidence
	}
	s.stateMu.Lock()
	stats := s.stats
	s.stateMu.Unlock()
	return s.readiness.write(state, linuxRootFingerprint(root), stats)
}

// wallTime invokes the injected clock behind panic containment.
func (s *Store) wallTime() (now time.Time, err error) {
	defer func() {
		if recover() != nil {
			now = time.Time{}
			err = ErrEvidence
		}
	}()
	now = s.now()
	if now.IsZero() {
		return time.Time{}, ErrEvidence
	}
	return now.UTC(), nil
}

// capacityAllows applies exact live count and actual encoded-byte caps.
func (s *Store) capacityAllows(size int64) bool {
	if size < 0 {
		return false
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.stats.Records < s.limits.MaxRecords &&
		s.stats.Bytes <= s.limits.MaxBytes-size
}

// expectedRecord proves a child still has its retained descriptor generation.
func (s *Store) expectedRecord(locator string, state descriptorState) bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	expected, ok := s.records[locator]
	return ok && expected == state
}

// publishRecord writes, proves, and durably no-replace publishes one record.
func (s *Store) publishRecord(
	ctx context.Context,
	locator string,
	encoded []byte,
) (published descriptorState, resultErr error) {
	temporary, file, before, createErr := s.createTemporary(ctx, publicationPrefix, locator)
	if createErr != nil {
		return descriptorState{}, createErr
	}
	owned := true
	defer func() {
		closeFD(file)
		if owned {
			unlinkErr := unix.Unlinkat(s.directory, temporary, 0)
			if (unlinkErr != nil && !errors.Is(unlinkErr, unix.ENOENT)) ||
				unix.Fsync(s.directory) != nil {
				published = descriptorState{}
				resultErr = ErrEvidence
			}
		}
	}()
	if contextErr(ctx, s.stop) != nil ||
		!writeAllContext(ctx, s.stop, file, encoded) ||
		unix.Fsync(file) != nil {
		if cancellationErr := contextErr(ctx, s.stop); cancellationErr != nil {
			return descriptorState{}, cancellationErr
		}
		return descriptorState{}, ErrEvidence
	}
	after, stateErr := inspectRecord(file)
	if stateErr != nil || after.device != before.device || after.inode != before.inode ||
		after.size != int64(len(encoded)) || after.modeBits != 0o600 ||
		after.linkCount != 1 {
		return descriptorState{}, ErrEvidence
	}
	if seekEnd, seekErr := unix.Seek(file, 0, io.SeekEnd); seekErr != nil ||
		seekEnd != int64(len(encoded)) {
		return descriptorState{}, ErrEvidence
	}
	if closeErr := unix.Close(file); closeErr != nil {
		file = -1
		return descriptorState{}, ErrEvidence
	}
	file = -1
	if contextErr(ctx, s.stop) != nil {
		return descriptorState{}, contextErr(ctx, s.stop)
	}
	if renameErr := unix.Renameat2(
		s.directory, temporary, s.directory, locator+finalSuffix,
		unix.RENAME_NOREPLACE,
	); renameErr != nil {
		return descriptorState{}, renameErr
	}
	owned = false
	if verifyErr := s.verifyPublished(context.Background(), locator, after, encoded); verifyErr != nil {
		return descriptorState{}, ErrEvidence
	}
	if unix.Fsync(s.directory) != nil {
		return descriptorState{}, ErrEvidence
	}
	final, statErr := statAtNoFollow(s.directory, locator+finalSuffix)
	if statErr != nil || !sameIdentityAndShape(final, after) {
		return descriptorState{}, ErrEvidence
	}
	return final, nil
}

// verifyPublished reopens and proves the exact final inode, bytes, and EOF.
func (s *Store) verifyPublished(
	ctx context.Context,
	locator string,
	expected descriptorState,
	encoded []byte,
) error {
	file, openErr := unix.Openat(
		s.directory, locator+finalSuffix,
		unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if openErr != nil {
		return ErrEvidence
	}
	defer closeFD(file)
	before, stateErr := inspectRecord(file)
	if stateErr != nil || !sameIdentityAndShape(before, expected) {
		return ErrEvidence
	}
	observed, readErr := readExactRecord(ctx, s.stop, file, before.size)
	if readErr != nil {
		return ErrEvidence
	}
	defer clear(observed)
	if subtle.ConstantTimeCompare(observed, encoded) != 1 {
		return ErrEvidence
	}
	after, afterErr := inspectRecord(file)
	if afterErr != nil || before != after {
		return ErrEvidence
	}
	return nil
}

// createTemporary creates one service-private reserved child without changing locator.
func (s *Store) createTemporary(ctx context.Context, prefix, locator string) (string, int, descriptorState, error) {
	for attempt := 0; attempt < publicationAttempts; attempt++ {
		if contextErr(ctx, s.stop) != nil {
			return "", -1, descriptorState{}, ErrEvidence
		}
		nonce, nonceErr := randomNonce(s.random)
		if nonceErr != nil {
			return "", -1, descriptorState{}, ErrEvidence
		}
		name := prefix + locator + "-" + nonce
		file, openErr := unix.Openat(
			s.directory, name,
			unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0o600,
		)
		if errors.Is(openErr, unix.EEXIST) {
			continue
		}
		if openErr != nil {
			return "", -1, descriptorState{}, ErrEvidence
		}
		state, stateErr := inspectRecord(file)
		if stateErr != nil || state.size != 0 {
			closeFD(file)
			unlinkErr := unix.Unlinkat(s.directory, name, 0)
			if unlinkErr == nil {
				_ = unix.Fsync(s.directory)
			}
			return "", -1, descriptorState{}, ErrEvidence
		}
		return name, file, state, nil
	}
	return "", -1, descriptorState{}, ErrCapacity
}

// openRecord opens, reads, authenticates, and metadata-revalidates one direct child.
func (s *Store) openRecord(ctx context.Context, name string, kind manifestKind) (manifestEntry, error) {
	entry, file, err := s.openRecordDescriptor(ctx, name, kind)
	closeFD(file)
	return entry, err
}

// openRecordDescriptor authenticates one child while retaining its read lease.
func (s *Store) openRecordDescriptor(
	ctx context.Context,
	name string,
	kind manifestKind,
) (manifestEntry, int, error) {
	return openRecordDescriptor(
		ctx,
		s.stop,
		s.directory,
		s.key,
		name,
		kind,
		nil,
	)
}

// openRecordDescriptor authenticates one direct child for any retained owner.
func openRecordDescriptor(
	ctx context.Context,
	stop <-chan struct{},
	directory int,
	key []byte,
	name string,
	kind manifestKind,
	afterValidate func(),
) (manifestEntry, int, error) {
	locator, file, err := openRecordFile(
		ctx,
		stop,
		directory,
		name,
		kind,
	)
	if err != nil {
		return manifestEntry{}, -1, err
	}
	entry, err := readRecordFile(
		ctx,
		stop,
		directory,
		key,
		name,
		locator,
		kind,
		file,
		afterValidate,
	)
	if err != nil {
		closeFD(file)
		return manifestEntry{}, -1, err
	}
	return entry, file, nil
}

// openRecordFile acquires one exact direct child without authenticating bytes.
func openRecordFile(
	ctx context.Context,
	stop <-chan struct{},
	directory int,
	name string,
	kind manifestKind,
) (string, int, error) {
	locator, parsedKind, parseErr := parseChildName(name)
	if parseErr != nil || parsedKind != kind || contextErr(ctx, stop) != nil ||
		directory < 0 {
		return "", -1, ErrEvidence
	}
	file, openErr := unix.Openat(
		directory, name,
		unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if openErr != nil {
		if errors.Is(openErr, unix.ENOENT) {
			return "", -1, errMissingEvidence
		}
		return "", -1, ErrEvidence
	}
	return locator, file, nil
}

// readRecordFile authenticates and revalidates one already-owned record file.
func readRecordFile(
	ctx context.Context,
	stop <-chan struct{},
	directory int,
	key []byte,
	name string,
	locator string,
	kind manifestKind,
	file int,
	afterValidate func(),
) (manifestEntry, error) {
	if contextErr(ctx, stop) != nil || directory < 0 ||
		len(key) != KeyBytes || file < 0 {
		return manifestEntry{}, ErrEvidence
	}
	before, stateErr := inspectRecord(file)
	if stateErr != nil {
		return manifestEntry{}, ErrEvidence
	}
	if afterValidate != nil {
		afterValidate()
	}
	encoded, readErr := readExactRecord(ctx, stop, file, before.size)
	if readErr != nil {
		return manifestEntry{}, ErrEvidence
	}
	defer clear(encoded)
	record, decodeErr := decodeAuthenticated(encoded, key)
	if decodeErr != nil || record.Locator() != locator {
		return manifestEntry{}, ErrEvidence
	}
	after, afterErr := inspectReadRecord(file)
	if afterErr != nil || !sameReadGeneration(before, after) {
		return manifestEntry{}, ErrEvidence
	}
	return manifestEntry{
		name: name, locator: locator, kind: kind, state: before, record: record,
	}, nil
}

// quarantineAndRemove atomically moves, identity-checks, and removes an expired entry.
func (s *Store) quarantineAndRemove(ctx context.Context, entry manifestEntry) error {
	current, file, openErr := s.openRecordDescriptor(ctx, entry.name, entry.kind)
	if openErr != nil || current.state != entry.state {
		closeFD(file)
		return ErrEvidence
	}
	defer closeFD(file)
	entry = current
	var quarantine string
	renamed := false
	for attempt := 0; attempt < publicationAttempts; attempt++ {
		if contextErr(ctx, s.stop) != nil {
			return ErrEvidence
		}
		nonce, nonceErr := randomNonce(s.random)
		if nonceErr != nil {
			return ErrEvidence
		}
		quarantine = quarantinePrefix + entry.locator + "-" + nonce
		renameErr := unix.Renameat2(
			s.directory, entry.name, s.directory, quarantine,
			unix.RENAME_NOREPLACE,
		)
		if errors.Is(renameErr, unix.EEXIST) {
			continue
		}
		if renameErr != nil {
			return ErrEvidence
		}
		renamed = true
		break
	}
	if !renamed {
		return ErrEvidence
	}
	if unix.Fsync(s.directory) != nil {
		return ErrEvidence
	}
	moved, statErr := statAtNoFollow(s.directory, quarantine)
	held, heldErr := inspectRecord(file)
	if statErr != nil || heldErr != nil ||
		!sameIdentityAndShape(moved, held) ||
		!sameIdentityAndShape(held, entry.state) {
		restoreErr := unix.Renameat2(
			s.directory, quarantine, s.directory, entry.name,
			unix.RENAME_NOREPLACE,
		)
		if restoreErr == nil {
			_ = unix.Fsync(s.directory)
		}
		return ErrEvidence
	}
	if unlinkErr := unix.Unlinkat(s.directory, quarantine, 0); unlinkErr != nil ||
		unix.Fsync(s.directory) != nil {
		return ErrEvidence
	}
	return nil
}

// recoverStartup validates the complete bounded manifest before recovery mutations.
func (s *Store) recoverStartup(ctx context.Context) error {
	s.writer.Lock()
	defer s.writer.Unlock()
	names, listErr := s.readManifestNames()
	if listErr != nil {
		return ErrEvidence
	}
	now, clockErr := s.wallTime()
	if clockErr != nil {
		return ErrEvidence
	}
	manifest := make([]manifestEntry, 0, len(names))
	locators := make(map[string]struct{}, len(names))
	quarantines := 0
	publications := 0
	scannedBytes := int64(0)
	for _, name := range names {
		if contextErr(ctx, s.stop) != nil {
			return ErrEvidence
		}
		locator, kind, parseErr := parseChildName(name)
		if parseErr != nil {
			return ErrEvidence
		}
		if _, duplicate := locators[locator]; duplicate {
			return ErrEvidence
		}
		locators[locator] = struct{}{}
		switch kind {
		case manifestQuarantine:
			quarantines++
			if quarantines > s.limits.MaxRecords {
				return ErrEvidence
			}
		case manifestPublication:
			publications++
			if publications > publicationAttempts {
				return ErrEvidence
			}
		}
		entry, openErr := s.openRecord(ctx, name, kind)
		if openErr != nil || entry.locator != locator {
			return ErrEvidence
		}
		if scannedBytes > s.limits.MaxBytes-entry.state.size {
			return ErrEvidence
		}
		scannedBytes += entry.state.size
		if now.Before(entry.record.CreatedAt()) ||
			(kind == manifestPublication && entry.record.Expired(now)) {
			return ErrEvidence
		}
		manifest = append(manifest, entry)
	}
	for _, entry := range manifest {
		if contextErr(ctx, s.stop) != nil {
			return ErrEvidence
		}
		switch entry.kind {
		case manifestQuarantine:
			if entry.record.Expired(now) {
				if removeErr := s.removeQuarantine(ctx, entry); removeErr != nil {
					return ErrEvidence
				}
			} else if restoreErr := s.restoreReserved(
				ctx, entry, entry.locator+finalSuffix,
			); restoreErr != nil {
				return ErrEvidence
			}
		case manifestPublication:
			if restoreErr := s.restoreReserved(
				ctx, entry, entry.locator+finalSuffix,
			); restoreErr != nil {
				return ErrEvidence
			}
		}
	}
	return s.recountAndCollectExpired(ctx, now)
}

// recountAndCollectExpired validates final state, removes authenticated expiry, and counts bytes.
func (s *Store) recountAndCollectExpired(ctx context.Context, now time.Time) error {
	names, listErr := s.readManifestNames()
	if listErr != nil {
		return ErrEvidence
	}
	var stats Stats
	records := make(map[string]descriptorState, len(names))
	for _, name := range names {
		locator, kind, parseErr := parseChildName(name)
		if parseErr != nil || kind != manifestFinal {
			return ErrEvidence
		}
		entry, openErr := s.openRecord(ctx, name, kind)
		if openErr != nil || entry.locator != locator {
			return ErrEvidence
		}
		if entry.record.Expired(now) {
			if removeErr := s.quarantineAndRemove(ctx, entry); removeErr != nil {
				return ErrEvidence
			}
			continue
		}
		if now.Before(entry.record.CreatedAt()) {
			return ErrEvidence
		}
		if stats.Records >= s.limits.MaxRecords ||
			stats.Bytes > s.limits.MaxBytes-entry.state.size {
			return ErrCapacity
		}
		stats.Records++
		stats.Bytes += entry.state.size
		records[locator] = entry.state
	}
	s.stateMu.Lock()
	s.stats = stats
	s.records = records
	s.stateMu.Unlock()
	return nil
}

// restoreReserved no-replace restores or publishes one validated reserved inode.
func (s *Store) restoreReserved(
	ctx context.Context,
	entry manifestEntry,
	final string,
) error {
	current, file, openErr := s.openRecordDescriptor(ctx, entry.name, entry.kind)
	if openErr != nil || current.state != entry.state {
		closeFD(file)
		return ErrEvidence
	}
	defer closeFD(file)
	if renameErr := unix.Renameat2(
		s.directory, entry.name, s.directory, final, unix.RENAME_NOREPLACE,
	); renameErr != nil {
		return ErrEvidence
	}
	moved, statErr := statAtNoFollow(s.directory, final)
	held, heldErr := inspectRecord(file)
	if statErr != nil || heldErr != nil ||
		!sameIdentityAndShape(moved, held) ||
		!sameIdentityAndShape(held, entry.state) ||
		unix.Fsync(s.directory) != nil {
		return ErrEvidence
	}
	return nil
}

// removeQuarantine removes only the exact already-validated quarantined inode.
func (s *Store) removeQuarantine(ctx context.Context, entry manifestEntry) error {
	currentEntry, file, openErr := s.openRecordDescriptor(
		ctx, entry.name, entry.kind,
	)
	if openErr != nil || currentEntry.state != entry.state {
		closeFD(file)
		return ErrEvidence
	}
	defer closeFD(file)
	current, statErr := statAtNoFollow(s.directory, entry.name)
	held, heldErr := inspectRecord(file)
	if statErr != nil || heldErr != nil ||
		!sameIdentityAndShape(current, held) ||
		!sameIdentityAndShape(held, entry.state) {
		return ErrEvidence
	}
	if unlinkErr := unix.Unlinkat(s.directory, entry.name, 0); unlinkErr != nil ||
		unix.Fsync(s.directory) != nil {
		return ErrEvidence
	}
	return nil
}

// readManifestNames snapshots a bounded direct-child name set.
func (s *Store) readManifestNames() ([]string, error) {
	if s.validateRoot() != nil {
		return nil, ErrEvidence
	}
	maxEntries, ok := recoveryEntryBound(s.limits.MaxRecords)
	if !ok {
		return nil, ErrEvidence
	}
	descriptor, openErr := unix.Openat(
		s.directory, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if openErr != nil {
		return nil, ErrEvidence
	}
	file := os.NewFile(uintptr(descriptor), "")
	if file == nil {
		closeFD(descriptor)
		return nil, ErrEvidence
	}
	defer func() { _ = file.Close() }()
	entries, readErr := file.ReadDir(maxEntries + 1)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, ErrEvidence
	}
	if len(entries) > maxEntries {
		return nil, ErrEvidence
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	sort.Strings(names)
	return names, nil
}

// recoveryEntryBound bounds final, publication, and quarantine startup work.
func recoveryEntryBound(maxRecords int) (int, bool) {
	if maxRecords < 1 || maxRecords > (math.MaxInt-publicationAttempts-1)/2 {
		return 0, false
	}
	return 2*maxRecords + publicationAttempts, true
}

// probeNoReplace proves Linux atomic no-replace support before readiness.
func (s *Store) probeNoReplace(ctx context.Context) error {
	var locatorBytes [LocatorBytes]byte
	if _, err := io.ReadFull(s.random, locatorBytes[:]); err != nil {
		return ErrEvidence
	}
	locator := base64.RawURLEncoding.EncodeToString(locatorBytes[:])
	clear(locatorBytes[:])
	source, sourceFD, _, sourceErr := s.createTemporary(ctx, publicationPrefix, locator)
	if sourceErr != nil {
		return ErrEvidence
	}
	closeFD(sourceFD)
	target, targetFD, _, targetErr := s.createTemporary(ctx, quarantinePrefix, locator)
	if targetErr != nil {
		_ = unix.Unlinkat(s.directory, source, 0)
		return ErrEvidence
	}
	closeFD(targetFD)
	if renameErr := unix.Renameat2(
		s.directory, source, s.directory, target, unix.RENAME_NOREPLACE,
	); !errors.Is(renameErr, unix.EEXIST) {
		_ = unix.Unlinkat(s.directory, source, 0)
		_ = unix.Unlinkat(s.directory, target, 0)
		return ErrEvidence
	}
	sourceErr = unix.Unlinkat(s.directory, source, 0)
	targetErr = unix.Unlinkat(s.directory, target, 0)
	if sourceErr != nil || targetErr != nil {
		return ErrEvidence
	}
	if unix.Fsync(s.directory) != nil {
		return ErrEvidence
	}
	return nil
}

// validateRoot proves the retained descriptor still owns the trusted generation.
func (s *Store) validateRoot() error {
	return validateRootDescriptor(s.directory, s.rootIdentity)
}

// validateRootDescriptor proves one retained root still owns its generation.
func validateRootDescriptor(directory int, expected descriptorState) error {
	current, err := inspectRoot(directory)
	if err != nil || current.device != expected.device ||
		current.inode != expected.inode ||
		current.typeBits != expected.typeBits ||
		current.modeBits != expected.modeBits ||
		current.uid != expected.uid ||
		current.linkCount != expected.linkCount {
		return ErrEvidence
	}
	return nil
}

// inspectRoot verifies one owned 0700 directory descriptor.
func inspectRoot(fd int) (descriptorState, error) {
	state, err := statDescriptor(fd)
	if err != nil || state.typeBits != unix.S_IFDIR || state.modeBits != 0o700 ||
		state.uid != uint32(os.Geteuid()) || state.linkCount != 2 {
		return descriptorState{}, ErrEvidence
	}
	return state, nil
}

// inspectRecord verifies one owned immutable 0600 regular-file descriptor.
func inspectRecord(fd int) (descriptorState, error) {
	return inspectRecordLinks(fd, false)
}

// inspectReadRecord permits an already-owned record to finish after GC unlink.
func inspectReadRecord(fd int) (descriptorState, error) {
	return inspectRecordLinks(fd, true)
}

// inspectRecordLinks verifies one immutable record with bounded link policy.
func inspectRecordLinks(fd int, allowUnlinked bool) (descriptorState, error) {
	state, err := statDescriptor(fd)
	validLinks := state.linkCount == 1 ||
		allowUnlinked && state.linkCount == 0
	if err != nil || state.typeBits != unix.S_IFREG || state.modeBits != 0o600 ||
		state.uid != uint32(os.Geteuid()) || !validLinks ||
		state.size < 0 || state.size > MaxRecordBytes {
		return descriptorState{}, ErrEvidence
	}
	return state, nil
}

// sameReadGeneration permits only the ctime/link transition caused by unlink.
func sameReadGeneration(before, after descriptorState) bool {
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

// inspectProtectedKeyParent verifies the exact protected key-parent policy.
func inspectProtectedKeyParent(fd int) (descriptorState, error) {
	state, err := statDescriptor(fd)
	if err != nil || state.typeBits != unix.S_IFDIR || state.modeBits != 0o500 ||
		state.uid != uint32(os.Geteuid()) || state.linkCount != 2 {
		return descriptorState{}, ErrEvidence
	}
	return state, nil
}

// inspectProtectedKey verifies one owned 0400 or 0600 exact-size regular child.
func inspectProtectedKey(fd int) (descriptorState, error) {
	state, err := statDescriptor(fd)
	if err != nil || state.typeBits != unix.S_IFREG ||
		(state.modeBits != 0o400 && state.modeBits != 0o600) ||
		state.uid != uint32(os.Geteuid()) || state.linkCount != 1 ||
		state.size != KeyBytes {
		return descriptorState{}, ErrEvidence
	}
	return state, nil
}

// statDescriptor reads security-relevant Linux descriptor metadata.
func statDescriptor(fd int) (descriptorState, error) {
	var state unix.Stat_t
	if fd < 0 || unix.Fstat(fd, &state) != nil {
		return descriptorState{}, ErrEvidence
	}
	return descriptorState{
		device: state.Dev, inode: state.Ino,
		typeBits: state.Mode & unix.S_IFMT,
		modeBits: state.Mode & 0o7777,
		uid:      state.Uid,
		// Stat_t.Nlink width differs across supported Linux architectures.
		linkCount: uint64(state.Nlink), //nolint:unconvert
		size:      state.Size,
		mtimeSec:  state.Mtim.Sec, mtimeNsec: state.Mtim.Nsec,
		ctimeSec: state.Ctim.Sec, ctimeNsec: state.Ctim.Nsec,
	}, nil
}

// statAtNoFollow reads one direct child's metadata without following a symlink.
func statAtNoFollow(directory int, name string) (descriptorState, error) {
	var state unix.Stat_t
	if unix.Fstatat(directory, name, &state, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return descriptorState{}, ErrEvidence
	}
	return descriptorState{
		device: state.Dev, inode: state.Ino,
		typeBits: state.Mode & unix.S_IFMT,
		modeBits: state.Mode & 0o7777,
		uid:      state.Uid,
		// Stat_t.Nlink width differs across supported Linux architectures.
		linkCount: uint64(state.Nlink), //nolint:unconvert
		size:      state.Size,
		mtimeSec:  state.Mtim.Sec, mtimeNsec: state.Mtim.Nsec,
		ctimeSec: state.Ctim.Sec, ctimeNsec: state.Ctim.Nsec,
	}, nil
}

// sameIdentityAndShape compares the complete immutable record generation.
func sameIdentityAndShape(left, right descriptorState) bool {
	return left.device == right.device && left.inode == right.inode &&
		left.typeBits == right.typeBits && left.modeBits == right.modeBits &&
		left.uid == right.uid && left.linkCount == right.linkCount &&
		left.size == right.size
}

// readExactRecord reads the descriptor-declared bounded bytes and exact EOF.
func readExactRecord(ctx context.Context, stop <-chan struct{}, fd int, size int64) ([]byte, error) {
	if size < recordPrefixBytes+recordMACBytes || size > MaxRecordBytes {
		return nil, ErrEvidence
	}
	encoded := make([]byte, int(size))
	offset := 0
	for offset < len(encoded) {
		if contextErr(ctx, stop) != nil {
			clear(encoded)
			return nil, ErrEvidence
		}
		count, err := unix.Read(fd, encoded[offset:])
		if err == unix.EINTR {
			continue
		}
		if err != nil || count <= 0 {
			clear(encoded)
			return nil, ErrEvidence
		}
		offset += count
	}
	var extra [1]byte
	for {
		count, err := unix.Read(fd, extra[:])
		clear(extra[:])
		if err == unix.EINTR {
			continue
		}
		if count != 0 || (err != nil && err != io.EOF) {
			clear(encoded)
			return nil, ErrEvidence
		}
		break
	}
	return encoded, nil
}

// writeAll writes every byte without silent partial-record publication.
func writeAll(fd int, input []byte) bool {
	return writeAllContext(context.Background(), nil, fd, input)
}

// writeAllContext writes every byte while honoring pre-publication cancellation.
func writeAllContext(ctx context.Context, stop <-chan struct{}, fd int, input []byte) bool {
	for len(input) != 0 {
		if contextErr(ctx, stop) != nil {
			return false
		}
		count, err := unix.Write(fd, input)
		if err == unix.EINTR {
			continue
		}
		if err != nil || count <= 0 {
			return false
		}
		input = input[count:]
	}
	return true
}

// randomNonce creates one exact 128-bit unpadded base64url reserved-name nonce.
func randomNonce(random io.Reader) (value string, err error) {
	defer func() {
		if recover() != nil {
			value = ""
			err = ErrEvidence
		}
	}()
	var nonce [nonceBytes]byte
	if random == nil {
		return "", ErrEvidence
	}
	if _, readErr := io.ReadFull(random, nonce[:]); readErr != nil {
		clear(nonce[:])
		return "", ErrEvidence
	}
	value = base64.RawURLEncoding.EncodeToString(nonce[:])
	clear(nonce[:])
	if len(value) != nonceTextBytes {
		return "", ErrEvidence
	}
	return value, nil
}

// contextErr checks caller and store cancellation without retaining causes.
func contextErr(ctx context.Context, stop <-chan struct{}) error {
	if ctx == nil {
		return ErrEvidence
	}
	select {
	case <-ctx.Done():
		return errOperationCancelled
	case <-stop:
		return ErrClosed
	default:
		return nil
	}
}

// validAbsoluteRoot rejects noncanonical, root, and trailing-separator paths.
func validAbsoluteRoot(root string) bool {
	return filepath.IsAbs(root) && root != string(filepath.Separator) &&
		filepath.Clean(root) == root && len(root) <= 4_096 &&
		!strings.ContainsRune(root, 0) &&
		filepath.Base(root) != "." && filepath.Base(root) != ".."
}

// closeFD closes one descriptor that has not already transferred ownership.
func closeFD(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
}
