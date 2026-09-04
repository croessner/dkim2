package replay

import (
	"bytes"
	"container/heap"
	"context"
	"fmt"
	"io"
	"sync"
	"time"
)

const memoryStoreRedactedText = "replay_memory_store"

// Clock supplies one deterministic operation time to the memory store.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapts one function to the memory-store clock seam.
type ClockFunc func() time.Time

// Now returns the function-provided time.
func (f ClockFunc) Now() time.Time { return f() }

// MemoryConfig contains the bounded resources and required injected clock.
type MemoryConfig struct {
	Limits Limits
	Clock  Clock
}

// MemoryStore is a deterministic bounded heap-expiring replay provider.
type MemoryStore struct {
	state *memoryStoreState
}

// memoryStoreState owns mutable replay entries behind one format-safe handle.
type memoryStoreState struct {
	gate       *lifecycleGate
	clock      Clock
	limits     Limits
	token      chan struct{}
	waitMu     sync.Mutex
	waiters    int
	entries    map[[storageKeyByteLength]byte]*memoryEntry
	expiries   expiryHeap
	lastNow    time.Time
	closeOnce  sync.Once
	clearCount int

	afterToken            chan struct{}
	continueAfterToken    chan struct{}
	afterMutation         chan struct{}
	continueAfterMutation chan struct{}
}

// NewMemoryStore validates and constructs one bounded memory replay provider.
func NewMemoryStore(config MemoryConfig) (*MemoryStore, error) {
	if nilInterface(config.Clock) {
		return nil, NewError(ErrorCodeMisconfigured)
	}
	limits, err := ResolveLimits(config.Limits)
	if err != nil {
		return nil, err
	}
	store := &MemoryStore{
		state: &memoryStoreState{
			gate:     newLifecycleGate(StoreReady),
			clock:    config.Clock,
			limits:   limits,
			token:    make(chan struct{}, 1),
			entries:  make(map[[storageKeyByteLength]byte]*memoryEntry),
			expiries: make(expiryHeap, 0),
		},
	}
	store.state.token <- struct{}{}
	return store, nil
}

// CheckAndRemember atomically classifies and retains one protected replay key.
func (s *MemoryStore) CheckAndRemember(
	ctx context.Context,
	key Key,
	retention Retention,
) (check Check, resultErr error) {
	defer func() {
		if recover() != nil {
			check = 0
			resultErr = NewError(ErrorCodeInternalInvariant)
		}
	}()
	storage, err := s.validateCheckRequest(ctx, key, retention)
	if err != nil {
		return 0, err
	}
	if err := s.state.gate.admit(StoreReady); err != nil {
		return 0, err
	}
	defer s.state.gate.finish()

	if err := s.acquireToken(ctx); err != nil {
		return 0, err
	}
	defer s.releaseToken()

	now, expiry, err := s.captureOperationTime(ctx, retention)
	if err != nil {
		return 0, err
	}

	s.state.lastNow = now
	check, err = s.rememberStorageKey(storage, now, expiry)
	if err != nil {
		return 0, err
	}
	s.waitAfterMutation()
	return check, nil
}

// validateCheckRequest applies exact context, lifecycle, key, and retention precedence.
func (s *MemoryStore) validateCheckRequest(
	ctx context.Context,
	key Key,
	retention Retention,
) ([storageKeyByteLength]byte, error) {
	storage, err := s.validateKeyRequest(ctx, key)
	if err != nil {
		return [storageKeyByteLength]byte{}, err
	}
	if !retention.Valid() {
		return [storageKeyByteLength]byte{}, NewError(ErrorCodeInvalidRequest)
	}
	return storage, nil
}

// validateKeyRequest applies exact context, lifecycle, and key precedence.
func (s *MemoryStore) validateKeyRequest(ctx context.Context, key Key) ([storageKeyByteLength]byte, error) {
	if err := PreflightContext(ctx); err != nil {
		return [storageKeyByteLength]byte{}, err
	}
	if s == nil || s.state == nil || s.state.gate == nil {
		return [storageKeyByteLength]byte{}, NewError(ErrorCodeMisconfigured)
	}
	switch s.state.gate.State() {
	case StoreClosing, StoreClosed:
		return [storageKeyByteLength]byte{}, NewError(ErrorCodeClosed)
	case StoreReady, StoreDegraded:
	default:
		return [storageKeyByteLength]byte{}, NewError(ErrorCodeInternalInvariant)
	}
	storage, present := key.storageValue()
	if !present || !validStorageKey(key) {
		return [storageKeyByteLength]byte{}, NewError(ErrorCodeInvalidRequest)
	}
	return storage, nil
}

// captureOperationTime rechecks admission state and derives one authoritative expiry.
func (s *MemoryStore) captureOperationTime(
	ctx context.Context,
	retention Retention,
) (time.Time, time.Time, error) {
	now, err := s.captureOperationNow(ctx)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	expiry, err := retention.AddTo(now)
	if err != nil {
		s.state.gate.degrade()
		return time.Time{}, time.Time{}, NewError(ErrorCodeInternalInvariant)
	}
	if err := PreflightContext(ctx); err != nil {
		return time.Time{}, time.Time{}, err
	}
	return now, expiry, nil
}

// captureOperationNow rechecks admission state and reads one monotone operation time.
func (s *MemoryStore) captureOperationNow(ctx context.Context) (time.Time, error) {
	if s.state.afterToken != nil {
		close(s.state.afterToken)
	}
	if s.state.continueAfterToken != nil {
		<-s.state.continueAfterToken
	}
	if err := PreflightContext(ctx); err != nil {
		return time.Time{}, err
	}
	switch s.state.gate.State() {
	case StoreReady:
	case StoreClosing, StoreClosed:
		return time.Time{}, NewError(ErrorCodeClosed)
	default:
		return time.Time{}, NewError(ErrorCodeInternalInvariant)
	}
	now, err := readClock(s.state.clock)
	if err != nil || now.IsZero() || !s.state.lastNow.IsZero() && now.Before(s.state.lastNow) {
		s.state.gate.degrade()
		return time.Time{}, NewError(ErrorCodeInternalInvariant)
	}
	return now, nil
}

// rememberStorageKey applies bounded pruning and one atomic replay classification.
func (s *MemoryStore) rememberStorageKey(
	storage [storageKeyByteLength]byte,
	now time.Time,
	expiry time.Time,
) (Check, error) {
	existing, err := s.liveEntry(storage, now, entryFirstSeen)
	if err != nil {
		return 0, err
	}
	if existing != nil {
		return CheckReplayed, nil
	}
	if _, err := s.insertEntry(storage, expiry, entryFirstSeen); err != nil {
		return 0, err
	}
	return CheckFirstSeen, nil
}

// ReservePropagation atomically inserts or refreshes one pending propagation
// coordinate. A live lease is reported as pending, a committed coordinate as
// committed, and an absent coordinate or an expired lease becomes pending
// with a fresh lease and a fresh retention.
func (s *MemoryStore) ReservePropagation(
	ctx context.Context,
	key Key,
	retention Retention,
	lease Lease,
) (reservation PropagationReservation, resultErr error) {
	defer func() {
		if recover() != nil {
			reservation = 0
			resultErr = NewError(ErrorCodeInternalInvariant)
		}
	}()
	storage, err := s.validateCheckRequest(ctx, key, retention)
	if err != nil {
		return 0, err
	}
	if !lease.Valid() {
		return 0, NewError(ErrorCodeInvalidRequest)
	}
	if err := s.state.gate.admit(StoreReady); err != nil {
		return 0, err
	}
	defer s.state.gate.finish()
	if err := s.acquireToken(ctx); err != nil {
		return 0, err
	}
	defer s.releaseToken()
	now, expiry, err := s.captureOperationTime(ctx, retention)
	if err != nil {
		return 0, err
	}
	leaseExpiry := now.Add(lease.Duration())
	if !leaseExpiry.After(now) {
		s.state.gate.degrade()
		return 0, NewError(ErrorCodeInternalInvariant)
	}
	s.state.lastNow = now
	reservation, err = s.reservePropagationKey(storage, now, expiry, leaseExpiry)
	if err != nil {
		return 0, err
	}
	s.waitAfterMutation()
	return reservation, nil
}

// reservePropagationKey applies the insert-if-absent and expired-lease refresh rules.
func (s *MemoryStore) reservePropagationKey(
	storage [storageKeyByteLength]byte,
	now time.Time,
	expiry time.Time,
	leaseExpiry time.Time,
) (PropagationReservation, error) {
	existing, err := s.liveEntry(storage, now, entryPropagation)
	if err != nil {
		return 0, err
	}
	if existing == nil {
		entry, insertErr := s.insertEntry(storage, expiry, entryPropagation)
		if insertErr != nil {
			return 0, insertErr
		}
		entry.propagation = PropagationStatePending
		entry.lease = leaseExpiry
		return PropagationReserved, nil
	}
	if existing.propagation == PropagationStateCommitted {
		return PropagationAlreadyCommitted, nil
	}
	if existing.lease.After(now) {
		return PropagationPending, nil
	}
	existing.lease = leaseExpiry
	existing.expiry = expiry
	heap.Fix(&s.state.expiries, existing.index)
	return PropagationReserved, nil
}

// CommitPropagation moves one pending propagation coordinate to committed by
// compare-and-set. A committed coordinate stays committed; an absent or
// expired coordinate is unknown.
func (s *MemoryStore) CommitPropagation(ctx context.Context, key Key) (commit PropagationCommit, resultErr error) {
	defer func() {
		if recover() != nil {
			commit = 0
			resultErr = NewError(ErrorCodeInternalInvariant)
		}
	}()
	storage, err := s.validateKeyRequest(ctx, key)
	if err != nil {
		return 0, err
	}
	if err := s.state.gate.admit(StoreReady); err != nil {
		return 0, err
	}
	defer s.state.gate.finish()
	if err := s.acquireToken(ctx); err != nil {
		return 0, err
	}
	defer s.releaseToken()
	now, err := s.captureOperationNow(ctx)
	if err != nil {
		return 0, err
	}
	if err := PreflightContext(ctx); err != nil {
		return 0, err
	}
	s.state.lastNow = now
	existing, err := s.liveEntry(storage, now, entryPropagation)
	if err != nil {
		return 0, err
	}
	if existing == nil {
		return PropagationCommitUnresolved, nil
	}
	existing.propagation = PropagationStateCommitted
	existing.lease = time.Time{}
	s.waitAfterMutation()
	return PropagationCommitted, nil
}

// liveEntry prunes expired records and returns the live record of the
// requested kind, nil when absent, and a typed error when the record is
// expired but unprunable or belongs to the other record kind.
func (s *MemoryStore) liveEntry(storage [storageKeyByteLength]byte, now time.Time, kind entryKind) (*memoryEntry, error) {
	pruned := s.pruneExpired(now)
	existing, exists := s.state.entries[storage]
	if !exists {
		return nil, nil
	}
	if !existing.expiry.After(now) {
		if pruned >= s.state.limits.PruneBudget {
			return nil, NewError(ErrorCodeLimitExceeded)
		}
		return nil, NewError(ErrorCodeInternalInvariant)
	}
	if existing.kind != kind {
		return nil, NewError(ErrorCodeInconsistent)
	}
	return existing, nil
}

// insertEntry adds one record under the entry ceiling.
func (s *MemoryStore) insertEntry(storage [storageKeyByteLength]byte, expiry time.Time, kind entryKind) (*memoryEntry, error) {
	if len(s.state.entries) >= s.state.limits.MaxEntries {
		return nil, NewError(ErrorCodeLimitExceeded)
	}
	entry := &memoryEntry{key: storage, expiry: expiry, index: -1, kind: kind}
	s.state.entries[storage] = entry
	heap.Push(&s.state.expiries, entry)
	return entry, nil
}

// waitAfterMutation runs only the deterministic post-linearization test seam.
func (s *MemoryStore) waitAfterMutation() {
	if s.state.afterMutation != nil {
		close(s.state.afterMutation)
	}
	if s.state.continueAfterMutation != nil {
		<-s.state.continueAfterMutation
	}
}

// State returns one bounded lock-free lifecycle snapshot.
func (s *MemoryStore) State() StoreState {
	if s == nil || s.state == nil || s.state.gate == nil {
		return 0
	}
	return s.state.gate.State()
}

// Close publishes closing, drains admitted work, and clears retained state once.
func (s *MemoryStore) Close(ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = NewError(ErrorCodeInternalInvariant)
		}
	}()
	if err := PreflightContext(ctx); err != nil {
		return err
	}
	if s == nil || s.state == nil || s.state.gate == nil {
		return NewError(ErrorCodeMisconfigured)
	}
	drained, err := s.state.gate.beginClose()
	if err != nil {
		return err
	}
	if err := waitForDrain(ctx, drained); err != nil {
		return err
	}
	s.state.closeOnce.Do(func() {
		<-s.state.token
		clear(s.state.entries)
		for index := range s.state.expiries {
			s.state.expiries[index] = nil
		}
		s.state.expiries = nil
		s.state.lastNow = time.Time{}
		s.state.clearCount++
		s.state.token <- struct{}{}
	})
	return s.state.gate.publishClosed()
}

// String returns a constant representation without keys or provider state.
func (MemoryStore) String() string { return memoryStoreRedactedText }

// GoString returns a constant representation without keys or provider state.
func (MemoryStore) GoString() string { return memoryStoreRedactedText }

// Format prevents every formatting verb from exposing retained replay data.
func (MemoryStore) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, memoryStoreRedactedText)
}

// MarshalText rejects serialization of memory-provider state.
func (MemoryStore) MarshalText() ([]byte, error) {
	return nil, NewError(ErrorCodeInvalidRequest)
}

// MarshalJSON rejects serialization of memory-provider state.
func (MemoryStore) MarshalJSON() ([]byte, error) {
	return nil, NewError(ErrorCodeInvalidRequest)
}

// acquireToken enters the bounded context-aware serialization queue.
func (s *MemoryStore) acquireToken(ctx context.Context) error {
	select {
	case <-s.state.token:
		return nil
	default:
	}

	s.state.waitMu.Lock()
	if s.state.waiters >= s.state.limits.MaxWaiters {
		s.state.waitMu.Unlock()
		return NewError(ErrorCodeLimitExceeded)
	}
	s.state.waiters++
	s.state.waitMu.Unlock()
	defer func() {
		s.state.waitMu.Lock()
		s.state.waiters--
		s.state.waitMu.Unlock()
	}()

	done := ctx.Done()
	select {
	case <-s.state.token:
		return nil
	case <-done:
		if err := PreflightContext(ctx); err != nil {
			return err
		}
		return NewError(ErrorCodeInternalInvariant)
	}
}

// releaseToken leaves the short serialization critical section.
func (s *MemoryStore) releaseToken() { s.state.token <- struct{}{} }

// pruneExpired removes at most the configured number of expired heap roots.
func (s *MemoryStore) pruneExpired(now time.Time) int {
	pruned := 0
	for pruned < s.state.limits.PruneBudget && len(s.state.expiries) > 0 {
		entry := s.state.expiries[0]
		if entry.expiry.After(now) {
			break
		}
		removed := heap.Pop(&s.state.expiries).(*memoryEntry)
		delete(s.state.entries, removed.key)
		pruned++
	}
	return pruned
}

// readClock contains injected clock panic and returns no raw failure detail.
func readClock(clock Clock) (now time.Time, resultErr error) {
	defer func() {
		if recover() != nil {
			now = time.Time{}
			resultErr = NewError(ErrorCodeInternalInvariant)
		}
	}()
	return clock.Now(), nil
}

// entryKind separates ordinary first-seen records from propagation coordinates.
type entryKind uint8

const (
	// entryFirstSeen is an ordinary single-value replay record.
	entryFirstSeen entryKind = iota
	// entryPropagation is a two-phase propagation coordinate.
	entryPropagation
)

// memoryEntry is one one-to-one map and heap replay record.
type memoryEntry struct {
	key         [storageKeyByteLength]byte
	expiry      time.Time
	index       int
	kind        entryKind
	propagation PropagationState
	lease       time.Time
}

// expiryHeap orders entries by expiry and protected-key bytes.
type expiryHeap []*memoryEntry

// Len returns the number of heap entries.
func (h expiryHeap) Len() int { return len(h) }

// Less orders equal expiries deterministically without exposing key bytes.
func (h expiryHeap) Less(left, right int) bool {
	if h[left].expiry.Equal(h[right].expiry) {
		return bytes.Compare(h[left].key[:], h[right].key[:]) < 0
	}
	return h[left].expiry.Before(h[right].expiry)
}

// Swap exchanges two entries and maintains their exact heap indexes.
func (h expiryHeap) Swap(left, right int) {
	h[left], h[right] = h[right], h[left]
	h[left].index = left
	h[right].index = right
}

// Push adds one entry and records its exact heap index.
func (h *expiryHeap) Push(value any) {
	entry := value.(*memoryEntry)
	entry.index = len(*h)
	*h = append(*h, entry)
}

// Pop removes one entry and clears its heap ownership.
func (h *expiryHeap) Pop() any {
	old := *h
	last := len(old) - 1
	entry := old[last]
	old[last] = nil
	entry.index = -1
	*h = old[:last]
	return entry
}
