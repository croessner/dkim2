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
	gate       *lifecycleGate
	clock      Clock
	limits     Limits
	token      chan struct{}
	waitMu     sync.Mutex
	waiters    int
	entries    map[Key]*memoryEntry
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
		gate:     newLifecycleGate(StoreReady),
		clock:    config.Clock,
		limits:   limits,
		token:    make(chan struct{}, 1),
		entries:  make(map[Key]*memoryEntry),
		expiries: make(expiryHeap, 0),
	}
	store.token <- struct{}{}
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
	if err := PreflightContext(ctx); err != nil {
		return 0, err
	}
	if s == nil || s.gate == nil {
		return 0, NewError(ErrorCodeMisconfigured)
	}
	switch s.gate.State() {
	case StoreClosing, StoreClosed:
		return 0, NewError(ErrorCodeClosed)
	case StoreReady, StoreDegraded:
	default:
		return 0, NewError(ErrorCodeInternalInvariant)
	}
	if !validStorageKey(key) || !retention.Valid() {
		return 0, NewError(ErrorCodeInvalidRequest)
	}
	if err := s.gate.admit(StoreReady); err != nil {
		return 0, err
	}
	defer s.gate.finish()

	if err := s.acquireToken(ctx); err != nil {
		return 0, err
	}
	defer s.releaseToken()

	if s.afterToken != nil {
		close(s.afterToken)
	}
	if s.continueAfterToken != nil {
		<-s.continueAfterToken
	}
	if err := PreflightContext(ctx); err != nil {
		return 0, err
	}
	switch s.gate.State() {
	case StoreReady:
	case StoreClosing, StoreClosed:
		return 0, NewError(ErrorCodeClosed)
	case StoreDegraded:
		return 0, NewError(ErrorCodeInternalInvariant)
	default:
		return 0, NewError(ErrorCodeInternalInvariant)
	}

	now, err := readClock(s.clock)
	if err != nil || now.IsZero() || !s.lastNow.IsZero() && now.Before(s.lastNow) {
		s.gate.degrade()
		return 0, NewError(ErrorCodeInternalInvariant)
	}
	expiry, err := retention.AddTo(now)
	if err != nil {
		s.gate.degrade()
		return 0, NewError(ErrorCodeInternalInvariant)
	}
	if err := PreflightContext(ctx); err != nil {
		return 0, err
	}

	s.lastNow = now
	pruned := s.pruneExpired(now)
	if existing, exists := s.entries[key]; exists {
		if existing.expiry.After(now) {
			check = CheckReplayed
		} else if pruned >= s.limits.PruneBudget {
			return 0, NewError(ErrorCodeLimitExceeded)
		} else {
			return 0, NewError(ErrorCodeInternalInvariant)
		}
	} else if len(s.entries) >= s.limits.MaxEntries {
		return 0, NewError(ErrorCodeLimitExceeded)
	} else {
		entry := &memoryEntry{key: key, expiry: expiry, index: -1}
		s.entries[key] = entry
		heap.Push(&s.expiries, entry)
		check = CheckFirstSeen
	}

	if s.afterMutation != nil {
		close(s.afterMutation)
	}
	if s.continueAfterMutation != nil {
		<-s.continueAfterMutation
	}
	return check, nil
}

// State returns one bounded lock-free lifecycle snapshot.
func (s *MemoryStore) State() StoreState {
	if s == nil || s.gate == nil {
		return 0
	}
	return s.gate.State()
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
	if s == nil || s.gate == nil {
		return NewError(ErrorCodeMisconfigured)
	}
	drained, err := s.gate.beginClose()
	if err != nil {
		return err
	}
	if err := waitForDrain(ctx, drained); err != nil {
		return err
	}
	s.closeOnce.Do(func() {
		<-s.token
		clear(s.entries)
		for index := range s.expiries {
			s.expiries[index] = nil
		}
		s.expiries = nil
		s.lastNow = time.Time{}
		s.clearCount++
		s.token <- struct{}{}
	})
	return s.gate.publishClosed()
}

// String returns a constant representation without keys or provider state.
func (*MemoryStore) String() string { return memoryStoreRedactedText }

// GoString returns a constant representation without keys or provider state.
func (*MemoryStore) GoString() string { return memoryStoreRedactedText }

// Format prevents every formatting verb from exposing retained replay data.
func (*MemoryStore) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, memoryStoreRedactedText)
}

// MarshalText rejects serialization of memory-provider state.
func (*MemoryStore) MarshalText() ([]byte, error) {
	return nil, NewError(ErrorCodeInvalidRequest)
}

// MarshalJSON rejects serialization of memory-provider state.
func (*MemoryStore) MarshalJSON() ([]byte, error) {
	return nil, NewError(ErrorCodeInvalidRequest)
}

// acquireToken enters the bounded context-aware serialization queue.
func (s *MemoryStore) acquireToken(ctx context.Context) error {
	select {
	case <-s.token:
		return nil
	default:
	}

	s.waitMu.Lock()
	if s.waiters >= s.limits.MaxWaiters {
		s.waitMu.Unlock()
		return NewError(ErrorCodeLimitExceeded)
	}
	s.waiters++
	s.waitMu.Unlock()
	defer func() {
		s.waitMu.Lock()
		s.waiters--
		s.waitMu.Unlock()
	}()

	done := ctx.Done()
	select {
	case <-s.token:
		return nil
	case <-done:
		if err := PreflightContext(ctx); err != nil {
			return err
		}
		return NewError(ErrorCodeInternalInvariant)
	}
}

// releaseToken leaves the short serialization critical section.
func (s *MemoryStore) releaseToken() { s.token <- struct{}{} }

// pruneExpired removes at most the configured number of expired heap roots.
func (s *MemoryStore) pruneExpired(now time.Time) int {
	pruned := 0
	for pruned < s.limits.PruneBudget && len(s.expiries) > 0 {
		entry := s.expiries[0]
		if entry.expiry.After(now) {
			break
		}
		removed := heap.Pop(&s.expiries).(*memoryEntry)
		delete(s.entries, removed.key)
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

// memoryEntry is one one-to-one map and heap replay record.
type memoryEntry struct {
	key    Key
	expiry time.Time
	index  int
}

// expiryHeap orders entries by expiry and protected-key bytes.
type expiryHeap []*memoryEntry

// Len returns the number of heap entries.
func (h expiryHeap) Len() int { return len(h) }

// Less orders equal expiries deterministically without exposing key bytes.
func (h expiryHeap) Less(left, right int) bool {
	if h[left].expiry.Equal(h[right].expiry) {
		return bytes.Compare(h[left].key.storage[:], h[right].key.storage[:]) < 0
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
