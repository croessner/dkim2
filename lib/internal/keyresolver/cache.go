package keyresolver

import (
	"sort"
	"sync"
	"time"
)

type cacheKey struct {
	owner     string
	algorithm Algorithm
}

type cacheEntry struct {
	outcome  KeyOutcome
	expiry   time.Time
	lastUsed time.Time
	sequence uint64
}

type cacheAdmission struct {
	key     cacheKey
	outcome KeyOutcome
	expiry  time.Time
	now     time.Time
}

// outcomeCache owns a bounded deterministic TTL/LRU result cache.
type outcomeCache struct {
	mu       sync.Mutex
	entries  map[cacheKey]*cacheEntry
	capacity int
	clock    func() time.Time
	sequence uint64
}

// newOutcomeCache constructs an instance-owned cache using injected time.
func newOutcomeCache(capacity int, clock func() time.Time) *outcomeCache {
	if capacity < 0 || capacity > hardMaxCacheEntries {
		capacity = 0
	}
	return &outcomeCache{entries: make(map[cacheKey]*cacheEntry, capacity), capacity: capacity, clock: clock}
}

// get returns a detached live entry or reports detected internal corruption.
func (c *outcomeCache) get(key cacheKey) (KeyOutcome, bool, bool) {
	if c == nil || c.capacity == 0 || c.clock == nil {
		return KeyOutcome{}, false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return KeyOutcome{}, false, false
	}
	if entry == nil {
		delete(c.entries, key)
		return KeyOutcome{}, false, true
	}
	now := c.clock()
	if !cacheKeyValid(key) || !cacheOutcomeValidForKey(entry.outcome, key) || entry.expiry.IsZero() {
		delete(c.entries, key)
		return KeyOutcome{}, false, true
	}
	if !now.Before(entry.expiry) {
		delete(c.entries, key)
		return KeyOutcome{}, false, false
	}
	entry.lastUsed = now
	entry.sequence = c.nextSequenceLocked()
	return cloneKeyOutcome(entry.outcome), true, false
}

// put stores a detached stable outcome only for a bounded trustworthy lifetime.
func (c *outcomeCache) put(key cacheKey, outcome KeyOutcome, ttl time.Duration) bool {
	if c == nil || c.capacity == 0 || c.clock == nil || ttl <= 0 || ttl > 24*time.Hour ||
		!cacheKeyValid(key) || !cacheOutcomeValidForKey(outcome, key) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	expiry := now.Add(ttl)
	if !expiry.After(now) || expiry.Year() > 9999 {
		return false
	}
	return c.putLocked(key, cloneKeyOutcome(outcome), expiry, now)
}

// prepareAdmission validates and clones cache state without making it visible.
func (c *outcomeCache) prepareAdmission(key cacheKey, outcome KeyOutcome, expiry time.Time) (cacheAdmission, bool) {
	if c == nil || c.capacity == 0 || c.clock == nil || expiry.IsZero() ||
		!cacheKeyValid(key) || !cacheOutcomeValidForKey(outcome, key) {
		return cacheAdmission{}, false
	}
	now := c.clock()
	if !expiry.After(now) || expiry.Year() > 9999 {
		return cacheAdmission{}, false
	}
	return cacheAdmission{key: key, outcome: cloneKeyOutcome(outcome), expiry: expiry, now: now}, true
}

// commitAdmission makes one prepared entry visible without invoking external callbacks.
func (c *outcomeCache) commitAdmission(admission cacheAdmission) bool {
	if c == nil || !cacheKeyValid(admission.key) || !cacheOutcomeValidForKey(admission.outcome, admission.key) ||
		admission.expiry.IsZero() || !admission.expiry.After(admission.now) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.putLocked(admission.key, admission.outcome, admission.expiry, admission.now)
}

// putLocked inserts or replaces one already-cloned live entry.
func (c *outcomeCache) putLocked(key cacheKey, outcome KeyOutcome, expiry, now time.Time) bool {
	c.purgeInvalidOrExpiredLocked(now)
	sequence := c.nextSequenceLocked()
	if existing, ok := c.entries[key]; ok {
		existing.outcome = outcome
		existing.expiry = expiry
		existing.lastUsed = now
		existing.sequence = sequence
		return true
	}
	if len(c.entries) >= c.capacity {
		c.evictLeastRecentLocked()
	}
	c.entries[key] = &cacheEntry{
		outcome: outcome, expiry: expiry,
		lastUsed: now, sequence: sequence,
	}
	return true
}

// purgeInvalidOrExpiredLocked removes unusable entries before capacity decisions.
func (c *outcomeCache) purgeInvalidOrExpiredLocked(now time.Time) {
	for key, entry := range c.entries {
		if entry == nil || !cacheKeyValid(key) || !cacheOutcomeValidForKey(entry.outcome, key) ||
			entry.expiry.IsZero() || !now.Before(entry.expiry) {
			delete(c.entries, key)
		}
	}
}

// nextSequenceLocked advances recency order and renormalizes before overflow.
func (c *outcomeCache) nextSequenceLocked() uint64 {
	if c.sequence == ^uint64(0) {
		c.renormalizeLocked()
	}
	c.sequence++
	return c.sequence
}

// renormalizeLocked compacts recency order while preserving deterministic ties.
func (c *outcomeCache) renormalizeLocked() {
	entries := make([]*cacheEntry, 0, len(c.entries))
	for key, entry := range c.entries {
		if entry == nil || !cacheKeyValid(key) || !cacheOutcomeValidForKey(entry.outcome, key) || entry.expiry.IsZero() {
			delete(c.entries, key)
			continue
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(left, right int) bool {
		if entries[left].lastUsed.Equal(entries[right].lastUsed) {
			return entries[left].sequence < entries[right].sequence
		}
		return entries[left].lastUsed.Before(entries[right].lastUsed)
	})
	for index, entry := range entries {
		entry.sequence = uint64(index + 1)
	}
	c.sequence = uint64(len(entries))
}

// evictLeastRecentLocked removes the deterministic oldest entry.
func (c *outcomeCache) evictLeastRecentLocked() {
	var oldestKey cacheKey
	var oldest *cacheEntry
	for key, entry := range c.entries {
		if entry == nil || !cacheKeyValid(key) || !cacheOutcomeValidForKey(entry.outcome, key) || entry.expiry.IsZero() {
			delete(c.entries, key)
			continue
		}
		if oldest == nil || entry.lastUsed.Before(oldest.lastUsed) ||
			entry.lastUsed.Equal(oldest.lastUsed) && entry.sequence < oldest.sequence {
			oldestKey, oldest = key, entry
		}
	}
	if oldest != nil {
		delete(c.entries, oldestKey)
	}
}

// cacheKeyValid checks bounded internal key identity without exposing its value.
func cacheKeyValid(key cacheKey) bool {
	return ValidAbsoluteOwner(key.owner) && key.algorithm.Known()
}

// cacheOutcomeValidForKey validates admission and lookup state coherence.
func cacheOutcomeValidForKey(outcome KeyOutcome, key cacheKey) bool {
	if !outcome.Valid() || outcome.Algorithm() != key.algorithm {
		return false
	}
	switch outcome.Status() {
	case KeyOutcomeFound, KeyOutcomeMissing, KeyOutcomeRevoked, KeyOutcomeInvalid,
		KeyOutcomeAmbiguous, KeyOutcomeUnsupportedKeyType, KeyOutcomeAlgorithmMismatch:
		if (outcome.Status() == KeyOutcomeMissing || outcome.Status() == KeyOutcomeAmbiguous) &&
			(outcome.Metadata().TestingDeclared() || outcome.Metadata().StrictIdentityDeclared()) {
			return false
		}
		return true
	default:
		return false
	}
}

// cloneKeyOutcome returns detached key material and immutable metadata.
func cloneKeyOutcome(outcome KeyOutcome) KeyOutcome {
	if !outcome.Valid() {
		return KeyOutcome{}
	}
	return KeyOutcome{
		status: outcome.status, algorithm: outcome.algorithm,
		material: cloneKeyMaterial(outcome.material), metadata: outcome.metadata,
		initialized: true,
	}
}
