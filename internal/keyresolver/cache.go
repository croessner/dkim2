package keyresolver

import (
	"container/heap"
	"container/list"
	"sync"
	"time"
)

// cacheKey identifies one cached lookup. The owner grammar separates the
// selector-key and Domain Policy Record key spaces; a policy key carries no
// algorithm.
type cacheKey struct {
	owner     string
	algorithm Algorithm
}

// cacheValue holds the detached outcome of the kind the cache key names.
type cacheValue struct {
	key    KeyOutcome
	policy DomainPolicyOutcome
}

type cacheEntry struct {
	key         cacheKey
	outcome     KeyOutcome
	policy      DomainPolicyOutcome
	expiry      time.Time
	recency     *list.Element
	expiryIndex int
}

type expiryQueue []*cacheEntry

type cacheAdmission struct {
	key    cacheKey
	value  cacheValue
	expiry time.Time
	now    time.Time
}

// outcomeCache owns a bounded deterministic TTL/LRU result cache.
type outcomeCache struct {
	mu       sync.Mutex
	entries  map[cacheKey]*cacheEntry
	capacity int
	clock    func() time.Time
	recency  list.List
	expiries expiryQueue
}

// newOutcomeCache constructs an instance-owned cache using injected time.
func newOutcomeCache(capacity int, clock func() time.Time) *outcomeCache {
	if capacity < 0 || capacity > hardMaxCacheEntries {
		capacity = 0
	}
	return &outcomeCache{entries: make(map[cacheKey]*cacheEntry, capacity), capacity: capacity, clock: clock}
}

// get returns a detached live key entry or reports detected internal corruption.
func (c *outcomeCache) get(key cacheKey) (KeyOutcome, bool, bool) {
	value, hit, corrupt := c.lookup(key)
	return value.key, hit, corrupt
}

// getPolicy returns a detached live Domain Policy Record entry or reports
// detected internal corruption.
func (c *outcomeCache) getPolicy(key cacheKey) (DomainPolicyOutcome, bool, bool) {
	value, hit, corrupt := c.lookup(key)
	return value.policy, hit, corrupt
}

// lookup returns a detached live entry of either kind or reports detected internal corruption.
func (c *outcomeCache) lookup(key cacheKey) (cacheValue, bool, bool) {
	if c == nil || c.capacity == 0 || c.clock == nil {
		return cacheValue{}, false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return cacheValue{}, false, false
	}
	if entry == nil {
		delete(c.entries, key)
		return cacheValue{}, false, true
	}
	now := c.clock()
	value := cacheValue{key: entry.outcome, policy: entry.policy}
	if entry.key != key || !cacheKeyValid(key) || !cacheValueValidForKey(value, key) ||
		entry.expiry.IsZero() || entry.recency == nil {
		c.removeEntryLocked(key, entry)
		return cacheValue{}, false, true
	}
	if !now.Before(entry.expiry) {
		c.removeEntryLocked(key, entry)
		return cacheValue{}, false, false
	}
	c.recency.MoveToBack(entry.recency)
	return cloneCacheValue(value), true, false
}

// put stores a detached stable key outcome only for a bounded trustworthy lifetime.
func (c *outcomeCache) put(key cacheKey, outcome KeyOutcome, ttl time.Duration) bool {
	return c.putValue(key, cacheValue{key: outcome}, ttl)
}

// putValue stores a detached stable outcome of either kind only for a bounded trustworthy lifetime.
func (c *outcomeCache) putValue(key cacheKey, value cacheValue, ttl time.Duration) bool {
	if c == nil || c.capacity == 0 || c.clock == nil || ttl <= 0 || ttl > 24*time.Hour ||
		!cacheKeyValid(key) || !cacheValueValidForKey(value, key) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	expiry := now.Add(ttl)
	if !expiry.After(now) || expiry.Year() > 9999 {
		return false
	}
	return c.putLocked(key, cloneCacheValue(value), expiry, now)
}

// prepareAdmission validates and clones cache state without making it visible.
func (c *outcomeCache) prepareAdmission(key cacheKey, value cacheValue, expiry time.Time) (cacheAdmission, bool) {
	if c == nil || c.capacity == 0 || c.clock == nil || expiry.IsZero() ||
		!cacheKeyValid(key) || !cacheValueValidForKey(value, key) {
		return cacheAdmission{}, false
	}
	now := c.clock()
	if !expiry.After(now) || expiry.Year() > 9999 {
		return cacheAdmission{}, false
	}
	return cacheAdmission{key: key, value: cloneCacheValue(value), expiry: expiry, now: now}, true
}

// commitAdmission makes one prepared entry visible without invoking external callbacks.
func (c *outcomeCache) commitAdmission(admission cacheAdmission) bool {
	if c == nil || !cacheKeyValid(admission.key) || !cacheValueValidForKey(admission.value, admission.key) ||
		admission.expiry.IsZero() || !admission.expiry.After(admission.now) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.putLocked(admission.key, admission.value, admission.expiry, admission.now)
}

// putLocked inserts or replaces one already-cloned live entry.
func (c *outcomeCache) putLocked(key cacheKey, value cacheValue, expiry, now time.Time) bool {
	c.purgeExpiredLocked(now)
	if len(c.entries) != c.recency.Len() || len(c.entries) != len(c.expiries) {
		c.repairCorruptEntriesLocked()
	}
	if existing, ok := c.entries[key]; ok {
		if existing == nil || existing.key != key || existing.recency == nil {
			c.removeEntryLocked(key, existing)
		} else {
			existing.outcome = value.key
			existing.policy = value.policy
			existing.expiry = expiry
			c.recency.MoveToBack(existing.recency)
			if c.expiryEntryIndexed(existing) {
				heap.Fix(&c.expiries, existing.expiryIndex)
			} else {
				heap.Push(&c.expiries, existing)
			}
			return true
		}
	}
	if len(c.entries) >= c.capacity {
		c.evictLeastRecentLocked()
	}
	entry := &cacheEntry{key: key, outcome: value.key, policy: value.policy, expiry: expiry, expiryIndex: -1}
	entry.recency = c.recency.PushBack(entry)
	c.entries[key] = entry
	heap.Push(&c.expiries, entry)
	return true
}

// purgeExpiredLocked removes heap-indexed entries whose trustworthy lifetime ended.
func (c *outcomeCache) purgeExpiredLocked(now time.Time) {
	for len(c.expiries) > 0 && !now.Before(c.expiries[0].expiry) {
		entry := c.expiries[0]
		c.removeEntryLocked(entry.key, entry)
	}
}

// evictLeastRecentLocked removes the oldest live entry in constant time.
func (c *outcomeCache) evictLeastRecentLocked() {
	for oldest := c.recency.Front(); oldest != nil; oldest = c.recency.Front() {
		entry, ok := oldest.Value.(*cacheEntry)
		if !ok || entry == nil {
			c.recency.Remove(oldest)
			continue
		}
		c.removeEntryLocked(entry.key, entry)
		return
	}
	c.repairCorruptEntriesLocked()
}

// removeEntryLocked detaches one exact entry from all cache indexes.
func (c *outcomeCache) removeEntryLocked(key cacheKey, entry *cacheEntry) {
	if current, ok := c.entries[key]; ok && current == entry {
		delete(c.entries, key)
	}
	if entry == nil {
		return
	}
	if entry.recency != nil {
		c.recency.Remove(entry.recency)
		entry.recency = nil
	}
	if c.expiryEntryIndexed(entry) {
		heap.Remove(&c.expiries, entry.expiryIndex)
	}
}

// expiryEntryIndexed reports whether the heap index still identifies the exact entry.
func (c *outcomeCache) expiryEntryIndexed(entry *cacheEntry) bool {
	return entry != nil && entry.expiryIndex >= 0 && entry.expiryIndex < len(c.expiries) &&
		c.expiries[entry.expiryIndex] == entry
}

// repairCorruptEntriesLocked removes map-only corruption on an exceptional capacity path.
func (c *outcomeCache) repairCorruptEntriesLocked() {
	for key, entry := range c.entries {
		if entry == nil || entry.key != key || entry.recency == nil || !c.expiryEntryIndexed(entry) {
			c.removeEntryLocked(key, entry)
		}
	}
}

// Len returns the number of expiry-indexed entries.
func (q expiryQueue) Len() int { return len(q) }

// Less orders expiry first and uses owner plus algorithm for deterministic ties.
func (q expiryQueue) Less(left, right int) bool {
	if q[left].expiry.Equal(q[right].expiry) {
		if q[left].key.owner == q[right].key.owner {
			return q[left].key.algorithm < q[right].key.algorithm
		}
		return q[left].key.owner < q[right].key.owner
	}
	return q[left].expiry.Before(q[right].expiry)
}

// Swap exchanges heap entries and keeps their indexes coherent.
func (q expiryQueue) Swap(left, right int) {
	q[left], q[right] = q[right], q[left]
	q[left].expiryIndex = left
	q[right].expiryIndex = right
}

// Push appends one cache entry to the expiry heap.
func (q *expiryQueue) Push(value any) {
	entry := value.(*cacheEntry)
	entry.expiryIndex = len(*q)
	*q = append(*q, entry)
}

// Pop removes and detaches the last expiry heap entry.
func (q *expiryQueue) Pop() any {
	old := *q
	last := len(old) - 1
	entry := old[last]
	old[last] = nil
	entry.expiryIndex = -1
	*q = old[:last]
	return entry
}

// cacheKeyValid checks bounded internal key identity without exposing its
// value: a selector owner requires a known algorithm and a Domain Policy
// Record owner requires none.
func cacheKeyValid(key cacheKey) bool {
	kind, ok := ClassifyAbsoluteOwner(key.owner)
	if !ok {
		return false
	}
	if kind == OwnerKindDomainPolicy {
		return key.algorithm == ""
	}
	return key.algorithm.Known()
}

// cacheValueValidForKey validates that exactly the outcome of the key's kind
// is present and admissible.
func cacheValueValidForKey(value cacheValue, key cacheKey) bool {
	if OwnerKindDomainPolicy.ValidAbsoluteOwner(key.owner) {
		return value.key.IsZero() && value.policy.cacheable()
	}
	return value.policy == (DomainPolicyOutcome{}) && cacheOutcomeValidForKey(value.key, key)
}

// cloneCacheValue detaches key material; policy outcomes carry no references.
func cloneCacheValue(value cacheValue) cacheValue {
	return cacheValue{key: cloneKeyOutcome(value.key), policy: value.policy}
}

// cacheOutcomeValidForKey validates admission and lookup state coherence.
func cacheOutcomeValidForKey(outcome KeyOutcome, key cacheKey) bool {
	if !outcome.Valid() || outcome.Algorithm() != key.algorithm {
		return false
	}
	switch outcome.Status() {
	case KeyOutcomeFound, KeyOutcomeMissing, KeyOutcomeRevoked, KeyOutcomeInvalid,
		KeyOutcomeAmbiguous, KeyOutcomeUnsupportedKeyType, KeyOutcomeAlgorithmMismatch:
		return true
	default:
		return false
	}
}

// cloneKeyOutcome returns a detached copy of key material and outcome state.
func cloneKeyOutcome(outcome KeyOutcome) KeyOutcome {
	if !outcome.Valid() {
		return KeyOutcome{}
	}
	return KeyOutcome{
		status: outcome.status, algorithm: outcome.algorithm,
		material:    cloneKeyMaterial(outcome.material),
		initialized: true,
	}
}
