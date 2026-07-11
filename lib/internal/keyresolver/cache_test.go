package keyresolver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"math"
	"math/big"
	"sync/atomic"
	"testing"
	"time"
)

type fakeCacheClock struct{ now time.Time }

// Now returns deterministic injected cache time.
func (c *fakeCacheClock) Now() time.Time { return c.now }

// TestOutcomeCacheHitExactExpiryAndTTLRejection verifies trust lifetime boundaries.
func TestOutcomeCacheHitExactExpiryAndTTLRejection(t *testing.T) {
	clock := &fakeCacheClock{now: time.Unix(100, 0)}
	cache := newOutcomeCache(2, clock.Now)
	key := cacheKey{owner: resolverTestOwner, algorithm: AlgorithmEd25519SHA256}
	outcome := foundEdOutcome(0x42)
	if !cache.put(key, outcome, 10*time.Second) {
		t.Fatal("positive cache admission failed")
	}
	if got, hit, corrupt := cache.get(key); !hit || corrupt || got.Status() != KeyOutcomeFound {
		t.Fatalf("initial get = %q hit=%v corrupt=%v", got.Status(), hit, corrupt)
	}
	clock.now = clock.now.Add(10*time.Second - time.Nanosecond)
	if _, hit, _ := cache.get(key); !hit {
		t.Fatal("entry expired one tick early")
	}
	clock.now = clock.now.Add(time.Nanosecond)
	if _, hit, corrupt := cache.get(key); hit || corrupt {
		t.Fatalf("exact expiry hit=%v corrupt=%v", hit, corrupt)
	}

	for _, ttl := range []time.Duration{0, -1, time.Duration(math.MaxInt64)} {
		clock.now = time.Unix(100, 0)
		if cache.put(key, outcome, ttl) {
			t.Fatalf("ttl %v admitted", ttl)
		}
	}
	overflowClock := &fakeCacheClock{now: time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)}
	if newOutcomeCache(1, overflowClock.Now).put(key, outcome, time.Nanosecond) {
		t.Fatal("time overflow admitted")
	}
}

// TestOutcomeCacheAdmitsOnlyStableClosedStates verifies forbidden classification caching.
func TestOutcomeCacheAdmitsOnlyStableClosedStates(t *testing.T) {
	clock := &fakeCacheClock{now: time.Unix(100, 0)}
	cache := newOutcomeCache(16, clock.Now)
	for index, status := range []KeyOutcomeStatus{KeyOutcomeFound, KeyOutcomeMissing, KeyOutcomeRevoked, KeyOutcomeInvalid, KeyOutcomeAmbiguous, KeyOutcomeUnsupportedKeyType, KeyOutcomeAlgorithmMismatch} {
		outcome := newStatusOutcome(status, AlgorithmRSASHA256, newMetadata(false, false))
		if status == KeyOutcomeFound {
			outcome = foundEdOutcome(byte(index))
		}
		if !cache.put(cacheKey{owner: cacheOwner(byte('a' + index)), algorithm: outcome.Algorithm()}, outcome, time.Second) {
			t.Fatalf("stable status %q not admitted", status)
		}
	}
	for index, status := range []KeyOutcomeStatus{KeyOutcomeTemporary, KeyOutcomePermanent, KeyOutcomeProviderContract} {
		outcome := newStatusOutcome(status, AlgorithmRSASHA256, newMetadata(false, false))
		if cache.put(cacheKey{owner: cacheOwner(byte('x' + index)), algorithm: AlgorithmRSASHA256}, outcome, time.Second) {
			t.Fatalf("forbidden status %q admitted", status)
		}
	}
}

// TestOutcomeCacheLRUPromotionTieAndSequenceRenormalization verifies deterministic eviction.
func TestOutcomeCacheLRUPromotionTieAndSequenceRenormalization(t *testing.T) {
	clock := &fakeCacheClock{now: time.Unix(100, 0)}
	cache := newOutcomeCache(2, clock.Now)
	first := cacheKey{owner: cacheOwner('a'), algorithm: AlgorithmEd25519SHA256}
	second := cacheKey{owner: cacheOwner('b'), algorithm: AlgorithmEd25519SHA256}
	third := cacheKey{owner: cacheOwner('c'), algorithm: AlgorithmEd25519SHA256}
	cache.put(first, foundEdOutcome(1), time.Minute)
	cache.put(second, foundEdOutcome(2), time.Minute)
	cache.entries[cacheKey{owner: cacheOwner('z'), algorithm: AlgorithmRSASHA256}] = nil
	if _, hit, _ := cache.get(first); !hit {
		t.Fatal("promotion miss")
	}
	cache.sequence = math.MaxUint64
	cache.put(third, foundEdOutcome(3), time.Minute)
	if _, hit, _ := cache.get(second); hit {
		t.Fatal("least-recent equal-clock entry was not evicted")
	}
	if _, hit, _ := cache.get(first); !hit {
		t.Fatal("promoted entry was evicted")
	}
	if cache.sequence == 0 || cache.sequence == math.MaxUint64 {
		t.Fatalf("sequence was not renormalized: %d", cache.sequence)
	}
}

// TestOutcomeCacheSeparatesAlgorithmsClonesMutationAndRejectsCorruption verifies ownership and keying.
func TestOutcomeCacheSeparatesAlgorithmsClonesMutationAndRejectsCorruption(t *testing.T) {
	clock := &fakeCacheClock{now: time.Unix(100, 0)}
	cache := newOutcomeCache(3, clock.Now)
	rsaKey := cacheKey{owner: cacheOwner('s'), algorithm: AlgorithmRSASHA256}
	edKey := cacheKey{owner: cacheOwner('s'), algorithm: AlgorithmEd25519SHA256}
	edOutcome := foundEdOutcome(0x42)
	cache.put(edKey, edOutcome, time.Minute)
	edOutcome.material.(ed25519.PublicKey)[0] = 0x11
	cache.put(rsaKey, newStatusOutcome(KeyOutcomeMissing, AlgorithmRSASHA256, newMetadata(false, false)), time.Minute)
	got, hit, corrupt := cache.get(edKey)
	if !hit || corrupt {
		t.Fatal("Ed25519 cache miss")
	}
	material := got.Material().(ed25519.PublicKey)
	material[0] = 0x99
	if fresh := cacheMustMaterial(t, cache, edKey); fresh[0] != 0x42 {
		t.Fatal("cache accessor exposed mutable Ed25519 storage")
	}
	if got, hit, _ := cache.get(rsaKey); !hit || got.Status() != KeyOutcomeMissing {
		t.Fatal("algorithm-separated entry was overwritten")
	}

	rsaOutcome := KeyOutcome{status: KeyOutcomeFound, algorithm: AlgorithmRSASHA256, material: &rsa.PublicKey{N: big.NewInt(65539), E: 3}, metadata: newMetadata(false, false), initialized: true}
	cache.put(rsaKey, rsaOutcome, time.Minute)
	rsaOutcome.material.(*rsa.PublicKey).N.SetInt64(17)
	gotRSA, hit, corrupt := cache.get(rsaKey)
	if !hit || corrupt || gotRSA.Material().(*rsa.PublicKey).N.Cmp(big.NewInt(65539)) != 0 {
		t.Fatal("cache retained source RSA modulus")
	}
	gotRSA.Material().(*rsa.PublicKey).N.SetInt64(19)
	gotRSA, _, _ = cache.get(rsaKey)
	if gotRSA.Material().(*rsa.PublicKey).N.Cmp(big.NewInt(65539)) != 0 {
		t.Fatal("cache accessor exposed RSA modulus")
	}

	corruptKey := cacheKey{owner: cacheOwner('c'), algorithm: AlgorithmRSASHA256}
	cache.entries[corruptKey] = &cacheEntry{outcome: KeyOutcome{status: "future", initialized: true}, expiry: clock.now.Add(time.Minute)}
	if _, hit, corrupt := cache.get(corruptKey); hit || !corrupt {
		t.Fatalf("corrupted entry hit=%v corrupt=%v", hit, corrupt)
	}
	nilKey := cacheKey{owner: cacheOwner('n'), algorithm: AlgorithmRSASHA256}
	cache.entries[nilKey] = nil
	if _, hit, corrupt := cache.get(nilKey); hit || !corrupt {
		t.Fatalf("nil corrupted entry hit=%v corrupt=%v", hit, corrupt)
	}
}

// TestOutcomeCacheDisabledCapacityNeverStores verifies explicit cache disablement.
func TestOutcomeCacheDisabledCapacityNeverStores(t *testing.T) {
	clock := &fakeCacheClock{now: time.Unix(100, 0)}
	key := cacheKey{owner: cacheOwner('d'), algorithm: AlgorithmEd25519SHA256}
	for _, capacity := range []int{-1, 0, hardMaxCacheEntries + 1} {
		cache := newOutcomeCache(capacity, clock.Now)
		if cache.put(key, foundEdOutcome(1), time.Minute) {
			t.Fatalf("capacity %d admitted entry", capacity)
		}
		if _, hit, corrupt := cache.get(key); hit || corrupt {
			t.Fatalf("capacity %d get hit=%v corrupt=%v", capacity, hit, corrupt)
		}
	}
}

// TestOutcomeCachePutPurgesNilAndExpiredEntriesBeforeEviction verifies maintenance safety.
func TestOutcomeCachePutPurgesNilAndExpiredEntriesBeforeEviction(t *testing.T) {
	clock := &fakeCacheClock{now: time.Unix(100, 0)}
	cache := newOutcomeCache(2, clock.Now)
	nilKey := cacheKey{owner: cacheOwner('n'), algorithm: AlgorithmEd25519SHA256}
	cache.entries[nilKey] = nil
	if !cache.put(nilKey, foundEdOutcome(1), time.Minute) {
		t.Fatal("same-key nil corruption was not safely replaced")
	}

	live := cacheKey{owner: cacheOwner('l'), algorithm: AlgorithmEd25519SHA256}
	expired := cacheKey{owner: cacheOwner('x'), algorithm: AlgorithmEd25519SHA256}
	inserted := cacheKey{owner: cacheOwner('i'), algorithm: AlgorithmEd25519SHA256}
	cache = newOutcomeCache(2, clock.Now)
	cache.put(live, foundEdOutcome(1), 10*time.Minute)
	cache.put(expired, foundEdOutcome(2), time.Minute)
	clock.now = clock.now.Add(2 * time.Minute)
	cache.put(inserted, foundEdOutcome(3), time.Minute)
	if _, hit, _ := cache.get(live); !hit {
		t.Fatal("live LRU was evicted instead of expired entry")
	}
	if _, hit, _ := cache.get(expired); hit {
		t.Fatal("expired entry survived capacity maintenance")
	}
	if _, hit, _ := cache.get(inserted); !hit {
		t.Fatal("new entry missing after expired purge")
	}
}

// TestOutcomeCacheRejectsMalformedKeysAndImpossibleMetadata verifies cache contract admission.
func TestOutcomeCacheRejectsMalformedKeysAndImpossibleMetadata(t *testing.T) {
	clock := &fakeCacheClock{now: time.Unix(100, 0)}
	cache := newOutcomeCache(4, clock.Now)
	for _, owner := range []string{"relative", "bad_name._domainkey.example.test.", "a._domainkey." + string(make([]byte, 254)) + "."} {
		if cache.put(cacheKey{owner: owner, algorithm: AlgorithmRSASHA256}, newStatusOutcome(KeyOutcomeMissing, AlgorithmRSASHA256, newMetadata(false, false)), time.Minute) {
			t.Fatalf("malformed owner admitted")
		}
	}
	badMetadata := newStatusOutcome(KeyOutcomeMissing, AlgorithmRSASHA256, newMetadata(true, false))
	if cache.put(cacheKey{owner: cacheOwner('m'), algorithm: AlgorithmRSASHA256}, badMetadata, time.Minute) {
		t.Fatal("missing outcome with record metadata admitted")
	}
}

// TestResolverCacheUsesExactPositiveNegativeAndStableTTLProvenance verifies TTL classes and caps.
func TestResolverCacheUsesExactPositiveNegativeAndStableTTLProvenance(t *testing.T) {
	edPayload := []byte("v=DKIM1; k=ed25519; p=" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	tests := []struct {
		name      string
		lookup    LookupResult
		algorithm Algorithm
		expires   time.Duration
		status    KeyOutcomeStatus
	}{
		{name: "positive clamped", lookup: cacheFoundLookup(t, edPayload, 2*time.Hour), algorithm: AlgorithmEd25519SHA256, expires: time.Hour, status: KeyOutcomeFound},
		{name: "positive supplied", lookup: cacheFoundLookup(t, edPayload, 30*time.Second), algorithm: AlgorithmEd25519SHA256, expires: 30 * time.Second, status: KeyOutcomeFound},
		{name: "negative nodata clamped", lookup: cacheAbsentClassLookup(t, AbsenceNODATA, 10*time.Minute), algorithm: AlgorithmRSASHA256, expires: 5 * time.Minute, status: KeyOutcomeMissing},
		{name: "negative nxdomain supplied", lookup: cacheAbsentClassLookup(t, AbsenceNXDOMAIN, 30*time.Second), algorithm: AlgorithmRSASHA256, expires: 30 * time.Second, status: KeyOutcomeMissing},
		{name: "invalid supplied", lookup: cacheFoundLookup(t, []byte("v=DKIM1; p=%%%"), 30*time.Second), algorithm: AlgorithmRSASHA256, expires: 30 * time.Second, status: KeyOutcomeInvalid},
		{name: "revoked stable state", lookup: cacheFoundLookup(t, []byte("v=DKIM1; p="), 10*time.Minute), algorithm: AlgorithmRSASHA256, expires: time.Minute, status: KeyOutcomeRevoked},
		{name: "ambiguous", lookup: cacheAmbiguousLookup(t, 10*time.Minute), algorithm: AlgorithmRSASHA256, expires: time.Minute, status: KeyOutcomeAmbiguous},
		{name: "unsupported", lookup: cacheFoundLookup(t, []byte("v=DKIM1; k=future; p=QQ=="), 10*time.Minute), algorithm: AlgorithmRSASHA256, expires: time.Minute, status: KeyOutcomeUnsupportedKeyType},
		{name: "mismatch", lookup: cacheFoundLookup(t, edPayload, 10*time.Minute), algorithm: AlgorithmRSASHA256, expires: time.Minute, status: KeyOutcomeAlgorithmMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := &fakeCacheClock{now: time.Unix(100, 0)}
			var calls atomic.Int32
			resolver, err := NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) {
				calls.Add(1)
				return tt.lookup, nil
			}), DefaultLimits(), WithResolverClock(clock.Now))
			if err != nil {
				t.Fatal(err)
			}
			for index := 0; index < 2; index++ {
				outcome, resolveErr := resolver.Resolve(context.Background(), "example.test", testSelector, tt.algorithm)
				if resolveErr != nil || outcome.Status() != tt.status {
					t.Fatalf("Resolve() = %q/%v", outcome.Status(), resolveErr)
				}
			}
			if calls.Load() != 1 {
				t.Fatalf("pre-expiry calls = %d", calls.Load())
			}
			clock.now = clock.now.Add(tt.expires)
			if _, err := resolver.Resolve(context.Background(), "example.test", testSelector, tt.algorithm); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 2 {
				t.Fatalf("exact-expiry calls = %d", calls.Load())
			}
		})
	}
}

// TestResolverCancellationDuringCacheAdmissionForcesTemporary verifies final worker-context ownership.
func TestResolverCancellationDuringCacheAdmissionForcesTemporary(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	base := time.Unix(100, 0)
	var clockCalls atomic.Int32
	clock := func() time.Time {
		if clockCalls.Add(1) == 2 {
			cancelParent()
		}
		return base
	}
	edPayload := []byte("v=DKIM1; k=ed25519; p=" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	resolver, err := NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) {
		return cacheFoundLookup(t, edPayload, time.Minute), nil
	}), DefaultLimits(), WithResolverClock(clock), WithResolverParentContext(parent))
	if err != nil {
		t.Fatal(err)
	}
	outcome, resolveErr := resolver.Resolve(context.Background(), "example.test", testSelector, AlgorithmEd25519SHA256)
	if resolveErr != nil || outcome.Status() != KeyOutcomeTemporary || outcome.Material() != nil {
		t.Fatalf("Resolve() = %q material=%T error=%v", outcome.Status(), outcome.Material(), resolveErr)
	}
	key := cacheKey{owner: resolverTestOwner, algorithm: AlgorithmEd25519SHA256}
	if _, hit, corrupt := resolver.cache.get(key); hit || corrupt {
		t.Fatalf("canceled admission hit=%v corrupt=%v", hit, corrupt)
	}
}

// TestResolverSoleWaiterCancellationDuringPrepareCannotCacheOrDeleteReplacement verifies publication ownership.
func TestResolverSoleWaiterCancellationDuringPrepareCannotCacheOrDeleteReplacement(t *testing.T) {
	base := time.Unix(100, 0)
	prepareEntered := make(chan struct{})
	releaseOldPrepare := make(chan struct{})
	var clockCalls atomic.Int32
	clock := func() time.Time {
		if clockCalls.Add(1) == 2 {
			close(prepareEntered)
			<-releaseOldPrepare
		}
		return base
	}
	edPayload := []byte("v=DKIM1; k=ed25519; p=" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	lookup := cacheFoundLookup(t, edPayload, time.Minute)
	var transportCalls atomic.Int32
	resolver, err := NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) {
		transportCalls.Add(1)
		return lookup, nil
	}), DefaultLimits(), WithResolverClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, resolveErr := resolver.Resolve(ctx, "example.test", testSelector, AlgorithmEd25519SHA256)
		firstDone <- resolveErr
	}()
	<-prepareEntered
	cancel()
	select {
	case <-firstDone:
		t.Fatal("sole waiter detached while its canceled flight was still preparing publication")
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseOldPrepare)
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("sole waiter error = %v", err)
	}

	replacementDone := make(chan error, 1)
	go func() {
		outcome, resolveErr := resolver.Resolve(context.Background(), "example.test", testSelector, AlgorithmEd25519SHA256)
		if resolveErr == nil && outcome.Status() != KeyOutcomeFound {
			resolveErr = errors.New("replacement did not find key")
		}
		replacementDone <- resolveErr
	}()
	if err := <-replacementDone; err != nil {
		t.Fatal(err)
	}
	waitForFlightCleanup(t, resolver.flights)
	if _, resolveErr := resolver.Resolve(context.Background(), "example.test", testSelector, AlgorithmEd25519SHA256); resolveErr != nil {
		t.Fatal(resolveErr)
	}
	if transportCalls.Load() != 2 {
		t.Fatalf("transport calls = %d, canceled old flight altered replacement cache", transportCalls.Load())
	}
}

// TestResolverCacheRejectsZeroAbsurdTemporaryAndContractLifetimes verifies forbidden admission.
func TestResolverCacheRejectsZeroAbsurdTemporaryAndContractLifetimes(t *testing.T) {
	edPayload := []byte("v=DKIM1; k=ed25519; p=" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	tests := []struct {
		name   string
		result LookupResult
		err    error
	}{
		{name: "zero positive", result: cacheFoundLookup(t, edPayload, 0)},
		{name: "zero negative", result: cacheAbsentLookup(t, 0)},
		{name: "absurd positive", result: cacheFoundLookup(t, edPayload, time.Duration(math.MaxInt64))},
		{name: "temporary", err: NewTransportError(TransportErrorTemporary)},
		{name: "provider contract", err: errors.New("SECRET-MARKER")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			resolver, err := NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) {
				calls.Add(1)
				return tt.result, tt.err
			}), DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			for index := 0; index < 2; index++ {
				if _, resolveErr := resolver.Resolve(context.Background(), "example.test", testSelector, AlgorithmEd25519SHA256); resolveErr != nil {
					t.Fatal(resolveErr)
				}
			}
			if calls.Load() != 2 {
				t.Fatalf("calls = %d, want no cache", calls.Load())
			}
		})
	}
}

// TestResolverCacheAnchorsExpiryAndAdmitsOnceBeforeFlightPublication verifies no trust extension or miss window.
func TestResolverCacheAnchorsExpiryAndAdmitsOnceBeforeFlightPublication(t *testing.T) {
	base := time.Unix(100, 0)
	var clockCalls atomic.Int32
	clock := func() time.Time {
		if clockCalls.Add(1)%2 == 1 {
			return base
		}
		return base.Add(2 * time.Minute)
	}
	lookup := cacheAbsentLookup(t, time.Minute)
	var transportCalls atomic.Int32
	resolver, err := NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) {
		transportCalls.Add(1)
		return lookup, nil
	}), DefaultLimits(), WithResolverClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		if _, resolveErr := resolver.Resolve(context.Background(), "example.test", testSelector, AlgorithmRSASHA256); resolveErr != nil {
			t.Fatal(resolveErr)
		}
	}
	if transportCalls.Load() != 2 {
		t.Fatalf("expired-before-admission calls = %d", transportCalls.Load())
	}

	stableClock := &fakeCacheClock{now: base}
	transportCalls.Store(0)
	clockCalls.Store(0)
	entered := make(chan struct{})
	release := make(chan struct{})
	resolver, err = NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) {
		transportCalls.Add(1)
		close(entered)
		<-release
		return lookup, nil
	}), DefaultLimits(), WithResolverClock(func() time.Time {
		clockCalls.Add(1)
		return stableClock.now
	}))
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for index := 0; index < 2; index++ {
		go func() {
			_, resolveErr := resolver.Resolve(context.Background(), "example.test", testSelector, AlgorithmRSASHA256)
			results <- resolveErr
		}()
		if index == 0 {
			<-entered
		}
	}
	key := cacheKey{owner: resolverTestOwner, algorithm: AlgorithmRSASHA256}
	waitForFlightWaiters(t, resolver.flights, key, 2)
	close(release)
	for index := 0; index < 2; index++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if transportCalls.Load() != 1 || clockCalls.Load() != 2 {
		t.Fatalf("flight transport/clock calls = %d/%d", transportCalls.Load(), clockCalls.Load())
	}
	if _, err := resolver.Resolve(context.Background(), "example.test", testSelector, AlgorithmRSASHA256); err != nil {
		t.Fatal(err)
	}
	if transportCalls.Load() != 1 {
		t.Fatalf("post-flight caller opened miss window: calls=%d", transportCalls.Load())
	}
}

// cacheFoundLookup constructs one found lookup with explicit positive TTL.
func cacheFoundLookup(t *testing.T, payload []byte, ttl time.Duration) LookupResult {
	t.Helper()
	result, err := NewFoundResult([][]byte{payload}, ttl, DNSSECStatusUnavailable)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// cacheAbsentLookup constructs authoritative absence with explicit negative TTL.
func cacheAbsentLookup(t *testing.T, ttl time.Duration) LookupResult {
	return cacheAbsentClassLookup(t, AbsenceNODATA, ttl)
}

// cacheAbsentClassLookup constructs one selected authoritative absence class.
func cacheAbsentClassLookup(t *testing.T, class AbsenceClass, ttl time.Duration) LookupResult {
	t.Helper()
	result, err := NewAbsentResult(class, ttl, DNSSECStatusUnavailable)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// cacheAmbiguousLookup constructs count-only ambiguity with explicit positive TTL.
func cacheAmbiguousLookup(t *testing.T, ttl time.Duration) LookupResult {
	t.Helper()
	result, err := NewAmbiguousResult(2, ttl, DNSSECStatusUnavailable)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// foundEdOutcome constructs a detached valid Ed25519 cache fixture.
func foundEdOutcome(value byte) KeyOutcome {
	return KeyOutcome{
		status: KeyOutcomeFound, algorithm: AlgorithmEd25519SHA256,
		material: ed25519.PublicKey(bytes.Repeat([]byte{value}, ed25519.PublicKeySize)),
		metadata: newMetadata(true, true), initialized: true,
	}
}

// cacheMustMaterial returns cached Ed25519 material for ownership assertions.
func cacheMustMaterial(t *testing.T, cache *outcomeCache, key cacheKey) ed25519.PublicKey {
	t.Helper()
	outcome, hit, corrupt := cache.get(key)
	if !hit || corrupt {
		t.Fatalf("cache get hit=%v corrupt=%v", hit, corrupt)
	}
	return outcome.Material().(ed25519.PublicKey)
}

// cacheOwner constructs one canonical bounded internal cache owner.
func cacheOwner(selector byte) string {
	return string([]byte{selector}) + "._domainkey.example.test."
}
