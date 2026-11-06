package replay

import (
	"container/heap"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const privacyStoreMapKey = "store"

// TestMemoryStoreConstructorRejectsClockAndLimitMisconfiguration verifies exact construction bounds.
func TestMemoryStoreConstructorRejectsClockAndLimitMisconfiguration(t *testing.T) {
	if store, err := NewMemoryStore(MemoryConfig{}); store != nil || ErrorCodeOf(err) != ErrorCodeMisconfigured {
		t.Fatalf("nil clock constructor = %v, %v", store, err)
	}
	var nilFunction ClockFunc
	var nilPointer *testClock
	for _, clock := range []Clock{nilFunction, nilPointer} {
		if store, err := NewMemoryStore(MemoryConfig{Clock: clock}); store != nil ||
			ErrorCodeOf(err) != ErrorCodeMisconfigured {
			t.Fatalf("typed-nil %T constructor = %v, %v", clock, store, err)
		}
	}
	hard := HardLimits()
	for _, mutate := range []func(*Limits){
		func(l *Limits) { l.MaxEntries = -1 },
		func(l *Limits) { l.MaxEntries = hard.MaxEntries + 1 },
		func(l *Limits) { l.MaxWaiters = -1 },
		func(l *Limits) { l.MaxWaiters = hard.MaxWaiters + 1 },
		func(l *Limits) { l.PruneBudget = -1 },
		func(l *Limits) { l.PruneBudget = hard.PruneBudget + 1 },
	} {
		limits := DefaultLimits()
		mutate(&limits)
		if store, err := NewMemoryStore(MemoryConfig{Limits: limits, Clock: ClockFunc(time.Now)}); store != nil ||
			ErrorCodeOf(err) != ErrorCodeMisconfigured {
			t.Fatalf("invalid limits constructor = %v, %v", store, err)
		}
	}
	if store, err := NewMemoryStore(MemoryConfig{Clock: ClockFunc(time.Now)}); err != nil || store == nil {
		t.Fatalf("default limits constructor = %v, %v", store, err)
	}
}

// TestMemoryStoreValidationPrecedenceAndClockSuppression verifies every pre-admission refusal.
func TestMemoryStoreValidationPrecedenceAndClockSuppression(t *testing.T) {
	clock := &countingClock{now: time.Unix(1_700_000_000, 0)}
	store := newTestMemoryStore(t, Limits{MaxEntries: 1, MaxWaiters: 1, PruneBudget: 1}, clock)
	validKey := testReplayKey(1)
	validRetention := mustRetention(t, time.Second)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	deadline, stop := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer stop()
	tests := []struct {
		name      string
		ctx       context.Context
		key       Key
		retention Retention
		code      ErrorCode
	}{
		{"nil context", nil, validKey, validRetention, ErrorCodeInvalidRequest}, //nolint:staticcheck // Nil is the contract case under test.
		{"cancelled", cancelled, validKey, validRetention, ErrorCodeCancelled},
		{"deadline", deadline, validKey, validRetention, ErrorCodeDeadlineExceeded},
		{"invalid key", context.Background(), Key{}, validRetention, ErrorCodeInvalidRequest},
		{"invalid retention", context.Background(), validKey, Retention{}, ErrorCodeInvalidRequest},
	}
	for _, test := range tests {
		check, err := store.CheckAndRemember(test.ctx, test.key, test.retention)
		if check != 0 || ErrorCodeOf(err) != test.code {
			t.Fatalf("%s result = %s, %v", test.name, check, err)
		}
	}
	if clock.Calls() != 0 {
		t.Fatalf("pre-admission refusals called clock %d times", clock.Calls())
	}

	if err := store.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if check, err := store.CheckAndRemember(cancelled, Key{}, Retention{}); check != 0 || ErrorCodeOf(err) != ErrorCodeCancelled {
		t.Fatalf("terminal-over-closed check = %s, %v", check, err)
	}
	if check, err := store.CheckAndRemember(context.Background(), Key{}, Retention{}); check != 0 || ErrorCodeOf(err) != ErrorCodeClosed {
		t.Fatalf("closed-over-invalid check = %s, %v", check, err)
	}
	if err := store.Close(cancelled); ErrorCodeOf(err) != ErrorCodeCancelled {
		t.Fatalf("terminal closed Close() = %v", err)
	}
	if err := store.Close(nil); ErrorCodeOf(err) != ErrorCodeInvalidRequest { //nolint:staticcheck // Nil is the contract case under test.
		t.Fatalf("nil closed Close() = %v", err)
	}
	if clock.Calls() != 0 {
		t.Fatalf("closed refusals called clock %d times", clock.Calls())
	}
}

// TestMemoryStoreDegradedStatePreservesInputValidationPrecedence verifies enabled ordering.
func TestMemoryStoreDegradedStatePreservesInputValidationPrecedence(t *testing.T) {
	clock := &countingClock{now: time.Unix(1_700_000_000, 0)}
	store := newTestMemoryStore(t, Limits{MaxEntries: 1, MaxWaiters: 1, PruneBudget: 1}, clock)
	store.state.gate.degrade()
	validKey := testReplayKey(1)
	validRetention := mustRetention(t, time.Second)
	if check, err := store.CheckAndRemember(context.Background(), Key{}, validRetention); check != 0 ||
		ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("degraded invalid key = %s, %v", check, err)
	}
	if check, err := store.CheckAndRemember(context.Background(), validKey, Retention{}); check != 0 ||
		ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("degraded invalid retention = %s, %v", check, err)
	}
	if check, err := store.CheckAndRemember(context.Background(), validKey, validRetention); check != 0 ||
		ErrorCodeOf(err) != ErrorCodeInternalInvariant {
		t.Fatalf("degraded valid request = %s, %v", check, err)
	}
	if clock.Calls() != 0 {
		t.Fatalf("degraded requests called clock %d times", clock.Calls())
	}
}

// TestMemoryStoreFirstSeenReplayExpiryAndNoExtension verifies the observable memory contract.
func TestMemoryStoreFirstSeenReplayExpiryAndNoExtension(t *testing.T) {
	clock := newTestClock(time.Unix(1_700_000_000, 0))
	store := newTestMemoryStore(t, Limits{MaxEntries: 2, MaxWaiters: 2, PruneBudget: 2}, clock)
	key := testReplayKey(1)
	retention := mustRetention(t, time.Second)

	assertMemoryCheck(t, store, key, retention, CheckFirstSeen)
	assertMemoryInvariant(t, store)
	clock.Set(clock.Now().Add(900 * time.Millisecond))
	assertMemoryCheck(t, store, key, retention, CheckReplayed)
	assertMemoryInvariant(t, store)
	clock.Set(clock.Now().Add(100 * time.Millisecond))
	assertMemoryCheck(t, store, key, retention, CheckFirstSeen)

	if store.State() != StoreReady {
		t.Fatalf("memory state = %s", store.State())
	}
}

// TestMemoryStoreCapacityNeverEvictsUnexpiredEntries verifies the exact hard entry bound.
func TestMemoryStoreCapacityNeverEvictsUnexpiredEntries(t *testing.T) {
	clock := &countingClock{now: time.Unix(1_700_000_000, 0)}
	store := newTestMemoryStore(t, Limits{MaxEntries: 1, MaxWaiters: 1, PruneBudget: 1}, clock)
	retention := mustRetention(t, time.Hour)

	assertMemoryCheck(t, store, testReplayKey(1), retention, CheckFirstSeen)
	before := store.testExpiry(testReplayKey(1))
	check, err := store.CheckAndRemember(context.Background(), testReplayKey(2), retention)
	if check != 0 || ErrorCodeOf(err) != ErrorCodeLimitExceeded {
		t.Fatalf("capacity result = %s, %v", check, err)
	}
	if after := store.testExpiry(testReplayKey(1)); !after.Equal(before) {
		t.Fatalf("capacity failure changed expiry: before %v after %v", before, after)
	}
	assertMemoryCheck(t, store, testReplayKey(1), retention, CheckReplayed)
	if clock.Calls() != 3 {
		t.Fatalf("admitted operations called clock %d times", clock.Calls())
	}
	assertMemoryInvariant(t, store)
}

// TestMemoryStoreCancellationAfterTokenPreventsClockAndMutation verifies the second context check.
func TestMemoryStoreCancellationAfterTokenPreventsClockAndMutation(t *testing.T) {
	clock := &countingClock{now: time.Unix(1_700_000_000, 0)}
	store := newTestMemoryStore(t, Limits{MaxEntries: 1, MaxWaiters: 1, PruneBudget: 1}, clock)
	store.state.afterToken = make(chan struct{})
	store.state.continueAfterToken = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := store.CheckAndRemember(ctx, testReplayKey(1), mustRetention(t, time.Second))
		result <- err
	}()
	<-store.state.afterToken
	cancel()
	close(store.state.continueAfterToken)
	if err := <-result; ErrorCodeOf(err) != ErrorCodeCancelled || !errors.Is(err, context.Canceled) {
		t.Fatalf("post-token cancellation = %v", err)
	}
	if clock.Calls() != 0 {
		t.Fatalf("post-token cancellation called clock %d times", clock.Calls())
	}
	if entries, nodes := store.testCounts(); entries != 0 || nodes != 0 {
		t.Fatalf("post-token cancellation mutated %d/%d", entries, nodes)
	}
}

// TestMemoryStoreCancellationDuringClockPreventsMutation verifies the final pre-mutation recheck.
func TestMemoryStoreCancellationDuringClockPreventsMutation(t *testing.T) {
	clock := newBlockingClock(time.Unix(1_700_000_000, 0))
	store := newTestMemoryStore(t, Limits{MaxEntries: 1, MaxWaiters: 1, PruneBudget: 1}, clock)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	retention := mustRetention(t, time.Second)
	go func() {
		_, err := store.CheckAndRemember(ctx, testReplayKey(1), retention)
		result <- err
	}()
	<-clock.Entered()
	cancel()
	clock.Release()
	if err := <-result; ErrorCodeOf(err) != ErrorCodeCancelled || !errors.Is(err, context.Canceled) {
		t.Fatalf("during-clock cancellation = %v", err)
	}
	if clock.Calls() != 1 {
		t.Fatalf("during-clock reads = %d", clock.Calls())
	}
	if entries, nodes := store.testCounts(); entries != 0 || nodes != 0 {
		t.Fatalf("during-clock cancellation mutated %d/%d", entries, nodes)
	}
}

// TestMemoryStorePruneBudgetPreservesHeapMapOneToOne verifies stale same-key replacement is budgeted.
func TestMemoryStorePruneBudgetPreservesHeapMapOneToOne(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	clock := newTestClock(start)
	store := newTestMemoryStore(t, Limits{MaxEntries: 3, MaxWaiters: 1, PruneBudget: 1}, clock)
	short := mustRetention(t, time.Second)
	long := mustRetention(t, time.Hour)
	first := testReplayKey(1)
	second := testReplayKey(2)
	third := testReplayKey(3)

	assertMemoryCheck(t, store, first, short, CheckFirstSeen)
	clock.Set(start.Add(time.Millisecond))
	assertMemoryCheck(t, store, second, short, CheckFirstSeen)
	clock.Set(start.Add(2 * time.Millisecond))
	assertMemoryCheck(t, store, third, long, CheckFirstSeen)
	clock.Set(start.Add(2 * time.Second))

	check, err := store.CheckAndRemember(context.Background(), second, long)
	if check != 0 || ErrorCodeOf(err) != ErrorCodeLimitExceeded {
		t.Fatalf("stale same-key result = %s, %v", check, err)
	}
	if entries, nodes := store.testCounts(); entries != 2 || nodes != 2 {
		t.Fatalf("post-budget counts = %d map, %d heap", entries, nodes)
	}
	assertMemoryInvariant(t, store)
	assertMemoryCheck(t, store, second, long, CheckFirstSeen)
	if entries, nodes := store.testCounts(); entries != 2 || nodes != 2 {
		t.Fatalf("replacement counts = %d map, %d heap", entries, nodes)
	}
	assertMemoryInvariant(t, store)
}

// TestMemoryStoreEqualExpiryOrderingIsDeterministic verifies protected-key tie breaking.
func TestMemoryStoreEqualExpiryOrderingIsDeterministic(t *testing.T) {
	clock := newTestClock(time.Unix(1_700_000_000, 0))
	store := newTestMemoryStore(t, Limits{MaxEntries: 3, MaxWaiters: 1, PruneBudget: 1}, clock)
	retention := mustRetention(t, time.Second)
	keys := []Key{testReplayKey(3), testReplayKey(1), testReplayKey(2)}
	for _, key := range keys {
		assertMemoryCheck(t, store, key, retention, CheckFirstSeen)
	}
	got := store.testHeapKeys()
	want := []Key{testReplayKey(1), testReplayKey(2), testReplayKey(3)}
	for index := range want {
		storage, present := want[index].storageValue()
		if !present || got[index] != storage {
			t.Fatalf("equal-expiry heap order differs at %d", index)
		}
	}
}

// TestMemoryStoreClockFailuresDegradeBeforeMutation verifies fail-closed clock handling.
func TestMemoryStoreClockFailuresDegradeBeforeMutation(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name  string
		clock Clock
		prime bool
	}{
		{"zero", ClockFunc(func() time.Time { return time.Time{} }), false},
		{"panic", ClockFunc(func() time.Time { panic("TOXIC-CLOCK-MARKER") }), false},
		{"backwards", newSequenceClock(base, base.Add(-time.Nanosecond)), true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newTestMemoryStore(t, Limits{MaxEntries: 2, MaxWaiters: 1, PruneBudget: 1}, test.clock)
			retention := mustRetention(t, time.Second)
			if test.prime {
				assertMemoryCheck(t, store, testReplayKey(1), retention, CheckFirstSeen)
			}
			beforeEntries, beforeNodes := store.testCounts()
			check, err := store.CheckAndRemember(context.Background(), testReplayKey(2), retention)
			if check != 0 || ErrorCodeOf(err) != ErrorCodeInternalInvariant ||
				strings.Contains(err.Error(), "TOXIC") {
				t.Fatalf("clock failure = %s, %v", check, err)
			}
			if store.State() != StoreDegraded {
				t.Fatalf("clock failure state = %s", store.State())
			}
			if entries, nodes := store.testCounts(); entries != beforeEntries || nodes != beforeNodes {
				t.Fatalf("clock failure mutated store: before %d/%d after %d/%d", beforeEntries, beforeNodes, entries, nodes)
			}
		})
	}
}

// TestMemoryStoreWaiterCapAndCancellationAreExact verifies only blocked callers consume waiter slots.
func TestMemoryStoreWaiterCapAndCancellationAreExact(t *testing.T) {
	blocking := newBlockingClock(time.Unix(1_700_000_000, 0))
	store := newTestMemoryStore(t, Limits{MaxEntries: 4, MaxWaiters: 1, PruneBudget: 1}, blocking)
	retention := mustRetention(t, time.Second)

	holderResult := make(chan error, 1)
	go func() {
		_, err := store.CheckAndRemember(context.Background(), testReplayKey(1), retention)
		holderResult <- err
	}()
	<-blocking.Entered()

	waitCtx, cancelWait := context.WithCancel(context.Background())
	waiterResult := make(chan error, 1)
	go func() {
		_, err := store.CheckAndRemember(waitCtx, testReplayKey(2), retention)
		waiterResult <- err
	}()
	waitForWaiters(t, store, 1)

	check, err := store.CheckAndRemember(context.Background(), testReplayKey(3), retention)
	if check != 0 || ErrorCodeOf(err) != ErrorCodeLimitExceeded {
		t.Fatalf("waiter cap+1 = %s, %v", check, err)
	}
	if blocking.Calls() != 1 {
		t.Fatalf("rejected waiter called clock %d times", blocking.Calls())
	}

	cancelWait()
	if err := <-waiterResult; ErrorCodeOf(err) != ErrorCodeCancelled || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled waiter = %v", err)
	}
	waitForWaiters(t, store, 0)
	blocking.Release()
	if err := <-holderResult; err != nil {
		t.Fatalf("holder result = %v", err)
	}
}

// TestMemoryStoreConcurrentSameKeyHasOneWinner verifies atomic first-seen behavior.
func TestMemoryStoreConcurrentSameKeyHasOneWinner(t *testing.T) {
	clock := newTestClock(time.Unix(1_700_000_000, 0))
	store := newTestMemoryStore(t, Limits{MaxEntries: 1, MaxWaiters: 64, PruneBudget: 1}, clock)
	retention := mustRetention(t, time.Second)
	firstHandle := testReplayKey(1)
	secondHandle := testReplayKey(1)
	if firstHandle.state == secondHandle.state {
		t.Fatal("synthetic identical content keys unexpectedly shared one handle")
	}

	const callers = 64
	var firstSeen atomic.Int64
	var replayed atomic.Int64
	start := make(chan struct{})
	var wait sync.WaitGroup
	for range callers {
		wait.Go(func() {
			<-start
			check, err := store.CheckAndRemember(context.Background(), testReplayKey(1), retention)
			if err != nil {
				t.Errorf("concurrent check = %v", err)
				return
			}
			switch check {
			case CheckFirstSeen:
				firstSeen.Add(1)
			case CheckReplayed:
				replayed.Add(1)
			default:
				t.Errorf("concurrent check = %s", check)
			}
		})
	}
	close(start)
	wait.Wait()
	if firstSeen.Load() != 1 || replayed.Load() != callers-1 {
		t.Fatalf("same-key results = first %d replay %d", firstSeen.Load(), replayed.Load())
	}
	assertMemoryInvariant(t, store)
}

// TestMemoryStoreDistinctKeysAreRaceSafe verifies serialized mutation preserves every key.
func TestMemoryStoreDistinctKeysAreRaceSafe(t *testing.T) {
	clock := newTestClock(time.Unix(1_700_000_000, 0))
	store := newTestMemoryStore(t, Limits{MaxEntries: 64, MaxWaiters: 64, PruneBudget: 1}, clock)
	retention := mustRetention(t, time.Second)
	const callers = 64
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := range callers {
		wait.Add(1)
		go func(seed byte) {
			defer wait.Done()
			<-start
			check, err := store.CheckAndRemember(context.Background(), testReplayKey(seed), retention)
			if err != nil || check != CheckFirstSeen {
				t.Errorf("distinct key %d = %s, %v", seed, check, err)
			}
		}(byte(index + 1))
	}
	close(start)
	wait.Wait()
	if entries, nodes := store.testCounts(); entries != callers || nodes != callers {
		t.Fatalf("distinct-key counts = %d/%d", entries, nodes)
	}
	assertMemoryInvariant(t, store)
}

// TestMemoryStorePostMutationCancellationKeepsAuthoritativeResult verifies the mutation boundary.
func TestMemoryStorePostMutationCancellationKeepsAuthoritativeResult(t *testing.T) {
	store := newTestMemoryStore(t, Limits{MaxEntries: 1, MaxWaiters: 1, PruneBudget: 1}, newTestClock(time.Unix(1_700_000_000, 0)))
	store.state.afterMutation = make(chan struct{})
	store.state.continueAfterMutation = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan struct {
		check Check
		err   error
	}, 1)
	go func() {
		check, err := store.CheckAndRemember(ctx, testReplayKey(1), mustRetention(t, time.Second))
		result <- struct {
			check Check
			err   error
		}{check, err}
	}()
	<-store.state.afterMutation
	cancel()
	close(store.state.continueAfterMutation)
	got := <-result
	if got.check != CheckFirstSeen || got.err != nil {
		t.Fatalf("post-mutation cancellation = %s, %v", got.check, got.err)
	}
}

// TestMemoryStoreCloseDrainsRetriesAndClearsExactlyOnce verifies close linearization.
func TestMemoryStoreCloseDrainsRetriesAndClearsExactlyOnce(t *testing.T) {
	blocking := newBlockingClock(time.Unix(1_700_000_000, 0))
	store := newTestMemoryStore(t, Limits{MaxEntries: 2, MaxWaiters: 2, PruneBudget: 1}, blocking)
	retention := mustRetention(t, time.Second)

	holderResult := make(chan struct {
		check Check
		err   error
	}, 1)
	go func() {
		check, err := store.CheckAndRemember(context.Background(), testReplayKey(1), retention)
		holderResult <- struct {
			check Check
			err   error
		}{check, err}
	}()
	<-blocking.Entered()

	closeCtx, cancelClose := context.WithCancel(context.Background())
	closeResult := make(chan error, 1)
	go func() { closeResult <- store.Close(closeCtx) }()
	waitForState(t, store, StoreClosing)

	check, err := store.CheckAndRemember(context.Background(), testReplayKey(2), retention)
	if check != 0 || ErrorCodeOf(err) != ErrorCodeClosed || blocking.Calls() != 1 {
		t.Fatalf("post-closing check = %s, %v, clock calls %d", check, err, blocking.Calls())
	}
	cancelClose()
	if err := <-closeResult; ErrorCodeOf(err) != ErrorCodeCancelled || !errors.Is(err, context.Canceled) {
		t.Fatalf("timed-out close = %v", err)
	}
	if store.State() != StoreClosing {
		t.Fatalf("state after close cancellation = %s", store.State())
	}

	blocking.Release()
	result := <-holderResult
	if result.check != CheckFirstSeen || result.err != nil {
		t.Fatalf("admitted result = %s, %v", result.check, result.err)
	}
	if err := store.Close(context.Background()); err != nil {
		t.Fatalf("retry Close() = %v", err)
	}
	if err := store.Close(context.Background()); err != nil {
		t.Fatalf("idempotent Close() = %v", err)
	}
	if store.State() != StoreClosed {
		t.Fatalf("final state = %s", store.State())
	}
	if entries, nodes := store.testCounts(); entries != 0 || nodes != 0 {
		t.Fatalf("closed counts = %d map, %d heap", entries, nodes)
	}
	if store.testClearCount() != 1 {
		t.Fatalf("clear count = %d", store.testClearCount())
	}
	assertMemoryInvariant(t, store)
}

// TestMemoryStoreCloseDeadlineAndHostileContextsAreContained verifies bounded close errors.
func TestMemoryStoreCloseDeadlineAndHostileContextsAreContained(t *testing.T) {
	for _, test := range []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		code ErrorCode
	}{
		{
			"deadline",
			func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), time.Millisecond)
			},
			ErrorCodeDeadlineExceeded,
		},
		{
			"hostile done panic",
			func() (context.Context, context.CancelFunc) {
				return hostileCloseContext{panicOnDone: true}, func() {}
			},
			ErrorCodeInternalInvariant,
		},
		{
			"hostile contradictory done",
			func() (context.Context, context.CancelFunc) {
				return hostileCloseContext{done: closedSignal()}, func() {}
			},
			ErrorCodeInternalInvariant,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := newBlockingClock(time.Unix(1_700_000_000, 0))
			store := newTestMemoryStore(t, Limits{MaxEntries: 1, MaxWaiters: 1, PruneBudget: 1}, clock)
			operation := make(chan error, 1)
			retention := mustRetention(t, time.Second)
			go func() {
				_, err := store.CheckAndRemember(context.Background(), testReplayKey(1), retention)
				operation <- err
			}()
			<-clock.Entered()
			ctx, cancel := test.ctx()
			err := store.Close(ctx)
			cancel()
			if ErrorCodeOf(err) != test.code {
				t.Fatalf("Close() = %v", err)
			}
			if store.State() != StoreClosing {
				t.Fatalf("failed Close state = %s", store.State())
			}
			clock.Release()
			if err := <-operation; err != nil {
				t.Fatalf("operation cleanup = %v", err)
			}
			if err := store.Close(context.Background()); err != nil {
				t.Fatalf("Close cleanup = %v", err)
			}
		})
	}
}

// TestMemoryStoreFormattingAndSerializationAreContentFree verifies provider privacy.
func TestMemoryStoreFormattingAndSerializationAreContentFree(t *testing.T) {
	store := newTestMemoryStore(t, Limits{MaxEntries: 1, MaxWaiters: 1, PruneBudget: 1}, newTestClock(time.Unix(1_700_000_000, 0)))
	key := testReplayKey(0x54)
	assertMemoryCheck(t, store, key, mustRetention(t, time.Second), CheckFirstSeen)
	var storage string
	if err := UseStorageKey(key, func(value string) error {
		storage = value
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x", store, store, store, store, store, store)
	if strings.Count(formatted, memoryStoreRedactedText) != 6 || containsKeyMaterial(formatted) {
		t.Fatal("memory formatting was not content-free")
	}
	value := *store
	for _, surface := range []any{
		store, value, any(store), any(value),
		[]*MemoryStore{store}, []MemoryStore{value},
		map[string]*MemoryStore{privacyStoreMapKey: store},
		map[string]MemoryStore{privacyStoreMapKey: value},
	} {
		diagnostic := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x|%p", surface, surface, surface, surface, surface, surface, surface)
		if strings.Contains(diagnostic, storage) || strings.Contains(diagnostic, fmt.Sprintf("%x", storage)) {
			t.Fatal("memory owner formatting exposed a protected storage key")
		}
		encoded, marshalErr := json.Marshal(surface)
		if strings.Contains(string(encoded), storage) ||
			marshalErr != nil && strings.Contains(marshalErr.Error(), storage) {
			t.Fatal("memory owner serialization exposed a protected storage key")
		}
	}
	internal := fmt.Sprintf("%v|%+v|%#v", store.state.entries, store.state.expiries, store.state.expiries)
	if strings.Contains(internal, storage) {
		t.Fatal("memory heap/map formatting exposed a protected storage key")
	}
	if encoded, err := json.Marshal(store); encoded != nil || ErrorCodeOf(err) != ErrorCodeInternalInvariant ||
		strings.Contains(err.Error(), "TOXIC") {
		t.Fatalf("memory JSON = %s, %v", encoded, err)
	}
	if text, err := store.MarshalText(); text != nil || ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("memory text = %q, %v", text, err)
	}
	if encoded, err := store.MarshalJSON(); encoded != nil || ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("memory direct JSON = %s, %v", encoded, err)
	}
}

// testClock is a deterministic synchronized injected clock.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

// countingClock records exact injected-clock call counts.
type countingClock struct {
	now   time.Time
	calls atomic.Int64
}

// Now returns the configured time and records the call.
func (c *countingClock) Now() time.Time {
	c.calls.Add(1)
	return c.now
}

// Calls returns the exact read count.
func (c *countingClock) Calls() int64 { return c.calls.Load() }

// newTestClock constructs a deterministic clock.
func newTestClock(now time.Time) *testClock { return &testClock{now: now} }

// Now returns the configured time.
func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Set changes the configured time.
func (c *testClock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// sequenceClock supplies a fixed sequence of clock values.
type sequenceClock struct {
	mu     sync.Mutex
	values []time.Time
}

// newSequenceClock constructs a fixed clock sequence.
func newSequenceClock(values ...time.Time) *sequenceClock {
	return &sequenceClock{values: append([]time.Time(nil), values...)}
}

// Now returns and consumes the next configured time.
func (c *sequenceClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.values) == 0 {
		panic("sequence clock exhausted")
	}
	now := c.values[0]
	c.values = c.values[1:]
	return now
}

// blockingClock blocks one clock read until released.
type blockingClock struct {
	now     time.Time
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int64
}

// newBlockingClock constructs a one-shot blocking clock.
func newBlockingClock(now time.Time) *blockingClock {
	return &blockingClock{now: now, entered: make(chan struct{}), release: make(chan struct{})}
}

// Now blocks until the test releases the clock.
func (c *blockingClock) Now() time.Time {
	if c.calls.Add(1) == 1 {
		close(c.entered)
	}
	<-c.release
	return c.now
}

// Entered reports when the first read begins.
func (c *blockingClock) Entered() <-chan struct{} { return c.entered }

// Release permits the blocked clock read to complete.
func (c *blockingClock) Release() { close(c.release) }

// Calls reports the number of clock reads.
func (c *blockingClock) Calls() int64 { return c.calls.Load() }

// newTestMemoryStore constructs a memory store with narrow test limits.
func newTestMemoryStore(t *testing.T, limits Limits, clock Clock) *MemoryStore {
	t.Helper()
	resolved := DefaultLimits()
	resolved.MaxEntries = limits.MaxEntries
	resolved.MaxWaiters = limits.MaxWaiters
	resolved.PruneBudget = limits.PruneBudget
	store, err := NewMemoryStore(MemoryConfig{Limits: resolved, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// mustRetention constructs one retention or fails the test.
func mustRetention(t *testing.T, duration time.Duration) Retention {
	t.Helper()
	retention, err := NewRetention(duration)
	if err != nil {
		t.Fatal(err)
	}
	return retention
}

// testReplayKey constructs a valid synthetic protected storage key.
func testReplayKey(seed byte) Key {
	var digest [32]byte
	for index := range digest {
		digest[index] = seed + byte(index)
	}
	storage := "dkim2:replay:v1:00000001:" + base64.RawURLEncoding.EncodeToString(digest[:])
	var key Key
	key.state = &keyState{}
	copy(key.state.storage[:], storage)
	return key
}

// assertMemoryCheck verifies one exact successful result.
func assertMemoryCheck(t *testing.T, store *MemoryStore, key Key, retention Retention, want Check) {
	t.Helper()
	check, err := store.CheckAndRemember(context.Background(), key, retention)
	if err != nil || check != want {
		t.Fatalf("CheckAndRemember() = %s, %v, want %s", check, err, want)
	}
}

// waitForWaiters waits for one deterministic waiter-count publication.
func waitForWaiters(t *testing.T, store *MemoryStore, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if store.testWaiterCount() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("waiters = %d, want %d", store.testWaiterCount(), want)
}

// waitForState waits for one deterministic lifecycle publication.
func waitForState(t *testing.T, store interface{ State() StoreState }, want StoreState) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if store.State() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("state = %s, want %s", store.State(), want)
}

// assertMemoryInvariant verifies exact one-to-one heap and map ownership.
func assertMemoryInvariant(t *testing.T, store *MemoryStore) {
	t.Helper()
	if !store.testValidInvariant() {
		t.Fatal("memory heap/map invariant failed")
	}
}

// testCounts returns exact map and heap ownership under the serialization token.
func (s *MemoryStore) testCounts() (int, int) {
	<-s.state.token
	defer s.releaseToken()
	return len(s.state.entries), len(s.state.expiries)
}

// testExpiry returns one exact retained expiry.
func (s *MemoryStore) testExpiry(key Key) time.Time {
	<-s.state.token
	defer s.releaseToken()
	storage, present := key.storageValue()
	if !present {
		return time.Time{}
	}
	entry := s.state.entries[storage]
	if entry == nil {
		return time.Time{}
	}
	return entry.expiry
}

// testHeapKeys returns entries in deterministic heap-pop order.
func (s *MemoryStore) testHeapKeys() [][storageKeyByteLength]byte {
	<-s.state.token
	defer s.releaseToken()
	clone := append(expiryHeap(nil), s.state.expiries...)
	for index, entry := range clone {
		copied := *entry
		clone[index] = &copied
	}
	output := make([][storageKeyByteLength]byte, 0, len(clone))
	for len(clone) > 0 {
		output = append(output, heap.Pop(&clone).(*memoryEntry).key)
	}
	return output
}

// testWaiterCount returns the exact number of blocked serialization callers.
func (s *MemoryStore) testWaiterCount() int {
	s.state.waitMu.Lock()
	defer s.state.waitMu.Unlock()
	return s.state.waiters
}

// testClearCount returns the number of terminal retained-state clears.
func (s *MemoryStore) testClearCount() int {
	<-s.state.token
	defer s.releaseToken()
	return s.state.clearCount
}

// testValidInvariant verifies map, heap, index, uniqueness, and parent ordering.
func (s *MemoryStore) testValidInvariant() bool {
	<-s.state.token
	defer s.releaseToken()
	if len(s.state.entries) != len(s.state.expiries) {
		return false
	}
	seen := make(map[[storageKeyByteLength]byte]struct{}, len(s.state.expiries))
	for index, entry := range s.state.expiries {
		if entry == nil || entry.index != index || s.state.entries[entry.key] != entry {
			return false
		}
		if _, exists := seen[entry.key]; exists {
			return false
		}
		seen[entry.key] = struct{}{}
		if index > 0 && s.state.expiries.Less(index, (index-1)/2) {
			return false
		}
	}
	for key, entry := range s.state.entries {
		if entry == nil || entry.key != key {
			return false
		}
		if _, exists := seen[key]; !exists {
			return false
		}
	}
	return true
}
