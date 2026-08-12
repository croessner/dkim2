package keyresolver

import (
	"context"
	"crypto/ed25519"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestFlightGroupCoalescesConcurrentSameKey verifies one worker and detached results.
func TestFlightGroupCoalescesConcurrentSameKey(t *testing.T) {
	group := newFlightGroup(context.Background(), 4, 8, time.Second)
	key := cacheKey{owner: cacheOwner('f'), algorithm: AlgorithmEd25519SHA256}
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	work := func(context.Context) flightResult {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return flightResult{outcome: foundEdOutcome(0x42)}
	}
	results := make(chan flightResult, 2)
	errorsCh := make(chan error, 2)
	for index := range 2 {
		go func() {
			result, saturated, err := group.do(context.Background(), key, work)
			if saturated {
				errorsCh <- errors.New("unexpected saturation")
				return
			}
			results <- result
			errorsCh <- err
		}()
		if index == 0 {
			<-entered
		}
	}
	waitForFlightWaiters(t, group, key, 2)
	close(release)
	var received [2]flightResult
	for index := range 2 {
		result := <-results
		if err := <-errorsCh; err != nil || result.outcome.Status() != KeyOutcomeFound {
			t.Fatalf("flight result/error = %q/%v", result.outcome.Status(), err)
		}
		received[index] = result
	}
	received[0].outcome.material.(ed25519.PublicKey)[0] = 0x99
	if received[1].outcome.Material().(ed25519.PublicKey)[0] != 0x42 {
		t.Fatal("coalesced waiters shared mutable result material")
	}
	if calls.Load() != 1 {
		t.Fatalf("worker calls = %d", calls.Load())
	}
	group.mu.Lock()
	remaining := len(group.flights)
	group.mu.Unlock()
	if remaining != 0 || len(group.semaphore) != 0 {
		t.Fatalf("completed flight retained state: flights=%d semaphore=%d", remaining, len(group.semaphore))
	}
}

// TestFlightWaiterLimitAllowsExactAndRejectsOneOver verifies initiating caller is counted.
func TestFlightWaiterLimitAllowsExactAndRejectsOneOver(t *testing.T) {
	group := newFlightGroup(context.Background(), 1, 2, time.Second)
	key := cacheKey{owner: cacheOwner('e'), algorithm: AlgorithmRSASHA256}
	entered := make(chan struct{})
	release := make(chan struct{})
	work := func(context.Context) flightResult {
		close(entered)
		<-release
		return flightResult{outcome: newStatusOutcome(KeyOutcomeMissing, AlgorithmRSASHA256, newMetadata(false, false))}
	}
	var waiters sync.WaitGroup
	for index := range 2 {
		waiters.Go(func() {
			_, _, _ = group.do(context.Background(), key, work)
		})
		if index == 0 {
			<-entered
		}
	}
	waitForFlightWaiters(t, group, key, 2)
	if _, saturated, err := group.do(context.Background(), key, work); err != nil || !saturated {
		t.Fatalf("one-over waiter saturation = %v/%v", saturated, err)
	}
	close(release)
	waiters.Wait()
}

// TestFlightWaiterCancellationDoesNotCancelLivePeer verifies independent caller contexts.
func TestFlightWaiterCancellationDoesNotCancelLivePeer(t *testing.T) {
	group := newFlightGroup(context.Background(), 2, 2, time.Second)
	key := cacheKey{owner: cacheOwner('w'), algorithm: AlgorithmRSASHA256}
	entered := make(chan context.Context, 1)
	release := make(chan struct{})
	work := func(ctx context.Context) flightResult {
		entered <- ctx
		<-release
		return flightResult{outcome: newStatusOutcome(KeyOutcomeMissing, AlgorithmRSASHA256, newMetadata(false, false))}
	}
	firstDone := make(chan error, 1)
	go func() {
		_, _, err := group.do(context.Background(), key, work)
		firstDone <- err
	}()
	workerCtx := <-entered
	secondCtx, secondCancel := context.WithCancel(context.Background())
	secondDone := make(chan error, 1)
	go func() {
		_, _, err := group.do(secondCtx, key, work)
		secondDone <- err
	}()
	waitForFlightWaiters(t, group, key, 2)
	secondCancel()
	if err := <-secondDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter error = %v", err)
	}
	if workerCtx.Err() != nil {
		t.Fatalf("live peer worker context canceled: %v", workerCtx.Err())
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("live waiter error = %v", err)
	}
}

// TestFlightLastWaiterCancellationCancelsWorker verifies last-departure ownership.
func TestFlightLastWaiterCancellationCancelsWorker(t *testing.T) {
	group := newFlightGroup(context.Background(), 1, 1, time.Second)
	key := cacheKey{owner: cacheOwner('l'), algorithm: AlgorithmRSASHA256}
	workerCanceled := make(chan struct{})
	work := func(ctx context.Context) flightResult {
		<-ctx.Done()
		close(workerCanceled)
		return flightResult{outcome: newStatusOutcome(KeyOutcomeTemporary, AlgorithmRSASHA256, newMetadata(false, false))}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, err := group.do(ctx, key, work)
		done <- err
	}()
	waitForFlightWaiters(t, group, key, 1)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("last waiter error = %v", err)
	}
	select {
	case <-workerCanceled:
	case <-time.After(time.Second):
		t.Fatal("last waiter did not cancel worker")
	}
}

// TestFlightWaiterAndGlobalSaturationAreImmediate verifies both non-blocking bounds.
func TestFlightWaiterAndGlobalSaturationAreImmediate(t *testing.T) {
	group := newFlightGroup(context.Background(), 1, 1, time.Second)
	firstKey := cacheKey{owner: cacheOwner('a'), algorithm: AlgorithmRSASHA256}
	secondKey := cacheKey{owner: cacheOwner('b'), algorithm: AlgorithmRSASHA256}
	entered := make(chan struct{})
	release := make(chan struct{})
	work := func(context.Context) flightResult {
		close(entered)
		<-release
		return flightResult{outcome: newStatusOutcome(KeyOutcomeMissing, AlgorithmRSASHA256, newMetadata(false, false))}
	}
	firstDone := make(chan struct{})
	go func() {
		_, _, _ = group.do(context.Background(), firstKey, work)
		close(firstDone)
	}()
	<-entered
	if _, saturated, err := group.do(context.Background(), firstKey, work); err != nil || !saturated {
		t.Fatalf("waiter saturation = %v/%v", saturated, err)
	}
	if _, saturated, err := group.do(context.Background(), secondKey, work); err != nil || !saturated {
		t.Fatalf("global saturation = %v/%v", saturated, err)
	}
	close(release)
	<-firstDone
}

// TestFlightCompletionCancellationRacePrefersCaller verifies deterministic outer control flow.
func TestFlightCompletionCancellationRacePrefersCaller(t *testing.T) {
	for iteration := range 64 {
		group := newFlightGroup(context.Background(), 1, 1, time.Second)
		key := cacheKey{owner: cacheOwner('r'), algorithm: AlgorithmRSASHA256}
		release := make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, _, err := group.do(ctx, key, func(context.Context) flightResult {
				<-release
				return flightResult{outcome: newStatusOutcome(KeyOutcomeMissing, AlgorithmRSASHA256, newMetadata(false, false))}
			})
			done <- err
		}()
		waitForFlightWaiters(t, group, key, 1)
		cancel()
		close(release)
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("iteration %d error = %v", iteration, err)
		}
	}
}

// TestFlightRetiresCanceledZeroWaiterBeforeReplacement verifies pointer-safe old completion.
func TestFlightRetiresCanceledZeroWaiterBeforeReplacement(t *testing.T) {
	group := newFlightGroup(context.Background(), 2, 2, time.Second)
	key := cacheKey{owner: cacheOwner('q'), algorithm: AlgorithmRSASHA256}
	oldRelease := make(chan struct{})
	oldCanceled := make(chan struct{})
	firstCtx, firstCancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, _, err := group.do(firstCtx, key, func(ctx context.Context) flightResult {
			<-ctx.Done()
			close(oldCanceled)
			<-oldRelease
			return flightResult{outcome: newStatusOutcome(KeyOutcomeTemporary, AlgorithmRSASHA256, newMetadata(false, false))}
		})
		firstDone <- err
	}()
	waitForFlightWaiters(t, group, key, 1)
	firstCancel()
	<-oldCanceled

	newEntered := make(chan struct{})
	newRelease := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		_, _, err := group.do(context.Background(), key, func(context.Context) flightResult {
			close(newEntered)
			<-newRelease
			return flightResult{outcome: newStatusOutcome(KeyOutcomeMissing, AlgorithmRSASHA256, newMetadata(false, false))}
		})
		secondDone <- err
	}()
	<-newEntered
	close(oldRelease)
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("first waiter error = %v", err)
	}
	thirdDone := make(chan error, 1)
	go func() {
		_, _, err := group.do(context.Background(), key, func(context.Context) flightResult {
			t.Error("replacement waiter started a third worker")
			return flightResult{}
		})
		thirdDone <- err
	}()
	waitForFlightWaiters(t, group, key, 2)
	close(newRelease)
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	if err := <-thirdDone; err != nil {
		t.Fatal(err)
	}
}

// TestFlightJoinPrunesCanceledWaiterBeforeLimit verifies no false per-key saturation.
func TestFlightJoinPrunesCanceledWaiterBeforeLimit(t *testing.T) {
	group := newFlightGroup(context.Background(), 2, 1, time.Second)
	key := cacheKey{owner: cacheOwner('j'), algorithm: AlgorithmRSASHA256}
	oldCtx, cancelOld := context.WithCancel(context.Background())
	oldRelease := make(chan struct{})
	oldDone := make(chan error, 1)
	go func() {
		_, _, err := group.do(oldCtx, key, func(ctx context.Context) flightResult {
			<-ctx.Done()
			<-oldRelease
			return flightResult{outcome: newStatusOutcome(KeyOutcomeTemporary, AlgorithmRSASHA256, newMetadata(false, false))}
		})
		oldDone <- err
	}()
	waitForFlightWaiters(t, group, key, 1)
	group.mu.Lock()
	cancelOld()
	newEntered := make(chan struct{})
	newRelease := make(chan struct{})
	newDone := make(chan struct {
		err       error
		saturated bool
	}, 1)
	go func() {
		_, saturated, err := group.do(context.Background(), key, func(context.Context) flightResult {
			close(newEntered)
			<-newRelease
			return flightResult{outcome: newStatusOutcome(KeyOutcomeMissing, AlgorithmRSASHA256, newMetadata(false, false))}
		})
		newDone <- struct {
			err       error
			saturated bool
		}{err: err, saturated: saturated}
	}()
	group.mu.Unlock()
	<-newEntered
	close(newRelease)
	result := <-newDone
	if result.err != nil || result.saturated {
		t.Fatalf("replacement join error/saturated = %v/%v", result.err, result.saturated)
	}
	close(oldRelease)
	if err := <-oldDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("old waiter error = %v", err)
	}

	group.mu.Lock()
	blockedCtx, cancelBlocked := context.WithCancel(context.Background())
	var workCalls atomic.Int32
	blockedDone := make(chan error, 1)
	go func() {
		_, _, err := group.do(blockedCtx, cacheKey{owner: cacheOwner('k'), algorithm: AlgorithmRSASHA256}, func(context.Context) flightResult {
			workCalls.Add(1)
			return flightResult{}
		})
		blockedDone <- err
	}()
	cancelBlocked()
	group.mu.Unlock()
	if err := <-blockedDone; !errors.Is(err, context.Canceled) || workCalls.Load() != 0 {
		t.Fatalf("mutex-blocked caller error=%v work=%d", err, workCalls.Load())
	}
}

// TestFlightParentCancellationAndInvalidConstructionFailClosed verifies instance ownership and bounds.
func TestFlightParentCancellationAndInvalidConstructionFailClosed(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	group := newFlightGroup(parent, 1, 1, time.Second)
	key := cacheKey{owner: cacheOwner('p'), algorithm: AlgorithmRSASHA256}
	started := make(chan struct{})
	done := make(chan flightResult, 1)
	go func() {
		result, _, _ := group.do(context.Background(), key, func(ctx context.Context) flightResult {
			close(started)
			<-ctx.Done()
			return flightResult{outcome: newStatusOutcome(KeyOutcomeTemporary, AlgorithmRSASHA256, newMetadata(false, false))}
		})
		done <- result
	}()
	<-started
	cancelParent()
	if result := <-done; result.outcome.Status() != KeyOutcomeTemporary {
		t.Fatalf("parent cancellation outcome = %q", result.outcome.Status())
	}

	var calls atomic.Int32
	invalid := []*flightGroup{
		newFlightGroup(nil, 1, 1, time.Second), //nolint:staticcheck // Explicit nil-context contract defense.
		newFlightGroup(context.Background(), 0, 1, time.Second),
		newFlightGroup(context.Background(), hardMaxConcurrentLookups+1, 1, time.Second),
		newFlightGroup(context.Background(), 1, 0, time.Second),
		newFlightGroup(context.Background(), 1, hardMaxCoalescedWaiters+1, time.Second),
		newFlightGroup(context.Background(), 1, 1, 31*time.Second),
	}
	for _, candidate := range invalid {
		_, saturated, err := candidate.do(context.Background(), key, func(context.Context) flightResult { calls.Add(1); return flightResult{} })
		if !IsErrorClass(err, ErrorClassContract) || saturated {
			t.Fatalf("invalid group error/saturated = %v/%v", err, saturated)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid groups started %d workers", calls.Load())
	}
}

// TestFlightOwnedTimeoutRejectsLateSuccessBeforePublisher verifies pre-publication deadline precedence.
func TestFlightOwnedTimeoutRejectsLateSuccessBeforePublisher(t *testing.T) {
	clock := &fakeCacheClock{now: time.Unix(100, 0)}
	cache := newOutcomeCache(1, clock.Now)
	group := newFlightGroup(context.Background(), 1, 1, time.Millisecond, flightPublication{cache: cache})
	key := cacheKey{owner: cacheOwner('t'), algorithm: AlgorithmEd25519SHA256}
	result, saturated, err := group.do(context.Background(), key, func(ctx context.Context) flightResult {
		<-ctx.Done()
		return flightResult{outcome: foundEdOutcome(0x42), expiry: clock.now.Add(time.Minute)}
	})
	_, hit, corrupt := cache.get(key)
	if err != nil || saturated || result.outcome.Status() != KeyOutcomeTemporary || result.outcome.Material() != nil || hit || corrupt {
		t.Fatalf("late success = %q material=%T error=%v saturated=%v hit=%v corrupt=%v", result.outcome.Status(), result.outcome.Material(), err, saturated, hit, corrupt)
	}
}

// TestFlightGlobalLimitAllowsExactSlotsAndRejectsOneOver verifies multi-slot saturation.
func TestFlightGlobalLimitAllowsExactSlotsAndRejectsOneOver(t *testing.T) {
	group := newFlightGroup(context.Background(), 2, 2, time.Second)
	release := make(chan struct{})
	var entered atomic.Int32
	work := func(context.Context) flightResult {
		entered.Add(1)
		<-release
		return flightResult{outcome: newStatusOutcome(KeyOutcomeMissing, AlgorithmRSASHA256, newMetadata(false, false))}
	}
	var waiters sync.WaitGroup
	for _, selector := range []byte{'a', 'b'} {
		waiters.Add(1)
		go func(value byte) {
			defer waiters.Done()
			_, _, _ = group.do(context.Background(), cacheKey{owner: cacheOwner(value), algorithm: AlgorithmRSASHA256}, work)
		}(selector)
	}
	deadline := time.Now().Add(time.Second)
	for entered.Load() != 2 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if entered.Load() != 2 {
		t.Fatalf("exact workers = %d", entered.Load())
	}
	if _, saturated, err := group.do(context.Background(), cacheKey{owner: cacheOwner('c'), algorithm: AlgorithmRSASHA256}, work); err != nil || !saturated {
		t.Fatalf("one-over saturation = %v/%v", saturated, err)
	}
	close(release)
	waiters.Wait()
}

// TestResolverCallerCancellationOutranksCacheAndSaturation verifies non-wait path precedence.
func TestResolverCallerCancellationOutranksCacheAndSaturation(t *testing.T) {
	lookup := cacheAbsentLookup(t, time.Minute)
	resolver, err := NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) { return lookup, nil }), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), "example.test", testSelector, AlgorithmRSASHA256); err != nil {
		t.Fatal(err)
	}
	resolver.cache.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, resolveErr := resolver.Resolve(ctx, "example.test", testSelector, AlgorithmRSASHA256)
		done <- resolveErr
	}()
	cancel()
	resolver.cache.mu.Unlock()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cache cancellation error = %v", err)
	}

	limits := DefaultLimits()
	limits.MaxConcurrentLookups = 1
	blocking := make(chan struct{})
	entered := make(chan struct{})
	resolver, err = NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) {
		close(entered)
		<-blocking
		return lookup, nil
	}), limits)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = resolver.Resolve(context.Background(), "example.test", "first", AlgorithmRSASHA256) }()
	<-entered
	resolver.flights.mu.Lock()
	ctx, cancel = context.WithCancel(context.Background())
	go func() {
		_, resolveErr := resolver.Resolve(ctx, "example.test", "second", AlgorithmRSASHA256)
		done <- resolveErr
	}()
	cancel()
	resolver.flights.mu.Unlock()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("saturation cancellation error = %v", err)
	}
	close(blocking)
}

// waitForFlightWaiters waits without sleeps until the bounded flight reaches a test state.
func waitForFlightWaiters(t *testing.T, group *flightGroup, key cacheKey, count int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		group.mu.Lock()
		flight := group.flights[key]
		matched := flight != nil && len(flight.waiterCtx) == count
		group.mu.Unlock()
		if matched {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("flight waiter count did not reach %d", count)
}

// waitForFlightCleanup waits for cooperative workers to release all bounded state.
func waitForFlightCleanup(t *testing.T, group *flightGroup) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		group.mu.Lock()
		remaining := len(group.flights)
		group.mu.Unlock()
		if remaining == 0 && len(group.semaphore) == 0 {
			return
		}
		runtime.Gosched()
	}
	t.Fatal("flight group did not release cooperative worker state")
}
