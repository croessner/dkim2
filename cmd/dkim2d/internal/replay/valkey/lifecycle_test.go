package valkey

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dkim2 "github.com/croessner/dkim2"
)

const syntheticCancelledName = "cancelled"

// blockingAdmissionContext blocks one exact Err capability call.
type blockingAdmissionContext struct {
	mu      sync.Mutex
	calls   int
	blockAt int
	once    sync.Once
	started chan struct{}
	release chan struct{}
}

// Deadline reports no deadline for the deterministic capability fixture.
func (*blockingAdmissionContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done exposes no asynchronous channel for the deterministic capability fixture.
func (*blockingAdmissionContext) Done() <-chan struct{} { return nil }

// Err blocks and then returns cancellation at one exact invocation.
func (c *blockingAdmissionContext) Err() error {
	c.mu.Lock()
	c.calls++
	call := c.calls
	c.mu.Unlock()
	if call != c.blockAt {
		return nil
	}
	c.once.Do(func() { close(c.started) })
	<-c.release
	return context.Canceled
}

// Value returns no values for the deterministic capability fixture.
func (*blockingAdmissionContext) Value(any) any { return nil }

type terminalDonePanicContext struct {
	terminal error
	errPanic bool
	armed    atomic.Bool
}

// Deadline reports no deadline because Err owns the exact terminal fixture.
func (*terminalDonePanicContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done establishes terminal caller state before injecting a capability panic.
func (c *terminalDonePanicContext) Done() <-chan struct{} {
	c.armed.Store(true)
	panic("synthetic terminal done panic")
}

// Err reports the caller terminal state only after Done establishes it.
func (c *terminalDonePanicContext) Err() error {
	if c.armed.Load() {
		if c.errPanic {
			panic("synthetic terminal err panic")
		}
		return c.terminal
	}
	return nil
}

// Value returns no values for the deterministic terminal fixture.
func (*terminalDonePanicContext) Value(any) any { return nil }

type terminalDoneContext struct {
	terminal error
	done     chan struct{}
	armed    atomic.Bool
}

// Deadline reports no deadline because Err owns the exact terminal fixture.
func (*terminalDoneContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done establishes terminal caller state and returns its ordinary closed channel.
func (c *terminalDoneContext) Done() <-chan struct{} {
	c.armed.Store(true)
	return c.done
}

// Err reports the caller terminal state only after Done establishes it.
func (c *terminalDoneContext) Err() error {
	if c.armed.Load() {
		return c.terminal
	}
	return nil
}

// Value returns no values for the ordinary terminal fixture.
func (*terminalDoneContext) Value(any) any { return nil }

// TestLifecycleAdmissionEnforcesInflightAndWaiterCaps covers bounded concurrent entry.
func TestLifecycleAdmissionEnforcesInflightAndWaiterCaps(t *testing.T) {
	gate := newAdmissionGate(1, 1)
	release, err := gate.admit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	waiting := make(chan error, 1)
	entered := make(chan func(), 1)
	go func() {
		done, waitErr := gate.admit(context.Background())
		if waitErr == nil {
			entered <- done
		}
		waiting <- waitErr
	}()
	waitAtomicCount(t, &gate.waiters, 1)

	if _, err := gate.admit(context.Background()); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorLimitExceeded {
		t.Fatalf("waiter cap+1 code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	release()
	if err := <-waiting; err != nil {
		t.Fatal(err)
	}
	(<-entered)()
}

// TestLifecyclePostAdmissionContextCannotHoldCloseLock proves capability lock safety.
func TestLifecyclePostAdmissionContextCannotHoldCloseLock(t *testing.T) {
	gate := newAdmissionGate(1, 1)
	ctx := &blockingAdmissionContext{
		blockAt: 3,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	admitted := make(chan error, 1)
	go func() {
		_, err := gate.admit(ctx)
		admitted <- err
	}()
	<-ctx.started

	closeResult := make(chan struct {
		drained <-chan struct{}
		err     error
	}, 1)
	go func() {
		drained, err := gate.beginClose()
		closeResult <- struct {
			drained <-chan struct{}
			err     error
		}{drained: drained, err: err}
	}()
	var closing struct {
		drained <-chan struct{}
		err     error
	}
	select {
	case closing = <-closeResult:
	case <-time.After(time.Second):
		t.Fatal("caller context capability held the lifecycle mutex")
	}
	if closing.err != nil || gate.stateValue() != lifecycleClosing {
		t.Fatalf("close err=%v state=%d", closing.err, gate.stateValue())
	}
	select {
	case <-closing.drained:
		t.Fatal("close drained before the admitted caller rolled back")
	default:
	}

	close(ctx.release)
	if err := <-admitted; dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorCancelled {
		t.Fatalf("admission code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	select {
	case <-closing.drained:
	case <-time.After(time.Second):
		t.Fatal("admission rollback did not complete close draining")
	}
}

// TestLifecycleZeroWaitersRefusesQueueing proves zero is not a fallback default.
func TestLifecycleZeroWaitersRefusesQueueing(t *testing.T) {
	gate := newAdmissionGate(1, 0)
	release, err := gate.admit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gate.admit(context.Background()); dkim2.ReplayErrorCodeOf(err) !=
		dkim2.ReplayErrorLimitExceeded {
		t.Fatalf("zero-waiter code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	if gate.waiters.Load() != 0 || gate.stateValue() != lifecycleReady {
		t.Fatalf("waiters=%d state=%d", gate.waiters.Load(), gate.stateValue())
	}
	release()
}

// TestLifecycleAdmissionCancellationRemovesWaiter proves queue cleanup needs no goroutine.
func TestLifecycleAdmissionCancellationRemovesWaiter(t *testing.T) {
	gate := newAdmissionGate(1, 1)
	release, err := gate.admit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, waitErr := gate.admit(ctx)
		result <- waitErr
	}()
	waitAtomicCount(t, &gate.waiters, 1)
	cancel()
	if err := <-result; dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorCancelled {
		t.Fatalf("cancel code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	waitAtomicCount(t, &gate.waiters, 0)
	release()
}

// TestLifecycleCallerCancellationPrecedesConcurrentClose proves exact terminal identity.
func TestLifecycleCallerCancellationPrecedesConcurrentClose(t *testing.T) {
	for range 100 {
		gate := newAdmissionGate(1, 1)
		release, err := gate.admit(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, waitErr := gate.admit(ctx)
			result <- waitErr
		}()
		waitAtomicCount(t, &gate.waiters, 1)
		cancel()
		if _, err := gate.beginClose(); err != nil {
			t.Fatal(err)
		}
		release()
		if waitErr := <-result; dkim2.ReplayErrorCodeOf(waitErr) != dkim2.ReplayErrorCancelled {
			t.Fatalf("code=%q", dkim2.ReplayErrorCodeOf(waitErr))
		}
	}
}

// TestLifecycleAdmissionDoesNotConsumeCommandSlots proves independent drain counting.
func TestLifecycleAdmissionDoesNotConsumeCommandSlots(t *testing.T) {
	gate := newAdmissionGate(1, 1)
	commandFinish, err := gate.admit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lifecycleFinish, err := gate.admitLifecycle(context.Background())
	if err != nil {
		t.Fatalf("lifecycle work waited for a command slot: %v", err)
	}
	if gate.inFlight != 2 || len(gate.slots) != 0 {
		t.Fatalf("in-flight=%d slots=%d", gate.inFlight, len(gate.slots))
	}
	lifecycleFinish()
	commandFinish()
}

// TestLifecycleCloseRejectsWaitersAndDrainsAdmittedCalls proves closing precedence.
func TestLifecycleCloseRejectsWaitersAndDrainsAdmittedCalls(t *testing.T) {
	gate := newAdmissionGate(1, 1)
	release, err := gate.admit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	waiter := make(chan error, 1)
	go func() {
		_, waitErr := gate.admit(context.Background())
		waiter <- waitErr
	}()
	waitAtomicCount(t, &gate.waiters, 1)
	drained, err := gate.beginClose()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-waiter; dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorClosed {
		t.Fatalf("waiter close code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	if _, err := gate.admit(context.Background()); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorClosed {
		t.Fatalf("new close code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	select {
	case <-drained:
		t.Fatal("drained before admitted release")
	default:
	}
	release()
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("drain did not complete")
	}
	if !gate.publishClosed() || gate.stateValue() != lifecycleClosed {
		t.Fatal("closed publication failed")
	}
}

// TestLifecycleCloseContextCanResumeSameDrain verifies close timeout leaves closing.
func TestLifecycleCloseContextCanResumeSameDrain(t *testing.T) {
	gate := newAdmissionGate(1, 1)
	release, err := gate.admit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	drained, err := gate.beginClose()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitAdmissionDrain(ctx, drained); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorCancelled {
		t.Fatalf("first drain code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	if gate.stateValue() != lifecycleClosing {
		t.Fatal("cancelled close did not remain closing")
	}
	release()
	if err := waitAdmissionDrain(context.Background(), drained); err != nil {
		t.Fatal(err)
	}
}

// TestLifecycleDonePanicAlwaysFailsAsInternal freezes capability-panic precedence.
func TestLifecycleDonePanicAlwaysFailsAsInternal(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		err      error
		errPanic bool
	}{
		{name: "no terminal state"},
		{name: syntheticCancelledName, err: context.Canceled},
		{name: syntheticDeadlineName, err: context.DeadlineExceeded},
		{name: "hostile err", errPanic: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := &terminalDonePanicContext{
				terminal: testCase.err,
				errPanic: testCase.errPanic,
			}
			if err := waitAdmissionDrain(ctx, make(chan struct{})); dkim2.ReplayErrorCodeOf(err) !=
				dkim2.ReplayErrorInternalInvariant {
				t.Fatalf("code=%q", dkim2.ReplayErrorCodeOf(err))
			}
		})
	}
}

// TestLifecycleOrdinaryDonePreservesCallerState freezes cancellation and deadline identity.
func TestLifecycleOrdinaryDonePreservesCallerState(t *testing.T) {
	for _, testCase := range []struct {
		name string
		err  error
		want dkim2.ReplayErrorCode
	}{
		{name: syntheticCancelledName, err: context.Canceled, want: dkim2.ReplayErrorCancelled},
		{name: syntheticDeadlineName, err: context.DeadlineExceeded, want: dkim2.ReplayErrorDeadlineExceeded},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			done := make(chan struct{})
			close(done)
			ctx := &terminalDoneContext{terminal: testCase.err, done: done}
			if err := waitAdmissionDrain(ctx, make(chan struct{})); dkim2.ReplayErrorCodeOf(err) != testCase.want {
				t.Fatalf("code=%q", dkim2.ReplayErrorCodeOf(err))
			}
		})
	}
}

// TestRecoveryFactsClearOnlyAuthorizedClasses proves independently clearable degradation.
func TestRecoveryFactsClearOnlyAuthorizedClasses(t *testing.T) {
	var facts recoveryFacts
	facts.add(recoveryTransient)
	facts.add(recoveryRevalidation)
	facts.add(recoveryRestart)
	facts.addStaleEvidence()
	facts.clearTransient()
	if facts.has(recoveryTransient) || !facts.has(recoveryRevalidation) ||
		!facts.has(recoveryRestart) || facts.load()&recoveryStaleEvidenceBit == 0 {
		t.Fatalf("transient clear facts=%03b", facts.load())
	}
	facts.clearRevalidation()
	if facts.has(recoveryRevalidation) || !facts.has(recoveryRestart) ||
		facts.load()&recoveryStaleEvidenceBit == 0 {
		t.Fatalf("revalidation clear facts=%03b", facts.load())
	}
	facts.clearStaleEvidence()
	facts.clearTransient()
	facts.clearRevalidation()
	if !facts.has(recoveryRestart) || facts.load()&recoveryStaleEvidenceBit != 0 {
		t.Fatal("ordinary recovery cleared restart fact")
	}
}

// TestRecoveryFactsUnknownClassFailsClosed proves zero and future classes become restart facts.
func TestRecoveryFactsUnknownClassFailsClosed(t *testing.T) {
	for _, class := range []recoveryClass{recoveryNone, 255} {
		var facts recoveryFacts
		facts.add(class)
		if !facts.has(recoveryRestart) {
			t.Fatalf("class %d did not fail closed", class)
		}
	}
}

// TestRecoveryFactsConcurrentPublicationLosesNoStickyFailure covers CAS races.
func TestRecoveryFactsConcurrentPublicationLosesNoStickyFailure(t *testing.T) {
	for range 100 {
		var facts recoveryFacts
		start := make(chan struct{})
		var workers sync.WaitGroup
		for _, class := range []recoveryClass{recoveryTransient, recoveryRevalidation, recoveryRestart} {
			workers.Add(1)
			go func(class recoveryClass) {
				defer workers.Done()
				<-start
				facts.add(class)
			}(class)
		}
		close(start)
		workers.Wait()
		if !facts.has(recoveryTransient) || !facts.has(recoveryRevalidation) || !facts.has(recoveryRestart) {
			t.Fatalf("lost concurrent fact=%03b", facts.load())
		}
	}
}

// TestEvidenceDeadlineUsesExactFiveMinuteBoundary freezes stale semantics.
func TestEvidenceDeadlineUsesExactFiveMinuteBoundary(t *testing.T) {
	base := time.Unix(10_000, 0)
	var evidence evidenceState
	if err := evidence.refresh(base); err != nil {
		t.Fatal(err)
	}
	if !evidence.fresh(base.Add(securityEvidenceValidity - time.Nanosecond)) {
		t.Fatal("evidence stale before exact boundary")
	}
	if evidence.fresh(base.Add(securityEvidenceValidity)) {
		t.Fatal("evidence fresh at exact boundary")
	}
}

// TestEvidenceDeadlineRejectsZeroBackwardAndPanicClock covers timer invariants.
func TestEvidenceDeadlineRejectsZeroBackwardAndPanicClock(t *testing.T) {
	var evidence evidenceState
	if err := evidence.refresh(time.Time{}); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
		t.Fatalf("zero refresh code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	base := time.Unix(10_000, 0)
	if err := evidence.refresh(base); err != nil {
		t.Fatal(err)
	}
	if err := evidence.refresh(base.Add(-time.Nanosecond)); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
		t.Fatalf("backward refresh code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	if _, err := readSecurityClock(panicSecurityClock{}); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
		t.Fatalf("panic clock code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	if err := evidence.refresh(time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
		t.Fatalf("overflow refresh code=%q", dkim2.ReplayErrorCodeOf(err))
	}
}

// TestEvidenceClockPublicationSerializesOverlappingSamples without false rollback.
func TestEvidenceClockPublicationSerializesOverlappingSamples(t *testing.T) {
	base := time.Unix(10_000, 0)
	clock := &barrierSecurityClock{
		values:  []time.Time{base, base.Add(time.Second)},
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	var evidence evidenceState
	owner := newSerializedSecurityClock(clock)
	results := make(chan error, 2)
	go func() { results <- evidence.refreshClock(owner) }()
	<-clock.started
	go func() { results <- evidence.refreshClock(owner) }()
	close(clock.release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("valid overlapping clock sample failed: %v", err)
		}
	}
	if clock.calls.Load() != 2 {
		t.Fatalf("clock samples=%d want=2", clock.calls.Load())
	}
}

// TestEvidenceClockPublicationRejectsSequentialRollback preserves rollback detection.
func TestEvidenceClockPublicationRejectsSequentialRollback(t *testing.T) {
	base := time.Unix(10_000, 0)
	clock := &mutableSecurityClock{now: base.Add(time.Second)}
	owner := newSerializedSecurityClock(clock)
	var evidence evidenceState
	if err := evidence.refreshClock(owner); err != nil {
		t.Fatal(err)
	}
	clock.set(base)
	if err := evidence.refreshClock(owner); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
		t.Fatalf("rollback code=%q", dkim2.ReplayErrorCodeOf(err))
	}
}

// TestStaleObservationCannotOutliveNewEvidence serializes stale publication before healing.
func TestStaleObservationCannotOutliveNewEvidence(t *testing.T) {
	now := time.Unix(10_000, 0)
	source := &barrierSecurityClock{
		values:  []time.Time{now, now},
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	store := &Store{storeCore: &storeCore{
		securityEnforced: true,
		clock:            newSerializedSecurityClock(source),
	}}
	if err := store.evidence.refresh(now.Add(-securityEvidenceValidity)); err != nil {
		t.Fatal(err)
	}

	checkResult := make(chan error, 1)
	go func() { checkResult <- store.requireFreshSecurityEvidence() }()
	<-source.started

	refreshStarted := make(chan struct{})
	refreshResult := make(chan error, 1)
	go func() {
		close(refreshStarted)
		refreshResult <- store.clock.withSample(func(sample time.Time) error {
			if err := store.evidence.refreshFromAuditSample(sample, sample); err != nil {
				return err
			}
			store.facts.clearStaleEvidence()
			return nil
		})
	}()
	<-refreshStarted
	select {
	case err := <-refreshResult:
		t.Fatalf("healing bypassed stale observation transaction: %v", err)
	default:
	}

	close(source.release)
	if err := <-checkResult; dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorUnavailable {
		t.Fatalf("stale check code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	if err := <-refreshResult; err != nil {
		t.Fatal(err)
	}
	if store.facts.has(recoveryRevalidation) ||
		store.facts.load()&recoveryStaleEvidenceBit != 0 ||
		!store.evidence.fresh(now) {
		t.Fatal("older stale observation outlived newer successful evidence")
	}
}

type panicSecurityClock struct{}

// Now panics to exercise the bounded timer seam.
func (panicSecurityClock) Now() time.Time { panic("synthetic security clock") }

type barrierSecurityClock struct {
	values  []time.Time
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

// Now blocks the first sample so publication sees one inverted ordering.
func (c *barrierSecurityClock) Now() time.Time {
	index := int(c.calls.Add(1)) - 1
	if index == 0 {
		close(c.started)
		<-c.release
	}
	return c.values[index]
}

// waitAtomicCount waits for one deterministic atomic count.
func waitAtomicCount(t *testing.T, value *atomic.Int32, expected int32) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for value.Load() != expected {
		if time.Now().After(deadline) {
			t.Fatalf("count=%d want=%d", value.Load(), expected)
		}
		runtime.Gosched()
	}
}
