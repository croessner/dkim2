package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/dkim2"
)

// revalidatorWaitResponse controls one deterministic one-shot wait.
type revalidatorWaitResponse struct {
	advance time.Duration
	elapsed bool
}

// revalidatorSchedule is a controllable monotonic schedule.
type revalidatorSchedule struct {
	mu        sync.Mutex
	now       time.Time
	waitCalls chan time.Duration
	responses chan revalidatorWaitResponse
	nowPanic  atomic.Bool
	waitPanic atomic.Bool
	afterWait func()
}

// Now returns the synchronized test instant.
func (s *revalidatorSchedule) Now() time.Time {
	if s.nowPanic.Load() {
		panic("protected schedule now marker")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now
}

// Wait exposes the requested delay and advances only on one controlled response.
func (s *revalidatorSchedule) Wait(done <-chan struct{}, delay time.Duration) bool {
	if s.waitPanic.Load() {
		panic("protected schedule wait marker")
	}
	select {
	case s.waitCalls <- delay:
	case <-done:
		return false
	}
	select {
	case response := <-s.responses:
		s.advance(response.advance)
		if s.afterWait != nil {
			s.afterWait()
		}
		return response.elapsed
	case <-done:
		return false
	}
}

// advance moves the monotonic test clock.
func (s *revalidatorSchedule) advance(duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = s.now.Add(duration)
}

// revalidatorTarget is a deterministic non-overlap target.
type revalidatorTarget struct {
	mu            sync.Mutex
	interval      time.Duration
	schedule      *revalidatorSchedule
	durations     []time.Duration
	responses     []error
	calls         int
	active        atomic.Int32
	maxActive     atomic.Int32
	callStarted   chan int
	panicCall     atomic.Bool
	panicInterval atomic.Bool
	duringCall    func()
	marker        string
}

// revalidatorPanicObserver records and panics during terminal publication.
type revalidatorPanicObserver struct {
	calls atomic.Int32
}

// NotifyServeReturn records the attempt before raising one hostile panic.
func (o *revalidatorPanicObserver) NotifyServeReturn() {
	o.calls.Add(1)
	panic("private observer marker")
}

// Revalidate records one call, checks overlap, and advances simulated work time.
func (t *revalidatorTarget) Revalidate(context.Context) error {
	if t.panicCall.Load() {
		panic("protected target call marker")
	}
	active := t.active.Add(1)
	defer t.active.Add(-1)
	for {
		maximum := t.maxActive.Load()
		if active <= maximum || t.maxActive.CompareAndSwap(maximum, active) {
			break
		}
	}
	t.mu.Lock()
	index := t.calls
	t.calls++
	duration := time.Duration(0)
	if index < len(t.durations) {
		duration = t.durations[index]
	}
	var response error
	if index < len(t.responses) {
		response = t.responses[index]
	}
	started := t.callStarted
	t.mu.Unlock()
	if started != nil {
		started <- index + 1
	}
	if t.duringCall != nil {
		t.duringCall()
	}
	if t.schedule != nil {
		t.schedule.advance(duration)
	}
	return response
}

// TestReplayRevalidatorCancellationBoundariesPreventFurtherDispatch proves context precedence.
func TestReplayRevalidatorCancellationBoundariesPreventFurtherDispatch(t *testing.T) {
	t.Run("after-wait-before-dispatch", func(t *testing.T) {
		schedule, target, revalidator := newRevalidatorHarness(t, 10*time.Second)
		ctx, cancel := context.WithCancel(context.Background())
		schedule.afterWait = cancel
		result := make(chan error, 1)
		go func() { result <- revalidator.Run(ctx) }()
		assertRevalidatorDelay(t, schedule, 10*time.Second)
		schedule.responses <- revalidatorWaitResponse{advance: 10 * time.Second, elapsed: true}
		if err := awaitRevalidatorResult(t, result); !errors.Is(err, context.Canceled) || target.Calls() != 0 {
			t.Fatal("cancellation after wait crossed the dispatch boundary")
		}
	})
	t.Run("during-target", func(t *testing.T) {
		schedule, target, revalidator := newRevalidatorHarness(t, 10*time.Second)
		ctx, cancel := context.WithCancel(context.Background())
		target.duringCall = cancel
		result := make(chan error, 1)
		go func() { result <- revalidator.Run(ctx) }()
		assertRevalidatorDelay(t, schedule, 10*time.Second)
		schedule.responses <- revalidatorWaitResponse{advance: 10 * time.Second, elapsed: true}
		if err := awaitRevalidatorResult(t, result); !errors.Is(err, context.Canceled) || target.Calls() != 1 {
			t.Fatal("cancellation during target dispatched further work")
		}
	})
}

// RevalidationInterval returns the configured construction-time interval.
func (t *revalidatorTarget) RevalidationInterval() time.Duration {
	if t.panicInterval.Load() {
		panic("protected target interval marker")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.interval
}

// TestReplayRevalidatorKeepsDelayedWakeOnTheFixedGrid proves anchor stability.
func TestReplayRevalidatorKeepsDelayedWakeOnTheFixedGrid(t *testing.T) {
	schedule, target, revalidator := newRevalidatorHarness(t, 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- revalidator.Run(ctx) }()
	assertRevalidatorDelay(t, schedule, 10*time.Second)
	schedule.responses <- revalidatorWaitResponse{advance: 12 * time.Second, elapsed: true}
	assertRevalidatorDelay(t, schedule, 8*time.Second)
	if target.Calls() != 1 {
		t.Fatal("delayed first wake queued more than one audit")
	}
	cancel()
	if err := awaitRevalidatorResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() returned %v after cancellation", err)
	}
}

// Calls returns the synchronized execution count.
func (t *revalidatorTarget) Calls() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.calls
}

// TestReplayRevalidatorUsesStartToStartCadence proves exact delay projection.
func TestReplayRevalidatorUsesStartToStartCadence(t *testing.T) {
	schedule, target, revalidator := newRevalidatorHarness(t, 10*time.Second)
	target.durations = []time.Duration{2 * time.Second, 7 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- revalidator.Run(ctx) }()

	assertRevalidatorDelay(t, schedule, 10*time.Second)
	schedule.responses <- revalidatorWaitResponse{advance: 10 * time.Second, elapsed: true}
	assertRevalidatorDelay(t, schedule, 8*time.Second)
	schedule.responses <- revalidatorWaitResponse{advance: 8 * time.Second, elapsed: true}
	assertRevalidatorDelay(t, schedule, 3*time.Second)

	target.mu.Lock()
	target.interval = 60 * time.Second
	target.mu.Unlock()
	schedule.responses <- revalidatorWaitResponse{advance: 3 * time.Second, elapsed: true}
	assertRevalidatorDelay(t, schedule, 10*time.Second)
	cancel()
	if err := awaitRevalidatorResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() returned %v after cancellation", err)
	}
	if target.Calls() != 3 || target.maxActive.Load() != 1 {
		t.Fatal("start-to-start loop changed interval or overlapped calls")
	}
}

// TestReplayRevalidatorCollapsesLongMissedIntervalsIntoOneCatchup proves the ticker regression.
func TestReplayRevalidatorCollapsesLongMissedIntervalsIntoOneCatchup(t *testing.T) {
	schedule, target, revalidator := newRevalidatorHarness(t, 10*time.Second)
	target.durations = []time.Duration{35 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- revalidator.Run(ctx) }()

	assertRevalidatorDelay(t, schedule, 10*time.Second)
	schedule.responses <- revalidatorWaitResponse{advance: 10 * time.Second, elapsed: true}
	assertRevalidatorDelay(t, schedule, 0)
	if target.Calls() != 1 {
		t.Fatal("long audit overlapped or created queued executions")
	}
	schedule.responses <- revalidatorWaitResponse{elapsed: true}
	assertRevalidatorDelay(t, schedule, 5*time.Second)
	if target.Calls() != 2 || target.maxActive.Load() != 1 {
		t.Fatal("missed intervals did not collapse into exactly one catch-up")
	}
	cancel()
	if err := awaitRevalidatorResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() returned %v after cancellation", err)
	}
}

// TestReplayRevalidatorContinuesOrdinaryReplayErrors proves resilient periodic operation.
func TestReplayRevalidatorContinuesOrdinaryReplayErrors(t *testing.T) {
	schedule, target, revalidator := newRevalidatorHarness(t, 10*time.Second)
	target.responses = []error{
		dkim2.NewReplayError(dkim2.ReplayErrorUnavailable),
		dkim2.NewReplayError(dkim2.ReplayErrorInconsistent),
		nil,
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- revalidator.Run(ctx) }()
	for range 3 {
		assertRevalidatorDelay(t, schedule, 10*time.Second)
		schedule.responses <- revalidatorWaitResponse{advance: 10 * time.Second, elapsed: true}
	}
	assertRevalidatorDelay(t, schedule, 10*time.Second)
	cancel()
	if err := awaitRevalidatorResult(t, result); !errors.Is(err, context.Canceled) || target.Calls() != 3 {
		t.Fatal("ordinary replay error stopped the periodic loop")
	}
}

// TestReplayRevalidatorUsesExactAllowedErrorTaxonomy proves every closed code.
func TestReplayRevalidatorUsesExactAllowedErrorTaxonomy(t *testing.T) {
	allowed := map[dkim2.ReplayErrorCode]bool{
		dkim2.ReplayErrorLimitExceeded:     true,
		dkim2.ReplayErrorUnavailable:       true,
		dkim2.ReplayErrorInconsistent:      true,
		dkim2.ReplayErrorInternalInvariant: true,
	}
	codes := []dkim2.ReplayErrorCode{
		dkim2.ReplayErrorInvalidRequest,
		dkim2.ReplayErrorMisconfigured,
		dkim2.ReplayErrorLimitExceeded,
		dkim2.ReplayErrorUnavailable,
		dkim2.ReplayErrorIndeterminate,
		dkim2.ReplayErrorInconsistent,
		dkim2.ReplayErrorCancelled,
		dkim2.ReplayErrorDeadlineExceeded,
		dkim2.ReplayErrorClosed,
		dkim2.ReplayErrorInternalInvariant,
	}
	for _, code := range codes {
		t.Run(string(code), func(t *testing.T) {
			schedule, target, revalidator := newRevalidatorHarness(t, 10*time.Second)
			target.responses = []error{dkim2.NewReplayError(code)}
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() { result <- revalidator.Run(ctx) }()
			assertRevalidatorDelay(t, schedule, 10*time.Second)
			schedule.responses <- revalidatorWaitResponse{advance: 10 * time.Second, elapsed: true}
			if allowed[code] {
				assertRevalidatorDelay(t, schedule, 10*time.Second)
				cancel()
				if err := awaitRevalidatorResult(t, result); !errors.Is(err, context.Canceled) {
					t.Fatalf("allowed %q did not continue", code)
				}
				return
			}
			if err := awaitRevalidatorResult(t, result); !IsReplayRuntimeError(err) {
				t.Fatalf("forbidden %q returned %v", code, err)
			}
			cancel()
		})
	}
}

// TestReplayRevalidatorStopsOnUnknownAndUnprovedContextErrors proves fail-closed taxonomy.
func TestReplayRevalidatorStopsOnUnknownAndUnprovedContextErrors(t *testing.T) {
	tests := []error{
		errors.New("protected target error marker"),
		dkim2.NewReplayError(dkim2.ReplayErrorCancelled),
		dkim2.NewReplayError(dkim2.ReplayErrorDeadlineExceeded),
	}
	for _, response := range tests {
		schedule, target, revalidator := newRevalidatorHarness(t, 10*time.Second)
		target.responses = []error{response}
		result := make(chan error, 1)
		go func() { result <- revalidator.Run(context.Background()) }()
		assertRevalidatorDelay(t, schedule, 10*time.Second)
		schedule.responses <- revalidatorWaitResponse{advance: 10 * time.Second, elapsed: true}
		if err := awaitRevalidatorResult(t, result); !IsReplayRuntimeError(err) {
			t.Fatalf("Run() exposed terminal target error %v", err)
		}
	}
}

// TestReplayRevalidatorHonorsTerminalContextAndRejectsConcurrentRun proves lifecycle.
func TestReplayRevalidatorHonorsTerminalContextAndRejectsConcurrentRun(t *testing.T) {
	schedule, _, revalidator := newRevalidatorHarness(t, 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { first <- revalidator.Run(ctx) }()
	assertRevalidatorDelay(t, schedule, 10*time.Second)
	if err := revalidator.Run(context.Background()); !IsReplayRuntimeError(err) {
		t.Fatal("concurrent Run() was not rejected")
	}
	cancel()
	if err := awaitRevalidatorResult(t, first); !errors.Is(err, context.Canceled) {
		t.Fatalf("active Run() returned %v after cancellation", err)
	}
	alreadyCancelled, cancelSecond := context.WithCancel(context.Background())
	cancelSecond()
	if err := revalidator.Run(alreadyCancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("terminal preflight context did not retain exact precedence")
	}
}

// TestReplayRevalidatorContainsObserverPanicBeforeClearingRunning freezes terminal order.
func TestReplayRevalidatorContainsObserverPanicBeforeClearingRunning(t *testing.T) {
	schedule, _, revalidator := newRevalidatorHarness(t, 10*time.Second)
	observer := &revalidatorPanicObserver{}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- revalidator.RunObserved(ctx, observer) }()
	<-revalidator.Started()
	if !revalidator.Running() {
		t.Fatal("Started closed without live Run ownership")
	}
	if err := revalidator.Activate(); err != nil {
		t.Fatalf("activate revalidator: %v", err)
	}
	assertRevalidatorDelay(t, schedule, 10*time.Second)
	cancel()
	if err := awaitRevalidatorResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunObserved returned %v", err)
	}
	if observer.calls.Load() != 1 {
		t.Fatalf("observer calls=%d, want 1", observer.calls.Load())
	}
	if revalidator.Running() {
		t.Fatal("observer panic left Running true")
	}
}

// TestReplayRevalidatorContainsHostileScheduleAndTargetBehavior proves panic boundaries.
func TestReplayRevalidatorContainsHostileScheduleAndTargetBehavior(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*revalidatorSchedule, *revalidatorTarget)
		drive  bool
	}{
		{
			name: "now-panic",
			mutate: func(schedule *revalidatorSchedule, _ *revalidatorTarget) {
				schedule.nowPanic.Store(true)
			},
		},
		{
			name: "wait-panic",
			mutate: func(schedule *revalidatorSchedule, _ *revalidatorTarget) {
				schedule.waitPanic.Store(true)
			},
		},
		{
			name: "target-panic",
			mutate: func(_ *revalidatorSchedule, target *revalidatorTarget) {
				target.panicCall.Store(true)
			},
			drive: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schedule, target, revalidator := newRevalidatorHarness(t, 10*time.Second)
			test.mutate(schedule, target)
			result := make(chan error, 1)
			go func() { result <- revalidator.Run(context.Background()) }()
			if test.drive {
				assertRevalidatorDelay(t, schedule, 10*time.Second)
				schedule.responses <- revalidatorWaitResponse{advance: 10 * time.Second, elapsed: true}
			}
			if err := awaitRevalidatorResult(t, result); !IsReplayRuntimeError(err) {
				t.Fatalf("Run() returned %v", err)
			}
		})
	}
}

// TestReplayRevalidatorRejectsInvalidConstructionAndClockBehavior proves closed seams.
func TestReplayRevalidatorRejectsInvalidConstructionAndClockBehavior(t *testing.T) {
	var typedNilTarget *revalidatorTarget
	var typedNilSchedule *revalidatorSchedule
	for _, input := range []struct {
		target   replayRevalidationTarget
		schedule replaySchedule
	}{
		{nil, &revalidatorSchedule{}},
		{typedNilTarget, &revalidatorSchedule{}},
		{&revalidatorTarget{interval: 10 * time.Second}, nil},
		{&revalidatorTarget{interval: 10 * time.Second}, typedNilSchedule},
		{&revalidatorTarget{interval: 9 * time.Second}, &revalidatorSchedule{}},
		{&revalidatorTarget{interval: 61 * time.Second}, &revalidatorSchedule{}},
	} {
		if value, err := newReplayRevalidator(input.target, input.schedule); value != nil || !IsReplayRuntimeError(err) {
			t.Fatal("invalid construction seam was accepted")
		}
	}
	panicTarget := &revalidatorTarget{interval: 10 * time.Second}
	panicTarget.panicInterval.Store(true)
	if value, err := newReplayRevalidator(panicTarget, &revalidatorSchedule{}); value != nil ||
		!IsReplayRuntimeError(err) {
		t.Fatal("panicking interval accessor escaped construction")
	}

	schedule, _, revalidator := newRevalidatorHarness(t, 10*time.Second)
	result := make(chan error, 1)
	go func() { result <- revalidator.Run(context.Background()) }()
	assertRevalidatorDelay(t, schedule, 10*time.Second)
	schedule.responses <- revalidatorWaitResponse{advance: -time.Second, elapsed: true}
	if err := awaitRevalidatorResult(t, result); !IsReplayRuntimeError(err) {
		t.Fatal("backwards clock did not fail closed")
	}

	schedule, _, revalidator = newRevalidatorHarness(t, 10*time.Second)
	result = make(chan error, 1)
	go func() { result <- revalidator.Run(context.Background()) }()
	assertRevalidatorDelay(t, schedule, 10*time.Second)
	schedule.responses <- revalidatorWaitResponse{elapsed: false}
	if err := awaitRevalidatorResult(t, result); !IsReplayRuntimeError(err) {
		t.Fatal("spurious wait termination did not fail closed")
	}

	schedule, _, revalidator = newRevalidatorHarness(t, 10*time.Second)
	schedule.now = time.Time{}
	if err := revalidator.Run(context.Background()); !IsReplayRuntimeError(err) {
		t.Fatal("zero schedule time did not fail closed")
	}

	schedule, target, revalidator := newRevalidatorHarness(t, 10*time.Second)
	schedule.afterWait = func() {
		schedule.mu.Lock()
		schedule.now = time.Time{}
		schedule.mu.Unlock()
	}
	result = make(chan error, 1)
	go func() { result <- revalidator.Run(context.Background()) }()
	assertRevalidatorDelay(t, schedule, 10*time.Second)
	schedule.responses <- revalidatorWaitResponse{advance: 10 * time.Second, elapsed: true}
	if err := awaitRevalidatorResult(t, result); !IsReplayRuntimeError(err) || target.Calls() != 0 {
		t.Fatal("zero post-wait time crossed the dispatch boundary")
	}

	schedule, target, revalidator = newRevalidatorHarness(t, 10*time.Second)
	schedule.afterWait = func() {
		schedule.mu.Lock()
		schedule.now = time.Date(5000, 1, 1, 0, 0, 0, 0, time.UTC)
		schedule.mu.Unlock()
	}
	result = make(chan error, 1)
	go func() { result <- revalidator.Run(context.Background()) }()
	assertRevalidatorDelay(t, schedule, 10*time.Second)
	schedule.responses <- revalidatorWaitResponse{elapsed: true}
	if err := awaitRevalidatorResult(t, result); !IsReplayRuntimeError(err) || target.Calls() != 0 {
		t.Fatal("saturated missed-grid arithmetic crossed the dispatch boundary")
	}
}

// TestReplayRevalidatorPrivacyMatrixRejectsTraversal proves secret-safe diagnostics.
func TestReplayRevalidatorPrivacyMatrixRejectsTraversal(t *testing.T) {
	_, target, revalidator := newRevalidatorHarness(t, 10*time.Second)
	target.marker = "revalidator-protected-marker"
	var interfaceValue any = revalidator
	nested := struct{ Loop any }{Loop: revalidator}
	values := []any{
		revalidator,
		*revalidator,
		interfaceValue,
		[]any{revalidator, *revalidator},
		nested,
		map[*ReplayRevalidator]string{revalidator: "value"},
		map[ReplayRevalidator]bool{*revalidator: true},
	}
	for _, value := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%p"} {
			representation := fmt.Sprintf(verb, value)
			if strings.Contains(representation, target.marker) {
				t.Fatalf("%s exposed target state: %q", verb, representation)
			}
			if verb != "%p" && !strings.Contains(representation, replayRevalidatorRedacted) {
				t.Fatalf("%s omitted redacted token: %q", verb, representation)
			}
		}
	}
	if data, err := json.Marshal(revalidator); data != nil || !IsReplayRuntimeError(err) {
		t.Fatal("JSON serialization did not reject loop state")
	}
	if data, err := revalidator.MarshalText(); data != nil || !IsReplayRuntimeError(err) {
		t.Fatal("text serialization did not reject loop state")
	}
}

// TestReplayRevalidatorRejectsHostileContextContracts proves bounded context handling.
func TestReplayRevalidatorRejectsHostileContextContracts(t *testing.T) {
	var typedNil *hostileReplayContext
	contexts := []context.Context{
		nil,
		typedNil,
		hostileReplayContext{panicErr: true},
		hostileReplayContext{panicDeadline: true},
		hostileReplayContext{err: errors.New("foreign context marker")},
		revalidatorDonePanicContext{},
	}
	for _, ctx := range contexts {
		_, _, revalidator := newRevalidatorHarness(t, 10*time.Second)
		if err := revalidator.Run(ctx); !IsReplayRuntimeError(err) {
			t.Fatalf("hostile context returned %v", err)
		}
	}
	_, _, revalidator := newRevalidatorHarness(t, 10*time.Second)
	if err := revalidator.Run(expiredNilErrorContext{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline returned %v", err)
	}
}

// revalidatorDonePanicContext panics from its Done accessor.
type revalidatorDonePanicContext struct{}

// Deadline reports no deadline.
func (revalidatorDonePanicContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done rejects unsafe channel access.
func (revalidatorDonePanicContext) Done() <-chan struct{} {
	panic("protected context done marker")
}

// Err reports no terminal state.
func (revalidatorDonePanicContext) Err() error { return nil }

// Value returns no value.
func (revalidatorDonePanicContext) Value(any) any { return nil }

// newRevalidatorHarness constructs one deterministic loop test harness.
func newRevalidatorHarness(
	t *testing.T,
	interval time.Duration,
) (*revalidatorSchedule, *revalidatorTarget, *ReplayRevalidator) {
	t.Helper()
	schedule := &revalidatorSchedule{
		now:       time.Unix(1_700_000_000, 0),
		waitCalls: make(chan time.Duration),
		responses: make(chan revalidatorWaitResponse),
	}
	target := &revalidatorTarget{interval: interval, schedule: schedule}
	revalidator, err := newReplayRevalidator(target, schedule)
	if err != nil {
		t.Fatalf("newReplayRevalidator() failed: %v", err)
	}
	return schedule, target, revalidator
}

// assertRevalidatorDelay receives one bounded wait request.
func assertRevalidatorDelay(
	t *testing.T,
	schedule *revalidatorSchedule,
	expected time.Duration,
) {
	t.Helper()
	select {
	case actual := <-schedule.waitCalls:
		if actual != expected {
			t.Fatalf("wait delay = %s, want %s", actual, expected)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for schedule request")
	}
}

// awaitRevalidatorResult bounds every negative loop assertion.
func awaitRevalidatorResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for revalidator termination")
		return nil
	}
}
