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
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
)

// healthProbeWaitResponse controls one deterministic one-shot wait.
type healthProbeWaitResponse struct {
	advance time.Duration
	elapsed bool
}

// healthProbeSchedule is a controllable monotonic schedule.
type healthProbeSchedule struct {
	mu        sync.Mutex
	now       time.Time
	waitCalls chan time.Duration
	responses chan healthProbeWaitResponse
	nowPanic  atomic.Bool
	waitPanic atomic.Bool
	afterWait func()
}

// Now returns the synchronized test instant.
func (s *healthProbeSchedule) Now() time.Time {
	if s.nowPanic.Load() {
		panic("protected schedule now marker")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now
}

// Wait exposes the requested delay and advances only on one controlled response.
func (s *healthProbeSchedule) Wait(done <-chan struct{}, delay time.Duration) bool {
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
func (s *healthProbeSchedule) advance(duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = s.now.Add(duration)
}

// healthProbeTarget is a deterministic non-overlap target.
type healthProbeTarget struct {
	mu            sync.Mutex
	interval      time.Duration
	schedule      *healthProbeSchedule
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

// healthProbePanicObserver records and panics during terminal publication.
type healthProbePanicObserver struct {
	calls atomic.Int32
}

// NotifyServeReturn records the attempt before raising one hostile panic.
func (o *healthProbePanicObserver) NotifyServeReturn() {
	o.calls.Add(1)
	panic("private observer marker")
}

// ProbeHealth records one call, checks overlap, and advances simulated work time.
func (t *healthProbeTarget) ProbeHealth(context.Context) error {
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

// TestReplayHealthProbeCancellationBoundariesPreventFurtherDispatch proves context precedence.
func TestReplayHealthProbeCancellationBoundariesPreventFurtherDispatch(t *testing.T) {
	t.Run("after-wait-before-dispatch", func(t *testing.T) {
		schedule, target, probe := newHealthProbeHarness(t, 10*time.Second)
		ctx, cancel := context.WithCancel(context.Background())
		schedule.afterWait = cancel
		result := make(chan error, 1)
		go func() { result <- probe.Run(ctx) }()
		assertHealthProbeDelay(t, schedule, 10*time.Second)
		schedule.responses <- healthProbeWaitResponse{advance: 10 * time.Second, elapsed: true}
		if err := awaitHealthProbeResult(t, result); !errors.Is(err, context.Canceled) || target.Calls() != 0 {
			t.Fatal("cancellation after wait crossed the dispatch boundary")
		}
	})
	t.Run("during-target", func(t *testing.T) {
		schedule, target, probe := newHealthProbeHarness(t, 10*time.Second)
		ctx, cancel := context.WithCancel(context.Background())
		target.duringCall = cancel
		result := make(chan error, 1)
		go func() { result <- probe.Run(ctx) }()
		assertHealthProbeDelay(t, schedule, 10*time.Second)
		schedule.responses <- healthProbeWaitResponse{advance: 10 * time.Second, elapsed: true}
		if err := awaitHealthProbeResult(t, result); !errors.Is(err, context.Canceled) || target.Calls() != 1 {
			t.Fatal("cancellation during target dispatched further work")
		}
	})
}

// HealthInterval returns the configured construction-time interval.
func (t *healthProbeTarget) HealthInterval() time.Duration {
	if t.panicInterval.Load() {
		panic("protected target interval marker")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.interval
}

// TestReplayHealthProbeKeepsDelayedWakeOnTheFixedGrid proves anchor stability.
func TestReplayHealthProbeKeepsDelayedWakeOnTheFixedGrid(t *testing.T) {
	schedule, target, probe := newHealthProbeHarness(t, 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- probe.Run(ctx) }()
	assertHealthProbeDelay(t, schedule, 10*time.Second)
	schedule.responses <- healthProbeWaitResponse{advance: 12 * time.Second, elapsed: true}
	assertHealthProbeDelay(t, schedule, 8*time.Second)
	if target.Calls() != 1 {
		t.Fatal("delayed first wake queued more than one probe")
	}
	cancel()
	if err := awaitHealthProbeResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() returned %v after cancellation", err)
	}
}

// Calls returns the synchronized execution count.
func (t *healthProbeTarget) Calls() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.calls
}

// TestReplayHealthProbeUsesStartToStartCadence proves exact delay projection.
func TestReplayHealthProbeUsesStartToStartCadence(t *testing.T) {
	schedule, target, probe := newHealthProbeHarness(t, 10*time.Second)
	target.durations = []time.Duration{2 * time.Second, 7 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- probe.Run(ctx) }()

	assertHealthProbeDelay(t, schedule, 10*time.Second)
	schedule.responses <- healthProbeWaitResponse{advance: 10 * time.Second, elapsed: true}
	assertHealthProbeDelay(t, schedule, 8*time.Second)
	schedule.responses <- healthProbeWaitResponse{advance: 8 * time.Second, elapsed: true}
	assertHealthProbeDelay(t, schedule, 3*time.Second)

	target.mu.Lock()
	target.interval = 60 * time.Second
	target.mu.Unlock()
	schedule.responses <- healthProbeWaitResponse{advance: 3 * time.Second, elapsed: true}
	assertHealthProbeDelay(t, schedule, 10*time.Second)
	cancel()
	if err := awaitHealthProbeResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() returned %v after cancellation", err)
	}
	if target.Calls() != 3 || target.maxActive.Load() != 1 {
		t.Fatal("start-to-start loop changed interval or overlapped calls")
	}
}

// TestReplayHealthProbeCollapsesLongMissedIntervalsIntoOneCatchup proves the ticker regression.
func TestReplayHealthProbeCollapsesLongMissedIntervalsIntoOneCatchup(t *testing.T) {
	schedule, target, probe := newHealthProbeHarness(t, 10*time.Second)
	target.durations = []time.Duration{35 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- probe.Run(ctx) }()

	assertHealthProbeDelay(t, schedule, 10*time.Second)
	schedule.responses <- healthProbeWaitResponse{advance: 10 * time.Second, elapsed: true}
	assertHealthProbeDelay(t, schedule, 0)
	if target.Calls() != 1 {
		t.Fatal("long probe overlapped or created queued executions")
	}
	schedule.responses <- healthProbeWaitResponse{elapsed: true}
	assertHealthProbeDelay(t, schedule, 5*time.Second)
	if target.Calls() != 2 || target.maxActive.Load() != 1 {
		t.Fatal("missed intervals did not collapse into exactly one catch-up")
	}
	cancel()
	if err := awaitHealthProbeResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() returned %v after cancellation", err)
	}
}

// TestReplayHealthProbeContinuesOrdinaryReplayErrors proves resilient periodic operation.
func TestReplayHealthProbeContinuesOrdinaryReplayErrors(t *testing.T) {
	schedule, target, probe := newHealthProbeHarness(t, 10*time.Second)
	target.responses = []error{
		dkim2.NewReplayError(dkim2.ReplayErrorUnavailable),
		dkim2.NewReplayError(dkim2.ReplayErrorInconsistent),
		nil,
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- probe.Run(ctx) }()
	for range 3 {
		assertHealthProbeDelay(t, schedule, 10*time.Second)
		schedule.responses <- healthProbeWaitResponse{advance: 10 * time.Second, elapsed: true}
	}
	assertHealthProbeDelay(t, schedule, 10*time.Second)
	cancel()
	if err := awaitHealthProbeResult(t, result); !errors.Is(err, context.Canceled) || target.Calls() != 3 {
		t.Fatal("ordinary replay error stopped the periodic loop")
	}
}

// TestReplayHealthProbeContinuesEveryTypedProbeFailure proves that no closed
// replay code ends the loop: probe failures are backend observations that the
// store records as recovery facts, never loop terminations.
func TestReplayHealthProbeContinuesEveryTypedProbeFailure(t *testing.T) {
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
			schedule, target, probe := newHealthProbeHarness(t, 10*time.Second)
			target.responses = []error{dkim2.NewReplayError(code)}
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() { result <- probe.Run(ctx) }()
			assertHealthProbeDelay(t, schedule, 10*time.Second)
			schedule.responses <- healthProbeWaitResponse{advance: 10 * time.Second, elapsed: true}
			assertHealthProbeDelay(t, schedule, 10*time.Second)
			cancel()
			if err := awaitHealthProbeResult(t, result); !errors.Is(err, context.Canceled) || target.Calls() != 1 {
				t.Fatalf("typed %q probe failure ended the loop: %v", code, err)
			}
		})
	}
}

// TestReplayHealthProbeStopsOnUntypedTargetErrors proves that only a broken
// target invariant, never a backend observation, returns from the loop.
func TestReplayHealthProbeStopsOnUntypedTargetErrors(t *testing.T) {
	schedule, target, probe := newHealthProbeHarness(t, 10*time.Second)
	target.responses = []error{errors.New("protected target error marker")}
	result := make(chan error, 1)
	go func() { result <- probe.Run(context.Background()) }()
	assertHealthProbeDelay(t, schedule, 10*time.Second)
	schedule.responses <- healthProbeWaitResponse{advance: 10 * time.Second, elapsed: true}
	err := awaitHealthProbeResult(t, result)
	if !IsReplayRuntimeError(err) || strings.Contains(fmt.Sprint(err), "marker") {
		t.Fatalf("Run() exposed terminal target error %v", err)
	}
}

// TestReplayHealthProbeHonorsTerminalContextAndRejectsConcurrentRun proves lifecycle.
func TestReplayHealthProbeHonorsTerminalContextAndRejectsConcurrentRun(t *testing.T) {
	schedule, _, probe := newHealthProbeHarness(t, 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { first <- probe.Run(ctx) }()
	assertHealthProbeDelay(t, schedule, 10*time.Second)
	if err := probe.Run(context.Background()); !IsReplayRuntimeError(err) {
		t.Fatal("concurrent Run() was not rejected")
	}
	cancel()
	if err := awaitHealthProbeResult(t, first); !errors.Is(err, context.Canceled) {
		t.Fatalf("active Run() returned %v after cancellation", err)
	}
	alreadyCancelled, cancelSecond := context.WithCancel(context.Background())
	cancelSecond()
	if err := probe.Run(alreadyCancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("terminal preflight context did not retain exact precedence")
	}
}

// TestReplayHealthProbeContainsObserverPanicBeforeClearingRunning freezes terminal order.
func TestReplayHealthProbeContainsObserverPanicBeforeClearingRunning(t *testing.T) {
	schedule, _, probe := newHealthProbeHarness(t, 10*time.Second)
	observer := &healthProbePanicObserver{}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- probe.RunObserved(ctx, observer) }()
	<-probe.Started()
	if !probe.Running() {
		t.Fatal("Started closed without live Run ownership")
	}
	if err := probe.Activate(); err != nil {
		t.Fatalf("activate health probe: %v", err)
	}
	assertHealthProbeDelay(t, schedule, 10*time.Second)
	cancel()
	if err := awaitHealthProbeResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunObserved returned %v", err)
	}
	if observer.calls.Load() != 1 {
		t.Fatalf("observer calls=%d, want 1", observer.calls.Load())
	}
	if probe.Running() {
		t.Fatal("observer panic left Running true")
	}
}

// TestReplayHealthProbeContainsHostileScheduleAndTargetBehavior proves panic boundaries.
func TestReplayHealthProbeContainsHostileScheduleAndTargetBehavior(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*healthProbeSchedule, *healthProbeTarget)
		drive  bool
	}{
		{
			name: "now-panic",
			mutate: func(schedule *healthProbeSchedule, _ *healthProbeTarget) {
				schedule.nowPanic.Store(true)
			},
		},
		{
			name: "wait-panic",
			mutate: func(schedule *healthProbeSchedule, _ *healthProbeTarget) {
				schedule.waitPanic.Store(true)
			},
		},
		{
			name: "target-panic",
			mutate: func(_ *healthProbeSchedule, target *healthProbeTarget) {
				target.panicCall.Store(true)
			},
			drive: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schedule, target, probe := newHealthProbeHarness(t, 10*time.Second)
			test.mutate(schedule, target)
			result := make(chan error, 1)
			go func() { result <- probe.Run(context.Background()) }()
			if test.drive {
				assertHealthProbeDelay(t, schedule, 10*time.Second)
				schedule.responses <- healthProbeWaitResponse{advance: 10 * time.Second, elapsed: true}
			}
			if err := awaitHealthProbeResult(t, result); !IsReplayRuntimeError(err) {
				t.Fatalf("Run() returned %v", err)
			}
		})
	}
}

// TestReplayHealthProbeRejectsInvalidConstructionAndClockBehavior proves closed seams.
func TestReplayHealthProbeRejectsInvalidConstructionAndClockBehavior(t *testing.T) {
	var typedNilTarget *healthProbeTarget
	var typedNilSchedule *healthProbeSchedule
	for _, input := range []struct {
		target   replayHealthProbeTarget
		schedule replaySchedule
	}{
		{nil, &healthProbeSchedule{}},
		{typedNilTarget, &healthProbeSchedule{}},
		{&healthProbeTarget{interval: 10 * time.Second}, nil},
		{&healthProbeTarget{interval: 10 * time.Second}, typedNilSchedule},
		{&healthProbeTarget{interval: time.Second - time.Nanosecond}, &healthProbeSchedule{}},
		{&healthProbeTarget{interval: 0}, &healthProbeSchedule{}},
		{&healthProbeTarget{interval: 61 * time.Second}, &healthProbeSchedule{}},
	} {
		if value, err := newReplayHealthProbe(input.target, input.schedule); value != nil || !IsReplayRuntimeError(err) {
			t.Fatal("invalid construction seam was accepted")
		}
	}
	if value, err := newReplayHealthProbe(
		&healthProbeTarget{interval: time.Second}, &healthProbeSchedule{},
	); value == nil || err != nil {
		t.Fatal("minimum one-second interval was rejected")
	}
	panicTarget := &healthProbeTarget{interval: 10 * time.Second}
	panicTarget.panicInterval.Store(true)
	if value, err := newReplayHealthProbe(panicTarget, &healthProbeSchedule{}); value != nil ||
		!IsReplayRuntimeError(err) {
		t.Fatal("panicking interval accessor escaped construction")
	}

	schedule, _, probe := newHealthProbeHarness(t, 10*time.Second)
	result := make(chan error, 1)
	go func() { result <- probe.Run(context.Background()) }()
	assertHealthProbeDelay(t, schedule, 10*time.Second)
	schedule.responses <- healthProbeWaitResponse{advance: -time.Second, elapsed: true}
	if err := awaitHealthProbeResult(t, result); !IsReplayRuntimeError(err) {
		t.Fatal("backwards clock did not fail closed")
	}

	schedule, _, probe = newHealthProbeHarness(t, 10*time.Second)
	result = make(chan error, 1)
	go func() { result <- probe.Run(context.Background()) }()
	assertHealthProbeDelay(t, schedule, 10*time.Second)
	schedule.responses <- healthProbeWaitResponse{elapsed: false}
	if err := awaitHealthProbeResult(t, result); !IsReplayRuntimeError(err) {
		t.Fatal("spurious wait termination did not fail closed")
	}

	schedule, _, probe = newHealthProbeHarness(t, 10*time.Second)
	schedule.now = time.Time{}
	if err := probe.Run(context.Background()); !IsReplayRuntimeError(err) {
		t.Fatal("zero schedule time did not fail closed")
	}

	schedule, target, probe := newHealthProbeHarness(t, 10*time.Second)
	schedule.afterWait = func() {
		schedule.mu.Lock()
		schedule.now = time.Time{}
		schedule.mu.Unlock()
	}
	result = make(chan error, 1)
	go func() { result <- probe.Run(context.Background()) }()
	assertHealthProbeDelay(t, schedule, 10*time.Second)
	schedule.responses <- healthProbeWaitResponse{advance: 10 * time.Second, elapsed: true}
	if err := awaitHealthProbeResult(t, result); !IsReplayRuntimeError(err) || target.Calls() != 0 {
		t.Fatal("zero post-wait time crossed the dispatch boundary")
	}

	schedule, target, probe = newHealthProbeHarness(t, 10*time.Second)
	schedule.afterWait = func() {
		schedule.mu.Lock()
		schedule.now = time.Date(5000, 1, 1, 0, 0, 0, 0, time.UTC)
		schedule.mu.Unlock()
	}
	result = make(chan error, 1)
	go func() { result <- probe.Run(context.Background()) }()
	assertHealthProbeDelay(t, schedule, 10*time.Second)
	schedule.responses <- healthProbeWaitResponse{elapsed: true}
	if err := awaitHealthProbeResult(t, result); !IsReplayRuntimeError(err) || target.Calls() != 0 {
		t.Fatal("saturated missed-grid arithmetic crossed the dispatch boundary")
	}
}

// TestReplayHealthProbePrivacyMatrixRejectsTraversal proves secret-safe diagnostics.
func TestReplayHealthProbePrivacyMatrixRejectsTraversal(t *testing.T) {
	_, target, probe := newHealthProbeHarness(t, 10*time.Second)
	target.marker = "health-probe-protected-marker"
	var interfaceValue any = probe
	nested := struct{ Loop any }{Loop: probe}
	values := []any{
		probe,
		*probe,
		interfaceValue,
		[]any{probe, *probe},
		nested,
		map[*ReplayHealthProbe]string{probe: "value"},
		map[ReplayHealthProbe]bool{*probe: true},
	}
	for _, value := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%p"} {
			representation := fmt.Sprintf(verb, value)
			if strings.Contains(representation, target.marker) {
				t.Fatalf("%s exposed target state: %q", verb, representation)
			}
			if verb != "%p" && !strings.Contains(representation, replayHealthProbeRedacted) {
				t.Fatalf("%s omitted redacted token: %q", verb, representation)
			}
		}
	}
	if data, err := json.Marshal(probe); data != nil || !IsReplayRuntimeError(err) {
		t.Fatal("JSON serialization did not reject loop state")
	}
	if data, err := probe.MarshalText(); data != nil || !IsReplayRuntimeError(err) {
		t.Fatal("text serialization did not reject loop state")
	}
}

// TestReplayHealthProbeRejectsHostileContextContracts proves bounded context handling.
func TestReplayHealthProbeRejectsHostileContextContracts(t *testing.T) {
	var typedNil *hostileReplayContext
	contexts := []context.Context{
		nil,
		typedNil,
		hostileReplayContext{panicErr: true},
		hostileReplayContext{panicDeadline: true},
		hostileReplayContext{err: errors.New("foreign context marker")},
		healthProbeDonePanicContext{},
	}
	for _, ctx := range contexts {
		_, _, probe := newHealthProbeHarness(t, 10*time.Second)
		if err := probe.Run(ctx); !IsReplayRuntimeError(err) {
			t.Fatalf("hostile context returned %v", err)
		}
	}
	_, _, probe := newHealthProbeHarness(t, 10*time.Second)
	if err := probe.Run(expiredNilErrorContext{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline returned %v", err)
	}
}

// healthProbeDonePanicContext panics from its Done accessor.
type healthProbeDonePanicContext struct{}

// Deadline reports no deadline.
func (healthProbeDonePanicContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done rejects unsafe channel access.
func (healthProbeDonePanicContext) Done() <-chan struct{} {
	panic("protected context done marker")
}

// Err reports no terminal state.
func (healthProbeDonePanicContext) Err() error { return nil }

// Value returns no value.
func (healthProbeDonePanicContext) Value(any) any { return nil }

// newHealthProbeHarness constructs one deterministic loop test harness.
func newHealthProbeHarness(
	t *testing.T,
	interval time.Duration,
) (*healthProbeSchedule, *healthProbeTarget, *ReplayHealthProbe) {
	t.Helper()
	schedule := &healthProbeSchedule{
		now:       time.Unix(1_700_000_000, 0),
		waitCalls: make(chan time.Duration),
		responses: make(chan healthProbeWaitResponse),
	}
	target := &healthProbeTarget{interval: interval, schedule: schedule}
	probe, err := newReplayHealthProbe(target, schedule)
	if err != nil {
		t.Fatalf("newReplayHealthProbe() failed: %v", err)
	}
	return schedule, target, probe
}

// assertHealthProbeDelay receives one bounded wait request.
func assertHealthProbeDelay(
	t *testing.T,
	schedule *healthProbeSchedule,
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

// awaitHealthProbeResult bounds every negative loop assertion.
func awaitHealthProbeResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for health-probe termination")
		return nil
	}
}

// TestReplayHealthProbeIsSelectedOnlyForTheRedisBackend proves the lifecycle
// starts the probe for exactly the networked backend and fails closed when a
// redis backend is not owned by the production runtime.
func TestReplayHealthProbeIsSelectedOnlyForTheRedisBackend(t *testing.T) {
	for _, backend := range []config.ReplayBackend{config.ReplayMemory, config.ReplayDisabled} {
		if probe, err := replayHealthProbeFor(backend, nil); probe != nil || err != nil {
			t.Fatalf("backend %v selected a health probe (%v, %v)", backend, probe, err)
		}
	}
	if probe, err := replayHealthProbeFor(config.ReplayRedis, nil); probe != nil || !IsLifecycleError(err) {
		t.Fatalf("foreign redis replay owner returned (%v, %v)", probe, err)
	}
	material := runtimeMaterial(t, runtimeRedisYAML())
	authority := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: true}
	runtime := runtimeWithAuthority(t, material, authority)
	t.Cleanup(func() {
		if err := closeReplayRuntimeBounded(runtime); err != nil {
			t.Errorf("Close() failed: %v", err)
		}
	})
	probe, err := replayHealthProbeFor(config.ReplayRedis, runtime)
	if err != nil || nilInterface(probe) {
		t.Fatalf("redis backend did not select a health probe: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- probe.RunObserved(ctx, &healthProbeCountingObserver{}) }()
	<-probe.Started()
	if err := probe.Activate(); err != nil || !probe.Running() {
		t.Fatalf("selected probe did not activate: %v", err)
	}
	cancel()
	if err := awaitHealthProbeResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("selected probe returned %v", err)
	}
}

// healthProbeCountingObserver records terminal publication without side effects.
type healthProbeCountingObserver struct {
	calls atomic.Int32
}

// NotifyServeReturn records one terminal publication.
func (o *healthProbeCountingObserver) NotifyServeReturn() { o.calls.Add(1) }
