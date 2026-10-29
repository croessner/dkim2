package app

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/croessner/dkim2"
)

const (
	replayHealthProbeRedacted   = "dkim2d_replay_health_probe"
	replayHealthMinimumInterval = time.Second
	replayHealthMaximumInterval = 60 * time.Second
)

// replayHealthProbeTarget is the narrow periodic replay backend probe boundary.
type replayHealthProbeTarget interface {
	ProbeHealth(context.Context) error
	HealthInterval() time.Duration
}

// replaySchedule owns monotonic start sampling and one-shot waits.
type replaySchedule interface {
	Now() time.Time
	Wait(<-chan struct{}, time.Duration) bool
}

// systemReplaySchedule adapts monotonic process time and one-shot timers.
type systemReplaySchedule struct{}

// Now samples process time while preserving its monotonic component.
func (systemReplaySchedule) Now() time.Time { return time.Now() }

// Wait blocks for one owned delay or caller termination and releases its timer.
func (systemReplaySchedule) Wait(done <-chan struct{}, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()
	select {
	case <-done:
		return false
	case <-timer.C:
		return true
	}
}

// ReplayHealthProbe owns one single-run start-to-start replay backend health
// probe loop. Probe failures are recorded by the store as recovery facts and
// never end the loop; only cancellation or a broken loop invariant returns.
type ReplayHealthProbe struct {
	state *replayHealthProbeState
}

// replayHealthProbeState keeps the loop target and overlap guard private.
type replayHealthProbeState struct {
	target    replayHealthProbeTarget
	schedule  replaySchedule
	interval  time.Duration
	running   atomic.Bool
	started   chan struct{}
	startOnce sync.Once
	activated atomic.Bool
	activate  chan struct{}
}

// NewReplayHealthProbe constructs the production Redis replay health-probe loop.
func NewReplayHealthProbe(runtime *ReplayRuntime) (*ReplayHealthProbe, error) {
	return newReplayHealthProbe(runtime, systemReplaySchedule{})
}

// newReplayHealthProbe constructs one deterministic health-probe loop whose
// interval must lie inside the validated 1s..60s configuration bound.
func newReplayHealthProbe(
	target replayHealthProbeTarget,
	schedule replaySchedule,
) (*ReplayHealthProbe, error) {
	if nilInterface(target) || nilInterface(schedule) {
		return nil, &ReplayRuntimeError{}
	}
	interval, valid := replayTargetInterval(target)
	if !valid || interval < replayHealthMinimumInterval || interval > replayHealthMaximumInterval {
		return nil, &ReplayRuntimeError{}
	}
	return &ReplayHealthProbe{state: &replayHealthProbeState{
		target: target, schedule: schedule, interval: interval,
		started: make(chan struct{}), activate: make(chan struct{}),
	}}, nil
}

// Started returns the exact-once proof that Run owns the health-probe loop.
func (r *ReplayHealthProbe) Started() <-chan struct{} {
	if r == nil || r.state == nil {
		return nil
	}
	return r.state.started
}

// Running reports whether Run currently owns the initialized loop.
func (r *ReplayHealthProbe) Running() bool {
	return r != nil && r.state != nil && r.state.running.Load()
}

// Activate releases the initialized loop only after protected runtime transfer.
func (r *ReplayHealthProbe) Activate() error {
	if r == nil || r.state == nil || r.state.activate == nil ||
		!r.state.activated.CompareAndSwap(false, true) {
		return &ReplayRuntimeError{}
	}
	close(r.state.activate)
	return nil
}

// Run performs non-overlapping start-to-start probes with one collapsed immediate catch-up.
func (r *ReplayHealthProbe) Run(ctx context.Context) error {
	if err := runtimeContextError(ctx); err != nil {
		return err
	}
	if r == nil || r.state == nil {
		return &ReplayRuntimeError{}
	}
	if !r.state.activated.Load() {
		if err := r.Activate(); err != nil {
			return err
		}
	}
	return r.run(ctx, nil)
}

// RunObserved performs one loop and synchronously classifies its physical return.
func (r *ReplayHealthProbe) RunObserved(
	ctx context.Context,
	observer ServeReturnObserver,
) (resultErr error) {
	if nilInterface(observer) {
		return &ReplayRuntimeError{}
	}
	return r.run(ctx, observer)
}

// run performs the single-owner health-probe loop implementation.
func (r *ReplayHealthProbe) run(
	ctx context.Context,
	observer ServeReturnObserver,
) error {
	if err := runtimeContextError(ctx); err != nil {
		return err
	}
	if r == nil || r.state == nil || nilInterface(r.state.target) ||
		nilInterface(r.state.schedule) || !r.state.running.CompareAndSwap(false, true) {
		return &ReplayRuntimeError{}
	}
	defer func() {
		if !nilInterface(observer) {
			notifyHealthProbeReturn(observer)
		}
		r.state.running.Store(false)
	}()

	done, cadence, err := r.initializeCadence(ctx)
	if err != nil {
		return err
	}
	r.state.startOnce.Do(func() { close(r.state.started) })
	select {
	case <-r.state.activate:
	case <-ctx.Done():
		return ctx.Err()
	}
	for {
		cadence, err = r.awaitScheduledStart(ctx, done, cadence)
		if err != nil {
			return err
		}
		if err := r.runScheduledProbe(ctx); err != nil {
			return err
		}
	}
}

// notifyHealthProbeReturn contains a hostile terminal observer before ownership clears.
func notifyHealthProbeReturn(observer ServeReturnObserver) {
	defer func() { _ = recover() }()
	observer.NotifyServeReturn()
}

// healthProbeCadence owns the fixed grid and last trustworthy clock sample.
type healthProbeCadence struct {
	lastObserved  time.Time
	nextScheduled time.Time
}

// initializeCadence validates cancellation signaling and freezes the first grid anchor.
func (r *ReplayHealthProbe) initializeCadence(
	ctx context.Context,
) (<-chan struct{}, healthProbeCadence, error) {
	done, valid := boundedContextDone(ctx)
	if !valid {
		return nil, healthProbeCadence{}, &ReplayRuntimeError{}
	}
	base, valid := replayScheduleNow(r.state.schedule)
	if !valid || base.IsZero() {
		return nil, healthProbeCadence{}, &ReplayRuntimeError{}
	}
	nextScheduled := base.Add(r.state.interval)
	if !nextScheduled.After(base) {
		return nil, healthProbeCadence{}, &ReplayRuntimeError{}
	}
	return done, healthProbeCadence{
		lastObserved: base, nextScheduled: nextScheduled,
	}, nil
}

// awaitScheduledStart waits once, collapses missed anchors, and advances the fixed grid.
func (r *ReplayHealthProbe) awaitScheduledStart(
	ctx context.Context,
	done <-chan struct{},
	cadence healthProbeCadence,
) (healthProbeCadence, error) {
	now, valid := replayScheduleNow(r.state.schedule)
	if !valid || now.IsZero() || now.Before(cadence.lastObserved) {
		return healthProbeCadence{}, &ReplayRuntimeError{}
	}
	delay := max(cadence.nextScheduled.Sub(now), 0)
	elapsed, valid := replayScheduleWait(r.state.schedule, done, delay)
	if !valid {
		return healthProbeCadence{}, &ReplayRuntimeError{}
	}
	if !elapsed {
		if err := runtimeContextError(ctx); err != nil {
			return healthProbeCadence{}, err
		}
		return healthProbeCadence{}, &ReplayRuntimeError{}
	}
	if err := runtimeContextError(ctx); err != nil {
		return healthProbeCadence{}, err
	}
	start, valid := replayScheduleNow(r.state.schedule)
	if !valid || start.IsZero() || start.Before(now) ||
		start.Before(cadence.nextScheduled) {
		return healthProbeCadence{}, &ReplayRuntimeError{}
	}
	missed := start.Sub(cadence.nextScheduled) / r.state.interval
	scheduledStart := cadence.nextScheduled.Add(missed * r.state.interval)
	nextScheduled := scheduledStart.Add(r.state.interval)
	if !nextScheduled.After(scheduledStart) || !nextScheduled.After(start) {
		return healthProbeCadence{}, &ReplayRuntimeError{}
	}
	return healthProbeCadence{
		lastObserved: start, nextScheduled: nextScheduled,
	}, nil
}

// runScheduledProbe performs one contained probe. Every typed replay failure
// is a backend observation that the store already recorded as a recovery
// fact, so it never ends the loop; only caller cancellation, a target panic,
// or an untyped error (a broken target invariant) returns.
func (r *ReplayHealthProbe) runScheduledProbe(ctx context.Context) error {
	valid, err := replayTargetProbe(ctx, r.state.target)
	if !valid {
		return &ReplayRuntimeError{}
	}
	if contextErr := runtimeContextError(ctx); contextErr != nil {
		return contextErr
	}
	if err != nil && !dkim2.IsReplayError(err) {
		return &ReplayRuntimeError{}
	}
	return nil
}

// replayTargetInterval contains hostile mutable target access during construction.
func replayTargetInterval(target replayHealthProbeTarget) (interval time.Duration, valid bool) {
	defer func() {
		if recover() != nil {
			interval = 0
			valid = false
		}
	}()
	return target.HealthInterval(), true
}

// replayTargetProbe contains unexpected background target panics.
func replayTargetProbe(
	ctx context.Context,
	target replayHealthProbeTarget,
) (valid bool, result error) {
	defer func() {
		if recover() != nil {
			valid = false
			result = nil
		}
	}()
	return true, target.ProbeHealth(ctx)
}

// replayScheduleNow contains hostile clock implementations.
func replayScheduleNow(schedule replaySchedule) (now time.Time, valid bool) {
	defer func() {
		if recover() != nil {
			now = time.Time{}
			valid = false
		}
	}()
	return schedule.Now(), true
}

// replayScheduleWait contains hostile one-shot wait implementations.
func replayScheduleWait(
	schedule replaySchedule,
	done <-chan struct{},
	delay time.Duration,
) (elapsed bool, valid bool) {
	defer func() {
		if recover() != nil {
			elapsed = false
			valid = false
		}
	}()
	return schedule.Wait(done, delay), true
}

// boundedContextDone contains hostile Done implementations without retaining context state.
func boundedContextDone(ctx context.Context) (done <-chan struct{}, valid bool) {
	defer func() {
		if recover() != nil {
			done = nil
			valid = false
		}
	}()
	if nilInterface(ctx) {
		return nil, false
	}
	done = ctx.Done()
	_, hasDeadline := ctx.Deadline()
	if hasDeadline && done == nil {
		return nil, false
	}
	return done, true
}

// String returns a content-free health-probe loop representation.
func (ReplayHealthProbe) String() string { return replayHealthProbeRedacted }

// GoString returns a content-free health-probe loop representation.
func (ReplayHealthProbe) GoString() string { return replayHealthProbeRedacted }

// Format prevents formatting from traversing the protected runtime target.
func (ReplayHealthProbe) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, replayHealthProbeRedacted)
}

// MarshalJSON rejects serialization of retained loop dependencies.
func (ReplayHealthProbe) MarshalJSON() ([]byte, error) {
	return nil, &ReplayRuntimeError{}
}

// MarshalText rejects diagnostic serialization of loop dependencies.
func (ReplayHealthProbe) MarshalText() ([]byte, error) {
	return nil, &ReplayRuntimeError{}
}
