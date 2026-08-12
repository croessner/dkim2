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

const replayRevalidatorRedacted = "dkim2d_replay_revalidator"

// replayRevalidationTarget is the narrow periodic authority-audit boundary.
type replayRevalidationTarget interface {
	Revalidate(context.Context) error
	RevalidationInterval() time.Duration
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

// ReplayRevalidator owns one single-run start-to-start authority audit loop.
type ReplayRevalidator struct {
	state *replayRevalidatorState
}

// replayRevalidatorState keeps the loop target and overlap guard private.
type replayRevalidatorState struct {
	target    replayRevalidationTarget
	schedule  replaySchedule
	interval  time.Duration
	running   atomic.Bool
	started   chan struct{}
	startOnce sync.Once
	activated atomic.Bool
	activate  chan struct{}
}

// NewReplayRevalidator constructs the production Valkey authority loop.
func NewReplayRevalidator(runtime *ReplayRuntime) (*ReplayRevalidator, error) {
	return newReplayRevalidator(runtime, systemReplaySchedule{})
}

// newReplayRevalidator constructs one deterministic authority loop.
func newReplayRevalidator(
	target replayRevalidationTarget,
	schedule replaySchedule,
) (*ReplayRevalidator, error) {
	if nilInterface(target) || nilInterface(schedule) {
		return nil, &ReplayRuntimeError{}
	}
	interval, valid := replayTargetInterval(target)
	if !valid || interval < 10*time.Second || interval > 60*time.Second {
		return nil, &ReplayRuntimeError{}
	}
	return &ReplayRevalidator{state: &replayRevalidatorState{
		target: target, schedule: schedule, interval: interval,
		started: make(chan struct{}), activate: make(chan struct{}),
	}}, nil
}

// Started returns the exact-once proof that Run owns the revalidation loop.
func (r *ReplayRevalidator) Started() <-chan struct{} {
	if r == nil || r.state == nil {
		return nil
	}
	return r.state.started
}

// Running reports whether Run currently owns the initialized loop.
func (r *ReplayRevalidator) Running() bool {
	return r != nil && r.state != nil && r.state.running.Load()
}

// Activate releases the initialized loop only after protected runtime transfer.
func (r *ReplayRevalidator) Activate() error {
	if r == nil || r.state == nil || r.state.activate == nil ||
		!r.state.activated.CompareAndSwap(false, true) {
		return &ReplayRuntimeError{}
	}
	close(r.state.activate)
	return nil
}

// Run performs non-overlapping start-to-start audits with one collapsed immediate catch-up.
func (r *ReplayRevalidator) Run(ctx context.Context) error {
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
func (r *ReplayRevalidator) RunObserved(
	ctx context.Context,
	observer ServeReturnObserver,
) (resultErr error) {
	if nilInterface(observer) {
		return &ReplayRuntimeError{}
	}
	return r.run(ctx, observer)
}

// run performs the single-owner revalidation loop implementation.
func (r *ReplayRevalidator) run(
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
			notifyRevalidatorReturn(observer)
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
		if err := r.runScheduledAudit(ctx); err != nil {
			return err
		}
	}
}

// notifyRevalidatorReturn contains a hostile terminal observer before ownership clears.
func notifyRevalidatorReturn(observer ServeReturnObserver) {
	defer func() { _ = recover() }()
	observer.NotifyServeReturn()
}

// revalidationCadence owns the fixed grid and last trustworthy clock sample.
type revalidationCadence struct {
	lastObserved  time.Time
	nextScheduled time.Time
}

// initializeCadence validates cancellation signaling and freezes the first grid anchor.
func (r *ReplayRevalidator) initializeCadence(
	ctx context.Context,
) (<-chan struct{}, revalidationCadence, error) {
	done, valid := boundedContextDone(ctx)
	if !valid {
		return nil, revalidationCadence{}, &ReplayRuntimeError{}
	}
	base, valid := replayScheduleNow(r.state.schedule)
	if !valid || base.IsZero() {
		return nil, revalidationCadence{}, &ReplayRuntimeError{}
	}
	nextScheduled := base.Add(r.state.interval)
	if !nextScheduled.After(base) {
		return nil, revalidationCadence{}, &ReplayRuntimeError{}
	}
	return done, revalidationCadence{
		lastObserved: base, nextScheduled: nextScheduled,
	}, nil
}

// awaitScheduledStart waits once, collapses missed anchors, and advances the fixed grid.
func (r *ReplayRevalidator) awaitScheduledStart(
	ctx context.Context,
	done <-chan struct{},
	cadence revalidationCadence,
) (revalidationCadence, error) {
	now, valid := replayScheduleNow(r.state.schedule)
	if !valid || now.IsZero() || now.Before(cadence.lastObserved) {
		return revalidationCadence{}, &ReplayRuntimeError{}
	}
	delay := max(cadence.nextScheduled.Sub(now), 0)
	elapsed, valid := replayScheduleWait(r.state.schedule, done, delay)
	if !valid {
		return revalidationCadence{}, &ReplayRuntimeError{}
	}
	if !elapsed {
		if err := runtimeContextError(ctx); err != nil {
			return revalidationCadence{}, err
		}
		return revalidationCadence{}, &ReplayRuntimeError{}
	}
	if err := runtimeContextError(ctx); err != nil {
		return revalidationCadence{}, err
	}
	start, valid := replayScheduleNow(r.state.schedule)
	if !valid || start.IsZero() || start.Before(now) ||
		start.Before(cadence.nextScheduled) {
		return revalidationCadence{}, &ReplayRuntimeError{}
	}
	missed := start.Sub(cadence.nextScheduled) / r.state.interval
	scheduledStart := cadence.nextScheduled.Add(missed * r.state.interval)
	nextScheduled := scheduledStart.Add(r.state.interval)
	if !nextScheduled.After(scheduledStart) || !nextScheduled.After(start) {
		return revalidationCadence{}, &ReplayRuntimeError{}
	}
	return revalidationCadence{
		lastObserved: start, nextScheduled: nextScheduled,
	}, nil
}

// runScheduledAudit performs one contained audit and enforces its live error taxonomy.
func (r *ReplayRevalidator) runScheduledAudit(ctx context.Context) error {
	valid, err := replayTargetRevalidate(ctx, r.state.target)
	if !valid {
		return &ReplayRuntimeError{}
	}
	if contextErr := runtimeContextError(ctx); contextErr != nil {
		return contextErr
	}
	if err == nil {
		return nil
	}
	if !dkim2.IsReplayError(err) || !allowedRevalidationError(err) {
		return &ReplayRuntimeError{}
	}
	return nil
}

// replayTargetInterval contains hostile mutable target access during construction.
func replayTargetInterval(target replayRevalidationTarget) (interval time.Duration, valid bool) {
	defer func() {
		if recover() != nil {
			interval = 0
			valid = false
		}
	}()
	return target.RevalidationInterval(), true
}

// replayTargetRevalidate contains unexpected background target panics.
func replayTargetRevalidate(
	ctx context.Context,
	target replayRevalidationTarget,
) (valid bool, result error) {
	defer func() {
		if recover() != nil {
			valid = false
			result = nil
		}
	}()
	return true, target.Revalidate(ctx)
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

// String returns a content-free revalidation-loop representation.
func (ReplayRevalidator) String() string { return replayRevalidatorRedacted }

// GoString returns a content-free revalidation-loop representation.
func (ReplayRevalidator) GoString() string { return replayRevalidatorRedacted }

// Format prevents formatting from traversing the protected runtime target.
func (ReplayRevalidator) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, replayRevalidatorRedacted)
}

// MarshalJSON rejects serialization of retained loop dependencies.
func (ReplayRevalidator) MarshalJSON() ([]byte, error) {
	return nil, &ReplayRuntimeError{}
}

// MarshalText rejects diagnostic serialization of loop dependencies.
func (ReplayRevalidator) MarshalText() ([]byte, error) {
	return nil, &ReplayRuntimeError{}
}
