package redisstore

import (
	"context"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	dkim2 "github.com/croessner/dkim2"
)

// lifecycleState identifies terminal-precedence store publication.
type lifecycleState uint32

const (
	lifecycleReady lifecycleState = iota + 1
	lifecycleClosing
	lifecycleClosed
)

// admissionGate owns bounded concurrent entry and close draining.
type admissionGate struct {
	mu          sync.Mutex
	state       atomic.Uint32
	slots       chan struct{}
	closing     chan struct{}
	drained     chan struct{}
	waiters     atomic.Int32
	waiterLimit atomic.Int32
	inFlight    int
	drainOnce   sync.Once
}

// newAdmissionGate constructs one ready gate with exact validated caps.
func newAdmissionGate(maxInFlight, maxWaiters int) *admissionGate {
	gate := &admissionGate{
		slots:   make(chan struct{}, maxInFlight),
		closing: make(chan struct{}),
		drained: make(chan struct{}),
	}
	for range maxInFlight {
		gate.slots <- struct{}{}
	}
	gate.state.Store(uint32(lifecycleReady))
	gate.waiterLimit.Store(int32(maxWaiters))
	return gate
}

// stateValue returns one bounded lock-free lifecycle snapshot.
func (g *admissionGate) stateValue() lifecycleState {
	if g == nil {
		return 0
	}
	return lifecycleState(g.state.Load())
}

// admit waits for one bounded operation slot while the store remains ready.
func (g *admissionGate) admit(ctx context.Context) (func(), error) {
	if err := preflightContext(ctx); err != nil {
		return nil, err
	}
	if g == nil {
		return nil, admissionResult(ctx, dkim2.ReplayErrorInternalInvariant)
	}
	if g.stateValue() != lifecycleReady {
		return nil, admissionResult(ctx, dkim2.ReplayErrorClosed)
	}

	select {
	case <-g.slots:
		return g.finishAdmission(ctx, true)
	default:
	}

	maxWaiters := g.maxWaiters()
	for {
		current := g.waiters.Load()
		if int(current) >= maxWaiters {
			return nil, admissionResult(ctx, dkim2.ReplayErrorLimitExceeded)
		}
		if g.waiters.CompareAndSwap(current, current+1) {
			break
		}
	}
	defer g.waiters.Add(-1)

	select {
	case <-g.closing:
		return nil, admissionResult(ctx, dkim2.ReplayErrorClosed)
	case <-ctx.Done():
		return nil, preflightContext(ctx)
	case <-g.slots:
		return g.finishAdmission(ctx, true)
	}
}

// finishAdmission registers one operation and optionally owns a command slot.
func (g *admissionGate) finishAdmission(ctx context.Context, ownsSlot bool) (func(), error) {
	if err := preflightContext(ctx); err != nil {
		if ownsSlot {
			g.slots <- struct{}{}
		}
		return nil, err
	}
	g.mu.Lock()
	if g.stateValue() != lifecycleReady {
		g.mu.Unlock()
		if ownsSlot {
			g.slots <- struct{}{}
		}
		return nil, admissionResult(ctx, dkim2.ReplayErrorClosed)
	}
	g.inFlight++
	g.mu.Unlock()

	var once sync.Once
	finish := func() {
		once.Do(func() {
			g.mu.Lock()
			if g.inFlight > 0 {
				g.inFlight--
			}
			g.publishDrainedLocked()
			g.mu.Unlock()
			if ownsSlot {
				g.slots <- struct{}{}
			}
		})
	}
	if err := preflightContext(ctx); err != nil {
		finish()
		return nil, err
	}
	return finish, nil
}

// admitLifecycle registers non-command work without consuming a replay slot.
func (g *admissionGate) admitLifecycle(ctx context.Context) (func(), error) {
	if err := preflightContext(ctx); err != nil {
		return nil, err
	}
	if g == nil {
		return nil, admissionResult(ctx, dkim2.ReplayErrorInternalInvariant)
	}
	return g.finishAdmission(ctx, false)
}

// admissionResult gives terminal caller state precedence over provider errors.
func admissionResult(ctx context.Context, code dkim2.ReplayErrorCode) error {
	if err := preflightContext(ctx); err != nil {
		return err
	}
	return dkim2.NewReplayError(code)
}

// maxWaiters returns the configured waiting-admission cap.
func (g *admissionGate) maxWaiters() int {
	return int(g.waiterLimit.Load())
}

// beginClose publishes closing before rejecting all later work.
func (g *admissionGate) beginClose() (<-chan struct{}, error) {
	if g == nil {
		return nil, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	switch g.stateValue() {
	case lifecycleReady:
		g.state.Store(uint32(lifecycleClosing))
		close(g.closing)
	case lifecycleClosing, lifecycleClosed:
	default:
		return nil, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	g.publishDrainedLocked()
	return g.drained, nil
}

// publishClosed atomically makes the terminal state visible after draining.
func (g *admissionGate) publishClosed() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	switch g.stateValue() {
	case lifecycleClosed:
		return true
	case lifecycleClosing:
		if g.inFlight != 0 {
			return false
		}
		g.state.Store(uint32(lifecycleClosed))
		return true
	default:
		return false
	}
}

// publishDrainedLocked closes the stable drain channel exactly once.
func (g *admissionGate) publishDrainedLocked() {
	if g.stateValue() == lifecycleClosing && g.inFlight == 0 {
		g.drainOnce.Do(func() { close(g.drained) })
	}
}

// waitAdmissionDrain waits without starting provider-owned goroutines.
func waitAdmissionDrain(ctx context.Context, drained <-chan struct{}) error {
	if err := preflightContext(ctx); err != nil {
		return err
	}
	select {
	case <-drained:
		return preflightContext(ctx)
	default:
	}
	callerDone, err := closeCallerDone(ctx)
	if err != nil {
		return err
	}
	select {
	case <-drained:
		return preflightContext(ctx)
	case <-callerDone:
		return preflightContext(ctx)
	}
}

// closeCallerDone contains a hostile Done capability as an internal invariant failure.
func closeCallerDone(ctx context.Context) (done <-chan struct{}, resultErr error) {
	defer func() {
		if recover() != nil {
			done = nil
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}()
	return ctx.Done(), nil
}

// recoveryClass identifies how one degraded provider may return to ready.
type recoveryClass uint32

const (
	recoveryNone recoveryClass = iota
	recoveryTransient
	recoveryRestart
)

const (
	recoveryTransientBit uint64 = 1 << iota
	recoveryRestartBit
)

// recoveryFacts owns independently clearable degradation facts. The transient
// fact is cleared by an authoritative operation or a successful health probe;
// the restart fact is sticky for the life of the store.
type recoveryFacts struct {
	bits atomic.Uint64
}

// recoveryBit maps one closed recovery class into its independent fact; an
// unknown class fails closed to the sticky restart fact.
func recoveryBit(class recoveryClass) uint64 {
	switch class {
	case recoveryTransient:
		return recoveryTransientBit
	default:
		return recoveryRestartBit
	}
}

// add publishes one degradation fact without losing concurrent facts.
func (f *recoveryFacts) add(class recoveryClass) {
	if class == recoveryNone {
		return
	}
	bit := recoveryBit(class)
	for {
		current := f.bits.Load()
		if current&bit != 0 || f.bits.CompareAndSwap(current, current|bit) {
			return
		}
	}
}

// clearTransient clears only the recoverable transient fact.
func (f *recoveryFacts) clearTransient() {
	for {
		current := f.bits.Load()
		if current&recoveryTransientBit == 0 ||
			f.bits.CompareAndSwap(current, current&^recoveryTransientBit) {
			return
		}
	}
}

// load returns all current facts; a nil receiver reports the sticky restart fact.
func (f *recoveryFacts) load() uint64 {
	if f == nil {
		return recoveryRestartBit
	}
	return f.bits.Load()
}

// strongest projects the independent facts into the closed recovery class.
func (f *recoveryFacts) strongest() recoveryClass {
	bits := f.load()
	switch {
	case bits&recoveryRestartBit != 0:
		return recoveryRestart
	case bits&recoveryTransientBit != 0:
		return recoveryTransient
	default:
		return recoveryNone
	}
}

// preflightContext maps context state before command construction or dispatch.
func preflightContext(ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}()
	if nilInterface(ctx) {
		return dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
	}
	switch ctx.Err() {
	case nil:
		deadline, present := ctx.Deadline()
		if present && !time.Now().Before(deadline) {
			return dkim2.NewReplayError(dkim2.ReplayErrorDeadlineExceeded)
		}
		return nil
	case context.Canceled:
		return dkim2.NewReplayError(dkim2.ReplayErrorCancelled)
	case context.DeadlineExceeded:
		return dkim2.NewReplayError(dkim2.ReplayErrorDeadlineExceeded)
	default:
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
}

// nilInterface reports nil-interface and typed-nil values without invoking them.
func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
