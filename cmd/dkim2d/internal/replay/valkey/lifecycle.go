package valkey

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	dkim2 "github.com/croessner/dkim2"
)

const securityEvidenceValidity = 5 * time.Minute

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

// publishWhileReady serializes one successful publication against terminal transition.
func (g *admissionGate) publishWhileReady(publish func() error) (bool, error) {
	if g == nil || publish == nil {
		return false, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stateValue() != lifecycleReady {
		return false, nil
	}
	return true, publish()
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

const (
	recoveryTransientBit uint64 = 1 << iota
	recoveryRevalidationBit
	recoveryRestartBit
	recoveryStaleEvidenceBit
)

const recoveryVersionShift = 4

// recoveryFacts owns independently clearable degradation facts.
type recoveryFacts struct {
	bits atomic.Uint64
}

// recoveryBit maps one closed recovery class into its independent fact.
func recoveryBit(class recoveryClass) uint64 {
	switch class {
	case recoveryTransient:
		return recoveryTransientBit
	case recoveryRevalidation:
		return recoveryRevalidationBit
	case recoveryRestart:
		return recoveryRestartBit
	default:
		return recoveryRestartBit
	}
}

// add publishes one degradation fact without losing concurrent facts.
func (f *recoveryFacts) add(class recoveryClass) {
	bit := recoveryBit(class)
	for {
		current := f.bits.Load()
		next := current | bit
		if class == recoveryRevalidation {
			version := current >> recoveryVersionShift
			if version == ^uint64(0)>>recoveryVersionShift {
				next |= recoveryRestartBit
			} else {
				next += 1 << recoveryVersionShift
			}
		}
		if next == current || f.bits.CompareAndSwap(current, next) {
			return
		}
	}
}

// clearTransient clears only ordinary-success recoverable degradation.
func (f *recoveryFacts) clearTransient() {
	f.clear(recoveryTransientBit)
}

// clearRevalidation clears only a complete-audit recoverable degradation.
func (f *recoveryFacts) clearRevalidation() {
	f.clearRevalidationAt(f.revalidationGeneration())
}

// addStaleEvidence records freshness loss separately from runtime policy drift.
func (f *recoveryFacts) addStaleEvidence() {
	f.addBit(recoveryStaleEvidenceBit)
}

// clearStaleEvidence clears freshness loss after one successful live audit.
func (f *recoveryFacts) clearStaleEvidence() {
	f.clear(recoveryStaleEvidenceBit)
}

// clearRevalidationAt clears only when no newer revalidation cause was published.
func (f *recoveryFacts) clearRevalidationAt(generation uint64) bool {
	for {
		current := f.bits.Load()
		if current>>recoveryVersionShift != generation {
			return false
		}
		if current&recoveryRevalidationBit == 0 {
			return true
		}
		if f.bits.CompareAndSwap(current, current&^recoveryRevalidationBit) {
			return true
		}
	}
}

// revalidationGeneration returns the monotonic cause generation.
func (f *recoveryFacts) revalidationGeneration() uint64 {
	if f == nil {
		return 0
	}
	return f.bits.Load() >> recoveryVersionShift
}

// clear removes one authorized fact with a lossless CAS loop.
func (f *recoveryFacts) clear(bit uint64) {
	for {
		current := f.bits.Load()
		if current&bit == 0 || f.bits.CompareAndSwap(current, current&^bit) {
			return
		}
	}
}

// addBit publishes one non-versioned fact with a lossless CAS loop.
func (f *recoveryFacts) addBit(bit uint64) {
	for {
		current := f.bits.Load()
		if current&bit != 0 || f.bits.CompareAndSwap(current, current|bit) {
			return
		}
	}
}

// has reports whether one exact degradation fact is present.
func (f *recoveryFacts) has(class recoveryClass) bool {
	return f.bits.Load()&recoveryBit(class) != 0
}

// load returns all current facts for bounded tests and state projection.
func (f *recoveryFacts) load() uint64 {
	if f == nil {
		return recoveryRestartBit
	}
	return f.bits.Load()
}

// evidenceState owns the monotonic successful-audit time and atomic deadline.
type evidenceState struct {
	mu        sync.Mutex
	lastAudit time.Time
	lastTime  time.Time
	deadline  time.Time
}

// refresh validates timer monotonicity and publishes an exact five-minute deadline.
func (e *evidenceState) refresh(now time.Time) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}()
	if e == nil || now.IsZero() {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.lastTime.IsZero() && now.Before(e.lastTime) {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	deadline := now.Add(securityEvidenceValidity)
	if deadline.Before(now) || deadline.UnixNano() <= 0 {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	e.lastAudit = now
	e.lastTime = now
	e.deadline = deadline
	return nil
}

// refreshClock serializes sampling with monotonic deadline publication.
func (e *evidenceState) refreshClock(clock *serializedSecurityClock) error {
	if clock == nil {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	return clock.withSample(e.refresh)
}

// refreshFromAuditSample publishes a pre-sampled exact audit deadline.
func (e *evidenceState) refreshFromAuditSample(completed, now time.Time) error {
	if e == nil || completed.IsZero() || now.IsZero() {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if now.Before(completed) ||
		!e.lastAudit.IsZero() && completed.Before(e.lastAudit) ||
		!e.lastTime.IsZero() && now.Before(e.lastTime) {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	deadline := completed.Add(securityEvidenceValidity)
	if !deadline.After(completed) || deadline.UnixNano() <= 0 {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	if !now.Before(deadline) {
		return dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)
	}
	e.lastAudit = completed
	e.lastTime = now
	e.deadline = deadline
	return nil
}

// observeSample validates one pre-sampled monotonic evidence observation.
func (e *evidenceState) observeSample(now time.Time) (bool, error) {
	if e == nil || now.IsZero() {
		return false, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.lastTime.IsZero() && now.Before(e.lastTime) {
		return false, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	e.lastTime = now
	return !e.deadline.IsZero() && now.Before(e.deadline), nil
}

// fresh reports exact boundary semantics without mutating timer state.
func (e *evidenceState) fresh(now time.Time) bool {
	if e == nil || now.IsZero() {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return !e.deadline.IsZero() && now.Before(e.deadline)
}

// securityClock supplies one deterministic evidence time.
type securityClock interface {
	Now() time.Time
}

// serializedSecurityClock owns ordered access to one security-time source.
type serializedSecurityClock struct {
	mu     sync.Mutex
	source securityClock
	last   time.Time
}

// newSerializedSecurityClock binds one time source to a single sampling order.
func newSerializedSecurityClock(source securityClock) *serializedSecurityClock {
	return &serializedSecurityClock{source: source}
}

// Now serializes one standalone audit-completion sample.
func (c *serializedSecurityClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	now, err := c.sampleLocked()
	if err != nil {
		return time.Time{}
	}
	return now
}

// withSample keeps one sample ordered through its state publication.
func (c *serializedSecurityClock) withSample(publish func(time.Time) error) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}()
	if c == nil || c.source == nil || publish == nil {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now, err := c.sampleLocked()
	if err != nil {
		return err
	}
	return publish(now)
}

// sampleLocked validates every source sample in one total monotonic order.
func (c *serializedSecurityClock) sampleLocked() (time.Time, error) {
	now, err := readSecurityClock(c.source)
	if err != nil {
		return time.Time{}, err
	}
	if !c.last.IsZero() && now.Before(c.last) {
		return time.Time{}, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	c.last = now
	return now, nil
}

// readSecurityClock contains clock panics and rejects impossible values.
func readSecurityClock(clock securityClock) (now time.Time, resultErr error) {
	defer func() {
		if recover() != nil {
			now = time.Time{}
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}()
	if nilInterface(clock) {
		return time.Time{}, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}
	now = clock.Now()
	if now.IsZero() {
		return time.Time{}, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	return now, nil
}
