package replay

import (
	"context"
	"sync"
	"sync/atomic"
)

// lifecycleGate owns lock-free state publication and admitted-work draining.
//
// Provider-specific cleanup remains with the owner and runs only after the
// gate reports that work admitted before closing has drained.
type lifecycleGate struct {
	mu             sync.Mutex
	state          atomic.Uint32
	inFlight       int
	drained        chan struct{}
	drainPublished bool
}

// newLifecycleGate constructs one gate in a valid operational state.
func newLifecycleGate(initial StoreState) *lifecycleGate {
	gate := &lifecycleGate{drained: make(chan struct{})}
	gate.state.Store(uint32(initial))
	return gate
}

// State returns one bounded lock-free lifecycle snapshot.
func (g *lifecycleGate) State() StoreState {
	if g == nil {
		return 0
	}
	return StoreState(g.state.Load())
}

// admit registers work only while the owner's exact operational state holds.
func (g *lifecycleGate) admit(operational StoreState) error {
	if g == nil {
		return NewError(ErrorCodeInternalInvariant)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	state := StoreState(g.state.Load())
	switch state {
	case operational:
		g.inFlight++
		return nil
	case StoreClosing, StoreClosed:
		return NewError(ErrorCodeClosed)
	case StoreDegraded:
		return NewError(ErrorCodeInternalInvariant)
	default:
		return NewError(ErrorCodeInternalInvariant)
	}
}

// finish releases admitted work and publishes drain completion while closing.
func (g *lifecycleGate) finish() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.inFlight <= 0 {
		return
	}
	g.inFlight--
	g.publishDrainLocked()
}

// beginClose publishes closing and returns the stable drain signal.
func (g *lifecycleGate) beginClose() (<-chan struct{}, error) {
	if g == nil {
		return nil, NewError(ErrorCodeInternalInvariant)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	switch StoreState(g.state.Load()) {
	case StoreReady, StoreDegraded, StoreDisabled:
		g.state.Store(uint32(StoreClosing))
	case StoreClosing, StoreClosed:
	default:
		return nil, NewError(ErrorCodeInternalInvariant)
	}
	g.publishDrainLocked()
	return g.drained, nil
}

// publishClosed makes the terminal state visible after owner cleanup.
func (g *lifecycleGate) publishClosed() error {
	if g == nil {
		return NewError(ErrorCodeInternalInvariant)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	switch StoreState(g.state.Load()) {
	case StoreClosing:
		if g.inFlight != 0 || !g.drainPublished {
			return NewError(ErrorCodeInternalInvariant)
		}
		g.state.Store(uint32(StoreClosed))
		return nil
	case StoreClosed:
		return nil
	default:
		return NewError(ErrorCodeInternalInvariant)
	}
}

// degrade publishes failure only while ready and never overwrites close state.
func (g *lifecycleGate) degrade() {
	if g == nil {
		return
	}
	g.state.CompareAndSwap(uint32(StoreReady), uint32(StoreDegraded))
}

// drainedNow reports whether closing work has fully drained without blocking.
func (g *lifecycleGate) drainedNow() bool {
	if g == nil {
		return false
	}
	select {
	case <-g.drained:
		return true
	default:
		return false
	}
}

// publishDrainLocked closes the stable drain signal exactly once.
func (g *lifecycleGate) publishDrainLocked() {
	if StoreState(g.state.Load()) == StoreClosing && g.inFlight == 0 && !g.drainPublished {
		close(g.drained)
		g.drainPublished = true
	}
}

// waitForDrain waits without creating a goroutine and preserves pre-mutation context identity.
func waitForDrain(ctx context.Context, drained <-chan struct{}) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = NewError(ErrorCodeInternalInvariant)
		}
	}()
	select {
	case <-drained:
		return nil
	default:
	}
	done := ctx.Done()
	select {
	case <-drained:
		return nil
	case <-done:
		if err := PreflightContext(ctx); err != nil {
			return err
		}
		return NewError(ErrorCodeInternalInvariant)
	}
}
