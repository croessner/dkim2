package keyresolver

import (
	"context"
	"sync"
	"time"
)

type flightResult struct {
	outcome KeyOutcome
	expiry  time.Time
}

type resolverFlight struct {
	done      chan struct{}
	cancel    context.CancelFunc
	completed bool
	result    flightResult
	waiterCtx map[uint64]context.Context
}

type flightPublication struct {
	cache *outcomeCache
}

// flightGroup owns bounded same-key miss coordination and transport concurrency.
type flightGroup struct {
	mu          sync.Mutex
	flights     map[cacheKey]*resolverFlight
	semaphore   chan struct{}
	parent      context.Context
	maxWaiters  int
	timeout     time.Duration
	initialized bool
	publication flightPublication
	waiterID    uint64
}

// newFlightGroup constructs an instance-owned bounded flight coordinator.
func newFlightGroup(parent context.Context, maxLookups, maxWaiters int, timeout time.Duration, publications ...flightPublication) *flightGroup {
	valid := parent != nil && maxLookups > 0 && maxLookups <= hardMaxConcurrentLookups &&
		maxWaiters > 0 && maxWaiters <= hardMaxCoalescedWaiters && timeout > 0 && timeout <= 30*time.Second
	if parent == nil {
		parent = context.Background()
	}
	if maxLookups <= 0 || maxLookups > hardMaxConcurrentLookups {
		maxLookups = 0
	}
	if maxWaiters <= 0 || maxWaiters > hardMaxCoalescedWaiters {
		maxWaiters = 0
	}
	group := &flightGroup{
		flights: make(map[cacheKey]*resolverFlight), semaphore: make(chan struct{}, maxLookups),
		parent: parent, maxWaiters: maxWaiters, timeout: timeout,
		initialized: valid,
	}
	if len(publications) == 1 {
		group.publication = publications[0]
	} else if len(publications) > 1 {
		group.initialized = false
	}
	return group
}

// do joins or starts one bounded flight while preserving caller cancellation.
func (g *flightGroup) do(ctx context.Context, key cacheKey, work func(context.Context) flightResult) (flightResult, bool, error) {
	if g == nil || !g.initialized || ctx == nil || work == nil || !cacheKeyValid(key) {
		return flightResult{}, false, newResolverError(ErrorClassContract)
	}
	if err := ctx.Err(); err != nil {
		return flightResult{}, false, err
	}
	g.mu.Lock()
	if err := ctx.Err(); err != nil {
		g.mu.Unlock()
		return flightResult{}, false, err
	}
	flight := g.flights[key]
	if flight != nil {
		g.pruneCanceledWaitersLocked(flight)
		if len(flight.waiterCtx) == 0 {
			if g.flights[key] == flight {
				delete(g.flights, key)
			}
			flight.cancel()
			flight = nil
		} else if len(flight.waiterCtx) >= g.maxWaiters {
			g.mu.Unlock()
			return flightResult{}, true, nil
		} else {
			waiterID := g.nextWaiterIDLocked(flight)
			flight.waiterCtx[waiterID] = ctx
			g.mu.Unlock()
			return g.wait(ctx, key, flight, waiterID)
		}
	}
	select {
	case g.semaphore <- struct{}{}:
	default:
		g.mu.Unlock()
		return flightResult{}, true, nil
	}
	workerCtx, cancel := context.WithTimeout(g.parent, g.timeout)
	flight = &resolverFlight{done: make(chan struct{}), cancel: cancel, waiterCtx: make(map[uint64]context.Context)}
	waiterID := g.nextWaiterIDLocked(flight)
	flight.waiterCtx[waiterID] = ctx
	g.flights[key] = flight
	g.mu.Unlock()
	go g.run(workerCtx, key, flight, work)
	return g.wait(ctx, key, flight, waiterID)
}

// run executes exactly one transport owner for a flight.
func (g *flightGroup) run(ctx context.Context, key cacheKey, flight *resolverFlight, work func(context.Context) flightResult) {
	result := work(ctx)
	var admission cacheAdmission
	prepared := false
	if ctx.Err() == nil && g.publication.cache != nil {
		admission, prepared = g.publication.cache.prepareAdmission(key, result.outcome, result.expiry)
	}
	g.mu.Lock()
	g.pruneCanceledWaitersLocked(flight)
	// This liveness and identity check is the cache-publication linearization point.
	if ctx.Err() != nil || g.flights[key] != flight || len(flight.waiterCtx) == 0 {
		result = flightResult{outcome: newStatusOutcome(KeyOutcomeTemporary, key.algorithm, newMetadata(false, false))}
	} else if prepared {
		g.publication.cache.commitAdmission(admission)
	}
	flight.result = cloneFlightResult(result)
	flight.completed = true
	if g.flights[key] == flight {
		delete(g.flights, key)
	}
	close(flight.done)
	flight.cancel()
	<-g.semaphore
	g.mu.Unlock()
}

// wait returns completion or retains final ownership until canceled work retires.
func (g *flightGroup) wait(ctx context.Context, key cacheKey, flight *resolverFlight, waiterID uint64) (flightResult, bool, error) {
	if err := ctx.Err(); err != nil {
		if g.leave(key, flight, waiterID) {
			<-flight.done
		}
		return flightResult{}, false, err
	}
	select {
	case <-flight.done:
		g.finishWaiter(flight, waiterID)
		if err := ctx.Err(); err != nil {
			return flightResult{}, false, err
		}
		return cloneFlightResult(flight.result), false, nil
	case <-ctx.Done():
		err := ctx.Err()
		if g.leave(key, flight, waiterID) {
			<-flight.done
		}
		return flightResult{}, false, err
	}
}

// leave removes a canceled waiter and reports final ownership of unfinished work.
func (g *flightGroup) leave(key cacheKey, flight *resolverFlight, waiterID uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(flight.waiterCtx, waiterID)
	last := len(flight.waiterCtx) == 0 && !flight.completed
	if last {
		if g.flights[key] == flight {
			delete(g.flights, key)
		}
		flight.cancel()
	}
	return last
}

// finishWaiter records one completed waiter without changing worker ownership.
func (g *flightGroup) finishWaiter(flight *resolverFlight, waiterID uint64) {
	g.mu.Lock()
	delete(flight.waiterCtx, waiterID)
	g.mu.Unlock()
}

// nextWaiterIDLocked allocates one bounded live-waiter identity.
func (g *flightGroup) nextWaiterIDLocked(flight *resolverFlight) uint64 {
	for {
		g.waiterID++
		if g.waiterID == 0 {
			g.waiterID++
		}
		if _, exists := flight.waiterCtx[g.waiterID]; !exists {
			return g.waiterID
		}
	}
}

// pruneCanceledWaitersLocked removes contexts canceled before publication.
func (g *flightGroup) pruneCanceledWaitersLocked(flight *resolverFlight) {
	for waiterID, waiterCtx := range flight.waiterCtx {
		if waiterCtx.Err() != nil {
			delete(flight.waiterCtx, waiterID)
		}
	}
	if len(flight.waiterCtx) == 0 && !flight.completed {
		flight.cancel()
	}
}

// cloneFlightResult detaches coalesced key material for each caller.
func cloneFlightResult(result flightResult) flightResult {
	return flightResult{outcome: cloneKeyOutcome(result.outcome), expiry: result.expiry}
}
