package httpjson

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

const (
	processWorkingSetUnitBytes      = uint64(536_870_912)
	processWorkingSetAggregateBytes = uint64(1_073_741_824)
	maxProcessInFlight              = 2
	maxProcessWaiters               = 1_024
	maxProcessAdmissionWait         = time.Second
)

var errAdmissionConfig = errors.New("http process admission configuration failure")

type admissionFailure uint8

const (
	admissionCanceled admissionFailure = iota + 1
	admissionDeadline
	admissionNotReady
	admissionOverloaded
)

type processAdmission struct {
	permits chan struct{}
	waiters chan struct{}
	wait    time.Duration
	closed  chan struct{}

	closeOnce sync.Once
	owned     atomic.Uint32
	newTimer  func(time.Duration) (<-chan time.Time, func())
	onWait    func()
}

// newProcessAdmission constructs one atomic permit and working-set reservation owner.
func newProcessAdmission(
	maxInFlight int,
	maxWaiters int,
	wait time.Duration,
) (*processAdmission, error) {
	if maxInFlight < 1 || maxInFlight > maxProcessInFlight ||
		maxWaiters < 0 || maxWaiters > maxProcessWaiters ||
		wait < 0 || wait > maxProcessAdmissionWait ||
		uint64(maxInFlight)*processWorkingSetUnitBytes > processWorkingSetAggregateBytes {
		return nil, errAdmissionConfig
	}
	return &processAdmission{
		permits:  make(chan struct{}, maxInFlight),
		waiters:  make(chan struct{}, maxWaiters),
		wait:     wait,
		closed:   make(chan struct{}),
		newTimer: newAdmissionTimer,
	}, nil
}

// TryAcquire atomically owns one process permit and its full fixed reservation.
func (a *processAdmission) TryAcquire(ctx context.Context) (*processLease, admissionFailure) {
	if ctx == nil {
		ctx = context.Background()
	}
	if failure := a.failure(ctx); failure != 0 {
		return nil, failure
	}
	select {
	case a.permits <- struct{}{}:
		return a.finishAcquire(ctx)
	default:
		return nil, admissionOverloaded
	}
}

// Acquire waits within the bounded ordinary queue for one atomic permit/reservation.
func (a *processAdmission) Acquire(ctx context.Context) (*processLease, admissionFailure) {
	if ctx == nil {
		ctx = context.Background()
	}
	if failure := a.failure(ctx); failure != 0 {
		return nil, failure
	}
	select {
	case a.permits <- struct{}{}:
		return a.finishAcquire(ctx)
	default:
	}
	select {
	case a.waiters <- struct{}{}:
		defer func() { <-a.waiters }()
	default:
		return nil, admissionOverloaded
	}
	if a.onWait != nil {
		a.onWait()
	}
	timerC, stopTimer := a.newTimer(a.wait)
	defer stopTimer()
	acquired := false
	expired := false
	select {
	case <-ctx.Done():
	case <-a.closed:
	case <-timerC:
		expired = true
	case a.permits <- struct{}{}:
		acquired = true
	}
	if failure := a.failure(ctx); failure != 0 {
		if acquired {
			<-a.permits
		}
		return nil, failure
	}
	if !expired {
		select {
		case <-timerC:
			expired = true
		default:
		}
	}
	if expired {
		if acquired {
			<-a.permits
		}
		return nil, admissionOverloaded
	}
	if !acquired {
		select {
		case a.permits <- struct{}{}:
			acquired = true
		default:
		}
	}
	if !acquired {
		return nil, admissionOverloaded
	}
	return a.finishAcquire(ctx)
}

// newAdmissionTimer creates one stoppable ordinary-wait deadline channel.
func newAdmissionTimer(wait time.Duration) (<-chan time.Time, func()) {
	timer := time.NewTimer(wait)
	return timer.C, func() { timer.Stop() }
}

// Close rejects future acquisitions and interrupts every ordinary waiter.
func (a *processAdmission) Close() {
	if a != nil {
		a.closeOnce.Do(func() { close(a.closed) })
	}
}

// Owned returns the current number of full working-set units.
func (a *processAdmission) Owned() uint32 {
	if a == nil {
		return 0
	}
	return a.owned.Load()
}

// finishAcquire rechecks higher-precedence terminal state after channel acquisition.
func (a *processAdmission) finishAcquire(ctx context.Context) (*processLease, admissionFailure) {
	if failure := a.failure(ctx); failure != 0 {
		<-a.permits
		return nil, failure
	}
	a.owned.Add(1)
	return &processLease{owner: a}, 0
}

// failure classifies already-observed terminal state without retaining a context.
func (a *processAdmission) failure(ctx context.Context) admissionFailure {
	if a == nil {
		return admissionNotReady
	}
	if ctx != nil {
		switch ctx.Err() {
		case context.Canceled:
			return admissionCanceled
		case context.DeadlineExceeded:
			return admissionDeadline
		}
	}
	select {
	case <-a.closed:
		return admissionNotReady
	default:
		return 0
	}
}

type processLease struct {
	owner *processAdmission
	once  sync.Once
}

// Release relinquishes one process permit and fixed reservation exactly once.
func (l *processLease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		if l.owner == nil {
			return
		}
		l.owner.owned.Add(^uint32(0))
		<-l.owner.permits
	})
}

// processReservation keeps admission ownership until both the handler and
// transport have made every request allocation unreachable.
type processReservation struct {
	lease  *processLease
	ledger *workingSetLedger

	mu            sync.Mutex
	handlerDone   bool
	transportDone bool
	released      bool
}

// newProcessReservation constructs one two-party request ownership barrier.
func newProcessReservation(
	lease *processLease,
	ledger *workingSetLedger,
) (*processReservation, error) {
	if lease == nil || ledger == nil {
		return nil, errAdmissionConfig
	}
	return &processReservation{lease: lease, ledger: ledger}, nil
}

// HandlerDone records that handler-owned request references were scrubbed.
func (r *processReservation) HandlerDone() {
	r.markDone(true)
}

// TransportDone records that final output and socket ownership are terminal.
func (r *processReservation) TransportDone() {
	r.markDone(false)
}

// markDone releases the reservation only after both independent owners finish.
func (r *processReservation) markDone(handler bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if handler {
		r.handlerDone = true
	} else {
		r.transportDone = true
	}
	if !r.handlerDone || !r.transportDone || r.released {
		r.mu.Unlock()
		return
	}
	r.released = true
	ledger := r.ledger
	lease := r.lease
	r.ledger = nil
	r.lease = nil
	r.mu.Unlock()
	ledger.ReleaseAll()
	lease.Release()
}
