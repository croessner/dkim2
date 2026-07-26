package httpjson

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// TestProcessAdmissionValidatesFixedBudget proves configuration cannot widen reservations.
func TestProcessAdmissionValidatesFixedBudget(t *testing.T) {
	for _, values := range []struct {
		inFlight int
		waiters  int
		wait     time.Duration
	}{
		{inFlight: 0},
		{inFlight: 3},
		{inFlight: 1, waiters: -1},
		{inFlight: 1, waiters: maxProcessWaiters + 1},
		{inFlight: 1, wait: maxProcessAdmissionWait + time.Nanosecond},
	} {
		if _, err := newProcessAdmission(values.inFlight, values.waiters, values.wait); !errors.Is(err, errAdmissionConfig) {
			t.Fatalf("newProcessAdmission(%+v) error = %v", values, err)
		}
	}
	for inFlight := 1; inFlight <= maxProcessInFlight; inFlight++ {
		if _, err := newProcessAdmission(inFlight, maxProcessWaiters, maxProcessAdmissionWait); err != nil {
			t.Fatalf("valid in-flight %d rejected: %v", inFlight, err)
		}
	}
}

// TestProcessAdmissionTryAcquireIsAtomicAndNonblocking proves Expect-path ownership.
func TestProcessAdmissionTryAcquireIsAtomicAndNonblocking(t *testing.T) {
	admission, err := newProcessAdmission(2, 64, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("newProcessAdmission() error = %v", err)
	}
	first, failure := admission.TryAcquire(context.Background())
	if failure != 0 || first == nil {
		t.Fatalf("first TryAcquire() = %v/%v", first, failure)
	}
	second, failure := admission.TryAcquire(context.Background())
	if failure != 0 || second == nil || admission.Owned() != 2 {
		t.Fatalf("second TryAcquire() = %v/%v owned=%d", second, failure, admission.Owned())
	}
	start := time.Now()
	if lease, got := admission.TryAcquire(context.Background()); lease != nil || got != admissionOverloaded {
		t.Fatalf("third TryAcquire() = %v/%v", lease, got)
	}
	if time.Since(start) > 50*time.Millisecond || len(admission.waiters) != 0 {
		t.Fatal("nonblocking acquisition joined the waiter queue")
	}
	first.Release()
	first.Release()
	second.Release()
	if admission.Owned() != 0 || len(admission.permits) != 0 {
		t.Fatal("leases did not release exactly once")
	}
}

// TestProcessAdmissionBoundsWaitersAndWakesOnRelease proves ordinary queue policy.
func TestProcessAdmissionBoundsWaitersAndWakesOnRelease(t *testing.T) {
	admission, err := newProcessAdmission(1, 1, time.Second)
	if err != nil {
		t.Fatalf("newProcessAdmission() error = %v", err)
	}
	owner, failure := admission.TryAcquire(context.Background())
	if failure != 0 {
		t.Fatalf("TryAcquire() failure = %v", failure)
	}
	entered := make(chan struct{})
	admission.onWait = func() { close(entered) }
	result := make(chan *processLease, 1)
	go func() {
		lease, _ := admission.Acquire(context.Background())
		result <- lease
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("ordinary waiter did not enter queue")
	}
	if lease, got := admission.Acquire(context.Background()); lease != nil || got != admissionOverloaded {
		t.Fatalf("excess waiter = %v/%v", lease, got)
	}
	owner.Release()
	select {
	case lease := <-result:
		if lease == nil {
			t.Fatal("queued acquisition did not receive released ownership")
		}
		lease.Release()
	case <-time.After(time.Second):
		t.Fatal("queued acquisition did not wake")
	}
}

// TestProcessAdmissionCancellationDeadlineAndCloseAreClosed proves terminal classes.
func TestProcessAdmissionCancellationDeadlineAndCloseAreClosed(t *testing.T) {
	tests := []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		want admissionFailure
	}{
		{
			name: "canceled",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, cancel
			},
			want: admissionCanceled,
		},
		{
			name: testDeadlineName,
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				return ctx, cancel
			},
			want: admissionDeadline,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			admission, _ := newProcessAdmission(1, 1, time.Second)
			ctx, cancel := test.ctx()
			defer cancel()
			if lease, failure := admission.Acquire(ctx); lease != nil || failure != test.want {
				t.Fatalf("Acquire() = %v/%v", lease, failure)
			}
		})
	}

	admission, _ := newProcessAdmission(1, 1, time.Second)
	owner, _ := admission.TryAcquire(context.Background())
	entered := make(chan struct{})
	admission.onWait = func() { close(entered) }
	result := make(chan admissionFailure, 1)
	go func() {
		_, failure := admission.Acquire(context.Background())
		result <- failure
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("closed waiter did not enter queue")
	}
	admission.Close()
	if failure := <-result; failure != admissionNotReady {
		t.Fatalf("closed waiter failure = %v", failure)
	}
	owner.Release()
}

// TestProcessAdmissionResolvesSimultaneousEventsInFrozenOrder proves deterministic precedence.
func TestProcessAdmissionResolvesSimultaneousEventsInFrozenOrder(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(context.CancelFunc, *processAdmission, chan time.Time, *processLease)
		want    admissionFailure
	}{
		{
			name: "cancel beats close timer and permit",
			prepare: func(cancel context.CancelFunc, admission *processAdmission, timer chan time.Time, owner *processLease) {
				cancel()
				admission.Close()
				timer <- time.Now()
				owner.Release()
			},
			want: admissionCanceled,
		},
		{
			name: "close beats timer and permit",
			prepare: func(_ context.CancelFunc, admission *processAdmission, timer chan time.Time, owner *processLease) {
				admission.Close()
				timer <- time.Now()
				owner.Release()
			},
			want: admissionNotReady,
		},
		{
			name: "timer beats permit",
			prepare: func(_ context.CancelFunc, _ *processAdmission, timer chan time.Time, owner *processLease) {
				timer <- time.Now()
				owner.Release()
			},
			want: admissionOverloaded,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			admission, _ := newProcessAdmission(1, 1, time.Second)
			owner, _ := admission.TryAcquire(context.Background())
			entered := make(chan struct{})
			releaseWaiter := make(chan struct{})
			admission.onWait = func() {
				close(entered)
				<-releaseWaiter
			}
			timer := make(chan time.Time, 1)
			admission.newTimer = func(time.Duration) (<-chan time.Time, func()) {
				return timer, func() {}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan admissionFailure, 1)
			go func() {
				lease, failure := admission.Acquire(ctx)
				if lease != nil {
					lease.Release()
				}
				result <- failure
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("waiter did not reach barrier")
			}
			test.prepare(cancel, admission, timer, owner)
			close(releaseWaiter)
			select {
			case failure := <-result:
				if failure != test.want {
					t.Fatalf("failure = %v, want %v", failure, test.want)
				}
			case <-time.After(time.Second):
				t.Fatal("simultaneous event resolution blocked")
			}
			if admission.Owned() != 0 || len(admission.permits) != 0 || len(admission.waiters) != 0 {
				t.Fatal("simultaneous resolution leaked ownership")
			}
		})
	}
}

// TestProcessAdmissionZeroWaiterAndZeroWaitAreImmediate proves zero-valued policy.
func TestProcessAdmissionZeroWaiterAndZeroWaitAreImmediate(t *testing.T) {
	noWaiters, _ := newProcessAdmission(1, 0, time.Second)
	owner, _ := noWaiters.TryAcquire(context.Background())
	if lease, failure := noWaiters.Acquire(context.Background()); lease != nil || failure != admissionOverloaded {
		t.Fatalf("zero-waiter Acquire() = %v/%v", lease, failure)
	}
	owner.Release()

	zeroWait, _ := newProcessAdmission(1, 1, 0)
	owner, _ = zeroWait.TryAcquire(context.Background())
	if lease, failure := zeroWait.Acquire(context.Background()); lease != nil || failure != admissionOverloaded {
		t.Fatalf("zero-wait Acquire() = %v/%v", lease, failure)
	}
	owner.Release()
}

// TestProcessAdmissionConcurrentReleaseRemainsExact proves lease race safety.
func TestProcessAdmissionConcurrentReleaseRemainsExact(t *testing.T) {
	admission, _ := newProcessAdmission(1, 0, 0)
	lease, _ := admission.TryAcquire(context.Background())
	var group sync.WaitGroup
	for index := 0; index < 64; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			lease.Release()
		}()
	}
	group.Wait()
	if admission.Owned() != 0 || len(admission.permits) != 0 {
		t.Fatal("concurrent Release did not relinquish exactly once")
	}
}

// TestProcessReservationRequiresBothOwners proves handler/transport ordering.
func TestProcessReservationRequiresBothOwners(t *testing.T) {
	t.Parallel()

	for _, handlerFirst := range []bool{true, false} {
		admission, err := newProcessAdmission(1, 0, 0)
		if err != nil {
			t.Fatal("newProcessAdmission() failed")
		}
		lease, failure := admission.TryAcquire(context.Background())
		if failure != 0 || lease == nil {
			t.Fatal("TryAcquire() failed")
		}
		ledger, err := newWorkingSetLedger(processWorkingSetUnitBytes)
		if err != nil || ledger.Claim(workingSetFixedStorage, 1) != nil {
			t.Fatal("ledger construction failed")
		}
		reservation, err := newProcessReservation(lease, ledger)
		if err != nil {
			t.Fatal("newProcessReservation() failed")
		}
		if handlerFirst {
			reservation.HandlerDone()
		} else {
			reservation.TransportDone()
		}
		if admission.Owned() != 1 || ledger.Snapshot().Live != 1 {
			t.Fatal("reservation released before both owners completed")
		}
		if handlerFirst {
			reservation.TransportDone()
		} else {
			reservation.HandlerDone()
		}
		if admission.Owned() != 0 || ledger.Snapshot().Live != 0 {
			t.Fatal("reservation survived both completed owners")
		}
		reservation.HandlerDone()
		reservation.TransportDone()
		if admission.Owned() != 0 {
			t.Fatal("duplicate completion released more than once")
		}
		reservation.mu.Lock()
		retained := reservation.lease != nil || reservation.ledger != nil
		reservation.mu.Unlock()
		if retained {
			t.Fatal("released reservation retained owned resources")
		}
	}
}

// TestProcessReservationConcurrentCompletion proves exact-once race behavior.
func TestProcessReservationConcurrentCompletion(t *testing.T) {
	t.Parallel()

	for iteration := 0; iteration < 100; iteration++ {
		admission, err := newProcessAdmission(1, 0, 0)
		if err != nil {
			t.Fatal("newProcessAdmission() failed")
		}
		lease, failure := admission.TryAcquire(context.Background())
		if failure != 0 || lease == nil {
			t.Fatal("TryAcquire() failed")
		}
		ledger, err := newWorkingSetLedger(processWorkingSetUnitBytes)
		if err != nil || ledger.Claim(workingSetFixedStorage, 1) != nil {
			t.Fatal("ledger construction failed")
		}
		reservation, err := newProcessReservation(lease, ledger)
		if err != nil {
			t.Fatal("newProcessReservation() failed")
		}
		start := make(chan struct{})
		var group sync.WaitGroup
		for _, handlerOwner := range []bool{true, false} {
			group.Add(1)
			go func(handler bool) {
				defer group.Done()
				<-start
				if handler {
					reservation.HandlerDone()
				} else {
					reservation.TransportDone()
				}
			}(handlerOwner)
		}
		close(start)
		group.Wait()
		if admission.Owned() != 0 || len(admission.permits) != 0 ||
			ledger.Snapshot().Live != 0 {
			t.Fatal("concurrent completion did not release exactly once")
		}
	}
}
