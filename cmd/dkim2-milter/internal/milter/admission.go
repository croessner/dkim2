package milter

import (
	"context"
	"fmt"
	"io"
	"sync"
)

const redactedAdmission = "dkim2_milter_admission{redacted}"

// Admission owns process-wide connection, message, and byte reservations.
type Admission struct {
	mu             sync.Mutex
	maxConnections int
	maxMessages    int
	maxBytes       int64
	connections    int
	messages       int
	bytes          int64
	stopping       bool
	used           bool
	observer       *observerDispatcher
}

// WaitObserver joins best-effort delivery only within the caller's shutdown budget.
func (a *Admission) WaitObserver(ctx context.Context) error {
	if a == nil || ctx == nil {
		return &Error{Class: FailureContract}
	}
	a.mu.Lock()
	observer := a.observer
	stopping := a.stopping
	a.mu.Unlock()
	if !stopping || observer == nil || !observer.wait(ctx) {
		return &Error{Class: FailureInternal}
	}
	return nil
}

// NewAdmission constructs one process-local bounded admission owner.
func NewAdmission(maxConnections, maxMessages int, maxBytes int64) (*Admission, error) {
	if maxConnections < 1 || maxMessages < 1 || maxMessages > maxConnections || maxBytes < 1 {
		return nil, &Error{Class: FailureContract}
	}
	return &Admission{
		maxConnections: maxConnections, maxMessages: maxMessages, maxBytes: maxBytes,
	}, nil
}

// SetObserver installs one immutable non-authoritative observation boundary.
func (a *Admission) SetObserver(observer Observer) error {
	if a == nil || observer == nil {
		return &Error{Class: FailureContract}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.used || a.stopping || a.observer != nil {
		return &Error{Class: FailureContract}
	}
	a.observer = newObserverDispatcher(observer)
	return nil
}

// ActivateObserver starts delivery after quiescent socket creation completes.
func (a *Admission) ActivateObserver() error {
	if a == nil {
		return &Error{Class: FailureContract}
	}
	a.mu.Lock()
	observer := a.observer
	a.mu.Unlock()
	if observer == nil || !observer.start() {
		return &Error{Class: FailureContract}
	}
	return nil
}

// AdmitConnection reserves one connection before a worker is launched.
func (a *Admission) AdmitConnection() (func(), bool) {
	if a == nil {
		return func() {}, false
	}
	a.mu.Lock()
	a.used = true
	observer := a.observer
	if a.stopping {
		a.mu.Unlock()
		safelyRecordConnection(observer, "stopping")
		return func() {}, false
	}
	if a.connections >= a.maxConnections {
		a.mu.Unlock()
		safelyRecordConnection(observer, "connection_limit")
		return func() {}, false
	}
	a.connections++
	a.mu.Unlock()
	safelyRecordConnection(observer, "accepted")
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			a.connections--
			a.mu.Unlock()
		})
	}, true
}

// AdmitMessage reserves one in-flight message and its initial byte budget.
func (a *Admission) AdmitMessage(initial int64) (*Reservation, bool) {
	if a == nil || initial < 0 {
		return nil, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.used = true
	if a.stopping || a.messages >= a.maxMessages || initial > a.maxBytes-a.bytes {
		return nil, false
	}
	a.messages++
	a.bytes += initial
	return &Reservation{owner: a, bytes: initial}, true
}

// ReserveBytes acquires one temporary process-wide byte account before allocation.
func (a *Admission) ReserveBytes(amount int64) (func(), bool) {
	if a == nil || amount < 0 {
		return func() {}, false
	}
	a.mu.Lock()
	a.used = true
	if a.stopping || amount > a.maxBytes-a.bytes {
		a.mu.Unlock()
		return func() {}, false
	}
	a.bytes += amount
	a.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			a.bytes -= amount
			a.mu.Unlock()
		})
	}, true
}

// observerSnapshot returns the immutable process observer.
func (a *Admission) observerSnapshot() Observer {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.observer
}

// safelyRecordConnection contains every injected telemetry defect.
func safelyRecordConnection(observer Observer, admission string) {
	if observer == nil {
		return
	}
	defer func() { _ = recover() }()
	observer.RecordConnectionAdmission(admission)
}

// Stop rejects new work while retained reservations drain.
func (a *Admission) Stop() {
	if a != nil {
		a.mu.Lock()
		a.stopping = true
		a.mu.Unlock()
	}
}

// CloseObserver stops delivery after active workers have drained.
func (a *Admission) CloseObserver() error {
	if a == nil {
		return &Error{Class: FailureContract}
	}
	a.mu.Lock()
	observer := a.observer
	stopping := a.stopping
	a.mu.Unlock()
	if !stopping || observer == nil {
		return &Error{Class: FailureContract}
	}
	observer.close()
	return nil
}

// snapshot returns one synchronized accounting view for runtime diagnostics.
func (a *Admission) snapshot() (connections, messages int, bytes int64, stopping bool) {
	if a == nil {
		return 0, 0, 0, true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.connections, a.messages, a.bytes, a.stopping
}

// String returns a content-free admission diagnostic.
func (*Admission) String() string { return redactedAdmission }

// GoString returns a content-free admission Go representation.
func (a *Admission) GoString() string { return a.String() }

// Format prevents formatting from traversing the observer owner.
func (a *Admission) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, a.String())
}

// MarshalJSON rejects serialization of the observer owner.
func (*Admission) MarshalJSON() ([]byte, error) {
	return nil, &Error{Class: FailureContract}
}

// MarshalText rejects text serialization of the observer owner.
func (*Admission) MarshalText() ([]byte, error) {
	return nil, &Error{Class: FailureContract}
}

// Reservation owns one exactly-once aggregate byte account.
type Reservation struct {
	mu       sync.Mutex
	owner    *Admission
	bytes    int64
	released bool
}

// Grow atomically reserves additional bytes before allocation.
func (r *Reservation) Grow(amount int64) bool {
	if r == nil || amount < 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released || r.owner == nil {
		return false
	}
	r.owner.mu.Lock()
	defer r.owner.mu.Unlock()
	if amount > r.owner.maxBytes-r.owner.bytes {
		return false
	}
	r.owner.bytes += amount
	r.bytes += amount
	return true
}

// Shrink returns retained bytes while preserving the in-flight message owner.
func (r *Reservation) Shrink(amount int64) bool {
	if r == nil || amount < 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released || r.owner == nil || amount > r.bytes {
		return false
	}
	r.owner.mu.Lock()
	r.owner.bytes -= amount
	r.owner.mu.Unlock()
	r.bytes -= amount
	return true
}

// Release returns the message and byte reservation exactly once.
func (r *Reservation) Release() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released || r.owner == nil {
		return
	}
	r.owner.mu.Lock()
	r.owner.bytes -= r.bytes
	r.owner.messages--
	r.owner.mu.Unlock()
	r.bytes = 0
	r.released = true
}
