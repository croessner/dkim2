package milter

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"
)

const observerQueueCapacity = 16_384

type observationEventKind uint8

const (
	observationConnection observationEventKind = iota + 1
	observationCallback
	observationMessage
	observationAction
)

type observationEvent struct {
	kind                         observationEventKind
	first, second, third, fourth string
	duration                     time.Duration
	messageBytes, recipients     uint64
	failOpen                     bool
}

// wait joins delivery only within the caller's authoritative shutdown budget.
func (d *observerDispatcher) wait(ctx context.Context) bool {
	if d == nil || ctx == nil {
		return false
	}
	select {
	case <-d.done:
		return true
	case <-ctx.Done():
		return false
	}
}

// observerDispatcher isolates mail processing from observer panic and latency.
type observerDispatcher struct {
	target  Observer
	events  chan observationEvent
	done    chan struct{}
	mu      sync.Mutex
	closed  bool
	started bool
}

// String returns a content-free dispatcher diagnostic.
func (*observerDispatcher) String() string { return redactedAdmission }

// GoString returns a content-free dispatcher Go representation.
func (d *observerDispatcher) GoString() string { return d.String() }

// Format prevents formatting from traversing the observer target.
func (d *observerDispatcher) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, d.String())
}

// MarshalJSON rejects dispatcher serialization.
func (*observerDispatcher) MarshalJSON() ([]byte, error) {
	return nil, &Error{Class: FailureContract}
}

// MarshalText rejects dispatcher text serialization.
func (*observerDispatcher) MarshalText() ([]byte, error) {
	return nil, &Error{Class: FailureContract}
}

// newObserverDispatcher constructs one dormant fixed-capacity dispatcher.
func newObserverDispatcher(target Observer) *observerDispatcher {
	return &observerDispatcher{
		target: target,
		events: make(chan observationEvent, observerQueueCapacity),
		done:   make(chan struct{}),
	}
}

// start activates delivery only after process-global umask work is complete.
func (d *observerDispatcher) start() bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return false
	}
	if d.started {
		return true
	}
	d.started = true
	go d.run()
	return true
}

// RecordConnectionAdmission queues one closed connection outcome without blocking mail.
func (d *observerDispatcher) RecordConnectionAdmission(admission string) {
	d.submit(observationEvent{kind: observationConnection, first: admission})
}

// RecordCallback queues one closed callback outcome without blocking mail.
func (d *observerDispatcher) RecordCallback(
	callback, state, result string,
	duration time.Duration,
) {
	d.submit(observationEvent{
		kind: observationCallback, first: callback, second: state,
		third: result, duration: duration,
	})
}

// RecordMessage queues one closed EOM outcome without blocking mail.
func (d *observerDispatcher) RecordMessage(
	mode, disposition, result, failure string,
	duration time.Duration,
	messageBytes, recipients uint64,
	failOpen bool,
) {
	d.submit(observationEvent{
		kind: observationMessage, first: mode, second: disposition,
		third: result, fourth: failure, duration: duration,
		messageBytes: messageBytes, recipients: recipients, failOpen: failOpen,
	})
}

// RecordAction queues one closed action outcome without blocking mail.
func (d *observerDispatcher) RecordAction(action, result string) {
	d.submit(observationEvent{kind: observationAction, first: action, second: result})
}

// submit performs a nonblocking best-effort enqueue under close synchronization.
func (d *observerDispatcher) submit(event observationEvent) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	select {
	case d.events <- event:
	default:
	}
}

// close stops new events without blocking authoritative shutdown on telemetry.
func (d *observerDispatcher) close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	if !d.started {
		d.started = true
		go d.run()
	}
	if !d.closed {
		d.closed = true
		close(d.events)
	}
	d.mu.Unlock()
}

// run serially invokes the target while containing every panic.
func (d *observerDispatcher) run() {
	defer close(d.done)
	for event := range d.events {
		d.deliver(event)
	}
}

// deliver maps one private event to the narrow observer method.
func (d *observerDispatcher) deliver(event observationEvent) {
	if d == nil || d.target == nil {
		return
	}
	defer func() { _ = recover() }()
	switch event.kind {
	case observationConnection:
		d.target.RecordConnectionAdmission(event.first)
	case observationCallback:
		d.target.RecordCallback(event.first, event.second, event.third, event.duration)
	case observationMessage:
		d.target.RecordMessage(
			event.first, event.second, event.third, event.fourth,
			event.duration, event.messageBytes, event.recipients, event.failOpen,
		)
	case observationAction:
		d.target.RecordAction(event.first, event.second)
	}
}
