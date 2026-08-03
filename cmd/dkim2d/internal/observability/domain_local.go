package observability

import (
	"context"
	"sync"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/domainadmin"
)

// DomainDurationBucket is one bounded command-local elapsed-time class.
type DomainDurationBucket string

const (
	// DomainDurationFast reports completion below one second.
	DomainDurationFast DomainDurationBucket = "fast"
	// DomainDurationMedium reports completion below ten seconds.
	DomainDurationMedium DomainDurationBucket = "medium"
	// DomainDurationSlow reports completion below one minute.
	DomainDurationSlow DomainDurationBucket = "slow"
	// DomainDurationOverflow reports completion at or above one minute.
	DomainDurationOverflow DomainDurationBucket = "overflow"
)

// LocalDomainSnapshot is one bounded command-local observation consistency record.
type LocalDomainSnapshot struct {
	Event          domainadmin.OnboardingObservation
	DurationBucket DomainDurationBucket
	Accepted       uint32
	Dropped        uint32
}

// LocalDomainObserver retains bounded exporter-free evidence for one offline command.
type LocalDomainObserver struct {
	mu       sync.Mutex
	started  time.Time
	now      func() time.Time
	last     domainadmin.OnboardingObservation
	accepted uint32
	dropped  uint32
}

// NewLocalDomainObserver constructs one command-scoped exporter-free observation owner.
func NewLocalDomainObserver() *LocalDomainObserver {
	return newLocalDomainObserver(time.Now)
}

// newLocalDomainObserver constructs a deterministic local observer for tests.
func newLocalDomainObserver(now func() time.Time) *LocalDomainObserver {
	if now == nil {
		return nil
	}
	return &LocalDomainObserver{started: now(), now: now}
}

// ObserveOnboarding validates and retains one bounded event without exporter or global state.
func (o *LocalDomainObserver) ObserveOnboarding(_ context.Context, event domainadmin.OnboardingObservation) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !event.Valid() || o.accepted == ^uint32(0) || o.dropped == ^uint32(0) {
		if o.dropped != ^uint32(0) {
			o.dropped++
		}
		return
	}
	o.last = event
	o.accepted++
}

// Snapshot returns detached bounded evidence including accepted, dropped, and elapsed classes.
func (o *LocalDomainObserver) Snapshot() (LocalDomainSnapshot, bool) {
	if o == nil {
		return LocalDomainSnapshot{}, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	elapsed := o.now().Sub(o.started)
	if elapsed < 0 {
		return LocalDomainSnapshot{}, false
	}
	return LocalDomainSnapshot{
		Event: o.last, DurationBucket: domainDurationBucket(elapsed),
		Accepted: o.accepted, Dropped: o.dropped,
	}, true
}

// MatchesResult proves one and only one local event agrees with a workflow result.
func (o *LocalDomainObserver) MatchesResult(
	command domainadmin.Command,
	backend datasourceadmin.BackendClass,
	result domainadmin.OnboardingResult,
) bool {
	snapshot, ok := o.Snapshot()
	return ok && snapshot.Accepted == 1 && snapshot.Dropped == 0 && snapshot.DurationBucket.valid() &&
		snapshot.Event == (domainadmin.OnboardingObservation{
			Command: command, State: result.State, Backend: backend, Result: result.Result,
			Failure: result.Failure, Receipt: result.ReceiptPhase,
		})
}

// MatchesStatus proves one and only one local event agrees with a read-only status result.
func (o *LocalDomainObserver) MatchesStatus(
	backend datasourceadmin.BackendClass,
	status domainadmin.StatusResult,
) bool {
	snapshot, ok := o.Snapshot()
	return ok && snapshot.Accepted == 1 && snapshot.Dropped == 0 && snapshot.DurationBucket.valid() &&
		snapshot.Event == (domainadmin.OnboardingObservation{
			Command: domainadmin.CommandStatus, State: status.State, Backend: backend,
			Result: domainadmin.OnboardingResultSuccess, Failure: status.Failure,
			Receipt: status.ReceiptPhase,
		})
}

// valid accepts only the closed duration vocabulary.
func (b DomainDurationBucket) valid() bool {
	return b == DomainDurationFast || b == DomainDurationMedium || b == DomainDurationSlow ||
		b == DomainDurationOverflow
}

// domainDurationBucket maps finite elapsed time to one bounded operational class.
func domainDurationBucket(elapsed time.Duration) DomainDurationBucket {
	switch {
	case elapsed < time.Second:
		return DomainDurationFast
	case elapsed < 10*time.Second:
		return DomainDurationMedium
	case elapsed < time.Minute:
		return DomainDurationSlow
	default:
		return DomainDurationOverflow
	}
}
