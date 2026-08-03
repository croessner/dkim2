package observability

import (
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/domainadmin"
)

// TestLocalDomainObserverRetainsBoundedSuccessFailureAndStatusEvidence freezes consistency checks.
func TestLocalDomainObserverRetainsBoundedSuccessFailureAndStatusEvidence(t *testing.T) {
	now := time.Unix(1, 0)
	clock := func() time.Time { return now }
	for _, test := range []struct {
		name   string
		event  domainadmin.OnboardingObservation
		result *domainadmin.OnboardingResult
		status *domainadmin.StatusResult
	}{
		{"success", domainadmin.OnboardingObservation{Command: domainadmin.CommandPrepare, State: domainadmin.StateStaged, Backend: datasourceadmin.BackendLDAP, Result: domainadmin.OnboardingResultSuccess, Failure: domainadmin.CodeNone}, &domainadmin.OnboardingResult{State: domainadmin.StateStaged, Result: domainadmin.OnboardingResultSuccess, Failure: domainadmin.CodeNone, PlanComplete: true}, nil},
		{"failure", domainadmin.OnboardingObservation{Command: domainadmin.CommandPrepare, State: domainadmin.StateConflict, Backend: datasourceadmin.BackendLDAP, Result: domainadmin.OnboardingResultFailure, Failure: domainadmin.CodeConflict}, &domainadmin.OnboardingResult{State: domainadmin.StateConflict, Result: domainadmin.OnboardingResultFailure, Failure: domainadmin.CodeConflict, PlanComplete: true}, nil},
		{"status", domainadmin.OnboardingObservation{Command: domainadmin.CommandStatus, State: domainadmin.StateReconcileRequired, Backend: datasourceadmin.BackendLDAP, Result: domainadmin.OnboardingResultSuccess, Failure: domainadmin.CodeNone}, nil, &domainadmin.StatusResult{State: domainadmin.StateReconcileRequired, PlanComplete: true, Failure: domainadmin.CodeNone}},
	} {
		t.Run(test.name, func(t *testing.T) {
			observer := newLocalDomainObserver(clock)
			now = now.Add(2 * time.Second)
			observer.ObserveOnboarding(t.Context(), test.event)
			if test.result != nil && !observer.MatchesResult(test.event.Command, datasourceadmin.BackendLDAP, *test.result) {
				t.Fatal("local observer did not match workflow result")
			}
			if test.status != nil && !observer.MatchesStatus(datasourceadmin.BackendLDAP, *test.status) {
				t.Fatal("local observer did not match status result")
			}
			snapshot, ok := observer.Snapshot()
			if !ok || snapshot.Accepted != 1 || snapshot.Dropped != 0 || snapshot.DurationBucket != DomainDurationMedium {
				t.Fatal("local observer did not retain bounded operational evidence")
			}
		})
	}
}

// TestLocalDomainObserverDropsInvalidOrDuplicateEvidence freezes fail-closed command coupling.
func TestLocalDomainObserverDropsInvalidOrDuplicateEvidence(t *testing.T) {
	observer := NewLocalDomainObserver()
	invalid := domainadmin.OnboardingObservation{
		Command: domainadmin.CommandPrepare, Backend: datasourceadmin.BackendClass("tenant.example.test"),
		Result: domainadmin.OnboardingResultSuccess, Failure: domainadmin.CodeNone,
	}
	observer.ObserveOnboarding(t.Context(), invalid)
	valid := domainadmin.OnboardingObservation{
		Command: domainadmin.CommandPrepare, State: domainadmin.StateStaged,
		Backend: datasourceadmin.BackendLDAP, Result: domainadmin.OnboardingResultSuccess,
		Failure: domainadmin.CodeNone,
	}
	observer.ObserveOnboarding(t.Context(), valid)
	observer.ObserveOnboarding(t.Context(), valid)
	result := domainadmin.OnboardingResult{
		State: domainadmin.StateStaged, Result: domainadmin.OnboardingResultSuccess,
		Failure: domainadmin.CodeNone, PlanComplete: true,
	}
	if observer.MatchesResult(domainadmin.CommandPrepare, datasourceadmin.BackendLDAP, result) {
		t.Fatal("invalid or duplicate observation evidence passed command consistency")
	}
}
