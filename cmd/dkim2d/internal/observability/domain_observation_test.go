package observability

import (
	"reflect"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/domainadmin"
)

// TestDomainObservationHasExactLowCardinalityAllowlist freezes the local no-exporter event shape.
func TestDomainObservationHasExactLowCardinalityAllowlist(t *testing.T) {
	typeOf := reflect.TypeFor[domainadmin.OnboardingObservation]()
	want := []string{"Command", "State", "Backend", "Result", "Failure", "Receipt"}
	if typeOf.NumField() != len(want) {
		t.Fatal("domain observation field cardinality drifted")
	}
	for index, name := range want {
		field := typeOf.Field(index)
		if field.Name != name || field.Type.PkgPath() == "" {
			t.Fatal("domain observation admitted raw or unknown attributes")
		}
	}
	valid := domainadmin.OnboardingObservation{
		Command: domainadmin.CommandPrepare, State: domainadmin.StateStaged,
		Backend: datasourceadmin.BackendLDAP, Result: domainadmin.OnboardingResultSuccess,
		Failure: domainadmin.CodeNone,
	}
	if !valid.Valid() {
		t.Fatal("closed bounded domain observation was rejected")
	}
	valid.Backend = datasourceadmin.BackendClass("tenant.example.test")
	if valid.Valid() {
		t.Fatal("identity-shaped unknown observation class was accepted")
	}
}

// TestDomainObservationRejectsCrossFieldAndToxicClasses freezes report-equivalent invariants.
func TestDomainObservationRejectsCrossFieldAndToxicClasses(t *testing.T) {
	invalid := []domainadmin.OnboardingObservation{
		{Command: domainadmin.CommandPrepare, Backend: datasourceadmin.BackendLDAP, Result: domainadmin.OnboardingResultSuccess, Failure: domainadmin.CodeConflict},
		{Command: domainadmin.CommandPrepare, State: domainadmin.StatePlanned, Backend: datasourceadmin.BackendLDAP, Result: domainadmin.OnboardingResultSuccess, Failure: domainadmin.CodeNone, Receipt: domainadmin.ReceiptPhaseClosed},
		{Command: domainadmin.CommandStatus, Backend: datasourceadmin.BackendLDAP, Result: domainadmin.OnboardingResultFailure, Failure: domainadmin.CodeConflict},
		{Command: domainadmin.CommandStatus, State: domainadmin.StateReconcileRequired, Backend: datasourceadmin.BackendLDAP, Result: domainadmin.OnboardingResultSuccess, Failure: domainadmin.CodeReconcileRequired},
		{Command: domainadmin.CommandStatus, Backend: datasourceadmin.BackendClass("tenant.example.test"), Result: domainadmin.OnboardingResultSuccess, Failure: domainadmin.CodeNone},
	}
	for _, observation := range invalid {
		if observation.Valid() {
			t.Fatal("toxic or contradictory observation class was accepted")
		}
	}
	validStatus := domainadmin.OnboardingObservation{
		Command: domainadmin.CommandStatus, State: domainadmin.StateReconcileRequired,
		Backend: datasourceadmin.BackendLDAP, Result: domainadmin.OnboardingResultSuccess,
		Failure: domainadmin.CodeNone,
	}
	if !validStatus.Valid() {
		t.Fatal("exact persisted status observation was rejected")
	}
}
