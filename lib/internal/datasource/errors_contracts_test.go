package datasource

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestDatasourceErrorTaxonomyIsClosedAndContextCompatible verifies all eleven exact stable codes.
func TestDatasourceErrorTaxonomyIsClosedAndContextCompatible(t *testing.T) {
	codes := []ErrorCode{
		ErrorCodeInvalidRequest,
		ErrorCodeNotFound,
		ErrorCodeAmbiguous,
		ErrorCodeInactive,
		ErrorCodeMalformedData,
		ErrorCodeLimitExceeded,
		ErrorCodeUnavailable,
		ErrorCodeUnsupportedPlatform,
		ErrorCodeCancelled,
		ErrorCodeDeadlineExceeded,
		ErrorCodeInternalInvariant,
	}
	for _, code := range codes {
		if !code.Known() {
			t.Fatalf("known code %q rejected", code)
		}
		err := NewError(code)
		if err == nil || ErrorCodeOf(err) != code || err.Error() != string(code) {
			t.Fatalf("NewError(%q) = %v code=%q", code, err, ErrorCodeOf(err))
		}
		if code == ErrorCodeCancelled && !errors.Is(err, context.Canceled) {
			t.Fatal("direct cancelled error lost context.Canceled identity")
		}
		if code == ErrorCodeDeadlineExceeded && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("direct deadline error lost context.DeadlineExceeded identity")
		}
	}
	if ErrorCode("future").Known() {
		t.Fatal("unknown error code accepted")
	}
	unknown := NewError(ErrorCode("marker.future"))
	if ErrorCodeOf(unknown) != ErrorCodeInternalInvariant || unknown.Error() != string(ErrorCodeInternalInvariant) {
		t.Fatalf("unknown NewError() = %v code=%q", unknown, ErrorCodeOf(unknown))
	}
}

// TestDatasourceErrorsFormatOnlyStableCodes verifies every formatting verb remains cause-free and bounded.
func TestDatasourceErrorsFormatOnlyStableCodes(t *testing.T) {
	for _, code := range []ErrorCode{
		ErrorCodeInvalidRequest,
		ErrorCodeNotFound,
		ErrorCodeAmbiguous,
		ErrorCodeInactive,
		ErrorCodeMalformedData,
		ErrorCodeLimitExceeded,
		ErrorCodeUnavailable,
		ErrorCodeUnsupportedPlatform,
		ErrorCodeCancelled,
		ErrorCodeDeadlineExceeded,
		ErrorCodeInternalInvariant,
	} {
		err := NewError(code)
		got := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x", err, err, err, err, err, err)
		if strings.Contains(got, "datasource.Error") || strings.Contains(got, "cause") ||
			strings.Count(got, string(code)) != 6 {
			t.Fatalf("error %q formatting was not stable", code)
		}
	}
}

// TestErrorFromContextMapsNilLiveCancelledAndDeadlineStates verifies exact context classification.
func TestErrorFromContextMapsNilLiveCancelledAndDeadlineStates(t *testing.T) {
	if err := ErrorFromContext(nil); ErrorCodeOf(err) != ErrorCodeInvalidRequest { //nolint:staticcheck // Nil is the explicit contract case under test.
		t.Fatalf("ErrorFromContext(nil) = %v", err)
	}
	if err := ErrorFromContext(context.Background()); err != nil {
		t.Fatalf("ErrorFromContext(live) = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ErrorFromContext(cancelled); ErrorCodeOf(err) != ErrorCodeCancelled || !errors.Is(err, context.Canceled) {
		t.Fatalf("ErrorFromContext(cancelled) = %v", err)
	}
	deadline, deadlineCancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer deadlineCancel()
	if err := ErrorFromContext(deadline); ErrorCodeOf(err) != ErrorCodeDeadlineExceeded || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ErrorFromContext(deadline) = %v", err)
	}
}

// TestOutcomeValidatorsRequireDirectKnownDatasourceErrors verifies raw, wrapped, typed-nil, and hostile errors fail closed.
func TestOutcomeValidatorsRequireDirectKnownDatasourceErrors(t *testing.T) {
	for _, code := range []ErrorCode{
		ErrorCodeInvalidRequest,
		ErrorCodeNotFound,
		ErrorCodeAmbiguous,
		ErrorCodeInactive,
		ErrorCodeMalformedData,
		ErrorCodeLimitExceeded,
		ErrorCodeUnavailable,
		ErrorCodeUnsupportedPlatform,
		ErrorCodeCancelled,
		ErrorCodeDeadlineExceeded,
		ErrorCodeInternalInvariant,
	} {
		if err := ValidateProfileOutcome(ResolvedProfile{}, NewError(code)); err != nil {
			t.Fatalf("ValidateProfileOutcome(zero, %q) = %v", code, err)
		}
		if err := ValidatePolicyOutcome(ResolvedPolicy{}, NewError(code)); err != nil {
			t.Fatalf("ValidatePolicyOutcome(zero, %q) = %v", code, err)
		}
	}

	const marker = "marker.raw-provider-error"
	var typedNil *Error
	invalidErrors := []error{
		errors.New(marker),
		fmt.Errorf("%s: %w", marker, NewError(ErrorCodeUnavailable)),
		typedNil,
		panickingAsDatasourceError{},
	}
	for _, invalid := range invalidErrors {
		profileErr := callProfileOutcomeWithoutPanic(t, invalid)
		if ErrorCodeOf(profileErr) != ErrorCodeInternalInvariant || strings.Contains(profileErr.Error(), marker) {
			t.Fatalf("ValidateProfileOutcome(raw) = %v", profileErr)
		}
		policyErr := callPolicyOutcomeWithoutPanic(t, invalid)
		if ErrorCodeOf(policyErr) != ErrorCodeInternalInvariant || strings.Contains(policyErr.Error(), marker) {
			t.Fatalf("ValidatePolicyOutcome(raw) = %v", policyErr)
		}
	}
}

// TestIncompleteResultsCannotBecomeSuccessfulOutcomes verifies partial values never represent provider success.
func TestIncompleteResultsCannotBecomeSuccessfulOutcomes(t *testing.T) {
	profileID, err := NewProfileID("profile.example")
	if err != nil {
		t.Fatal(err)
	}
	partialProfile := ResolvedProfile{generation: 1, profile: Profile{id: profileID}}
	partialPolicy := ResolvedPolicy{generation: 2, profile: ResolvedProfile{
		generation: 1,
		profile:    Profile{id: profileID},
	}}
	for name, result := range map[string]struct {
		valid      bool
		outcomeErr error
	}{
		"zero profile": {
			valid:      (ResolvedProfile{}).Valid(),
			outcomeErr: ValidateProfileOutcome(ResolvedProfile{}, nil),
		},
		"partial profile": {
			valid:      partialProfile.Valid(),
			outcomeErr: ValidateProfileOutcome(partialProfile, nil),
		},
		"zero policy": {
			valid:      (ResolvedPolicy{}).Valid(),
			outcomeErr: ValidatePolicyOutcome(ResolvedPolicy{}, nil),
		},
		"partial policy": {
			valid:      partialPolicy.Valid(),
			outcomeErr: ValidatePolicyOutcome(partialPolicy, nil),
		},
	} {
		if result.valid || ErrorCodeOf(result.outcomeErr) != ErrorCodeInternalInvariant {
			t.Fatalf("%s valid=%t outcome=%v", name, result.valid, result.outcomeErr)
		}
	}
	if partialProfile.Generation() != 1 || partialPolicy.Generation() != 2 {
		t.Fatal("test result generations were not retained")
	}
}

// TestMalformedNonemptyResultIdentityIsNotZero verifies typed failures reject partial protected state.
func TestMalformedNonemptyResultIdentityIsNotZero(t *testing.T) {
	malformed := ProfileID{identifier{value: "protected/invalid"}}
	profile := ResolvedProfile{profile: Profile{id: malformed}}
	if err := ValidateProfileOutcome(profile, NewError(ErrorCodeNotFound)); ErrorCodeOf(err) != ErrorCodeInternalInvariant {
		t.Fatal("malformed nonempty profile result was accepted as zero")
	}
	policy := ResolvedPolicy{profile: ResolvedProfile{profile: Profile{id: malformed}}}
	if err := ValidatePolicyOutcome(policy, NewError(ErrorCodeNotFound)); ErrorCodeOf(err) != ErrorCodeInternalInvariant {
		t.Fatal("malformed nested policy result was accepted as zero")
	}
}

// TestErrorCodeOfDoesNotInvokeHostileErrors verifies classification cannot execute provider-controlled traversal.
func TestErrorCodeOfDoesNotInvokeHostileErrors(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("ErrorCodeOf panicked: %v", recovered)
		}
	}()
	if code := ErrorCodeOf(panickingAsDatasourceError{}); code != ErrorCodeInternalInvariant {
		t.Fatalf("ErrorCodeOf(hostile) = %q", code)
	}
}

type panickingAsDatasourceError struct{}

// Error returns a constant hostile-provider diagnostic.
func (panickingAsDatasourceError) Error() string { return "hostile provider error" }

// As panics if outcome validation invokes attacker-controlled error traversal.
func (panickingAsDatasourceError) As(any) bool { panic("hostile As invoked") }

// callProfileOutcomeWithoutPanic proves profile outcome validation does not invoke hostile methods.
func callProfileOutcomeWithoutPanic(t *testing.T, err error) (result error) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("ValidateProfileOutcome panicked: %v", recovered)
		}
	}()
	return ValidateProfileOutcome(ResolvedProfile{}, err)
}

// callPolicyOutcomeWithoutPanic proves policy outcome validation does not invoke hostile methods.
func callPolicyOutcomeWithoutPanic(t *testing.T, err error) (result error) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("ValidatePolicyOutcome panicked: %v", recovered)
		}
	}()
	return ValidatePolicyOutcome(ResolvedPolicy{}, err)
}
