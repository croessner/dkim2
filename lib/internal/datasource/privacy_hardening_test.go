package datasource

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestDatasourcePrivacyMatrixCoversFormattingTextJSONAndWrapping proves all
// domain surfaces remain marker-free across generic diagnostic mechanisms.
func TestDatasourcePrivacyMatrixCoversFormattingTextJSONAndWrapping(t *testing.T) {
	t.Parallel()

	const marker = "privacy-marker-x"
	limits := DefaultLimits()
	profileID := mustModelProfileID(t, "profile."+marker)
	handleID := mustModelKeyHandleID(t, "handle."+marker)
	tenantID := mustModelTenantID(t, "tenant."+marker)
	routeID := mustModelFeedbackRouteID(t, "route."+marker)
	credential := mustModelCredential(
		t,
		marker,
		AlgorithmEd25519SHA256,
		"handle."+marker,
		limits,
	)
	profile, err := NewProfile(
		profileID,
		marker+".test",
		RecordStatusActive,
		[]Credential{credential},
		time.Time{},
		time.Time{},
		limits,
	)
	if err != nil {
		t.Fatal("privacy profile construction failed")
	}
	policy, err := NewPolicy(
		tenantID,
		profile.SigningDomain(),
		ProfileUseOriginator,
		profileID,
		RecordStatusActive,
		RolloutEnforce,
		CompatibilityStrict,
		routeID,
		limits,
	)
	if err != nil {
		t.Fatal("privacy policy construction failed")
	}
	at := time.Unix(1_700_000_000, 0).UTC()
	profileRequest, err := NewProfileRequest(
		profileID,
		ProfileUseOriginator,
		at,
		limits,
	)
	if err != nil {
		t.Fatal("privacy profile request construction failed")
	}
	policyRequest, err := NewPolicyRequest(
		tenantID,
		profile.SigningDomain(),
		ProfileUseOriginator,
		at,
		limits,
	)
	if err != nil {
		t.Fatal("privacy policy request construction failed")
	}
	resolvedProfile, err := NewResolvedProfile(1, profile)
	if err != nil {
		t.Fatal("privacy profile result construction failed")
	}
	resolvedPolicy, err := NewResolvedPolicy(1, policy, resolvedProfile)
	if err != nil {
		t.Fatal("privacy policy result construction failed")
	}
	usage, err := NewUsage(1, 1, 1, 1, len(marker), limits)
	if err != nil {
		t.Fatal("privacy usage construction failed")
	}
	wrapped := fmt.Errorf("outer datasource failure: %w", NewError(ErrorCodeMalformedData))
	rawProviderErr := errors.New(marker)
	wrappedProviderErr := fmt.Errorf("provider wrapper: %w", rawProviderErr)
	sanitizedProfileErr := ValidateProfileOutcome(
		ResolvedProfile{},
		wrappedProviderErr,
	)
	sanitizedPolicyErr := ValidatePolicyOutcome(
		ResolvedPolicy{},
		wrappedProviderErr,
	)
	if ErrorCodeOf(sanitizedProfileErr) != ErrorCodeInternalInvariant ||
		ErrorCodeOf(sanitizedPolicyErr) != ErrorCodeInternalInvariant {
		t.Fatal("marker-bearing provider errors were not sanitized")
	}

	values := []any{
		profileID,
		handleID,
		tenantID,
		routeID,
		usage,
		credential,
		profile,
		policy,
		profileRequest,
		policyRequest,
		resolvedProfile,
		resolvedPolicy,
		NewError(ErrorCodeMalformedData),
		wrapped,
		sanitizedProfileErr,
		sanitizedPolicyErr,
	}
	for _, value := range values {
		assertDatasourcePrivacySurface(t, value, marker)
	}
}

// assertDatasourcePrivacySurface checks formatting, optional text marshaling,
// and value/pointer/container JSON without exposing the marker on failure.
func assertDatasourcePrivacySurface(t *testing.T, value any, marker string) {
	t.Helper()
	pointerValue := reflect.New(reflect.TypeOf(value))
	pointerValue.Elem().Set(reflect.ValueOf(value))
	pointer := pointerValue.Interface()
	subjects := []any{value, pointer}
	for index, subject := range subjects {
		renderings := []string{
			fmt.Sprintf("%v", subject),
			fmt.Sprintf("%+v", subject),
			fmt.Sprintf("%#v", subject),
			fmt.Sprintf("%s", subject),
			fmt.Sprintf("%q", subject),
			fmt.Sprintf("%x", subject),
			fmt.Sprintf("%X", subject),
			fmt.Sprintf("%d", subject),
			fmt.Sprintf("%T", subject),
			fmt.Sprint(subject),
			fmt.Sprintln(subject),
		}
		if index == 1 {
			renderings = append(renderings, fmt.Sprintf("%p", subject))
		}
		for _, rendered := range renderings {
			if strings.Contains(rendered, marker) {
				t.Fatalf(
					"datasource formatting exposed a protected marker for %T",
					subject,
				)
			}
		}
		if marshaler, ok := subject.(encoding.TextMarshaler); ok {
			text, err := marshaler.MarshalText()
			if strings.Contains(string(text), marker) ||
				strings.Contains(fmt.Sprint(err), marker) {
				t.Fatal("datasource text marshaling exposed a protected marker")
			}
		}
	}
	for _, candidate := range []any{
		value,
		pointer,
		[]any{value},
		map[string]any{"safe": value},
	} {
		encoded, err := json.Marshal(candidate)
		if strings.Contains(string(encoded), marker) ||
			strings.Contains(fmt.Sprint(err), marker) {
			t.Fatal("datasource JSON marshaling exposed a protected marker")
		}
	}
}
