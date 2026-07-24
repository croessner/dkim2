package datasource

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestClosedEnumsRecognizeOnlyDeclaredValues verifies zero and future numeric values remain invalid.
func TestClosedEnumsRecognizeOnlyDeclaredValues(t *testing.T) {
	known := []interface {
		Known() bool
		String() string
	}{
		ProfileUseOriginator,
		ProfileUseOrdinaryTransit,
		ProfileUseNextDomainTransit,
		RecordStatusActive,
		RecordStatusDisabled,
		RolloutEnforce,
		RolloutObserve,
		RolloutOff,
		CompatibilityStrict,
		ProviderStateReady,
		ProviderStateDegraded,
		ProviderStateClosed,
	}
	for _, value := range known {
		if !value.Known() || value.String() == "" || value.String() == unknownEnumText {
			t.Fatalf("known enum = %T %q known=%t", value, value.String(), value.Known())
		}
	}
	unknown := []interface {
		Known() bool
		String() string
	}{
		ProfileUse(0),
		ProfileUse(255),
		RecordStatus(0),
		RecordStatus(255),
		Rollout(0),
		Rollout(255),
		Compatibility(0),
		Compatibility(255),
		ProviderState(0),
		ProviderState(255),
	}
	for _, value := range unknown {
		if value.Known() || value.String() != unknownEnumText {
			t.Fatalf("unknown enum = %T %q known=%t", value, value.String(), value.Known())
		}
		formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q", value, value, value, value, value)
		if strings.Contains(formatted, "255") || strings.Contains(formatted, "0xff") {
			t.Fatalf("unknown enum leaked raw numeric value: %q", formatted)
		}
		if encoded, err := json.Marshal(value); err == nil || encoded != nil {
			t.Fatalf("json.Marshal(%T unknown) = %s, %v", value, encoded, err)
		}
	}
}

// TestClosedEnumParsersAcceptOnlyExactCanonicalStrings verifies provider input is never normalized.
func TestClosedEnumParsersAcceptOnlyExactCanonicalStrings(t *testing.T) {
	profileUses := map[string]ProfileUse{
		profileUseOriginatorText:        ProfileUseOriginator,
		profileUseOrdinaryTransitText:   ProfileUseOrdinaryTransit,
		profileUseNextDomainTransitText: ProfileUseNextDomainTransit,
	}
	for input, want := range profileUses {
		got, err := ParseProfileUse(input)
		if err != nil || got != want {
			t.Fatalf("ParseProfileUse(%q) = %q, %v", input, got, err)
		}
	}
	statuses := map[string]RecordStatus{
		recordStatusActiveText: RecordStatusActive, recordStatusDisabledText: RecordStatusDisabled,
	}
	for input, want := range statuses {
		got, err := ParseRecordStatus(input)
		if err != nil || got != want {
			t.Fatalf("ParseRecordStatus(%q) = %q, %v", input, got, err)
		}
	}
	rollouts := map[string]Rollout{
		rolloutEnforceText: RolloutEnforce, rolloutObserveText: RolloutObserve,
		rolloutOffText: RolloutOff,
	}
	for input, want := range rollouts {
		got, err := ParseRollout(input)
		if err != nil || got != want {
			t.Fatalf("ParseRollout(%q) = %q, %v", input, got, err)
		}
	}
	if got, err := ParseCompatibility(compatibilityStrictText); err != nil || got != CompatibilityStrict {
		t.Fatalf("ParseCompatibility(strict) = %q, %v", got, err)
	}

	for _, input := range []string{"", "Originator", " active", "observe ", "STRICT", "marker.future"} {
		if got, err := ParseProfileUse(input); got != 0 || ErrorCodeOf(err) != ErrorCodeMalformedData {
			t.Fatalf("ParseProfileUse(%q) = %q, %v", input, got, err)
		}
		if got, err := ParseRecordStatus(input); got != 0 || ErrorCodeOf(err) != ErrorCodeMalformedData {
			t.Fatalf("ParseRecordStatus(%q) = %q, %v", input, got, err)
		}
		if got, err := ParseRollout(input); got != 0 || ErrorCodeOf(err) != ErrorCodeMalformedData {
			t.Fatalf("ParseRollout(%q) = %q, %v", input, got, err)
		}
		if got, err := ParseCompatibility(input); got != 0 || ErrorCodeOf(err) != ErrorCodeMalformedData {
			t.Fatalf("ParseCompatibility(%q) = %q, %v", input, got, err)
		}
	}
}

// TestClosedEnumsMarshalOnlyKnownStableStrings verifies canonical values serialize without widening the vocabulary.
func TestClosedEnumsMarshalOnlyKnownStableStrings(t *testing.T) {
	for _, value := range []any{
		ProfileUseOriginator,
		ProfileUseOrdinaryTransit,
		ProfileUseNextDomainTransit,
		RecordStatusActive,
		RecordStatusDisabled,
		RolloutEnforce,
		RolloutObserve,
		RolloutOff,
		CompatibilityStrict,
		ProviderStateReady,
		ProviderStateDegraded,
		ProviderStateClosed,
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("json.Marshal(%T) error = %v", value, err)
		}
		if string(encoded) != `"`+fmt.Sprint(value)+`"` {
			t.Fatalf("json.Marshal(%T) = %s", value, encoded)
		}
	}
}
