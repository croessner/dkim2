package datasource

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const (
	profileCase = "profile"
	handleCase  = "handle"
	tenantCase  = "tenant"
	routeCase   = "route"
)

// TestIdentifierConstructorsEnforceExactGrammar verifies every identifier owner shares the exact canonical grammar.
func TestIdentifierConstructorsEnforceExactGrammar(t *testing.T) {
	type constructor func(string) (bool, error)
	constructors := map[string]constructor{
		profileCase: func(value string) (bool, error) {
			identifier, err := NewProfileID(value)
			return identifier.Valid(), err
		},
		handleCase: func(value string) (bool, error) {
			identifier, err := NewKeyHandleID(value)
			return identifier.Valid(), err
		},
		tenantCase: func(value string) (bool, error) {
			identifier, err := NewTenantID(value)
			return identifier.Valid(), err
		},
		"feedback route": func(value string) (bool, error) {
			identifier, err := NewFeedbackRouteID(value)
			return identifier.Valid(), err
		},
	}
	valid := []string{
		"a",
		"a0",
		"a.valid_id-9",
		"a._-",
		strings.Repeat("a", 128),
	}
	invalid := []string{
		"",
		"A",
		".leading",
		"_leading",
		"-leading",
		"a/b",
		`a\b`,
		"a:b",
		"a b",
		"a\tb",
		"a\x00b",
		"ä",
		strings.Repeat("a", 129),
	}
	for name, construct := range constructors {
		for index, value := range valid {
			isValid, err := construct(value)
			if err != nil || !isValid {
				t.Fatalf("%s valid case %d rejected", name, index)
			}
		}
		for index, value := range invalid {
			isValid, err := construct(value)
			if err == nil || isValid || ErrorCodeOf(err) != ErrorCodeInvalidRequest {
				t.Fatalf("%s invalid case %d accepted", name, index)
			}
			if value != "" && strings.Contains(err.Error(), value) {
				t.Fatalf("%s invalid input leaked through error", name)
			}
		}
	}
}

// TestIdentifiersRedactFormattingAndGenericJSON verifies protected IDs have no accidental generic serialization path.
func TestIdentifiersRedactFormattingAndGenericJSON(t *testing.T) {
	const marker = "marker.profile-handle-tenant-route"
	profile, profileErr := NewProfileID(marker)
	handle, handleErr := NewKeyHandleID(marker)
	tenant, tenantErr := NewTenantID(marker)
	route, routeErr := NewFeedbackRouteID(marker)
	if profileErr != nil || handleErr != nil || tenantErr != nil || routeErr != nil {
		t.Fatalf("identifier construction errors = %v, %v, %v, %v", profileErr, handleErr, tenantErr, routeErr)
	}
	for name, value := range map[string]any{
		profileCase: profile,
		handleCase:  handle,
		tenantCase:  tenant,
		routeCase:   route,
	} {
		formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q", value, value, value, value, value)
		if strings.Contains(formatted, marker) || !strings.Contains(formatted, "redacted") {
			t.Fatalf("%s formatting was not redacted", name)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("json.Marshal(%s) error = %v", name, err)
		}
		if strings.Contains(string(encoded), marker) {
			t.Fatalf("%s JSON leaked marker", name)
		}
	}
}

// TestIdentifierZeroValuesRemainInvalidAndRedacted verifies zero values cannot become identities through formatting.
func TestIdentifierZeroValuesRemainInvalidAndRedacted(t *testing.T) {
	for name, value := range map[string]interface {
		Valid() bool
	}{
		profileCase: ProfileID{},
		handleCase:  KeyHandleID{},
		tenantCase:  TenantID{},
		routeCase:   FeedbackRouteID{},
	} {
		if value.Valid() {
			t.Fatalf("%s zero identifier is valid", name)
		}
		if formatted := fmt.Sprintf("%#v", value); !strings.Contains(formatted, "redacted") {
			t.Fatalf("%s zero formatting was not redacted", name)
		}
	}
}

// TestIdentifiersExposeOnlySafeLengthChecksForNarrowedLimits verifies bounded selection without a raw-value accessor.
func TestIdentifiersExposeOnlySafeLengthChecksForNarrowedLimits(t *testing.T) {
	const value = "identifier.example"
	profile, _ := NewProfileID(value)
	handle, _ := NewKeyHandleID(value)
	tenant, _ := NewTenantID(value)
	route, _ := NewFeedbackRouteID(value)
	for name, identifier := range map[string]interface {
		ByteLen() int
		WithinMaxBytes(int) bool
	}{
		profileCase: profile,
		handleCase:  handle,
		tenantCase:  tenant,
		routeCase:   route,
	} {
		if identifier.ByteLen() != len(value) {
			t.Fatalf("%s ByteLen() = %d", name, identifier.ByteLen())
		}
		if !identifier.WithinMaxBytes(len(value)) ||
			identifier.WithinMaxBytes(len(value)-1) ||
			identifier.WithinMaxBytes(0) ||
			identifier.WithinMaxBytes(129) {
			t.Fatalf("%s narrowed-bound result is inconsistent", name)
		}
	}
}
