package datasource

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestProfileRequestValidatesExactFactsAndCapturesUTC verifies one immutable profile lookup request.
func TestProfileRequestValidatesExactFactsAndCapturesUTC(t *testing.T) {
	profileID, err := NewProfileID("profile.example")
	if err != nil {
		t.Fatal(err)
	}
	local := time.Date(2026, 7, 23, 19, 5, 29, 123, time.FixedZone("test", 2*60*60))
	request, err := NewProfileRequest(profileID, ProfileUseOriginator, local, DefaultLimits())
	if err != nil || !request.Valid() || request.ProfileID() != profileID ||
		request.Use() != ProfileUseOriginator || !request.EvaluationTime().Equal(local) ||
		request.EvaluationTime().Location() != time.UTC {
		t.Fatalf("NewProfileRequest() = %#v, %v", request, err)
	}
	for _, test := range []struct {
		id  ProfileID
		use ProfileUse
		at  time.Time
	}{
		{use: ProfileUseOriginator, at: local},
		{id: profileID, at: local},
		{id: profileID, use: ProfileUse(255), at: local},
		{id: profileID, use: ProfileUseOriginator},
	} {
		got, requestErr := NewProfileRequest(test.id, test.use, test.at, DefaultLimits())
		if got.Valid() || ErrorCodeOf(requestErr) != ErrorCodeInvalidRequest {
			t.Fatalf("NewProfileRequest(invalid) = %#v, %v", got, requestErr)
		}
	}
	exactIDLimit := DefaultLimits()
	exactIDLimit.MaxIdentifierBytes = profileID.ByteLen()
	if _, requestErr := NewProfileRequest(profileID, ProfileUseOriginator, local, exactIDLimit); requestErr != nil {
		t.Fatalf("NewProfileRequest(exact ID limit) error = %v", requestErr)
	}
	oneUnderIDLimit := exactIDLimit
	oneUnderIDLimit.MaxIdentifierBytes--
	if got, requestErr := NewProfileRequest(profileID, ProfileUseOriginator, local, oneUnderIDLimit); got.Valid() || ErrorCodeOf(requestErr) != ErrorCodeLimitExceeded {
		t.Fatalf("NewProfileRequest(ID one over) = %#v, %v", got, requestErr)
	}
}

// TestPolicyRequestUsesSharedExactDomainRulesAndNarrowedBounds verifies no IDNA, dot repair, or fallback.
func TestPolicyRequestUsesSharedExactDomainRulesAndNarrowedBounds(t *testing.T) {
	tenant, err := NewTenantID("tenant.example")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 7, 23, 19, 5, 29, 0, time.FixedZone("test", -5*60*60))
	request, err := NewPolicyRequest(
		tenant,
		"Mail.Example.TEST",
		ProfileUseOrdinaryTransit,
		at,
		DefaultLimits(),
	)
	if err != nil || !request.Valid() || request.SigningDomain() != "mail.example.test" ||
		request.TenantID() != tenant || request.Use() != ProfileUseOrdinaryTransit ||
		!request.EvaluationTime().Equal(at) || request.EvaluationTime().Location() != time.UTC {
		t.Fatalf("NewPolicyRequest() = %#v, %v", request, err)
	}

	invalidDomains := []string{
		"",
		"example.test.",
		"example..test",
		"example_test",
		"*.example.test",
		"exämple.test",
		"xn--exmple-cua.test.",
	}
	for index, domain := range invalidDomains {
		got, requestErr := NewPolicyRequest(tenant, domain, ProfileUseOriginator, at, DefaultLimits())
		if got.Valid() || ErrorCodeOf(requestErr) != ErrorCodeInvalidRequest {
			t.Fatalf("invalid domain case %d accepted", index)
		}
		if domain != "" && strings.Contains(requestErr.Error(), domain) {
			t.Fatalf("invalid domain case %d leaked in request error", index)
		}
	}

	narrowed := DefaultLimits()
	narrowed.MaxDomainBytes = len("a.test")
	if _, requestErr := NewPolicyRequest(tenant, "aa.test", ProfileUseOriginator, at, narrowed); ErrorCodeOf(requestErr) != ErrorCodeLimitExceeded {
		t.Fatalf("narrow domain error = %v", requestErr)
	}
	narrowed = DefaultLimits()
	narrowed.MaxDomainLabels = 2
	if _, requestErr := NewPolicyRequest(tenant, "a.b.test", ProfileUseOriginator, at, narrowed); ErrorCodeOf(requestErr) != ErrorCodeLimitExceeded {
		t.Fatalf("narrow label error = %v", requestErr)
	}
	narrowed = DefaultLimits()
	narrowed.MaxIdentifierBytes = tenant.ByteLen()
	if _, requestErr := NewPolicyRequest(tenant, "example.test", ProfileUseOriginator, at, narrowed); requestErr != nil {
		t.Fatalf("NewPolicyRequest(exact tenant limit) error = %v", requestErr)
	}
	narrowed.MaxIdentifierBytes--
	if got, requestErr := NewPolicyRequest(tenant, "example.test", ProfileUseOriginator, at, narrowed); got.Valid() || ErrorCodeOf(requestErr) != ErrorCodeLimitExceeded {
		t.Fatalf("NewPolicyRequest(tenant one over) = %#v, %v", got, requestErr)
	}
}

// TestRequestsAndResultsRedactFormattingAndGenericJSON verifies lookup facts remain protected.
func TestRequestsAndResultsRedactFormattingAndGenericJSON(t *testing.T) {
	const marker = "marker.profile.example"
	profileID, _ := NewProfileID(marker)
	tenant, _ := NewTenantID(marker)
	at := time.Unix(1_700_000_000, 0)
	profileRequest, _ := NewProfileRequest(profileID, ProfileUseOriginator, at, DefaultLimits())
	policyRequest, _ := NewPolicyRequest(tenant, "marker.example.test", ProfileUseOriginator, at, DefaultLimits())
	values := map[string]any{
		"profile request": profileRequest,
		"policy request":  policyRequest,
		"profile result":  ResolvedProfile{generation: 1, profile: Profile{id: profileID}},
		"policy result": ResolvedPolicy{
			generation: 1,
			profile: ResolvedProfile{
				generation: 1,
				profile:    Profile{id: profileID},
			},
		},
	}
	for name, value := range values {
		formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q", value, value, value, value, value)
		if strings.Contains(formatted, marker) || !strings.Contains(formatted, "redacted") {
			t.Fatalf("%s formatting was not redacted", name)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("json.Marshal(%s) error = %v", name, err)
		}
		if strings.Contains(string(encoded), marker) || strings.Contains(string(encoded), "marker.example.test") {
			t.Fatalf("%s JSON leaked protected facts", name)
		}
	}
}
