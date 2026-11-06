package datasource

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const fuzzLookupInputBytes = 256

// FuzzIdentifierAndLookupFacts proves shared identifier and request
// constructors remain deterministic, closed, canonical, and redacted.
func FuzzIdentifierAndLookupFacts(f *testing.F) {
	f.Add([]byte("profile.example"), []byte("example.test"), uint8(ProfileUseOriginator))
	f.Add([]byte("a"), []byte("a.test"), uint8(ProfileUseOrdinaryTransit))
	f.Add([]byte("A"), []byte("EXAMPLE.TEST"), uint8(0))
	f.Add([]byte{0xff}, []byte{0xff}, uint8(255))

	f.Fuzz(func(t *testing.T, rawIdentifier []byte, rawDomain []byte, rawUse uint8) {
		if len(rawIdentifier) > fuzzLookupInputBytes || len(rawDomain) > fuzzLookupInputBytes {
			return
		}
		identifierValue := string(rawIdentifier)
		domainValue := string(rawDomain)
		profile, tenant, identifiersValid := exerciseFuzzIdentifiers(
			t,
			identifierValue,
			len(rawIdentifier),
		)
		use := ProfileUse(rawUse)
		at := time.Unix(1_700_000_000, 123).UTC()
		profileErr := exerciseFuzzProfileRequest(t, profile, use, at)
		policyErr := exerciseFuzzPolicyRequest(
			t,
			tenant,
			domainValue,
			use,
			at,
		)
		if identifierValue == "profile.example" &&
			domainValue == "example.test" &&
			use == ProfileUseOriginator &&
			(!identifiersValid || profileErr != nil || policyErr != nil) {
			t.Fatal("known-valid identifier and lookup facts were rejected")
		}
	})
}

// exerciseFuzzIdentifiers compares all shared identifier constructors and
// returns the two identifiers needed by request fuzzing.
func exerciseFuzzIdentifiers(
	t *testing.T,
	value string,
	byteLen int,
) (ProfileID, TenantID, bool) {
	t.Helper()
	profileA, profileErrA := NewProfileID(value)
	profileB, profileErrB := NewProfileID(value)
	handle, handleErr := NewKeyHandleID(value)
	tenant, tenantErr := NewTenantID(value)
	route, routeErr := NewFeedbackRouteID(value)
	identifierErrors := []error{profileErrA, profileErrB, handleErr, tenantErr, routeErr}
	success := profileErrA == nil
	for _, err := range identifierErrors {
		if (err == nil) != success {
			t.Fatal("shared identifier constructors disagreed")
		}
		if err != nil && ErrorCodeOf(err) != ErrorCodeInvalidRequest {
			t.Fatal("identifier constructor returned a non-closed error")
		}
	}
	if profileA != profileB {
		t.Fatal("identifier construction was nondeterministic")
	}
	if !success {
		return profileA, tenant, false
	}
	if !profileA.Valid() || !handle.Valid() || !tenant.Valid() || !route.Valid() ||
		profileA.ByteLen() != byteLen ||
		!profileA.WithinMaxBytes(HardLimits().MaxIdentifierBytes) {
		t.Fatal("valid identifier facts were not preserved")
	}
	redacted := map[any]string{
		profileA: "datasource.ProfileID{redacted}",
		handle:   "datasource.KeyHandleID{redacted}",
		tenant:   "datasource.TenantID{redacted}",
		route:    "datasource.FeedbackRouteID{redacted}",
	}
	for identifier, expected := range redacted {
		if fmt.Sprintf("%v", identifier) != expected ||
			fmt.Sprintf("%#v", identifier) != expected ||
			fmt.Sprintf("%s", identifier) != expected ||
			fmt.Sprintf("%q", identifier) != expected {
			t.Fatal("identifier formatting was not exactly redacted")
		}
	}
	return profileA, tenant, true
}

// exerciseFuzzProfileRequest proves deterministic profile-request validation
// while preserving all accepted lookup facts.
func exerciseFuzzProfileRequest(
	t *testing.T,
	profile ProfileID,
	use ProfileUse,
	at time.Time,
) error {
	t.Helper()
	left, leftErr := NewProfileRequest(profile, use, at, DefaultLimits())
	right, rightErr := NewProfileRequest(profile, use, at, DefaultLimits())
	if left != right || ErrorCodeOf(leftErr) != ErrorCodeOf(rightErr) {
		t.Fatal("profile request construction was nondeterministic")
	}
	assertFuzzRequestPair(t, left.Valid(), leftErr)
	if leftErr == nil &&
		(left.ProfileID() != profile ||
			left.Use() != use ||
			!left.EvaluationTime().Equal(at)) {
		t.Fatal("profile request changed exact lookup facts")
	}
	return leftErr
}

// exerciseFuzzPolicyRequest proves deterministic policy-request validation
// and exact canonical signing-domain preservation.
func exerciseFuzzPolicyRequest(
	t *testing.T,
	tenant TenantID,
	domain string,
	use ProfileUse,
	at time.Time,
) error {
	t.Helper()
	left, leftErr := NewPolicyRequest(tenant, domain, use, at, DefaultLimits())
	right, rightErr := NewPolicyRequest(tenant, domain, use, at, DefaultLimits())
	if left != right || ErrorCodeOf(leftErr) != ErrorCodeOf(rightErr) {
		t.Fatal("policy request construction was nondeterministic")
	}
	assertFuzzRequestPair(t, left.Valid(), leftErr)
	if leftErr == nil &&
		(left.TenantID() != tenant ||
			!strings.EqualFold(left.SigningDomain(), domain) ||
			left.SigningDomain() != strings.ToLower(domain) ||
			left.Use() != use ||
			!left.EvaluationTime().Equal(at)) {
		t.Fatal("policy request changed exact lookup facts")
	}
	return leftErr
}

// assertFuzzRequestPair verifies constructor success or one direct closed
// request failure without printing fuzz-controlled facts.
func assertFuzzRequestPair(t *testing.T, valid bool, err error) {
	t.Helper()
	if err == nil {
		if !valid {
			t.Fatal("request constructor returned incomplete success")
		}
		return
	}
	if valid {
		t.Fatal("request constructor returned a partial result")
	}
	code := ErrorCodeOf(err)
	if code != ErrorCodeInvalidRequest && code != ErrorCodeLimitExceeded {
		t.Fatal("request constructor returned a non-closed error")
	}
}
