package datasource

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	modelTestDomain   = "example.test"
	modelTestSelector = "selector"
)

// TestCredentialValidatesStrictSPKIAndOwnsDetachedBytes proves credential key
// material is strict algorithm-matching SPKI and never aliases caller storage.
func TestCredentialValidatesStrictSPKIAndOwnsDetachedBytes(t *testing.T) {
	limits := DefaultLimits()
	handleID := mustModelKeyHandleID(t, "key.example.ed25519")
	der := modelPublicKeySPKI(t, AlgorithmEd25519SHA256)
	original := slices.Clone(der)

	credential, err := NewCredential(
		modelTestSelector, AlgorithmEd25519SHA256, der, handleID, limits,
	)
	if err != nil {
		t.Fatalf("NewCredential() error = %v", err)
	}
	if !credential.Valid() || credential.Selector() != modelTestSelector ||
		credential.Algorithm() != AlgorithmEd25519SHA256 ||
		credential.KeyHandleID() != handleID {
		t.Fatalf("NewCredential() produced an invalid or incomplete credential")
	}

	der[0] ^= 0xff
	if got := credential.PublicKeySPKIDER(); !bytes.Equal(got, original) {
		t.Fatalf("credential retained caller SPKI alias")
	}
	returned := credential.PublicKeySPKIDER()
	returned[len(returned)-1] ^= 0xff
	if got := credential.PublicKeySPKIDER(); !bytes.Equal(got, original) {
		t.Fatalf("PublicKeySPKIDER() returned mutable owned storage")
	}
}

// TestCredentialRejectsMalformedMismatchedAndOverLimitFacts proves the closed
// credential constructor rejects non-SPKI, algorithm, selector, and bound errors.
func TestCredentialRejectsMalformedMismatchedAndOverLimitFacts(t *testing.T) {
	limits := DefaultLimits()
	handleID := mustModelKeyHandleID(t, "key.example")
	rsaDER := modelPublicKeySPKI(t, AlgorithmRSASHA256)
	edDER := modelPublicKeySPKI(t, AlgorithmEd25519SHA256)
	rsaKey := modelRSAPublicKey()
	pkcs1 := x509.MarshalPKCS1PublicKey(rsaKey)
	trailing := append(slices.Clone(edDER), 0)

	tests := []struct {
		name      string
		selector  string
		algorithm Algorithm
		der       []byte
		handleID  KeyHandleID
		limits    Limits
		code      ErrorCode
	}{
		{name: "empty selector", selector: "", algorithm: AlgorithmEd25519SHA256, der: edDER, handleID: handleID, limits: limits, code: ErrorCodeInvalidRequest},
		{name: "unknown algorithm", selector: modelTestSelector, algorithm: Algorithm("unknown"), der: edDER, handleID: handleID, limits: limits, code: ErrorCodeInvalidRequest},
		{name: "zero handle", selector: modelTestSelector, algorithm: AlgorithmEd25519SHA256, der: edDER, limits: limits, code: ErrorCodeInvalidRequest},
		{name: "nil DER", selector: modelTestSelector, algorithm: AlgorithmEd25519SHA256, handleID: handleID, limits: limits, code: ErrorCodeInvalidRequest},
		{name: "malformed DER", selector: modelTestSelector, algorithm: AlgorithmEd25519SHA256, der: []byte{1, 2, 3}, handleID: handleID, limits: limits, code: ErrorCodeInvalidRequest},
		{name: "PKCS1 is not SPKI", selector: modelTestSelector, algorithm: AlgorithmRSASHA256, der: pkcs1, handleID: handleID, limits: limits, code: ErrorCodeInvalidRequest},
		{name: "trailing DER", selector: modelTestSelector, algorithm: AlgorithmEd25519SHA256, der: trailing, handleID: handleID, limits: limits, code: ErrorCodeInvalidRequest},
		{name: "RSA key with Ed algorithm", selector: modelTestSelector, algorithm: AlgorithmEd25519SHA256, der: rsaDER, handleID: handleID, limits: limits, code: ErrorCodeInvalidRequest},
		{name: "Ed key with RSA algorithm", selector: modelTestSelector, algorithm: AlgorithmRSASHA256, der: edDER, handleID: handleID, limits: limits, code: ErrorCodeInvalidRequest},
	}

	narrowed := limits
	narrowed.MaxDecodedPublicKeyBytes = len(edDER) - 1
	tests = append(tests, struct {
		name      string
		selector  string
		algorithm Algorithm
		der       []byte
		handleID  KeyHandleID
		limits    Limits
		code      ErrorCode
	}{
		name: "SPKI one over narrowed limit", selector: modelTestSelector,
		algorithm: AlgorithmEd25519SHA256, der: edDER, handleID: handleID,
		limits: narrowed, code: ErrorCodeLimitExceeded,
	})
	tests = append(tests, struct {
		name      string
		selector  string
		algorithm Algorithm
		der       []byte
		handleID  KeyHandleID
		limits    Limits
		code      ErrorCode
	}{
		name: "SPKI one over hard limit", selector: modelTestSelector,
		algorithm: AlgorithmEd25519SHA256,
		der:       bytes.Repeat([]byte{0x42}, HardLimits().MaxDecodedPublicKeyBytes+1),
		handleID:  handleID, limits: limits, code: ErrorCodeLimitExceeded,
	})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, credentialErr := NewCredential(
				test.selector, test.algorithm, test.der, test.handleID, test.limits,
			)
			if got.Valid() || ErrorCodeOf(credentialErr) != test.code {
				t.Fatalf("NewCredential(invalid) valid=%t code=%s, want %s",
					got.Valid(), ErrorCodeOf(credentialErr), test.code)
			}
		})
	}

	exact := limits
	exact.MaxDecodedPublicKeyBytes = len(edDER)
	if _, err := NewCredential(
		modelTestSelector, AlgorithmEd25519SHA256, edDER, handleID, exact,
	); err != nil {
		t.Fatalf("NewCredential(exact SPKI limit) error = %v", err)
	}
	exactSelector := limits
	exactSelector.MaxSelectorBytes = len("s1")
	if _, err := NewCredential(
		"s1", AlgorithmEd25519SHA256, edDER, handleID, exactSelector,
	); err != nil {
		t.Fatalf("NewCredential(exact selector limit) error = %v", err)
	}
	selectorOneOver := exactSelector
	selectorOneOver.MaxSelectorBytes--
	if got, err := NewCredential(
		"s1", AlgorithmEd25519SHA256, edDER, handleID, selectorOneOver,
	); got.Valid() || ErrorCodeOf(err) != ErrorCodeLimitExceeded {
		t.Fatalf("NewCredential(selector one over) valid=%t code=%s",
			got.Valid(), ErrorCodeOf(err))
	}
	oneSelectorLabel := limits
	oneSelectorLabel.MaxSelectorLabels = 1
	if got, err := NewCredential(
		"a.b", AlgorithmEd25519SHA256, edDER, handleID, oneSelectorLabel,
	); got.Valid() || ErrorCodeOf(err) != ErrorCodeLimitExceeded {
		t.Fatalf("NewCredential(selector label one over) valid=%t code=%s",
			got.Valid(), ErrorCodeOf(err))
	}
}

// TestProfileCanonicalizesCredentialsAndRejectsDuplicates proves profiles own
// complete credentials in canonical RSA-then-Ed25519 order without ambiguity.
func TestProfileCanonicalizesCredentialsAndRejectsDuplicates(t *testing.T) {
	limits := DefaultLimits()
	profileID := mustModelProfileID(t, "profile.example")
	rsaCredential := mustModelCredential(
		t, "rsa", AlgorithmRSASHA256, "key.example.rsa", limits,
	)
	edCredential := mustModelCredential(
		t, "ed", AlgorithmEd25519SHA256, "key.example.ed", limits,
	)

	profile, err := NewProfile(
		profileID, "EXAMPLE.TEST", RecordStatusActive,
		[]Credential{edCredential, rsaCredential}, time.Time{}, time.Time{}, limits,
	)
	if err != nil {
		t.Fatalf("NewProfile() error = %v", err)
	}
	credentials := profile.Credentials()
	if !profile.Valid() || profile.ID() != profileID ||
		profile.SigningDomain() != modelTestDomain ||
		profile.Status() != RecordStatusActive ||
		len(credentials) != 2 ||
		credentials[0].Algorithm() != AlgorithmRSASHA256 ||
		credentials[1].Algorithm() != AlgorithmEd25519SHA256 {
		t.Fatalf("NewProfile() did not preserve complete canonical facts")
	}
	if _, _, present := profile.ValidityWindow(); present {
		t.Fatalf("profile without validity instants exposed a window")
	}

	sameAlgorithm := mustModelCredential(
		t, "other", AlgorithmRSASHA256, "key.example.other", limits,
	)
	sameSelector := mustModelCredential(
		t, "rsa", AlgorithmEd25519SHA256, "key.example.same-selector", limits,
	)
	sameHandle := mustModelCredential(
		t, "different", AlgorithmEd25519SHA256, "key.example.rsa", limits,
	)
	tests := []struct {
		name        string
		credentials []Credential
		code        ErrorCode
	}{
		{name: "empty", credentials: nil, code: ErrorCodeInvalidRequest},
		{name: "too many", credentials: []Credential{rsaCredential, edCredential, rsaCredential}, code: ErrorCodeLimitExceeded},
		{name: "duplicate algorithm", credentials: []Credential{rsaCredential, sameAlgorithm}, code: ErrorCodeInvalidRequest},
		{name: "duplicate selector", credentials: []Credential{rsaCredential, sameSelector}, code: ErrorCodeInvalidRequest},
		{name: "duplicate handle", credentials: []Credential{rsaCredential, sameHandle}, code: ErrorCodeInvalidRequest},
		{name: "zero credential", credentials: []Credential{{}}, code: ErrorCodeInvalidRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, profileErr := NewProfile(
				profileID, modelTestDomain, RecordStatusActive,
				test.credentials, time.Time{}, time.Time{}, limits,
			)
			if got.Valid() || ErrorCodeOf(profileErr) != test.code {
				t.Fatalf("NewProfile(invalid credentials) valid=%t code=%s, want %s",
					got.Valid(), ErrorCodeOf(profileErr), test.code)
			}
		})
	}

	for _, test := range []struct {
		name   string
		id     ProfileID
		domain string
		status RecordStatus
		limits Limits
	}{
		{name: "zero ID", domain: modelTestDomain, status: RecordStatusActive, limits: limits},
		{name: "invalid domain", id: profileID, domain: ".example.test", status: RecordStatusActive, limits: limits},
		{name: "unknown status", id: profileID, domain: modelTestDomain, status: RecordStatus(255), limits: limits},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, profileErr := NewProfile(
				test.id, test.domain, test.status, []Credential{rsaCredential},
				time.Time{}, time.Time{}, test.limits,
			)
			if got.Valid() || ErrorCodeOf(profileErr) != ErrorCodeInvalidRequest {
				t.Fatalf("NewProfile(invalid facts) valid=%t code=%s",
					got.Valid(), ErrorCodeOf(profileErr))
			}
		})
	}

	oneCredential := limits
	oneCredential.MaxCredentialsPerProfile = 1
	if got, profileErr := NewProfile(
		profileID, modelTestDomain, RecordStatusActive,
		[]Credential{rsaCredential, edCredential}, time.Time{}, time.Time{},
		oneCredential,
	); got.Valid() || ErrorCodeOf(profileErr) != ErrorCodeLimitExceeded {
		t.Fatalf("NewProfile(credential one over) valid=%t code=%s",
			got.Valid(), ErrorCodeOf(profileErr))
	}
}

// TestProfileValidityUsesHalfOpenUTCWindowAndStatus proves callers supply the
// only evaluation instant and eligibility follows [not-before, not-after).
func TestProfileValidityUsesHalfOpenUTCWindowAndStatus(t *testing.T) {
	limits := DefaultLimits()
	profileID := mustModelProfileID(t, "profile.window")
	credential := mustModelCredential(
		t, modelTestSelector, AlgorithmEd25519SHA256, "key.window", limits,
	)
	notBefore := time.Date(2026, 7, 23, 10, 0, 0, 0, time.FixedZone("west", -5*60*60))
	notAfter := notBefore.Add(2 * time.Hour)

	profile, err := NewProfile(
		profileID, modelTestDomain, RecordStatusActive, []Credential{credential},
		notBefore, notAfter, limits,
	)
	if err != nil {
		t.Fatalf("NewProfile(validity window) error = %v", err)
	}
	gotBefore, gotAfter, present := profile.ValidityWindow()
	if !present || gotBefore.Location() != time.UTC || gotAfter.Location() != time.UTC ||
		!gotBefore.Equal(notBefore) || !gotAfter.Equal(notAfter) {
		t.Fatalf("ValidityWindow() = %v, %v, %t; want canonical UTC instants",
			gotBefore, gotAfter, present)
	}
	tests := []struct {
		name string
		at   time.Time
		code ErrorCode
	}{
		{name: "zero", at: time.Time{}, code: ErrorCodeInvalidRequest},
		{name: "before", at: notBefore.Add(-time.Nanosecond), code: ErrorCodeInactive},
		{name: "not-before inclusive", at: notBefore},
		{name: "inside", at: notBefore.Add(time.Hour)},
		{name: "not-after exclusive", at: notAfter, code: ErrorCodeInactive},
		{name: "after", at: notAfter.Add(time.Nanosecond), code: ErrorCodeInactive},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if activeErr := profile.ActiveAt(test.at); ErrorCodeOf(activeErr) != test.code {
				if test.code == "" && activeErr == nil {
					return
				}
				t.Fatalf("ActiveAt() code = %s, want %s", ErrorCodeOf(activeErr), test.code)
			}
		})
	}

	disabled, err := NewProfile(
		profileID, modelTestDomain, RecordStatusDisabled, []Credential{credential},
		time.Time{}, time.Time{}, limits,
	)
	if err != nil {
		t.Fatalf("NewProfile(disabled) error = %v", err)
	}
	if ErrorCodeOf(disabled.ActiveAt(notBefore)) != ErrorCodeInactive {
		t.Fatalf("disabled ActiveAt() did not fail inactive")
	}

	invalidWindows := [][2]time.Time{
		{notBefore, time.Time{}},
		{time.Time{}, notAfter},
		{notBefore, notBefore},
		{notAfter, notBefore},
	}
	for _, window := range invalidWindows {
		got, profileErr := NewProfile(
			profileID, modelTestDomain, RecordStatusActive, []Credential{credential},
			window[0], window[1], limits,
		)
		if got.Valid() || ErrorCodeOf(profileErr) != ErrorCodeInvalidRequest {
			t.Fatalf("NewProfile(invalid window) valid=%t code=%s",
				got.Valid(), ErrorCodeOf(profileErr))
		}
	}
}

// TestProfileOwnsCredentialCollections proves construction and access cannot
// mutate the profile's canonical credential or public-key state.
func TestProfileOwnsCredentialCollections(t *testing.T) {
	limits := DefaultLimits()
	profileID := mustModelProfileID(t, "profile.immutable")
	credential := mustModelCredential(
		t, modelTestSelector, AlgorithmEd25519SHA256, "key.immutable", limits,
	)
	input := []Credential{credential}
	profile, err := NewProfile(
		profileID, modelTestDomain, RecordStatusActive, input,
		time.Time{}, time.Time{}, limits,
	)
	if err != nil {
		t.Fatalf("NewProfile() error = %v", err)
	}

	input[0] = Credential{}
	first := profile.Credentials()
	first[0] = Credential{}
	if got := profile.Credentials(); len(got) != 1 || !got[0].Valid() {
		t.Fatalf("profile credentials alias caller or accessor storage")
	}
	key := firstPublicKey(profile)
	key[0] ^= 0xff
	if bytes.Equal(key, firstPublicKey(profile)) {
		t.Fatalf("nested credential public key aliases profile storage")
	}
}

// TestPolicyValidatesExactFactsAndEligibility proves administrative policy is
// complete, canonical, strict-only, and eligible only when active and enforced.
func TestPolicyValidatesExactFactsAndEligibility(t *testing.T) {
	limits := DefaultLimits()
	tenantID := mustModelTenantID(t, "tenant.example")
	profileID := mustModelProfileID(t, "profile.example")
	feedbackID := mustModelFeedbackRouteID(t, "feedback.example")

	policy, err := NewPolicy(
		tenantID, "EXAMPLE.TEST", ProfileUseOriginator, profileID,
		RecordStatusActive, RolloutEnforce, CompatibilityStrict, feedbackID, limits,
	)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	gotFeedback, present := policy.FeedbackRouteID()
	if !policy.Valid() || policy.TenantID() != tenantID ||
		policy.SigningDomain() != modelTestDomain ||
		policy.Use() != ProfileUseOriginator || policy.ProfileID() != profileID ||
		policy.Status() != RecordStatusActive || policy.Rollout() != RolloutEnforce ||
		policy.Compatibility() != CompatibilityStrict ||
		!present || gotFeedback != feedbackID {
		t.Fatalf("NewPolicy() did not preserve exact canonical facts")
	}
	if err := policy.Eligible(); err != nil {
		t.Fatalf("Eligible() error = %v", err)
	}

	withoutFeedback, err := NewPolicy(
		tenantID, modelTestDomain, ProfileUseOriginator, profileID,
		RecordStatusActive, RolloutEnforce, CompatibilityStrict, FeedbackRouteID{}, limits,
	)
	if err != nil {
		t.Fatalf("NewPolicy(no feedback) error = %v", err)
	}
	if got, exists := withoutFeedback.FeedbackRouteID(); exists || got.Valid() {
		t.Fatalf("FeedbackRouteID() = valid=%t, present=%t; want absent", got.Valid(), exists)
	}

	for _, test := range []struct {
		name    string
		status  RecordStatus
		rollout Rollout
	}{
		{name: "disabled", status: RecordStatusDisabled, rollout: RolloutEnforce},
		{name: "observe", status: RecordStatusActive, rollout: RolloutObserve},
		{name: "off", status: RecordStatusActive, rollout: RolloutOff},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, policyErr := NewPolicy(
				tenantID, modelTestDomain, ProfileUseOrdinaryTransit, profileID,
				test.status, test.rollout, CompatibilityStrict, FeedbackRouteID{}, limits,
			)
			if policyErr != nil {
				t.Fatalf("NewPolicy() error = %v", policyErr)
			}
			if ErrorCodeOf(got.Eligible()) != ErrorCodeInactive {
				t.Fatalf("Eligible() did not fail inactive")
			}
		})
	}
}

// TestPolicyRejectsUnknownOrIncompleteFacts proves no zero or open-ended
// administrative vocabulary enters an immutable policy.
func TestPolicyRejectsUnknownOrIncompleteFacts(t *testing.T) {
	limits := DefaultLimits()
	tenantID := mustModelTenantID(t, "tenant.example")
	profileID := mustModelProfileID(t, "profile.example")
	tests := []struct {
		name          string
		tenantID      TenantID
		domain        string
		use           ProfileUse
		profileID     ProfileID
		status        RecordStatus
		rollout       Rollout
		compatibility Compatibility
	}{
		{name: "zero tenant", domain: modelTestDomain, use: ProfileUseOriginator, profileID: profileID, status: RecordStatusActive, rollout: RolloutEnforce, compatibility: CompatibilityStrict},
		{name: "invalid domain", tenantID: tenantID, domain: ".example.test", use: ProfileUseOriginator, profileID: profileID, status: RecordStatusActive, rollout: RolloutEnforce, compatibility: CompatibilityStrict},
		{name: "zero use", tenantID: tenantID, domain: modelTestDomain, profileID: profileID, status: RecordStatusActive, rollout: RolloutEnforce, compatibility: CompatibilityStrict},
		{name: "zero profile", tenantID: tenantID, domain: modelTestDomain, use: ProfileUseOriginator, status: RecordStatusActive, rollout: RolloutEnforce, compatibility: CompatibilityStrict},
		{name: "unknown status", tenantID: tenantID, domain: modelTestDomain, use: ProfileUseOriginator, profileID: profileID, status: RecordStatus(255), rollout: RolloutEnforce, compatibility: CompatibilityStrict},
		{name: "unknown rollout", tenantID: tenantID, domain: modelTestDomain, use: ProfileUseOriginator, profileID: profileID, status: RecordStatusActive, rollout: Rollout(255), compatibility: CompatibilityStrict},
		{name: "non-strict compatibility", tenantID: tenantID, domain: modelTestDomain, use: ProfileUseOriginator, profileID: profileID, status: RecordStatusActive, rollout: RolloutEnforce, compatibility: Compatibility(255)},
	}
	malformedFeedback := FeedbackRouteID{identifier{value: "protected/invalid"}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NewPolicy(
				test.tenantID, test.domain, test.use, test.profileID, test.status,
				test.rollout, test.compatibility, FeedbackRouteID{}, limits,
			)
			if got.Valid() || ErrorCodeOf(err) != ErrorCodeInvalidRequest {
				t.Fatalf("NewPolicy(invalid) valid=%t code=%s", got.Valid(), ErrorCodeOf(err))
			}
		})
	}
	if got, err := NewPolicy(
		tenantID, modelTestDomain, ProfileUseOriginator, profileID,
		RecordStatusActive, RolloutEnforce, CompatibilityStrict,
		malformedFeedback, limits,
	); got.Valid() || ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("NewPolicy(malformed feedback) valid=%t code=%s",
			got.Valid(), ErrorCodeOf(err))
	}
}

// TestResolvedModelsAreCompleteSelfContainedAndGenerationBound proves results
// own one immutable profile and reject zero generations or policy mismatches.
func TestResolvedModelsAreCompleteSelfContainedAndGenerationBound(t *testing.T) {
	limits := DefaultLimits()
	profileID := mustModelProfileID(t, "profile.resolved")
	credential := mustModelCredential(
		t, modelTestSelector, AlgorithmEd25519SHA256, "key.resolved", limits,
	)
	profile, err := NewProfile(
		profileID, modelTestDomain, RecordStatusActive, []Credential{credential},
		time.Time{}, time.Time{}, limits,
	)
	if err != nil {
		t.Fatalf("NewProfile() error = %v", err)
	}
	policy, err := NewPolicy(
		mustModelTenantID(t, "tenant.resolved"), modelTestDomain,
		ProfileUseNextDomainTransit, profileID, RecordStatusActive,
		RolloutEnforce, CompatibilityStrict, FeedbackRouteID{}, limits,
	)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}

	resolvedProfile, err := NewResolvedProfile(7, profile)
	if err != nil {
		t.Fatalf("NewResolvedProfile() error = %v", err)
	}
	if !resolvedProfile.Valid() || resolvedProfile.Generation() != 7 ||
		resolvedProfile.ProfileID() != profileID ||
		!resolvedProfile.Profile().Valid() {
		t.Fatalf("NewResolvedProfile() valid=%t generation=%d ID-match=%t profile-valid=%t",
			resolvedProfile.Valid(), resolvedProfile.Generation(),
			resolvedProfile.ProfileID() == profileID, resolvedProfile.Profile().Valid())
	}
	resolvedPolicy, err := NewResolvedPolicy(7, policy, resolvedProfile)
	if err != nil {
		t.Fatalf("NewResolvedPolicy() error = %v", err)
	}
	if !resolvedPolicy.Valid() || resolvedPolicy.Generation() != 7 ||
		resolvedPolicy.Policy().ProfileID() != profileID ||
		resolvedPolicy.Profile().ID() != profileID {
		t.Fatalf("NewResolvedPolicy() produced incomplete result")
	}
	aliasProbe, err := NewResolvedProfile(7, profile)
	if err != nil {
		t.Fatalf("NewResolvedProfile(alias probe) error = %v", err)
	}
	aliasPolicy, err := NewResolvedPolicy(7, policy, aliasProbe)
	if err != nil {
		t.Fatalf("NewResolvedPolicy(alias probe) error = %v", err)
	}
	aliasProbe.profile.credentials[0] = Credential{}
	if !aliasPolicy.Valid() {
		t.Fatal("NewResolvedPolicy() retained the caller's nested profile slice")
	}

	detached := resolvedPolicy.Profile().Credentials()[0].PublicKeySPKIDER()
	detached[0] ^= 0xff
	if bytes.Equal(detached, resolvedPolicy.Profile().Credentials()[0].PublicKeySPKIDER()) {
		t.Fatalf("ResolvedPolicy.Profile() leaked mutable SPKI storage")
	}
	otherGeneration, err := NewResolvedProfile(8, profile)
	if err != nil {
		t.Fatalf("NewResolvedProfile(other generation) error = %v", err)
	}
	if got, resolveErr := NewResolvedPolicy(7, policy, otherGeneration); got.Valid() ||
		ErrorCodeOf(resolveErr) != ErrorCodeInvalidRequest {
		t.Fatalf("NewResolvedPolicy(generation mismatch) valid=%t code=%s",
			got.Valid(), ErrorCodeOf(resolveErr))
	}
	corruptedGeneration := ResolvedPolicy{
		generation: 7, policy: policy, profile: otherGeneration, complete: true,
	}
	if outcomeErr := ValidatePolicyOutcome(corruptedGeneration, nil); ErrorCodeOf(outcomeErr) != ErrorCodeInternalInvariant {
		t.Fatalf("ValidatePolicyOutcome(generation mismatch) code=%s", ErrorCodeOf(outcomeErr))
	}

	if got, resolveErr := NewResolvedProfile(0, profile); got.Valid() ||
		ErrorCodeOf(resolveErr) != ErrorCodeInvalidRequest {
		t.Fatalf("NewResolvedProfile(zero generation) valid=%t code=%s",
			got.Valid(), ErrorCodeOf(resolveErr))
	}
	if got, resolveErr := NewResolvedProfile(7, Profile{}); got.Valid() ||
		ErrorCodeOf(resolveErr) != ErrorCodeInvalidRequest {
		t.Fatalf("NewResolvedProfile(zero profile) valid=%t code=%s",
			got.Valid(), ErrorCodeOf(resolveErr))
	}
	nonNilEmptyProfile := ResolvedProfile{
		profile: Profile{credentials: []Credential{}},
	}
	if outcomeErr := ValidateProfileOutcome(
		nonNilEmptyProfile, NewError(ErrorCodeNotFound),
	); ErrorCodeOf(outcomeErr) != ErrorCodeInternalInvariant {
		t.Fatalf("ValidateProfileOutcome(non-nil empty profile) code=%s",
			ErrorCodeOf(outcomeErr))
	}

	otherID := mustModelProfileID(t, "profile.other")
	mismatchedID, err := NewPolicy(
		mustModelTenantID(t, "tenant.other"), modelTestDomain,
		ProfileUseOriginator, otherID, RecordStatusActive,
		RolloutEnforce, CompatibilityStrict, FeedbackRouteID{}, limits,
	)
	if err != nil {
		t.Fatalf("NewPolicy(mismatched ID) error = %v", err)
	}
	mismatchedDomain, err := NewPolicy(
		mustModelTenantID(t, "tenant.domain"), "other.test",
		ProfileUseOriginator, profileID, RecordStatusActive,
		RolloutEnforce, CompatibilityStrict, FeedbackRouteID{}, limits,
	)
	if err != nil {
		t.Fatalf("NewPolicy(mismatched domain) error = %v", err)
	}
	assertModelResolvedPolicyRejectsMismatch(
		t, 7, resolvedProfile, mismatchedID, mismatchedDomain,
	)
}

// assertModelResolvedPolicyRejectsMismatch verifies exact policy/profile binding failures.
func assertModelResolvedPolicyRejectsMismatch(
	t *testing.T,
	generation uint64,
	profile ResolvedProfile,
	policies ...Policy,
) {
	t.Helper()
	for _, policy := range policies {
		got, resolveErr := NewResolvedPolicy(generation, policy, profile)
		if got.Valid() || ErrorCodeOf(resolveErr) != ErrorCodeInvalidRequest {
			t.Fatalf("NewResolvedPolicy(mismatch) valid=%t code=%s",
				got.Valid(), ErrorCodeOf(resolveErr))
		}
	}
}

// TestDatasourceModelsKeepFormattingAndJSONSecretSafe proves crossing-boundary
// representations contain no raw identifiers, domains, selectors, or SPKI.
func TestDatasourceModelsKeepFormattingAndJSONSecretSafe(t *testing.T) {
	const marker = "model-private-marker"
	limits := DefaultLimits()
	profileID := mustModelProfileID(t, "profile."+marker)
	credential := mustModelCredential(
		t, marker, AlgorithmEd25519SHA256, "key."+marker, limits,
	)
	profile, err := NewProfile(
		profileID, marker+".test", RecordStatusActive, []Credential{credential},
		time.Time{}, time.Time{}, limits,
	)
	if err != nil {
		t.Fatalf("NewProfile() error = %v", err)
	}
	policy, err := NewPolicy(
		mustModelTenantID(t, "tenant."+marker), marker+".test",
		ProfileUseOriginator, profileID, RecordStatusActive, RolloutEnforce,
		CompatibilityStrict, mustModelFeedbackRouteID(t, "feedback."+marker), limits,
	)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	resolvedProfile, err := NewResolvedProfile(1, profile)
	if err != nil {
		t.Fatalf("NewResolvedProfile() error = %v", err)
	}
	resolvedPolicy, err := NewResolvedPolicy(1, policy, resolvedProfile)
	if err != nil {
		t.Fatalf("NewResolvedPolicy() error = %v", err)
	}

	spkiMarker := base64.StdEncoding.EncodeToString(credential.PublicKeySPKIDER())
	values := []any{credential, profile, policy, resolvedProfile, resolvedPolicy}
	for _, value := range values {
		for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
			rendered := fmt.Sprintf(format, value)
			if strings.Contains(rendered, marker) || strings.Contains(rendered, spkiMarker) {
				t.Fatalf("format %q exposed protected model facts", format)
			}
		}
		encoded, marshalErr := json.Marshal(value)
		if strings.Contains(string(encoded), marker) ||
			strings.Contains(string(encoded), spkiMarker) ||
			strings.Contains(fmt.Sprint(marshalErr), marker) {
			t.Fatalf("json.Marshal(%T) exposed protected model facts", value)
		}
	}
}

// mustModelProfileID constructs one validated profile fixture.
func mustModelProfileID(t *testing.T, value string) ProfileID {
	t.Helper()
	id, err := NewProfileID(value)
	if err != nil {
		t.Fatalf("NewProfileID() error = %v", err)
	}
	return id
}

// mustModelKeyHandleID constructs one validated handle fixture.
func mustModelKeyHandleID(t *testing.T, value string) KeyHandleID {
	t.Helper()
	id, err := NewKeyHandleID(value)
	if err != nil {
		t.Fatalf("NewKeyHandleID() error = %v", err)
	}
	return id
}

// mustModelTenantID constructs one validated tenant fixture.
func mustModelTenantID(t *testing.T, value string) TenantID {
	t.Helper()
	id, err := NewTenantID(value)
	if err != nil {
		t.Fatalf("NewTenantID() error = %v", err)
	}
	return id
}

// mustModelFeedbackRouteID constructs one validated feedback-route fixture.
func mustModelFeedbackRouteID(t *testing.T, value string) FeedbackRouteID {
	t.Helper()
	id, err := NewFeedbackRouteID(value)
	if err != nil {
		t.Fatalf("NewFeedbackRouteID() error = %v", err)
	}
	return id
}

// mustModelCredential constructs one valid detached credential fixture.
func mustModelCredential(
	t *testing.T,
	selector string,
	algorithm Algorithm,
	handleValue string,
	limits Limits,
) Credential {
	t.Helper()
	credential, err := NewCredential(
		selector, algorithm, modelPublicKeySPKI(t, algorithm),
		mustModelKeyHandleID(t, handleValue), limits,
	)
	if err != nil {
		t.Fatalf("NewCredential() error = %v", err)
	}
	return credential
}

// modelPublicKeySPKI returns deterministic valid public SPKI DER for one algorithm.
func modelPublicKeySPKI(t *testing.T, algorithm Algorithm) []byte {
	t.Helper()
	var publicKey any
	switch algorithm {
	case AlgorithmRSASHA256:
		publicKey = modelRSAPublicKey()
	case AlgorithmEd25519SHA256:
		publicKey = ed25519.PublicKey(bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize))
	default:
		t.Fatalf("unsupported fixture algorithm")
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	return der
}

// modelRSAPublicKey returns deterministic structurally valid 2048-bit RSA material.
func modelRSAPublicKey() *rsa.PublicKey {
	modulus := new(big.Int).Lsh(big.NewInt(1), 2047)
	modulus.Add(modulus, big.NewInt(0x31))
	return &rsa.PublicKey{N: modulus, E: 65537}
}

// firstPublicKey returns one detached profile credential key for alias tests.
func firstPublicKey(profile Profile) []byte {
	return profile.Credentials()[0].PublicKeySPKIDER()
}
