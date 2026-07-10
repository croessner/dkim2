package verify

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestVerifierHandlesManySignatureSetsAtLimit verifies exact and over-limit evaluation within one legal header line.
func TestVerifierHandlesManySignatureSetsAtLimit(t *testing.T) {
	const testSignatureSetLimit = 8

	fixture := newDeterministicRSAVerificationFixture(t)
	verifier := mustVerifierForFixtureWithOptions(t, fixture, WithLimits(Limits{
		MaxSignatureSets:      testSignatureSetLimit,
		MaxEnvelopeRecipients: defaultMaxEnvelopeRecipients,
	}))

	atLimit, err := fixture.withSignatureSetResult(uniqueUnsupportedSignatureSetList(testSignatureSetLimit, "AA=="))
	if err != nil {
		t.Fatalf("at-limit fixture parse error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), Request{Message: atLimit.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Status() != TargetStatusUnsupported {
		t.Fatalf("Status() = %q, want unsupported", result.Status())
	}
	if got := len(result.SignatureSets()); got != testSignatureSetLimit {
		t.Fatalf("SignatureSets() length = %d, want %d", got, testSignatureSetLimit)
	}
	if hasCheckCode(result, CheckKindSignature, CheckStatusFail, ErrorCodeLimitExceeded, "", "") {
		t.Fatalf("checks = %#v, did not expect limit failure at parser limit", result.Checks())
	}

	overLimit, err := fixture.withSignatureSetResult(uniqueUnsupportedSignatureSetList(testSignatureSetLimit+1, "AA=="))
	if err != nil {
		t.Fatalf("over-limit fixture parse error = %v", err)
	}
	result, err = verifier.Verify(context.Background(), Request{Message: overLimit.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("Verify() over limit error = %v", err)
	}
	if result.Status() != TargetStatusFail || !hasCheckCode(result, CheckKindSignature, CheckStatusFail, ErrorCodeLimitExceeded, "", "") {
		t.Fatalf("result = %q checks=%#v, want typed verifier limit failure", result.Status(), result.Checks())
	}
}

// TestVerifierPerformsRepeatedMissingKeyLookups verifies every checkable missing key is classified.
func TestVerifierPerformsRepeatedMissingKeyLookups(t *testing.T) {
	fixture := newDeterministicRSAVerificationFixture(t)
	provider := &countingMissingProvider{}
	verifier, err := NewVerifier(provider, testClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	var result Result
	for i := 0; i < defaultMaxSignatureSets; i++ {
		result, err = verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
		if err != nil {
			t.Fatalf("Verify() iteration %d error = %v", i, err)
		}
	}
	if provider.count != defaultMaxSignatureSets {
		t.Fatalf("provider lookups = %d, want %d", provider.count, defaultMaxSignatureSets)
	}
	for _, set := range result.SignatureSets() {
		if set.Status != SignatureSetStatusMissingKey || set.KeyStatus != KeyStatusMissing {
			t.Fatalf("signature set = %#v, want missing key", set)
		}
	}
}

// TestStaticKeyProviderRejectsMalformedLookupTuples verifies unsafe tuple tokens fail closed.
func TestStaticKeyProviderRejectsMalformedLookupTuples(t *testing.T) {
	marker := "path/nonce/signature/key"
	_, err := NewStaticKeyProvider([]StaticKey{{
		Domain:    "example.test/" + marker,
		Selector:  testSelector,
		Algorithm: AlgorithmEd25519SHA256,
		Material:  deterministicEd25519PublicKey("tuple abuse"),
	}})
	if !IsErrorCode(err, ErrorCodeInvalidKey) {
		t.Fatalf("NewStaticKeyProvider() error = %v, want invalid key", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("Error() leaked tuple marker in %q", err.Error())
	}
}

// TestVerifierTimestampBoundaries verifies exact future and age boundaries are accepted.
func TestVerifierTimestampBoundaries(t *testing.T) {
	now := time.Unix(int64(testTimestampSeconds), 0)
	policy := TimestampPolicy{FutureTolerance: 5 * time.Minute, MaxAge: time.Hour}

	tests := []struct {
		name      string
		timestamp uint64
	}{
		{name: "exact future tolerance", timestamp: uint64(now.Add(policy.FutureTolerance).Unix())},
		{name: "exact max age", timestamp: uint64(now.Add(-policy.MaxAge).Unix())},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newRSAVerificationFixtureAt(t, tt.timestamp)
			verifier := mustVerifierForFixtureWithOptions(t, fixture, WithClock(func() time.Time { return now }), WithTimestampPolicy(policy))

			result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if result.Status() != TargetStatusPass || !hasTimestampCheck(result, TimestampStatusPass, CheckStatusPass) {
				t.Fatalf("result = %#v checks=%#v, want timestamp boundary pass", result, result.Checks())
			}
		})
	}
}

// TestVerifierBoundsEnvelopeRequestShape verifies oversized current envelopes fail closed.
func TestVerifierBoundsEnvelopeRequestShape(t *testing.T) {
	fixture := newDeterministicRSAVerificationFixture(t)
	verifier := mustVerifierForFixtureWithOptions(t, fixture, WithLimits(Limits{
		MaxSignatureSets:      defaultMaxSignatureSets,
		MaxEnvelopeRecipients: 1,
	}))

	result, err := verifier.Verify(context.Background(), Request{
		Message: fixture.message,
		Envelope: NewEnvelope([]byte("<>"), [][]byte{
			[]byte("<one@example.test>"),
			[]byte("<two@example.test>"),
		}),
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Status() != TargetStatusFail || !hasCheckCode(result, CheckKindEnvelope, CheckStatusFail, ErrorCodeLimitExceeded, EnvelopeStatusInvalid, "") {
		t.Fatalf("result = %#v checks=%#v, want envelope limit failure", result, result.Checks())
	}
}

type countingMissingProvider struct {
	count int
}

// LookupKey records one lookup and returns a bounded missing-key result.
func (p *countingMissingProvider) LookupKey(_ context.Context, query KeyQuery) (PublicKey, error) {
	p.count++

	return publicKeyResult(query.Algorithm, nil, KeyStatusMissing), missingKeyError(query.Algorithm)
}

// uniqueUnsupportedSignatureSetList renders distinct unsupported algorithms up to parser limits.
func uniqueUnsupportedSignatureSetList(count int, signatureText string) string {
	sets := make([]string, count)
	for i := range sets {
		sets[i] = fmt.Sprintf("selector%02d.test:future-sha%03d:%s", i, i, signatureText)
	}

	return strings.Join(sets, ",")
}
