package verify

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
)

// TestVerifierAppliesDraft07TimestampWindows reproduces the fixed Draft-07
// Section 14.3 windows: at most 14 days old and at most one day in the future,
// with exact boundaries accepted and one second beyond rejected.
func TestVerifierAppliesDraft07TimestampWindows(t *testing.T) {
	now := time.Unix(int64(testTimestampSeconds), 0).Add(time.Hour)

	tests := []struct {
		name            string
		timestamp       uint64
		wantStatus      TargetStatus
		wantTimestamp   TimestampStatus
		wantCheckStatus CheckStatus
	}{
		{"recent signature", testTimestampSeconds, TargetStatusPass, TimestampStatusPass, CheckStatusPass},
		{"exact fourteen day boundary", uint64(now.Add(-14 * 24 * time.Hour).Unix()), TargetStatusPass, TimestampStatusPass, CheckStatusPass},
		{"one second beyond fourteen days", uint64(now.Add(-14*24*time.Hour - time.Second).Unix()), TargetStatusFail, TimestampStatusExpired, CheckStatusFail},
		{"exact one day future boundary", uint64(now.Add(24 * time.Hour).Unix()), TargetStatusPass, TimestampStatusPass, CheckStatusPass},
		{"one second beyond one day future", uint64(now.Add(24*time.Hour + time.Second).Unix()), TargetStatusFail, TimestampStatusFuture, CheckStatusFail},
		{"ten minutes future is accepted", uint64(now.Add(10 * time.Minute).Unix()), TargetStatusPass, TimestampStatusPass, CheckStatusPass},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newRSAVerificationFixtureAt(t, tt.timestamp)
			verifier := mustVerifierForFixtureWithOptions(t, fixture, WithClock(func() time.Time {
				return now
			}))

			result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if result.Status() != tt.wantStatus {
				t.Fatalf("Status() = %q, want %q; checks=%#v", result.Status(), tt.wantStatus, result.Checks())
			}
			if !hasTimestampCheck(result, tt.wantTimestamp, tt.wantCheckStatus) {
				t.Fatalf("timestamp check = %#v, want %s/%s", result.Checks(), tt.wantTimestamp, tt.wantCheckStatus)
			}
		})
	}
}

// TestVerifierRejectsTimestampOverflow verifies unrepresentable t= values fail closed.
func TestVerifierRejectsTimestampOverflow(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	overflow := fixture.withRaw(strings.Replace(fixture.raw, "t=1700000000", "t=9223372036854775808", 1))
	verifier := mustVerifierForFixture(t, fixture)

	result, err := verifier.Verify(context.Background(), Request{Message: overflow.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Status() != TargetStatusFail || !hasTimestampCheck(result, TimestampStatusInvalid, CheckStatusFail) {
		t.Fatalf("result = %#v checks=%#v, want invalid timestamp failure", result, result.Checks())
	}
}

// mustVerifierForFixtureWithOptions builds a fixture verifier with local policy options.
func mustVerifierForFixtureWithOptions(t *testing.T, fixture verificationFixture, options ...Option) Verifier {
	t.Helper()

	var key StaticKey
	switch fixture.algorithm {
	case AlgorithmRSASHA256:
		key = StaticKey{
			Domain:    testDomain,
			Selector:  testSelector,
			Algorithm: AlgorithmRSASHA256,
			Material:  fixture.rsaPublicKey,
		}
	case AlgorithmEd25519SHA256:
		key = StaticKey{
			Domain:    testDomain,
			Selector:  testSelector,
			Algorithm: AlgorithmEd25519SHA256,
			Material:  fixture.ed25519PublicKey,
		}
	default:
		t.Fatalf("unsupported fixture algorithm %q", fixture.algorithm)
	}

	provider, err := NewStaticKeyProvider([]StaticKey{key})
	if err != nil {
		t.Fatalf("NewStaticKeyProvider() error = %v", err)
	}
	resolvedOptions := append([]Option{testClockOption()}, options...)
	verifier, err := NewVerifier(provider, resolvedOptions...)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	return verifier
}

// hasTimestampCheck reports whether result has one timestamp fact.
func hasTimestampCheck(result Result, status TimestampStatus, checkStatus CheckStatus) bool {
	for _, check := range result.Checks() {
		if check.Kind == CheckKindTimestamp && check.TimestampStatus == status && check.Status == checkStatus {
			return true
		}
	}

	return false
}

// TestRequestReferenceTimeReplacesClock verifies that a non-zero
// Request.ReferenceTime evaluates the Section 10.4 window at that instant
// instead of the injected clock, while the zero value keeps the clock.
func TestRequestReferenceTimeReplacesClock(t *testing.T) {
	signed := time.Unix(int64(testTimestampSeconds), 0)
	wallClock := signed.Add(30 * 24 * time.Hour)
	fixture := newRSAVerificationFixtureAt(t, testTimestampSeconds)
	verifier := mustVerifierForFixtureWithOptions(t, fixture, WithClock(func() time.Time { return wallClock }))
	for _, tt := range []struct {
		name          string
		reference     time.Time
		wantStatus    TargetStatus
		wantTimestamp TimestampStatus
	}{
		{name: "zero reference keeps the clock", wantStatus: TargetStatusFail, wantTimestamp: TimestampStatusExpired},
		{name: "reference one day after signing passes", reference: signed.Add(24 * time.Hour), wantStatus: TargetStatusPass, wantTimestamp: TimestampStatusPass},
		{name: "reference beyond one day before signing is future", reference: signed.Add(-25 * time.Hour), wantStatus: TargetStatusFail, wantTimestamp: TimestampStatusFuture},
		{name: "reference beyond max age is expired", reference: signed.Add(15 * 24 * time.Hour), wantStatus: TargetStatusFail, wantTimestamp: TimestampStatusExpired},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope(), ReferenceTime: tt.reference})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if result.Status() != tt.wantStatus || !hasTimestampCheck(result, tt.wantTimestamp, checkStatusForTarget(tt.wantStatus)) {
				t.Fatalf("Status() = %q checks=%#v, want %q/%q", result.Status(), result.Checks(), tt.wantStatus, tt.wantTimestamp)
			}
		})
	}
}

// checkStatusForTarget maps the expected target status to the timestamp check status.
func checkStatusForTarget(status TargetStatus) CheckStatus {
	if status == TargetStatusPass {
		return CheckStatusPass
	}
	return CheckStatusFail
}

// TestVerifierChecksTimestampsOfEverySignature reproduces Draft-07 Section
// 14.3: any signature outside the windows makes the message invalid, not only
// the selected highest signature. The failure is attributed to the offending
// i=.
func TestVerifierChecksTimestampsOfEverySignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	headerDigest, bodyDigest := baseMessageDigests(t)
	placeholder := testSelector + ":" + string(AlgorithmRSASHA256) + ":" + base64.StdEncoding.EncodeToString(bytesOf(0xa5, 128))
	expired := strconv.FormatUint(testTimestampSeconds-15*24*3600, 10)
	firstField := func(sets string) string {
		return strings.Replace(signatureField(1, sets), "t="+strconv.FormatUint(testTimestampSeconds, 10), "t="+expired, 1)
	}
	secondField := func(sets string) string {
		return strings.Replace(signatureField(2, sets), "mf=PD4=", "mf=PHNlbmRlckBleGFtcGxlLnRlc3Q+", 1)
	}
	sign := func(message rawmsg.Message, sequence uint64) string {
		signatureBytes, signErr := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, signatureDigestForTarget(t, message, sequence))
		if signErr != nil {
			t.Fatalf("rsa.SignPKCS1v15() error = %v", signErr)
		}
		return testSelector + ":" + string(AlgorithmRSASHA256) + ":" + base64.StdEncoding.EncodeToString(signatureBytes)
	}
	firstSet := sign(mustParseVerificationMessage(t, rawWithSignatureFields(headerDigest, bodyDigest, []string{firstField(placeholder)})), 1)
	secondSet := sign(mustParseVerificationMessage(t, rawWithSignatureFields(headerDigest, bodyDigest, []string{firstField(firstSet), secondField(placeholder)})), 2)
	fixture, err := parseVerificationFixture(rawWithSignatureFields(headerDigest, bodyDigest, []string{firstField(firstSet), secondField(secondSet)}))
	if err != nil {
		t.Fatalf("parseVerificationFixture() error = %v", err)
	}
	verifier := mustVerifierWithKeys(t, []StaticKey{{Domain: testDomain, Selector: testSelector, Algorithm: AlgorithmRSASHA256, Material: &key.PublicKey}})
	result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: sequentialCurrentEnvelope()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Status() != TargetStatusFail || result.Target().Sequence != 2 {
		t.Fatalf("Status()/Target() = %q/%#v, want fail on target 2", result.Status(), result.Target())
	}
	for _, check := range result.Checks() {
		if check.Kind == CheckKindTimestamp {
			if check.Status != CheckStatusFail || check.TimestampStatus != TimestampStatusExpired || check.Target.Sequence != 1 {
				t.Fatalf("timestamp check = %#v, want expired attributed to i=1", check)
			}
			return
		}
	}
	t.Fatal("missing timestamp check")
}

// TestCheckTimestampsFailsClosedOnUnorderedChain proves that a chain whose
// sequence order cannot be established never yields a timestamp PASS, even
// when every individual timestamp is in range.
func TestCheckTimestampsFailsClosedOnUnorderedChain(t *testing.T) {
	verifier, err := NewVerifier(providerFunc(func(context.Context, KeyQuery) (PublicKey, error) {
		return PublicKey{}, nil
	}), testClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	duplicate := fromTestSignature(t, 1, 1, "example.test")
	evaluation := verifier.checkTimestamps(Request{}, []signature.Signature{duplicate, duplicate}, Target{Sequence: 1, InstanceNumber: 1})
	if evaluation.pass || evaluation.check.TimestampStatus != TimestampStatusInvalid {
		t.Fatalf("unordered chain timestamp pass=%t status=%q", evaluation.pass, evaluation.check.TimestampStatus)
	}
}
