package verify

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestVerifierAppliesTimestampPolicy verifies deterministic future, age, and disabled-age behavior.
func TestVerifierAppliesTimestampPolicy(t *testing.T) {
	now := time.Unix(int64(testTimestampSeconds), 0).Add(time.Hour)

	tests := []struct {
		name            string
		timestamp       uint64
		policy          TimestampPolicy
		wantStatus      TargetStatus
		wantTimestamp   TimestampStatus
		wantCheckStatus CheckStatus
	}{
		{
			name:            "default max age accepts recent signature",
			timestamp:       testTimestampSeconds,
			policy:          DefaultTimestampPolicy(),
			wantStatus:      TargetStatusPass,
			wantTimestamp:   TimestampStatusPass,
			wantCheckStatus: CheckStatusPass,
		},
		{
			name:            "default max age accepts exact fourteen day boundary",
			timestamp:       uint64(now.Add(-14 * 24 * time.Hour).Unix()),
			policy:          DefaultTimestampPolicy(),
			wantStatus:      TargetStatusPass,
			wantTimestamp:   TimestampStatusPass,
			wantCheckStatus: CheckStatusPass,
		},
		{
			name:            "default max age rejects one second beyond fourteen days",
			timestamp:       uint64(now.Add(-14*24*time.Hour - time.Second).Unix()),
			policy:          DefaultTimestampPolicy(),
			wantStatus:      TargetStatusFail,
			wantTimestamp:   TimestampStatusExpired,
			wantCheckStatus: CheckStatusFail,
		},
		{
			name:      "configured max age pass",
			timestamp: uint64(now.Add(-30 * time.Minute).Unix()),
			policy: TimestampPolicy{
				FutureTolerance: 5 * time.Minute,
				MaxAge:          time.Hour,
			},
			wantStatus:      TargetStatusPass,
			wantTimestamp:   TimestampStatusPass,
			wantCheckStatus: CheckStatusPass,
		},
		{
			name:      "future beyond tolerance",
			timestamp: uint64(now.Add(10 * time.Minute).Unix()),
			policy: TimestampPolicy{
				FutureTolerance: 5 * time.Minute,
				MaxAge:          time.Hour,
			},
			wantStatus:      TargetStatusFail,
			wantTimestamp:   TimestampStatusFuture,
			wantCheckStatus: CheckStatusFail,
		},
		{
			name:      "expired max age",
			timestamp: uint64(now.Add(-2 * time.Hour).Unix()),
			policy: TimestampPolicy{
				FutureTolerance: 5 * time.Minute,
				MaxAge:          time.Hour,
			},
			wantStatus:      TargetStatusFail,
			wantTimestamp:   TimestampStatusExpired,
			wantCheckStatus: CheckStatusFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newRSAVerificationFixtureAt(t, tt.timestamp)
			verifier := mustVerifierForFixtureWithOptions(t, fixture, WithClock(func() time.Time {
				return now
			}), WithTimestampPolicy(tt.policy))

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
