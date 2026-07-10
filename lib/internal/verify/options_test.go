package verify

import (
	"context"
	"testing"
	"time"
)

type testKeyProvider struct{}

// LookupKey returns an empty key for constructor-focused tests.
func (testKeyProvider) LookupKey(context.Context, KeyQuery) (PublicKey, error) {
	return PublicKey{}, nil
}

// TestDefaultAlgorithmPolicyMatchesM4Contract verifies the M4 verifier defaults.
func TestDefaultAlgorithmPolicyMatchesM4Contract(t *testing.T) {
	policy := DefaultAlgorithmPolicy()
	algorithms := policy.Algorithms()
	if len(algorithms) != 2 {
		t.Fatalf("default algorithm count = %d, want 2", len(algorithms))
	}
	if algorithms[0] != AlgorithmRSASHA256 || algorithms[1] != AlgorithmEd25519SHA256 {
		t.Fatalf("default algorithms = %#v, want rsa-sha256 and ed25519-sha256", algorithms)
	}
	if policy.MinRSABits != 1024 {
		t.Fatalf("MinRSABits = %d, want 1024", policy.MinRSABits)
	}
	if !policy.Allows(AlgorithmRSASHA256) || !policy.Allows(AlgorithmEd25519SHA256) {
		t.Fatal("default algorithm policy does not allow both M4 algorithms")
	}
	if policy.Allows("sha512") {
		t.Fatal("default algorithm policy allowed unsupported algorithm")
	}
}

// TestNewVerifierRejectsUnsafeOptions verifies fail-closed construction validation.
func TestNewVerifierRejectsUnsafeOptions(t *testing.T) {
	if _, err := NewVerifier(nil); !IsErrorCode(err, ErrorCodeInvalidOptions) {
		t.Fatalf("NewVerifier(nil) error = %v, want invalid options", err)
	}

	tests := []struct {
		name   string
		option Option
		code   ErrorCode
	}{
		{
			name:   "nil clock",
			option: WithClock(nil),
			code:   ErrorCodeInvalidOptions,
		},
		{
			name: "rsa minimum below contract",
			option: WithAlgorithmPolicy(AlgorithmPolicy{
				AllowedAlgorithms: []Algorithm{AlgorithmRSASHA256},
				MinRSABits:        512,
			}),
			code: ErrorCodeInvalidOptions,
		},
		{
			name: "unknown enabled algorithm",
			option: WithAlgorithmPolicy(AlgorithmPolicy{
				AllowedAlgorithms: []Algorithm{"sha512"},
				MinRSABits:        1024,
			}),
			code: ErrorCodeUnsupportedAlgorithm,
		},
		{
			name: "negative future tolerance",
			option: WithTimestampPolicy(TimestampPolicy{
				FutureTolerance: -time.Second,
			}),
			code: ErrorCodeInvalidOptions,
		},
		{
			name: "negative max age",
			option: WithTimestampPolicy(TimestampPolicy{
				MaxAge: -time.Second,
			}),
			code: ErrorCodeInvalidOptions,
		},
		{
			name: "zero signature set limit",
			option: WithLimits(Limits{
				MaxEnvelopeRecipients: 1,
			}),
			code: ErrorCodeInvalidOptions,
		},
		{
			name: "zero recipient limit",
			option: WithLimits(Limits{
				MaxSignatureSets: 1,
			}),
			code: ErrorCodeInvalidOptions,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewVerifier(testKeyProvider{}, tt.option)
			if !IsErrorCode(err, tt.code) {
				t.Fatalf("NewVerifier() error = %v, want %s", err, tt.code)
			}
		})
	}
}

// TestNewVerifierUsesValidatedDefaults verifies constructor success and option copying.
func TestNewVerifierUsesValidatedDefaults(t *testing.T) {
	fixedNow := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	verifier, err := NewVerifier(testKeyProvider{}, WithClock(func() time.Time {
		return fixedNow
	}))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	options := verifier.Options()
	if got := options.Clock.Now(); !got.Equal(fixedNow) {
		t.Fatalf("Clock.Now() = %s, want fixed time", got)
	}
	if options.TimestampPolicy.FutureTolerance != 5*time.Minute {
		t.Fatalf("FutureTolerance = %s, want 5m", options.TimestampPolicy.FutureTolerance)
	}
	if options.TimestampPolicy.MaxAge != 14*24*time.Hour {
		t.Fatalf("MaxAge = %s, want 14 days", options.TimestampPolicy.MaxAge)
	}

	algorithms := options.AlgorithmPolicy.Algorithms()
	algorithms[0] = "mutated"
	if got := verifier.Options().AlgorithmPolicy.Algorithms()[0]; got != AlgorithmRSASHA256 {
		t.Fatalf("verifier options were mutated through accessor: %q", got)
	}
	if verifier.KeyProvider() == nil {
		t.Fatal("KeyProvider() returned nil for injected provider")
	}
}
