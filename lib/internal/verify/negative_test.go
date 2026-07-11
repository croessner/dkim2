package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"strings"
	"testing"
	"time"
)

type negativeVectorWant struct {
	targetStatus    TargetStatus
	checkKind       CheckKind
	checkStatus     CheckStatus
	checkCode       ErrorCode
	signatureStatus SignatureSetStatus
	envelopeStatus  EnvelopeStatus
	timestampStatus TimestampStatus
	algorithm       Algorithm
}

// TestVerifierNegativeVectors verifies fail-closed static-key vector outcomes.
func TestVerifierNegativeVectors(t *testing.T) {
	now := time.Unix(int64(testTimestampSeconds), 0)

	tests := []struct {
		name string
		run  func(*testing.T) (Result, error)
		want negativeVectorWant
	}{
		{
			name: "body hash mismatch",
			run: func(t *testing.T) (Result, error) {
				fixture := newDeterministicRSAVerificationFixture(t)
				changed := fixture.withRaw(strings.Replace(fixture.raw, "body line\r\n", "changed body\r\n", 1))

				return mustVerifierForFixture(t, fixture).Verify(context.Background(), Request{Message: changed.message, Envelope: matchingEnvelope()})
			},
			want: negativeVectorWant{targetStatus: TargetStatusFail, checkKind: CheckKindBodyHash, checkStatus: CheckStatusFail, checkCode: ErrorCodeHashMismatch},
		},
		{
			name: "header hash mismatch",
			run: func(t *testing.T) (Result, error) {
				fixture := newDeterministicEd25519VerificationFixture(t)
				changed := fixture.withRaw(strings.Replace(fixture.raw, "Subject: Static verification\r\n", "Subject: Changed verification\r\n", 1))

				return mustVerifierForFixture(t, fixture).Verify(context.Background(), Request{Message: changed.message, Envelope: matchingEnvelope()})
			},
			want: negativeVectorWant{targetStatus: TargetStatusFail, checkKind: CheckKindHeaderHash, checkStatus: CheckStatusFail, checkCode: ErrorCodeHashMismatch},
		},
		{
			name: "wrong rsa key",
			run: func(t *testing.T) (Result, error) {
				fixture := newDeterministicRSAVerificationFixture(t)
				wrongKey := newDeterministicRSAKey(t, "wrong rsa key")
				verifier := mustVerifierWithKeys(t, []StaticKey{{Domain: testDomain, Selector: testSelector, Algorithm: AlgorithmRSASHA256, Material: &wrongKey.PublicKey}})

				return verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
			},
			want: negativeVectorWant{targetStatus: TargetStatusFail, signatureStatus: SignatureSetStatusFail, algorithm: AlgorithmRSASHA256},
		},
		{
			name: "wrong ed25519 key",
			run: func(t *testing.T) (Result, error) {
				fixture := newDeterministicEd25519VerificationFixture(t)
				verifier := mustVerifierWithKeys(t, []StaticKey{{Domain: testDomain, Selector: testSelector, Algorithm: AlgorithmEd25519SHA256, Material: deterministicEd25519PublicKey("wrong ed25519 key")}})

				return verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
			},
			want: negativeVectorWant{targetStatus: TargetStatusFail, signatureStatus: SignatureSetStatusFail, algorithm: AlgorithmEd25519SHA256},
		},
		{
			name: "missing key",
			run: func(t *testing.T) (Result, error) {
				fixture := newDeterministicRSAVerificationFixture(t)

				return mustVerifierWithKeys(t, nil).Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
			},
			want: negativeVectorWant{targetStatus: TargetStatusUnsupported, signatureStatus: SignatureSetStatusMissingKey, algorithm: AlgorithmRSASHA256},
		},
		{
			name: "unsupported algorithm",
			run: func(t *testing.T) (Result, error) {
				fixture := newDeterministicRSAVerificationFixture(t)
				unsupported := fixture.withSignatureSet(testSelector + ":future-sha998:" + fixture.signatureBase64)

				return mustVerifierWithKeys(t, nil).Verify(context.Background(), Request{Message: unsupported.message, Envelope: matchingEnvelope()})
			},
			want: negativeVectorWant{targetStatus: TargetStatusUnsupported, signatureStatus: SignatureSetStatusUnsupportedAlgorithm, algorithm: AlgorithmUnknown},
		},
		{
			name: "malformed signature bytes",
			run: func(t *testing.T) (Result, error) {
				fixture := newDeterministicRSAVerificationFixture(t)
				changed := fixture.withSignatureBytes([]byte{0x01})

				return mustVerifierForFixture(t, fixture).Verify(context.Background(), Request{Message: changed.message, Envelope: matchingEnvelope()})
			},
			want: negativeVectorWant{targetStatus: TargetStatusFail, signatureStatus: SignatureSetStatusFail, algorithm: AlgorithmRSASHA256},
		},
		{
			name: "too small rsa key",
			run: func(t *testing.T) (Result, error) {
				fixture := newDeterministicRSAVerificationFixture(t)
				verifier, err := NewVerifier(providerFunc(func(context.Context, KeyQuery) (PublicKey, error) {
					return PublicKey{Algorithm: AlgorithmRSASHA256, Material: tinyRSAPublicKey(), Metadata: KeyMetadata{Status: KeyStatusFound}}, nil
				}), testClockOption())
				if err != nil {
					t.Fatalf("NewVerifier() error = %v", err)
				}

				return verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
			},
			want: negativeVectorWant{targetStatus: TargetStatusFail, signatureStatus: SignatureSetStatusKeyPolicyRejected, algorithm: AlgorithmRSASHA256},
		},
		{
			name: "stale timestamp",
			run: func(t *testing.T) (Result, error) {
				fixture := newRSAVerificationFixtureAt(t, uint64(now.Add(-2*time.Hour).Unix()))
				verifier := mustVerifierForFixtureWithOptions(t, fixture, WithClock(func() time.Time { return now }), WithTimestampPolicy(TimestampPolicy{FutureTolerance: 5 * time.Minute, MaxAge: time.Hour}))

				return verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
			},
			want: negativeVectorWant{targetStatus: TargetStatusFail, checkKind: CheckKindTimestamp, checkStatus: CheckStatusFail, checkCode: ErrorCodeTimestampInvalid, timestampStatus: TimestampStatusExpired},
		},
		{
			name: "future timestamp",
			run: func(t *testing.T) (Result, error) {
				fixture := newRSAVerificationFixtureAt(t, uint64(now.Add(10*time.Minute).Unix()))
				verifier := mustVerifierForFixtureWithOptions(t, fixture, WithClock(func() time.Time { return now }), WithTimestampPolicy(TimestampPolicy{FutureTolerance: 5 * time.Minute, MaxAge: time.Hour}))

				return verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
			},
			want: negativeVectorWant{targetStatus: TargetStatusFail, checkKind: CheckKindTimestamp, checkStatus: CheckStatusFail, checkCode: ErrorCodeTimestampInvalid, timestampStatus: TimestampStatusFuture},
		},
		{
			name: "envelope mismatch",
			run: func(t *testing.T) (Result, error) {
				fixture := newDeterministicRSAVerificationFixture(t)

				return mustVerifierForFixture(t, fixture).Verify(context.Background(), Request{Message: fixture.message, Envelope: NewEnvelope([]byte("<sender@example.test>"), [][]byte{[]byte("<rcpt@example.test>")})})
			},
			want: negativeVectorWant{targetStatus: TargetStatusFail, checkKind: CheckKindEnvelope, checkStatus: CheckStatusFail, checkCode: ErrorCodeEnvelopeMismatch, envelopeStatus: EnvelopeStatusReversePathMismatch},
		},
		{
			name: "unsigned recipient mismatch",
			run: func(t *testing.T) (Result, error) {
				recipients := [][]byte{[]byte("<one@example.test>"), []byte("<two@example.test>")}
				fixture := newRSAVerificationFixtureWithEnvelopeAt(t, testTimestampSeconds, []byte("<>"), recipients)

				return mustVerifierForFixture(t, fixture).Verify(context.Background(), Request{Message: fixture.message, Envelope: NewEnvelope([]byte("<>"), [][]byte{[]byte("<one@example.test>"), []byte("<not-signed@example.test>")})})
			},
			want: negativeVectorWant{targetStatus: TargetStatusFail, checkKind: CheckKindEnvelope, checkStatus: CheckStatusFail, checkCode: ErrorCodeEnvelopeMismatch, envelopeStatus: EnvelopeStatusRecipientValueMismatch},
		},
		{
			name: "no checkable signatures",
			run: func(t *testing.T) (Result, error) {
				fixture := newDeterministicRSAVerificationFixture(t)
				provider, err := NewStaticKeyProvider([]StaticKey{{Domain: testDomain, Selector: testSelector, Algorithm: AlgorithmRSASHA256, Material: fixture.rsaPublicKey}})
				if err != nil {
					t.Fatalf("NewStaticKeyProvider() error = %v", err)
				}
				verifier, err := NewVerifier(provider, testClockOption(), WithAlgorithmPolicy(AlgorithmPolicy{AllowedAlgorithms: []Algorithm{AlgorithmEd25519SHA256}, MinRSABits: 1024}))
				if err != nil {
					t.Fatalf("NewVerifier() error = %v", err)
				}

				return verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
			},
			want: negativeVectorWant{targetStatus: TargetStatusUnsupported, signatureStatus: SignatureSetStatusDisabledAlgorithm, algorithm: AlgorithmRSASHA256},
		},
		{
			name: "mixed multi signature outcome",
			run: func(t *testing.T) (Result, error) {
				fixture := newMultiSignatureFixture(t)
				keys := []StaticKey{
					{Domain: testDomain, Selector: testSelector, Algorithm: AlgorithmRSASHA256, Material: fixture.rsaKey},
					{Domain: testDomain, Selector: ed25519Selector, Algorithm: AlgorithmEd25519SHA256, Material: fixture.wrongEd25519},
				}

				return mustVerifierWithKeys(t, keys).Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
			},
			want: negativeVectorWant{targetStatus: TargetStatusMixed, signatureStatus: SignatureSetStatusFail, algorithm: AlgorithmEd25519SHA256},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.run(t)
			if err != nil {
				t.Fatalf("negative vector returned unexpected error = %v", err)
			}
			assertNegativeVectorResult(t, result, tt.want)
		})
	}
}

// assertNegativeVectorResult verifies the expected non-success vector facts.
func assertNegativeVectorResult(t *testing.T, result Result, want negativeVectorWant) {
	t.Helper()

	if result.Status() != want.targetStatus {
		t.Fatalf("Status() = %q, want %q; checks=%#v sets=%#v", result.Status(), want.targetStatus, result.Checks(), result.SignatureSets())
	}
	if want.checkKind != "" && !hasCheckCode(result, want.checkKind, want.checkStatus, want.checkCode, want.envelopeStatus, want.timestampStatus) {
		t.Fatalf("checks = %#v, want %s/%s/%s", result.Checks(), want.checkKind, want.checkStatus, want.checkCode)
	}
	if want.signatureStatus != "" && !hasSignatureSet(result, want.algorithm, want.signatureStatus) {
		t.Fatalf("signature sets = %#v, want %s/%s", result.SignatureSets(), want.algorithm, want.signatureStatus)
	}
}

// hasCheckCode reports whether result contains one matching check and code fact.
func hasCheckCode(result Result, kind CheckKind, status CheckStatus, code ErrorCode, envelopeStatus EnvelopeStatus, timestampStatus TimestampStatus) bool {
	for _, check := range result.Checks() {
		if check.Kind != kind || check.Status != status || check.Code != code {
			continue
		}
		if envelopeStatus != "" && check.EnvelopeStatus != envelopeStatus {
			continue
		}
		if timestampStatus != "" && check.TimestampStatus != timestampStatus {
			continue
		}

		return true
	}

	return false
}

// newDeterministicRSAKey creates a synthetic RSA key from a fixed test seed.
func newDeterministicRSAKey(t *testing.T, seed string) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(newDeterministicReader(syntheticVectorSeed+" "+seed), 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	return key
}

// deterministicEd25519PublicKey returns a synthetic Ed25519 public key.
func deterministicEd25519PublicKey(seed string) ed25519.PublicKey {
	digest := sha256Sum(seed)
	privateKey := ed25519.NewKeyFromSeed(digest[:])

	return privateKey.Public().(ed25519.PublicKey)
}

// sha256Sum wraps SHA-256 seeding for synthetic Ed25519 keys.
func sha256Sum(seed string) [32]byte {
	return sha256.Sum256([]byte(syntheticVectorSeed + " " + seed))
}

// tinyRSAPublicKey returns a parser-shaped key below the verifier bit minimum.
func tinyRSAPublicKey() *rsa.PublicKey {
	return &rsa.PublicKey{N: big.NewInt(65539), E: 3}
}
