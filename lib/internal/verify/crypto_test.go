package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"math/big"
	"strings"
	"testing"
)

// TestVerifierUsesEd25519OverSignatureInputDigest verifies corrected Ed25519-SHA256 semantics.
func TestVerifierUsesEd25519OverSignatureInputDigest(t *testing.T) {
	fixture := newEd25519RawInputSignatureFixture(t)
	verifier := mustVerifierForFixture(t, fixture)

	result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if result.Status() == TargetStatusPass || !hasSignatureSet(result, AlgorithmEd25519SHA256, SignatureSetStatusFail) {
		t.Fatalf("result = %#v sets=%#v, want Ed25519 raw-input signature failure", result, result.SignatureSets())
	}
}

// TestVerifierReportsWrongKey verifies cryptographic failure with a mismatched key.
func TestVerifierReportsWrongKey(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	wrong := newRSAVerificationFixture(t)
	verifier := mustVerifierWithKeys(t, []StaticKey{{
		Domain:    testDomain,
		Selector:  testSelector,
		Algorithm: AlgorithmRSASHA256,
		Material:  wrong.rsaPublicKey,
	}})

	result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if result.Status() == TargetStatusPass || !hasSignatureSet(result, AlgorithmRSASHA256, SignatureSetStatusFail) {
		t.Fatalf("result = %#v sets=%#v, want signature failure", result, result.SignatureSets())
	}
}

// TestVerifierReportsModifiedSignatureInput verifies Section 9.6 input changes fail crypto.
func TestVerifierReportsModifiedSignatureInput(t *testing.T) {
	fixture := newEd25519VerificationFixture(t)
	changed := fixture.withRaw(strings.Replace(fixture.raw, "t=1700000000", "t=1700000001", 1))
	verifier := mustVerifierForFixture(t, fixture)

	result, err := verifier.Verify(context.Background(), Request{Message: changed.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if result.Status() == TargetStatusPass || !hasSignatureSet(result, AlgorithmEd25519SHA256, SignatureSetStatusFail) {
		t.Fatalf("result = %#v sets=%#v, want signature input failure", result, result.SignatureSets())
	}
}

// TestVerifierReportsModifiedSignatureBytes verifies decoded signature mutations fail crypto.
func TestVerifierReportsModifiedSignatureBytes(t *testing.T) {
	fixture := newEd25519VerificationFixture(t)
	changed := fixture.withSignatureBytes(bytesWithFirstBitFlipped(fixture.signatureBytes))
	verifier := mustVerifierForFixture(t, fixture)

	result, err := verifier.Verify(context.Background(), Request{Message: changed.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if result.Status() == TargetStatusPass || !hasSignatureSet(result, AlgorithmEd25519SHA256, SignatureSetStatusFail) {
		t.Fatalf("result = %#v sets=%#v, want modified signature failure", result, result.SignatureSets())
	}
}

// TestVerifierReportsMissingKeyAndUnsupportedAlgorithm verifies non-checkable sets cannot pass.
func TestVerifierReportsMissingKeyAndUnsupportedAlgorithm(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	emptyVerifier := mustVerifierWithKeys(t, nil)

	missingResult, err := emptyVerifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("Verify() missing key error = %v", err)
	}
	if missingResult.Status() == TargetStatusPass || !hasSignatureSet(missingResult, AlgorithmRSASHA256, SignatureSetStatusMissingKey) {
		t.Fatalf("missing key result = %#v sets=%#v", missingResult, missingResult.SignatureSets())
	}

	unsupported := fixture.withSignatureSet("selector.test:future-sha999:" + fixture.signatureBase64)
	unsupportedResult, err := emptyVerifier.Verify(context.Background(), Request{Message: unsupported.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("Verify() unsupported algorithm error = %v", err)
	}
	if unsupportedResult.Status() == TargetStatusPass || !hasSignatureSet(unsupportedResult, AlgorithmUnknown, SignatureSetStatusUnsupportedAlgorithm) {
		t.Fatalf("unsupported result = %#v sets=%#v", unsupportedResult, unsupportedResult.SignatureSets())
	}
}

// TestVerifierReportsRejectedAndWrongTypeKeys verifies provider-returned invalid keys fail closed.
func TestVerifierReportsRejectedAndWrongTypeKeys(t *testing.T) {
	fixture := newRSAVerificationFixture(t)

	tests := []struct {
		name     string
		material any
		status   SignatureSetStatus
	}{
		{
			name:     "too small rsa",
			material: &rsa.PublicKey{N: big.NewInt(65539), E: 3},
			status:   SignatureSetStatusKeyPolicyRejected,
		},
		{
			name:     "wrong key type",
			material: ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)),
			status:   SignatureSetStatusWrongKeyType,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := NewVerifier(providerFunc(func(context.Context, KeyQuery) (PublicKey, error) {
				return PublicKey{
					Algorithm: AlgorithmRSASHA256,
					Material:  tt.material,
					Metadata:  KeyMetadata{Status: KeyStatusFound},
				}, nil
			}), testClockOption())
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}

			result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if result.Status() == TargetStatusPass || !hasSignatureSet(result, AlgorithmRSASHA256, tt.status) {
				t.Fatalf("result = %#v sets=%#v, want %s", result, result.SignatureSets(), tt.status)
			}
		})
	}
}

// TestVerifierRejectsInvalidProviderSuccessInvariants verifies nil-error provider results still fail closed.
func TestVerifierRejectsInvalidProviderSuccessInvariants(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	tests := []struct {
		name   string
		key    PublicKey
		status SignatureSetStatus
	}{
		{
			name: "algorithm mismatch",
			key: PublicKey{
				Algorithm: AlgorithmEd25519SHA256,
				Material:  fixture.rsaPublicKey,
				Metadata:  KeyMetadata{Status: KeyStatusFound},
			},
			status: SignatureSetStatusProviderContract,
		},
		{
			name: "missing found status",
			key: PublicKey{
				Algorithm: AlgorithmRSASHA256,
				Material:  fixture.rsaPublicKey,
			},
			status: SignatureSetStatusProviderContract,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := NewVerifier(providerFunc(func(context.Context, KeyQuery) (PublicKey, error) {
				return tt.key, nil
			}), testClockOption())
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}

			result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if result.Status() == TargetStatusPass || !hasSignatureSet(result, AlgorithmRSASHA256, tt.status) {
				t.Fatalf("result = %#v sets=%#v, want %q", result, result.SignatureSets(), tt.status)
			}
		})
	}
}

type providerFunc func(context.Context, KeyQuery) (PublicKey, error)

// TestSignatureCheckResultPreservesDNSKeyReasons verifies distinct DNS policy failures are not collapsed.
func TestSignatureCheckResultPreservesDNSKeyReasons(t *testing.T) {
	target := Target{Sequence: 1, InstanceNumber: 1}
	for _, tt := range []struct {
		status SignatureSetStatus
		code   ErrorCode
	}{
		{status: SignatureSetStatusRevokedKey, code: ErrorCodeRevokedKey},
		{status: SignatureSetStatusUnsupportedKeyType, code: ErrorCodeUnsupportedKeyType},
		{status: SignatureSetStatusKeyAlgorithmMismatch, code: ErrorCodeKeyAlgorithmMismatch},
	} {
		check := signatureCheckResult(SignatureSetResult{Algorithm: AlgorithmRSASHA256, Status: tt.status}, target)
		if check.Status != CheckStatusFail || check.Code != tt.code || check.Target != target {
			t.Fatalf("signatureCheckResult(%q) = %q/%q/%#v", tt.status, check.Status, check.Code, check.Target)
		}
	}
}

// LookupKey resolves a key through the test function.
func (f providerFunc) LookupKey(ctx context.Context, query KeyQuery) (PublicKey, error) {
	return f(ctx, query)
}
