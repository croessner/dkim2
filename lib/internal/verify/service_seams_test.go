package verify

import (
	"context"
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"
)

// TestServiceSeamVocabulariesAreClosed verifies typed provider and custody facts fail closed.
func TestServiceSeamVocabulariesAreClosed(t *testing.T) {
	for _, status := range []SignatureSetStatus{SignatureSetStatusProviderTemporary, SignatureSetStatusProviderPermanent, SignatureSetStatusProviderContract} {
		if !status.Known() {
			t.Fatalf("SignatureSetStatus(%q).Known() = false", status)
		}
	}
	for _, status := range []KeyStatus{KeyStatusProviderTemporary, KeyStatusProviderPermanent, KeyStatusProviderContract} {
		if !status.Known() {
			t.Fatalf("KeyStatus(%q).Known() = false", status)
		}
	}
	for _, status := range []CustodyStatus{CustodyStatusNotPresent, CustodyStatusNDLinksEvaluated, CustodyStatusTerminalNDRequiresOOB} {
		if !status.Known() {
			t.Fatalf("CustodyStatus(%q).Known() = false", status)
		}
	}
	if SignatureSetStatus("future").Known() || KeyStatus("future").Known() || CustodyStatus("future").Known() {
		t.Fatal("unknown service-seam status reported known")
	}
}

// TestTypedTemporaryProviderProducesIndeterminateTarget verifies the real M4 temporary path.
func TestTypedTemporaryProviderProducesIndeterminateTarget(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	verifier, err := NewVerifier(providerFunc(func(context.Context, KeyQuery) (PublicKey, error) {
		return PublicKey{}, NewProviderFailure(ProviderFailureTemporary)
	}), testClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Status() != TargetStatusIndeterminate || !hasSignatureSet(result, AlgorithmRSASHA256, SignatureSetStatusProviderTemporary) {
		t.Fatalf("result = %q sets=%#v", result.Status(), result.SignatureSets())
	}
}

// TestSupportedPassAndTemporaryProviderRemainIndeterminate verifies incomplete mixed availability cannot pass.
func TestSupportedPassAndTemporaryProviderRemainIndeterminate(t *testing.T) {
	fixture := newMultiSignatureFixture(t)
	verifier, err := NewVerifier(providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
		if query.Algorithm == AlgorithmRSASHA256 {
			return PublicKey{Algorithm: query.Algorithm, Material: fixture.rsaKey, Metadata: KeyMetadata{Status: KeyStatusFound}}, nil
		}
		return PublicKey{}, NewProviderFailure(ProviderFailureTemporary)
	}), testClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Status() != TargetStatusIndeterminate || !hasSignatureSet(result, AlgorithmRSASHA256, SignatureSetStatusPass) || !hasSignatureSet(result, AlgorithmEd25519SHA256, SignatureSetStatusProviderTemporary) {
		t.Fatalf("result = %q sets=%#v", result.Status(), result.SignatureSets())
	}
}

// TestProviderFailureClassificationIsTypedAndCauseFree verifies no text-based classification.
func TestProviderFailureClassificationIsTypedAndCauseFree(t *testing.T) {
	for _, class := range []ProviderFailureClass{ProviderFailureTemporary, ProviderFailurePermanent, ProviderFailureContract} {
		err := NewProviderFailure(class)
		if ProviderFailureClassOf(err) != class {
			t.Fatalf("ProviderFailureClassOf() = %q, want %q", ProviderFailureClassOf(err), class)
		}
		if errors.Unwrap(err) != nil {
			t.Fatal("typed provider failure retained a raw cause")
		}
	}
	if ProviderFailureClassOf(errors.New("temporary")) != "" {
		t.Fatal("provider failure was classified from error text")
	}
}

// TestDeclaredNonFoundProviderStatusesRemainDistinct verifies no-error provider results are not collapsed.
func TestDeclaredNonFoundProviderStatusesRemainDistinct(t *testing.T) {
	tests := []struct {
		key       KeyStatus
		signature SignatureSetStatus
	}{
		{KeyStatusMissing, SignatureSetStatusMissingKey},
		{KeyStatusInvalid, SignatureSetStatusInvalidKey},
		{KeyStatusAmbiguous, SignatureSetStatusAmbiguousKey},
	}
	for _, tt := range tests {
		fixture := newRSAVerificationFixture(t)
		verifier, err := NewVerifier(providerFunc(func(context.Context, KeyQuery) (PublicKey, error) {
			return PublicKey{Algorithm: AlgorithmRSASHA256, Metadata: KeyMetadata{Status: tt.key}}, nil
		}), testClockOption())
		if err != nil {
			t.Fatalf("NewVerifier() error = %v", err)
		}
		result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
		if err != nil || !hasSignatureSet(result, AlgorithmRSASHA256, tt.signature) {
			t.Fatalf("status %q result/error = %#v/%v", tt.key, result.SignatureSets(), err)
		}
	}
}

// TestArbitraryProviderEvenRSAModulusIsRejected verifies provider-independent key validation.
func TestArbitraryProviderEvenRSAModulusIsRejected(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	evenModulus := new(big.Int).SetBit(new(big.Int).Set(fixture.rsaPublicKey.N), 0, 0)
	verifier, err := NewVerifier(providerFunc(func(context.Context, KeyQuery) (PublicKey, error) {
		return PublicKey{
			Algorithm: AlgorithmRSASHA256,
			Material:  &rsa.PublicKey{N: evenModulus, E: fixture.rsaPublicKey.E},
			Metadata:  KeyMetadata{Status: KeyStatusFound},
		}, nil
	}), testClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	if err != nil || !hasSignatureSet(result, AlgorithmRSASHA256, SignatureSetStatusInvalidKey) {
		t.Fatalf("Verify() result/error = %#v/%v, want invalid key", result.SignatureSets(), err)
	}
}

// TestArbitraryProviderUsesVerifierBoundMinimumRSABits verifies no provider or default-policy shortcut.
func TestArbitraryProviderUsesVerifierBoundMinimumRSABits(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	policy := DefaultAlgorithmPolicy()
	policy.MinRSABits = fixture.rsaPublicKey.N.BitLen() + 1
	verifier, err := NewVerifier(providerFunc(func(context.Context, KeyQuery) (PublicKey, error) {
		return PublicKey{
			Algorithm: AlgorithmRSASHA256,
			Material:  fixture.rsaPublicKey,
			Metadata:  KeyMetadata{Status: KeyStatusFound},
		}, nil
	}), WithAlgorithmPolicy(policy), testClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	if err != nil || !hasSignatureSet(result, AlgorithmRSASHA256, SignatureSetStatusKeyPolicyRejected) {
		t.Fatalf("Verify() result/error = %#v/%v, want key policy rejected", result.SignatureSets(), err)
	}
}

// TestProviderKeyPolicyMetadataSurvivesPassFailAndPermanentStates verifies every evaluator return.
func TestProviderKeyPolicyMetadataSurvivesPassFailAndPermanentStates(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	other := newRSAVerificationFixture(t)
	policy := KeyPolicyMetadata{TestingDeclared: true, StrictIdentityDeclared: true}
	tests := []struct {
		name     string
		material any
		key      KeyStatus
		status   SignatureSetStatus
	}{
		{name: "pass", material: fixture.rsaPublicKey, key: KeyStatusFound, status: SignatureSetStatusPass},
		{name: "fail", material: other.rsaPublicKey, key: KeyStatusFound, status: SignatureSetStatusFail},
		{name: "invalid", key: KeyStatusInvalid, status: SignatureSetStatusInvalidKey},
		{name: "revoked", key: KeyStatusRevoked, status: SignatureSetStatusRevokedKey},
		{name: "unsupported key type", key: KeyStatusUnsupportedKeyType, status: SignatureSetStatusUnsupportedKeyType},
		{name: "algorithm mismatch", key: KeyStatusAlgorithmMismatch, status: SignatureSetStatusKeyAlgorithmMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := NewVerifier(providerFunc(func(context.Context, KeyQuery) (PublicKey, error) {
				return PublicKey{Algorithm: AlgorithmRSASHA256, Material: tt.material, Metadata: KeyMetadata{Status: tt.key, Policy: policy}}, nil
			}), testClockOption())
			if err != nil {
				t.Fatal(err)
			}
			result, verifyErr := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
			sets := result.SignatureSets()
			if verifyErr != nil || len(sets) != 1 || sets[0].Status != tt.status || sets[0].KeyPolicy != policy {
				t.Fatalf("Verify() sets/error = %#v/%v", sets, verifyErr)
			}
		})
	}
}

// TestProviderMissingAmbiguousAndStaticMetadataRemainFalse verifies metadata requires a unique record.
func TestProviderMissingAmbiguousAndStaticMetadataRemainFalse(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	for _, status := range []KeyStatus{KeyStatusMissing, KeyStatusAmbiguous} {
		verifier, err := NewVerifier(providerFunc(func(context.Context, KeyQuery) (PublicKey, error) {
			return PublicKey{Algorithm: AlgorithmRSASHA256, Metadata: KeyMetadata{Status: status}}, nil
		}), testClockOption())
		if err != nil {
			t.Fatal(err)
		}
		result, verifyErr := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
		if verifyErr != nil || result.SignatureSets()[0].KeyPolicy != (KeyPolicyMetadata{}) {
			t.Fatalf("status %q metadata/error = %#v/%v", status, result.SignatureSets()[0].KeyPolicy, verifyErr)
		}
	}
}

// TestProviderUnknownKeyStatusAndInvalidMetadataBecomeContract verifies injected state fails closed.
func TestProviderUnknownKeyStatusAndInvalidMetadataBecomeContract(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	for _, metadata := range []KeyMetadata{
		{Status: KeyStatus("future")},
		{Status: KeyStatusFound, Policy: KeyPolicyMetadata{StrictIdentityApplicable: true}},
	} {
		verifier, err := NewVerifier(providerFunc(func(context.Context, KeyQuery) (PublicKey, error) {
			return PublicKey{Algorithm: AlgorithmRSASHA256, Material: fixture.rsaPublicKey, Metadata: metadata}, nil
		}), testClockOption())
		if err != nil {
			t.Fatal(err)
		}
		result, verifyErr := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
		if verifyErr != nil || !hasSignatureSet(result, AlgorithmRSASHA256, SignatureSetStatusProviderContract) {
			t.Fatalf("Verify() sets/error = %#v/%v", result.SignatureSets(), verifyErr)
		}
	}
}

// TestProviderRawErrorAndAlgorithmMismatchMetadataBecomeCleanContract verifies no fallback classification.
func TestProviderRawErrorAndAlgorithmMismatchMetadataBecomeCleanContract(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	policy := KeyPolicyMetadata{TestingDeclared: true, StrictIdentityDeclared: true}
	tests := []struct {
		name string
		key  PublicKey
		err  error
	}{
		{name: "raw missing error", key: PublicKey{Algorithm: AlgorithmRSASHA256, Metadata: KeyMetadata{Status: KeyStatusMissing}}, err: errors.New("SECRET-MARKER missing")},
		{name: "nonzero material plus error", key: PublicKey{Algorithm: AlgorithmRSASHA256, Material: fixture.rsaPublicKey, Metadata: KeyMetadata{Status: KeyStatusFound}}, err: NewProviderFailure(ProviderFailureTemporary)},
		{name: "algorithm mismatch with metadata", key: PublicKey{Algorithm: AlgorithmEd25519SHA256, Material: fixture.rsaPublicKey, Metadata: KeyMetadata{Status: KeyStatusFound, Policy: policy}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := NewVerifier(providerFunc(func(context.Context, KeyQuery) (PublicKey, error) { return tt.key, tt.err }), testClockOption())
			if err != nil {
				t.Fatal(err)
			}
			result, verifyErr := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
			sets := result.SignatureSets()
			if verifyErr != nil || len(sets) != 1 || sets[0].Status != SignatureSetStatusProviderContract || sets[0].KeyPolicy != (KeyPolicyMetadata{}) {
				t.Fatalf("Verify() sets/error = %#v/%v", sets, verifyErr)
			}
		})
	}
}
