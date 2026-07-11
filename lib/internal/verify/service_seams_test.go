package verify

import (
	"context"
	"errors"
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
