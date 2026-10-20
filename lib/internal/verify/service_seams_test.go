package verify

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"strings"
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

// TestKeyProviderBoundaryFormattingIsRedacted proves provider tuples and key material never render.
func TestKeyProviderBoundaryFormattingIsRedacted(t *testing.T) {
	query := KeyQuery{Domain: "SECRET.example.test", Selector: "SECRET-selector", Algorithm: AlgorithmRSASHA256}
	key := PublicKey{Algorithm: AlgorithmRSASHA256, Material: []byte("SECRET-key")}
	for _, value := range []any{query, key} {
		formatted := fmt.Sprintf("%v %+v %#v", value, value, value)
		if strings.Contains(formatted, "SECRET") || !strings.Contains(formatted, "redacted") {
			t.Fatalf("unsafe provider boundary formatting %q", formatted)
		}
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

// TestVerifierClassifiesProviderFailureOnce proves stateful external classifiers cannot drift.
func TestVerifierClassifiesProviderFailureOnce(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	failure := &togglingVerifierProviderFailure{}
	verifier, err := NewVerifier(providerFunc(func(context.Context, KeyQuery) (PublicKey, error) {
		return PublicKey{}, failure
	}), testClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, verifyErr := verifier.Verify(context.Background(), Request{
		Message: fixture.message, Envelope: matchingEnvelope(),
	})
	if verifyErr != nil || !hasSignatureSet(result, AlgorithmRSASHA256, SignatureSetStatusProviderTemporary) {
		t.Fatalf("Verify() sets/error = %#v/%v", result.SignatureSets(), verifyErr)
	}
	if failure.calls != 1 {
		t.Fatalf("ProviderFailureClass() calls = %d, want 1", failure.calls)
	}
}

type togglingVerifierProviderFailure struct{ calls int }

// Error returns one constant secret-safe provider failure summary.
func (*togglingVerifierProviderFailure) Error() string { return "provider failure" }

// ProviderFailureClass changes after its first invocation to expose repeated classification.
func (e *togglingVerifierProviderFailure) ProviderFailureClass() ProviderFailureClass {
	e.calls++
	if e.calls == 1 {
		return ProviderFailureTemporary
	}
	return ProviderFailurePermanent
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

// TestProviderUnknownKeyStatusAndInvalidMetadataBecomeContract verifies injected state fails closed.
func TestProviderUnknownKeyStatusAndInvalidMetadataBecomeContract(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	for _, metadata := range []KeyMetadata{
		{Status: KeyStatus("future")},
		{Status: KeyStatusFound, Source: strings.Repeat("a", 65)},
		{Status: KeyStatusFound, Source: "unsafe/source"},
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

// TestProviderErrorsRemainContractAndAlgorithmMismatchStaysTyped verifies disjoint provider classifications.
func TestProviderErrorsRemainContractAndAlgorithmMismatchStaysTyped(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	tests := []struct {
		name   string
		key    PublicKey
		err    error
		status SignatureSetStatus
	}{
		{name: "raw missing error", key: PublicKey{Algorithm: AlgorithmRSASHA256, Metadata: KeyMetadata{Status: KeyStatusMissing}}, err: errors.New("SECRET-MARKER missing"), status: SignatureSetStatusProviderContract},
		{name: "nonzero material plus error", key: PublicKey{Algorithm: AlgorithmRSASHA256, Material: fixture.rsaPublicKey, Metadata: KeyMetadata{Status: KeyStatusFound}}, err: NewProviderFailure(ProviderFailureTemporary), status: SignatureSetStatusProviderContract},
		{name: "contradictory found algorithm mismatch", key: PublicKey{Algorithm: AlgorithmEd25519SHA256, Material: deterministicEd25519PublicKey("metadata algorithm mismatch"), Metadata: KeyMetadata{Status: KeyStatusFound}}, status: SignatureSetStatusProviderContract},
		{name: "reported key algorithm mismatch", key: PublicKey{Algorithm: AlgorithmRSASHA256, Metadata: KeyMetadata{Status: KeyStatusAlgorithmMismatch}}, status: SignatureSetStatusKeyAlgorithmMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := NewVerifier(providerFunc(func(context.Context, KeyQuery) (PublicKey, error) { return tt.key, tt.err }), testClockOption())
			if err != nil {
				t.Fatal(err)
			}
			result, verifyErr := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
			sets := result.SignatureSets()
			if verifyErr != nil || len(sets) != 1 || sets[0].Status != tt.status {
				t.Fatalf("Verify() sets/error = %#v/%v", sets, verifyErr)
			}
		})
	}
}
