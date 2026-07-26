package dkim2

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"

	"github.com/croessner/dkim2/internal/verify"
)

const (
	testSigningDomain = "example.test"
	testSelector      = "selector"
)

type permanentProviderDeadline struct{}

type typedNilPublicKeyProvider struct{}

// LookupPublicKey panics if a typed-nil provider crosses bridge preflight.
func (*typedNilPublicKeyProvider) LookupPublicKey(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
	panic("typed-nil public key provider invoked")
}

// Error returns a bounded provider-owned deadline diagnostic.
func (permanentProviderDeadline) Error() string { return "provider deadline" }

// Unwrap exposes deadline identity for control-flow discrimination.
func (permanentProviderDeadline) Unwrap() error { return context.DeadlineExceeded }

// ProviderErrorClass deliberately supplies an invalid permanent deadline classification.
func (permanentProviderDeadline) ProviderErrorClass() ProviderErrorClass {
	return ProviderErrorClassPermanent
}

// TestPublicProviderBridgeRejectsTypedNilProviderBeforeCallback proves direct
// internal bridge construction cannot bypass the shared typed-nil guard.
func TestPublicProviderBridgeRejectsTypedNilProviderBeforeCallback(t *testing.T) {
	var provider *typedNilPublicKeyProvider
	_, err := (publicKeyBridge{provider: provider}).LookupKey(
		context.Background(),
		verify.KeyQuery{
			Domain: testSigningDomain, Selector: testSelector,
			Algorithm: verify.AlgorithmRSASHA256,
		},
	)
	if verify.ProviderFailureClassOf(err) != verify.ProviderFailureContract {
		t.Fatalf("typed-nil provider failure class = %q", verify.ProviderFailureClassOf(err))
	}
}

// TestPublicProviderBridgeClassifiesClosedMatrix verifies error classes without text matching.
func TestPublicProviderBridgeClassifiesClosedMatrix(t *testing.T) {
	query := verify.KeyQuery{Domain: testSigningDomain, Selector: testSelector, Algorithm: verify.AlgorithmRSASHA256}
	tests := []struct {
		name   string
		result PublicKeyResult
		err    error
		class  verify.ProviderFailureClass
	}{
		{name: string(ProviderErrorClassTemporary), err: NewTemporaryProviderError(), class: verify.ProviderFailureTemporary},
		{name: string(ProviderErrorClassPermanent), err: NewPermanentProviderError(), class: verify.ProviderFailurePermanent},
		{name: "permanent provider deadline", err: permanentProviderDeadline{}, class: verify.ProviderFailureContract},
		{name: "unclassified", err: context.DeadlineExceeded, class: verify.ProviderFailureContract},
		{name: "unclassified raw", err: errors.New("opaque provider failure"), class: verify.ProviderFailureContract},
		{name: "nonzero plus error", result: MissingPublicKey(AlgorithmRSASHA256), err: NewTemporaryProviderError(), class: verify.ProviderFailureContract},
		{name: "zero nil", class: verify.ProviderFailureContract},
		{name: "algorithm mismatch", result: MissingPublicKey(AlgorithmEd25519SHA256), class: verify.ProviderFailureContract},
		{name: "unknown status", result: PublicKeyResult{state: &publicKeyResultState{status: PublicKeyStatus("future"), algorithm: AlgorithmRSASHA256}}, class: verify.ProviderFailureContract},
		{name: "unknown algorithm", result: MissingPublicKey(Algorithm("future")), class: verify.ProviderFailureContract},
		{name: "found without material", result: PublicKeyResult{state: &publicKeyResultState{status: PublicKeyStatusFound, algorithm: AlgorithmRSASHA256}}, class: verify.ProviderFailureContract},
		{name: "found with wrong variant", result: PublicKeyResult{state: &publicKeyResultState{status: PublicKeyStatusFound, algorithm: AlgorithmRSASHA256, ed25519Key: make(ed25519.PublicKey, ed25519.PublicKeySize)}}, class: verify.ProviderFailureContract},
		{name: "nonfound with material", result: PublicKeyResult{state: &publicKeyResultState{status: PublicKeyStatusMissing, algorithm: AlgorithmRSASHA256, rsaKey: &rsa.PublicKey{N: big.NewInt(3), E: 3}}}, class: verify.ProviderFailureContract},
		{name: "both material variants", result: PublicKeyResult{state: &publicKeyResultState{status: PublicKeyStatusFound, algorithm: AlgorithmRSASHA256, rsaKey: &rsa.PublicKey{N: big.NewInt(3), E: 3}, ed25519Key: make(ed25519.PublicKey, ed25519.PublicKeySize)}}, class: verify.ProviderFailureContract},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bridge := publicKeyBridge{provider: publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
				return tt.result, tt.err
			})}
			_, err := bridge.LookupKey(context.Background(), query)
			if verify.ProviderFailureClassOf(err) != tt.class {
				t.Fatalf("failure class = %q, want %q", verify.ProviderFailureClassOf(err), tt.class)
			}
		})
	}
}

// TestPublicProviderBridgePreservesDeclaredNonFoundStatus verifies no-error provider facts remain distinct.
func TestPublicProviderBridgePreservesDeclaredNonFoundStatus(t *testing.T) {
	tests := []struct {
		result PublicKeyResult
		status verify.KeyStatus
	}{
		{MissingPublicKey(AlgorithmRSASHA256), verify.KeyStatusMissing},
		{InvalidPublicKey(AlgorithmRSASHA256), verify.KeyStatusInvalid},
		{AmbiguousPublicKey(AlgorithmRSASHA256), verify.KeyStatusAmbiguous},
		{RevokedPublicKey(AlgorithmRSASHA256), verify.KeyStatusRevoked},
		{UnsupportedKeyTypePublicKey(AlgorithmRSASHA256), verify.KeyStatusUnsupportedKeyType},
		{AlgorithmMismatchPublicKey(AlgorithmRSASHA256), verify.KeyStatusAlgorithmMismatch},
	}
	for _, tt := range tests {
		bridge := publicKeyBridge{provider: publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) { return tt.result, nil })}
		key, err := bridge.LookupKey(context.Background(), verify.KeyQuery{Domain: testSigningDomain, Selector: testSelector, Algorithm: verify.AlgorithmRSASHA256})
		if err != nil || key.Metadata.Status != tt.status {
			t.Fatalf("LookupKey() = %q, %v; want %q", key.Metadata.Status, err, tt.status)
		}
	}
}

// TestPublicProviderBridgePreservesPolicyMetadata verifies metadata survives every declared early return.
func TestPublicProviderBridgePreservesPolicyMetadata(t *testing.T) {
	for _, result := range []PublicKeyResult{
		withKeyPolicyMetadata(InvalidPublicKey(AlgorithmRSASHA256), newKeyPolicyMetadata(true, true)),
		withKeyPolicyMetadata(RevokedPublicKey(AlgorithmRSASHA256), newKeyPolicyMetadata(true, true)),
		withKeyPolicyMetadata(UnsupportedKeyTypePublicKey(AlgorithmRSASHA256), newKeyPolicyMetadata(true, true)),
		withKeyPolicyMetadata(AlgorithmMismatchPublicKey(AlgorithmRSASHA256), newKeyPolicyMetadata(true, true)),
	} {
		bridge := publicKeyBridge{provider: publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) { return result, nil })}
		key, err := bridge.LookupKey(context.Background(), verify.KeyQuery{Domain: testSigningDomain, Selector: testSelector, Algorithm: verify.AlgorithmRSASHA256})
		if err != nil || !key.Metadata.Policy.TestingDeclared || !key.Metadata.Policy.StrictIdentityDeclared || key.Metadata.Policy.StrictIdentityApplicable {
			t.Fatalf("LookupKey() metadata=%#v error=%v", key.Metadata.Policy, err)
		}
	}
}

// TestPublicProviderBridgeRejectsMetadataWithoutUniqueRecord verifies closed metadata legality.
func TestPublicProviderBridgeRejectsMetadataWithoutUniqueRecord(t *testing.T) {
	for _, result := range []PublicKeyResult{
		withKeyPolicyMetadata(MissingPublicKey(AlgorithmRSASHA256), newKeyPolicyMetadata(true, false)),
		withKeyPolicyMetadata(AmbiguousPublicKey(AlgorithmRSASHA256), newKeyPolicyMetadata(false, true)),
	} {
		bridge := publicKeyBridge{provider: publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) { return result, nil })}
		_, err := bridge.LookupKey(context.Background(), verify.KeyQuery{Domain: testSigningDomain, Selector: testSelector, Algorithm: verify.AlgorithmRSASHA256})
		if verify.ProviderFailureClassOf(err) != verify.ProviderFailureContract {
			t.Fatalf("LookupKey() error = %v", err)
		}
	}
}

// TestPublicProviderBridgePreservesFoundMetadata verifies successful key metadata mapping.
func TestPublicProviderBridgePreservesFoundMetadata(t *testing.T) {
	result := withKeyPolicyMetadata(FoundEd25519PublicKey(make(ed25519.PublicKey, ed25519.PublicKeySize)), newKeyPolicyMetadata(true, true))
	bridge := publicKeyBridge{provider: publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) { return result, nil })}
	key, err := bridge.LookupKey(context.Background(), verify.KeyQuery{Domain: testSigningDomain, Selector: testSelector, Algorithm: verify.AlgorithmEd25519SHA256})
	if err != nil || !key.Metadata.Policy.TestingDeclared || !key.Metadata.Policy.StrictIdentityDeclared || key.Metadata.Policy.StrictIdentityApplicable {
		t.Fatalf("LookupKey() metadata=%#v error=%v", key.Metadata.Policy, err)
	}
}

// TestPublicProviderBridgePreservesEd25519Type verifies cloning retains the named key type.
func TestPublicProviderBridgePreservesEd25519Type(t *testing.T) {
	key := make(ed25519.PublicKey, ed25519.PublicKeySize)
	bridge := publicKeyBridge{provider: publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return FoundEd25519PublicKey(key), nil
	})}
	got, err := bridge.LookupKey(context.Background(), verify.KeyQuery{Domain: testSigningDomain, Selector: testSelector, Algorithm: verify.AlgorithmEd25519SHA256})
	if err != nil {
		t.Fatalf("LookupKey() error = %v", err)
	}
	if _, ok := got.Material.(ed25519.PublicKey); !ok {
		t.Fatalf("material type = %T, want ed25519.PublicKey", got.Material)
	}
}

// TestPublicProviderBridgePreservesCallerControlFlow verifies a live provider deadline is not caller cancellation.
func TestPublicProviderBridgePreservesCallerControlFlow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	bridge := publicKeyBridge{provider: publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return PublicKeyResult{}, context.Canceled
	})}
	_, err := bridge.LookupKey(ctx, verify.KeyQuery{Domain: testSigningDomain, Selector: testSelector, Algorithm: verify.AlgorithmRSASHA256})
	if !errors.Is(err, context.Canceled) || verify.ProviderFailureClassOf(err) != "" {
		t.Fatalf("caller error = %v", err)
	}
}

// TestPublicProviderBridgeClonesRSA verifies provider-owned modulus storage is not retained.
func TestPublicProviderBridgeClonesRSA(t *testing.T) {
	key := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 1023), E: 65537}
	bridge := publicKeyBridge{provider: publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return FoundRSAPublicKey(key), nil
	})}
	got, err := bridge.LookupKey(context.Background(), verify.KeyQuery{Domain: testSigningDomain, Selector: testSelector, Algorithm: verify.AlgorithmRSASHA256})
	if err != nil {
		t.Fatalf("LookupKey() error = %v", err)
	}
	key.N.SetInt64(3)
	gotKey, ok := got.Material.(*rsa.PublicKey)
	if !ok || gotKey.N.BitLen() != 1024 {
		t.Fatal("bridge retained provider-owned RSA modulus")
	}
}
