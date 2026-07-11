package verify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
)

// TestMessageDigestAndSignatureStatusAreImmutable verifies verifier-owned state is detached.
func TestMessageDigestAndSignatureStatusAreImmutable(t *testing.T) {
	fixture := newDeterministicEd25519VerificationFixture(t)

	verifier := mustVerifierForFixture(t, fixture)
	result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	assertTargetPass(t, result, AlgorithmEd25519SHA256)

	sets := result.SignatureSets()
	checks := result.Checks()
	sets[0].Status = SignatureSetStatusFail
	checks[0].Status = CheckStatusFail
	if result.SignatureSets()[0].Status != SignatureSetStatusPass {
		t.Fatalf("SignatureSets()[0].Status = %q, want immutable pass", result.SignatureSets()[0].Status)
	}
	if result.Checks()[0].Status != CheckStatusPass {
		t.Fatalf("Checks()[0].Status = %q, want immutable pass", result.Checks()[0].Status)
	}

	canonicalizer := mustCanonicalizer(t)
	digest, err := signatureInputDigest(canonicalizer, fixture.message, Target{Sequence: 1, InstanceNumber: 1})
	if err != nil {
		t.Fatalf("signatureInputDigest() error = %v", err)
	}
	originalDigest := bytes.Clone(digest)
	digest[0] ^= 0xff
	freshDigest, err := signatureInputDigest(canonicalizer, fixture.message, Target{Sequence: 1, InstanceNumber: 1})
	if err != nil {
		t.Fatalf("second signatureInputDigest() error = %v", err)
	}
	if !bytes.Equal(freshDigest, originalDigest) || bytes.Equal(freshDigest, digest) {
		t.Fatal("signatureInputDigest() exposed mutable digest storage")
	}
}

// TestStaticProviderEd25519KeyMaterialAndMetadataAreImmutable verifies key copies.
func TestStaticProviderEd25519KeyMaterialAndMetadataAreImmutable(t *testing.T) {
	key := deterministicEd25519PublicKey("immutability key")
	original := bytes.Clone(key)
	provider, err := NewStaticKeyProvider([]StaticKey{{
		Domain:    testDomain,
		Selector:  testSelector,
		Algorithm: AlgorithmEd25519SHA256,
		Material:  key,
		Metadata: KeyMetadata{Source: "immutability.fixture", Policy: KeyPolicyMetadata{
			TestingDeclared: true, StrictIdentityDeclared: true,
		}},
	}})
	if err != nil {
		t.Fatalf("NewStaticKeyProvider() error = %v", err)
	}
	key[0] ^= 0xff

	resolved, err := provider.LookupKey(context.Background(), KeyQuery{Domain: testDomain, Selector: testSelector, Algorithm: AlgorithmEd25519SHA256})
	if err != nil {
		t.Fatalf("LookupKey() error = %v", err)
	}
	if resolved.Metadata.Source != "immutability.fixture" || resolved.Metadata.Status != KeyStatusFound {
		t.Fatalf("Metadata = %#v, want immutable fixture metadata", resolved.Metadata)
	}
	if resolved.Metadata.Policy != (KeyPolicyMetadata{}) {
		t.Fatalf("static provider leaked DNS policy metadata: %#v", resolved.Metadata.Policy)
	}
	resolvedKey := resolved.Material.(ed25519.PublicKey)
	if !bytes.Equal(resolvedKey, original) {
		t.Fatal("provider did not preserve original Ed25519 public key bytes")
	}
	resolvedKey[0] ^= 0xff

	again, err := provider.LookupKey(context.Background(), KeyQuery{Domain: testDomain, Selector: testSelector, Algorithm: AlgorithmEd25519SHA256})
	if err != nil {
		t.Fatalf("second LookupKey() error = %v", err)
	}
	if !bytes.Equal(again.Material.(ed25519.PublicKey), original) {
		t.Fatal("LookupKey() reused mutable Ed25519 public key storage")
	}
}
