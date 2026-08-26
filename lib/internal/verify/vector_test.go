package verify

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"hash/fnv"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
)

const syntheticVectorSeed = "draft-ietf-dkim-dkim2-spec-05 synthetic static verifier vector"

type deterministicReader struct {
	state uint64
}

// TestStaticKeyPositiveVectors verifies draft-versioned RSA and Ed25519 pass vectors.
func TestStaticKeyPositiveVectors(t *testing.T) {
	tests := []struct {
		name      string
		fixture   func(*testing.T) verificationFixture
		algorithm Algorithm
	}{
		{
			name:      "rsa sha256 pkcs1v15",
			fixture:   newDeterministicRSAVerificationFixture,
			algorithm: AlgorithmRSASHA256,
		},
		{
			name:      "ed25519 sha256 digest",
			fixture:   newDeterministicEd25519VerificationFixture,
			algorithm: AlgorithmEd25519SHA256,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := tt.fixture(t)
			verifier := mustVerifierForFixture(t, fixture)

			result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}

			assertPositiveVectorResult(t, result, tt.algorithm)
		})
	}
}

// TestEd25519VectorSignsSignatureInputDigest verifies Ed25519 signs SHA-256 digest bytes.
func TestEd25519VectorSignsSignatureInputDigest(t *testing.T) {
	fixture := newDeterministicEd25519VerificationFixture(t)
	input := signatureInputForFixture(t, fixture)
	digest := sha256.Sum256(input.Bytes())

	if !ed25519.Verify(fixture.ed25519PublicKey, digest[:], fixture.signatureBytes) {
		t.Fatal("Ed25519 vector did not verify over Section 9.6 SHA-256 digest bytes")
	}
	if ed25519.Verify(fixture.ed25519PublicKey, input.Bytes(), fixture.signatureBytes) {
		t.Fatal("Ed25519 vector unexpectedly verified over raw Section 9.6 bytes")
	}
}

// newDeterministicRSAVerificationFixture creates a synthetic static RSA vector.
func newDeterministicRSAVerificationFixture(t *testing.T) verificationFixture {
	t.Helper()

	key, err := rsa.GenerateKey(newDeterministicReader(syntheticVectorSeed+" rsa key"), 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	fixture := buildVerificationFixture(t, AlgorithmRSASHA256, func(digest []byte, _ []byte) []byte {
		signatureBytes, signErr := rsa.SignPKCS1v15(newDeterministicReader(syntheticVectorSeed+" rsa signature"), key, crypto.SHA256, digest)
		if signErr != nil {
			t.Fatalf("rsa.SignPKCS1v15() error = %v", signErr)
		}

		return signatureBytes
	})
	fixture.rsaPublicKey = &key.PublicKey

	return fixture
}

// newDeterministicEd25519VerificationFixture creates a synthetic static Ed25519 vector.
func newDeterministicEd25519VerificationFixture(t *testing.T) verificationFixture {
	t.Helper()

	seed := sha256.Sum256([]byte(syntheticVectorSeed + " ed25519 seed"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	fixture := buildVerificationFixture(t, AlgorithmEd25519SHA256, func(digest []byte, _ []byte) []byte {
		return ed25519.Sign(privateKey, digest)
	})
	fixture.ed25519PublicKey = publicKey

	return fixture
}

// newDeterministicReader returns a reproducible reader for synthetic test keys.
func newDeterministicReader(seed string) *deterministicReader {
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(seed))
	state := hasher.Sum64()
	if state == 0 {
		state = 0x9e3779b97f4a7c15
	}

	return &deterministicReader{state: state}
}

// Read fills p with deterministic pseudo-random bytes for synthetic tests.
func (r *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		r.state ^= r.state << 13
		r.state ^= r.state >> 7
		r.state ^= r.state << 17
		p[i] = byte(r.state >> 56)
	}

	return len(p), nil
}

// signatureInputForFixture returns M3 Section 9.6 bytes for a fixture target.
func signatureInputForFixture(t *testing.T, fixture verificationFixture) canonical.ByteInput {
	t.Helper()

	canonicalizer := mustCanonicalizer(t)
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{
		Headers:        fixture.message.Headers(),
		TargetSequence: 1,
	})
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}

	return input
}

// assertPositiveVectorResult verifies all expected pass facts for a static vector.
func assertPositiveVectorResult(t *testing.T, result Result, algorithm Algorithm) {
	t.Helper()

	if result.Draft() != DraftBaseline {
		t.Fatalf("Draft() = %q, want %q", result.Draft(), DraftBaseline)
	}
	if result.Target() != (Target{Sequence: 1, InstanceNumber: 1}) {
		t.Fatalf("Target() = %#v, want sequence 1 instance 1", result.Target())
	}
	assertTargetPass(t, result, algorithm)
}
