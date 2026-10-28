package verify

import (
	"context"
	"strings"
	"testing"
)

// compositeAlgorithmToken is the Draft-08 Section 3.4 post-quantum composite
// token this implementation deliberately does not support.
const compositeAlgorithmToken Algorithm = "mldsa44-ed25519-sha512"

// TestAlgorithmPolicyRejectsPostQuantumComposite proves the composite token
// cannot be enabled in a verifier allowlist: it is outside the known
// vocabulary and fails closed as an unsupported algorithm.
func TestAlgorithmPolicyRejectsPostQuantumComposite(t *testing.T) {
	policy := DefaultAlgorithmPolicy()
	policy.AllowedAlgorithms = append(policy.AllowedAlgorithms, compositeAlgorithmToken)
	if err := policy.Validate(); !IsErrorCode(err, ErrorCodeUnsupportedAlgorithm) {
		t.Fatalf("Validate() error = %v, want unsupported algorithm", err)
	}
	if status := DefaultAlgorithmPolicy().ClassifyAlgorithm(compositeAlgorithmToken); status != KeyStatusUnsupportedAlgorithm {
		t.Fatalf("ClassifyAlgorithm(composite) = %q", status)
	}
}

// TestVerifierNeverPassesRSASHA1OnlySignatures reproduces DNS-02 Section 3.3:
// rsa-sha1 MUST NOT be validated, so a signature set holding only rsa-sha1 is
// an ignored unknown algorithm and cannot yield PASS.
func TestVerifierNeverPassesRSASHA1OnlySignatures(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	raw := strings.Replace(fixture.raw, ":"+string(AlgorithmRSASHA256)+":", ":rsa-sha1:", 1)
	sha1Only, err := parseVerificationFixture(raw)
	if err != nil {
		t.Fatalf("parseVerificationFixture() error = %v", err)
	}
	result, err := mustVerifierForFixture(t, fixture).Verify(context.Background(), Request{Message: sha1Only.message, Envelope: matchingEnvelope()})
	if err == nil && result.Status() == TargetStatusPass {
		t.Fatal("rsa-sha1-only signature produced PASS")
	}
}
