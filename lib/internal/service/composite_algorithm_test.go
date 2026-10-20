package service

import (
	"testing"

	"github.com/croessner/dkim2/internal/policy"
	"github.com/croessner/dkim2/internal/verify"
)

// TestCompositeAlgorithmMapsThroughServiceVocabulary proves the Draft-07
// mldsa44-ed25519-sha512 algorithm is a supported, known service fact and
// projects into the policy vocabulary instead of an internal contract failure.
func TestCompositeAlgorithmMapsThroughServiceVocabulary(t *testing.T) {
	mapped, ok := mapAlgorithm(verify.AlgorithmMLDSA44Ed25519SHA512)
	if !ok || mapped != AlgorithmMLDSA44Ed25519SHA512 || !mapped.Known() {
		t.Fatalf("mapAlgorithm() = %q/%v", mapped, ok)
	}
	if !supportedAlgorithm(verify.AlgorithmMLDSA44Ed25519SHA512) || !knownAlgorithm(verify.AlgorithmMLDSA44Ed25519SHA512) {
		t.Fatal("composite algorithm is not a supported service algorithm")
	}
	if !signatureAlgorithmCoherent(verify.AlgorithmMLDSA44Ed25519SHA512, verify.SignatureSetStatusPass) {
		t.Fatal("composite PASS set is incoherent")
	}
	projected, ok := policySetAlgorithm(AlgorithmMLDSA44Ed25519SHA512)
	if !ok || projected != policy.SetAlgorithmMLDSA44Ed25519 || !projected.Known() {
		t.Fatalf("policySetAlgorithm() = %q/%v", projected, ok)
	}
	if _, err := policy.NewSignatureFact(projected, policy.SetStatusPass, policy.SetReasonNone, false, false); err != nil {
		t.Fatalf("policy.NewSignatureFact() error = %v", err)
	}
}
