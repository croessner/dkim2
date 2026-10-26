package signature

import (
	"slices"
	"testing"
)

// TestSigningAlgorithmOrderIsDetached proves callers cannot reorder the
// canonical signing order through the returned slice.
func TestSigningAlgorithmOrderIsDetached(t *testing.T) {
	want := []Algorithm{AlgorithmRSASHA256, AlgorithmEd25519SHA256}
	order := SigningAlgorithmOrder()
	if !slices.Equal(order, want) {
		t.Fatalf("SigningAlgorithmOrder() = %v", order)
	}
	order[0], order[1] = order[1], order[0]
	if got := SigningAlgorithmOrder(); !slices.Equal(got, want) {
		t.Fatalf("SigningAlgorithmOrder() after caller mutation = %v", got)
	}
	if rank, ok := AlgorithmRSASHA256.SigningRank(); !ok || rank != 0 {
		t.Fatalf("SigningRank(rsa-sha256) = %d, %t", rank, ok)
	}
}

// TestPostQuantumCompositeIsOutsideTheAlgorithmVocabulary pins the deliberate
// deviation from DNS-01: the unsettled mldsa44-ed25519-sha512 construction is
// neither known nor signable, so it is handled like any extension token.
func TestPostQuantumCompositeIsOutsideTheAlgorithmVocabulary(t *testing.T) {
	composite := Algorithm("mldsa44-ed25519-sha512")
	if composite.Known() || composite.Signable() {
		t.Fatalf("composite known=%t signable=%t", composite.Known(), composite.Signable())
	}
	if _, ranked := composite.SigningRank(); ranked {
		t.Fatal("composite has a signing rank")
	}
}
