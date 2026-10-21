package signature

import (
	"slices"
	"testing"
)

// TestSigningAlgorithmOrderIsDetached proves callers cannot reorder the
// canonical signing order through the returned slice.
func TestSigningAlgorithmOrderIsDetached(t *testing.T) {
	want := []Algorithm{AlgorithmRSASHA256, AlgorithmEd25519SHA256, AlgorithmMLDSA44Ed25519SHA512}
	order := SigningAlgorithmOrder()
	if !slices.Equal(order, want) {
		t.Fatalf("SigningAlgorithmOrder() = %v", order)
	}
	order[0], order[2] = order[2], order[0]
	if got := SigningAlgorithmOrder(); !slices.Equal(got, want) {
		t.Fatalf("SigningAlgorithmOrder() after caller mutation = %v", got)
	}
	if rank, ok := AlgorithmRSASHA256.SigningRank(); !ok || rank != 0 {
		t.Fatalf("SigningRank(rsa-sha256) = %d, %t", rank, ok)
	}
}
