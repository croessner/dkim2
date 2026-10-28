package signature

import (
	"slices"
	"testing"
)

// TestSigningAlgorithmOrderIsDetached proves callers cannot reorder the
// canonical signing order through the returned slice.
func TestSigningAlgorithmOrderIsDetached(t *testing.T) {
	want := []Algorithm{AlgorithmRSASHA256, AlgorithmEd25519SHA256, AlgorithmMLDSA44}
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

// TestPostQuantumCompositeIsOutsideTheAlgorithmVocabulary pins that the
// Draft-07 composite mldsa44-ed25519-sha512, which Draft-08 replaced by pure
// mldsa44 and DNS-02 still lists, is neither known nor signable, so it is
// handled like any extension token.
func TestPostQuantumCompositeIsOutsideTheAlgorithmVocabulary(t *testing.T) {
	composite := Algorithm("mldsa44-ed25519-sha512")
	if composite.Known() || composite.Signable() {
		t.Fatalf("composite known=%t signable=%t", composite.Known(), composite.Signable())
	}
	if _, ranked := composite.SigningRank(); ranked {
		t.Fatal("composite has a signing rank")
	}
}

// TestDNS02OnlyAlgorithmNamesAreUnknownSigNames pins DKIM2-ISSUE-0021:
// DNS-02 Section 3.3 lists rsa-sha512, ed25519-sha512, and the composite,
// but Draft-08 Section 10.9 defines only rsa-sha256, ed25519-sha256, and
// mldsa44 as sig-names. The DNS-02-only names stay unknown, unsignable
// extension tokens (a PERMERROR intermediate in verification).
func TestDNS02OnlyAlgorithmNamesAreUnknownSigNames(t *testing.T) {
	for _, name := range []Algorithm{"rsa-sha512", "ed25519-sha512", "mldsa44-ed25519-sha512", "MLDSA44"} {
		if name.Known() || name.Signable() {
			t.Fatalf("%s known=%t signable=%t", name, name.Known(), name.Signable())
		}
	}
	for _, name := range []Algorithm{AlgorithmRSASHA256, AlgorithmEd25519SHA256, AlgorithmMLDSA44} {
		if !name.Known() || !name.Signable() {
			t.Fatalf("Draft-08 sig-name %s is not implemented", name)
		}
	}
}
