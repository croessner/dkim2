package verify

import (
	"crypto/fips140"
	"crypto/mldsa"
	"encoding/base64"
	"testing"

	"github.com/croessner/dkim2/internal/cryptodkim2"
)

const templateClassicalOrMLDSA = "{rsa},{ed}|{ml}"

// TestMLDSA44SignatureVerifiesOverCompleteInput proves a Draft-08 Section 3.4
// pure ML-DSA-44 set passes with the right key and fails with another key,
// and that the verifier signs nothing it was not given: the representative
// is the complete Section 12.8 input with the "DKIM2" context string.
func TestMLDSA44SignatureVerifiesOverCompleteInput(t *testing.T) {
	fixture := newCombinationFixture(t, "{ml}")
	if result, _ := verifyCombination(t, fixture, combinationKeys{ml: keyModeOK}); result.Status() != TargetStatusPass {
		t.Fatalf("mldsa44 Status() = %q sets=%#v", result.Status(), result.SignatureSets())
	}
	result, _ := verifyCombination(t, fixture, combinationKeys{ml: keyModeWrong})
	if result.Status() != TargetStatusFail || result.SignatureSets()[0].Status != SignatureSetStatusFail {
		t.Fatalf("mldsa44 wrong key Status() = %q sets=%#v", result.Status(), result.SignatureSets())
	}
	if result, _ := verifyCombination(t, fixture, combinationKeys{ml: keyModeMissing}); result.Status() != TargetStatusUnsupported {
		t.Fatalf("mldsa44 missing key Status() = %q", result.Status())
	}
}

// TestMLDSA44PhasedDeploymentLayout proves the signer layout
// "rsa,ed25519 | mldsa44" is the Section 10.9 phased-deployment pattern: a
// verifier with every algorithm passes, a verifier that disables mldsa44 by
// local policy still passes through the classical group, and a verifier
// that only enables mldsa44 passes through the ML-DSA group.
func TestMLDSA44PhasedDeploymentLayout(t *testing.T) {
	fixture := newCombinationFixture(t, templateClassicalOrMLDSA)
	keys := combinationKeys{rsa: keyModeOK, ed: keyModeOK, ml: keyModeOK}
	result, _ := verifyCombination(t, fixture, keys)
	if result.Status() != TargetStatusPass {
		t.Fatalf("full verifier Status() = %q", result.Status())
	}
	for _, set := range result.SignatureSets() {
		if set.Status != SignatureSetStatusPass {
			t.Fatalf("full verifier set %d = %q", set.Index, set.Status)
		}
	}

	classical := DefaultAlgorithmPolicy()
	classical.AllowedAlgorithms = []Algorithm{AlgorithmRSASHA256, AlgorithmEd25519SHA256}
	result, provider := verifyCombination(t, fixture, keys, WithAlgorithmPolicy(classical))
	sets := result.SignatureSets()
	if result.Status() != TargetStatusPass || len(sets) != 3 || sets[2].Status != SignatureSetStatusDisabledAlgorithm {
		t.Fatalf("classical-only verifier Status() = %q sets=%#v", result.Status(), sets)
	}
	for _, selector := range provider.lookups {
		if selector == combinationMLDSASelector {
			t.Fatal("a disabled mldsa44 set triggered a key lookup")
		}
	}

	postQuantum := DefaultAlgorithmPolicy()
	postQuantum.AllowedAlgorithms = []Algorithm{AlgorithmMLDSA44}
	result, _ = verifyCombination(t, fixture, keys, WithAlgorithmPolicy(postQuantum))
	sets = result.SignatureSets()
	if result.Status() != TargetStatusPass || sets[0].Status != SignatureSetStatusDisabledAlgorithm ||
		sets[1].Status != SignatureSetStatusDisabledAlgorithm || sets[2].Status != SignatureSetStatusPass {
		t.Fatalf("mldsa44-only verifier Status() = %q sets=%#v", result.Status(), sets)
	}

	if result, _ := verifyCombination(t, fixture, combinationKeys{rsa: keyModeOK, ed: keyModeOK, ml: keyModeWrong}); result.Status() != TargetStatusPass {
		t.Fatalf("classical group beside a failing mldsa44 alternative Status() = %q", result.Status())
	}
	if result, _ := verifyCombination(t, fixture, combinationKeys{rsa: keyModeOK, ed: keyModeWrong, ml: keyModeOK}); result.Status() != TargetStatusPass {
		t.Fatalf("mldsa44 alternative beside a failing classical group Status() = %q", result.Status())
	}
	if result, _ := verifyCombination(t, fixture, combinationKeys{rsa: keyModeOK, ed: keyModeWrong, ml: keyModeWrong}); result.Status() != TargetStatusFail {
		t.Fatalf("both groups failing Status() = %q, want fail", result.Status())
	}
}

// TestMLDSA44SignatureLengthIsExact is the wrong-length signature reproducer:
// an mldsa44 set whose decoded value is not exactly 2420 octets is a
// malformed field, like a wrong-length Ed25519 value.
func TestMLDSA44SignatureLengthIsExact(t *testing.T) {
	for _, length := range []int{mldsa.MLDSA44SignatureSize - 1, mldsa.MLDSA44SignatureSize + 1, 64} {
		headerDigest, bodyDigest := baseMessageDigests(t)
		value := combinationMLDSASelector + ":mldsa44:" + foldedBase64(base64.StdEncoding.EncodeToString(bytesOf(0x11, length)))
		if _, err := parseVerificationFixture(rawWithSignatureFields(headerDigest, bodyDigest, []string{signatureField(1, value)})); err == nil {
			t.Fatalf("mldsa44 signature of %d octets parsed", length)
		}
	}
}

// TestMLDSA44KeyMaterialIsValidatedBeforeUse proves the verifier rejects key
// material that is not an ML-DSA-44 public key for an mldsa44 set.
func TestMLDSA44KeyMaterialIsValidatedBeforeUse(t *testing.T) {
	ml87, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatal(err)
	}
	if _, status, err := validatePublicKeyMaterial(AlgorithmMLDSA44, ml87.PublicKey(), DefaultAlgorithmPolicy()); err == nil || status != KeyStatusInvalid {
		t.Fatalf("ML-DSA-87 key status=%q error=%v", status, err)
	}
	if _, status, err := validatePublicKeyMaterial(AlgorithmMLDSA44, []byte("raw"), DefaultAlgorithmPolicy()); err == nil || status != KeyStatusWrongType {
		t.Fatalf("raw key status=%q error=%v", status, err)
	}
	if cryptodkim2.MLDSA44Available() != nil {
		t.Fatal("ML-DSA-44 runtime unavailable")
	}
}

// TestMLDSA44PolicyFailsClosedWithoutRuntime proves verifier construction
// fails closed when mldsa44 is enabled but the runtime cannot provide it
// (the FIPS 140-3 Go Cryptographic Module v1.0.0, exercised by make
// test-fips140-mldsa44), while a classical-only policy stays valid.
func TestMLDSA44PolicyFailsClosedWithoutRuntime(t *testing.T) {
	classical := DefaultAlgorithmPolicy()
	classical.AllowedAlgorithms = []Algorithm{AlgorithmRSASHA256, AlgorithmEd25519SHA256}
	if err := classical.Validate(); err != nil {
		t.Fatalf("classical policy error = %v", err)
	}
	err := DefaultAlgorithmPolicy().Validate()
	if fips140.Version() == "v1.0.0" {
		t.Log("built against the FIPS 140-3 Go Cryptographic Module v1.0.0")
		if !IsErrorCode(err, ErrorCodeUnsupportedAlgorithm) {
			t.Fatalf("default policy under FIPS v1.0.0 error = %v", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("default policy error = %v", err)
	}
}
