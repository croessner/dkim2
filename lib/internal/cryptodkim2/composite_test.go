package cryptodkim2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha512"
	"testing"

	"github.com/croessner/dkim2/internal/signature"
)

// compositeTestKeys returns deterministic ML-DSA-44 and Ed25519 test keys.
func compositeTestKeys(t *testing.T) (*mldsa.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	mlKey, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), bytes.Repeat([]byte{0x42}, mldsa.PrivateKeySize))
	if err != nil {
		t.Fatalf("mldsa.NewPrivateKey() error = %v", err)
	}
	return mlKey, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize))
}

// compositeTestSignature signs digest per Draft-07 Section 3.4: pure
// ML-DSA-44 with empty context, then PureEd25519, concatenated in that order.
func compositeTestSignature(t *testing.T, mlKey *mldsa.PrivateKey, edKey ed25519.PrivateKey, digest []byte) []byte {
	t.Helper()
	mlSignature, err := mlKey.SignDeterministic(digest, &mldsa.Options{})
	if err != nil {
		t.Fatalf("SignDeterministic() error = %v", err)
	}
	return append(mlSignature, ed25519.Sign(edKey, digest)...)
}

// TestCompositeVerifiesDraft07Construction proves the exact Section 3.4
// construction and the fixed DNS key and signature sizes.
func TestCompositeVerifiesDraft07Construction(t *testing.T) {
	mlKey, edKey := compositeTestKeys(t)
	raw := append(mlKey.PublicKey().Bytes(), edKey.Public().(ed25519.PublicKey)...)
	if len(raw) != CompositePublicKeyBytes {
		t.Fatalf("raw composite key = %d bytes, want %d", len(raw), CompositePublicKeyBytes)
	}
	key, err := ParseCompositePublicKey(raw)
	if err != nil {
		t.Fatalf("ParseCompositePublicKey() error = %v", err)
	}
	sum := sha512.Sum512([]byte("canonical signature input"))
	signatureBytes := compositeTestSignature(t, mlKey, edKey, sum[:])
	if len(signatureBytes) != CompositeSignatureBytes {
		t.Fatalf("composite signature = %d bytes, want %d", len(signatureBytes), CompositeSignatureBytes)
	}
	if err := VerifyDigest(signature.AlgorithmMLDSA44Ed25519SHA512, key, sum[:], signatureBytes, Limits{}); err != nil {
		t.Fatalf("VerifyDigest() error = %v", err)
	}
}

// TestCompositeRejectsEveryPartialOrConfusedForm requires both halves under
// the same input and rejects alternate profiles and malformed material.
func TestCompositeRejectsEveryPartialOrConfusedForm(t *testing.T) {
	mlKey, edKey := compositeTestKeys(t)
	raw := append(mlKey.PublicKey().Bytes(), edKey.Public().(ed25519.PublicKey)...)
	key, err := ParseCompositePublicKey(raw)
	if err != nil {
		t.Fatalf("ParseCompositePublicKey() error = %v", err)
	}
	sum := sha512.Sum512([]byte("canonical signature input"))
	good := compositeTestSignature(t, mlKey, edKey, sum[:])
	mlLen := len(good) - ed25519.SignatureSize
	contextSigned, err := mlKey.SignDeterministic(sum[:], &mldsa.Options{Context: "dkim2"})
	if err != nil {
		t.Fatal(err)
	}
	other := sha512.Sum512([]byte("other input"))
	tests := map[string][]byte{
		"corrupted ml-dsa half":  flipByte(good, 10),
		"corrupted ed25519 half": flipByte(good, mlLen+5),
		"swapped halves":         append(append([]byte(nil), good[mlLen:]...), good[:mlLen]...),
		"truncated":              good[:len(good)-1],
		"trailing byte":          append(append([]byte(nil), good...), 0),
		"ml-dsa with context":    append(contextSigned, good[mlLen:]...),
		"ed25519 over other":     append(append([]byte(nil), good[:mlLen]...), ed25519.Sign(edKey, other[:])...),
		"ml-dsa only":            good[:mlLen],
	}
	for name, signatureBytes := range tests {
		if err := VerifyDigest(signature.AlgorithmMLDSA44Ed25519SHA512, key, sum[:], signatureBytes, Limits{}); err == nil {
			t.Fatalf("%s: VerifyDigest() accepted", name)
		}
	}
	if err := VerifyDigest(signature.AlgorithmMLDSA44Ed25519SHA512, key, sum[:32], good, Limits{}); ErrorCodeOf(err) != ErrorCodeInvalidDigestLength {
		t.Fatalf("SHA-256 digest error = %v", err)
	}
	ed := edKey.Public().(ed25519.PublicKey)
	if err := VerifyDigest(signature.AlgorithmEd25519SHA256, ed, sum[:], good[mlLen:], Limits{}); ErrorCodeOf(err) != ErrorCodeInvalidDigestLength {
		t.Fatalf("Ed25519 with SHA-512 digest error = %v", err)
	}
	if err := VerifyDigest(signature.AlgorithmMLDSA44Ed25519SHA512, ed, sum[:], good, Limits{}); ErrorCodeOf(err) != ErrorCodeWrongKeyType {
		t.Fatalf("composite with Ed25519 key error = %v", err)
	}
	for name, material := range map[string][]byte{
		"short":    raw[:len(raw)-1],
		"long":     append(append([]byte(nil), raw...), 0),
		"empty":    nil,
		"ml-dsa65": append(make([]byte, 1952), raw[len(raw)-32:]...),
	} {
		if _, err := ParseCompositePublicKey(material); err == nil {
			t.Fatalf("%s: ParseCompositePublicKey() accepted", name)
		}
	}
}

// flipByte returns a copy of input with one bit flipped at index.
func flipByte(input []byte, index int) []byte {
	output := append([]byte(nil), input...)
	output[index] ^= 0x01
	return output
}
