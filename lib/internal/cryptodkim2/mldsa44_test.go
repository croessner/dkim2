package cryptodkim2

import (
	"bytes"
	"crypto/fips140"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/croessner/dkim2/internal/signature"
)

// decodeVectorField decodes one base64 golden field or fails the test.
func decodeVectorField(t *testing.T, name, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 {
		t.Fatalf("%s base64 error=%v", name, err)
	}
	return decoded
}

// TestMLDSA44KnownAnswerVector locks the Draft-08 Section 3.4 construction:
// the fixed seed derives the stored 1312-octet public key, deterministic
// ML-DSA.Sign with ctx "DKIM2" over the complete input reproduces the stored
// signature (OpenSSL 4.0.3 produced the same bytes), the shared verifier
// accepts both it and an independently produced OpenSSL hedged signature,
// and neither verifies without the context string.
func TestMLDSA44KnownAnswerVector(t *testing.T) {
	vector := loadCryptoGolden(t).MLDSA44
	seed := decodeVectorField(t, "seed", vector.Seed)
	raw := decodeVectorField(t, "public raw", vector.PublicRaw)
	spki := decodeVectorField(t, "public SPKI", vector.PublicSPKI)
	input := decodeVectorField(t, "input", vector.Input)
	deterministic := decodeVectorField(t, "deterministic signature", vector.DeterministicSig)
	hedged := decodeVectorField(t, "hedged signature", vector.IndependentHedgedSig)
	if len(raw) != MLDSA44PublicKeyBytes || len(deterministic) != MLDSA44SignatureBytes || len(hedged) != MLDSA44SignatureBytes {
		t.Fatal("ML-DSA-44 vector has incoherent sizes")
	}
	if len(vector.PublicRaw) != 1752 || len(vector.DeterministicSig) != 3228 {
		t.Fatal("ML-DSA-44 vector base64 lengths differ from Draft-08 Sections 3.4 and 14.5")
	}

	private, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	if err != nil || !bytes.Equal(private.PublicKey().Bytes(), raw) {
		t.Fatalf("seed does not derive the stored public key: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil || !bytes.Equal(pkcs8, decodeVectorField(t, "private PKCS#8", vector.PrivatePKCS8)) {
		t.Fatal("seed-only PKCS#8 encoding differs from the stored vector")
	}
	parsed, err := ParseSigningPublicKeySPKI(signature.AlgorithmMLDSA44, spki)
	if err != nil || !PublicKeysEqual(parsed, private.PublicKey()) {
		t.Fatalf("ParseSigningPublicKeySPKI() code=%s", ErrorCodeOf(err))
	}
	resigned, err := private.SignDeterministic(input, MLDSA44SignerOptions())
	if err != nil || !bytes.Equal(resigned, deterministic) {
		t.Fatal("deterministic ML-DSA.Sign with ctx DKIM2 does not reproduce the vector")
	}

	public, err := ParseMLDSA44PublicKey(raw)
	if err != nil {
		t.Fatalf("ParseMLDSA44PublicKey() code=%s", ErrorCodeOf(err))
	}
	representative, err := MessageRepresentative(signature.AlgorithmMLDSA44, input)
	if err != nil || !bytes.Equal(representative, input) {
		t.Fatal("mldsa44 representative is not the complete input")
	}
	for name, candidate := range map[string][]byte{"deterministic": deterministic, "independent hedged": hedged} {
		if err := VerifyRepresentative(signature.AlgorithmMLDSA44, public, representative, candidate, Limits{}); err != nil {
			t.Fatalf("%s VerifyRepresentative() code=%s", name, ErrorCodeOf(err))
		}
		if mldsa.Verify(public, input, candidate, nil) == nil {
			t.Fatalf("%s signature verified without the DKIM2 context string", name)
		}
		digest := sha256.Sum256(input)
		if mldsa.Verify(public, digest[:], candidate, MLDSA44SignerOptions()) == nil {
			t.Fatalf("%s signature verified over a pre-hash", name)
		}
	}
	tampered := bytes.Clone(input)
	tampered[len(tampered)-3] ^= 1
	if err := VerifyRepresentative(signature.AlgorithmMLDSA44, public, tampered, deterministic, Limits{}); ErrorCodeOf(err) != ErrorCodeSignatureMismatch {
		t.Fatalf("tampered input code=%s", ErrorCodeOf(err))
	}
}

// TestMLDSA44ExactLengths is the wrong-length reproducer for keys and
// signatures: a key that is not exactly 1312 octets is invalid_key (Section
// 14.5 "malformed"), and a signature that is not exactly 2420 octets is an
// invalid signature length.
func TestMLDSA44ExactLengths(t *testing.T) {
	private, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	raw := private.PublicKey().Bytes()
	for _, candidate := range [][]byte{raw[:MLDSA44PublicKeyBytes-1], append(bytes.Clone(raw), 0), nil, make([]byte, 32)} {
		if _, err := ParseMLDSA44PublicKey(candidate); ErrorCodeOf(err) != ErrorCodeInvalidKey {
			t.Fatalf("%d-octet key code=%s", len(candidate), ErrorCodeOf(err))
		}
	}
	public := private.PublicKey()
	for _, length := range []int{MLDSA44SignatureBytes - 1, MLDSA44SignatureBytes + 1, 64, 1024} {
		if err := ValidateSignatureLength(signature.AlgorithmMLDSA44, public, length, Limits{}); ErrorCodeOf(err) != ErrorCodeInvalidSignatureLength {
			t.Fatalf("%d-octet signature code=%s", length, ErrorCodeOf(err))
		}
	}
	if err := ValidateSignatureLength(signature.AlgorithmMLDSA44, public, MLDSA44SignatureBytes, Limits{}); err != nil {
		t.Fatalf("exact signature code=%s", ErrorCodeOf(err))
	}
	narrowed := DefaultLimits()
	narrowed.MaxSignatureBytes = maxRSASignatureBytes
	if err := ValidateSignatureLength(signature.AlgorithmMLDSA44, public, MLDSA44SignatureBytes, narrowed); ErrorCodeOf(err) != ErrorCodeInvalidSignatureLength {
		t.Fatalf("narrowed cap code=%s", ErrorCodeOf(err))
	}
	if err := ValidateSignatureLength(signature.AlgorithmRSASHA256, syntheticRSAKey(8192, 65537), MLDSA44SignatureBytes, Limits{}); ErrorCodeOf(err) != ErrorCodeInvalidSignatureLength {
		t.Fatalf("RSA value above its own bound code=%s", ErrorCodeOf(err))
	}
	signatureBytes, err := private.Sign(rand.Reader, []byte("input"), MLDSA44SignerOptions())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRepresentative(signature.AlgorithmMLDSA44, public, []byte("input"), signatureBytes[:MLDSA44SignatureBytes-1], Limits{}); ErrorCodeOf(err) != ErrorCodeInvalidSignatureLength {
		t.Fatalf("short signature verify code=%s", ErrorCodeOf(err))
	}
	if _, err := ValidatePublicKey(signature.AlgorithmMLDSA44, raw, Limits{}); ErrorCodeOf(err) != ErrorCodeWrongKeyType {
		t.Fatalf("raw bytes as key code=%s", ErrorCodeOf(err))
	}
	other, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatePublicKey(signature.AlgorithmMLDSA44, other.PublicKey(), Limits{}); ErrorCodeOf(err) != ErrorCodeInvalidKey {
		t.Fatalf("ML-DSA-65 key code=%s", ErrorCodeOf(err))
	}
	if _, err := ValidatePublicKey(signature.AlgorithmEd25519SHA256, public, Limits{}); ErrorCodeOf(err) != ErrorCodeWrongKeyType {
		t.Fatalf("ML-DSA key for ed25519 code=%s", ErrorCodeOf(err))
	}
}

// TestMessageRepresentativeOwnsAlgorithmInputs proves the single owner maps
// classical algorithms to the SHA-256 digest and mldsa44 to the input.
func TestMessageRepresentativeOwnsAlgorithmInputs(t *testing.T) {
	input := []byte("dkim2-signature:i=1;\r\n")
	digest := sha256.Sum256(input)
	for _, algorithm := range []signature.Algorithm{signature.AlgorithmRSASHA256, signature.AlgorithmEd25519SHA256} {
		representative, err := MessageRepresentative(algorithm, input)
		if err != nil || !bytes.Equal(representative, digest[:]) || SignsInputDirectly(algorithm) {
			t.Fatalf("%s representative is not the SHA-256 digest", algorithm)
		}
	}
	representative, err := MessageRepresentative(signature.AlgorithmMLDSA44, input)
	if err != nil || !bytes.Equal(representative, input) || !SignsInputDirectly(signature.AlgorithmMLDSA44) {
		t.Fatal("mldsa44 representative is not the input")
	}
	representative[0] ^= 1
	if input[0] != 'd' {
		t.Fatal("mldsa44 representative aliases the caller input")
	}
	if _, err := MessageRepresentative(signature.Algorithm("mldsa44-ed25519-sha512"), input); ErrorCodeOf(err) != ErrorCodeUnsupportedAlgorithm {
		t.Fatalf("composite representative code=%s", ErrorCodeOf(err))
	}
	if _, err := MessageRepresentative(signature.AlgorithmMLDSA44, nil); err == nil {
		t.Fatal("empty input produced a representative")
	}
	if !ValidRepresentativeLength(signature.AlgorithmMLDSA44, 1) || ValidRepresentativeLength(signature.AlgorithmMLDSA44, 0) ||
		ValidRepresentativeLength(signature.AlgorithmEd25519SHA256, 64) {
		t.Fatal("representative length contract changed")
	}
}

// TestMLDSA44AvailabilityFollowsCryptographicModule pins the fail-closed
// runtime guard. Built against the FIPS 140-3 Go Cryptographic Module
// v1.0.0 (make test-fips140-mldsa44), ML-DSA is unavailable and every mldsa44
// entry point reports algorithm_unavailable; otherwise it is available.
func TestMLDSA44AvailabilityFollowsCryptographicModule(t *testing.T) {
	err := MLDSA44Available()
	if fips140.Version() == "v1.0.0" {
		if ErrorCodeOf(err) != ErrorCodeAlgorithmUnavailable {
			t.Fatalf("MLDSA44Available() under FIPS v1.0.0 code=%s", ErrorCodeOf(err))
		}
		if _, parseErr := ParseMLDSA44PublicKey(make([]byte, MLDSA44PublicKeyBytes)); ErrorCodeOf(parseErr) != ErrorCodeAlgorithmUnavailable {
			t.Fatalf("ParseMLDSA44PublicKey() under FIPS v1.0.0 code=%s", ErrorCodeOf(parseErr))
		}
		return
	}
	if err != nil {
		t.Fatalf("MLDSA44Available() code=%s", ErrorCodeOf(err))
	}
}
