package cryptodkim2

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/croessner/dkim2/internal/signature"
)

type cryptoGoldenFile struct {
	Draft         string              `json:"draft"`
	RSABoundaries []rsaBoundaryVector `json:"rsa_boundaries"`
	RSA8192Verify rsaVerifyVector     `json:"rsa_8192_verify"`
	Ed25519Verify ed25519VerifyVector `json:"ed25519_verify"`
	MLDSA44       mldsa44Vector       `json:"mldsa44_vector"`
}

// mldsa44Vector is one pure ML-DSA-44 known-answer vector over a fixed
// Section 12.8 input with the "DKIM2" context string.
type mldsa44Vector struct {
	Seed                 string `json:"seed_base64"`
	PrivatePKCS8         string `json:"private_pkcs8_base64"`
	PublicSPKI           string `json:"public_spki_base64"`
	PublicRaw            string `json:"public_raw_base64"`
	Input                string `json:"input_base64"`
	DeterministicSig     string `json:"deterministic_signature_base64"`
	IndependentHedgedSig string `json:"openssl_hedged_signature_base64"`
}

type ed25519VerifyVector struct {
	PublicKey string `json:"public_base64"`
	Digest    string `json:"digest_base64"`
	Signature string `json:"signature_base64"`
}

type rsaVerifyVector struct {
	PublicDER string `json:"public_der_base64"`
	Digest    string `json:"digest_base64"`
	Signature string `json:"signature_base64"`
}

type rsaBoundaryVector struct {
	Name     string `json:"name"`
	Bits     int    `json:"bits"`
	Exponent int    `json:"exponent"`
	Valid    bool   `json:"valid"`
}

// loadCryptoGolden reads the closed cryptographic conformance corpus.
func loadCryptoGolden(t *testing.T) cryptoGoldenFile {
	t.Helper()
	data, err := os.ReadFile("../../testdata/vectors/draft-ietf-dkim-dkim2-spec-08/custody-crypto-golden.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var golden cryptoGoldenFile
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if golden.Draft != "draft-ietf-dkim-dkim2-spec-08" || len(golden.RSABoundaries) == 0 {
		t.Fatal("crypto golden file has wrong or empty draft contract")
	}
	return golden
}

// TestCryptoPublicKeyPolicyBoundaryGoldenVectors locks local RSA acceptance limits.
func TestCryptoPublicKeyPolicyBoundaryGoldenVectors(t *testing.T) {
	golden := loadCryptoGolden(t)
	for _, vector := range golden.RSABoundaries {
		t.Run(vector.Name, func(t *testing.T) {
			_, validationErr := ValidatePublicKey(signature.AlgorithmRSASHA256, syntheticRSAKey(vector.Bits, vector.Exponent), Limits{})
			if (validationErr == nil) != vector.Valid {
				t.Fatalf("ValidatePublicKey(%d,%d) code=%s valid=%v", vector.Bits, vector.Exponent, ErrorCodeOf(validationErr), vector.Valid)
			}
		})
	}
}

// TestDraft08CryptoVerificationGoldenVectors locks RSA and Ed25519 verification bytes.
func TestDraft08CryptoVerificationGoldenVectors(t *testing.T) {
	golden := loadCryptoGolden(t)
	publicDER, err := base64.StdEncoding.DecodeString(golden.RSA8192Verify.PublicDER)
	if err != nil {
		t.Fatalf("public DER base64 error = %v", err)
	}
	publicKey, err := x509.ParsePKCS1PublicKey(publicDER)
	if err != nil {
		t.Fatalf("ParsePKCS1PublicKey() error = %v", err)
	}
	digest, err := base64.StdEncoding.DecodeString(golden.RSA8192Verify.Digest)
	if err != nil {
		t.Fatalf("digest base64 error = %v", err)
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(golden.RSA8192Verify.Signature)
	if err != nil {
		t.Fatalf("signature base64 error = %v", err)
	}
	if publicKey.N.BitLen() != 8192 || publicKey.E != 65537 || len(signatureBytes) != 1024 {
		t.Fatal("RSA-8192 verification vector has incoherent public dimensions")
	}
	if err := VerifyRepresentative(signature.AlgorithmRSASHA256, publicKey, digest, signatureBytes, Limits{}); err != nil {
		t.Fatalf("RSA-8192 VerifyRepresentative() code=%s", ErrorCodeOf(err))
	}
	edPublic, err := base64.StdEncoding.DecodeString(golden.Ed25519Verify.PublicKey)
	if err != nil || len(edPublic) != ed25519.PublicKeySize {
		t.Fatalf("Ed25519 public key vector error=%v length=%d", err, len(edPublic))
	}
	edDigest, err := base64.StdEncoding.DecodeString(golden.Ed25519Verify.Digest)
	if err != nil || len(edDigest) != 32 {
		t.Fatalf("Ed25519 digest vector error=%v length=%d", err, len(edDigest))
	}
	edSignature, err := base64.StdEncoding.DecodeString(golden.Ed25519Verify.Signature)
	if err != nil || len(edSignature) != ed25519.SignatureSize {
		t.Fatalf("Ed25519 signature vector error=%v length=%d", err, len(edSignature))
	}
	if err := VerifyRepresentative(signature.AlgorithmEd25519SHA256, ed25519.PublicKey(edPublic), edDigest, edSignature, Limits{}); err != nil {
		t.Fatalf("Ed25519 VerifyRepresentative() code=%s", ErrorCodeOf(err))
	}
}
