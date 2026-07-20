package cryptodkim2

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/signature"
)

// TestValidatePublicKeyEnforcesSharedRSAAndEd25519Policy locks the leaf key contract.
func TestValidatePublicKeyEnforcesSharedRSAAndEd25519Policy(t *testing.T) {
	validRSA := syntheticRSAKey(1024, 65537)
	validated, err := ValidatePublicKey(signature.AlgorithmRSASHA256, validRSA, Limits{})
	if err != nil {
		t.Fatalf("valid RSA code=%s", ErrorCodeOf(err))
	}
	cloned := validated.(*rsa.PublicKey)
	validRSA.N.SetInt64(3)
	if cloned.N.BitLen() != 1024 {
		t.Fatal("validated RSA key retained caller storage")
	}
	maxRSA := syntheticRSAKey(8192, 65537)
	if _, err := ValidatePublicKey(signature.AlgorithmRSASHA256, maxRSA, Limits{}); err != nil {
		t.Fatalf("exact maximum RSA code=%s", ErrorCodeOf(err))
	}
	for _, length := range []int{1024, 1023, 1025} {
		err := ValidateSignatureLength(signature.AlgorithmRSASHA256, maxRSA, length, Limits{})
		if length == 1024 && err != nil {
			t.Fatalf("exact RSA signature length code=%s", ErrorCodeOf(err))
		}
		if length != 1024 && ErrorCodeOf(err) != ErrorCodeInvalidSignatureLength {
			t.Fatalf("non-exact RSA signature length=%d code=%s", length, ErrorCodeOf(err))
		}
	}
	for _, test := range []struct {
		name string
		key  *rsa.PublicKey
		code ErrorCode
	}{
		{name: "bad exponent", key: syntheticRSAKey(1024, 3), code: ErrorCodeKeyPolicyRejected},
		{name: "below minimum", key: syntheticRSAKey(1023, 65537), code: ErrorCodeKeyPolicyRejected},
		{name: "above maximum", key: syntheticRSAKey(8193, 65537), code: ErrorCodeKeyPolicyRejected},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ValidatePublicKey(signature.AlgorithmRSASHA256, test.key, Limits{}); ErrorCodeOf(err) != test.code {
				t.Fatalf("ValidatePublicKey() code=%s", ErrorCodeOf(err))
			}
		})
	}
	ed := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	if _, err := ValidatePublicKey(signature.AlgorithmEd25519SHA256, ed, Limits{}); err != nil {
		t.Fatalf("valid Ed25519 code=%s", ErrorCodeOf(err))
	}
	if _, err := ValidatePublicKey(signature.AlgorithmEd25519SHA256, ed[:31], Limits{}); ErrorCodeOf(err) != ErrorCodeInvalidKey {
		t.Fatalf("short Ed25519 code=%s", ErrorCodeOf(err))
	}
	for _, length := range []int{64, 63, 65} {
		err := ValidateSignatureLength(signature.AlgorithmEd25519SHA256, ed, length, Limits{})
		if length == 64 && err != nil {
			t.Fatalf("exact Ed25519 signature length code=%s", ErrorCodeOf(err))
		}
		if length != 64 && ErrorCodeOf(err) != ErrorCodeInvalidSignatureLength {
			t.Fatalf("non-exact Ed25519 signature length=%d code=%s", length, ErrorCodeOf(err))
		}
	}
	if _, err := ValidatePublicKey(signature.AlgorithmEd25519SHA256, validRSA, Limits{}); ErrorCodeOf(err) != ErrorCodeWrongKeyType {
		t.Fatalf("algorithm/key mismatch code=%s", ErrorCodeOf(err))
	}
}

// TestCryptoErrorFormattingNeverIncludesCallerContent verifies all fmt paths.
func TestCryptoErrorFormattingNeverIncludesCallerContent(t *testing.T) {
	err := newError(ErrorCodeInvalidKey)
	for _, formatted := range []string{
		err.Error(), err.GoString(), fmt.Sprintf("%s", err), fmt.Sprintf("%q", err),
		fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err),
	} {
		if strings.Contains(formatted, "PUBLICKEYSECRET") || !strings.Contains(formatted, "code=invalid_key") {
			t.Fatalf("unsafe crypto formatting %q", formatted)
		}
	}
}

// TestVerifyDigestUsesOneSharedAlgorithmLeaf proves RSA and Ed25519 verification semantics.
func TestVerifyDigestUsesOneSharedAlgorithmLeaf(t *testing.T) {
	digest := make([]byte, crypto.SHA256.Size())
	for index := range digest {
		digest[index] = byte(index + 1)
	}
	rsaPrivate, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal("rsa.GenerateKey() failed")
	}
	rsaSignature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivate, crypto.SHA256, digest)
	if err != nil {
		t.Fatal("rsa.SignPKCS1v15() failed")
	}
	if err := VerifyDigest(signature.AlgorithmRSASHA256, &rsaPrivate.PublicKey, digest, rsaSignature, Limits{}); err != nil {
		t.Fatalf("RSA verify code=%s", ErrorCodeOf(err))
	}
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("ed25519.GenerateKey() failed")
	}
	edSignature := ed25519.Sign(edPrivate, digest)
	if err := VerifyDigest(signature.AlgorithmEd25519SHA256, edPublic, digest, edSignature, Limits{}); err != nil {
		t.Fatalf("Ed25519 verify code=%s", ErrorCodeOf(err))
	}
	edSignature[0] ^= 1
	if err := VerifyDigest(signature.AlgorithmEd25519SHA256, edPublic, digest, edSignature, Limits{}); ErrorCodeOf(err) != ErrorCodeSignatureMismatch {
		t.Fatalf("Ed25519 mismatch code=%s", ErrorCodeOf(err))
	}
	if err := VerifyDigest(signature.AlgorithmEd25519SHA256, edPublic, digest[:31], edSignature, Limits{}); ErrorCodeOf(err) != ErrorCodeInvalidDigestLength {
		t.Fatalf("digest length code=%s", ErrorCodeOf(err))
	}
}

// syntheticRSAKey returns a structurally shaped RSA public key without expensive generation.
func syntheticRSAKey(bits int, exponent int) *rsa.PublicKey {
	modulus := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	modulus.SetBit(modulus, 0, 1)
	return &rsa.PublicKey{N: modulus, E: exponent}
}
