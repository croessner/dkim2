package verify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha512"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/cryptodkim2"
	"github.com/croessner/dkim2/internal/signature"
)

// newCompositeVerificationFixture signs a synthetic DKIM2 message with the
// Draft-07 Section 3.4 mldsa44-ed25519-sha512 construction over SHA-512 of
// the exact Section 12.8 input, and returns its raw DNS public key.
func newCompositeVerificationFixture(t *testing.T) (verificationFixture, cryptodkim2.CompositePublicKey) {
	t.Helper()
	mlKey, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), bytes.Repeat([]byte{0x31}, mldsa.PrivateKeySize))
	if err != nil {
		t.Fatalf("mldsa.NewPrivateKey() error = %v", err)
	}
	edKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x13}, ed25519.SeedSize))
	fixture := buildVerificationFixtureWithEnvelopeAt(t, signature.AlgorithmMLDSA44Ed25519SHA512, testTimestampSeconds,
		[]byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}, func(_ []byte, input []byte) []byte {
			sum := sha512.Sum512(input)
			mlSignature, signErr := mlKey.SignDeterministic(sum[:], &mldsa.Options{})
			if signErr != nil {
				t.Fatalf("SignDeterministic() error = %v", signErr)
			}
			return append(mlSignature, ed25519.Sign(edKey, sum[:])...)
		})
	key, err := cryptodkim2.ParseCompositePublicKey(append(mlKey.PublicKey().Bytes(), edKey.Public().(ed25519.PublicKey)...))
	if err != nil {
		t.Fatalf("ParseCompositePublicKey() error = %v", err)
	}
	return fixture, key
}

// TestVerifierPassesDraft07CompositeSignature proves end-to-end verification
// of a composite DKIM2 signature, including the 2484-byte signature value in
// a parsed DKIM2-Signature field, and that a corrupted half fails.
func TestVerifierPassesDraft07CompositeSignature(t *testing.T) {
	fixture, key := newCompositeVerificationFixture(t)
	verifier := mustVerifierWithKeys(t, []StaticKey{{
		Domain: testDomain, Selector: testSelector, Algorithm: signature.AlgorithmMLDSA44Ed25519SHA512, Material: key,
	}})
	result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	if err != nil || result.Status() != TargetStatusPass {
		t.Fatalf("Verify() status=%q error=%v checks=%#v", result.Status(), err, result.Checks())
	}

	corrupted := append([]byte(nil), fixture.signatureBytes...)
	corrupted[len(corrupted)-1] ^= 0x01
	raw := strings.Replace(fixture.raw, fixture.signatureBase64, foldLongBase64(base64.StdEncoding.EncodeToString(corrupted)), 1)
	tampered, err := parseVerificationFixture(raw)
	if err != nil {
		t.Fatalf("parseVerificationFixture() error = %v", err)
	}
	result, err = verifier.Verify(context.Background(), Request{Message: tampered.message, Envelope: matchingEnvelope()})
	if err != nil || result.Status() != TargetStatusFail {
		t.Fatalf("tampered Verify() status=%q error=%v", result.Status(), err)
	}
}

// TestVerifierNeverPassesRSASHA1OnlySignatures reproduces DNS-01 Section 3.3:
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
