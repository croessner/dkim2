package dkim2

import (
	"context"
	"crypto/ed25519"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"
)

const stalwartVectorDirectory = "testdata/vectors/external/stalwart-mail-auth/"

// stalwartCompositePublicKey derives the raw DNS p= value from the Stalwart
// PKCS#8 test key: a fixed id-MLDSA44-Ed25519-SHA512 prefix followed by the
// ML-DSA-44 seed and the Ed25519 seed.
func stalwartCompositePublicKey(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(stalwartVectorDirectory + "mldsa44._domainkey.test1.dkim2.com.pem")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || len(block.Bytes) != 19+64 {
		t.Fatal("Stalwart composite key is not one 83-byte PKCS#8 block")
	}
	seeds := block.Bytes[19:]
	mlKey, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seeds[:32])
	if err != nil {
		t.Fatalf("mldsa.NewPrivateKey() error = %v", err)
	}
	edPublic := ed25519.NewKeyFromSeed(seeds[32:]).Public().(ed25519.PublicKey)
	return append(mlKey.PublicKey().Bytes(), edPublic...)
}

// TestVerifierAcceptsStalwartCompositeSignature is external interoperability
// evidence: a DKIM2 message Stalwart mail-auth signed with
// mldsa44-ed25519-sha512 under the LAMPS composite construction verifies.
func TestVerifierAcceptsStalwartCompositeSignature(t *testing.T) {
	message, err := os.ReadFile(stalwartVectorDirectory + "simple-mldsa44.eml")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	// The artifact is stored with LF line endings; Stalwart's own tests
	// normalize to CRLF the same way before parsing.
	message = []byte(strings.ReplaceAll(strings.ReplaceAll(string(message), "\r\n", "\n"), "\n", "\r\n"))
	message = foldStalwartSignatureValue(t, message)
	publicKey := stalwartCompositePublicKey(t)
	if base64.StdEncoding.EncodedLen(len(publicKey)) == 0 {
		t.Fatal("empty derived key")
	}
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return FoundCompositePublicKey(publicKey), nil
	}), WithVerificationClock(func() time.Time { return time.Unix(1_740_000_000, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), NewVerifyRequest(
		message, []byte("<sender@test1.dkim2.com>"), [][]byte{[]byte("<recipient@example.com>")},
	))
	if err != nil || result.State() != ResultStatePASS {
		t.Fatalf("Verify() state=%q reason=%q error=%v", result.State(), result.PrimaryReason(), err)
	}
}

// foldStalwartSignatureValue folds the base64 signature value of the
// Stalwart test artifact. Stalwart writes its expected-output files with the
// unfolded Dkim2Signed::write form, which exceeds the RFC 5322 998-octet line
// limit this implementation enforces; on the wire Stalwart folds through its
// HeaderFolder writer. Section 2.12 ignores FWS inside base64 values and
// Section 12.8 removes the signature value from the signed input, so the
// signed bytes are unchanged.
func foldStalwartSignatureValue(t *testing.T, message []byte) []byte {
	t.Helper()
	const marker = "mldsa44-ed25519-sha512:"
	text := string(message)
	start := strings.Index(text, marker)
	end := strings.Index(text[start:], ";")
	if start < 0 || end < 0 {
		t.Fatal("Stalwart artifact lacks one composite signature value")
	}
	start += len(marker)
	end += start - len(marker)
	value := text[start:end]
	var folded strings.Builder
	for len(value) > 76 {
		folded.WriteString(value[:76] + "\r\n ")
		value = value[76:]
	}
	folded.WriteString(value)
	return []byte(text[:start] + folded.String() + text[end:])
}
