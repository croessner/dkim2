package dkim2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha512"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
)

const (
	compositeTestPublicKeyBytes = 1312 + ed25519.PublicKeySize
	compositeTestSignatureBytes = 2420 + ed25519.SignatureSize
	compositeTestFoldWidth      = 76
)

// publicCompositeFixture builds a current DKIM2 message signed with the
// Draft-07 Section 3.4 mldsa44-ed25519-sha512 construction: SHA-512 over the
// Section 12.8 input, pure ML-DSA-44 with an empty context, then PureEd25519
// over the same 64-byte digest. It returns the raw message, the raw DNS p=
// key form, and the decoded signature value.
func publicCompositeFixture(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	mlKey, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), bytes.Repeat([]byte{0x42}, mldsa.PrivateKeySize))
	if err != nil {
		t.Fatalf("mldsa.NewPrivateKey() error = %v", err)
	}
	edKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize))
	placeholder := foldCompositeBase64(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, compositeTestSignatureBytes)))
	unsigned := publicFixtureForAlgorithm(t, string(AlgorithmMLDSA44Ed25519SHA512), placeholder)
	message, err := rawmsg.Parse(unsigned)
	if err != nil {
		t.Fatalf("rawmsg.Parse(unsigned) error = %v", err)
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{Headers: message.Headers(), TargetSequence: 1})
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}
	digest := sha512.Sum512(input.Bytes())
	mlSignature, err := mlKey.SignDeterministic(digest[:], &mldsa.Options{})
	if err != nil {
		t.Fatalf("SignDeterministic() error = %v", err)
	}
	signatureBytes := append(mlSignature, ed25519.Sign(edKey, digest[:])...)
	if len(signatureBytes) != compositeTestSignatureBytes {
		t.Fatalf("composite signature length = %d", len(signatureBytes))
	}
	signed := bytes.Replace(unsigned, []byte(placeholder), []byte(foldCompositeBase64(base64.StdEncoding.EncodeToString(signatureBytes))), 1)
	publicKey := append(mlKey.PublicKey().Bytes(), edKey.Public().(ed25519.PublicKey)...)
	return signed, publicKey, signatureBytes
}

// foldCompositeBase64 folds a long base64 tag value with CRLF HTAB so every
// RFC 5322 header line stays well below the 998-octet limit.
func foldCompositeBase64(value string) string {
	var builder strings.Builder
	for start := 0; start < len(value); start += compositeTestFoldWidth {
		if start > 0 {
			builder.WriteString("\r\n\t")
		}
		builder.WriteString(value[start:min(start+compositeTestFoldWidth, len(value))])
	}
	return builder.String()
}

// verifyCompositeFixture runs one public facade verification at the fixture clock.
func verifyCompositeFixture(t *testing.T, provider PublicKeyProvider, raw []byte) VerifyResult {
	t.Helper()
	verifier, err := NewVerifier(provider, WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	return result
}

// assertCompositeSignatureFact checks the single public composite signature-set fact.
func assertCompositeSignatureFact(t *testing.T, result VerifyResult, status SignatureStatus, reason ReasonCode) {
	t.Helper()
	sets := result.SignatureSets()
	if len(sets) != 1 || sets[0].Algorithm() != AlgorithmMLDSA44Ed25519SHA512 ||
		sets[0].Status() != status || sets[0].Reason() != reason {
		t.Fatalf("signature sets = %#v, want %q/%q", sets, status, reason)
	}
}

// TestFacadeVerifiesCompositeWithCustomProvider proves a composite-signed
// message reaches PASS through a caller-owned provider and that the found
// constructor detaches provider-owned key storage.
func TestFacadeVerifiesCompositeWithCustomProvider(t *testing.T) {
	raw, publicKey, _ := publicCompositeFixture(t)
	result := verifyCompositeFixture(t, publicProviderFunc(func(_ context.Context, query PublicKeyQuery) (PublicKeyResult, error) {
		if query.Algorithm() != AlgorithmMLDSA44Ed25519SHA512 || query.Selector() != "selector.test" {
			t.Errorf("query = %q/%q", query.Algorithm(), query.Selector())
		}
		found := FoundCompositePublicKey(publicKey)
		publicKey[0] ^= 0xff
		return found, nil
	}), raw)
	if result.State() != ResultStatePASS || result.PrimaryReason() != ReasonNone {
		t.Fatalf("Verify() = %q/%q", result.State(), result.PrimaryReason())
	}
	assertCompositeSignatureFact(t, result, SignatureStatusPASS, ReasonNone)
}

// TestFacadeVerifiesCompositeThroughDNSProvider proves DNS-01
// k=mldsa44-ed25519-sha512 records decode into verifiable composite keys.
func TestFacadeVerifiesCompositeThroughDNSProvider(t *testing.T) {
	raw, publicKey, _ := publicCompositeFixture(t)
	result := verifyCompositeFixture(t, compositeDNSProvider(t, publicKey), raw)
	if result.State() != ResultStatePASS || result.PrimaryReason() != ReasonNone {
		t.Fatalf("Verify() = %q/%q", result.State(), result.PrimaryReason())
	}
	assertCompositeSignatureFact(t, result, SignatureStatusPASS, ReasonNone)
}

// TestFacadeFailsCorruptedCompositeSignature proves a flipped bit in the
// Ed25519 half of the composite signature yields FAIL, not PASS.
func TestFacadeFailsCorruptedCompositeSignature(t *testing.T) {
	raw, publicKey, signatureBytes := publicCompositeFixture(t)
	corrupted := bytes.Clone(signatureBytes)
	corrupted[len(corrupted)-1] ^= 0x01
	tampered := bytes.Replace(raw,
		[]byte(foldCompositeBase64(base64.StdEncoding.EncodeToString(signatureBytes))),
		[]byte(foldCompositeBase64(base64.StdEncoding.EncodeToString(corrupted))), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("signature replacement did not change the fixture")
	}
	result := verifyCompositeFixture(t, compositeDNSProvider(t, publicKey), tampered)
	if result.State() != ResultStateFAIL || result.PrimaryReason() != ReasonSignatureMismatch {
		t.Fatalf("Verify() = %q/%q", result.State(), result.PrimaryReason())
	}
	assertCompositeSignatureFact(t, result, SignatureStatusFAIL, ReasonSignatureMismatch)
}

// TestFacadeRejectsOversizedCompositeDNSKey proves a 1345-byte composite p=
// fails closed as an invalid key.
func TestFacadeRejectsOversizedCompositeDNSKey(t *testing.T) {
	raw, publicKey, _ := publicCompositeFixture(t)
	result := verifyCompositeFixture(t, compositeDNSProvider(t, append(publicKey, 0x00)), raw)
	if result.State() != ResultStatePERMERROR || result.PrimaryReason() != ReasonInvalidKey {
		t.Fatalf("Verify() = %q/%q", result.State(), result.PrimaryReason())
	}
	assertCompositeSignatureFact(t, result, SignatureStatusPERMERROR, ReasonInvalidKey)
}

// TestFoundCompositePublicKeyFailsClosedAndClones proves the public
// constructor rejects every non-canonical size and returns detached copies.
func TestFoundCompositePublicKeyFailsClosedAndClones(t *testing.T) {
	_, publicKey, _ := publicCompositeFixture(t)
	for _, size := range []int{0, ed25519.PublicKeySize, compositeTestPublicKeyBytes - 1, compositeTestPublicKeyBytes + 1} {
		result := FoundCompositePublicKey(make([]byte, size))
		if result.Status() != PublicKeyStatusInvalid || result.Algorithm() != AlgorithmMLDSA44Ed25519SHA512 {
			t.Fatalf("size %d: status=%q algorithm=%q", size, result.Status(), result.Algorithm())
		}
		if _, ok := result.CompositePublicKey(); ok {
			t.Fatalf("size %d: invalid result exposed composite material", size)
		}
	}
	result := FoundCompositePublicKey(publicKey)
	first, ok := result.CompositePublicKey()
	if !ok || result.Status() != PublicKeyStatusFound || !bytes.Equal(first, publicKey) {
		t.Fatalf("found composite = %q ok=%v", result.Status(), ok)
	}
	if _, hasRSA := result.RSAPublicKey(); hasRSA {
		t.Fatal("composite result exposed RSA material")
	}
	if _, hasEd := result.Ed25519PublicKey(); hasEd {
		t.Fatal("composite result exposed Ed25519 material")
	}
	first[0] ^= 0xff
	second, _ := result.CompositePublicKey()
	if !bytes.Equal(second, publicKey) {
		t.Fatal("composite accessor exposed mutable result storage")
	}
	if !AlgorithmMLDSA44Ed25519SHA512.Known() {
		t.Fatal("composite algorithm is outside the public vocabulary")
	}
}

// compositeDNSProvider serves one DNS-01 composite key record for the fixture selector.
func compositeDNSProvider(t *testing.T, publicKey []byte) *DNSPublicKeyProvider {
	t.Helper()
	record := []byte("v=DKIM1; k=mldsa44-ed25519-sha512; p=" + base64.StdEncoding.EncodeToString(publicKey))
	provider, err := NewDNSPublicKeyProvider(txtTransportFunc(func(_ context.Context, owner string) (TXTLookupResult, error) {
		if owner != "selector.test._domainkey.example.test." {
			t.Errorf("owner = %q", owner)
		}
		return mustPublicFoundLookup(t, record), nil
	}))
	if err != nil {
		t.Fatalf("NewDNSPublicKeyProvider() error = %v", err)
	}
	return provider
}
