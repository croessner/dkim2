package verify

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
)

// TestVerifyDeliveryStatusHeadersOnlyProvesHeadersAreNotAnEmptyBody verifies
// the dedicated DSN path accepts a cryptographically valid header-only original
// while rejecting the superficially similar delimited empty-body representation.
func TestVerifyDeliveryStatusHeadersOnlyProvesHeadersAreNotAnEmptyBody(t *testing.T) {
	fixture := newDeliveryStatusHeadersOnlyFixture(t)
	verifier := mustVerifierForFixture(t, fixture)
	request := Request{
		Message: fixture.message,
	}

	evidence, err := verifier.VerifyDeliveryStatusHeadersOnly(context.Background(), request)
	if err != nil || evidence.Status() != TargetStatusPass || !evidence.Valid() {
		t.Fatalf("VerifyDeliveryStatusHeadersOnly() evidence=%#v error=%v", evidence, err)
	}
	if result, verifyErr := verifier.VerifyCurrent(context.Background(), request); verifyErr != nil || result.Status() == TargetStatusPass {
		t.Fatalf("VerifyCurrent() status=%q error=%v, want non-pass because body evidence is unavailable", result.Status(), verifyErr)
	}

	delimited, parseErr := rawmsg.Parse([]byte(fixture.raw + "\r\n"))
	if parseErr != nil {
		t.Fatalf("rawmsg.Parse(delimited empty body) error=%v", parseErr)
	}
	_, err = verifier.VerifyDeliveryStatusHeadersOnly(context.Background(), Request{
		Message: delimited,
	})
	if !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("VerifyDeliveryStatusHeadersOnly(delimited empty body) error=%v, want invalid request", err)
	}
}

// TestVerifyDeliveryStatusHeadersOnlyDoesNotRequireFabricatedEnvelope proves
// the embedded DSN verifier authenticates protocol bytes without copied claims.
func TestVerifyDeliveryStatusHeadersOnlyDoesNotRequireFabricatedEnvelope(t *testing.T) {
	fixture := newDeliveryStatusHeadersOnlyFixture(t)
	verifier := mustVerifierForFixture(t, fixture)
	request := Request{Message: fixture.message}
	evidence, err := verifier.VerifyDeliveryStatusHeadersOnly(context.Background(), request)
	if err != nil || evidence.Status() != TargetStatusPass || !evidence.Valid() {
		t.Fatalf("VerifyDeliveryStatusHeadersOnly(expanded envelope) evidence=%#v error=%v", evidence, err)
	}
}

// TestVerifyDeliveryStatusHeadersOnlyRejectsChangedHeader verifies the
// headers-only path still authenticates the retained original header bytes.
func TestVerifyDeliveryStatusHeadersOnlyRejectsChangedHeader(t *testing.T) {
	fixture := newDeliveryStatusHeadersOnlyFixture(t)
	verifier := mustVerifierForFixture(t, fixture)
	changed, err := rawmsg.Parse([]byte(strings.Replace(fixture.raw, "Subject: Static verification", "Subject: altered", 1)))
	if err != nil {
		t.Fatalf("rawmsg.Parse(changed header) error=%v", err)
	}
	evidence, verifyErr := verifier.VerifyDeliveryStatusHeadersOnly(context.Background(), Request{
		Message: changed,
	})
	if verifyErr != nil || evidence.Status() != TargetStatusFail || evidence.Valid() {
		t.Fatalf("VerifyDeliveryStatusHeadersOnly(changed header) evidence=%#v error=%v", evidence, verifyErr)
	}
}

// newDeliveryStatusHeadersOnlyFixture constructs a cryptographically signed
// RFC 5322 header-only original with intentionally unavailable body evidence.
func newDeliveryStatusHeadersOnlyFixture(t *testing.T) verificationFixture {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error=%v", err)
	}
	canonicalizer := mustCanonicalizer(t)
	base := baseVerificationHeaders()
	baseMessage := mustParseVerificationMessage(t, base)
	headerHash, err := canonicalizer.HeaderHashFromMessage(baseMessage)
	if err != nil {
		t.Fatalf("HeaderHashFromMessage() error=%v", err)
	}
	headerDigest := mustDigest(t, headerHash)
	dummyBodyDigest := base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
	placeholder := base64.StdEncoding.EncodeToString(bytesOf(0xa5, placeholderSignatureLength(AlgorithmRSASHA256)))
	unsignedRaw := rawWithHeaderOnlySignature(
		headerDigest.Base64(), dummyBodyDigest, placeholder,
		[]byte("<sender@example.test>"), [][]byte{[]byte("<recipient@example.test>")},
	)
	unsigned := mustParseVerificationMessage(t, unsignedRaw)
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{Headers: unsigned.Headers(), TargetSequence: 1})
	if err != nil {
		t.Fatalf("SignatureInput() error=%v", err)
	}
	digest := sha256.Sum256(input.Bytes())
	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error=%v", err)
	}
	raw := rawWithHeaderOnlySignature(
		headerDigest.Base64(), dummyBodyDigest, base64.StdEncoding.EncodeToString(signatureBytes),
		[]byte("<sender@example.test>"), [][]byte{[]byte("<recipient@example.test>")},
	)
	fixture, err := parseVerificationFixture(raw)
	if err != nil {
		t.Fatalf("parseVerificationFixture() error=%v", err)
	}
	fixture.algorithm = AlgorithmRSASHA256
	fixture.rsaPublicKey = &key.PublicKey
	fixture.signatureBase64 = base64.StdEncoding.EncodeToString(signatureBytes)
	fixture.signatureBytes = signatureBytes
	fixture.headerDigestBase64 = headerDigest.Base64()
	fixture.bodyDigestBase64 = dummyBodyDigest
	return fixture
}

// rawWithHeaderOnlySignature renders a strict header-only DKIM2 test message.
func rawWithHeaderOnlySignature(headerDigest string, bodyDigest string, signatureText string, reversePath []byte, forwardPaths [][]byte) string {
	return baseVerificationHeaders() +
		"Message-Instance: m=1; h=sha256:" + headerDigest + ":" + bodyDigest + ";\r\n" +
		"DKIM2-Signature: i=1; m=1; t=" + "1700000000" + "; mf=" + encodeEnvelopePath(reversePath) + "; rt=" + encodeEnvelopePaths(forwardPaths) + "; d=" + testDomain + "; s=" + testSelector + ":" + string(AlgorithmRSASHA256) + ":" + signatureText + ";\r\n"
}
