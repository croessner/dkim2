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

// TestVerifyDeliveryStatusHeadersOnlyHashMatrix proves every supported retained-header tuple is checked.
func TestVerifyDeliveryStatusHeadersOnlyHashMatrix(t *testing.T) {
	tests := []struct {
		name       string
		algorithms []canonical.HashAlgorithm
		mismatch   canonical.HashAlgorithm
		unknown    bool
		status     TargetStatus
	}{
		{testHashCaseSHA512Only, []canonical.HashAlgorithm{canonical.HashAlgorithmSHA512}, "", false, TargetStatusPass},
		{"dual pass", []canonical.HashAlgorithm{canonical.HashAlgorithmSHA256, canonical.HashAlgorithmSHA512}, "", false, TargetStatusPass},
		{testHashCaseDualMismatch, []canonical.HashAlgorithm{canonical.HashAlgorithmSHA256, canonical.HashAlgorithmSHA512}, canonical.HashAlgorithmSHA512, false, TargetStatusFail},
		{"unknown only", nil, "", true, TargetStatusFail},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDeliveryStatusHeadersOnlyHashFixture(t, test.algorithms, test.mismatch, test.unknown)
			evidence, err := mustVerifierForFixture(t, fixture).VerifyDeliveryStatusHeadersOnly(context.Background(), Request{Message: fixture.message})
			if err != nil || evidence.Status() != test.status || evidence.Valid() != (test.status == TargetStatusPass) {
				t.Fatalf("VerifyDeliveryStatusHeadersOnly() = status:%q valid:%t error:%v", evidence.Status(), evidence.Valid(), err)
			}
		})
	}
}

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
	return newDeliveryStatusHeadersOnlyHashFixture(t, []canonical.HashAlgorithm{canonical.HashAlgorithmSHA256}, "", false)
}

// newDeliveryStatusHeadersOnlyHashFixture constructs a signed header-only message with controlled hash tuples.
func newDeliveryStatusHeadersOnlyHashFixture(t *testing.T, algorithms []canonical.HashAlgorithm, mismatch canonical.HashAlgorithm, unknown bool) verificationFixture {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error=%v", err)
	}
	base := baseVerificationHeaders()
	baseMessage := mustParseVerificationMessage(t, base)
	sets := make([]string, 0, len(algorithms))
	for _, algorithm := range algorithms {
		canonicalizer, newErr := canonical.NewCanonicalizer(canonical.WithHashAlgorithm(algorithm))
		if newErr != nil {
			t.Fatal(newErr)
		}
		headerHash, headerErr := canonicalizer.HeaderHashFromMessage(baseMessage)
		if headerErr != nil {
			t.Fatalf("HeaderHashFromMessage() error=%v", headerErr)
		}
		headerBytes := mustDigest(t, headerHash).Bytes()
		if algorithm == mismatch {
			headerBytes[0] ^= 0xff
		}
		bodyLength := sha256.Size
		if algorithm == canonical.HashAlgorithmSHA512 {
			bodyLength = 64
		}
		sets = append(sets, string(algorithm)+":"+base64.StdEncoding.EncodeToString(headerBytes)+":"+base64.StdEncoding.EncodeToString(make([]byte, bodyLength)))
	}
	if unknown {
		sets = []string{"future:" + base64.StdEncoding.EncodeToString([]byte("unknown header")) + ":" + base64.StdEncoding.EncodeToString([]byte("unknown body"))}
	}
	placeholder := base64.StdEncoding.EncodeToString(bytesOf(0xa5, placeholderSignatureLength(AlgorithmRSASHA256)))
	unsignedRaw := rawWithHeaderOnlyHashSets(
		strings.Join(sets, ","), placeholder,
		[]byte("<sender@example.test>"), [][]byte{[]byte("<recipient@example.test>")},
	)
	unsigned := mustParseVerificationMessage(t, unsignedRaw)
	canonicalizer := mustCanonicalizer(t)
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{Headers: unsigned.Headers(), TargetSequence: 1})
	if err != nil {
		t.Fatalf("SignatureInput() error=%v", err)
	}
	digest := sha256.Sum256(input.Bytes())
	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error=%v", err)
	}
	raw := rawWithHeaderOnlyHashSets(
		strings.Join(sets, ","), base64.StdEncoding.EncodeToString(signatureBytes),
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
	return fixture
}

// rawWithHeaderOnlyHashSets renders a strict header-only message with a complete h= list.
func rawWithHeaderOnlyHashSets(hashSets string, signatureText string, reversePath []byte, forwardPaths [][]byte) string {
	return baseVerificationHeaders() +
		"Message-Instance: m=1; h=" + hashSets + ";\r\n" +
		"DKIM2-Signature: i=1; m=1; t=" + "1700000000" + "; mf=" + encodeEnvelopePath(reversePath) + "; rt=" + encodeEnvelopePaths(forwardPaths) + "; d=" + testDomain + "; s=" + testSelector + ":" + string(AlgorithmRSASHA256) + ":" + signatureText + ";\r\n"
}
