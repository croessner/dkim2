package dsn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/verify"
)

const (
	evidenceTimestamp = uint64(1700000000)
	evidenceDomain    = "example.test"
)

// TestEvidenceEvaluatorAuthenticatesCompleteAndHeadersOnlyOriginals verifies
// both RFC 3462 representations use real DKIM2 cryptographic evidence without
// treating the headers-only representation as a complete message.
func TestEvidenceEvaluatorAuthenticatesCompleteAndHeadersOnlyOriginals(t *testing.T) {
	for _, form := range []struct {
		name        string
		contentType ContentType
		headersOnly bool
		wantForm    EvidenceForm
	}{
		{name: "complete", contentType: ContentTypeRFC822, wantForm: EvidenceFormComplete},
		{name: "headers only", contentType: ContentTypeRFC822Headers, headersOnly: true, wantForm: EvidenceFormHeadersOnly},
	} {
		t.Run(form.name, func(t *testing.T) {
			fixture := newEvidenceFixture(t, form.headersOnly)
			report := mustEvidenceReport(t, form.contentType, fixture.raw)
			evaluator, err := NewEvidenceEvaluator(fixture.verifier)
			if err != nil {
				t.Fatalf("NewEvidenceEvaluator() error=%v", err)
			}
			evidence, err := evaluator.Evaluate(context.Background(), EvidenceRequest{
				Report: report,
				OriginalEnvelope: verify.NewEnvelope(
					[]byte("<sender@example.test>"), [][]byte{[]byte("<recipient@example.test>")},
				),
			})
			if err != nil || !evidence.Valid() || evidence.Form() != form.wantForm || evidence.Target().Sequence != 1 || evidence.Target().InstanceNumber != 1 ||
				evidence.SigningDomain() != evidenceDomain || len(evidence.RecipientDomains()) != 1 || evidence.RecipientDomains()[0] != evidenceDomain {
				t.Fatalf("Evaluate() evidence=%#v error=%v", evidence, err)
			}
			domains := evidence.RecipientDomains()
			domains[0] = "mutated.invalid"
			if got := evidence.RecipientDomains()[0]; got != evidenceDomain {
				t.Fatalf("RecipientDomains() exposed mutable evidence: %q", got)
			}
		})
	}
}

// TestEvidenceEvaluatorRejectsHeadersOnlyWithInventedEmptyBody proves the
// DSN evaluator does not silently replace unavailable body evidence with an
// empty body when the MIME type promises retained headers only.
func TestEvidenceEvaluatorRejectsHeadersOnlyWithInventedEmptyBody(t *testing.T) {
	fixture := newEvidenceFixture(t, false)
	report := mustEvidenceReport(t, ContentTypeRFC822Headers, fixture.raw)
	evaluator, err := NewEvidenceEvaluator(fixture.verifier)
	if err != nil {
		t.Fatalf("NewEvidenceEvaluator() error=%v", err)
	}
	_, err = evaluator.Evaluate(context.Background(), EvidenceRequest{
		Report: report,
		OriginalEnvelope: verify.NewEnvelope(
			[]byte("<sender@example.test>"), [][]byte{[]byte("<recipient@example.test>")},
		),
	})
	if !IsEvidenceErrorCode(err, EvidenceErrorCodeVerificationFailed) {
		t.Fatalf("Evaluate() error=%v, want verification failed", err)
	}
}

// TestEvidenceEvaluatorRejectsNullOrChangedOriginalEvidence proves callers
// cannot authorize DSN signing with a null original envelope or altered bytes.
func TestEvidenceEvaluatorRejectsNullOrChangedOriginalEvidence(t *testing.T) {
	fixture := newEvidenceFixture(t, false)
	evaluator, err := NewEvidenceEvaluator(fixture.verifier)
	if err != nil {
		t.Fatalf("NewEvidenceEvaluator() error=%v", err)
	}
	validReport := mustEvidenceReport(t, ContentTypeRFC822, fixture.raw)
	_, err = evaluator.Evaluate(context.Background(), EvidenceRequest{
		Report:           validReport,
		OriginalEnvelope: verify.NewEnvelope([]byte("<>"), [][]byte{[]byte("<recipient@example.test>")}),
	})
	if !IsEvidenceErrorCode(err, EvidenceErrorCodeInvalidRequest) {
		t.Fatalf("Evaluate(null original envelope) error=%v, want invalid request", err)
	}

	const toxic = "TOXIC-ORIGINAL-MARKER"
	changed := strings.Replace(fixture.raw, "Subject: original", "Subject: "+toxic, 1)
	changedReport := mustEvidenceReport(t, ContentTypeRFC822, changed)
	_, err = evaluator.Evaluate(context.Background(), EvidenceRequest{
		Report: changedReport,
		OriginalEnvelope: verify.NewEnvelope(
			[]byte("<sender@example.test>"), [][]byte{[]byte("<recipient@example.test>")},
		),
	})
	if !IsEvidenceErrorCode(err, EvidenceErrorCodeVerificationFailed) {
		t.Fatalf("Evaluate(changed original) error=%v, want verification failed", err)
	}
	if strings.Contains(err.Error(), toxic) {
		t.Fatalf("Evaluate(changed original) leaked message content: %q", err)
	}
}

// evidenceFixture stores a real cryptographic embedded original and its verifier.
type evidenceFixture struct {
	raw      string
	verifier verify.Verifier
}

// newEvidenceFixture constructs either a complete or header-only signed embedded original.
func newEvidenceFixture(t *testing.T, headersOnly bool) evidenceFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error=%v", err)
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatalf("canonical.NewCanonicalizer() error=%v", err)
	}
	baseHeaders := "From: sender@example.test\r\nSubject: original\r\n"
	baseRaw := baseHeaders
	if !headersOnly {
		baseRaw += "\r\nbody\r\n"
	}
	baseMessage := mustEvidenceMessage(t, baseRaw)
	headerHash, err := canonicalizer.HeaderHashFromMessage(baseMessage)
	if err != nil {
		t.Fatalf("HeaderHashFromMessage() error=%v", err)
	}
	headerDigest, ok := headerHash.Digest()
	if !ok {
		t.Fatal("HeaderHashFromMessage() missing digest")
	}
	bodyDigest := base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
	if !headersOnly {
		bodyHash, hashErr := canonicalizer.BodyHashFromMessage(baseMessage)
		if hashErr != nil {
			t.Fatalf("BodyHashFromMessage() error=%v", hashErr)
		}
		digest, digestOK := bodyHash.Digest()
		if !digestOK {
			t.Fatal("BodyHashFromMessage() missing digest")
		}
		bodyDigest = digest.Base64()
	}
	placeholder := base64.StdEncoding.EncodeToString(make([]byte, 128))
	unsignedRaw := renderEvidenceOriginal(baseHeaders, headerDigest.Base64(), bodyDigest, placeholder, headersOnly)
	unsigned := mustEvidenceMessage(t, unsignedRaw)
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{Headers: unsigned.Headers(), TargetSequence: 1})
	if err != nil {
		t.Fatalf("SignatureInput() error=%v", err)
	}
	digest := sha256.Sum256(input.Bytes())
	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error=%v", err)
	}
	raw := renderEvidenceOriginal(baseHeaders, headerDigest.Base64(), bodyDigest, base64.StdEncoding.EncodeToString(signatureBytes), headersOnly)
	provider, err := verify.NewStaticKeyProvider([]verify.StaticKey{{
		Domain: "example.test", Selector: "selector", Algorithm: verify.AlgorithmRSASHA256, Material: &key.PublicKey,
	}})
	if err != nil {
		t.Fatalf("verify.NewStaticKeyProvider() error=%v", err)
	}
	verifier, err := verify.NewVerifier(provider, verify.WithClock(func() time.Time {
		return time.Unix(int64(evidenceTimestamp), 0).Add(time.Minute)
	}))
	if err != nil {
		t.Fatalf("verify.NewVerifier() error=%v", err)
	}
	return evidenceFixture{raw: raw, verifier: verifier}
}

// renderEvidenceOriginal renders one signed original with RFC 5322 framing chosen by headersOnly.
func renderEvidenceOriginal(baseHeaders string, headerDigest string, bodyDigest string, signatureText string, headersOnly bool) string {
	recipient := base64.StdEncoding.EncodeToString([]byte("<recipient@EXAMPLE.TEST>"))
	raw := baseHeaders +
		"Message-Instance: m=1; h=sha256:" + headerDigest + ":" + bodyDigest + ";\r\n" +
		"DKIM2-Signature: i=1; m=1; t=1700000000; mf=PHNlbmRlckBleGFtcGxlLnRlc3Q+; rt=" + recipient + "; d=example.test; s=selector:rsa-sha256:" + signatureText + ";\r\n"
	if headersOnly {
		return raw
	}
	return raw + "\r\nbody\r\n"
}

// mustEvidenceMessage parses a strict embedded original test fixture.
func mustEvidenceMessage(t *testing.T, raw string) rawmsg.Message {
	t.Helper()
	message, err := rawmsg.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("rawmsg.Parse() error=%v", err)
	}
	return message
}

// mustEvidenceReport embeds an exact original in a structurally valid RFC 3462 report.
func mustEvidenceReport(t *testing.T, contentType ContentType, original string) Report {
	t.Helper()
	separator := ""
	if contentType == ContentTypeRFC822Headers {
		// Preserve the embedded header block's terminating CRLF separately from
		// the MIME delimiter's required leading CRLF.
		separator = "\r\n"
	}
	raw := "From: postmaster@example.test\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n" +
		"--dsn\r\nContent-Type: text/plain\r\n\r\nhuman\r\n" +
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; example.test\r\n\r\n" +
		"--dsn\r\nContent-Type: " + string(contentType) + "\r\n\r\n" + original + separator +
		"--dsn--\r\n"
	report, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse(report) error=%v", err)
	}
	return report
}
