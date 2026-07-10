package verify

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/signature"
)

const nextHopDomain = "next.example.test"

// TestVerifierAcceptsExactNextDomainChain verifies an intermediate nd= target against the next d= value.
func TestVerifierAcceptsExactNextDomainChain(t *testing.T) {
	fixture := newNextDomainChainFixture(t, strings.ToUpper(nextHopDomain))
	verifier := mustVerifierWithKeys(t, []StaticKey{{
		Domain:    testDomain,
		Selector:  testSelector,
		Algorithm: AlgorithmRSASHA256,
		Material:  fixture.rsaKey,
	}})

	result, err := verifier.Verify(context.Background(), Request{
		Message:        fixture.message,
		TargetSequence: fixture.sequenceOne,
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Status() != TargetStatusPass || !hasNextDomainCheck(result, NextDomainStatusPass, CheckStatusPass) {
		t.Fatalf("result = %q checks=%#v, want exact next-domain pass", result.Status(), result.Checks())
	}
	if !hasEnvelopeCheck(result, EnvelopeStatusNotApplicable, CheckStatusNotApplicable) {
		t.Fatalf("checks = %#v, want nd= envelope check not applicable", result.Checks())
	}
	if !hasDomainAlignmentCheck(result, DomainAlignmentStatusNotApplicable, CheckStatusNotApplicable) {
		t.Fatalf("checks = %#v, want nd= domain alignment not applicable", result.Checks())
	}
}

// TestVerifierRejectsNextDomainMismatch verifies fail-closed exact canonical comparison without domain diagnostics.
func TestVerifierRejectsNextDomainMismatch(t *testing.T) {
	fixture := newNextDomainChainFixture(t, "wrong.example.test")
	verifier := mustVerifierWithKeys(t, nil)

	_, err := verifier.Verify(context.Background(), Request{Message: fixture.message})
	if !IsErrorCode(err, ErrorCodeNextDomainMismatch) {
		t.Fatalf("Verify() error = %v, want %s", err, ErrorCodeNextDomainMismatch)
	}
	var verifyErr *Error
	if !errors.As(err, &verifyErr) || verifyErr.Class() != ErrorClassNextDomain || verifyErr.Location().Check != CheckKindNextDomain {
		t.Fatalf("Verify() classification = %#v, want bounded next-domain error", verifyErr)
	}
	for _, domain := range []string{testDomain, nextHopDomain, "wrong.example.test"} {
		if strings.Contains(err.Error(), domain) {
			t.Fatalf("Verify() error leaked domain %q: %v", domain, err)
		}
	}
}

// TestValidateNextDomainChainRejectsMissingNextSignature verifies a bounded missing-successor error.
func TestValidateNextDomainChainRejectsMissingNextSignature(t *testing.T) {
	fixture := newNextDomainChainFixture(t, nextHopDomain)
	raw := strings.Replace(fixture.raw, "DKIM2-Signature: i=2;", "DKIM2-Signature: i=3;", 1)
	message := mustParseVerificationMessage(t, raw)
	fields := message.Headers().FieldsByName(signature.HeaderName)
	parsed := make([]signature.Signature, 0, len(fields))
	for _, field := range fields {
		value, err := signature.Parse(field)
		if err != nil {
			t.Fatalf("signature.Parse() error = %v", err)
		}
		parsed = append(parsed, value)
	}

	err := validateNextDomainChain(parsed)
	if !IsErrorCode(err, ErrorCodeMissingNextSignature) {
		t.Fatalf("validateNextDomainChain() error = %v, want %s", err, ErrorCodeMissingNextSignature)
	}
	var verifyErr *Error
	if !errors.As(err, &verifyErr) || verifyErr.Class() != ErrorClassNextDomain || verifyErr.Location().Check != CheckKindNextDomain {
		t.Fatalf("validateNextDomainChain() classification = %#v, want bounded next-domain error", verifyErr)
	}
	if strings.Contains(err.Error(), nextHopDomain) {
		t.Fatalf("validateNextDomainChain() error leaked domain: %v", err)
	}
}

// TestVerifierDoesNotPassHighestNextDomain verifies OOB acceptance is required for a terminal nd= target.
func TestVerifierDoesNotPassHighestNextDomain(t *testing.T) {
	fixture := newHighestNextDomainFixture(t)
	verifier := mustVerifierWithKeys(t, []StaticKey{{
		Domain:    testDomain,
		Selector:  testSelector,
		Algorithm: AlgorithmRSASHA256,
		Material:  fixture.rsaKey,
	}})

	result, err := verifier.Verify(context.Background(), Request{Message: fixture.message})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Status() != TargetStatusUnsupported || !hasNextDomainCheck(result, NextDomainStatusOutOfBandRequired, CheckStatusUnsupported) {
		t.Fatalf("result = %q checks=%#v, want OOB-required unsupported state", result.Status(), result.Checks())
	}
	if !hasEnvelopeCheck(result, EnvelopeStatusNotApplicable, CheckStatusNotApplicable) ||
		!hasDomainAlignmentCheck(result, DomainAlignmentStatusNotApplicable, CheckStatusNotApplicable) {
		t.Fatalf("checks = %#v, want nd= envelope/alignment checks not applicable", result.Checks())
	}
}

// newNextDomainChainFixture signs an i=1 nd= target followed by an i=2 envelope target.
func newNextDomainChainFixture(t *testing.T, firstNextDomain string) multiSignatureFixture {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	headerDigest, bodyDigest := baseMessageDigests(t)
	placeholder := testSelector + ":" + string(AlgorithmRSASHA256) + ":" + base64.StdEncoding.EncodeToString(bytesOf(0xa5, 128))

	firstUnsigned := mustParseVerificationMessage(t, rawWithSignatureFields(headerDigest, bodyDigest, []string{
		nextDomainSignatureField(1, testDomain, firstNextDomain, placeholder),
	}))
	firstDigest := signatureDigestForTarget(t, firstUnsigned, 1)
	firstSignature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, firstDigest)
	if err != nil {
		t.Fatalf("first rsa.SignPKCS1v15() error = %v", err)
	}
	firstSet := testSelector + ":" + string(AlgorithmRSASHA256) + ":" + base64.StdEncoding.EncodeToString(firstSignature)

	secondUnsigned := mustParseVerificationMessage(t, rawWithSignatureFields(headerDigest, bodyDigest, []string{
		nextDomainSignatureField(1, testDomain, firstNextDomain, firstSet),
		envelopeSignatureField(2, nextHopDomain, placeholder),
	}))
	secondDigest := signatureDigestForTarget(t, secondUnsigned, 2)
	secondSignature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, secondDigest)
	if err != nil {
		t.Fatalf("second rsa.SignPKCS1v15() error = %v", err)
	}
	secondSet := testSelector + ":" + string(AlgorithmRSASHA256) + ":" + base64.StdEncoding.EncodeToString(secondSignature)

	parsed, err := parseVerificationFixture(rawWithSignatureFields(headerDigest, bodyDigest, []string{
		nextDomainSignatureField(1, testDomain, firstNextDomain, firstSet),
		envelopeSignatureField(2, nextHopDomain, secondSet),
	}))
	if err != nil {
		t.Fatalf("parseVerificationFixture() error = %v", err)
	}

	return multiSignatureFixture{
		verificationFixture: parsed,
		rsaKey:              &key.PublicKey,
		sequenceOne:         1,
		sequenceTwo:         2,
	}
}

// newHighestNextDomainFixture signs one terminal nd= target for OOB policy testing.
func newHighestNextDomainFixture(t *testing.T) multiSignatureFixture {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	headerDigest, bodyDigest := baseMessageDigests(t)
	placeholder := testSelector + ":" + string(AlgorithmRSASHA256) + ":" + base64.StdEncoding.EncodeToString(bytesOf(0xa5, 128))
	unsigned := mustParseVerificationMessage(t, rawWithSignatureFields(headerDigest, bodyDigest, []string{
		nextDomainSignatureField(1, testDomain, nextHopDomain, placeholder),
	}))
	digest := signatureDigestForTarget(t, unsigned, 1)
	signed, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
	}
	signedSet := testSelector + ":" + string(AlgorithmRSASHA256) + ":" + base64.StdEncoding.EncodeToString(signed)
	parsed, err := parseVerificationFixture(rawWithSignatureFields(headerDigest, bodyDigest, []string{
		nextDomainSignatureField(1, testDomain, nextHopDomain, signedSet),
	}))
	if err != nil {
		t.Fatalf("parseVerificationFixture() error = %v", err)
	}

	return multiSignatureFixture{verificationFixture: parsed, rsaKey: &key.PublicKey, sequenceOne: 1}
}

// nextDomainSignatureField renders a bounded nd= DKIM2-Signature value.
func nextDomainSignatureField(sequence uint64, domain string, nextDomain string, signatureSets string) string {
	return signatureFieldPrefix(sequence) + "nd=" + nextDomain + "; d=" + domain + "; s=" + signatureSets + ";"
}

// envelopeSignatureField renders a bounded mf=/rt= DKIM2-Signature value for one domain.
func envelopeSignatureField(sequence uint64, domain string, signatureSets string) string {
	return signatureFieldPrefix(sequence) + "mf=PD4=; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==; d=" + domain + "; s=" + signatureSets + ";"
}

// signatureFieldPrefix renders common bounded DKIM2-Signature tags.
func signatureFieldPrefix(sequence uint64) string {
	return "i=" + strconv.FormatUint(sequence, 10) + "; m=1; t=" + strconv.FormatUint(testTimestampSeconds, 10) + "; "
}

// hasNextDomainCheck reports whether result carries one bounded next-domain fact.
func hasNextDomainCheck(result Result, status NextDomainStatus, checkStatus CheckStatus) bool {
	for _, check := range result.Checks() {
		if check.Kind == CheckKindNextDomain && check.NextDomainStatus == status && check.Status == checkStatus {
			return true
		}
	}

	return false
}
