package verify

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

// TestVerifierVerifiesMessageInputWithRSA verifies the message extraction path.
func TestVerifierVerifiesMessageInputWithRSA(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	verifier := mustVerifierForFixture(t, fixture)

	result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	assertTargetPass(t, result, AlgorithmRSASHA256)
}

// TestVerifierVerifiesMessageInputWithEd25519 verifies the sole message extraction path.
func TestVerifierVerifiesMessageInputWithEd25519(t *testing.T) {
	fixture := newEd25519VerificationFixture(t)
	verifier := mustVerifierForFixture(t, fixture)

	result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	assertTargetPass(t, result, AlgorithmEd25519SHA256)
}

// TestVerifierRejectsForeignParsedProtocolState verifies message bytes remain the sole protocol authority.
func TestVerifierRejectsForeignParsedProtocolState(t *testing.T) {
	trusted := newRSAVerificationFixture(t)
	foreign := newRSAVerificationFixture(t)
	verifier := mustVerifierForFixture(t, trusted)

	result, err := verifier.Verify(context.Background(), Request{Message: foreign.message, Envelope: matchingEnvelope()})
	if err == nil && result.Status() == TargetStatusPass {
		t.Fatalf("Verify() accepted protocol fields from another message: %#v", result)
	}
}

// TestVerifierSelectsExplicitTargetSequence verifies explicit target selection.
func TestVerifierSelectsExplicitTargetSequence(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	verifier := mustVerifierForFixture(t, fixture)

	result, err := verifier.Verify(context.Background(), Request{
		Message:        fixture.message,
		Envelope:       matchingEnvelope(),
		TargetSequence: 1,
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if result.Target().Sequence != 1 || result.Target().InstanceNumber != 1 {
		t.Fatalf("target = %#v, want sequence 1 instance 1", result.Target())
	}
	assertTargetPass(t, result, AlgorithmRSASHA256)
}

// TestVerifierFailsClosedForMissingTargets verifies absent selected state is rejected.
func TestVerifierFailsClosedForMissingTargets(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	verifier := mustVerifierForFixture(t, fixture)

	_, err := verifier.Verify(context.Background(), Request{
		Message:        fixture.message,
		Envelope:       matchingEnvelope(),
		TargetSequence: 2,
	})
	if !IsErrorCode(err, ErrorCodeMissingTarget) {
		t.Fatalf("Verify() error = %v, want missing target", err)
	}
}

// TestVerifierFailsClosedForDuplicateTargets verifies parsed duplicate targets are rejected.
func TestVerifierFailsClosedForDuplicateTargets(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	verifier := mustVerifierForFixture(t, fixture)
	duplicateField := "DKIM2-Signature: " + signatureField(1, testSelector+":"+string(AlgorithmRSASHA256)+":"+fixture.signatureBase64) + "\r\n"
	raw := strings.Replace(fixture.raw, "\r\n\r\n"+verificationBody(), "\r\n"+duplicateField+"\r\n"+verificationBody(), 1)
	message := mustParseVerificationMessage(t, raw)

	_, err := verifier.Verify(context.Background(), Request{Message: message, Envelope: matchingEnvelope()})
	if !IsErrorCode(err, ErrorCodeSequenceInvalid) {
		t.Fatalf("Verify() error = %v, want typed invalid sequence", err)
	}
}

// TestVerifierRejectsCurrentSignatureReferencingOlderInstance records the Section 8.2 interpretation.
func TestVerifierRejectsCurrentSignatureReferencingOlderInstance(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	hashSet := "sha256:" + fixture.headerDigestBase64 + ":" + fixture.bodyDigestBase64
	placeholder := testSelector + ":" + string(AlgorithmRSASHA256) + ":" + base64.StdEncoding.EncodeToString(bytesOf(0xa5, 128))
	first := strings.Replace(signatureField(1, placeholder), "m=1", "m=2", 1)
	second := signatureField(2, placeholder)
	raw := baseVerificationHeaders() +
		"Message-Instance: m=1; h=" + hashSet + ";\r\n" +
		"Message-Instance: m=2; h=" + hashSet + ";\r\n" +
		"DKIM2-Signature: " + first + "\r\n" +
		"DKIM2-Signature: " + second + "\r\n\r\n" + verificationBody()
	parsed, err := parseVerificationFixture(raw)
	if err != nil {
		t.Fatalf("parseVerificationFixture() error = %v", err)
	}
	verifier := mustVerifierForFixture(t, fixture)

	_, err = verifier.Verify(context.Background(), Request{
		Message:  parsed.message,
		Envelope: matchingEnvelope(),
	})
	if !IsErrorCode(err, ErrorCodeMalformedState) {
		t.Fatalf("Verify() error = %v, want malformed current instance reference", err)
	}
}

// TestVerifierRejectsExplicitHistoricalTargetBeforeHashingCurrentBytes verifies unsupported historical reconstruction fails early.
func TestVerifierRejectsExplicitHistoricalTargetBeforeHashingCurrentBytes(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	hashSet := "sha256:" + fixture.headerDigestBase64 + ":" + fixture.bodyDigestBase64
	placeholder := testSelector + ":" + string(AlgorithmRSASHA256) + ":" + base64.StdEncoding.EncodeToString(bytesOf(0xa5, 128))
	raw := baseVerificationHeaders() +
		"Message-Instance: m=1; h=" + hashSet + ";\r\n" +
		"Message-Instance: m=2; h=" + hashSet + ";\r\n" +
		"DKIM2-Signature: " + signatureField(1, placeholder) + "\r\n" +
		"DKIM2-Signature: " + strings.Replace(signatureField(2, placeholder), "m=1", "m=2", 1) + "\r\n\r\n" + verificationBody()
	parsed, err := parseVerificationFixture(raw)
	if err != nil {
		t.Fatalf("parseVerificationFixture() error = %v", err)
	}
	verifier := mustVerifierForFixture(t, fixture)

	_, err = verifier.Verify(context.Background(), Request{
		Message:        parsed.message,
		Envelope:       NewEnvelope([]byte("<different@example.test>"), nil),
		TargetSequence: 1,
	})
	if !IsErrorCode(err, ErrorCodeUnsupportedTarget) {
		t.Fatalf("Verify() error = %v, want unsupported historical target", err)
	}
}

// assertTargetPass verifies the common success facts for one algorithm.
func assertTargetPass(t *testing.T, result Result, algorithm Algorithm) {
	t.Helper()

	if result.Status() != TargetStatusPass {
		t.Fatalf("Status() = %q, want pass; checks=%#v sets=%#v", result.Status(), result.Checks(), result.SignatureSets())
	}
	if !hasCheck(result, CheckKindBodyHash, CheckStatusPass, "") {
		t.Fatalf("body hash check missing pass: %#v", result.Checks())
	}
	if !hasCheck(result, CheckKindHeaderHash, CheckStatusPass, "") {
		t.Fatalf("header hash check missing pass: %#v", result.Checks())
	}
	if !hasCheck(result, CheckKindSignature, CheckStatusPass, algorithm) {
		t.Fatalf("signature check missing pass for %s: %#v", algorithm, result.Checks())
	}
	if !hasCheck(result, CheckKindTimestamp, CheckStatusPass, "") {
		t.Fatalf("timestamp check missing pass: %#v", result.Checks())
	}
	if !hasCheck(result, CheckKindEnvelope, CheckStatusPass, "") {
		t.Fatalf("envelope check missing pass: %#v", result.Checks())
	}
	if !hasSignatureSet(result, algorithm, SignatureSetStatusPass) {
		t.Fatalf("signature set missing pass for %s: %#v", algorithm, result.SignatureSets())
	}
}

// hasCheck reports whether result contains one matching check fact.
func hasCheck(result Result, kind CheckKind, status CheckStatus, algorithm Algorithm) bool {
	for _, check := range result.Checks() {
		if check.Kind == kind && check.Status == status && (algorithm == "" || check.Algorithm == algorithm) {
			return true
		}
	}

	return false
}

// hasSignatureSet reports whether result contains one matching signature-set fact.
func hasSignatureSet(result Result, algorithm Algorithm, status SignatureSetStatus) bool {
	for _, set := range result.SignatureSets() {
		if set.Algorithm == algorithm && set.Status == status {
			return true
		}
	}

	return false
}
