package verify

import (
	"context"
	"encoding/base64"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/signature"
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
	second := strings.Replace(signatureField(2, placeholder), "mf=PD4=", "mf=PHNlbmRlckBleGFtcGxlLnRlc3Q+", 1)
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
		"DKIM2-Signature: " + strings.Replace(strings.Replace(signatureField(2, placeholder), "m=1", "m=2", 1), "mf=PD4=", "mf=PHNlbmRlckBleGFtcGxlLnRlc3Q+", 1) + "\r\n\r\n" + verificationBody()
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

// TestSelectVerificationTargetPreservesInheritedInstanceReferences locks i1/m1 i2/m2 i3/m3.
func TestSelectVerificationTargetPreservesInheritedInstanceReferences(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	hashSet := "sha256:" + fixture.headerDigestBase64 + ":" + fixture.bodyDigestBase64
	placeholder := testSelector + ":" + string(AlgorithmRSASHA256) + ":" + base64.StdEncoding.EncodeToString(bytesOf(0xa5, 128))
	field := func(sequence, messageInstance int, domain, mailFrom, recipient string) string {
		value := signatureField(uint64(sequence), placeholder)
		value = strings.Replace(value, "m=1", "m="+strconv.Itoa(messageInstance), 1)
		value = strings.Replace(value, "mf=PD4=", "mf="+encodeEnvelopePath([]byte(mailFrom)), 1)
		value = strings.Replace(value, "rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==", "rt="+encodeEnvelopePath([]byte(recipient)), 1)
		return strings.Replace(value, "d="+testDomain, "d="+domain, 1)
	}
	raw := baseVerificationHeaders() +
		"Message-Instance: m=1; h=" + hashSet + ";\r\n" +
		"Message-Instance: m=2; h=" + hashSet + ";\r\n" +
		"Message-Instance: m=3; h=" + hashSet + ";\r\n" +
		"DKIM2-Signature: " + field(1, 1, "origin.test", "<a@origin.test>", "<b@relay.test>") + "\r\n" +
		"DKIM2-Signature: " + field(2, 2, "relay.test", "<b@relay.test>", "<c@final.test>") + "\r\n" +
		"DKIM2-Signature: " + field(3, 3, "final.test", "<c@final.test>", "<d@destination.test>") + "\r\n\r\n" + verificationBody()
	message := mustParseVerificationMessage(t, raw)
	instanceParser, err := instance.NewParser(instance.Limits{})
	if err != nil {
		t.Fatalf("instance.NewParser() error = %v", err)
	}
	instances, err := instanceParser.Extract(message)
	if err != nil {
		t.Fatalf("instance Extract() error = %v", err)
	}
	signatureParser, err := signature.NewParser(signature.Limits{})
	if err != nil {
		t.Fatalf("signature.NewParser() error = %v", err)
	}
	signatures, err := signatureParser.Extract(message)
	if err != nil {
		t.Fatalf("signature Extract() error = %v", err)
	}
	for index, parsed := range signatures {
		if parsed.InstanceNumber() != uint64(index+1) {
			t.Fatalf("signature i=%d references m=%d", parsed.Sequence(), parsed.InstanceNumber())
		}
	}
	_, _, custody, target, err := selectVerificationTarget(verificationInput{request: Request{Message: message}, instances: instances, signatures: signatures})
	if err != nil || !custody.Valid() || target != (Target{Sequence: 3, InstanceNumber: 3}) {
		t.Fatalf("select target=%#v custody_valid=%v error=%v", target, custody.Valid(), err)
	}
}

// TestVerifierCollectionWrappersBoundMaxUintSequences verifies owner validation prevents unbounded loops.
func TestVerifierCollectionWrappersBoundMaxUintSequences(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	maxText := strconv.FormatUint(math.MaxUint64, 10)
	signatureMessage := mustParseVerificationMessage(t, baseVerificationHeaders()+
		"DKIM2-Signature: "+strings.Replace(signatureField(1, testSelector+":"+string(AlgorithmRSASHA256)+":"+fixture.signatureBase64), "i=1", "i="+maxText, 1)+"\r\n\r\n"+verificationBody())
	parsedSignature, err := signature.Parse(signatureMessage.Headers().FieldsByName(signature.HeaderName)[0])
	if err != nil {
		t.Fatalf("signature.Parse() error = %v", err)
	}
	if err := validateSignatureCollection([]signature.Signature{parsedSignature}); !IsErrorCode(err, ErrorCodeMalformedState) {
		t.Fatalf("signature MaxUint mapping error = %v", err)
	}
	instanceMessage := mustParseVerificationMessage(t, baseVerificationHeaders()+
		"Message-Instance: m="+maxText+"; h=sha256:"+fixture.headerDigestBase64+":"+fixture.bodyDigestBase64+";\r\n\r\n"+verificationBody())
	parsedInstance, err := instance.Parse(instanceMessage.Headers().FieldsByName(instance.HeaderName)[0])
	if err != nil {
		t.Fatalf("instance.Parse() error = %v", err)
	}
	if err := validateInstanceCollection([]instance.MessageInstance{parsedInstance}); !IsErrorCode(err, ErrorCodeMalformedState) {
		t.Fatalf("instance MaxUint mapping error = %v", err)
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
