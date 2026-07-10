package verify

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

// TestVerifierReportsBodyHashMismatch verifies body hash failures are non-success facts.
func TestVerifierReportsBodyHashMismatch(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	changed := fixture.withRaw(strings.Replace(fixture.raw, "body line\r\n", "changed body\r\n", 1))
	verifier := mustVerifierForFixture(t, fixture)

	result, err := verifier.Verify(context.Background(), Request{Message: changed.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if result.Status() == TargetStatusPass || !hasCheck(result, CheckKindBodyHash, CheckStatusFail, "") {
		t.Fatalf("result = %#v checks=%#v, want body hash failure", result, result.Checks())
	}
}

// TestVerifierReportsHeaderHashMismatch verifies header hash failures are separate facts.
func TestVerifierReportsHeaderHashMismatch(t *testing.T) {
	fixture := newEd25519VerificationFixture(t)
	changed := fixture.withRaw(strings.Replace(fixture.raw, "Subject: Static verification\r\n", "Subject: Mutated verification\r\n", 1))
	verifier := mustVerifierForFixture(t, fixture)

	result, err := verifier.Verify(context.Background(), Request{Message: changed.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if result.Status() == TargetStatusPass || !hasCheck(result, CheckKindHeaderHash, CheckStatusFail, "") {
		t.Fatalf("result = %#v checks=%#v, want header hash failure", result, result.Checks())
	}
}

// TestVerifierRejectsUnknownOnlyHashSets verifies unsupported hash state cannot pass.
func TestVerifierRejectsUnknownOnlyHashSets(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	unknownHash := "h=sha512:" + base64.StdEncoding.EncodeToString([]byte("unknown-header")) + ":" + base64.StdEncoding.EncodeToString([]byte("unknown-body"))
	knownHash := "h=sha256:" + fixture.headerDigestBase64 + ":" + fixture.bodyDigestBase64
	changed := fixture.withRaw(strings.Replace(fixture.raw, knownHash, unknownHash, 1))
	verifier := mustVerifierForFixture(t, fixture)

	result, err := verifier.Verify(context.Background(), Request{Message: changed.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if result.Status() == TargetStatusPass || !hasCheck(result, CheckKindBodyHash, CheckStatusUnsupported, "") {
		t.Fatalf("result = %#v checks=%#v, want unsupported hash state", result, result.Checks())
	}
}

// TestVerifierRejectsMissingSHA256HashSet verifies absent known hash state is fail closed.
func TestVerifierRejectsMissingSHA256HashSet(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	emptyDigest := base64.StdEncoding.EncodeToString([]byte("not-a-digest"))
	raw := strings.Replace(fixture.raw, fixture.headerDigestBase64, emptyDigest, 1)
	_, err := parseVerificationFixture(raw)
	if err == nil {
		t.Fatal("parseVerificationFixture() succeeded with malformed sha256 digest")
	}
}
