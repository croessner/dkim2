package verify

import (
	"context"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
)

// TestVerifierAttachesSelectedParsedFlagCandidate proves the production parse-to-result seam.
func TestVerifierAttachesSelectedParsedFlagCandidate(t *testing.T) {
	passing := newDeterministicRSAVerificationFixture(t)
	passResult, err := mustVerifierForFixture(t, passing).Verify(context.Background(), Request{Message: passing.message, Envelope: matchingEnvelope()})
	if err != nil || passResult.Status() != TargetStatusPass {
		t.Fatalf("passing Verify() = %q error=%v", passResult.Status(), err)
	}
	passCandidate, ok := passResult.TargetFlagCandidate()
	if !ok || passCandidate.Sequence() != passResult.Target().Sequence || passCandidate.DoNotModify() || passCandidate.DoNotExplode() || passCandidate.Feedback() || passCandidate.FeedHere() || passCandidate.Exploded() {
		t.Fatalf("passing candidate = %#v/%v", passCandidate, ok)
	}

	toxicRaw := strings.Replace(passing.raw, "; d=example.test;", "; f=donotmodify,donotexplode,feedback,feedhere,exploded,TOXIC-UNKNOWN; d=example.test;", 1)
	toxic := passing.withRaw(toxicRaw)
	nonPass, err := mustVerifierForFixture(t, toxic).Verify(context.Background(), Request{Message: toxic.message, Envelope: matchingEnvelope()})
	if err != nil || nonPass.Status() == TargetStatusPass {
		t.Fatalf("non-PASS Verify() = %q error=%v", nonPass.Status(), err)
	}
	nonPassCandidate, ok := nonPass.TargetFlagCandidate()
	if !ok || nonPassCandidate.Sequence() != nonPass.Target().Sequence || !nonPassCandidate.DoNotModify() || !nonPassCandidate.DoNotExplode() || !nonPassCandidate.Feedback() || !nonPassCandidate.FeedHere() || !nonPassCandidate.Exploded() {
		t.Fatalf("non-PASS candidate = %#v/%v", nonPassCandidate, ok)
	}
}

// TestTargetFlagCandidateUsesAlreadyParsedKnownFlags verifies bounded candidate derivation.
func TestTargetFlagCandidateUsesAlreadyParsedKnownFlags(t *testing.T) {
	parsed := parsedPolicySignature(t)
	candidate := newTargetFlagCandidate(parsed)
	if !candidate.Valid() || candidate.Sequence() != 1 || !candidate.DoNotModify() || !candidate.DoNotExplode() || !candidate.Feedback() || !candidate.FeedHere() || !candidate.Exploded() {
		t.Fatalf("candidate = %#v", candidate)
	}
	result := NewResult(Target{Sequence: 1, InstanceNumber: 1}, TargetStatusPass, nil, nil).withTargetFlagCandidate(candidate)
	got, ok := result.TargetFlagCandidate()
	if !ok || got != candidate {
		t.Fatalf("result candidate = %#v/%v", got, ok)
	}
	mismatch := (Result{target: Target{Sequence: 2, InstanceNumber: 1}}).withTargetFlagCandidate(candidate)
	if _, ok := mismatch.TargetFlagCandidate(); ok {
		t.Fatal("result accepted mismatched candidate sequence")
	}
	for _, corrupt := range []Result{
		{target: Target{Sequence: 1, InstanceNumber: 1}, hasTargetFlags: true},
		{target: Target{Sequence: 1, InstanceNumber: 1}, targetFlags: TargetFlagCandidate{sequence: 2}, hasTargetFlags: true},
		{targetFlags: candidate, hasTargetFlags: true},
	} {
		if _, ok := corrupt.TargetFlagCandidate(); ok {
			t.Fatalf("corrupt result exposed candidate = %#v", corrupt)
		}
	}
}

// parsedPolicySignature parses one toxic-extension fixture through the existing parser once.
func parsedPolicySignature(t *testing.T) signature.Signature {
	t.Helper()
	raw := []byte("From: sender@example.test\r\n" +
		"DKIM2-Signature: i=1; m=1; t=1700000000; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==; d=example.test; s=selector:rsa-sha256:QQ==; f=donotmodify,donotexplode,feedback,feedhere,exploded,TOXIC-UNKNOWN;\r\n\r\nbody\r\n")
	message, err := rawmsg.Parse(raw)
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}
	parser, err := signature.NewParser(signature.DefaultLimits())
	if err != nil {
		t.Fatalf("signature.NewParser() error = %v", err)
	}
	signatures, err := parser.Extract(message)
	if err != nil || len(signatures) != 1 {
		t.Fatalf("Extract() = %d signatures error=%v", len(signatures), err)
	}
	return signatures[0]
}
