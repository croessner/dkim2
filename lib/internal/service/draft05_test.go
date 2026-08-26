package service

import (
	"slices"
	"testing"

	"github.com/croessner/dkim2/internal/policy"
	"github.com/croessner/dkim2/internal/verify"
)

// TestSignatureResultsPreserveOccurrenceOrder proves repeated algorithms do not merge or reorder positional results.
func TestSignatureResultsPreserveOccurrenceOrder(t *testing.T) {
	target := verify.Target{Sequence: 1, InstanceNumber: 1}
	checks := requiredChecksWithSignatures(target,
		verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusPass, Algorithm: verify.AlgorithmRSASHA256, Target: target},
		verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusFail, Code: verify.ErrorCodeSignatureMismatch, Algorithm: verify.AlgorithmRSASHA256, Target: target},
	)
	sets := []verify.SignatureSetResult{
		{Index: 0, Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound},
		{Index: 1, Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusFail, KeyStatus: verify.KeyStatusFound},
	}
	result := mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusMixed, checks, sets), DefaultLimits())
	got := result.SignatureSets()
	if len(got) != 2 || !slices.Equal([]SignatureStatus{got[0].Status, got[1].Status}, []SignatureStatus{SignaturePASS, SignatureFAIL}) {
		t.Fatalf("SignatureSets() = %#v", got)
	}
}

// TestDraft05ProtocolInfractionsMapToDistinctPermanentReasons proves the four Section 11.2 failures stay distinct.
func TestDraft05ProtocolInfractionsMapToDistinctPermanentReasons(t *testing.T) {
	tests := []struct {
		code   verify.ErrorCode
		reason Reason
	}{
		{verify.ErrorCodeDuplicateHashAlgorithm, ReasonDuplicateHashAlgorithm},
		{verify.ErrorCodeInvalidRecipeJSON, ReasonInvalidRecipeJSON},
		{verify.ErrorCodeDuplicateSelector, ReasonDuplicateSelector},
		{verify.ErrorCodeTooManySignatures, ReasonTooManySignatures},
	}
	seen := make(map[Reason]struct{}, len(tests))
	for _, test := range tests {
		reason, class, state := mapVerificationErrorCode(test.code)
		if reason != test.reason || class != CheckProtocol || state != StatePERMERROR || !reason.Known() {
			t.Fatalf("mapVerificationErrorCode(%q) = %q/%q/%q", test.code, reason, class, state)
		}
		seen[reason] = struct{}{}
	}
	if len(seen) != len(tests) {
		t.Fatalf("distinct reasons = %d, want %d", len(seen), len(tests))
	}
}

// TestRevisionProofFailuresRetainSelectedPolicyAuthority covers every closed history failure outcome.
func TestRevisionProofFailuresRetainSelectedPolicyAuthority(t *testing.T) {
	passFact := SignatureSetFact{Algorithm: AlgorithmRSASHA256, Status: SignaturePASS, Reason: ReasonNone}
	policyFact, err := policy.NewSignatureFact(policy.SetAlgorithmRSA, policy.SetStatusPass, policy.SetReasonNone, false, false)
	if err != nil {
		t.Fatalf("policy.NewSignatureFact() error = %v", err)
	}
	hop, err := policy.NewAuthenticatedHopFact(1, policy.TransitionOrigin, false, false, false, false, false)
	if err != nil {
		t.Fatalf("policy.NewAuthenticatedHopFact() error = %v", err)
	}
	projection, err := policy.NewSelectedProjection(policy.ProtocolPASS, policy.VerificationReasonNone, 1, []policy.HopFact{hop}, []policy.SignatureFact{policyFact}, policy.DefaultLimits())
	if err != nil {
		t.Fatalf("policy.NewSelectedProjection() error = %v", err)
	}
	current := newResult(StatePASS, CustodyNotPresent, Target{Sequence: 1, Instance: 2}, ReasonNone, []CheckFact{{Class: CheckSignature, Reason: ReasonNone}}, []SignatureSetFact{passFact}).withPolicyProjection(projection)
	tests := []struct {
		outcome verify.RevisionProofOutcome
		state   State
		reason  Reason
	}{
		{verify.RevisionProofHashMismatch, StateFAIL, ReasonHashMismatch},
		{verify.RevisionProofSignatureMismatch, StateFAIL, ReasonSignatureMismatch},
		{verify.RevisionProofUnsupported, StatePERMERROR, ReasonUnsupportedAlgorithm},
		{verify.RevisionProofProviderTemporary, StateTEMPERROR, ReasonProviderTemporary},
		{verify.RevisionProofProviderRejected, StatePERMERROR, ReasonProviderPermanent},
		{verify.RevisionProofProviderContract, StatePERMERROR, ReasonProviderContract},
		{verify.RevisionProofLimitExceeded, StatePERMERROR, ReasonLimitExceeded},
		{verify.RevisionProofTerminalNextDomainAuthorizationRequired, StatePERMERROR, ReasonOutOfBandRequired},
		{verify.RevisionProofInvalidRecipeJSON, StatePERMERROR, ReasonInvalidRecipeJSON},
		{verify.RevisionProofProtocolRejected, StatePERMERROR, ReasonMalformedProtocol},
		{verify.RevisionProofVerified, StatePERMERROR, ReasonInternalContract},
		{verify.RevisionProofOutcome("future"), StatePERMERROR, ReasonInternalContract},
	}
	for _, test := range tests {
		result := mapRevisionProofFailure(current, test.outcome)
		got := result.PolicyProjection()
		if result.State() != test.state || result.PrimaryReason() != test.reason || !got.Valid() || got.Form() != policy.TargetSelected || got.TargetSequence() != current.Target().Sequence || string(got.Protocol()) != string(test.state) || string(got.VerificationReason()) != string(test.reason) {
			t.Errorf("mapRevisionProofFailure(%q) = %q/%q projection=%#v", test.outcome, result.State(), result.PrimaryReason(), got)
		}
	}
}
