package service

import (
	"slices"
	"testing"

	"github.com/croessner/dkim2/internal/verify"
)

// TestMappingEnforcesHardPublicFactCaps proves exact 128/16 retention and one-over bounded defense.
func TestMappingEnforcesHardPublicFactCaps(t *testing.T) {
	target := verify.Target{Sequence: 1, InstanceNumber: 1}
	limits := DefaultLimits()

	exactChecks := repeatedBodyChecks(target, limits.MaxCheckFacts)
	exactCheckResult := mapVerificationResult(verify.NewResultWithCustody(target, verify.TargetStatusFail, exactChecks, nil, verify.CustodyStatusNotPresent), limits)
	if len(exactCheckResult.Checks()) != limits.MaxCheckFacts || exactCheckResult.State() != StatePERMERROR || exactCheckResult.PrimaryReason() != ReasonInternalContract {
		t.Fatal("exact hard check-fact cap was not retained fail-closed")
	}
	overCheckResult := mapVerificationResult(verify.NewResultWithCustody(target, verify.TargetStatusFail, repeatedBodyChecks(target, limits.MaxCheckFacts+1), nil, verify.CustodyStatusNotPresent), limits)
	if len(overCheckResult.Checks()) > limits.MaxCheckFacts || overCheckResult.State() != StatePERMERROR || overCheckResult.PrimaryReason() != ReasonInternalContract {
		t.Fatal("one-over hard check-fact input escaped bounded contract defense")
	}

	exactSets, exactSignatureChecks := unsupportedSetFacts(target, limits.MaxSignatureFacts)
	exactSignatureResult := mapVerificationResult(verify.NewResultWithCustody(target, verify.TargetStatusUnsupported, exactSignatureChecks, exactSets, verify.CustodyStatusNotPresent), limits)
	if len(exactSignatureResult.SignatureSets()) != limits.MaxSignatureFacts || exactSignatureResult.State() != StatePERMERROR || exactSignatureResult.PrimaryReason() != ReasonUnsupportedAlgorithm {
		t.Fatal("exact hard signature-fact cap was not fully retained")
	}
	overSets, overSignatureChecks := unsupportedSetFacts(target, limits.MaxSignatureFacts+1)
	var retainedSignatures []SignatureSetFact
	for _, ordered := range [][]verify.SignatureSetResult{overSets, reverseSignatureSets(overSets)} {
		overSignatureResult := mapVerificationResult(verify.NewResultWithCustody(target, verify.TargetStatusUnsupported, overSignatureChecks, ordered, verify.CustodyStatusNotPresent), limits)
		if len(overSignatureResult.SignatureSets()) > limits.MaxSignatureFacts || overSignatureResult.State() != StatePERMERROR || overSignatureResult.PrimaryReason() != ReasonLimitExceeded {
			t.Fatal("one-over hard signature-fact input did not fail with bounded limit state")
		}
		if retainedSignatures == nil {
			retainedSignatures = overSignatureResult.SignatureSets()
		} else if !slices.Equal(retainedSignatures, overSignatureResult.SignatureSets()) {
			t.Fatal("capped signature details depended on input order")
		}
	}
}

// TestMappingAccumulatorCheckHardCapDistinguishesExactAndOver proves the owning 128/129 seam.
func TestMappingAccumulatorCheckHardCapDistinguishesExactAndOver(t *testing.T) {
	limits := DefaultLimits()
	accumulator := mappingAccumulator{maxChecks: limits.MaxCheckFacts, reason: ReasonNone}
	fact := CheckFact{Class: CheckMessage, Reason: ReasonNone}
	for range limits.MaxCheckFacts {
		accumulator.appendCheck(fact)
	}
	if len(accumulator.checks) != limits.MaxCheckFacts || accumulator.hardOverflow || accumulator.reason != ReasonNone {
		t.Fatal("exact hard check cap reported overflow")
	}
	accumulator.appendCheck(fact)
	if len(accumulator.checks) != limits.MaxCheckFacts || accumulator.hardOverflow || accumulator.severity != severityPass || accumulator.reason != ReasonNone {
		t.Fatal("one-over hard check cap changed protocol semantics before aggregation")
	}
	accumulator.add(severityPermanent, ReasonLimitExceeded)
	if accumulator.severity != severityPermanent || accumulator.reason != ReasonLimitExceeded {
		t.Fatal("hard check overflow did not aggregate as a bounded limit failure")
	}
}

// repeatedBodyChecks creates a deliberately inconsistent but shape-valid cap-defense input.
func repeatedBodyChecks(target verify.Target, count int) []verify.CheckResult {
	checks := make([]verify.CheckResult, count)
	for index := range checks {
		checks[index] = verify.CheckResult{Kind: verify.CheckKindBodyHash, Status: verify.CheckStatusPass, HashStatus: verify.HashStatusPass, Target: target}
	}
	return checks
}

// unsupportedSetFacts creates contiguous ignored sets with corresponding typed checks.
func unsupportedSetFacts(target verify.Target, count int) ([]verify.SignatureSetResult, []verify.CheckResult) {
	sets := make([]verify.SignatureSetResult, count)
	signatureChecks := make([]verify.CheckResult, count)
	for index := range sets {
		sets[index] = verify.SignatureSetResult{Index: index, Algorithm: verify.AlgorithmUnknown, Status: verify.SignatureSetStatusUnsupportedAlgorithm, KeyStatus: verify.KeyStatusUnsupportedAlgorithm}
		signatureChecks[index] = verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusUnsupported, Code: verify.ErrorCodeUnsupportedAlgorithm, Algorithm: verify.AlgorithmUnknown, Target: target}
	}
	return sets, requiredChecksWithSignatures(target, signatureChecks...)
}
