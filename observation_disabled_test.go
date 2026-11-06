package dkim2

import (
	"context"
	"testing"
)

// TestVerificationObservationSeparatesLocallyDisabledAlgorithm proves the
// bounded observation reason distinguishes an algorithm disabled by local
// policy (policy) from an unknown algorithm (protocol) while both report
// PERMERROR unsupported_algorithm.
func TestVerificationObservationSeparatesLocallyDisabledAlgorithm(t *testing.T) {
	target := newVerificationTarget(1, 1)
	base := verifyResultData{
		state: ResultStatePERMERROR, scope: VerificationScopeCurrent,
		historicalContent: HistoricalStateNotEvaluated, historicalSignatures: HistoricalStateNotEvaluated,
		custodyStructure: CustodyStructureNotPresent, target: target, primaryReason: ReasonUnsupportedAlgorithm,
	}
	unknown := newVerifyResult(base)
	if _, reason, _ := verificationEventOutcome(context.Background(), unknown, nil); reason != ObservationReasonProtocol {
		t.Fatalf("unknown algorithm observation reason = %v, want protocol", reason)
	}
	base.locallyDisabled = true
	disabled := newVerifyResult(base)
	if _, reason, _ := verificationEventOutcome(context.Background(), disabled, nil); reason != ObservationReasonPolicy {
		t.Fatalf("disabled algorithm observation reason = %v, want policy", reason)
	}
	base.primaryReason = ReasonMissingKey
	if newVerifyResult(base).locallyDisabledAlgorithm() {
		t.Fatal("locally disabled marker escaped an unrelated reason")
	}
}
