package policy

import (
	"slices"
	"testing"
)

// TestFeedbackCausalityAndRelaySelection verifies same/lower request eligibility.
func TestFeedbackCausalityAndRelaySelection(t *testing.T) {
	tests := []struct {
		name          string
		hops          []HopFact
		requested     bool
		relayRequired bool
		relaySequence uint64
		findings      []sequencedReason
	}{
		{name: "absent", hops: []HopFact{mustFeedbackHop(t, 1, false, false)}},
		{name: "request", hops: []HopFact{mustFeedbackHop(t, 1, true, false)}, requested: true, findings: []sequencedReason{{ReasonFeedbackRequested, 1}}},
		{name: "inert relay", hops: []HopFact{mustFeedbackHop(t, 1, false, true)}, findings: []sequencedReason{{ReasonFeedHereInert, 1}}},
		{name: "same hop", hops: []HopFact{mustFeedbackHop(t, 1, true, true)}, requested: true, relayRequired: true, relaySequence: 1, findings: []sequencedReason{{ReasonFeedbackRequested, 1}, {ReasonFeedbackRelaySelected, 1}}},
		{name: "later request not retroactive", hops: []HopFact{mustFeedbackHop(t, 1, false, true), mustFeedbackHop(t, 2, true, false)}, requested: true, findings: []sequencedReason{{ReasonFeedbackRequested, 2}, {ReasonFeedHereInert, 1}}},
		{name: "highest eligible relay", hops: []HopFact{mustFeedbackHop(t, 1, true, false), mustFeedbackHop(t, 2, false, true), mustFeedbackHop(t, 3, false, true)}, requested: true, relayRequired: true, relaySequence: 3, findings: []sequencedReason{{ReasonFeedbackRequested, 1}, {ReasonFeedbackRelaySelected, 3}}},
		{name: "inert then eligible", hops: []HopFact{mustFeedbackHop(t, 1, false, true), mustFeedbackHop(t, 2, true, false), mustFeedbackHop(t, 3, false, true)}, requested: true, relayRequired: true, relaySequence: 3, findings: []sequencedReason{{ReasonFeedbackRequested, 2}, {ReasonFeedHereInert, 1}, {ReasonFeedbackRelaySelected, 3}}},
		{name: "multiple requests", hops: []HopFact{mustFeedbackHop(t, 1, true, false), mustFeedbackHop(t, 2, true, false)}, requested: true, findings: []sequencedReason{{ReasonFeedbackRequested, 1}, {ReasonFeedbackRequested, 2}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := mustEvaluateCompliance(t, ModeStrict, mustComplianceHistory(t, HistoryComplete, tt.hops...), DefaultLimits())
			intent := decision.FeedbackIntent()
			if !intent.Valid() || intent.Requested() != tt.requested || intent.RelayRequired() != tt.relayRequired || intent.RelaySequence() != tt.relaySequence || intent.HistoryCoverage() != HistoryComplete {
				t.Fatalf("intent = %#v", intent)
			}
			if got := feedbackFindingPairs(decision.Findings()); !slices.Equal(got, tt.findings) {
				t.Fatalf("feedback findings = %v, want %v", got, tt.findings)
			}
		})
	}
}

// TestCurrentFeedbackIntentDoesNotClaimCompleteHistory verifies current PASS semantics.
func TestCurrentFeedbackIntentDoesNotClaimCompleteHistory(t *testing.T) {
	set := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPass, SetReasonNone, false, false)
	hop, err := NewAuthenticatedHopFact(2, TransitionNotEvaluated, false, false, true, true, false)
	if err != nil {
		t.Fatalf("NewAuthenticatedHopFact() error = %v", err)
	}
	projection, err := NewSelectedProjection(ProtocolPASS, VerificationReasonNone, 2, []HopFact{hop}, []SignatureFact{set}, DefaultLimits())
	if err != nil {
		t.Fatalf("NewSelectedProjection() error = %v", err)
	}
	decision := mustEvaluateCompliance(t, ModeStrict, projection, DefaultLimits())
	intent := decision.FeedbackIntent()
	if !intent.Requested() || !intent.RelayRequired() || intent.RelaySequence() != 2 || intent.HistoryCoverage() != HistoryNotEvaluated ||
		!hasSequencedFinding(decision, ReasonFeedbackRequested, 2) || !hasSequencedFinding(decision, ReasonFeedbackRelaySelected, 2) {
		t.Fatalf("current feedback intent = %#v decision=%#v", intent, decision)
	}
}

// TestCurrentFeedbackRequestWithoutRelayPreservesHistoryUncertainty verifies no absence claim.
func TestCurrentFeedbackRequestWithoutRelayPreservesHistoryUncertainty(t *testing.T) {
	set := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPass, SetReasonNone, false, false)
	hop, err := NewAuthenticatedHopFact(2, TransitionNotEvaluated, false, false, true, false, false)
	if err != nil {
		t.Fatalf("NewAuthenticatedHopFact() error = %v", err)
	}
	projection, err := NewSelectedProjection(ProtocolPASS, VerificationReasonNone, 2, []HopFact{hop}, []SignatureFact{set}, DefaultLimits())
	if err != nil {
		t.Fatalf("NewSelectedProjection() error = %v", err)
	}
	intent := mustEvaluateCompliance(t, ModeStrict, projection, DefaultLimits()).FeedbackIntent()
	if !intent.Requested() || intent.RelayRequired() || intent.RelaySequence() != 0 || intent.HistoryCoverage() != HistoryNotEvaluated {
		t.Fatalf("current request-only intent = %#v", intent)
	}
}

// TestFeedbackFindingLimitIsPrecounted verifies no partial intent or decision.
func TestFeedbackFindingLimitIsPrecounted(t *testing.T) {
	projection := mustComplianceHistory(t, HistoryComplete, mustFeedbackHop(t, 1, true, true))
	limits := DefaultLimits()
	limits.MaxFindings = 3
	if decision := mustEvaluateCompliance(t, ModeStrict, projection, limits); len(decision.Findings()) != 3 || !decision.FeedbackIntent().RelayRequired() {
		t.Fatalf("exact feedback limit = %#v", decision)
	}
	limits.MaxFindings = 2
	config := DefaultConfig()
	config.Limits = limits
	evaluator, err := NewEvaluator(config)
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}
	decision, err := evaluator.EvaluateProjection(projection)
	if !IsErrorCode(err, ErrorLimitExceeded) || !decision.IsZero() {
		t.Fatalf("over feedback limit = %#v error=%v", decision, err)
	}
}

type sequencedReason struct {
	reason   PolicyReason
	sequence uint64
}

// mustFeedbackHop constructs one synthetic feedback fact at a valid transition.
func mustFeedbackHop(t *testing.T, sequence uint64, feedback, feedHere bool) HopFact {
	t.Helper()
	transition := TransitionUnchanged
	if sequence == 1 {
		transition = TransitionOrigin
	}
	hop, err := NewAuthenticatedHopFact(sequence, transition, false, false, feedback, feedHere, false)
	if err != nil {
		t.Fatalf("NewAuthenticatedHopFact() error = %v", err)
	}
	return hop
}

// feedbackFindingPairs returns only ordered feedback-class findings.
func feedbackFindingPairs(findings []Finding) []sequencedReason {
	result := make([]sequencedReason, 0)
	for _, finding := range findings {
		switch finding.Reason() {
		case ReasonFeedbackRequested, ReasonFeedbackRelaySelected, ReasonFeedHereInert:
			sequence, _ := finding.Sequence()
			result = append(result, sequencedReason{finding.Reason(), sequence})
		}
	}
	return result
}
