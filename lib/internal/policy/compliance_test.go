package policy

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// TestDoNotModifyEvaluatesOnlyLaterAuthenticatedTransitions verifies the transition table.
func TestDoNotModifyEvaluatesOnlyLaterAuthenticatedTransitions(t *testing.T) {
	tests := []struct {
		transition TransitionState
		state      ComplianceState
		reason     PolicyReason
		verdict    Verdict
	}{
		{TransitionBodyChanged, ComplianceViolated, ReasonDoNotModifyViolated, VerdictReject},
		{TransitionHeadersChanged, ComplianceViolated, ReasonDoNotModifyViolated, VerdictReject},
		{TransitionBodyAndHeadersChanged, ComplianceViolated, ReasonDoNotModifyViolated, VerdictReject},
		{TransitionUnchanged, ComplianceHonored, ReasonDoNotModifyHonored, VerdictAccept},
		{TransitionHeaderAdditionOnly, ComplianceHonored, ReasonDoNotModifyHonored, VerdictAccept},
		{TransitionIndeterminate, ComplianceIndeterminate, ReasonDoNotModifyIndeterminate, VerdictAccept},
	}
	for _, tt := range tests {
		t.Run(string(tt.transition), func(t *testing.T) {
			projection := mustComplianceHistory(t, HistoryComplete,
				mustComplianceHop(t, 1, TransitionOrigin, true, false, false),
				mustComplianceHop(t, 2, tt.transition, false, false, false),
			)
			decision := mustEvaluateCompliance(t, ModeStrict, projection, DefaultLimits())
			if decision.DoNotModifyCompliance() != tt.state || decision.Verdict() != tt.verdict || !hasSequencedFinding(decision, tt.reason, 1) {
				t.Fatalf("decision = state=%q verdict=%q findings=%v", decision.DoNotModifyCompliance(), decision.Verdict(), findingReasons(decision.Findings()))
			}
		})
	}
}

// TestDoNotModifyIgnoresBeforeAndSameHopTransitions verifies strictly-later semantics.
func TestDoNotModifyIgnoresBeforeAndSameHopTransitions(t *testing.T) {
	tests := []struct {
		name   string
		hops   []HopFact
		want   ComplianceState
		reason PolicyReason
	}{
		{name: "same hop", hops: []HopFact{
			mustComplianceHop(t, 1, TransitionOrigin, false, false, false),
			mustComplianceHop(t, 2, TransitionBodyChanged, true, false, false),
			mustComplianceHop(t, 3, TransitionUnchanged, false, false, false),
		}, want: ComplianceHonored},
		{name: "before request", hops: []HopFact{
			mustComplianceHop(t, 1, TransitionOrigin, false, false, false),
			mustComplianceHop(t, 2, TransitionBodyChanged, false, false, false),
			mustComplianceHop(t, 3, TransitionUnchanged, true, false, false),
			mustComplianceHop(t, 4, TransitionHeaderAdditionOnly, false, false, false),
		}, want: ComplianceHonored},
		{name: "after request", hops: []HopFact{
			mustComplianceHop(t, 1, TransitionOrigin, false, false, false),
			mustComplianceHop(t, 2, TransitionUnchanged, true, false, false),
			mustComplianceHop(t, 3, TransitionBodyChanged, false, false, false),
		}, want: ComplianceViolated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := mustEvaluateCompliance(t, ModeStrict, mustComplianceHistory(t, HistoryComplete, tt.hops...), DefaultLimits())
			if decision.DoNotModifyCompliance() != tt.want {
				t.Fatalf("modify compliance = %q, want %q", decision.DoNotModifyCompliance(), tt.want)
			}
		})
	}
}

// TestDoNotModifyRequiresPositiveLaterEvidenceAndViolationDominates verifies aggregation.
func TestDoNotModifyRequiresPositiveLaterEvidenceAndViolationDominates(t *testing.T) {
	tests := []struct {
		name     string
		hops     []HopFact
		want     ComplianceState
		reason   PolicyReason
		sequence uint64
	}{
		{name: "terminal request has no positive evidence", hops: []HopFact{
			mustComplianceHop(t, 1, TransitionOrigin, false, false, false),
			mustComplianceHop(t, 2, TransitionUnchanged, true, false, false),
		}, want: ComplianceIndeterminate, reason: ReasonDoNotModifyIndeterminate, sequence: 2},
		{name: "indeterminate then violation", hops: []HopFact{
			mustComplianceHop(t, 1, TransitionOrigin, true, false, false),
			mustComplianceHop(t, 2, TransitionIndeterminate, false, false, false),
			mustComplianceHop(t, 3, TransitionBodyChanged, false, false, false),
		}, want: ComplianceViolated, reason: ReasonDoNotModifyViolated, sequence: 1},
		{name: "violation then indeterminate", hops: []HopFact{
			mustComplianceHop(t, 1, TransitionOrigin, true, false, false),
			mustComplianceHop(t, 2, TransitionBodyChanged, false, false, false),
			mustComplianceHop(t, 3, TransitionIndeterminate, false, false, false),
		}, want: ComplianceViolated, reason: ReasonDoNotModifyViolated, sequence: 1},
		{name: "indeterminate then unchanged", hops: []HopFact{
			mustComplianceHop(t, 1, TransitionOrigin, true, false, false),
			mustComplianceHop(t, 2, TransitionIndeterminate, false, false, false),
			mustComplianceHop(t, 3, TransitionUnchanged, false, false, false),
		}, want: ComplianceIndeterminate, reason: ReasonDoNotModifyIndeterminate, sequence: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := mustEvaluateCompliance(t, ModeStrict, mustComplianceHistory(t, HistoryComplete, tt.hops...), DefaultLimits())
			if decision.DoNotModifyCompliance() != tt.want || !hasSequencedFinding(decision, tt.reason, tt.sequence) {
				t.Fatalf("modify compliance = %q, want %q", decision.DoNotModifyCompliance(), tt.want)
			}
		})
	}
}

// TestMultipleModificationRequestsProduceOrderedViolations verifies bounded per-request output.
func TestMultipleModificationRequestsProduceOrderedViolations(t *testing.T) {
	projection := mustComplianceHistory(t, HistoryComplete,
		mustComplianceHop(t, 1, TransitionOrigin, true, false, false),
		mustComplianceHop(t, 2, TransitionUnchanged, true, false, false),
		mustComplianceHop(t, 3, TransitionBodyChanged, false, false, false),
	)
	decision := mustEvaluateCompliance(t, ModeStrict, projection, DefaultLimits())
	sequences := make([]uint64, 0, 2)
	for _, finding := range decision.Findings() {
		if finding.Reason() == ReasonDoNotModifyViolated {
			sequence, _ := finding.Sequence()
			sequences = append(sequences, sequence)
		}
	}
	if !slices.Equal(sequences, []uint64{1, 2}) || len(decision.Actions()) != 1 || decision.PrimaryReason() != ReasonDoNotModifyViolated {
		t.Fatalf("multiple violations = sequences=%v decision=%#v", sequences, decision)
	}
}

// TestDoNotExplodeRequiresLaterPositiveReport verifies absence and same-hop safety.
func TestDoNotExplodeRequiresLaterPositiveReport(t *testing.T) {
	tests := []struct {
		name     string
		hops     []HopFact
		state    ComplianceState
		verdict  Verdict
		reported []uint64
	}{
		{name: "earlier and same are not later", hops: []HopFact{
			mustComplianceHop(t, 1, TransitionOrigin, false, false, true),
			mustComplianceHop(t, 2, TransitionUnchanged, false, true, true),
			mustComplianceHop(t, 3, TransitionUnchanged, false, false, false),
		}, state: ComplianceIndeterminate, verdict: VerdictAccept, reported: []uint64{1, 2}},
		{name: "later report violates", hops: []HopFact{
			mustComplianceHop(t, 1, TransitionOrigin, false, true, false),
			mustComplianceHop(t, 2, TransitionUnchanged, false, false, true),
		}, state: ComplianceViolated, verdict: VerdictReject, reported: []uint64{2}},
		{name: "absence never honors", hops: []HopFact{
			mustComplianceHop(t, 1, TransitionOrigin, false, true, false),
			mustComplianceHop(t, 2, TransitionUnchanged, false, false, false),
		}, state: ComplianceIndeterminate, verdict: VerdictAccept},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := mustEvaluateCompliance(t, ModeStrict, mustComplianceHistory(t, HistoryComplete, tt.hops...), DefaultLimits())
			if decision.DoNotExplodeCompliance() != tt.state || decision.Verdict() != tt.verdict {
				t.Fatalf("decision = state=%q verdict=%q", decision.DoNotExplodeCompliance(), decision.Verdict())
			}
			for _, sequence := range tt.reported {
				if !hasSequencedFinding(decision, ReasonExplodedReported, sequence) {
					t.Fatalf("missing exploded report at %d", sequence)
				}
			}
			if hasFindingReason(decision, PolicyReason("donotexplode_honored")) {
				t.Fatal("absence created a false donotexplode honor")
			}
		})
	}
}

// TestComplianceDistinguishesCurrentPartialAndCompleteCoverage verifies explicit coverage states.
func TestComplianceDistinguishesCurrentPartialAndCompleteCoverage(t *testing.T) {
	passSet := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPass, SetReasonNone, false, false)
	currentHop := mustComplianceHop(t, 1, TransitionOrigin, true, true, true)
	current, err := NewSelectedProjection(ProtocolPASS, VerificationReasonNone, 1, []HopFact{currentHop}, []SignatureFact{passSet}, DefaultLimits())
	if err != nil {
		t.Fatalf("NewSelectedProjection() error = %v", err)
	}
	currentDecision := mustEvaluateCompliance(t, ModeStrict, current, DefaultLimits())
	if currentDecision.DoNotModifyCompliance() != ComplianceNotEvaluated || currentDecision.DoNotExplodeCompliance() != ComplianceNotEvaluated ||
		!hasSequencedFinding(currentDecision, ReasonDoNotModifyNotEvaluated, 1) || !hasSequencedFinding(currentDecision, ReasonDoNotExplodeNotEvaluated, 1) || !hasSequencedFinding(currentDecision, ReasonExplodedReported, 1) {
		t.Fatalf("current decision = %#v", currentDecision)
	}

	partial := mustComplianceHistory(t, HistoryIndeterminate,
		mustComplianceHop(t, 1, TransitionOrigin, true, true, false),
		mustComplianceHop(t, 3, TransitionUnchanged, false, false, false),
	)
	partialDecision := mustEvaluateCompliance(t, ModeStrict, partial, DefaultLimits())
	if partialDecision.DoNotModifyCompliance() != ComplianceIndeterminate || partialDecision.DoNotExplodeCompliance() != ComplianceIndeterminate ||
		!hasSequencedFinding(partialDecision, ReasonDoNotModifyIndeterminate, 1) || !hasSequencedFinding(partialDecision, ReasonDoNotExplodeIndeterminate, 1) {
		t.Fatalf("partial decision = %#v", partialDecision)
	}
}

// TestPartialCoverageCannotProveViolation verifies incomplete history never rejects.
func TestPartialCoverageCannotProveViolation(t *testing.T) {
	projection := mustComplianceHistory(t, HistoryIndeterminate,
		mustComplianceHop(t, 1, TransitionOrigin, true, true, false),
		mustComplianceHop(t, 3, TransitionBodyAndHeadersChanged, false, false, true),
	)
	decision := mustEvaluateCompliance(t, ModeStrict, projection, DefaultLimits())
	if decision.DoNotModifyCompliance() != ComplianceIndeterminate || decision.DoNotExplodeCompliance() != ComplianceIndeterminate || decision.Verdict() != VerdictAccept ||
		hasFindingReason(decision, ReasonDoNotModifyViolated) || hasFindingReason(decision, ReasonDoNotExplodeViolated) ||
		!hasSequencedFinding(decision, ReasonDoNotModifyIndeterminate, 1) || !hasSequencedFinding(decision, ReasonDoNotExplodeIndeterminate, 1) ||
		!hasSequencedFinding(decision, ReasonExplodedReported, 3) {
		t.Fatalf("partial violation inference = %#v", decision)
	}
}

// TestComplianceFindingsAreDeterministicAndModeAware verifies class and sequence ordering.
func TestComplianceFindingsAreDeterministicAndModeAware(t *testing.T) {
	projection := mustComplianceHistory(t, HistoryComplete,
		mustComplianceHop(t, 1, TransitionOrigin, true, true, false),
		mustComplianceHop(t, 2, TransitionBodyChanged, true, false, true),
		mustComplianceHop(t, 3, TransitionUnchanged, false, true, true),
	)
	want := []PolicyReason{
		ReasonProtocolPass,
		ReasonDoNotModifyViolated, ReasonDoNotModifyHonored,
		ReasonDoNotExplodeViolated, ReasonDoNotExplodeIndeterminate,
		ReasonExplodedReported, ReasonExplodedReported,
	}
	for _, tt := range []struct {
		mode    Mode
		verdict Verdict
		primary PolicyReason
	}{
		{ModeStrict, VerdictReject, ReasonDoNotModifyViolated},
		{ModePermissive, VerdictAccept, ReasonProtocolPass},
		{ModeTesting, VerdictContinue, ReasonTestingModeObserve},
	} {
		decision := mustEvaluateCompliance(t, tt.mode, projection, DefaultLimits())
		reasons := findingReasons(decision.Findings())
		if tt.mode == ModeTesting {
			wantWithMode := append([]PolicyReason{ReasonProtocolPass, ReasonTestingModeObserve}, want[1:]...)
			if !slices.Equal(reasons, wantWithMode) {
				t.Fatalf("testing findings = %v, want %v", reasons, wantWithMode)
			}
		} else if !slices.Equal(reasons, want) {
			t.Fatalf("findings = %v, want %v", reasons, want)
		}
		if decision.Verdict() != tt.verdict || decision.PrimaryReason() != tt.primary || !decision.Valid() {
			t.Fatalf("mode %q decision = %#v", tt.mode, decision)
		}
	}
}

// TestComplianceFindingLimitPrecountsWithoutPartialDecision verifies exact bounded output.
func TestComplianceFindingLimitPrecountsWithoutPartialDecision(t *testing.T) {
	projection := mustComplianceHistory(t, HistoryComplete,
		mustComplianceHop(t, 1, TransitionOrigin, true, true, false),
		mustComplianceHop(t, 2, TransitionBodyChanged, false, false, true),
	)
	limits := DefaultLimits()
	limits.MaxFindings = 4
	decision := mustEvaluateCompliance(t, ModeStrict, projection, limits)
	if len(decision.Findings()) != 4 {
		t.Fatalf("exact findings = %d", len(decision.Findings()))
	}
	limits.MaxFindings = 3
	config := DefaultConfig()
	config.Limits = limits
	evaluator, err := NewEvaluator(config)
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}
	decision, err = evaluator.EvaluateProjection(projection)
	if !IsErrorCode(err, ErrorLimitExceeded) || !decision.IsZero() {
		t.Fatalf("over-limit decision = %#v error=%v", decision, err)
	}
}

// TestComplianceEvaluatorEnforcesNarrowAuthenticatedHopLimit verifies exact and one-over input.
func TestComplianceEvaluatorEnforcesNarrowAuthenticatedHopLimit(t *testing.T) {
	projection := mustComplianceHistory(t, HistoryComplete,
		mustComplianceHop(t, 1, TransitionOrigin, true, false, false),
		mustComplianceHop(t, 2, TransitionUnchanged, false, false, false),
	)
	limits := DefaultLimits()
	limits.MaxAuthenticatedHops = 2
	if decision := mustEvaluateCompliance(t, ModeStrict, projection, limits); !decision.Valid() {
		t.Fatal("exact hop limit produced invalid decision")
	}
	limits.MaxAuthenticatedHops = 1
	config := DefaultConfig()
	config.Limits = limits
	evaluator, err := NewEvaluator(config)
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}
	decision, err := evaluator.EvaluateProjection(projection)
	if !IsErrorCode(err, ErrorLimitExceeded) || !decision.IsZero() {
		t.Fatalf("over hop limit = %#v error=%v", decision, err)
	}
	var typed *Error
	if !errorsAs(err, &typed) || typed.LimitName() != limitNameAuthenticatedHops || typed.ConfiguredLimit() != 1 || typed.ObservedCount() != 2 {
		t.Fatalf("hop limit metadata = %#v", typed)
	}
}

// TestComplianceDecisionIsImmutableAndDoesNotRetainToxicInput verifies safe value output.
func TestComplianceDecisionIsImmutableAndDoesNotRetainToxicInput(t *testing.T) {
	const toxic = "TOXIC-COMPLIANCE-MARKER"
	projection := mustComplianceHistory(t, HistoryComplete,
		mustComplianceHop(t, 1, TransitionOrigin, true, true, false),
		mustComplianceHop(t, 2, TransitionHeaderAdditionOnly, false, false, true),
	)
	decision := mustEvaluateCompliance(t, ModeStrict, projection, DefaultLimits())
	findings := decision.Findings()
	actions := decision.Actions()
	findings[0] = Finding{}
	actions[0] = Action{}
	if !decision.Valid() || !decision.Findings()[0].Valid() || !decision.Actions()[0].Valid() {
		t.Fatal("compliance decision exposed mutable storage")
	}
	projection.hops[1].transition = TransitionState(toxic)
	evaluator, err := NewEvaluator(DefaultConfig())
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}
	corruptDecision, corruptErr := evaluator.EvaluateProjection(projection)
	if !IsErrorCode(corruptErr, ErrorInternalContract) || !corruptDecision.IsZero() {
		t.Fatalf("corrupt evaluation = %#v error=%v", corruptDecision, corruptErr)
	}
	for _, rendered := range []string{fmt.Sprintf("%v", corruptDecision), fmt.Sprintf("%#v", corruptDecision), fmt.Sprintf("%v", corruptErr), fmt.Sprintf("%#v", corruptErr)} {
		if strings.Contains(rendered, toxic) {
			t.Fatalf("decision retained toxic marker: %s", rendered)
		}
	}
}

// mustComplianceHistory constructs one valid synthetic authenticated history.
func mustComplianceHistory(t *testing.T, coverage HistoryCoverage, hops ...HopFact) Projection {
	t.Helper()
	target := uint64(0)
	for _, hop := range hops {
		if hop.Sequence() > target {
			target = hop.Sequence()
		}
	}
	projection, err := newHistoricalProjection(target, coverage, hops, DefaultLimits())
	if err != nil {
		t.Fatalf("newHistoricalProjection() error = %v", err)
	}
	return projection
}

// mustComplianceHop constructs one bounded hop with compliance flags.
func mustComplianceHop(t *testing.T, sequence uint64, transition TransitionState, modify, explode, exploded bool) HopFact {
	t.Helper()
	hop, err := NewAuthenticatedHopFact(sequence, transition, modify, explode, false, false, exploded)
	if err != nil {
		t.Fatalf("NewAuthenticatedHopFact() error = %v", err)
	}
	return hop
}

// mustEvaluateCompliance evaluates one projection with explicit mode and limits.
func mustEvaluateCompliance(t *testing.T, mode Mode, projection Projection, limits Limits) Decision {
	t.Helper()
	config := DefaultConfig()
	config.Mode = mode
	config.Limits = limits
	evaluator, err := NewEvaluator(config)
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}
	decision, err := evaluator.EvaluateProjection(projection)
	if err != nil {
		t.Fatalf("evaluateProjection() error = %v", err)
	}
	return decision
}

// hasSequencedFinding reports whether a decision contains one exact finding.
func hasSequencedFinding(decision Decision, reason PolicyReason, sequence uint64) bool {
	for _, finding := range decision.Findings() {
		got, ok := finding.Sequence()
		if finding.Reason() == reason && ok && got == sequence {
			return true
		}
	}
	return false
}

// hasFindingReason reports whether a decision contains one reason.
func hasFindingReason(decision Decision, reason PolicyReason) bool {
	for _, finding := range decision.Findings() {
		if finding.Reason() == reason {
			return true
		}
	}
	return false
}
