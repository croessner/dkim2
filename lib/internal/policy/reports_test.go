package policy

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// TestRemovedDraft06RequestsCarryNoPolicyMeaning reproduces the Draft-07
// Section 10.10 removal of donotmodify and donotexplode: later modification and
// exploded transitions never produce compliance findings or a reject verdict.
func TestRemovedDraft06RequestsCarryNoPolicyMeaning(t *testing.T) {
	projection := mustHistoryProjection(t, HistoryComplete,
		mustHistoryHop(t, 1, TransitionOrigin, false),
		mustHistoryHop(t, 2, TransitionBodyAndHeadersChanged, true),
		mustHistoryHop(t, 3, TransitionBodyChanged, true),
	)
	decision := mustEvaluateProjection(t, ModeStrict, projection, DefaultLimits())
	want := []PolicyReason{ReasonProtocolPass, ReasonExplodedReported, ReasonExplodedReported}
	if reasons := findingReasons(decision.Findings()); !slices.Equal(reasons, want) {
		t.Fatalf("findings = %v, want %v", reasons, want)
	}
	if decision.Verdict() != VerdictAccept || decision.PrimaryReason() != ReasonProtocolPass || !decision.Valid() {
		t.Fatalf("decision = verdict=%q primary=%q", decision.Verdict(), decision.PrimaryReason())
	}
	for _, removed := range []PolicyReason{"donotmodify_violated", "donotexplode_violated", "donotmodify_honored"} {
		if removed.Known() {
			t.Fatalf("removed reason %q remains known", removed)
		}
	}
}

// TestExplodedReportsDistinguishCurrentPartialAndCompleteCoverage verifies
// exploded reports remain informational at every coverage level.
func TestExplodedReportsDistinguishCurrentPartialAndCompleteCoverage(t *testing.T) {
	passSet := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPass, SetReasonNone)
	currentHop := mustHistoryHop(t, 1, TransitionOrigin, true)
	current, err := NewSelectedProjection(ProtocolPASS, VerificationReasonNone, 1, []HopFact{currentHop}, []SignatureFact{passSet}, DefaultLimits())
	if err != nil {
		t.Fatalf("NewSelectedProjection() error = %v", err)
	}
	currentDecision := mustEvaluateProjection(t, ModeStrict, current, DefaultLimits())
	if !hasSequencedFinding(currentDecision, ReasonExplodedReported, 1) || currentDecision.Verdict() != VerdictAccept {
		t.Fatalf("current decision = %#v", currentDecision)
	}

	partial := mustHistoryProjection(t, HistoryIndeterminate,
		mustHistoryHop(t, 1, TransitionOrigin, false),
		mustHistoryHop(t, 3, TransitionBodyAndHeadersChanged, true),
	)
	partialDecision := mustEvaluateProjection(t, ModeStrict, partial, DefaultLimits())
	if partialDecision.Verdict() != VerdictAccept || !hasSequencedFinding(partialDecision, ReasonExplodedReported, 3) {
		t.Fatalf("partial decision = %#v", partialDecision)
	}
}

// TestReportFindingsAreDeterministicAndModeAware verifies class and sequence ordering.
func TestReportFindingsAreDeterministicAndModeAware(t *testing.T) {
	projection := mustHistoryProjection(t, HistoryComplete,
		mustHistoryHop(t, 1, TransitionOrigin, false),
		mustHistoryHop(t, 2, TransitionBodyChanged, true),
		mustHistoryHop(t, 3, TransitionUnchanged, true),
	)
	want := []PolicyReason{ReasonProtocolPass, ReasonExplodedReported, ReasonExplodedReported}
	for _, tt := range []struct {
		mode    Mode
		verdict Verdict
		primary PolicyReason
	}{
		{ModeStrict, VerdictAccept, ReasonProtocolPass},
		{ModePermissive, VerdictAccept, ReasonProtocolPass},
		{ModeTesting, VerdictContinue, ReasonTestingModeObserve},
	} {
		decision := mustEvaluateProjection(t, tt.mode, projection, DefaultLimits())
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

// TestReportFindingLimitPrecountsWithoutPartialDecision verifies exact bounded output.
func TestReportFindingLimitPrecountsWithoutPartialDecision(t *testing.T) {
	projection := mustHistoryProjection(t, HistoryComplete,
		mustHistoryHop(t, 1, TransitionOrigin, true),
		mustHistoryHop(t, 2, TransitionBodyChanged, true),
	)
	limits := DefaultLimits()
	limits.MaxFindings = 3
	decision := mustEvaluateProjection(t, ModeStrict, projection, limits)
	if len(decision.Findings()) != 3 {
		t.Fatalf("exact findings = %d", len(decision.Findings()))
	}
	limits.MaxFindings = 2
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

// TestEvaluatorEnforcesNarrowAuthenticatedHopLimit verifies exact and one-over input.
func TestEvaluatorEnforcesNarrowAuthenticatedHopLimit(t *testing.T) {
	projection := mustHistoryProjection(t, HistoryComplete,
		mustHistoryHop(t, 1, TransitionOrigin, false),
		mustHistoryHop(t, 2, TransitionUnchanged, false),
	)
	limits := DefaultLimits()
	limits.MaxAuthenticatedHops = 2
	if decision := mustEvaluateProjection(t, ModeStrict, projection, limits); !decision.Valid() {
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

// TestHistoryDecisionIsImmutableAndDoesNotRetainToxicInput verifies safe value output.
func TestHistoryDecisionIsImmutableAndDoesNotRetainToxicInput(t *testing.T) {
	const toxic = "TOXIC-HISTORY-MARKER"
	projection := mustHistoryProjection(t, HistoryComplete,
		mustHistoryHop(t, 1, TransitionOrigin, false),
		mustHistoryHop(t, 2, TransitionHeaderAdditionOnly, true),
	)
	decision := mustEvaluateProjection(t, ModeStrict, projection, DefaultLimits())
	findings := decision.Findings()
	actions := decision.Actions()
	findings[0] = Finding{}
	actions[0] = Action{}
	if !decision.Valid() || !decision.Findings()[0].Valid() || !decision.Actions()[0].Valid() {
		t.Fatal("history decision exposed mutable storage")
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

// mustHistoryProjection constructs one valid synthetic authenticated history.
func mustHistoryProjection(t *testing.T, coverage HistoryCoverage, hops ...HopFact) Projection {
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

// mustHistoryHop constructs one bounded hop with an optional exploded report.
func mustHistoryHop(t *testing.T, sequence uint64, transition TransitionState, exploded bool) HopFact {
	t.Helper()
	hop, err := NewAuthenticatedHopFact(sequence, transition, false, false, exploded)
	if err != nil {
		t.Fatalf("NewAuthenticatedHopFact() error = %v", err)
	}
	return hop
}

// mustEvaluateProjection evaluates one projection with explicit mode and limits.
func mustEvaluateProjection(t *testing.T, mode Mode, projection Projection, limits Limits) Decision {
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
