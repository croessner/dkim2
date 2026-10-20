package policy

import "testing"

// TestEvaluatorFindingHardBoundaryDoesNotTruncate proves exact 128 output and one-over no-decision behavior.
func TestEvaluatorFindingHardBoundaryDoesNotTruncate(t *testing.T) {
	hops := maximumOutputHops(t)
	exactProjection, err := newHistoricalProjection(uint64(len(hops)), HistoryComplete, hops, DefaultLimits())
	if err != nil {
		t.Fatalf("newHistoricalProjection(exact) error = %v", err)
	}
	evaluator, err := NewEvaluator(DefaultConfig())
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}
	exact, err := evaluator.EvaluateProjection(exactProjection)
	if err != nil || !exact.Valid() || len(exact.Findings()) != 128 || len(exact.Actions()) != 1 {
		t.Fatalf("exact decision = findings %d actions %d error %v", len(exact.Findings()), len(exact.Actions()), err)
	}
	last := len(hops) - 1
	hops[last] = mustProjectionHopWithFlags(t, uint64(last+1), transitionForTestIndex(last), true, false, true)
	overProjection, err := newHistoricalProjection(uint64(len(hops)), HistoryComplete, hops, DefaultLimits())
	if err != nil {
		t.Fatalf("newHistoricalProjection(over) error = %v", err)
	}
	over, err := evaluator.EvaluateProjection(overProjection)
	policyErr, ok := err.(*Error)
	if !ok || policyErr.Code() != ErrorLimitExceeded || policyErr.LimitName() != limitNameFindings || policyErr.ConfiguredLimit() != 128 || policyErr.ObservedCount() != 129 || !over.IsZero() || len(over.Actions()) != 0 {
		t.Fatalf("one-over decision/error = %#v/%#v", over, err)
	}
}

// TestDecisionRejectsZeroMultipleUnknownAndMismatchedActions proves action cardinality and verdict binding are closed.
func TestDecisionRejectsZeroMultipleUnknownAndMismatchedActions(t *testing.T) {
	evaluator, err := NewEvaluator(DefaultConfig())
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}
	valid, err := evaluator.evaluateBase(ProtocolPASS)
	if err != nil || !valid.Valid() {
		t.Fatalf("evaluateBase() = %#v, %v", valid, err)
	}
	corruptions := []Decision{
		func() Decision { decision := valid; decision.actions = nil; return decision }(),
		func() Decision {
			decision := valid
			decision.actions = []Action{{kind: ActionAccept}, {kind: ActionAccept}}
			return decision
		}(),
		func() Decision {
			decision := valid
			decision.actions = []Action{{kind: ActionKind("future")}}
			return decision
		}(),
		func() Decision { decision := valid; decision.actions = []Action{{kind: ActionReject}}; return decision }(),
	}
	for index, decision := range corruptions {
		if decision.Valid() {
			t.Fatalf("corrupt action decision %d accepted", index)
		}
	}
}

// TestEvaluatorAllocationRemainsBoundedAtMaximumOutput guards proportional allocation at the 128-finding boundary.
func TestEvaluatorAllocationRemainsBoundedAtMaximumOutput(t *testing.T) {
	hops := maximumOutputHops(t)
	projection, err := newHistoricalProjection(uint64(len(hops)), HistoryComplete, hops, DefaultLimits())
	if err != nil {
		t.Fatalf("newHistoricalProjection() error = %v", err)
	}
	evaluator, err := NewEvaluator(DefaultConfig())
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}
	valid := true
	allocations := testing.AllocsPerRun(100, func() {
		decision, evaluateErr := evaluator.EvaluateProjection(projection)
		valid = valid && evaluateErr == nil && decision.Valid() && len(decision.Findings()) == 128
	})
	const generousAllocationCeiling = 256
	if !valid || allocations > generousAllocationCeiling {
		t.Fatalf("maximum-output allocations = %.0f, ceiling %d, valid %t", allocations, generousAllocationCeiling, valid)
	}
}

// maximumOutputHops builds a complete history whose evaluation yields exactly
// the hard finding limit: 63 hops each report feedback and exploded (126
// findings), one final exploded-only hop adds one, and protocol_pass completes
// 128.
func maximumOutputHops(t *testing.T) []HopFact {
	t.Helper()
	hops := make([]HopFact, 64)
	for index := range hops {
		feedback := index < len(hops)-1
		hops[index] = mustProjectionHopWithFlags(t, uint64(index+1), transitionForTestIndex(index), feedback, false, true)
	}
	return hops
}

// mustProjectionHopWithFlags constructs one exact abuse-boundary hop.
func mustProjectionHopWithFlags(t *testing.T, sequence uint64, transition TransitionState, feedback, feedHere, exploded bool) HopFact {
	t.Helper()
	hop, err := NewAuthenticatedHopFact(sequence, transition, feedback, feedHere, exploded)
	if err != nil {
		t.Fatalf("NewAuthenticatedHopFact() error = %v", err)
	}
	return hop
}
