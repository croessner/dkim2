package app

import (
	"testing"

	"github.com/croessner/dkim2"
)

// eligibleProjection is the projection of a notification that reached the
// last matrix row: every stage passed and propagation is eligible.
func eligibleProjection() DeliveryStatusProjection {
	return DeliveryStatusProjection{
		structure:        dkim2.ReceivedDSNStructureValid,
		embedded:         dkim2.ReceivedDSNEmbeddedVerified,
		localHop:         dkim2.ReceivedDSNLocalHopLocal,
		outerAlignment:   dkim2.ReceivedDSNOuterAlignmentAligned,
		recipientLinkage: dkim2.ReceivedDSNRecipientLinkageLinked,
		propagation:      dkim2.ReceivedDSNPropagationEligible,
		valid:            true,
	}
}

// withPropagation returns the eligible projection with one replaced member.
func withPropagation(value dkim2.ReceivedDSNPropagation) DeliveryStatusProjection {
	projection := eligibleProjection()
	projection.propagation = value
	return projection
}

func TestPropagationEvaluationMatrixFollowsSpecificationOrder(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		outer       dkim2.ResultState
		projection  DeliveryStatusProjection
		result      PropagationResultClass
		disposition PropagationDispositionClass
		failure     PropagationFailureClass
	}{
		{
			name: "outer temperror", outer: dkim2.ResultStateTEMPERROR,
			projection: eligibleProjection(),
			result:     PropagationTemperror, disposition: PropagationDispositionTempfail,
		},
		{
			name: "outer fail", outer: dkim2.ResultStateFAIL,
			projection: eligibleProjection(),
			result:     PropagationFail, disposition: PropagationDispositionReject,
		},
		{
			name: "outer permerror", outer: dkim2.ResultStatePERMERROR,
			projection: eligibleProjection(),
			result:     PropagationFail, disposition: PropagationDispositionReject,
		},
		{
			name: "structure malformed", outer: dkim2.ResultStatePASS,
			projection: func() DeliveryStatusProjection {
				projection := eligibleProjection()
				projection.structure = dkim2.ReceivedDSNStructureMalformed
				return projection
			}(),
			result: PropagationFail, disposition: PropagationDispositionReject,
		},
		{
			name: "structure limit exceeded", outer: dkim2.ResultStatePASS,
			projection: func() DeliveryStatusProjection {
				projection := eligibleProjection()
				projection.structure = dkim2.ReceivedDSNStructureLimitExceeded
				return projection
			}(),
			result: PropagationFail, disposition: PropagationDispositionReject,
		},
		{
			name: "embedded unverified", outer: dkim2.ResultStatePASS,
			projection: func() DeliveryStatusProjection {
				projection := eligibleProjection()
				projection.embedded = dkim2.ReceivedDSNEmbeddedUnverified
				return projection
			}(),
			result: PropagationFail, disposition: PropagationDispositionReject,
		},
		{
			name: "embedded absent", outer: dkim2.ResultStatePASS,
			projection: func() DeliveryStatusProjection {
				projection := eligibleProjection()
				projection.embedded = dkim2.ReceivedDSNEmbeddedAbsent
				return projection
			}(),
			result: PropagationFail, disposition: PropagationDispositionReject,
		},
		{
			name: "local hop mismatch", outer: dkim2.ResultStatePASS,
			projection: func() DeliveryStatusProjection {
				projection := eligibleProjection()
				projection.localHop = dkim2.ReceivedDSNLocalHopMismatch
				return projection
			}(),
			result: PropagationFail, disposition: PropagationDispositionReject,
		},
		{
			name: "outer alignment misaligned", outer: dkim2.ResultStatePASS,
			projection: func() DeliveryStatusProjection {
				projection := eligibleProjection()
				projection.outerAlignment = dkim2.ReceivedDSNOuterAlignmentMisaligned
				return projection
			}(),
			result: PropagationFail, disposition: PropagationDispositionReject,
		},
		{
			name: "recipient linkage unlinked", outer: dkim2.ResultStatePASS,
			projection: func() DeliveryStatusProjection {
				projection := eligibleProjection()
				projection.recipientLinkage = dkim2.ReceivedDSNRecipientLinkageUnlinked
				return projection
			}(),
			result: PropagationFail, disposition: PropagationDispositionReject,
		},
		{
			name: "local hop not local is misrouting", outer: dkim2.ResultStatePASS,
			projection: func() DeliveryStatusProjection {
				projection := eligibleProjection()
				projection.localHop = dkim2.ReceivedDSNLocalHopNotLocal
				return projection
			}(),
			result: PropagationFail, disposition: PropagationDispositionReject,
		},
		{
			name: "embedded temperror", outer: dkim2.ResultStatePASS,
			projection: func() DeliveryStatusProjection {
				projection := eligibleProjection()
				projection.embedded = dkim2.ReceivedDSNEmbeddedTemperror
				return projection
			}(),
			result: PropagationTemperror, disposition: PropagationDispositionTempfail,
		},
		{
			name: "local hop temperror", outer: dkim2.ResultStatePASS,
			projection: func() DeliveryStatusProjection {
				projection := eligibleProjection()
				projection.localHop = dkim2.ReceivedDSNLocalHopTemperror
				return projection
			}(),
			result: PropagationTemperror, disposition: PropagationDispositionTempfail,
		},
		{
			name: "local hop not evaluated fails closed", outer: dkim2.ResultStatePASS,
			projection: func() DeliveryStatusProjection {
				projection := eligibleProjection()
				projection.localHop = dkim2.ReceivedDSNLocalHopNotEvaluated
				return projection
			}(),
			result: PropagationTemperror, disposition: PropagationDispositionTempfail,
		},
		{
			name: "terminal origin", outer: dkim2.ResultStatePASS,
			projection: withPropagation(dkim2.ReceivedDSNPropagationTerminalOrigin),
			result:     PropagationPass, disposition: PropagationDispositionDiscard,
		},
		{
			name: "not failure", outer: dkim2.ResultStatePASS,
			projection: withPropagation(dkim2.ReceivedDSNPropagationNotFailure),
			result:     PropagationPass, disposition: PropagationDispositionDiscard,
		},
		{
			name: "forbidden null previous sender", outer: dkim2.ResultStatePASS,
			projection: withPropagation(dkim2.ReceivedDSNPropagationForbiddenNullPreviousSender),
			result:     PropagationPass, disposition: PropagationDispositionDiscard,
		},
		{
			name: "unsupported chain", outer: dkim2.ResultStatePASS,
			projection: withPropagation(dkim2.ReceivedDSNPropagationUnsupportedChain),
			result:     PropagationPass, disposition: PropagationDispositionDiscard,
		},
		{
			name: "not applicable", outer: dkim2.ResultStatePASS,
			projection: withPropagation(dkim2.ReceivedDSNPropagationNotApplicable),
			result:     PropagationPass, disposition: PropagationDispositionDiscard,
		},
		{
			name: "not reconstructable", outer: dkim2.ResultStatePASS,
			projection: withPropagation(dkim2.ReceivedDSNPropagationNotReconstructable),
			result:     PropagationPermerror, disposition: PropagationDispositionDiscard,
			failure: PropagationFailureNotReconstructable,
		},
		{
			name: "propagation not evaluated fails closed", outer: dkim2.ResultStatePASS,
			projection: withPropagation(dkim2.ReceivedDSNPropagationNotEvaluated),
			result:     PropagationTemperror, disposition: PropagationDispositionTempfail,
		},
		{
			name: "eligible reaches the replay gate", outer: dkim2.ResultStatePASS,
			projection: eligibleProjection(),
			result:     "", disposition: "",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			decision := classifyPropagationEvaluation(testCase.outer, testCase.projection)
			if testCase.result == "" {
				if decision.decided {
					t.Fatalf("eligible input decided early as %q/%q",
						decision.result, decision.disposition)
				}
				return
			}
			if !decision.decided || decision.result != testCase.result ||
				decision.disposition != testCase.disposition ||
				decision.failure != testCase.failure {
				t.Fatalf("got %v %q/%q failure %q, want %q/%q failure %q",
					decision.decided, decision.result, decision.disposition,
					decision.failure, testCase.result, testCase.disposition,
					testCase.failure)
			}
			if !validPropagationOutcome(decision.result, decision.disposition,
				decision.failure, false) {
				t.Fatal("decision violates the operation coherence rule")
			}
		})
	}
}

func TestPropagationEvaluationMatrixPrefersEarlierRows(t *testing.T) {
	t.Parallel()

	projection := eligibleProjection()
	projection.structure = dkim2.ReceivedDSNStructureMalformed
	projection.embedded = dkim2.ReceivedDSNEmbeddedTemperror
	decision := classifyPropagationEvaluation(dkim2.ResultStatePASS, projection)
	if !decision.decided || decision.result != PropagationFail {
		t.Fatalf("structure row did not win over the temperror row: %q", decision.result)
	}
	decision = classifyPropagationEvaluation(dkim2.ResultStateTEMPERROR, projection)
	if !decision.decided || decision.result != PropagationTemperror {
		t.Fatalf("outer temperror row did not win: %q", decision.result)
	}
}

func TestPropagationEvaluationMatrixFailsClosedOnAnInvalidProjection(t *testing.T) {
	t.Parallel()

	decision := classifyPropagationEvaluation(dkim2.ResultStatePASS, DeliveryStatusProjection{})
	if !decision.decided || decision.result != PropagationTemperror ||
		decision.disposition != PropagationDispositionTempfail {
		t.Fatalf("invalid projection did not fail closed: %v %q", decision.decided, decision.result)
	}
}

func TestPropagationEvaluationMatrixFailsClosedOnAnUnknownOuterState(t *testing.T) {
	t.Parallel()

	decision := classifyPropagationEvaluation(dkim2.ResultState("unknown"), eligibleProjection())
	if !decision.decided || decision.result != PropagationTemperror {
		t.Fatalf("unknown outer state did not fail closed: %v %q", decision.decided, decision.result)
	}
}

func TestPropagationOutcomeCoherenceRule(t *testing.T) {
	t.Parallel()

	results := []PropagationResultClass{
		PropagationPass, PropagationFail, PropagationPermerror, PropagationTemperror,
	}
	dispositions := []PropagationDispositionClass{
		PropagationDispositionAccept, PropagationDispositionReject,
		PropagationDispositionDiscard, PropagationDispositionTempfail,
	}
	failures := []PropagationFailureClass{
		PropagationFailureNone, PropagationFailureNotReconstructable,
		PropagationFailureUnprovisionedDomain,
	}
	permitted := map[string]struct{}{
		"pass|accept||true":                            {},
		"pass|discard||false":                          {},
		"fail|reject||false":                           {},
		"permerror|discard|not_reconstructable|false":  {},
		"permerror|discard|unprovisioned_domain|false": {},
		"temperror|tempfail||false":                    {},
	}
	for _, result := range results {
		for _, disposition := range dispositions {
			for _, failure := range failures {
				for _, signed := range []bool{false, true} {
					key := string(result) + "|" + string(disposition) + "|" +
						string(failure) + "|" + boolText(signed)
					_, want := permitted[key]
					if got := validPropagationOutcome(result, disposition, failure, signed); got != want {
						t.Fatalf("combination %s: got %v want %v", key, got, want)
					}
				}
			}
		}
	}
}

// boolText renders one boolean as its stable lowercase literal.
func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
