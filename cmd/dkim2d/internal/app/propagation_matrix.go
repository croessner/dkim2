package app

import "github.com/croessner/dkim2"

// propagationDecision is one matrix row result. It is undecided only when
// every evaluation row passed and the request reaches the replay gate.
type propagationDecision struct {
	decided     bool
	result      PropagationResultClass
	disposition PropagationDispositionClass
	failure     PropagationFailureClass
}

// decidedPropagation seals one coherent matrix row.
func decidedPropagation(
	result PropagationResultClass,
	disposition PropagationDispositionClass,
	failure PropagationFailureClass,
) propagationDecision {
	return propagationDecision{
		decided: true, result: result, disposition: disposition, failure: failure,
	}
}

// temporaryPropagation is the fail-closed row for every ambiguous state.
func temporaryPropagation() propagationDecision {
	return decidedPropagation(PropagationTemperror, PropagationDispositionTempfail,
		PropagationFailureNone)
}

// rejectedPropagation is the row for every notification that must not be
// propagated and must surface to the delivering MTA.
func rejectedPropagation() propagationDecision {
	return decidedPropagation(PropagationFail, PropagationDispositionReject,
		PropagationFailureNone)
}

// discardedPropagation is the row for a valid notification that must not be
// propagated and must not be reported as a failure.
func discardedPropagation() propagationDecision {
	return decidedPropagation(PropagationPass, PropagationDispositionDiscard,
		PropagationFailureNone)
}

// classifyPropagationEvaluation applies the evaluation rows of the
// propagation coherence matrix in specification order and stops at the first
// match. It never reaches the replay gate, the rebuild, or a private key for
// an ambiguous or refused state, and it fails closed as temperror for every
// value outside the closed vocabularies. On this route local_hop = not_local
// is a misrouting and is rejected, unlike the informational process
// projection, because the delivering socket is reserved for our own
// return-path addresses.
func classifyPropagationEvaluation(
	outer dkim2.ResultState,
	projection DeliveryStatusProjection,
) propagationDecision {
	if !projection.Valid() {
		return temporaryPropagation()
	}
	switch outer {
	case dkim2.ResultStateTEMPERROR:
		return temporaryPropagation()
	case dkim2.ResultStateFAIL, dkim2.ResultStatePERMERROR:
		return rejectedPropagation()
	case dkim2.ResultStatePASS:
	default:
		return temporaryPropagation()
	}
	if projection.Structure() != dkim2.ReceivedDSNStructureValid {
		return rejectedPropagation()
	}
	switch projection.Embedded() {
	case dkim2.ReceivedDSNEmbeddedUnverified, dkim2.ReceivedDSNEmbeddedAbsent:
		return rejectedPropagation()
	case dkim2.ReceivedDSNEmbeddedTemperror:
		return temporaryPropagation()
	case dkim2.ReceivedDSNEmbeddedVerified, dkim2.ReceivedDSNEmbeddedVerifiedHeadersOnly:
	default:
		return temporaryPropagation()
	}
	switch projection.LocalHop() {
	case dkim2.ReceivedDSNLocalHopMismatch, dkim2.ReceivedDSNLocalHopNotLocal:
		return rejectedPropagation()
	case dkim2.ReceivedDSNLocalHopTemperror, dkim2.ReceivedDSNLocalHopNotEvaluated:
		return temporaryPropagation()
	case dkim2.ReceivedDSNLocalHopLocal:
	default:
		return temporaryPropagation()
	}
	if projection.OuterAlignment() != dkim2.ReceivedDSNOuterAlignmentAligned {
		return rejectedPropagation()
	}
	if projection.RecipientLinkage() != dkim2.ReceivedDSNRecipientLinkageLinked {
		return rejectedPropagation()
	}
	switch projection.Propagation() {
	case dkim2.ReceivedDSNPropagationEligible:
		return propagationDecision{}
	case dkim2.ReceivedDSNPropagationTerminalOrigin,
		dkim2.ReceivedDSNPropagationNotFailure,
		dkim2.ReceivedDSNPropagationForbiddenNullPreviousSender,
		dkim2.ReceivedDSNPropagationUnsupportedChain,
		dkim2.ReceivedDSNPropagationNotApplicable:
		return discardedPropagation()
	case dkim2.ReceivedDSNPropagationNotReconstructable:
		return decidedPropagation(PropagationPermerror, PropagationDispositionDiscard,
			PropagationFailureNotReconstructable)
	default:
		return temporaryPropagation()
	}
}
