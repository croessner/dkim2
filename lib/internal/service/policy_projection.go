package service

import (
	"github.com/croessner/dkim2/internal/policy"
	"github.com/croessner/dkim2/internal/verify"
)

// buildSelectedPolicyProjection authenticates parser evidence and seals complete facts.
func buildSelectedPolicyProjection(state State, reason Reason, target Target, input verify.Result, complete []SignatureSetFact) (policy.Projection, error) {
	protocol, ok := policyProtocolClass(state)
	verificationReason, reasonOK := policyVerificationReason(reason)
	if !ok || !reasonOK || target.Sequence == 0 || input.Target().Sequence != target.Sequence || !serviceStateMatchesCoreStatus(state, input.Status()) {
		return policy.Projection{}, newError(ErrorInvalidRequest)
	}
	candidate, ok := input.TargetFlagCandidate()
	if !ok || !candidate.Valid() || candidate.Sequence() != target.Sequence {
		return policy.Projection{}, newError(ErrorInvalidRequest)
	}
	signatures := make([]policy.SignatureFact, 0, len(complete))
	for _, fact := range complete {
		mapped, err := policySignatureFact(fact)
		if err != nil {
			return policy.Projection{}, err
		}
		signatures = append(signatures, mapped)
	}
	var hops []policy.HopFact
	if state == StatePASS {
		transition := policy.TransitionNotEvaluated
		if target.Sequence == 1 {
			transition = policy.TransitionOrigin
		}
		hop, err := policy.NewAuthenticatedHopFact(target.Sequence, transition,
			candidate.DoNotModify(), candidate.DoNotExplode(), candidate.Feedback(), candidate.FeedHere(), candidate.Exploded())
		if err != nil {
			return policy.Projection{}, err
		}
		hops = []policy.HopFact{hop}
	}
	return policy.NewSelectedProjection(protocol, verificationReason, target.Sequence, hops, signatures, policy.DefaultLimits())
}

// policyVerificationReason maps the authoritative aggregate service reason.
func policyVerificationReason(reason Reason) (policy.VerificationReason, bool) {
	if !reason.Known() || reason == ReasonInvalidRequest {
		return "", false
	}
	mapped := policy.VerificationReason(reason)
	return mapped, mapped.Known()
}

// serviceStateMatchesCoreStatus rejects impossible aggregate status upgrades.
func serviceStateMatchesCoreStatus(state State, status verify.TargetStatus) bool {
	switch state {
	case StatePASS:
		return status == verify.TargetStatusPass
	case StateFAIL:
		return status == verify.TargetStatusFail || status == verify.TargetStatusMixed
	case StateTEMPERROR:
		return status == verify.TargetStatusIndeterminate
	case StatePERMERROR:
		return status.Known() && status != verify.TargetStatusNotEvaluated && status != verify.TargetStatusUnknown
	default:
		return false
	}
}

// buildUnavailablePolicyProjection seals one exact pre-target service reason.
func buildUnavailablePolicyProjection(reason Reason) (policy.Projection, error) {
	var mapped policy.PreTargetReason
	switch reason {
	case ReasonLimitExceeded:
		mapped = policy.PreTargetLimitExceeded
	case ReasonMalformedMessage:
		mapped = policy.PreTargetMalformedMessage
	case ReasonMalformedProtocol:
		mapped = policy.PreTargetMalformedProtocol
	case ReasonMissingProtocol:
		mapped = policy.PreTargetMissingProtocol
	case ReasonSequenceInvalid:
		mapped = policy.PreTargetSequenceInvalid
	case ReasonInternalContract:
		mapped = policy.PreTargetInternalContract
	default:
		return policy.Projection{}, newError(ErrorInvalidRequest)
	}
	return policy.NewUnavailableProjection(mapped)
}

// policyProtocolClass exhaustively maps the authoritative service state.
func policyProtocolClass(state State) (policy.ProtocolClass, bool) {
	switch state {
	case StatePASS:
		return policy.ProtocolPASS, true
	case StateFAIL:
		return policy.ProtocolFAIL, true
	case StatePERMERROR:
		return policy.ProtocolPERMERROR, true
	case StateTEMPERROR:
		return policy.ProtocolTEMPERROR, true
	default:
		return "", false
	}
}

// policySignatureFact maps one complete normalized service signature fact.
func policySignatureFact(fact SignatureSetFact) (policy.SignatureFact, error) {
	algorithm, algorithmOK := policySetAlgorithm(fact.Algorithm)
	status, statusOK := policySetStatus(fact.Status)
	reason, reasonOK := policySetReason(fact.Reason)
	if !algorithmOK || !statusOK || !reasonOK || !fact.KeyPolicy.Valid() {
		return policy.SignatureFact{}, newError(ErrorInvalidRequest)
	}
	return policy.NewSignatureFact(algorithm, status, reason, fact.KeyPolicy.TestingDeclared, fact.KeyPolicy.StrictIdentityDeclared)
}

// policySetAlgorithm maps the complete bounded algorithm vocabulary.
func policySetAlgorithm(value Algorithm) (policy.SetAlgorithm, bool) {
	switch value {
	case AlgorithmRSASHA256:
		return policy.SetAlgorithmRSA, true
	case AlgorithmEd25519SHA256:
		return policy.SetAlgorithmEd25519, true
	case AlgorithmUnknown:
		return policy.SetAlgorithmUnknown, true
	default:
		return "", false
	}
}

// policySetStatus maps the complete bounded signature status vocabulary.
func policySetStatus(value SignatureStatus) (policy.SetStatus, bool) {
	switch value {
	case SignaturePASS:
		return policy.SetStatusPass, true
	case SignatureFAIL:
		return policy.SetStatusFail, true
	case SignaturePERMERROR:
		return policy.SetStatusPermerror, true
	case SignatureTEMPERROR:
		return policy.SetStatusTemperror, true
	case SignatureIgnored:
		return policy.SetStatusIgnored, true
	default:
		return "", false
	}
}

// policySetReason maps all signature-set reasons allowed by policy facts.
func policySetReason(value Reason) (policy.SetReason, bool) {
	switch value {
	case ReasonNone:
		return policy.SetReasonNone, true
	case ReasonSignatureMismatch:
		return policy.SetReasonSignatureMismatch, true
	case ReasonUnsupportedAlgorithm:
		return policy.SetReasonUnsupportedAlgorithm, true
	case ReasonMissingKey:
		return policy.SetReasonMissingKey, true
	case ReasonInvalidKey:
		return policy.SetReasonInvalidKey, true
	case ReasonAmbiguousKey:
		return policy.SetReasonAmbiguousKey, true
	case ReasonRevokedKey:
		return policy.SetReasonRevokedKey, true
	case ReasonUnsupportedKeyType:
		return policy.SetReasonUnsupportedKeyType, true
	case ReasonKeyAlgorithmMismatch:
		return policy.SetReasonKeyAlgorithmMismatch, true
	case ReasonProviderTemporary:
		return policy.SetReasonProviderTemporary, true
	case ReasonProviderPermanent:
		return policy.SetReasonProviderPermanent, true
	case ReasonProviderContract:
		return policy.SetReasonProviderContract, true
	case ReasonInternalContract:
		return policy.SetReasonInternalContract, true
	default:
		return "", false
	}
}
