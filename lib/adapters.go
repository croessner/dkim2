package dkim2

import (
	"github.com/croessner/dkim2/internal/policy"
	"github.com/croessner/dkim2/internal/service"
)

// adaptServiceResult maps the internal coordinator DTO into the immutable public contract.
func adaptServiceResult(input service.Result) VerifyResult {
	result := adaptServiceResultWithProjection(input, input.PolicyProjection())
	replayProjection, present := input.ReplayProjection()
	result = result.withReplayProjection(replayProjection, present)
	serviceVerifier, verifierPresent := input.VerifierProjection()
	verifierProjection, mapped := adaptVerifierProjection(serviceVerifier)
	return result.withVerifierProjection(verifierProjection, verifierPresent && mapped)
}

// adaptServiceResultWithProjection maps one service result with an explicit sealed clone.
func adaptServiceResultWithProjection(input service.Result, projection policy.Projection) VerifyResult {
	state, okState := adaptState(input.State())
	custody, okCustody := adaptCustody(input.Custody())
	reason, okReason := adaptReason(input.PrimaryReason())
	if input.Draft() != DraftIdentifier || !input.Scope().Known() ||
		!input.HistoricalContent().Known() || !input.HistoricalSignatures().Known() ||
		!okState || !okCustody || !okReason {
		return internalContractResult(newVerificationTarget(input.Target().Sequence, input.Target().Instance))
	}
	if !projection.Valid() || !projectionMatchesServiceResult(projection, input) {
		projection = policy.Projection{}
	}
	checks := input.Checks()
	signatures := input.SignatureSets()
	if len(checks) > HardMaxCheckFacts || len(signatures) > HardMaxSignatureFacts {
		return internalContractResult(newVerificationTarget(input.Target().Sequence, input.Target().Instance))
	}
	publicChecks := make([]CheckFact, 0, len(checks))
	for _, fact := range checks {
		class, classOK := adaptCheckClass(fact.Class)
		factReason, reasonOK := adaptReason(fact.Reason)
		if !classOK || !reasonOK {
			return internalContractResult(newVerificationTarget(input.Target().Sequence, input.Target().Instance))
		}
		publicChecks = append(publicChecks, newCheckFact(class, factReason))
	}
	publicSignatures := make([]SignatureSetFact, 0, len(signatures))
	for _, fact := range signatures {
		algorithm, algorithmOK := adaptAlgorithm(fact.Algorithm)
		status, statusOK := adaptSignatureStatus(fact.Status)
		factReason, reasonOK := adaptReason(fact.Reason)
		if !algorithmOK || !statusOK || !reasonOK {
			return internalContractResult(newVerificationTarget(input.Target().Sequence, input.Target().Instance))
		}
		metadata := newKeyPolicyMetadata(fact.KeyPolicy.TestingDeclared, fact.KeyPolicy.StrictIdentityDeclared)
		if fact.KeyPolicy.StrictIdentityApplicable {
			return internalContractResult(newVerificationTarget(input.Target().Sequence, input.Target().Instance))
		}
		publicSignatures = append(publicSignatures, newSignatureSetFact(algorithm, status, factReason, fact.Selector, metadata))
	}
	scope, content, historicalSignatures, ok := adaptHistory(input)
	if !ok {
		return internalContractResult(newVerificationTarget(input.Target().Sequence, input.Target().Instance))
	}
	return newVerifyResult(verifyResultData{
		state: state, scope: scope,
		historicalContent: content, historicalSignatures: historicalSignatures,
		custodyStructure: custody, target: newVerificationTarget(input.Target().Sequence, input.Target().Instance),
		primaryReason: reason, checks: publicChecks, signatures: publicSignatures,
		policyProjection: projection,
	})
}

func adaptHistory(input service.Result) (VerificationScope, HistoricalState, HistoricalState, bool) {
	if input.Scope() == service.ScopeCurrent && input.HistoricalContent() == service.HistoricalNotEvaluated && input.HistoricalSignatures() == service.HistoricalNotEvaluated {
		return VerificationScopeCurrent, HistoricalStateNotEvaluated, HistoricalStateNotEvaluated, true
	}
	if input.Scope() != service.ScopeChain || input.HistoricalSignatures() != service.HistoricalComplete {
		return "", "", "", false
	}
	switch input.HistoricalContent() {
	case service.HistoricalComplete:
		return VerificationScopeChain, HistoricalStateComplete, HistoricalStateComplete, true
	case service.HistoricalPartial:
		return VerificationScopeChain, HistoricalStatePartial, HistoricalStateComplete, true
	default:
		return "", "", "", false
	}
}

// projectionMatchesServiceResult validates facade transfer without rebuilding provenance.
func projectionMatchesServiceResult(projection policy.Projection, input service.Result) bool {
	wantProtocol, ok := mapServicePolicyProtocol(input.State())
	if !ok || projection.Protocol() != wantProtocol {
		return false
	}
	if projection.Form() == policy.TargetUnavailable {
		return input.Target() == (service.Target{}) && input.State() == service.StatePERMERROR && preTargetReasonMatchesService(projection.PreTargetReason(), input.PrimaryReason())
	}
	reason, reasonOK := mapServiceVerificationReason(input.PrimaryReason())
	return projection.Form() == policy.TargetSelected && reasonOK && projection.VerificationReason() == reason && input.Target().Sequence > 0 && projection.TargetSequence() == input.Target().Sequence
}

// mapServiceVerificationReason exhaustively binds selected aggregate reason provenance.
func mapServiceVerificationReason(reason service.Reason) (policy.VerificationReason, bool) {
	if reason == service.ReasonInvalidRequest || !reason.Known() {
		return "", false
	}
	mapped := policy.VerificationReason(reason)
	return mapped, mapped.Known()
}

// preTargetReasonMatchesService binds every unavailable provenance reason exactly.
func preTargetReasonMatchesService(reason policy.PreTargetReason, serviceReason service.Reason) bool {
	switch reason {
	case policy.PreTargetLimitExceeded:
		return serviceReason == service.ReasonLimitExceeded
	case policy.PreTargetMalformedMessage:
		return serviceReason == service.ReasonMalformedMessage
	case policy.PreTargetMalformedProtocol:
		return serviceReason == service.ReasonMalformedProtocol
	case policy.PreTargetDuplicateHashAlgorithm:
		return serviceReason == service.ReasonDuplicateHashAlgorithm
	case policy.PreTargetDuplicateSelector:
		return serviceReason == service.ReasonDuplicateSelector
	case policy.PreTargetTooManySignatures:
		return serviceReason == service.ReasonTooManySignatures
	case policy.PreTargetMissingProtocol:
		return serviceReason == service.ReasonMissingProtocol
	case policy.PreTargetSequenceInvalid:
		return serviceReason == service.ReasonSequenceInvalid
	case policy.PreTargetInternalContract:
		return serviceReason == service.ReasonInternalContract
	default:
		return false
	}
}

// mapServicePolicyProtocol exhaustively validates the projection protocol class.
func mapServicePolicyProtocol(state service.State) (policy.ProtocolClass, bool) {
	switch state {
	case service.StatePASS:
		return policy.ProtocolPASS, true
	case service.StateFAIL:
		return policy.ProtocolFAIL, true
	case service.StatePERMERROR:
		return policy.ProtocolPERMERROR, true
	case service.StateTEMPERROR:
		return policy.ProtocolTEMPERROR, true
	default:
		return "", false
	}
}

// adaptState maps the closed internal four-state vocabulary.
func adaptState(value service.State) (ResultState, bool) {
	switch value {
	case service.StatePASS:
		return ResultStatePASS, true
	case service.StateFAIL:
		return ResultStateFAIL, true
	case service.StatePERMERROR:
		return ResultStatePERMERROR, true
	case service.StateTEMPERROR:
		return ResultStateTEMPERROR, true
	default:
		return "", false
	}
}

// adaptCustody maps the closed structural coverage vocabulary.
func adaptCustody(value service.Custody) (CustodyStructure, bool) {
	switch value {
	case service.CustodyNotEvaluated:
		return CustodyStructureNotEvaluated, true
	case service.CustodyNotPresent:
		return CustodyStructureNotPresent, true
	case service.CustodyNDLinksEvaluated:
		return CustodyStructureNDLinksEvaluated, true
	case service.CustodyTerminalNDRequiresOOB:
		return CustodyStructureTerminalNDRequiresOOB, true
	default:
		return "", false
	}
}

// adaptCheckClass maps the closed internal check vocabulary.
func adaptCheckClass(value service.CheckClass) (CheckClass, bool) {
	if !value.Known() {
		return "", false
	}
	class := CheckClass(value)
	return class, class.Known()
}

// adaptReason maps the closed internal reason vocabulary.
func adaptReason(value service.Reason) (ReasonCode, bool) {
	if !value.Known() {
		return "", false
	}
	reason := ReasonCode(value)
	return reason, reason.Known()
}

// adaptAlgorithm maps bounded algorithm-family detail.
func adaptAlgorithm(value service.Algorithm) (Algorithm, bool) {
	if !value.Known() {
		return AlgorithmUnknown, false
	}
	algorithm := Algorithm(value)
	return algorithm, algorithm.Known()
}

// adaptSignatureStatus maps the closed per-set status vocabulary.
func adaptSignatureStatus(value service.SignatureStatus) (SignatureStatus, bool) {
	if !value.Known() {
		return "", false
	}
	status := SignatureStatus(value)
	return status, status.Known()
}
