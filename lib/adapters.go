package dkim2

import "github.com/croessner/dkim2/internal/service"

// adaptServiceResult maps the internal coordinator DTO into the immutable public contract.
func adaptServiceResult(input service.Result) VerifyResult {
	state, okState := adaptState(input.State())
	custody, okCustody := adaptCustody(input.Custody())
	reason, okReason := adaptReason(input.PrimaryReason())
	if input.Draft() != DraftIdentifier || input.Scope() != service.ScopeCurrent ||
		input.HistoricalContent() != service.HistoricalNotEvaluated || input.HistoricalSignatures() != service.HistoricalNotEvaluated ||
		!okState || !okCustody || !okReason {
		return internalContractResult(newVerificationTarget(input.Target().Sequence, input.Target().Instance))
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
		publicSignatures = append(publicSignatures, newSignatureSetFact(algorithm, status, factReason))
	}
	return newVerifyResult(verifyResultData{
		state: state, scope: VerificationScopeCurrent,
		historicalContent: HistoricalStateNotEvaluated, historicalSignatures: HistoricalStateNotEvaluated,
		custodyStructure: custody, target: newVerificationTarget(input.Target().Sequence, input.Target().Instance),
		primaryReason: reason, checks: publicChecks, signatures: publicSignatures,
	})
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
