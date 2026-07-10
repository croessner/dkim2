package verify

import "github.com/croessner/dkim2/internal/signature"

type nextDomainEvaluation struct {
	check       CheckResult
	unsupported bool
}

// validateNextDomainChain enforces exact nd= to immediate-successor d= matching.
func validateNextDomainChain(signatures []signature.Signature) error {
	bySequence := make(map[uint64]signature.Signature, len(signatures))
	maxSequence := uint64(0)
	for _, parsed := range signatures {
		sequence := parsed.Sequence()
		if _, duplicate := bySequence[sequence]; duplicate {
			return nil
		}
		bySequence[sequence] = parsed
		if sequence > maxSequence {
			maxSequence = sequence
		}
	}

	for _, parsed := range signatures {
		nextDomain, present := parsed.NextDomain()
		if !present || parsed.Sequence() == maxSequence {
			continue
		}
		next, exists := bySequence[parsed.Sequence()+1]
		if !exists {
			return nextDomainChainError(ErrorCodeMissingNextSignature, parsed.Sequence())
		}
		if nextDomain != next.Domain() {
			return nextDomainChainError(ErrorCodeNextDomainMismatch, parsed.Sequence())
		}
	}

	return nil
}

// checkNextDomain returns a bounded target fact after whole-chain validation.
func checkNextDomain(parsed signature.Signature, target Target, currentSequence uint64) nextDomainEvaluation {
	if !parsed.HasNextDomain() {
		return nextDomainCheckResult(target, NextDomainStatusNotApplicable)
	}
	if parsed.Sequence() == currentSequence {
		return nextDomainCheckResult(target, NextDomainStatusOutOfBandRequired)
	}

	return nextDomainCheckResult(target, NextDomainStatusPass)
}

// nextDomainCheckResult constructs a domain-free nd= verification fact.
func nextDomainCheckResult(target Target, status NextDomainStatus) nextDomainEvaluation {
	checkStatus := CheckStatusFail
	code := ErrorCodeNextDomainMismatch
	switch status {
	case NextDomainStatusPass:
		checkStatus = CheckStatusPass
		code = ""
	case NextDomainStatusNotApplicable:
		checkStatus = CheckStatusNotApplicable
		code = ""
	case NextDomainStatusMissingNext:
		code = ErrorCodeMissingNextSignature
	case NextDomainStatusOutOfBandRequired:
		checkStatus = CheckStatusUnsupported
		code = ErrorCodeOutOfBandRequired
	}

	return nextDomainEvaluation{
		check: CheckResult{
			Kind:             CheckKindNextDomain,
			Status:           checkStatus,
			Code:             code,
			NextDomainStatus: status,
			Target:           target,
		},
		unsupported: status == NextDomainStatusOutOfBandRequired,
	}
}

// nextDomainChainError reports chain failure using only bounded sequence metadata.
func nextDomainChainError(code ErrorCode, sequence uint64) *Error {
	return newError(code, ErrorLocation{
		Check:          CheckKindNextDomain,
		TargetSequence: sequence,
	}, ErrorDetails{
		Class:      ErrorClassNextDomain,
		Status:     CheckStatusFail,
		TargetName: "next_dkim2_signature",
	}, nil)
}
