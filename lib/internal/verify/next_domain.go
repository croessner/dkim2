package verify

import (
	"errors"

	"github.com/croessner/dkim2/internal/signature"
)

type nextDomainEvaluation struct {
	check       CheckResult
	unsupported bool
}

// validateNextDomainChain maps the shared complete custody result for direct callers.
func validateNextDomainChain(signatures []signature.Signature) error {
	_, err := validateCustodyChain(signatures, 0)
	return err
}

// validateCustodyChain evaluates the shared complete custody state machine once.
func validateCustodyChain(signatures []signature.Signature, allowedDirectSequence uint64) (signature.CustodyResult, error) {
	result, err := signature.ValidateCustody(signatures, signature.CustodyLimits{})
	if err == nil {
		return result, nil
	}
	var typed *signature.Error
	if !errors.As(err, &typed) {
		return signature.CustodyResult{}, nextDomainChainError(ErrorCodeCustodyMismatch, 0)
	}
	switch typed.Code() {
	case signature.ErrorCodeLimitExceeded:
		return signature.CustodyResult{}, newError(ErrorCodeLimitExceeded, ErrorLocation{Check: CheckKindSignature}, ErrorDetails{
			Class: ErrorClassLimit, LimitName: typed.LimitName(), Limit: typed.Limit(), Count: typed.Count(),
			TargetName: "dkim2_signature",
		}, nil)
	case signature.ErrorCodeMissingOrigin, signature.ErrorCodeDuplicateSequence:
		return signature.CustodyResult{}, malformedSequenceError("dkim2_signature", Target{})
	case signature.ErrorCodeSequenceGap:
		if sequence, ok := nextDomainMissingSuccessor(signatures); ok {
			return signature.CustodyResult{}, nextDomainChainError(ErrorCodeMissingNextSignature, sequence)
		}
		return signature.CustodyResult{}, malformedSequenceError("dkim2_signature", Target{})
	case signature.ErrorCodeCustodyMismatch:
		sequence := typed.ObservedNumber()
		if typed.TagName() == string(signature.TagNameMailFrom) && result.Evaluated() &&
			allowedDirectSequence == sequence && result.AllDirectAlignedExcept(allowedDirectSequence) {
			return result, nil
		}
		code := ErrorCodeCustodyMismatch
		if typed.TagName() == string(signature.TagNameNextDomain) {
			code = ErrorCodeNextDomainMismatch
		}
		mapped := nextDomainChainError(code, sequence)
		if code == ErrorCodeNextDomainMismatch {
			mapped.custody = CustodyStatusNDLinksEvaluated
		}
		return signature.CustodyResult{}, mapped
	default:
		return signature.CustodyResult{}, nextDomainChainError(ErrorCodeCustodyMismatch, 0)
	}
}

// nextDomainMissingSuccessor finds a bounded nd= predecessor to a missing sequence.
func nextDomainMissingSuccessor(signatures []signature.Signature) (uint64, bool) {
	present := make(map[uint64]struct{}, len(signatures))
	for _, parsed := range signatures {
		present[parsed.Sequence()] = struct{}{}
	}
	for _, parsed := range signatures {
		if parsed.HasNextDomain() {
			if parsed.Sequence() == ^uint64(0) {
				continue
			}
			if _, ok := present[parsed.Sequence()+1]; !ok {
				return parsed.Sequence(), true
			}
		}
	}
	return 0, false
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
	class := ErrorClassNextDomain
	check := CheckKindNextDomain
	targetName := "next_dkim2_signature"
	if code == ErrorCodeCustodyMismatch {
		class = ErrorClassCustody
		check = CheckKindSignature
		targetName = "dkim2_signature"
	}
	return newError(code, ErrorLocation{
		Check:          check,
		TargetSequence: sequence,
	}, ErrorDetails{
		Class:      class,
		Status:     CheckStatusFail,
		TargetName: targetName,
	}, nil)
}
