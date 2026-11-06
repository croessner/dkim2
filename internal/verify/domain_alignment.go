package verify

import "github.com/croessner/dkim2/internal/signature"

type domainAlignmentEvaluation struct {
	check CheckResult
	pass  bool
}

// checkDomainAlignment maps the shared custody fact for the selected target.
func checkDomainAlignment(custody signature.CustodyResult, target Target) (domainAlignmentEvaluation, error) {
	if !custody.Evaluated() {
		return domainAlignmentEvaluation{}, newError(ErrorCodeInternalMisuse, ErrorLocation{Check: CheckKindDomainAlignment}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	switch custody.DirectAlignment(target.Sequence) {
	case signature.CustodyDirectAlignmentPass:
		return domainAlignmentCheckResult(target, DomainAlignmentStatusPass), nil
	case signature.CustodyDirectAlignmentNotApplicableNull, signature.CustodyDirectAlignmentNotApplicableNextDomain:
		return domainAlignmentCheckResult(target, DomainAlignmentStatusNotApplicable), nil
	case signature.CustodyDirectAlignmentMismatch:
		return domainAlignmentCheckResult(target, DomainAlignmentStatusMismatch), nil
	case signature.CustodyDirectAlignmentInvalid:
		return domainAlignmentCheckResult(target, DomainAlignmentStatusInvalid), nil
	default:
		return domainAlignmentEvaluation{}, newError(ErrorCodeInternalMisuse, ErrorLocation{Check: CheckKindDomainAlignment}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
}

// domainAlignmentCheckResult constructs a bounded alignment fact without path values.
func domainAlignmentCheckResult(target Target, status DomainAlignmentStatus) domainAlignmentEvaluation {
	checkStatus := CheckStatusFail
	code := ErrorCodeDomainAlignmentMismatch
	if status == DomainAlignmentStatusPass {
		checkStatus = CheckStatusPass
		code = ""
	}
	if status == DomainAlignmentStatusNotApplicable {
		checkStatus = CheckStatusNotApplicable
		code = ""
	}
	if status == DomainAlignmentStatusInvalid {
		code = ErrorCodeMalformedState
	}

	return domainAlignmentEvaluation{
		check: CheckResult{
			Kind:                  CheckKindDomainAlignment,
			Status:                checkStatus,
			Code:                  code,
			DomainAlignmentStatus: status,
			Target:                target,
		},
		pass: checkStatus == CheckStatusPass || checkStatus == CheckStatusNotApplicable,
	}
}
