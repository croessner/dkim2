package verify

import (
	"bytes"
	"strings"

	"github.com/croessner/dkim2/internal/signature"
)

const maxSMTPDomainBytes = 253

type domainAlignmentEvaluation struct {
	check CheckResult
	pass  bool
}

// checkDomainAlignment checks the signing domain against the signed MAIL FROM domain.
func checkDomainAlignment(signed signature.Signature, target Target) domainAlignmentEvaluation {
	if signed.HasNextDomain() {
		return domainAlignmentCheckResult(target, DomainAlignmentStatusNotApplicable)
	}
	reversePath := signed.MailFrom().Value()
	if bytes.Equal(reversePath, []byte("<>")) {
		return domainAlignmentCheckResult(target, DomainAlignmentStatusNotApplicable)
	}

	mailFromDomain, ok := smtpReversePathDomain(reversePath)
	if !ok {
		return domainAlignmentCheckResult(target, DomainAlignmentStatusInvalid)
	}
	if !relaxedDomainMatch(signed.Domain(), mailFromDomain) {
		return domainAlignmentCheckResult(target, DomainAlignmentStatusMismatch)
	}

	return domainAlignmentCheckResult(target, DomainAlignmentStatusPass)
}

// smtpReversePathDomain extracts and validates an ASCII domain from a bracketed reverse-path.
func smtpReversePathDomain(reversePath []byte) (string, bool) {
	if len(reversePath) < 4 || reversePath[0] != '<' || reversePath[len(reversePath)-1] != '>' {
		return "", false
	}
	mailbox := reversePath[1 : len(reversePath)-1]
	separator := bytes.LastIndexByte(mailbox, '@')
	if separator < 1 || separator == len(mailbox)-1 {
		return "", false
	}

	domain := asciiLower(mailbox[separator+1:])
	if !validSMTPDomain(domain) {
		return "", false
	}

	return string(domain), true
}

// asciiLower returns a lowercased ASCII copy without Unicode normalization.
func asciiLower(value []byte) []byte {
	result := bytes.Clone(value)
	for index, b := range result {
		if b >= 'A' && b <= 'Z' {
			result[index] = b + ('a' - 'A')
		}
	}

	return result
}

// validSMTPDomain validates the RFC 5321 sub-domain shape needed for alignment.
func validSMTPDomain(domain []byte) bool {
	if len(domain) == 0 || len(domain) > maxSMTPDomainBytes || domain[0] == '.' || domain[len(domain)-1] == '.' {
		return false
	}
	labelStart := 0
	for index := 0; index <= len(domain); index++ {
		if index != len(domain) && domain[index] != '.' {
			continue
		}
		label := domain[labelStart:index]
		if len(label) == 0 || len(label) > 63 || !isASCIILetterOrDigit(label[0]) || !isASCIILetterOrDigit(label[len(label)-1]) {
			return false
		}
		for _, b := range label[1 : len(label)-1] {
			if !isASCIILetterOrDigit(b) && b != '-' {
				return false
			}
		}
		labelStart = index + 1
	}

	return true
}

// isASCIILetterOrDigit reports whether b is an RFC 5321 domain atom character.
func isASCIILetterOrDigit(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
}

// relaxedDomainMatch applies a lowercased DNS label-boundary suffix comparison.
func relaxedDomainMatch(signingDomain string, mailFromDomain string) bool {
	canonicalSigningDomain := string(asciiLower([]byte(signingDomain)))
	canonicalMailFromDomain := string(asciiLower([]byte(mailFromDomain)))

	return canonicalMailFromDomain == canonicalSigningDomain || strings.HasSuffix(canonicalMailFromDomain, "."+canonicalSigningDomain)
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
