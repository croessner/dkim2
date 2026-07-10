package verify

import (
	"bytes"

	"github.com/croessner/dkim2/internal/signature"
)

// Envelope stores immutable current SMTP envelope path bytes.
type Envelope struct {
	reversePath  []byte
	forwardPaths [][]byte
}

type envelopeEvaluation struct {
	check CheckResult
	pass  bool
}

// NewEnvelope constructs an immutable current SMTP envelope container.
func NewEnvelope(reversePath []byte, forwardPaths [][]byte) Envelope {
	return Envelope{
		reversePath:  bytes.Clone(reversePath),
		forwardPaths: cloneByteSlices(forwardPaths),
	}
}

// ReversePath returns the current reverse-path bytes.
func (e Envelope) ReversePath() []byte {
	return bytes.Clone(e.reversePath)
}

// ForwardPaths returns ordered current forward-path byte copies.
func (e Envelope) ForwardPaths() [][]byte {
	return cloneByteSlices(e.forwardPaths)
}

// RecipientCount returns the number of ordered forward paths.
func (e Envelope) RecipientCount() int {
	return len(e.forwardPaths)
}

// IsZero reports whether no envelope evidence was supplied.
func (e Envelope) IsZero() bool {
	return len(e.reversePath) == 0 && len(e.forwardPaths) == 0
}

// cloneByteSlices returns a deep copy of byte-slice collections.
func cloneByteSlices(input [][]byte) [][]byte {
	if len(input) == 0 {
		return nil
	}

	output := make([][]byte, len(input))
	for i, value := range input {
		output[i] = bytes.Clone(value)
	}

	return output
}

// compareCurrentEnvelope matches current SMTP paths against parser-owned signature paths.
func compareCurrentEnvelope(current Envelope, signed signature.Signature) EnvelopeStatus {
	if current.IsZero() {
		return EnvelopeStatusMissing
	}

	currentReverse := current.ReversePath()
	signedReverse := signed.MailFrom().Value()
	switch {
	case len(currentReverse) == 0:
		return EnvelopeStatusMissing
	case !validReversePathBytes(currentReverse) || !validReversePathBytes(signedReverse):
		return EnvelopeStatusInvalid
	case !equalEnvelopePath(currentReverse, signedReverse):
		return EnvelopeStatusReversePathMismatch
	}

	currentRecipients := current.ForwardPaths()
	signedRecipients := signed.Recipients()
	if len(currentRecipients) == 0 || len(signedRecipients) == 0 {
		return EnvelopeStatusMissing
	}
	signedRecipientSet := make(map[string]struct{}, len(signedRecipients))
	for _, signedRecipient := range signedRecipients {
		signedPath := signedRecipient.Value()
		if !validForwardPathBytes(signedPath) {
			return EnvelopeStatusInvalid
		}
		signedRecipientSet[envelopePathComparisonKey(signedPath)] = struct{}{}
	}
	for _, currentRecipient := range currentRecipients {
		if !validForwardPathBytes(currentRecipient) {
			return EnvelopeStatusInvalid
		}
		if _, found := signedRecipientSet[envelopePathComparisonKey(currentRecipient)]; !found {
			return EnvelopeStatusRecipientValueMismatch
		}
	}

	return EnvelopeStatusPass
}

// equalEnvelopePath compares SMTP paths with ASCII domain case folding and case-sensitive local parts.
func equalEnvelopePath(left []byte, right []byte) bool {
	if bytes.Equal(left, right) {
		return true
	}

	leftAt := bytes.LastIndexByte(left, '@')
	rightAt := bytes.LastIndexByte(right, '@')
	if leftAt <= 0 || rightAt <= 0 || leftAt >= len(left)-1 || rightAt >= len(right)-1 {
		return false
	}
	if !bytes.Equal(left[:leftAt+1], right[:rightAt+1]) {
		return false
	}

	leftDomain := left[leftAt+1:]
	rightDomain := right[rightAt+1:]
	if len(leftDomain) != len(rightDomain) {
		return false
	}
	for i := range leftDomain {
		if lowerASCII(leftDomain[i]) != lowerASCII(rightDomain[i]) {
			return false
		}
	}

	return true
}

// envelopePathComparisonKey returns a map-safe path copy with only ASCII domain bytes lowercased.
func envelopePathComparisonKey(path []byte) string {
	normalized := bytes.Clone(path)
	at := bytes.LastIndexByte(normalized, '@')
	if at <= 0 || at >= len(normalized)-1 {
		return string(normalized)
	}
	for i := at + 1; i < len(normalized); i++ {
		normalized[i] = lowerASCII(normalized[i])
	}

	return string(normalized)
}

// lowerASCII lowercases one ASCII letter without normalizing non-ASCII bytes.
func lowerASCII(value byte) byte {
	if value >= 'A' && value <= 'Z' {
		return value + ('a' - 'A')
	}

	return value
}

// envelopeCheckResult turns envelope detail into a bounded verification fact.
func envelopeCheckResult(target Target, status EnvelopeStatus) envelopeEvaluation {
	checkStatus := CheckStatusFail
	code := ErrorCodeEnvelopeMismatch
	if status == EnvelopeStatusPass {
		checkStatus = CheckStatusPass
		code = ""
	}
	if status == EnvelopeStatusNotApplicable {
		checkStatus = CheckStatusNotApplicable
		code = ""
	}

	return envelopeEvaluation{
		check: CheckResult{
			Kind:           CheckKindEnvelope,
			Status:         checkStatus,
			Code:           code,
			EnvelopeStatus: status,
			Target:         target,
		},
		pass: checkStatus == CheckStatusPass || checkStatus == CheckStatusNotApplicable,
	}
}

// envelopeLimitCheckResult records an oversized current-envelope request shape.
func envelopeLimitCheckResult(target Target) envelopeEvaluation {
	return envelopeEvaluation{
		check: CheckResult{
			Kind:           CheckKindEnvelope,
			Status:         CheckStatusFail,
			Code:           ErrorCodeLimitExceeded,
			EnvelopeStatus: EnvelopeStatusInvalid,
			Target:         target,
		},
		pass: false,
	}
}

// validReversePathBytes checks bracketed SMTP reverse-path bytes without parsing addresses.
func validReversePathBytes(path []byte) bool {
	return validEnvelopePathBytes(path, true)
}

// validForwardPathBytes checks bracketed SMTP forward-path bytes without parsing addresses.
func validForwardPathBytes(path []byte) bool {
	return validEnvelopePathBytes(path, false)
}

// validEnvelopePathBytes validates path framing while preserving byte semantics.
func validEnvelopePathBytes(path []byte, allowNullPath bool) bool {
	if len(path) == 0 {
		return false
	}
	for _, b := range path {
		if b == '\r' || b == '\n' || b == 0 {
			return false
		}
	}
	if bytes.Equal(path, []byte("<>")) {
		return allowNullPath
	}

	return len(path) >= 3 && path[0] == '<' && path[len(path)-1] == '>'
}
