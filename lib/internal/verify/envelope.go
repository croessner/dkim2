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
	return compareEnvelope(current, signed, false)
}

// compareEnvelope applies the selected closed recipient-set relation after
// exact reverse-path comparison.
func compareEnvelope(current Envelope, signed signature.Signature, allowPostSigningRecipientExpansion bool) EnvelopeStatus {
	if current.IsZero() {
		return EnvelopeStatusMissing
	}

	currentReverse := current.ReversePath()
	signedReverse := signed.MailFrom().Value()
	currentReverseCanonical, currentReverseValid := signature.CanonicalEnvelopePath(currentReverse, true)
	signedReverseCanonical, signedReverseValid := signature.CanonicalEnvelopePath(signedReverse, true)
	switch {
	case len(currentReverse) == 0:
		return EnvelopeStatusMissing
	case !currentReverseValid || !signedReverseValid:
		return EnvelopeStatusInvalid
	case !bytes.Equal(currentReverseCanonical, signedReverseCanonical):
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
		canonical, valid := signature.CanonicalEnvelopePath(signedPath, false)
		if !valid {
			return EnvelopeStatusInvalid
		}
		signedRecipientSet[string(canonical)] = struct{}{}
	}
	if allowPostSigningRecipientExpansion {
		currentRecipientSet := make(map[string]struct{}, len(currentRecipients))
		for _, currentRecipient := range currentRecipients {
			canonical, valid := signature.CanonicalEnvelopePath(currentRecipient, false)
			if !valid {
				return EnvelopeStatusInvalid
			}
			currentRecipientSet[string(canonical)] = struct{}{}
		}
		for signedRecipient := range signedRecipientSet {
			if _, found := currentRecipientSet[signedRecipient]; !found {
				return EnvelopeStatusRecipientValueMismatch
			}
		}
		return EnvelopeStatusPass
	}
	for _, currentRecipient := range currentRecipients {
		canonical, valid := signature.CanonicalEnvelopePath(currentRecipient, false)
		if !valid {
			return EnvelopeStatusInvalid
		}
		if _, found := signedRecipientSet[string(canonical)]; !found {
			return EnvelopeStatusRecipientValueMismatch
		}
	}

	return EnvelopeStatusPass
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
