package verify

import (
	"context"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
)

// HeaderEvidence records bounded authentication facts for a DSN
// text/rfc822-headers embedded original. It deliberately does not represent
// body-hash evidence and therefore cannot be used as a generic verification result.
type HeaderEvidence struct {
	target Target
	status TargetStatus
}

// Valid reports whether the dedicated header-only evidence is cryptographically complete for its restricted DSN purpose.
func (e HeaderEvidence) Valid() bool {
	return e.status == TargetStatusPass && e.target.Sequence > 0 && e.target.InstanceNumber > 0
}

// Target returns the authenticated highest embedded DKIM2 target identifiers.
func (e HeaderEvidence) Target() Target {
	return e.target
}

// Status returns the bounded authentication outcome for the retained header evidence.
func (e HeaderEvidence) Status() TargetStatus {
	return e.status
}

// VerifyDeliveryStatusHeadersOnly verifies the restricted evidence carried by a
// DSN text/rfc822-headers original. It requires RFC 5322 header-only framing,
// validates the highest DKIM2 target header hash, Section 9.6 signature,
// timestamp, and custody structure without inventing current-envelope evidence,
// and never evaluates or substitutes body evidence.
func (v Verifier) VerifyDeliveryStatusHeadersOnly(ctx context.Context, request Request) (HeaderEvidence, error) {
	if ctx == nil || !request.Message.Initialized() || request.Message.Framing() != rawmsg.MessageFramingHeaderOnly ||
		request.TargetSequence != 0 || request.SkipEnvelopeForNonCurrentTarget || request.RequireEnvelope || !request.Envelope.IsZero() || !v.valid() {
		return HeaderEvidence{}, newError(ErrorCodeInvalidRequest, ErrorLocation{}, ErrorDetails{Class: ErrorClassRequest}, nil)
	}
	input, err := v.extractVerificationInput(request, 0)
	if err != nil {
		return HeaderEvidence{}, err
	}
	targetSignature, targetInstance, custody, target, err := selectVerificationTarget(input)
	if err != nil {
		return HeaderEvidence{}, err
	}
	if target.InstanceNumber < highestInstanceNumber(input.instances) {
		return HeaderEvidence{}, unsupportedHistoricalTargetError(target)
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		return HeaderEvidence{}, malformedStateError(CheckKindSignature, target, err)
	}
	header, err := compareTargetHeaderHash(canonicalizer, request.Message, targetInstance, target)
	if err != nil {
		return HeaderEvidence{}, err
	}
	digest, err := signatureInputDigest(canonicalizer, request.Message, target)
	if err != nil {
		return HeaderEvidence{}, err
	}
	signatures := v.evaluateSignatureSets(ctx, targetSignature, digest, target)
	if err := ctx.Err(); err != nil {
		return HeaderEvidence{}, err
	}
	timestamp := v.checkTimestamp(targetSignature, target)
	nextDomain := checkNextDomain(targetSignature, target, target.Sequence)
	envelope := envelopeCheckResult(target, EnvelopeStatusNotApplicable)
	domainAlignment, err := checkDomainAlignment(custody, target)
	if err != nil {
		return HeaderEvidence{}, err
	}
	status := targetStatus(header.pass, timestamp.pass, envelope.pass, domainAlignment.pass, nextDomain, signatures)
	return HeaderEvidence{target: target, status: status}, nil
}
