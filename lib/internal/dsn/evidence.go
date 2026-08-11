package dsn

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
	"github.com/croessner/dkim2/internal/verify"
)

// EvidenceForm identifies the bounded representation retained for the original message.
type EvidenceForm string

const (
	// EvidenceFormComplete identifies a complete message/rfc822 original with body evidence.
	EvidenceFormComplete EvidenceForm = "complete"
	// EvidenceFormHeadersOnly identifies a text/rfc822-headers original without body evidence.
	EvidenceFormHeadersOnly EvidenceForm = "headers_only"
)

// EvidenceErrorCode identifies one content-free DSN evidence failure.
type EvidenceErrorCode string

const (
	// EvidenceErrorCodeInvalidEvaluator reports an uninitialized verifier dependency.
	EvidenceErrorCodeInvalidEvaluator EvidenceErrorCode = "invalid_evaluator"
	// EvidenceErrorCodeInvalidRequest reports an unsafe DSN evidence request shape.
	EvidenceErrorCodeInvalidRequest EvidenceErrorCode = "invalid_request"
	// EvidenceErrorCodeInvalidOriginal reports malformed or ambiguous embedded original bytes.
	EvidenceErrorCodeInvalidOriginal EvidenceErrorCode = "invalid_original"
	// EvidenceErrorCodeVerificationFailed reports non-passing cryptographic original evidence.
	EvidenceErrorCodeVerificationFailed EvidenceErrorCode = "verification_failed"
	// EvidenceErrorCodeVerificationIndeterminate reports transient or otherwise non-final verification evidence.
	EvidenceErrorCodeVerificationIndeterminate EvidenceErrorCode = "verification_indeterminate"
)

// EvidenceError is a typed, content-free DSN evidence failure.
type EvidenceError struct {
	code  EvidenceErrorCode
	cause error
}

// Error returns a bounded diagnostic that never includes original message or envelope content.
func (e *EvidenceError) Error() string {
	if e == nil {
		return "dsn evidence error: <nil>"
	}
	return fmt.Sprintf("dsn evidence error: code=%s", e.code)
}

// Unwrap exposes an already content-free verifier or parser cause for typed callers.
func (e *EvidenceError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Is matches evidence errors by stable code.
func (e *EvidenceError) Is(target error) bool {
	var targetError *EvidenceError
	return errors.As(target, &targetError) && e != nil && targetError != nil && e.code == targetError.code
}

// Code returns the stable evidence failure code.
func (e *EvidenceError) Code() EvidenceErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}

// IsEvidenceErrorCode reports whether err contains the requested evidence code.
func IsEvidenceErrorCode(err error, code EvidenceErrorCode) bool {
	var evidenceError *EvidenceError
	return errors.As(err, &evidenceError) && evidenceError.Code() == code
}

// EvidenceRequest carries one parsed DSN and independently observed original SMTP envelope.
type EvidenceRequest struct {
	// Report is the parser-owned RFC 3462 DSN report.
	Report Report
	// OriginalEnvelope is independently observed SMTP evidence for the embedded original.
	OriginalEnvelope verify.Envelope
}

// Evidence stores the authenticated embedded DKIM2 target without retaining message content.
type Evidence struct {
	form             EvidenceForm
	target           verify.Target
	mailFrom         []byte
	signingDomain    string
	recipientDomains []string
}

// Valid reports whether the evidence binds one supported original representation to an authenticated target.
func (e Evidence) Valid() bool {
	return (e.form == EvidenceFormComplete || e.form == EvidenceFormHeadersOnly) && e.target.Sequence > 0 && e.target.InstanceNumber > 0 &&
		len(e.mailFrom) > 0 && !bytes.Equal(e.mailFrom, []byte("<>")) && e.signingDomain != "" && len(e.recipientDomains) > 0
}

// Form returns the retained original representation.
func (e Evidence) Form() EvidenceForm {
	return e.form
}

// Target returns the authenticated highest embedded DKIM2 target identifiers.
func (e Evidence) Target() verify.Target {
	return e.target
}

// MailFrom returns a detached exact highest-signature mf= path. It is retained
// only to bind the outer DSN recipient to the authenticated original sender.
func (e Evidence) MailFrom() []byte { return bytes.Clone(e.mailFrom) }

// SigningDomain returns the canonical d= domain from the authenticated highest embedded DKIM2 signature.
func (e Evidence) SigningDomain() string {
	return e.signingDomain
}

// RecipientDomains returns detached canonical DNS domains from every highest embedded rt= recipient.
func (e Evidence) RecipientDomains() []string {
	return append([]string(nil), e.recipientDomains...)
}

// EvidenceEvaluator owns the narrow Draft-04 Section 12 embedded-original verification boundary.
type EvidenceEvaluator struct {
	verifier verify.Verifier
}

// NewEvidenceEvaluator constructs a DSN evaluator from one validated DKIM2 verifier.
func NewEvidenceEvaluator(verifier verify.Verifier) (EvidenceEvaluator, error) {
	if !verifier.Valid() {
		return EvidenceEvaluator{}, newEvidenceError(EvidenceErrorCodeInvalidEvaluator, nil)
	}
	return EvidenceEvaluator{verifier: verifier}, nil
}

// Evaluate verifies an embedded original before DSN signing authorization. It
// accepts only non-null independently observed original envelopes; complete
// originals require complete body and header verification, while headers-only
// originals use the dedicated header-only verifier and never substitute a body.
func (e EvidenceEvaluator) Evaluate(ctx context.Context, request EvidenceRequest) (Evidence, error) {
	if ctx == nil || !e.verifier.Valid() || !request.Report.RawMessage().Initialized() || !originalEnvelopeValid(request.OriginalEnvelope) {
		return Evidence{}, newEvidenceError(EvidenceErrorCodeInvalidRequest, nil)
	}
	original := request.Report.OriginalMessage()
	parsed, err := rawmsg.Parse(original.BodyBytes())
	if err != nil {
		return Evidence{}, newEvidenceError(EvidenceErrorCodeInvalidOriginal, nil)
	}
	verificationRequest := verify.Request{
		Message:         parsed,
		Envelope:        request.OriginalEnvelope,
		RequireEnvelope: true,
	}
	switch original.ContentType() {
	case ContentTypeRFC822:
		result, verifyErr := e.verifier.VerifyDeliveryStatusComplete(ctx, verificationRequest)
		if verifyErr != nil {
			return Evidence{}, newEvidenceError(EvidenceErrorCodeVerificationFailed, verifyErr)
		}
		if result.Status() != verify.TargetStatusPass {
			return Evidence{}, evidenceStatusError(result.Status())
		}
		return authenticatedEvidence(EvidenceFormComplete, parsed, result.Target())
	case ContentTypeRFC822Headers:
		headerEvidence, verifyErr := e.verifier.VerifyDeliveryStatusHeadersOnly(ctx, verificationRequest)
		if verifyErr != nil {
			return Evidence{}, newEvidenceError(EvidenceErrorCodeVerificationFailed, verifyErr)
		}
		if !headerEvidence.Valid() {
			return Evidence{}, evidenceStatusError(headerEvidence.Status())
		}
		return authenticatedEvidence(EvidenceFormHeadersOnly, parsed, headerEvidence.Target())
	default:
		return Evidence{}, newEvidenceError(EvidenceErrorCodeInvalidOriginal, nil)
	}
}

// authenticatedEvidence derives only the local-identity facts required from the already authenticated highest target.
func authenticatedEvidence(form EvidenceForm, message rawmsg.Message, target verify.Target) (Evidence, error) {
	signatures, err := signature.Extract(message)
	if err != nil {
		return Evidence{}, newEvidenceError(EvidenceErrorCodeInvalidOriginal, nil)
	}
	for _, parsed := range signatures {
		if parsed.Sequence() != target.Sequence || parsed.InstanceNumber() != target.InstanceNumber {
			continue
		}
		recipients := parsed.Recipients()
		domains := make([]string, len(recipients))
		for index, recipient := range recipients {
			domain, valid := signature.CanonicalEnvelopeDomain(recipient.Value(), false)
			if !valid {
				return Evidence{}, newEvidenceError(EvidenceErrorCodeInvalidOriginal, nil)
			}
			domains[index] = domain
		}
		mailFrom := parsed.MailFrom().Value()
		if parsed.Domain() == "" || len(domains) == 0 || !signature.ValidEnvelopePath(mailFrom, false) {
			return Evidence{}, newEvidenceError(EvidenceErrorCodeInvalidOriginal, nil)
		}
		return Evidence{
			form: form, target: target, mailFrom: bytes.Clone(mailFrom),
			signingDomain: parsed.Domain(), recipientDomains: domains,
		}, nil
	}
	return Evidence{}, newEvidenceError(EvidenceErrorCodeInvalidOriginal, nil)
}

// originalEnvelopeValid rejects missing and null original-envelope evidence before generic DKIM2 checks.
func originalEnvelopeValid(envelope verify.Envelope) bool {
	return !envelope.IsZero() && envelope.RecipientCount() > 0 && len(envelope.ReversePath()) > 0 && !bytes.Equal(envelope.ReversePath(), []byte("<>"))
}

// evidenceStatusError maps bounded verifier outcomes to a DSN evidence authorization failure.
func evidenceStatusError(status verify.TargetStatus) error {
	if status == verify.TargetStatusIndeterminate {
		return newEvidenceError(EvidenceErrorCodeVerificationIndeterminate, nil)
	}
	return newEvidenceError(EvidenceErrorCodeVerificationFailed, nil)
}

// newEvidenceError constructs a content-free evidence error around typed parser or verifier causes.
func newEvidenceError(code EvidenceErrorCode, cause error) *EvidenceError {
	return &EvidenceError{code: code, cause: cause}
}
