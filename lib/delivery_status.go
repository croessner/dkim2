package dkim2

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/dsn"
	"github.com/croessner/dkim2/internal/keyresolver"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signing"
	"github.com/croessner/dkim2/internal/verify"
)

// DSNIdentity is the daemon-owned canonical DNS identity permitted to sign a
// delivery-status notification.
type DSNIdentity struct{ domain string }

// NewDSNIdentity validates and canonicalizes one delivery-status signing identity.
func NewDSNIdentity(domain string) (DSNIdentity, error) {
	limits := keyresolver.DefaultLimits()
	canonical, err := keyresolver.CanonicalSigningDomain(domain, limits.MaxSigningDomainBytes, limits.MaxSigningDomainLabels)
	if err != nil {
		return DSNIdentity{}, newSigningError(SigningErrorInvalidRequest)
	}
	return DSNIdentity{domain: canonical}, nil
}

// Valid reports whether the identity carries a canonical nonempty DNS domain.
func (i DSNIdentity) Valid() bool { return i.domain != "" }

// String prevents identity formatting from becoming a caller-controlled diagnostic channel.
func (DSNIdentity) String() string { return "dkim2.DSNIdentity{redacted}" }

// GoString returns the constant secret-safe identity representation.
func (i DSNIdentity) GoString() string { return i.String() }

// Format routes every identity formatting form through the redacted representation.
func (i DSNIdentity) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, i.String()) }

// DSNSigningEvidenceRequest carries the exact outer and independently observed
// original SMTP evidence needed before a DSN can be authorized for signing.
type DSNSigningEvidenceRequest struct {
	outerRaw          []byte
	outerReversePath  []byte
	outerForwardPaths [][]byte
	originalReverse   []byte
	originalForward   [][]byte
	identity          DSNIdentity
}

// NewDSNSigningEvidenceRequest snapshots one DSN evidence request.
func NewDSNSigningEvidenceRequest(outerRaw, outerReversePath []byte, outerForwardPaths [][]byte, originalReversePath []byte, originalForwardPaths [][]byte, identity DSNIdentity) DSNSigningEvidenceRequest {
	return DSNSigningEvidenceRequest{
		outerRaw: bytes.Clone(outerRaw), outerReversePath: bytes.Clone(outerReversePath),
		outerForwardPaths: cloneByteSlices(outerForwardPaths), originalReverse: bytes.Clone(originalReversePath),
		originalForward: cloneByteSlices(originalForwardPaths), identity: identity,
	}
}

// String prevents raw DSN or envelope content from reaching diagnostics.
func (DSNSigningEvidenceRequest) String() string { return "dkim2.DSNSigningEvidenceRequest{redacted}" }

// GoString returns the constant secret-safe request representation.
func (r DSNSigningEvidenceRequest) GoString() string { return r.String() }

// Format routes every request formatting form through the redacted representation.
func (r DSNSigningEvidenceRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// DSNSigningEvidence is an opaque exact-input authorization produced only by
// EvaluateDSNForSigning. It carries no raw-message accessor.
type DSNSigningEvidence struct {
	raw          []byte
	reversePath  []byte
	forwardPaths [][]byte
	identity     DSNIdentity
	evidence     dsn.Evidence
	valid        bool
}

// Valid reports whether the opaque evidence was issued by the DSN boundary.
func (e DSNSigningEvidence) Valid() bool {
	return e.valid && len(e.raw) > 0 && bytes.Equal(e.reversePath, []byte("<>")) &&
		len(e.forwardPaths) == 1 && e.identity.Valid() && e.evidence.Valid()
}

// String prevents DSN evidence from exposing raw message or recipient data.
func (DSNSigningEvidence) String() string { return "dkim2.DSNSigningEvidence{redacted}" }

// GoString returns the constant secret-safe evidence representation.
func (e DSNSigningEvidence) GoString() string { return e.String() }

// Format routes every evidence formatting form through the redacted representation.
func (e DSNSigningEvidence) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, e.String()) }

// DSNSigningRequest binds one issued DSN evidence object to a purpose-specific route ticket and profile.
type DSNSigningRequest struct {
	evidence  DSNSigningEvidence
	ticket    RouteCopyTicket
	profile   SigningProfile
	metadata  SigningMetadata
	transport SigningTransportForm
}

// NewDSNSigningRequest constructs one exact DSN signing request without accepting caller-supplied message or envelope bytes.
func NewDSNSigningRequest(evidence DSNSigningEvidence, ticket RouteCopyTicket, profile SigningProfile, metadata SigningMetadata, transport SigningTransportForm) DSNSigningRequest {
	return DSNSigningRequest{evidence: evidence, ticket: ticket, profile: profile, metadata: metadata, transport: transport}
}

// String prevents DSN signing request formatting from exposing protected state.
func (DSNSigningRequest) String() string { return "dkim2.DSNSigningRequest{redacted}" }

// GoString returns the constant secret-safe signing-request representation.
func (r DSNSigningRequest) GoString() string { return r.String() }

// Format routes every signing-request formatting form through the redacted representation.
func (r DSNSigningRequest) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// EvaluateDSNForSigning derives the sole opaque authorization for a null
// reverse-path DSN after structure, embedded DKIM2 verification, original SMTP
// evidence, and local identity alignment all pass.
func (s *Signer) EvaluateDSNForSigning(ctx context.Context, request DSNSigningEvidenceRequest) (DSNSigningEvidence, error) {
	if s == nil || !s.initialized || ctx == nil || !request.identity.Valid() ||
		!bytes.Equal(request.outerReversePath, []byte("<>")) || len(request.outerForwardPaths) != 1 ||
		len(request.originalForward) == 0 {
		return DSNSigningEvidence{}, newSigningError(SigningErrorInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return DSNSigningEvidence{}, err
	}
	report, err := dsn.Parse(request.outerRaw)
	if err != nil {
		return DSNSigningEvidence{}, newSigningError(SigningErrorMalformedInput)
	}
	evidence, err := s.revision.EvaluateDeliveryStatus(ctx, report, verify.NewEnvelope(request.originalReverse, request.originalForward))
	if err != nil {
		return DSNSigningEvidence{}, mapDSNEvidenceError(ctx, err)
	}
	if !bytes.Equal(request.outerForwardPaths[0], evidence.MailFrom()) ||
		evidence.SigningDomain() != request.identity.domain ||
		!dsnRecipientMatchesIdentity(evidence, request.identity) {
		return DSNSigningEvidence{}, newSigningError(SigningErrorAuthorizationDenied)
	}
	return DSNSigningEvidence{
		raw: bytes.Clone(request.outerRaw), reversePath: bytes.Clone(request.outerReversePath),
		forwardPaths: cloneByteSlices(request.outerForwardPaths), identity: request.identity,
		evidence: evidence, valid: true,
	}, nil
}

// SignDSN signs only a DSN previously authorized by EvaluateDSNForSigning.
func (s *Signer) SignDSN(ctx context.Context, request DSNSigningRequest) (SigningResult, SigningRecovery, error) {
	if s == nil || !s.initialized || ctx == nil || !request.evidence.Valid() ||
		!request.transport.Known() || !request.ticket.Valid() ||
		request.ticket.value.Purpose() != "delivery_status" ||
		!request.ticket.value.MatchesEnvelope(request.evidence.reversePath, request.evidence.forwardPaths) ||
		!request.profile.value.ValidForLimits(s.limits) || request.profile.value.Domain() != request.evidence.identity.domain ||
		!request.metadata.value.Valid() {
		return SigningResult{}, SigningRecovery{}, newSigningError(SigningErrorInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return SigningResult{}, SigningRecovery{}, err
	}
	message, err := rawmsg.Parse(request.evidence.raw)
	if err != nil {
		return SigningResult{}, SigningRecovery{}, newSigningError(SigningErrorMalformedInput)
	}
	plan, err := s.planner.PlanDeliveryStatus(ctx, signing.OriginatorPlanRequest{Message: message, Ticket: request.ticket.value})
	if err != nil {
		return SigningResult{}, SigningRecovery{}, mapOperationError(err)
	}
	return s.complete(ctx, signing.SignFieldRequest{
		Plan: plan, Message: message, Ticket: request.ticket.value,
		ReversePath: bytes.Clone(request.evidence.reversePath), ForwardPaths: cloneByteSlices(request.evidence.forwardPaths),
		Profile: request.profile.value, Metadata: request.metadata.value, Transport: rawmsg.TransportForm(request.transport),
		EnvelopeForm: signing.SignatureEnvelopeOrdinary,
	})
}

// dsnRecipientMatchesIdentity enforces the local exact canonical recipient-domain interpretation.
func dsnRecipientMatchesIdentity(evidence dsn.Evidence, identity DSNIdentity) bool {
	for _, domain := range evidence.RecipientDomains() {
		if domain == identity.domain {
			return true
		}
	}
	return false
}

// mapDSNEvidenceError preserves cancellation and converts content-free DSN outcomes into the public signing vocabulary.
func mapDSNEvidenceError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if dsn.IsEvidenceErrorCode(err, dsn.EvidenceErrorCodeVerificationIndeterminate) {
		return newSigningError(SigningErrorCallbackTemporary)
	}
	return newSigningError(SigningErrorAuthorizationDenied)
}
