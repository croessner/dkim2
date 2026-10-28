package dkim2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/dsn"
	"github.com/croessner/dkim2/internal/keyresolver"
	"github.com/croessner/dkim2/internal/niliface"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signing"
	"github.com/croessner/dkim2/internal/verify"
)

// DSNIdentity is one canonical DNS domain that may be preferred as the
// signing identity of a delivery-status notification. It never becomes the
// signing domain on its own: Draft-08 Section 16.2 admits only domains that
// relaxed-match an rt= address of the reported message.
type DSNIdentity struct{ domain string }

// DSNEvidenceStage identifies one closed content-free DSN authorization stage.
type DSNEvidenceStage string

const (
	// DSNEvidenceStagePreflight identifies invalid evaluator or request state.
	DSNEvidenceStagePreflight DSNEvidenceStage = "preflight"
	// DSNEvidenceStageMIMEParse identifies outer DSN framing failure.
	DSNEvidenceStageMIMEParse DSNEvidenceStage = "mime_parse"
	// DSNEvidenceStageEmbeddedMessage identifies embedded RFC 5322 parsing failure.
	DSNEvidenceStageEmbeddedMessage DSNEvidenceStage = "embedded_message"
	// DSNEvidenceStageEmbeddedVerification identifies embedded cryptographic evidence failure.
	DSNEvidenceStageEmbeddedVerification DSNEvidenceStage = "embedded_verification"
	// DSNEvidenceStageEmbeddedUnsigned identifies a well-formed embedded
	// original without any DKIM2-Signature header field. Draft-08 Section 16
	// defines DKIM2 DSN handling only for DKIM2-signed originals, so such a
	// report cannot be authorized for signing. The wrapped cause remains
	// SigningErrorAuthorizationDenied; only a caller with an explicit
	// compatibility policy may let the report leave unsigned and unchanged.
	DSNEvidenceStageEmbeddedUnsigned DSNEvidenceStage = "embedded_unsigned"
	// DSNEvidenceStageEmbeddedClaims identifies invalid authenticated protocol claims.
	DSNEvidenceStageEmbeddedClaims DSNEvidenceStage = "embedded_claims"
	// DSNEvidenceStageDeliveryStatusLinkage identifies RFC 3464 recipient linkage failure.
	DSNEvidenceStageDeliveryStatusLinkage DSNEvidenceStage = "delivery_status_linkage"
	// DSNEvidenceStageOuterRecipientLinkage identifies outer recipient and mf= mismatch.
	DSNEvidenceStageOuterRecipientLinkage DSNEvidenceStage = "outer_recipient_linkage"
	// DSNEvidenceStageSigningDomain identifies a failed Section 16.2 signing
	// identity resolution: an unavailable or inconsistent local profile
	// source, or cancellation during resolution.
	DSNEvidenceStageSigningDomain DSNEvidenceStage = "signing_domain"
	// DSNEvidenceStageIdentityUnavailable identifies a report for which no
	// local delivery_status profile domain relaxed-matches an rt= address of
	// the highest DKIM2-Signature of the reported message (Draft-08 Sections
	// 7.1 item 4 and 16.2). The report cannot be DKIM2 signed; callers
	// deliver it unsigned. The wrapped cause is SigningErrorAuthorizationDenied.
	DSNEvidenceStageIdentityUnavailable DSNEvidenceStage = "identity_unavailable"
	// DSNEvidenceStageFromNotAuthentic identifies a report for which Section
	// 16.2 candidates with a local profile exist, but none makes the report's
	// own From header field Authentic (Draft-08 Sections 11 and 12.4). The
	// report cannot be DKIM2 signed; callers deliver it unsigned. The wrapped
	// cause is SigningErrorAuthorizationDenied.
	DSNEvidenceStageFromNotAuthentic DSNEvidenceStage = "from_not_authentic"
	// DSNEvidenceStageAuthorized identifies completed pre-policy evidence authorization.
	DSNEvidenceStageAuthorized DSNEvidenceStage = "authorized"
)

// Known reports whether the stage belongs to the fixed DSN evidence pipeline.
func (s DSNEvidenceStage) Known() bool {
	switch s {
	case DSNEvidenceStagePreflight, DSNEvidenceStageMIMEParse,
		DSNEvidenceStageEmbeddedMessage, DSNEvidenceStageEmbeddedVerification,
		DSNEvidenceStageEmbeddedUnsigned, DSNEvidenceStageEmbeddedClaims,
		DSNEvidenceStageDeliveryStatusLinkage, DSNEvidenceStageOuterRecipientLinkage, DSNEvidenceStageSigningDomain,
		DSNEvidenceStageIdentityUnavailable, DSNEvidenceStageFromNotAuthentic, DSNEvidenceStageAuthorized:
		return true
	default:
		return false
	}
}

// DSNEvidenceError preserves only a closed failure stage while retaining the
// existing public signing error through errors.Unwrap.
type DSNEvidenceError struct {
	stage DSNEvidenceStage
	cause error
}

// Error returns a bounded diagnostic without message, envelope, or identity data.
func (e *DSNEvidenceError) Error() string {
	if e == nil || !e.stage.Known() {
		return "dkim2 dsn evidence error"
	}
	return "dkim2 dsn evidence error: stage=" + string(e.stage)
}

// Unwrap preserves existing SigningError and context classification.
func (e *DSNEvidenceError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Stage returns the closed failure stage or the zero value.
func (e *DSNEvidenceError) Stage() DSNEvidenceStage {
	if e == nil || !e.stage.Known() {
		return ""
	}
	return e.stage
}

// Format routes every formatting verb through the bounded diagnostic.
func (e *DSNEvidenceError) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, e.Error())
}

// DSNEvidenceStageOf returns a closed stage only for a typed DSN evidence failure.
func DSNEvidenceStageOf(err error) DSNEvidenceStage {
	var evidenceError *DSNEvidenceError
	if errors.As(err, &evidenceError) {
		return evidenceError.Stage()
	}
	return ""
}

// NewDSNIdentity validates and canonicalizes one preferred delivery-status signing identity.
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

// Domain returns the canonical DNS domain or an empty string.
func (i DSNIdentity) Domain() string { return i.domain }

// String prevents identity formatting from becoming a caller-controlled diagnostic channel.
func (DSNIdentity) String() string { return "dkim2.DSNIdentity{redacted}" }

// GoString returns the constant secret-safe identity representation.
func (i DSNIdentity) GoString() string { return i.String() }

// Format routes every identity formatting form through the redacted representation.
func (i DSNIdentity) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, i.String()) }

// DSNSigningEvidenceRequest carries the exact outer evidence needed before a
// locally generated DSN can be authorized for signing, and an optional
// operator-preferred identity for the Section 16.2 candidate order.
type DSNSigningEvidenceRequest struct {
	outerRaw                 []byte
	outerReversePath         []byte
	outerForwardPaths        [][]byte
	preferred                DSNIdentity
	postfixBounceWireProfile bool
}

// NewDSNSigningEvidenceRequest snapshots one DSN evidence request whose
// delivery-status fields must follow the strict RFC 3464 sequence.
func NewDSNSigningEvidenceRequest(outerRaw, outerReversePath []byte, outerForwardPaths [][]byte) DSNSigningEvidenceRequest {
	return DSNSigningEvidenceRequest{
		outerRaw: bytes.Clone(outerRaw), outerReversePath: bytes.Clone(outerReversePath),
		outerForwardPaths: cloneByteSlices(outerForwardPaths),
	}
}

// NewPostfixDSNSigningEvidenceRequest snapshots a DSN evidence request whose
// delivery-status field order may use the exact bounded form emitted by
// Postfix bounce(8).
//
// Security precondition: trusted adapters must select this constructor only
// after independently proving that Postfix bounce(8) generated the DSN. It is
// not a parser hint for untrusted message input. Generic and non-Postfix paths
// must use NewDSNSigningEvidenceRequest.
func NewPostfixDSNSigningEvidenceRequest(outerRaw, outerReversePath []byte, outerForwardPaths [][]byte) DSNSigningEvidenceRequest {
	request := NewDSNSigningEvidenceRequest(outerRaw, outerReversePath, outerForwardPaths)
	request.postfixBounceWireProfile = true
	return request
}

// WithPreferredIdentity returns a copy of the request that prefers one
// operator-configured domain within its Section 16.2 linkage tier. The
// preferred domain is used only when it relaxed-matches an rt= address of
// the reported message; it is never a signing domain on its own. An invalid
// identity clears the preference.
func (r DSNSigningEvidenceRequest) WithPreferredIdentity(preferred DSNIdentity) DSNSigningEvidenceRequest {
	r.outerRaw = bytes.Clone(r.outerRaw)
	r.outerReversePath = bytes.Clone(r.outerReversePath)
	r.outerForwardPaths = cloneByteSlices(r.outerForwardPaths)
	r.preferred = preferred
	return r
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
// EvaluateDSNForSigning and bound to one signing identity only by
// ResolveDSNSigningIdentity. It carries no raw-message accessor.
type DSNSigningEvidence struct {
	raw          []byte
	reversePath  []byte
	forwardPaths [][]byte
	preferred    DSNIdentity
	identity     DSNIdentity
	evidence     dsn.Evidence
	valid        bool
}

// Valid reports whether the opaque evidence was issued by the DSN boundary.
// It does not imply that a signing identity was resolved.
func (e DSNSigningEvidence) Valid() bool {
	return e.valid && len(e.raw) > 0 && bytes.Equal(e.reversePath, []byte("<>")) &&
		len(e.forwardPaths) == 1 && e.evidence.Valid()
}

// Resolved reports whether ResolveDSNSigningIdentity bound the evidence to a
// Section 16.2 signing identity with an Authentic report From.
func (e DSNSigningEvidence) Resolved() bool { return e.Valid() && e.identity.Valid() }

// SigningDomain returns the canonical DSN signing identity chosen by
// ResolveDSNSigningIdentity, or an empty string before resolution.
func (e DSNSigningEvidence) SigningDomain() string {
	if !e.Resolved() {
		return ""
	}
	return e.identity.domain
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

// EvaluateDSNForSigning derives the opaque pre-policy authorization for a
// null reverse-path DSN after RFC 6522/3464 structure and recipient linkage,
// embedded DKIM2 verification, and outer-recipient binding all pass. It never
// touches a signing profile; ResolveDSNSigningIdentity selects the Draft-08
// Section 16.2 signing identity afterwards. A returned original without any
// DKIM2-Signature header field fails with DSNEvidenceStageEmbeddedUnsigned;
// one that carries such a field always takes the strict verification path.
func (s *Signer) EvaluateDSNForSigning(ctx context.Context, request DSNSigningEvidenceRequest) (DSNSigningEvidence, error) {
	if s == nil || !s.initialized || ctx == nil ||
		!bytes.Equal(request.outerReversePath, []byte("<>")) || len(request.outerForwardPaths) != 1 ||
		len(request.outerRaw) == 0 {
		return DSNSigningEvidence{}, newDSNEvidenceError(
			DSNEvidenceStagePreflight, newSigningError(SigningErrorInvalidRequest),
		)
	}
	if err := ctx.Err(); err != nil {
		return DSNSigningEvidence{}, err
	}
	report, err := dsn.Parse(request.outerRaw)
	if err != nil {
		return DSNSigningEvidence{}, newDSNEvidenceError(
			DSNEvidenceStageMIMEParse, newSigningError(SigningErrorMalformedInput),
		)
	}
	var evidence dsn.Evidence
	if request.postfixBounceWireProfile {
		evidence, err = s.revision.EvaluatePostfixDeliveryStatus(ctx, report)
	} else {
		evidence, err = s.revision.EvaluateDeliveryStatus(ctx, report)
	}
	if err != nil {
		return DSNSigningEvidence{}, mapDSNEvidenceError(ctx, err)
	}
	if !bytes.Equal(request.outerForwardPaths[0], evidence.MailFrom()) {
		return DSNSigningEvidence{}, newDSNEvidenceError(
			DSNEvidenceStageOuterRecipientLinkage,
			newSigningError(SigningErrorAuthorizationDenied),
		)
	}
	return DSNSigningEvidence{
		raw: bytes.Clone(request.outerRaw), reversePath: bytes.Clone(request.outerReversePath),
		forwardPaths: cloneByteSlices(request.outerForwardPaths), preferred: request.preferred,
		evidence: evidence, valid: true,
	}, nil
}

// DSNProfileSource resolves the local delivery_status signing profile of one
// candidate domain for ResolveDSNSigningIdentity. Implementations return
// found=false with a nil error only when the domain has no such profile;
// every unavailable, ambiguous, or otherwise undecided answer is an error.
type DSNProfileSource interface {
	DeliveryStatusProfile(ctx context.Context, domain string) (profile SigningProfile, found bool, err error)
}

// ResolveDSNSigningIdentity is the single owner of the Draft-08 Section 16.2
// DSN signing identity. It walks the candidates of
// dsn.Evidence.SigningIdentityCandidates (domains that relaxed-match an rt=
// address of the highest DKIM2-Signature of the reported message, RFC 3464
// linked recipients first, then the preferred identity, then the most specific
// domain) and binds the first candidate that has a local delivery_status
// profile and makes the report's own From header field Authentic (Sections 11
// and 12.4). It returns the bound evidence and that profile.
//
// No candidate with a profile yields DSNEvidenceStageIdentityUnavailable;
// candidates with a profile that all leave the From non-Authentic yield
// DSNEvidenceStageFromNotAuthentic. Both are explicit "cannot be DKIM2
// signed" outcomes, never a fallback to another domain. A profile source
// error, a profile for a different domain, or cancellation fails with
// DSNEvidenceStageSigningDomain and preserves the cause.
func (s *Signer) ResolveDSNSigningIdentity(ctx context.Context, evidence DSNSigningEvidence, source DSNProfileSource) (DSNSigningEvidence, SigningProfile, error) {
	if s == nil || !s.initialized || ctx == nil || !evidence.Valid() || evidence.identity.Valid() || niliface.IsNil(source) {
		return DSNSigningEvidence{}, SigningProfile{}, newDSNEvidenceError(
			DSNEvidenceStagePreflight, newSigningError(SigningErrorInvalidRequest),
		)
	}
	message, err := rawmsg.Parse(evidence.raw)
	if err != nil {
		return DSNSigningEvidence{}, SigningProfile{}, newDSNEvidenceError(
			DSNEvidenceStagePreflight, newSigningError(SigningErrorMalformedInput),
		)
	}
	headers := message.Headers()
	profileFound := false
	for _, candidate := range evidence.evidence.SigningIdentityCandidates(evidence.preferred.domain) {
		if err := ctx.Err(); err != nil {
			return DSNSigningEvidence{}, SigningProfile{}, newDSNEvidenceError(DSNEvidenceStageSigningDomain, err)
		}
		authentic := verify.FromAuthenticFor(headers, candidate.Domain())
		if !authentic && profileFound {
			continue
		}
		profile, found, lookupErr := source.DeliveryStatusProfile(ctx, candidate.Domain())
		if lookupErr != nil {
			return DSNSigningEvidence{}, SigningProfile{}, newDSNEvidenceError(DSNEvidenceStageSigningDomain, lookupErr)
		}
		if !found {
			continue
		}
		if !profile.value.ValidForLimits(s.limits) || profile.value.Domain() != candidate.Domain() {
			return DSNSigningEvidence{}, SigningProfile{}, newDSNEvidenceError(
				DSNEvidenceStageSigningDomain, newSigningError(SigningErrorInvalidRequest),
			)
		}
		profileFound = true
		if !authentic {
			continue
		}
		bound := evidence
		bound.raw = bytes.Clone(evidence.raw)
		bound.reversePath = bytes.Clone(evidence.reversePath)
		bound.forwardPaths = cloneByteSlices(evidence.forwardPaths)
		bound.identity = DSNIdentity{domain: candidate.Domain()}
		return bound, profile, nil
	}
	stage := DSNEvidenceStageIdentityUnavailable
	if profileFound {
		stage = DSNEvidenceStageFromNotAuthentic
	}
	return DSNSigningEvidence{}, SigningProfile{}, newDSNEvidenceError(stage, newSigningError(SigningErrorAuthorizationDenied))
}

// SignDSN signs only a DSN previously authorized by EvaluateDSNForSigning.
func (s *Signer) SignDSN(ctx context.Context, request DSNSigningRequest) (SigningResult, SigningRecovery, error) {
	if s == nil || !s.initialized || ctx == nil || !request.evidence.Resolved() ||
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

// mapDSNEvidenceError preserves cancellation and converts content-free DSN
// outcomes into the public signing vocabulary. An unsigned embedded original
// maps to its own closed stage but keeps the authorization-denied cause, so
// callers that do not opt into a compatibility policy still refuse it.
func mapDSNEvidenceError(ctx context.Context, err error) error {
	if ctx != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return newDSNEvidenceError(DSNEvidenceStageEmbeddedVerification, ctxErr)
		}
	}
	stage := DSNEvidenceStagePreflight
	switch {
	case dsn.IsEvidenceErrorCode(err, dsn.EvidenceErrorCodeInvalidEmbeddedMessage):
		stage = DSNEvidenceStageEmbeddedMessage
	case dsn.IsEvidenceErrorCode(err, dsn.EvidenceErrorCodeUnsignedEmbeddedMessage):
		stage = DSNEvidenceStageEmbeddedUnsigned
	case dsn.IsEvidenceErrorCode(err, dsn.EvidenceErrorCodeVerificationFailed),
		dsn.IsEvidenceErrorCode(err, dsn.EvidenceErrorCodeVerificationIndeterminate):
		stage = DSNEvidenceStageEmbeddedVerification
	case dsn.IsEvidenceErrorCode(err, dsn.EvidenceErrorCodeInvalidEmbeddedClaims):
		stage = DSNEvidenceStageEmbeddedClaims
	case dsn.IsEvidenceErrorCode(err, dsn.EvidenceErrorCodeDeliveryStatusLinkage):
		stage = DSNEvidenceStageDeliveryStatusLinkage
	}
	code := SigningErrorAuthorizationDenied
	if dsn.IsEvidenceErrorCode(err, dsn.EvidenceErrorCodeVerificationIndeterminate) {
		code = SigningErrorCallbackTemporary
	}
	return newDSNEvidenceError(stage, newSigningError(code))
}

// newDSNEvidenceError binds a closed diagnostic stage to an existing bounded cause.
func newDSNEvidenceError(stage DSNEvidenceStage, cause error) error {
	if !stage.Known() || cause == nil {
		return newSigningError(SigningErrorInternalInvariant)
	}
	return &DSNEvidenceError{stage: stage, cause: cause}
}
