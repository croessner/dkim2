package dkim2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/dsn"
	"github.com/croessner/dkim2/internal/keyresolver"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signing"
)

// DSNIdentity is the daemon-owned canonical DNS identity permitted to sign a
// delivery-status notification.
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
	// DSNEvidenceStageEmbeddedClaims identifies invalid authenticated protocol claims.
	DSNEvidenceStageEmbeddedClaims DSNEvidenceStage = "embedded_claims"
	// DSNEvidenceStageDeliveryStatusLinkage identifies RFC 3464 recipient linkage failure.
	DSNEvidenceStageDeliveryStatusLinkage DSNEvidenceStage = "delivery_status_linkage"
	// DSNEvidenceStageOuterRecipientLinkage identifies outer recipient and mf= mismatch.
	DSNEvidenceStageOuterRecipientLinkage DSNEvidenceStage = "outer_recipient_linkage"
	// DSNEvidenceStageSigningDomain identifies authenticated signing-domain derivation failure.
	DSNEvidenceStageSigningDomain DSNEvidenceStage = "signing_domain"
	// DSNEvidenceStageAuthorized identifies completed pre-policy evidence authorization.
	DSNEvidenceStageAuthorized DSNEvidenceStage = "authorized"
)

// Known reports whether the stage belongs to the fixed DSN evidence pipeline.
func (s DSNEvidenceStage) Known() bool {
	switch s {
	case DSNEvidenceStagePreflight, DSNEvidenceStageMIMEParse,
		DSNEvidenceStageEmbeddedMessage, DSNEvidenceStageEmbeddedVerification,
		DSNEvidenceStageEmbeddedClaims, DSNEvidenceStageDeliveryStatusLinkage,
		DSNEvidenceStageOuterRecipientLinkage, DSNEvidenceStageSigningDomain,
		DSNEvidenceStageAuthorized:
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

// DSNSigningEvidenceRequest carries the exact outer evidence needed before a
// locally generated DSN can be authorized for signing.
type DSNSigningEvidenceRequest struct {
	outerRaw                 []byte
	outerReversePath         []byte
	outerForwardPaths        [][]byte
	identity                 DSNIdentity
	deriveIdentity           bool
	postfixBounceWireProfile bool
}

// NewDerivedDSNSigningEvidenceRequest snapshots a DSN evidence request whose
// signing identity must be derived only from verified embedded DKIM2 evidence.
func NewDerivedDSNSigningEvidenceRequest(outerRaw, outerReversePath []byte, outerForwardPaths [][]byte) DSNSigningEvidenceRequest {
	return DSNSigningEvidenceRequest{
		outerRaw: bytes.Clone(outerRaw), outerReversePath: bytes.Clone(outerReversePath),
		outerForwardPaths: cloneByteSlices(outerForwardPaths), deriveIdentity: true,
	}
}

// NewPostfixDerivedDSNSigningEvidenceRequest snapshots a derived DSN evidence
// request whose delivery-status field order may use the exact bounded form
// emitted by Postfix bounce(8).
//
// Security precondition: trusted adapters must select this constructor only
// after independently proving that Postfix bounce(8) generated the DSN. It is
// not a parser hint for untrusted message input. Generic and non-Postfix paths
// must use NewDerivedDSNSigningEvidenceRequest.
func NewPostfixDerivedDSNSigningEvidenceRequest(
	outerRaw, outerReversePath []byte,
	outerForwardPaths [][]byte,
) DSNSigningEvidenceRequest {
	return DSNSigningEvidenceRequest{
		outerRaw: bytes.Clone(outerRaw), outerReversePath: bytes.Clone(outerReversePath),
		outerForwardPaths: cloneByteSlices(outerForwardPaths), deriveIdentity: true,
		postfixBounceWireProfile: true,
	}
}

// NewDSNSigningEvidenceRequest snapshots one DSN evidence request.
func NewDSNSigningEvidenceRequest(outerRaw, outerReversePath []byte, outerForwardPaths [][]byte, identity DSNIdentity) DSNSigningEvidenceRequest {
	return DSNSigningEvidenceRequest{
		outerRaw: bytes.Clone(outerRaw), outerReversePath: bytes.Clone(outerReversePath),
		outerForwardPaths: cloneByteSlices(outerForwardPaths), identity: identity,
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

// SigningDomain returns the canonical identity derived from authenticated
// embedded DKIM2 evidence. Invalid evidence returns an empty string.
func (e DSNSigningEvidence) SigningDomain() string {
	if !e.Valid() {
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

// EvaluateDSNForSigning derives the sole opaque authorization for a null
// reverse-path DSN after RFC 3462/3464 structure and recipient linkage,
// embedded DKIM2 verification, and either derived or compatibility-bound
// identity alignment all pass.
func (s *Signer) EvaluateDSNForSigning(ctx context.Context, request DSNSigningEvidenceRequest) (DSNSigningEvidence, error) {
	if s == nil || !s.initialized || ctx == nil ||
		(!request.deriveIdentity && !request.identity.Valid()) ||
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
	identity := request.identity
	if request.deriveIdentity {
		identity, err = NewDSNIdentity(evidence.SigningDomain())
		if err != nil {
			return DSNSigningEvidence{}, newDSNEvidenceError(
				DSNEvidenceStageSigningDomain,
				newSigningError(SigningErrorAuthorizationDenied),
			)
		}
	} else if evidence.SigningDomain() != identity.domain {
		return DSNSigningEvidence{}, newDSNEvidenceError(
			DSNEvidenceStageSigningDomain,
			newSigningError(SigningErrorAuthorizationDenied),
		)
	}
	return DSNSigningEvidence{
		raw: bytes.Clone(request.outerRaw), reversePath: bytes.Clone(request.outerReversePath),
		forwardPaths: cloneByteSlices(request.outerForwardPaths), identity: identity,
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

// mapDSNEvidenceError preserves cancellation and converts content-free DSN outcomes into the public signing vocabulary.
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
