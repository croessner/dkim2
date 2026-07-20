package dkim2

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/signing"
)

// NextDomainPublicationRequest is one closed candidate future credential request.
type NextDomainPublicationRequest struct {
	domain     string
	credential signing.Credential
	valid      bool
}

// NewRSANextDomainPublicationRequest binds one RSA future credential to its nd= domain.
func NewRSANextDomainPublicationRequest(domain string, credential RSASigningCredential) NextDomainPublicationRequest {
	return NextDomainPublicationRequest{domain: domain, credential: credential.value, valid: credential.Valid()}
}

// NewEd25519NextDomainPublicationRequest binds one Ed25519 future credential to its nd= domain.
func NewEd25519NextDomainPublicationRequest(domain string, credential Ed25519SigningCredential) NextDomainPublicationRequest {
	return NextDomainPublicationRequest{domain: domain, credential: credential.value, valid: credential.Valid()}
}

// String returns a constant secret-safe publication-request summary.
func (r NextDomainPublicationRequest) String() string {
	return "dkim2.NextDomainPublicationRequest{redacted}"
}

// GoString returns the constant secret-safe publication-request Go representation.
func (r NextDomainPublicationRequest) GoString() string { return r.String() }

// Format routes every publication-request formatting form through the redacted summary.
func (r NextDomainPublicationRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// PublishedNextDomainCapability is opaque fresh single-use publication evidence.
type PublishedNextDomainCapability struct {
	value signing.PublishedNextDomainCapability
}

// Valid reports only whether the capability has an issued coherent shape.
func (c PublishedNextDomainCapability) Valid() bool { return c.value.Valid() }

// String returns a constant secret-safe publication-capability summary.
func (c PublishedNextDomainCapability) String() string {
	return "dkim2.PublishedNextDomainCapability{redacted}"
}

// GoString returns the constant secret-safe publication-capability Go representation.
func (c PublishedNextDomainCapability) GoString() string { return c.String() }

// Format routes every publication-capability formatting form through the redacted summary.
func (c PublishedNextDomainCapability) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, c.String())
}

// IssueNextDomainPublication performs one fresh authoritative publication lookup.
func (s *Signer) IssueNextDomainPublication(ctx context.Context, request NextDomainPublicationRequest) (PublishedNextDomainCapability, error) {
	if s == nil || !s.initialized || s.publication == nil || ctx == nil ||
		!request.valid || !request.credential.Valid() {
		return PublishedNextDomainCapability{}, newSigningError(SigningErrorInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return PublishedNextDomainCapability{}, err
	}
	value, err := s.publication.IssueNextDomain(ctx, request.domain, request.credential)
	if err != nil {
		return PublishedNextDomainCapability{}, mapOperationError(err)
	}
	return PublishedNextDomainCapability{value: value}, nil
}

// NextDomainSigningRequest is one exact terminal nd= creation or continuation request.
type NextDomainSigningRequest struct {
	capability    VerifiedRevisionInput
	raw           []byte
	reversePath   []byte
	forwardPaths  [][]byte
	ticket        RouteCopyTicket
	profile       SigningProfile
	metadata      SigningMetadata
	transport     SigningTransportForm
	bodyPolicy    BodyUnavailablePolicy
	literalPolicy RecipeLiteralPolicy
	nextDomain    string
	published     PublishedNextDomainCapability
}

// NewNextDomainSigningRequest snapshots one exact terminal nd= request.
func NewNextDomainSigningRequest(
	capability VerifiedRevisionInput,
	rawMessage, reversePath []byte,
	forwardPaths [][]byte,
	ticket RouteCopyTicket,
	profile SigningProfile,
	metadata SigningMetadata,
	transport SigningTransportForm,
	bodyPolicy BodyUnavailablePolicy,
	literalPolicy RecipeLiteralPolicy,
	nextDomain string,
	published PublishedNextDomainCapability,
) NextDomainSigningRequest {
	return NextDomainSigningRequest{
		capability: capability, raw: bytes.Clone(rawMessage),
		reversePath: bytes.Clone(reversePath), forwardPaths: cloneByteSlices(forwardPaths),
		ticket: ticket, profile: profile, metadata: metadata, transport: transport,
		bodyPolicy: bodyPolicy, literalPolicy: literalPolicy,
		nextDomain: nextDomain, published: published,
	}
}

// String returns a constant secret-safe request summary.
func (r NextDomainSigningRequest) String() string {
	return "dkim2.NextDomainSigningRequest{redacted}"
}

// GoString returns the constant secret-safe request Go representation.
func (r NextDomainSigningRequest) GoString() string { return r.String() }

// Format routes every request formatting form through the redacted summary.
func (r NextDomainSigningRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// SignNextDomain executes the distinct terminal next-domain request path.
func (s *Signer) SignNextDomain(ctx context.Context, request NextDomainSigningRequest) (SigningResult, SigningRecovery, error) {
	if s == nil || !s.initialized || ctx == nil {
		return SigningResult{}, SigningRecovery{}, newSigningError(SigningErrorInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return SigningResult{}, SigningRecovery{}, err
	}
	if !request.capability.Valid() || !request.transport.Known() ||
		!request.bodyPolicy.Known() || !request.literalPolicy.Known() ||
		!request.ticket.Valid() || !request.published.Valid() ||
		!request.ticket.value.MatchesEnvelope(request.reversePath, request.forwardPaths) ||
		!request.profile.value.ValidForLimits(s.limits) || !request.metadata.value.Valid() {
		return SigningResult{}, SigningRecovery{}, newSigningError(SigningErrorInvalidRequest)
	}
	message, err := rawmsg.Parse(request.raw)
	if err != nil {
		return SigningResult{}, SigningRecovery{}, newSigningError(SigningErrorMalformedInput)
	}
	plan, err := s.planner.PlanNextDomain(ctx, signing.ExistingPlanRequest{
		Capability: request.capability.value, Message: message, Ticket: request.ticket.value,
		BodyPolicy:    recipe.BodyUnavailablePolicy(request.bodyPolicy),
		LiteralPolicy: recipe.LiteralDisclosurePolicy(request.literalPolicy),
	})
	if err != nil {
		return SigningResult{}, SigningRecovery{}, mapOperationError(err)
	}
	return s.complete(ctx, signing.SignFieldRequest{
		Plan: plan, Capability: request.capability.value, Message: message,
		Ticket: request.ticket.value, ReversePath: bytes.Clone(request.reversePath),
		ForwardPaths: cloneByteSlices(request.forwardPaths), Profile: request.profile.value,
		Metadata: request.metadata.value, Transport: rawmsg.TransportForm(request.transport),
		EnvelopeForm: signing.SignatureEnvelopeNextDomain,
		NextDomain:   request.nextDomain, Published: request.published.value,
	})
}
