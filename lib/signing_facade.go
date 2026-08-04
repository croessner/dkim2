package dkim2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/routeplan"
	"github.com/croessner/dkim2/internal/signing"
	"github.com/croessner/dkim2/internal/verify"
)

// SigningTransportForm identifies the closed signable transport declaration.
type SigningTransportForm string

const (
	// SigningTransportFinalNetworkPreDotStuffing declares final network-form
	// RFC 5322 bytes before SMTP dot-stuffing.
	SigningTransportFinalNetworkPreDotStuffing SigningTransportForm = "final_network_form_pre_dot_stuffing"
)

// Known reports whether form is the sole signable transport declaration.
func (f SigningTransportForm) Known() bool {
	return f == SigningTransportFinalNetworkPreDotStuffing
}

// SigningFlag identifies one caller-requestable baseline flag.
type SigningFlag string

const (
	// SigningFlagDoNotModify requests authenticated donotmodify.
	SigningFlagDoNotModify SigningFlag = "donotmodify"
	// SigningFlagDoNotExplode requests authenticated donotexplode.
	SigningFlagDoNotExplode SigningFlag = "donotexplode"
	// SigningFlagFeedback requests authenticated feedback.
	SigningFlagFeedback SigningFlag = "feedback"
)

// Known reports whether the flag may be requested by a caller.
func (f SigningFlag) Known() bool {
	return f == SigningFlagDoNotModify || f == SigningFlagDoNotExplode || f == SigningFlagFeedback
}

// SigningMetadata is immutable optional nonce and requested-flag metadata.
type SigningMetadata struct{ value signing.Metadata }

// NewSigningMetadata validates and snapshots optional nonce and requested flags.
func NewSigningMetadata(nonce []byte, noncePresent bool, flags []SigningFlag) (SigningMetadata, error) {
	requested := make([]string, len(flags))
	for index := range flags {
		requested[index] = string(flags[index])
	}
	value, err := signing.NewSigningMetadata(nonce, noncePresent, requested)
	if err != nil {
		return SigningMetadata{}, mapSigningError(err)
	}
	return SigningMetadata{value: value}, nil
}

// String returns a constant secret-safe metadata summary.
func (m SigningMetadata) String() string { return "dkim2.SigningMetadata{redacted}" }

// GoString returns the constant secret-safe metadata Go representation.
func (m SigningMetadata) GoString() string { return m.String() }

// Format routes every metadata formatting form through the redacted summary.
func (m SigningMetadata) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, m.String()) }

// BodyUnavailablePolicy controls whether a revision may emit explicit b:null.
type BodyUnavailablePolicy uint8

const (
	// RejectUnavailableBody fails when the prior body cannot be represented.
	RejectUnavailableBody BodyUnavailablePolicy = iota
	// AllowUnavailableBody permits explicit b:null when representation is impossible.
	AllowUnavailableBody
)

// Known reports whether policy belongs to the closed revision vocabulary.
func (p BodyUnavailablePolicy) Known() bool {
	return p == RejectUnavailableBody || p == AllowUnavailableBody
}

// RecipeLiteralPolicy controls whether a generated inverse recipe may disclose literals.
type RecipeLiteralPolicy uint8

const (
	// RecipeCopyOnly forbids embedding previous content as literals.
	RecipeCopyOnly RecipeLiteralPolicy = iota
	// RecipeAllowLiterals permits bounded literal disclosure.
	RecipeAllowLiterals
)

// Known reports whether policy belongs to the closed recipe vocabulary.
func (p RecipeLiteralPolicy) Known() bool {
	return p == RecipeCopyOnly || p == RecipeAllowLiterals
}

// RevisionVerificationStatus identifies one dedicated all-hop revision outcome.
type RevisionVerificationStatus string

const (
	// RevisionVerificationVerified reports complete ordinary proof.
	RevisionVerificationVerified RevisionVerificationStatus = "verified"
	// RevisionVerificationTerminalNextDomainAuthorizationRequired reports a
	// clean terminal nd= chain that requires authorized completion or continuation.
	RevisionVerificationTerminalNextDomainAuthorizationRequired RevisionVerificationStatus = "terminal_next_domain_authorization_required"
	// RevisionVerificationProtocolRejected reports rejected inherited evidence.
	RevisionVerificationProtocolRejected RevisionVerificationStatus = "protocol_rejected"
	// RevisionVerificationUnsupported reports unsupported-only inherited evidence.
	RevisionVerificationUnsupported RevisionVerificationStatus = "unsupported"
	// RevisionVerificationProviderTemporary reports retryable key lookup failure.
	RevisionVerificationProviderTemporary RevisionVerificationStatus = "provider_temporary"
	// RevisionVerificationProviderRejected reports permanent key rejection.
	RevisionVerificationProviderRejected RevisionVerificationStatus = "provider_rejected"
	// RevisionVerificationProviderContract reports an illegal provider matrix.
	RevisionVerificationProviderContract RevisionVerificationStatus = "provider_contract"
	// RevisionVerificationLimitExceeded reports exhausted verification bounds.
	RevisionVerificationLimitExceeded RevisionVerificationStatus = "limit_exceeded"
)

// Known reports whether status belongs to the closed revision vocabulary.
func (s RevisionVerificationStatus) Known() bool {
	return signing.RevisionVerificationStatus(s).Known()
}

// RevisionVerification is one initialized dedicated revision outcome.
type RevisionVerification struct {
	status RevisionVerificationStatus
	valid  bool
}

// Valid reports whether the outcome was produced by VerifyForRevision.
func (r RevisionVerification) Valid() bool { return r.valid && r.status.Known() }

// Status returns the closed revision outcome.
func (r RevisionVerification) Status() RevisionVerificationStatus {
	if !r.Valid() {
		return ""
	}
	return r.status
}

// String returns a constant secret-safe outcome summary.
func (r RevisionVerification) String() string { return "dkim2.RevisionVerification{redacted}" }

// GoString returns the constant secret-safe outcome Go representation.
func (r RevisionVerification) GoString() string { return r.String() }

// Format routes every outcome formatting form through the redacted summary.
func (r RevisionVerification) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// VerifiedRevisionInput is an opaque exact-input capability with no raw-message accessor.
type VerifiedRevisionInput struct{ value signing.VerifiedRevisionInput }

// Valid reports only whether the capability has an issued structural shape.
func (c VerifiedRevisionInput) Valid() bool { return c.value.Valid() }

// String returns a constant secret-safe capability summary.
func (c VerifiedRevisionInput) String() string { return "dkim2.VerifiedRevisionInput{redacted}" }

// GoString returns the constant secret-safe capability Go representation.
func (c VerifiedRevisionInput) GoString() string { return c.String() }

// Format routes every capability formatting form through the redacted summary.
func (c VerifiedRevisionInput) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, c.String())
}

// OriginatorSigningRequest is one immutable exact originator signing request.
type OriginatorSigningRequest struct {
	raw          []byte
	reversePath  []byte
	forwardPaths [][]byte
	ticket       RouteCopyTicket
	profile      SigningProfile
	metadata     SigningMetadata
	transport    SigningTransportForm
}

// NewOriginatorSigningRequest snapshots one originator signing request.
func NewOriginatorSigningRequest(rawMessage, reversePath []byte, forwardPaths [][]byte, ticket RouteCopyTicket, profile SigningProfile, metadata SigningMetadata, transport SigningTransportForm) OriginatorSigningRequest {
	return OriginatorSigningRequest{
		raw: bytes.Clone(rawMessage), reversePath: bytes.Clone(reversePath),
		forwardPaths: cloneByteSlices(forwardPaths), ticket: ticket, profile: profile,
		metadata: metadata, transport: transport,
	}
}

// String returns a constant secret-safe request summary.
func (r OriginatorSigningRequest) String() string { return "dkim2.OriginatorSigningRequest{redacted}" }

// GoString returns the constant secret-safe request Go representation.
func (r OriginatorSigningRequest) GoString() string { return r.String() }

// Format routes every request formatting form through the redacted summary.
func (r OriginatorSigningRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// ExistingSigningRequest is one immutable exact verified forwarding or revision request.
type ExistingSigningRequest struct {
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
}

// NewExistingSigningRequest snapshots one verified forwarding or revision request.
func NewExistingSigningRequest(capability VerifiedRevisionInput, rawMessage, reversePath []byte, forwardPaths [][]byte, ticket RouteCopyTicket, profile SigningProfile, metadata SigningMetadata, transport SigningTransportForm, bodyPolicy BodyUnavailablePolicy, literalPolicy RecipeLiteralPolicy) ExistingSigningRequest {
	return ExistingSigningRequest{
		capability: capability, raw: bytes.Clone(rawMessage),
		reversePath: bytes.Clone(reversePath), forwardPaths: cloneByteSlices(forwardPaths),
		ticket:  ticket,
		profile: profile, metadata: metadata, transport: transport,
		bodyPolicy: bodyPolicy, literalPolicy: literalPolicy,
	}
}

// String returns a constant secret-safe request summary.
func (r ExistingSigningRequest) String() string { return "dkim2.ExistingSigningRequest{redacted}" }

// GoString returns the constant secret-safe request Go representation.
func (r ExistingSigningRequest) GoString() string { return r.String() }

// Format routes every request formatting form through the redacted summary.
func (r ExistingSigningRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

type signerConfig struct {
	clock  func() time.Time
	limits SigningLimits
}

// SignerOption configures one validated signing facade dependency.
type SignerOption func(*signerConfig) error

// WithSigningClock injects the single deterministic operation clock.
func WithSigningClock(clock func() time.Time) SignerOption {
	return func(config *signerConfig) error {
		if config == nil || clock == nil {
			return newSigningError(SigningErrorInvalidOptions)
		}
		config.clock = clock
		return nil
	}
}

// Signer owns revision proof, fanout planning, authorization, publication,
// private signing, insertion, and final atomic proof for all three signing paths.
type Signer struct {
	revision    signing.RevisionVerifier
	routes      routeplan.Coordinator
	planner     signing.HashPlanCoordinator
	coordinator signing.Coordinator
	publication *signing.PublicationAuthority
	limits      signing.Limits
	initialized bool
}

// NewSigner constructs the complete three-path signing facade.
func NewSigner(publicKeys PublicKeyProvider, routes RouteFanoutAuthority, authorizer SigningAuthorizer, privateKeys PrivateKeySigner, options ...SignerOption) (*Signer, error) {
	if nilPublicKeyProvider(publicKeys) || nilSigningCallback(routes) ||
		nilSigningCallback(authorizer) || nilSigningCallback(privateKeys) {
		return nil, newSigningError(SigningErrorInvalidOptions)
	}
	config := signerConfig{clock: time.Now, limits: DefaultSigningLimits()}
	for _, option := range options {
		if option == nil || option(&config) != nil {
			return nil, newSigningError(SigningErrorInvalidOptions)
		}
	}
	resolvedLimits, err := resolveSigningLimits(config.limits)
	if err != nil {
		return nil, newSigningError(SigningErrorInvalidOptions)
	}
	limits := resolvedLimits.signing
	verification, err := verify.NewVerifier(
		publicKeyBridge{provider: publicKeys},
		verify.WithClock(config.clock),
		verify.WithAlgorithmPolicy(resolvedLimits.algorithm),
		verify.WithLimits(resolvedLimits.verification),
		verify.WithRevisionLimits(resolvedLimits.revision),
	)
	if err != nil {
		return nil, newSigningError(SigningErrorInvalidOptions)
	}
	revision, err := signing.NewRevisionVerifier(verification, limits)
	if err != nil {
		return nil, mapSigningError(err)
	}
	routeCoordinator, err := routeplan.NewCoordinator(routeAuthorityBridge{authority: routes}, resolvedLimits.routes)
	if err != nil {
		return nil, mapRouteError(err)
	}
	publication, err := signing.NewPublicationAuthority(publicKeyBridge{provider: publicKeys}, config.clock, 0)
	if err != nil {
		return nil, mapSigningError(err)
	}
	planner, err := signing.NewHashPlanCoordinator(revision, resolvedLimits.generation, limits)
	if err != nil {
		return nil, mapSigningError(err)
	}
	coordinator, err := signing.NewCoordinator(
		revision, routeCoordinator, publication,
		signingAuthorizerBridge{authorizer: authorizer},
		privateKeySignerBridge{signer: privateKeys}, limits,
	)
	if err != nil {
		return nil, mapSigningError(err)
	}
	return &Signer{
		revision: revision, routes: routeCoordinator, planner: planner,
		coordinator: coordinator, publication: publication,
		limits: limits, initialized: true,
	}, nil
}

// PlanRouteFanout finalizes one complete intended fanout and returns its exact tickets.
func (s *Signer) PlanRouteFanout(ctx context.Context, request RouteFanoutRequest) (RouteFanoutPlan, []RouteCopyTicket, error) {
	if s == nil || !s.initialized || ctx == nil {
		return RouteFanoutPlan{}, nil, newSigningError(SigningErrorInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return RouteFanoutPlan{}, nil, err
	}
	plan, tickets, err := s.routes.Finalize(ctx, request.value)
	if err != nil {
		return RouteFanoutPlan{}, nil, mapOperationError(err)
	}
	output := make([]RouteCopyTicket, len(tickets))
	for index := range tickets {
		output[index] = RouteCopyTicket{value: tickets[index]}
	}
	return RouteFanoutPlan{value: plan}, output, nil
}

// VerifyForRevision verifies all inherited protocol evidence and seals clean exact input.
func (s *Signer) VerifyForRevision(ctx context.Context, request VerifyRequest) (RevisionVerification, VerifiedRevisionInput, error) {
	if s == nil || !s.initialized || ctx == nil {
		return RevisionVerification{}, VerifiedRevisionInput{}, newSigningError(SigningErrorInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return RevisionVerification{}, VerifiedRevisionInput{}, err
	}
	message, err := rawmsg.Parse(request.RawMessage())
	if err != nil {
		return RevisionVerification{
			status: RevisionVerificationProtocolRejected, valid: true,
		}, VerifiedRevisionInput{}, nil
	}
	outcome, capability, err := s.revision.VerifyForRevision(ctx, signing.RevisionRequest{
		Message:  message,
		Envelope: verify.NewEnvelope(request.ReversePath(), request.ForwardPaths()),
	})
	if err != nil {
		return RevisionVerification{}, VerifiedRevisionInput{}, mapOperationError(err)
	}
	return RevisionVerification{
		status: RevisionVerificationStatus(outcome.Status()), valid: outcome.Valid(),
	}, VerifiedRevisionInput{value: capability}, nil
}

// SignOriginator executes the sole originator request path.
func (s *Signer) SignOriginator(ctx context.Context, request OriginatorSigningRequest) (SigningResult, SigningRecovery, error) {
	if s == nil || !s.initialized || ctx == nil {
		return SigningResult{}, SigningRecovery{}, newSigningError(SigningErrorInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return SigningResult{}, SigningRecovery{}, err
	}
	if !request.transport.Known() || !request.ticket.Valid() ||
		!request.ticket.value.MatchesEnvelope(request.reversePath, request.forwardPaths) ||
		!request.profile.value.ValidForLimits(s.limits) || !request.metadata.value.Valid() {
		return SigningResult{}, SigningRecovery{}, newSigningError(SigningErrorInvalidRequest)
	}
	if bytes.Equal(request.reversePath, []byte("<>")) {
		return SigningResult{}, SigningRecovery{}, newSigningError(SigningErrorInvalidRequest)
	}
	message, err := rawmsg.Parse(request.raw)
	if err != nil {
		return SigningResult{}, SigningRecovery{}, newSigningError(SigningErrorMalformedInput)
	}
	plan, err := s.planner.PlanOriginator(ctx, signing.OriginatorPlanRequest{
		Message: message, Ticket: request.ticket.value,
	})
	if err != nil {
		return SigningResult{}, SigningRecovery{}, mapOperationError(err)
	}
	return s.complete(ctx, signing.SignFieldRequest{
		Plan: plan, Message: message, Ticket: request.ticket.value,
		ReversePath: bytes.Clone(request.reversePath), ForwardPaths: cloneByteSlices(request.forwardPaths),
		Profile: request.profile.value, Metadata: request.metadata.value,
		Transport:    rawmsg.TransportForm(request.transport),
		EnvelopeForm: signing.SignatureEnvelopeOrdinary,
	})
}

// SignExisting executes the sole combined verified forwarding or revision path.
func (s *Signer) SignExisting(ctx context.Context, request ExistingSigningRequest) (SigningResult, SigningRecovery, error) {
	if s == nil || !s.initialized || ctx == nil {
		return SigningResult{}, SigningRecovery{}, newSigningError(SigningErrorInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return SigningResult{}, SigningRecovery{}, err
	}
	if !request.capability.Valid() || !request.transport.Known() ||
		!request.bodyPolicy.Known() || !request.literalPolicy.Known() ||
		!request.ticket.Valid() ||
		!request.ticket.value.MatchesEnvelope(request.reversePath, request.forwardPaths) ||
		!request.profile.value.ValidForLimits(s.limits) || !request.metadata.value.Valid() {
		return SigningResult{}, SigningRecovery{}, newSigningError(SigningErrorInvalidRequest)
	}
	if bytes.Equal(request.reversePath, []byte("<>")) {
		return SigningResult{}, SigningRecovery{}, newSigningError(SigningErrorInvalidRequest)
	}
	message, err := rawmsg.Parse(request.raw)
	if err != nil {
		return SigningResult{}, SigningRecovery{}, newSigningError(SigningErrorMalformedInput)
	}
	plan, err := s.planner.PlanExisting(ctx, signing.ExistingPlanRequest{
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
		EnvelopeForm: signing.SignatureEnvelopeOrdinary,
	})
}

// complete signs, inserts, reparses, self-verifies, and maps one atomic result.
func (s *Signer) complete(ctx context.Context, request signing.SignFieldRequest) (SigningResult, SigningRecovery, error) {
	field, recovery, err := s.coordinator.CompleteField(ctx, request)
	if err != nil {
		return SigningResult{}, newSigningRecovery(recovery), mapOperationError(err)
	}
	completed, recovery, err := s.coordinator.CompleteMessage(ctx, field)
	if err != nil {
		return SigningResult{}, newSigningRecovery(recovery), mapOperationError(err)
	}
	return newSigningResult(completed), SigningRecovery{}, nil
}

// mapOperationError preserves cancellation and maps closed internal domains.
func mapOperationError(err error) error {
	if err == nil {
		return nil
	}
	for _, code := range []routeplan.ErrorCode{
		routeplan.ErrorInvalidOptions, routeplan.ErrorInvalidRequest, routeplan.ErrorLimitExceeded,
		routeplan.ErrorDenied, routeplan.ErrorTemporary, routeplan.ErrorPermanent,
		routeplan.ErrorContract, routeplan.ErrorState,
	} {
		if routeplan.IsErrorCode(err, code) {
			return mapRouteError(err)
		}
	}
	return mapSigningError(err)
}
