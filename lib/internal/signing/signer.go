package signing

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/cryptodkim2"
	"github.com/croessner/dkim2/internal/provider"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/routeplan"
	"github.com/croessner/dkim2/internal/signature"
	"github.com/croessner/dkim2/internal/verify"
)

// PrivateKeySignStatus identifies the sole successful private-signing outcome.
type PrivateKeySignStatus string

const (
	// PrivateKeySigned reports one completed signature byte string.
	PrivateKeySigned PrivateKeySignStatus = "signed"
)

// PrivateKeySignRequest carries only the closed algorithm and one SHA-256 digest.
type PrivateKeySignRequest struct {
	algorithm   Algorithm
	digest      [sha256.Size]byte
	initialized bool
}

// NewPrivateKeySignRequest constructs one immutable native-digest request.
func NewPrivateKeySignRequest(algorithm Algorithm, digest [sha256.Size]byte) (PrivateKeySignRequest, error) {
	if !algorithm.Known() {
		return PrivateKeySignRequest{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	return PrivateKeySignRequest{algorithm: algorithm, digest: digest, initialized: true}, nil
}

// Valid reports whether the request was constructed for one closed algorithm.
func (r PrivateKeySignRequest) Valid() bool { return r.initialized && r.algorithm.Known() }

// Algorithm returns the requested baseline signature algorithm.
func (r PrivateKeySignRequest) Algorithm() Algorithm { return r.algorithm }

// Digest returns the exact SHA-256 digest by value.
func (r PrivateKeySignRequest) Digest() [sha256.Size]byte { return r.digest }

// String returns a constant secret-safe private request summary.
func (r PrivateKeySignRequest) String() string { return "signing.PrivateKeySignRequest{redacted}" }

// GoString returns the constant secret-safe private request Go representation.
func (r PrivateKeySignRequest) GoString() string { return r.String() }

// Format routes every private request formatting form through the redacted summary.
func (r PrivateKeySignRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// PrivateKeySignResult owns detached signature bytes from one successful callback.
type PrivateKeySignResult struct {
	status    PrivateKeySignStatus
	signature []byte
}

// NewPrivateKeySignResult constructs a detached successful callback result.
func NewPrivateKeySignResult(signatureBytes []byte) PrivateKeySignResult {
	return PrivateKeySignResult{status: PrivateKeySigned, signature: bytes.Clone(signatureBytes)}
}

// String returns a constant secret-safe private result summary.
func (r PrivateKeySignResult) String() string { return "signing.PrivateKeySignResult{redacted}" }

// GoString returns the constant secret-safe private result Go representation.
func (r PrivateKeySignResult) GoString() string { return r.String() }

// Format routes every private result formatting form through the redacted summary.
func (r PrivateKeySignResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// PrivateKeySigner signs one native SHA-256 digest through an opaque key handle.
type PrivateKeySigner interface {
	SignDigest(context.Context, PrivateKeyHandle, PrivateKeySignRequest) (PrivateKeySignResult, error)
}

// SignFieldRequest binds one plan to exact source, route, profile, and metadata.
type SignFieldRequest struct {
	Plan         UnsignedOperationPlan
	Capability   VerifiedRevisionInput
	Message      rawmsg.Message
	Ticket       routeplan.CopyTicket
	ReversePath  []byte
	ForwardPaths [][]byte
	Profile      Profile
	Metadata     Metadata
	Transport    rawmsg.TransportForm
	EnvelopeForm SignatureEnvelopeForm
	NextDomain   string
	Published    PublishedNextDomainCapability
}

// String returns a constant secret-safe field request summary.
func (r SignFieldRequest) String() string { return "signing.SignFieldRequest{redacted}" }

// GoString returns the constant secret-safe field request Go representation.
func (r SignFieldRequest) GoString() string { return r.String() }

// Format routes every field request formatting form through the redacted summary.
func (r SignFieldRequest) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// CompletedSigningField is an internal complete field plus its sole burned route authority.
type CompletedSigningField struct {
	field          signature.CompleteField
	reservation    *routeplan.Reservation
	message        rawmsg.Message
	plan           UnsignedOperationPlan
	profile        Profile
	input          canonical.ByteInput
	metadata       EffectiveMetadata
	transport      rawmsg.TransportForm
	envelopeForm   SignatureEnvelopeForm
	multiplicity   int
	authorizations []AuthorizationFact
	completion     *messageCompletion
	restriction    ForwardingRestriction
	initialized    bool
}

type messageCompletion struct {
	mu   sync.Mutex
	done bool
}

// Valid reports whether the internal completed field retains exactly one burned reservation.
func (f CompletedSigningField) Valid() bool {
	return f.initialized && f.field.Valid() && f.reservation != nil &&
		f.reservation.ReplacementRequired() && f.message.Initialized() &&
		f.plan.Valid() && f.profile.Valid() && f.input.Kind() == canonical.KindSignatureInput &&
		f.input.Len() > 0 && validGeneratedFlags(f.metadata.flags) && f.transport.Known() &&
		f.envelopeForm.Known() &&
		f.multiplicity > 0 && f.multiplicity <= DefaultLimits().MaxParentOutputCopiesAndTickets &&
		authorizationFactsValid(f.authorizations) &&
		authorizationFactsMatchFlags(f.authorizations, f.metadata.flags, f.plan.Role()) &&
		authorizationRestriction(f.authorizations) == f.restriction &&
		f.completion != nil && f.restriction.Known()
}

// String returns a constant secret-safe completed-field summary.
func (f CompletedSigningField) String() string { return "signing.CompletedSigningField{redacted}" }

// GoString returns the constant secret-safe completed-field Go representation.
func (f CompletedSigningField) GoString() string { return f.String() }

// Format routes every completed-field formatting form through the redacted summary.
func (f CompletedSigningField) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, f.String())
}

// Recovery carries only route lineage recovery and never partial signature state.
type Recovery struct {
	replacement routeplan.CopyTicket
	reservation *routeplan.Reservation
	initialized bool
}

// Valid reports whether recovery owns either one replacement or one retryable transition.
func (r Recovery) Valid() bool {
	actionableReservation := r.reservation != nil &&
		(r.reservation.ReleaseRequired() || r.reservation.ReplacementRequired())
	return r.initialized && (r.replacement.Valid() != actionableReservation)
}

// ReplacementReady reports whether Recover will consume an already issued replacement.
func (r Recovery) ReplacementReady() bool {
	return r.Valid() && r.replacement.Valid()
}

// RecoveryPending reports whether route authority recovery must be retried.
func (r Recovery) RecoveryPending() bool {
	return r.Valid() && !r.replacement.Valid() && r.reservation != nil
}

// Recover resumes pending authority cleanup or yields the already issued replacement.
func (r *Recovery) Recover(ctx context.Context) (routeplan.CopyTicket, error) {
	if r == nil || !r.Valid() || ctx == nil {
		return routeplan.CopyTicket{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
	}
	if err := ctx.Err(); err != nil {
		return routeplan.CopyTicket{}, err
	}
	if r.replacement.Valid() {
		replacement := r.replacement
		*r = Recovery{}
		return replacement, nil
	}
	if r.reservation == nil {
		return routeplan.CopyTicket{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
	}
	if r.reservation.ReleaseRequired() {
		err := r.reservation.ReleaseBeforeBoundary(ctx)
		if err == nil || (!r.reservation.ReleaseRequired() && !r.reservation.ReplacementRequired()) {
			*r = Recovery{}
		}
		return routeplan.CopyTicket{}, err
	}
	if r.reservation.ReplacementRequired() {
		replacement, err := r.reservation.Replacement(ctx)
		if err != nil {
			if recovered, recoverErr := r.reservation.RecoverReplacement(); recoverErr == nil {
				r.replacement = recovered
				r.reservation = nil
				return routeplan.CopyTicket{}, err
			}
		}
		if err == nil {
			*r = Recovery{}
		} else if !r.reservation.ReplacementRequired() {
			*r = Recovery{}
		}
		return replacement, err
	}
	return routeplan.CopyTicket{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
}

// String returns a constant secret-safe recovery summary.
func (r Recovery) String() string { return "signing.Recovery{redacted}" }

// GoString returns the constant secret-safe recovery Go representation.
func (r Recovery) GoString() string { return r.String() }

// Format routes every recovery formatting form through the redacted summary.
func (r Recovery) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// Coordinator owns deterministic local preflight and frozen callback ordering.
type Coordinator struct {
	revision    RevisionVerifier
	routes      routeplan.Coordinator
	publication *PublicationAuthority
	authorizer  Authorizer
	signer      PrivateKeySigner
	canonical   canonical.Canonicalizer
	messageHash canonical.Canonicalizer
	limits      Limits
	initialized bool
}

// NewCoordinator constructs one bounded internal field-signing coordinator.
func NewCoordinator(revision RevisionVerifier, routes routeplan.Coordinator, publication *PublicationAuthority, authorizer Authorizer, signer PrivateKeySigner, limits Limits) (Coordinator, error) {
	resolved, err := limits.normalized()
	if err != nil || !revision.valid() || !routes.Valid() || !publication.Valid() || isNilSigningInterface(authorizer) || isNilSigningInterface(signer) {
		return Coordinator{}, newError(ErrorCodeInvalidOptions, ErrorLocation{Phase: PhaseOptions}, ErrorDetails{})
	}
	canonicalLimits := canonical.DefaultLimits()
	canonicalLimits.MaxFieldBytes = resolved.MaxFieldBytes
	canonicalLimits.MaxFieldCount = resolved.MaxProtocolFields
	canonicalLimits.MaxSignatureInputBytes = resolved.MaxSignatureInputBytes
	canonicalizer, err := canonical.NewCanonicalizer(canonical.WithLimits(canonicalLimits))
	if err != nil {
		return Coordinator{}, newError(ErrorCodeInvalidOptions, ErrorLocation{Phase: PhaseOptions}, ErrorDetails{})
	}
	messageLimits := canonical.DefaultLimits()
	rawLimits := rawmsg.DefaultParserOptions()
	messageLimits.MaxFieldBytes = rawLimits.MaxHeaderFieldBytes
	messageLimits.MaxFieldCount = resolved.MaxHeaderFields
	messageHasher, err := canonical.NewCanonicalizer(canonical.WithLimits(messageLimits))
	if err != nil {
		return Coordinator{}, newError(ErrorCodeInvalidOptions, ErrorLocation{Phase: PhaseOptions}, ErrorDetails{})
	}
	return Coordinator{
		revision: revision, routes: routes, publication: publication, authorizer: authorizer,
		signer: signer, canonical: canonicalizer, messageHash: messageHasher,
		limits: resolved, initialized: true,
	}, nil
}

type preparedSigningBranch struct {
	target   signature.UnsignedTarget
	input    canonical.ByteInput
	digest   [sha256.Size]byte
	size     int
	metadata EffectiveMetadata
}

type preparedSigningOperation struct {
	base, feedback                    preparedSigningBranch
	hasFeedback                       bool
	revision                          PreparedRevisionRevalidation
	hasRevision                       bool
	receive, send                     AuthorizationQuery
	policy, feedbackQuery, disclosure AuthorizationQuery
	hasReceive, hasSend               bool
	hasPolicy, hasDisclosure          bool
	session                           *AuthorizationSession
}

// CompleteField executes one already-planned internal signing operation.
//
//nolint:gocyclo // The explicit branches preserve the frozen external callback order.
func (c Coordinator) CompleteField(ctx context.Context, request SignFieldRequest) (CompletedSigningField, Recovery, error) {
	prepared, err := c.preflight(ctx, request)
	if err != nil {
		return CompletedSigningField{}, Recovery{}, err
	}
	reservation, err := c.routes.Reserve(ctx, request.Ticket)
	if err != nil {
		if reservation.RecoveryRequired() {
			return CompletedSigningField{}, Recovery{reservation: &reservation, initialized: true}, err
		}
		return CompletedSigningField{}, Recovery{}, err
	}
	if err := reservation.PrepareExternalBoundary(ctx); err != nil {
		recovery := c.recoverFailure(ctx, &reservation)
		return CompletedSigningField{}, recovery, err
	}
	fail := func(failure error) (CompletedSigningField, Recovery, error) {
		return CompletedSigningField{}, c.recoverFailure(ctx, &reservation), failure
	}

	if prepared.hasRevision {
		if err := c.revision.ExecuteRevalidationForSigning(ctx, prepared.revision); err != nil {
			return fail(err)
		}
	}
	if err := c.publication.ValidateProfilePublication(ctx, request.Profile); err != nil {
		return fail(err)
	}
	if prepared.hasSend {
		if err := c.publication.ConsumeAndRevalidateAt(
			ctx, request.Published, request.Plan.operationInstant().Time(),
		); err != nil {
			return fail(err)
		}
	}
	session := prepared.session
	restriction := RestrictionUnrestricted
	authorizations := make([]AuthorizationFact, 0, 5)
	if prepared.hasReceive {
		authorization, status, callErr := session.Evaluate(ctx, c.authorizer, prepared.receive)
		if callErr != nil || status != AuthorizationAuthorized || !authorization.Valid() {
			if callErr == nil {
				callErr = newError(ErrorCodeAuthorizationDenied, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
			}
			return fail(callErr)
		}
		authorizations = append(authorizations, newAuthorizationFact(
			AuthorizationReceiveNextDomain, status, RestrictionOutOfBand,
		))
	}
	if prepared.hasSend {
		authorization, status, callErr := session.Evaluate(ctx, c.authorizer, prepared.send)
		if callErr != nil || status != AuthorizationAuthorized || !authorization.Valid() {
			if callErr == nil {
				callErr = newError(ErrorCodeAuthorizationDenied, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
			}
			return fail(callErr)
		}
		restriction = RestrictionOutOfBand
		authorizations = append(authorizations, newAuthorizationFact(
			AuthorizationSendNextDomain, status, RestrictionOutOfBand,
		))
	}
	if prepared.hasPolicy {
		authorization, status, callErr := session.Evaluate(ctx, c.authorizer, prepared.policy)
		if callErr != nil || status != AuthorizationAuthorized || !authorization.Valid() {
			if callErr == nil {
				callErr = newError(ErrorCodeAuthorizationDenied, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
			}
			return fail(callErr)
		}
		policyRestriction := authorization.Restriction()
		if restriction == RestrictionOutOfBand && policyRestriction == RestrictionLocalOnly {
			return fail(newError(ErrorCodeAuthorizationDenied, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{}))
		}
		if restriction != RestrictionOutOfBand {
			restriction = policyRestriction
		}
		authorizations = append(authorizations, newAuthorizationFact(AuthorizationPolicy, status, policyRestriction))
	}
	branch := prepared.base
	if prepared.hasFeedback {
		authorization, status, callErr := session.Evaluate(ctx, c.authorizer, prepared.feedbackQuery)
		if callErr != nil {
			return fail(callErr)
		}
		if status == AuthorizationAuthorized && authorization.Valid() {
			effective, deriveErr := DeriveEffectiveMetadata(request.Metadata, request.Capability, request.Ticket, authorization, session)
			if deriveErr != nil || !slices.Equal(effective.Flags(), prepared.feedback.metadata.Flags()) {
				return fail(newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{}))
			}
			branch = prepared.feedback
			authorizations = append(authorizations, newAuthorizationFact(AuthorizationFeedbackRelay, status, RestrictionUnrestricted))
		} else if status != AuthorizationDenied {
			return fail(newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{}))
		} else {
			authorizations = append(authorizations, newAuthorizationFact(AuthorizationFeedbackRelay, status, RestrictionUnrestricted))
		}
	}
	if prepared.hasDisclosure {
		authorization, status, callErr := session.Evaluate(ctx, c.authorizer, prepared.disclosure)
		if callErr != nil || status != AuthorizationAuthorized || !authorization.Valid() {
			if callErr == nil {
				callErr = newError(ErrorCodeDisclosureDenied, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
			}
			return fail(callErr)
		}
		authorizations = append(authorizations, newAuthorizationFact(AuthorizationDisclosure, status, RestrictionUnrestricted))
	}

	values := make([]signature.SetValue, 0, len(request.Profile.credentials))
	cryptoLimits := c.cryptoLimits()
	for _, credential := range request.Profile.credentials {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		signRequest, requestErr := NewPrivateKeySignRequest(credential.algorithm, branch.digest)
		if requestErr != nil {
			return fail(requestErr)
		}
		result, callErr := c.signer.SignDigest(ctx, credential.handle, signRequest)
		signatureBytes, resultErr := c.validateSignerResult(ctx, credential, result, callErr)
		if resultErr != nil {
			return fail(resultErr)
		}
		if selfErr := cryptodkim2.SelfVerifyDigest(credential.algorithm, credential.publicKey, branch.digest[:], signatureBytes, cryptoLimits); selfErr != nil {
			return fail(newError(ErrorCodeCryptographicSelfCheck, ErrorLocation{Phase: PhaseCallback, Algorithm: credential.algorithm}, ErrorDetails{}))
		}
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		values = append(values, signature.SetValue{Selector: credential.selector, Algorithm: credential.algorithm, Signature: signatureBytes})
	}
	complete, err := branch.target.Complete(values)
	if err != nil || len(complete.Bytes()) != branch.size {
		return fail(newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{}))
	}
	rebuiltTarget, err := branch.target.RebuildUnsignedFromComplete(complete)
	if err != nil {
		return fail(newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{}))
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	rebuilt, err := c.canonical.SigningInput(c.signingSelection(request, rebuiltTarget))
	if err != nil || !bytes.Equal(rebuilt.Bytes(), branch.input.Bytes()) {
		return fail(newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{}))
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	custody, err := signature.ValidateCompletedExtension(request.Message.Headers(), complete, signature.CustodyLimits{
		MaxSignatures:             c.limits.MaxSignatures,
		MaxRecipientsPerSignature: signature.DefaultCustodyLimits().MaxRecipientsPerSignature,
	})
	if err != nil || !custody.Valid() {
		return fail(newError(ErrorCodeChainFailure, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{}))
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return CompletedSigningField{
		field: complete, reservation: &reservation, message: request.Message,
		plan: request.Plan, profile: request.Profile, input: branch.input, metadata: branch.metadata,
		transport: request.Transport, multiplicity: request.Ticket.TotalMultiplicity(),
		envelopeForm:   requestEnvelopeForm(request),
		authorizations: slices.Clone(authorizations),
		completion:     &messageCompletion{},
		restriction:    restriction, initialized: true,
	}, Recovery{}, nil
}

// preflight completes every pure check and prepares both possible feedback branches.
//
//nolint:gocyclo // Each explicit guard corresponds to a distinct fail-closed resource or policy gate.
func (c Coordinator) preflight(ctx context.Context, request SignFieldRequest) (preparedSigningOperation, error) {
	if ctx == nil || !c.initialized || !request.Plan.matchesOperation(request.Message, request.Ticket, request.Capability) ||
		!request.Ticket.MatchesEnvelope(request.ReversePath, request.ForwardPaths) ||
		!request.Profile.Valid() || !metadataValid(request.Metadata) || !request.Transport.Known() {
		return preparedSigningOperation{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	nextDomainOperation := requestEnvelopeForm(request) == SignatureEnvelopeNextDomain
	if nextDomainOperation != (request.Ticket.Purpose() == routeplan.PurposeNextDomain) ||
		nextDomainOperation != (request.NextDomain != "") ||
		nextDomainOperation != request.Published.Valid() {
		return preparedSigningOperation{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if nextDomainOperation {
		if err := c.publication.ValidateNextDomainCapabilityAt(
			request.Published, request.Plan.operationInstant().Time(),
		); err != nil {
			return preparedSigningOperation{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return preparedSigningOperation{}, err
	}
	if multiplicity := request.Ticket.TotalMultiplicity(); multiplicity > c.limits.MaxParentOutputCopiesAndTickets {
		return preparedSigningOperation{}, limitError(
			LimitNameMaxParentOutputCopiesAndTickets, c.limits.MaxParentOutputCopiesAndTickets, multiplicity,
		)
	}
	if fields := request.Plan.sizes.FinalHeaderFields(); fields > c.limits.MaxHeaderFields {
		return preparedSigningOperation{}, limitError(LimitNameMaxHeaderFields, c.limits.MaxHeaderFields, fields)
	}
	credentials := request.Profile.credentials
	if len(credentials) == 0 || len(credentials) > c.limits.MaxPrivateSigningCalls {
		return preparedSigningOperation{}, limitError(LimitNameMaxPrivateSigningCalls, c.limits.MaxPrivateSigningCalls, len(credentials))
	}
	cryptoLimits := c.cryptoLimits()
	lengths := make([]signature.SetLength, len(credentials))
	for index, credential := range credentials {
		validated, err := cryptodkim2.ValidatePublicKey(credential.algorithm, credential.publicKey, cryptoLimits)
		if err != nil {
			return preparedSigningOperation{}, newError(ErrorCodeKeyMismatch, ErrorLocation{Phase: PhasePreflight, Algorithm: credential.algorithm}, ErrorDetails{})
		}
		length := c.limits.Ed25519SignatureBytes
		if key, ok := validated.(*rsa.PublicKey); ok {
			length = key.Size()
		}
		if err := cryptodkim2.ValidateSignatureLength(credential.algorithm, validated, length, cryptoLimits); err != nil {
			return preparedSigningOperation{}, newError(ErrorCodeKeyMismatch, ErrorLocation{Phase: PhasePreflight, Algorithm: credential.algorithm}, ErrorDetails{})
		}
		lengths[index] = signature.SetLength{Selector: credential.selector, Algorithm: credential.algorithm, Bytes: length}
	}
	baseMetadata, err := DeriveEffectiveMetadata(request.Metadata, request.Capability, request.Ticket, Authorization{}, nil)
	if err != nil {
		return preparedSigningOperation{}, err
	}
	base, err := c.prepareBranch(request, baseMetadata, lengths)
	if err != nil {
		return preparedSigningOperation{}, err
	}
	if _, err := signature.ValidateUnsignedExtension(request.Message.Headers(), base.target, signature.CustodyLimits{
		MaxSignatures:             c.limits.MaxSignatures,
		MaxRecipientsPerSignature: signature.DefaultCustodyLimits().MaxRecipientsPerSignature,
	}); err != nil {
		return preparedSigningOperation{}, mapSignaturePreflightError(err, ErrorCodeChainFailure)
	}
	prepared := preparedSigningOperation{base: base}
	if request.Capability.Valid() {
		prepared.revision, err = c.revision.PrepareRevalidationForSigningAt(ctx, request.Capability, request.Plan.instant)
		if err != nil {
			return preparedSigningOperation{}, err
		}
		prepared.hasRevision = true
		if request.Capability.proof.State() == verify.RevisionProofTerminalNextDomainAuthorizationRequired {
			prepared.receive, err = NewReceiveNextDomainAuthorizationQuery(
				request.Capability, request.Ticket, request.Profile.domain,
			)
			if err != nil {
				return preparedSigningOperation{}, err
			}
			prepared.hasReceive = true
		}
		if nextDomainOperation {
			prepared.send, err = NewSendNextDomainAuthorizationQuery(
				request.Capability, request.Ticket, request.Published,
				request.Profile.domain, request.NextDomain,
			)
			if err != nil {
				return preparedSigningOperation{}, err
			}
			prepared.hasSend = true
		}
		prepared.policy, err = NewPolicyAuthorizationQuery(request.Capability, request.Ticket, request.Plan.modifications)
		if err != nil {
			return preparedSigningOperation{}, err
		}
		if prepared.policy.restriction == RestrictionLocalOnly &&
			request.Ticket.RouteClass() != routeplan.RouteInControl {
			return preparedSigningOperation{}, newError(
				ErrorCodeAuthorizationDenied, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{},
			)
		}
		if prepared.hasSend && prepared.policy.restriction == RestrictionLocalOnly {
			return preparedSigningOperation{}, newError(
				ErrorCodeAuthorizationDenied, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{},
			)
		}
		prepared.hasPolicy = true
		if capabilityHasFeedback(request.Capability) {
			prepared.feedbackQuery, err = NewFeedbackAuthorizationQuery(request.Capability, request.Ticket)
			if err != nil {
				return preparedSigningOperation{}, err
			}
			feedbackMetadata := effectiveMetadataWithFeedbackIntent(baseMetadata)
			prepared.feedback, err = c.prepareBranch(request, feedbackMetadata, lengths)
			if err != nil {
				return preparedSigningOperation{}, err
			}
			prepared.hasFeedback = true
		}
	}
	if !nextDomainOperation && len(request.Ticket.DisclosureRecipients()) > 1 {
		prepared.disclosure, err = NewDisclosureAuthorizationQuery(request.Ticket)
		if err != nil {
			return preparedSigningOperation{}, err
		}
		prepared.hasDisclosure = true
	}
	inheritedLookups, inheritedSets := 0, 0
	if prepared.hasRevision {
		usage := prepared.revision.Usage()
		inheritedLookups, inheritedSets = usage.KeyLookups(), usage.SignatureSets()
	}
	if inheritedLookups > c.limits.MaxPublicKeyLookups-len(credentials) {
		return preparedSigningOperation{}, limitError(LimitNameMaxPublicKeyLookups, c.limits.MaxPublicKeyLookups, inheritedLookups+len(credentials))
	}
	if inheritedSets > c.limits.MaxTotalSignatureSets-len(credentials) {
		return preparedSigningOperation{}, limitError(
			LimitNameMaxTotalSignatureSets, c.limits.MaxTotalSignatureSets, inheritedSets+len(credentials),
		)
	}
	totalCanonical, ok := checkedAdd(request.Plan.generation.canonical, prepared.base.input.Len())
	if ok && prepared.hasFeedback {
		totalCanonical, ok = checkedAdd(totalCanonical, prepared.feedback.input.Len())
	}
	finalPass := prepared.base.input.Len()
	if prepared.hasFeedback && prepared.feedback.input.Len() > finalPass {
		finalPass = prepared.feedback.input.Len()
	}
	if ok {
		totalCanonical, ok = checkedAdd(totalCanonical, finalPass)
	}
	if ok {
		totalCanonical, ok = checkedAdd(totalCanonical, request.Plan.generation.currentCanonical)
	}
	if ok {
		totalCanonical, ok = checkedAdd(totalCanonical, finalPass)
	}
	if !ok || totalCanonical > c.limits.MaxCanonicalWorkBytes {
		if !ok {
			totalCanonical = c.limits.MaxCanonicalWorkBytes + 1
		}
		return preparedSigningOperation{}, limitError(
			LimitNameMaxCanonicalWorkBytes, c.limits.MaxCanonicalWorkBytes, totalCanonical,
		)
	}
	if prepared.hasReceive || prepared.hasSend || prepared.hasPolicy || prepared.hasFeedback || prepared.hasDisclosure {
		authorizationCalls := 0
		if prepared.hasReceive {
			authorizationCalls++
		}
		if prepared.hasSend {
			authorizationCalls++
		}
		if prepared.hasPolicy {
			authorizationCalls++
		}
		if prepared.hasFeedback {
			authorizationCalls++
		}
		if prepared.hasDisclosure {
			authorizationCalls++
		}
		if authorizationCalls > c.limits.MaxAuthorizationCalls {
			return preparedSigningOperation{}, limitError(
				LimitNameMaxAuthorizationCalls, c.limits.MaxAuthorizationCalls, authorizationCalls,
			)
		}
		prepared.session, err = NewAuthorizationSession(c.limits.MaxAuthorizationCalls)
		if err != nil {
			return preparedSigningOperation{}, err
		}
	}
	return prepared, ctx.Err()
}

// prepareBranch renders, sizes, canonicalizes, and hashes one local feedback branch.
func (c Coordinator) prepareBranch(request SignFieldRequest, metadata EffectiveMetadata, lengths []signature.SetLength) (preparedSigningBranch, error) {
	nonce, noncePresent := request.Metadata.Nonce()
	sets := make([]signature.SetPlan, len(request.Profile.credentials))
	for index, credential := range request.Profile.credentials {
		sets[index] = signature.SetPlan{Selector: credential.selector, Algorithm: credential.algorithm}
	}
	mailFrom := request.Ticket.ReversePath()
	recipients := request.Ticket.DisclosureRecipients()
	if requestEnvelopeForm(request) == SignatureEnvelopeNextDomain {
		mailFrom = nil
		recipients = nil
	}
	target, err := signature.NewUnsignedTarget(signature.TargetRequest{
		Sequence: request.Plan.NextSequence(), InstanceNumber: request.Plan.SignatureInstance(),
		Timestamp: request.Plan.operationTimestamp(), MailFrom: mailFrom,
		Recipients: recipients, NextDomain: request.NextDomain,
		Domain: request.Profile.domain,
		Sets:   sets, Nonce: nonce, NoncePresent: noncePresent, Flags: metadata.Flags(),
	}, signature.RenderLimits{
		MaxFieldBytes: c.limits.MaxFieldBytes, MaxLineBytes: c.limits.MaxLineBytes,
		MaxRecipients: c.limits.MaxGeneratedRecipients, MaxSignatureSets: c.limits.MaxGeneratedSignatureSets,
		MaxEnvelopePathBytes: c.limits.MaxEnvelopePathBytes, MaxNonceBytes: c.limits.MaxNonceBytes,
		MaxSignatureBytes: c.limits.MaxPrivateSignatureBytes,
	})
	if err != nil {
		return preparedSigningBranch{}, mapSignaturePreflightError(err, ErrorCodeInternalInvariant)
	}
	size, err := target.PreflightComplete(lengths)
	if err != nil {
		return preparedSigningBranch{}, mapSignaturePreflightError(err, ErrorCodeInternalInvariant)
	}
	baseHeader := request.Plan.sizes.headerBytes - request.Plan.sizes.signatureFieldBytes
	baseMessage := request.Plan.sizes.messageBytes - request.Plan.sizes.signatureFieldBytes
	if size > c.limits.MaxHeaderBytes-baseHeader {
		return preparedSigningBranch{}, limitError(LimitNameMaxHeaderBytes, c.limits.MaxHeaderBytes, baseHeader+size)
	}
	if size > c.limits.MaxMessageBytes-baseMessage {
		return preparedSigningBranch{}, limitError(LimitNameMaxMessageBytes, c.limits.MaxMessageBytes, baseMessage+size)
	}
	if size > request.Plan.sizes.signatureFieldBytes {
		name, limit, actual, ok := request.Plan.sizes.signatureAllowanceFailure(size)
		if !ok {
			return preparedSigningBranch{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
		}
		return preparedSigningBranch{}, limitError(name, limit, actual)
	}
	input, err := c.canonical.SigningInput(c.signingSelection(request, target))
	if err != nil {
		return preparedSigningBranch{}, mapCanonicalPreflightError(err)
	}
	if input.Len() > c.limits.MaxSignatureInputBytes {
		return preparedSigningBranch{}, limitError(
			LimitNameMaxSignatureInputBytes, c.limits.MaxSignatureInputBytes, input.Len(),
		)
	}
	if request.Plan.generation.canonical > c.limits.MaxCanonicalWorkBytes-input.Len() {
		return preparedSigningBranch{}, limitError(LimitNameMaxCanonicalWorkBytes, c.limits.MaxCanonicalWorkBytes, request.Plan.generation.canonical+input.Len())
	}
	return preparedSigningBranch{
		target: target, input: input, digest: sha256.Sum256(input.Bytes()), size: size, metadata: metadata,
	}, nil
}

// requestEnvelopeForm derives the sole generated signature shape from closed request evidence.
func requestEnvelopeForm(request SignFieldRequest) SignatureEnvelopeForm {
	if request.EnvelopeForm == SignatureEnvelopeNextDomain ||
		request.Ticket.Purpose() == routeplan.PurposeNextDomain ||
		request.NextDomain != "" || request.Published.Valid() {
		return SignatureEnvelopeNextDomain
	}
	return SignatureEnvelopeOrdinary
}

// mapCanonicalPreflightError preserves exact bounded canonical limit taxonomy.
func mapCanonicalPreflightError(err error) error {
	if !canonical.IsErrorCode(err, canonical.ErrorCodeLimitExceeded) {
		return newError(ErrorCodeMalformedInput, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	var typed *canonical.Error
	if !errors.As(err, &typed) {
		return newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	var name LimitName
	switch typed.LimitName() {
	case "max_field_count":
		name = LimitNameMaxProtocolFields
	case "max_field_bytes":
		name = LimitNameMaxFieldBytes
	case "max_signature_input_bytes":
		name = LimitNameMaxSignatureInputBytes
	default:
		return newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	return limitError(name, typed.Limit(), typed.Count())
}

// mapSignaturePreflightError preserves owner-reported generated-field and custody limits.
func mapSignaturePreflightError(err error, fallback ErrorCode) error {
	if !signature.IsErrorCode(err, signature.ErrorCodeLimitExceeded) {
		return newError(fallback, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	var typed *signature.Error
	if !errors.As(err, &typed) {
		return newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	var name LimitName
	switch signature.LimitName(typed.LimitName()) {
	case signature.LimitNameMaxRecipients:
		name = LimitNameMaxGeneratedRecipients
	case signature.LimitNameMaxSignatureSets:
		name = LimitNameMaxGeneratedSignatureSets
	case signature.LimitNameMaxNonceBytes:
		name = LimitNameMaxNonceBytes
	case signature.LimitNameMaxSignatures:
		name = LimitNameMaxSignatures
	case signature.LimitNameMaxFieldBytes:
		name = LimitNameMaxFieldBytes
	case signature.LimitNameMaxLineBytes:
		name = LimitNameMaxLineBytes
	case signature.LimitNameMaxEnvelopePathBytes:
		name = LimitNameMaxEnvelopePathBytes
	case signature.LimitNameMaxSignatureBytes:
		name = LimitNameMaxPrivateSignatureBytes
	default:
		return newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	return limitError(name, typed.Limit(), typed.Count())
}

// signingSelection binds exact planner-owned generated-instance bytes to canonical input.
func (c Coordinator) signingSelection(request SignFieldRequest, target signature.UnsignedTarget) canonical.SigningInputSelection {
	model, hasModel := request.Plan.MessageInstance()
	return canonical.SigningInputSelection{
		Headers: request.Message.Headers(), GeneratedInstance: model,
		GeneratedInstanceField: request.Plan.RenderedInstance(), HasGeneratedInstance: hasModel, Target: target,
	}
}

// validateSignerResult enforces the strict result/error/context matrix.
func (c Coordinator) validateSignerResult(ctx context.Context, credential Credential, result PrivateKeySignResult, callErr error) ([]byte, error) {
	ctxErr := ctx.Err()
	if isTypedNilSigningError(callErr) {
		return nil, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
	}
	if callErr != nil {
		if result.status != "" || result.signature != nil {
			return nil, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
		}
		if ctxErr != nil && errors.Is(callErr, ctxErr) {
			return nil, ctxErr
		}
		class := provider.ClassOf(callErr)
		if !class.Known() {
			return nil, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
		}
		if ctxErr != nil {
			return nil, ctxErr
		}
		switch class {
		case provider.FailureTemporary:
			return nil, newError(ErrorCodeCallbackTemporary, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
		case provider.FailurePermanent:
			return nil, newError(ErrorCodeCallbackPermanent, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
		default:
			return nil, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
		}
	}
	if result.status != PrivateKeySigned || len(result.signature) == 0 ||
		len(result.signature) > c.limits.MaxPrivateSignatureBytes {
		return nil, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
	}
	detached := bytes.Clone(result.signature)
	if err := cryptodkim2.ValidateSignatureLength(credential.algorithm, credential.publicKey, len(detached), c.cryptoLimits()); err != nil {
		return nil, newError(ErrorCodeCryptographicSelfCheck, ErrorLocation{Phase: PhaseCallback, Algorithm: credential.algorithm}, ErrorDetails{})
	}
	if ctxErr != nil {
		return nil, ctxErr
	}
	return bytes.Clone(detached), nil
}

// recoverFailure releases before burn or obtains one same-lineage replacement after burn.
func (c Coordinator) recoverFailure(ctx context.Context, reservation *routeplan.Reservation) Recovery {
	if reservation == nil {
		return Recovery{}
	}
	recoveryContext := context.WithoutCancel(ctx)
	if reservation.ReleaseRequired() {
		if err := reservation.ReleaseBeforeBoundary(recoveryContext); err != nil {
			if reservation.ReleaseRequired() {
				return Recovery{reservation: reservation, initialized: true}
			}
			return Recovery{}
		}
		return Recovery{}
	}
	if reservation.ReplacementRequired() {
		replacement, err := reservation.Replacement(recoveryContext)
		if err == nil && replacement.Valid() {
			return Recovery{replacement: replacement, initialized: true}
		}
		if recovered, recoverErr := reservation.RecoverReplacement(); recoverErr == nil && recovered.Valid() {
			return Recovery{replacement: recovered, initialized: true}
		}
		if reservation.ReplacementRequired() {
			return Recovery{reservation: reservation, initialized: true}
		}
		return Recovery{}
	}
	return Recovery{}
}

// cryptoLimits returns the shared strict signing and self-verification contract.
func (c Coordinator) cryptoLimits() cryptodkim2.Limits {
	return cryptodkim2.Limits{
		MinRSABits: c.limits.MinRSABits, MaxRSABits: c.limits.MaxRSABits,
		RequiredRSAExponent: c.limits.RequiredRSAExponent, MaxSignatureBytes: c.limits.MaxPrivateSignatureBytes,
	}
}
