package signing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/croessner/dkim2/internal/cryptodkim2"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/routeplan"
	"github.com/croessner/dkim2/internal/signature"
)

// SignatureEnvelopeForm identifies one closed generated signature envelope shape.
type SignatureEnvelopeForm string

const (
	// SignatureEnvelopeOrdinary identifies the required mf= plus rt= form.
	SignatureEnvelopeOrdinary SignatureEnvelopeForm = "ordinary_mf_rt"
	// SignatureEnvelopeNextDomain identifies the terminal nd= form.
	SignatureEnvelopeNextDomain SignatureEnvelopeForm = "next_domain"
)

// Known reports whether the envelope form belongs to this signing contract.
func (f SignatureEnvelopeForm) Known() bool {
	return f == SignatureEnvelopeOrdinary || f == SignatureEnvelopeNextDomain
}

// CompletedMessage is one fully proved immutable signing result.
type CompletedMessage struct {
	raw             []byte
	generatedFields [][]byte
	role            DerivedRole
	envelopeForm    SignatureEnvelopeForm
	newInstance     uint64
	sequence        uint64
	algorithms      []Algorithm
	bodyUnavailable bool
	unavailable     recipe.BodyUnavailableReason
	recipeOutcome   recipe.GenerationOutcome
	flags           []string
	multiplicity    int
	authorizations  []AuthorizationFact
	restriction     ForwardingRestriction
	reservation     *routeplan.Reservation
	initialized     bool
}

// AuthorizationFact records one bounded completed signing authorization stage.
type AuthorizationFact struct {
	purpose     AuthorizationPurpose
	status      AuthorizationStatus
	restriction ForwardingRestriction
	initialized bool
}

// newAuthorizationFact constructs one bounded completed authorization fact.
func newAuthorizationFact(purpose AuthorizationPurpose, status AuthorizationStatus, restriction ForwardingRestriction) AuthorizationFact {
	return AuthorizationFact{purpose: purpose, status: status, restriction: restriction, initialized: true}
}

// Valid reports whether the fact contains one coherent stage result.
func (f AuthorizationFact) Valid() bool {
	if !f.initialized || !f.purpose.Known() || !f.status.Known() || !f.restriction.Known() {
		return false
	}
	switch f.purpose {
	case AuthorizationReceiveNextDomain, AuthorizationSendNextDomain:
		return f.status == AuthorizationAuthorized && f.restriction == RestrictionOutOfBand
	case AuthorizationPolicy:
		return f.status == AuthorizationAuthorized &&
			(f.restriction == RestrictionUnrestricted || f.restriction == RestrictionLocalOnly)
	case AuthorizationFeedbackRelay:
		return f.restriction == RestrictionUnrestricted
	case AuthorizationDisclosure:
		return f.status == AuthorizationAuthorized && f.restriction == RestrictionUnrestricted
	default:
		return false
	}
}

// Purpose returns the completed authorization stage.
func (f AuthorizationFact) Purpose() AuthorizationPurpose {
	if !f.Valid() {
		return ""
	}
	return f.purpose
}

// Status returns the closed authorization result.
func (f AuthorizationFact) Status() AuthorizationStatus {
	if !f.Valid() {
		return ""
	}
	return f.status
}

// Restriction returns the authorization's resulting restriction.
func (f AuthorizationFact) Restriction() ForwardingRestriction {
	if !f.Valid() {
		return ""
	}
	return f.restriction
}

// String returns a constant secret-safe authorization-fact summary.
func (f AuthorizationFact) String() string { return "signing.AuthorizationFact{redacted}" }

// GoString returns the constant secret-safe authorization-fact Go representation.
func (f AuthorizationFact) GoString() string { return f.String() }

// Format routes every authorization-fact formatting form through the redacted summary.
func (f AuthorizationFact) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, f.String())
}

// authorizationFactsValid verifies unique ordered applicable signing stages.
func authorizationFactsValid(facts []AuthorizationFact) bool {
	order := map[AuthorizationPurpose]int{
		AuthorizationReceiveNextDomain: 1, AuthorizationSendNextDomain: 2,
		AuthorizationPolicy: 3, AuthorizationFeedbackRelay: 4, AuthorizationDisclosure: 5,
	}
	previous := 0
	for _, fact := range facts {
		position, ok := order[fact.purpose]
		if !ok || !fact.Valid() || position <= previous {
			return false
		}
		previous = position
	}
	return true
}

// Valid reports whether the completed output has one coherent closed restriction.
func (m CompletedMessage) Valid() bool {
	if !m.validFacts() {
		return false
	}
	restricted := m.restriction == RestrictionLocalOnly || m.restriction == RestrictionOutOfBand
	reservationCoherent := !restricted && m.reservation == nil ||
		restricted && m.reservation != nil && m.reservation.RestrictedReleaseRequired()
	return reservationCoherent
}

// validFacts validates every immutable non-route-state result invariant before success commit.
func (m CompletedMessage) validFacts() bool {
	if !m.validBasicFacts() || !validCompletedAlgorithms(m.algorithms) ||
		!m.validProgressionFacts() || !m.validRecipeFacts() {
		return false
	}
	return validGeneratedFlags(m.flags) &&
		authorizationFactsMatchFlags(m.authorizations, m.flags, m.role) &&
		authorizationRestriction(m.authorizations) == m.restriction
}

// validBasicFacts validates initialized, bounded, and closed result dimensions.
func (m CompletedMessage) validBasicFacts() bool {
	return m.initialized && len(m.raw) > 0 && m.role.Known() && m.sequence > 0 &&
		m.envelopeForm.Known() && len(m.algorithms) > 0 && len(m.algorithms) <= 2 &&
		m.recipeOutcome.Known() && m.flags != nil && m.multiplicity > 0 &&
		m.multiplicity <= DefaultLimits().MaxParentOutputCopiesAndTickets &&
		authorizationFactsValid(m.authorizations) && m.restriction.Known() &&
		(m.envelopeForm == SignatureEnvelopeNextDomain) == (m.restriction == RestrictionOutOfBand)
}

// validCompletedAlgorithms requires canonical one- or two-algorithm order.
func validCompletedAlgorithms(algorithms []Algorithm) bool {
	for index, algorithm := range algorithms {
		if !algorithm.Known() || index > 0 && algorithm != AlgorithmEd25519SHA256 ||
			index == 0 && len(algorithms) == 2 && algorithm != AlgorithmRSASHA256 {
			return false
		}
	}
	return true
}

// validProgressionFacts correlates the role with the emitted m= and i= values.
func (m CompletedMessage) validProgressionFacts() bool {
	roleCoherent := m.role == RoleOriginator && m.newInstance == 1 ||
		m.role == RoleHashUnchangedForwarder && m.newInstance == 0 ||
		m.role == RoleReviser && m.newInstance > 1
	sequenceCoherent := m.role == RoleOriginator && m.sequence == 1 ||
		m.role != RoleOriginator && m.sequence > 1
	return roleCoherent && sequenceCoherent
}

// validRecipeFacts correlates role, recipe outcome, and explicit unavailable body state.
func (m CompletedMessage) validRecipeFacts() bool {
	roleCoherent := (m.role == RoleReviser) == (m.recipeOutcome != recipe.GenerationOutcomeUnchanged)
	bodyCoherent := !m.bodyUnavailable || m.role == RoleReviser
	reasonCoherent := m.bodyUnavailable && m.unavailable.Known() ||
		!m.bodyUnavailable && m.unavailable == ""
	return roleCoherent && bodyCoherent && reasonCoherent
}

// EnvelopeForm returns the closed generated signature envelope form.
func (m CompletedMessage) EnvelopeForm() SignatureEnvelopeForm {
	if !m.Valid() {
		return ""
	}
	return m.envelopeForm
}

// Role returns the role derived by the exact Section 9.1 hash gate.
func (m CompletedMessage) Role() DerivedRole {
	if !m.Valid() {
		return ""
	}
	return m.role
}

// NewInstanceNumber returns the newly emitted m= number or zero when none was emitted.
func (m CompletedMessage) NewInstanceNumber() uint64 {
	if !m.Valid() {
		return 0
	}
	return m.newInstance
}

// Sequence returns the newly emitted i= number.
func (m CompletedMessage) Sequence() uint64 {
	if !m.Valid() {
		return 0
	}
	return m.sequence
}

// Algorithms returns detached generated algorithms in canonical order.
func (m CompletedMessage) Algorithms() []Algorithm {
	if !m.Valid() {
		return nil
	}
	return slices.Clone(m.algorithms)
}

// GeneratedFields returns detached complete fields emitted by the signing
// coordinator in their insertion order.
func (m CompletedMessage) GeneratedFields() [][]byte {
	if !m.Valid() {
		return nil
	}
	return cloneSlices(m.generatedFields)
}

// BodyUnavailable reports whether the generated revision recipe explicitly used b:null.
func (m CompletedMessage) BodyUnavailable() bool {
	return m.Valid() && m.bodyUnavailable
}

// BodyUnavailableReason returns the bounded reason only for an explicit b:null result.
func (m CompletedMessage) BodyUnavailableReason() recipe.BodyUnavailableReason {
	if !m.Valid() || !m.bodyUnavailable {
		return ""
	}
	return m.unavailable
}

// RecipeOutcome returns the closed recipe generation outcome used by the operation.
func (m CompletedMessage) RecipeOutcome() recipe.GenerationOutcome {
	if !m.Valid() {
		return ""
	}
	return m.recipeOutcome
}

// Flags returns detached generated flags in canonical order.
func (m CompletedMessage) Flags() []string {
	if !m.Valid() {
		return nil
	}
	return slices.Clone(m.flags)
}

// Multiplicity returns the sealed parent fanout copy count.
func (m CompletedMessage) Multiplicity() int {
	if !m.Valid() {
		return 0
	}
	return m.multiplicity
}

// Authorizations returns detached bounded completed authorization facts.
func (m CompletedMessage) Authorizations() []AuthorizationFact {
	if !m.Valid() {
		return nil
	}
	return slices.Clone(m.authorizations)
}

// Restriction returns the strongest closed output restriction.
func (m CompletedMessage) Restriction() ForwardingRestriction {
	if !m.Valid() {
		return ""
	}
	return m.restriction
}

// UnrestrictedBytes returns a detached complete message only for unrestricted output.
func (m CompletedMessage) UnrestrictedBytes() ([]byte, bool) {
	if !m.Valid() || m.restriction != RestrictionUnrestricted {
		return nil, false
	}
	return bytes.Clone(m.raw), true
}

// ReleaseLocalOnly atomically releases bytes to the exact sealed in-control route.
func (m CompletedMessage) ReleaseLocalOnly(
	ctx context.Context,
	ticket routeplan.CopyTicket,
	routeScope []byte,
) ([]byte, error) {
	proof, err := routeplan.NewLocalReleaseProof(ticket, routeScope)
	if err != nil {
		return nil, err
	}
	return m.releaseRestricted(ctx, proof, RestrictionLocalOnly)
}

// ReleaseOutOfBand atomically releases bytes to the exact sealed OOB receiver route.
func (m CompletedMessage) ReleaseOutOfBand(
	ctx context.Context,
	ticket routeplan.CopyTicket,
	reversePath []byte,
	forwardPaths [][]byte,
	receiverBinding, routeScope []byte,
) ([]byte, error) {
	proof, err := routeplan.NewOutOfBandReleaseProof(
		ticket, reversePath, forwardPaths, receiverBinding, routeScope,
	)
	if err != nil {
		return nil, err
	}
	return m.releaseRestricted(ctx, proof, RestrictionOutOfBand)
}

// releaseRestricted consumes the shared route-authority release phase before returning bytes.
func (m CompletedMessage) releaseRestricted(
	ctx context.Context,
	proof routeplan.RestrictedReleaseProof,
	restriction ForwardingRestriction,
) ([]byte, error) {
	if ctx == nil || !m.validFacts() || m.restriction != restriction ||
		m.reservation == nil || !m.reservation.RestrictedReleaseRequired() {
		return nil, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := m.reservation.ConsumeRestrictedRelease(ctx, proof); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return bytes.Clone(m.raw), nil
}

// String returns a constant secret-safe completed-message summary.
func (m CompletedMessage) String() string { return "signing.CompletedMessage{redacted}" }

// GoString returns the constant secret-safe completed-message Go representation.
func (m CompletedMessage) GoString() string { return m.String() }

// Format routes every completed-message formatting form through the redacted summary.
func (m CompletedMessage) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, m.String())
}

// CompleteMessage inserts and independently proves the generated fields.
func (c Coordinator) CompleteMessage(ctx context.Context, completed CompletedSigningField) (CompletedMessage, Recovery, error) {
	if ctx == nil || !c.initialized || completed.completion == nil {
		return CompletedMessage{}, Recovery{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	completed.completion.mu.Lock()
	defer completed.completion.mu.Unlock()
	if completed.completion.done || !completed.Valid() {
		return CompletedMessage{}, Recovery{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	if err := ctx.Err(); err != nil {
		completed.completion.done = true
		return CompletedMessage{}, c.recoverFailure(context.WithoutCancel(ctx), completed.reservation), err
	}
	fail := func(err error) (CompletedMessage, Recovery, error) {
		completed.completion.done = true
		return CompletedMessage{}, c.recoverFailure(context.WithoutCancel(ctx), completed.reservation), err
	}
	fields := make([][]byte, 0, 2)
	if completed.plan.HasNewInstance() {
		fields = append(fields, completed.plan.RenderedInstance())
	}
	fields = append(fields, completed.field.Bytes())
	inserted, err := rawmsg.InsertValidatedFields(rawmsg.InsertionRequest{
		Message: completed.message, TransportForm: completed.transport, Fields: fields,
		Options: c.insertionOptions(),
	})
	if err != nil {
		return fail(mapInsertionError(err))
	}
	if err := c.proveCompletedMessage(inserted, completed, fields); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	algorithms := make([]Algorithm, len(completed.profile.credentials))
	for index, credential := range completed.profile.credentials {
		algorithms[index] = credential.algorithm
	}
	bodyUnavailable := completed.plan.GenerationFacts().BodyOutcome() == recipe.BodyGenerationUnavailable
	releaseRequirement := routeplan.ReleaseUnrestricted
	switch completed.restriction {
	case RestrictionLocalOnly:
		releaseRequirement = routeplan.ReleaseLocalOnly
	case RestrictionOutOfBand:
		releaseRequirement = routeplan.ReleaseOutOfBand
	}
	restricted := releaseRequirement.Restricted()
	result := CompletedMessage{
		raw: inserted.RawBytes(), generatedFields: cloneSlices(fields),
		role: completed.plan.Role(), envelopeForm: completed.envelopeForm,
		newInstance: completed.plan.NewInstanceNumber(), sequence: completed.plan.NextSequence(),
		algorithms: algorithms, bodyUnavailable: bodyUnavailable,
		unavailable:   completed.plan.GenerationFacts().BodyUnavailableReason(),
		recipeOutcome: completed.plan.GenerationFacts().Outcome(),
		flags:         completed.metadata.Flags(), multiplicity: completed.multiplicity,
		authorizations: slices.Clone(completed.authorizations),
		restriction:    completed.restriction, initialized: true,
	}
	if restricted {
		result.reservation = completed.reservation
	}
	if !result.validFacts() {
		return fail(newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{}))
	}
	if completed.reservation == nil || !completed.reservation.ReplacementRequired() {
		return fail(newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{}))
	}
	completed.completion.done = true
	if err := completed.reservation.CommitSuccessfulSigning(releaseRequirement); err != nil {
		return fail(newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{}))
	}
	return result, Recovery{}, nil
}

// validGeneratedFlags requires the sole canonical known-flag order without duplicates.
func validGeneratedFlags(flags []string) bool {
	order := []string{
		signature.FlagDoNotModify, signature.FlagDoNotExplode, signature.FlagFeedback,
		signature.FlagFeedHere, signature.FlagExploded,
	}
	next := 0
	for _, flag := range flags {
		for next < len(order) && order[next] != flag {
			next++
		}
		if next == len(order) {
			return false
		}
		next++
	}
	return true
}

// authorizationRestriction derives the sole completed signing result restriction.
func authorizationRestriction(facts []AuthorizationFact) ForwardingRestriction {
	restriction := RestrictionUnrestricted
	for _, fact := range facts {
		if fact.purpose == AuthorizationSendNextDomain {
			restriction = RestrictionOutOfBand
			continue
		}
		if fact.purpose == AuthorizationPolicy {
			if restriction != RestrictionOutOfBand {
				restriction = fact.restriction
			}
		}
	}
	return restriction
}

// authorizationFactsMatchFlags correlates existing-message policy and feedback facts to output.
func authorizationFactsMatchFlags(facts []AuthorizationFact, flags []string, role DerivedRole) bool {
	hasPolicy := false
	feedbackStatus := AuthorizationStatus("")
	for _, fact := range facts {
		switch fact.purpose {
		case AuthorizationPolicy:
			if hasPolicy {
				return false
			}
			hasPolicy = true
		case AuthorizationFeedbackRelay:
			if !hasPolicy || feedbackStatus.Known() {
				return false
			}
			feedbackStatus = fact.status
		}
	}
	if (role != RoleOriginator) != hasPolicy {
		return false
	}
	hasFeedHere := slices.Contains(flags, signature.FlagFeedHere)
	return hasFeedHere == (feedbackStatus == AuthorizationAuthorized)
}

// insertionOptions derives final parser ceilings from the signing coordinator limits.
func (c Coordinator) insertionOptions() rawmsg.ParserOptions {
	options := rawmsg.DefaultParserOptions()
	options.MaxMessageBytes = c.limits.MaxMessageBytes
	options.MaxHeaderBytes = c.limits.MaxHeaderBytes
	options.MaxHeaderFields = c.limits.MaxHeaderFields
	return options
}

// proveCompletedMessage reparses and proves all local protocol, hash, custody, and crypto facts.
func (c Coordinator) proveCompletedMessage(message rawmsg.Message, completed CompletedSigningField, generated [][]byte) error {
	if message.Metadata().HeaderFields != completed.plan.SizeFacts().FinalHeaderFields() {
		return newError(ErrorCodeProtocolTampering, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	expectedProtocol := append(revisionProtocolFields(completed.message), cloneSlices(generated)...)
	if !equalProtocolFields(expectedProtocol, revisionProtocolFields(message)) {
		return newError(ErrorCodeProtocolTampering, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}

	instanceLimits := instance.DefaultLimits()
	instanceLimits.MaxInstances = c.limits.MaxInstances
	instanceLimits.MaxHashSets = c.limits.MaxHashSetsPerInstance
	instanceParser, err := instance.NewParser(instanceLimits)
	if err != nil {
		return newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	instances, err := instanceParser.Extract(message)
	if err != nil || len(instances) != int(completed.plan.SignatureInstance()) {
		return newError(ErrorCodeSequenceFailure, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}

	signatureLimits := signature.DefaultLimits()
	signatureLimits.MaxSignatures = c.limits.MaxSignatures
	signatureLimits.MaxSignatureSets = c.limits.MaxSignatureSetsPerField
	signatureParser, err := signature.NewParser(signatureLimits)
	if err != nil {
		return newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	signatures, err := signatureParser.Extract(message)
	if err != nil || len(signatures) != completed.plan.SizeFacts().SignatureFields() {
		return newError(ErrorCodeSequenceFailure, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	if err := signature.ValidateInstanceReferences(instances, signatures); err != nil {
		return newError(ErrorCodeReferenceFailure, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	custody, err := signature.ValidateCustody(signatures, signature.CustodyLimits{
		MaxSignatures:             c.limits.MaxSignatures,
		MaxRecipientsPerSignature: signature.DefaultCustodyLimits().MaxRecipientsPerSignature,
	})
	expectedCustody := signature.CustodyStatusOrdinaryComplete
	if completed.envelopeForm == SignatureEnvelopeNextDomain {
		expectedCustody = signature.CustodyStatusTerminalNextDomain
	}
	if err != nil || !custody.Evaluated() || custody.Status() != expectedCustody {
		return newError(ErrorCodeChainFailure, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	if err := c.proveCompletedHashes(message, completed.plan.CurrentHashes()); err != nil {
		return err
	}
	return c.proveCompletedSignature(message, signatures, completed)
}

// proveCompletedHashes requires final current hashes to equal the already sealed plan tuple.
func (c Coordinator) proveCompletedHashes(message rawmsg.Message, expected HashTuple) error {
	header, err := c.messageHash.HeaderHashFromMessage(message)
	if err != nil {
		return newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	body, err := c.messageHash.BodyHashFromMessage(message)
	if err != nil {
		return newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	headerDigest, headerOK := header.Digest()
	bodyDigest, bodyOK := body.Digest()
	expectedHeader := expected.Header()
	expectedBody := expected.Body()
	if !headerOK || !bodyOK ||
		!bytes.Equal(headerDigest.Bytes(), expectedHeader[:]) ||
		!bytes.Equal(bodyDigest.Bytes(), expectedBody[:]) {
		return newError(ErrorCodeHashStateAmbiguity, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	return nil
}

// proveCompletedSignature derives the final Section 9.6 input and verifies every generated set.
func (c Coordinator) proveCompletedSignature(message rawmsg.Message, signatures []signature.Signature, completed CompletedSigningField) error {
	ordered, err := signature.OrderBySequence(signatures)
	if err != nil || len(ordered) == 0 {
		return newError(ErrorCodeSequenceFailure, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	target := ordered[len(ordered)-1]
	if target.Sequence() != completed.plan.NextSequence() ||
		target.InstanceNumber() != completed.plan.SignatureInstance() ||
		!bytes.Equal(message.Headers().FieldsByName(signature.HeaderName)[len(signatures)-1].OriginalBytes(), completed.field.Bytes()) {
		return newError(ErrorCodeProtocolTampering, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	input, err := c.canonical.SignatureInputFromMessage(message, target.Sequence())
	if err != nil || !bytes.Equal(input.Bytes(), completed.input.Bytes()) {
		return newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	digest := sha256.Sum256(input.Bytes())
	sets := target.SignatureSets()
	if len(sets) != len(completed.profile.credentials) {
		return newError(ErrorCodeCryptographicSelfCheck, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	limits := c.cryptoLimits()
	for index, set := range sets {
		credential := completed.profile.credentials[index]
		if !set.KnownAlgorithm() || set.Selector() != credential.selector ||
			Algorithm(set.Algorithm()) != credential.algorithm ||
			cryptodkim2.VerifyDigest(credential.algorithm, credential.publicKey, digest[:], set.Signature().Decoded(), limits) != nil {
			return newError(ErrorCodeCryptographicSelfCheck, ErrorLocation{
				Phase: PhaseComplete, Algorithm: credential.algorithm,
			}, ErrorDetails{})
		}
	}
	return nil
}

// cloneSlices deep-clones one protected nested byte collection.
func cloneSlices(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for index := range values {
		cloned[index] = bytes.Clone(values[index])
	}
	return cloned
}

// mapInsertionError converts raw-message insertion failures into the signing vocabulary.
func mapInsertionError(err error) error {
	var parserErr *rawmsg.ParserError
	if !errors.As(err, &parserErr) || parserErr == nil {
		return newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	switch parserErr.Code() {
	case rawmsg.ErrorCodeLimitExceeded:
		return newError(ErrorCodeLimitExceeded, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	case rawmsg.ErrorCodeInvalidTransportForm:
		return newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	default:
		return newError(ErrorCodeMalformedInput, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
}
