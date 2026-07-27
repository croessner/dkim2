package dkim2

import (
	"context"
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/croessner/dkim2/internal/signing"
)

// SigningRole identifies the role derived by the exact Section 9.1 hash gate.
type SigningRole string

const (
	// SigningRoleOriginator creates the initial protocol fields.
	SigningRoleOriginator SigningRole = "originator"
	// SigningRoleHashUnchangedForwarder appends a signature without a new instance.
	SigningRoleHashUnchangedForwarder SigningRole = "hash_unchanged_forwarder"
	// SigningRoleReviser appends one inverse-recipe instance and signature.
	SigningRoleReviser SigningRole = "reviser"
)

// Known reports whether role belongs to the closed signing vocabulary.
func (r SigningRole) Known() bool {
	return r == SigningRoleOriginator || r == SigningRoleHashUnchangedForwarder || r == SigningRoleReviser
}

// SigningEnvelopeForm identifies the generated signature envelope shape.
type SigningEnvelopeForm string

const (
	// SigningEnvelopeOrdinary identifies the ordinary mf=/rt= form.
	SigningEnvelopeOrdinary SigningEnvelopeForm = "ordinary_mf_rt"
	// SigningEnvelopeNextDomain identifies the terminal nd= form.
	SigningEnvelopeNextDomain SigningEnvelopeForm = "next_domain"
)

// Known reports whether form belongs to the closed signing vocabulary.
func (f SigningEnvelopeForm) Known() bool {
	return f == SigningEnvelopeOrdinary || f == SigningEnvelopeNextDomain
}

// SigningRecipeOutcome identifies whether an inverse recipe was emitted.
type SigningRecipeOutcome string

const (
	// SigningRecipeUnchanged reports that no recipe was emitted.
	SigningRecipeUnchanged SigningRecipeOutcome = "unchanged"
	// SigningRecipeGenerated reports one emitted inverse recipe.
	SigningRecipeGenerated SigningRecipeOutcome = "recipe"
)

// Known reports whether outcome belongs to the closed recipe vocabulary.
func (o SigningRecipeOutcome) Known() bool {
	return o == SigningRecipeUnchanged || o == SigningRecipeGenerated
}

// SigningBodyUnavailableReason identifies why an explicit b:null was required.
type SigningBodyUnavailableReason string

const (
	// SigningBodyUnavailableUnrepresentable reports that the prior body cannot
	// be represented by the bounded inverse recipe.
	SigningBodyUnavailableUnrepresentable SigningBodyUnavailableReason = "unrepresentable"
	// SigningBodyUnavailableLiteralRequired reports a forbidden literal was required.
	SigningBodyUnavailableLiteralRequired SigningBodyUnavailableReason = "literal_required"
)

// Known reports whether reason belongs to the closed unavailable-body vocabulary.
func (r SigningBodyUnavailableReason) Known() bool {
	return r == SigningBodyUnavailableUnrepresentable ||
		r == SigningBodyUnavailableLiteralRequired
}

// SignedMessageFlag identifies one emitted known protocol flag.
type SignedMessageFlag string

const (
	// SignedMessageFlagDoNotModify reports emitted donotmodify.
	SignedMessageFlagDoNotModify SignedMessageFlag = "donotmodify"
	// SignedMessageFlagDoNotExplode reports emitted donotexplode.
	SignedMessageFlagDoNotExplode SignedMessageFlag = "donotexplode"
	// SignedMessageFlagFeedback reports emitted feedback.
	SignedMessageFlagFeedback SignedMessageFlag = "feedback"
	// SignedMessageFlagFeedHere reports emitted feedhere.
	SignedMessageFlagFeedHere SignedMessageFlag = "feedhere"
	// SignedMessageFlagExploded reports emitted exploded.
	SignedMessageFlagExploded SignedMessageFlag = "exploded"
)

// Known reports whether flag belongs to the emitted closed vocabulary.
func (f SignedMessageFlag) Known() bool {
	return f == SignedMessageFlagDoNotModify || f == SignedMessageFlagDoNotExplode ||
		f == SignedMessageFlagFeedback || f == SignedMessageFlagFeedHere ||
		f == SignedMessageFlagExploded
}

// SigningAuthorizationFact records one bounded completed authorization stage.
type SigningAuthorizationFact struct {
	purpose     SigningAuthorizationPurpose
	status      SigningAuthorizationStatus
	restriction SigningRestriction
	valid       bool
}

// Valid reports whether this is one coherent signing authorization fact.
func (f SigningAuthorizationFact) Valid() bool {
	if !f.valid || !f.purpose.Known() || !f.status.Known() || !f.restriction.Known() {
		return false
	}
	switch f.purpose {
	case SigningAuthorizationReceiveNextDomain, SigningAuthorizationSendNextDomain:
		return f.status == SigningAuthorizationAuthorized &&
			f.restriction == SigningRestrictionOutOfBandAcceptance
	case SigningAuthorizationPolicy:
		return f.status == SigningAuthorizationAuthorized &&
			(f.restriction == SigningRestrictionUnrestricted ||
				f.restriction == SigningRestrictionLocalOnly)
	case SigningAuthorizationFeedbackRelay:
		return f.restriction == SigningRestrictionUnrestricted
	case SigningAuthorizationRecipientDisclosure:
		return f.status == SigningAuthorizationAuthorized &&
			f.restriction == SigningRestrictionUnrestricted
	default:
		return false
	}
}

// Purpose returns the completed authorization purpose.
func (f SigningAuthorizationFact) Purpose() SigningAuthorizationPurpose { return f.purpose }

// Status returns the completed authorization status.
func (f SigningAuthorizationFact) Status() SigningAuthorizationStatus { return f.status }

// Restriction returns the completed authorization restriction.
func (f SigningAuthorizationFact) Restriction() SigningRestriction { return f.restriction }

// String returns a constant secret-safe authorization-fact summary.
func (f SigningAuthorizationFact) String() string {
	return "dkim2.SigningAuthorizationFact{redacted}"
}

// GoString returns the constant secret-safe authorization-fact Go representation.
func (f SigningAuthorizationFact) GoString() string { return f.String() }

// Format routes every authorization-fact formatting form through the redacted summary.
func (f SigningAuthorizationFact) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, f.String())
}

// SignedMessageFacts contains bounded immutable non-secret operation facts.
type SignedMessageFacts struct {
	role            SigningRole
	envelope        SigningEnvelopeForm
	newInstance     uint64
	sequence        uint64
	algorithms      []Algorithm
	bodyUnavailable bool
	unavailable     SigningBodyUnavailableReason
	recipe          SigningRecipeOutcome
	flags           []SignedMessageFlag
	multiplicity    int
	restriction     SigningRestriction
	authorizations  []SigningAuthorizationFact
	valid           bool
}

// Valid reports whether every closed fact correlation is coherent.
func (f SignedMessageFacts) Valid() bool {
	if !f.valid || !f.role.Known() || !f.envelope.Known() || !f.recipe.Known() ||
		!f.restriction.Known() || f.sequence == 0 || f.multiplicity <= 0 || f.multiplicity > 128 ||
		!validSigningAlgorithms(f.algorithms) || !validSignedFlags(f.flags) {
		return false
	}
	roleValid := f.role == SigningRoleOriginator && f.newInstance == 1 && f.sequence == 1 &&
		f.recipe == SigningRecipeUnchanged ||
		f.role == SigningRoleHashUnchangedForwarder && f.newInstance == 0 && f.sequence > 1 &&
			f.recipe == SigningRecipeUnchanged ||
		f.role == SigningRoleReviser && f.newInstance > 1 && f.sequence > 1 &&
			f.recipe == SigningRecipeGenerated
	envelopeValid := (f.envelope == SigningEnvelopeNextDomain) ==
		(f.restriction == SigningRestrictionOutOfBandAcceptance)
	return roleValid && envelopeValid &&
		(f.bodyUnavailable && f.recipe == SigningRecipeGenerated && f.unavailable.Known() ||
			!f.bodyUnavailable && f.unavailable == "") &&
		validSigningAuthorizationFacts(f)
}

// validSigningAlgorithms enforces the sole canonical one- or two-set order.
func validSigningAlgorithms(algorithms []Algorithm) bool {
	return len(algorithms) == 1 &&
		(algorithms[0] == AlgorithmRSASHA256 || algorithms[0] == AlgorithmEd25519SHA256) ||
		len(algorithms) == 2 && algorithms[0] == AlgorithmRSASHA256 &&
			algorithms[1] == AlgorithmEd25519SHA256
}

// validSignedFlags enforces the sole canonical known-flag order without duplicates.
func validSignedFlags(flags []SignedMessageFlag) bool {
	order := []SignedMessageFlag{
		SignedMessageFlagDoNotModify, SignedMessageFlagDoNotExplode,
		SignedMessageFlagFeedback, SignedMessageFlagFeedHere, SignedMessageFlagExploded,
	}
	next := 0
	for _, flag := range flags {
		for next < len(order) && order[next] != flag {
			next++
		}
		if next == len(order) || !flag.Known() {
			return false
		}
		next++
	}
	return true
}

// validSigningAuthorizationFacts enforces unique order and restriction correlation.
func validSigningAuthorizationFacts(facts SignedMessageFacts) bool {
	order := map[SigningAuthorizationPurpose]int{
		SigningAuthorizationReceiveNextDomain: 1, SigningAuthorizationSendNextDomain: 2,
		SigningAuthorizationPolicy: 3, SigningAuthorizationFeedbackRelay: 4,
		SigningAuthorizationRecipientDisclosure: 5,
	}
	previous := 0
	restriction := SigningRestrictionUnrestricted
	hasPolicy := false
	hasFeedback := false
	feedbackAuthorized := false
	for _, fact := range facts.authorizations {
		position, ok := order[fact.purpose]
		if !ok || !fact.Valid() || position <= previous {
			return false
		}
		previous = position
		if fact.purpose == SigningAuthorizationPolicy {
			hasPolicy = true
			if restriction != SigningRestrictionOutOfBandAcceptance {
				restriction = fact.restriction
			}
		}
		if fact.purpose == SigningAuthorizationSendNextDomain {
			restriction = SigningRestrictionOutOfBandAcceptance
		}
		if fact.purpose == SigningAuthorizationFeedbackRelay {
			hasFeedback = true
			feedbackAuthorized = fact.status == SigningAuthorizationAuthorized
		}
	}
	hasFeedHere := slices.Contains(facts.flags, SignedMessageFlagFeedHere)
	return (facts.role != SigningRoleOriginator) == hasPolicy &&
		(!hasFeedback || hasPolicy) &&
		(!hasFeedback && !hasFeedHere || hasFeedback && feedbackAuthorized == hasFeedHere) &&
		restriction == facts.restriction
}

// Role returns the exact hash-derived role.
func (f SignedMessageFacts) Role() SigningRole { return f.role }

// EnvelopeForm returns the generated signature envelope form.
func (f SignedMessageFacts) EnvelopeForm() SigningEnvelopeForm { return f.envelope }

// NewInstanceNumber returns the emitted m= number or zero.
func (f SignedMessageFacts) NewInstanceNumber() uint64 { return f.newInstance }

// Sequence returns the emitted i= number.
func (f SignedMessageFacts) Sequence() uint64 { return f.sequence }

// Algorithms returns detached generated algorithms in canonical order.
func (f SignedMessageFacts) Algorithms() []Algorithm { return slices.Clone(f.algorithms) }

// BodyUnavailable reports whether the revision emitted explicit b:null.
func (f SignedMessageFacts) BodyUnavailable() bool { return f.bodyUnavailable }

// BodyUnavailableReason returns the bounded reason only for explicit b:null.
func (f SignedMessageFacts) BodyUnavailableReason() SigningBodyUnavailableReason {
	return f.unavailable
}

// RecipeOutcome returns whether an inverse recipe was emitted.
func (f SignedMessageFacts) RecipeOutcome() SigningRecipeOutcome { return f.recipe }

// Flags returns detached generated known flags.
func (f SignedMessageFacts) Flags() []SignedMessageFlag { return slices.Clone(f.flags) }

// Multiplicity returns the sealed parent fanout copy count.
func (f SignedMessageFacts) Multiplicity() int { return f.multiplicity }

// Restriction returns the strongest closed output restriction.
func (f SignedMessageFacts) Restriction() SigningRestriction { return f.restriction }

// Authorizations returns detached completed authorization facts.
func (f SignedMessageFacts) Authorizations() []SigningAuthorizationFact {
	return slices.Clone(f.authorizations)
}

// String returns a constant secret-safe facts summary.
func (f SignedMessageFacts) String() string { return "dkim2.SignedMessageFacts{redacted}" }

// GoString returns the constant secret-safe facts Go representation.
func (f SignedMessageFacts) GoString() string { return f.String() }

// Format routes every facts formatting form through the redacted summary.
func (f SignedMessageFacts) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, f.String()) }

type unrestrictedResultMarker bool
type localOnlyResultMarker bool
type outOfBandResultMarker bool

// UnrestrictedSignedMessage is a fully proved message with a generic byte-copy accessor.
type UnrestrictedSignedMessage struct {
	message signing.CompletedMessage
	facts   SignedMessageFacts
	marker  unrestrictedResultMarker
}

// Valid reports whether this is a coherent unrestricted result.
func (m UnrestrictedSignedMessage) Valid() bool {
	return bool(m.marker) && m.message.Valid() && m.facts.Valid() &&
		m.facts.restriction == SigningRestrictionUnrestricted
}

// Bytes returns an independent copy of the complete RFC 5322 output.
func (m UnrestrictedSignedMessage) Bytes() []byte {
	if !m.Valid() {
		return nil
	}
	output, ok := m.message.UnrestrictedBytes()
	if !ok {
		return nil
	}
	return output
}

// GeneratedFields returns detached complete RFC 5322 fields in the exact
// insertion order proved by the signing coordinator.
func (m UnrestrictedSignedMessage) GeneratedFields() [][]byte {
	if !m.Valid() {
		return nil
	}
	return m.message.GeneratedFields()
}

// Facts returns bounded immutable operation facts.
func (m UnrestrictedSignedMessage) Facts() SignedMessageFacts { return m.facts }

// String returns a constant secret-safe message summary.
func (m UnrestrictedSignedMessage) String() string {
	return "dkim2.UnrestrictedSignedMessage{redacted}"
}

// GoString returns the constant secret-safe message Go representation.
func (m UnrestrictedSignedMessage) GoString() string { return m.String() }

// Format routes every message formatting form through the redacted summary.
func (m UnrestrictedSignedMessage) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, m.String())
}

// LocalOnlySignedMessage is a fully proved restricted result with no byte,
// marshal, text, or generic release accessor.
type LocalOnlySignedMessage struct {
	message signing.CompletedMessage
	facts   SignedMessageFacts
	marker  localOnlyResultMarker
}

// OutOfBandAcceptanceSignedMessage is a terminal nd= result with no generic byte escape.
type OutOfBandAcceptanceSignedMessage struct {
	message signing.CompletedMessage
	facts   SignedMessageFacts
	marker  outOfBandResultMarker
}

// Valid reports whether this is a coherent OOB-restricted terminal result.
func (m OutOfBandAcceptanceSignedMessage) Valid() bool {
	return bool(m.marker) && m.message.Valid() && m.facts.Valid() &&
		m.facts.restriction == SigningRestrictionOutOfBandAcceptance &&
		m.facts.envelope == SigningEnvelopeNextDomain
}

// Facts returns bounded immutable operation facts.
func (m OutOfBandAcceptanceSignedMessage) Facts() SignedMessageFacts { return m.facts }

// ReleaseForOutOfBandAcceptance atomically releases bytes only for the exact
// sealed receiver, envelope, route, and ticket lineage.
func (m OutOfBandAcceptanceSignedMessage) ReleaseForOutOfBandAcceptance(
	ctx context.Context,
	ticket RouteCopyTicket,
	reversePath []byte,
	forwardPaths [][]byte,
	receiverBinding, routeScope []byte,
) ([]byte, error) {
	if !m.Valid() || !ticket.Valid() {
		return nil, newSigningError(SigningErrorInvalidRequest)
	}
	output, err := m.message.ReleaseOutOfBand(
		ctx, ticket.value, reversePath, forwardPaths, receiverBinding, routeScope,
	)
	if err != nil {
		return nil, mapOperationError(err)
	}
	return output, nil
}

// String returns a constant secret-safe message summary.
func (m OutOfBandAcceptanceSignedMessage) String() string {
	return "dkim2.OutOfBandAcceptanceSignedMessage{redacted}"
}

// GoString returns the constant secret-safe message Go representation.
func (m OutOfBandAcceptanceSignedMessage) GoString() string { return m.String() }

// Format routes every message formatting form through the redacted summary.
func (m OutOfBandAcceptanceSignedMessage) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, m.String())
}

// Valid reports whether this is a coherent local-only result.
func (m LocalOnlySignedMessage) Valid() bool {
	return bool(m.marker) && m.message.Valid() && m.facts.Valid() &&
		m.facts.restriction == SigningRestrictionLocalOnly
}

// Facts returns bounded immutable operation facts.
func (m LocalOnlySignedMessage) Facts() SignedMessageFacts { return m.facts }

// ReleaseToInControl atomically releases bytes only to the exact sealed local route.
func (m LocalOnlySignedMessage) ReleaseToInControl(
	ctx context.Context,
	ticket RouteCopyTicket,
	routeScope []byte,
) ([]byte, error) {
	if !m.Valid() || !ticket.Valid() {
		return nil, newSigningError(SigningErrorInvalidRequest)
	}
	output, err := m.message.ReleaseLocalOnly(ctx, ticket.value, routeScope)
	if err != nil {
		return nil, mapOperationError(err)
	}
	return output, nil
}

// String returns a constant secret-safe message summary.
func (m LocalOnlySignedMessage) String() string { return "dkim2.LocalOnlySignedMessage{redacted}" }

// GoString returns the constant secret-safe message Go representation.
func (m LocalOnlySignedMessage) GoString() string { return m.String() }

// Format routes every message formatting form through the redacted summary.
func (m LocalOnlySignedMessage) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, m.String())
}

// SigningResult is a closed signing result sum.
type SigningResult struct {
	unrestricted UnrestrictedSignedMessage
	localOnly    LocalOnlySignedMessage
	outOfBand    OutOfBandAcceptanceSignedMessage
	kind         SigningRestriction
}

// Valid reports whether exactly one coherent result variant is present.
func (r SigningResult) Valid() bool {
	return r.kind == SigningRestrictionUnrestricted && r.unrestricted.Valid() &&
		!r.localOnly.Valid() && !r.outOfBand.Valid() ||
		r.kind == SigningRestrictionLocalOnly && r.localOnly.Valid() &&
			!r.unrestricted.Valid() && !r.outOfBand.Valid() ||
		r.kind == SigningRestrictionOutOfBandAcceptance && r.outOfBand.Valid() &&
			!r.unrestricted.Valid() && !r.localOnly.Valid()
}

// OutOfBandAcceptance returns the OOB-restricted no-byte variant when present.
func (r SigningResult) OutOfBandAcceptance() (OutOfBandAcceptanceSignedMessage, bool) {
	if !r.Valid() || r.kind != SigningRestrictionOutOfBandAcceptance {
		return OutOfBandAcceptanceSignedMessage{}, false
	}
	return r.outOfBand, true
}

// Unrestricted returns the sole byte-releasable variant when present.
func (r SigningResult) Unrestricted() (UnrestrictedSignedMessage, bool) {
	if !r.Valid() || r.kind != SigningRestrictionUnrestricted {
		return UnrestrictedSignedMessage{}, false
	}
	return r.unrestricted, true
}

// LocalOnly returns the restricted no-byte variant when present.
func (r SigningResult) LocalOnly() (LocalOnlySignedMessage, bool) {
	if !r.Valid() || r.kind != SigningRestrictionLocalOnly {
		return LocalOnlySignedMessage{}, false
	}
	return r.localOnly, true
}

// String returns a constant secret-safe result summary.
func (r SigningResult) String() string { return "dkim2.SigningResult{redacted}" }

// GoString returns the constant secret-safe result Go representation.
func (r SigningResult) GoString() string { return r.String() }

// Format routes every result formatting form through the redacted summary.
func (r SigningResult) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// newSigningResult performs a total projection from an internally valid result.
func newSigningResult(message signing.CompletedMessage) SigningResult {
	internalAlgorithms := message.Algorithms()
	algorithms := make([]Algorithm, len(internalAlgorithms))
	for index, algorithm := range internalAlgorithms {
		algorithms[index] = Algorithm(algorithm)
	}
	internalFlags := message.Flags()
	flags := make([]SignedMessageFlag, len(internalFlags))
	for index, flag := range internalFlags {
		flags[index] = SignedMessageFlag(flag)
	}
	internalAuthorizations := message.Authorizations()
	authorizations := make([]SigningAuthorizationFact, len(internalAuthorizations))
	for index, fact := range internalAuthorizations {
		authorizations[index] = SigningAuthorizationFact{
			purpose:     SigningAuthorizationPurpose(fact.Purpose()),
			status:      SigningAuthorizationStatus(fact.Status()),
			restriction: SigningRestriction(fact.Restriction()), valid: true,
		}
	}
	facts := SignedMessageFacts{
		role: SigningRole(message.Role()), envelope: SigningEnvelopeForm(message.EnvelopeForm()),
		newInstance: message.NewInstanceNumber(), sequence: message.Sequence(),
		algorithms: algorithms, bodyUnavailable: message.BodyUnavailable(),
		unavailable: SigningBodyUnavailableReason(message.BodyUnavailableReason()),
		recipe:      SigningRecipeOutcome(message.RecipeOutcome()), flags: flags,
		multiplicity:   message.Multiplicity(),
		restriction:    SigningRestriction(message.Restriction()),
		authorizations: authorizations, valid: true,
	}
	if facts.restriction == SigningRestrictionLocalOnly {
		value := LocalOnlySignedMessage{message: message, facts: facts, marker: true}
		return SigningResult{localOnly: value, kind: facts.restriction}
	}
	if facts.restriction == SigningRestrictionOutOfBandAcceptance {
		value := OutOfBandAcceptanceSignedMessage{message: message, facts: facts, marker: true}
		return SigningResult{outOfBand: value, kind: facts.restriction}
	}
	value := UnrestrictedSignedMessage{message: message, facts: facts, marker: true}
	return SigningResult{unrestricted: value, kind: facts.restriction}
}

// SigningRecovery owns one shared consumptive same-lineage route recovery action.
type SigningRecovery struct{ state *signingRecoveryState }

type signingRecoveryState struct {
	mu    sync.Mutex
	value signing.Recovery
}

// newSigningRecovery shares one consumptive internal recovery across copied public wrappers.
func newSigningRecovery(value signing.Recovery) SigningRecovery {
	if !value.Valid() {
		return SigningRecovery{}
	}
	return SigningRecovery{state: &signingRecoveryState{value: value}}
}

// Valid reports whether recovery has one actionable closed state.
func (r SigningRecovery) Valid() bool {
	if r.state == nil {
		return false
	}
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	return r.state.value.Valid()
}

// ReplacementReady reports whether Recover will yield an already issued ticket.
func (r SigningRecovery) ReplacementReady() bool {
	if r.state == nil {
		return false
	}
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	return r.state.value.ReplacementReady()
}

// RecoveryPending reports whether authority cleanup must be retried.
func (r SigningRecovery) RecoveryPending() bool {
	if r.state == nil {
		return false
	}
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	return r.state.value.RecoveryPending()
}

// Recover consumes this recovery action and returns a same-lineage replacement when ready.
func (r SigningRecovery) Recover(ctx context.Context) (RouteCopyTicket, error) {
	if r.state == nil {
		return RouteCopyTicket{}, newSigningError(SigningErrorInvalidRequest)
	}
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	if !r.state.value.Valid() {
		return RouteCopyTicket{}, newSigningError(SigningErrorInvalidRequest)
	}
	ticket, err := r.state.value.Recover(ctx)
	if err != nil {
		return RouteCopyTicket{}, mapOperationError(err)
	}
	return RouteCopyTicket{value: ticket}, nil
}

// String returns a constant secret-safe recovery summary.
func (r SigningRecovery) String() string { return "dkim2.SigningRecovery{redacted}" }

// GoString returns the constant secret-safe recovery Go representation.
func (r SigningRecovery) GoString() string { return r.String() }

// Format routes every recovery formatting form through the redacted summary.
func (r SigningRecovery) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }
