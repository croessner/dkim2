package signing

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"

	"github.com/croessner/dkim2/internal/keyresolver"
	"github.com/croessner/dkim2/internal/niliface"
	"github.com/croessner/dkim2/internal/provider"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/routeplan"
	"github.com/croessner/dkim2/internal/signature"
	"github.com/croessner/dkim2/internal/verify"
)

const authorizationTranscriptDomain = "dkim2/signing-authorization/v1"

// AuthorizationPurpose identifies one closed trusted authorization decision.
type AuthorizationPurpose string

const (
	// AuthorizationPolicy evaluates inherited modification and explosion restrictions.
	AuthorizationPolicy AuthorizationPurpose = "policy"
	// AuthorizationDisclosure permits one exact ordered multi-recipient rt set.
	AuthorizationDisclosure AuthorizationPurpose = "recipient_disclosure"
	// AuthorizationFeedbackRelay permits causally valid feedhere for one route.
	AuthorizationFeedbackRelay AuthorizationPurpose = "feedback_relay"
	// AuthorizationReceiveNextDomain permits receipt from an inherited terminal nd=.
	AuthorizationReceiveNextDomain AuthorizationPurpose = "receive_terminal_next_domain"
	// AuthorizationSendNextDomain permits one exact terminal nd= route.
	AuthorizationSendNextDomain AuthorizationPurpose = "send_terminal_next_domain"
)

// Known reports whether purpose belongs to the closed authorization vocabulary.
func (p AuthorizationPurpose) Known() bool {
	switch p {
	case AuthorizationPolicy, AuthorizationDisclosure, AuthorizationFeedbackRelay,
		AuthorizationReceiveNextDomain, AuthorizationSendNextDomain:
		return true
	default:
		return false
	}
}

// AuthorizationStatus identifies one closed authorizer decision.
type AuthorizationStatus string

const (
	// AuthorizationAuthorized reports an explicit exact-query authorization.
	AuthorizationAuthorized AuthorizationStatus = "authorized"
	// AuthorizationDenied reports an explicit exact-query denial.
	AuthorizationDenied AuthorizationStatus = "denied"
)

// Known reports whether status belongs to the closed authorizer vocabulary.
func (s AuthorizationStatus) Known() bool {
	return s == AuthorizationAuthorized || s == AuthorizationDenied
}

// ModificationFacts records invariant-owned bounded policy facts without message content.
type ModificationFacts struct {
	bodyChanged, existingHeadersChanged bool
	initialized                         bool
	capabilitySeal, parentID            [sha256.Size]byte
	ticketID, ticketBinding             [sha256.Size]byte
}

// BodyChanged reports whether the verified prior body differs from the proposed body.
func (f ModificationFacts) BodyChanged() bool { return f.initialized && f.bodyChanged }

// ExistingHeadersChanged reports whether any prior header was removed, changed, or reordered.
func (f ModificationFacts) ExistingHeadersChanged() bool {
	return f.initialized && f.existingHeadersChanged
}

// String returns a constant secret-safe modification summary.
func (f ModificationFacts) String() string { return "signing.ModificationFacts{redacted}" }

// GoString returns a constant secret-safe modification Go representation.
func (f ModificationFacts) GoString() string { return f.String() }

// Format routes every modification-facts formatting form through the redacted summary.
func (f ModificationFacts) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, f.String()) }

// validFor authenticates the exact capability and proposed-copy scope of comparison evidence.
func (f ModificationFacts) validFor(capability VerifiedRevisionInput, ticket routeplan.CopyTicket) bool {
	if !f.initialized || !capability.Valid() || !ticket.Valid() {
		return false
	}
	parentID := ticket.ParentIdentity()
	ticketID := ticket.TicketIdentity()
	ticketBinding := ticket.BindingIdentity()
	return subtle.ConstantTimeCompare(f.capabilitySeal[:], capability.seal[:]) == 1 &&
		subtle.ConstantTimeCompare(f.parentID[:], parentID[:]) == 1 &&
		subtle.ConstantTimeCompare(f.ticketID[:], ticketID[:]) == 1 &&
		subtle.ConstantTimeCompare(f.ticketBinding[:], ticketBinding[:]) == 1
}

// ForwardingRestriction identifies the strongest closed output restriction.
type ForwardingRestriction string

const (
	// RestrictionUnrestricted permits the later ordinary release path.
	RestrictionUnrestricted ForwardingRestriction = "unrestricted"
	// RestrictionLocalOnly permits only the later exact in-control route release.
	RestrictionLocalOnly ForwardingRestriction = "local_only"
	// RestrictionOutOfBand requires the later exact OOB acceptance release path.
	RestrictionOutOfBand ForwardingRestriction = "requires_out_of_band_acceptance"
)

// Known reports whether restriction belongs to the closed output vocabulary.
func (r ForwardingRestriction) Known() bool {
	return r == RestrictionUnrestricted || r == RestrictionLocalOnly || r == RestrictionOutOfBand
}

// AuthorizationQuery is an immutable exact operation authorization request.
type AuthorizationQuery struct {
	purpose        AuthorizationPurpose
	binding        [sha256.Size]byte
	recipients     [][]byte
	restriction    ForwardingRestriction
	policyFacts    ModificationFacts
	hasPolicyFacts bool
	oobFacts       OutOfBandFacts
}

// Purpose returns the exact closed authorization purpose.
func (q AuthorizationQuery) Purpose() AuthorizationPurpose { return q.purpose }

// Binding returns the opaque exact operation binding.
func (q AuthorizationQuery) Binding() [sha256.Size]byte { return q.binding }

// Recipients returns exact cloned paths only across the trusted authorizer boundary.
func (q AuthorizationQuery) Recipients() [][]byte {
	output := make([][]byte, len(q.recipients))
	for index := range q.recipients {
		output[index] = bytes.Clone(q.recipients[index])
	}
	return output
}

// PolicyFacts returns bounded modification facts and the requested restriction.
func (q AuthorizationQuery) PolicyFacts() (ModificationFacts, ForwardingRestriction, bool) {
	return q.policyFacts, q.restriction, q.purpose == AuthorizationPolicy && q.Valid()
}

// OutOfBandFacts returns detached decision-capable terminal-route facts.
func (q AuthorizationQuery) OutOfBandFacts() (OutOfBandFacts, bool) {
	if (q.purpose != AuthorizationReceiveNextDomain && q.purpose != AuthorizationSendNextDomain) || !q.Valid() {
		return OutOfBandFacts{}, false
	}
	return q.oobFacts.clone(), true
}

// Valid reports whether the query has one exact purpose and binding.
func (q AuthorizationQuery) Valid() bool {
	policyState := q.purpose == AuthorizationPolicy
	if q.hasPolicyFacts != policyState || q.policyFacts.initialized != policyState {
		return false
	}
	return q.purpose.Known() && q.binding != [sha256.Size]byte{} &&
		(q.purpose == AuthorizationDisclosure || len(q.recipients) == 0) &&
		(q.purpose == AuthorizationPolicy && q.restriction.Known() ||
			(q.purpose == AuthorizationReceiveNextDomain || q.purpose == AuthorizationSendNextDomain) && q.restriction == RestrictionOutOfBand && q.oobFacts.validForPurpose(q.purpose) ||
			q.purpose != AuthorizationPolicy && q.purpose != AuthorizationReceiveNextDomain && q.purpose != AuthorizationSendNextDomain && q.restriction == "")
}

// String returns a constant secret-safe query summary.
func (q AuthorizationQuery) String() string { return "signing.AuthorizationQuery{redacted}" }

// GoString returns a constant secret-safe query Go representation.
func (q AuthorizationQuery) GoString() string { return q.String() }

// Format routes every query formatting form through the redacted summary.
func (q AuthorizationQuery) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, q.String()) }

// NewPolicyAuthorizationQuery binds inherited policy to one exact route ticket.
func NewPolicyAuthorizationQuery(capability VerifiedRevisionInput, ticket routeplan.CopyTicket, facts ModificationFacts) (AuthorizationQuery, error) {
	if !capability.Valid() || !ticket.Valid() || ticket.Purpose() == routeplan.PurposeOrigin ||
		!ticket.MatchesRevisionBinding(capability.seal[:]) || !facts.validFor(capability, ticket) {
		return AuthorizationQuery{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	restriction := RestrictionUnrestricted
	for _, inherited := range capability.proof.Facts().Flags() {
		if inherited.DoNotModify() && (facts.bodyChanged || facts.existingHeadersChanged) ||
			inherited.DoNotExplode() && (ticket.TotalMultiplicity() > 1 || len(ticket.DisclosureRecipients()) > 1) {
			restriction = RestrictionLocalOnly
		}
	}
	query := newAuthorizationQuery(AuthorizationPolicy, ticket, capability.seal[:],
		boolBytes(facts.bodyChanged), boolBytes(facts.existingHeadersChanged), []byte(restriction))
	query.restriction = restriction
	query.policyFacts = facts
	query.hasPolicyFacts = true
	return query, nil
}

// NewDisclosureAuthorizationQuery binds one exact ordered multi-recipient set.
func NewDisclosureAuthorizationQuery(ticket routeplan.CopyTicket) (AuthorizationQuery, error) {
	if !ticket.Valid() || len(ticket.DisclosureRecipients()) < 2 ||
		ticket.DisclosureClass() != routeplan.DisclosureAuthorizedGroup {
		return AuthorizationQuery{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	query := newAuthorizationQuery(AuthorizationDisclosure, ticket)
	query.recipients = ticket.DisclosureRecipients()
	return query, nil
}

// NewFeedbackAuthorizationQuery binds causal feedback relay to one exact route.
func NewFeedbackAuthorizationQuery(capability VerifiedRevisionInput, ticket routeplan.CopyTicket) (AuthorizationQuery, error) {
	if !capability.Valid() || !ticket.Valid() || ticket.Purpose() == routeplan.PurposeOrigin ||
		!ticket.MatchesRevisionBinding(capability.seal[:]) || !capabilityHasFeedback(capability) {
		return AuthorizationQuery{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	return newAuthorizationQuery(AuthorizationFeedbackRelay, ticket, capability.seal[:]), nil
}

// PredecessorKind identifies the authenticated predecessor envelope form.
type PredecessorKind string

const (
	// PredecessorOrdinary identifies an ordinary predecessor recipient domain.
	PredecessorOrdinary PredecessorKind = "ordinary"
	// PredecessorNextDomain identifies an inherited terminal nd= domain.
	PredecessorNextDomain PredecessorKind = "next_domain"
)

// Known reports whether kind belongs to the closed predecessor vocabulary.
func (k PredecessorKind) Known() bool { return k == PredecessorOrdinary || k == PredecessorNextDomain }

// OutOfBandFacts stores exact terminal-route authorization evidence.
type OutOfBandFacts struct {
	profileDomain, proposedNextDomain, predecessorDomain string
	predecessorKind                                      PredecessorKind
	reversePath                                          []byte
	forwardPaths                                         [][]byte
	routeScope                                           [sha256.Size]byte
	route, receiver                                      []byte
}

// ProfileDomain returns the canonical proposed signer domain.
func (f OutOfBandFacts) ProfileDomain() string { return f.profileDomain }

// ProposedNextDomain returns the future nd= or empty for receive authorization.
func (f OutOfBandFacts) ProposedNextDomain() string { return f.proposedNextDomain }

// PredecessorDomain returns the authenticated predecessor domain.
func (f OutOfBandFacts) PredecessorDomain() string { return f.predecessorDomain }

// PredecessorKind returns the authenticated predecessor envelope form.
func (f OutOfBandFacts) PredecessorKind() PredecessorKind { return f.predecessorKind }

// ReversePath returns the detached exact intended reverse-path.
func (f OutOfBandFacts) ReversePath() []byte { return bytes.Clone(f.reversePath) }

// ForwardPaths returns detached exact intended forward-paths.
func (f OutOfBandFacts) ForwardPaths() [][]byte { return f.clone().forwardPaths }

// RouteScope returns the opaque exact route binding.
func (f OutOfBandFacts) RouteScope() [sha256.Size]byte { return f.routeScope }

// Route returns the detached exact trusted route-scope handle.
func (f OutOfBandFacts) Route() []byte { return bytes.Clone(f.route) }

// ReceiverBinding returns the detached exact receiver-transaction binding.
func (f OutOfBandFacts) ReceiverBinding() []byte { return bytes.Clone(f.receiver) }

// String returns a constant secret-safe OOB facts summary.
func (f OutOfBandFacts) String() string { return "signing.OutOfBandFacts{redacted}" }

// GoString returns a constant secret-safe OOB facts Go representation.
func (f OutOfBandFacts) GoString() string { return f.String() }

// Format routes every OOB facts formatting form through the redacted summary.
func (f OutOfBandFacts) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, f.String()) }

// Valid reports whether facts are complete and locally coherent.
func (f OutOfBandFacts) Valid() bool {
	return f.validForPurpose(AuthorizationReceiveNextDomain) || f.validForPurpose(AuthorizationSendNextDomain)
}

// validForPurpose enforces absent versus required receive/send evidence.
func (f OutOfBandFacts) validForPurpose(purpose AuthorizationPurpose) bool {
	base := canonicalAuthorizationDomain(f.profileDomain) && canonicalAuthorizationDomain(f.predecessorDomain) &&
		f.predecessorKind.Known() && f.profileDomain == f.predecessorDomain &&
		len(f.reversePath) > 0 && len(f.forwardPaths) > 0 && f.routeScope != [sha256.Size]byte{} &&
		len(f.route) > 0 && len(f.receiver) > 0
	switch purpose {
	case AuthorizationReceiveNextDomain:
		return base && f.predecessorKind == PredecessorNextDomain && f.proposedNextDomain == ""
	case AuthorizationSendNextDomain:
		return base && canonicalAuthorizationDomain(f.proposedNextDomain)
	default:
		return false
	}
}

// clone returns detached trusted-boundary facts.
func (f OutOfBandFacts) clone() OutOfBandFacts {
	f.reversePath = bytes.Clone(f.reversePath)
	f.route = bytes.Clone(f.route)
	f.receiver = bytes.Clone(f.receiver)
	output := make([][]byte, len(f.forwardPaths))
	for index := range f.forwardPaths {
		output[index] = bytes.Clone(f.forwardPaths[index])
	}
	f.forwardPaths = output
	return f
}

// NewReceiveNextDomainAuthorizationQuery binds trust in one inherited terminal nd=.
func NewReceiveNextDomainAuthorizationQuery(capability VerifiedRevisionInput, ticket routeplan.CopyTicket, profileDomain string) (AuthorizationQuery, error) {
	if !capability.Valid() || !ticket.Valid() || len(ticket.InboundReceiverBinding()) == 0 ||
		!canonicalAuthorizationDomain(profileDomain) {
		return AuthorizationQuery{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if ticket.Purpose() != routeplan.PurposeRevision && ticket.Purpose() != routeplan.PurposeNextDomain {
		return AuthorizationQuery{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if !ticket.MatchesRevisionBinding(capability.seal[:]) {
		return AuthorizationQuery{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	kind, predecessor, ok := revisionPredecessor(capability, profileDomain)
	if !ok || kind != PredecessorNextDomain || profileDomain != predecessor {
		return AuthorizationQuery{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	facts := OutOfBandFacts{
		profileDomain:     profileDomain,
		predecessorDomain: predecessor, predecessorKind: kind,
		reversePath:  bytes.Clone(capability.reversePath),
		forwardPaths: cloneSlices(capability.forwardPaths),
		routeScope:   ticket.BindingIdentity(), route: ticket.RouteScope(),
		receiver: ticket.InboundReceiverBinding(),
	}
	return newOutOfBandQuery(AuthorizationReceiveNextDomain, capability, ticket, PublishedNextDomainCapability{}, facts)
}

// NewSendNextDomainAuthorizationQuery binds one proposed nd= and exact publication evidence.
func NewSendNextDomainAuthorizationQuery(capability VerifiedRevisionInput, ticket routeplan.CopyTicket, published PublishedNextDomainCapability, profileDomain, proposedNextDomain string) (AuthorizationQuery, error) {
	if !capability.Valid() || !ticket.Valid() || !published.Valid() ||
		ticket.Purpose() != routeplan.PurposeNextDomain ||
		ticket.RouteClass() != routeplan.RouteOutOfBand ||
		!ticket.MatchesRevisionBinding(capability.seal[:]) ||
		!canonicalAuthorizationDomain(profileDomain) || !canonicalAuthorizationDomain(proposedNextDomain) ||
		published.domain != proposedNextDomain {
		return AuthorizationQuery{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	kind, predecessor, ok := revisionPredecessor(capability, profileDomain)
	if !ok || profileDomain != predecessor {
		return AuthorizationQuery{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	facts := OutOfBandFacts{
		profileDomain: profileDomain, proposedNextDomain: proposedNextDomain,
		predecessorDomain: predecessor, predecessorKind: kind,
		reversePath: ticket.ReversePath(), forwardPaths: ticket.DisclosureRecipients(),
		routeScope: ticket.BindingIdentity(), route: ticket.RouteScope(),
		receiver: ticket.OutboundReceiverBinding(),
	}
	return newOutOfBandQuery(AuthorizationSendNextDomain, capability, ticket, published, facts)
}

// NewBoundRouteEntry derives one ordinary revision route from exact sealed capability evidence.
func NewBoundRouteEntry(capability VerifiedRevisionInput, source routeplan.ImmutableSource, purpose routeplan.Purpose, reversePath []byte, forwardPaths [][]byte, disclosure routeplan.DisclosureClass, routeBinding []byte) (routeplan.Entry, error) {
	if !capability.Valid() ||
		capability.proof.State() == verify.RevisionProofTerminalNextDomainAuthorizationRequired ||
		purpose != routeplan.PurposeRevision {
		return routeplan.Entry{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	entry, err := routeplan.NewEntry(source, purpose, reversePath, forwardPaths, disclosure, routeBinding, capability.seal[:])
	if err != nil {
		return routeplan.Entry{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	return entry, nil
}

// NewClassifiedBoundRouteEntry derives one exact classified route binding from
// the sealed revision capability without exposing its seal.
func NewClassifiedBoundRouteEntry(
	capability VerifiedRevisionInput,
	source routeplan.ImmutableSource,
	purpose routeplan.Purpose,
	reversePath []byte,
	forwardPaths [][]byte,
	disclosure routeplan.DisclosureClass,
	routeClass routeplan.RouteClass,
	routeBinding, receiverBinding []byte,
) (routeplan.Entry, error) {
	inboundReceiverBinding, outboundReceiverBinding := receiverBinding, []byte(nil)
	if purpose == routeplan.PurposeNextDomain {
		inboundReceiverBinding, outboundReceiverBinding = nil, receiverBinding
	}
	return NewDualReceiverClassifiedBoundRouteEntry(
		capability, source, purpose, reversePath, forwardPaths, disclosure,
		routeClass, routeBinding, inboundReceiverBinding, outboundReceiverBinding,
	)
}

// NewDualReceiverClassifiedBoundRouteEntry derives one exact classified route
// binding with independently sealed inbound and outbound OOB trust edges.
func NewDualReceiverClassifiedBoundRouteEntry(
	capability VerifiedRevisionInput,
	source routeplan.ImmutableSource,
	purpose routeplan.Purpose,
	reversePath []byte,
	forwardPaths [][]byte,
	disclosure routeplan.DisclosureClass,
	routeClass routeplan.RouteClass,
	routeBinding, inboundReceiverBinding, outboundReceiverBinding []byte,
) (routeplan.Entry, error) {
	if !capability.Valid() || purpose != routeplan.PurposeRevision && purpose != routeplan.PurposeNextDomain ||
		!routeClass.Known() {
		return routeplan.Entry{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	terminal := capability.proof.State() == verify.RevisionProofTerminalNextDomainAuthorizationRequired
	if purpose == routeplan.PurposeRevision {
		if len(outboundReceiverBinding) != 0 ||
			terminal != (len(inboundReceiverBinding) > 0) {
			return routeplan.Entry{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
		}
	} else if routeClass != routeplan.RouteOutOfBand ||
		len(outboundReceiverBinding) == 0 ||
		terminal != (len(inboundReceiverBinding) > 0) {
		return routeplan.Entry{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	entry, err := routeplan.NewDualReceiverClassifiedEntry(
		source, purpose, reversePath, forwardPaths, disclosure, routeClass,
		routeBinding, inboundReceiverBinding, outboundReceiverBinding, capability.seal[:],
	)
	if err != nil {
		return routeplan.Entry{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	return entry, nil
}

// newOutOfBandQuery builds one purpose-specific exact OOB transcript.
func newOutOfBandQuery(purpose AuthorizationPurpose, capability VerifiedRevisionInput, ticket routeplan.CopyTicket, published PublishedNextDomainCapability, facts OutOfBandFacts) (AuthorizationQuery, error) {
	if !facts.validForPurpose(purpose) {
		return AuthorizationQuery{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	pathHash := sha256.New()
	for _, path := range facts.forwardPaths {
		writeAuthorizationPart(pathHash, path)
	}
	publicationSeal := []byte(nil)
	if purpose == AuthorizationSendNextDomain {
		publicationSeal = published.seal[:]
	}
	query := newAuthorizationQuery(purpose, ticket, capability.seal[:], publicationSeal,
		[]byte(facts.profileDomain), []byte(facts.proposedNextDomain), []byte(facts.predecessorKind),
		[]byte(facts.predecessorDomain), facts.reversePath, pathHash.Sum(nil), facts.routeScope[:],
		facts.route, facts.receiver,
		[]byte(RestrictionOutOfBand))
	query.restriction = RestrictionOutOfBand
	query.oobFacts = facts
	return query, nil
}

// newAuthorizationQuery constructs one unambiguous route-bound query.
func newAuthorizationQuery(purpose AuthorizationPurpose, ticket routeplan.CopyTicket, additional ...[]byte) AuthorizationQuery {
	h := sha256.New()
	writeAuthorizationPart(h, []byte(authorizationTranscriptDomain))
	writeAuthorizationPart(h, []byte(purpose))
	parent := ticket.ParentIdentity()
	copyID := ticket.TicketIdentity()
	binding := ticket.BindingIdentity()
	writeAuthorizationPart(h, parent[:])
	writeAuthorizationPart(h, copyID[:])
	writeAuthorizationPart(h, binding[:])
	writeAuthorizationCount(h, ticket.TotalMultiplicity())
	writeAuthorizationPart(h, []byte(ticket.DisclosureClass()))
	for _, part := range additional {
		writeAuthorizationPart(h, part)
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return AuthorizationQuery{purpose: purpose, binding: digest}
}

// AuthorizationResult is one authorizer-returned exact-query decision.
type AuthorizationResult struct {
	status  AuthorizationStatus
	purpose AuthorizationPurpose
	binding [sha256.Size]byte
}

// NewAuthorizationResult constructs a decision bound to one exact query.
func NewAuthorizationResult(query AuthorizationQuery, status AuthorizationStatus) AuthorizationResult {
	if !query.Valid() || !status.Known() {
		return AuthorizationResult{}
	}
	return AuthorizationResult{status: status, purpose: query.purpose, binding: query.binding}
}

// Status returns the closed decision.
func (r AuthorizationResult) Status() AuthorizationStatus { return r.status }

// String returns a constant secret-safe result summary.
func (r AuthorizationResult) String() string { return "signing.AuthorizationResult{redacted}" }

// GoString returns a constant secret-safe result Go representation.
func (r AuthorizationResult) GoString() string { return r.String() }

// Format routes every result formatting form through the redacted summary.
func (r AuthorizationResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// Authorizer decides one exact policy, disclosure, feedback, or OOB query.
type Authorizer interface {
	Authorize(context.Context, AuthorizationQuery) (AuthorizationResult, error)
}

// Authorization is sealed single-operation evidence of one authorization.
type Authorization struct {
	purpose     AuthorizationPurpose
	binding     [sha256.Size]byte
	restriction ForwardingRestriction
	seal        [sha256.Size]byte
}

// Valid reports whether the authorization was sealed for one exact query.
func (a Authorization) Valid() bool {
	return a.purpose.Known() && a.binding != [sha256.Size]byte{} && a.seal != [sha256.Size]byte{} &&
		(a.purpose == AuthorizationPolicy && a.restriction.Known() ||
			(a.purpose == AuthorizationReceiveNextDomain || a.purpose == AuthorizationSendNextDomain) && a.restriction == RestrictionOutOfBand ||
			a.purpose != AuthorizationPolicy && a.purpose != AuthorizationReceiveNextDomain && a.purpose != AuthorizationSendNextDomain && a.restriction == "")
}

// Purpose returns the closed authorization purpose.
func (a Authorization) Purpose() AuthorizationPurpose {
	if !a.Valid() {
		return ""
	}
	return a.purpose
}

// Matches reports whether evidence belongs to the exact query.
func (a Authorization) Matches(query AuthorizationQuery) bool {
	return a.Valid() && query.Valid() && a.purpose == query.purpose && a.binding == query.binding &&
		a.restriction == query.restriction
}

// Restriction returns the closed policy or OOB result restriction.
func (a Authorization) Restriction() ForwardingRestriction {
	if !a.Valid() {
		return ""
	}
	return a.restriction
}

// String returns a constant secret-safe authorization summary.
func (a Authorization) String() string { return "signing.Authorization{redacted}" }

// GoString returns a constant secret-safe authorization Go representation.
func (a Authorization) GoString() string { return a.String() }

// Format routes every authorization formatting form through the redacted summary.
func (a Authorization) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, a.String()) }

// AuthorizationSession enforces one operation's separate four-call authorizer budget.
type AuthorizationSession struct {
	mu       sync.Mutex
	maxCalls int
	calls    int
	sealKey  [sha256.Size]byte
}

// String returns a constant secret-safe authorization session summary.
func (s *AuthorizationSession) String() string { return "signing.AuthorizationSession{redacted}" }

// GoString returns a constant secret-safe session Go representation.
func (s *AuthorizationSession) GoString() string { return s.String() }

// Format routes every session formatting form through the redacted summary.
func (s *AuthorizationSession) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, s.String())
}

// NewAuthorizationSession constructs one bounded operation session with private entropy.
func NewAuthorizationSession(maxCalls int) (*AuthorizationSession, error) {
	var sealKey [sha256.Size]byte
	if _, err := io.ReadFull(rand.Reader, sealKey[:]); err != nil || sealKey == [sha256.Size]byte{} {
		return nil, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseOptions}, ErrorDetails{})
	}
	return newAuthorizationSession(maxCalls, sealKey)
}

// newAuthorizationSession constructs a deterministic session for tests.
func newAuthorizationSession(maxCalls int, sealKey [sha256.Size]byte) (*AuthorizationSession, error) {
	if maxCalls == 0 {
		maxCalls = DefaultLimits().MaxAuthorizationCalls
	}
	if maxCalls <= 0 || maxCalls > DefaultLimits().MaxAuthorizationCalls || sealKey == [sha256.Size]byte{} {
		return nil, newError(ErrorCodeInvalidOptions, ErrorLocation{Phase: PhaseOptions}, ErrorDetails{})
	}
	return &AuthorizationSession{maxCalls: maxCalls, sealKey: sealKey}, nil
}

// Evaluate validates context, call budget, typed nils, and the exact result matrix.
func (s *AuthorizationSession) Evaluate(ctx context.Context, authorizer Authorizer, query AuthorizationQuery) (Authorization, AuthorizationStatus, error) {
	if s == nil || ctx == nil || isNilSigningInterface(authorizer) || !query.Valid() {
		return Authorization{}, "", newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if err := ctx.Err(); err != nil {
		return Authorization{}, "", err
	}
	s.mu.Lock()
	if s.calls >= s.maxCalls {
		s.mu.Unlock()
		return Authorization{}, "", limitError(LimitNameMaxAuthorizationCalls, s.maxCalls, s.calls+1)
	}
	s.calls++
	s.mu.Unlock()
	result, callErr := authorizer.Authorize(ctx, query)
	ctxErr := ctx.Err()
	if ctxErr != nil && callErr != nil && result == (AuthorizationResult{}) && errors.Is(callErr, ctxErr) {
		return Authorization{}, "", ctxErr
	}
	if isTypedNilSigningError(callErr) {
		return Authorization{}, "", newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
	}
	if callErr != nil {
		if result.status != "" || result.purpose != "" || result.binding != [sha256.Size]byte{} {
			return Authorization{}, "", newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
		}
		switch provider.ClassOf(callErr) {
		case provider.FailureTemporary:
			if ctxErr != nil {
				return Authorization{}, "", ctxErr
			}
			return Authorization{}, "", newError(ErrorCodeCallbackTemporary, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
		case provider.FailurePermanent:
			if ctxErr != nil {
				return Authorization{}, "", ctxErr
			}
			return Authorization{}, "", newError(ErrorCodeCallbackPermanent, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
		default:
			return Authorization{}, "", newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
		}
	}
	if !result.status.Known() || result.purpose != query.purpose || result.binding != query.binding {
		return Authorization{}, "", newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
	}
	if ctxErr != nil {
		return Authorization{}, "", ctxErr
	}
	if result.status == AuthorizationDenied {
		return Authorization{}, result.status, nil
	}
	authorization := Authorization{purpose: query.purpose, binding: query.binding, restriction: query.restriction}
	authorization.seal = s.authorizationSeal(authorization)
	return authorization, result.status, nil
}

// authorizationSeal seals exact authorized evidence.
func (s *AuthorizationSession) authorizationSeal(authorization Authorization) [sha256.Size]byte {
	h := hmac.New(sha256.New, s.sealKey[:])
	writeAuthorizationPart(h, []byte("dkim2/authorization-seal/v1"))
	writeAuthorizationPart(h, []byte(authorization.purpose))
	writeAuthorizationPart(h, authorization.binding[:])
	writeAuthorizationPart(h, []byte(authorization.restriction))
	var result [sha256.Size]byte
	copy(result[:], h.Sum(nil))
	return result
}

// Metadata contains an optional nonce and caller-requestable baseline flags.
type Metadata struct {
	nonce        []byte
	noncePresent bool
	requested    []string
}

// NewSigningMetadata validates immutable nonce presence and caller-requestable flags.
func NewSigningMetadata(nonce []byte, noncePresent bool, requested []string) (Metadata, error) {
	if noncePresent != (nonce != nil) || len(nonce) > DefaultLimits().MaxNonceBytes {
		return Metadata{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if !signature.ValidNonceSyntax(nonce) {
		return Metadata{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	seen := make(map[string]struct{}, len(requested))
	for _, flag := range requested {
		switch flag {
		case signature.FlagDoNotModify, signature.FlagDoNotExplode, signature.FlagFeedback:
		default:
			return Metadata{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
		}
		if _, duplicate := seen[flag]; duplicate {
			return Metadata{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
		}
		seen[flag] = struct{}{}
	}
	return Metadata{nonce: bytes.Clone(nonce), noncePresent: noncePresent, requested: slices.Clone(requested)}, nil
}

// Nonce returns exact detached nonce bytes and explicit presence.
func (m Metadata) Nonce() ([]byte, bool) { return bytes.Clone(m.nonce), m.noncePresent }

// RequestedFlags returns detached caller-requested flags.
func (m Metadata) RequestedFlags() []string { return slices.Clone(m.requested) }

// Valid reports whether metadata satisfies the closed caller-owned contract.
func (m Metadata) Valid() bool { return metadataValid(m) }

// String returns a constant secret-safe metadata summary.
func (m Metadata) String() string { return "signing.Metadata{redacted}" }

// GoString returns a constant secret-safe metadata Go representation.
func (m Metadata) GoString() string { return m.String() }

// Format routes every metadata formatting form through the redacted summary.
func (m Metadata) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, m.String()) }

// EffectiveMetadata contains fixed-order derived and inherited signing flags.
type EffectiveMetadata struct{ flags []string }

// DeriveEffectiveMetadata combines caller requests, every authenticated prior flag, and route facts.
func DeriveEffectiveMetadata(metadata Metadata, capability VerifiedRevisionInput, ticket routeplan.CopyTicket, feedback Authorization, session *AuthorizationSession) (EffectiveMetadata, error) {
	if !ticket.Valid() || !metadataValid(metadata) {
		return EffectiveMetadata{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	switch ticket.Purpose() {
	case routeplan.PurposeOrigin, routeplan.PurposeDeliveryStatus, routeplan.PurposeDeliveryStatusPropagation:
		if !zeroRevisionInput(capability) {
			return EffectiveMetadata{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
		}
	case routeplan.PurposeRevision, routeplan.PurposeNextDomain:
		if !capability.Valid() || !ticket.MatchesRevisionBinding(capability.seal[:]) {
			return EffectiveMetadata{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
		}
	default:
		return EffectiveMetadata{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	values := make(map[string]bool, 5)
	for _, flag := range metadata.requested {
		values[flag] = true
	}
	if capability.Valid() {
		for _, facts := range capability.proof.Facts().Flags() {
			values[signature.FlagDoNotModify] = values[signature.FlagDoNotModify] || facts.DoNotModify()
			values[signature.FlagDoNotExplode] = values[signature.FlagDoNotExplode] || facts.DoNotExplode()
			values[signature.FlagExploded] = values[signature.FlagExploded] || facts.Exploded()
		}
	}
	if ticket.TotalMultiplicity() > 1 || len(ticket.DisclosureRecipients()) > 1 {
		values[signature.FlagExploded] = true
	}
	if feedback.Valid() {
		query, queryErr := NewFeedbackAuthorizationQuery(capability, ticket)
		if queryErr != nil || session == nil || !session.ValidAuthorization(feedback, query) {
			return EffectiveMetadata{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
		}
		values[signature.FlagFeedHere] = true
	}
	return effectiveMetadataFromValues(values), nil
}

// zeroRevisionInput reports whether no inherited revision capability was supplied.
func zeroRevisionInput(capability VerifiedRevisionInput) bool {
	return capability.IsZero()
}

// ValidAuthorization authenticates exact session-issued evidence for one query.
func (s *AuthorizationSession) ValidAuthorization(authorization Authorization, query AuthorizationQuery) bool {
	if s == nil || !authorization.Matches(query) {
		return false
	}
	expected := s.authorizationSeal(authorization)
	return subtle.ConstantTimeCompare(authorization.seal[:], expected[:]) == 1
}

// Flags returns the exact fixed-order effective flags.
func (m EffectiveMetadata) Flags() []string { return slices.Clone(m.flags) }

// String returns a constant secret-safe derived metadata summary.
func (m EffectiveMetadata) String() string { return "signing.EffectiveMetadata{redacted}" }

// GoString returns a constant secret-safe derived metadata Go representation.
func (m EffectiveMetadata) GoString() string { return m.String() }

// Format routes every metadata formatting form through the redacted summary.
func (m EffectiveMetadata) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, m.String()) }

// effectiveMetadataWithFeedbackIntent derives the sole preflight feedhere branch ordering.
func effectiveMetadataWithFeedbackIntent(base EffectiveMetadata) EffectiveMetadata {
	values := make(map[string]bool, len(base.flags)+1)
	for _, flag := range base.flags {
		values[flag] = true
	}
	values[signature.FlagFeedHere] = true
	return effectiveMetadataFromValues(values)
}

// effectiveMetadataFromValues applies the sole fixed known-flag order.
func effectiveMetadataFromValues(values map[string]bool) EffectiveMetadata {
	order := []string{
		signature.FlagDoNotModify, signature.FlagDoNotExplode, signature.FlagFeedback,
		signature.FlagFeedHere, signature.FlagExploded,
	}
	flags := make([]string, 0, len(values))
	for _, flag := range order {
		if values[flag] {
			flags = append(flags, flag)
		}
	}
	return EffectiveMetadata{flags: flags}
}

// capabilityHasFeedback reports causal authenticated feedback across all prior signatures.
func capabilityHasFeedback(capability VerifiedRevisionInput) bool {
	if !capability.Valid() {
		return false
	}
	for _, facts := range capability.proof.Facts().Flags() {
		if facts.Feedback() {
			return true
		}
	}
	return false
}

// metadataValid rejects zero-state contradictions and forged caller flags.
func metadataValid(metadata Metadata) bool {
	if metadata.noncePresent != (metadata.nonce != nil) {
		return false
	}
	_, err := NewSigningMetadata(metadata.nonce, metadata.noncePresent, metadata.requested)
	return err == nil
}

// boolBytes encodes one explicit policy boolean.
func boolBytes(value bool) []byte {
	if value {
		return []byte{1}
	}
	return []byte{0}
}

// canonicalAuthorizationDomain validates already-canonical ASCII DNS names.
func canonicalAuthorizationDomain(domain string) bool {
	query, err := keyresolver.NewQuery(domain, "authorization", signature.AlgorithmEd25519SHA256, keyresolver.DefaultLimits())
	return err == nil && query.SigningDomain() == domain
}

// revisionPredecessor derives the exact highest authenticated predecessor domain.
func revisionPredecessor(capability VerifiedRevisionInput, profileDomain string) (PredecessorKind, string, bool) {
	message, err := rawmsg.Parse(capability.raw)
	if err != nil {
		return "", "", false
	}
	parser, err := signature.NewParser(signature.DefaultLimits())
	if err != nil {
		return "", "", false
	}
	parsed := make([]signature.Signature, 0)
	for _, field := range message.Headers().Fields() {
		if field.NameLower() != strings.ToLower(signature.HeaderName) {
			continue
		}
		value, parseErr := parser.ParseField(field)
		if parseErr != nil {
			return "", "", false
		}
		parsed = append(parsed, value)
	}
	ordered, err := signature.OrderBySequence(parsed)
	if err != nil || len(ordered) == 0 {
		return "", "", false
	}
	highest := ordered[len(ordered)-1]
	if next, present := highest.NextDomain(); present {
		return PredecessorNextDomain, next, canonicalAuthorizationDomain(next)
	}
	for _, recipient := range highest.Recipients() {
		domain, ok := envelopeDomain(recipient.Value())
		if ok && domain == profileDomain {
			return PredecessorOrdinary, domain, true
		}
	}
	return "", "", false
}

// envelopeDomain extracts one canonical DNS domain from validated SMTP path bytes.
func envelopeDomain(path []byte) (string, bool) {
	if !signature.ValidEnvelopePath(path, false) {
		return "", false
	}
	at := bytes.LastIndexByte(path, '@')
	if at < 2 || at >= len(path)-2 {
		return "", false
	}
	domain := strings.ToLower(string(path[at+1 : len(path)-1]))
	return domain, canonicalAuthorizationDomain(domain)
}

// writeAuthorizationPart writes presence and length framing.
func writeAuthorizationPart(w io.Writer, value []byte) {
	if value == nil {
		_, _ = w.Write([]byte{0})
		return
	}
	_, _ = w.Write([]byte{1})
	var encoded [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(encoded[:], uint64(len(value)))
	_, _ = w.Write(encoded[:n])
	_, _ = w.Write(value)
}

// writeAuthorizationCount writes one explicit count.
func writeAuthorizationCount(w io.Writer, value int) {
	var encoded [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(encoded[:], uint64(value))
	writeAuthorizationPart(w, encoded[:n])
}

// isNilSigningInterface rejects nil and typed-nil injected implementations.
func isNilSigningInterface(value any) bool {
	return niliface.IsNil(value)
}

// isTypedNilSigningError detects an error interface containing a nil pointer.
func isTypedNilSigningError(err error) bool { return err != nil && isNilSigningInterface(err) }
