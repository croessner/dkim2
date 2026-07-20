// Package routeplan owns bounded DKIM2 fanout planning and ticket state.
package routeplan

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
	"math"
	"slices"
	"sync"

	"github.com/croessner/dkim2/internal/niliface"
	"github.com/croessner/dkim2/internal/provider"
	"github.com/croessner/dkim2/internal/signature"
)

const (
	transcriptDomain = "dkim2/route-plan/v1"
	hardCopies       = 128
	hardDescriptors  = 256 * 1024
	hardWork         = 4096
	hardPerSource    = 32 * 1024 * 1024
	hardSourceBytes  = 64 * 1024 * 1024
	hardRecipients   = 128
	hardEnvelopePath = 32 * 1024
	hardCalls        = 4
)

type authorityMethod string

const (
	methodReserve authorityMethod = "reserve"
	methodRelease authorityMethod = "release"
	methodBurn    authorityMethod = "burn"
	methodReplace authorityMethod = "replace"
	methodConsume authorityMethod = "consume"
)

// Purpose identifies why exact pre-sign bytes are being routed.
type Purpose string

const (
	// PurposeOrigin identifies an originator copy.
	PurposeOrigin Purpose = "origin"
	// PurposeRevision identifies a verified revision copy.
	PurposeRevision Purpose = "revision"
	// PurposeNextDomain identifies a terminal next-domain copy.
	PurposeNextDomain Purpose = "next_domain"
)

// Known reports whether purpose belongs to the closed route vocabulary.
func (p Purpose) Known() bool {
	return p == PurposeOrigin || p == PurposeRevision || p == PurposeNextDomain
}

// DisclosureClass identifies the recipient-disclosure policy of one copy.
type DisclosureClass string

const (
	// DisclosureSingle exposes exactly one recipient.
	DisclosureSingle DisclosureClass = "single"
	// DisclosureAuthorizedGroup requires exact multi-recipient authorization.
	DisclosureAuthorizedGroup DisclosureClass = "authorized_group"
	// DisclosureBccSeparated identifies a single-recipient privacy copy.
	DisclosureBccSeparated DisclosureClass = "bcc_separated"
)

// Known reports whether class belongs to the closed disclosure vocabulary.
func (c DisclosureClass) Known() bool {
	return c == DisclosureSingle || c == DisclosureAuthorizedGroup || c == DisclosureBccSeparated
}

// RouteClass identifies whether a sealed route is eligible for restricted release.
type RouteClass string

const (
	// RouteExternal identifies an ordinary route that cannot release restricted output.
	RouteExternal RouteClass = "external"
	// RouteInControl identifies a sealed in-control route eligible for local-only release.
	RouteInControl RouteClass = "in_control"
	// RouteOutOfBand identifies a sealed receiver arrangement eligible for OOB release.
	RouteOutOfBand RouteClass = "out_of_band"
)

// Known reports whether class belongs to the closed route-scope vocabulary.
func (c RouteClass) Known() bool {
	return c == RouteExternal || c == RouteInControl || c == RouteOutOfBand
}

// Limits contains routeplan-owned narrowable ceilings.
type Limits struct {
	MaxCopiesAndTickets  int
	MaxDescriptorBytes   int
	MaxWorkUnits         int
	MaxSourceBytes       int
	MaxUniqueSourceBytes int
	MaxRecipientsPerCopy int
	MaxEnvelopePathBytes int
	MaxAuthorityCalls    int
}

// DefaultLimits returns the route planning hard ceilings.
func DefaultLimits() Limits {
	return Limits{
		MaxCopiesAndTickets: hardCopies, MaxDescriptorBytes: hardDescriptors,
		MaxWorkUnits: hardWork, MaxSourceBytes: hardPerSource,
		MaxUniqueSourceBytes: hardSourceBytes, MaxRecipientsPerCopy: hardRecipients,
		MaxEnvelopePathBytes: hardEnvelopePath, MaxAuthorityCalls: hardCalls,
	}
}

// Validate rejects widening and incoherent route planning ceilings.
func (l Limits) Validate() error {
	_, err := l.normalized()
	return err
}

// normalized fills zero limits and rejects widening or independent cardinality.
func (l Limits) normalized() (Limits, error) {
	d := DefaultLimits()
	values := []struct {
		value          *int
		fallback, hard int
	}{
		{&l.MaxCopiesAndTickets, d.MaxCopiesAndTickets, hardCopies},
		{&l.MaxDescriptorBytes, d.MaxDescriptorBytes, hardDescriptors},
		{&l.MaxWorkUnits, d.MaxWorkUnits, hardWork},
		{&l.MaxSourceBytes, d.MaxSourceBytes, hardPerSource},
		{&l.MaxUniqueSourceBytes, d.MaxUniqueSourceBytes, hardSourceBytes},
		{&l.MaxRecipientsPerCopy, d.MaxRecipientsPerCopy, hardRecipients},
		{&l.MaxEnvelopePathBytes, d.MaxEnvelopePathBytes, hardEnvelopePath},
		{&l.MaxAuthorityCalls, d.MaxAuthorityCalls, hardCalls},
	}
	for _, item := range values {
		if *item.value == 0 {
			*item.value = item.fallback
		}
		if *item.value <= 0 || *item.value > item.hard {
			return Limits{}, newError(ErrorInvalidOptions)
		}
	}
	if l.MaxAuthorityCalls < 3 {
		return Limits{}, newError(ErrorInvalidOptions)
	}
	return l, nil
}

type sourceIdentity struct{ marker byte }

// ImmutableSource owns exact cloned pre-sign RFC 5322 bytes and explicit identity.
type ImmutableSource struct {
	raw []byte
	id  *sourceIdentity
}

// NewImmutableSource clones one exact source; equal independent inputs remain distinct sources.
func NewImmutableSource(raw []byte) (ImmutableSource, error) {
	if len(raw) == 0 || len(raw) > hardPerSource {
		return ImmutableSource{}, newError(ErrorInvalidRequest)
	}
	return ImmutableSource{raw: bytes.Clone(raw), id: &sourceIdentity{marker: 1}}, nil
}

// Valid reports whether the source was constructed with owned bytes.
func (s ImmutableSource) Valid() bool { return s.id != nil && len(s.raw) > 0 }

// String returns a constant secret-safe source summary.
func (s ImmutableSource) String() string { return "routeplan.ImmutableSource{redacted}" }

// GoString returns a constant secret-safe source Go representation.
func (s ImmutableSource) GoString() string { return s.String() }

// Format routes every source formatting form through the redacted summary.
func (s ImmutableSource) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, s.String()) }

// Entry describes one intended output before authority issuance.
type Entry struct {
	source                  ImmutableSource
	purpose                 Purpose
	reversePath             []byte
	forwardPaths            [][]byte
	disclosure              DisclosureClass
	routeClass              RouteClass
	routeBinding            []byte
	inboundReceiverBinding  []byte
	outboundReceiverBinding []byte
	revisionBinding         []byte
}

// NewEntry constructs one immutable ordinary external route entry.
func NewEntry(source ImmutableSource, purpose Purpose, reversePath []byte, forwardPaths [][]byte, disclosure DisclosureClass, routeScope, revisionBinding []byte) (Entry, error) {
	return NewClassifiedEntry(
		source, purpose, reversePath, forwardPaths, disclosure,
		RouteExternal, routeScope, nil, revisionBinding,
	)
}

// NewClassifiedEntry constructs one immutable route entry with a closed release class.
func NewClassifiedEntry(
	source ImmutableSource,
	purpose Purpose,
	reversePath []byte,
	forwardPaths [][]byte,
	disclosure DisclosureClass,
	routeClass RouteClass,
	routeScope, receiverBinding, revisionBinding []byte,
) (Entry, error) {
	if routeClass == RouteOutOfBand {
		return NewDualReceiverClassifiedEntry(
			source, purpose, reversePath, forwardPaths, disclosure, routeClass,
			routeScope, nil, receiverBinding, revisionBinding,
		)
	}
	return NewDualReceiverClassifiedEntry(
		source, purpose, reversePath, forwardPaths, disclosure, routeClass,
		routeScope, receiverBinding, nil, revisionBinding,
	)
}

// NewDualReceiverClassifiedEntry constructs one immutable route entry with
// independently sealed inbound and outbound OOB receiver evidence.
func NewDualReceiverClassifiedEntry(
	source ImmutableSource,
	purpose Purpose,
	reversePath []byte,
	forwardPaths [][]byte,
	disclosure DisclosureClass,
	routeClass RouteClass,
	routeScope, inboundReceiverBinding, outboundReceiverBinding, revisionBinding []byte,
) (Entry, error) {
	unowned := Entry{
		source: source, purpose: purpose, reversePath: reversePath,
		forwardPaths: forwardPaths, disclosure: disclosure,
		routeClass: routeClass, routeBinding: routeScope,
		inboundReceiverBinding:  inboundReceiverBinding,
		outboundReceiverBinding: outboundReceiverBinding,
		revisionBinding:         revisionBinding,
	}
	if !unowned.valid() || len(revisionBinding) != 0 && len(revisionBinding) != sha256.Size ||
		descriptorSize(routeBinding{
			purpose: purpose, reversePath: reversePath, forwardPaths: forwardPaths,
			disclosure: disclosure, routeClass: routeClass, route: routeScope,
			inboundReceiver: inboundReceiverBinding, outboundReceiver: outboundReceiverBinding,
			revision: revisionBinding, total: 1,
		}) > hardDescriptors {
		return Entry{}, newError(ErrorInvalidRequest)
	}
	entry := Entry{
		source: source, purpose: purpose, reversePath: bytes.Clone(reversePath),
		forwardPaths: cloneSlices(forwardPaths), disclosure: disclosure,
		routeClass: routeClass, routeBinding: bytes.Clone(routeScope),
		inboundReceiverBinding:  bytes.Clone(inboundReceiverBinding),
		outboundReceiverBinding: bytes.Clone(outboundReceiverBinding),
		revisionBinding:         bytes.Clone(revisionBinding),
	}
	return entry, nil
}

// valid enforces exact purpose, path, disclosure, route, and revision bindings.
func (e Entry) valid() bool {
	if !e.source.Valid() || !e.purpose.Known() || !e.disclosure.Known() ||
		!e.routeClass.Known() || !validPath(e.reversePath, true) ||
		len(e.forwardPaths) == 0 || len(e.routeBinding) == 0 {
		return false
	}
	if (e.routeClass == RouteOutOfBand) != (len(e.outboundReceiverBinding) > 0) ||
		e.purpose == PurposeOrigin &&
			(e.routeClass != RouteExternal || len(e.inboundReceiverBinding) > 0) ||
		e.purpose == PurposeRevision &&
			(e.routeClass == RouteOutOfBand || len(e.outboundReceiverBinding) > 0) ||
		e.purpose == PurposeNextDomain && e.routeClass != RouteOutOfBand {
		return false
	}
	if (e.purpose != PurposeOrigin) != (len(e.revisionBinding) > 0) {
		return false
	}
	if len(e.forwardPaths) > hardCopies {
		return false
	}
	seen := make(map[string]struct{}, len(e.forwardPaths))
	for _, path := range e.forwardPaths {
		if !validPath(path, false) {
			return false
		}
		key := pathComparisonKey(path)
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
	}
	if len(e.forwardPaths) == 1 {
		return e.disclosure == DisclosureSingle || e.disclosure == DisclosureBccSeparated
	}
	return e.disclosure == DisclosureAuthorizedGroup
}

// String returns a constant secret-safe entry summary.
func (e Entry) String() string { return "routeplan.Entry{redacted}" }

// GoString returns a constant secret-safe entry Go representation.
func (e Entry) GoString() string { return e.String() }

// Format routes every entry formatting form through the redacted summary.
func (e Entry) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, e.String()) }

// PlanRequest contains one immutable complete intended fanout.
type PlanRequest struct{ entries []Entry }

// NewPlanRequest snapshots the exact ordered route entries.
func NewPlanRequest(entries []Entry) (PlanRequest, error) {
	if len(entries) == 0 {
		return PlanRequest{}, newError(ErrorInvalidRequest)
	}
	if len(entries) > hardCopies {
		return PlanRequest{}, newLimitError(len(entries))
	}
	owned := make([]Entry, len(entries))
	for index, entry := range entries {
		if !entry.valid() {
			return PlanRequest{}, newError(ErrorInvalidRequest)
		}
		owned[index] = entry
	}
	return PlanRequest{entries: owned}, nil
}

// Count returns the immutable intended copy count.
func (r PlanRequest) Count() int { return len(r.entries) }

// String returns a constant secret-safe request summary.
func (r PlanRequest) String() string { return "routeplan.PlanRequest{redacted}" }

// GoString returns a constant secret-safe request Go representation.
func (r PlanRequest) GoString() string { return r.String() }

// Format routes every request formatting form through the redacted summary.
func (r PlanRequest) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// Usage reports bounded planning work without identities.
type Usage struct {
	Copies, Tickets, DescriptorBytes, WorkUnits, UniqueSourceBytes int
}

// Valid reports whether usage is nonnegative and one-to-one.
func (u Usage) Valid() bool {
	return u.Copies > 0 && u.Copies == u.Tickets && u.DescriptorBytes > 0 && u.WorkUnits > 0 && u.UniqueSourceBytes > 0
}

type routeBinding struct {
	sourceDigest     [sha256.Size]byte
	digest           [sha256.Size]byte
	purpose          Purpose
	reversePath      []byte
	forwardPaths     [][]byte
	disclosure       DisclosureClass
	routeClass       RouteClass
	route            []byte
	inboundReceiver  []byte
	outboundReceiver []byte
	revision         []byte
	total            int
}

// FinalizeQuery carries trusted exact bindings across the explicit authority boundary.
type FinalizeQuery struct {
	bindings []routeBinding
	usage    Usage
}

// Valid reports whether the query owns a complete coupled binding and usage shape.
func (q FinalizeQuery) Valid() bool {
	if len(q.bindings) == 0 || !q.usage.Valid() ||
		q.usage.Copies != len(q.bindings) || q.usage.Tickets != len(q.bindings) {
		return false
	}
	for _, binding := range q.bindings {
		if binding.digest == [sha256.Size]byte{} || binding.sourceDigest == [sha256.Size]byte{} ||
			!binding.purpose.Known() || !binding.disclosure.Known() ||
			!binding.routeClass.Known() || len(binding.forwardPaths) == 0 ||
			len(binding.route) == 0 ||
			(binding.routeClass == RouteOutOfBand) != (len(binding.outboundReceiver) > 0) ||
			binding.purpose == PurposeOrigin &&
				(binding.routeClass != RouteExternal || len(binding.inboundReceiver) > 0) ||
			binding.purpose == PurposeRevision &&
				(binding.routeClass == RouteOutOfBand || len(binding.outboundReceiver) > 0) ||
			binding.purpose == PurposeNextDomain && binding.routeClass != RouteOutOfBand ||
			binding.total != len(q.bindings) {
			return false
		}
	}
	return true
}

// Count returns the required coupled copy/ticket count.
func (q FinalizeQuery) Count() int { return len(q.bindings) }

// Usage returns bounded planning charges.
func (q FinalizeQuery) Usage() Usage { return q.usage }

// BindingDigest returns one detached exact pre-sign binding digest.
func (q FinalizeQuery) BindingDigest(index int) []byte {
	if index < 0 || index >= len(q.bindings) {
		return nil
	}
	return bytes.Clone(q.bindings[index].digest[:])
}

// String returns a constant secret-safe query summary.
func (q FinalizeQuery) String() string { return "routeplan.FinalizeQuery{redacted}" }

// GoString returns a constant secret-safe query Go representation.
func (q FinalizeQuery) GoString() string { return q.String() }

// Format routes every query formatting form through the redacted summary.
func (q FinalizeQuery) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, q.String()) }

// AuthorityStatus identifies one method-specific route authority outcome.
type AuthorityStatus string

const (
	// AuthorityIssued reports successful parent and ticket identity issuance.
	AuthorityIssued AuthorityStatus = "issued"
	// AuthorityReserved reports an atomic fresh-to-reserved transition.
	AuthorityReserved AuthorityStatus = "reserved"
	// AuthorityReleased reports a pre-boundary reserved-to-released transition.
	AuthorityReleased AuthorityStatus = "released"
	// AuthorityBurned reports a reserved-to-burned external-boundary transition.
	AuthorityBurned AuthorityStatus = "burned"
	// AuthorityReplacementIssued reports same-lineage replacement issuance.
	AuthorityReplacementIssued AuthorityStatus = "replacement_issued"
	// AuthorityConsumed reports restricted release-phase consumption.
	AuthorityConsumed AuthorityStatus = "consumed"
	// AuthorityDenied reports a valid request refused by authority policy or state.
	AuthorityDenied AuthorityStatus = "denied"
)

// Known reports whether status belongs to the closed authority vocabulary.
func (s AuthorityStatus) Known() bool {
	switch s {
	case AuthorityIssued, AuthorityReserved, AuthorityReleased, AuthorityBurned,
		AuthorityReplacementIssued, AuthorityConsumed, AuthorityDenied:
		return true
	default:
		return false
	}
}

// AuthorityResult carries only opaque authority identities and a closed status.
type AuthorityResult struct {
	status      AuthorityStatus
	parentID    [sha256.Size]byte
	parentSeal  [sha256.Size]byte
	ticketIDs   [][sha256.Size]byte
	ticketSeals [][sha256.Size]byte
	bindingIDs  [][sha256.Size]byte
	query       TicketQuery
	hasQuery    bool
}

// NewAuthorityResult constructs a detached authority result for a specific method.
func NewAuthorityResult(status AuthorityStatus, parentID [sha256.Size]byte, ticketIDs [][sha256.Size]byte) AuthorityResult {
	return AuthorityResult{status: status, parentID: parentID, ticketIDs: slices.Clone(ticketIDs)}
}

// NewFinalizeAuthorityResult constructs issuance bound to exact ordered finalize bindings.
func NewFinalizeAuthorityResult(query FinalizeQuery, parentID, parentSeal [sha256.Size]byte, ticketIDs, ticketSeals [][sha256.Size]byte) AuthorityResult {
	bindingIDs := make([][sha256.Size]byte, len(query.bindings))
	for index := range query.bindings {
		bindingIDs[index] = query.bindings[index].digest
	}
	return AuthorityResult{
		status: AuthorityIssued, parentID: parentID, parentSeal: parentSeal,
		ticketIDs: slices.Clone(ticketIDs), ticketSeals: slices.Clone(ticketSeals), bindingIDs: bindingIDs,
	}
}

// NewTransitionAuthorityResult constructs one transition bound to the exact queried ticket.
func NewTransitionAuthorityResult(status AuthorityStatus, query TicketQuery, replacementIDs, replacementSeals [][sha256.Size]byte) AuthorityResult {
	return AuthorityResult{
		status: status, parentID: query.parentID, ticketIDs: slices.Clone(replacementIDs),
		ticketSeals: slices.Clone(replacementSeals), query: query, hasQuery: true,
	}
}

// Status returns the closed result status.
func (r AuthorityResult) Status() AuthorityStatus { return r.status }

// String returns a constant secret-safe authority result summary.
func (r AuthorityResult) String() string { return "routeplan.AuthorityResult{redacted}" }

// GoString returns a constant secret-safe authority result Go representation.
func (r AuthorityResult) GoString() string { return r.String() }

// Format routes every result formatting form through the redacted summary.
func (r AuthorityResult) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// TicketQuery identifies one exact authority-owned ticket transition.
type TicketQuery struct {
	parentID, ticketID [sha256.Size]byte
	binding            [sha256.Size]byte
	seal               [sha256.Size]byte
}

// Valid reports whether every opaque ticket-transition identity is nonzero.
func (q TicketQuery) Valid() bool {
	return q.parentID != [sha256.Size]byte{} && q.ticketID != [sha256.Size]byte{} &&
		q.binding != [sha256.Size]byte{} && q.seal != [sha256.Size]byte{}
}

// ParentIdentity returns the opaque parent identity across the authority boundary.
func (q TicketQuery) ParentIdentity() [sha256.Size]byte { return q.parentID }

// TicketIdentity returns the opaque ticket identity across the authority boundary.
func (q TicketQuery) TicketIdentity() [sha256.Size]byte { return q.ticketID }

// BindingIdentity returns the opaque exact-copy binding across the authority boundary.
func (q TicketQuery) BindingIdentity() [sha256.Size]byte { return q.binding }

// CapabilitySeal returns the authority-issued opaque ticket seal.
func (q TicketQuery) CapabilitySeal() [sha256.Size]byte { return q.seal }

// String returns a constant secret-safe ticket query summary.
func (q TicketQuery) String() string { return "routeplan.TicketQuery{redacted}" }

// GoString returns a constant secret-safe ticket query Go representation.
func (q TicketQuery) GoString() string { return q.String() }

// Format routes every query formatting form through the redacted summary.
func (q TicketQuery) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, q.String()) }

// RouteFanoutAuthority is the sole issuer and state-transition owner.
type RouteFanoutAuthority interface {
	Finalize(context.Context, FinalizeQuery) (AuthorityResult, error)
	Reserve(context.Context, TicketQuery) (AuthorityResult, error)
	ReleaseReservation(context.Context, TicketQuery) (AuthorityResult, error)
	Burn(context.Context, TicketQuery) (AuthorityResult, error)
	Replace(context.Context, TicketQuery) (AuthorityResult, error)
	ConsumeRelease(context.Context, TicketQuery) (AuthorityResult, error)
}

// RouteFanoutPlan is an immutable finalized parent fanout.
type RouteFanoutPlan struct {
	parentID [sha256.Size]byte
	bindings []routeBinding
	usage    Usage
	seal     [sha256.Size]byte
}

// Valid reports whether the parent has a complete one-to-one sealed shape.
func (p RouteFanoutPlan) Valid() bool {
	return p.parentID != [sha256.Size]byte{} && p.seal != [sha256.Size]byte{} &&
		len(p.bindings) > 0 && len(p.bindings) == p.usage.Copies && p.usage.Valid()
}

// CopyCount returns finalized total multiplicity.
func (p RouteFanoutPlan) CopyCount() int {
	if !p.Valid() {
		return 0
	}
	return len(p.bindings)
}

// Usage returns bounded planning usage.
func (p RouteFanoutPlan) Usage() Usage { return p.usage }

// String returns a constant secret-safe parent summary.
func (p RouteFanoutPlan) String() string { return "routeplan.RouteFanoutPlan{redacted}" }

// GoString returns a constant secret-safe parent Go representation.
func (p RouteFanoutPlan) GoString() string { return p.String() }

// Format routes every parent formatting form through the redacted summary.
func (p RouteFanoutPlan) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, p.String()) }

// CopyTicket is one immutable, non-reusable authority-bound fanout capability.
type CopyTicket struct {
	parentID, ticketID [sha256.Size]byte
	binding            routeBinding
	seal               [sha256.Size]byte
}

// Valid reports whether the ticket has complete sealed binding state.
func (t CopyTicket) Valid() bool {
	if t.parentID == [sha256.Size]byte{} || t.ticketID == [sha256.Size]byte{} ||
		t.seal == [sha256.Size]byte{} || t.binding.digest == [sha256.Size]byte{} || t.binding.total <= 0 {
		return false
	}
	recomputed := bindingDigest(t.binding)
	return subtle.ConstantTimeCompare(t.binding.digest[:], recomputed[:]) == 1
}

// TotalMultiplicity returns the authority-sealed parent copy count.
func (t CopyTicket) TotalMultiplicity() int {
	if !t.Valid() {
		return 0
	}
	return t.binding.total
}

// Purpose returns the closed pre-sign binding purpose.
func (t CopyTicket) Purpose() Purpose {
	if !t.Valid() {
		return ""
	}
	return t.binding.purpose
}

// DisclosureClass returns the exact copy disclosure class.
func (t CopyTicket) DisclosureClass() DisclosureClass {
	if !t.Valid() {
		return ""
	}
	return t.binding.disclosure
}

// RouteClass returns the sealed restricted-release classification.
func (t CopyTicket) RouteClass() RouteClass {
	if !t.Valid() {
		return ""
	}
	return t.binding.routeClass
}

// RouteScope returns a detached opaque scope for trusted internal authorization.
func (t CopyTicket) RouteScope() []byte {
	if !t.Valid() {
		return nil
	}
	return bytes.Clone(t.binding.route)
}

// InboundReceiverBinding returns detached inbound OOB acceptance evidence.
func (t CopyTicket) InboundReceiverBinding() []byte {
	if !t.Valid() || len(t.binding.inboundReceiver) == 0 {
		return nil
	}
	return bytes.Clone(t.binding.inboundReceiver)
}

// OutboundReceiverBinding returns detached outbound OOB acceptance evidence.
func (t CopyTicket) OutboundReceiverBinding() []byte {
	if !t.Valid() || len(t.binding.outboundReceiver) == 0 {
		return nil
	}
	return bytes.Clone(t.binding.outboundReceiver)
}

// DisclosureRecipients returns only this copy's disclosure-safe ordered rt set.
func (t CopyTicket) DisclosureRecipients() [][]byte {
	if !t.Valid() {
		return nil
	}
	return cloneSlices(t.binding.forwardPaths)
}

// ReversePath returns this copy's exact detached SMTP reverse-path.
func (t CopyTicket) ReversePath() []byte {
	if !t.Valid() {
		return nil
	}
	return bytes.Clone(t.binding.reversePath)
}

// ParentIdentity returns an opaque parent binding for trusted internal coordinators.
func (t CopyTicket) ParentIdentity() [sha256.Size]byte {
	if !t.Valid() {
		return [sha256.Size]byte{}
	}
	return t.parentID
}

// TicketIdentity returns an opaque copy binding for trusted internal coordinators.
func (t CopyTicket) TicketIdentity() [sha256.Size]byte {
	if !t.Valid() {
		return [sha256.Size]byte{}
	}
	return t.ticketID
}

// BindingIdentity returns the opaque exact pre-sign transcript digest.
func (t CopyTicket) BindingIdentity() [sha256.Size]byte {
	if !t.Valid() {
		return [sha256.Size]byte{}
	}
	return t.binding.digest
}

// MatchesRevisionBinding compares one sealed revision identity in constant time.
func (t CopyTicket) MatchesRevisionBinding(binding []byte) bool {
	if !t.Valid() || len(t.binding.revision) == 0 || len(binding) != len(t.binding.revision) {
		return false
	}
	return subtle.ConstantTimeCompare(t.binding.revision, binding) == 1
}

// MatchesSource reports whether exact bytes match the library-computed binding.
func (t CopyTicket) MatchesSource(raw []byte) bool {
	if !t.Valid() || len(raw) == 0 || len(raw) > hardPerSource {
		return false
	}
	binding := t.binding
	binding.sourceDigest = digestSource(raw)
	digest := bindingDigest(binding)
	return digest == t.binding.digest
}

// MatchesEnvelope reports exact reverse-path and ordered forward-path equality.
func (t CopyTicket) MatchesEnvelope(reversePath []byte, forwardPaths [][]byte) bool {
	if !t.Valid() || !bytes.Equal(t.binding.reversePath, reversePath) ||
		len(t.binding.forwardPaths) != len(forwardPaths) {
		return false
	}
	for index := range forwardPaths {
		if !bytes.Equal(t.binding.forwardPaths[index], forwardPaths[index]) {
			return false
		}
	}
	return true
}

// String returns a constant secret-safe ticket summary.
func (t CopyTicket) String() string { return "routeplan.CopyTicket{redacted}" }

// GoString returns a constant secret-safe ticket Go representation.
func (t CopyTicket) GoString() string { return t.String() }

// Format routes every ticket formatting form through the redacted summary.
func (t CopyTicket) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, t.String()) }

// Coordinator validates local planning and every injected authority matrix.
type Coordinator struct {
	authority RouteFanoutAuthority
	limits    Limits
}

// String returns a constant secret-safe coordinator summary.
func (c Coordinator) String() string { return "routeplan.Coordinator{redacted}" }

// GoString returns a constant secret-safe coordinator Go representation.
func (c Coordinator) GoString() string { return c.String() }

// Format routes every coordinator formatting form through the redacted summary.
func (c Coordinator) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, c.String()) }

// Valid reports whether the coordinator owns a bounded non-nil authority.
func (c Coordinator) Valid() bool {
	resolved, err := c.limits.normalized()
	return !isNilInterface(c.authority) && err == nil && resolved == c.limits
}

// NewCoordinator constructs a bounded route authority coordinator.
func NewCoordinator(authority RouteFanoutAuthority, limits Limits) (Coordinator, error) {
	resolved, err := limits.normalized()
	if err != nil || isNilInterface(authority) {
		return Coordinator{}, newError(ErrorInvalidOptions)
	}
	return Coordinator{authority: authority, limits: resolved}, nil
}

// Finalize validates and issues one immutable one-to-one parent fanout.
func (c Coordinator) Finalize(ctx context.Context, request PlanRequest) (RouteFanoutPlan, []CopyTicket, error) {
	if ctx == nil || isNilInterface(c.authority) {
		return RouteFanoutPlan{}, nil, newError(ErrorInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return RouteFanoutPlan{}, nil, err
	}
	query, err := c.preflight(request)
	if err != nil {
		return RouteFanoutPlan{}, nil, err
	}
	result, callErr := c.authority.Finalize(ctx, query)
	ctxErr := ctx.Err()
	if ctxErr != nil && callErr != nil && isZeroAuthorityResult(result) && errors.Is(callErr, ctxErr) {
		return RouteFanoutPlan{}, nil, ctxErr
	}
	if err := validateAuthorityResult(result, callErr, AuthorityIssued, query.Count()); err != nil {
		if ctxErr != nil && validAuthorityOutcomeError(err) {
			return RouteFanoutPlan{}, nil, ctxErr
		}
		return RouteFanoutPlan{}, nil, err
	}
	if !finalizeAcknowledgementMatches(result, query) {
		return RouteFanoutPlan{}, nil, newError(ErrorContract)
	}
	if ctxErr != nil {
		return RouteFanoutPlan{}, nil, ctxErr
	}
	bindings := cloneBindings(query.bindings)
	parent := RouteFanoutPlan{
		parentID: result.parentID, bindings: bindings, usage: query.usage, seal: result.parentSeal,
	}
	tickets := make([]CopyTicket, len(bindings))
	for index := range bindings {
		tickets[index] = CopyTicket{
			parentID: result.parentID, ticketID: result.ticketIDs[index],
			binding: bindings[index], seal: result.ticketSeals[index],
		}
	}
	return parent, tickets, nil
}

// preflight computes exact charges and transcript bindings before any authority call.
func (c Coordinator) preflight(request PlanRequest) (FinalizeQuery, error) {
	count := len(request.entries)
	if count == 0 || count > c.limits.MaxCopiesAndTickets {
		return FinalizeQuery{}, newLimitError(count)
	}
	usage := Usage{Copies: count, Tickets: count}
	sources := make(map[*sourceIdentity]struct{}, count)
	for _, entry := range request.entries {
		if !entry.valid() {
			return FinalizeQuery{}, newError(ErrorInvalidRequest)
		}
		envelopeBytes := len(entry.reversePath)
		for _, path := range entry.forwardPaths {
			if envelopeBytes > c.limits.MaxEnvelopePathBytes-len(path) {
				return FinalizeQuery{}, newLimitError(math.MaxInt)
			}
			envelopeBytes += len(path)
		}
		if len(entry.source.raw) > c.limits.MaxSourceBytes ||
			len(entry.forwardPaths) > c.limits.MaxRecipientsPerCopy ||
			envelopeBytes > c.limits.MaxEnvelopePathBytes {
			return FinalizeQuery{}, newLimitError(math.MaxInt)
		}
		_, seen := sources[entry.source.id]
		if !seen {
			if !checkedCharge(&usage.UniqueSourceBytes, len(entry.source.raw), c.limits.MaxUniqueSourceBytes) ||
				!checkedCharge(&usage.WorkUnits, 1, c.limits.MaxWorkUnits) {
				return FinalizeQuery{}, newLimitError(math.MaxInt)
			}
			sources[entry.source.id] = struct{}{}
		}
		work := 4 + len(entry.forwardPaths)
		if len(entry.inboundReceiverBinding) > 0 {
			work++
		}
		if len(entry.outboundReceiverBinding) > 0 {
			work++
		}
		if !checkedCharge(&usage.WorkUnits, work, c.limits.MaxWorkUnits) {
			return FinalizeQuery{}, newLimitError(math.MaxInt)
		}
		binding := routeBinding{
			purpose: entry.purpose, reversePath: entry.reversePath,
			forwardPaths: entry.forwardPaths, disclosure: entry.disclosure,
			routeClass: entry.routeClass, route: entry.routeBinding,
			inboundReceiver:  entry.inboundReceiverBinding,
			outboundReceiver: entry.outboundReceiverBinding,
			revision:         entry.revisionBinding, total: count,
		}
		if !checkedCharge(&usage.DescriptorBytes, descriptorSize(binding), c.limits.MaxDescriptorBytes) {
			return FinalizeQuery{}, newLimitError(math.MaxInt)
		}
	}
	bindings := make([]routeBinding, 0, count)
	sourceDigests := make(map[*sourceIdentity][sha256.Size]byte, len(sources))
	for _, entry := range request.entries {
		sourceDigest, seen := sourceDigests[entry.source.id]
		if !seen {
			sourceDigest = digestSource(entry.source.raw)
			sourceDigests[entry.source.id] = sourceDigest
		}
		binding := routeBinding{
			sourceDigest: sourceDigest,
			purpose:      entry.purpose, reversePath: bytes.Clone(entry.reversePath),
			forwardPaths: cloneSlices(entry.forwardPaths), disclosure: entry.disclosure,
			routeClass: entry.routeClass, route: bytes.Clone(entry.routeBinding),
			inboundReceiver:  bytes.Clone(entry.inboundReceiverBinding),
			outboundReceiver: bytes.Clone(entry.outboundReceiverBinding),
			revision:         bytes.Clone(entry.revisionBinding), total: count,
		}
		binding.digest = bindingDigest(binding)
		bindings = append(bindings, binding)
	}
	return FinalizeQuery{bindings: bindings, usage: usage}, nil
}

// Reserve atomically acquires one fresh ticket for an operation.
func (c Coordinator) Reserve(ctx context.Context, ticket CopyTicket) (Reservation, error) {
	if ctx == nil || !c.validTicket(ticket) {
		return Reservation{}, newError(ErrorInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return Reservation{}, err
	}
	query := ticket.query()
	result, callErr := c.authority.Reserve(ctx, query)
	ctxErr := ctx.Err()
	if ctxErr != nil && callErr != nil && isZeroAuthorityResult(result) && errors.Is(callErr, ctxErr) {
		return Reservation{}, ctxErr
	}
	if err := validateAuthorityResult(result, callErr, AuthorityReserved, 0); err != nil {
		if ctxErr != nil && validAuthorityOutcomeError(err) {
			return Reservation{}, ctxErr
		}
		return Reservation{}, err
	}
	if !transitionAcknowledgementMatches(result, query) {
		return Reservation{}, newError(ErrorContract)
	}
	if ctxErr != nil {
		releaseResult, releaseErr := c.authority.ReleaseReservation(context.WithoutCancel(ctx), query)
		recovery := Reservation{
			coordinator: &c, ticket: ticket, calls: 2, state: reservationReserved, recoveryRequired: true,
			releaseMu: new(sync.Mutex),
		}
		if err := validateAuthorityResult(releaseResult, releaseErr, AuthorityReleased, 0); err != nil {
			return recovery, err
		}
		if !transitionAcknowledgementMatches(releaseResult, query) {
			return recovery, newError(ErrorContract)
		}
		return Reservation{}, ctxErr
	}
	return Reservation{
		coordinator: &c, ticket: ticket, calls: 1, state: reservationReserved,
		releaseMu: new(sync.Mutex),
	}, nil
}

// Reservation owns one operation's route-authority call budget and boundary state.
type Reservation struct {
	coordinator        *Coordinator
	ticket             CopyTicket
	pendingReplacement CopyTicket
	calls              int
	state              reservationState
	recoveryRequired   bool
	releaseRequirement ReleaseRequirement
	releaseMu          *sync.Mutex
}

// RecoveryRequired reports whether a failed cancellation cleanup retained a releasable reservation.
func (r Reservation) RecoveryRequired() bool {
	return r.recoveryRequired && r.coordinator != nil && r.ticket.Valid() && r.state == reservationReserved
}

// ReleaseRequired reports whether a reserved ticket still precedes the external boundary.
func (r Reservation) ReleaseRequired() bool {
	return r.coordinator != nil && r.ticket.Valid() && r.state == reservationReserved
}

// ReplacementRequired reports whether a committed burn requires a replacement after failure.
func (r Reservation) ReplacementRequired() bool {
	return r.coordinator != nil && r.ticket.Valid() && r.state == reservationBurned
}

// RestrictedReleaseRequired reports whether successful local-only signing awaits route-bound release.
func (r *Reservation) RestrictedReleaseRequired() bool {
	if r == nil || r.releaseMu == nil {
		return false
	}
	r.releaseMu.Lock()
	defer r.releaseMu.Unlock()
	return r.coordinator != nil && r.ticket.Valid() && r.state == reservationRestricted &&
		r.releaseRequirement.Restricted()
}

// RequiredRelease returns the exact pending restricted release requirement.
func (r *Reservation) RequiredRelease() ReleaseRequirement {
	if r == nil || r.releaseMu == nil {
		return ""
	}
	r.releaseMu.Lock()
	defer r.releaseMu.Unlock()
	if r.coordinator == nil || !r.ticket.Valid() || r.state != reservationRestricted ||
		!r.releaseRequirement.Restricted() {
		return ""
	}
	return r.releaseRequirement
}

// ReleaseRequirement identifies the sole route proof required after successful signing.
type ReleaseRequirement string

const (
	// ReleaseUnrestricted completes signing without a restricted release phase.
	ReleaseUnrestricted ReleaseRequirement = "unrestricted"
	// ReleaseLocalOnly requires a same-ticket sealed in-control route proof.
	ReleaseLocalOnly ReleaseRequirement = "local_only"
	// ReleaseOutOfBand requires a same-ticket sealed OOB receiver and envelope proof.
	ReleaseOutOfBand ReleaseRequirement = "out_of_band"
)

// Known reports whether requirement belongs to the closed release vocabulary.
func (r ReleaseRequirement) Known() bool {
	return r == ReleaseUnrestricted || r == ReleaseLocalOnly || r == ReleaseOutOfBand
}

// Restricted reports whether successful signing retains an authority release phase.
func (r ReleaseRequirement) Restricted() bool {
	return r == ReleaseLocalOnly || r == ReleaseOutOfBand
}

// RestrictedReleaseProof is an opaque exact-ticket release authorization.
type RestrictedReleaseProof struct {
	requirement ReleaseRequirement
	query       TicketQuery
}

// NewLocalReleaseProof proves one exact in-control route against its sealed ticket.
func NewLocalReleaseProof(ticket CopyTicket, routeScope []byte) (RestrictedReleaseProof, error) {
	if !ticket.Valid() || ticket.binding.routeClass != RouteInControl ||
		len(routeScope) == 0 || !protectedBindingEqual(ticket.binding.route, routeScope) {
		return RestrictedReleaseProof{}, newError(ErrorInvalidRequest)
	}
	return RestrictedReleaseProof{requirement: ReleaseLocalOnly, query: ticket.query()}, nil
}

// NewOutOfBandReleaseProof proves one exact OOB receiver, envelope, and route.
func NewOutOfBandReleaseProof(
	ticket CopyTicket,
	reversePath []byte,
	forwardPaths [][]byte,
	receiverBinding, routeScope []byte,
) (RestrictedReleaseProof, error) {
	if !ticket.Valid() || ticket.binding.routeClass != RouteOutOfBand ||
		len(receiverBinding) == 0 || len(routeScope) == 0 ||
		!ticket.MatchesEnvelope(reversePath, forwardPaths) ||
		!protectedBindingEqual(ticket.binding.outboundReceiver, receiverBinding) ||
		!protectedBindingEqual(ticket.binding.route, routeScope) {
		return RestrictedReleaseProof{}, newError(ErrorInvalidRequest)
	}
	return RestrictedReleaseProof{requirement: ReleaseOutOfBand, query: ticket.query()}, nil
}

// protectedBindingEqual compares opaque route authority evidence without prefix timing.
func protectedBindingEqual(left, right []byte) bool {
	return len(left) == len(right) && len(left) > 0 &&
		subtle.ConstantTimeCompare(left, right) == 1
}

// Valid reports whether the proof binds one exact authority-issued ticket transition.
func (p RestrictedReleaseProof) Valid() bool {
	return p.requirement.Restricted() && p.query.Valid()
}

// Requirement returns the proof's closed restricted-release class.
func (p RestrictedReleaseProof) Requirement() ReleaseRequirement {
	if !p.Valid() {
		return ""
	}
	return p.requirement
}

// String returns a constant secret-safe release-proof summary.
func (p RestrictedReleaseProof) String() string {
	return "routeplan.RestrictedReleaseProof{redacted}"
}

// GoString returns a constant secret-safe release-proof Go representation.
func (p RestrictedReleaseProof) GoString() string { return p.String() }

// Format routes every release-proof formatting form through the redacted summary.
func (p RestrictedReleaseProof) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, p.String())
}

// CommitSuccessfulSigning closes replacement and records the exact release requirement.
func (r *Reservation) CommitSuccessfulSigning(requirement ReleaseRequirement) error {
	if r == nil || r.coordinator == nil || !r.ticket.Valid() || r.releaseMu == nil {
		return newError(ErrorState)
	}
	if !requirement.Known() {
		return newError(ErrorInvalidRequest)
	}
	r.releaseMu.Lock()
	defer r.releaseMu.Unlock()
	if r.state != reservationBurned {
		return newError(ErrorState)
	}
	if !releaseRequirementMatchesRoute(requirement, r.ticket.binding.routeClass) {
		return newError(ErrorInvalidRequest)
	}
	if requirement.Restricted() {
		r.state = reservationRestricted
	} else {
		r.state = reservationCompleted
	}
	r.releaseRequirement = requirement
	return nil
}

// releaseRequirementMatchesRoute prevents restricted output from committing to an ineligible route.
func releaseRequirementMatchesRoute(requirement ReleaseRequirement, routeClass RouteClass) bool {
	switch requirement {
	case ReleaseUnrestricted:
		return routeClass.Known()
	case ReleaseLocalOnly:
		return routeClass == RouteInControl
	case ReleaseOutOfBand:
		return routeClass == RouteOutOfBand
	default:
		return false
	}
}

// String returns a constant secret-safe reservation summary.
func (r Reservation) String() string { return "routeplan.Reservation{redacted}" }

// GoString returns a constant secret-safe reservation Go representation.
func (r Reservation) GoString() string { return r.String() }

// Format routes every reservation formatting form through the redacted summary.
func (r Reservation) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

type reservationState string

const (
	reservationReserved   reservationState = "reserved"
	reservationReleased   reservationState = "released"
	reservationBurned     reservationState = "burned"
	reservationRestricted reservationState = "restricted_release_required"
	reservationReplaced   reservationState = "replacement_issued"
	reservationCompleted  reservationState = "completed"
	reservationConsumed   reservationState = "consumed"
	reservationUnusable   reservationState = "unusable"
)

// ReleaseBeforeBoundary releases a reservation only before any external boundary.
func (r *Reservation) ReleaseBeforeBoundary(ctx context.Context) error {
	if r == nil || r.coordinator == nil || r.state != reservationReserved {
		return newError(ErrorState)
	}
	if ctx == nil {
		return newError(ErrorInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.nextCall(); err != nil {
		return err
	}
	_, committed, err := r.coordinator.call(ctx, methodRelease, r.ticket.query(), AuthorityReleased)
	if committed {
		r.state = reservationReleased
		r.recoveryRequired = false
	}
	if err != nil {
		return err
	}
	return nil
}

// PrepareExternalBoundary burns the ticket before the first non-routeplan callback.
func (r *Reservation) PrepareExternalBoundary(ctx context.Context) error {
	if r == nil || r.coordinator == nil || r.state != reservationReserved {
		return newError(ErrorState)
	}
	if r.recoveryRequired {
		return newError(ErrorState)
	}
	if ctx == nil {
		return newError(ErrorInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		releaseErr := r.ReleaseBeforeBoundary(context.WithoutCancel(ctx))
		if releaseErr != nil {
			return releaseErr
		}
		return err
	}
	if err := r.nextBoundaryCall(); err != nil {
		return err
	}
	_, committed, err := r.coordinator.call(ctx, methodBurn, r.ticket.query(), AuthorityBurned)
	if committed {
		r.state = reservationBurned
	} else if IsErrorCode(err, ErrorContract) {
		r.state = reservationUnusable
	}
	if err != nil {
		return err
	}
	return nil
}

// Replacement requests one fresh same-lineage ticket after a burn.
func (r *Reservation) Replacement(ctx context.Context) (CopyTicket, error) {
	if r == nil || r.coordinator == nil || r.state != reservationBurned {
		return CopyTicket{}, newError(ErrorState)
	}
	if ctx == nil {
		return CopyTicket{}, newError(ErrorInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return CopyTicket{}, err
	}
	if err := r.nextCall(); err != nil {
		return CopyTicket{}, err
	}
	result, committed, err := r.coordinator.call(ctx, methodReplace, r.ticket.query(), AuthorityReplacementIssued)
	if committed {
		if result.ticketIDs[0] == r.ticket.ticketID {
			r.state = reservationUnusable
			return CopyTicket{}, newError(ErrorContract)
		}
		replacement := r.ticket
		replacement.ticketID = result.ticketIDs[0]
		replacement.seal = result.ticketSeals[0]
		r.pendingReplacement = replacement
		r.state = reservationReplaced
	} else if IsErrorCode(err, ErrorContract) {
		r.state = reservationUnusable
	}
	if err != nil {
		return CopyTicket{}, err
	}
	replacement := r.pendingReplacement
	r.pendingReplacement = CopyTicket{}
	return replacement, nil
}

// RecoverReplacement returns a replacement issued before post-call cancellation.
func (r *Reservation) RecoverReplacement() (CopyTicket, error) {
	if r == nil || !r.pendingReplacement.Valid() {
		return CopyTicket{}, newError(ErrorState)
	}
	replacement := r.pendingReplacement
	r.pendingReplacement = CopyTicket{}
	return replacement, nil
}

// ConsumeRestrictedRelease atomically consumes the exact proved release phase.
func (r *Reservation) ConsumeRestrictedRelease(ctx context.Context, proof RestrictedReleaseProof) error {
	if r == nil || r.coordinator == nil || r.releaseMu == nil {
		return newError(ErrorState)
	}
	if ctx == nil {
		return newError(ErrorInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.releaseMu.Lock()
	defer r.releaseMu.Unlock()
	if r.state != reservationRestricted || !r.releaseRequirement.Restricted() ||
		!proof.Valid() || proof.requirement != r.releaseRequirement ||
		proof.query != r.ticket.query() {
		return newError(ErrorState)
	}
	if err := r.nextCall(); err != nil {
		return err
	}
	_, committed, err := r.coordinator.call(ctx, methodConsume, r.ticket.query(), AuthorityConsumed)
	if committed {
		r.state = reservationConsumed
	} else if IsErrorCode(err, ErrorContract) {
		r.state = reservationUnusable
	}
	if err != nil {
		return err
	}
	return nil
}

// nextCall enforces the separate route-authority call budget.
func (r *Reservation) nextCall() error {
	if r.calls >= r.coordinator.limits.MaxAuthorityCalls {
		return newLimitError(r.calls + 1)
	}
	r.calls++
	return nil
}

// nextBoundaryCall preserves one final callback for mandatory pre-boundary release recovery.
func (r *Reservation) nextBoundaryCall() error {
	if r.calls >= r.coordinator.limits.MaxAuthorityCalls-1 {
		return newLimitError(r.calls + 1)
	}
	r.calls++
	return nil
}

// call validates context and a method-specific authority result matrix.
func (c Coordinator) call(ctx context.Context, method authorityMethod, query TicketQuery, success AuthorityStatus) (AuthorityResult, bool, error) {
	if ctx == nil {
		return AuthorityResult{}, false, newError(ErrorInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return AuthorityResult{}, false, err
	}
	var result AuthorityResult
	var err error
	switch method {
	case methodReserve:
		result, err = c.authority.Reserve(ctx, query)
	case methodRelease:
		result, err = c.authority.ReleaseReservation(ctx, query)
	case methodBurn:
		result, err = c.authority.Burn(ctx, query)
	case methodReplace:
		result, err = c.authority.Replace(ctx, query)
	case methodConsume:
		result, err = c.authority.ConsumeRelease(ctx, query)
	default:
		return AuthorityResult{}, false, newError(ErrorContract)
	}
	expectedIDs := 0
	if success == AuthorityReplacementIssued {
		expectedIDs = 1
	}
	ctxErr := ctx.Err()
	if ctxErr != nil && err != nil && isZeroAuthorityResult(result) && errors.Is(err, ctxErr) {
		return AuthorityResult{}, false, ctxErr
	}
	if validationErr := validateAuthorityResult(result, err, success, expectedIDs); validationErr != nil {
		if ctxErr != nil && validAuthorityOutcomeError(validationErr) {
			return AuthorityResult{}, false, ctxErr
		}
		return AuthorityResult{}, false, validationErr
	}
	if !transitionAcknowledgementMatches(result, query) {
		return AuthorityResult{}, false, newError(ErrorContract)
	}
	if ctxErr != nil {
		return result, true, ctxErr
	}
	return result, true, nil
}

// validAuthorityOutcomeError identifies valid non-success callback pairs before post-call cancellation.
func validAuthorityOutcomeError(err error) bool {
	return IsErrorCode(err, ErrorDenied) || IsErrorCode(err, ErrorTemporary) || IsErrorCode(err, ErrorPermanent)
}

// isZeroAuthorityResult reports the only legal result paired with control-flow/provider errors.
func isZeroAuthorityResult(result AuthorityResult) bool {
	return result.status == "" && result.parentID == [sha256.Size]byte{} && result.parentSeal == [sha256.Size]byte{} &&
		len(result.ticketIDs) == 0 && len(result.ticketSeals) == 0 && len(result.bindingIDs) == 0 &&
		!result.hasQuery && result.query == (TicketQuery{})
}

// finalizeAcknowledgementMatches validates exact ordered binding ownership.
func finalizeAcknowledgementMatches(result AuthorityResult, query FinalizeQuery) bool {
	if result.hasQuery || result.query != (TicketQuery{}) || len(result.bindingIDs) != len(query.bindings) {
		return false
	}
	for index := range query.bindings {
		if subtle.ConstantTimeCompare(result.bindingIDs[index][:], query.bindings[index].digest[:]) != 1 {
			return false
		}
	}
	return true
}

// transitionAcknowledgementMatches validates the exact parent, ticket, and binding query.
func transitionAcknowledgementMatches(result AuthorityResult, query TicketQuery) bool {
	return result.hasQuery && result.query == query && result.parentID == query.parentID && len(result.bindingIDs) == 0
}

// validTicket proves ticket integrity before any authority call.
func (c Coordinator) validTicket(ticket CopyTicket) bool {
	return ticket.Valid()
}

// query projects one exact ticket state transition binding.
func (t CopyTicket) query() TicketQuery {
	return TicketQuery{parentID: t.parentID, ticketID: t.ticketID, binding: t.binding.digest, seal: t.seal}
}

// bindingDigest constructs an unambiguous versioned exact-copy transcript.
func bindingDigest(binding routeBinding) [sha256.Size]byte {
	h := sha256.New()
	writePart(h, []byte(transcriptDomain))
	writePart(h, binding.sourceDigest[:])
	writePart(h, []byte(binding.purpose))
	writePart(h, binding.reversePath)
	writeCount(h, len(binding.forwardPaths))
	for _, path := range binding.forwardPaths {
		writePart(h, path)
	}
	writePart(h, []byte(binding.disclosure))
	writePart(h, []byte(binding.routeClass))
	writePart(h, binding.route)
	writePart(h, binding.inboundReceiver)
	writePart(h, binding.outboundReceiver)
	writePart(h, binding.revision)
	writeCount(h, binding.total)
	var result [sha256.Size]byte
	copy(result[:], h.Sum(nil))
	return result
}

// digestSource hashes exact bytes once per explicit immutable source identity.
func digestSource(raw []byte) [sha256.Size]byte {
	h := sha256.New()
	writePart(h, []byte("dkim2/route-source/v1"))
	writePart(h, raw)
	var result [sha256.Size]byte
	copy(result[:], h.Sum(nil))
	return result
}

// descriptorSize uses the same framed components as the exact route binding.
func descriptorSize(binding routeBinding) int {
	counter := &countWriter{}
	writePart(counter, []byte("dkim2/route-descriptor/v1"))
	writePart(counter, binding.sourceDigest[:])
	writePart(counter, []byte(binding.purpose))
	writePart(counter, binding.reversePath)
	writeCount(counter, len(binding.forwardPaths))
	for _, path := range binding.forwardPaths {
		writePart(counter, path)
	}
	writePart(counter, []byte(binding.disclosure))
	writePart(counter, []byte(binding.routeClass))
	writePart(counter, binding.route)
	writePart(counter, binding.inboundReceiver)
	writePart(counter, binding.outboundReceiver)
	writePart(counter, binding.revision)
	writeCount(counter, binding.total)
	// Parent and ticket identities are fixed-size authority output fields.
	writePart(counter, make([]byte, sha256.Size))
	writePart(counter, make([]byte, sha256.Size))
	return counter.total
}

type countWriter struct{ total int }

// Write counts canonical descriptor bytes with checked saturation.
func (w *countWriter) Write(value []byte) (int, error) {
	if w.total > math.MaxInt-len(value) {
		w.total = math.MaxInt
		return len(value), nil
	}
	w.total += len(value)
	return len(value), nil
}

// writePart writes a presence marker and length-prefixed transcript component.
func writePart(w io.Writer, value []byte) {
	var length [binary.MaxVarintLen64]byte
	if value == nil {
		_, _ = w.Write([]byte{0})
		return
	}
	_, _ = w.Write([]byte{1})
	n := binary.PutUvarint(length[:], uint64(len(value)))
	_, _ = w.Write(length[:n])
	_, _ = w.Write(value)
}

// writeCount writes one nonnegative count with an explicit marker.
func writeCount(w io.Writer, count int) {
	var encoded [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(encoded[:], uint64(count))
	writePart(w, encoded[:n])
}

// validateAuthorityResult enforces exact success, denial, error, identity, and alias matrices.
func validateAuthorityResult(result AuthorityResult, err error, expected AuthorityStatus, count int) error {
	if err != nil {
		return validateAuthorityFailure(result, err)
	}
	if result.status == AuthorityDenied {
		return validateAuthorityDenial(result)
	}
	if result.status != expected || result.parentID == [sha256.Size]byte{} || len(result.ticketIDs) != count {
		return newError(ErrorContract)
	}
	if err := validateAuthorityShape(result, expected, count); err != nil {
		return err
	}
	return validateAuthorityIdentities(result)
}

// validateAuthorityFailure enforces zero-result typed provider failure pairs.
func validateAuthorityFailure(result AuthorityResult, err error) error {
	if isTypedNilError(err) || !isZeroAuthorityResult(result) {
		return newError(ErrorContract)
	}
	switch provider.ClassOf(err) {
	case provider.FailureTemporary:
		return newError(ErrorTemporary)
	case provider.FailurePermanent:
		return newError(ErrorPermanent)
	default:
		return newError(ErrorContract)
	}
}

// validateAuthorityDenial enforces the only legal policy-denial result shape.
func validateAuthorityDenial(result AuthorityResult) error {
	if result.parentID != [sha256.Size]byte{} || result.parentSeal != [sha256.Size]byte{} ||
		len(result.ticketIDs) != 0 || len(result.ticketSeals) != 0 ||
		len(result.bindingIDs) != 0 || result.hasQuery || result.query != (TicketQuery{}) {
		return newError(ErrorContract)
	}
	return newError(ErrorDenied)
}

// validateAuthorityShape enforces method-specific seal and acknowledgement cardinality.
func validateAuthorityShape(result AuthorityResult, expected AuthorityStatus, count int) error {
	if expected == AuthorityIssued {
		if result.parentSeal == [sha256.Size]byte{} || result.hasQuery || result.query != (TicketQuery{}) ||
			len(result.bindingIDs) != count || len(result.ticketSeals) != count {
			return newError(ErrorContract)
		}
		return nil
	}
	if result.parentSeal != [sha256.Size]byte{} || !result.hasQuery ||
		result.query == (TicketQuery{}) || len(result.bindingIDs) != 0 || len(result.ticketSeals) != count {
		return newError(ErrorContract)
	}
	return nil
}

// validateAuthorityIdentities rejects zero, aliased, duplicated, or unsealed ticket identities.
func validateAuthorityIdentities(result AuthorityResult) error {
	seen := make(map[[sha256.Size]byte]struct{}, len(result.ticketIDs))
	for index, id := range result.ticketIDs {
		if id == [sha256.Size]byte{} || id == result.parentID {
			return newError(ErrorContract)
		}
		if result.ticketSeals[index] == [sha256.Size]byte{} {
			return newError(ErrorContract)
		}
		if _, duplicate := seen[id]; duplicate {
			return newError(ErrorContract)
		}
		seen[id] = struct{}{}
	}
	return nil
}

// MemoryAuthority is a concurrency-safe reference authority for library use and tests.
type MemoryAuthority struct {
	mu      sync.Mutex
	parents map[[sha256.Size]byte]struct{}
	tickets map[[sha256.Size]byte]*authorityTicket
	sealKey [sha256.Size]byte
	nextID  authorityIDGenerator
}

type authorityIDGenerator func() ([sha256.Size]byte, bool)

// String returns a constant secret-safe authority summary.
func (a *MemoryAuthority) String() string { return "routeplan.MemoryAuthority{redacted}" }

// GoString returns a constant secret-safe authority Go representation.
func (a *MemoryAuthority) GoString() string { return a.String() }

// Format routes every authority formatting form through the redacted summary.
func (a *MemoryAuthority) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, a.String()) }

type authorityTicket struct {
	parent, binding, lineage, seal [sha256.Size]byte
	state                          authorityTicketState
}

type authorityTicketState string

const (
	ticketFresh    authorityTicketState = "fresh"
	ticketReserved authorityTicketState = "reserved"
	ticketReleased authorityTicketState = "released"
	ticketBurned   authorityTicketState = "burned"
	ticketReplaced authorityTicketState = "replaced"
	ticketConsumed authorityTicketState = "consumed"
)

// NewMemoryAuthority constructs an empty authority state owner.
func NewMemoryAuthority() *MemoryAuthority {
	return newMemoryAuthorityWithEntropy(randomID, randomID)
}

// newMemoryAuthorityWithEntropy constructs an authority while rejecting partial secret entropy.
func newMemoryAuthorityWithEntropy(nextID, sealEntropy authorityIDGenerator) *MemoryAuthority {
	sealKey, complete := sealEntropy()
	if !complete {
		sealKey = [sha256.Size]byte{}
	}
	return newMemoryAuthority(nextID, sealKey)
}

// newMemoryAuthority constructs an authority with injectable identity entropy for invariant tests.
func newMemoryAuthority(nextID authorityIDGenerator, sealKey [sha256.Size]byte) *MemoryAuthority {
	return &MemoryAuthority{
		parents: make(map[[sha256.Size]byte]struct{}), tickets: make(map[[sha256.Size]byte]*authorityTicket),
		sealKey: sealKey, nextID: nextID,
	}
}

// Finalize atomically issues one parent and exactly one unique ticket per binding.
func (a *MemoryAuthority) Finalize(ctx context.Context, query FinalizeQuery) (AuthorityResult, error) {
	if err := authorityContext(ctx); err != nil {
		return AuthorityResult{}, err
	}
	if a == nil || query.Count() == 0 || !query.usage.Valid() || query.Count() != query.usage.Tickets {
		return NewAuthorityResult(AuthorityDenied, [sha256.Size]byte{}, nil), nil
	}
	if a.sealKey == [sha256.Size]byte{} {
		return AuthorityResult{}, provider.NewFailure(provider.FailurePermanent)
	}
	if a.nextID == nil {
		return AuthorityResult{}, provider.NewFailure(provider.FailureContract)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	parent, ok := a.nextID()
	if !ok {
		return AuthorityResult{}, provider.NewFailure(provider.FailurePermanent)
	}
	ids := make([][sha256.Size]byte, len(query.bindings))
	seals := make([][sha256.Size]byte, len(query.bindings))
	records := make([]*authorityTicket, len(ids))
	for index, binding := range query.bindings {
		id, generated := a.nextID()
		if !generated {
			return AuthorityResult{}, provider.NewFailure(provider.FailurePermanent)
		}
		ids[index] = id
		seals[index] = a.ticketAuthoritySeal(parent, id, binding.digest)
		records[index] = &authorityTicket{
			parent: parent, binding: binding.digest, lineage: id, seal: seals[index], state: ticketFresh,
		}
	}
	if _, collision := a.parents[parent]; collision {
		return AuthorityResult{}, provider.NewFailure(provider.FailureContract)
	}
	if _, collision := a.tickets[parent]; collision {
		return AuthorityResult{}, provider.NewFailure(provider.FailureContract)
	}
	seen := make(map[[sha256.Size]byte]struct{}, len(ids))
	for _, id := range ids {
		if id == parent {
			return AuthorityResult{}, provider.NewFailure(provider.FailureContract)
		}
		if _, collision := a.tickets[id]; collision {
			return AuthorityResult{}, provider.NewFailure(provider.FailureContract)
		}
		if _, collision := a.parents[id]; collision {
			return AuthorityResult{}, provider.NewFailure(provider.FailureContract)
		}
		if _, duplicate := seen[id]; duplicate {
			return AuthorityResult{}, provider.NewFailure(provider.FailureContract)
		}
		seen[id] = struct{}{}
	}
	a.parents[parent] = struct{}{}
	for index, id := range ids {
		a.tickets[id] = records[index]
	}
	return NewFinalizeAuthorityResult(query, parent, a.parentAuthoritySeal(parent, query), ids, seals), nil
}

// Reserve atomically moves one fresh ticket to reserved.
func (a *MemoryAuthority) Reserve(ctx context.Context, query TicketQuery) (AuthorityResult, error) {
	return a.transition(ctx, query, AuthorityReserved, ticketReserved, ticketFresh, ticketReleased)
}

// ReleaseReservation atomically moves a pre-boundary reservation to the released retry state.
// Releasing the same authority-sealed ticket is idempotent so callers can
// reconcile a committed release whose acknowledgement was lost or malformed.
func (a *MemoryAuthority) ReleaseReservation(ctx context.Context, query TicketQuery) (AuthorityResult, error) {
	if err := authorityContext(ctx); err != nil {
		return AuthorityResult{}, err
	}
	if a == nil {
		return AuthorityResult{}, provider.NewFailure(provider.FailureContract)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	record, ok := a.match(query)
	if !ok || record.state != ticketReserved && record.state != ticketReleased {
		return NewAuthorityResult(AuthorityDenied, [sha256.Size]byte{}, nil), nil
	}
	record.state = ticketReleased
	return NewTransitionAuthorityResult(AuthorityReleased, query, nil, nil), nil
}

// Burn atomically consumes retryability before an external callback.
func (a *MemoryAuthority) Burn(ctx context.Context, query TicketQuery) (AuthorityResult, error) {
	return a.transition(ctx, query, AuthorityBurned, ticketBurned, ticketReserved)
}

// Replace atomically issues one fresh same-lineage replacement for a burned ticket.
func (a *MemoryAuthority) Replace(ctx context.Context, query TicketQuery) (AuthorityResult, error) {
	if err := authorityContext(ctx); err != nil {
		return AuthorityResult{}, err
	}
	if a == nil {
		return AuthorityResult{}, provider.NewFailure(provider.FailureContract)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	record, ok := a.match(query)
	if !ok || record.state != ticketBurned {
		return NewAuthorityResult(AuthorityDenied, [sha256.Size]byte{}, nil), nil
	}
	if a.nextID == nil {
		return AuthorityResult{}, provider.NewFailure(provider.FailureContract)
	}
	id, generated := a.nextID()
	if !generated || id == query.ticketID {
		if !generated {
			return AuthorityResult{}, provider.NewFailure(provider.FailurePermanent)
		}
		return AuthorityResult{}, provider.NewFailure(provider.FailureContract)
	}
	if _, collision := a.tickets[id]; collision {
		return AuthorityResult{}, provider.NewFailure(provider.FailureContract)
	}
	if _, collision := a.parents[id]; collision {
		return AuthorityResult{}, provider.NewFailure(provider.FailureContract)
	}
	record.state = ticketReplaced
	replacementSeal := a.ticketAuthoritySeal(record.parent, id, record.binding)
	a.tickets[id] = &authorityTicket{
		parent: record.parent, binding: record.binding, lineage: record.lineage,
		seal: replacementSeal, state: ticketFresh,
	}
	return NewTransitionAuthorityResult(
		AuthorityReplacementIssued, query, [][sha256.Size]byte{id}, [][sha256.Size]byte{replacementSeal},
	), nil
}

// ConsumeRelease atomically consumes one burned ticket's restricted release phase.
func (a *MemoryAuthority) ConsumeRelease(ctx context.Context, query TicketQuery) (AuthorityResult, error) {
	return a.transition(ctx, query, AuthorityConsumed, ticketConsumed, ticketBurned)
}

// transition applies one exact ticket state transition.
func (a *MemoryAuthority) transition(
	ctx context.Context,
	query TicketQuery,
	status AuthorityStatus,
	to authorityTicketState,
	from ...authorityTicketState,
) (AuthorityResult, error) {
	if err := authorityContext(ctx); err != nil {
		return AuthorityResult{}, err
	}
	if a == nil {
		return AuthorityResult{}, provider.NewFailure(provider.FailureContract)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	record, ok := a.match(query)
	if !ok || !slices.Contains(from, record.state) {
		return NewAuthorityResult(AuthorityDenied, [sha256.Size]byte{}, nil), nil
	}
	record.state = to
	return NewTransitionAuthorityResult(status, query, nil, nil), nil
}

// match validates parent, ticket, and exact pre-sign binding identity.
func (a *MemoryAuthority) match(query TicketQuery) (*authorityTicket, bool) {
	record, ok := a.tickets[query.ticketID]
	return record, ok && record.parent == query.parentID && record.binding == query.binding &&
		subtle.ConstantTimeCompare(record.seal[:], query.seal[:]) == 1
}

// parentAuthoritySeal issues one authority-owned opaque parent capability seal.
func (a *MemoryAuthority) parentAuthoritySeal(parentID [sha256.Size]byte, query FinalizeQuery) [sha256.Size]byte {
	h := hmac.New(sha256.New, a.sealKey[:])
	writePart(h, []byte("dkim2/route-authority-parent/v1"))
	writePart(h, parentID[:])
	for _, binding := range query.bindings {
		writePart(h, binding.digest[:])
	}
	var seal [sha256.Size]byte
	copy(seal[:], h.Sum(nil))
	return seal
}

// ticketAuthoritySeal issues one authority-owned opaque exact-ticket seal.
func (a *MemoryAuthority) ticketAuthoritySeal(parentID, ticketID, binding [sha256.Size]byte) [sha256.Size]byte {
	h := hmac.New(sha256.New, a.sealKey[:])
	writePart(h, []byte("dkim2/route-authority-ticket/v1"))
	writePart(h, parentID[:])
	writePart(h, ticketID[:])
	writePart(h, binding[:])
	var seal [sha256.Size]byte
	copy(seal[:], h.Sum(nil))
	return seal
}

// authorityContext validates caller control flow without string classification.
func authorityContext(ctx context.Context) error {
	if ctx == nil {
		return provider.NewFailure(provider.FailureContract)
	}
	return ctx.Err()
}

// randomID returns one nonzero opaque authority identity.
func randomID() ([sha256.Size]byte, bool) {
	var id [sha256.Size]byte
	_, err := io.ReadFull(rand.Reader, id[:])
	return id, err == nil && id != [sha256.Size]byte{}
}

// checkedCharge adds one nonnegative charge without overflow or partial mutation.
func checkedCharge(total *int, amount, limit int) bool {
	if total == nil || amount < 0 || *total < 0 || *total > math.MaxInt-amount || *total+amount > limit {
		return false
	}
	*total += amount
	return true
}

// validPath accepts only bounded ASCII bracketed RFC 5321 path evidence.
func validPath(path []byte, allowNull bool) bool {
	for _, value := range path {
		if value > 0x7f {
			return false
		}
	}
	return signature.ValidEnvelopePath(path, allowNull)
}

// pathComparisonKey preserves local-part case and folds only ASCII domain letters.
func pathComparisonKey(path []byte) string {
	cloned := bytes.Clone(path)
	at := bytes.LastIndexByte(cloned, '@')
	for index := at + 1; index < len(cloned)-1; index++ {
		if cloned[index] >= 'A' && cloned[index] <= 'Z' {
			cloned[index] += 'a' - 'A'
		}
	}
	return string(cloned)
}

// cloneSlices returns detached nested bytes.
func cloneSlices(input [][]byte) [][]byte {
	output := make([][]byte, len(input))
	for index := range input {
		output[index] = bytes.Clone(input[index])
	}
	return output
}

// cloneBindings returns detached ordered route bindings.
func cloneBindings(input []routeBinding) []routeBinding {
	output := slices.Clone(input)
	for index := range output {
		output[index].reversePath = bytes.Clone(output[index].reversePath)
		output[index].forwardPaths = cloneSlices(output[index].forwardPaths)
		output[index].route = bytes.Clone(output[index].route)
		output[index].inboundReceiver = bytes.Clone(output[index].inboundReceiver)
		output[index].outboundReceiver = bytes.Clone(output[index].outboundReceiver)
		output[index].revision = bytes.Clone(output[index].revision)
	}
	return output
}

// isNilInterface rejects nil and typed-nil injected dependencies.
func isNilInterface(value any) bool {
	return niliface.IsNil(value)
}

// isTypedNilError detects an error interface containing a nil pointer.
func isTypedNilError(err error) bool { return err != nil && isNilInterface(err) }
