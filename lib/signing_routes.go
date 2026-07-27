package dkim2

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/provider"
	"github.com/croessner/dkim2/internal/routeplan"
	"github.com/croessner/dkim2/internal/signing"
)

// RouteDisclosure identifies one closed recipient-disclosure shape.
type RouteDisclosure string

const (
	// RouteDisclosureSingle identifies one ordinary disclosed recipient.
	RouteDisclosureSingle RouteDisclosure = "single"
	// RouteDisclosureAuthorizedGroup identifies an explicitly authorized recipient group.
	RouteDisclosureAuthorizedGroup RouteDisclosure = "authorized_group"
	// RouteDisclosureBccSeparated identifies a privacy-preserving one-recipient copy.
	RouteDisclosureBccSeparated RouteDisclosure = "bcc_separated"
)

// Known reports whether the disclosure belongs to the closed route vocabulary.
func (d RouteDisclosure) Known() bool {
	return d == RouteDisclosureSingle || d == RouteDisclosureAuthorizedGroup || d == RouteDisclosureBccSeparated
}

// SigningSource is one immutable exact pre-sign RFC 5322 source identity.
type SigningSource struct{ value routeplan.ImmutableSource }

// NewSigningSource snapshots exact pre-sign RFC 5322 bytes for fanout planning.
func NewSigningSource(rawMessage []byte) (SigningSource, error) {
	value, err := routeplan.NewImmutableSource(rawMessage)
	if err != nil {
		return SigningSource{}, mapRouteError(err)
	}
	return SigningSource{value: value}, nil
}

// Valid reports whether the source owns initialized exact bytes.
func (s SigningSource) Valid() bool { return s.value.Valid() }

// String returns a constant secret-safe source summary.
func (s SigningSource) String() string { return "dkim2.SigningSource{redacted}" }

// GoString returns the constant secret-safe source Go representation.
func (s SigningSource) GoString() string { return s.String() }

// Format routes every source formatting form through the redacted summary.
func (s SigningSource) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, s.String()) }

// RouteEntry is one immutable intended signing output copy.
type RouteEntry struct{ value routeplan.Entry }

// NewOriginatorRouteEntry constructs one exact originator route descriptor.
func NewOriginatorRouteEntry(source SigningSource, reversePath []byte, forwardPaths [][]byte, disclosure RouteDisclosure, routeScope []byte) (RouteEntry, error) {
	value, err := routeplan.NewEntry(
		source.value, routeplan.PurposeOrigin, reversePath, forwardPaths,
		routeplan.DisclosureClass(disclosure), routeScope, nil,
	)
	if err != nil {
		return RouteEntry{}, mapRouteError(err)
	}
	return RouteEntry{value: value}, nil
}

// NewExistingRouteEntry constructs one exact forwarding or revision route
// descriptor bound to a verified revision capability.
func NewExistingRouteEntry(capability VerifiedRevisionInput, source SigningSource, reversePath []byte, forwardPaths [][]byte, disclosure RouteDisclosure, routeScope []byte) (RouteEntry, error) {
	value, err := signing.NewBoundRouteEntry(
		capability.value, source.value, routeplan.PurposeRevision, reversePath,
		forwardPaths, routeplan.DisclosureClass(disclosure), routeScope,
	)
	if err != nil {
		return RouteEntry{}, mapSigningError(err)
	}
	return RouteEntry{value: value}, nil
}

// NewInControlExistingRouteEntry constructs an existing-message route eligible
// for local-only release; inbound receiver evidence is required exactly for
// terminal next-domain completion and absent for ordinary predecessors.
func NewInControlExistingRouteEntry(
	capability VerifiedRevisionInput,
	source SigningSource,
	reversePath []byte,
	forwardPaths [][]byte,
	disclosure RouteDisclosure,
	routeScope, receiverBinding []byte,
) (RouteEntry, error) {
	value, err := signing.NewClassifiedBoundRouteEntry(
		capability.value, source.value, routeplan.PurposeRevision,
		reversePath, forwardPaths, routeplan.DisclosureClass(disclosure),
		routeplan.RouteInControl, routeScope, receiverBinding,
	)
	if err != nil {
		return RouteEntry{}, mapSigningError(err)
	}
	return RouteEntry{value: value}, nil
}

// NewReceiverBoundExistingRouteEntry constructs an ordinary external route
// carrying exact inbound OOB receiver-transaction evidence for nd completion.
func NewReceiverBoundExistingRouteEntry(
	capability VerifiedRevisionInput,
	source SigningSource,
	reversePath []byte,
	forwardPaths [][]byte,
	disclosure RouteDisclosure,
	routeScope, receiverBinding []byte,
) (RouteEntry, error) {
	value, err := signing.NewClassifiedBoundRouteEntry(
		capability.value, source.value, routeplan.PurposeRevision,
		reversePath, forwardPaths, routeplan.DisclosureClass(disclosure),
		routeplan.RouteExternal, routeScope, receiverBinding,
	)
	if err != nil {
		return RouteEntry{}, mapSigningError(err)
	}
	return RouteEntry{value: value}, nil
}

// NewNextDomainRouteEntry constructs one outbound-only OOB route for creating
// a terminal nd= signature from an ordinary predecessor.
func NewNextDomainRouteEntry(
	capability VerifiedRevisionInput,
	source SigningSource,
	reversePath []byte,
	forwardPaths [][]byte,
	disclosure RouteDisclosure,
	routeScope, receiverBinding []byte,
) (RouteEntry, error) {
	value, err := signing.NewClassifiedBoundRouteEntry(
		capability.value, source.value, routeplan.PurposeNextDomain,
		reversePath, forwardPaths, routeplan.DisclosureClass(disclosure),
		routeplan.RouteOutOfBand, routeScope, receiverBinding,
	)
	if err != nil {
		return RouteEntry{}, mapSigningError(err)
	}
	return RouteEntry{value: value}, nil
}

// NewNextDomainContinuationRouteEntry constructs one exact terminal nd= route
// with independently sealed inbound and outbound OOB receiver evidence.
func NewNextDomainContinuationRouteEntry(
	capability VerifiedRevisionInput,
	source SigningSource,
	reversePath []byte,
	forwardPaths [][]byte,
	disclosure RouteDisclosure,
	routeScope, inboundReceiverBinding, outboundReceiverBinding []byte,
) (RouteEntry, error) {
	value, err := signing.NewDualReceiverClassifiedBoundRouteEntry(
		capability.value, source.value, routeplan.PurposeNextDomain,
		reversePath, forwardPaths, routeplan.DisclosureClass(disclosure),
		routeplan.RouteOutOfBand, routeScope,
		inboundReceiverBinding, outboundReceiverBinding,
	)
	if err != nil {
		return RouteEntry{}, mapSigningError(err)
	}
	return RouteEntry{value: value}, nil
}

// String returns a constant secret-safe route-entry summary.
func (e RouteEntry) String() string { return "dkim2.RouteEntry{redacted}" }

// GoString returns the constant secret-safe route-entry Go representation.
func (e RouteEntry) GoString() string { return e.String() }

// Format routes every route-entry formatting form through the redacted summary.
func (e RouteEntry) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, e.String()) }

// RouteFanoutRequest snapshots one complete ordered collection of intended copies.
type RouteFanoutRequest struct{ value routeplan.PlanRequest }

// NewRouteFanoutRequest constructs a complete immutable fanout request.
func NewRouteFanoutRequest(entries []RouteEntry) (RouteFanoutRequest, error) {
	values := make([]routeplan.Entry, len(entries))
	for index := range entries {
		values[index] = entries[index].value
	}
	value, err := routeplan.NewPlanRequest(values)
	if err != nil {
		return RouteFanoutRequest{}, mapRouteError(err)
	}
	return RouteFanoutRequest{value: value}, nil
}

// String returns a constant secret-safe fanout-request summary.
func (r RouteFanoutRequest) String() string { return "dkim2.RouteFanoutRequest{redacted}" }

// GoString returns the constant secret-safe fanout-request Go representation.
func (r RouteFanoutRequest) GoString() string { return r.String() }

// Format routes every request formatting form through the redacted summary.
func (r RouteFanoutRequest) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// RouteFanoutPlan is the immutable finalized parent route plan.
type RouteFanoutPlan struct{ value routeplan.RouteFanoutPlan }

// Valid reports whether the plan carries a coherent authority seal.
func (p RouteFanoutPlan) Valid() bool { return p.value.Valid() }

// CopyCount returns the exact finalized multiplicity.
func (p RouteFanoutPlan) CopyCount() int { return p.value.CopyCount() }

// String returns a constant secret-safe route-plan summary.
func (p RouteFanoutPlan) String() string { return "dkim2.RouteFanoutPlan{redacted}" }

// GoString returns the constant secret-safe route-plan Go representation.
func (p RouteFanoutPlan) GoString() string { return p.String() }

// Format routes every plan formatting form through the redacted summary.
func (p RouteFanoutPlan) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, p.String()) }

// RouteCopyTicket is one immutable non-reusable exact-copy capability.
type RouteCopyTicket struct{ value routeplan.CopyTicket }

// Valid reports whether the ticket carries a coherent authority seal.
func (t RouteCopyTicket) Valid() bool { return t.value.Valid() }

// TotalMultiplicity returns the sealed parent fanout copy count.
func (t RouteCopyTicket) TotalMultiplicity() int { return t.value.TotalMultiplicity() }

// String returns a constant secret-safe ticket summary.
func (t RouteCopyTicket) String() string { return "dkim2.RouteCopyTicket{redacted}" }

// GoString returns the constant secret-safe ticket Go representation.
func (t RouteCopyTicket) GoString() string { return t.String() }

// Format routes every ticket formatting form through the redacted summary.
func (t RouteCopyTicket) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, t.String()) }

// RouteAuthorityStatus identifies a method-specific authority outcome.
type RouteAuthorityStatus string

const (
	// RouteAuthorityIssued reports successful parent and ticket issuance.
	RouteAuthorityIssued RouteAuthorityStatus = "issued"
	// RouteAuthorityReserved reports successful atomic reservation.
	RouteAuthorityReserved RouteAuthorityStatus = "reserved"
	// RouteAuthorityReleased reports successful pre-boundary release.
	RouteAuthorityReleased RouteAuthorityStatus = "released"
	// RouteAuthorityBurned reports successful external-boundary commitment.
	RouteAuthorityBurned RouteAuthorityStatus = "burned"
	// RouteAuthorityReplacementIssued reports successful same-lineage replacement.
	RouteAuthorityReplacementIssued RouteAuthorityStatus = "replacement_issued"
	// RouteAuthorityConsumed reports successful restricted release consumption.
	RouteAuthorityConsumed RouteAuthorityStatus = "consumed"
	// RouteAuthorityDenied reports a content-free authority denial.
	RouteAuthorityDenied RouteAuthorityStatus = "denied"
)

// Known reports whether status belongs to the closed route authority vocabulary.
func (s RouteAuthorityStatus) Known() bool {
	return routeplan.AuthorityStatus(s).Known()
}

// RouteFinalizeQuery carries only opaque exact fanout bindings to an authority.
type RouteFinalizeQuery struct{ value routeplan.FinalizeQuery }

// Count returns the coupled copy and ticket count.
func (q RouteFinalizeQuery) Count() int { return q.value.Count() }

// Valid reports whether the query has a complete authority-bound shape.
func (q RouteFinalizeQuery) Valid() bool { return q.value.Valid() }

// BindingDigest returns a detached exact binding digest by ordered index.
func (q RouteFinalizeQuery) BindingDigest(index int) []byte { return q.value.BindingDigest(index) }

// String returns a constant secret-safe query summary.
func (q RouteFinalizeQuery) String() string { return "dkim2.RouteFinalizeQuery{redacted}" }

// GoString returns the constant secret-safe query Go representation.
func (q RouteFinalizeQuery) GoString() string { return q.String() }

// Format routes every query formatting form through the redacted summary.
func (q RouteFinalizeQuery) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, q.String()) }

// RouteTicketQuery carries only opaque exact ticket-transition identities.
type RouteTicketQuery struct{ value routeplan.TicketQuery }

// Valid reports whether every opaque transition identity is present.
func (q RouteTicketQuery) Valid() bool { return q.value.Valid() }

// ParentIdentity returns the opaque parent identity.
func (q RouteTicketQuery) ParentIdentity() [sha256.Size]byte { return q.value.ParentIdentity() }

// TicketIdentity returns the opaque ticket identity.
func (q RouteTicketQuery) TicketIdentity() [sha256.Size]byte { return q.value.TicketIdentity() }

// BindingIdentity returns the opaque exact-copy binding.
func (q RouteTicketQuery) BindingIdentity() [sha256.Size]byte { return q.value.BindingIdentity() }

// CapabilitySeal returns the opaque authority-issued ticket seal.
func (q RouteTicketQuery) CapabilitySeal() [sha256.Size]byte { return q.value.CapabilitySeal() }

// String returns a constant secret-safe query summary.
func (q RouteTicketQuery) String() string { return "dkim2.RouteTicketQuery{redacted}" }

// GoString returns the constant secret-safe query Go representation.
func (q RouteTicketQuery) GoString() string { return q.String() }

// Format routes every query formatting form through the redacted summary.
func (q RouteTicketQuery) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, q.String()) }

// RouteAuthorityResult is one closed authority callback result.
type RouteAuthorityResult struct{ value routeplan.AuthorityResult }

// NewRouteIssuedResult constructs exact fanout issuance bound to the supplied query.
func NewRouteIssuedResult(query RouteFinalizeQuery, parentID, parentSeal [sha256.Size]byte, ticketIDs, ticketSeals [][sha256.Size]byte) RouteAuthorityResult {
	return RouteAuthorityResult{value: routeplan.NewFinalizeAuthorityResult(
		query.value, parentID, parentSeal, ticketIDs, ticketSeals,
	)}
}

// NewRouteTransitionResult constructs an exact ticket transition acknowledgement.
func NewRouteTransitionResult(status RouteAuthorityStatus, query RouteTicketQuery, replacementIDs, replacementSeals [][sha256.Size]byte) RouteAuthorityResult {
	return RouteAuthorityResult{value: routeplan.NewTransitionAuthorityResult(
		routeplan.AuthorityStatus(status), query.value, replacementIDs, replacementSeals,
	)}
}

// RouteDeniedResult constructs the sole content-free authority denial.
func RouteDeniedResult() RouteAuthorityResult {
	return RouteAuthorityResult{value: routeplan.NewAuthorityResult(routeplan.AuthorityDenied, [sha256.Size]byte{}, nil)}
}

// IsZero reports whether no authority outcome was declared.
func (r RouteAuthorityResult) IsZero() bool { return r.value.Status() == "" }

// String returns a constant secret-safe authority-result summary.
func (r RouteAuthorityResult) String() string { return "dkim2.RouteAuthorityResult{redacted}" }

// GoString returns the constant secret-safe authority-result Go representation.
func (r RouteAuthorityResult) GoString() string { return r.String() }

// Format routes every result formatting form through the redacted summary.
func (r RouteAuthorityResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// RouteFanoutAuthority owns issuance and atomic ticket transitions.
type RouteFanoutAuthority interface {
	Finalize(context.Context, RouteFinalizeQuery) (RouteAuthorityResult, error)
	Reserve(context.Context, RouteTicketQuery) (RouteAuthorityResult, error)
	ReleaseReservation(context.Context, RouteTicketQuery) (RouteAuthorityResult, error)
	Burn(context.Context, RouteTicketQuery) (RouteAuthorityResult, error)
	Replace(context.Context, RouteTicketQuery) (RouteAuthorityResult, error)
	ConsumeRelease(context.Context, RouteTicketQuery) (RouteAuthorityResult, error)
}

type requestRouteAuthority struct {
	value *routeplan.MemoryAuthority
}

// NewRequestRouteAuthority constructs one operation-scoped in-memory route
// authority. Callers must create a fresh value per request and discard it
// after the resulting signing operation completes.
func NewRequestRouteAuthority() RouteFanoutAuthority {
	return &requestRouteAuthority{value: routeplan.NewMemoryAuthority()}
}

// Finalize issues one bounded request-local route plan.
func (a *requestRouteAuthority) Finalize(
	ctx context.Context,
	query RouteFinalizeQuery,
) (RouteAuthorityResult, error) {
	if a == nil || a.value == nil {
		return RouteAuthorityResult{}, newSigningError(SigningErrorInvalidRequest)
	}
	result, err := a.value.Finalize(ctx, query.value)
	return RouteAuthorityResult{value: result}, err
}

// Reserve reserves one request-local route ticket.
func (a *requestRouteAuthority) Reserve(
	ctx context.Context,
	query RouteTicketQuery,
) (RouteAuthorityResult, error) {
	if a == nil || a.value == nil {
		return RouteAuthorityResult{}, newSigningError(SigningErrorInvalidRequest)
	}
	result, err := a.value.Reserve(ctx, query.value)
	return RouteAuthorityResult{value: result}, err
}

// ReleaseReservation releases one pre-boundary request-local reservation.
func (a *requestRouteAuthority) ReleaseReservation(
	ctx context.Context,
	query RouteTicketQuery,
) (RouteAuthorityResult, error) {
	if a == nil || a.value == nil {
		return RouteAuthorityResult{}, newSigningError(SigningErrorInvalidRequest)
	}
	result, err := a.value.ReleaseReservation(ctx, query.value)
	return RouteAuthorityResult{value: result}, err
}

// Burn commits one request-local route ticket at the external boundary.
func (a *requestRouteAuthority) Burn(
	ctx context.Context,
	query RouteTicketQuery,
) (RouteAuthorityResult, error) {
	if a == nil || a.value == nil {
		return RouteAuthorityResult{}, newSigningError(SigningErrorInvalidRequest)
	}
	result, err := a.value.Burn(ctx, query.value)
	return RouteAuthorityResult{value: result}, err
}

// Replace acknowledges one same-lineage request-local replacement.
func (a *requestRouteAuthority) Replace(
	ctx context.Context,
	query RouteTicketQuery,
) (RouteAuthorityResult, error) {
	if a == nil || a.value == nil {
		return RouteAuthorityResult{}, newSigningError(SigningErrorInvalidRequest)
	}
	result, err := a.value.Replace(ctx, query.value)
	return RouteAuthorityResult{value: result}, err
}

// ConsumeRelease consumes one restricted request-local release.
func (a *requestRouteAuthority) ConsumeRelease(
	ctx context.Context,
	query RouteTicketQuery,
) (RouteAuthorityResult, error) {
	if a == nil || a.value == nil {
		return RouteAuthorityResult{}, newSigningError(SigningErrorInvalidRequest)
	}
	result, err := a.value.ConsumeRelease(ctx, query.value)
	return RouteAuthorityResult{value: result}, err
}

type routeAuthorityBridge struct{ authority RouteFanoutAuthority }

// Finalize adapts one public fanout issuance callback.
func (b routeAuthorityBridge) Finalize(ctx context.Context, query routeplan.FinalizeQuery) (routeplan.AuthorityResult, error) {
	return b.callFinalize(ctx, query)
}

// callFinalize validates and adapts one public fanout issuance callback.
func (b routeAuthorityBridge) callFinalize(ctx context.Context, query routeplan.FinalizeQuery) (routeplan.AuthorityResult, error) {
	if nilSigningCallback(b.authority) || !query.Valid() {
		return routeplan.AuthorityResult{}, provider.NewFailure(provider.FailureContract)
	}
	result, err := b.authority.Finalize(ctx, RouteFinalizeQuery{value: query})
	return bridgeRouteResult(ctx, result, err)
}

// Reserve adapts one public reserve transition callback.
func (b routeAuthorityBridge) Reserve(ctx context.Context, query routeplan.TicketQuery) (routeplan.AuthorityResult, error) {
	if nilSigningCallback(b.authority) || !query.Valid() {
		return routeplan.AuthorityResult{}, provider.NewFailure(provider.FailureContract)
	}
	result, err := b.authority.Reserve(ctx, RouteTicketQuery{value: query})
	return bridgeRouteResult(ctx, result, err)
}

// ReleaseReservation adapts one public pre-boundary release callback.
func (b routeAuthorityBridge) ReleaseReservation(ctx context.Context, query routeplan.TicketQuery) (routeplan.AuthorityResult, error) {
	if nilSigningCallback(b.authority) || !query.Valid() {
		return routeplan.AuthorityResult{}, provider.NewFailure(provider.FailureContract)
	}
	result, err := b.authority.ReleaseReservation(ctx, RouteTicketQuery{value: query})
	return bridgeRouteResult(ctx, result, err)
}

// Burn adapts one public external-boundary transition callback.
func (b routeAuthorityBridge) Burn(ctx context.Context, query routeplan.TicketQuery) (routeplan.AuthorityResult, error) {
	if nilSigningCallback(b.authority) || !query.Valid() {
		return routeplan.AuthorityResult{}, provider.NewFailure(provider.FailureContract)
	}
	result, err := b.authority.Burn(ctx, RouteTicketQuery{value: query})
	return bridgeRouteResult(ctx, result, err)
}

// Replace adapts one public same-lineage replacement callback.
func (b routeAuthorityBridge) Replace(ctx context.Context, query routeplan.TicketQuery) (routeplan.AuthorityResult, error) {
	if nilSigningCallback(b.authority) || !query.Valid() {
		return routeplan.AuthorityResult{}, provider.NewFailure(provider.FailureContract)
	}
	result, err := b.authority.Replace(ctx, RouteTicketQuery{value: query})
	return bridgeRouteResult(ctx, result, err)
}

// ConsumeRelease adapts one public restricted-release transition callback.
func (b routeAuthorityBridge) ConsumeRelease(ctx context.Context, query routeplan.TicketQuery) (routeplan.AuthorityResult, error) {
	if nilSigningCallback(b.authority) || !query.Valid() {
		return routeplan.AuthorityResult{}, provider.NewFailure(provider.FailureContract)
	}
	result, err := b.authority.ConsumeRelease(ctx, RouteTicketQuery{value: query})
	return bridgeRouteResult(ctx, result, err)
}

// bridgeRouteResult preserves the exact closed result/error matrix.
func bridgeRouteResult(ctx context.Context, result RouteAuthorityResult, err error) (routeplan.AuthorityResult, error) {
	if err != nil {
		if !result.IsZero() {
			return routeplan.AuthorityResult{}, provider.NewFailure(provider.FailureContract)
		}
		return routeplan.AuthorityResult{}, bridgeProviderError(ctx, err)
	}
	return result.value, nil
}

// mapRouteError translates route failures into the bounded public signing vocabulary.
func mapRouteError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	switch {
	case routeplan.IsErrorCode(err, routeplan.ErrorInvalidOptions):
		return newSigningError(SigningErrorInvalidOptions)
	case routeplan.IsErrorCode(err, routeplan.ErrorInvalidRequest), routeplan.IsErrorCode(err, routeplan.ErrorState):
		return newSigningError(SigningErrorInvalidRequest)
	case routeplan.IsErrorCode(err, routeplan.ErrorLimitExceeded):
		return newSigningError(SigningErrorLimitExceeded)
	case routeplan.IsErrorCode(err, routeplan.ErrorDenied):
		return newSigningError(SigningErrorAuthorizationDenied)
	case routeplan.IsErrorCode(err, routeplan.ErrorTemporary):
		return newSigningError(SigningErrorCallbackTemporary)
	case routeplan.IsErrorCode(err, routeplan.ErrorPermanent):
		return newSigningError(SigningErrorCallbackPermanent)
	default:
		return newSigningError(SigningErrorInternalInvariant)
	}
}
