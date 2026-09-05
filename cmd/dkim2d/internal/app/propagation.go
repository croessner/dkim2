package app

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
)

const (
	propagationRedacted = "dkim2d_propagation"
	// PropagationOperation is the closed operation value of the route.
	PropagationOperation = "delivery_status_propagation"
	// maxPropagationReportingMTABytes bounds the canonical reporting name.
	maxPropagationReportingMTABytes = 253
)

// PropagationResultClass is the closed result vocabulary of the propagation route.
type PropagationResultClass string

const (
	// PropagationPass reports a coherent completed evaluation.
	PropagationPass PropagationResultClass = "pass"
	// PropagationFail reports a notification that must not be propagated and must surface.
	PropagationFail PropagationResultClass = "fail"
	// PropagationPermerror reports a permanent local inability to propagate.
	PropagationPermerror PropagationResultClass = "permerror"
	// PropagationTemperror reports a retryable condition.
	PropagationTemperror PropagationResultClass = "temperror"
)

// Known reports whether the result belongs to the closed vocabulary.
func (r PropagationResultClass) Known() bool {
	switch r {
	case PropagationPass, PropagationFail, PropagationPermerror, PropagationTemperror:
		return true
	default:
		return false
	}
}

// PropagationDispositionClass is the closed propagation disposition vocabulary.
// It is distinct from the shared operation disposition because propagation
// adds discard and never uses continue.
type PropagationDispositionClass string

const (
	// PropagationDispositionAccept authorizes re-injection of the signed notification.
	PropagationDispositionAccept PropagationDispositionClass = "accept"
	// PropagationDispositionReject refuses the notification permanently.
	PropagationDispositionReject PropagationDispositionClass = "reject"
	// PropagationDispositionDiscard accepts responsibility without producing output.
	PropagationDispositionDiscard PropagationDispositionClass = "discard"
	// PropagationDispositionTempfail defers the notification.
	PropagationDispositionTempfail PropagationDispositionClass = "tempfail"
)

// Known reports whether the disposition belongs to the closed vocabulary.
func (d PropagationDispositionClass) Known() bool {
	switch d {
	case PropagationDispositionAccept, PropagationDispositionReject,
		PropagationDispositionDiscard, PropagationDispositionTempfail:
		return true
	default:
		return false
	}
}

// PropagationFailureClass is the closed permanent propagation-failure vocabulary.
type PropagationFailureClass string

const (
	// PropagationFailureNone reports that no permanent failure applies.
	PropagationFailureNone PropagationFailureClass = ""
	// PropagationFailureNotReconstructable reports a state the rebuild could not prove.
	PropagationFailureNotReconstructable PropagationFailureClass = "not_reconstructable"
	// PropagationFailureUnprovisionedDomain reports a local domain without a delivery-status profile.
	PropagationFailureUnprovisionedDomain PropagationFailureClass = "unprovisioned_domain"
)

// Known reports whether the failure class belongs to the closed vocabulary.
func (f PropagationFailureClass) Known() bool {
	switch f {
	case PropagationFailureNone, PropagationFailureNotReconstructable,
		PropagationFailureUnprovisionedDomain:
		return true
	default:
		return false
	}
}

// validPropagationOutcome enforces this operation's own coherence rule: pass
// permits accept or discard, permerror requires discard, fail requires
// reject, and temperror requires tempfail. Only accept carries a signed
// notification and only permerror carries a failure class.
func validPropagationOutcome(
	result PropagationResultClass,
	disposition PropagationDispositionClass,
	failure PropagationFailureClass,
	signed bool,
) bool {
	if !result.Known() || !disposition.Known() || !failure.Known() {
		return false
	}
	if (failure != PropagationFailureNone) != (result == PropagationPermerror) {
		return false
	}
	if signed != (disposition == PropagationDispositionAccept) {
		return false
	}
	switch result {
	case PropagationPass:
		return disposition == PropagationDispositionAccept ||
			disposition == PropagationDispositionDiscard
	case PropagationFail:
		return disposition == PropagationDispositionReject
	case PropagationPermerror:
		return disposition == PropagationDispositionDiscard
	case PropagationTemperror:
		return disposition == PropagationDispositionTempfail
	default:
		return false
	}
}

// validPropagationProjection enforces where an absent projection is coherent.
// Only the two outcomes that stop before the evaluation may omit it: a
// notification that carries no DKIM2 field family at all, which is a
// permanent refusal, and an unusable outer assessment, which is temporary.
// Every other outcome is reached through a completed evaluation and must
// carry its closed projection.
func validPropagationProjection(
	projection DeliveryStatusProjection,
	result PropagationResultClass,
) bool {
	if projection.Valid() {
		return true
	}
	return projection.Absent() &&
		(result == PropagationFail || result == PropagationTemperror)
}

// DeliveryStatusProjection is the immutable closed received-DSN projection
// shared by the process and propagation routes. It is read-only evidence and
// can never authorize a signing operation.
type DeliveryStatusProjection struct {
	structure        dkim2.ReceivedDSNStructure
	embedded         dkim2.ReceivedDSNEmbedded
	localHop         dkim2.ReceivedDSNLocalHop
	outerAlignment   dkim2.ReceivedDSNOuterAlignment
	recipientLinkage dkim2.ReceivedDSNRecipientLinkage
	propagation      dkim2.ReceivedDSNPropagation
	valid            bool
}

// NewDeliveryStatusProjection seals one library evaluation into the closed
// daemon projection. Every member must belong to its closed vocabulary.
func NewDeliveryStatusProjection(
	evaluation dkim2.ReceivedDSNEvaluation,
) (DeliveryStatusProjection, error) {
	if !evaluation.Valid() {
		return DeliveryStatusProjection{}, &DomainError{}
	}
	projection := DeliveryStatusProjection{
		structure:        evaluation.Structure(),
		embedded:         evaluation.Embedded(),
		localHop:         evaluation.LocalHop(),
		outerAlignment:   evaluation.OuterAlignment(),
		recipientLinkage: evaluation.RecipientLinkage(),
		propagation:      evaluation.Propagation(),
		valid:            true,
	}
	if !projection.Valid() {
		return DeliveryStatusProjection{}, &DomainError{}
	}
	return projection, nil
}

// NewClosedDeliveryStatusProjection seals one projection from its six closed
// members. It exists for the daemon-owned sources of a projection that are
// not a library evaluation, and it refuses any member outside its closed
// vocabulary, so no caller can assemble evidence the library never produced.
func NewClosedDeliveryStatusProjection(
	structure dkim2.ReceivedDSNStructure,
	embedded dkim2.ReceivedDSNEmbedded,
	localHop dkim2.ReceivedDSNLocalHop,
	outerAlignment dkim2.ReceivedDSNOuterAlignment,
	recipientLinkage dkim2.ReceivedDSNRecipientLinkage,
	propagation dkim2.ReceivedDSNPropagation,
) (DeliveryStatusProjection, error) {
	projection := DeliveryStatusProjection{
		structure: structure, embedded: embedded, localHop: localHop,
		outerAlignment: outerAlignment, recipientLinkage: recipientLinkage,
		propagation: propagation, valid: true,
	}
	if !projection.Valid() {
		return DeliveryStatusProjection{}, &DomainError{}
	}
	return projection, nil
}

// Valid reports whether every member belongs to its closed vocabulary.
func (p DeliveryStatusProjection) Valid() bool {
	return p.valid && p.structure.Known() && p.embedded.Known() && p.localHop.Known() &&
		p.outerAlignment.Known() && p.recipientLinkage.Known() && p.propagation.Known()
}

// Absent reports the zero projection, which carries no evidence at all. It is
// the only representation of an evaluation that never ran: the closed
// vocabularies hold no "not assessed" value for structure, so a fabricated
// member would be false evidence rather than a missing one.
func (p DeliveryStatusProjection) Absent() bool {
	return p == DeliveryStatusProjection{}
}

// Structure returns the closed RFC 6522 and RFC 3464 structure member.
func (p DeliveryStatusProjection) Structure() dkim2.ReceivedDSNStructure { return p.structure }

// Embedded returns the closed embedded-original verification member.
func (p DeliveryStatusProjection) Embedded() dkim2.ReceivedDSNEmbedded { return p.embedded }

// LocalHop returns the closed local-hop identity member.
func (p DeliveryStatusProjection) LocalHop() dkim2.ReceivedDSNLocalHop { return p.localHop }

// OuterAlignment returns the closed outer-signer alignment member.
func (p DeliveryStatusProjection) OuterAlignment() dkim2.ReceivedDSNOuterAlignment {
	return p.outerAlignment
}

// RecipientLinkage returns the closed RFC 3464 recipient-linkage member.
func (p DeliveryStatusProjection) RecipientLinkage() dkim2.ReceivedDSNRecipientLinkage {
	return p.recipientLinkage
}

// Propagation returns the closed informational propagation member.
func (p DeliveryStatusProjection) Propagation() dkim2.ReceivedDSNPropagation {
	return p.propagation
}

// String returns a content-free projection representation.
func (DeliveryStatusProjection) String() string { return propagationRedacted }

// GoString returns a content-free projection representation.
func (DeliveryStatusProjection) GoString() string { return propagationRedacted }

// Format prevents formatting from traversing the projection members.
func (DeliveryStatusProjection) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, propagationRedacted)
}

// PropagationRequest carries one validated propagation input. The signing
// domain is never a member: it is derived from the authenticated completion
// signature of the removed local hop run.
type PropagationRequest struct {
	state *propagationRequestState
}

// propagationRequestState stores the immutable private request values.
type propagationRequestState struct {
	raw             []byte
	outerReverse    []byte
	outerRecipients [][]byte
	smtputf8        bool
	tenant          string
	reportingMTA    string
	fidelity        MessageFidelity
}

// AdmitsPropagationFidelity reports whether the propagation route may consume
// the declared representation. A locally delivered notification reaches the
// adapter over LMTP, which is acceptable evidence for verification and
// propagation but is not a claim of unmodified raw submission bytes.
func AdmitsPropagationFidelity(fidelity MessageFidelity) bool {
	return fidelity == FidelityRawRFC5322 || fidelity == FidelityLMTPDeliveredCRLF
}

// NewPropagationRequest snapshots one validated propagation request. The
// observed reverse path must be null, exactly one forward path must be
// present, a tenant is mandatory because propagation without locality is
// meaningless, and the reporting name must be canonical.
func NewPropagationRequest(
	raw, outerReverse []byte,
	outerRecipients [][]byte,
	smtputf8 bool,
	tenant, reportingMTA string,
	fidelity MessageFidelity,
) (PropagationRequest, error) {
	if len(raw) == 0 || !bytes.Equal(outerReverse, []byte("<>")) ||
		len(outerRecipients) != 1 || len(outerRecipients[0]) == 0 ||
		!config.ValidTenant(tenant) || !AdmitsPropagationFidelity(fidelity) ||
		len(reportingMTA) > maxPropagationReportingMTABytes ||
		!canonicalAuthorityDomain(reportingMTA) {
		return PropagationRequest{}, &DomainError{}
	}
	return PropagationRequest{state: &propagationRequestState{
		raw:             bytes.Clone(raw),
		outerReverse:    bytes.Clone(outerReverse),
		outerRecipients: cloneOperationRecipients(outerRecipients),
		smtputf8:        smtputf8,
		tenant:          tenant,
		reportingMTA:    reportingMTA,
		fidelity:        fidelity,
	}}, nil
}

// Valid reports whether the request passed its owning constructor.
func (r PropagationRequest) Valid() bool { return r.state != nil }

// RawMessage returns an isolated exact received-notification snapshot.
func (r PropagationRequest) RawMessage() []byte {
	if r.state == nil {
		return nil
	}
	return bytes.Clone(r.state.raw)
}

// OuterReversePath returns the exact observed null reverse path.
func (r PropagationRequest) OuterReversePath() []byte {
	if r.state == nil {
		return nil
	}
	return bytes.Clone(r.state.outerReverse)
}

// OuterRecipients returns the single isolated observed forward path.
func (r PropagationRequest) OuterRecipients() [][]byte {
	if r.state == nil {
		return nil
	}
	return cloneOperationRecipients(r.state.outerRecipients)
}

// SMTPUTF8 reports whether the delivering MAIL command carried the parameter.
func (r PropagationRequest) SMTPUTF8() bool { return r.state != nil && r.state.smtputf8 }

// Tenant returns the bounded administrative tenant.
func (r PropagationRequest) Tenant() string {
	if r.state == nil {
		return ""
	}
	return r.state.tenant
}

// ReportingMTA returns the canonical reporting name rendered into the report.
func (r PropagationRequest) ReportingMTA() string {
	if r.state == nil {
		return ""
	}
	return r.state.reportingMTA
}

// Fidelity returns the admitted representation claim.
func (r PropagationRequest) Fidelity() MessageFidelity {
	if r.state == nil {
		return ""
	}
	return r.state.fidelity
}

// String returns a content-free propagation-request representation.
func (PropagationRequest) String() string { return propagationRedacted }

// GoString returns a content-free propagation-request representation.
func (PropagationRequest) GoString() string { return propagationRedacted }

// Format prevents formatting from traversing message and envelope data.
func (PropagationRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, propagationRedacted)
}

// MarshalJSON rejects serialization of propagation request evidence.
func (PropagationRequest) MarshalJSON() ([]byte, error) { return nil, &DomainError{} }

// MarshalText rejects diagnostic serialization of propagation request evidence.
func (PropagationRequest) MarshalText() ([]byte, error) { return nil, &DomainError{} }

// PropagationOutput carries the signed notification and everything the caller
// needs to re-inject it and to commit the reserved coordinate.
type PropagationOutput struct {
	state *propagationOutputState
}

// propagationOutputState stores the immutable private output values.
type propagationOutputState struct {
	raw             []byte
	nextHop         []byte
	commitToken     string
	smtputf8        bool
	eightBitMIME    bool
	signingDomainOK bool
}

// Valid reports whether the output carries a complete signed notification.
func (o PropagationOutput) Valid() bool {
	return o.state != nil && len(o.state.raw) > 0 && len(o.state.nextHop) > 0 &&
		o.state.commitToken != "" && o.state.signingDomainOK
}

// RawMessage returns an isolated copy of the signed notification bytes.
func (o PropagationOutput) RawMessage() []byte {
	if !o.Valid() {
		return nil
	}
	return bytes.Clone(o.state.raw)
}

// NextHopRecipient returns the authenticated previous-hop forward path.
func (o PropagationOutput) NextHopRecipient() []byte {
	if !o.Valid() {
		return nil
	}
	return bytes.Clone(o.state.nextHop)
}

// CommitToken returns the opaque coordinate-bound commit token.
func (o PropagationOutput) CommitToken() string {
	if !o.Valid() {
		return ""
	}
	return o.state.commitToken
}

// SMTPUTF8Required reports whether re-injection needs the SMTPUTF8 extension.
func (o PropagationOutput) SMTPUTF8Required() bool { return o.Valid() && o.state.smtputf8 }

// EightBitMIMERequired reports whether re-injection needs the 8BITMIME extension.
func (o PropagationOutput) EightBitMIMERequired() bool { return o.Valid() && o.state.eightBitMIME }

// String returns a content-free propagation-output representation.
func (PropagationOutput) String() string { return propagationRedacted }

// GoString returns a content-free propagation-output representation.
func (PropagationOutput) GoString() string { return propagationRedacted }

// Format prevents formatting from traversing signed message bytes.
func (PropagationOutput) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, propagationRedacted)
}

// MarshalJSON rejects serialization of signed notification bytes.
func (PropagationOutput) MarshalJSON() ([]byte, error) { return nil, &DomainError{} }

// MarshalText rejects diagnostic serialization of signed notification bytes.
func (PropagationOutput) MarshalText() ([]byte, error) { return nil, &DomainError{} }

// PropagationResult is one immutable coherent propagation outcome.
type PropagationResult struct {
	state *propagationResultState
}

// propagationResultState stores the immutable private result values.
type propagationResultState struct {
	result      PropagationResultClass
	disposition PropagationDispositionClass
	failure     PropagationFailureClass
	projection  DeliveryStatusProjection
	replay      ReplayResultClass
	output      PropagationOutput
}

// NewPropagationResult seals one coherent propagation outcome. It refuses
// every result, disposition, failure, and output combination outside this
// operation's own coherence rule.
func NewPropagationResult(
	result PropagationResultClass,
	disposition PropagationDispositionClass,
	failure PropagationFailureClass,
	projection DeliveryStatusProjection,
	replay ReplayResultClass,
	output PropagationOutput,
) (PropagationResult, error) {
	if !validPropagationProjection(projection, result) || !replay.Known() ||
		!validPropagationOutcome(result, disposition, failure, output.Valid()) {
		return PropagationResult{}, &DomainError{}
	}
	return PropagationResult{state: &propagationResultState{
		result: result, disposition: disposition, failure: failure,
		projection: projection, replay: replay, output: output,
	}}, nil
}

// Valid reports whether the result passed its owning constructor.
func (r PropagationResult) Valid() bool {
	return r.state != nil && r.state.replay.Known() &&
		validPropagationProjection(r.state.projection, r.state.result) &&
		validPropagationOutcome(r.state.result, r.state.disposition, r.state.failure,
			r.state.output.Valid())
}

// Result returns the closed result class.
func (r PropagationResult) Result() PropagationResultClass {
	if !r.Valid() {
		return ""
	}
	return r.state.result
}

// Disposition returns the closed propagation disposition.
func (r PropagationResult) Disposition() PropagationDispositionClass {
	if !r.Valid() {
		return ""
	}
	return r.state.disposition
}

// Failure returns the closed permanent failure class, empty outside permerror.
func (r PropagationResult) Failure() PropagationFailureClass {
	if !r.Valid() {
		return PropagationFailureNone
	}
	return r.state.failure
}

// Projection returns the closed received-DSN projection. It is absent when
// the outcome was decided before the evaluation ran.
func (r PropagationResult) Projection() DeliveryStatusProjection {
	if !r.Valid() {
		return DeliveryStatusProjection{}
	}
	return r.state.projection
}

// Replay returns the closed replay aggregate of the propagation coordinate.
func (r PropagationResult) Replay() ReplayResultClass {
	if !r.Valid() {
		return ReplayResultNotChecked
	}
	return r.state.replay
}

// Output returns the signed notification, present only with accept.
func (r PropagationResult) Output() (PropagationOutput, bool) {
	if !r.Valid() || !r.state.output.Valid() {
		return PropagationOutput{}, false
	}
	return r.state.output, true
}

// String returns a content-free propagation-result representation.
func (PropagationResult) String() string { return propagationRedacted }

// GoString returns a content-free propagation-result representation.
func (PropagationResult) GoString() string { return propagationRedacted }

// Format prevents formatting from traversing the signed notification.
func (PropagationResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, propagationRedacted)
}

// MarshalJSON rejects serialization outside the package-owned response mapper.
func (PropagationResult) MarshalJSON() ([]byte, error) { return nil, &DomainError{} }

// MarshalText rejects diagnostic serialization of propagation results.
func (PropagationResult) MarshalText() ([]byte, error) { return nil, &DomainError{} }

// PropagationCommitState is the closed outcome of one commit attempt.
type PropagationCommitState string

const (
	// PropagationCommitCommitted reports a coordinate that is now committed,
	// whether by this call or by an earlier one.
	PropagationCommitCommitted PropagationCommitState = "committed"
	// PropagationCommitUnresolved reports a token that resolves to no pending
	// or committed coordinate within retention. The route answers 409 so that
	// the caller defers instead of leaving the coordinate uncommitted.
	PropagationCommitUnresolved PropagationCommitState = "unresolved"
)

// Known reports whether the commit state belongs to the closed vocabulary.
func (s PropagationCommitState) Known() bool {
	return s == PropagationCommitCommitted || s == PropagationCommitUnresolved
}

// PropagationService is the narrow two-phase propagation application seam.
type PropagationService interface {
	Propagate(context.Context, PropagationRequest) (PropagationResult, error)
	CommitPropagation(context.Context, string) (PropagationCommitState, error)
}
