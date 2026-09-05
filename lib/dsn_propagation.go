package dkim2

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/dsn"
	"github.com/croessner/dkim2/internal/keyresolver"
	"github.com/croessner/dkim2/internal/niliface"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/routeplan"
	"github.com/croessner/dkim2/internal/signing"
	"github.com/croessner/dkim2/internal/verify"
)

const (
	dsnPropagationRequestRedactedText        = "dkim2.DSNPropagationRequest{redacted}"
	dsnPropagationEvidenceRedactedText       = "dkim2.DSNPropagationEvidence{redacted}"
	dsnPropagationSigningRequestRedactedText = "dkim2.DSNPropagationSigningRequest{redacted}"
	propagatedDSNRedactedText                = "dkim2.PropagatedDSN{redacted}"
	// propagationMessageIDEntropyBytes is the random material behind one Message-ID token.
	propagationMessageIDEntropyBytes = 16
)

// DSNPropagationStage identifies one closed content-free propagation stage.
type DSNPropagationStage string

const (
	// DSNPropagationStagePreflight identifies invalid signer or request state.
	DSNPropagationStagePreflight DSNPropagationStage = "preflight"
	// DSNPropagationStageEvaluation identifies the received-DSN evaluation.
	DSNPropagationStageEvaluation DSNPropagationStage = "evaluation"
	// DSNPropagationStageRebuild identifies the Section 12.1.1 rebuild.
	DSNPropagationStageRebuild DSNPropagationStage = "rebuild"
	// DSNPropagationStageSigning identifies the propagation signing operation.
	DSNPropagationStageSigning DSNPropagationStage = "signing"
)

// Known reports whether the stage belongs to the closed vocabulary.
func (s DSNPropagationStage) Known() bool {
	switch s {
	case DSNPropagationStagePreflight, DSNPropagationStageEvaluation, DSNPropagationStageRebuild, DSNPropagationStageSigning:
		return true
	default:
		return false
	}
}

// DSNPropagationError preserves only a closed failure stage while exposing
// the caller context error or the public signing error through errors.Unwrap.
type DSNPropagationError struct {
	stage DSNPropagationStage
	cause error
}

// Error returns a bounded diagnostic without message, envelope, or identity data.
func (e *DSNPropagationError) Error() string {
	if e == nil || !e.stage.Known() {
		return "dkim2 dsn propagation error"
	}
	return "dkim2 dsn propagation error: stage=" + string(e.stage)
}

// Unwrap preserves context and signing error classification.
func (e *DSNPropagationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Stage returns the closed failure stage or the zero value.
func (e *DSNPropagationError) Stage() DSNPropagationStage {
	if e == nil || !e.stage.Known() {
		return ""
	}
	return e.stage
}

// Format routes every formatting verb through the bounded diagnostic.
func (e *DSNPropagationError) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, e.Error())
}

// DSNPropagationStageOf returns the closed stage only for a typed propagation failure.
func DSNPropagationStageOf(err error) DSNPropagationStage {
	var typed *DSNPropagationError
	if errors.As(err, &typed) {
		return typed.Stage()
	}
	return ""
}

// newDSNPropagationError binds a closed stage to an existing bounded cause.
func newDSNPropagationError(stage DSNPropagationStage, cause error) error {
	if !stage.Known() || cause == nil {
		return newSigningError(SigningErrorInternalInvariant)
	}
	return &DSNPropagationError{stage: stage, cause: cause}
}

// DSNPropagationOutcome is the closed result of one rebuild attempt.
type DSNPropagationOutcome string

const (
	// DSNPropagationRebuilt reports an unsigned Section 12.1.1 report ready for SignPropagatedDSN.
	DSNPropagationRebuilt DSNPropagationOutcome = "rebuilt"
	// DSNPropagationNotEligible reports an evaluation whose propagation projection is not eligible.
	DSNPropagationNotEligible DSNPropagationOutcome = "not_eligible"
	// DSNPropagationNotReconstructable reports a rebuild that could not prove or render the previous state.
	DSNPropagationNotReconstructable DSNPropagationOutcome = "not_reconstructable"
	// DSNPropagationTemporaryError reports a temporary key failure while verifying the previous hop.
	DSNPropagationTemporaryError DSNPropagationOutcome = "temperror"
)

// Known reports whether the outcome belongs to the closed vocabulary.
func (o DSNPropagationOutcome) Known() bool {
	switch o {
	case DSNPropagationRebuilt, DSNPropagationNotEligible, DSNPropagationNotReconstructable, DSNPropagationTemporaryError:
		return true
	default:
		return false
	}
}

// DSNPropagationRequest carries cloned received-DSN bytes, the observed null
// reverse path and single forward path, the tenant-bound local authority, and
// the canonical reporting MTA name rendered into the rebuilt report.
type DSNPropagationRequest struct {
	state *dsnPropagationRequestState
}

// dsnPropagationRequestState stores the immutable private request values.
// entropy is the source of the fresh report identifier; it is nil for every
// public request, which selects crypto/rand, and is set only by in-package
// vector tests so that rebuilt reports can be pinned byte-exact.
type dsnPropagationRequestState struct {
	raw          []byte
	reversePath  []byte
	forwardPaths [][]byte
	authority    LocalAuthority
	reportingMTA string
	entropy      io.Reader
}

// identifierEntropy returns the request's identifier entropy source.
func (s *dsnPropagationRequestState) identifierEntropy() io.Reader {
	if s.entropy == nil {
		return rand.Reader
	}
	return s.entropy
}

// NewDSNPropagationRequest snapshots one propagation request. The authority
// is mandatory because propagation without locality is meaningless.
func NewDSNPropagationRequest(raw, reversePath []byte, forwardPaths [][]byte, authority LocalAuthority, reportingMTA string) DSNPropagationRequest {
	state := &dsnPropagationRequestState{
		raw: bytes.Clone(raw), reversePath: bytes.Clone(reversePath), forwardPaths: cloneByteSlices(forwardPaths), reportingMTA: reportingMTA,
	}
	if !niliface.IsNil(authority) {
		state.authority = authority
	}
	return DSNPropagationRequest{state: state}
}

// String prevents raw DSN or envelope content from reaching diagnostics.
func (DSNPropagationRequest) String() string { return dsnPropagationRequestRedactedText }

// GoString returns the constant secret-safe request representation.
func (r DSNPropagationRequest) GoString() string { return r.String() }

// Format routes every request formatting form through the redacted representation.
func (r DSNPropagationRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// MarshalJSON rejects serialization of message or envelope bytes.
func (DSNPropagationRequest) MarshalJSON() ([]byte, error) {
	return nil, newSigningError(SigningErrorInvalidRequest)
}

// MarshalText rejects diagnostic serialization of message or envelope bytes.
func (DSNPropagationRequest) MarshalText() ([]byte, error) {
	return nil, newSigningError(SigningErrorInvalidRequest)
}

// DSNPropagationEvidence is the immutable outcome of RebuildDSNForPropagation.
// It carries the received-DSN evaluation, the closed rebuild outcome, and,
// for a rebuilt report, the unsigned report, the signing domain proven by the
// removed completion signature, and the authenticated next-hop recipient. No
// accessor exposes the report bytes before signing.
type DSNPropagationEvidence struct {
	state *dsnPropagationEvidenceState
}

// dsnPropagationEvidenceState stores the sealed evidence values.
type dsnPropagationEvidenceState struct {
	evaluation ReceivedDSNEvaluation
	outcome    DSNPropagationOutcome
	report     dsn.RebuiltReport
	instant    verify.RevisionInstant
}

// Valid reports whether the evidence was issued by RebuildDSNForPropagation and is coherent.
func (e DSNPropagationEvidence) Valid() bool {
	if e.state == nil || !e.state.outcome.Known() || !e.state.evaluation.Valid() {
		return false
	}
	if e.state.outcome == DSNPropagationRebuilt {
		return e.state.report.Valid() && e.state.report.Outcome() == dsn.RebuildRebuilt && e.state.instant.Valid()
	}
	return true
}

// Evaluation returns the received-DSN evaluation the rebuild was based on.
func (e DSNPropagationEvidence) Evaluation() ReceivedDSNEvaluation {
	if e.state == nil {
		return ReceivedDSNEvaluation{}
	}
	return e.state.evaluation
}

// Outcome returns the closed rebuild outcome.
func (e DSNPropagationEvidence) Outcome() DSNPropagationOutcome {
	if e.state == nil {
		return ""
	}
	return e.state.outcome
}

// Rebuilt reports whether an unsigned report is ready for SignPropagatedDSN.
func (e DSNPropagationEvidence) Rebuilt() bool {
	return e.Valid() && e.state.outcome == DSNPropagationRebuilt
}

// SigningDomain returns the canonical d= of the removed completion signature or an empty string.
func (e DSNPropagationEvidence) SigningDomain() string {
	if !e.Rebuilt() {
		return ""
	}
	return e.state.report.SigningDomain()
}

// NextHopRecipient returns a detached copy of the exact bracketed previous-hop mf= or nil.
func (e DSNPropagationEvidence) NextHopRecipient() []byte {
	if !e.Rebuilt() {
		return nil
	}
	return e.state.report.NextHopRecipient()
}

// SMTPUTF8Required reports whether any header field of the rebuilt DSN,
// including the embedded original's header block and the To: field carrying
// the next-hop path, contains a non-ASCII byte; an 8-bit body alone does not set it.
func (e DSNPropagationEvidence) SMTPUTF8Required() bool {
	return e.Rebuilt() && e.state.report.SMTPUTF8Required()
}

// EightBitMIMERequired reports whether the embedded original's body contains
// a non-ASCII byte, which is an 8BITMIME question for the re-injection client.
func (e DSNPropagationEvidence) EightBitMIMERequired() bool {
	return e.Rebuilt() && e.state.report.EightBitMIMERequired()
}

// OriginalForm returns the representation of the rebuilt third part or the empty value.
func (e DSNPropagationEvidence) OriginalForm() ReceivedDSNOriginalForm {
	if !e.Rebuilt() {
		return ""
	}
	return ReceivedDSNOriginalForm(e.state.report.Form())
}

// String returns a constant representation without sealed evidence facts.
func (DSNPropagationEvidence) String() string { return dsnPropagationEvidenceRedactedText }

// GoString returns the constant secret-safe evidence representation.
func (e DSNPropagationEvidence) GoString() string { return e.String() }

// Format routes every evidence formatting form through the redacted representation.
func (e DSNPropagationEvidence) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, e.String())
}

// MarshalJSON rejects direct serialization outside generated response DTOs.
func (DSNPropagationEvidence) MarshalJSON() ([]byte, error) {
	return nil, newSigningError(SigningErrorInvalidRequest)
}

// MarshalText rejects diagnostic serialization of sealed evidence.
func (DSNPropagationEvidence) MarshalText() ([]byte, error) {
	return nil, newSigningError(SigningErrorInvalidRequest)
}

// DSNPropagationSigningRequest binds rebuilt evidence to a propagation route
// ticket, the delivery_status profile of the signing domain, and metadata.
type DSNPropagationSigningRequest struct {
	evidence  DSNPropagationEvidence
	ticket    RouteCopyTicket
	profile   SigningProfile
	metadata  SigningMetadata
	transport SigningTransportForm
}

// NewDSNPropagationSigningRequest constructs one propagation signing request
// without accepting caller-supplied message, envelope, or domain values.
func NewDSNPropagationSigningRequest(evidence DSNPropagationEvidence, ticket RouteCopyTicket, profile SigningProfile, metadata SigningMetadata, transport SigningTransportForm) DSNPropagationSigningRequest {
	return DSNPropagationSigningRequest{evidence: evidence, ticket: ticket, profile: profile, metadata: metadata, transport: transport}
}

// String prevents signing request formatting from exposing protected state.
func (DSNPropagationSigningRequest) String() string { return dsnPropagationSigningRequestRedactedText }

// GoString returns the constant secret-safe signing-request representation.
func (r DSNPropagationSigningRequest) GoString() string { return r.String() }

// Format routes every signing-request formatting form through the redacted representation.
func (r DSNPropagationSigningRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// PropagatedDSN is the signed propagated report with its bounded transport facts.
type PropagatedDSN struct {
	state *propagatedDSNState
}

// propagatedDSNState stores the immutable signed output.
type propagatedDSNState struct {
	raw      []byte
	nextHop  []byte
	domain   string
	smtputf8 bool
	eightBit bool
	facts    SignedMessageFacts
}

// Valid reports whether the value was produced by SignPropagatedDSN.
func (p PropagatedDSN) Valid() bool {
	return p.state != nil && len(p.state.raw) > 0 && len(p.state.nextHop) > 2 && p.state.domain != "" && p.state.facts.Valid()
}

// Bytes returns a detached copy of the complete signed DSN or nil.
func (p PropagatedDSN) Bytes() []byte {
	if !p.Valid() {
		return nil
	}
	return bytes.Clone(p.state.raw)
}

// NextHopRecipient returns a detached copy of the exact bracketed SMTP forward path or nil.
func (p PropagatedDSN) NextHopRecipient() []byte {
	if !p.Valid() {
		return nil
	}
	return bytes.Clone(p.state.nextHop)
}

// SigningDomain returns the canonical domain that signed the report or an empty string.
func (p PropagatedDSN) SigningDomain() string {
	if !p.Valid() {
		return ""
	}
	return p.state.domain
}

// SMTPUTF8Required reports whether the re-injection needs the SMTPUTF8
// extension because a header field of the signed DSN carries a non-ASCII byte.
func (p PropagatedDSN) SMTPUTF8Required() bool { return p.Valid() && p.state.smtputf8 }

// EightBitMIMERequired reports whether the re-injection needs the 8BITMIME
// extension because the embedded original's body carries a non-ASCII byte.
func (p PropagatedDSN) EightBitMIMERequired() bool { return p.Valid() && p.state.eightBit }

// Facts returns the bounded signed-message facts.
func (p PropagatedDSN) Facts() SignedMessageFacts {
	if !p.Valid() {
		return SignedMessageFacts{}
	}
	return p.state.facts
}

// String returns a constant representation without message bytes.
func (PropagatedDSN) String() string { return propagatedDSNRedactedText }

// GoString returns the constant secret-safe representation.
func (p PropagatedDSN) GoString() string { return p.String() }

// Format routes every formatting form through the redacted representation.
func (p PropagatedDSN) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, p.String()) }

// MarshalJSON rejects direct serialization outside generated response DTOs.
func (PropagatedDSN) MarshalJSON() ([]byte, error) {
	return nil, newSigningError(SigningErrorInvalidRequest)
}

// MarshalText rejects diagnostic serialization of message bytes.
func (PropagatedDSN) MarshalText() ([]byte, error) {
	return nil, newSigningError(SigningErrorInvalidRequest)
}

// RebuildDSNForPropagation evaluates one received DSN under Draft-06 Section
// 12.1.2 with the signer's own verifier and, when the evaluation is eligible,
// rebuilds it under Section 12.1.1 into an unsigned report addressed to the
// authenticated previous hop. The signing domain is the canonical d= of the
// removed completion signature; neither the request nor the adapter can
// select it. Protocol outcomes are returned in the evidence; only invalid
// requests, cancellation, and internal contract violations return a Go error.
func (s *Signer) RebuildDSNForPropagation(ctx context.Context, request DSNPropagationRequest) (DSNPropagationEvidence, error) {
	if s == nil || !s.initialized || ctx == nil || !validDSNPropagationRequest(request) {
		return DSNPropagationEvidence{}, newDSNPropagationError(DSNPropagationStagePreflight, newSigningError(SigningErrorInvalidRequest))
	}
	if err := ctx.Err(); err != nil {
		return DSNPropagationEvidence{}, newDSNPropagationError(DSNPropagationStagePreflight, err)
	}
	evaluator, err := newSignerReceivedDSNEvaluator(s.revision.Core(), s.limits)
	if err != nil {
		return DSNPropagationEvidence{}, newDSNPropagationError(DSNPropagationStagePreflight, newSigningError(SigningErrorInternalInvariant))
	}
	inner, err := evaluator.Evaluate(ctx, dsn.ReceivedRequest{
		Raw: request.state.raw, OuterRecipient: request.state.forwardPaths[0],
		Authority: localAuthorityBridge{authority: request.state.authority},
	})
	if err != nil {
		return DSNPropagationEvidence{}, mapDSNPropagationEvaluationError(ctx, err)
	}
	evaluation := ReceivedDSNEvaluation{state: &receivedDSNEvaluationState{inner: inner}}
	if !evaluation.Valid() {
		return DSNPropagationEvidence{}, newDSNPropagationError(DSNPropagationStageEvaluation, newSigningError(SigningErrorInternalInvariant))
	}
	if evaluation.Propagation() != ReceivedDSNPropagationEligible {
		return DSNPropagationEvidence{state: &dsnPropagationEvidenceState{evaluation: evaluation, outcome: DSNPropagationNotEligible}}, nil
	}
	instant, err := s.revision.CaptureOperationInstant()
	if err != nil || !instant.Valid() {
		return DSNPropagationEvidence{}, newDSNPropagationError(DSNPropagationStageRebuild, newSigningError(SigningErrorInternalInvariant))
	}
	token, err := propagationMessageIDToken(request.state.identifierEntropy())
	if err != nil {
		return DSNPropagationEvidence{}, newDSNPropagationError(DSNPropagationStageRebuild, err)
	}
	report, err := evaluator.Rebuild(ctx, dsn.RebuildRequest{
		Evaluation: inner, ReportingMTA: request.state.reportingMTA, Timestamp: instant.UnixSeconds(), MessageIDToken: token,
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return DSNPropagationEvidence{}, newDSNPropagationError(DSNPropagationStageRebuild, ctxErr)
		}
		return DSNPropagationEvidence{}, newDSNPropagationError(DSNPropagationStageRebuild, newSigningError(SigningErrorInternalInvariant))
	}
	evidence := DSNPropagationEvidence{state: &dsnPropagationEvidenceState{evaluation: evaluation, report: report, instant: instant}}
	switch report.Outcome() {
	case dsn.RebuildRebuilt:
		evidence.state.outcome = DSNPropagationRebuilt
	case dsn.RebuildTemporary:
		evidence.state.outcome = DSNPropagationTemporaryError
	default:
		evidence.state.outcome = DSNPropagationNotReconstructable
	}
	if !evidence.Valid() {
		return DSNPropagationEvidence{}, newDSNPropagationError(DSNPropagationStageRebuild, newSigningError(SigningErrorInternalInvariant))
	}
	return evidence, nil
}

// validDSNPropagationRequest applies the request preflight rules.
func validDSNPropagationRequest(request DSNPropagationRequest) bool {
	state := request.state
	if state == nil || len(state.raw) == 0 || !bytes.Equal(state.reversePath, []byte("<>")) || len(state.forwardPaths) != 1 || state.authority == nil {
		return false
	}
	limits := keyresolver.DefaultLimits()
	canonical, err := keyresolver.CanonicalSigningDomain(state.reportingMTA, limits.MaxSigningDomainBytes, limits.MaxSigningDomainLabels)
	return err == nil && canonical == state.reportingMTA
}

// propagationMessageIDToken draws one fresh hexadecimal Message-ID token from entropy.
func propagationMessageIDToken(entropy io.Reader) ([]byte, error) {
	var material [propagationMessageIDEntropyBytes]byte
	if _, err := io.ReadFull(entropy, material[:]); err != nil {
		return nil, newSigningError(SigningErrorInternalInvariant)
	}
	return []byte(hex.EncodeToString(material[:])), nil
}

// newSignerReceivedDSNEvaluator binds the received-DSN evaluator and rebuilder
// to the signer's protocol-core verifier and narrows the RFC 6522 parser to
// the signer's message ceiling less the fixed report parts and the two
// generated protocol fields, so a received DSN the parser admits can always
// be rebuilt and signed within the plan's size limit instead of failing late.
func newSignerReceivedDSNEvaluator(core verify.Verifier, limits signing.Limits) (dsn.ReceivedEvaluator, error) {
	ceiling := limits.MaxMessageBytes - dsn.PropagationFixedPartsBound - 2*limits.MaxFieldBytes
	if ceiling <= 0 {
		return dsn.ReceivedEvaluator{}, newSigningError(SigningErrorInvalidOptions)
	}
	parser := dsn.DefaultOptions()
	parser.MaxMessageBytes = min(parser.MaxMessageBytes, ceiling)
	parser.MaxPartBytes = min(parser.MaxPartBytes, parser.MaxMessageBytes)
	return dsn.NewReceivedEvaluator(core, dsn.ReceivedEvaluatorConfig{Parser: parser})
}

// mapDSNPropagationEvaluationError preserves cancellation and maps the evaluator's contract errors.
func mapDSNPropagationEvaluationError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
		return newDSNPropagationError(DSNPropagationStageEvaluation, ctxErr)
	}
	return newDSNPropagationError(DSNPropagationStageEvaluation, newSigningError(SigningErrorInvalidRequest))
}

// PlanPropagationRoute plans exactly one delivery_status_propagation route
// ticket over the rebuilt report that the evidence carries. The ticket source
// is the report's own bytes, so it matches the message SignPropagatedDSN
// signs; the reverse path is null, the single forward path is the
// authenticated previous-hop mf=, and the disclosure and route class are the
// fixed single external shape. Neither the caller nor the route scope can
// select the recipient or the signing domain: both stay derived from the
// removed completion signature and the verified previous hop.
func (s *Signer) PlanPropagationRoute(ctx context.Context, evidence DSNPropagationEvidence, routeScope []byte) (RouteCopyTicket, error) {
	if s == nil || !s.initialized || ctx == nil || !evidence.Rebuilt() {
		return RouteCopyTicket{}, newSigningError(SigningErrorInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return RouteCopyTicket{}, err
	}
	source, err := NewSigningSource(evidence.state.report.Bytes())
	if err != nil {
		return RouteCopyTicket{}, err
	}
	entry, err := NewDeliveryStatusPropagationRouteEntry(source, []byte("<>"), [][]byte{evidence.NextHopRecipient()}, routeScope)
	if err != nil {
		return RouteCopyTicket{}, err
	}
	request, err := NewRouteFanoutRequest([]RouteEntry{entry})
	if err != nil {
		return RouteCopyTicket{}, err
	}
	_, tickets, err := s.PlanRouteFanout(ctx, request)
	if err != nil {
		return RouteCopyTicket{}, err
	}
	if len(tickets) != 1 || !tickets[0].Valid() || tickets[0].TotalMultiplicity() != 1 {
		return RouteCopyTicket{}, newSigningError(SigningErrorInternalInvariant)
	}
	return tickets[0], nil
}

// SignPropagatedDSN signs only a report rebuilt by RebuildDSNForPropagation.
// The ticket must carry the delivery_status_propagation purpose with the
// null reverse path and the authenticated next-hop recipient, the profile
// must belong to the derived signing domain, and the result must carry
// exactly one Message-Instance m=1 and one DKIM2-Signature i=1 with mf=<>
// and rt= equal to the previous hop's mf=.
func (s *Signer) SignPropagatedDSN(ctx context.Context, request DSNPropagationSigningRequest) (PropagatedDSN, SigningRecovery, error) {
	if s == nil || !s.initialized || ctx == nil || !request.evidence.Rebuilt() ||
		!request.transport.Known() || !request.ticket.Valid() ||
		request.ticket.value.Purpose() != routeplan.PurposeDeliveryStatusPropagation ||
		!request.ticket.value.MatchesEnvelope([]byte("<>"), [][]byte{request.evidence.NextHopRecipient()}) ||
		!request.profile.value.ValidForLimits(s.limits) || request.profile.value.Domain() != request.evidence.SigningDomain() ||
		!request.metadata.value.Valid() {
		return PropagatedDSN{}, SigningRecovery{}, newSigningError(SigningErrorInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return PropagatedDSN{}, SigningRecovery{}, err
	}
	report := request.evidence.state.report
	message, err := rawmsg.Parse(report.Bytes())
	if err != nil {
		return PropagatedDSN{}, SigningRecovery{}, newSigningError(SigningErrorMalformedInput)
	}
	plan, err := s.planner.PlanDeliveryStatusPropagation(ctx, signing.OriginatorPlanRequest{
		Message: message, Ticket: request.ticket.value, Instant: request.evidence.state.instant,
	})
	if err != nil {
		return PropagatedDSN{}, SigningRecovery{}, mapOperationError(err)
	}
	nextHop := report.NextHopRecipient()
	result, recovery, err := s.complete(ctx, signing.SignFieldRequest{
		Plan: plan, Message: message, Ticket: request.ticket.value,
		ReversePath: []byte("<>"), ForwardPaths: [][]byte{bytes.Clone(nextHop)},
		Profile: request.profile.value, Metadata: request.metadata.value, Transport: rawmsg.TransportForm(request.transport),
		EnvelopeForm: signing.SignatureEnvelopeOrdinary,
	})
	if err != nil {
		return PropagatedDSN{}, recovery, err
	}
	signed, ok := result.Unrestricted()
	if !ok || !signed.Valid() {
		return PropagatedDSN{}, SigningRecovery{}, newSigningError(SigningErrorInternalInvariant)
	}
	raw := signed.Bytes()
	if err := dsn.ProvePropagatedReport(raw, nextHop, report.SigningDomain()); err != nil {
		return PropagatedDSN{}, SigningRecovery{}, newSigningError(SigningErrorInternalInvariant)
	}
	propagated := PropagatedDSN{state: &propagatedDSNState{
		raw: raw, nextHop: nextHop, domain: report.SigningDomain(),
		smtputf8: report.SMTPUTF8Required(), eightBit: report.EightBitMIMERequired(), facts: signed.Facts(),
	}}
	if !propagated.Valid() || propagated.state.facts.NewInstanceNumber() != 1 || propagated.state.facts.Sequence() != 1 {
		return PropagatedDSN{}, SigningRecovery{}, newSigningError(SigningErrorInternalInvariant)
	}
	return propagated, SigningRecovery{}, nil
}
