package dsn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/keyresolver"
	"github.com/croessner/dkim2/internal/niliface"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
	"github.com/croessner/dkim2/internal/verify"
)

const (
	receivedEvaluationRedactedText = "dsn.ReceivedEvaluation{redacted}"
	// maxReferenceUnixSeconds bounds an outer t= so it converts to a time.Time without overflow.
	maxReferenceUnixSeconds = uint64(1<<63 - 1)
)

// ReceivedError is a typed, content-free received-DSN evaluation failure. It
// carries only the closed stage and failure class; the wrapped cause is a
// context error or an already content-free protocol error.
type ReceivedError struct {
	stage ReceivedStage
	code  ReceivedErrorCode
	cause error
}

// Error returns a bounded diagnostic without report, address, or identity content.
func (e *ReceivedError) Error() string {
	if e == nil {
		return "dsn received evaluation error: <nil>"
	}
	return fmt.Sprintf("dsn received evaluation error: stage=%s code=%s", e.stage, e.code)
}

// Unwrap exposes the context or content-free protocol cause.
func (e *ReceivedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Is matches received errors by their closed failure class.
func (e *ReceivedError) Is(target error) bool {
	var typed *ReceivedError
	return errors.As(target, &typed) && e != nil && typed != nil && e.code == typed.code
}

// Stage returns the closed stage in which the failure occurred.
func (e *ReceivedError) Stage() ReceivedStage {
	if e == nil {
		return ""
	}
	return e.stage
}

// Code returns the closed failure class.
func (e *ReceivedError) Code() ReceivedErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}

// Format routes every formatting verb through the bounded diagnostic.
func (e *ReceivedError) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, e.Error()) }

// IsReceivedErrorCode reports whether err carries the requested failure class.
func IsReceivedErrorCode(err error, code ReceivedErrorCode) bool {
	var typed *ReceivedError
	return errors.As(err, &typed) && typed.Code() == code
}

// ReceivedStageOf returns the closed stage of a typed received error or the zero value.
func ReceivedStageOf(err error) ReceivedStage {
	var typed *ReceivedError
	if errors.As(err, &typed) {
		return typed.Stage()
	}
	return ""
}

// newReceivedError constructs one bounded staged error.
func newReceivedError(stage ReceivedStage, code ReceivedErrorCode, cause error) *ReceivedError {
	if !stage.Known() {
		stage = ReceivedStagePreflight
	}
	if !code.Known() {
		code = ReceivedErrorInternal
	}
	return &ReceivedError{stage: stage, code: code, cause: cause}
}

// contextError wraps caller cancellation observed in one stage.
func contextError(stage ReceivedStage, cause error) *ReceivedError {
	return newReceivedError(stage, ReceivedErrorCanceled, cause)
}

// ReceivedEvaluatorConfig bounds one received-DSN evaluator.
type ReceivedEvaluatorConfig struct {
	// Parser bounds RFC 6522 structural parsing; the zero value selects DefaultOptions.
	Parser Options
	// RunLimits bounds local-hop run detection; the zero value selects the defaults.
	RunLimits verify.LocalHopRunLimits
}

// ReceivedEvaluator owns the read-only Draft-06 Section 12.1.2 evaluation of
// an inbound DKIM2-signed delivery-status notification. It never authorizes
// signing and never rebuilds a report.
type ReceivedEvaluator struct {
	verifier  verify.Verifier
	parser    Options
	runLimits verify.LocalHopRunLimits
	valid     bool
}

// NewReceivedEvaluator constructs a received-DSN evaluator from one validated verifier.
func NewReceivedEvaluator(verifier verify.Verifier, config ReceivedEvaluatorConfig) (ReceivedEvaluator, error) {
	if !verifier.Valid() {
		return ReceivedEvaluator{}, newReceivedError(ReceivedStagePreflight, ReceivedErrorInvalidRequest, nil)
	}
	parser := config.Parser
	if parser == (Options{}) {
		parser = DefaultOptions()
	}
	if err := validateOptions(parser); err != nil {
		return ReceivedEvaluator{}, newReceivedError(ReceivedStagePreflight, ReceivedErrorInvalidRequest, err)
	}
	return ReceivedEvaluator{verifier: verifier, parser: parser, runLimits: config.RunLimits, valid: true}, nil
}

// ReceivedRequest carries one inbound DSN whose outer message the caller has
// already verified as an ordinary message.
type ReceivedRequest struct {
	// Raw is the complete outer RFC 5322 report.
	Raw []byte
	// OuterRecipient is the single observed bracketed outer SMTP forward path.
	OuterRecipient []byte
	// Authority resolves local authority domains for the caller's tenant; nil means no tenant.
	Authority verify.LocalAuthority
}

// completionFacts stores bounded facts about the verified completion signature.
type completionFacts struct {
	sequence  uint64
	instance  uint64
	timestamp uint64
	domain    string
}

// ReceivedEvaluation is the immutable outcome of one received-DSN evaluation.
// It exposes the closed projection plus the bounded facts a later rebuild
// needs; it never exposes report text, addresses, or message bytes except the
// syntactically validated status code, ENVID, and matching ORCPT value.
type ReceivedEvaluation struct {
	structure         StructureResult
	embedded          EmbeddedResult
	localHop          LocalHopResult
	outerAlignment    OuterAlignmentResult
	recipientLinkage  RecipientLinkageResult
	propagation       PropagationResult
	form              EvidenceForm
	completion        completionFacts
	run               verify.LocalHopRun
	hasRun            bool
	original          rawmsg.Message
	input             verify.EmbeddedInput
	status            []byte
	envelopeID        []byte
	hasEnvelopeID     bool
	originalRecipient []byte
	originalPath      []byte
	hasOriginal       bool
	receivedBytes     int
	initialized       bool
}

// Valid reports whether the evaluation was produced by a ReceivedEvaluator and is coherent.
func (e ReceivedEvaluation) Valid() bool {
	if !e.initialized || !e.structure.Known() || !e.localHop.Known() || !e.outerAlignment.Known() ||
		!e.recipientLinkage.Known() || !e.propagation.Known() {
		return false
	}
	if e.structure != StructureValid {
		return e.embedded == "" && e.propagation == PropagationNotEvaluated
	}
	return e.embedded.Known()
}

// Structure returns the closed structure outcome.
func (e ReceivedEvaluation) Structure() StructureResult { return e.structure }

// Embedded returns the closed embedded-verification outcome or the empty value before that stage.
func (e ReceivedEvaluation) Embedded() EmbeddedResult { return e.embedded }

// LocalHop returns the closed local-hop identity outcome.
func (e ReceivedEvaluation) LocalHop() LocalHopResult { return e.localHop }

// OuterAlignment returns the closed outer-signer alignment outcome.
func (e ReceivedEvaluation) OuterAlignment() OuterAlignmentResult { return e.outerAlignment }

// RecipientLinkage returns the closed recipient-linkage outcome.
func (e ReceivedEvaluation) RecipientLinkage() RecipientLinkageResult { return e.recipientLinkage }

// Propagation returns the closed informational propagation projection.
func (e ReceivedEvaluation) Propagation() PropagationResult { return e.propagation }

// Form returns the embedded original representation once structure passed.
func (e ReceivedEvaluation) Form() EvidenceForm { return e.form }

// CompletionSequence returns the i= of the verified completion signature or zero.
func (e ReceivedEvaluation) CompletionSequence() uint64 { return e.completion.sequence }

// CompletionInstance returns the m= referenced by the completion signature or zero.
func (e ReceivedEvaluation) CompletionInstance() uint64 { return e.completion.instance }

// CompletionTimestamp returns the completion signature's t= value or zero.
func (e ReceivedEvaluation) CompletionTimestamp() uint64 { return e.completion.timestamp }

// CompletionDomain returns the canonical d= of the completion signature once
// it was verified and proven local, otherwise an empty string.
func (e ReceivedEvaluation) CompletionDomain() string {
	if e.localHop != LocalHopLocal {
		return ""
	}
	return e.completion.domain
}

// Run returns the detected local hop run when the local-hop stage passed.
func (e ReceivedEvaluation) Run() (verify.LocalHopRun, bool) {
	if !e.hasRun || !e.run.Valid() {
		return verify.LocalHopRun{}, false
	}
	return e.run, true
}

// PropagationStatus returns a detached copy of the propagation group's
// syntactically valid Status code, or nil without a propagation group.
func (e ReceivedEvaluation) PropagationStatus() []byte {
	if len(e.status) == 0 {
		return nil
	}
	return bytes.Clone(e.status)
}

// OriginalEnvelopeID returns a detached copy of the report's Original-Envelope-Id when present.
func (e ReceivedEvaluation) OriginalEnvelopeID() ([]byte, bool) {
	if !e.hasEnvelopeID {
		return nil, false
	}
	return bytes.Clone(e.envelopeID), true
}

// OriginalRecipientFor returns the propagation group's verbatim
// Original-Recipient value only when its xtext-decoded address equals the
// given canonical bracketed path. The rebuild passes the previous hop's
// single rt= path, which is the recipient the sender-supplied ORCPT would
// name; the evaluation itself never interprets the value beyond linkage.
func (e ReceivedEvaluation) OriginalRecipientFor(path []byte) ([]byte, bool) {
	if !e.hasOriginal || len(path) == 0 {
		return nil, false
	}
	canonicalPath, ok := signature.CanonicalEnvelopePath(path, false)
	if !ok || !bytes.Equal(canonicalPath, e.originalPath) {
		return nil, false
	}
	return bytes.Clone(e.originalRecipient), true
}

// String returns a constant secret-safe evaluation summary.
func (ReceivedEvaluation) String() string { return receivedEvaluationRedactedText }

// GoString returns the constant secret-safe evaluation Go representation.
func (e ReceivedEvaluation) GoString() string { return e.String() }

// Format routes every evaluation formatting form through the redacted summary.
func (e ReceivedEvaluation) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, e.String()) }

// receivedState carries the parsed inputs of one evaluation between stages.
type receivedState struct {
	report         Report
	status         deliveryStatusReport
	embedded       rawmsg.Message
	outerSigner    string
	outerTimestamp uint64
	recipient      []byte
	authority      verify.LocalAuthority
	target         verify.Target
	input          verify.EmbeddedInput
	ordered        []signature.Signature
	evidence       Evidence
	linked         []deliveryStatusRecipient
	group          deliveryStatusRecipient
	unsupported    bool
}

// Evaluate runs the seven Section 12.1.2 stages in order and stops at the
// first failure. Protocol outcomes are encoded in the returned evaluation;
// only invalid requests, cancellation, and internal contract violations
// return a Go error.
func (e ReceivedEvaluator) Evaluate(ctx context.Context, request ReceivedRequest) (ReceivedEvaluation, error) {
	if ctx == nil || !e.valid || !e.verifier.Valid() || len(request.Raw) == 0 {
		return ReceivedEvaluation{}, newReceivedError(ReceivedStagePreflight, ReceivedErrorInvalidRequest, nil)
	}
	recipient, ok := signature.CanonicalEnvelopePath(request.OuterRecipient, false)
	if !ok {
		return ReceivedEvaluation{}, newReceivedError(ReceivedStagePreflight, ReceivedErrorInvalidRequest, nil)
	}
	if err := ctx.Err(); err != nil {
		return ReceivedEvaluation{}, contextError(ReceivedStagePreflight, err)
	}
	evaluation := ReceivedEvaluation{
		localHop: LocalHopNotEvaluated, outerAlignment: OuterAlignmentNotEvaluated,
		recipientLinkage: RecipientLinkageNotEvaluated, propagation: PropagationNotEvaluated,
		receivedBytes: len(request.Raw), initialized: true,
	}
	state := &receivedState{recipient: recipient}
	if !niliface.IsNil(request.Authority) {
		state.authority = request.Authority
	}
	defer state.status.clear()
	if stop, err := e.evaluateStructure(request.Raw, state, &evaluation); stop || err != nil {
		return evaluation, err
	}
	if stop, err := e.evaluateEmbedded(ctx, state, &evaluation); stop || err != nil {
		return evaluation, err
	}
	if stop, err := e.evaluateLocalHop(ctx, state, &evaluation); stop || err != nil {
		return evaluation, err
	}
	if stop := evaluateOuterAlignment(state, &evaluation); stop {
		return evaluation, nil
	}
	if stop := evaluateRecipientLinkage(state, &evaluation); stop {
		return evaluation, nil
	}
	if stop := evaluateFailureClass(state, &evaluation); stop {
		return evaluation, nil
	}
	if err := ctx.Err(); err != nil {
		return ReceivedEvaluation{}, contextError(ReceivedStagePreviousHop, err)
	}
	evaluation.propagation = classifyPreviousHop(state, evaluation.run)
	return evaluation, nil
}

// evaluateStructure parses the outer report, the generic RFC 3464 body, the
// outer signer identity, and the embedded original.
func (e ReceivedEvaluator) evaluateStructure(raw []byte, state *receivedState, evaluation *ReceivedEvaluation) (bool, error) {
	report, err := ParseWithOptions(raw, e.parser)
	if err != nil {
		evaluation.structure = StructureMalformed
		if IsErrorCode(err, ErrorCodeLimitExceeded) {
			evaluation.structure = StructureLimitExceeded
		}
		return true, nil
	}
	outerSignature, ok := highestSignature(report.RawMessage())
	if !ok || outerSignature.TimestampSeconds() > maxReferenceUnixSeconds {
		return true, newReceivedError(ReceivedStageStructure, ReceivedErrorInvalidRequest, nil)
	}
	status, ok := parseDeliveryStatusBody(report.DeliveryStatus().BodyBytes(), false)
	if !ok {
		evaluation.structure = StructureMalformed
		return true, nil
	}
	embedded, err := rawmsg.Parse(report.OriginalMessage().BodyBytes())
	if err != nil {
		status.clear()
		evaluation.structure = StructureMalformed
		return true, nil
	}
	state.report, state.status, state.embedded = report, status, embedded
	state.outerSigner, state.outerTimestamp = outerSignature.Domain(), outerSignature.TimestampSeconds()
	evaluation.structure = StructureValid
	evaluation.form = EvidenceFormComplete
	if report.OriginalMessage().ContentType() == ContentTypeRFC822Headers {
		evaluation.form = EvidenceFormHeadersOnly
	}
	return false, nil
}

// evaluateEmbedded verifies the embedded original's highest signature and
// instance. The completion signature's Section 8.4 window is evaluated at the
// outer DSN's highest-signature t= instead of the clock, because a DSN may
// legitimately arrive long after the forwarding it reports on.
func (e ReceivedEvaluator) evaluateEmbedded(ctx context.Context, state *receivedState, evaluation *ReceivedEvaluation) (bool, error) {
	if len(state.embedded.Headers().FieldsByName(signature.HeaderName)) == 0 {
		evaluation.embedded = EmbeddedAbsent
		evaluation.propagation = PropagationNotApplicable
		return true, nil
	}
	if evaluation.form == EvidenceFormHeadersOnly && state.embedded.Framing() != rawmsg.MessageFramingHeaderOnly {
		// A text/rfc822-headers original that carries a body separator invents
		// body evidence the report cannot have; it is a protocol failure of the
		// message, never a verifier request the evaluator would issue.
		evaluation.embedded = EmbeddedUnverified
		return true, nil
	}
	request := verify.Request{Message: state.embedded, ReferenceTime: time.Unix(int64(state.outerTimestamp), 0)}
	var status verify.TargetStatus
	var target verify.Target
	var err error
	if evaluation.form == EvidenceFormHeadersOnly {
		var headerEvidence verify.HeaderEvidence
		headerEvidence, err = e.verifier.VerifyDeliveryStatusHeadersOnly(ctx, request)
		status, target = headerEvidence.Status(), headerEvidence.Target()
	} else {
		var result verify.Result
		result, err = e.verifier.VerifyDeliveryStatusComplete(ctx, request)
		status, target = result.Status(), result.Target()
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return true, contextError(ReceivedStageEmbeddedVerification, ctxErr)
	}
	switch {
	case verifierContractError(err):
		return true, newReceivedError(ReceivedStageEmbeddedVerification, ReceivedErrorInternal, err)
	case err != nil:
		evaluation.embedded = EmbeddedUnverified
	case status == verify.TargetStatusPass:
		evaluation.embedded = EmbeddedVerified
		if evaluation.form == EvidenceFormHeadersOnly {
			evaluation.embedded = EmbeddedVerifiedHeadersOnly
		}
	case status == verify.TargetStatusIndeterminate:
		evaluation.embedded = EmbeddedTemporaryError
	default:
		evaluation.embedded = EmbeddedUnverified
	}
	if evaluation.embedded != EmbeddedVerified && evaluation.embedded != EmbeddedVerifiedHeadersOnly {
		return true, nil
	}
	input, err := e.verifier.ExtractEmbeddedInput(state.embedded)
	if err != nil {
		return true, newReceivedError(ReceivedStageEmbeddedVerification, ReceivedErrorInternal, err)
	}
	state.target, state.input = target, input
	// The verified embedded original and its extracted protocol fields are
	// retained privately so that a later rebuild works on exactly the bytes
	// this evaluation proved; no accessor exposes them.
	evaluation.original, evaluation.input = state.embedded, input
	return false, nil
}

// verifierContractError reports a verifier error that classifies a malformed
// request or an internal misuse rather than a protocol failure of the message.
func verifierContractError(err error) bool {
	var typed *verify.Error
	if !errors.As(err, &typed) {
		return false
	}
	class := typed.Class()
	return class == verify.ErrorClassInternal || class == verify.ErrorClassRequest
}

// evaluateLocalHop applies Section 12.1.2 item 2: verified completion
// signature, datasource locality of its d=, Section 11.4 relaxed d=/mf=
// match, and exact mf= equality with the outer recipient. It then extends
// and cryptographically verifies the local hop run.
func (e ReceivedEvaluator) evaluateLocalHop(ctx context.Context, state *receivedState, evaluation *ReceivedEvaluation) (bool, error) {
	ordered, err := signature.OrderBySequence(state.input.Signatures())
	if err != nil || state.target.Sequence == 0 || state.target.Sequence > uint64(len(ordered)) {
		return true, newReceivedError(ReceivedStageLocalHop, ReceivedErrorInternal, err)
	}
	state.ordered = ordered
	completion := ordered[state.target.Sequence-1]
	evaluation.completion = completionFacts{
		sequence: completion.Sequence(), instance: completion.InstanceNumber(),
		timestamp: completion.TimestampSeconds(), domain: completion.Domain(),
	}
	if state.authority == nil {
		return true, nil
	}
	// The signature parser canonicalizes d= and the completion signature verified
	// through a key lookup under the resolver grammar, so a d= that fails the
	// resolver bound here is a contract violation, not a signer fact. It must
	// never reach the authority and fails closed as an internal error.
	limits := keyresolver.DefaultLimits()
	domain, err := keyresolver.CanonicalSigningDomain(completion.Domain(), limits.MaxSigningDomainBytes, limits.MaxSigningDomainLabels)
	if err != nil || domain != completion.Domain() {
		return true, newReceivedError(ReceivedStageLocalHop, ReceivedErrorInternal, err)
	}
	status, err := state.authority.LookupLocalAuthority(ctx, domain)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return true, contextError(ReceivedStageLocalHop, ctxErr)
	}
	if err != nil || !status.Known() {
		evaluation.localHop = LocalHopTemporaryError
		return true, nil
	}
	if status != verify.LocalAuthorityLocal {
		evaluation.localHop = LocalHopNotLocal
		return true, nil
	}
	if !completionBindsOuterRecipient(state, completion, evaluation.form) {
		evaluation.localHop = LocalHopMismatch
		return true, nil
	}
	return e.evaluateRun(ctx, state, evaluation)
}

// completionBindsOuterRecipient checks the Section 11.4 relaxed d=/mf= match
// and the exact outer-recipient binding of the completion signature.
func completionBindsOuterRecipient(state *receivedState, completion signature.Signature, form EvidenceForm) bool {
	evidence, err := authenticatedEvidenceFrom(form, state.ordered, state.target)
	if err != nil {
		return false
	}
	custody, err := signature.ValidateCustody(state.ordered, signature.CustodyLimits{})
	if err != nil || custody.DirectAlignment(completion.Sequence()) != signature.CustodyDirectAlignmentPass {
		return false
	}
	mailFrom, ok := signature.CanonicalEnvelopePath(evidence.mailFrom, false)
	if !ok || !bytes.Equal(mailFrom, state.recipient) {
		return false
	}
	state.evidence = evidence
	return true
}

// evaluateRun detects the local hop run and verifies every member below the
// completion signature. A temporary key failure makes the embedded
// verification incomplete; a non-verifying member marks the chain unsupported.
func (e ReceivedEvaluator) evaluateRun(ctx context.Context, state *receivedState, evaluation *ReceivedEvaluation) (bool, error) {
	run, outcome, err := verify.DetectLocalHopRun(ctx, state.ordered, state.target.Sequence, state.authority, e.runLimits)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return true, contextError(ReceivedStageLocalHop, ctxErr)
		}
		return true, newReceivedError(ReceivedStageLocalHop, ReceivedErrorInternal, err)
	}
	switch outcome {
	case verify.LocalHopRunDetected:
		evaluation.run, evaluation.hasRun = run, true
	case verify.LocalHopRunTemporary:
		evaluation.localHop = LocalHopTemporaryError
		return true, nil
	default:
		state.unsupported = true
	}
	if evaluation.hasRun {
		members := run.Members()
		members = members[:len(members)-1]
		memberOutcome, memberErr := e.verifier.VerifyEmbeddedSignatures(ctx, state.input, members)
		if memberErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return true, contextError(ReceivedStageLocalHop, ctxErr)
			}
			return true, newReceivedError(ReceivedStageLocalHop, ReceivedErrorInternal, memberErr)
		}
		switch memberOutcome {
		case verify.RunMemberVerified:
		case verify.RunMemberTemporary:
			evaluation.embedded = EmbeddedTemporaryError
			evaluation.run, evaluation.hasRun = verify.LocalHopRun{}, false
			return true, nil
		default:
			state.unsupported = true
		}
	}
	evaluation.localHop = LocalHopLocal
	return false, nil
}

// evaluateOuterAlignment applies Section 12.1.2 item 1 with the relaxed domain match.
func evaluateOuterAlignment(state *receivedState, evaluation *ReceivedEvaluation) bool {
	for _, domain := range state.evidence.recipientDomains {
		if signature.RelaxedDomainMatch(state.outerSigner, domain) {
			evaluation.outerAlignment = OuterAlignmentAligned
			return false
		}
	}
	evaluation.outerAlignment = OuterAlignmentMisaligned
	return true
}

// evaluateRecipientLinkage selects the recipient groups naming an authenticated completion rt= path.
func evaluateRecipientLinkage(state *receivedState, evaluation *ReceivedEvaluation) bool {
	state.linked = state.status.linked(state.evidence.recipientPaths)
	if len(state.linked) == 0 {
		evaluation.recipientLinkage = RecipientLinkageUnlinked
		return true
	}
	evaluation.recipientLinkage = RecipientLinkageLinked
	return false
}

// evaluateFailureClass selects the first linked group with Action: failed as
// the propagation group and retains its bounded report facts.
func evaluateFailureClass(state *receivedState, evaluation *ReceivedEvaluation) bool {
	for _, group := range state.linked {
		if !group.failed() {
			continue
		}
		state.group = group
		evaluation.status = bytes.Clone(group.status)
		if state.status.hasEnvelopeID {
			evaluation.envelopeID, evaluation.hasEnvelopeID = bytes.Clone(state.status.envelopeID), true
		}
		if group.hasOriginal {
			evaluation.originalRecipient, evaluation.originalPath, evaluation.hasOriginal = bytes.Clone(group.originalRecipient), bytes.Clone(group.originalPath), true
		}
		return false
	}
	evaluation.propagation = PropagationNotFailure
	return true
}

// classifyPreviousHop classifies i=k-1 and the conditions visible without a rebuild.
func classifyPreviousHop(state *receivedState, run verify.LocalHopRun) PropagationResult {
	if state.unsupported || !run.Valid() {
		return PropagationUnsupportedChain
	}
	if !run.HasPreviousHop() {
		return PropagationTerminalOrigin
	}
	if run.PreviousHopIsNextDomain() {
		return PropagationUnsupportedChain
	}
	if run.PreviousHopNullSender() {
		return PropagationForbiddenNullPreviousSender
	}
	if len(run.PreviousHopRecipients()) != 1 || !historicalInstancesSupported(state.input.Instances(), run.PreviousHopInstance()) {
		return PropagationNotReconstructable
	}
	return PropagationEligible
}

// historicalInstancesSupported reports whether every extracted Message-Instance
// from the previous hop's instance upwards carries a supported hash tuple,
// which the descent needs to re-prove each intermediate state.
func historicalInstancesSupported(instances []instance.MessageInstance, previousInstance uint64) bool {
	if len(instances) == 0 || previousInstance == 0 {
		return false
	}
	for _, parsed := range instances {
		if parsed.Number() < previousInstance {
			continue
		}
		if _, selection := parsed.SupportedHashSets(); selection != instance.HashSelectionStatusSelected {
			return false
		}
	}
	return true
}

// highestSignature returns the outer report's highest DKIM2-Signature, whose
// canonical d= identifies the outer signer and whose t= is the reference
// instant for the embedded completion signature.
func highestSignature(message rawmsg.Message) (signature.Signature, bool) {
	signatures, err := signature.Extract(message)
	if err != nil || len(signatures) == 0 {
		return signature.Signature{}, false
	}
	ordered, err := signature.OrderBySequence(signatures)
	if err != nil {
		return signature.Signature{}, false
	}
	return ordered[len(ordered)-1], true
}
