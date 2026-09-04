package dsn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/keyresolver"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/signature"
	"github.com/croessner/dkim2/internal/verify"
)

const rebuiltReportRedactedText = "dsn.RebuiltReport{redacted}"

// RebuildErrorCode is the closed class of a rebuild Go error.
type RebuildErrorCode string

const (
	// RebuildErrorInvalidRequest reports an invalid evaluator, evaluation, or request value.
	RebuildErrorInvalidRequest RebuildErrorCode = "invalid_request"
	// RebuildErrorNotEligible reports an evaluation whose propagation projection is not eligible.
	RebuildErrorNotEligible RebuildErrorCode = "not_eligible"
	// RebuildErrorCanceled reports caller cancellation.
	RebuildErrorCanceled RebuildErrorCode = "canceled"
	// RebuildErrorInternal reports an internal contract violation.
	RebuildErrorInternal RebuildErrorCode = "internal"
)

// Known reports whether the code belongs to the closed vocabulary.
func (c RebuildErrorCode) Known() bool {
	switch c {
	case RebuildErrorInvalidRequest, RebuildErrorNotEligible, RebuildErrorCanceled, RebuildErrorInternal:
		return true
	default:
		return false
	}
}

// RebuildError is a typed, content-free rebuild failure.
type RebuildError struct {
	code  RebuildErrorCode
	cause error
}

// Error returns a bounded diagnostic without report, address, or identity content.
func (e *RebuildError) Error() string {
	if e == nil {
		return "dsn rebuild error: <nil>"
	}
	return fmt.Sprintf("dsn rebuild error: code=%s", e.code)
}

// Unwrap exposes the context or content-free protocol cause.
func (e *RebuildError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Code returns the closed failure class.
func (e *RebuildError) Code() RebuildErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}

// Format routes every formatting verb through the bounded diagnostic.
func (e *RebuildError) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, e.Error()) }

// IsRebuildErrorCode reports whether err carries the requested failure class.
func IsRebuildErrorCode(err error, code RebuildErrorCode) bool {
	var typed *RebuildError
	return errors.As(err, &typed) && typed.Code() == code
}

// newRebuildError constructs one bounded rebuild error.
func newRebuildError(code RebuildErrorCode, cause error) *RebuildError {
	if !code.Known() {
		code = RebuildErrorInternal
	}
	return &RebuildError{code: code, cause: cause}
}

// RebuildOutcome is the closed result of one rebuild attempt.
type RebuildOutcome string

const (
	// RebuildRebuilt reports a complete Section 12.1.1 report ready for signing.
	RebuildRebuilt RebuildOutcome = "rebuilt"
	// RebuildNotReconstructable reports that the previous state could not be proven or rendered.
	RebuildNotReconstructable RebuildOutcome = "not_reconstructable"
	// RebuildTemporary reports a temporary key-provider failure while verifying the previous hop.
	RebuildTemporary RebuildOutcome = "temporary"
)

// Known reports whether the outcome belongs to the closed vocabulary.
func (o RebuildOutcome) Known() bool {
	return o == RebuildRebuilt || o == RebuildNotReconstructable || o == RebuildTemporary
}

// RebuildFailure is the closed internal cause of a not-reconstructable rebuild.
type RebuildFailure string

const (
	// RebuildFailureRecipeInvalid reports malformed authenticated recipe JSON in the run.
	RebuildFailureRecipeInvalid RebuildFailure = "recipe_invalid"
	// RebuildFailureApplicationInvalid reports a recipe that cannot be applied.
	RebuildFailureApplicationInvalid RebuildFailure = "application_invalid"
	// RebuildFailureSourceUnavailable reports a copy from unavailable state.
	RebuildFailureSourceUnavailable RebuildFailure = "source_unavailable"
	// RebuildFailureLimitExceeded reports a descent ceiling or a rebuilt report larger than the received one plus the fixed parts.
	RebuildFailureLimitExceeded RebuildFailure = "limit_exceeded"
	// RebuildFailureHashMismatch reports a reconstructed state that does not match its instance.
	RebuildFailureHashMismatch RebuildFailure = "hash_mismatch"
	// RebuildFailureUnsupportedHash reports an instance without a supported hash tuple.
	RebuildFailureUnsupportedHash RebuildFailure = "unsupported_hash"
	// RebuildFailurePreviousHopUnverified reports a previous hop signature that does not verify.
	RebuildFailurePreviousHopUnverified RebuildFailure = "previous_hop_unverified"
	// RebuildFailurePreviousHopTimestamp reports a previous hop t= outside the completion window.
	RebuildFailurePreviousHopTimestamp RebuildFailure = "previous_hop_timestamp"
	// RebuildFailurePreviousHopAlignment reports a failed previous hop d=/mf= match.
	RebuildFailurePreviousHopAlignment RebuildFailure = "previous_hop_alignment"
	// RebuildFailureCustodyRejected reports a broken custody link in the chain below and including the previous hop.
	RebuildFailureCustodyRejected RebuildFailure = "custody_rejected"
	// RebuildFailureNullPreviousSender reports a previous hop whose mf= is the null reverse path.
	RebuildFailureNullPreviousSender RebuildFailure = "null_previous_sender"
	// RebuildFailureAmbiguousPreviousRecipient reports a previous hop rt= with more than one path.
	RebuildFailureAmbiguousPreviousRecipient RebuildFailure = "ambiguous_previous_recipient"
	// RebuildFailureSourceRoute reports a previous hop rt= or mf= carrying an obsolete RFC 5321 source route.
	RebuildFailureSourceRoute RebuildFailure = "source_route"
	// RebuildFailureProtocolFieldsAltered reports a preserved protocol field that changed during the descent.
	RebuildFailureProtocolFieldsAltered RebuildFailure = "protocol_fields_altered"
	// RebuildFailureInternal reports an internal rendering or contract failure.
	RebuildFailureInternal RebuildFailure = "internal"
)

// Known reports whether the failure belongs to the closed vocabulary.
func (f RebuildFailure) Known() bool {
	switch f {
	case RebuildFailureRecipeInvalid, RebuildFailureApplicationInvalid, RebuildFailureSourceUnavailable,
		RebuildFailureLimitExceeded, RebuildFailureHashMismatch, RebuildFailureUnsupportedHash,
		RebuildFailurePreviousHopUnverified, RebuildFailurePreviousHopTimestamp, RebuildFailurePreviousHopAlignment,
		RebuildFailureCustodyRejected, RebuildFailureNullPreviousSender, RebuildFailureAmbiguousPreviousRecipient,
		RebuildFailureSourceRoute, RebuildFailureProtocolFieldsAltered, RebuildFailureInternal:
		return true
	default:
		return false
	}
}

// RebuildRequest binds one eligible evaluation to the deterministic inputs
// of the rebuilt report.
type RebuildRequest struct {
	// Evaluation is the received-DSN evaluation that reached propagation = eligible.
	Evaluation ReceivedEvaluation
	// ReportingMTA is the canonical lowercase DNS name of this system.
	ReportingMTA string
	// Timestamp is the signing instant in Unix seconds, rendered as Date.
	Timestamp uint64
	// MessageIDToken is a fresh bounded alphanumeric token for the Message-ID.
	MessageIDToken []byte
}

// String returns a constant secret-safe request summary.
func (RebuildRequest) String() string { return "dsn.RebuildRequest{redacted}" }

// GoString returns the constant secret-safe request Go representation.
func (r RebuildRequest) GoString() string { return r.String() }

// Format routes every request formatting form through the redacted summary.
func (r RebuildRequest) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// RebuiltReport is the immutable outcome of one rebuild. A rebuilt report
// exposes the unsigned report bytes, the exact next-hop recipient, the
// signing domain proven by the removed completion signature, and the form of
// the third part; every other outcome exposes only closed values.
type RebuiltReport struct {
	outcome     RebuildOutcome
	failure     RebuildFailure
	raw         []byte
	nextHop     []byte
	domain      string
	form        EvidenceForm
	smtputf8    bool
	eightBit    bool
	initialized bool
}

// Valid reports whether the report was produced by Rebuild and is coherent.
func (r RebuiltReport) Valid() bool {
	if !r.initialized || !r.outcome.Known() {
		return false
	}
	if r.outcome == RebuildRebuilt {
		return r.failure == "" && len(r.raw) > 0 && len(r.nextHop) > 2 && r.domain != "" &&
			(r.form == EvidenceFormComplete || r.form == EvidenceFormHeadersOnly)
	}
	return len(r.raw) == 0 && len(r.nextHop) == 0 && r.domain == "" && (r.outcome != RebuildNotReconstructable || r.failure.Known())
}

// Outcome returns the closed rebuild outcome.
func (r RebuiltReport) Outcome() RebuildOutcome { return r.outcome }

// Failure returns the closed cause of a not-reconstructable rebuild.
func (r RebuiltReport) Failure() RebuildFailure { return r.failure }

// Bytes returns a detached copy of the unsigned rebuilt report or nil.
func (r RebuiltReport) Bytes() []byte {
	if !r.Valid() || r.outcome != RebuildRebuilt {
		return nil
	}
	return bytes.Clone(r.raw)
}

// NextHopRecipient returns a detached copy of the exact bracketed previous-hop mf= or nil.
func (r RebuiltReport) NextHopRecipient() []byte {
	if !r.Valid() || r.outcome != RebuildRebuilt {
		return nil
	}
	return bytes.Clone(r.nextHop)
}

// SigningDomain returns the canonical d= of the removed completion signature or an empty string.
func (r RebuiltReport) SigningDomain() string {
	if !r.Valid() || r.outcome != RebuildRebuilt {
		return ""
	}
	return r.domain
}

// Form returns the representation of the rebuilt third part.
func (r RebuiltReport) Form() EvidenceForm {
	if !r.Valid() || r.outcome != RebuildRebuilt {
		return ""
	}
	return r.form
}

// SMTPUTF8Required reports whether any header field of the rebuilt DSN,
// including the header block of the embedded original, carries a non-ASCII
// byte in the RFC 6531/6532 sense. The next-hop path is covered by the To:
// field; an 8-bit body alone never sets it.
func (r RebuiltReport) SMTPUTF8Required() bool {
	return r.Valid() && r.outcome == RebuildRebuilt && r.smtputf8
}

// EightBitMIMERequired reports whether the embedded original's body carries a
// non-ASCII byte, which is an 8BITMIME question for the re-injection client
// rather than an SMTPUTF8 one.
func (r RebuiltReport) EightBitMIMERequired() bool {
	return r.Valid() && r.outcome == RebuildRebuilt && r.eightBit
}

// String returns a constant secret-safe report summary.
func (RebuiltReport) String() string { return rebuiltReportRedactedText }

// GoString returns the constant secret-safe report Go representation.
func (r RebuiltReport) GoString() string { return r.String() }

// Format routes every report formatting form through the redacted summary.
func (r RebuiltReport) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// notReconstructableReport seals one closed failure without output.
func notReconstructableReport(failure RebuildFailure) RebuiltReport {
	if !failure.Known() {
		failure = RebuildFailureInternal
	}
	return RebuiltReport{outcome: RebuildNotReconstructable, failure: failure, initialized: true}
}

// rebuildState carries the intermediate values of one rebuild.
type rebuildState struct {
	run          verify.LocalHopRun
	previousSeq  uint64
	previousInst uint64
	nextHop      []byte
	recipient    []byte
	protocol     []rawmsg.HeaderField
	pruned       rawmsg.HeaderBlock
	initial      recipe.State
	floor        recipe.State
	degraded     bool
}

// Rebuild turns an eligible evaluation into an unsigned Draft-06 Section
// 12.1.1 report: it removes the local hop run and every unsigned field above
// the previous hop, descends the run to the previous hop's instance while
// re-proving every state, restores the pruned wire order for every header
// name the run's recipes did not rewrite, proves the surviving protocol
// fields byte-exact before any key fetch, verifies the previous hop signature
// over that state at the completion instant, degrades to text/rfc822-headers
// when body evidence was unavailable, and generates the fresh report parts.
// Protocol outcomes are returned in the report; only invalid requests,
// ineligible evaluations, cancellation, and internal contract violations
// return a Go error.
func (e ReceivedEvaluator) Rebuild(ctx context.Context, request RebuildRequest) (RebuiltReport, error) {
	if ctx == nil || !e.valid || !e.verifier.Valid() {
		return RebuiltReport{}, newRebuildError(RebuildErrorInvalidRequest, nil)
	}
	if err := ctx.Err(); err != nil {
		return RebuiltReport{}, newRebuildError(RebuildErrorCanceled, err)
	}
	if err := validateRebuildRequest(request); err != nil {
		return RebuiltReport{}, err
	}
	evaluation := request.Evaluation
	state, report := newRebuildState(evaluation)
	if report.initialized {
		return report, nil
	}
	if err := state.prepareInitialState(evaluation); err != nil {
		return notReconstructableReport(RebuildFailureInternal), nil
	}
	descent, err := e.verifier.DescendEmbeddedRun(ctx, evaluation.input, state.initial, state.previousInst)
	if err != nil {
		return RebuiltReport{}, mapRebuildContextError(ctx, err)
	}
	if descent.Outcome() != verify.RunDescentReconstructed {
		return notReconstructableReport(rebuildFailureForDescent(descent.Failure())), nil
	}
	floor, _ := descent.State()
	state.floor, err = restoreWireOrder(state.pruned, floor, descent.RewrittenHeaderNames())
	if err != nil {
		return notReconstructableReport(RebuildFailureInternal), nil
	}
	state.degraded = descent.Degraded() || evaluation.form == EvidenceFormHeadersOnly
	if !state.protocolFieldsPreserved() {
		return notReconstructableReport(RebuildFailureProtocolFieldsAltered), nil
	}
	outcome, err := e.verifier.VerifyHistoricalTarget(ctx, evaluation.input, verify.HistoricalTargetRequest{
		State: state.floor, Sequence: state.previousSeq,
		ReferenceTime: time.Unix(int64(evaluation.completion.timestamp), 0), MaxTimestamp: evaluation.completion.timestamp,
	})
	if err != nil {
		return RebuiltReport{}, mapRebuildContextError(ctx, err)
	}
	if report, stop := rebuildReportForHistoricalOutcome(outcome); stop {
		return report, nil
	}
	return state.render(evaluation, request)
}

// validateRebuildRequest applies the preflight rules for the request values.
func validateRebuildRequest(request RebuildRequest) error {
	evaluation := request.Evaluation
	if !evaluation.Valid() || !validPropagationToken(request.MessageIDToken) || request.Timestamp == 0 || request.Timestamp > maxReferenceUnixSeconds {
		return newRebuildError(RebuildErrorInvalidRequest, nil)
	}
	limits := keyresolver.DefaultLimits()
	canonicalMTA, err := keyresolver.CanonicalSigningDomain(request.ReportingMTA, limits.MaxSigningDomainBytes, limits.MaxSigningDomainLabels)
	if err != nil || canonicalMTA != request.ReportingMTA {
		return newRebuildError(RebuildErrorInvalidRequest, nil)
	}
	if evaluation.Propagation() != PropagationEligible || !evaluation.hasRun || !evaluation.input.Valid() || !evaluation.original.Initialized() ||
		evaluation.CompletionDomain() == "" || evaluation.completion.timestamp == 0 || evaluation.completion.timestamp > maxReferenceUnixSeconds {
		return newRebuildError(RebuildErrorNotEligible, nil)
	}
	return nil
}

// newRebuildState snapshots the run facts and applies the previous-hop
// preconditions that do not need a descent.
func newRebuildState(evaluation ReceivedEvaluation) (*rebuildState, RebuiltReport) {
	run := evaluation.run
	if !run.Valid() || !run.HasPreviousHop() || run.PreviousHopIsNextDomain() {
		return nil, notReconstructableReport(RebuildFailureInternal)
	}
	if run.PreviousHopNullSender() {
		return nil, notReconstructableReport(RebuildFailureNullPreviousSender)
	}
	recipients := run.PreviousHopRecipients()
	if len(recipients) != 1 {
		return nil, notReconstructableReport(RebuildFailureAmbiguousPreviousRecipient)
	}
	nextHop := run.PreviousHopMailFrom()
	if !signature.ValidEnvelopePath(nextHop, false) || !signature.ValidEnvelopePath(recipients[0], false) {
		return nil, notReconstructableReport(RebuildFailureInternal)
	}
	if envelopePathHasSourceRoute(nextHop) || envelopePathHasSourceRoute(recipients[0]) {
		return nil, notReconstructableReport(RebuildFailureSourceRoute)
	}
	return &rebuildState{
		run: run, previousSeq: run.PreviousHopSequence(), previousInst: run.PreviousHopInstance(),
		nextHop: nextHop, recipient: recipients[0],
	}, RebuiltReport{}
}

// envelopePathHasSourceRoute reports whether a grammar-valid bracketed SMTP
// path carries the obsolete RFC 5321 A-d-l source route. A valid local part
// never starts with '@', so the first inner byte decides. The rebuild refuses
// such paths because a propagated DSN must never emit a source route in
// Final-Recipient or To:.
func envelopePathHasSourceRoute(path []byte) bool {
	return len(path) > 2 && path[0] == '<' && path[1] == '@'
}

// prepareInitialState removes the run's DKIM2-Signature fields, every
// Message-Instance above the previous hop's instance, and every Section 4
// hash-excluded field above the previous hop signature, and wraps the
// remaining fields and the embedded body into the proven initial state.
func (s *rebuildState) prepareInitialState(evaluation ReceivedEvaluation) error {
	fields, protocol, err := pruneHeaderBlock(evaluation.original.Headers(), evaluation.input, s.run)
	if err != nil {
		return err
	}
	s.protocol = protocol
	options := rawmsg.DefaultParserOptions()
	headers, err := rawmsg.NewReconstructedHeaderBlock(fields, options)
	if err != nil {
		return newRebuildError(RebuildErrorInternal, err)
	}
	s.pruned = headers
	if evaluation.form == EvidenceFormHeadersOnly {
		s.initial, err = recipe.NewHeadersOnlyState(headers)
		if err != nil {
			return newRebuildError(RebuildErrorInternal, err)
		}
		return nil
	}
	message, err := rawmsg.NewReconstructedMessageWithFraming(headers, evaluation.original.Body(), options, evaluation.original.Framing())
	if err != nil {
		return newRebuildError(RebuildErrorInternal, err)
	}
	s.initial, err = recipe.NewState(message)
	if err != nil {
		return newRebuildError(RebuildErrorInternal, err)
	}
	return nil
}

// pruneHeaderBlock applies the Section 12.1.1 removal rules by field and tag
// value. It returns the surviving field bytes in wire order and the surviving
// protocol fields, whose bytes must reach the rebuilt report unchanged.
func pruneHeaderBlock(headers rawmsg.HeaderBlock, input verify.EmbeddedInput, run verify.LocalHopRun) ([][]byte, []rawmsg.HeaderField, error) {
	sequences := make(map[int]uint64)
	previousIndex := -1
	for _, parsed := range input.Signatures() {
		sequences[parsed.HeaderIndex()] = parsed.Sequence()
		if parsed.Sequence() == run.PreviousHopSequence() {
			previousIndex = parsed.HeaderIndex()
		}
	}
	numbers := make(map[int]uint64)
	for _, parsed := range input.Instances() {
		numbers[parsed.HeaderIndex()] = parsed.Number()
	}
	if previousIndex < 0 {
		return nil, nil, newRebuildError(RebuildErrorInternal, nil)
	}
	members := make(map[uint64]struct{})
	for _, member := range run.Members() {
		members[member] = struct{}{}
	}
	relevance := canonical.NewHeaderRelevance()
	fields := make([][]byte, 0, headers.Len())
	protocol := make([]rawmsg.HeaderField, 0)
	for _, field := range headers.Fields() {
		switch field.NameLower() {
		case signature.HeaderName:
			sequence, ok := sequences[field.Index()]
			if !ok {
				return nil, nil, newRebuildError(RebuildErrorInternal, nil)
			}
			if _, member := members[sequence]; member {
				continue
			}
			protocol = append(protocol, field)
		case instance.HeaderName:
			number, ok := numbers[field.Index()]
			if !ok {
				return nil, nil, newRebuildError(RebuildErrorInternal, nil)
			}
			if number > run.PreviousHopInstance() {
				continue
			}
			protocol = append(protocol, field)
		default:
			if field.Index() < previousIndex {
				relevant, err := relevance.IsRelevantHeader(field.NameLower())
				if err != nil {
					return nil, nil, newRebuildError(RebuildErrorInternal, err)
				}
				if !relevant {
					continue
				}
			}
		}
		fields = append(fields, field.OriginalBytes())
	}
	return fields, protocol, nil
}

// restoreWireOrder re-emits the floor state's header fields so that every
// name the run's recipes did not rewrite keeps the pruned wire order, while
// each rewritten name keeps the applier's regrouped fields at the position of
// its first wire occurrence; a rewritten name without a wire anchor is
// appended after the wire-ordered fields in floor order. The Section 6.2
// header hash is order-neutral across names, so the re-ordered state proves
// against the same instance. An untouched name whose floor group differs
// from its wire group is an internal contract violation and fails closed.
func restoreWireOrder(pruned rawmsg.HeaderBlock, floor recipe.State, rewritten []string) (recipe.State, error) {
	if !floor.Valid() {
		return recipe.State{}, newRebuildError(RebuildErrorInternal, nil)
	}
	touched := make(map[string]struct{}, len(rewritten))
	for _, name := range rewritten {
		touched[name] = struct{}{}
	}
	groups := make(map[string][]rawmsg.HeaderField)
	floorOrder := make([]string, 0)
	for _, field := range floor.Headers().Fields() {
		name := field.NameLower()
		if _, seen := groups[name]; !seen {
			floorOrder = append(floorOrder, name)
		}
		groups[name] = append(groups[name], field)
	}
	ordered := make([][]byte, 0, floor.Headers().Len())
	emitted := make(map[string]struct{})
	consumed := make(map[string]int)
	for _, field := range pruned.Fields() {
		name := field.NameLower()
		if _, rewrote := touched[name]; rewrote {
			if _, done := emitted[name]; !done {
				emitted[name] = struct{}{}
				for _, regrouped := range groups[name] {
					ordered = append(ordered, regrouped.OriginalBytes())
				}
			}
			continue
		}
		group := groups[name]
		index := consumed[name]
		if index >= len(group) || !bytes.Equal(group[index].OriginalBytes(), field.OriginalBytes()) {
			return recipe.State{}, newRebuildError(RebuildErrorInternal, nil)
		}
		consumed[name] = index + 1
		ordered = append(ordered, field.OriginalBytes())
	}
	for _, name := range floorOrder {
		if _, rewrote := touched[name]; !rewrote {
			if consumed[name] != len(groups[name]) {
				return recipe.State{}, newRebuildError(RebuildErrorInternal, nil)
			}
			continue
		}
		if _, done := emitted[name]; done {
			continue
		}
		emitted[name] = struct{}{}
		for _, regrouped := range groups[name] {
			ordered = append(ordered, regrouped.OriginalBytes())
		}
	}
	if len(ordered) != floor.Headers().Len() {
		return recipe.State{}, newRebuildError(RebuildErrorInternal, nil)
	}
	options := rawmsg.DefaultParserOptions()
	headers, err := rawmsg.NewReconstructedHeaderBlock(ordered, options)
	if err != nil {
		return recipe.State{}, newRebuildError(RebuildErrorInternal, err)
	}
	body, known := floor.Body()
	if !known {
		state, err := recipe.NewHeadersOnlyState(headers)
		if err != nil {
			return recipe.State{}, newRebuildError(RebuildErrorInternal, err)
		}
		return state, nil
	}
	message, err := rawmsg.NewReconstructedMessageWithFraming(headers, body, options, floor.Framing())
	if err != nil {
		return recipe.State{}, newRebuildError(RebuildErrorInternal, err)
	}
	state, err := recipe.NewState(message)
	if err != nil {
		return recipe.State{}, newRebuildError(RebuildErrorInternal, err)
	}
	return state, nil
}

// protocolFieldsPreserved proves that every surviving DKIM2-Signature and
// Message-Instance field reached the floor state byte-exact and in order.
func (s *rebuildState) protocolFieldsPreserved() bool {
	remaining := s.floor.Headers().Fields()
	return equalFieldSequence(filterFields(s.protocol, signature.HeaderName), filterFields(remaining, signature.HeaderName)) &&
		equalFieldSequence(filterFields(s.protocol, instance.HeaderName), filterFields(remaining, instance.HeaderName))
}

// filterFields keeps the fields whose lowercase name equals nameLower, preserving order.
func filterFields(fields []rawmsg.HeaderField, nameLower string) []rawmsg.HeaderField {
	filtered := make([]rawmsg.HeaderField, 0, len(fields))
	for _, field := range fields {
		if field.NameLower() == nameLower {
			filtered = append(filtered, field)
		}
	}
	return filtered
}

// equalFieldSequence compares two field lists byte-exact in order.
func equalFieldSequence(left, right []rawmsg.HeaderField) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !bytes.Equal(left[index].OriginalBytes(), right[index].OriginalBytes()) {
			return false
		}
	}
	return true
}

// render serializes the third part and generates the report.
func (s *rebuildState) render(evaluation ReceivedEvaluation, request RebuildRequest) (RebuiltReport, error) {
	var original []byte
	var err error
	form := EvidenceFormComplete
	contentType := ContentTypeRFC822
	if s.degraded {
		form, contentType = EvidenceFormHeadersOnly, ContentTypeRFC822Headers
		original, err = serializeHeadersOnly(s.floor)
	} else {
		original, err = serializeComplete(s.floor)
	}
	if err != nil {
		return notReconstructableReport(RebuildFailureInternal), nil
	}
	headers := s.floor.Headers().OriginalBytes()
	if !bytes.HasPrefix(original, headers) {
		return notReconstructableReport(RebuildFailureInternal), nil
	}
	input := propagationReportInput{
		reportingMTA: request.ReportingMTA, timestamp: request.Timestamp, token: bytes.Clone(request.MessageIDToken),
		nextHop: s.nextHop, finalRecipient: s.recipient[1 : len(s.recipient)-1],
		status: propagationStatus(evaluation.status), originalContentType: contentType,
		originalHeaders: headers, originalBody: original[len(headers):],
	}
	if envelopeID, ok := evaluation.OriginalEnvelopeID(); ok && validPropagationEnvelopeID(envelopeID) {
		input.envelopeID, input.hasEnvelopeID = envelopeID, true
	}
	if originalRecipient, ok := evaluation.OriginalRecipientFor(s.recipient); ok && len(originalRecipient) <= propagationMaxOriginalRecipientBytes {
		input.originalRecipient, input.hasOriginal = originalRecipient, true
	}
	rendered, err := renderPropagationReport(input)
	if err != nil {
		return notReconstructableReport(RebuildFailureInternal), nil
	}
	if len(rendered.raw) > evaluation.receivedBytes+PropagationFixedPartsBound {
		return notReconstructableReport(RebuildFailureLimitExceeded), nil
	}
	report := RebuiltReport{
		outcome: RebuildRebuilt, raw: rendered.raw, nextHop: bytes.Clone(s.nextHop), domain: evaluation.CompletionDomain(),
		form: form, smtputf8: rendered.transport.smtputf8, eightBit: rendered.transport.eightBitMIME, initialized: true,
	}
	if !report.Valid() {
		return notReconstructableReport(RebuildFailureInternal), nil
	}
	return report, nil
}

// rebuildFailureForDescent maps the closed descent failure onto the rebuild failure.
func rebuildFailureForDescent(failure verify.RunDescentFailure) RebuildFailure {
	switch failure {
	case verify.RunDescentRecipeInvalid:
		return RebuildFailureRecipeInvalid
	case verify.RunDescentApplicationInvalid:
		return RebuildFailureApplicationInvalid
	case verify.RunDescentSourceUnavailable:
		return RebuildFailureSourceUnavailable
	case verify.RunDescentLimitExceeded:
		return RebuildFailureLimitExceeded
	case verify.RunDescentHashMismatch:
		return RebuildFailureHashMismatch
	case verify.RunDescentUnsupportedHash:
		return RebuildFailureUnsupportedHash
	default:
		return RebuildFailureInternal
	}
}

// rebuildReportForHistoricalOutcome maps the previous-hop verification
// outcome onto a stopping report; verified continues the rebuild.
func rebuildReportForHistoricalOutcome(outcome verify.HistoricalTargetOutcome) (RebuiltReport, bool) {
	switch outcome {
	case verify.HistoricalTargetVerified:
		return RebuiltReport{}, false
	case verify.HistoricalTargetTemporary:
		return RebuiltReport{outcome: RebuildTemporary, initialized: true}, true
	case verify.HistoricalTargetTimestampRejected:
		return notReconstructableReport(RebuildFailurePreviousHopTimestamp), true
	case verify.HistoricalTargetAlignmentRejected:
		return notReconstructableReport(RebuildFailurePreviousHopAlignment), true
	case verify.HistoricalTargetCustodyRejected:
		return notReconstructableReport(RebuildFailureCustodyRejected), true
	case verify.HistoricalTargetNullSender:
		return notReconstructableReport(RebuildFailureNullPreviousSender), true
	default:
		return notReconstructableReport(RebuildFailurePreviousHopUnverified), true
	}
}

// mapRebuildContextError classifies a verifier seam error as cancellation or an internal failure.
func mapRebuildContextError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
		return newRebuildError(RebuildErrorCanceled, ctxErr)
	}
	return newRebuildError(RebuildErrorInternal, err)
}

// ProvePropagatedReport re-parses a signed propagated report and requires
// exactly one Message-Instance m=1 and one DKIM2-Signature i=1 under the
// signing domain with mf=<> and rt= equal to the next-hop recipient, the
// Draft-06 Section 12.1.1 single-signature invariant of a propagated DSN.
func ProvePropagatedReport(raw, nextHop []byte, domain string) error {
	message, err := rawmsg.Parse(raw)
	if err != nil {
		return newRebuildError(RebuildErrorInternal, err)
	}
	instances, err := instance.Extract(message)
	if err != nil || len(instances) != 1 || instances[0].Number() != 1 {
		return newRebuildError(RebuildErrorInternal, err)
	}
	signatures, err := signature.Extract(message)
	if err != nil || len(signatures) != 1 {
		return newRebuildError(RebuildErrorInternal, err)
	}
	parsed := signatures[0]
	recipients := parsed.Recipients()
	if parsed.Sequence() != 1 || parsed.InstanceNumber() != 1 || parsed.HasNextDomain() || parsed.Domain() != domain ||
		!bytes.Equal(parsed.MailFrom().Value(), []byte("<>")) || len(recipients) != 1 || !bytes.Equal(recipients[0].Value(), nextHop) {
		return newRebuildError(RebuildErrorInternal, nil)
	}
	return nil
}
