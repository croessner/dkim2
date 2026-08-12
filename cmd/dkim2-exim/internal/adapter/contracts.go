package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
)

const (
	buildIDBytes                = 64
	maxPeerBytes                = 64
	maxHELOBytes                = 255
	maxReceivedProtocolBytes    = 32
	maxEnvelopeBytes            = 256
	maxRecipients               = 2_000
	maxHeaders                  = 2_000
	maxHeaderFieldBytes         = 65_536
	maxHeaderAggregateBytes     = 1 << 20
	maxMessageBytes             = 32 << 20
	maxActionValueBytes         = 65_535
	headerAuthenticationResults = "Authentication-Results"
	headerMessageInstance       = "Message-Instance"
	headerDKIM2Signature        = "DKIM2-Signature"
)

// Fidelity identifies the exact Exim-derived daemon representation.
type Fidelity uint8

const (
	// FidelityLocalScanCRLF identifies deterministic local-scan CRLF projection.
	FidelityLocalScanCRLF Fidelity = iota + 1
	// FidelityTransportFilterCRLF identifies deterministic filter CRLF projection.
	FidelityTransportFilterCRLF
)

// FailureClass is the closed adapter failure vocabulary.
type FailureClass uint8

const (
	// FailureInvalidRequest identifies malformed adapter input.
	FailureInvalidRequest FailureClass = iota + 1
	// FailureFidelity identifies ambiguous message representation.
	FailureFidelity
	// FailureContract identifies daemon or IPC contract drift.
	FailureContract
	// FailureResource identifies a bounded resource rejection.
	FailureResource
	// FailureUnavailable identifies an unavailable dependency.
	FailureUnavailable
	// FailureTimeout identifies an operation deadline.
	FailureTimeout
	// FailureInternal identifies a closed internal invariant.
	FailureInternal
	// FailurePartialOutput identifies indeterminate filter output.
	FailurePartialOutput
)

// Error identifies an adapter failure without retaining rejected data.
type Error struct {
	class FailureClass
}

// NewError constructs one closed content-free adapter failure.
func NewError(class FailureClass) error {
	if class < FailureInvalidRequest || class > FailurePartialOutput {
		class = FailureInternal
	}
	return &Error{class: class}
}

// Class returns the closed failure class.
func (e *Error) Class() FailureClass {
	if e == nil || e.class < FailureInvalidRequest || e.class > FailurePartialOutput {
		return FailureInternal
	}
	return e.class
}

// Error returns one bounded content-free failure class.
func (e *Error) Error() string {
	if e == nil {
		return "exim adapter failure"
	}
	switch e.Class() {
	case FailureInvalidRequest:
		return "exim adapter invalid request"
	case FailureFidelity:
		return "exim adapter fidelity failure"
	case FailureContract:
		return "exim adapter contract failure"
	case FailureResource:
		return "exim adapter resource failure"
	case FailureUnavailable:
		return "exim adapter unavailable"
	case FailureTimeout:
		return "exim adapter timeout"
	case FailureInternal:
		return "exim adapter internal failure"
	case FailurePartialOutput:
		return "exim adapter partial output indeterminate"
	default:
		return "exim adapter failure"
	}
}

// String returns a content-free adapter diagnostic.
func (e Error) String() string { return e.Error() }

// GoString returns the content-free Go representation.
func (e Error) GoString() string { return e.String() }

// Format prevents formatting from traversing rejected adapter evidence.
func (e Error) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, e.String())
}

// MarshalJSON rejects serialization that could weaken the closed diagnostic.
func (Error) MarshalJSON() ([]byte, error) {
	return nil, NewError(FailureContract)
}

// MarshalText rejects textual serialization outside the closed diagnostic.
func (Error) MarshalText() ([]byte, error) {
	return nil, NewError(FailureContract)
}

// SessionClass identifies one canonical Exim ingress class.
type SessionClass uint8

const (
	// SessionLocal identifies non-SMTP local submission.
	SessionLocal SessionClass = iota
	// SessionSMTP identifies ordinary SMTP input.
	SessionSMTP
	// SessionBSMTP identifies BSMTP input with canonical precedence.
	SessionBSMTP
)

// ObservedHeader is one exact non-deleted Exim header field.
type ObservedHeader struct {
	bytes []byte
}

// LocalScanRequest owns immutable primitive receive-time evidence.
type LocalScanRequest struct {
	buildID          []byte
	session          SessionClass
	peer             []byte
	peerPort         uint16
	helo             []byte
	receivedProtocol []byte
	mailFrom         []byte
	recipients       [][]byte
	headers          []ObservedHeader
	body             []byte
}

// NewLocalScanRequest validates required state and copies receive-time evidence.
func NewLocalScanRequest(
	buildID []byte,
	session SessionClass,
	peer []byte,
	peerPort uint16,
	helo []byte,
	receivedProtocol []byte,
	mailFrom []byte,
	recipients [][]byte,
	headers [][]byte,
	body []byte,
) (LocalScanRequest, error) {
	if !validBuildID(buildID) || session > SessionBSMTP || len(recipients) == 0 ||
		(len(peer) == 0) != (peerPort == 0) ||
		!validScalar(peer) || !validScalar(helo) ||
		!validScalar(receivedProtocol) || !validScalar(mailFrom) {
		return LocalScanRequest{}, NewError(FailureInvalidRequest)
	}
	if len(peer) > maxPeerBytes || len(helo) > maxHELOBytes ||
		len(receivedProtocol) > maxReceivedProtocolBytes ||
		len(mailFrom) > maxEnvelopeBytes || len(recipients) > maxRecipients ||
		len(headers) > maxHeaders {
		return LocalScanRequest{}, NewError(FailureResource)
	}
	for _, recipient := range recipients {
		if !validScalar(recipient) {
			return LocalScanRequest{}, NewError(FailureInvalidRequest)
		}
		if len(recipient) > maxEnvelopeBytes {
			return LocalScanRequest{}, NewError(FailureResource)
		}
	}
	headerBytes := 0
	for _, header := range headers {
		if !validHeader(header) {
			return LocalScanRequest{}, NewError(FailureFidelity)
		}
		if len(header) > maxHeaderFieldBytes ||
			len(header) > maxHeaderAggregateBytes-headerBytes {
			return LocalScanRequest{}, NewError(FailureResource)
		}
		headerBytes += len(header)
	}
	if len(body) > maxMessageBytes-1-headerBytes {
		return LocalScanRequest{}, NewError(FailureResource)
	}
	observed := make([]ObservedHeader, len(headers))
	for index := range headers {
		observed[index] = ObservedHeader{bytes: slices.Clone(headers[index])}
	}
	return LocalScanRequest{
		buildID: slices.Clone(buildID), session: session, peer: slices.Clone(peer),
		peerPort: peerPort, helo: slices.Clone(helo),
		receivedProtocol: slices.Clone(receivedProtocol),
		mailFrom:         slices.Clone(mailFrom), recipients: cloneBytes(recipients),
		headers: observed, body: slices.Clone(body),
	}, nil
}

// BuildID returns an immutable compatibility identifier copy.
func (r LocalScanRequest) BuildID() []byte { return slices.Clone(r.buildID) }

// Session returns the canonical receive-session class.
func (r LocalScanRequest) Session() SessionClass { return r.session }

// Peer returns an immutable peer observation copy.
func (r LocalScanRequest) Peer() []byte { return slices.Clone(r.peer) }

// PeerPort returns the peer port or zero when the peer is absent.
func (r LocalScanRequest) PeerPort() uint16 { return r.peerPort }

// HELO returns an immutable HELO observation copy.
func (r LocalScanRequest) HELO() []byte { return slices.Clone(r.helo) }

// ReceivedProtocol returns an immutable protocol observation copy.
func (r LocalScanRequest) ReceivedProtocol() []byte {
	return slices.Clone(r.receivedProtocol)
}

// MailFrom returns an immutable reverse-path copy.
func (r LocalScanRequest) MailFrom() []byte { return slices.Clone(r.mailFrom) }

// Recipients returns immutable ordered recipient copies.
func (r LocalScanRequest) Recipients() [][]byte { return cloneBytes(r.recipients) }

// Headers returns immutable observed header copies.
func (r LocalScanRequest) Headers() [][]byte {
	output := make([][]byte, len(r.headers))
	for index := range r.headers {
		output[index] = slices.Clone(r.headers[index].bytes)
	}
	return output
}

// Body returns an immutable observed body copy.
func (r LocalScanRequest) Body() []byte { return slices.Clone(r.body) }

// String returns a content-free request diagnostic.
func (LocalScanRequest) String() string { return "exim_local_scan_request{redacted}" }

// GoString returns a content-free request representation.
func (r LocalScanRequest) GoString() string { return r.String() }

// Format prevents formatting from traversing received mail.
func (r LocalScanRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// MarshalJSON rejects serialization of received mail.
func (LocalScanRequest) MarshalJSON() ([]byte, error) {
	return nil, NewError(FailureContract)
}

// MarshalText rejects textual serialization of received mail.
func (LocalScanRequest) MarshalText() ([]byte, error) {
	return nil, NewError(FailureContract)
}

// IncomingEvidence owns immutable receive-time SMTP authority.
type IncomingEvidence struct {
	mailFrom   []byte
	recipients [][]byte
	session    SessionClass
}

// NewIncomingEvidence validates and copies immutable receive-time authority.
func NewIncomingEvidence(
	mailFrom []byte,
	recipients [][]byte,
	session SessionClass,
) (IncomingEvidence, error) {
	canonicalMailFrom, err := CanonicalEximPath(mailFrom, true)
	if err != nil || len(recipients) == 0 || session > SessionBSMTP {
		return IncomingEvidence{}, NewError(FailureInvalidRequest)
	}
	if len(canonicalMailFrom) > maxEnvelopeBytes || len(recipients) > maxRecipients {
		return IncomingEvidence{}, NewError(FailureResource)
	}
	canonicalRecipients := make([][]byte, len(recipients))
	for index, recipient := range recipients {
		canonicalRecipient, canonicalErr := CanonicalEximPath(recipient, false)
		if canonicalErr != nil {
			return IncomingEvidence{}, NewError(FailureInvalidRequest)
		}
		if len(canonicalRecipient) > maxEnvelopeBytes {
			return IncomingEvidence{}, NewError(FailureResource)
		}
		canonicalRecipients[index] = canonicalRecipient
	}
	return IncomingEvidence{
		mailFrom: canonicalMailFrom, recipients: canonicalRecipients, session: session,
	}, nil
}

// CanonicalEximPath converts an Exim bare address or an already bracketed path
// into one unambiguous RFC 5321 path while preserving every permitted EAI byte.
func CanonicalEximPath(value []byte, reverse bool) ([]byte, error) {
	if !validScalar(value) {
		return nil, NewError(FailureInvalidRequest)
	}
	if len(value) == 0 {
		if reverse {
			return []byte("<>"), nil
		}
		return nil, NewError(FailureInvalidRequest)
	}
	if value[0] == '<' || value[len(value)-1] == '>' {
		if reverse && len(value) == 2 && value[0] == '<' && value[1] == '>' {
			return slices.Clone(value), nil
		}
		if len(value) < 3 || value[0] != '<' || value[len(value)-1] != '>' ||
			bytes.ContainsAny(value[1:len(value)-1], "<>") {
			return nil, NewError(FailureInvalidRequest)
		}
		return slices.Clone(value), nil
	}
	if bytes.ContainsAny(value, "<>") {
		return nil, NewError(FailureInvalidRequest)
	}
	canonical := make([]byte, 0, len(value)+2)
	canonical = append(canonical, '<')
	canonical = append(canonical, value...)
	canonical = append(canonical, '>')
	return canonical, nil
}

// MailFrom returns an immutable receive-time reverse-path copy.
func (e IncomingEvidence) MailFrom() []byte { return slices.Clone(e.mailFrom) }

// Recipients returns immutable ordered receive-time recipient copies.
func (e IncomingEvidence) Recipients() [][]byte { return cloneBytes(e.recipients) }

// Session returns the canonical receive-session class.
func (e IncomingEvidence) Session() SessionClass { return e.session }

// String returns a content-free incoming-evidence diagnostic.
func (IncomingEvidence) String() string { return "exim_incoming_evidence{redacted}" }

// GoString returns a content-free incoming-evidence representation.
func (e IncomingEvidence) GoString() string { return e.String() }

// Format prevents formatting from traversing receive-time authority.
func (e IncomingEvidence) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, e.String())
}

// MarshalJSON rejects incoming-evidence serialization.
func (IncomingEvidence) MarshalJSON() ([]byte, error) {
	return nil, NewError(FailureContract)
}

// MarshalText rejects incoming-evidence text serialization.
func (IncomingEvidence) MarshalText() ([]byte, error) {
	return nil, NewError(FailureContract)
}

// OutgoingEnvelope owns distinct current transport authority.
type OutgoingEnvelope struct {
	mailFrom  []byte
	recipient []byte
}

// NewOutgoingEnvelope validates and copies one single-recipient batch.
func NewOutgoingEnvelope(mailFrom, recipient []byte) (OutgoingEnvelope, error) {
	if len(recipient) == 0 || !validOutboundScalar(mailFrom) ||
		!validOutboundScalar(recipient) {
		return OutgoingEnvelope{}, NewError(FailureInvalidRequest)
	}
	if len(mailFrom) > maxEnvelopeBytes || len(recipient) > maxEnvelopeBytes {
		return OutgoingEnvelope{}, NewError(FailureResource)
	}
	return OutgoingEnvelope{
		mailFrom: slices.Clone(mailFrom), recipient: slices.Clone(recipient),
	}, nil
}

// MailFrom returns an immutable current reverse-path copy.
func (e OutgoingEnvelope) MailFrom() []byte { return slices.Clone(e.mailFrom) }

// Recipient returns an immutable sole delivery-recipient copy.
func (e OutgoingEnvelope) Recipient() []byte { return slices.Clone(e.recipient) }

// String returns a content-free outgoing-envelope diagnostic.
func (OutgoingEnvelope) String() string { return "exim_outgoing_envelope{redacted}" }

// GoString returns a content-free outgoing-envelope representation.
func (e OutgoingEnvelope) GoString() string { return e.String() }

// Format prevents formatting from traversing transport authority.
func (e OutgoingEnvelope) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, e.String())
}

// MarshalJSON rejects outgoing-envelope serialization.
func (OutgoingEnvelope) MarshalJSON() ([]byte, error) {
	return nil, NewError(FailureContract)
}

// MarshalText rejects outgoing-envelope text serialization.
func (OutgoingEnvelope) MarshalText() ([]byte, error) {
	return nil, NewError(FailureContract)
}

// FilterOperation identifies one fixed one-shot daemon operation.
type FilterOperation uint8

const (
	// FilterSign identifies originator signing.
	FilterSign FilterOperation = iota + 1
	// FilterRevise identifies ordinary-transit revision.
	FilterRevise
)

// Operation identifies the adapter path that owns an admitted plan.
type Operation uint8

const (
	// OperationProcess identifies receive-time verification and policy.
	OperationProcess Operation = iota + 1
	// OperationSign identifies originator signing.
	OperationSign
	// OperationRevise identifies ordinary-transit revision.
	OperationRevise
)

// Disposition identifies one closed daemon outcome.
type Disposition uint8

const (
	// DispositionAccept admits a complete action plan.
	DispositionAccept Disposition = iota + 1
	// DispositionContinue admits unchanged delivery.
	DispositionContinue
	// DispositionReject identifies a permanent policy failure.
	DispositionReject
	// DispositionTempfail identifies a temporary failure.
	DispositionTempfail
)

// ActionKind identifies one append-only admitted header action.
type ActionKind uint8

// ActionAddHeader identifies an append-only header action.
const ActionAddHeader ActionKind = 1

// Action is one immutable admitted daemon mutation.
type Action struct {
	kind  ActionKind
	name  string
	value string
}

// NewAction validates and copies one generated append-only action.
func NewAction(kind ActionKind, name, value string) (Action, error) {
	if kind != ActionAddHeader || !validActionName(name) ||
		len(value) == 0 || len(value) > maxActionValueBytes ||
		stringsContainFraming(value) {
		return Action{}, NewError(FailureContract)
	}
	return Action{kind: kind, name: name, value: value}, nil
}

// Name returns the admitted bounded field name.
func (a Action) Name() string { return a.name }

// Value returns the admitted bounded field value.
func (a Action) Value() string { return a.value }

// String returns a content-free action diagnostic.
func (Action) String() string { return "exim_action{redacted}" }

// GoString returns a content-free action representation.
func (a Action) GoString() string { return a.String() }

// Format prevents formatting from traversing a header value.
func (a Action) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, a.String()) }

// MarshalJSON rejects serialization outside the generated boundary.
func (Action) MarshalJSON() ([]byte, error) { return nil, NewError(FailureContract) }

// MarshalText rejects textual serialization outside the generated boundary.
func (Action) MarshalText() ([]byte, error) { return nil, NewError(FailureContract) }

// Result identifies one closed daemon result.
type Result uint8

const (
	// ResultPass identifies successful protocol processing.
	ResultPass Result = iota + 1
	// ResultFail identifies a protocol failure.
	ResultFail
	// ResultPermerror identifies permanent malformed state.
	ResultPermerror
	// ResultTemperror identifies temporary processing failure.
	ResultTemperror
	// ResultNone identifies an operation-owned not-applicable result.
	ResultNone
)

// Plan is one complete admitted daemon outcome and ordered mutation list.
type Plan struct {
	operation   Operation
	result      Result
	disposition Disposition
	actions     []Action
}

// NewPlan validates one process outcome and its receive-time action ownership.
func NewPlan(result Result, disposition Disposition, actions []Action) (Plan, error) {
	return newPlan(OperationProcess, result, disposition, actions)
}

// NewFilterPlan validates one sign or revise outcome and its exact action matrix.
func NewFilterPlan(
	operation FilterOperation,
	result Result,
	disposition Disposition,
	actions []Action,
) (Plan, error) {
	if operation != FilterSign && operation != FilterRevise {
		return Plan{}, NewError(FailureContract)
	}
	owner := OperationSign
	if operation == FilterRevise {
		owner = OperationRevise
	}
	return newPlan(owner, result, disposition, actions)
}

// newPlan validates and copies one operation-owned admitted outcome.
func newPlan(
	operation Operation,
	result Result,
	disposition Disposition,
	actions []Action,
) (Plan, error) {
	if result < ResultPass || result > ResultNone ||
		disposition < DispositionAccept || disposition > DispositionTempfail ||
		!validPlanActions(operation, result, disposition, actions) {
		return Plan{}, NewError(FailureContract)
	}
	return Plan{
		operation: operation, result: result, disposition: disposition,
		actions: slices.Clone(actions),
	}, nil
}

// validPlanActions keeps operation result, disposition, and action ownership closed.
func validPlanActions(
	operation Operation,
	result Result,
	disposition Disposition,
	actions []Action,
) bool {
	if !validPlanActionFraming(disposition, actions) {
		return false
	}
	if result == ResultNone {
		return (operation == OperationProcess || operation == OperationSign) &&
			disposition == DispositionContinue && len(actions) == 0
	}
	if operation == OperationProcess {
		return validProcessPlanActions(actions)
	}
	if !validFilterDisposition(result, disposition) {
		return false
	}
	if disposition != DispositionAccept {
		return len(actions) == 0
	}
	if result != ResultPass {
		return false
	}
	for _, action := range actions {
		if action.value[0] != ' ' && action.value[0] != '\t' {
			return false
		}
	}
	switch operation {
	case OperationSign:
		return len(actions) == 2 &&
			actions[0].name == headerMessageInstance &&
			actions[1].name == headerDKIM2Signature
	case OperationRevise:
		return len(actions) == 1 && actions[0].name == headerDKIM2Signature ||
			len(actions) == 2 &&
				actions[0].name == headerMessageInstance &&
				actions[1].name == headerDKIM2Signature
	default:
		return false
	}
}

// validPlanActionFraming rejects malformed mutations before operation-specific ownership checks.
func validPlanActionFraming(disposition Disposition, actions []Action) bool {
	if disposition != DispositionAccept && len(actions) != 0 {
		return false
	}
	for _, action := range actions {
		if action.kind != ActionAddHeader || !validActionName(action.name) ||
			len(action.value) == 0 || len(action.value) > maxActionValueBytes ||
			stringsContainFraming(action.value) {
			return false
		}
	}
	return true
}

// validProcessPlanActions preserves receive-time policy ownership separately from filter outcomes.
func validProcessPlanActions(actions []Action) bool {
	return len(actions) == 0 || len(actions) == 1 &&
		actions[0].name == headerAuthenticationResults
}

// validFilterDisposition keeps the filter result and disposition matrix closed.
func validFilterDisposition(result Result, disposition Disposition) bool {
	switch result {
	case ResultPass:
		return disposition == DispositionAccept || disposition == DispositionContinue
	case ResultFail, ResultPermerror:
		return disposition == DispositionReject
	case ResultTemperror:
		return disposition == DispositionTempfail
	default:
		return false
	}
}

// Operation returns the operation that owns the admitted plan.
func (p Plan) Operation() Operation { return p.operation }

// Result returns the closed daemon result.
func (p Plan) Result() Result { return p.result }

// Disposition returns the closed daemon disposition.
func (p Plan) Disposition() Disposition { return p.disposition }

// Actions returns an immutable action copy.
func (p Plan) Actions() []Action { return slices.Clone(p.actions) }

// String returns a content-free plan diagnostic.
func (Plan) String() string { return "exim_action_plan{redacted}" }

// GoString returns a content-free plan representation.
func (p Plan) GoString() string { return p.String() }

// Format prevents formatting from traversing action values.
func (p Plan) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, p.String()) }

// MarshalJSON rejects plan serialization outside the generated boundary.
func (Plan) MarshalJSON() ([]byte, error) { return nil, NewError(FailureContract) }

// MarshalText rejects textual plan serialization outside the generated boundary.
func (Plan) MarshalText() ([]byte, error) { return nil, NewError(FailureContract) }

// FilterRequest owns one immutable full-message operation projection.
type FilterRequest struct {
	operation FilterOperation
	message   []byte
	outgoing  OutgoingEnvelope
	incoming  *IncomingEvidence
}

// NewSignRequest constructs one originator request without incoming evidence.
func NewSignRequest(message []byte, outgoing OutgoingEnvelope) (FilterRequest, error) {
	if !validOutgoingEnvelope(outgoing) {
		return FilterRequest{}, NewError(FailureInvalidRequest)
	}
	complete, err := prepareTransportMessage(message)
	if err != nil {
		return FilterRequest{}, err
	}
	return FilterRequest{
		operation: FilterSign, message: complete, outgoing: outgoing.clone(),
	}, nil
}

// NewReviseRequest constructs one ordinary-transit request with distinct evidence.
func NewReviseRequest(
	message []byte,
	outgoing OutgoingEnvelope,
	incoming IncomingEvidence,
) (FilterRequest, error) {
	if !validOutgoingEnvelope(outgoing) || !validIncomingEvidence(incoming) {
		return FilterRequest{}, NewError(FailureInvalidRequest)
	}
	complete, err := prepareTransportMessage(message)
	if err != nil {
		return FilterRequest{}, err
	}
	value := incoming.clone()
	return FilterRequest{
		operation: FilterRevise, message: complete,
		outgoing: outgoing.clone(), incoming: &value,
	}, nil
}

// Operation returns the exact one-shot filter operation.
func (r FilterRequest) Operation() FilterOperation { return r.operation }

// Message returns an immutable complete-message copy.
func (r FilterRequest) Message() []byte { return slices.Clone(r.message) }

// Outgoing returns an immutable copy of current transport authority.
func (r FilterRequest) Outgoing() OutgoingEnvelope { return r.outgoing.clone() }

// Incoming returns immutable receive-time authority when revision owns it.
func (r FilterRequest) Incoming() (IncomingEvidence, bool) {
	if r.incoming == nil {
		return IncomingEvidence{}, false
	}
	return r.incoming.clone(), true
}

// clone returns a deep immutable evidence copy.
func (e IncomingEvidence) clone() IncomingEvidence {
	e.mailFrom = slices.Clone(e.mailFrom)
	e.recipients = cloneBytes(e.recipients)
	return e
}

// clone returns a deep immutable outgoing-envelope copy.
func (e OutgoingEnvelope) clone() OutgoingEnvelope {
	e.mailFrom = slices.Clone(e.mailFrom)
	e.recipient = slices.Clone(e.recipient)
	return e
}

// String returns a content-free filter-request diagnostic.
func (FilterRequest) String() string { return "exim_filter_request{redacted}" }

// GoString returns a content-free filter-request representation.
func (r FilterRequest) GoString() string { return r.String() }

// Format prevents formatting from traversing mail and envelope evidence.
func (r FilterRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// MarshalJSON rejects filter-request serialization.
func (FilterRequest) MarshalJSON() ([]byte, error) {
	return nil, NewError(FailureContract)
}

// MarshalText rejects textual filter-request serialization.
func (FilterRequest) MarshalText() ([]byte, error) {
	return nil, NewError(FailureContract)
}

// cloneBytes returns a deep copy of one byte-slice vector.
func cloneBytes(values [][]byte) [][]byte {
	output := make([][]byte, len(values))
	for index := range values {
		output[index] = slices.Clone(values[index])
	}
	return output
}

// validBuildID accepts one exact lowercase hexadecimal SHA-256 spelling.
func validBuildID(value []byte) bool {
	if len(value) != buildIDBytes {
		return false
	}
	for _, current := range value {
		if (current < '0' || current > '9') && (current < 'a' || current > 'f') {
			return false
		}
	}
	return true
}

// validScalar rejects framing bytes in inbound envelope and session evidence.
func validScalar(value []byte) bool {
	return !bytes.ContainsAny(value, "\x00\r\n")
}

// validOutboundScalar accepts ASCII-only transport authority without framing bytes.
func validOutboundScalar(value []byte) bool {
	for _, current := range value {
		if current == 0 || current == '\r' || current == '\n' || current > 0x7f {
			return false
		}
	}
	return true
}

// validHeader accepts exact LF folding and one terminal LF.
func validHeader(value []byte) bool {
	if len(value) == 0 || value[len(value)-1] != '\n' ||
		bytes.ContainsAny(value, "\x00\r") {
		return false
	}
	for index := 0; index < len(value)-1; index++ {
		if value[index] == '\n' &&
			value[index+1] != ' ' && value[index+1] != '\t' {
			return false
		}
	}
	return true
}

// validActionName accepts only adapter-owned append-only fields.
func validActionName(value string) bool {
	return value == headerAuthenticationResults ||
		value == headerMessageInstance ||
		value == headerDKIM2Signature
}

// stringsContainFraming rejects bytes that would alter a field boundary.
func stringsContainFraming(value string) bool {
	return bytes.ContainsAny([]byte(value), "\x00\r\n")
}

// validOutgoingEnvelope rejects zero-value or forged transport authority.
func validOutgoingEnvelope(outgoing OutgoingEnvelope) bool {
	return len(outgoing.recipient) > 0 &&
		len(outgoing.mailFrom) <= maxEnvelopeBytes &&
		len(outgoing.recipient) <= maxEnvelopeBytes &&
		validOutboundScalar(outgoing.mailFrom) &&
		validOutboundScalar(outgoing.recipient)
}

// prepareTransportMessage owns and proves the exact completed LF representation.
func prepareTransportMessage(message []byte) ([]byte, error) {
	if len(message) == 0 {
		return nil, NewError(FailureInvalidRequest)
	}
	if len(message) > maxMessageBytes {
		return nil, NewError(FailureResource)
	}
	missingFinalLF := message[len(message)-1] != '\n'
	if missingFinalLF {
		if len(message) == maxMessageBytes {
			return nil, NewError(FailureResource)
		}
	}
	if err := validateTransportMessage(message, missingFinalLF); err != nil {
		return nil, err
	}
	var complete []byte
	if missingFinalLF {
		complete = make([]byte, len(message)+1)
		copy(complete, message)
		complete[len(message)] = '\n'
	} else {
		complete = slices.Clone(message)
	}
	return complete, nil
}

// validateTransportMessage proves LF header framing before copying message bytes.
func validateTransportMessage(message []byte, virtualFinalLF bool) error {
	if len(message) == 0 {
		return NewError(FailureFidelity)
	}
	headerCount := 0
	headerBytes := 0
	for offset := 0; offset < len(message); {
		lineEnd := bytes.IndexByte(message[offset:], '\n')
		if lineEnd < 0 {
			if !virtualFinalLF ||
				!validFieldNameLine(message[offset:]) ||
				!validHeaderWithoutFinalLF(message[offset:]) {
				return NewError(FailureFidelity)
			}
			if err := validateTransportHeaderLimit(
				headerCount+1, len(message)-offset+1, headerBytes,
			); err != nil {
				return err
			}
			return nil
		}
		lineEnd += offset
		if lineEnd == offset {
			return nil
		}
		fieldStart := offset
		if !validFieldNameLine(message[fieldStart:lineEnd]) {
			return NewError(FailureFidelity)
		}
		offset = lineEnd + 1
		for offset < len(message) &&
			(message[offset] == ' ' || message[offset] == '\t') {
			lineEnd = bytes.IndexByte(message[offset:], '\n')
			if lineEnd < 0 {
				if !virtualFinalLF ||
					!validHeaderWithoutFinalLF(message[fieldStart:]) {
					return NewError(FailureFidelity)
				}
				fieldLength := len(message) - fieldStart + 1
				return validateTransportHeaderLimit(
					headerCount+1, fieldLength, headerBytes,
				)
			}
			offset += lineEnd + 1
		}
		fieldLength := offset - fieldStart
		headerCount++
		if err := validateTransportHeaderLimit(
			headerCount, fieldLength, headerBytes,
		); err != nil {
			return err
		}
		if !validHeader(message[fieldStart:offset]) {
			return NewError(FailureFidelity)
		}
		headerBytes += fieldLength
	}
	return nil
}

// validHeaderWithoutFinalLF validates a field whose sole missing byte is terminal LF.
func validHeaderWithoutFinalLF(value []byte) bool {
	if len(value) == 0 || bytes.ContainsAny(value, "\x00\r") {
		return false
	}
	for index := range value {
		if value[index] == '\n' &&
			(index+1 >= len(value) ||
				value[index+1] != ' ' && value[index+1] != '\t') {
			return false
		}
	}
	return true
}

// validateTransportHeaderLimit proves one cumulative header bound without overflow.
func validateTransportHeaderLimit(count, fieldBytes, aggregateBytes int) error {
	if count > maxHeaders || fieldBytes > maxHeaderFieldBytes ||
		fieldBytes > maxHeaderAggregateBytes-aggregateBytes {
		return NewError(FailureResource)
	}
	return nil
}

// validFieldNameLine proves one RFC 5322 field-name precedes the first colon.
func validFieldNameLine(line []byte) bool {
	colon := bytes.IndexByte(line, ':')
	if colon < 1 {
		return false
	}
	for _, current := range line[:colon] {
		if current < 33 || current > 126 || current == ':' {
			return false
		}
	}
	return true
}

// validIncomingEvidence rejects forged zero values at the revision boundary.
func validIncomingEvidence(incoming IncomingEvidence) bool {
	if incoming.session > SessionBSMTP || len(incoming.recipients) == 0 ||
		len(incoming.recipients) > maxRecipients ||
		len(incoming.mailFrom) > maxEnvelopeBytes ||
		!validScalar(incoming.mailFrom) {
		return false
	}
	for _, recipient := range incoming.recipients {
		if len(recipient) > maxEnvelopeBytes || !validScalar(recipient) {
			return false
		}
	}
	return true
}

var _ json.Marshaler = LocalScanRequest{}
var _ json.Marshaler = FilterRequest{}
