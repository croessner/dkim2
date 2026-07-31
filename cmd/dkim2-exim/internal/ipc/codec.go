// Package ipc implements the bounded Exim local-scan wire protocol.
package ipc

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

const (
	// Version is the sole supported IPC protocol version.
	Version = uint8(1)
	// RequestKind identifies one local-scan request frame.
	RequestKind = uint8(1)
	// ResponseKind identifies one local-scan response frame.
	ResponseKind = uint8(2)
	// FrameHeaderBytes is the exact DXI1 envelope size.
	FrameHeaderBytes = 12
	// RequestPayloadBytes is the exact hard request payload cap.
	RequestPayloadBytes = 34_079_124
	// RequestFrameBytes is the exact hard request frame cap.
	RequestFrameBytes = RequestPayloadBytes + FrameHeaderBytes
	// ResponsePayloadBytes is the exact hard response payload cap.
	ResponsePayloadBytes = 69_575
	// ResponseFrameBytes is the exact hard response frame cap.
	ResponseFrameBytes = ResponsePayloadBytes + FrameHeaderBytes
	// MaxRecipients bounds receive-time envelope entries.
	MaxRecipients = 2_000
	// MaxHeaders bounds observed header fields.
	MaxHeaders = 2_000
	// MaxHeaderAggregateBytes bounds observed header bytes.
	MaxHeaderAggregateBytes = 1 << 20
	// MaxHeaderFieldBytes bounds one observed field.
	MaxHeaderFieldBytes = 65_536
	// MaxMessageBytes bounds headers, separator, and body.
	MaxMessageBytes = 32 << 20
	// MaxEnvelopeBytes bounds one SMTP path.
	MaxEnvelopeBytes = 256
	// MaxPeerBytes bounds one peer observation.
	MaxPeerBytes = 64
	// MaxHELOBytes bounds one HELO observation.
	MaxHELOBytes = 255
	// MaxReceivedProtocolBytes bounds one Exim protocol observation.
	MaxReceivedProtocolBytes = 32
	// BuildIDBytes is the exact lowercase SHA-256 spelling length.
	BuildIDBytes = 64
	// MaxAddValueBytes bounds one response header value.
	MaxAddValueBytes = 65_535
	// EvidenceLocatorBytes is the exact encoded locator length.
	EvidenceLocatorBytes = 32
)

// RequestLimits narrows the hard protocol ceilings for one configured service.
type RequestLimits struct {
	MessageBytes     int
	HeaderBytes      int
	HeaderCount      int
	HeaderFieldBytes int
	RecipientCount   int
}

// DefaultRequestLimits returns the immutable protocol maximums.
func DefaultRequestLimits() RequestLimits {
	return RequestLimits{
		MessageBytes: MaxMessageBytes, HeaderBytes: MaxHeaderAggregateBytes,
		HeaderCount: MaxHeaders, HeaderFieldBytes: MaxHeaderFieldBytes,
		RecipientCount: MaxRecipients,
	}
}

// Valid reports whether every configured ceiling is positive and no wider than wire policy.
func (l RequestLimits) Valid() bool {
	return l.MessageBytes >= 1 && l.MessageBytes <= MaxMessageBytes &&
		l.HeaderBytes >= 1 && l.HeaderBytes <= MaxHeaderAggregateBytes &&
		l.HeaderCount >= 1 && l.HeaderCount <= MaxHeaders &&
		l.HeaderFieldBytes >= 1 && l.HeaderFieldBytes <= MaxHeaderFieldBytes &&
		l.RecipientCount >= 1 && l.RecipientCount <= MaxRecipients &&
		l.HeaderBytes <= l.MessageBytes && l.HeaderFieldBytes <= l.HeaderBytes
}

var (
	errInvalidFrame   = errors.New("exim ipc invalid frame")
	errResourceLimit  = errors.New("exim ipc resource limit")
	errInvalidRequest = errors.New("exim ipc invalid request")
	errInvalidReply   = errors.New("exim ipc invalid response")
)

// FailureClass identifies one closed, content-free wire failure category.
type FailureClass uint8

const (
	// FailureUnknown identifies a zero-value or otherwise unclassified failure.
	FailureUnknown FailureClass = iota
	// FailureInvalidFrame identifies an invalid DXI1 framing envelope.
	FailureInvalidFrame
	// FailureResourceLimit identifies a bounded wire resource violation.
	FailureResourceLimit
	// FailureInvalidRequest identifies an invalid request payload.
	FailureInvalidRequest
	// FailureInvalidResponse identifies an invalid response payload.
	FailureInvalidResponse
)

// Source identifies the observed Exim representation.
type Source uint8

// SourceLocalScanObserved identifies Exim local-scan evidence.
const SourceLocalScanObserved Source = 1

// Session identifies the canonical ingress class.
type Session uint8

const (
	// SessionLocal identifies local non-SMTP input.
	SessionLocal Session = iota
	// SessionSMTP identifies ordinary SMTP input.
	SessionSMTP
	// SessionBSMTP identifies canonical BSMTP input.
	SessionBSMTP
)

// Decision identifies a closed local-scan outcome.
type Decision uint8

const (
	// DecisionAccept admits the message and optional mutation.
	DecisionAccept Decision = iota + 1
	// DecisionReject permanently rejects by policy.
	DecisionReject
	// DecisionTempfail temporarily rejects.
	DecisionTempfail
)

// Reason identifies one bounded failure or policy class.
type Reason uint8

const (
	// ReasonNone is required for acceptance.
	ReasonNone Reason = iota
	// ReasonPolicyReject is required for permanent rejection.
	ReasonPolicyReject
	// ReasonServiceUnavailable identifies daemon unavailability.
	ReasonServiceUnavailable
	// ReasonTimeout identifies an operation deadline.
	ReasonTimeout
	// ReasonInvalidRequest identifies malformed adapter input.
	ReasonInvalidRequest
	// ReasonFidelity identifies ambiguous observed bytes.
	ReasonFidelity
	// ReasonContract identifies protocol drift.
	ReasonContract
	// ReasonResource identifies a configured limit.
	ReasonResource
	// ReasonInternal identifies a closed invariant.
	ReasonInternal
)

// AddName identifies the sole inbound header field that may be added.
type AddName uint16

const (
	// AddNone prohibits an added header value.
	AddNone AddName = iota
	// AddAuthenticationResults admits the sole inbound report field.
	AddAuthenticationResults
)

// Request is an immutable primitive projection of Exim evidence.
type Request struct {
	buildID          []byte
	source           Source
	session          Session
	peer             []byte
	peerPort         uint16
	helo             []byte
	receivedProtocol []byte
	mailFrom         []byte
	recipients       [][]byte
	headers          [][]byte
	body             []byte
}

// Response is the closed mutation and decision projection returned to C.
type Response struct {
	decision Decision
	reason   Reason
	removals []uint16
	addName  AddName
	addValue []byte
	locator  []byte
}

type requestPrefix struct {
	source         Source
	session        Session
	recipientCount uint16
	headerCount    uint16
	peerLength     uint16
	peerPort       uint16
	heloLength     uint16
	protocolLength uint16
	mailFromLength uint16
}

// Error returns a content-free error class.
func (*WireError) Error() string { return "exim ipc contract failure" }

// String returns the content-free wire diagnostic.
func (WireError) String() string { return "exim_ipc_error{redacted}" }

// GoString returns the content-free Go representation.
func (e WireError) GoString() string { return e.String() }

// Format prevents formatting from traversing rejected wire input.
func (e WireError) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, e.String())
}

// MarshalJSON rejects serialization of wire failure internals.
func (WireError) MarshalJSON() ([]byte, error) { return nil, wireError(errInvalidFrame) }

// MarshalText rejects textual serialization of wire failure internals.
func (WireError) MarshalText() ([]byte, error) { return nil, wireError(errInvalidFrame) }

// WireError identifies invalid wire data without retaining it.
type WireError struct {
	cause error
	class FailureClass
}

// Class returns the closed, content-free failure category.
func (e *WireError) Class() FailureClass {
	if e == nil {
		return FailureUnknown
	}
	return e.class
}

// Unwrap returns only a closed package error.
func (e *WireError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Clone returns an immutable deep copy of the request.
func (r Request) Clone() Request {
	r.buildID = slices.Clone(r.buildID)
	r.peer = slices.Clone(r.peer)
	r.helo = slices.Clone(r.helo)
	r.receivedProtocol = slices.Clone(r.receivedProtocol)
	r.mailFrom = slices.Clone(r.mailFrom)
	r.recipients = cloneByteSlices(r.recipients)
	r.headers = cloneByteSlices(r.headers)
	r.body = slices.Clone(r.body)
	return r
}

// Clone returns an immutable deep copy of the response.
func (r Response) Clone() Response {
	r.removals = slices.Clone(r.removals)
	r.addValue = slices.Clone(r.addValue)
	r.locator = slices.Clone(r.locator)
	return r
}

// NewRequest validates and takes immutable copies of one primitive request.
func NewRequest(
	buildID []byte,
	source Source,
	session Session,
	peer []byte,
	peerPort uint16,
	helo []byte,
	receivedProtocol []byte,
	mailFrom []byte,
	recipients [][]byte,
	headers [][]byte,
	body []byte,
) (Request, error) {
	borrowed := Request{
		buildID: buildID, source: source, session: session,
		peer: peer, peerPort: peerPort, helo: helo,
		receivedProtocol: receivedProtocol,
		mailFrom:         mailFrom, recipients: recipients,
		headers: headers, body: body,
	}
	if err := validateRequest(borrowed); err != nil {
		return Request{}, err
	}
	return borrowed.Clone(), nil
}

// NewResponse validates and copies one response against exact request evidence.
func NewResponse(
	decision Decision,
	reason Reason,
	removals []uint16,
	addName AddName,
	addValue []byte,
	locator []byte,
	eligibleRemovals []uint16,
	headerCount uint16,
) (Response, error) {
	borrowed := Response{
		decision: decision, reason: reason, removals: removals,
		addName: addName, addValue: addValue, locator: locator,
	}
	if err := ValidateResponse(borrowed, eligibleRemovals, headerCount); err != nil {
		return Response{}, err
	}
	return borrowed.Clone(), nil
}

// BuildID returns an immutable compatibility-identifier copy.
func (r Request) BuildID() []byte { return slices.Clone(r.buildID) }

// Peer returns an immutable peer-address observation copy.
func (r Request) Peer() []byte { return slices.Clone(r.peer) }

// PeerPort returns the observed peer port or zero when no peer was observed.
func (r Request) PeerPort() uint16 { return r.peerPort }

// HELO returns an immutable HELO observation copy.
func (r Request) HELO() []byte { return slices.Clone(r.helo) }

// ReceivedProtocol returns an immutable received-protocol observation copy.
func (r Request) ReceivedProtocol() []byte { return slices.Clone(r.receivedProtocol) }

// MailFrom returns an immutable reverse-path copy.
func (r Request) MailFrom() []byte { return slices.Clone(r.mailFrom) }

// Recipients returns immutable ordered recipient copies.
func (r Request) Recipients() [][]byte { return cloneByteSlices(r.recipients) }

// Headers returns immutable observed-header copies.
func (r Request) Headers() [][]byte { return cloneByteSlices(r.headers) }

// Body returns an immutable body copy.
func (r Request) Body() []byte { return slices.Clone(r.body) }

// Session returns the canonical ingress class.
func (r Request) Session() Session { return r.session }

// Decision returns the closed response decision.
func (r Response) Decision() Decision { return r.decision }

// Removals returns immutable occurrence copies.
func (r Response) Removals() []uint16 { return slices.Clone(r.removals) }

// AddValue returns an immutable add-header value copy.
func (r Response) AddValue() []byte { return slices.Clone(r.addValue) }

// Locator returns an immutable evidence-locator copy.
func (r Response) Locator() []byte { return slices.Clone(r.locator) }

// String returns a content-free request diagnostic.
func (Request) String() string { return "exim_ipc_request{redacted}" }

// GoString returns a content-free request representation.
func (r Request) GoString() string { return r.String() }

// Format prevents formatting from traversing mail evidence.
func (r Request) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// MarshalJSON rejects serialization of mail evidence.
func (Request) MarshalJSON() ([]byte, error) { return nil, wireError(errInvalidRequest) }

// MarshalText rejects textual serialization of mail evidence.
func (Request) MarshalText() ([]byte, error) { return nil, wireError(errInvalidRequest) }

// String returns a content-free response diagnostic.
func (Response) String() string { return "exim_ipc_response{redacted}" }

// GoString returns a content-free response representation.
func (r Response) GoString() string { return r.String() }

// Format prevents formatting from traversing action/evidence values.
func (r Response) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// MarshalJSON rejects serialization of action/evidence values.
func (Response) MarshalJSON() ([]byte, error) { return nil, wireError(errInvalidReply) }

// MarshalText rejects textual serialization of action/evidence values.
func (Response) MarshalText() ([]byte, error) { return nil, wireError(errInvalidReply) }

// EncodeRequest validates and encodes one canonical request frame.
func EncodeRequest(request Request) ([]byte, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	payload := &bytes.Buffer{}
	payload.Grow(requestPayloadLength(request))
	writeU16(payload, uint16(len(request.buildID)))
	payload.WriteByte(byte(request.source))
	payload.WriteByte(byte(request.session))
	writeU16(payload, uint16(len(request.recipients)))
	writeU16(payload, uint16(len(request.headers)))
	writeU16(payload, uint16(len(request.peer)))
	writeU16(payload, request.peerPort)
	writeU16(payload, uint16(len(request.helo)))
	writeU16(payload, uint16(len(request.receivedProtocol)))
	writeU16(payload, uint16(len(request.mailFrom)))
	payload.Write(request.buildID)
	payload.Write(request.peer)
	payload.Write(request.helo)
	payload.Write(request.receivedProtocol)
	payload.Write(request.mailFrom)
	writeU16Bytes(payload, request.recipients)
	writeU32Bytes(payload, request.headers)
	writeU32(payload, uint32(len(request.body)))
	payload.Write(request.body)
	return frame(RequestKind, payload.Bytes())
}

// DecodeRequest validates a complete request frame with explicit build admission.
func DecodeRequest(data []byte, allowBuild func([]byte) bool) (Request, error) {
	return DecodeRequestStream(bytes.NewReader(data), allowBuild)
}

// DecodeRequestStream rejects incompatible builds before allocating mail data.
func DecodeRequestStream(input io.Reader, allowBuild func([]byte) bool) (Request, error) {
	return DecodeRequestStreamReserved(input, allowBuild, nil)
}

// DecodeRequestStreamReserved reserves the framed payload before allocating mail fields.
func DecodeRequestStreamReserved(input io.Reader, allowBuild func([]byte) bool, reserve func(uint32) bool) (Request, error) {
	return DecodeRequestStreamLimited(input, allowBuild, DefaultRequestLimits(), reserve)
}

// DecodeRequestStreamLimited applies configured limits and admission before mail allocation.
func DecodeRequestStreamLimited(input io.Reader, allowBuild func([]byte) bool, limits RequestLimits, reserve func(uint32) bool) (Request, error) {
	if input == nil || allowBuild == nil || !limits.Valid() {
		return Request{}, wireError(errInvalidRequest)
	}
	var header [FrameHeaderBytes]byte
	if _, err := io.ReadFull(input, header[:]); err != nil ||
		!bytes.Equal(header[:4], []byte("DXI1")) || header[4] != Version ||
		header[5] != RequestKind || header[6] != 0 || header[7] != 0 {
		return Request{}, wireError(errInvalidFrame)
	}
	payloadLength := binary.BigEndian.Uint32(header[8:12])
	if payloadLength > RequestPayloadBytes || payloadLength < 18+BuildIDBytes {
		return Request{}, wireError(errInvalidFrame)
	}
	limited := &io.LimitedReader{R: input, N: int64(payloadLength)}
	var prefix [18]byte
	if _, err := io.ReadFull(limited, prefix[:]); err != nil {
		return Request{}, wireError(errInvalidRequest)
	}
	parsed, ok := parseRequestPrefix(prefix[:], limits)
	if !ok {
		return Request{}, wireError(errInvalidRequest)
	}
	var buildID [BuildIDBytes]byte
	if _, err := io.ReadFull(limited, buildID[:]); err != nil || !validBuildID(buildID[:]) {
		return Request{}, wireError(errInvalidRequest)
	}
	if !allowBuild(buildID[:]) {
		return Request{}, wireError(errInvalidRequest)
	}
	if reserve != nil && !reserve(payloadLength) {
		clear(buildID[:])
		return Request{}, wireError(errResourceLimit)
	}
	defer func() {
		clear(buildID[:])
	}()
	request, err := readRequestFields(limited, parsed, buildID[:], limits)
	if err != nil {
		return Request{}, err
	}
	if limited.N != 0 {
		request.clear()
		return Request{}, wireError(errInvalidRequest)
	}
	var trailing [1]byte
	count, trailingErr := input.Read(trailing[:])
	if count != 0 || !errors.Is(trailingErr, io.EOF) {
		request.clear()
		return Request{}, wireError(errInvalidFrame)
	}
	admitted, err := admitOwnedRequest(request)
	if err != nil {
		return Request{}, err
	}
	return admitted, nil
}

// parseRequestPrefix validates the allocation-free request scalars.
func parseRequestPrefix(value []byte, limits RequestLimits) (requestPrefix, bool) {
	if len(value) != 18 || binary.BigEndian.Uint16(value[0:2]) != BuildIDBytes {
		return requestPrefix{}, false
	}
	prefix := requestPrefix{
		source: Source(value[2]), session: Session(value[3]),
		recipientCount: binary.BigEndian.Uint16(value[4:6]),
		headerCount:    binary.BigEndian.Uint16(value[6:8]),
		peerLength:     binary.BigEndian.Uint16(value[8:10]),
		peerPort:       binary.BigEndian.Uint16(value[10:12]),
		heloLength:     binary.BigEndian.Uint16(value[12:14]),
		protocolLength: binary.BigEndian.Uint16(value[14:16]),
		mailFromLength: binary.BigEndian.Uint16(value[16:18]),
	}
	valid := prefix.source == SourceLocalScanObserved &&
		prefix.session <= SessionBSMTP &&
		prefix.recipientCount >= 1 && int(prefix.recipientCount) <= limits.RecipientCount &&
		int(prefix.headerCount) <= limits.HeaderCount && prefix.peerLength <= MaxPeerBytes &&
		prefix.heloLength <= MaxHELOBytes &&
		prefix.protocolLength <= MaxReceivedProtocolBytes &&
		prefix.mailFromLength <= MaxEnvelopeBytes &&
		(prefix.peerLength == 0) == (prefix.peerPort == 0)
	return prefix, valid
}

// readRequestFields allocates mail data only after build compatibility admission.
func readRequestFields(
	input *io.LimitedReader,
	prefix requestPrefix,
	buildID []byte,
	limits RequestLimits,
) (Request, error) {
	request := Request{
		buildID: slices.Clone(buildID), source: prefix.source, session: prefix.session,
		peerPort: prefix.peerPort,
	}
	success := false
	defer func() {
		if !success {
			request.clear()
		}
	}()
	var (
		ok      bool
		readErr error
	)
	request.peer, ok = readLimitedExact(input, int(prefix.peerLength))
	if !ok {
		return Request{}, wireError(errInvalidRequest)
	}
	request.helo, ok = readLimitedExact(input, int(prefix.heloLength))
	if !ok {
		return Request{}, wireError(errInvalidRequest)
	}
	request.receivedProtocol, ok = readLimitedExact(input, int(prefix.protocolLength))
	if !ok {
		return Request{}, wireError(errInvalidRequest)
	}
	request.mailFrom, ok = readLimitedExact(input, int(prefix.mailFromLength))
	if !ok {
		return Request{}, wireError(errInvalidRequest)
	}
	request.recipients, readErr = readU16ByteSlices(
		input, int(prefix.recipientCount), MaxEnvelopeBytes,
	)
	if readErr != nil {
		return Request{}, wireError(readErr)
	}
	var headerBytes int
	request.headers, headerBytes, readErr = readU32ByteSlices(
		input, int(prefix.headerCount), limits.HeaderFieldBytes, limits.HeaderBytes,
	)
	if readErr != nil {
		return Request{}, wireError(readErr)
	}
	bodyLength, ok := readU32(input)
	if !ok || bodyLength > uint32(limits.MessageBytes) ||
		int(bodyLength) > limits.MessageBytes-headerBytes-1 {
		return Request{}, wireError(errResourceLimit)
	}
	request.body, ok = readLimitedExact(input, int(bodyLength))
	if !ok {
		return Request{}, wireError(errInvalidRequest)
	}
	success = true
	return request, nil
}

// EncodeResponse validates and encodes one canonical response frame.
func EncodeResponse(
	response Response,
	eligibleRemovals []uint16,
	headerCount uint16,
) ([]byte, error) {
	if err := ValidateResponse(response, eligibleRemovals, headerCount); err != nil {
		return nil, err
	}
	payload := &bytes.Buffer{}
	payload.Grow(8 + len(response.removals)*2 + len(response.addValue) + len(response.locator))
	payload.WriteByte(byte(response.decision))
	payload.WriteByte(byte(response.reason))
	writeU16(payload, uint16(len(response.removals)))
	writeU16(payload, uint16(response.addName))
	writeU16(payload, uint16(len(response.addValue)))
	for _, occurrence := range response.removals {
		writeU16(payload, occurrence)
	}
	payload.Write(response.addValue)
	payload.Write(response.locator)
	return frame(ResponseKind, payload.Bytes())
}

// DecodeResponse validates and decodes one canonical response frame.
func DecodeResponse(
	data []byte,
	eligibleRemovals []uint16,
	headerCount uint16,
) (Response, error) {
	payload, err := unframe(data, ResponseKind, ResponsePayloadBytes)
	if err != nil {
		return Response{}, err
	}
	reader := bytes.NewReader(payload)
	decision, ok := readByte(reader)
	if !ok {
		return Response{}, wireError(errInvalidReply)
	}
	reason, ok := readByte(reader)
	if !ok {
		return Response{}, wireError(errInvalidReply)
	}
	removalCount, ok := readU16(reader)
	if !ok || removalCount > MaxHeaders {
		return Response{}, wireError(errResourceLimit)
	}
	addName, ok := readU16(reader)
	if !ok {
		return Response{}, wireError(errInvalidReply)
	}
	addLength, ok := readU16(reader)
	if !ok || addLength > MaxAddValueBytes {
		return Response{}, wireError(errResourceLimit)
	}
	response := Response{
		decision: Decision(decision), reason: Reason(reason), addName: AddName(addName),
		removals: make([]uint16, int(removalCount)),
	}
	success := false
	defer func() {
		if !success {
			response.clear()
		}
	}()
	for index := range response.removals {
		response.removals[index], ok = readU16(reader)
		if !ok {
			return Response{}, wireError(errInvalidReply)
		}
	}
	response.addValue, ok = readBytes(reader, int(addLength))
	if !ok {
		return Response{}, wireError(errInvalidReply)
	}
	if reader.Len() != 0 {
		if reader.Len() != EvidenceLocatorBytes {
			return Response{}, wireError(errInvalidReply)
		}
		response.locator, ok = readBytes(reader, EvidenceLocatorBytes)
		if !ok {
			return Response{}, wireError(errInvalidReply)
		}
	}
	admitted, err := admitOwnedResponse(response, eligibleRemovals, headerCount)
	if err != nil {
		return Response{}, err
	}
	success = true
	return admitted, nil
}

// ValidateResponse proves the closed decision, reason and mutation matrix.
func ValidateResponse(
	response Response,
	eligibleRemovals []uint16,
	headerCount uint16,
) error {
	if headerCount > MaxHeaders || len(eligibleRemovals) > MaxHeaders ||
		len(eligibleRemovals) > int(headerCount) ||
		len(response.removals) > MaxHeaders ||
		len(response.removals) > len(eligibleRemovals) ||
		len(response.addValue) > MaxAddValueBytes ||
		(len(response.locator) != 0 && len(response.locator) != EvidenceLocatorBytes) {
		return wireError(errResourceLimit)
	}
	if !validDecisionReason(response) || !validResponseMutation(response) ||
		!validRemovalSet(response.removals, eligibleRemovals, headerCount) {
		return wireError(errInvalidReply)
	}
	return nil
}

// admitOwnedResponse validates an owned decoded response and erases it on failure.
func admitOwnedResponse(
	response Response,
	eligibleRemovals []uint16,
	headerCount uint16,
) (Response, error) {
	if err := ValidateResponse(response, eligibleRemovals, headerCount); err != nil {
		response.clear()
		return Response{}, err
	}
	return response, nil
}

// admitOwnedRequest validates an owned decoded request and erases it on failure.
func admitOwnedRequest(request Request) (Request, error) {
	if err := validateRequest(request); err != nil {
		request.clear()
		return Request{}, err
	}
	return request, nil
}

// validDecisionReason proves the closed decision and reason matrix.
func validDecisionReason(response Response) bool {
	switch response.decision {
	case DecisionAccept:
		return response.reason == ReasonNone
	case DecisionReject:
		return response.reason == ReasonPolicyReject
	case DecisionTempfail:
		return response.reason >= ReasonServiceUnavailable && response.reason <= ReasonInternal
	default:
		return false
	}
}

// validResponseMutation proves accept-only action and locator grammar.
func validResponseMutation(response Response) bool {
	if response.decision != DecisionAccept &&
		(len(response.removals) != 0 || response.addName != AddNone ||
			len(response.addValue) != 0 || len(response.locator) != 0) {
		return false
	}
	if response.addName == AddNone && len(response.addValue) != 0 {
		return false
	}
	if response.addName == AddAuthenticationResults &&
		(len(response.addValue) == 0 || bytes.ContainsAny(response.addValue, "\r\n\x00")) {
		return false
	}
	if response.addName != AddNone && response.addName != AddAuthenticationResults {
		return false
	}
	if len(response.locator) != 0 && !validLocator(response.locator) {
		return false
	}
	return true
}

// validRemovalSet proves exact eligibility, bounds, uniqueness and ordering.
func validRemovalSet(
	removals []uint16,
	eligibleRemovals []uint16,
	headerCount uint16,
) bool {
	eligible := make(map[uint16]struct{}, len(eligibleRemovals))
	for _, occurrence := range eligibleRemovals {
		if occurrence == 0 || occurrence > headerCount {
			return false
		}
		if _, duplicate := eligible[occurrence]; duplicate {
			return false
		}
		eligible[occurrence] = struct{}{}
	}
	previous := uint16(0)
	for index, occurrence := range removals {
		_, admitted := eligible[occurrence]
		if !admitted ||
			(index > 0 && occurrence >= previous) {
			return false
		}
		previous = occurrence
	}
	return true
}

// clear erases temporary request evidence on failed stream decoding.
func (r *Request) clear() {
	if r == nil {
		return
	}
	clear(r.buildID)
	clear(r.peer)
	clear(r.helo)
	clear(r.receivedProtocol)
	clear(r.mailFrom)
	clearByteSlices(r.recipients)
	clearByteSlices(r.headers)
	clear(r.body)
	*r = Request{}
}

// clear erases temporary response evidence on failed wire admission.
func (r *Response) clear() {
	if r == nil {
		return
	}
	clear(r.removals)
	clear(r.addValue)
	clear(r.locator)
	*r = Response{}
}

// validateRequest proves every semantic request bound and structural invariant.
func validateRequest(request Request) error {
	if !validBuildID(request.buildID) || request.source != SourceLocalScanObserved ||
		request.session > SessionBSMTP || len(request.recipients) < 1 ||
		len(request.recipients) > MaxRecipients ||
		len(request.headers) > MaxHeaders || len(request.peer) > MaxPeerBytes ||
		len(request.helo) > MaxHELOBytes ||
		len(request.receivedProtocol) > MaxReceivedProtocolBytes ||
		len(request.mailFrom) > MaxEnvelopeBytes ||
		(len(request.peer) == 0) != (request.peerPort == 0) ||
		!validScalar(request.peer) || !validScalar(request.helo) ||
		!validScalar(request.receivedProtocol) || !validScalar(request.mailFrom) {
		return wireError(errInvalidRequest)
	}
	headerBytes := 0
	for _, recipient := range request.recipients {
		if len(recipient) > MaxEnvelopeBytes || !validScalar(recipient) {
			return wireError(errResourceLimit)
		}
	}
	for _, header := range request.headers {
		if len(header) > MaxHeaderFieldBytes || !validHeader(header) {
			return wireError(errResourceLimit)
		}
		headerBytes += len(header)
		if headerBytes > MaxHeaderAggregateBytes {
			return wireError(errResourceLimit)
		}
	}
	if headerBytes+len(request.body)+1 > MaxMessageBytes ||
		requestPayloadLength(request) > RequestPayloadBytes {
		return wireError(errResourceLimit)
	}
	return nil
}

// requestPayloadLength returns the overflow-safe encoded payload size.
func requestPayloadLength(request Request) int {
	total := 18 + len(request.buildID) + len(request.peer) + len(request.helo) +
		len(request.receivedProtocol) + len(request.mailFrom) + 4
	for _, recipient := range request.recipients {
		total += 2 + len(recipient)
	}
	for _, header := range request.headers {
		total += 4 + len(header)
	}
	return total + len(request.body)
}

// validBuildID accepts one exact lowercase hexadecimal SHA-256 spelling.
func validBuildID(value []byte) bool {
	if len(value) != BuildIDBytes {
		return false
	}
	for _, current := range value {
		if (current < '0' || current > '9') && (current < 'a' || current > 'f') {
			return false
		}
	}
	return true
}

// validScalar rejects framing bytes in envelope/session evidence.
func validScalar(value []byte) bool {
	return !bytes.ContainsAny(value, "\x00\r\n")
}

// validHeader accepts exact LF folding and one terminal LF.
func validHeader(value []byte) bool {
	if len(value) == 0 || value[len(value)-1] != '\n' ||
		bytes.ContainsAny(value, "\x00\r") {
		return false
	}
	for index := 0; index < len(value)-1; index++ {
		if value[index] == '\n' &&
			(value[index+1] != ' ' && value[index+1] != '\t') {
			return false
		}
	}
	return true
}

// validLocator proves exact canonical unpadded base64url over 24 bytes.
func validLocator(value []byte) bool {
	if len(value) != EvidenceLocatorBytes || strings.ContainsAny(string(value), "+/=") {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(string(value))
	return err == nil && len(decoded) == 24 &&
		base64.RawURLEncoding.EncodeToString(decoded) == string(value)
}

// frame wraps one already validated payload in the canonical envelope.
func frame(kind uint8, payload []byte) ([]byte, error) {
	if (kind == RequestKind && len(payload) > RequestPayloadBytes) ||
		(kind == ResponseKind && len(payload) > ResponsePayloadBytes) {
		return nil, wireError(errResourceLimit)
	}
	output := make([]byte, FrameHeaderBytes+len(payload))
	copy(output[:4], "DXI1")
	output[4] = Version
	output[5] = kind
	binary.BigEndian.PutUint32(output[8:12], uint32(len(payload)))
	copy(output[12:], payload)
	return output, nil
}

// unframe validates the complete canonical envelope before returning payload.
func unframe(data []byte, kind uint8, maximum int) ([]byte, error) {
	if len(data) < FrameHeaderBytes || len(data) > maximum+FrameHeaderBytes ||
		!bytes.Equal(data[:4], []byte("DXI1")) || data[4] != Version ||
		data[5] != kind || data[6] != 0 || data[7] != 0 {
		return nil, wireError(errInvalidFrame)
	}
	length := binary.BigEndian.Uint32(data[8:12])
	if length > uint32(maximum) || int(length) != len(data)-FrameHeaderBytes {
		return nil, wireError(errInvalidFrame)
	}
	return data[FrameHeaderBytes:], nil
}

// wireError returns one immutable content-free typed failure.
func wireError(cause error) error {
	class := FailureUnknown
	switch {
	case errors.Is(cause, errInvalidFrame):
		class = FailureInvalidFrame
	case errors.Is(cause, errResourceLimit):
		class = FailureResourceLimit
	case errors.Is(cause, errInvalidRequest):
		class = FailureInvalidRequest
	case errors.Is(cause, errInvalidReply):
		class = FailureInvalidResponse
	}
	return &WireError{cause: cause, class: class}
}

// cloneByteSlices returns a deep immutable copy.
func cloneByteSlices(input [][]byte) [][]byte {
	output := make([][]byte, len(input))
	for index := range input {
		output[index] = slices.Clone(input[index])
	}
	return output
}

// clearByteSlices erases one temporary vector.
func clearByteSlices(input [][]byte) {
	for index := range input {
		clear(input[index])
	}
}

// writeU16 writes one canonical unsigned integer.
func writeU16(output io.Writer, value uint16) {
	_ = binary.Write(output, binary.BigEndian, value)
}

// writeU32 writes one canonical unsigned integer.
func writeU32(output io.Writer, value uint32) {
	_ = binary.Write(output, binary.BigEndian, value)
}

// writeU16Bytes writes a length-prefixed vector.
func writeU16Bytes(output *bytes.Buffer, values [][]byte) {
	for _, value := range values {
		writeU16(output, uint16(len(value)))
		output.Write(value)
	}
}

// writeU32Bytes writes a length-prefixed vector.
func writeU32Bytes(output *bytes.Buffer, values [][]byte) {
	for _, value := range values {
		writeU32(output, uint32(len(value)))
		output.Write(value)
	}
}

// readByte reads one byte without retaining failed input.
func readByte(input *bytes.Reader) (byte, bool) {
	value, err := input.ReadByte()
	return value, err == nil
}

// readU16 reads one canonical unsigned integer.
func readU16(input io.Reader) (uint16, bool) {
	var value uint16
	err := binary.Read(input, binary.BigEndian, &value)
	return value, err == nil
}

// readU32 reads one canonical unsigned integer.
func readU32(input io.Reader) (uint32, bool) {
	var value uint32
	err := binary.Read(input, binary.BigEndian, &value)
	return value, err == nil
}

// readBytes reads one exact immutable byte string.
func readBytes(input *bytes.Reader, length int) ([]byte, bool) {
	if length < 0 || length > input.Len() {
		return nil, false
	}
	value := make([]byte, length)
	_, err := io.ReadFull(input, value)
	return value, err == nil
}

// readLimitedExact verifies declared frame bytes before allocating one value.
func readLimitedExact(input *io.LimitedReader, length int) ([]byte, bool) {
	if input == nil || length < 0 || length > RequestPayloadBytes || int64(length) > input.N {
		return nil, false
	}
	value := make([]byte, length)
	_, err := io.ReadFull(input, value)
	if err != nil {
		clear(value)
		return nil, false
	}
	return value, true
}

// readU16ByteSlices reads one bounded vector.
func readU16ByteSlices(input *io.LimitedReader, count, maximum int) ([][]byte, error) {
	output := make([][]byte, count)
	for index := range output {
		length, ok := readU16(input)
		if !ok {
			clearByteSlices(output)
			return nil, errInvalidRequest
		}
		if int(length) > maximum {
			clearByteSlices(output)
			return nil, errResourceLimit
		}
		output[index], ok = readLimitedExact(input, int(length))
		if !ok {
			clearByteSlices(output)
			return nil, errInvalidRequest
		}
	}
	return output, nil
}

// readU32ByteSlices reads one individually and cumulatively bounded vector.
func readU32ByteSlices(
	input *io.LimitedReader,
	count int,
	maximum int,
	aggregateMaximum int,
) ([][]byte, int, error) {
	output := make([][]byte, count)
	aggregate := 0
	for index := range output {
		length, ok := readU32(input)
		if !ok {
			clearByteSlices(output)
			return nil, 0, errInvalidRequest
		}
		if length > uint32(maximum) || int(length) > aggregateMaximum-aggregate {
			clearByteSlices(output)
			return nil, 0, errResourceLimit
		}
		aggregate += int(length)
		output[index], ok = readLimitedExact(input, int(length))
		if !ok {
			clearByteSlices(output)
			return nil, 0, errInvalidRequest
		}
	}
	return output, aggregate, nil
}
