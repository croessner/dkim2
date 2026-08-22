package milter

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/resource"
	"golang.org/x/net/idna"
)

const (
	commandAbort     byte = 'A'
	commandBody      byte = 'B'
	commandConnect   byte = 'C'
	commandMacro     byte = 'D'
	commandEOM       byte = 'E'
	commandHelo      byte = 'H'
	commandHeader    byte = 'L'
	commandMail      byte = 'M'
	commandEOH       byte = 'N'
	commandNegotiate byte = 'O'
	commandQuit      byte = 'Q'
	commandRecipient byte = 'R'

	replyAccept       byte = 'a'
	replyContinue     byte = 'c'
	replyAddHeader    byte = 'h'
	replyInsertHeader byte = 'i'
	replyChangeHeader byte = 'm'
	replyReject       byte = 'r'
	replyTempfail     byte = 't'
	replyCode         byte = 'y'

	milterVersion6         uint32 = 6
	actionAddHeaders       uint32 = 0x00000001
	actionChangeHeaders    uint32 = 0x00000010
	actionSetSymbolList    uint32 = 0x00000100
	requiredActions               = actionAddHeaders | actionChangeHeaders
	protocolNoUnknown      uint32 = 0x00000100
	protocolNoData         uint32 = 0x00000200
	protocolHeaderSpace    uint32 = 0x00100000
	requiredProtocol              = protocolNoUnknown | protocolNoData | protocolHeaderSpace
	maxMilterPayloadLength        = 65535
	maxMilterFrameLength          = 1 + maxMilterPayloadLength
	hardMessageBytes       int64  = 32 << 20
	hardHeaderBytes        int64  = 1 << 20
	hardHeaderCount               = 2000
	hardHeaderFieldBytes          = 65536
	hardRecipientCount            = 2000
)

const (
	fixedRejectReply   = "550 5.7.1 DKIM2 policy rejection"
	fixedTempfailReply = "451 4.7.1 DKIM2 service unavailable"
)

type callbackState uint8

const (
	stateInitial callbackState = iota
	stateNegotiated
	stateConnected
	stateHelo
	stateMail
	stateRecipients
	stateHeaders
	stateEOH
	stateBody
)

// Limits bounds every independently attacker-controlled collection.
type Limits struct {
	MessageBytes     int64
	HeaderBytes      int64
	HeaderCount      int
	HeaderFieldBytes int
	RecipientCount   int
}

// FailurePolicy owns explicit fail-open and recipient-group compatibility switches.
type FailurePolicy struct {
	FailOpen            bool
	AllowRecipientGroup bool
}

// Session handles one connection-owned Milter state machine.
type Session struct {
	handler        Handler
	admission      *Admission
	limits         Limits
	timeout        time.Duration
	policy         FailurePolicy
	mode           string
	authservID     string
	state          callbackState
	reverse        []byte
	recipients     [][]byte
	headers        []headerField
	headerBytes    int64
	body           []byte
	reservation    *Reservation
	mutationMayRun bool
	eomPending     bool
	smtpUTF8       bool
	observation    *messageObservation
	transactionAt  time.Time
	postfixDSN     postfixDSNMacroState
}

type headerField struct {
	name, value []byte
}

// NewSession constructs one connection-owned callback runtime.
func NewSession(
	handler Handler,
	admission *Admission,
	limits Limits,
	timeout time.Duration,
	policy FailurePolicy,
	mode, authservID string,
) (*Session, error) {
	if handler == nil || admission == nil || timeout < 100*time.Millisecond ||
		limits.MessageBytes < 1 || limits.HeaderBytes < 1 || limits.HeaderCount < 1 ||
		limits.HeaderFieldBytes < 1 || limits.RecipientCount < 1 ||
		limits.MessageBytes > hardMessageBytes || limits.HeaderBytes > hardHeaderBytes ||
		limits.HeaderCount > hardHeaderCount ||
		limits.HeaderFieldBytes > hardHeaderFieldBytes ||
		limits.RecipientCount > hardRecipientCount ||
		int64(limits.HeaderFieldBytes) > limits.HeaderBytes ||
		limits.HeaderBytes+2 > limits.MessageBytes ||
		policy.AllowRecipientGroup ||
		(mode != modeInbound && mode != modeOriginator && mode != modeTransit &&
			mode != modePostfixDSN) ||
		(mode != modeInbound && authservID != "") {
		return nil, &Error{Class: FailureContract}
	}
	if authservID != "" && !validAuthservToken(authservID) {
		return nil, &Error{Class: FailureContract}
	}
	return &Session{
		handler: handler, admission: admission, limits: limits, timeout: timeout,
		policy: policy, mode: mode, authservID: authservID,
	}, nil
}

// Serve consumes one bounded Milter-v6 connection until quit or failure.
func (s *Session) Serve(ctx context.Context, stream io.ReadWriter) (resultErr error) {
	if s == nil || ctx == nil || stream == nil {
		return &Error{Class: FailureContract}
	}
	var releaseFrame func()
	defer func() {
		if releaseFrame != nil {
			releaseFrame()
		}
		if s.observation != nil {
			s.failMessageObservation(FailureInternal)
			s.finishMessageObservation()
		}
		s.resetTransaction()
		if recover() != nil {
			resultErr = &Error{Class: FailureInternal}
		}
	}()
	for {
		callbackStarted := time.Now()
		previousState := s.state
		command, payload, release, err := readAdmittedFrame(stream, s.admission)
		if err != nil {
			var classified *Error
			if !errors.As(err, &classified) {
				classified = &Error{Class: FailureContract}
			}
			if s.mayFailOpenBeforeOperation(command, classified) {
				s.observeCallback(command, previousState, nil, time.Since(callbackStarted))
				s.setPreOperationFailOpen(time.Since(callbackStarted))
				s.resetTransaction()
				s.state = stateHelo
				if writeErr := s.writeFrames(stream, oneFrame(replyAccept, nil)); writeErr != nil {
					s.failMessageObservation(FailureIndeterminate)
					s.finishMessageObservation()
					return writeErr
				}
				s.finishMessageObservation()
				continue
			}
			if s.isPreOperationCapacity(command, classified) {
				s.setPreOperationOutcome(false, time.Since(callbackStarted))
			}
			s.setTerminalTransactionFailure(command, classified)
			s.observeCallback(command, previousState, classified, time.Since(callbackStarted))
			if commandExpectsReply(command) {
				if writeErr := s.writeFrames(stream, failureFrames(fixedTempfailReply)); writeErr != nil {
					s.failMessageObservation(FailureIndeterminate)
					s.finishMessageObservation()
					return writeErr
				}
			}
			s.finishMessageObservation()
			return classified
		}
		releaseFrame = release
		terminal, response, handleErr := s.handleFrame(ctx, command, payload)
		clear(payload)
		releaseFrame()
		releaseFrame = nil
		s.observeCallback(command, previousState, handleErr, time.Since(callbackStarted))
		if handleErr != nil {
			if s.mayFailOpenBeforeOperation(command, handleErr) {
				s.setPreOperationFailOpen(time.Since(callbackStarted))
				s.resetTransaction()
				s.state = stateHelo
				if writeErr := s.writeFrames(stream, oneFrame(replyAccept, nil)); writeErr != nil {
					s.failMessageObservation(FailureIndeterminate)
					s.finishMessageObservation()
					return writeErr
				}
				s.finishMessageObservation()
				continue
			}
			if s.isPreOperationCapacity(command, handleErr) {
				s.setPreOperationOutcome(false, time.Since(callbackStarted))
			}
			s.setTerminalTransactionFailure(command, handleErr)
			if !commandExpectsReply(command) {
				s.finishMessageObservation()
				return handleErr
			}
			if writeErr := s.writeFrames(stream, failureFrames(fixedTempfailReply)); writeErr != nil {
				s.failMessageObservation(FailureIndeterminate)
				s.finishMessageObservation()
				return writeErr
			}
			s.finishMessageObservation()
			if s.eomPending {
				s.resetTransaction()
				s.state = stateHelo
				continue
			}
			return handleErr
		}
		if len(response) > 0 {
			if err := s.writeFrames(stream, response); err != nil {
				s.failMessageObservation(FailureIndeterminate)
				s.finishMessageObservation()
				return err
			}
		}
		s.finishMessageObservation()
		if s.eomPending {
			s.resetTransaction()
			s.state = stateHelo
		}
		if terminal {
			return nil
		}
	}
}

// mayFailOpenBeforeOperation restricts overload bypass to MAIL before message admission.
func (s *Session) mayFailOpenBeforeOperation(command byte, err error) bool {
	return s.policy.FailOpen && s.isPreOperationCapacity(command, err)
}

// isPreOperationCapacity identifies the sole safe pre-daemon overload boundary.
func (s *Session) isPreOperationCapacity(command byte, err error) bool {
	var classified *Error
	return command == commandMail &&
		errors.As(err, &classified) && classified.Class == FailureCapacity &&
		s.reservation == nil && s.state == stateHelo && !s.mutationMayRun
}

// handleFrame validates one state transition before changing state.
func (s *Session) handleFrame(ctx context.Context, command byte, payload []byte) (bool, [][]byte, error) {
	switch command {
	case commandNegotiate:
		response, err := s.negotiate(payload)
		return false, response, err
	case commandConnect:
		return false, oneFrame(replyContinue, nil), s.handleConnect(payload)
	case commandHelo:
		return false, oneFrame(replyContinue, nil), s.handleHelo(payload)
	case commandMail:
		return false, oneFrame(replyContinue, nil), s.handleMail(payload)
	case commandRecipient:
		return false, oneFrame(replyContinue, nil), s.handleRecipient(payload)
	case commandHeader:
		return false, oneFrame(replyContinue, nil), s.handleHeader(payload)
	case commandEOH:
		return false, oneFrame(replyContinue, nil), s.handleEOH()
	case commandBody:
		return false, oneFrame(replyContinue, nil), s.handleBody(payload)
	case commandEOM:
		return s.handleEOM(ctx, payload)
	case commandAbort:
		return false, nil, s.handleAbort(payload)
	case commandMacro:
		return false, nil, s.handleMacro(payload)
	case commandQuit:
		return s.handleQuit(payload)
	default:
		return false, nil, &Error{Class: FailureContract}
	}
}

// handleConnect validates the connection tuple transition.
func (s *Session) handleConnect(payload []byte) error {
	if s.state != stateNegotiated || !validConnect(payload) {
		return &Error{Class: FailureContract}
	}
	s.state = stateConnected
	return nil
}

// handleHelo validates initial and Postfix-restarted HELO without retaining identity.
func (s *Session) handleHelo(payload []byte) error {
	if (s.state != stateConnected && s.state != stateHelo) ||
		!validSingleNUL(payload, 255) {
		return &Error{Class: FailureContract}
	}
	s.state = stateHelo
	return nil
}

// handleMail admits a transaction before retaining one normalized RFC 5321 reverse-path.
func (s *Session) handleMail(payload []byte) error {
	path, ok := normalizedESMTPCallbackPath(payload, 256, true)
	if s.state != stateHelo || !ok {
		return &Error{Class: FailureContract}
	}
	s.smtpUTF8 = callbackHasParameter(payload, "SMTPUTF8")
	if !asciiBytes(path) && !s.smtpUTF8 {
		return &Error{Class: FailureFidelity}
	}
	if !s.startTransaction(int64(len(path))) {
		return &Error{Class: FailureCapacity}
	}
	s.reverse = bytes.Clone(path)
	if s.mode == modeTransit && !asciiBytes(s.reverse) {
		return &Error{Class: FailureFidelity}
	}
	s.state = stateMail
	return nil
}

// handleRecipient validates and retains one ordered normalized RFC 5321 recipient.
func (s *Session) handleRecipient(payload []byte) error {
	path, ok := normalizedESMTPCallbackPath(payload, 256, false)
	if (s.state != stateMail && s.state != stateRecipients) || !ok ||
		len(s.recipients) >= s.limits.RecipientCount {
		return &Error{Class: FailureContract}
	}
	if s.mode != modeInbound && s.mode != modePostfixDSN && len(s.recipients) >= 1 {
		return &Error{Class: FailureContract}
	}
	if (!asciiBytes(path) && !s.smtpUTF8) ||
		(s.mode == modeTransit && !asciiBytes(path)) {
		return &Error{Class: FailureFidelity}
	}
	if !s.reserve(int64(len(path))) {
		return &Error{Class: FailureCapacity}
	}
	s.recipients = append(s.recipients, bytes.Clone(path))
	s.state = stateRecipients
	return nil
}

// handleHeader validates fidelity and retains one ordered reconstructed field.
func (s *Session) handleHeader(payload []byte) error {
	if (s.state != stateRecipients && s.state != stateHeaders) || len(s.recipients) == 0 {
		return &Error{Class: FailureContract}
	}
	name, callbackValue, valueLength, ok := validateHeaderCallback(
		payload, s.limits.HeaderFieldBytes,
	)
	fieldBytes := len(name) + 1 + valueLength + 2
	if !ok || len(s.headers) >= s.limits.HeaderCount ||
		int64(fieldBytes) > s.limits.HeaderBytes-s.headerBytes ||
		!s.reserve(int64(fieldBytes)) {
		return &Error{Class: FailureFidelity}
	}
	value, ok := reconstructFoldedValue(name, callbackValue)
	if !ok {
		return &Error{Class: FailureInternal}
	}
	s.headers = append(s.headers, headerField{
		name: bytes.Clone(name), value: value,
	})
	s.headerBytes += int64(fieldBytes)
	s.state = stateHeaders
	return nil
}

// handleEOH closes the header section and reserves its exact separator.
func (s *Session) handleEOH() error {
	if (s.state != stateRecipients && s.state != stateHeaders) || !s.reserve(2) {
		return &Error{Class: FailureContract}
	}
	s.state = stateEOH
	return nil
}

// handleBody appends one body chunk only after aggregate capacity admission.
func (s *Session) handleBody(payload []byte) error {
	if s.state != stateEOH && s.state != stateBody {
		return &Error{Class: FailureContract}
	}
	if int64(len(payload)) > s.limits.MessageBytes-int64(len(s.body))-s.headerBytes-2 ||
		!s.reserve(int64(len(payload))*2) {
		return &Error{Class: FailureCapacity}
	}
	s.body = append(s.body, payload...)
	s.state = stateBody
	return nil
}

// handleEOM invokes the handler once after a complete transaction.
func (s *Session) handleEOM(ctx context.Context, payload []byte) (bool, [][]byte, error) {
	if len(payload) != 0 || (s.state != stateEOH && s.state != stateBody) {
		return false, nil, &Error{Class: FailureContract}
	}
	response, err := s.endMessage(ctx)
	s.eomPending = true
	return false, response, err
}

// handleAbort clears any live transaction and tolerates Postfix pre-MAIL aborts.
func (s *Session) handleAbort(payload []byte) error {
	if len(payload) != 0 || s.state < stateHelo {
		return &Error{Class: FailureContract}
	}
	if s.state >= stateMail {
		s.resetTransaction()
	}
	s.state = stateHelo
	return nil
}

// handleMacro retains only the EOD record of the dedicated Postfix DSN mode.
func (s *Session) handleMacro(payload []byte) error {
	valid := validMacro(payload)
	if s.mode == modePostfixDSN {
		valid = validPostfixDSNMacroPayload(payload)
	}
	if !valid {
		return &Error{Class: FailureContract}
	}
	if s.mode != modePostfixDSN {
		return nil
	}
	retained, ok := s.postfixDSN.accept(payload, s.state, s.reservation != nil)
	// Postfix sends ordinary connection macros before MAIL has opened a
	// transaction. Only retained DSN proof bytes need transaction accounting.
	if !ok || retained > int64(^uint64(0)>>1) ||
		(retained > 0 && !s.reserve(retained)) {
		s.postfixDSN.clear()
		return &Error{Class: FailureContract}
	}
	return nil
}

// handleQuit validates the terminal connection callback.
func (s *Session) handleQuit(payload []byte) (bool, [][]byte, error) {
	if len(payload) != 0 || s.state == stateInitial {
		return false, nil, &Error{Class: FailureContract}
	}
	return true, nil, nil
}

// negotiate requires protocol v6, add-header capability, and leading-space fidelity.
func (s *Session) negotiate(payload []byte) ([][]byte, error) {
	if s.state != stateInitial || len(payload) != 12 {
		return nil, &Error{Class: FailureContract}
	}
	version := binary.BigEndian.Uint32(payload[:4])
	actions := binary.BigEndian.Uint32(payload[4:8])
	protocol := binary.BigEndian.Uint32(payload[8:12])
	if version < milterVersion6 || actions&requiredActions != requiredActions ||
		(s.mode == modePostfixDSN && actions&actionSetSymbolList == 0) ||
		protocol&requiredProtocol != requiredProtocol {
		return nil, &Error{Class: FailureFidelity}
	}
	replyActions := requiredActions
	if s.mode == modePostfixDSN {
		replyActions |= actionSetSymbolList
	}
	reply := make([]byte, 12, 12+4+len(postfixDSNEOHMacroList)+1)
	binary.BigEndian.PutUint32(reply[:4], milterVersion6)
	binary.BigEndian.PutUint32(reply[4:8], replyActions)
	binary.BigEndian.PutUint32(reply[8:12], requiredProtocol)
	if s.mode == modePostfixDSN {
		macroType := make([]byte, 4)
		binary.BigEndian.PutUint32(macroType, postfixDSNMacroClassEOH)
		reply = append(reply, macroType...)
		reply = append(reply, postfixDSNEOHMacroList...)
		reply = append(reply, 0)
	}
	s.state = stateNegotiated
	return oneFrame(commandNegotiate, reply), nil
}

// startTransaction atomically acquires admission before retaining callback bytes.
func (s *Session) startTransaction(initial int64) bool {
	if s.reservation != nil {
		return false
	}
	reservation, ok := s.admission.AdmitMessage(initial)
	if !ok {
		return false
	}
	s.reservation = reservation
	s.transactionAt = time.Now()
	return true
}

// reserve grows the process aggregate before slice allocation.
func (s *Session) reserve(amount int64) bool {
	return s.reservation != nil && s.reservation.Grow(amount)
}

// endMessage freezes bytes, calls once, and prevalidates the full response.
func (s *Session) endMessage(ctx context.Context) (frames [][]byte, resultErr error) {
	started := time.Now()
	messageBytes := uint64(0)
	recipients := uint64(len(s.recipients))
	disposition := string(DispositionTempfail)
	resultClass := observationFailure
	failureClass := string(FailureInternal)
	failOpen := false
	domains := DomainObservation{}
	defer func() {
		s.observation = &messageObservation{
			mode: s.mode, disposition: disposition, resultClass: resultClass,
			failureClass: failureClass, duration: time.Since(started),
			messageBytes: messageBytes, recipients: recipients, failOpen: failOpen,
			domains: domains,
		}
	}()
	localAuthenticationResults := localAuthenticationResultOccurrences(
		s.headers,
		s.authservID,
	)
	rawSize := s.headerBytes + 2 + int64(len(s.body))
	if rawSize > 0 {
		messageBytes = uint64(rawSize)
	}
	if rawSize < 1 || !s.reserve(rawSize) {
		failureClass = string(FailureCapacity)
		return nil, &Error{Class: FailureCapacity}
	}
	raw := make([]byte, 0, int(rawSize))
	for _, field := range s.headers {
		raw = append(raw, field.name...)
		raw = append(raw, ':')
		raw = append(raw, field.value...)
		raw = append(raw, '\r', '\n')
	}
	raw = append(raw, '\r', '\n')
	raw = append(raw, s.body...)
	for index := range s.headers {
		clear(s.headers[index].name)
		clear(s.headers[index].value)
	}
	clear(s.body)
	s.headers = nil
	s.headerBytes = 0
	s.body = nil
	if !s.reservation.Shrink(rawSize) {
		clear(raw)
		return nil, &Error{Class: FailureInternal}
	}
	envelopeBytes := int64(len(s.reverse))
	for index := range s.recipients {
		envelopeBytes += int64(len(s.recipients[index]))
	}
	var message Message
	var err error
	if s.mode == modePostfixDSN {
		if !s.postfixDSN.present() {
			clear(raw)
			disposition = string(DispositionAccept)
			resultClass = observationSuccess
			failureClass = observationNoFailure
			return oneFrame(replyAccept, nil), nil
		}
		evidence, applicable, valid := s.postfixDSN.take(s.reverse, s.recipients)
		if !valid {
			clear(raw)
			failureClass = string(FailureContract)
			return nil, &Error{Class: FailureContract}
		}
		if !applicable {
			clear(raw)
			disposition = string(DispositionAccept)
			resultClass = observationSuccess
			failureClass = observationNoFailure
			return oneFrame(replyAccept, nil), nil
		}
		message, err = newOwnedPostfixDSNMessage(raw, s.reverse, s.recipients, evidence)
	} else {
		message, err = newOwnedMessage(raw, s.reverse, s.recipients)
	}
	if err != nil {
		clear(raw)
		failureClass = string(FailureContract)
		return nil, err
	}
	if message.postfixDSN != nil {
		envelopeBytes += message.postfixDSN.retainedBytes()
	}
	s.reverse = nil
	s.recipients = nil
	transportReservation, bounded := eomTransportReservationBytes(rawSize, envelopeBytes)
	if !bounded {
		message.clear()
		failureClass = string(FailureCapacity)
		return nil, &Error{Class: FailureCapacity}
	}
	if transportReservation > int64(^uint64(0)>>1)-resource.EOMResponseWorkingSetBytes ||
		!s.reserve(transportReservation+resource.EOMResponseWorkingSetBytes) {
		message.clear()
		failureClass = string(FailureCapacity)
		return nil, &Error{Class: FailureCapacity}
	}
	operationContext, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	result, err := callHandler(operationContext, s.handler, message)
	domains = result.Domains
	if err != nil {
		class := classifyHandlerError(operationContext, err)
		failureClass = string(class)
		resultClass = observationResultForFailure(class)
		if s.policy.FailOpen && len(localAuthenticationResults) == 0 &&
			(class == FailureUnavailable || class == FailureTimeout) {
			disposition = string(DispositionAccept)
			failOpen = true
			return oneFrame(replyAccept, nil), nil
		}
		return failureFrames(fixedTempfailReply), nil
	}
	frames, err = s.serializeResult(result, localAuthenticationResults)
	if err != nil {
		disposition = string(DispositionTempfail)
		resultClass = observationFailure
		failureClass = string(FailureContract)
		return nil, err
	}
	disposition = string(result.Outcome)
	resultClass = observationResultForDaemon(result.Result)
	failureClass = observationNoFailure
	return frames, nil
}

// eomTransportReservationBytes bounds concurrent raw, Base64, JSON, and
// transport-owned copies retained while the daemon request is in flight.
func eomTransportReservationBytes(rawBytes, envelopeBytes int64) (int64, bool) {
	const maximumInputBytes = int64(^uint64(0)>>1) / resource.EOMRequestCopyCount
	if rawBytes < 1 || envelopeBytes < 0 ||
		envelopeBytes > maximumInputBytes ||
		rawBytes > maximumInputBytes-envelopeBytes {
		return 0, false
	}
	return (rawBytes + envelopeBytes) * resource.EOMRequestCopyCount, true
}

// callHandler contains panics at the injected application seam.
func callHandler(ctx context.Context, handler Handler, message Message) (result Result, resultErr error) {
	defer func() {
		message.clear()
		if recover() != nil {
			result = Result{}
			resultErr = &Error{Class: FailureInternal}
		}
	}()
	return handler.Handle(ctx, message)
}

// serializeResult validates and serializes all mutations before the first write.
func (s *Session) serializeResult(
	result Result,
	localAuthenticationResults []uint32,
) ([][]byte, error) {
	if !validResult(result, s.mode, s.authservID) {
		return nil, &Error{Class: FailureContract}
	}
	if (s.mode != modeInbound || s.authservID == "") &&
		len(localAuthenticationResults) != 0 {
		return nil, &Error{Class: FailureContract}
	}
	switch result.Outcome {
	case DispositionContinue:
		return s.serializeAcceptance(result.Actions, localAuthenticationResults), nil
	case DispositionReject:
		return failureFrames(fixedRejectReply), nil
	case DispositionTempfail:
		return failureFrames(fixedTempfailReply), nil
	case DispositionAccept:
		return s.serializeAcceptance(result.Actions, localAuthenticationResults), nil
	default:
		return nil, &Error{Class: FailureContract}
	}
}

// serializeAcceptance emits trust-boundary scrubbing before approved actions
// and the terminal acceptance frame.
func (s *Session) serializeAcceptance(
	actions []Action,
	localAuthenticationResults []uint32,
) [][]byte {
	frames := make(
		[][]byte,
		0,
		len(localAuthenticationResults)+len(actions)+1,
	)
	for index := len(localAuthenticationResults); index > 0; index-- {
		payload := make([]byte, 4, 4+len(headerAuthResults)+2)
		binary.BigEndian.PutUint32(payload, localAuthenticationResults[index-1])
		payload = append(payload, headerAuthResults...)
		payload = append(payload, 0, 0)
		frames = append(frames, encodeFrame(replyChangeHeader, payload))
	}
	for _, action := range actions {
		prefix := 0
		command := replyAddHeader
		if s.mode == modeInbound && action.Name == headerAuthResults {
			prefix = 4
			command = replyInsertHeader
		}
		valuePrefix := ""
		if action.Name == headerAuthResults {
			valuePrefix = " "
		}
		payload := make(
			[]byte,
			prefix,
			prefix+len(action.Name)+len(valuePrefix)+len(action.Value)+2,
		)
		payload = append(payload, action.Name...)
		payload = append(payload, 0)
		payload = append(payload, valuePrefix...)
		payload = append(payload, action.Value...)
		payload = append(payload, 0)
		frames = append(frames, encodeFrame(command, payload))
	}
	frames = append(frames, encodeFrame(replyAccept, nil))
	if len(actions) > 0 || len(localAuthenticationResults) > 0 {
		s.mutationMayRun = true
	}
	return frames
}

// resetTransaction releases all retained callback state exactly once.
func (s *Session) resetTransaction() {
	clear(s.reverse)
	for index := range s.recipients {
		clear(s.recipients[index])
	}
	for index := range s.headers {
		clear(s.headers[index].name)
		clear(s.headers[index].value)
	}
	clear(s.body)
	s.postfixDSN.clear()
	s.reverse = nil
	s.recipients = nil
	s.headers = nil
	s.headerBytes = 0
	s.body = nil
	if s.reservation != nil {
		s.reservation.Release()
		s.reservation = nil
	}
	s.mutationMayRun = false
	s.eomPending = false
	s.smtpUTF8 = false
	s.transactionAt = time.Time{}
}

// readFrame validates fixed and command-specific caps before payload allocation.
func readFrame(reader io.Reader) (byte, []byte, error) {
	command, payload, _, err := readBoundedFrame(reader, nil)
	return command, payload, err
}

// readAdmittedFrame accounts payload bytes before allocation.
func readAdmittedFrame(reader io.Reader, admission *Admission) (byte, []byte, func(), error) {
	return readBoundedFrame(reader, admission)
}

// readBoundedFrame owns framing, command caps, and optional temporary accounting.
func readBoundedFrame(
	reader io.Reader,
	admission *Admission,
) (byte, []byte, func(), error) {
	noRelease := func() {}
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return 0, nil, noRelease, err
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length < 1 || length > maxMilterFrameLength {
		return 0, nil, noRelease, &Error{Class: FailureContract}
	}
	var command [1]byte
	if _, err := io.ReadFull(reader, command[:]); err != nil {
		return 0, nil, noRelease, err
	}
	payloadLength := int(length) - 1
	if payloadLength > commandPayloadCap(command[0]) {
		return command[0], nil, noRelease, &Error{Class: FailureContract}
	}
	release := noRelease
	if admission != nil {
		var admitted bool
		release, admitted = admission.ReserveBytes(int64(payloadLength))
		if !admitted {
			if err := drainFramePayload(reader, payloadLength); err != nil {
				return command[0], nil, noRelease, &Error{Class: FailureContract}
			}
			return command[0], nil, noRelease, &Error{Class: FailureCapacity}
		}
	}
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(reader, payload); err != nil {
		clear(payload)
		release()
		return 0, nil, noRelease, err
	}
	return command[0], payload, release, nil
}

// drainFramePayload consumes one denied frame with fixed stack memory.
func drainFramePayload(reader io.Reader, remaining int) error {
	var scratch [4096]byte
	for remaining > 0 {
		chunk := min(remaining, len(scratch))
		if _, err := io.ReadFull(reader, scratch[:chunk]); err != nil {
			return err
		}
		remaining -= chunk
	}
	return nil
}

// commandExpectsReply reports whether one callback permits a filter response.
func commandExpectsReply(command byte) bool {
	switch command {
	case commandConnect, commandHelo, commandMail, commandRecipient,
		commandHeader, commandEOH, commandBody, commandEOM:
		return true
	default:
		return false
	}
}

// commandPayloadCap returns the fixed pre-allocation bound for one known command.
func commandPayloadCap(command byte) int {
	switch command {
	case commandNegotiate:
		return 12
	case commandConnect:
		return 515
	case commandHelo:
		return 256
	case commandMail, commandRecipient:
		return 256 + 1 + 4096
	case commandHeader, commandBody, commandMacro:
		return maxMilterPayloadLength
	case commandAbort, commandEOH, commandEOM, commandQuit:
		return 0
	default:
		return -1
	}
}

// encodeFrame creates one complete Milter frame.
func encodeFrame(command byte, payload []byte) []byte {
	frame := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(1+len(payload)))
	frame[4] = command
	copy(frame[5:], payload)
	return frame
}

// oneFrame returns one encoded response batch.
func oneFrame(command byte, payload []byte) [][]byte {
	return [][]byte{encodeFrame(command, payload)}
}

// failureFrames emits one exact terminal enhanced-status reply.
func failureFrames(reply string) [][]byte {
	return oneFrame(replyCode, append([]byte(reply), 0))
}

// writeFrames preserves action order and reports any possible partial effect.
func writeFrames(writer io.Writer, frames [][]byte) (resultErr error) {
	return writeFramesObserved(writer, frames, nil)
}

// writeFramesObserved preserves frame order and reports only closed action facts.
func writeFramesObserved(
	writer io.Writer,
	frames [][]byte,
	observe func(byte, string),
) (resultErr error) {
	totalWritten := 0
	currentCommand := byte(0)
	defer func() {
		if recover() != nil {
			safelyObserveWrittenFrame(observe, currentCommand, observationInternal)
			resultErr = &Error{Class: FailureIndeterminate}
		}
	}()
	for _, frame := range frames {
		if len(frame) < 5 {
			safelyObserveWrittenFrame(observe, 0, observationFailure)
			return &Error{Class: FailureContract}
		}
		currentCommand = frame[4]
		written := 0
		for written < len(frame) {
			count, err := writer.Write(frame[written:])
			if count < 0 || count > len(frame)-written {
				safelyObserveWrittenFrame(observe, frame[4], observationFailure)
				if totalWritten > 0 || count != 0 {
					return &Error{Class: FailureIndeterminate}
				}
				return &Error{Class: FailureInternal}
			}
			if count > 0 {
				written += count
				totalWritten += count
			}
			if err != nil || count == 0 {
				safelyObserveWrittenFrame(observe, frame[4], observationFailure)
				if totalWritten > 0 {
					return &Error{Class: FailureIndeterminate}
				}
				return &Error{Class: FailureUnavailable}
			}
		}
		safelyObserveWrittenFrame(observe, frame[4], observationSuccess)
	}
	return nil
}

// writeFrames applies one batch while containing the process observer seam.
func (s *Session) writeFrames(writer io.Writer, frames [][]byte) error {
	return writeFramesObserved(writer, frames, func(command byte, result string) {
		s.observeAction(command, result)
	})
}

// parseHeader validates and reconstructs one exact CRLF header field value.
func parseHeader(payload []byte, maximum int) ([]byte, []byte, bool) {
	name, callbackValue, _, ok := validateHeaderCallback(payload, maximum)
	if !ok {
		return nil, nil, false
	}
	value, ok := reconstructFoldedValue(name, callbackValue)
	return name, value, ok
}

// validateHeaderCallback proves header shape and computes reconstructed value length.
func validateHeaderCallback(payload []byte, maximum int) ([]byte, []byte, int, bool) {
	name, next, ok := nextNULField(payload, 0)
	if !ok {
		return nil, nil, 0, false
	}
	value, next, ok := nextNULField(payload, next)
	if !ok || next != len(payload) || len(name) == 0 ||
		len(name)+len(value)+1 > maximum {
		return nil, nil, 0, false
	}
	for _, current := range name {
		if current < 33 || current > 126 || current == ':' {
			return nil, nil, 0, false
		}
	}
	valueLength, ok := reconstructedFoldedValueLength(name, value)
	if !ok || len(name)+valueLength+1 > maximum {
		return nil, nil, 0, false
	}
	return name, value, valueLength, true
}

// reconstructFoldedValue maps Milter LF folds to declared reconstructed CRLF.
func reconstructFoldedValue(name, value []byte) ([]byte, bool) {
	length, ok := reconstructedFoldedValueLength(name, value)
	if !ok {
		return nil, false
	}
	output := make([]byte, 0, length)
	for index := range value {
		if value[index] == '\n' && (index == 0 || value[index-1] != '\r') {
			output = append(output, '\r')
		}
		output = append(output, value[index])
	}
	return output, true
}

// reconstructedFoldedValueLength validates physical lines without allocating.
func reconstructedFoldedValueLength(name, value []byte) (int, bool) {
	length := len(value)
	line := len(name) + 1
	if line > 998 {
		return 0, false
	}
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '\r':
			if index+2 >= len(value) || value[index+1] != '\n' ||
				(value[index+2] != ' ' && value[index+2] != '\t') || line > 998 {
				return 0, false
			}
			line = 0
			index++
		case '\n':
			if index+1 >= len(value) || (value[index+1] != ' ' && value[index+1] != '\t') ||
				line > 998 {
				return 0, false
			}
			length++
			line = 0
		case 0:
			return 0, false
		default:
			line++
			if line > 998 {
				return 0, false
			}
		}
	}
	return length, true
}

// validESMTPCallback validates an exact path plus bounded ESMTP arguments.
func validESMTPCallback(payload []byte, maximum int, allowNull bool) bool {
	_, ok := validatedESMTPCallbackPath(payload, maximum, allowNull)
	return ok
}

// normalizedESMTPCallbackPath validates callback arguments and normalizes Postfix's
// unbracketed non-SMTP simulation into the RFC 5321 path form used by DKIM2.
func normalizedESMTPCallbackPath(payload []byte, maximum int, allowNull bool) ([]byte, bool) {
	path, ok := validatedESMTPCallbackPath(payload, maximum, allowNull)
	if !ok {
		return nil, false
	}
	return normalizeMilterEnvelopePath(path, allowNull)
}

// validatedESMTPCallbackPath returns the accepted callback path without
// allocating or changing its Postfix-specific framing.
func validatedESMTPCallbackPath(payload []byte, maximum int, allowNull bool) ([]byte, bool) {
	if len(payload) < 1 || len(payload) > maximum+1+4096 || payload[len(payload)-1] != 0 {
		return nil, false
	}
	path, next, ok := nextNULField(payload, 0)
	if !ok || len(path) > maximum || !validMilterEnvelopePath(path, allowNull) {
		return nil, false
	}
	for next < len(payload) {
		argument, following, present := nextNULField(payload, next)
		if !present {
			return nil, false
		}
		if !validESMTPArgument(argument) {
			return nil, false
		}
		next = following
	}
	return path, true
}

// normalizeMilterEnvelopePath preserves framed paths and unambiguously frames
// the bare mailbox spelling emitted by Postfix for non-SMTP submissions.
func normalizeMilterEnvelopePath(path []byte, allowNull bool) ([]byte, bool) {
	if !validMilterEnvelopePath(path, allowNull) {
		return nil, false
	}
	if len(path) >= 2 && path[0] == '<' && path[len(path)-1] == '>' {
		return bytes.Clone(path), true
	}
	normalized := make([]byte, 0, len(path)+2)
	normalized = append(normalized, '<')
	normalized = append(normalized, path...)
	normalized = append(normalized, '>')
	return normalized, true
}

// validMilterEnvelopePath accepts RFC framing or Postfix's unambiguous bare
// non-SMTP callback spelling without allocating.
func validMilterEnvelopePath(path []byte, allowNull bool) bool {
	if validEnvelopePath(path, allowNull) {
		return true
	}
	if bytes.ContainsAny(path, "<>") {
		return false
	}
	return validEnvelopePathInner(path, allowNull)
}

// validSingleNUL accepts one bounded NUL-terminated value.
func validSingleNUL(payload []byte, maximum int) bool {
	return len(payload) >= 1 && len(payload) <= maximum+1 &&
		payload[len(payload)-1] == 0 && bytes.IndexByte(payload, 0) == len(payload)-1 &&
		!bytes.ContainsAny(payload[:len(payload)-1], "\r\n")
}

// validConnect validates the documented host, family, port, and address tuple.
func validConnect(payload []byte) bool {
	hostEnd := bytes.IndexByte(payload, 0)
	if hostEnd < 1 || hostEnd > 255 || bytes.ContainsAny(payload[:hostEnd], "\r\n") ||
		hostEnd+1 >= len(payload) {
		return false
	}
	address := payload[hostEnd+1:]
	switch address[0] {
	case 'U':
		return len(address) == 1
	case '4', '6', 'L':
		if len(address) < 5 || address[len(address)-1] != 0 {
			return false
		}
		if address[0] == 'L' && (address[1] != 0 || address[2] != 0) {
			return false
		}
		value := address[3 : len(address)-1]
		return len(value) > 0 && len(value) <= 255 &&
			bytes.IndexByte(value, 0) < 0 && !bytes.ContainsAny(value, "\r\n")
	default:
		return false
	}
}

// validMacro accepts one bounded opaque-stage macro name/value sequence.
func validMacro(payload []byte) bool {
	if len(payload) < 1 || len(payload) > maxMilterPayloadLength {
		return false
	}
	if len(payload) == 1 {
		return true
	}
	next := 1
	for next < len(payload) {
		name, following, ok := nextNULField(payload, next)
		if !ok || len(name) == 0 || len(name) > 255 {
			return false
		}
		value, followingValue, ok := nextNULField(payload, following)
		if !ok || len(value) > 4096 {
			return false
		}
		next = followingValue
	}
	return true
}

// validESMTPArgument accepts one RFC 5321 extension keyword and optional value.
func validESMTPArgument(argument []byte) bool {
	if len(argument) == 0 || len(argument) > 512 {
		return false
	}
	before, after, ok := bytes.Cut(argument, []byte{'='})
	keyword := argument
	value := []byte(nil)
	if ok {
		keyword = before
		value = after
		if len(value) == 0 {
			return false
		}
	}
	if len(keyword) == 0 || len(keyword) > 64 {
		return false
	}
	if !isASCIIAlphaNumeric(keyword[0]) {
		return false
	}
	for _, current := range keyword[1:] {
		if !isASCIIAlphaNumeric(current) && current != '-' {
			return false
		}
	}
	if asciiEqualFold(keyword, "SMTPUTF8") && ok {
		return false
	}
	for index := 0; index < len(value); {
		current := value[index]
		if current < utf8.RuneSelf {
			if current < 33 || current > 126 || current == '=' {
				return false
			}
			index++
			continue
		}
		_, size := utf8.DecodeRune(value[index:])
		if size == 1 {
			return false
		}
		index += size
	}
	return true
}

// callbackHasParameter reports whether one exact valueless ESMTP parameter is present.
func callbackHasParameter(payload []byte, name string) bool {
	if len(payload) == 0 || payload[len(payload)-1] != 0 {
		return false
	}
	_, next, ok := nextNULField(payload, 0)
	if !ok {
		return false
	}
	for next < len(payload) {
		field, following, present := nextNULField(payload, next)
		if !present {
			return false
		}
		if asciiEqualFold(field, name) {
			return true
		}
		next = following
	}
	return false
}

// nextNULField returns one non-copying NUL-delimited field and its next offset.
func nextNULField(payload []byte, offset int) ([]byte, int, bool) {
	if offset < 0 || offset >= len(payload) {
		return nil, offset, false
	}
	relative := bytes.IndexByte(payload[offset:], 0)
	if relative < 0 {
		return nil, offset, false
	}
	end := offset + relative
	return payload[offset:end], end + 1, true
}

// asciiEqualFold compares one byte field with an ASCII protocol token.
func asciiEqualFold(value []byte, token string) bool {
	if len(value) != len(token) {
		return false
	}
	for index, current := range value {
		expected := token[index]
		if current >= 'A' && current <= 'Z' {
			current += 'a' - 'A'
		}
		if expected >= 'A' && expected <= 'Z' {
			expected += 'a' - 'A'
		}
		if current != expected {
			return false
		}
	}
	return true
}

// validEnvelopePath checks RFC 5321 path framing and RFC 6531 UTF-8 mailbox extensions.
func validEnvelopePath(path []byte, allowNull bool) bool {
	if len(path) < 2 || len(path) > 256 || path[0] != '<' || path[len(path)-1] != '>' {
		return false
	}
	return validEnvelopePathInner(path[1:len(path)-1], allowNull)
}

// validEnvelopePathInner checks one bounded mailbox or permitted null path
// after the callback-specific framing decision has been made.
func validEnvelopePathInner(inner []byte, allowNull bool) bool {
	if len(inner) == 0 {
		return allowNull
	}
	if len(inner) > 254 {
		return false
	}
	if inner[0] == '@' {
		separator := bytes.IndexByte(inner, ':')
		if separator < 2 || !validSourceRoute(inner[:separator]) {
			return false
		}
		inner = inner[separator+1:]
	}
	localEnd, ok := smtpLocalEnd(inner)
	return ok && localEnd < len(inner) && inner[localEnd] == '@' &&
		localEnd <= 64 && validSMTPDomain(inner[localEnd+1:])
}

// validSourceRoute validates the obsolete route form required for RFC 5321 acceptance.
func validSourceRoute(route []byte) bool {
	if len(route) == 0 {
		return false
	}
	for start := 0; start < len(route); {
		relative := bytes.IndexByte(route[start:], ',')
		end := len(route)
		if relative >= 0 {
			end = start + relative
		}
		part := route[start:end]
		if len(part) < 2 || part[0] != '@' || !validSMTPDomain(part[1:]) {
			return false
		}
		if relative < 0 {
			return true
		}
		start = end + 1
		if start == len(route) {
			return false
		}
	}
	return false
}

// smtpLocalEnd returns the byte after one ASCII or SMTPUTF8 local-part.
func smtpLocalEnd(mailbox []byte) (int, bool) {
	if len(mailbox) == 0 {
		return 0, false
	}
	if mailbox[0] == '"' {
		for index := 1; index < len(mailbox); {
			current := mailbox[index]
			if current == '"' {
				return index + 1, true
			}
			if current == '\\' {
				index++
				if index >= len(mailbox) || mailbox[index] < 32 || mailbox[index] > 126 {
					return 0, false
				}
				index++
				continue
			}
			if current < utf8.RuneSelf {
				if current < 32 || current == 127 || current == '\\' {
					return 0, false
				}
				index++
				continue
			}
			_, size := utf8.DecodeRune(mailbox[index:])
			if size == 1 {
				return 0, false
			}
			index += size
		}
		return 0, false
	}
	at := bytes.IndexByte(mailbox, '@')
	if at < 1 || !validDotString(mailbox[:at]) {
		return 0, false
	}
	return at, true
}

// validDotString validates nonempty RFC 5321 or SMTPUTF8 atoms.
func validDotString(local []byte) bool {
	if len(local) == 0 {
		return false
	}
	for start := 0; start < len(local); {
		relative := bytes.IndexByte(local[start:], '.')
		end := len(local)
		if relative >= 0 {
			end = start + relative
		}
		part := local[start:end]
		if len(part) == 0 {
			return false
		}
		for index := 0; index < len(part); {
			current := part[index]
			if current < utf8.RuneSelf {
				if !isSMTPAtext(current) {
					return false
				}
				index++
				continue
			}
			_, size := utf8.DecodeRune(part[index:])
			if size == 1 {
				return false
			}
			index += size
		}
		if relative < 0 {
			return true
		}
		start = end + 1
		if start == len(local) {
			return false
		}
	}
	return false
}

// isSMTPAtext reports whether one byte is RFC 5321 ASCII atext.
func isSMTPAtext(value byte) bool {
	return isASCIIAlphaNumeric(value) ||
		bytes.ContainsRune([]byte("!#$%&'*+-/=?^_`{|}~"), rune(value))
}

// validSMTPDomain validates an ASCII/EAI domain or an address literal without rewriting it.
func validSMTPDomain(domain []byte) bool {
	if len(domain) == 0 || len(domain) > 255 {
		return false
	}
	if domain[0] == '[' {
		return validAddressLiteral(domain)
	}
	for start := 0; start < len(domain); {
		relative := bytes.IndexByte(domain[start:], '.')
		end := len(domain)
		if relative >= 0 {
			end = start + relative
		}
		label := domain[start:end]
		if len(label) == 0 || !validDomainEdge(label, true) || !validDomainEdge(label, false) {
			return false
		}
		nonASCII := false
		for index := 0; index < len(label); {
			current := label[index]
			if current < utf8.RuneSelf {
				if !isASCIIAlphaNumeric(current) && current != '-' {
					return false
				}
				index++
				continue
			}
			_, size := utf8.DecodeRune(label[index:])
			if size == 1 {
				return false
			}
			nonASCII = true
			index += size
		}
		if nonASCII {
			if !validULabel(label) {
				return false
			}
		} else if len(label) > 63 {
			return false
		}
		if relative < 0 {
			return true
		}
		start = end + 1
		if start == len(domain) {
			return false
		}
	}
	return false
}

// validULabel requires one canonical RFC 5890 U-label without rewriting it.
func validULabel(label []byte) bool {
	text := string(label)
	profile := smtpIDNAProfile()
	ascii, err := profile.ToASCII(text)
	if err != nil || len(ascii) > 63 || !strings.HasPrefix(strings.ToLower(ascii), "xn--") {
		return false
	}
	unicode, err := profile.ToUnicode(ascii)
	return err == nil && unicode == text
}

// smtpIDNAProfile constructs the strict stateless U-label validator.
func smtpIDNAProfile() *idna.Profile {
	return idna.New(
		idna.ValidateForRegistration(),
		idna.BidiRule(),
		idna.CheckHyphens(true),
		idna.CheckJoiners(true),
		idna.StrictDomainName(true),
		idna.ValidateLabels(true),
		idna.VerifyDNSLength(true),
	)
}

// validDomainEdge rejects ASCII hyphens while accepting valid UTF-8 edge runes.
func validDomainEdge(label []byte, first bool) bool {
	value := label[0]
	if !first {
		value = label[len(label)-1]
	}
	if value < utf8.RuneSelf {
		return isASCIIAlphaNumeric(value)
	}
	var size int
	if first {
		_, size = utf8.DecodeRune(label)
	} else {
		_, size = utf8.DecodeLastRune(label)
	}
	return size > 1
}

// validAddressLiteral validates IPv4, IPv6, and bounded general address literals.
func validAddressLiteral(domain []byte) bool {
	if len(domain) < 3 || domain[0] != '[' || domain[len(domain)-1] != ']' {
		return false
	}
	content := string(domain[1 : len(domain)-1])
	if parsed, err := netip.ParseAddr(content); err == nil {
		return parsed.Is4()
	}
	if len(content) > len("IPv6:") && strings.EqualFold(content[:len("IPv6:")], "IPv6:") {
		parsed, err := netip.ParseAddr(content[len("IPv6:"):])
		return err == nil && parsed.Is6()
	}
	separator := strings.IndexByte(content, ':')
	if separator < 1 || separator > 63 || separator == len(content)-1 {
		return false
	}
	if !isASCIIAlphaNumeric(content[0]) || !isASCIIAlphaNumeric(content[separator-1]) {
		return false
	}
	for index := range separator {
		if !isASCIIAlphaNumeric(content[index]) && content[index] != '-' {
			return false
		}
	}
	for index := separator + 1; index < len(content); index++ {
		if content[index] < 33 || content[index] > 126 ||
			content[index] == '[' || content[index] == ']' || content[index] == '\\' {
			return false
		}
	}
	return true
}

// isASCIIAlphaNumeric reports whether one byte is an ASCII letter or digit.
func isASCIIAlphaNumeric(value byte) bool {
	return isASCIIAlpha(value) || value >= '0' && value <= '9'
}

// isASCIIAlpha reports whether one byte is an ASCII letter.
func isASCIIAlpha(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

// firstNULField returns the exact first callback field.
func firstNULField(payload []byte) []byte {
	before, _, ok := bytes.Cut(payload, []byte{0})
	if !ok {
		return nil
	}
	return before
}

// asciiBytes reports whether a path is within the signing engine's ASCII baseline.
func asciiBytes(value []byte) bool {
	for _, current := range value {
		if current > 0x7f {
			return false
		}
	}
	return true
}

// classifyHandlerError maps only bounded pre-response failures.
func classifyHandlerError(ctx context.Context, err error) FailureClass {
	var adapterError *Error
	if errors.As(err, &adapterError) {
		return adapterError.Class
	}
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return FailureTimeout
	}
	return FailureInternal
}
