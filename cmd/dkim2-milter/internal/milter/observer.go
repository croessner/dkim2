package milter

import (
	"context"
	"time"
)

const (
	observationFailure   = "failure"
	observationInternal  = "internal"
	observationNoFailure = "none"
	observationSuccess   = "success"
	observationTemporary = "temporary"
)

// messageObservation retains only closed facts until MTA writes finish.
type messageObservation struct {
	mode         string
	disposition  string
	resultClass  string
	failureClass string
	duration     time.Duration
	messageBytes uint64
	recipients   uint64
	failOpen     bool
	domains      DomainObservation
}

// setPreOperationFailOpen records the sole local-overload compatibility outcome.
func (s *Session) setPreOperationFailOpen(duration time.Duration) {
	s.setPreOperationOutcome(true, duration)
}

// setPreOperationOutcome records one local-overload result before daemon work.
func (s *Session) setPreOperationOutcome(failOpen bool, duration time.Duration) {
	if s == nil {
		return
	}
	disposition := string(DispositionTempfail)
	if failOpen {
		disposition = string(DispositionAccept)
	}
	s.observation = &messageObservation{
		mode: s.mode, disposition: disposition,
		resultClass: observationTemporary, failureClass: string(FailureCapacity),
		duration: duration, failOpen: failOpen,
	}
}

// setTerminalTransactionFailure records one admitted transaction that cannot reach EOM.
func (s *Session) setTerminalTransactionFailure(command byte, err error) {
	if s == nil || s.reservation == nil || s.observation != nil || err == nil {
		return
	}
	class := classifyHandlerError(context.Background(), err)
	disposition := string(DispositionTempfail)
	if !commandExpectsReply(command) {
		disposition = "close"
	}
	duration := time.Duration(0)
	if !s.transactionAt.IsZero() {
		duration = time.Since(s.transactionAt)
	}
	messageBytes := max(s.headerBytes+2+int64(len(s.body)), 0)
	s.observation = &messageObservation{
		mode: s.mode, disposition: disposition,
		resultClass: observationResultForFailure(class), failureClass: string(class),
		duration: duration, messageBytes: uint64(messageBytes),
		recipients: uint64(len(s.recipients)),
	}
}

// finishMessageObservation emits and clears one pending EOM observation.
func (s *Session) finishMessageObservation() {
	if s == nil || s.observation == nil {
		return
	}
	observation := s.observation
	s.observation = nil
	s.observeMessage(
		observation.disposition,
		observation.resultClass,
		observation.failureClass,
		observation.duration,
		observation.messageBytes,
		observation.recipients,
		observation.failOpen,
		observation.domains,
	)
}

// failMessageObservation replaces a pending outcome after an ambiguous MTA write.
func (s *Session) failMessageObservation(class FailureClass) {
	if s == nil || s.observation == nil {
		return
	}
	s.observation.disposition = "close"
	s.observation.resultClass = observationResultForFailure(class)
	s.observation.failureClass = string(class)
	s.observation.failOpen = false
}

// observeCallback reports one closed callback and state outcome.
func (s *Session) observeCallback(
	command byte,
	state callbackState,
	err error,
	duration time.Duration,
) {
	if s == nil || s.admission == nil {
		return
	}
	callback, ok := callbackObservationClass(command)
	if !ok {
		return
	}
	result := observationSuccess
	if err != nil {
		result = observationResultForFailure(classifyHandlerError(context.Background(), err))
	}
	observer := s.admission.observerSnapshot()
	safelyObserve(func() {
		observer.RecordCallback(callback, stateObservationClass(state), result, duration)
	}, observer)
}

// observeMessage reports one terminal message outcome exactly once.
func (s *Session) observeMessage(
	disposition string,
	resultClass string,
	failureClass string,
	duration time.Duration,
	messageBytes uint64,
	recipients uint64,
	failOpen bool,
	domains DomainObservation,
) {
	if s == nil || s.admission == nil {
		return
	}
	observer := s.admission.observerSnapshot()
	safelyObserve(func() {
		observer.RecordMessage(
			s.mode,
			disposition,
			resultClass,
			failureClass,
			duration,
			messageBytes,
			recipients,
			failOpen,
			domains,
		)
	}, observer)
}

// observeAction reports one frame outcome without retaining its payload.
func (s *Session) observeAction(command byte, result string) {
	if s == nil || s.admission == nil {
		return
	}
	action, ok := actionObservationClass(command)
	if !ok {
		return
	}
	observer := s.admission.observerSnapshot()
	safelyObserve(func() {
		observer.RecordAction(action, result)
	}, observer)
}

// safelyObserve contains observer panics and skips absent observers.
func safelyObserve(call func(), observer Observer) {
	if observer == nil || call == nil {
		return
	}
	defer func() { _ = recover() }()
	call()
}

// safelyObserveWrittenFrame contains frame-observer panics.
func safelyObserveWrittenFrame(observe func(byte, string), command byte, result string) {
	if observe == nil {
		return
	}
	defer func() { _ = recover() }()
	observe(command, result)
}

// callbackObservationClass maps one wire command to a fixed callback name.
func callbackObservationClass(command byte) (string, bool) {
	switch command {
	case commandAbort:
		return "abort", true
	case commandBody:
		return "body", true
	case commandConnect:
		return "connect", true
	case commandMacro:
		return "macro", true
	case commandEOM:
		return "eom", true
	case commandHelo:
		return "helo", true
	case commandHeader:
		return "header", true
	case commandMail:
		return "mail", true
	case commandEOH:
		return "eoh", true
	case commandNegotiate:
		return "negotiate", true
	case commandQuit:
		return "quit", true
	case commandRecipient:
		return "recipient", true
	default:
		return "", false
	}
}

// stateObservationClass maps one connection state to a fixed label.
func stateObservationClass(state callbackState) string {
	switch state {
	case stateInitial:
		return "initial"
	case stateNegotiated:
		return "negotiated"
	case stateConnected:
		return "connected"
	case stateHelo:
		return "helo"
	case stateMail:
		return "mail"
	case stateRecipients:
		return "recipients"
	case stateHeaders:
		return "headers"
	case stateEOH:
		return "eoh"
	case stateBody:
		return "body"
	default:
		return "terminal"
	}
}

// actionObservationClass maps one response command to a fixed action name.
func actionObservationClass(command byte) (string, bool) {
	switch command {
	case replyAccept:
		return "accept", true
	case replyAddHeader:
		return "add_header", true
	case replyInsertHeader:
		return "insert_header", true
	case replyChangeHeader:
		return "change_header", true
	case replyContinue:
		return "continue", true
	case replyReject:
		return "reject", true
	case replyCode:
		return "reply_code", true
	case replyTempfail:
		return "tempfail", true
	default:
		return "", false
	}
}

// observationResultForFailure maps one failure class to a closed result class.
func observationResultForFailure(class FailureClass) string {
	switch class {
	case FailureCapacity, FailureUnavailable, FailureTimeout:
		return observationTemporary
	case FailureInternal:
		return observationInternal
	default:
		return observationFailure
	}
}

// observationResultForDaemon maps one closed daemon result to an outcome class.
func observationResultForDaemon(result string) string {
	switch result {
	case resultPass, resultNone:
		return observationSuccess
	case resultTemperror:
		return observationTemporary
	default:
		return observationFailure
	}
}
