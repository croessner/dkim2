// Package lmtp owns the bounded LMTP receiver of the propagation adapter.
//
// The receiver implements the RFC 2033 subset the adapter needs: LHLO, MAIL,
// RCPT, DATA, RSET, NOOP, and QUIT, with the mandatory PIPELINING and
// ENHANCEDSTATUSCODES extensions and with SIZE, 8BITMIME, and SMTPUTF8 so a
// forwarded EAI notification can reach the socket. HELO and EHLO are answered
// 500 because this endpoint is not an SMTP server. Exactly one transaction
// with a null reverse path and one forward path is accepted, and after DATA
// exactly one reply is returned for the single accepted recipient.
package lmtp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	redactedReceiver = "dkim2_dsn_propagator_lmtp{redacted}"
	crlf             = "\r\n"
	maxCommandBytes  = 1024
	maxDataLineBytes = 65_536
	maxForwardPath   = 256

	replyGreeting          = "220 %s LMTP ready" + crlf
	replyClosing           = "221 2.0.0 closing" + crlf
	replyOK                = "250 2.0.0 ok" + crlf
	replyStartData         = "354 start mail input" + crlf
	replyAccepted          = "250 2.0.0 accepted" + crlf
	replyDeferredTransport = "451 4.4.1 propagation deferred" + crlf
	replyDeferredPolicy    = "451 4.7.1 propagation deferred" + crlf
	replyRejected          = "550 5.7.1 propagation refused" + crlf
	replyNotSMTP           = "500 5.5.1 command not implemented" + crlf
	replyUnknownCommand    = "502 5.5.1 command not implemented" + crlf
	replyBadSequence       = "503 5.5.1 bad sequence of commands" + crlf
	replyBadParameter      = "555 5.5.4 parameter not recognized" + crlf
	replySyntax            = "500 5.5.2 syntax error" + crlf
	replyNotNullSender     = "550 5.7.1 reserved for delivery-status notifications" + crlf
	replyTooManyRecipients = "452 4.5.3 too many recipients" + crlf
	replyTooLarge          = "552 5.3.4 message exceeds size limit" + crlf
	replyLocalError        = "451 4.3.0 local error" + crlf
	replyShuttingDown      = "421 4.3.2 shutting down" + crlf
)

// Error is one content-free receiver failure.
type Error struct{}

// Error returns a stable secret-safe diagnostic.
func (*Error) Error() string { return "dkim2-dsn-propagator lmtp failure" }

// Is recognizes the bounded receiver error.
func (*Error) Is(target error) bool {
	_, ok := target.(*Error)
	return ok
}

// IsError reports whether err is a bounded receiver failure.
func IsError(err error) bool { return errors.Is(err, &Error{}) }

// Reply is the closed answer the propagation handler may return.
type Reply uint8

const (
	// ReplyAccepted acknowledges delivery responsibility with 250.
	ReplyAccepted Reply = iota + 1
	// ReplyRejected refuses the notification permanently with 550 5.7.1.
	ReplyRejected
	// ReplyDeferredTransport defers with 451 4.4.1 after a transport failure.
	ReplyDeferredTransport
	// ReplyDeferredPolicy defers with 451 4.7.1 after a daemon or contract failure.
	ReplyDeferredPolicy
)

// text returns the exact wire reply of one closed handler answer.
func (r Reply) text() string {
	switch r {
	case ReplyAccepted:
		return replyAccepted
	case ReplyRejected:
		return replyRejected
	case ReplyDeferredTransport:
		return replyDeferredTransport
	case ReplyDeferredPolicy:
		return replyDeferredPolicy
	default:
		return replyDeferredPolicy
	}
}

// Delivery is one immutable received notification handed to the handler.
type Delivery struct {
	// ForwardPath is the exact unrewritten angle-addressed recipient.
	ForwardPath string
	// SMTPUTF8 records whether the MAIL command carried the parameter.
	SMTPUTF8 bool
	// Bytes is the exact CRLF, dot-unstuffed message content.
	Bytes []byte
}

// Handler processes exactly one delivered notification.
//
// It must never return before it has decided the final LMTP answer, because
// the receiver acknowledges only what the handler already completed.
type Handler interface {
	Handle(context.Context, Delivery) Reply
}

// Limits bounds one receiver session.
type Limits struct {
	// MessageBytes is the advertised and enforced message size limit.
	MessageBytes int64
	// GreetingName is the bounded name announced in the greeting and LHLO.
	GreetingName string
}

// valid rejects incomplete session bounds before any connection is served.
func (l Limits) valid() bool {
	return l.MessageBytes >= 1024 && l.GreetingName != "" &&
		len(l.GreetingName) <= 253
}

// sessionState is the closed LMTP transaction state.
type sessionState uint8

const (
	stateInitial sessionState = iota + 1
	stateGreeted
	stateMail
	stateRecipient
)

// session serves exactly one connection and one transaction at a time.
type session struct {
	reader  *bufio.Reader
	writer  *bufio.Writer
	limits  Limits
	handler Handler

	state       sessionState
	smtputf8    bool
	forwardPath string
}

// newSession constructs one isolated connection state machine.
func newSession(stream io.ReadWriter, limits Limits, handler Handler) (*session, error) {
	if stream == nil || handler == nil || !limits.valid() {
		return nil, &Error{}
	}
	return &session{
		reader:  bufio.NewReaderSize(stream, maxCommandBytes),
		writer:  bufio.NewWriterSize(stream, 4096),
		limits:  limits,
		handler: handler,
		state:   stateInitial,
	}, nil
}

// Serve runs the connection until QUIT, cancellation, or stream closure.
func (s *session) Serve(ctx context.Context) error {
	if ctx == nil {
		return &Error{}
	}
	if err := s.emit(fmt.Sprintf(replyGreeting, s.limits.GreetingName)); err != nil {
		return err
	}
	for {
		if ctx.Err() != nil {
			_ = s.emit(replyShuttingDown)
			return nil
		}
		line, err := s.readCommandLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			if errors.Is(err, errLineTooLong) {
				if emitErr := s.emit(replySyntax); emitErr != nil {
					return emitErr
				}
				continue
			}
			return err
		}
		done, err := s.dispatch(ctx, line)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

// errLineTooLong marks one command line beyond the receiver bound.
var errLineTooLong = errors.New("lmtp command line too long")

// readCommandLine reads one exact CRLF-terminated bounded command line.
func (s *session) readCommandLine() (string, error) {
	line, err := s.reader.ReadString('\n')
	if err != nil {
		if len(line) > 0 && errors.Is(err, io.EOF) {
			return "", io.EOF
		}
		return "", err
	}
	if len(line) > maxCommandBytes {
		return "", errLineTooLong
	}
	if !strings.HasSuffix(line, crlf) {
		return "", errLineTooLong
	}
	return strings.TrimSuffix(line, crlf), nil
}

// dispatch executes exactly one command and reports whether to close.
func (s *session) dispatch(ctx context.Context, line string) (bool, error) {
	verb, argument, _ := strings.Cut(line, " ")
	verb = strings.ToUpper(verb)
	argument = strings.TrimPrefix(argument, " ")
	switch verb {
	case "LHLO":
		return false, s.handleLHLO(argument)
	case "HELO", "EHLO":
		return false, s.emit(replyNotSMTP)
	case "MAIL":
		return false, s.handleMail(argument)
	case "RCPT":
		return false, s.handleRecipient(argument)
	case "DATA":
		return false, s.handleData(ctx)
	case "RSET":
		s.resetTransaction()
		if s.state == stateInitial {
			return false, s.emit(replyBadSequence)
		}
		return false, s.emit(replyOK)
	case "NOOP":
		return false, s.emit(replyOK)
	case "QUIT":
		return true, s.emit(replyClosing)
	default:
		return false, s.emit(replyUnknownCommand)
	}
}

// handleLHLO answers the exact advertised extension set and resets state.
func (s *session) handleLHLO(argument string) error {
	if argument == "" || len(argument) > 253 || strings.ContainsAny(argument, " \t") {
		return s.emit(replySyntax)
	}
	s.resetTransaction()
	s.state = stateGreeted
	name := s.limits.GreetingName
	return s.emit(
		"250-" + name + crlf +
			"250-PIPELINING" + crlf +
			"250-ENHANCEDSTATUSCODES" + crlf +
			"250-SIZE " + strconv.FormatInt(s.limits.MessageBytes, 10) + crlf +
			"250-8BITMIME" + crlf +
			"250 SMTPUTF8" + crlf,
	)
}

// handleMail admits exactly one null-sender transaction.
func (s *session) handleMail(argument string) error {
	if s.state == stateInitial {
		return s.emit(replyBadSequence)
	}
	if s.state != stateGreeted {
		return s.emit(replyBadSequence)
	}
	rest, ok := cutPrefixFold(argument, "FROM:")
	if !ok {
		return s.emit(replySyntax)
	}
	path, parameters, ok := splitPathParameters(rest)
	if !ok {
		return s.emit(replySyntax)
	}
	if path != "<>" {
		return s.emit(replyNotNullSender)
	}
	smtputf8 := false
	for _, parameter := range parameters {
		keyword, value, hasValue := strings.Cut(parameter, "=")
		switch strings.ToUpper(keyword) {
		case "SMTPUTF8":
			if hasValue {
				return s.emit(replyBadParameter)
			}
			smtputf8 = true
		case "BODY":
			if !hasValue || strings.ToUpper(value) != "8BITMIME" &&
				strings.ToUpper(value) != "7BIT" {
				return s.emit(replyBadParameter)
			}
		case "SIZE":
			size, err := strconv.ParseInt(value, 10, 64)
			if !hasValue || err != nil || size < 0 {
				return s.emit(replyBadParameter)
			}
			if size > s.limits.MessageBytes {
				return s.emit(replyTooLarge)
			}
		default:
			return s.emit(replyBadParameter)
		}
	}
	s.smtputf8 = smtputf8
	s.state = stateMail
	return s.emit(replyOK)
}

// handleRecipient admits exactly one forward path and defers every further one.
func (s *session) handleRecipient(argument string) error {
	if s.state != stateMail && s.state != stateRecipient {
		return s.emit(replyBadSequence)
	}
	rest, ok := cutPrefixFold(argument, "TO:")
	if !ok {
		return s.emit(replySyntax)
	}
	path, parameters, ok := splitPathParameters(rest)
	if !ok {
		return s.emit(replySyntax)
	}
	if len(parameters) != 0 {
		return s.emit(replyBadParameter)
	}
	if !validForwardPath(path) {
		return s.emit(replySyntax)
	}
	if s.state == stateRecipient {
		return s.emit(replyTooManyRecipients)
	}
	s.forwardPath = path
	s.state = stateRecipient
	return s.emit(replyOK)
}

// handleData collects the message and returns exactly one recipient reply.
func (s *session) handleData(ctx context.Context) error {
	if s.state != stateRecipient {
		return s.emit(replyBadSequence)
	}
	if err := s.emit(replyStartData); err != nil {
		return err
	}
	message, oversize, err := s.collect()
	if err != nil {
		return err
	}
	delivery := Delivery{
		ForwardPath: s.forwardPath,
		SMTPUTF8:    s.smtputf8,
		Bytes:       message,
	}
	s.resetTransaction()
	if oversize {
		clear(message)
		return s.emit(replyTooLarge)
	}
	if len(message) == 0 {
		clear(message)
		return s.emit(replyLocalError)
	}
	reply := s.callHandler(ctx, delivery)
	clear(message)
	return s.emit(reply.text())
}

// callHandler contains handler panics without acknowledging the transaction.
func (s *session) callHandler(ctx context.Context, delivery Delivery) (reply Reply) {
	defer func() {
		if recover() != nil {
			reply = ReplyDeferredPolicy
		}
	}()
	return s.handler.Handle(ctx, delivery)
}

// collect reads the dot-terminated message with exact CRLF and unstuffing.
//
// The complete message is always drained so the connection stays usable, even
// when the transfer already exceeded the configured limit.
func (s *session) collect() ([]byte, bool, error) {
	message := make([]byte, 0, 16<<10)
	oversize := false
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			clear(message)
			return nil, false, err
		}
		if len(line) > maxDataLineBytes || !strings.HasSuffix(line, crlf) {
			clear(message)
			return nil, false, &Error{}
		}
		content := strings.TrimSuffix(line, crlf)
		if content == "." {
			return message, oversize, nil
		}
		content = strings.TrimPrefix(content, ".")
		if oversize {
			continue
		}
		if int64(len(message))+int64(len(content))+2 > s.limits.MessageBytes {
			oversize = true
			clear(message)
			message = message[:0]
			continue
		}
		message = append(message, content...)
		message = append(message, crlf...)
	}
}

// resetTransaction clears every transaction-scoped value.
func (s *session) resetTransaction() {
	s.smtputf8 = false
	s.forwardPath = ""
	if s.state == stateMail || s.state == stateRecipient {
		s.state = stateGreeted
	}
}

// emit writes one complete bounded reply.
func (s *session) emit(reply string) error {
	if _, err := s.writer.WriteString(reply); err != nil {
		return &Error{}
	}
	if err := s.writer.Flush(); err != nil {
		return &Error{}
	}
	return nil
}

// cutPrefixFold removes one case-insensitive command prefix.
func cutPrefixFold(value, prefix string) (string, bool) {
	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimLeft(value[len(prefix):], " "), true
}

// splitPathParameters separates one angle-addressed path from its parameters.
func splitPathParameters(value string) (string, []string, bool) {
	if !strings.HasPrefix(value, "<") {
		return "", nil, false
	}
	end := strings.IndexByte(value, '>')
	if end < 0 {
		return "", nil, false
	}
	path := value[:end+1]
	rest := strings.TrimLeft(value[end+1:], " ")
	if rest == "" {
		return path, nil, true
	}
	parameters := strings.Split(rest, " ")
	for _, parameter := range parameters {
		if parameter == "" {
			return "", nil, false
		}
	}
	return path, parameters, true
}

// validForwardPath accepts one bounded angle-addressed non-null forward path.
func validForwardPath(value string) bool {
	if len(value) < 3 || len(value) > maxForwardPath ||
		value[0] != '<' || value[len(value)-1] != '>' {
		return false
	}
	if bytes.ContainsAny([]byte(value), "\x00\r\n") {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] == 0x7f {
			return false
		}
	}
	return !strings.ContainsAny(value[1:len(value)-1], "<>")
}

// String returns a content-free session diagnostic.
func (session) String() string { return redactedReceiver }

// GoString returns a content-free session representation.
func (s session) GoString() string { return s.String() }

// Format prevents formatting from traversing envelope or message state.
func (s session) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, s.String())
}

// MarshalJSON rejects session serialization.
func (session) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// MarshalText rejects session text serialization.
func (session) MarshalText() ([]byte, error) { return nil, &Error{} }

// String returns a content-free delivery diagnostic.
func (Delivery) String() string { return redactedReceiver }

// GoString returns a content-free delivery representation.
func (d Delivery) GoString() string { return d.String() }

// Format prevents formatting from traversing the recipient or the content.
func (d Delivery) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, d.String())
}

// MarshalJSON rejects delivery serialization.
func (Delivery) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// MarshalText rejects delivery text serialization.
func (Delivery) MarshalText() ([]byte, error) { return nil, &Error{} }
