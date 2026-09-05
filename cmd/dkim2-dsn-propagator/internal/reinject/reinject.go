// Package reinject owns the SMTP submission of one signed notification.
//
// The client opens exactly one session to the configured literal loopback
// listener, sends a null reverse path and the single previous-hop forward
// path, transfers the signed bytes, and reports one closed outcome. It never
// retries, never rewrites the message, and never selects a recipient.
package reinject

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/endpoint"
)

const (
	redactedClient       = "dkim2_dsn_propagator_reinjection{redacted}"
	maxReplyLineBytes    = 512
	maxReplyLines        = 64
	maxExtensionEntries  = 64
	crlf                 = "\r\n"
	extensionSMTPUTF8    = "SMTPUTF8"
	extension8BITMIME    = "8BITMIME"
	extensionSIZE        = "SIZE"
	nullReversePath      = "<>"
	greetingCode         = 220
	completionCode       = 250
	dataIntermediateCode = 354
)

// Outcome is the closed result vocabulary of one re-injection attempt.
type Outcome string

const (
	// OutcomeAccepted marks a listener that answered 250 to the final dot.
	OutcomeAccepted Outcome = "accepted"
	// OutcomeDeferred marks a temporary listener refusal.
	OutcomeDeferred Outcome = "deferred"
	// OutcomeFailed marks a permanent refusal or a transport failure.
	OutcomeFailed Outcome = "failed"
	// OutcomeSMTPUTF8Unavailable marks a listener without required SMTPUTF8.
	OutcomeSMTPUTF8Unavailable Outcome = "smtputf8_unavailable"
)

// Error is one content-free re-injection failure carrying its closed outcome.
type Error struct {
	// Outcome is the closed observable classification of this failure.
	Outcome Outcome
}

// Error returns a stable secret-safe diagnostic without peer or content.
func (*Error) Error() string { return "dkim2-dsn-propagator re-injection failure" }

// Is recognizes any bounded re-injection error.
func (*Error) Is(target error) bool {
	_, ok := target.(*Error)
	return ok
}

// OutcomeOf returns the closed outcome of a re-injection error.
func OutcomeOf(err error) Outcome {
	var typed *Error
	if errors.As(err, &typed) && typed != nil {
		return typed.Outcome
	}
	return OutcomeFailed
}

// Message is one immutable re-injection request.
type Message struct {
	// ForwardPath is the exact angle-addressed previous-hop recipient.
	ForwardPath string
	// SMTPUTF8Required requires the listener to advertise SMTPUTF8.
	SMTPUTF8Required bool
	// EightBitMIMERequired requires the listener to advertise 8BITMIME.
	EightBitMIMERequired bool
	// Bytes is the complete signed notification.
	Bytes []byte
}

// Timeouts bounds every phase of one re-injection session.
type Timeouts struct {
	// Connect bounds the dial.
	Connect time.Duration
	// Command bounds the greeting and every command reply.
	Command time.Duration
	// Data bounds the DATA transfer and its final reply.
	Data time.Duration
}

// dialer opens one stream to the already validated literal authority.
type dialer func(context.Context, string, string) (net.Conn, error)

// Client submits signed notifications to one literal loopback listener.
type Client struct {
	state *clientState
}

// clientState keeps the public holder copy-safe while owning its settings.
type clientState struct {
	authority string
	ehloName  string
	timeouts  Timeouts
	dial      dialer
}

// NewClient validates the endpoint and freezes the session bounds.
func NewClient(
	origin string,
	ehloName string,
	timeouts Timeouts,
) (*Client, error) {
	netDialer := &net.Dialer{}
	return newClient(origin, ehloName, timeouts, netDialer.DialContext)
}

// newClient constructs one client through an injected transport seam.
func newClient(
	origin string,
	ehloName string,
	timeouts Timeouts,
	dial dialer,
) (*Client, error) {
	if !endpoint.IsCanonicalLoopbackSMTPURL(origin) || dial == nil ||
		ehloName == "" || len(ehloName) > 253 ||
		timeouts.Connect <= 0 || timeouts.Command <= 0 || timeouts.Data <= 0 {
		return nil, &Error{Outcome: OutcomeFailed}
	}
	authority, ok := endpoint.Authority(origin)
	if !ok {
		return nil, &Error{Outcome: OutcomeFailed}
	}
	return &Client{state: &clientState{
		authority: authority, ehloName: ehloName, timeouts: timeouts, dial: dial,
	}}, nil
}

// Send performs exactly one session and returns only after the listener's
// final reply. It never retries and never falls back to another route.
func (c *Client) Send(ctx context.Context, message Message) error {
	if c == nil || c.state == nil || ctx == nil ||
		len(message.Bytes) == 0 || !validForwardPath(message.ForwardPath) {
		return &Error{Outcome: OutcomeFailed}
	}
	dialContext, cancel := context.WithTimeout(ctx, c.state.timeouts.Connect)
	connection, err := c.state.dial(dialContext, "tcp", c.state.authority)
	cancel()
	if err != nil || connection == nil {
		return &Error{Outcome: OutcomeFailed}
	}
	defer func() { _ = connection.Close() }()
	session := &session{
		connection: connection,
		reader:     bufio.NewReaderSize(connection, maxReplyLineBytes),
		writer:     bufio.NewWriterSize(connection, 4096),
		timeouts:   c.state.timeouts,
	}
	return session.run(c.state.ehloName, message)
}

// String returns a content-free client diagnostic.
func (Client) String() string { return redactedClient }

// GoString returns a content-free client representation.
func (c Client) GoString() string { return c.String() }

// Format prevents formatting from traversing endpoint state.
func (c Client) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, c.String())
}

// MarshalJSON rejects client serialization.
func (Client) MarshalJSON() ([]byte, error) { return nil, &Error{Outcome: OutcomeFailed} }

// MarshalText rejects client text serialization.
func (Client) MarshalText() ([]byte, error) { return nil, &Error{Outcome: OutcomeFailed} }

// String returns a content-free private client-state diagnostic.
func (clientState) String() string { return redactedClient }

// GoString returns a content-free private client-state representation.
func (state clientState) GoString() string { return state.String() }

// Format prevents nested formatting from traversing endpoint state.
func (state clientState) Format(output fmt.State, _ rune) {
	_, _ = io.WriteString(output, state.String())
}

// MarshalJSON rejects private client-state serialization.
func (clientState) MarshalJSON() ([]byte, error) {
	return nil, &Error{Outcome: OutcomeFailed}
}

// MarshalText rejects private client-state text serialization.
func (clientState) MarshalText() ([]byte, error) {
	return nil, &Error{Outcome: OutcomeFailed}
}

// session owns one bounded SMTP conversation.
type session struct {
	connection net.Conn
	reader     *bufio.Reader
	writer     *bufio.Writer
	timeouts   Timeouts
}

// run performs greeting, capability negotiation, envelope, and data transfer.
func (s *session) run(ehloName string, message Message) error {
	if err := s.expect(s.timeouts.Command, greetingCode); err != nil {
		return err
	}
	extensions, err := s.hello(ehloName)
	if err != nil {
		return err
	}
	if message.SMTPUTF8Required {
		if _, present := extensions[extensionSMTPUTF8]; !present {
			return &Error{Outcome: OutcomeSMTPUTF8Unavailable}
		}
	}
	if message.EightBitMIMERequired {
		if _, present := extensions[extension8BITMIME]; !present {
			return &Error{Outcome: OutcomeFailed}
		}
	}
	if err := s.checkAdvertisedSize(extensions, len(message.Bytes)); err != nil {
		return err
	}
	if err := s.command(
		s.timeouts.Command, completionCode, mailCommand(message),
	); err != nil {
		return err
	}
	if err := s.command(
		s.timeouts.Command, completionCode, "RCPT TO:"+message.ForwardPath,
	); err != nil {
		return err
	}
	if err := s.command(s.timeouts.Command, dataIntermediateCode, "DATA"); err != nil {
		return err
	}
	if err := s.transfer(message.Bytes); err != nil {
		return err
	}
	if err := s.expect(s.timeouts.Data, completionCode); err != nil {
		return err
	}
	s.quit()
	return nil
}

// mailCommand renders the null-sender MAIL command with required parameters.
func mailCommand(message Message) string {
	command := "MAIL FROM:" + nullReversePath
	if message.EightBitMIMERequired {
		command += " BODY=8BITMIME"
	}
	if message.SMTPUTF8Required {
		command += " " + extensionSMTPUTF8
	}
	return command
}

// hello sends EHLO and collects the advertised extension keywords.
func (s *session) hello(ehloName string) (map[string]string, error) {
	if err := s.write(s.timeouts.Command, "EHLO "+ehloName+crlf); err != nil {
		return nil, err
	}
	code, lines, err := s.readReply(s.timeouts.Command)
	if err != nil {
		return nil, err
	}
	if code != completionCode {
		return nil, classifyReply(code)
	}
	extensions := make(map[string]string, len(lines))
	for index, line := range lines {
		if index == 0 {
			continue
		}
		keyword, parameter, _ := strings.Cut(line, " ")
		keyword = strings.ToUpper(strings.TrimSpace(keyword))
		if keyword == "" || len(extensions) >= maxExtensionEntries {
			continue
		}
		extensions[keyword] = strings.TrimSpace(parameter)
	}
	return extensions, nil
}

// checkAdvertisedSize refuses a transfer the listener already declared too large.
func (s *session) checkAdvertisedSize(extensions map[string]string, size int) error {
	parameter, present := extensions[extensionSIZE]
	if !present || parameter == "" {
		return nil
	}
	limit, err := strconv.ParseInt(parameter, 10, 64)
	if err != nil || limit <= 0 {
		return nil
	}
	if int64(size) > limit {
		return &Error{Outcome: OutcomeFailed}
	}
	return nil
}

// command writes one command line and requires one exact reply code.
func (s *session) command(bound time.Duration, expected int, line string) error {
	if err := s.write(bound, line+crlf); err != nil {
		return err
	}
	return s.expect(bound, expected)
}

// transfer writes the dot-stuffed message and its terminating sequence.
//
// A message that already ends with CRLF is terminated by the bare dot line
// alone, so the transfer never appends an empty line to the signed content.
func (s *session) transfer(message []byte) error {
	if err := s.connection.SetWriteDeadline(time.Now().Add(s.timeouts.Data)); err != nil {
		return &Error{Outcome: OutcomeFailed}
	}
	endsWithCRLF := bytes.HasSuffix(message, []byte(crlf))
	for len(message) > 0 {
		line := message
		if index := bytes.Index(message, []byte(crlf)); index >= 0 {
			line = message[:index+2]
			message = message[index+2:]
		} else {
			message = nil
		}
		if len(line) > 0 && line[0] == '.' {
			if _, err := s.writer.WriteString("."); err != nil {
				return &Error{Outcome: OutcomeFailed}
			}
		}
		if _, err := s.writer.Write(line); err != nil {
			return &Error{Outcome: OutcomeFailed}
		}
	}
	terminator := "." + crlf
	if !endsWithCRLF {
		terminator = crlf + terminator
	}
	if _, err := s.writer.WriteString(terminator); err != nil {
		return &Error{Outcome: OutcomeFailed}
	}
	if err := s.writer.Flush(); err != nil {
		return &Error{Outcome: OutcomeFailed}
	}
	return nil
}

// quit closes the session politely without changing an already final outcome.
func (s *session) quit() {
	_ = s.write(s.timeouts.Command, "QUIT"+crlf)
	_, _, _ = s.readReply(s.timeouts.Command)
}

// write emits one bounded command within its deadline.
func (s *session) write(bound time.Duration, line string) error {
	if err := s.connection.SetWriteDeadline(time.Now().Add(bound)); err != nil {
		return &Error{Outcome: OutcomeFailed}
	}
	if _, err := s.writer.WriteString(line); err != nil {
		return &Error{Outcome: OutcomeFailed}
	}
	if err := s.writer.Flush(); err != nil {
		return &Error{Outcome: OutcomeFailed}
	}
	return nil
}

// expect reads one reply and requires the exact expected code.
func (s *session) expect(bound time.Duration, expected int) error {
	code, _, err := s.readReply(bound)
	if err != nil {
		return err
	}
	if code != expected {
		return classifyReply(code)
	}
	return nil
}

// readReply parses one bounded multiline SMTP reply.
func (s *session) readReply(bound time.Duration) (int, []string, error) {
	if err := s.connection.SetReadDeadline(time.Now().Add(bound)); err != nil {
		return 0, nil, &Error{Outcome: OutcomeFailed}
	}
	var code int
	lines := make([]string, 0, 8)
	for count := 0; count < maxReplyLines; count++ {
		line, err := s.reader.ReadString('\n')
		if err != nil || len(line) > maxReplyLineBytes ||
			!strings.HasSuffix(line, crlf) {
			return 0, nil, &Error{Outcome: OutcomeFailed}
		}
		line = strings.TrimSuffix(line, crlf)
		if len(line) < 3 {
			return 0, nil, &Error{Outcome: OutcomeFailed}
		}
		current, err := strconv.Atoi(line[:3])
		if err != nil || current < 200 || current > 599 {
			return 0, nil, &Error{Outcome: OutcomeFailed}
		}
		if count == 0 {
			code = current
		} else if current != code {
			return 0, nil, &Error{Outcome: OutcomeFailed}
		}
		if len(line) == 3 {
			lines = append(lines, "")
			return code, lines, nil
		}
		lines = append(lines, line[4:])
		switch line[3] {
		case ' ':
			return code, lines, nil
		case '-':
			continue
		default:
			return 0, nil, &Error{Outcome: OutcomeFailed}
		}
	}
	return 0, nil, &Error{Outcome: OutcomeFailed}
}

// classifyReply maps one unexpected reply code to its closed outcome.
func classifyReply(code int) error {
	if code >= 400 && code < 500 {
		return &Error{Outcome: OutcomeDeferred}
	}
	return &Error{Outcome: OutcomeFailed}
}

// validForwardPath accepts one bounded angle-addressed non-null forward path.
func validForwardPath(value string) bool {
	if len(value) < 3 || len(value) > 256 ||
		value[0] != '<' || value[len(value)-1] != '>' {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] == 0x7f {
			return false
		}
	}
	return !strings.ContainsAny(value[1:len(value)-1], "<>")
}
