package reinject

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testDataPhase     = "DATA"
	testDataEndPhase  = "DATA-END"
	testDeferredReply = "451 later"
	testEightBitMIME  = "8BITMIME"
)

// fakeListener answers a scripted SMTP conversation over an in-memory pipe.
type fakeListener struct {
	mu         sync.Mutex
	transcript []string
	data       []byte
	extensions []string
	replies    map[string]string
	closeAt    string
}

// newFakeListener constructs one listener advertising the given extensions.
func newFakeListener(extensions []string) *fakeListener {
	return &fakeListener{extensions: extensions, replies: map[string]string{}}
}

// dial returns the client side of one in-memory session.
func (l *fakeListener) dial(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	go l.serve(server)
	return client, nil
}

// serve answers the scripted conversation and records every received command.
func (l *fakeListener) serve(connection net.Conn) {
	defer func() { _ = connection.Close() }()
	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = writer.WriteString("220 listener ready\r\n")
	_ = writer.Flush()
	inData := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSuffix(line, "\r\n")
		if inData {
			if line != "." {
				l.appendData(strings.TrimPrefix(line, "."))
				continue
			}
			inData = false
			if !l.answer(writer, testDataEndPhase) {
				return
			}
			continue
		}
		verb, _, _ := strings.Cut(line, " ")
		verb = strings.ToUpper(verb)
		l.record(line)
		switch verb {
		case "EHLO":
			if l.closeAt == "EHLO" {
				return
			}
			_, _ = writer.WriteString("250-listener\r\n")
			for index, extension := range l.extensions {
				separator := "-"
				if index == len(l.extensions)-1 {
					separator = " "
				}
				_, _ = writer.WriteString("250" + separator + extension + "\r\n")
			}
			if len(l.extensions) == 0 {
				_, _ = writer.WriteString("250 HELP\r\n")
			}
			_ = writer.Flush()
		case testDataPhase:
			if !l.answer(writer, testDataPhase) {
				return
			}
			inData = true
		case "QUIT":
			_, _ = writer.WriteString("221 bye\r\n")
			_ = writer.Flush()
			return
		default:
			if !l.answer(writer, verb) {
				return
			}
		}
	}
}

// answer emits the configured reply and reports whether the session continues.
func (l *fakeListener) answer(writer *bufio.Writer, phase string) bool {
	if l.closeAt == phase {
		return false
	}
	reply, present := l.replies[phase]
	if !present {
		switch phase {
		case testDataPhase:
			reply = "354 send it"
		default:
			reply = "250 ok"
		}
	}
	_, _ = writer.WriteString(reply + "\r\n")
	_ = writer.Flush()
	return true
}

// appendData records one unstuffed received data line.
func (l *fakeListener) appendData(line string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.data = append(l.data, line...)
	l.data = append(l.data, "\r\n"...)
}

// received returns the reassembled unstuffed message.
func (l *fakeListener) received() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return string(l.data)
}

// record appends one received command line to the transcript.
func (l *fakeListener) record(line string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.transcript = append(l.transcript, line)
}

// commands returns the recorded command transcript.
func (l *fakeListener) commands() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.transcript...)
}

// testTimeouts returns the bounded session policy used by every test.
func testTimeouts() Timeouts {
	return Timeouts{Connect: time.Second, Command: 2 * time.Second, Data: 2 * time.Second}
}

// testMessage returns one bounded re-injection request.
func testMessage() Message {
	return Message{
		ForwardPath: "<previous@hop.example>",
		Bytes:       []byte("Subject: notice\r\n\r\n.stuffed\r\n"),
	}
}

// TestSuccessfulReinjection proves the exact null-sender envelope and stuffing.
func TestSuccessfulReinjection(t *testing.T) {
	listener := newFakeListener([]string{"PIPELINING", testEightBitMIME, extensionSMTPUTF8})
	client, err := newClient(
		"smtp://127.0.0.1:10025", "mta.example", testTimeouts(), listener.dial,
	)
	if err != nil {
		t.Fatal("client construction failed")
	}
	if err := client.Send(context.Background(), testMessage()); err != nil {
		t.Fatalf("send failed: %v", err)
	}
	commands := listener.commands()
	if listener.received() != string(testMessage().Bytes) {
		t.Fatalf("transferred bytes differ: %q", listener.received())
	}
	if len(commands) < 4 || commands[0] != "EHLO mta.example" ||
		commands[1] != "MAIL FROM:<>" ||
		commands[2] != "RCPT TO:<previous@hop.example>" ||
		commands[3] != testDataPhase {
		t.Fatalf("unexpected transcript %v", commands)
	}
}

// TestSMTPUTF8Required proves the fail-closed capability requirement.
func TestSMTPUTF8Required(t *testing.T) {
	listener := newFakeListener([]string{"PIPELINING"})
	client, err := newClient(
		"smtp://127.0.0.1:10025", "mta.example", testTimeouts(), listener.dial,
	)
	if err != nil {
		t.Fatal("client construction failed")
	}
	message := testMessage()
	message.SMTPUTF8Required = true
	err = client.Send(context.Background(), message)
	if OutcomeOf(err) != OutcomeSMTPUTF8Unavailable {
		t.Fatalf("expected smtputf8_unavailable, got %q", OutcomeOf(err))
	}
	for _, command := range listener.commands() {
		if strings.HasPrefix(command, "MAIL") {
			t.Fatal("delivery was attempted without SMTPUTF8")
		}
	}
}

// TestSMTPUTF8Advertised proves the parameter is sent when required.
func TestSMTPUTF8Advertised(t *testing.T) {
	listener := newFakeListener([]string{extensionSMTPUTF8, testEightBitMIME})
	client, err := newClient(
		"smtp://127.0.0.1:10025", "mta.example", testTimeouts(), listener.dial,
	)
	if err != nil {
		t.Fatal("client construction failed")
	}
	message := testMessage()
	message.SMTPUTF8Required = true
	message.EightBitMIMERequired = true
	if err := client.Send(context.Background(), message); err != nil {
		t.Fatalf("send failed: %v", err)
	}
	commands := listener.commands()
	if len(commands) < 2 || commands[1] != "MAIL FROM:<> BODY=8BITMIME SMTPUTF8" {
		t.Fatalf("unexpected MAIL command %v", commands)
	}
}

// TestEightBitMIMERequired proves a listener without 8BITMIME fails closed.
func TestEightBitMIMERequired(t *testing.T) {
	listener := newFakeListener([]string{extensionSMTPUTF8})
	client, err := newClient(
		"smtp://127.0.0.1:10025", "mta.example", testTimeouts(), listener.dial,
	)
	if err != nil {
		t.Fatal("client construction failed")
	}
	message := testMessage()
	message.EightBitMIMERequired = true
	if OutcomeOf(client.Send(context.Background(), message)) != OutcomeFailed {
		t.Fatal("missing 8BITMIME did not fail closed")
	}
}

// TestRefusedAndDeferredReplies proves the closed outcome classification.
func TestRefusedAndDeferredReplies(t *testing.T) {
	cases := map[string]struct {
		phase   string
		reply   string
		outcome Outcome
	}{
		"permanent mail refusal":   {"MAIL", "550 no", OutcomeFailed},
		"temporary mail refusal":   {"MAIL", testDeferredReply, OutcomeDeferred},
		"permanent rcpt refusal":   {"RCPT", "550 no", OutcomeFailed},
		"temporary rcpt refusal":   {"RCPT", "452 later", OutcomeDeferred},
		"data refused":             {testDataPhase, testDeferredReply, OutcomeDeferred},
		"final dot refused":        {testDataEndPhase, testDeferredReply, OutcomeDeferred},
		"final dot permanently no": {testDataEndPhase, "554 no", OutcomeFailed},
	}
	for name, testCase := range cases {
		listener := newFakeListener([]string{testEightBitMIME})
		listener.replies[testCase.phase] = testCase.reply
		client, err := newClient(
			"smtp://127.0.0.1:10025", "mta.example", testTimeouts(), listener.dial,
		)
		if err != nil {
			t.Fatalf("%s: client construction failed", name)
		}
		err = client.Send(context.Background(), testMessage())
		if err == nil {
			t.Fatalf("%s: refusal reported success", name)
		}
		if OutcomeOf(err) != testCase.outcome {
			t.Fatalf("%s: got %q want %q", name, OutcomeOf(err), testCase.outcome)
		}
	}
}

// TestMidTransferFailure proves a truncated session never reports success.
func TestMidTransferFailure(t *testing.T) {
	listener := newFakeListener([]string{testEightBitMIME})
	listener.closeAt = testDataEndPhase
	client, err := newClient(
		"smtp://127.0.0.1:10025", "mta.example", testTimeouts(), listener.dial,
	)
	if err != nil {
		t.Fatal("client construction failed")
	}
	if err := client.Send(context.Background(), testMessage()); err == nil {
		t.Fatal("a closed session reported success")
	}
}

// TestDialFailure proves a refused listener is a failure, not a success.
func TestDialFailure(t *testing.T) {
	client, err := newClient(
		"smtp://127.0.0.1:10025", "mta.example", testTimeouts(),
		func(context.Context, string, string) (net.Conn, error) {
			return nil, net.ErrClosed
		},
	)
	if err != nil {
		t.Fatal("client construction failed")
	}
	if OutcomeOf(client.Send(context.Background(), testMessage())) != OutcomeFailed {
		t.Fatal("a refused dial was not a failure")
	}
}

// TestAdvertisedSizeRefusal proves a declared listener limit is honored.
func TestAdvertisedSizeRefusal(t *testing.T) {
	listener := newFakeListener([]string{"SIZE 4"})
	client, err := newClient(
		"smtp://127.0.0.1:10025", "mta.example", testTimeouts(), listener.dial,
	)
	if err != nil {
		t.Fatal("client construction failed")
	}
	if OutcomeOf(client.Send(context.Background(), testMessage())) != OutcomeFailed {
		t.Fatal("an oversized transfer was attempted")
	}
}

// TestEndpointConfinement proves only literal loopback SMTP origins are used.
func TestEndpointConfinement(t *testing.T) {
	listener := newFakeListener(nil)
	for _, origin := range []string{
		"smtp://mail.example:25", "http://127.0.0.1:10025",
		"smtp://127.0.0.1:10025/relay", "smtp://user@127.0.0.1:10025",
		"smtps://127.0.0.1:465",
	} {
		if _, err := newClient(
			origin, "mta.example", testTimeouts(), listener.dial,
		); err == nil {
			t.Fatalf("endpoint %q was admitted", origin)
		}
	}
}

// TestInvalidRequestsRefused proves the client never invents an envelope.
func TestInvalidRequestsRefused(t *testing.T) {
	listener := newFakeListener([]string{testEightBitMIME})
	client, err := newClient(
		"smtp://127.0.0.1:10025", "mta.example", testTimeouts(), listener.dial,
	)
	if err != nil {
		t.Fatal("client construction failed")
	}
	invalid := []Message{
		{ForwardPath: "<a@b.example>"},
		{ForwardPath: "", Bytes: []byte("x")},
		{ForwardPath: "<>", Bytes: []byte("x")},
		{ForwardPath: "a@b.example", Bytes: []byte("x")},
	}
	for _, message := range invalid {
		if err := client.Send(context.Background(), message); err == nil {
			t.Fatal("an invalid re-injection request was attempted")
		}
	}
	if len(listener.commands()) != 0 {
		t.Fatal("an invalid request reached the listener")
	}
}

// TestClientRedaction proves the client never renders its endpoint.
func TestClientRedaction(t *testing.T) {
	client, err := newClient(
		"smtp://127.0.0.1:10025", "mta.example", testTimeouts(),
		newFakeListener(nil).dial,
	)
	if err != nil {
		t.Fatal("client construction failed")
	}
	rendered := client.String() + client.GoString()
	if strings.Contains(rendered, "127.0.0.1") || strings.Contains(rendered, "mta.example") {
		t.Fatalf("client leaked endpoint state: %q", rendered)
	}
	if _, err := client.MarshalJSON(); err == nil {
		t.Fatal("client serialization was permitted")
	}
}
