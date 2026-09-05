package lmtp

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// testGreetingName is the bounded greeting name used by every scripted test.
const testGreetingName = "mta.example"

// scriptedStream feeds one fixed peer script and records every reply.
type scriptedStream struct {
	input  *bytes.Reader
	output bytes.Buffer
}

// Read serves the remaining scripted peer bytes.
func (s *scriptedStream) Read(buffer []byte) (int, error) { return s.input.Read(buffer) }

// Write records one reply without bounding the test transcript.
func (s *scriptedStream) Write(buffer []byte) (int, error) { return s.output.Write(buffer) }

// recordingHandler captures deliveries and answers a fixed reply.
type recordingHandler struct {
	reply      Reply
	deliveries []Delivery
}

// Handle records one delivery and returns the configured fixed answer.
func (h *recordingHandler) Handle(_ context.Context, delivery Delivery) Reply {
	copied := append([]byte(nil), delivery.Bytes...)
	h.deliveries = append(h.deliveries, Delivery{
		ForwardPath: delivery.ForwardPath,
		SMTPUTF8:    delivery.SMTPUTF8,
		Bytes:       copied,
	})
	return h.reply
}

// runScript drives one complete session against a scripted peer.
func runScript(t *testing.T, script string, handler Handler, limits Limits) string {
	t.Helper()
	stream := &scriptedStream{input: bytes.NewReader([]byte(script))}
	session, err := newSession(stream, limits, handler)
	if err != nil {
		t.Fatalf("session construction failed")
	}
	if err := session.Serve(context.Background()); err != nil && err != io.EOF {
		t.Fatalf("serve failed")
	}
	return stream.output.String()
}

// testLimits returns the bounded session policy used by every scripted test.
func testLimits() Limits {
	return Limits{MessageBytes: 65_536, GreetingName: testGreetingName}
}

// TestGreetingAndLHLOAdvertisement freezes the mandatory extension set.
func TestGreetingAndLHLOAdvertisement(t *testing.T) {
	handler := &recordingHandler{reply: ReplyAccepted}
	transcript := runScript(t, "LHLO client.example\r\nQUIT\r\n", handler, testLimits())
	for _, expected := range []string{
		"220 mta.example LMTP ready\r\n",
		"250-mta.example\r\n",
		"250-PIPELINING\r\n",
		"250-ENHANCEDSTATUSCODES\r\n",
		"250-SIZE 65536\r\n",
		"250-8BITMIME\r\n",
		"250 SMTPUTF8\r\n",
		"221 2.0.0 closing\r\n",
	} {
		if !strings.Contains(transcript, expected) {
			t.Fatalf("missing %q in transcript %q", expected, transcript)
		}
	}
	for _, forbidden := range []string{"CHUNKING", "STARTTLS", "AUTH", "DSN", "XCLIENT", "XFORWARD"} {
		if strings.Contains(transcript, forbidden) {
			t.Fatalf("advertised forbidden extension %q", forbidden)
		}
	}
}

// TestSMTPGreetingsRefused proves this endpoint is not an SMTP server.
func TestSMTPGreetingsRefused(t *testing.T) {
	handler := &recordingHandler{reply: ReplyAccepted}
	transcript := runScript(t, "HELO x\r\nEHLO x\r\nQUIT\r\n", handler, testLimits())
	if strings.Count(transcript, "500 5.5.1 command not implemented\r\n") != 2 {
		t.Fatalf("HELO/EHLO were not refused: %q", transcript)
	}
}

// TestPipelinedTransactionDeliversOnce proves one reply for one recipient.
func TestPipelinedTransactionDeliversOnce(t *testing.T) {
	handler := &recordingHandler{reply: ReplyAccepted}
	script := "LHLO client.example\r\n" +
		"MAIL FROM:<> SMTPUTF8\r\n" +
		"RCPT TO:<bounce+abc@local.example>\r\n" +
		"DATA\r\n" +
		"Subject: report\r\n" +
		"\r\n" +
		"..leading dot\r\n" +
		".\r\n" +
		"QUIT\r\n"
	transcript := runScript(t, script, handler, testLimits())
	if len(handler.deliveries) != 1 {
		t.Fatalf("expected exactly one delivery, got %d", len(handler.deliveries))
	}
	delivery := handler.deliveries[0]
	if delivery.ForwardPath != "<bounce+abc@local.example>" || !delivery.SMTPUTF8 {
		t.Fatalf("envelope not preserved: %q utf8=%t", delivery.ForwardPath, delivery.SMTPUTF8)
	}
	expected := "Subject: report\r\n\r\n.leading dot\r\n"
	if string(delivery.Bytes) != expected {
		t.Fatalf("dot-unstuffing or CRLF discipline broken: %q", string(delivery.Bytes))
	}
	if strings.Count(transcript, "250 2.0.0 accepted\r\n") != 1 {
		t.Fatalf("expected exactly one final reply: %q", transcript)
	}
}

// TestNonNullSenderRefused proves the reserved address class is enforced.
func TestNonNullSenderRefused(t *testing.T) {
	handler := &recordingHandler{reply: ReplyAccepted}
	transcript := runScript(
		t,
		"LHLO c\r\nMAIL FROM:<sender@example.com>\r\nQUIT\r\n",
		handler,
		testLimits(),
	)
	if !strings.Contains(transcript, "550 5.7.1 reserved for delivery-status notifications\r\n") {
		t.Fatalf("non-null sender admitted: %q", transcript)
	}
	if len(handler.deliveries) != 0 {
		t.Fatal("non-null sender reached the handler")
	}
}

// TestSecondRecipientDeferred proves one DSN per daemon request.
func TestSecondRecipientDeferred(t *testing.T) {
	handler := &recordingHandler{reply: ReplyAccepted}
	script := "LHLO c\r\nMAIL FROM:<>\r\n" +
		"RCPT TO:<a@local.example>\r\nRCPT TO:<b@local.example>\r\n" +
		"DATA\r\nx\r\n.\r\nQUIT\r\n"
	transcript := runScript(t, script, handler, testLimits())
	if !strings.Contains(transcript, "452 4.5.3 too many recipients\r\n") {
		t.Fatalf("second recipient admitted: %q", transcript)
	}
	if len(handler.deliveries) != 1 ||
		handler.deliveries[0].ForwardPath != "<a@local.example>" {
		t.Fatalf("wrong recipient reached the handler")
	}
	if strings.Count(transcript, "250 2.0.0 accepted\r\n") != 1 {
		t.Fatalf("more than one final reply: %q", transcript)
	}
}

// TestUnadvertisedCommandsAndParameters proves the closed command surface.
func TestUnadvertisedCommandsAndParameters(t *testing.T) {
	handler := &recordingHandler{reply: ReplyAccepted}
	script := "LHLO c\r\nBDAT 10\r\nSTARTTLS\r\nAUTH PLAIN\r\nXCLIENT NAME=x\r\n" +
		"MAIL FROM:<> NOTIFY=NEVER\r\nQUIT\r\n"
	transcript := runScript(t, script, handler, testLimits())
	if strings.Count(transcript, "502 5.5.1 command not implemented\r\n") != 4 {
		t.Fatalf("unadvertised commands were not refused: %q", transcript)
	}
	if !strings.Contains(transcript, "555 5.5.4 parameter not recognized\r\n") {
		t.Fatalf("unadvertised parameter admitted: %q", transcript)
	}
}

// TestBadSequenceAndReset proves ordering and transaction reset behavior.
func TestBadSequenceAndReset(t *testing.T) {
	handler := &recordingHandler{reply: ReplyAccepted}
	script := "MAIL FROM:<>\r\nLHLO c\r\nDATA\r\nMAIL FROM:<>\r\n" +
		"RCPT TO:<a@local.example>\r\nRSET\r\nDATA\r\nQUIT\r\n"
	transcript := runScript(t, script, handler, testLimits())
	if strings.Count(transcript, "503 5.5.1 bad sequence of commands\r\n") != 3 {
		t.Fatalf("sequence rules not enforced: %q", transcript)
	}
	if !strings.Contains(transcript, "250 2.0.0 ok\r\n") {
		t.Fatalf("RSET was not accepted: %q", transcript)
	}
	if len(handler.deliveries) != 0 {
		t.Fatal("a reset transaction reached the handler")
	}
}

// TestOversizedDataRefusedAndConnectionSurvives proves the SIZE bound.
func TestOversizedDataRefusedAndConnectionSurvives(t *testing.T) {
	handler := &recordingHandler{reply: ReplyAccepted}
	limits := Limits{MessageBytes: 1024, GreetingName: testGreetingName}
	body := strings.Repeat("0123456789\r\n", 200)
	script := "LHLO c\r\nMAIL FROM:<>\r\nRCPT TO:<a@local.example>\r\nDATA\r\n" +
		body + ".\r\nNOOP\r\nQUIT\r\n"
	transcript := runScript(t, script, handler, limits)
	if !strings.Contains(transcript, "552 5.3.4 message exceeds size limit\r\n") {
		t.Fatalf("oversized message admitted: %q", transcript)
	}
	if len(handler.deliveries) != 0 {
		t.Fatal("oversized message reached the handler")
	}
	if !strings.Contains(transcript, "221 2.0.0 closing\r\n") {
		t.Fatalf("connection did not survive the oversized transfer: %q", transcript)
	}
}

// TestDeclaredSizeParameterRefused proves the advertised SIZE is enforced early.
func TestDeclaredSizeParameterRefused(t *testing.T) {
	handler := &recordingHandler{reply: ReplyAccepted}
	limits := Limits{MessageBytes: 2048, GreetingName: testGreetingName}
	transcript := runScript(
		t, "LHLO c\r\nMAIL FROM:<> SIZE=99999\r\nQUIT\r\n", handler, limits,
	)
	if !strings.Contains(transcript, "552 5.3.4 message exceeds size limit\r\n") {
		t.Fatalf("declared oversize admitted: %q", transcript)
	}
}

// TestHostilePeerLines proves bare LF and overlong lines fail closed.
func TestHostilePeerLines(t *testing.T) {
	handler := &recordingHandler{reply: ReplyAccepted}
	transcript := runScript(t, "LHLO c\nQUIT\r\n", handler, testLimits())
	if !strings.Contains(transcript, "500 5.5.2 syntax error\r\n") {
		t.Fatalf("bare LF admitted: %q", transcript)
	}
	long := "LHLO " + strings.Repeat("a", 2048) + "\r\n"
	transcript = runScript(t, long+"QUIT\r\n", handler, testLimits())
	if !strings.Contains(transcript, "500 5.5.2 syntax error\r\n") {
		t.Fatalf("overlong command line admitted: %q", transcript)
	}
}

// TestHandlerReplyMapping freezes the wire text of every closed answer.
func TestHandlerReplyMapping(t *testing.T) {
	cases := map[Reply]string{
		ReplyAccepted:          "250 2.0.0 accepted\r\n",
		ReplyRejected:          "550 5.7.1 propagation refused\r\n",
		ReplyDeferredTransport: "451 4.4.1 propagation deferred\r\n",
		ReplyDeferredPolicy:    "451 4.7.1 propagation deferred\r\n",
	}
	for reply, expected := range cases {
		handler := &recordingHandler{reply: reply}
		script := "LHLO c\r\nMAIL FROM:<>\r\nRCPT TO:<a@local.example>\r\nDATA\r\nx\r\n.\r\nQUIT\r\n"
		transcript := runScript(t, script, handler, testLimits())
		if !strings.Contains(transcript, expected) {
			t.Fatalf("reply %d rendered %q", reply, transcript)
		}
	}
}

// TestPanickingHandlerDefers proves a defective handler never acknowledges.
func TestPanickingHandlerDefers(t *testing.T) {
	script := "LHLO c\r\nMAIL FROM:<>\r\nRCPT TO:<a@local.example>\r\nDATA\r\nx\r\n.\r\nQUIT\r\n"
	transcript := runScript(t, script, panicHandler{}, testLimits())
	if !strings.Contains(transcript, "451 4.7.1 propagation deferred\r\n") {
		t.Fatalf("panicking handler did not defer: %q", transcript)
	}
}

// panicHandler models a defective propagation handler.
type panicHandler struct{}

// Handle always panics to prove the receiver's containment boundary.
func (panicHandler) Handle(context.Context, Delivery) Reply { panic("handler defect") }

// TestDeliveryRedaction proves the delivery never renders its content.
func TestDeliveryRedaction(t *testing.T) {
	delivery := Delivery{ForwardPath: "<victim@example.com>", Bytes: []byte("secret")}
	rendered := delivery.String() + delivery.GoString()
	if strings.Contains(rendered, "victim") || strings.Contains(rendered, "secret") {
		t.Fatalf("delivery leaked content: %q", rendered)
	}
	if _, err := delivery.MarshalJSON(); err == nil {
		t.Fatal("delivery serialization was permitted")
	}
}

// TestInvalidLimitsRefused proves an unbounded session cannot be constructed.
func TestInvalidLimitsRefused(t *testing.T) {
	stream := &scriptedStream{input: bytes.NewReader(nil)}
	handler := &recordingHandler{reply: ReplyAccepted}
	for _, limits := range []Limits{
		{MessageBytes: 0, GreetingName: testGreetingName},
		{MessageBytes: 65_536, GreetingName: ""},
		{MessageBytes: 65_536, GreetingName: strings.Repeat("a", 254)},
	} {
		if _, err := newSession(stream, limits, handler); !IsError(err) {
			t.Fatal("unbounded session policy accepted")
		}
	}
	if _, err := newSession(stream, testLimits(), nil); !IsError(err) {
		t.Fatal("session without handler accepted")
	}
}
