package milter

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

const (
	testAdmissionBytes = 64 << 20
	testSenderPath     = "<sender@example.test>"
)

type testHandler struct {
	message Message
	result  Result
	err     error
	calls   int
}

type retainingHandler struct{ message Message }

// Handle deliberately retains the synchronous snapshot for zeroization evidence.
func (h *retainingHandler) Handle(_ context.Context, message Message) (Result, error) {
	h.message = message
	return Result{
		Operation: operationProcess, Result: resultPass, Outcome: DispositionContinue,
	}, nil
}

// Handle captures one immutable EOM message for independent-oracle tests.
func (h *testHandler) Handle(_ context.Context, message Message) (Result, error) {
	h.calls++
	snapshot, copyErr := NewMessage(message.Raw(), message.ReversePath(), message.Recipients())
	if copyErr != nil {
		return Result{}, copyErr
	}
	h.message = snapshot
	return h.result, h.err
}

type splitStream struct {
	reader *bytes.Reader
	writer bytes.Buffer
}

// Read consumes only prebuilt peer input.
func (s *splitStream) Read(output []byte) (int, error) { return s.reader.Read(output) }

// Write captures only adapter output.
func (s *splitStream) Write(input []byte) (int, error) { return s.writer.Write(input) }

// TestSessionReconstructsExactCallbackBytes proves the independent EOM oracle.
func TestSessionReconstructsExactCallbackBytes(t *testing.T) {
	handler := &testHandler{result: Result{
		Operation: operationProcess, Result: resultPass, Outcome: DispositionContinue,
	}}
	session := testSession(t, handler, false, modeInbound, "")
	body := []byte{'b', 0, 'o', 'd', 'y', '\r', '\n'}
	input := appendPeerFrames(
		peerFrame(commandNegotiate, negotiationPayload()),
		peerFrame(commandConnect, []byte("mx\x00U")),
		peerFrame(commandHelo, []byte("helo.example\x00")),
		peerFrame(commandMail, []byte("<from@example>\x00SIZE=1\x00")),
		peerFrame(commandRecipient, []byte("<to@example>\x00")),
		peerFrame(commandRecipient, []byte("<to@example>\x00")),
		peerFrame(commandHeader, []byte("X-Duplicate\x00 one\x00")),
		peerFrame(commandHeader, []byte("x-duplicate\x00\ttwo\n more\x00")),
		peerFrame(commandEOH, nil),
		peerFrame(commandBody, body),
		peerFrame(commandEOM, nil),
		peerFrame(commandQuit, nil),
	)
	stream := &splitStream{reader: bytes.NewReader(input)}
	if err := session.Serve(context.Background(), stream); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if handler.calls != 1 {
		t.Fatalf("Handle() calls = %d, want 1", handler.calls)
	}
	want := append(
		[]byte("X-Duplicate: one\r\nx-duplicate:\ttwo\r\n more\r\n\r\n"),
		body...,
	)
	if got := handler.message.Raw(); !bytes.Equal(got, want) {
		t.Fatalf("Raw() = %q, want exact %q", got, want)
	}
	recipients := handler.message.Recipients()
	if len(recipients) != 2 || !bytes.Equal(recipients[0], recipients[1]) {
		t.Fatal("duplicate recipients were not retained in callback order")
	}
}

// TestSessionAllowsEmptyHeaderAndBodySequence freezes the header-star grammar.
func TestSessionAllowsEmptyHeaderAndBodySequence(t *testing.T) {
	handler := &testHandler{result: Result{
		Operation: operationProcess, Result: resultPass, Outcome: DispositionContinue,
	}}
	session := testSession(t, handler, false, modeInbound, "")
	input := appendPeerFrames(
		peerFrame(commandNegotiate, negotiationPayload()),
		peerFrame(commandConnect, []byte("mx\x00U")),
		peerFrame(commandHelo, []byte("helo\x00")),
		peerFrame(commandMail, []byte("<>\x00")),
		peerFrame(commandRecipient, []byte("<to@example>\x00")),
		peerFrame(commandEOH, nil),
		peerFrame(commandEOM, nil),
		peerFrame(commandQuit, nil),
	)
	stream := &splitStream{reader: bytes.NewReader(input)}
	if err := session.Serve(context.Background(), stream); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if got := handler.message.Raw(); !bytes.Equal(got, []byte("\r\n")) {
		t.Fatalf("Raw() = %q, want empty header separator", got)
	}
}

// TestHandlerSnapshotBytesAreClearedAfterReturn proves bounded mail-data lifetime.
func TestHandlerSnapshotBytesAreClearedAfterReturn(t *testing.T) {
	handler := &retainingHandler{}
	message, err := NewMessage(
		[]byte("From: marker@example.test\r\n\r\nprivate-body"),
		[]byte("<marker@example.test>"),
		[][]byte{[]byte("<recipient@example.test>")},
	)
	if err != nil {
		t.Fatal("message construction failed")
	}
	if _, err := callHandler(context.Background(), handler, message); err != nil {
		t.Fatal("handler call failed")
	}
	for _, retained := range append(
		[][]byte{handler.message.Raw(), handler.message.ReversePath()},
		handler.message.Recipients()...,
	) {
		if !allZeroBytes(retained) {
			t.Fatal("handler-return snapshot retained mail bytes")
		}
	}
}

// allZeroBytes reports whether best-effort clearing erased every retained byte.
func allZeroBytes(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

// TestOriginatorSMTPUTF8ReachesApplicabilityBoundary proves valid EAI envelope
// evidence is retained for a mutation-free signing applicability decision.
func TestOriginatorSMTPUTF8ReachesApplicabilityBoundary(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		mail      []byte
		recipient []byte
	}{
		{
			name:      "sender local part",
			mail:      append([]byte("<fröm@example.test>\x00SMTPUTF8"), 0),
			recipient: append([]byte("<recipient@example.test>"), 0),
		},
		{
			name:      "sender domain",
			mail:      append([]byte("<sender@exämple.test>\x00SMTPUTF8"), 0),
			recipient: append([]byte("<recipient@example.test>"), 0),
		},
		{
			name:      "recipient",
			mail:      append([]byte("<sender@example.test>\x00SMTPUTF8"), 0),
			recipient: append([]byte("<tö@example.test>"), 0),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			handler := &testHandler{result: Result{
				Operation: operationSign, Result: resultNone, Outcome: DispositionContinue,
			}}
			session := testSession(t, handler, false, modeOriginator, "")
			input := appendPeerFrames(
				peerFrame(commandNegotiate, negotiationPayload()),
				peerFrame(commandConnect, []byte("mx\x00U")),
				peerFrame(commandHelo, []byte("helo\x00")),
				peerFrame(commandMail, testCase.mail),
				peerFrame(commandRecipient, testCase.recipient),
				peerFrame(commandEOH, nil),
				peerFrame(commandEOM, nil),
				peerFrame(commandQuit, nil),
			)
			stream := &splitStream{reader: bytes.NewReader(input)}
			if err := session.Serve(context.Background(), stream); err != nil || handler.calls != 1 {
				t.Fatalf("Serve() error = %v, calls = %d", err, handler.calls)
			}
		})
	}
}

// TestMessageSigningDomainUsesOnlyCanonicalEnvelopeSenderDNS proves exact bounded derivation.
func TestMessageSigningDomainUsesOnlyCanonicalEnvelopeSenderDNS(t *testing.T) {
	const exampleDomain = "example.test"
	tests := []struct {
		name    string
		reverse string
		want    string
		ok      bool
	}{
		{name: "lowercase", reverse: testSenderPath, want: exampleDomain, ok: true},
		{name: "canonicalizes ASCII DNS case", reverse: "<sender@Example.TEST>", want: exampleDomain, ok: true},
		{name: "quoted local part", reverse: "<\"a@b\"@example.test>", want: exampleDomain, ok: true},
		{name: "source route", reverse: "<@relay.test:sender@example.test>", want: exampleDomain, ok: true},
		{name: "null sender", reverse: "<>"},
		{name: "domain literal", reverse: "<sender@[192.0.2.1]>"},
		{name: "SMTPUTF8 local part", reverse: "<séndér@example.test>"},
		{name: "SMTPUTF8 domain", reverse: "<sender@exämple.test>"},
		{name: "unframed", reverse: "sender@example.test"},
		{name: "malformed", reverse: "<sender@example.test"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			message, err := NewMessage(
				[]byte("From: sender@example.test\r\n\r\nbody"),
				[]byte(testCase.reverse),
				[][]byte{[]byte("<recipient@example.test>")},
			)
			if err != nil {
				t.Fatal(err)
			}
			got, ok := message.SigningDomain()
			if got != testCase.want || ok != testCase.ok {
				t.Fatalf("SigningDomain()=(%q,%t), want (%q,%t)", got, ok, testCase.want, testCase.ok)
			}
		})
	}
}

// TestMessageDomainObservationsPreserveOnlyCanonicalOperationalDomains proves
// that operator logging exposes domains without retaining mailbox local parts.
func TestMessageDomainObservationsPreserveOnlyCanonicalOperationalDomains(t *testing.T) {
	message, err := NewMessage(
		[]byte("Subject: test\r\n\r\nbody\r\n"),
		[]byte("<sender@Origin.Example>"),
		[][]byte{
			[]byte("<first@Target.Example>"),
			[]byte("<second@target.example>"),
			[]byte("<third@other.example>"),
		},
	)
	if err != nil {
		t.Fatal("message construction failed")
	}
	observation := message.RecipientDomainObservation()
	if observation.Role() != domainRoleRecipient ||
		observation.Domains() != "target.example,other.example" ||
		observation.Count() != 2 || observation.Truncated() {
		t.Fatalf("recipient domain observation=%#v", observation)
	}
	signing, ok := NewSigningDomainObservation("origin.example")
	if !ok || signing.Role() != domainRoleSigning ||
		signing.Domains() != "origin.example" || signing.Count() != 1 ||
		signing.Truncated() {
		t.Fatalf("signing domain observation=%#v ok=%t", signing, ok)
	}
	if strings.Contains(observation.Domains(), "first") ||
		strings.Contains(observation.Domains(), "second") {
		t.Fatal("mailbox local part escaped domain observation")
	}
}

// TestMessageDomainObservationBoundsLargeRecipientSets proves that logs remain
// bounded while retaining the exact distinct canonical domain count.
func TestMessageDomainObservationBoundsLargeRecipientSets(t *testing.T) {
	recipients := make([][]byte, 0, maxObservedDomains+2)
	for index := range maxObservedDomains + 2 {
		recipients = append(recipients, fmt.Appendf(nil, "<user@d%d.example>", index))
	}
	message, err := NewMessage(
		[]byte("Subject: test\r\n\r\nbody\r\n"),
		[]byte("<sender@origin.example>"),
		recipients,
	)
	if err != nil {
		t.Fatal("message construction failed")
	}
	observation := message.RecipientDomainObservation()
	if observation.Count() != maxObservedDomains+2 || !observation.Truncated() ||
		len(strings.Split(observation.Domains(), ",")) != maxObservedDomains {
		t.Fatalf("bounded domain observation=%#v", observation)
	}
}

// TestFailOpenIsNarrowlyLimited freezes timeout and contract behavior.
func TestFailOpenIsNarrowlyLimited(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		failure    FailureClass
		wantAccept bool
	}{
		{name: "timeout", failure: FailureTimeout, wantAccept: true},
		{name: "unavailable", failure: FailureUnavailable, wantAccept: true},
		{name: "capacity after operation start", failure: FailureCapacity, wantAccept: false},
		{name: "contract", failure: FailureContract, wantAccept: false},
		{name: "fidelity", failure: FailureFidelity, wantAccept: false},
		{name: "indeterminate", failure: FailureIndeterminate, wantAccept: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			handler := &testHandler{err: &Error{Class: testCase.failure}}
			session := testSession(t, handler, true, modeInbound, "")
			if !session.startTransaction(0) {
				t.Fatal("startTransaction() failed")
			}
			session.reverse = []byte("<from@example>")
			session.recipients = [][]byte{[]byte("<to@example>")}
			session.headers = []headerField{{name: []byte("From"), value: []byte(" from@example")}}
			session.headerBytes = int64(len("From: from@example\r\n"))
			frames, err := session.endMessage(context.Background())
			if err != nil {
				t.Fatalf("endMessage() error = %v", err)
			}
			accepted := len(frames) == 1 && len(frames[0]) >= 5 && frames[0][4] == replyAccept
			if accepted != testCase.wantAccept {
				t.Fatalf("endMessage() accepted=%t, want %t", accepted, testCase.wantAccept)
			}
		})
	}
}

// TestFailOpenCannotPreserveForgedLocalAuthenticationResults proves an
// unavailable daemon never admits spoofed local trust assertions unchanged.
func TestFailOpenCannotPreserveForgedLocalAuthenticationResults(t *testing.T) {
	handler := &testHandler{err: &Error{Class: FailureUnavailable}}
	session := testSession(t, handler, true, modeInbound, testAuthservID)
	if !session.startTransaction(0) {
		t.Fatal("startTransaction() failed")
	}
	session.reverse = []byte("<from@example>")
	session.recipients = [][]byte{[]byte("<to@example>")}
	session.headers = []headerField{
		{name: []byte(headerAuthResults), value: []byte(" mx.example; dkim=pass")},
		{name: []byte("From"), value: []byte(" from@example")},
	}
	session.headerBytes = int64(
		len("Authentication-Results: mx.example; dkim=pass\r\n") +
			len("From: from@example\r\n"),
	)
	frames, err := session.endMessage(context.Background())
	if err != nil || len(frames) != 1 || len(frames[0]) < 5 ||
		frames[0][4] != replyCode ||
		!bytes.Contains(frames[0], []byte(fixedTempfailReply)) {
		t.Fatalf("endMessage() frames=%x error=%v", frames, err)
	}
}

// TestTypedHandlerFailureSurvivesConcurrentDeadline proves closed classes are authoritative.
func TestTypedHandlerFailureSurvivesConcurrentDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
	cancel()
	for _, class := range []FailureClass{
		FailureIndeterminate,
		FailureContract,
		FailureFidelity,
		FailureCapacity,
		FailureUnavailable,
		FailureTrust,
		FailureInternal,
	} {
		if got := classifyHandlerError(ctx, &Error{Class: class}); got != class {
			t.Fatalf("classifyHandlerError(%q)=%q, want exact typed class", class, got)
		}
	}
}

type stagedWriter struct {
	writes int
}

// Write completes the first frame and fails before the second.
func (w *stagedWriter) Write(input []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		return len(input), nil
	}
	return 0, io.ErrClosedPipe
}

// TestWriteFramesClassifiesPriorMutationAsIndeterminate freezes no-rollback semantics.
func TestWriteFramesClassifiesPriorMutationAsIndeterminate(t *testing.T) {
	writer := &stagedWriter{}
	err := writeFrames(writer, [][]byte{
		encodeFrame(replyAddHeader, []byte("Name\x00value\x00")),
		encodeFrame(replyAccept, nil),
	})
	if !errors.Is(err, &Error{Class: FailureIndeterminate}) {
		t.Fatalf("writeFrames() error = %v", err)
	}
}

// testSession builds one bounded session for state-machine tests.
func testSession(
	t *testing.T,
	handler Handler,
	failOpen bool,
	mode string,
	authservID string,
) *Session {
	t.Helper()
	admission, err := NewAdmission(2, 2, testAdmissionBytes)
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(handler, admission, Limits{
		MessageBytes: 1 << 16, HeaderBytes: 1 << 15,
		HeaderCount: 100, HeaderFieldBytes: 1024, RecipientCount: 100,
	}, time.Second, FailurePolicy{FailOpen: failOpen}, mode, authservID)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

// negotiationPayload returns the independent peer's required v6 tuple.
func negotiationPayload() []byte {
	output := make([]byte, 12)
	binary.BigEndian.PutUint32(output[:4], 6)
	binary.BigEndian.PutUint32(output[4:8], requiredActions)
	binary.BigEndian.PutUint32(output[8:12], requiredProtocol)
	return output
}

// peerFrame independently serializes one MTA-side frame.
func peerFrame(command byte, payload []byte) []byte {
	output := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(output[:4], uint32(len(payload)+1))
	output[4] = command
	copy(output[5:], payload)
	return output
}

// appendPeerFrames concatenates independent peer frames.
func appendPeerFrames(frames ...[]byte) []byte {
	var output []byte
	for _, frame := range frames {
		output = append(output, frame...)
	}
	return output
}
