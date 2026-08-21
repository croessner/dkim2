package milter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// TestSigningRecipientGroupsFailClosedWithoutPerMessageBccEvidence freezes
// the draft privacy boundary.
func TestSigningRecipientGroupsFailClosedWithoutPerMessageBccEvidence(t *testing.T) {
	for _, mode := range []string{modeOriginator, modeTransit} {
		t.Run(mode+"/default-deny", func(t *testing.T) {
			handler := &testHandler{result: Result{
				Operation: map[string]string{
					modeOriginator: operationSign,
					modeTransit:    operationRevise,
				}[mode],
				Result: resultPass, Outcome: DispositionContinue,
			}}
			session := policySession(t, handler, mode, FailurePolicy{})
			stream := &splitStream{reader: bytes.NewReader(completeTwoRecipientMessage())}
			err := session.Serve(context.Background(), stream)
			if !errors.Is(err, &Error{Class: FailureContract}) || handler.calls != 0 {
				t.Fatalf("group policy=(%v,calls=%d)", err, handler.calls)
			}
		})
		handler := &testHandler{}
		admission, err := NewAdmission(2, 2, testAdmissionBytes)
		if err != nil {
			t.Fatal(err)
		}
		if session, sessionErr := NewSession(
			handler,
			admission,
			Limits{
				MessageBytes: 1 << 16, HeaderBytes: 1 << 15,
				HeaderCount: 100, HeaderFieldBytes: 1024, RecipientCount: 100,
			},
			time.Second,
			FailurePolicy{AllowRecipientGroup: true},
			mode,
			"",
		); sessionErr == nil || session != nil {
			t.Fatal("recipient-group compatibility switch was accepted")
		}
	}
}

// TestInboundRecipientGroupsRemainProtocolEvidence proves signing policy isolation.
func TestInboundRecipientGroupsRemainProtocolEvidence(t *testing.T) {
	handler := &testHandler{result: Result{
		Operation: operationProcess, Result: resultPass, Outcome: DispositionContinue,
	}}
	session := policySession(t, handler, modeInbound, FailurePolicy{})
	stream := &splitStream{reader: bytes.NewReader(completeTwoRecipientMessage())}
	if err := session.Serve(context.Background(), stream); err != nil ||
		handler.calls != 1 || len(handler.message.Recipients()) != 2 {
		t.Fatal("inbound recipient evidence was restricted by signing policy")
	}
}

// TestInboundTestingContinueEmitsDaemonReport proves a successful testing
// verdict remains accepting while preserving its authoritative report action.
func TestInboundTestingContinueEmitsDaemonReport(t *testing.T) {
	handler := &testHandler{result: Result{
		Operation: operationProcess, Result: resultPass, Outcome: DispositionContinue,
		Actions: []Action{{
			Kind: ActionAddHeader, Name: headerAuthResults,
			Value: testAuthservID + "; dkim2=pass",
		}},
	}}
	session := testSession(t, handler, false, modeInbound, testAuthservID)
	stream := &splitStream{reader: bytes.NewReader(completeTwoRecipientMessage())}
	if err := session.Serve(context.Background(), stream); err != nil || handler.calls != 1 {
		t.Fatalf("Serve() error=%v calls=%d", err, handler.calls)
	}
	commands := responseCommands(t, stream.writer.Bytes())
	if len(commands) < 2 || commands[len(commands)-2] != replyInsertHeader ||
		commands[len(commands)-1] != replyAccept {
		t.Fatalf("response commands=%q, want report insertion then accept", commands)
	}
}

// TestInboundTestingContinueWithoutReportingEmitsNoMutation proves the same
// non-terminal result remains mutation-free when no local authority is set.
func TestInboundTestingContinueWithoutReportingEmitsNoMutation(t *testing.T) {
	handler := &testHandler{result: Result{
		Operation: operationProcess, Result: resultPass, Outcome: DispositionContinue,
	}}
	session := policySession(t, handler, modeInbound, FailurePolicy{})
	stream := &splitStream{reader: bytes.NewReader(completeTwoRecipientMessage())}
	if err := session.Serve(context.Background(), stream); err != nil || handler.calls != 1 {
		t.Fatalf("Serve() error=%v calls=%d", err, handler.calls)
	}
	commands := responseCommands(t, stream.writer.Bytes())
	if len(commands) == 0 || commands[len(commands)-1] != replyAccept {
		t.Fatalf("response commands=%q, want accept", commands)
	}
	for _, command := range commands {
		if command == replyAddHeader || command == replyInsertHeader ||
			command == replyChangeHeader {
			t.Fatalf("reporting-disabled continue emitted mutation %q", command)
		}
	}
}

// TestUnsignedInboundEOMContinuesWithoutActions proves the not-applicable action plan.
func TestUnsignedInboundEOMContinuesWithoutActions(t *testing.T) {
	handler := &testHandler{result: Result{
		Operation: operationProcess, Result: resultNone, Outcome: DispositionContinue,
	}}
	session := policySession(t, handler, modeInbound, FailurePolicy{})
	stream := &splitStream{reader: bytes.NewReader(completeTwoRecipientMessage())}
	if err := session.Serve(context.Background(), stream); err != nil || handler.calls != 1 {
		t.Fatalf("Serve() error=%v calls=%d", err, handler.calls)
	}
	commands := responseCommands(t, stream.writer.Bytes())
	if len(commands) == 0 || commands[len(commands)-1] != replyAccept {
		t.Fatalf("response commands=%q", commands)
	}
	for _, command := range commands {
		if command == replyAddHeader || command == replyChangeHeader || command == replyReject || command == replyTempfail {
			t.Fatalf("unsigned EOM emitted terminal or mutation command %q", command)
		}
	}
}

// TestUnsignedInboundEOMRemovesForgedLocalAuthenticationResults proves the
// RFC 8601 trust-boundary scrub remains mandatory when DKIM2 is not applicable.
func TestUnsignedInboundEOMRemovesForgedLocalAuthenticationResults(t *testing.T) {
	handler := &testHandler{result: Result{
		Operation: operationProcess, Result: resultNone, Outcome: DispositionContinue,
	}}
	session := testSession(t, handler, false, modeInbound, testAuthservID)
	input := appendPeerFrames(
		peerFrame(commandNegotiate, negotiationPayload()),
		peerFrame(commandConnect, []byte("mx\x00U")),
		peerFrame(commandHelo, []byte("helo\x00")),
		peerFrame(commandMail, []byte("<a@example.test>\x00")),
		peerFrame(commandRecipient, []byte("<b@example.test>\x00")),
		peerFrame(commandHeader, []byte("Authentication-Results\x00 mx.example; dkim=pass\x00")),
		peerFrame(commandEOH, nil),
		peerFrame(commandEOM, nil),
		peerFrame(commandQuit, nil),
	)
	stream := &splitStream{reader: bytes.NewReader(input)}
	if err := session.Serve(context.Background(), stream); err != nil || handler.calls != 1 {
		t.Fatalf("Serve() error=%v calls=%d", err, handler.calls)
	}
	commands := responseCommands(t, stream.writer.Bytes())
	if len(commands) < 2 || commands[len(commands)-2] != replyChangeHeader ||
		commands[len(commands)-1] != replyAccept {
		t.Fatalf("response commands=%q, want local-header deletion then accept", commands)
	}
}

// TestOriginatorNotApplicableEOMContinuesWithoutActions proves the no-profile
// outcome cannot mutate headers or emit reject/tempfail commands.
func TestOriginatorNotApplicableEOMContinuesWithoutActions(t *testing.T) {
	handler := &testHandler{result: Result{
		Operation: operationSign, Result: resultNone, Outcome: DispositionContinue,
	}}
	session := policySession(t, handler, modeOriginator, FailurePolicy{})
	stream := &splitStream{reader: bytes.NewReader(completeOriginatorMessage())}
	if err := session.Serve(context.Background(), stream); err != nil || handler.calls != 1 {
		t.Fatalf("Serve() error=%v calls=%d", err, handler.calls)
	}
	commands := responseCommands(t, stream.writer.Bytes())
	if len(commands) == 0 || commands[len(commands)-1] != replyAccept {
		t.Fatalf("response commands=%q", commands)
	}
	for _, command := range commands {
		if command == replyAddHeader || command == replyChangeHeader ||
			command == replyReject || command == replyTempfail {
			t.Fatalf("originator no-op emitted terminal or mutation command %q", command)
		}
	}
}

// TestNewSessionRejectsInvalidAuthenticationAuthority freezes the public gate.
func TestNewSessionRejectsInvalidAuthenticationAuthority(t *testing.T) {
	admission, err := NewAdmission(1, 1, testAdmissionBytes)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewSession(&testHandler{}, admission, Limits{
		MessageBytes: 1 << 16, HeaderBytes: 1 << 15,
		HeaderCount: 100, HeaderFieldBytes: 1024, RecipientCount: 100,
	}, time.Second, FailurePolicy{}, modeInbound, "MX.Example")
	if !errors.Is(err, &Error{Class: FailureContract}) {
		t.Fatal("invalid authserv-id reached the callback runtime")
	}
}

type abusiveWriter struct {
	count int
	err   error
	panic bool
}

// Write returns one deliberately invalid writer outcome.
func (w abusiveWriter) Write([]byte) (int, error) {
	if w.panic {
		panic("private writer marker")
	}
	return w.count, w.err
}

// TestWriteFramesRejectsInvalidWriterContracts proves finite indeterminate handling.
func TestWriteFramesRejectsInvalidWriterContracts(t *testing.T) {
	frame := encodeFrame(replyAddHeader, []byte("Name\x00value\x00"))
	for _, testCase := range []struct {
		name   string
		writer io.Writer
		class  FailureClass
	}{
		{name: "zero nil", writer: abusiveWriter{}, class: FailureUnavailable},
		{name: "negative", writer: abusiveWriter{count: -1}, class: FailureIndeterminate},
		{name: "oversized", writer: abusiveWriter{count: len(frame) + 1}, class: FailureIndeterminate},
		{name: "partial error", writer: abusiveWriter{count: 1, err: io.ErrClosedPipe}, class: FailureIndeterminate},
		{name: "panic", writer: abusiveWriter{panic: true}, class: FailureIndeterminate},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := writeFrames(testCase.writer, [][]byte{frame})
			if !errors.Is(err, &Error{Class: testCase.class}) {
				t.Fatalf("writeFrames()=%v, want %q", err, testCase.class)
			}
		})
	}
}

// TestWriteFramesObservesCompletedAndAmbiguousActionsExactly proves write evidence.
func TestWriteFramesObservesCompletedAndAmbiguousActionsExactly(t *testing.T) {
	var observations []string
	err := writeFramesObserved(
		&stagedWriter{},
		[][]byte{
			encodeFrame(replyAddHeader, []byte("Name\x00value\x00")),
			encodeFrame(replyAccept, nil),
		},
		func(command byte, result string) {
			action, ok := actionObservationClass(command)
			if ok {
				observations = append(observations, action+"/"+result)
			}
		},
	)
	if !errors.Is(err, &Error{Class: FailureIndeterminate}) ||
		len(observations) != 2 ||
		observations[0] != "add_header/"+observationSuccess ||
		observations[1] != "accept/"+observationFailure {
		t.Fatalf("partial action observations=%v, error=%v", observations, err)
	}
}

// policySession builds one operation-policy session.
func policySession(
	t *testing.T,
	handler Handler,
	mode string,
	policy FailurePolicy,
) *Session {
	t.Helper()
	admission, err := NewAdmission(2, 2, testAdmissionBytes)
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(handler, admission, Limits{
		MessageBytes: 1 << 16, HeaderBytes: 1 << 15,
		HeaderCount: 100, HeaderFieldBytes: 1024, RecipientCount: 100,
	}, time.Second, policy, mode, "")
	if err != nil {
		t.Fatal(err)
	}
	return session
}

// completeTwoRecipientMessage returns one independent MTA-side callback stream.
func completeTwoRecipientMessage() []byte {
	return appendPeerFrames(
		peerFrame(commandNegotiate, negotiationPayload()),
		peerFrame(commandConnect, []byte("mx\x00U")),
		peerFrame(commandHelo, []byte("helo\x00")),
		peerFrame(commandMail, []byte("<a@example.test>\x00")),
		peerFrame(commandRecipient, []byte("<b@example.test>\x00")),
		peerFrame(commandRecipient, []byte("<c@example.test>\x00")),
		peerFrame(commandEOH, nil),
		peerFrame(commandEOM, nil),
		peerFrame(commandQuit, nil),
	)
}

// completeOriginatorMessage returns one single-recipient originator callback stream.
func completeOriginatorMessage() []byte {
	return appendPeerFrames(
		peerFrame(commandNegotiate, negotiationPayload()),
		peerFrame(commandConnect, []byte("mx\x00U")),
		peerFrame(commandHelo, []byte("helo\x00")),
		peerFrame(commandMail, []byte("<a@example.test>\x00")),
		peerFrame(commandRecipient, []byte("<b@example.test>\x00")),
		peerFrame(commandEOH, nil),
		peerFrame(commandEOM, nil),
		peerFrame(commandQuit, nil),
	)
}
