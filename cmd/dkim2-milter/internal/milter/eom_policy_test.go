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
