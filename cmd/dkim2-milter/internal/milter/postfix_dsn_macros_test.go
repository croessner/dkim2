package milter

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

// postfixDSNEvidenceHandler captures only detached evidence required to prove
// the Postfix-only Milter callback contract.
type postfixDSNEvidenceHandler struct {
	evidence PostfixDSNEvidence
	fidelity Fidelity
	hasProof bool
	calls    int
}

// Handle records an isolated evidence copy and returns the delivery-status
// signing action shape owned by the adapter state machine.
func (h *postfixDSNEvidenceHandler) Handle(_ context.Context, message Message) (Result, error) {
	h.calls++
	h.evidence, h.hasProof = message.PostfixDSNEvidence()
	h.fidelity = message.Fidelity()
	return Result{
		Operation: operationDSNSign, Result: resultPass, Outcome: DispositionAccept,
		Actions: []Action{
			{Kind: ActionAddHeader, Name: headerMessage, Value: "v=1"},
			{Kind: ActionAddHeader, Name: headerDKIM2, Value: "v=2"},
		},
	}, nil
}

// TestPostfixDSNNegotiationRequestsOnlyOriginMacro proves this adapter uses
// the standard secondary negotiation payload rather than a new Milter command.
func TestPostfixDSNNegotiationRequestsOnlyOriginMacro(t *testing.T) {
	session := testSession(t, &postfixDSNEvidenceHandler{}, false, modePostfixDSN, "")
	frames, err := session.negotiate(postfixDSNNegotiationPayload())
	if err != nil || len(frames) != 1 || frames[0][4] != commandNegotiate {
		t.Fatalf("negotiate() frames=%x err=%v", frames, err)
	}
	payload := frames[0][5:]
	if len(payload) != 12+4+len(postfixDSNEOHMacroList)+1 ||
		binary.BigEndian.Uint32(payload[4:8]) != requiredActions|actionSetSymbolList ||
		binary.BigEndian.Uint32(payload[12:16]) != postfixDSNMacroClassEOH ||
		!bytes.Equal(payload[16:len(payload)-1], []byte(postfixDSNEOHMacroList)) ||
		payload[len(payload)-1] != 0 {
		t.Fatalf("secondary negotiation=%x", payload)
	}
}

// TestPostfixDSNNegotiationRequiresMacroListCapability proves the DSN adapter
// rejects an MTA that cannot provide explicitly requested EOH macros.
func TestPostfixDSNNegotiationRequiresMacroListCapability(t *testing.T) {
	session := testSession(t, &postfixDSNEvidenceHandler{}, false, modePostfixDSN, "")
	if _, err := session.negotiate(negotiationPayload()); !errors.Is(err, &Error{Class: FailureFidelity}) {
		t.Fatalf("negotiate() error=%v, want macro-list fidelity failure", err)
	}
}

// TestPostfixDSNWithoutEvidenceContinues proves the shared non-SMTP Milter
// chain leaves ordinary local mail and unauthenticated null-sender input
// unchanged without invoking the delivery-status handler.
func TestPostfixDSNWithoutEvidenceContinues(t *testing.T) {
	for _, reverse := range []string{testSenderPath, "<>"} {
		t.Run(reverse, func(t *testing.T) {
			handler := &postfixDSNEvidenceHandler{}
			session := testSession(t, handler, false, modePostfixDSN, "")
			input := appendPeerFrames(
				peerFrame(commandNegotiate, postfixDSNNegotiationPayload()),
				peerFrame(commandConnect, []byte("localhost\x00U")),
				peerFrame(commandHelo, []byte("localhost\x00")),
				peerFrame(commandMail, []byte(reverse+"\x00")),
				peerFrame(commandRecipient, []byte("<recipient@example.test>\x00")),
				peerFrame(commandHeader, []byte("Subject\x00 ordinary local mail\x00")),
				peerFrame(commandEOH, nil),
				peerFrame(commandEOM, nil),
				peerFrame(commandQuit, nil),
			)
			stream := &splitStream{reader: bytes.NewReader(input)}
			if err := session.Serve(context.Background(), stream); err != nil || handler.calls != 0 {
				t.Fatalf("Serve() error/calls = %v/%d", err, handler.calls)
			}
			commands := responseCommands(t, stream.writer.Bytes())
			if len(commands) == 0 || commands[len(commands)-1] != replyAccept {
				t.Fatalf("missing accept response: %q", commands)
			}
		})
	}
}

// TestPostfixDSNEOMAcceptsInternalOrigin proves exact bounce provenance is the
// sole macro value that reaches the delivery-status handler.
func TestPostfixDSNEOMAcceptsInternalOrigin(t *testing.T) {
	handler := &postfixDSNEvidenceHandler{}
	session := testSession(t, handler, false, modePostfixDSN, "")
	input := appendPeerFrames(
		peerFrame(commandNegotiate, postfixDSNNegotiationPayload()),
		peerFrame(commandMacro, postfixDSNMacroPayload(
			commandConnect, "{daemon_name}", "postfix",
		)),
		peerFrame(commandConnect, []byte("localhost\x00U")),
		peerFrame(commandHelo, []byte("localhost\x00")),
		peerFrame(commandMail, []byte("<>\x00")),
		peerFrame(commandRecipient, []byte("<report@example.test>\x00")),
		peerFrame(commandMacro, postfixDSNMacroPayload(commandHeader,
			postfixDSNMacroOrigin, postfixDSNOriginInternal,
		)),
		peerFrame(commandHeader, []byte("Subject\x00 Delivery Status\x00")),
		peerFrame(commandMacro, postfixDSNMacroPayload(commandEOH,
			postfixDSNMacroOrigin, postfixDSNOriginInternal,
		)),
		peerFrame(commandEOH, nil),
		peerFrame(commandEOM, nil),
		peerFrame(commandQuit, nil),
	)
	stream := &splitStream{reader: bytes.NewReader(input)}
	if err := session.Serve(context.Background(), stream); err != nil {
		t.Fatalf("Serve() error=%v", err)
	}
	if handler.calls != 1 || !handler.hasProof ||
		handler.fidelity != FidelityPostfixDSNReconstructedCRLF {
		t.Fatalf("handler calls/proof/fidelity = %d/%t/%q", handler.calls, handler.hasProof, handler.fidelity)
	}
	if !handler.evidence.Internal() {
		t.Fatal("PostfixDSNEvidence did not retain internal provenance")
	}
}

// TestPostfixDSNEOMRejectsMalformedOrAmbiguousOrigin proves malformed proof
// material cannot become ordinary originator input or reach a handler.
func TestPostfixDSNEOMRejectsMalformedOrAmbiguousOrigin(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		stage byte
		pairs []string
	}{
		{name: "duplicate", stage: commandEOH, pairs: []string{
			postfixDSNMacroOrigin, postfixDSNOriginInternal,
			postfixDSNMacroOrigin, postfixDSNOriginInternal,
		}},
		{name: "conflicting duplicate", stage: commandEOH, pairs: []string{
			postfixDSNMacroOrigin, postfixDSNOriginInternal,
			postfixDSNMacroOrigin, postfixDSNOriginExternal,
		}},
		{name: "wrong macro stage", stage: commandEOM, pairs: []string{
			postfixDSNMacroOrigin, postfixDSNOriginInternal,
		}},
		{name: "invalid enum", stage: commandEOH, pairs: []string{
			postfixDSNMacroOrigin, "local",
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			handler := &postfixDSNEvidenceHandler{}
			session := testSession(t, handler, false, modePostfixDSN, "")
			input := appendPeerFrames(
				peerFrame(commandNegotiate, postfixDSNNegotiationPayload()),
				peerFrame(commandConnect, []byte("localhost\x00U")),
				peerFrame(commandHelo, []byte("localhost\x00")),
				peerFrame(commandMail, []byte("<>\x00")),
				peerFrame(commandRecipient, []byte("<report@example.test>\x00")),
				peerFrame(commandMacro, postfixDSNMacroPayload(testCase.stage, testCase.pairs...)),
				peerFrame(commandEOH, nil),
				peerFrame(commandEOM, nil),
			)
			stream := &splitStream{reader: bytes.NewReader(input)}
			if err := session.Serve(context.Background(), stream); !errors.Is(err, &Error{Class: FailureContract}) || handler.calls != 0 {
				t.Fatalf("Serve() error/calls = %v/%d", err, handler.calls)
			}
		})
	}
}

// TestPostfixDSNExternalOriginContinues proves external provenance never
// authorizes signing and does not impose bounce envelope shape on ordinary
// messages sharing the non-SMTP Milter chain.
func TestPostfixDSNExternalOriginContinues(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		reverse    string
		recipients []string
	}{
		{name: "external null sender", reverse: "<>", recipients: []string{"<report@example.test>"}},
		{name: "ordinary multiple recipients", reverse: testSenderPath, recipients: []string{
			"<first@example.test>", "<second@example.test>",
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			handler := &postfixDSNEvidenceHandler{}
			session := testSession(t, handler, false, modePostfixDSN, "")
			frames := [][]byte{
				peerFrame(commandNegotiate, postfixDSNNegotiationPayload()),
				peerFrame(commandConnect, []byte("localhost\x00U")),
				peerFrame(commandHelo, []byte("localhost\x00")),
				peerFrame(commandMail, []byte(testCase.reverse+"\x00")),
			}
			for _, recipient := range testCase.recipients {
				frames = append(frames, peerFrame(commandRecipient, []byte(recipient+"\x00")))
			}
			frames = append(frames,
				peerFrame(commandMacro, postfixDSNMacroPayload(commandHeader, postfixDSNMacroOrigin, postfixDSNOriginExternal)),
				peerFrame(commandHeader, []byte("Subject\x00 external message\x00")),
				peerFrame(commandMacro, postfixDSNMacroPayload(commandEOH, postfixDSNMacroOrigin, postfixDSNOriginExternal)),
				peerFrame(commandEOH, nil), peerFrame(commandEOM, nil), peerFrame(commandQuit, nil),
			)
			stream := &splitStream{reader: bytes.NewReader(appendPeerFrames(frames...))}
			if err := session.Serve(context.Background(), stream); err != nil || handler.calls != 0 {
				t.Fatalf("Serve() error/calls = %v/%d", err, handler.calls)
			}
		})
	}
}

// TestPostfixDSNRequiresOriginAtEOH proves a header-stage value cannot be
// promoted by an empty or unrelated EOH macro callback.
func TestPostfixDSNRequiresOriginAtEOH(t *testing.T) {
	for _, eohPairs := range [][]string{
		nil,
		{"{unrelated}", "value"},
	} {
		handler := &postfixDSNEvidenceHandler{}
		session := testSession(t, handler, false, modePostfixDSN, "")
		input := appendPeerFrames(
			peerFrame(commandNegotiate, postfixDSNNegotiationPayload()),
			peerFrame(commandConnect, []byte("localhost\x00U")),
			peerFrame(commandHelo, []byte("localhost\x00")),
			peerFrame(commandMail, []byte("<>\x00")),
			peerFrame(commandRecipient, []byte("<report@example.test>\x00")),
			peerFrame(commandMacro, postfixDSNMacroPayload(commandHeader, postfixDSNMacroOrigin, postfixDSNOriginInternal)),
			peerFrame(commandHeader, []byte("Subject\x00 Delivery Status\x00")),
			peerFrame(commandMacro, postfixDSNMacroPayload(commandEOH, eohPairs...)),
			peerFrame(commandEOH, nil), peerFrame(commandEOM, nil),
		)
		stream := &splitStream{reader: bytes.NewReader(input)}
		if err := session.Serve(context.Background(), stream); !errors.Is(err, &Error{Class: FailureContract}) || handler.calls != 0 {
			t.Fatalf("Serve() error/calls = %v/%d", err, handler.calls)
		}
	}
}

// postfixDSNNegotiationPayload advertises the mandatory standard macro-list action.
func postfixDSNNegotiationPayload() []byte {
	payload := negotiationPayload()
	binary.BigEndian.PutUint32(payload[4:8], requiredActions|actionSetSymbolList)
	return payload
}

// postfixDSNMacroPayload builds one protocol-shaped test-only callback.
func postfixDSNMacroPayload(stage byte, pairs ...string) []byte {
	payload := []byte{stage}
	for index := 0; index < len(pairs); index += 2 {
		payload = append(payload, pairs[index]...)
		payload = append(payload, 0)
		payload = append(payload, pairs[index+1]...)
		payload = append(payload, 0)
	}
	return payload
}
