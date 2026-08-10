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

// TestPostfixDSNNegotiationRequestsOnlyEOHProofMacros proves this adapter uses
// the standard secondary negotiation payload rather than a new Milter command.
func TestPostfixDSNNegotiationRequestsOnlyEOHProofMacros(t *testing.T) {
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

// TestPostfixDSNEOMTransfersExactEvidence proves a complete one-recipient
// null-sender DSN is the sole path that reaches the delivery-status handler.
func TestPostfixDSNEOMTransfersExactEvidence(t *testing.T) {
	handler := &postfixDSNEvidenceHandler{}
	session := testSession(t, handler, false, modePostfixDSN, "")
	queueSender := []byte("sender@example.test")
	queueRecipients := [][]byte{[]byte("first@example.test"), []byte("second@example.test")}
	originalSender := []byte("<sender@example.test>")
	originalRecipients := [][]byte{[]byte("<first@example.test>"), []byte("<second@example.test>")}
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
			postfixDSNMacroMarker, postfixDSNMarker,
			postfixDSNMacroEnvelope, string(encodedPostfixDSNEnvelope(postfixDSNEnvelopeRecord(queueSender, queueRecipients))),
		)),
		peerFrame(commandHeader, []byte("Subject\x00 Delivery Status\x00")),
		peerFrame(commandMacro, postfixDSNMacroPayload(commandEOH,
			postfixDSNMacroMarker, postfixDSNMarker,
			postfixDSNMacroEnvelope, string(encodedPostfixDSNEnvelope(postfixDSNEnvelopeRecord(queueSender, queueRecipients))),
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
	sender, recipients := handler.evidence.OriginalEnvelope()
	if !bytes.Equal(sender, originalSender) || len(recipients) != len(originalRecipients) {
		t.Fatalf("OriginalEnvelope() did not preserve exact values")
	}
	for index := range originalRecipients {
		if !bytes.Equal(recipients[index], originalRecipients[index]) {
			t.Fatalf("recipient %d changed", index)
		}
	}
}

// TestPostfixDSNEOMRejectsIncompleteOrAmbiguousProof proves malformed proof
// material cannot become ordinary originator input or reach a handler.
func TestPostfixDSNEOMRejectsIncompleteOrAmbiguousProof(t *testing.T) {
	validEnvelope := string(encodedPostfixDSNEnvelope(postfixDSNEnvelopeRecord(
		[]byte("sender@example.test"), [][]byte{[]byte("recipient@example.test")},
	)))
	for _, testCase := range []struct {
		name  string
		stage byte
		pairs []string
	}{
		{name: "missing original envelope", stage: commandEOH, pairs: []string{
			postfixDSNMacroMarker, postfixDSNMarker,
		}},
		{name: "duplicate original envelope", stage: commandEOH, pairs: []string{
			postfixDSNMacroMarker, postfixDSNMarker,
			postfixDSNMacroEnvelope, validEnvelope,
			postfixDSNMacroEnvelope, string(encodedPostfixDSNEnvelope(postfixDSNEnvelopeRecord(
				[]byte("other@example.test"), [][]byte{[]byte("recipient@example.test")},
			))),
		}},
		{name: "wrong macro stage", stage: commandEOM, pairs: []string{
			postfixDSNMacroMarker, postfixDSNMarker,
			postfixDSNMacroEnvelope, validEnvelope,
		}},
		{name: "unexpected local proof member", stage: commandEOH, pairs: []string{
			postfixDSNMacroMarker, postfixDSNMarker,
			postfixDSNMacroEnvelope, validEnvelope, "{postfix_dsn_extra}", "x",
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
