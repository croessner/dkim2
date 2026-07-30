package milter

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"
)

const testEnvelopePath = "<a@example.test>"

// TestNegotiationRequiresExactFidelityCapabilities proves the required v6 subset.
func TestNegotiationRequiresExactFidelityCapabilities(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		version  uint32
		actions  uint32
		protocol uint32
		wantOK   bool
	}{
		{name: "exact", version: 6, actions: actionAddHeaders | actionChangeHeaders, protocol: requiredProtocol, wantOK: true},
		{name: "peer extras", version: 6, actions: ^uint32(0), protocol: ^uint32(0), wantOK: true},
		{name: "newer peer selects v6", version: 7, actions: actionAddHeaders | actionChangeHeaders, protocol: requiredProtocol, wantOK: true},
		{name: "old version", version: 5, actions: actionAddHeaders | actionChangeHeaders, protocol: requiredProtocol},
		{name: "missing action", version: 6, protocol: requiredProtocol},
		{name: "cannot remove forged local results", version: 6, actions: actionAddHeaders, protocol: requiredProtocol},
		{name: "missing header space", version: 6, actions: actionAddHeaders, protocol: requiredProtocol &^ protocolHeaderSpace},
		{name: "cannot suppress unknown", version: 6, actions: actionAddHeaders, protocol: requiredProtocol &^ protocolNoUnknown},
		{name: "cannot suppress data", version: 6, actions: actionAddHeaders, protocol: requiredProtocol &^ protocolNoData},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			session := testSession(t, &testHandler{}, false, modeInbound, "")
			payload := make([]byte, 12)
			binary.BigEndian.PutUint32(payload[:4], testCase.version)
			binary.BigEndian.PutUint32(payload[4:8], testCase.actions)
			binary.BigEndian.PutUint32(payload[8:12], testCase.protocol)
			frames, err := session.negotiate(payload)
			if testCase.wantOK {
				if err != nil || len(frames) != 1 || frames[0][4] != commandNegotiate ||
					binary.BigEndian.Uint32(frames[0][5:9]) != milterVersion6 ||
					binary.BigEndian.Uint32(frames[0][13:17]) != requiredProtocol {
					t.Fatalf("negotiate() frames=%x err=%v", frames, err)
				}
				return
			}
			if !errors.Is(err, &Error{Class: FailureFidelity}) || session.state != stateInitial {
				t.Fatalf("negotiate() err=%v state=%d", err, session.state)
			}
		})
	}
}

// TestConnectAndMacroFramingMatrix proves known shape-only callbacks are strict.
func TestConnectAndMacroFramingMatrix(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		payload []byte
		valid   bool
	}{
		{name: "unknown family", payload: []byte("peer\x00U"), valid: true},
		{name: "IPv4 shape", payload: []byte{'p', 0, '4', 0, 25, '1', '.', '2', '.', '3', '.', '4', 0}, valid: true},
		{name: "IPv6 shape", payload: []byte{'p', 0, '6', 0, 25, ':', ':', '1', 0}, valid: true},
		{name: "Unix shape", payload: []byte{'p', 0, 'L', 0, 0, '/', 's', 0}, valid: true},
		{name: "Unix nonzero port", payload: []byte{'p', 0, 'L', 0, 1, '/', 's', 0}},
		{name: "legacy truncated", payload: []byte("peer\x00")},
		{name: "unknown has trailing", payload: []byte("peer\x00U\x00")},
		{name: "address lacks terminator", payload: []byte{'p', 0, '4', 0, 25, 'x'}},
		{name: "embedded address NUL", payload: []byte{'p', 0, '4', 0, 25, 'x', 0, 'y', 0}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := validConnect(testCase.payload); got != testCase.valid {
				t.Fatalf("validConnect()=%t, want %t", got, testCase.valid)
			}
		})
	}
	for _, testCase := range []struct {
		name    string
		payload []byte
		valid   bool
	}{
		{name: "empty arbitrary stage", payload: []byte{'X'}, valid: true},
		{name: "pair", payload: []byte{'M', 'i', 0, 'v', 0}, valid: true},
		{name: "opaque value", payload: []byte{'?', 'i', 0, 'v', '\r', '\n', 0}, valid: true},
		{name: "odd pair", payload: []byte{'M', 'i', 0}},
		{name: "empty name", payload: []byte{'M', 0, 'v', 0}},
	} {
		t.Run("macro_"+testCase.name, func(t *testing.T) {
			if got := validMacro(testCase.payload); got != testCase.valid {
				t.Fatalf("validMacro()=%t, want %t", got, testCase.valid)
			}
		})
	}
}

// TestMacroIsMetadataAtEveryCallbackState proves macro stage bytes do not drive state.
func TestMacroIsMetadataAtEveryCallbackState(t *testing.T) {
	for state := stateInitial; state <= stateBody; state++ {
		session := testSession(t, &testHandler{}, false, modeInbound, "")
		session.state = state
		if err := session.handleMacro([]byte{'?', 'n', 0, 'v', '\r', '\n', 0}); err != nil {
			t.Fatalf("handleMacro() state=%d error=%v", state, err)
		}
		if session.state != state {
			t.Fatalf("handleMacro() changed state %d to %d", state, session.state)
		}
	}
}

// TestMacroPairBounds proves discarded metadata remains independently bounded.
func TestMacroPairBounds(t *testing.T) {
	build := func(nameBytes, valueBytes int) []byte {
		payload := []byte{'?'}
		payload = append(payload, bytes.Repeat([]byte{'n'}, nameBytes)...)
		payload = append(payload, 0)
		payload = append(payload, bytes.Repeat([]byte{'v'}, valueBytes)...)
		return append(payload, 0)
	}
	if !validMacro(build(255, 4096)) {
		t.Fatal("exact macro name/value limits were rejected")
	}
	if validMacro(build(256, 1)) || validMacro(build(1, 4097)) {
		t.Fatal("macro name/value limit overflow succeeded")
	}
}

// TestEnvelopePathAndESMTPArgumentMatrix proves syntax checks preserve accepted bytes.
func TestEnvelopePathAndESMTPArgumentMatrix(t *testing.T) {
	for _, testCase := range []struct {
		path      string
		allowNull bool
		valid     bool
	}{
		{path: "<>", allowNull: true, valid: true},
		{path: "<>", allowNull: false},
		{path: testEnvelopePath, valid: true},
		{path: "<\"a b\"@example.test>", valid: true},
		{path: "<@route.test:a@example.test>", valid: true},
		{path: "<fröm@exämple.test>", valid: true},
		{path: "<a@[192.0.2.1]>", valid: true},
		{path: "<a@[IPv6:::1]>", valid: true},
		{path: "<a@[::1]>"},
		{path: "<a@ex ample.test>"},
		{path: "<a@\u200d.test>"},
		{path: "a@example.test"},
		{path: "<a..b@example.test>"},
		{path: "<a@-example.test>"},
		{path: "<a@example.test.>"},
		{path: "<a\xff@example.test>"},
		{path: "<a@example.test>\r"},
	} {
		if got := validEnvelopePath([]byte(testCase.path), testCase.allowNull); got != testCase.valid {
			t.Errorf("validEnvelopePath(%q)=%t, want %t", testCase.path, got, testCase.valid)
		}
	}
	for _, testCase := range []struct {
		argument string
		valid    bool
	}{
		{argument: "SMTPUTF8", valid: true},
		{argument: "SIZE=123", valid: true},
		{argument: "BODY=8BITMIME", valid: true},
		{argument: "1BAD", valid: true},
		{argument: "ALT=fröm", valid: true},
		{argument: ""},
		{argument: "=bad"},
		{argument: "-BAD"},
		{argument: "SIZE="},
		{argument: "SMTPUTF8=value"},
		{argument: "BAD ARG"},
		{argument: "BAD==VALUE"},
	} {
		if got := validESMTPArgument([]byte(testCase.argument)); got != testCase.valid {
			t.Errorf("validESMTPArgument(%q)=%t, want %t", testCase.argument, got, testCase.valid)
		}
	}
	for _, testCase := range []struct {
		name      string
		path      string
		allowNull bool
		want      string
		valid     bool
	}{
		{name: "framed", path: testEnvelopePath, want: testEnvelopePath, valid: true},
		{name: "bare Postfix simulation", path: "a@example.test", want: testEnvelopePath, valid: true},
		{name: "framed null", path: "<>", allowNull: true, want: "<>", valid: true},
		{name: "bare null", path: "", allowNull: true, want: "<>", valid: true},
		{name: "bare null recipient", path: ""},
		{name: "partial opening frame", path: "<a@example.test"},
		{name: "partial closing frame", path: "a@example.test>"},
		{name: "embedded frame", path: "a@<example.test>"},
	} {
		t.Run("normalize "+testCase.name, func(t *testing.T) {
			got, ok := normalizeMilterEnvelopePath([]byte(testCase.path), testCase.allowNull)
			if ok != testCase.valid || string(got) != testCase.want {
				t.Fatalf(
					"normalizeMilterEnvelopePath() value=%q valid=%t, want %q/%t",
					got,
					ok,
					testCase.want,
					testCase.valid,
				)
			}
		})
	}
}

// TestPostfixNonSMTPBarePathsAreNormalized proves simulated callbacks reach DKIM2
// with unambiguous RFC 5321 framing instead of the Postfix-specific wire shape.
func TestPostfixNonSMTPBarePathsAreNormalized(t *testing.T) {
	handler := &testHandler{result: Result{
		Operation: operationSign, Result: resultPass, Outcome: DispositionContinue,
	}}
	session := testSession(t, handler, false, modeOriginator, "")
	input := appendPeerFrames(
		peerFrame(commandNegotiate, negotiationPayload()),
		peerFrame(commandConnect, []byte("localhost\x00U")),
		peerFrame(commandHelo, []byte("localhost\x00")),
		peerFrame(commandMail, []byte("sender@example.test\x00")),
		peerFrame(commandRecipient, []byte("recipient@example.test\x00")),
		peerFrame(commandEOH, nil),
		peerFrame(commandEOM, nil),
		peerFrame(commandQuit, nil),
	)
	stream := &splitStream{reader: bytes.NewReader(input)}
	if err := session.Serve(context.Background(), stream); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if handler.calls != 1 ||
		!bytes.Equal(handler.message.ReversePath(), []byte("<sender@example.test>")) ||
		!bytes.Equal(handler.message.Recipients()[0], []byte("<recipient@example.test>")) {
		t.Fatalf("normalized callback path was not retained calls=%d", handler.calls)
	}
}

// TestInboundEAIRequiresMailSMTPUTF8AndPreservesAcceptedBytes proves RFC 6531 coupling.
func TestInboundEAIRequiresMailSMTPUTF8AndPreservesAcceptedBytes(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		mail      []byte
		recipient []byte
		wantOK    bool
	}{
		{
			name:      "asserted",
			mail:      append([]byte("<fröm@exämple.test>\x00SMTPUTF8"), 0),
			recipient: append([]byte("<tö@exämple.test>"), 0),
			wantOK:    true,
		},
		{
			name:      "missing assertion",
			mail:      append([]byte("<fröm@exämple.test>"), 0),
			recipient: append([]byte("<tö@exämple.test>"), 0),
		},
		{
			name:      "recipient needs assertion",
			mail:      append([]byte("<from@example.test>"), 0),
			recipient: append([]byte("<tö@exämple.test>"), 0),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			handler := &testHandler{result: Result{
				Operation: operationProcess, Result: resultPass, Outcome: DispositionContinue,
			}}
			session := testSession(t, handler, false, modeInbound, "")
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
			err := session.Serve(context.Background(), stream)
			if testCase.wantOK {
				if err != nil || handler.calls != 1 ||
					!bytes.Equal(handler.message.ReversePath(), firstNULField(testCase.mail)) ||
					!bytes.Equal(handler.message.Recipients()[0], firstNULField(testCase.recipient)) {
					t.Fatalf("Serve() error=%v calls=%d", err, handler.calls)
				}
				return
			}
			var adapterError *Error
			if !errors.As(err, &adapterError) || adapterError.Class != FailureFidelity ||
				handler.calls != 0 {
				t.Fatalf("Serve() error=%v calls=%d", err, handler.calls)
			}
		})
	}
}

// TestAbortResetsTransactionWithoutReplyAndAllowsReuse proves connection reuse.
func TestAbortResetsTransactionWithoutReplyAndAllowsReuse(t *testing.T) {
	handler := &testHandler{result: Result{
		Operation: operationProcess, Result: resultPass, Outcome: DispositionContinue,
	}}
	session := testSession(t, handler, false, modeInbound, "")
	input := appendPeerFrames(
		peerFrame(commandNegotiate, negotiationPayload()),
		peerFrame(commandConnect, []byte("mx\x00U")),
		peerFrame(commandHelo, []byte("helo\x00")),
		peerFrame(commandMail, []byte("<first@example>\x00")),
		peerFrame(commandRecipient, []byte("<drop@example>\x00")),
		peerFrame(commandAbort, nil),
		peerFrame(commandMail, []byte("<second@example>\x00")),
		peerFrame(commandRecipient, []byte("<keep@example>\x00")),
		peerFrame(commandEOH, nil),
		peerFrame(commandEOM, nil),
		peerFrame(commandQuit, nil),
	)
	stream := &splitStream{reader: bytes.NewReader(input)}
	if err := session.Serve(context.Background(), stream); err != nil {
		t.Fatalf("Serve() error=%v", err)
	}
	if handler.calls != 1 || !bytes.Equal(handler.message.ReversePath(), []byte("<second@example>")) {
		t.Fatal("aborted transaction data reached the reusable connection")
	}
	if got := responseCommands(t, stream.writer.Bytes()); !bytes.Equal(got, []byte{'O', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'a'}) {
		t.Fatalf("response commands=%q", got)
	}
	_, messages, retained, _ := session.admission.snapshot()
	if messages != 0 || retained != 0 {
		t.Fatalf("post-abort accounting messages=%d bytes=%d", messages, retained)
	}
}

// TestAbortBeforeMailAllowsPostfixConnectionReuse proves pre-MAIL cleanup is idempotent.
func TestAbortBeforeMailAllowsPostfixConnectionReuse(t *testing.T) {
	handler := &testHandler{result: Result{
		Operation: operationProcess, Result: resultPass, Outcome: DispositionContinue,
	}}
	session := testSession(t, handler, false, modeInbound, "")
	input := appendPeerFrames(
		peerFrame(commandNegotiate, negotiationPayload()),
		peerFrame(commandConnect, []byte("mx\x00U")),
		peerFrame(commandHelo, []byte("helo\x00")),
		peerFrame(commandAbort, nil),
		peerFrame(commandMail, []byte("<sender@example>\x00")),
		peerFrame(commandRecipient, []byte("<recipient@example>\x00")),
		peerFrame(commandEOH, nil),
		peerFrame(commandEOM, nil),
		peerFrame(commandQuit, nil),
	)
	stream := &splitStream{reader: bytes.NewReader(input)}
	if err := session.Serve(context.Background(), stream); err != nil {
		t.Fatalf("Serve() error=%v", err)
	}
	if handler.calls != 1 {
		t.Fatalf("handler calls=%d, want 1", handler.calls)
	}
	if got := responseCommands(t, stream.writer.Bytes()); !bytes.Equal(got, []byte{'O', 'c', 'c', 'c', 'c', 'c', 'a'}) {
		t.Fatalf("response commands=%q", got)
	}
}

// TestTerminalReplyIsSingleFrameAndConnectionRemainsSynchronized proves EOM reuse.
func TestTerminalReplyIsSingleFrameAndConnectionRemainsSynchronized(t *testing.T) {
	handler := &sequenceHandler{results: []Result{
		{Operation: operationProcess, Result: resultFail, Outcome: DispositionReject},
		{Operation: operationProcess, Result: resultPass, Outcome: DispositionContinue},
	}}
	session := testSession(t, handler, false, modeInbound, "")
	transaction := func(sender string) []byte {
		return appendPeerFrames(
			peerFrame(commandMail, append(append([]byte{}, sender...), 0)),
			peerFrame(commandRecipient, []byte("<b@example.test>\x00")),
			peerFrame(commandEOH, nil),
			peerFrame(commandEOM, nil),
		)
	}
	input := appendPeerFrames(
		peerFrame(commandNegotiate, negotiationPayload()),
		peerFrame(commandConnect, []byte("mx\x00U")),
		peerFrame(commandHelo, []byte("helo\x00")),
		transaction("<first@example.test>"),
		transaction("<second@example.test>"),
		peerFrame(commandQuit, nil),
	)
	stream := &splitStream{reader: bytes.NewReader(input)}
	if err := session.Serve(context.Background(), stream); err != nil {
		t.Fatalf("Serve() error=%v", err)
	}
	if handler.calls != 2 {
		t.Fatalf("Handle() calls=%d", handler.calls)
	}
	commands := responseCommands(t, stream.writer.Bytes())
	if bytes.Count(commands, []byte{replyCode}) != 1 ||
		bytes.ContainsAny(commands, string([]byte{replyReject, replyTempfail})) ||
		commands[len(commands)-1] != replyAccept {
		t.Fatalf("terminal commands=%q", commands)
	}
}

// TestInboundNestedOutcomesPreserveReplayAndPermissiveDispositions proves the
// flattened verification class cannot override the daemon's process decision.
func TestInboundNestedOutcomesPreserveReplayAndPermissiveDispositions(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		result  Result
		reply   byte
		payload string
	}{
		{
			name: "replayed", reply: replyCode, payload: fixedRejectReply,
			result: Result{
				Operation: operationProcess, Result: resultPass, Outcome: DispositionReject,
			},
		},
		{
			name: "indeterminate", reply: replyCode, payload: fixedTempfailReply,
			result: Result{
				Operation: operationProcess, Result: resultPass, Outcome: DispositionTempfail,
			},
		},
		{
			name: "permissive failure", reply: replyAccept,
			result: Result{
				Operation: operationProcess, Result: resultFail, Outcome: DispositionAccept,
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			session := testSession(
				t,
				&testHandler{result: testCase.result},
				false,
				modeInbound,
				"",
			)
			if !session.startTransaction(0) {
				t.Fatal("startTransaction() failed")
			}
			session.reverse = []byte("<from@example>")
			session.recipients = [][]byte{[]byte("<to@example>")}
			session.headers = []headerField{{name: []byte("From"), value: []byte(" from@example")}}
			session.headerBytes = int64(len("From: from@example\r\n"))
			frames, err := session.endMessage(context.Background())
			if err != nil || len(frames) != 1 || len(frames[0]) < 5 ||
				frames[0][4] != testCase.reply ||
				testCase.payload != "" &&
					!bytes.Equal(frames[0][5:], append([]byte(testCase.payload), 0)) {
				t.Fatalf("endMessage() frames=%x error=%v", frames, err)
			}
		})
	}
}

// TestIllegalCallbackOrderFailsClosed freezes representative singleton and phase violations.
func TestIllegalCallbackOrderFailsClosed(t *testing.T) {
	for _, commands := range [][][]byte{
		{peerFrame(commandConnect, []byte("mx\x00U"))},
		{peerFrame(commandNegotiate, negotiationPayload()), peerFrame(commandHelo, []byte("helo\x00"))},
		{peerFrame(commandNegotiate, negotiationPayload()), peerFrame(commandConnect, []byte("mx\x00U")), peerFrame(commandHelo, []byte("helo\x00")), peerFrame(commandEOH, nil)},
		{peerFrame(commandNegotiate, negotiationPayload()), peerFrame(commandConnect, []byte("mx\x00U")), peerFrame(commandHelo, []byte("helo\x00")), peerFrame(commandMail, []byte("<a@b.test>\x00")), peerFrame(commandMail, []byte("<a@b.test>\x00"))},
	} {
		session := testSession(t, &testHandler{}, false, modeInbound, "")
		stream := &splitStream{reader: bytes.NewReader(appendPeerFrames(commands...))}
		var adapterError *Error
		if err := session.Serve(context.Background(), stream); !errors.As(err, &adapterError) ||
			adapterError.Class != FailureContract {
			t.Fatalf("Serve() error=%v for %d commands", err, len(commands))
		}
	}
}

// TestHandlerPanicIsContainedAndTempfailed proves the injected seam cannot escape.
func TestHandlerPanicIsContainedAndTempfailed(t *testing.T) {
	session := testSession(t, panicHandler{}, true, modeInbound, "")
	input := appendPeerFrames(
		peerFrame(commandNegotiate, negotiationPayload()),
		peerFrame(commandConnect, []byte("mx\x00U")),
		peerFrame(commandHelo, []byte("helo\x00")),
		peerFrame(commandMail, []byte("<a@example.test>\x00")),
		peerFrame(commandRecipient, []byte("<b@example.test>\x00")),
		peerFrame(commandEOH, nil),
		peerFrame(commandEOM, nil),
		peerFrame(commandQuit, nil),
	)
	stream := &splitStream{reader: bytes.NewReader(input)}
	if err := session.Serve(context.Background(), stream); err != nil {
		t.Fatalf("Serve() error=%v", err)
	}
	commands := responseCommands(t, stream.writer.Bytes())
	if len(commands) < 1 || commands[len(commands)-1] != replyCode {
		t.Fatalf("terminal response commands=%q", commands)
	}
}

// TestAdmissionFailureBeforeOperationMayFailOpen proves the sole local-overload exception.
func TestAdmissionFailureBeforeOperationMayFailOpen(t *testing.T) {
	admission, err := NewAdmission(1, 1, 25)
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(&testHandler{}, admission, Limits{
		MessageBytes: 1024, HeaderBytes: 512, HeaderCount: 10,
		HeaderFieldBytes: 128, RecipientCount: 10,
	}, time.Second, FailurePolicy{FailOpen: true}, modeInbound, "")
	if err != nil {
		t.Fatal(err)
	}
	input := appendPeerFrames(
		peerFrame(commandNegotiate, negotiationPayload()),
		peerFrame(commandConnect, []byte("mx\x00U")),
		peerFrame(commandHelo, []byte("helo\x00")),
		peerFrame(commandMail, []byte("<long@example.test>\x00")),
		peerFrame(commandQuit, nil),
	)
	stream := &splitStream{reader: bytes.NewReader(input)}
	if err := session.Serve(context.Background(), stream); err != nil {
		t.Fatalf("Serve() error=%v", err)
	}
	commands := responseCommands(t, stream.writer.Bytes())
	if commands[len(commands)-1] != replyAccept {
		t.Fatalf("response commands=%q", commands)
	}
	_, messages, retained, _ := admission.snapshot()
	if messages != 0 || retained != 0 {
		t.Fatalf("failed admission retained messages=%d bytes=%d", messages, retained)
	}
}

// TestHandlerDeadlineMapsToFixedTempfail proves deadline ownership and response privacy.
func TestHandlerDeadlineMapsToFixedTempfail(t *testing.T) {
	admission, err := NewAdmission(1, 1, testAdmissionBytes)
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(deadlineHandler{}, admission, Limits{
		MessageBytes: 1024, HeaderBytes: 512, HeaderCount: 10,
		HeaderFieldBytes: 128, RecipientCount: 10,
	}, 100*time.Millisecond, FailurePolicy{}, modeInbound, "")
	if err != nil {
		t.Fatal(err)
	}
	input := appendPeerFrames(
		peerFrame(commandNegotiate, negotiationPayload()),
		peerFrame(commandConnect, []byte("mx\x00U")),
		peerFrame(commandHelo, []byte("helo\x00")),
		peerFrame(commandMail, []byte("<a@example.test>\x00")),
		peerFrame(commandRecipient, []byte("<b@example.test>\x00")),
		peerFrame(commandEOH, nil),
		peerFrame(commandEOM, nil),
		peerFrame(commandQuit, nil),
	)
	stream := &splitStream{reader: bytes.NewReader(input)}
	if err := session.Serve(context.Background(), stream); err != nil {
		t.Fatalf("Serve() error=%v", err)
	}
	if got := stream.writer.String(); !bytes.Contains([]byte(got), []byte(fixedTempfailReply)) ||
		bytes.Contains([]byte(got), []byte("private deadline marker")) {
		t.Fatalf("deadline response=%q", got)
	}
}

// TestReadFrameRejectsLengthsBeforePayloadAllocation proves framing bounds.
func TestReadFrameRejectsLengthsBeforePayloadAllocation(t *testing.T) {
	for _, encoded := range [][]byte{
		{0, 0, 0, 0},
		{0, 0x10, 0, 1},
		{0, 0, 0, 2, commandHelo},
	} {
		_, _, err := readFrame(bytes.NewReader(encoded))
		if err == nil {
			t.Fatalf("readFrame(%x) succeeded", encoded)
		}
	}
}

// TestReadFrameEnforcesDefaultAndCommandSpecificCaps proves negotiation-bound framing.
func TestReadFrameEnforcesDefaultAndCommandSpecificCaps(t *testing.T) {
	maximum := make([]byte, 4+maxMilterFrameLength)
	binary.BigEndian.PutUint32(maximum[:4], maxMilterFrameLength)
	maximum[4] = commandBody
	command, payload, err := readFrame(bytes.NewReader(maximum))
	if err != nil || command != commandBody || len(payload) != maxMilterPayloadLength {
		t.Fatalf("maximum read = %q,%d,%v", command, len(payload), err)
	}
	oversized := make([]byte, 5)
	binary.BigEndian.PutUint32(oversized[:4], maxMilterFrameLength+1)
	oversized[4] = commandBody
	if _, _, err := readFrame(bytes.NewReader(oversized)); err == nil {
		t.Fatal("oversized default frame succeeded")
	}
	control := make([]byte, 5)
	binary.BigEndian.PutUint32(control[:4], 14)
	control[4] = commandNegotiate
	if _, _, err := readFrame(bytes.NewReader(control)); err == nil {
		t.Fatal("oversized negotiation payload reached allocation/read")
	}
}

// TestDeniedFrameAdmissionDrainsBeforeReturning proves the next frame stays aligned.
func TestDeniedFrameAdmissionDrainsBeforeReturning(t *testing.T) {
	admission, err := NewAdmission(1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	stream := bytes.NewReader(appendPeerFrames(
		peerFrame(commandBody, []byte{1, 2}),
		peerFrame(commandQuit, nil),
	))
	command, payload, release, err := readAdmittedFrame(stream, admission)
	release()
	if command != commandBody || payload != nil ||
		!errors.Is(err, &Error{Class: FailureCapacity}) {
		t.Fatalf("denied frame=(%q,%x,%v)", command, payload, err)
	}
	command, payload, release, err = readAdmittedFrame(stream, admission)
	release()
	if command != commandQuit || len(payload) != 0 || err != nil {
		t.Fatalf("following frame=(%q,%x,%v)", command, payload, err)
	}
}

// TestDeniedFrameAdmissionUsesFixedReplyPolicy proves overload is never silent.
func TestDeniedFrameAdmissionUsesFixedReplyPolicy(t *testing.T) {
	for _, failOpen := range []bool{false, true} {
		t.Run(map[bool]string{false: "tempfail", true: "pre-operation fail-open"}[failOpen], func(t *testing.T) {
			admission, err := NewAdmission(1, 1, 1)
			if err != nil {
				t.Fatal(err)
			}
			session, err := NewSession(&testHandler{}, admission, Limits{
				MessageBytes: 1024, HeaderBytes: 512, HeaderCount: 10,
				HeaderFieldBytes: 128, RecipientCount: 10,
			}, time.Second, FailurePolicy{FailOpen: failOpen}, modeInbound, "")
			if err != nil {
				t.Fatal(err)
			}
			session.state = stateHelo
			stream := &splitStream{reader: bytes.NewReader(appendPeerFrames(
				peerFrame(commandMail, []byte("<a@example.test>\x00")),
				peerFrame(commandQuit, nil),
			))}
			serveErr := session.Serve(context.Background(), stream)
			commands := responseCommands(t, stream.writer.Bytes())
			if failOpen {
				if serveErr != nil || !bytes.Equal(commands, []byte{replyAccept}) {
					t.Fatalf("fail-open Serve()=%v commands=%q", serveErr, commands)
				}
				return
			}
			if !errors.Is(serveErr, &Error{Class: FailureCapacity}) ||
				!bytes.Equal(commands, []byte{replyCode}) ||
				!bytes.Contains(stream.writer.Bytes(), []byte(fixedTempfailReply)) {
				t.Fatalf("tempfail Serve()=%v commands=%q response=%q",
					serveErr, commands, stream.writer.Bytes())
			}
		})
	}
}

// TestNULFieldValidatorsAllocateNothing proves validation does not amplify aggregate input.
func TestNULFieldValidatorsAllocateNothing(t *testing.T) {
	header := []byte("Subject\x00 exact\x00")
	esmtp := []byte("<a@example.test>\x00SIZE=123\x00SMTPUTF8\x00")
	macro := []byte{'?', 'n', 0, 'v', '\r', '\n', 0}
	if allocations := testing.AllocsPerRun(1000, func() {
		_, _, _, _ = validateHeaderCallback(header, 1024)
		_ = validESMTPCallback(esmtp, 256, false)
		_ = callbackHasParameter(esmtp, "SMTPUTF8")
		_ = validMacro(macro)
	}); allocations != 0 {
		t.Fatalf("NUL validation allocations=%f, want 0", allocations)
	}
}

// TestHeaderRetentionAllocatesOnlyOwnedFields proves reconstruction has no unbudgeted clone.
func TestHeaderRetentionAllocatesOnlyOwnedFields(t *testing.T) {
	session := testSession(t, &testHandler{}, false, modeInbound, "")
	if !session.startTransaction(0) {
		t.Fatal("startTransaction() failed")
	}
	session.state = stateRecipients
	session.recipients = [][]byte{[]byte("<to@example.test>")}
	session.headers = make([]headerField, 0, 1)
	payload := []byte("Subject\x00 exact\x00")
	fieldBytes := int64(len("Subject: exact\r\n"))
	failed := false
	allocations := testing.AllocsPerRun(1000, func() {
		session.state = stateRecipients
		if err := session.handleHeader(payload); err != nil {
			failed = true
			return
		}
		clear(session.headers[0].name)
		clear(session.headers[0].value)
		session.headers = session.headers[:0]
		session.headerBytes = 0
		if !session.reservation.Shrink(fieldBytes) {
			failed = true
		}
	})
	if failed {
		t.Fatal("handleHeader() or reservation rollback failed")
	}
	if allocations != 2 {
		t.Fatalf("handleHeader() allocations=%f, want owned name and value only", allocations)
	}
	_, messages, retained, _ := session.admission.snapshot()
	if messages != 1 || retained != 0 {
		t.Fatalf("post-run accounting messages=%d bytes=%d", messages, retained)
	}
	session.resetTransaction()
}

// TestNoReplyCommandsCloseWithoutOutOfPhaseFailureFrame proves Milter response grammar.
func TestNoReplyCommandsCloseWithoutOutOfPhaseFailureFrame(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		input []byte
		want  []byte
	}{
		{
			name:  "negotiate mismatch",
			input: peerFrame(commandNegotiate, make([]byte, 12)),
		},
		{
			name: "malformed macro",
			input: appendPeerFrames(
				peerFrame(commandNegotiate, negotiationPayload()),
				peerFrame(commandMacro, []byte{'X'}),
			),
			want: []byte{'O'},
		},
		{
			name: "malformed quit",
			input: appendPeerFrames(
				peerFrame(commandNegotiate, negotiationPayload()),
				peerFrame(commandQuit, []byte{1}),
			),
			want: []byte{'O'},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			session := testSession(t, &testHandler{}, false, modeInbound, "")
			stream := &splitStream{reader: bytes.NewReader(testCase.input)}
			if err := session.Serve(context.Background(), stream); err == nil {
				t.Fatal("Serve() succeeded")
			}
			if got := responseCommands(t, stream.writer.Bytes()); !bytes.Equal(got, testCase.want) {
				t.Fatalf("response commands=%q, want %q", got, testCase.want)
			}
		})
	}
}

// TestHeaderValidationAndLimitsPreserveExactLegalBytes proves line and field boundaries.
func TestHeaderValidationAndLimitsPreserveExactLegalBytes(t *testing.T) {
	name, value, ok := parseHeader([]byte("X-Test\x00 value\r\n\tcontinued\x00"), 128)
	if !ok || !bytes.Equal(name, []byte("X-Test")) ||
		!bytes.Equal(value, []byte(" value\r\n\tcontinued")) {
		t.Fatalf("parseHeader()=(%q,%q,%t)", name, value, ok)
	}
	for _, invalid := range [][]byte{
		[]byte("Bad Name\x00 value\x00"),
		[]byte("X\x00bare\nline\x00"),
		[]byte("X\x00bad\r\nfold\x00"),
		[]byte("X\x00value"),
		[]byte("\x00value\x00"),
		[]byte("X\x00value\x00extra\x00"),
	} {
		if _, _, ok := parseHeader(invalid, 128); ok {
			t.Fatalf("parseHeader(%q) succeeded", invalid)
		}
	}
	physical := append([]byte("X\x00"), bytes.Repeat([]byte{'a'}, 998)...)
	physical = append(physical, 0)
	if _, _, ok := parseHeader(physical, 2000); ok {
		t.Fatal("physical line beyond 998 octets succeeded")
	}
	exactName := bytes.Repeat([]byte{'X'}, 997)
	exact := append(append(bytes.Clone(exactName), 0), 0)
	if _, _, ok := parseHeader(exact, 2000); !ok {
		t.Fatal("exact 998-octet empty-value physical line was rejected")
	}
	tooLongName := bytes.Repeat([]byte{'X'}, 998)
	tooLong := append(append(bytes.Clone(tooLongName), 0), 0)
	if _, _, ok := parseHeader(tooLong, 2000); ok {
		t.Fatal("999-octet empty-value physical line succeeded")
	}
}

// TestEOMReservationSurvivesUntilTerminalWrite proves response working-set
// accounting remains charged until the terminal Milter frames are written.
func TestEOMReservationSurvivesUntilTerminalWrite(t *testing.T) {
	const minimumResponseWorkingSetBytes = 7*(4<<20) + 3*65536
	session := testSession(t, &testHandler{result: Result{
		Operation: operationProcess, Result: resultPass, Outcome: DispositionContinue,
	}}, false, modeInbound, "")
	steps := []struct {
		command byte
		payload []byte
	}{
		{commandNegotiate, negotiationPayload()},
		{commandConnect, []byte("mx\x00U")},
		{commandHelo, []byte("helo\x00")},
		{commandMail, []byte("<a@example.test>\x00")},
		{commandRecipient, []byte("<b@example.test>\x00")},
		{commandEOH, nil},
	}
	for _, step := range steps {
		if _, _, err := session.handleFrame(context.Background(), step.command, step.payload); err != nil {
			t.Fatalf("handleFrame(%q) error=%v", step.command, err)
		}
	}
	_, frames, err := session.handleFrame(context.Background(), commandEOM, nil)
	if err != nil || !session.eomPending {
		t.Fatalf("EOM frames=%x err=%v pending=%t", frames, err, session.eomPending)
	}
	_, messages, retained, _ := session.admission.snapshot()
	if messages != 1 || retained < minimumResponseWorkingSetBytes {
		t.Fatalf("pre-write accounting messages=%d bytes=%d", messages, retained)
	}
	if err := writeFrames(io.Discard, frames); err != nil {
		t.Fatal(err)
	}
	session.resetTransaction()
	_, messages, retained, _ = session.admission.snapshot()
	if messages != 0 || retained != 0 {
		t.Fatalf("post-write accounting messages=%d bytes=%d", messages, retained)
	}
}

// TestSessionLimitInvariantsFailAtConstruction proves no impossible message budget exists.
func TestSessionLimitInvariantsFailAtConstruction(t *testing.T) {
	admission, err := NewAdmission(1, 1, testAdmissionBytes)
	if err != nil {
		t.Fatal(err)
	}
	valid := Limits{
		MessageBytes: 1024, HeaderBytes: 512, HeaderCount: 10,
		HeaderFieldBytes: 128, RecipientCount: 10,
	}
	for _, mutate := range []func(*Limits){
		func(limits *Limits) { limits.HeaderFieldBytes = 513 },
		func(limits *Limits) { limits.HeaderBytes = 1023 },
		func(limits *Limits) { limits.MessageBytes = hardMessageBytes + 1 },
		func(limits *Limits) { limits.HeaderBytes = hardHeaderBytes + 1 },
		func(limits *Limits) { limits.HeaderCount = hardHeaderCount + 1 },
		func(limits *Limits) { limits.RecipientCount = hardRecipientCount + 1 },
	} {
		candidate := valid
		mutate(&candidate)
		if _, err := NewSession(
			&testHandler{}, admission, candidate, time.Second,
			FailurePolicy{}, modeInbound, "",
		); err == nil {
			t.Fatalf("NewSession(%+v) succeeded", candidate)
		}
	}
}

type panicHandler struct{}

// Handle simulates one panic at the application seam.
func (panicHandler) Handle(context.Context, Message) (Result, error) {
	panic("private marker must not escape")
}

type sequenceHandler struct {
	results []Result
	calls   int
}

// Handle returns one deterministic result for each reusable transaction.
func (h *sequenceHandler) Handle(context.Context, Message) (Result, error) {
	if h.calls >= len(h.results) {
		return Result{}, &Error{Class: FailureInternal}
	}
	result := h.results[h.calls]
	h.calls++
	return result, nil
}

type deadlineHandler struct{}

// Handle waits for the operation deadline and returns a marker-bearing dependency error.
func (deadlineHandler) Handle(ctx context.Context, _ Message) (Result, error) {
	<-ctx.Done()
	return Result{}, errors.New("private deadline marker")
}

type panicAfterWriter struct {
	writes int
}

// Write completes one frame and panics before the next frame.
func (w *panicAfterWriter) Write(input []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		return len(input), nil
	}
	panic("private writer marker")
}

// TestWriteFramesClassifiesWriterPanicAsIndeterminate proves conservative side effects.
func TestWriteFramesClassifiesWriterPanicAsIndeterminate(t *testing.T) {
	err := writeFrames(&panicAfterWriter{}, [][]byte{
		encodeFrame(replyAddHeader, []byte("Name\x00value\x00")),
		encodeFrame(replyAccept, nil),
	})
	if !errors.Is(err, &Error{Class: FailureIndeterminate}) {
		t.Fatalf("writeFrames() error=%v", err)
	}
}

// responseCommands independently decodes only response command octets.
func responseCommands(t *testing.T, encoded []byte) []byte {
	t.Helper()
	var commands []byte
	for len(encoded) > 0 {
		if len(encoded) < 5 {
			t.Fatalf("truncated response frame: %x", encoded)
		}
		length := int(binary.BigEndian.Uint32(encoded[:4]))
		if length < 1 || length+4 > len(encoded) {
			t.Fatalf("invalid response frame length %d in %x", length, encoded)
		}
		commands = append(commands, encoded[4])
		encoded = encoded[length+4:]
	}
	return commands
}

// FuzzReadFrameNeverAllocatesBeyondTheFixedCap exercises framing and negotiation decoding.
func FuzzReadFrameNeverAllocatesBeyondTheFixedCap(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, commandQuit}, negotiationPayload())
	f.Add([]byte{0, 0, 0, 0}, []byte{})
	f.Add([]byte{0, 0, 0, 2, commandHelo}, bytes.Repeat([]byte{0xff}, 12))
	f.Fuzz(func(t *testing.T, encoded, negotiation []byte) {
		command, payload, err := readFrame(bytes.NewReader(encoded))
		if err == nil && (command == 0 || len(payload) >= maxMilterFrameLength) {
			t.Fatalf("accepted command=%d payload=%d", command, len(payload))
		}
		if len(negotiation) > 64 {
			negotiation = negotiation[:64]
		}
		session := testSession(t, &testHandler{}, false, modeInbound, "")
		frames, negotiationErr := session.negotiate(negotiation)
		if negotiationErr != nil {
			return
		}
		if len(frames) != 1 || len(frames[0]) != 17 ||
			frames[0][4] != commandNegotiate ||
			binary.BigEndian.Uint32(frames[0][:4]) != 13 {
			t.Fatalf("accepted negotiation emitted malformed frames: %x", frames)
		}
	})
}

// FuzzEnvelopeAndESMTPValidationNeverPanics exercises byte-preserving syntax admission.
func FuzzEnvelopeAndESMTPValidationNeverPanics(f *testing.F) {
	f.Add([]byte(testEnvelopePath), true)
	f.Add([]byte("<fröm@exämple.test>"), false)
	f.Add([]byte("<>\x00SIZE=1\x00"), true)
	f.Fuzz(func(_ *testing.T, input []byte, allowNull bool) {
		_ = validEnvelopePath(input, allowNull)
		_ = validESMTPCallback(input, 256, allowNull)
		message := Message{reverse: bytes.Clone(input)}
		_, _ = message.SigningDomain()
	})
}

// FuzzHeaderValidationNeverPanics exercises full header and body reconstruction.
func FuzzHeaderValidationNeverPanics(f *testing.F) {
	f.Add([]byte("Subject\x00 value\x00"), []byte("body\r\n"), uint16(2))
	f.Add([]byte("X\x00a\r\n b\x00"), []byte{0, 1, 2}, uint16(1))
	f.Fuzz(func(t *testing.T, payload, body []byte, split uint16) {
		if len(payload) > 2048 {
			payload = payload[:2048]
		}
		if len(body) > 8192 {
			body = body[:8192]
		}
		bodySplit := int(split)
		if bodySplit > len(body) {
			bodySplit = len(body)
		}
		handler := &testHandler{result: Result{
			Operation: operationProcess, Result: resultPass, Outcome: DispositionContinue,
		}}
		session := testSession(t, handler, false, modeInbound, "")
		input := appendPeerFrames(
			peerFrame(commandNegotiate, negotiationPayload()),
			peerFrame(commandConnect, []byte("mx\x00U")),
			peerFrame(commandHelo, []byte("helo.example\x00")),
			peerFrame(commandMail, []byte("<from@example.test>\x00")),
			peerFrame(commandRecipient, []byte("<to@example.test>\x00")),
			peerFrame(commandHeader, payload),
			peerFrame(commandEOH, nil),
			peerFrame(commandBody, body[:bodySplit]),
			peerFrame(commandBody, body[bodySplit:]),
			peerFrame(commandEOM, nil),
			peerFrame(commandQuit, nil),
		)
		stream := &splitStream{reader: bytes.NewReader(input)}
		if err := session.Serve(context.Background(), stream); err != nil {
			return
		}
		if handler.calls != 1 {
			t.Fatalf("successful reconstruction invoked handler %d times", handler.calls)
		}
		want, ok := independentReconstructionOracle(payload, body)
		if !ok || !bytes.Equal(handler.message.Raw(), want) {
			t.Fatalf("successful reconstruction mismatch: got=%x want=%x", handler.message.Raw(), want)
		}
	})
}

// independentReconstructionOracle assembles one accepted callback outside the session.
func independentReconstructionOracle(payload, body []byte) ([]byte, bool) {
	nameEnd := bytes.IndexByte(payload, 0)
	if nameEnd < 0 {
		return nil, false
	}
	valueEnd := bytes.IndexByte(payload[nameEnd+1:], 0)
	if valueEnd < 0 || nameEnd+1+valueEnd+1 != len(payload) {
		return nil, false
	}
	value := payload[nameEnd+1 : nameEnd+1+valueEnd]
	output := make([]byte, 0, len(payload)+len(body)+4)
	output = append(output, payload[:nameEnd]...)
	output = append(output, ':')
	for index, current := range value {
		if current == '\n' && (index == 0 || value[index-1] != '\r') {
			output = append(output, '\r')
		}
		output = append(output, current)
	}
	output = append(output, '\r', '\n', '\r', '\n')
	output = append(output, body...)
	return output, true
}

// FuzzCallbackStateMachineNeverPanics exercises arbitrary callback sequences.
func FuzzCallbackStateMachineNeverPanics(f *testing.F) {
	f.Add([]byte{commandNegotiate, commandConnect, commandHelo, commandMail})
	f.Add([]byte{commandAbort, commandEOM, commandQuit})
	f.Fuzz(func(t *testing.T, commands []byte) {
		if len(commands) > 128 {
			commands = commands[:128]
		}
		session := testSession(t, &testHandler{result: Result{
			Operation: operationProcess, Result: resultPass, Outcome: DispositionContinue,
		}}, false, modeInbound, "")
		defer session.resetTransaction()
		for _, command := range commands {
			payload := fuzzCallbackPayload(command)
			terminal, _, err := session.handleFrame(context.Background(), command, payload)
			if err != nil || terminal {
				return
			}
		}
	})
}

// fuzzCallbackPayload supplies one bounded canonical payload for state fuzzing.
func fuzzCallbackPayload(command byte) []byte {
	switch command {
	case commandNegotiate:
		return negotiationPayload()
	case commandConnect:
		return []byte("mx\x00U")
	case commandHelo:
		return []byte("helo\x00")
	case commandMail:
		return []byte("<a@example.test>\x00")
	case commandRecipient:
		return []byte("<b@example.test>\x00")
	case commandHeader:
		return []byte("Subject\x00 value\x00")
	case commandMacro:
		return []byte{commandMail}
	default:
		return nil
	}
}
