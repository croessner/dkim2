package milter

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/croessner/dkim2/headerfold"
)

const (
	testActionValue = " v=1"
	testAuthservID  = "mx.example"
)

// TestValidResultEnforcesModeDispositionAndActionMatrix proves closed mutation admission.
func TestValidResultEnforcesModeDispositionAndActionMatrix(t *testing.T) {
	originator := []Action{
		{Kind: ActionAddHeader, Name: headerMessage, Value: testActionValue},
		{Kind: ActionAddHeader, Name: headerDKIM2, Value: testActionValue},
	}
	revision := []Action{{Kind: ActionAddHeader, Name: headerDKIM2, Value: testActionValue}}
	for _, testCase := range []struct {
		name       string
		mode       string
		authservID string
		result     Result
		headers    []headerField
		valid      bool
	}{
		{
			name: "originator accept", mode: modeOriginator,
			result: Result{Operation: operationSign, Result: resultPass, Outcome: DispositionAccept, Actions: originator},
			valid:  true,
		},
		{
			name: "originator refusal has no actions", mode: modeOriginator,
			result: Result{Operation: operationSign, Result: resultFail, Outcome: DispositionReject},
			valid:  true,
		},
		{
			name: "originator not applicable", mode: modeOriginator,
			result: Result{Operation: operationSign, Result: resultNone, Outcome: DispositionContinue},
			valid:  true,
		},
		{
			name: "originator not applicable cannot mutate", mode: modeOriginator,
			result: Result{Operation: operationSign, Result: resultNone, Outcome: DispositionContinue, Actions: originator},
		},
		{
			name: "originator pass continue cannot mutate", mode: modeOriginator,
			result: Result{Operation: operationSign, Result: resultPass, Outcome: DispositionContinue, Actions: originator},
		},
		{
			name: "originator wrong order", mode: modeOriginator,
			result: Result{Operation: operationSign, Result: resultPass, Outcome: DispositionAccept, Actions: []Action{originator[1], originator[0]}},
		},
		{
			name: "originator non-pass cannot mutate", mode: modeOriginator,
			result: Result{Operation: operationSign, Result: resultFail, Outcome: DispositionAccept, Actions: originator},
		},
		{
			name: "revision unchanged", mode: modeTransit,
			result: Result{Operation: operationRevise, Result: resultPass, Outcome: DispositionAccept, Actions: revision},
			valid:  true,
		},
		{
			name: "revision changed", mode: modeTransit,
			result: Result{Operation: operationRevise, Result: resultPass, Outcome: DispositionAccept, Actions: originator},
			valid:  true,
		},
		{
			name: "revision pass continue cannot mutate", mode: modeTransit,
			result: Result{Operation: operationRevise, Result: resultPass, Outcome: DispositionContinue, Actions: revision},
		},
		{
			name: "delivery status pass continue cannot mutate", mode: modePostfixDSN,
			result: Result{Operation: operationDSNSign, Result: resultPass, Outcome: DispositionContinue, Actions: originator},
		},
		{
			name: "inbound exact report", mode: modeInbound, authservID: testAuthservID,
			result: Result{
				Operation: operationProcess, Result: resultPass, Outcome: DispositionAccept,
				Actions: []Action{{Kind: ActionAddHeader, Name: headerAuthResults, Value: testAuthservID + "; dkim2=pass"}},
			},
			valid: true,
		},
		{
			name: "inbound testing continue exact report", mode: modeInbound, authservID: testAuthservID,
			result: Result{
				Operation: operationProcess, Result: resultPass, Outcome: DispositionContinue,
				Actions: []Action{{Kind: ActionAddHeader, Name: headerAuthResults, Value: testAuthservID + "; dkim2=pass"}},
			},
			valid: true,
		},
		{
			name: "inbound testing continue missing report", mode: modeInbound, authservID: testAuthservID,
			result: Result{
				Operation: operationProcess, Result: resultPass, Outcome: DispositionContinue,
			},
		},
		{
			name: "inbound replay rejection", mode: modeInbound,
			result: Result{
				Operation: operationProcess, Result: resultPass, Outcome: DispositionReject,
			},
			valid: true,
		},
		{
			name: "inbound replay indeterminate", mode: modeInbound,
			result: Result{
				Operation: operationProcess, Result: resultPass, Outcome: DispositionTempfail,
			},
			valid: true,
		},
		{
			name: "inbound permissive policy acceptance", mode: modeInbound,
			result: Result{
				Operation: operationProcess, Result: resultFail, Outcome: DispositionAccept,
			},
			valid: true,
		},
		{
			name: "inbound invented report", mode: modeInbound, authservID: testAuthservID,
			result: Result{
				Operation: operationProcess, Result: resultPass, Outcome: DispositionAccept,
				Actions: []Action{{Kind: ActionAddHeader, Name: headerAuthResults, Value: "attacker.example; dkim2=pass"}},
			},
		},
		{
			name: "inbound trust conflict", mode: modeInbound, authservID: testAuthservID,
			headers: []headerField{{name: []byte("authentication-results"), value: []byte(" mx.example; dkim=pass")}},
			result: Result{
				Operation: operationProcess, Result: resultPass, Outcome: DispositionAccept,
				Actions: []Action{{Kind: ActionAddHeader, Name: headerAuthResults, Value: testAuthservID + "; dkim2=pass"}},
			},
			valid: true,
		},
		{
			name: "refusal cannot mutate", mode: modeInbound, authservID: testAuthservID,
			result: Result{
				Operation: operationProcess, Result: resultFail, Outcome: DispositionReject,
				Actions: []Action{{Kind: ActionAddHeader, Name: headerAuthResults, Value: testAuthservID + "; dkim2=fail"}},
			},
		},
		{
			name: "arbitrary field rejected", mode: modeInbound,
			result: Result{
				Operation: operationProcess, Result: resultPass, Outcome: DispositionAccept,
				Actions: []Action{{Kind: ActionAddHeader, Name: "X-Injected", Value: "value"}},
			},
		},
		{
			name: "fold injection rejected", mode: modeOriginator,
			result: Result{
				Operation: operationSign, Result: resultPass, Outcome: DispositionAccept,
				Actions: []Action{
					{Kind: ActionAddHeader, Name: headerMessage, Value: " v=1\r\n injected"},
					originator[1],
				},
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := validResult(testCase.result, testCase.mode, testCase.authservID); got != testCase.valid {
				t.Fatalf("validResult()=%t, want %t", got, testCase.valid)
			}
		})
	}
}

// TestAuthenticationConflictRejectsFalsePrefixAndAcceptsLegalFolding proves authority matching.
func TestAuthenticationConflictRejectsFalsePrefixAndAcceptsLegalFolding(t *testing.T) {
	headers := []headerField{
		{name: []byte(headerAuthResults), value: []byte(" mx.example.attacker; dkim=pass")},
		{name: []byte(headerAuthResults), value: []byte("\r\n\tmx.example; dkim=pass")},
	}
	if !authenticationConflict(headers, "mx.example") {
		t.Fatal("folded exact authserv-id conflict was not detected")
	}
	if authenticationConflict(headers[:1], "mx.example") {
		t.Fatal("false-prefix authserv-id was treated as local authority")
	}
	for _, value := range [][]byte{
		[]byte(" (edge) mx.example (comment) 1; dkim=pass"),
		[]byte(" \"mx.example\" 1; dkim=pass"),
		[]byte("\r\n\t(comment) mx.example; dkim=pass"),
	} {
		if !authenticationConflict(
			[]headerField{{name: []byte(headerAuthResults), value: value}},
			testAuthservID,
		) {
			t.Fatalf("RFC 8601 local authority conflict missed for %q", value)
		}
	}
}

// TestAuthenticationConflictMatchesEquivalentALabelAndULabel proves RFC 8601
// trust-boundary comparison cannot be bypassed with an EAI U-label spelling.
func TestAuthenticationConflictMatchesEquivalentALabelAndULabel(t *testing.T) {
	for _, value := range [][]byte{
		[]byte(" bücher.example; dkim=pass"),
		[]byte(" \"bücher.example\"; dkim=pass"),
	} {
		if !authenticationConflict(
			[]headerField{{name: []byte(headerAuthResults), value: value}},
			"xn--bcher-kva.example",
		) {
			t.Fatalf("IDNA-equivalent local authority conflict missed for %q", value)
		}
	}
}

// TestAuthenticationResultsReplacementIsPreSerializedInRFCOrder proves
// forged local fields are deleted safely before one top insertion.
func TestAuthenticationResultsReplacementIsPreSerializedInRFCOrder(t *testing.T) {
	session := testSession(t, &testHandler{}, false, modeInbound, testAuthservID)
	frames, err := session.serializeResult(
		Result{
			Operation: operationProcess,
			Result:    resultPass,
			Outcome:   DispositionAccept,
			Actions: []Action{{
				Kind:  ActionAddHeader,
				Name:  headerAuthResults,
				Value: testAuthservID + "; dkim2=pass",
			}},
		},
		[]uint32{1, 3},
	)
	if err != nil || len(frames) != 4 {
		t.Fatalf("serializeResult() frames=%x error=%v", frames, err)
	}
	wantCommands := []byte{
		replyChangeHeader,
		replyChangeHeader,
		replyInsertHeader,
		replyAccept,
	}
	for index, want := range wantCommands {
		if len(frames[index]) < 5 || frames[index][4] != want ||
			index < 3 && len(frames[index]) < 9 {
			t.Fatalf("frame %d command=%x, want=%x", index, frames[index], want)
		}
	}
	if binary.BigEndian.Uint32(frames[0][5:9]) != 3 ||
		binary.BigEndian.Uint32(frames[1][5:9]) != 1 ||
		binary.BigEndian.Uint32(frames[2][5:9]) != 0 {
		t.Fatalf("replacement indexes=%d,%d,%d",
			binary.BigEndian.Uint32(frames[0][5:9]),
			binary.BigEndian.Uint32(frames[1][5:9]),
			binary.BigEndian.Uint32(frames[2][5:9]),
		)
	}
	wantInsertion := []byte(headerAuthResults + "\x00 " + testAuthservID + "; dkim2=pass\x00")
	if !bytes.Equal(frames[2][9:], wantInsertion) {
		t.Fatalf("replacement insertion payload=%q, want=%q", frames[2][9:], wantInsertion)
	}
}

// TestActionAndResultFormattingNeverExposeValues proves toxic mutation data is redacted.
func TestActionAndResultFormattingNeverExposeValues(t *testing.T) {
	const marker = "toxic-private-signature-marker"
	action := Action{Kind: ActionAddHeader, Name: headerDKIM2, Value: marker}
	result := Result{
		Operation: operationSign, Result: resultPass, Outcome: DispositionAccept,
		Actions: []Action{action},
	}
	for _, value := range []string{
		fmt.Sprint(action), fmt.Sprintf("%+v", action), fmt.Sprintf("%#v", action),
		fmt.Sprint(result), fmt.Sprintf("%+v", result), fmt.Sprintf("%#v", result),
	} {
		if strings.Contains(value, marker) {
			t.Fatalf("formatted mutation leaked marker: %q", value)
		}
	}
	if _, err := json.Marshal(action); err == nil {
		t.Fatal("Action JSON serialization succeeded")
	}
	if _, err := json.Marshal(result); err == nil {
		t.Fatal("Result JSON serialization succeeded")
	}
}

// foldableValue returns an unfolded header value whose Postfix-folded form
// has exactly target octets, with every physical line inside RFC 5322 limits.
func foldableValue(target int) string {
	var builder strings.Builder
	folded, line := 0, 0
	for folded < target {
		if line == 63 && target-folded > 2 {
			builder.WriteByte('\t')
			folded += 2
			line = 0
			continue
		}
		builder.WriteByte('a')
		folded++
		line++
	}
	return builder.String()
}

// TestActionFrameLimitIncludesWireOverhead proves folded values cannot exceed Milter framing.
func TestActionFrameLimitIncludesWireOverhead(t *testing.T) {
	name := headerDKIM2
	limit := maxMilterFrameLength - len(name) - 3
	base := Result{
		Operation: operationRevise, Result: resultPass, Outcome: DispositionAccept,
		Actions: []Action{{Kind: ActionAddHeader, Name: name, Value: foldableValue(limit)}},
	}
	if len(headerfold.Restore(base.Actions[0].Value)) != limit {
		t.Fatal("fixture does not fold to the exact frame limit")
	}
	if !validResult(base, modeTransit, "") {
		t.Fatal("exact maximum action frame was rejected")
	}
	base.Actions[0].Value += "a"
	if validResult(base, modeTransit, "") {
		t.Fatal("oversized action frame was accepted")
	}
}

// FuzzActionPlanAdmissionNeverPanics exercises bounded daemon-controlled values.
func FuzzActionPlanAdmissionNeverPanics(f *testing.F) {
	f.Add(operationProcess, resultPass, "accept", headerAuthResults, testAuthservID+"; dkim2=pass")
	f.Add(operationSign, resultPass, "reject", "", "")
	f.Fuzz(func(_ *testing.T, operation, result, disposition, name, value string) {
		if len(operation)+len(result)+len(disposition)+len(name)+len(value) > 1<<20 {
			return
		}
		actions := []Action(nil)
		if name != "" || value != "" {
			actions = []Action{{Kind: ActionAddHeader, Name: name, Value: value}}
		}
		_ = validResult(Result{
			Operation: operation, Result: result,
			Outcome: Disposition(disposition), Actions: actions,
		}, modeInbound, testAuthservID)
	})
}

// TestFormatAuthenticationResultsIsExactAndBounded proves the reporting projection.
func TestFormatAuthenticationResultsIsExactAndBounded(t *testing.T) {
	value, err := FormatAuthenticationResults(testAuthservID, resultTemperror)
	if err != nil || value != testAuthservID+"; dkim2=temperror" {
		t.Fatalf("FormatAuthenticationResults()=%q,%v", value, err)
	}
	for _, invalid := range []string{"", "MX.example", "-mx.example", "mx..example", strings.Repeat("a", 64) + ".example"} {
		if _, err := FormatAuthenticationResults(invalid, resultPass); err == nil {
			t.Fatalf("FormatAuthenticationResults(%q) succeeded", invalid)
		}
	}
	if _, err := FormatAuthenticationResults("mx.example", "none"); err == nil {
		t.Fatal("unknown Authentication-Results value succeeded")
	}
}

// TestInboundDiagnosticRetainsAuthorityAndOutcome binds enriched reports at EOM.
func TestInboundDiagnosticRetainsAuthorityAndOutcome(t *testing.T) {
	result := Result{Operation: operationProcess, Result: resultFail, Outcome: DispositionContinue,
		Actions: []Action{{Kind: ActionAddHeader, Name: headerAuthResults, Value: testAuthservID + "; dkim2=fail (reason=signature_mismatch)"}}}
	if !validResult(result, modeInbound, testAuthservID) {
		t.Fatal("bounded report rejected")
	}
	result.Actions[0].Value = "attacker.example; dkim2=fail (reason=signature_mismatch)"
	if validResult(result, modeInbound, testAuthservID) {
		t.Fatal("forged authority accepted")
	}
	result.Actions[0].Value = testAuthservID + "; dkim2=pass"
	if validResult(result, modeInbound, testAuthservID) {
		t.Fatal("forged outcome accepted")
	}
}

// TestValidResultConfinesNullSenderSkipToOriginatorContinue proves a skip
// reason can only accompany the mutation-free originator continue.
func TestValidResultConfinesNullSenderSkipToOriginatorContinue(t *testing.T) {
	skip := Result{
		Operation: "sign", Result: resultNone, Outcome: DispositionContinue,
		NullSenderSkip: NullSenderSkipDeliveryStatus,
	}
	if !validResult(skip, modeOriginator, "") {
		t.Fatal("originator continue with a closed skip reason was refused")
	}
	open := skip
	open.NullSenderSkip = "user@example.test"
	accepted := skip
	accepted.Outcome = DispositionAccept
	inbound := skip
	inbound.Operation = "process"
	for name, candidate := range map[string]struct {
		result Result
		mode   string
	}{
		"open reason": {open, modeOriginator}, "accept": {accepted, modeOriginator},
		"inbound": {inbound, modeInbound},
	} {
		if validResult(candidate.result, candidate.mode, "") {
			t.Fatalf("%s skip result was admitted", name)
		}
	}
}

// TestLongSignatureFieldIsRefoldedForPostfix reproduces a long (8192-bit RSA)
// DKIM2-Signature whose daemon projection is one unfolded value of several
// kilobytes. Postfix stores a Milter header value line by line, so the
// adapter must restore the library's CRLF+TAB fold points as LF+TAB; otherwise
// the queued field exceeds the RFC 5322 998-octet line limit, every DSN that
// returns it fails MIME parsing, and SMTP output breaks it at arbitrary bytes.
func TestLongSignatureFieldIsRefoldedForPostfix(t *testing.T) {
	chunk := strings.Repeat("A", 64)
	signature := strings.TrimSuffix(strings.Repeat(chunk+"\t", 22), "\t")
	value := " i=1;\tm=1;\tt=1792590164;\tmf=PHNlbmRlckBleGFtcGxlLnRlc3Q+;\trt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==;" +
		"\td=example.test;\ts=sel:rsa-sha256:" + signature + ";"
	if len(value) <= 998 {
		t.Fatalf("fixture is not over-long: %d", len(value))
	}
	session := testSession(t, &testHandler{}, false, modeOriginator, "")
	frames, err := session.serializeResult(Result{
		Operation: operationSign, Result: resultPass, Outcome: DispositionAccept,
		Actions: []Action{
			{Kind: ActionAddHeader, Name: headerMessage, Value: " v=1; m=1"},
			{Kind: ActionAddHeader, Name: headerDKIM2, Value: value},
		},
	}, nil)
	// Top placement emits the plan in reverse: DKIM2-Signature, then Message-Instance.
	if err != nil || len(frames) != 3 || len(frames[0]) < 9 || frames[0][4] != replyInsertHeader {
		t.Fatalf("serializeResult() frames=%d error=%v", len(frames), err)
	}
	if !bytes.Equal(frames[1][9:], []byte(headerMessage+"\x00 v=1; m=1\x00")) {
		t.Fatalf("short field changed: %q", frames[1][9:])
	}
	payload := frames[0][9:]
	name, rest, ok := bytes.Cut(payload, []byte{0})
	if !ok || string(name) != headerDKIM2 || !bytes.HasSuffix(rest, []byte{0}) {
		t.Fatalf("header payload framing invalid")
	}
	emitted := rest[:len(rest)-1]
	if bytes.Contains(emitted, []byte("\r")) {
		t.Fatal("Milter header value must use LF folding, never CR")
	}
	for _, line := range bytes.Split(emitted, []byte("\n")) {
		if len(line) > 998-len(headerDKIM2)-1 {
			t.Fatalf("emitted physical line has %d octets", len(line))
		}
	}
	if bytes.Count(emitted, []byte("\n\t")) != strings.Count(value, "\t") ||
		string(bytes.ReplaceAll(emitted, []byte("\n"), nil)) != value {
		t.Fatal("refolding changed the field beyond restoring fold points")
	}
}

// TestTraceFieldsArePrependedAsOneTopBlock proves Draft-08 Sections 9 and 10
// trace placement: this hop's fields are inserted with SMFIR_INSHEADER at
// index 0 in reverse plan order, so the queued top of the header block reads
// Message-Instance, DKIM2-Signature, X-DKIM2-Info in plan order directly above
// the previous top field (above the MTA's own Received field under Postfix).
func TestTraceFieldsArePrependedAsOneTopBlock(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		mode      string
		operation string
		actions   []Action
	}{
		{
			name: "originator", mode: modeOriginator, operation: operationSign,
			actions: []Action{
				{Kind: ActionAddHeader, Name: headerMessage, Value: " m=1"},
				{Kind: ActionAddHeader, Name: headerDKIM2, Value: " i=1"},
				{Kind: ActionAddHeader, Name: headerInteropInfo, Value: " info"},
			},
		},
		{
			name: "reviser", mode: modeTransit, operation: operationRevise,
			actions: []Action{
				{Kind: ActionAddHeader, Name: headerMessage, Value: " m=2"},
				{Kind: ActionAddHeader, Name: headerDKIM2, Value: " i=2"},
			},
		},
		{
			name: "forwarder", mode: modeTransit, operation: operationRevise,
			actions: []Action{{Kind: ActionAddHeader, Name: headerDKIM2, Value: " i=2"}},
		},
		{
			name: "delivery status", mode: modePostfixDSN, operation: operationDSNSign,
			actions: []Action{
				{Kind: ActionAddHeader, Name: headerMessage, Value: " m=1"},
				{Kind: ActionAddHeader, Name: headerDKIM2, Value: " i=1"},
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			session := testSession(t, &testHandler{}, false, testCase.mode, "")
			frames, err := session.serializeResult(Result{
				Operation: testCase.operation, Result: resultPass, Outcome: DispositionAccept,
				Actions: testCase.actions,
			}, nil)
			if err != nil || len(frames) != len(testCase.actions)+1 {
				t.Fatalf("serializeResult() frames=%d error=%v", len(frames), err)
			}
			// Replaying the inserts against a model header block proves the
			// resulting top-down order, independent of the emission order.
			queued := []string{"Received", "Subject"}
			for index, frame := range frames[:len(frames)-1] {
				if len(frame) < 9 || frame[4] != replyInsertHeader {
					t.Fatalf("frame %d is not SMFIR_INSHEADER: %x", index, frame)
				}
				if position := binary.BigEndian.Uint32(frame[5:9]); position != 0 {
					t.Fatalf("frame %d inserts at index %d, want 0", index, position)
				}
				name, _, ok := bytes.Cut(frame[9:], []byte{0})
				if !ok {
					t.Fatalf("frame %d lacks a name terminator", index)
				}
				queued = append([]string{string(name)}, queued...)
			}
			want := make([]string, 0, len(testCase.actions)+2)
			for _, action := range testCase.actions {
				want = append(want, action.Name)
			}
			want = append(want, "Received", "Subject")
			if strings.Join(queued, ",") != strings.Join(want, ",") {
				t.Fatalf("queued order=%v want=%v", queued, want)
			}
			if frames[len(frames)-1][4] != replyAccept {
				t.Fatal("terminal frame is not accept")
			}
		})
	}
}
