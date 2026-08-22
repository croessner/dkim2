package milter

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
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

// TestActionFrameLimitIncludesWireOverhead proves values cannot exceed Milter framing.
func TestActionFrameLimitIncludesWireOverhead(t *testing.T) {
	name := headerDKIM2
	limit := maxMilterFrameLength - len(name) - 3
	base := Result{
		Operation: operationRevise, Result: resultPass, Outcome: DispositionAccept,
		Actions: []Action{{Kind: ActionAddHeader, Name: name, Value: strings.Repeat("a", limit)}},
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
