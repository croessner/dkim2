package milter

import "testing"

const interopTestValue = " value"

// TestInteropInfoActionMatrix keeps optional metadata within successful outgoing plans.
func TestInteropInfoActionMatrix(t *testing.T) {
	instance := Action{Kind: ActionAddHeader, Name: headerMessage, Value: interopTestValue}
	signature := Action{Kind: ActionAddHeader, Name: headerDKIM2, Value: interopTestValue}
	info := Action{Kind: ActionAddHeader, Name: headerInteropInfo, Value: interopTestValue}
	for _, mode := range []string{modeOriginator, modeTransit, modePostfixDSN} {
		operation, _ := operationForMode(mode)
		result := Result{Operation: operation, Result: resultPass, Outcome: DispositionAccept, Actions: []Action{instance, signature, info}}
		if !validResult(result, mode, "") {
			t.Fatal("valid diagnostic plan rejected")
		}
		for _, actions := range [][]Action{{info}, {info, instance, signature}, {instance, info, signature}, {signature, info, info}} {
			result.Actions = actions
			if validResult(result, mode, "") {
				t.Fatal("invalid diagnostic plan accepted")
			}
		}
		result.Outcome = DispositionContinue
		result.Actions = []Action{info}
		if validResult(result, mode, "") {
			t.Fatal("continue diagnostic admitted")
		}
	}
	inbound := Result{Operation: operationProcess, Result: resultPass, Outcome: DispositionAccept, Actions: []Action{info}}
	if validResult(inbound, modeInbound, "mx.example") {
		t.Fatal("inbound diagnostic admitted")
	}
}
