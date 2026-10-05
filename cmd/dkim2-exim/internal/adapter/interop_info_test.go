package adapter

import "testing"

const interopTestValue = " value"

// TestInteropInfoActionMatrix preserves the closed filter-only diagnostic order.
func TestInteropInfoActionMatrix(t *testing.T) {
	instance, _ := NewAction(ActionAddHeader, headerMessageInstance, interopTestValue)
	signature, _ := NewAction(ActionAddHeader, headerDKIM2Signature, interopTestValue)
	info, err := NewAction(ActionAddHeader, headerInteropInfo, interopTestValue)
	if err != nil {
		t.Fatal("diagnostic action rejected")
	}
	for _, operation := range []Operation{OperationSign, OperationRevise} {
		if !validPlanActions(operation, ResultPass, DispositionAccept, []Action{instance, signature, info}) {
			t.Fatal("valid interop plan rejected")
		}
		for _, actions := range [][]Action{{info}, {info, instance, signature}, {instance, info, signature}, {signature, info, info}} {
			if validPlanActions(operation, ResultPass, DispositionAccept, actions) {
				t.Fatal("invalid interop plan admitted")
			}
		}
	}
	if validPlanActions(OperationProcess, ResultPass, DispositionAccept, []Action{info}) {
		t.Fatal("inbound interop plan admitted")
	}
}
