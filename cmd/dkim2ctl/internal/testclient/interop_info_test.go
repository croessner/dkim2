package testclient

import (
	"github.com/croessner/dkim2/cmd/dkim2ctl/internal/testclient/generated"
	"testing"
)

const interopTestValue = " value"

// TestInteropInfoActionMatrix admits exactly one trailing diagnostic on accepting signing operations.
func TestInteropInfoActionMatrix(t *testing.T) {
	instance := generated.AddHeaderAction{Name: generated.MessageInstance, Type: generated.AddHeader, Value: interopTestValue}
	signature := generated.AddHeaderAction{Name: generated.DKIM2Signature, Type: generated.AddHeader, Value: interopTestValue}
	info := generated.AddHeaderAction{Name: generated.XDKIM2Info, Type: generated.AddHeader, Value: interopTestValue}
	for _, operation := range []generated.OperationResponseOperation{generated.Sign, generated.Revise, generated.DeliveryStatus} {
		if !validOperationActions(operation, generated.DispositionAccept, generated.ActionPlan{instance, signature, info}) {
			t.Fatal("valid interop plan rejected")
		}
		for _, actions := range []generated.ActionPlan{{info}, {info, instance, signature}, {instance, info, signature}, {instance, signature, info, info}} {
			if validOperationActions(operation, generated.DispositionAccept, actions) {
				t.Fatal("invalid interop order accepted")
			}
		}
		if validOperationActions(operation, generated.DispositionContinue, generated.ActionPlan{info}) {
			t.Fatal("non-accept info admitted")
		}
	}
	if !validOperationActions(generated.Revise, generated.DispositionAccept, generated.ActionPlan{signature, info}) {
		t.Fatal("unchanged revision rejected")
	}
}
