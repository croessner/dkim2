package httpjson

import (
	"testing"

	"github.com/croessner/dkim2"
)

// ceilingSizing returns the deployment sizing at the closed library ceiling.
// Tests that exercise the maximum legal request use it so their expectations
// stay anchored to the same inventory production derives.
func ceilingSizing(t testing.TB) workingSetSizing {
	t.Helper()
	sizing, err := newWorkingSetSizing(dkim2.HardMaxRawMessageBytes)
	if err != nil {
		t.Fatalf("newWorkingSetSizing(ceiling) error = %v", err)
	}
	return sizing
}

// mustSizing returns one deployment sizing or fails the test.
func mustSizing(t testing.TB, messageBytes int64) workingSetSizing {
	t.Helper()
	sizing, err := newWorkingSetSizing(messageBytes)
	if err != nil {
		t.Fatalf("newWorkingSetSizing(%d) error = %v", messageBytes, err)
	}
	return sizing
}

// ceilingSizingValue returns the ceiling sizing where no testing.TB is in
// scope. An unusable sizing stays zero-valued and fails the ledger closed.
func ceilingSizingValue() workingSetSizing {
	sizing, err := newWorkingSetSizing(dkim2.HardMaxRawMessageBytes)
	if err != nil {
		return workingSetSizing{}
	}
	return sizing
}

// ledgerWithLimit builds one ledger with an arbitrary reservation so the
// accounting mechanics can be exercised without a realistic inventory.
func ledgerWithLimit(limit uint64) (*workingSetLedger, error) {
	return newWorkingSetLedger(workingSetSizing{unitBytes: limit})
}
