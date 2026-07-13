package verify

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
)

// FuzzHistoryWalk exercises deterministic bounded authenticated descent and cancellation.
func FuzzHistoryWalk(f *testing.F) {
	f.Add([]byte(`{"b":[]}`), false)
	f.Add([]byte(`{"h":{"Subject":[{"d":["previous"]}]},"b":null}`), false)
	f.Add([]byte(`{"b":[{"c":[1,999999]}]}`), false)
	f.Add([]byte(`{"x":{"TOXIC_HISTORY_MARKER":"value"}}`), false)
	f.Add([]byte(`{"b":[]}`), true)
	f.Fuzz(func(t *testing.T, encodedRecipe []byte, cancel bool) {
		// Keep the synthetic unfurled Message-Instance fixture within RFC 5322's
		// physical-line ceiling; recipe parsing itself owns larger-input abuse tests.
		if len(encodedRecipe) > 512 {
			t.Skip()
		}
		current, collection := historyFixture(t, string(encodedRecipe), []byte("Subject:previous\r\n\r\n"), testHistorySHA256)
		coordinator := mustHistoryCoordinator(t, HistoryLimits{})
		ctx := context.Background()
		if cancel {
			cancelled, stop := context.WithCancel(ctx)
			stop()
			ctx = cancelled
		}
		before, materializeErr := current.Materialize()
		if materializeErr != nil {
			t.Fatal("history fixture state did not materialize")
		}
		first, firstErr := coordinator.Walk(ctx, historyPassResult(2), collection, current)
		second, secondErr := coordinator.Walk(ctx, historyPassResult(2), collection, current)
		assertHistoryFuzzContract(t, first, firstErr, cancel)
		assertHistoryFuzzContract(t, second, secondErr, cancel)
		if historyFuzzErrorCode(firstErr) != historyFuzzErrorCode(secondErr) || !reflect.DeepEqual(first, second) {
			t.Fatal("history descent is not deterministic")
		}
		if first.Valid() {
			exposed := first.Transitions()
			if len(exposed) > 0 {
				exposed[0] = HistoryTransition{}
			}
			if !reflect.DeepEqual(first, second) {
				t.Fatal("history transition accessor exposed owned storage")
			}
		}
		after, materializeErr := current.Materialize()
		if materializeErr != nil || !bytes.Equal(before.RawBytes(), after.RawBytes()) {
			t.Fatal("history descent mutated its initial state")
		}
	})
}

// assertHistoryFuzzContract verifies disjoint walk/error outcomes and bounded diagnostics.
func assertHistoryFuzzContract(t *testing.T, walk HistoryWalk, err error, cancelled bool) {
	t.Helper()
	if cancelled {
		if walk.Valid() || !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled history descent returned authenticated facts")
		}
		return
	}
	if err != nil {
		var typed *Error
		if walk.Valid() || !errors.As(err, &typed) || len(err.Error()) > 512 {
			t.Fatal("history descent returned an incoherent direct error")
		}
		return
	}
	if !walk.Valid() || !walk.Usage().Valid() {
		t.Fatal("history descent returned invalid authenticated facts")
	}
}

// historyFuzzErrorCode extracts only a closed verification error code.
func historyFuzzErrorCode(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code()
	}
	return ""
}
