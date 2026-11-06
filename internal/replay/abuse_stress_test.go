package replay

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestMemoryCancellationStormRacingClose preserves bounded outcomes under hostile concurrency.
func TestMemoryCancellationStormRacingClose(t *testing.T) {
	const callers = 512

	store := newTestMemoryStore(
		t,
		Limits{MaxEntries: 1, MaxWaiters: callers, PruneBudget: 1},
		newTestClock(time.Unix(1_700_000_000, 0)),
	)
	key := testReplayKey(0x71)
	retention := mustRetention(t, time.Second)
	start := make(chan struct{})
	results := make(chan memoryStormResult, callers)

	var wait sync.WaitGroup
	wait.Add(callers)
	for index := range callers {
		go func(cancelled bool) {
			defer wait.Done()
			ctx := context.Background()
			cancel := func() {}
			if cancelled {
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			defer cancel()
			<-start
			check, err := store.CheckAndRemember(ctx, key, retention)
			results <- memoryStormResult{
				cancelled: cancelled,
				check:     check,
				err:       err,
			}
		}(index%3 == 0)
	}

	closeResult := make(chan error, 1)
	go func() {
		<-start
		closeResult <- store.Close(context.Background())
	}()
	close(start)
	wait.Wait()
	close(results)

	if err := <-closeResult; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	var firstSeen atomic.Int64
	for result := range results {
		if result.cancelled {
			if result.check != 0 || ErrorCodeOf(result.err) != ErrorCodeCancelled {
				t.Fatalf("cancelled result = (%q,%q)", result.check, ErrorCodeOf(result.err))
			}
			continue
		}
		switch {
		case ErrorCodeOf(result.err) == ErrorCodeClosed && result.check == 0:
		case result.err == nil && result.check == CheckFirstSeen:
			firstSeen.Add(1)
		case result.err == nil && result.check == CheckReplayed:
		default:
			t.Fatalf("live result = (%q,%q)", result.check, ErrorCodeOf(result.err))
		}
	}
	if firstSeen.Load() > 1 {
		t.Fatalf("first-seen winners = %d, want at most one", firstSeen.Load())
	}
	if state := store.State(); state != StoreClosed {
		t.Fatalf("state = %q, want closed", state)
	}
	if entries, nodes := store.testCounts(); entries != 0 || nodes != 0 {
		t.Fatalf("closed counts = %d/%d, want 0/0", entries, nodes)
	}
}

// memoryStormResult captures one bounded cancellation-storm outcome.
type memoryStormResult struct {
	cancelled bool
	check     Check
	err       error
}
