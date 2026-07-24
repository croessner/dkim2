package valkey

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	dkim2 "github.com/croessner/dkim2"
	valkeygo "github.com/valkey-io/valkey-go"
)

// TestValkeyCancellationStormRacingClose preserves exact pre-dispatch and terminal outcomes.
func TestValkeyCancellationStormRacingClose(t *testing.T) {
	const callers = 512

	client := &stressCommandClient{message: cachedMessage(t, '+', "OK")}
	store := mustCommandStore(t, client)
	key := validReplayKey(t)
	retention := dkim2.DefaultReplayRetention()
	start := make(chan struct{})
	results := make(chan valkeyStormResult, callers)

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
			results <- valkeyStormResult{
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
		t.Fatalf("Close() error code = %q", dkim2.ReplayErrorCodeOf(err))
	}
	successes := int64(0)
	for result := range results {
		if result.cancelled {
			if result.check != 0 ||
				dkim2.ReplayErrorCodeOf(result.err) != dkim2.ReplayErrorCancelled {
				t.Fatalf("cancelled result = (%q,%q)",
					result.check, dkim2.ReplayErrorCodeOf(result.err))
			}
			continue
		}
		switch {
		case dkim2.ReplayErrorCodeOf(result.err) == dkim2.ReplayErrorClosed &&
			result.check == 0:
		case result.err == nil && result.check == dkim2.ReplayCheckFirstSeen:
			successes++
		default:
			t.Fatalf("live result = (%q,%q)",
				result.check, dkim2.ReplayErrorCodeOf(result.err))
		}
	}
	if client.dispatches.Load() != successes {
		t.Fatalf("dispatches = %d, successes = %d", client.dispatches.Load(), successes)
	}
	if state := store.State(); state != dkim2.ReplayStoreClosed {
		t.Fatalf("state = %q, want closed", state)
	}
}

// valkeyStormResult captures one bounded provider-storm outcome.
type valkeyStormResult struct {
	cancelled bool
	check     dkim2.ReplayCheck
	err       error
}

// stressCommandClient supplies one independent authoritative result per dispatch.
type stressCommandClient struct {
	builds     atomic.Int64
	dispatches atomic.Int64
	message    valkeygo.ValkeyMessage
}

// BuildSet returns one non-retryable command without retaining protected inputs.
func (c *stressCommandClient) BuildSet(string, string, int64) command {
	c.builds.Add(1)
	return fakeCommand{}
}

// Do returns one fresh result reader so concurrent decoding never shares counters.
func (c *stressCommandClient) Do(context.Context, command) resultReader {
	c.dispatches.Add(1)
	return &fakeResult{raw: "OK", message: c.message}
}
