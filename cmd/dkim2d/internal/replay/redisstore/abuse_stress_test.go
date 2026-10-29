package redisstore

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	dkim2 "github.com/croessner/dkim2"
	"github.com/redis/go-redis/v9"
)

// stormResult captures one bounded provider-storm outcome.
type stormResult struct {
	cancelled bool
	check     dkim2.ReplayCheck
	err       error
}

// TestCancellationStormRacingClose preserves exact pre-dispatch and terminal
// outcomes while hundreds of callers race Close, with production nonces.
func TestCancellationStormRacingClose(t *testing.T) {
	const callers = 512
	fake := newFakeBackend()
	var dispatches atomic.Int64
	fake.reply = func([]any) *redis.Cmd {
		dispatches.Add(1)
		return redis.NewCmdResult(nil, redis.Nil)
	}
	deps := fakeDependencies(fake)
	deps.nonceSource = nil
	store, err := newStoreWithDependencies(context.Background(), testConfig(), Secrets{}, deps)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := testReplayKey(t, false)
	retention := dkim2.DefaultReplayRetention()
	start := make(chan struct{})
	results := make(chan stormResult, callers)
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
			results <- stormResult{cancelled: cancelled, check: check, err: err}
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
		t.Fatalf("Close() code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	successes := int64(0)
	for result := range results {
		if result.cancelled {
			if result.check != 0 || dkim2.ReplayErrorCodeOf(result.err) != dkim2.ReplayErrorCancelled {
				t.Fatalf("cancelled result=(%v,%q)", result.check, dkim2.ReplayErrorCodeOf(result.err))
			}
			continue
		}
		switch {
		case result.check == 0 && dkim2.ReplayErrorCodeOf(result.err) == dkim2.ReplayErrorClosed:
		case result.err == nil && result.check == dkim2.ReplayCheckFirstSeen:
			successes++
		default:
			t.Fatalf("live result=(%v,%q)", result.check, dkim2.ReplayErrorCodeOf(result.err))
		}
	}
	if dispatches.Load() != successes {
		t.Fatalf("dispatches=%d successes=%d", dispatches.Load(), successes)
	}
	if store.State() != dkim2.ReplayStoreClosed || fake.closeCalls != 1 {
		t.Fatalf("state=%v closeCalls=%d", store.State(), fake.closeCalls)
	}
}
