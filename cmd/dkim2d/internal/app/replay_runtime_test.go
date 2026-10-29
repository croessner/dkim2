package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/observability"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/replay/redisstore"
)

const runtimeTestGeneration = "0123456789abcdef0123456789abcdef"

// newReplayRuntime gives focused tests one independent live rollback budget.
func newReplayRuntime(
	acquisitionCtx context.Context,
	material replayMaterialSource,
	factories replayRuntimeFactories,
) (*ReplayRuntime, error) {
	var rollbackCancel context.CancelFunc
	runtime, err := newReplayRuntimeWithRollback(
		acquisitionCtx,
		func() context.Context {
			ctx, cancel := context.WithTimeout(context.Background(), replayRollbackLimit)
			rollbackCancel = cancel
			return ctx
		},
		material,
		factories,
	)
	if rollbackCancel != nil {
		rollbackCancel()
	}
	return runtime, err
}

// closeReplayRuntimeBounded gives cleanup one explicit test-owned five-second bound.
func closeReplayRuntimeBounded(runtime *ReplayRuntime) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return runtime.Close(ctx)
}

// runtimeMaterialFake lends fresh, callback-bounded protected clones.
type runtimeMaterialFake struct {
	snapshot         config.Snapshot
	hmac             []byte
	password         []byte
	sentinelPassword []byte
	certificatePEM   []byte
	keyPEM           []byte
	roots            [][]byte

	mu            sync.Mutex
	materialCalls int
	materialErr   error
	afterMaterial func()
}

// Snapshot returns the immutable effective configuration.
func (f *runtimeMaterialFake) Snapshot() config.Snapshot { return f.snapshot }

// UseReplayMaterial lends independent complete startup material and zeroes
// every lent clone after the callback, mirroring the protected config borrow.
func (f *runtimeMaterialFake) UseReplayMaterial(
	use func([]byte, redisstore.Secrets) error,
) error {
	f.mu.Lock()
	f.materialCalls++
	borrowErr := f.materialErr
	hmac := append([]byte(nil), f.hmac...)
	secrets := redisstore.Secrets{
		Password:             append([]byte(nil), f.password...),
		SentinelPassword:     append([]byte(nil), f.sentinelPassword...),
		ClientCertificatePEM: append([]byte(nil), f.certificatePEM...),
		ClientKeyPEM:         append([]byte(nil), f.keyPEM...),
		RootsDER:             runtimeCloneDER(f.roots),
	}
	after := f.afterMaterial
	f.mu.Unlock()
	if borrowErr != nil {
		return borrowErr
	}
	err := use(hmac, secrets)
	clear(hmac)
	clear(secrets.Password)
	clear(secrets.SentinelPassword)
	clear(secrets.ClientCertificatePEM)
	clear(secrets.ClientKeyPEM)
	runtimeClearDER(secrets.RootsDER)
	if after != nil {
		after()
	}
	return err
}

// Calls returns the synchronized startup borrow count.
func (f *runtimeMaterialFake) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.materialCalls
}

// runtimeAuthorityFake is one deterministic production-authority double.
type runtimeAuthorityFake struct {
	mu               sync.Mutex
	state            dkim2.ReplayStoreState
	ready            bool
	closeCalls       int
	readyCalls       int
	probeCalls       int
	probeResponses   []error
	probeHook        func()
	closeErr         error
	closeHook        func()
	closeContextHook func(context.Context)
}

// CheckAndRemember returns a deterministic first-seen result.
func (s *runtimeAuthorityFake) CheckAndRemember(
	context.Context,
	dkim2.ReplayKey,
	dkim2.ReplayRetention,
) (dkim2.ReplayCheck, error) {
	return dkim2.ReplayCheckFirstSeen, nil
}

// State returns the synchronized lifecycle state.
func (s *runtimeAuthorityFake) State() dkim2.ReplayStoreState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Close records release and publishes closed unless an error is injected.
func (s *runtimeAuthorityFake) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeCalls++
	if s.closeContextHook != nil {
		s.closeContextHook(ctx)
	}
	if s.closeHook != nil {
		s.closeHook()
	}
	if s.closeErr != nil {
		return s.closeErr
	}
	s.state = dkim2.ReplayStoreClosed
	return nil
}

// TestReplayRuntimePostCallContextPrecedenceUsesExactCallerTerminalState proves final checks.
func TestReplayRuntimePostCallContextPrecedenceUsesExactCallerTerminalState(t *testing.T) {
	responses := []error{
		nil,
		dkim2.NewReplayError(dkim2.ReplayErrorUnavailable),
		errors.New("protected provider result marker"),
	}
	for index, response := range responses {
		t.Run(fmt.Sprintf("cancel-%d", index), func(t *testing.T) {
			material := runtimeMaterial(t, runtimeRedisYAML())
			authority := &runtimeAuthorityFake{
				state:          dkim2.ReplayStoreReady,
				ready:          true,
				probeResponses: []error{response},
			}
			runtime := runtimeWithAuthority(t, material, authority)
			ctx, cancel := context.WithCancel(context.Background())
			authority.probeHook = cancel
			if err := runtime.ProbeHealth(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("post-call cancellation returned %v", err)
			}
			_ = closeReplayRuntimeBounded(runtime)
		})
	}
	t.Run("deadline-after-unknown-result", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeRedisYAML())
		authority := &runtimeAuthorityFake{
			state:          dkim2.ReplayStoreReady,
			ready:          true,
			probeResponses: []error{errors.New("protected provider result marker")},
		}
		runtime := runtimeWithAuthority(t, material, authority)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		authority.probeHook = func() { <-ctx.Done() }
		if err := runtime.ProbeHealth(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("post-call deadline returned %v", err)
		}
		if authority.Probes() != 1 {
			t.Fatal("deadline case did not exercise post-probe precedence")
		}
		_ = closeReplayRuntimeBounded(runtime)
	})
}

// TestReplayRuntimeCloseCollapsesErrorsAndPreservesContextPrecedence proves release semantics.
func TestReplayRuntimeCloseCollapsesErrorsAndPreservesContextPrecedence(t *testing.T) {
	t.Run("store-error-still-closes-deriver", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeRedisYAML())
		authority := &runtimeAuthorityFake{
			state:    dkim2.ReplayStoreReady,
			ready:    true,
			closeErr: errors.New("protected close marker"),
		}
		runtime := runtimeWithAuthority(t, material, authority)
		deriver := runtime.state.deriver
		if err := closeReplayRuntimeBounded(runtime); !IsReplayRuntimeError(err) {
			t.Fatalf("Close() returned %v", err)
		}
		if _, err := deriver.Derive(context.Background(), dkim2.ReplayIdentity{}); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorClosed {
			t.Fatal("store close error prevented deriver release")
		}
	})
	t.Run("cancellation-during-store-close", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeRedisYAML())
		authority := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: true}
		runtime := runtimeWithAuthority(t, material, authority)
		deriver := runtime.state.deriver
		parent, parentCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer parentCancel()
		ctx, cancel := context.WithCancel(parent)
		authority.closeHook = cancel
		if err := runtime.Close(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("Close() returned %v", err)
		}
		if _, err := deriver.Derive(context.Background(), dkim2.ReplayIdentity{}); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorClosed {
			t.Fatal("cancellation during store close retained the acquired deriver")
		}
		authority.closeHook = nil
		if err := closeReplayRuntimeBounded(runtime); err != nil {
			t.Fatalf("retry Close() failed: %v", err)
		}
	})
}

// TestReplayRuntimeCloseContextMatrix freezes join and caller-terminal precedence.
func TestReplayRuntimeCloseContextMatrix(t *testing.T) {
	testReplayRuntimeCloseOwnershipMatrix(t)
	testReplayRuntimeCloseCompletionMatrix(t)
}

// testReplayRuntimeCloseOwnershipMatrix proves ownership is either untouched or released exactly once.
func testReplayRuntimeCloseOwnershipMatrix(t *testing.T) {
	t.Run("terminal-before-ownership", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeRedisYAML())
		authority := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: true}
		runtime := runtimeWithAuthority(t, material, authority)
		parent, parentCancel := context.WithTimeout(context.Background(), time.Second)
		defer parentCancel()
		ctx, cancel := context.WithCancel(parent)
		cancel()
		if err := runtime.Close(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-close cancellation returned %v", err)
		}
		if authority.closeCalls != 0 {
			t.Fatal("terminal caller context changed ownership")
		}
		if err := closeReplayRuntimeBounded(runtime); err != nil {
			t.Fatalf("valid retry failed: %v", err)
		}
	})
	t.Run("malformed-bound-before-ownership", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeRedisYAML())
		authority := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: true}
		runtime := runtimeWithAuthority(t, material, authority)
		var typedNil *hostileReplayContext
		if err := runtime.Close(typedNil); !IsReplayRuntimeError(err) {
			t.Fatalf("typed-nil bound returned %v", err)
		}
		if err := runtime.Close(futureDeadlineNilDoneReplayContext{}); !IsReplayRuntimeError(err) {
			t.Fatalf("malformed bound returned %v", err)
		}
		if err := runtime.Close(newClosedDoneNilErrorReplayContext()); !IsReplayRuntimeError(err) {
			t.Fatalf("contradictory closed Done returned %v", err)
		}
		if authority.closeCalls != 0 {
			t.Fatal("malformed bound changed ownership")
		}
		if err := closeReplayRuntimeBounded(runtime); err != nil {
			t.Fatalf("valid retry failed: %v", err)
		}
	})
	t.Run("pre-child-start-failure-reopens-and-wakes-waiter", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeRedisYAML())
		authority := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: true}
		runtime := runtimeWithAuthority(t, material, authority)
		realStarter := runtime.state.startCleanup
		entered := make(chan struct{})
		release := make(chan struct{})
		var calls atomic.Int32
		runtime.state.startCleanup = func(
			bound replayCleanupBound,
			store dkim2.ManagedReplayStore,
			deriver *dkim2.ReplayDeriver,
			closeDeriver func(context.Context) error,
		) (<-chan bool, error) {
			if calls.Add(1) == 1 {
				close(entered)
				<-release
				return nil, &ReplayRuntimeError{}
			}
			return realStarter(bound, store, deriver, closeDeriver)
		}
		first := make(chan error, 1)
		second := make(chan error, 1)
		go func() { first <- closeReplayRuntimeBounded(runtime) }()
		<-entered
		go func() { second <- closeReplayRuntimeBounded(runtime) }()
		close(release)
		if err := <-first; !IsReplayRuntimeError(err) {
			t.Fatalf("pre-child failure returned %v", err)
		}
		if err := <-second; err != nil {
			t.Fatalf("woken waiter retry failed: %v", err)
		}
		if authority.closeCalls != 1 || calls.Load() != 2 {
			t.Fatalf(
				"retry ownership calls store=%d starter=%d",
				authority.closeCalls,
				calls.Load(),
			)
		}
	})
	t.Run("post-freeze-cancellation-cannot-skip-owners", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeRedisYAML())
		authority := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: true}
		runtime := runtimeWithAuthority(t, material, authority)
		deriver := runtime.state.deriver
		ctx := newSingleSnapshotReplayContext(true)
		if err := runtime.Close(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("post-freeze cancellation returned %v", err)
		}
		if authority.closeCalls != 1 {
			t.Fatalf("post-freeze cancellation closed store %d times", authority.closeCalls)
		}
		if _, err := deriver.Derive(context.Background(), dkim2.ReplayIdentity{}); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorClosed {
			t.Fatal("post-freeze cancellation retained the deriver")
		}
		if ctx.deadlineCalls.Load() != 1 || ctx.doneCalls.Load() != 1 {
			t.Fatalf(
				"cleanup re-read frozen methods deadline=%d done=%d",
				ctx.deadlineCalls.Load(),
				ctx.doneCalls.Load(),
			)
		}
		if err := closeReplayRuntimeBounded(runtime); err != nil || authority.closeCalls != 1 {
			t.Fatalf("terminal retry changed ownership: %v/%d", err, authority.closeCalls)
		}
	})
}

// testReplayRuntimeCloseCompletionMatrix proves joined completion and caller precedence.
func testReplayRuntimeCloseCompletionMatrix(t *testing.T) {
	t.Run("proven-child-completion-wins-deadline-edge", func(t *testing.T) {
		done := make(chan struct{})
		close(done)
		for range 100 {
			result := make(chan error, 1)
			result <- nil
			remaining, failed := waitReplayCleanupPhase(
				closedDoneReplayContext{done: done},
				result,
			)
			if remaining != nil || failed {
				t.Fatal("simultaneous completion was classified as a phase timeout")
			}
		}
	})
	t.Run("expired-frozen-bound-still-starts-child-owners", func(t *testing.T) {
		store := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: true}
		deriver, err := dkim2.NewReplayDeriver(
			[]byte("0123456789abcdef0123456789abcdef"),
			1,
		)
		if err != nil {
			t.Fatalf("NewReplayDeriver() failed: %v", err)
		}
		var deriverCalls atomic.Int32
		var deriverSawDeadline atomic.Bool
		bound := replayCleanupBound{
			caller: context.Background(), deadline: time.Now().Add(-time.Second),
			done: make(chan struct{}),
		}
		result, err := startReplayRuntimeCleanup(
			bound,
			store,
			deriver,
			func(ctx context.Context) error {
				deriverCalls.Add(1)
				deriverSawDeadline.Store(errors.Is(ctx.Err(), context.DeadlineExceeded))
				return ctx.Err()
			},
		)
		if err != nil {
			t.Fatalf("expired frozen cleanup failed to start: %v", err)
		}
		select {
		case <-result:
		case <-time.After(time.Second):
			t.Fatal("expired frozen cleanup did not join child owners")
		}
		if store.closeCalls != 1 {
			t.Fatalf("expired frozen cleanup closed store %d times", store.closeCalls)
		}
		if deriverCalls.Load() != 1 || !deriverSawDeadline.Load() {
			t.Fatal("expired frozen cleanup did not invoke the deriver exactly once")
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Second)
		defer cleanupCancel()
		if err := deriver.Close(cleanupCtx); err != nil {
			t.Fatalf("test deriver cleanup failed: %v", err)
		}
	})
	t.Run("joined-cleanup-preserves-exact-terminal-identity", func(t *testing.T) {
		done := make(chan struct{})
		close(done)
		parent, parentCancel := context.WithTimeout(context.Background(), time.Second)
		defer parentCancel()
		cancelled, cancel := context.WithCancel(parent)
		cancel()
		cancelledBound := replayCleanupBound{
			caller: cancelled, deadline: time.Now().Add(time.Second), done: cancelled.Done(),
		}
		if err := waitReplayRuntimeWaiter(cancelledBound, done); !errors.Is(err, context.Canceled) {
			t.Fatalf("joined cancellation returned %v", err)
		}
		expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer expire()
		expiredBound := replayCleanupBound{
			caller: expired, deadline: time.Now().Add(-time.Second), done: expired.Done(),
		}
		if err := waitReplayRuntimeWaiter(expiredBound, done); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("joined deadline returned %v", err)
		}
	})
	t.Run("terminal-state-repeats-without-new-ownership", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeRedisYAML())
		authority := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: true}
		runtime := runtimeWithAuthority(t, material, authority)
		if err := closeReplayRuntimeBounded(runtime); err != nil {
			t.Fatalf("first Close() failed: %v", err)
		}
		parent, parentCancel := context.WithTimeout(context.Background(), time.Second)
		defer parentCancel()
		cancelled, cancel := context.WithCancel(parent)
		cancel()
		for range 2 {
			if err := runtime.Close(cancelled); !errors.Is(err, context.Canceled) {
				t.Fatalf("repeated terminal Close() returned %v", err)
			}
		}
		if authority.closeCalls != 1 {
			t.Fatalf("terminal retries changed store calls to %d", authority.closeCalls)
		}
	})
	t.Run("already-complete-still-preserves-late-cancellation", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeRedisYAML())
		authority := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: true}
		runtime := runtimeWithAuthority(t, material, authority)
		if err := closeReplayRuntimeBounded(runtime); err != nil {
			t.Fatalf("first Close() failed: %v", err)
		}
		ctx := newSingleSnapshotReplayContext(true)
		if err := runtime.Close(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("complete-state cancellation returned %v", err)
		}
		if authority.closeCalls != 1 {
			t.Fatalf("complete-state call changed ownership: %d", authority.closeCalls)
		}
	})
	t.Run("child-cleanup-contexts-drop-caller-values", func(t *testing.T) {
		type markerKey struct{}
		material := runtimeMaterial(t, runtimeRedisYAML())
		var storeClean, deriverClean atomic.Bool
		authority := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: true}
		authority.closeContextHook = func(ctx context.Context) {
			storeClean.Store(ctx.Value(markerKey{}) == nil)
		}
		runtime := runtimeWithAuthority(t, material, authority)
		deriver := runtime.state.deriver
		runtime.state.closeDeriver = func(ctx context.Context) error {
			deriverClean.Store(ctx.Value(markerKey{}) == nil)
			return deriver.Close(ctx)
		}
		parent, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		ctx := context.WithValue(parent, markerKey{}, "protected-context-marker")
		if err := runtime.Close(ctx); err != nil {
			t.Fatalf("Close() failed: %v", err)
		}
		if !storeClean.Load() || !deriverClean.Load() {
			t.Fatal("caller values reached an owned child cleanup")
		}
	})
}

// Probe records one health probe and returns the scripted response.
func (s *runtimeAuthorityFake) Probe(context.Context) error {
	s.mu.Lock()
	s.probeCalls++
	index := s.probeCalls - 1
	hook := s.probeHook
	var response error
	if index < len(s.probeResponses) {
		response = s.probeResponses[index]
	}
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
	return response
}

// Probes returns the synchronized probe count.
func (s *runtimeAuthorityFake) Probes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.probeCalls
}

// AuthorityReady records delegation and returns the configured fact.
func (s *runtimeAuthorityFake) AuthorityReady() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readyCalls++
	return s.ready
}

// runtimeFixedClock supplies one stable memory-store clock.
type runtimeFixedClock struct{ now time.Time }

// Now returns the injected instant.
func (c *runtimeFixedClock) Now() time.Time { return c.now }

// TestReplayRuntimeDisabledConstructsOnlyDisabledStore proves backend isolation.
func TestReplayRuntimeDisabledConstructsOnlyDisabledStore(t *testing.T) {
	material := runtimeMaterial(t, runtimeDisabledYAML())
	var disabledCalls, deriverCalls, memoryCalls, productionCalls atomic.Int32
	factories := replayRuntimeFactories{
		newDisabled: func() dkim2.ManagedReplayStore {
			disabledCalls.Add(1)
			return dkim2.NewReplayDisabledStore()
		},
		newDeriver: func(secret []byte, epoch uint32) (*dkim2.ReplayDeriver, error) {
			deriverCalls.Add(1)
			return dkim2.NewReplayDeriver(secret, epoch)
		},
		newMemory: func(cfg dkim2.ReplayMemoryConfig) (*dkim2.ReplayMemoryStore, error) {
			memoryCalls.Add(1)
			return dkim2.NewReplayMemoryStore(cfg)
		},
		newProduction: func(
			context.Context,
			redisstore.Config,
			redisstore.Secrets,
		) (replayAuthorityStore, error) {
			productionCalls.Add(1)
			return nil, errors.New("must not run")
		},
		clock: &runtimeFixedClock{now: time.Unix(1, 0)},
	}
	runtime, err := newReplayRuntime(context.Background(), material, factories)
	if err != nil || runtime == nil {
		t.Fatalf("newReplayRuntime() = (%v, %v)", runtime, err)
	}
	if disabledCalls.Load() != 1 || deriverCalls.Load() != 0 ||
		memoryCalls.Load() != 0 || productionCalls.Load() != 0 {
		t.Fatal("disabled backend crossed a forbidden construction boundary")
	}
	if material.Calls() != 0 {
		t.Fatal("disabled backend borrowed protected material")
	}
	if !runtime.AuthorityReady() || runtime.HealthInterval() != 0 {
		t.Fatal("disabled backend readiness or interval is wrong")
	}
	if err := closeReplayRuntimeBounded(runtime); err != nil || runtime.AuthorityReady() {
		t.Fatal("disabled backend did not close exactly")
	}
}

// TestReplayRuntimeDisabledRejectsTypedNilStore proves pre-method nil containment.
func TestReplayRuntimeDisabledRejectsTypedNilStore(t *testing.T) {
	material := runtimeMaterial(t, runtimeDisabledYAML())
	var store *runtimeAuthorityFake
	runtime, err := newReplayRuntime(
		context.Background(),
		material,
		replayRuntimeFactories{
			newDisabled: func() dkim2.ManagedReplayStore { return store },
		},
	)
	if runtime != nil || !IsReplayRuntimeError(err) {
		t.Fatalf("typed-nil disabled factory returned (%v, %v)", runtime, err)
	}
}

// TestReplayRuntimeMemoryProjectsExactParametersAndOwnedClones proves composition.
func TestReplayRuntimeMemoryProjectsExactParametersAndOwnedClones(t *testing.T) {
	material := runtimeMaterial(t, runtimeMemoryYAML())
	clock := &runtimeFixedClock{now: time.Unix(1_700_000_000, 0)}
	var captured dkim2.ReplayMemoryConfig
	var memoryCalls, deriverCalls atomic.Int32
	factories := replayRuntimeFactories{
		newDeriver: func(secret []byte, epoch uint32) (*dkim2.ReplayDeriver, error) {
			deriverCalls.Add(1)
			return dkim2.NewReplayDeriver(secret, epoch)
		},
		newMemory: func(cfg dkim2.ReplayMemoryConfig) (*dkim2.ReplayMemoryStore, error) {
			memoryCalls.Add(1)
			captured = cfg
			return dkim2.NewReplayMemoryStore(cfg)
		},
		newDisabled: newDisabledReplayStore,
		clock:       clock,
	}
	runtime, err := newReplayRuntime(context.Background(), material, factories)
	if err != nil || runtime == nil {
		t.Fatalf("newReplayRuntime() = (%v, %v)", runtime, err)
	}
	replayConfig := material.snapshot.Replay()
	expectedLimits := replayLimits(replayConfig)
	if captured.Limits != expectedLimits || captured.Clock != clock {
		t.Fatal("memory construction changed exact limits or injected clock")
	}
	if runtime.state.coordinator.state.retention.Duration() != replayConfig.Retention() ||
		deriverCalls.Load() != 1 || memoryCalls.Load() != 1 {
		t.Fatal("memory construction changed exact retention or factory count")
	}
	if material.Calls() != 1 || runtime.HealthInterval() != 0 {
		t.Fatal("memory backend used the wrong protected-material boundary")
	}
	if !runtime.AuthorityReady() {
		t.Fatal("ready memory store reported unavailable")
	}
	outcome, err := runtime.Coordinate(
		context.Background(),
		authenticReplayDomain(t, [][]byte{[]byte("<one@example.net>")}, config.PolicyStrict),
	)
	if err != nil || outcome.Class() != ReplayResultFirstSeen {
		t.Fatalf("post-borrow memory use = (%q, %v)", outcome.Class(), err)
	}
	if err := closeReplayRuntimeBounded(runtime); err != nil || runtime.AuthorityReady() {
		t.Fatal("memory owners did not close")
	}
}

// TestReplayRuntimeCarriesDirectDeliveryCountingPolicy proves the configured
// local replay policy reaches the runtime that builds authenticators.
func TestReplayRuntimeCarriesDirectDeliveryCountingPolicy(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		document := runtimeMemoryYAML()
		if enabled {
			document = strings.Replace(document, "  epoch: 7\n", "  epoch: 7\n  count_direct_deliveries: true\n", 1)
		}
		material := runtimeMaterial(t, document)
		factories := replayRuntimeFactories{
			newDeriver:  dkim2.NewReplayDeriver,
			newMemory:   dkim2.NewReplayMemoryStore,
			newDisabled: newDisabledReplayStore,
			clock:       &runtimeFixedClock{now: time.Unix(1_700_000_000, 0)},
		}
		runtime, err := newReplayRuntime(context.Background(), material, factories)
		if err != nil || runtime == nil || runtime.state.counting.CountsDirectDeliveries() != enabled {
			t.Fatalf("count_direct_deliveries=%t runtime policy=%v error=%v", enabled, runtime != nil && runtime.state.counting.CountsDirectDeliveries(), err)
		}
		if runtime.state.coordinator.state.counting.CountsDirectDeliveries() != enabled {
			t.Fatal("process replay coordinator did not receive the counting policy")
		}
		if err := closeReplayRuntimeBounded(runtime); err != nil {
			t.Fatal("memory owners did not close")
		}
	}
}

// TestInboundProcessCountsDirectDeliveriesEndToEnd proves the production
// /v1/process path with a real memory store and bound authenticator: with
// count_direct_deliveries a direct i=1 message is first_seen and accepted
// once, then replayed and rejected; without it both are not_eligible.
func TestInboundProcessCountsDirectDeliveriesEndToEnd(t *testing.T) {
	raw, recipients, provider := goldenReplayInput(t)
	for _, test := range []struct {
		enabled bool
		want    []ReplayResultClass
		final   []FinalDisposition
	}{
		{enabled: false, want: []ReplayResultClass{ReplayResultNotEligible, ReplayResultNotEligible}, final: []FinalDisposition{FinalDispositionAccept, FinalDispositionAccept}},
		{enabled: true, want: []ReplayResultClass{ReplayResultFirstSeen, ReplayResultReplayed}, final: []FinalDisposition{FinalDispositionAccept, FinalDispositionReject}},
	} {
		document := runtimeMemoryYAML()
		if test.enabled {
			document = strings.Replace(document, "  epoch: 7\n", "  epoch: 7\n  count_direct_deliveries: true\n", 1)
		}
		runtime, err := newReplayRuntime(context.Background(), runtimeMaterial(t, document), replayRuntimeFactories{
			newDeriver: dkim2.NewReplayDeriver, newMemory: dkim2.NewReplayMemoryStore,
			newDisabled: newDisabledReplayStore, clock: &runtimeFixedClock{now: time.Unix(replayTestTimestamp, 0)},
		})
		if err != nil {
			t.Fatalf("newReplayRuntime() error = %v", err)
		}
		verifier, err := dkim2.NewVerifier(provider, dkim2.WithVerificationClock(func() time.Time { return time.Unix(replayTestTimestamp, 0) }))
		if err != nil {
			t.Fatal("verifier construction failed")
		}
		authentication, err := runtime.NewAuthenticator(&DNSVerifier{verifier: verifier, provider: provider})
		if err != nil {
			t.Fatalf("NewAuthenticator() error = %v", err)
		}
		domain, err := NewDomainProcessor(verifier, config.PolicyStrict, authentication)
		if err != nil {
			t.Fatal("domain processor construction failed")
		}
		processor, err := NewInboundProcessor(domain, runtime)
		if err != nil {
			t.Fatal("inbound processor construction failed")
		}
		for index := range test.want {
			result, err := processor.Process(context.Background(), dkim2.NewVerifyRequest(raw, []byte("<>"), recipients))
			if err != nil {
				t.Fatalf("Process() error = %v", err)
			}
			outcome, err := result.Replay()
			if err != nil || outcome.Class() != test.want[index] || outcome.Disposition() != test.final[index] {
				t.Fatalf("enabled=%t delivery %d replay=%q disposition=%q error=%v",
					test.enabled, index, outcome.Class(), outcome.Disposition(), err)
			}
		}
		if err := closeReplayRuntimeBounded(runtime); err != nil {
			t.Fatal("memory owners did not close")
		}
	}
}

// TestReplayRuntimeRedisUsesOneStartupBorrowAndExactProviderConfig proves
// that one borrow builds deriver and store, that every typed replay.redis
// accessor reaches the provider configuration unchanged, and that the lent
// secrets are callback-local views zeroed after the factory returns.
func TestReplayRuntimeRedisUsesOneStartupBorrowAndExactProviderConfig(t *testing.T) {
	for name, document := range map[string]string{
		"standalone": runtimeRedisYAML(),
		"sentinel":   runtimeRedisSentinelYAML(),
		"cluster":    runtimeRedisClusterYAML(),
	} {
		t.Run(name, func(t *testing.T) {
			material := runtimeMaterial(t, document)
			authority := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: true}
			var factoryCalls atomic.Int32
			var captured redisstore.Config
			var lent redisstore.Secrets
			var lentCopy [][]byte
			factories := replayRuntimeFactories{
				newDeriver:  dkim2.NewReplayDeriver,
				newDisabled: newDisabledReplayStore,
				newProduction: func(
					_ context.Context,
					storeConfig redisstore.Config,
					secrets redisstore.Secrets,
				) (replayAuthorityStore, error) {
					factoryCalls.Add(1)
					captured = storeConfig
					lent = secrets
					lentCopy = [][]byte{
						append([]byte(nil), secrets.Password...),
						append([]byte(nil), secrets.SentinelPassword...),
						append([]byte(nil), secrets.ClientCertificatePEM...),
						append([]byte(nil), secrets.ClientKeyPEM...),
					}
					return authority, nil
				},
			}
			runtime, err := newReplayRuntime(context.Background(), material, factories)
			if err != nil || runtime == nil {
				t.Fatalf("newReplayRuntime() = (%v, %v)", runtime, err)
			}
			replayConfig := material.snapshot.Replay()
			redisConfig, present := replayConfig.Redis()
			if !present {
				t.Fatal("fixture omitted Redis config")
			}
			if factoryCalls.Load() != 1 || material.Calls() != 1 {
				t.Fatal("Redis startup did not use exactly one borrow and one factory call")
			}
			expected := redisStoreConfig(redisConfig, replayLimits(replayConfig))
			if !reflect.DeepEqual(captured, expected) || captured.Validate() != nil {
				t.Fatal("Redis provider received a changed or invalid configuration")
			}
			assertRuntimeRedisProjection(t, captured, redisConfig, replayLimits(replayConfig))
			if string(lentCopy[0]) != "application-secret" || string(lentCopy[1]) != "sentinel-secret" ||
				string(lentCopy[2]) != "certificate-pem" || string(lentCopy[3]) != "key-pem" ||
				!reflect.DeepEqual(lent.RootsDER, [][]byte{nil}) {
				t.Fatal("Redis provider received changed secrets or retained roots past the borrow")
			}
			for _, value := range [][]byte{lent.Password, lent.SentinelPassword, lent.ClientCertificatePEM, lent.ClientKeyPEM} {
				if strings.Trim(string(value), "\x00") != "" {
					t.Fatal("lent Redis secret outlived the startup borrow")
				}
			}
			if !runtime.AuthorityReady() || authority.readyCalls != 1 ||
				runtime.HealthInterval() != redisConfig.HealthInterval() {
				t.Fatal("Redis readiness delegation or health interval is wrong")
			}
			if err := closeReplayRuntimeBounded(runtime); err != nil || authority.closeCalls != 1 {
				t.Fatal("Redis runtime did not close its authority")
			}
		})
	}
}

// assertRuntimeRedisProjection pins the field-by-field accessor mapping so a
// silently dropped field cannot hide behind a shared projection helper.
func assertRuntimeRedisProjection(
	t *testing.T,
	captured redisstore.Config,
	redis config.RedisConfig,
	limits dkim2.ReplayLimits,
) {
	t.Helper()
	modes := map[config.RedisMode]redisstore.Mode{
		config.RedisStandalone: redisstore.ModeStandalone,
		config.RedisSentinel:   redisstore.ModeSentinel,
		config.RedisCluster:    redisstore.ModeCluster,
	}
	if captured.Mode != modes[redis.Mode()] ||
		captured.StandaloneAddress != redis.StandaloneAddress() ||
		captured.SentinelMasterName != redis.SentinelMasterName() ||
		!reflect.DeepEqual(captured.SentinelAddresses, redis.SentinelAddresses()) ||
		captured.SentinelUsername != redis.SentinelUsername() ||
		!reflect.DeepEqual(captured.ClusterAddresses, redis.ClusterAddresses()) ||
		captured.ClusterMaxRedirects != redis.ClusterMaxRedirects() ||
		captured.Username != redis.Username() ||
		captured.DatabaseNumber != redis.DatabaseNumber() ||
		captured.KeyPrefix != redis.KeyPrefix() ||
		captured.Protocol != redis.Protocol() ||
		captured.TLS.Enabled != redis.TLSEnabled() ||
		captured.TLS.ServerName != redis.TLSServerName() ||
		uint16(captured.TLS.MinVersion) != redis.TLSMinVersion() ||
		captured.TLS.InsecureSkipVerify != redis.TLSInsecureSkipVerify() ||
		captured.PoolSize != redis.PoolSize() ||
		captured.MinIdleConnections != redis.MinIdleConnections() ||
		captured.PoolTimeout != redis.PoolTimeout() ||
		captured.DialTimeout != redis.DialTimeout() ||
		captured.ReadTimeout != redis.ReadTimeout() ||
		captured.WriteTimeout != redis.WriteTimeout() ||
		captured.MaxAttempts != redis.RetryMaxAttempts() ||
		captured.MinRetryBackoff != redis.RetryMinBackoff() ||
		captured.MaxRetryBackoff != redis.RetryMaxBackoff() ||
		captured.Health.Interval != redis.HealthInterval() ||
		captured.Health.Timeout != redis.HealthTimeout() ||
		captured.Health.FailureThreshold != redis.HealthFailureThreshold() ||
		captured.RequireNoEviction != redis.RequireNoEviction() ||
		captured.Limits != limits {
		t.Fatal("Redis provider configuration diverged from the typed accessors")
	}
}

// TestReplayRuntimeRedisAddressListsAreCopied proves the provider never
// aliases config-owned address slices.
func TestReplayRuntimeRedisAddressListsAreCopied(t *testing.T) {
	material := runtimeMaterial(t, runtimeRedisSentinelYAML())
	redisConfig, _ := material.snapshot.Replay().Redis()
	projected := redisStoreConfig(redisConfig, dkim2.ReplayLimits{})
	projected.SentinelAddresses[0] = "mutated.internal:1"
	if again := redisConfig.SentinelAddresses(); again[0] == "mutated.internal:1" {
		t.Fatal("projected Sentinel addresses alias typed configuration")
	}
}

// TestReplayRuntimeReadinessDelegatesWithoutProbeTimestamps proves that a
// successful probe never substitutes a timestamp for the store's own fact.
func TestReplayRuntimeReadinessDelegatesWithoutProbeTimestamps(t *testing.T) {
	material := runtimeMaterial(t, runtimeRedisYAML())
	authority := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: false}
	runtime := runtimeWithAuthority(t, material, authority)
	t.Cleanup(func() {
		if closeErr := closeReplayRuntimeBounded(runtime); closeErr != nil {
			t.Errorf("ReplayRuntime.Close() failed: %v", closeErr)
		}
	})
	if runtime.AuthorityReady() {
		t.Fatal("unready authority reported ready before probe")
	}
	if err := runtime.ProbeHealth(context.Background()); err != nil {
		t.Fatalf("successful ProbeHealth() failed: %v", err)
	}
	if runtime.AuthorityReady() || authority.readyCalls != 2 || authority.Probes() != 1 {
		t.Fatal("successful probe replaced delegated readiness with a timestamp")
	}
}

// TestReplayRuntimeUsesTheValidatedDefaultHealthInterval proves default projection.
func TestReplayRuntimeUsesTheValidatedDefaultHealthInterval(t *testing.T) {
	material := runtimeMaterial(t, runtimeRedisYAML())
	authority := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: true}
	runtime := runtimeWithAuthority(t, material, authority)
	if runtime.HealthInterval() != 5*time.Second {
		t.Fatalf("default interval = %s", runtime.HealthInterval())
	}
	if err := closeReplayRuntimeBounded(runtime); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
}

// TestReplayRuntimeRedisFactoryErrorKeepsNoStore proves that the production
// constructor never returns a typed-nil authority for a failed store.
func TestReplayRuntimeRedisFactoryErrorKeepsNoStore(t *testing.T) {
	storeConfig := redisstore.DefaultConfig("127.0.0.1:1")
	storeConfig.Mode = 0
	store, err := newRedisReplayStore(context.Background(), storeConfig, redisstore.Secrets{})
	if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorMisconfigured {
		t.Fatalf("invalid provider config returned (%v, %v)", store, err)
	}
}

// TestReplayRuntimeRollsBackEveryConstructionFailure proves owner cleanup.
func TestReplayRuntimeRollsBackEveryConstructionFailure(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{
			name: "memory-acquired-store-plus-error",
			run: func(t *testing.T) {
				material := runtimeMaterial(t, runtimeMemoryYAML())
				var deriver *dkim2.ReplayDeriver
				var store *dkim2.ReplayMemoryStore
				var constructorErr error
				runtime, err := newReplayRuntime(context.Background(), material, replayRuntimeFactories{
					newDeriver: func(secret []byte, epoch uint32) (*dkim2.ReplayDeriver, error) {
						deriver, constructorErr = dkim2.NewReplayDeriver(secret, epoch)
						return deriver, constructorErr
					},
					newMemory: func(cfg dkim2.ReplayMemoryConfig) (*dkim2.ReplayMemoryStore, error) {
						store, constructorErr = dkim2.NewReplayMemoryStore(cfg)
						if constructorErr != nil {
							return nil, constructorErr
						}
						return store, errors.New("private store marker")
					},
					clock: &runtimeFixedClock{now: time.Unix(1, 0)},
				})
				if runtime != nil || !IsReplayRuntimeError(err) {
					t.Fatalf("construction = (%v, %v)", runtime, err)
				}
				if _, deriveErr := deriver.Derive(context.Background(), dkim2.ReplayIdentity{}); dkim2.ReplayErrorCodeOf(deriveErr) != dkim2.ReplayErrorClosed {
					t.Fatal("memory construction failure retained the deriver")
				}
				if store.State() != dkim2.ReplayStoreClosed || runtimeMemoryClearCount(store) != 1 {
					t.Fatal("memory construction failure did not release the acquired store exactly once")
				}
			},
		},
		{
			name: "production-acquired-authority-plus-error",
			run: func(t *testing.T) {
				material := runtimeMaterial(t, runtimeRedisYAML())
				var deriver *dkim2.ReplayDeriver
				authority := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: true}
				var constructorErr error
				runtime, err := newReplayRuntime(context.Background(), material, replayRuntimeFactories{
					newDeriver: func(secret []byte, epoch uint32) (*dkim2.ReplayDeriver, error) {
						deriver, constructorErr = dkim2.NewReplayDeriver(secret, epoch)
						return deriver, constructorErr
					},
					newProduction: func(
						context.Context,
						redisstore.Config,
						redisstore.Secrets,
					) (replayAuthorityStore, error) {
						return authority, errors.New("private provider marker")
					},
				})
				if runtime != nil || !IsReplayRuntimeError(err) {
					t.Fatalf("construction = (%v, %v)", runtime, err)
				}
				if _, deriveErr := deriver.Derive(context.Background(), dkim2.ReplayIdentity{}); dkim2.ReplayErrorCodeOf(deriveErr) != dkim2.ReplayErrorClosed {
					t.Fatal("production construction failure retained the deriver")
				}
				if authority.closeCalls != 1 || authority.State() != dkim2.ReplayStoreClosed {
					t.Fatal("production construction failure did not release authority exactly once")
				}
			},
		},
		{
			name: "disabled-wrong-state",
			run: func(t *testing.T) {
				material := runtimeMaterial(t, runtimeDisabledYAML())
				store := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady}
				runtime, err := newReplayRuntime(context.Background(), material, replayRuntimeFactories{
					newDisabled: func() dkim2.ManagedReplayStore { return store },
				})
				if runtime != nil || !IsReplayRuntimeError(err) ||
					store.State() != dkim2.ReplayStoreClosed || store.closeCalls != 1 {
					t.Fatal("wrong-state disabled store was accepted or retained")
				}
			},
		},
		{
			name: "terminal-context-after-memory-construction",
			run: func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				material := runtimeMaterial(t, runtimeMemoryYAML())
				material.afterMaterial = cancel
				var store *dkim2.ReplayMemoryStore
				var constructorErr error
				runtime, err := newReplayRuntime(ctx, material, replayRuntimeFactories{
					newDeriver: dkim2.NewReplayDeriver,
					newMemory: func(cfg dkim2.ReplayMemoryConfig) (*dkim2.ReplayMemoryStore, error) {
						store, constructorErr = dkim2.NewReplayMemoryStore(cfg)
						return store, constructorErr
					},
					clock: &runtimeFixedClock{now: time.Unix(1, 0)},
				})
				if runtime != nil || !errors.Is(err, context.Canceled) ||
					store.State() != dkim2.ReplayStoreClosed {
					t.Fatal("terminal final boundary did not roll back memory owners")
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

// TestReplayRuntimeRejectsBorrowAndNilFactoryResultsWithoutFallback proves fail-closed seams.
func TestReplayRuntimeRejectsBorrowAndNilFactoryResultsWithoutFallback(t *testing.T) {
	t.Run("material-borrow-error", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeMemoryYAML())
		material.materialErr = errors.New("protected borrow marker")
		var factoryCalls atomic.Int32
		runtime, err := newReplayRuntime(context.Background(), material, replayRuntimeFactories{
			newDeriver: func([]byte, uint32) (*dkim2.ReplayDeriver, error) {
				factoryCalls.Add(1)
				return nil, nil
			},
			newMemory: func(dkim2.ReplayMemoryConfig) (*dkim2.ReplayMemoryStore, error) {
				factoryCalls.Add(1)
				return nil, nil
			},
			clock: &runtimeFixedClock{now: time.Unix(1, 0)},
		})
		if runtime != nil || !IsReplayRuntimeError(err) || factoryCalls.Load() != 0 {
			t.Fatal("borrow failure reached a provider factory or escaped")
		}
	})
	t.Run("nil-deriver-without-error", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeMemoryYAML())
		var memoryCalls atomic.Int32
		runtime, err := newReplayRuntime(context.Background(), material, replayRuntimeFactories{
			newDeriver: func([]byte, uint32) (*dkim2.ReplayDeriver, error) { return nil, nil },
			newMemory: func(dkim2.ReplayMemoryConfig) (*dkim2.ReplayMemoryStore, error) {
				memoryCalls.Add(1)
				return nil, nil
			},
			clock: &runtimeFixedClock{now: time.Unix(1, 0)},
		})
		if runtime != nil || !IsReplayRuntimeError(err) || memoryCalls.Load() != 0 {
			t.Fatal("nil deriver fell through to memory construction")
		}
	})
	t.Run("nil-memory-store-without-error", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeMemoryYAML())
		var deriver *dkim2.ReplayDeriver
		var constructorErr error
		runtime, err := newReplayRuntime(context.Background(), material, replayRuntimeFactories{
			newDeriver: func(secret []byte, epoch uint32) (*dkim2.ReplayDeriver, error) {
				deriver, constructorErr = dkim2.NewReplayDeriver(secret, epoch)
				return deriver, constructorErr
			},
			newMemory: func(dkim2.ReplayMemoryConfig) (*dkim2.ReplayMemoryStore, error) {
				return nil, nil
			},
			clock: &runtimeFixedClock{now: time.Unix(1, 0)},
		})
		if runtime != nil || !IsReplayRuntimeError(err) {
			t.Fatal("nil memory store was accepted")
		}
		if _, deriveErr := deriver.Derive(context.Background(), dkim2.ReplayIdentity{}); dkim2.ReplayErrorCodeOf(deriveErr) != dkim2.ReplayErrorClosed {
			t.Fatal("nil memory result retained the acquired deriver")
		}
	})
	t.Run("nil-authority-without-error", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeRedisYAML())
		var deriver *dkim2.ReplayDeriver
		var constructorErr error
		runtime, err := newReplayRuntime(context.Background(), material, replayRuntimeFactories{
			newDeriver: func(secret []byte, epoch uint32) (*dkim2.ReplayDeriver, error) {
				deriver, constructorErr = dkim2.NewReplayDeriver(secret, epoch)
				return deriver, constructorErr
			},
			newProduction: func(
				context.Context,
				redisstore.Config,
				redisstore.Secrets,
			) (replayAuthorityStore, error) {
				return nil, nil
			},
		})
		if runtime != nil || !IsReplayRuntimeError(err) {
			t.Fatal("nil production authority was accepted")
		}
		if _, deriveErr := deriver.Derive(context.Background(), dkim2.ReplayIdentity{}); dkim2.ReplayErrorCodeOf(deriveErr) != dkim2.ReplayErrorClosed {
			t.Fatal("nil authority result retained the acquired deriver")
		}
	})
}

// TestReplayRuntimeProbeHealthPassesEveryTypedCode proves that every closed
// replay code from the store reaches the loop unchanged, so the loop keeps
// running and the store's own recovery fact drives readiness.
func TestReplayRuntimeProbeHealthPassesEveryTypedCode(t *testing.T) {
	codes := []dkim2.ReplayErrorCode{
		dkim2.ReplayErrorInvalidRequest,
		dkim2.ReplayErrorMisconfigured,
		dkim2.ReplayErrorLimitExceeded,
		dkim2.ReplayErrorUnavailable,
		dkim2.ReplayErrorIndeterminate,
		dkim2.ReplayErrorInconsistent,
		dkim2.ReplayErrorCancelled,
		dkim2.ReplayErrorDeadlineExceeded,
		dkim2.ReplayErrorClosed,
		dkim2.ReplayErrorInternalInvariant,
	}
	for _, code := range codes {
		t.Run(string(code), func(t *testing.T) {
			material := runtimeMaterial(t, runtimeRedisYAML())
			authority := &runtimeAuthorityFake{
				state:          dkim2.ReplayStoreReady,
				ready:          true,
				probeResponses: []error{dkim2.NewReplayError(code)},
			}
			runtime := runtimeWithAuthority(t, material, authority)
			if err := runtime.ProbeHealth(context.Background()); dkim2.ReplayErrorCodeOf(err) != code {
				t.Fatalf("typed %q returned %v", code, err)
			}
			if closeErr := closeReplayRuntimeBounded(runtime); closeErr != nil {
				t.Fatalf("Close() failed: %v", closeErr)
			}
		})
	}
}

// TestReplayRuntimeProbeHealthRejectsNonRedisBackends proves that the probe
// seam exists only for the networked authority.
func TestReplayRuntimeProbeHealthRejectsNonRedisBackends(t *testing.T) {
	material := runtimeMaterial(t, runtimeDisabledYAML())
	runtime, err := newReplayRuntime(context.Background(), material, replayRuntimeFactories{
		newDisabled: newDisabledReplayStore,
	})
	if err != nil {
		t.Fatalf("newReplayRuntime() failed: %v", err)
	}
	if err := runtime.ProbeHealth(context.Background()); !IsReplayRuntimeError(err) {
		t.Fatalf("disabled ProbeHealth() returned %v", err)
	}
	var missing *ReplayRuntime
	if err := missing.ProbeHealth(context.Background()); !IsReplayRuntimeError(err) || missing.HealthInterval() != 0 {
		t.Fatal("nil runtime probe seam did not fail closed")
	}
	if err := closeReplayRuntimeBounded(runtime); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
}

// TestReplayRuntimeErrorsContextAndPrivacyRemainBounded proves public surfaces.
func TestReplayRuntimeErrorsContextAndPrivacyRemainBounded(t *testing.T) {
	material := runtimeMaterial(t, runtimeRedisYAML())
	authority := &runtimeAuthorityFake{
		state: dkim2.ReplayStoreReady,
		ready: true,
		probeResponses: []error{
			dkim2.NewReplayError(dkim2.ReplayErrorUnavailable),
			errors.New("protected authority marker"),
		},
	}
	runtime, err := newReplayRuntime(context.Background(), material, replayRuntimeFactories{
		newDeriver: dkim2.NewReplayDeriver,
		newProduction: func(
			context.Context,
			redisstore.Config,
			redisstore.Secrets,
		) (replayAuthorityStore, error) {
			return authority, nil
		},
	})
	if err != nil {
		t.Fatalf("newReplayRuntime() failed: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := closeReplayRuntimeBounded(runtime); closeErr != nil {
			t.Errorf("ReplayRuntime.Close() failed: %v", closeErr)
		}
	})
	if err := runtime.ProbeHealth(context.Background()); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorUnavailable {
		t.Fatal("ordinary typed replay error did not survive")
	}
	if err := runtime.ProbeHealth(context.Background()); !IsReplayRuntimeError(err) ||
		strings.Contains(fmt.Sprint(err), "marker") {
		t.Fatal("unknown provider error did not collapse")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.ProbeHealth(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("terminal caller context lost precedence")
	}
	const marker = "runtime-protected-marker"
	material.password = []byte(marker)
	var interfaceValue any = runtime
	nested := struct{ Runtime any }{Runtime: runtime}
	values := []any{
		runtime,
		*runtime,
		interfaceValue,
		[]any{runtime, *runtime},
		nested,
		map[*ReplayRuntime]string{runtime: "value"},
		map[ReplayRuntime]bool{*runtime: true},
	}
	for _, value := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%p"} {
			representation := fmt.Sprintf(verb, value)
			if strings.Contains(representation, marker) {
				t.Fatalf("%s exposed protected runtime state: %q", verb, representation)
			}
			if verb != "%p" && !strings.Contains(representation, replayRuntimeRedacted) {
				t.Fatalf("%s omitted the redacted token: %q", verb, representation)
			}
		}
	}
	if data, marshalErr := json.Marshal(runtime); data != nil || !IsReplayRuntimeError(marshalErr) {
		t.Fatal("JSON serialization did not reject runtime state")
	}
	if data, marshalErr := runtime.MarshalText(); data != nil || !IsReplayRuntimeError(marshalErr) {
		t.Fatal("text serialization did not reject runtime state")
	}
}

// TestReplayRuntimeRejectsHostileContextContracts proves bounded context handling.
func TestReplayRuntimeRejectsHostileContextContracts(t *testing.T) {
	var typedNil *hostileReplayContext
	contexts := []context.Context{
		nil,
		typedNil,
		hostileReplayContext{panicErr: true},
		hostileReplayContext{panicDeadline: true},
		hostileReplayContext{err: errors.New("foreign context marker")},
	}
	for _, ctx := range contexts {
		material := runtimeMaterial(t, runtimeDisabledYAML())
		if runtime, err := newReplayRuntime(ctx, material, replayRuntimeFactories{
			newDisabled: newDisabledReplayStore,
		}); runtime != nil || !IsReplayRuntimeError(err) {
			t.Fatalf("hostile construction context returned (%v, %v)", runtime, err)
		}
	}
	material := runtimeMaterial(t, runtimeDisabledYAML())
	if runtime, err := newReplayRuntime(
		expiredNilErrorContext{},
		material,
		replayRuntimeFactories{newDisabled: newDisabledReplayStore},
	); runtime != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline returned (%v, %v)", runtime, err)
	}
}

// TestReplayRuntimeSupportsConcurrentReadinessProbeAndClose proves race safety.
func TestReplayRuntimeSupportsConcurrentReadinessProbeAndClose(t *testing.T) {
	material := runtimeMaterial(t, runtimeRedisYAML())
	authority := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: true}
	runtime, err := newReplayRuntime(context.Background(), material, replayRuntimeFactories{
		newDeriver: dkim2.NewReplayDeriver,
		newProduction: func(
			context.Context,
			redisstore.Config,
			redisstore.Secrets,
		) (replayAuthorityStore, error) {
			return authority, nil
		},
	})
	if err != nil {
		t.Fatalf("newReplayRuntime() failed: %v", err)
	}
	var group sync.WaitGroup
	start := make(chan struct{})
	for range 24 {
		group.Go(func() {
			<-start
			_ = runtime.AuthorityReady()
			_ = runtime.ProbeHealth(context.Background())
		})
	}
	group.Go(func() {
		<-start
		_ = closeReplayRuntimeBounded(runtime)
	})
	close(start)
	group.Wait()
	if authority.closeCalls != 1 {
		t.Fatal("concurrent Close() did not reach the authority exactly once")
	}
}

// TestReplayRuntimeConcurrentCloseInvokesEachOwnerOnce proves waiter serialization.
func TestReplayRuntimeConcurrentCloseInvokesEachOwnerOnce(t *testing.T) {
	material := runtimeMaterial(t, runtimeRedisYAML())
	entered := make(chan struct{})
	release := make(chan struct{})
	var enterOnce sync.Once
	authority := &runtimeAuthorityFake{
		state: dkim2.ReplayStoreReady,
		ready: true,
		closeHook: func() {
			enterOnce.Do(func() { close(entered) })
			<-release
		},
	}
	runtime := runtimeWithAuthority(t, material, authority)
	const callers = 24
	results := make(chan error, callers)
	for range callers {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			results <- runtime.Close(ctx)
		}()
	}
	<-entered
	close(release)
	for range callers {
		if err := <-results; err != nil {
			t.Fatalf("concurrent Close() failed: %v", err)
		}
	}
	if authority.closeCalls != 1 {
		t.Fatalf("store Close() calls = %d, want 1", authority.closeCalls)
	}
	if err := closeReplayRuntimeBounded(runtime); err != nil ||
		authority.closeCalls != 1 {
		t.Fatalf("terminal Close() changed exact owner count: %v/%d", err, authority.closeCalls)
	}
}

// TestReplayRuntimeBlockedStoreKeepsRunningUntilOwnedJoin proves bounded no-teardown state.
func TestReplayRuntimeBlockedStoreKeepsRunningUntilOwnedJoin(t *testing.T) {
	material := runtimeMaterial(t, runtimeRedisYAML())
	entered := make(chan struct{})
	release := make(chan struct{})
	authority := &runtimeAuthorityFake{
		state: dkim2.ReplayStoreReady,
		ready: true,
		closeHook: func() {
			close(entered)
			<-release
		},
	}
	runtime := runtimeWithAuthority(t, material, authority)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- runtime.Close(ctx) }()
	<-entered
	if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked Close() returned %v", err)
	}
	runtime.state.close.mu.Lock()
	running := runtime.state.close.running
	runtime.state.close.mu.Unlock()
	if !running || authority.closeCalls != 1 {
		t.Fatalf("blocked cleanup lost ownership running=%t calls=%d", running, authority.closeCalls)
	}
	waiterCtx := newSingleSnapshotReplayContext(false)
	waiterCtx.deadline = time.Now().Add(25 * time.Millisecond)
	if err := runtime.Close(waiterCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bounded waiter returned %v", err)
	}
	if waiterCtx.deadlineCalls.Load() != 1 || waiterCtx.doneCalls.Load() != 1 {
		t.Fatal("bounded waiter re-read frozen deadline methods")
	}
	close(release)
	terminalCtx, terminalCancel := context.WithTimeout(context.Background(), time.Second)
	defer terminalCancel()
	if err := runtime.Close(terminalCtx); !IsReplayRuntimeError(err) {
		t.Fatalf("post-join terminal Close() returned %v", err)
	}
	if authority.closeCalls != 1 {
		t.Fatalf("post-join store Close() calls = %d", authority.closeCalls)
	}
}

// TestReplayRuntimeContainsChildClosePanicsAndReleasesWaiters proves terminal containment.
func TestReplayRuntimeContainsChildClosePanicsAndReleasesWaiters(t *testing.T) {
	t.Run("store panic still closes deriver", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeRedisYAML())
		authority := &runtimeAuthorityFake{
			state: dkim2.ReplayStoreReady,
			ready: true,
			closeHook: func() {
				panic("toxic-store-close-marker")
			},
		}
		runtime := runtimeWithAuthority(t, material, authority)
		deriver := runtime.state.deriver
		if err := closeReplayRuntimeBounded(runtime); !IsReplayRuntimeError(err) ||
			strings.Contains(fmt.Sprint(err), "toxic-store-close-marker") {
			t.Fatalf("store panic escaped as %v", err)
		}
		if _, err := deriver.Derive(context.Background(), dkim2.ReplayIdentity{}); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorClosed {
			t.Fatal("store panic prevented deriver release")
		}
		if err := closeReplayRuntimeBounded(runtime); !IsReplayRuntimeError(err) ||
			authority.closeCalls != 1 {
			t.Fatalf("terminal store panic result changed: %v/%d", err, authority.closeCalls)
		}
	})
	t.Run("deriver panic releases concurrent waiters", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeRedisYAML())
		authority := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: true}
		runtime := runtimeWithAuthority(t, material, authority)
		var deriverCalls atomic.Int32
		runtime.state.closeDeriver = func(context.Context) error {
			deriverCalls.Add(1)
			panic("toxic-deriver-close-marker")
		}
		results := make(chan error, 8)
		for range 8 {
			go func() { results <- closeReplayRuntimeBounded(runtime) }()
		}
		for range 8 {
			err := <-results
			if !IsReplayRuntimeError(err) ||
				strings.Contains(fmt.Sprint(err), "toxic-deriver-close-marker") {
				t.Fatalf("deriver panic escaped as %v", err)
			}
		}
		if authority.closeCalls != 1 || deriverCalls.Load() != 1 {
			t.Fatalf("panic cleanup calls store=%d deriver=%d", authority.closeCalls, deriverCalls.Load())
		}
	})
}

// TestReplayRuntimeRollbackUsesOneSharedLazyBudget proves aggregate rollback ownership.
func TestReplayRuntimeRollbackUsesOneSharedLazyBudget(t *testing.T) {
	t.Run("late failure creates one rollback scope", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeMemoryYAML())
		acquisitionCtx, cancelAcquisition := context.WithCancel(context.Background())
		material.afterMaterial = cancelAcquisition
		var calls atomic.Int32
		rollbackCtx, rollbackCancel := context.WithTimeout(
			context.Background(), replayRollbackLimit,
		)
		defer rollbackCancel()
		runtime, err := newReplayRuntimeWithRollback(
			acquisitionCtx,
			func() context.Context {
				calls.Add(1)
				return rollbackCtx
			},
			material,
			replayRuntimeFactories{
				newDeriver: dkim2.NewReplayDeriver,
				newMemory:  dkim2.NewReplayMemoryStore,
				clock:      &runtimeFixedClock{now: time.Unix(1_700_000_000, 0)},
			},
		)
		if runtime != nil || !errors.Is(err, context.Canceled) || calls.Load() != 1 {
			t.Fatalf("late rollback returned runtime=%v err=%v calls=%d", runtime, err, calls.Load())
		}
	})
	t.Run("prior cleanup may consume shared budget", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeMemoryYAML())
		material.afterMaterial = func() {}
		var calls atomic.Int32
		rollbackCtx, rollbackCancel := context.WithTimeout(
			context.Background(), 500*time.Millisecond,
		)
		defer rollbackCancel()
		runtime, err := newReplayRuntimeWithRollback(
			context.Background(),
			func() context.Context {
				calls.Add(1)
				return rollbackCtx
			},
			material,
			replayRuntimeFactories{
				newDeriver: dkim2.NewReplayDeriver,
				newMemory: func(dkim2.ReplayMemoryConfig) (*dkim2.ReplayMemoryStore, error) {
					return nil, errors.New("construction marker")
				},
				clock: &runtimeFixedClock{now: time.Unix(1_700_000_000, 0)},
			},
		)
		if runtime != nil || !IsReplayRuntimeError(err) || calls.Load() != 1 {
			t.Fatalf("shared remainder returned runtime=%v err=%v calls=%d", runtime, err, calls.Load())
		}
	})
	t.Run("pre-owner failure never starts rollback", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeMemoryYAML())
		var calls atomic.Int32
		var rollbackCancel context.CancelFunc
		runtime, err := newReplayRuntimeWithRollback(
			context.Background(),
			func() context.Context {
				calls.Add(1)
				ctx, cancel := context.WithTimeout(context.Background(), replayRollbackLimit)
				rollbackCancel = cancel
				return ctx
			},
			material,
			replayRuntimeFactories{},
		)
		if rollbackCancel != nil {
			rollbackCancel()
		}
		if runtime != nil || !IsReplayRuntimeError(err) || calls.Load() != 0 {
			t.Fatalf("pre-owner failure returned runtime=%v err=%v calls=%d", runtime, err, calls.Load())
		}
	})
	t.Run("malformed-bounded-context-never-starts-owner-cleanup", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeDisabledYAML())
		store := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady}
		var calls atomic.Int32
		runtime, err := newReplayRuntimeWithRollback(
			context.Background(),
			func() context.Context {
				calls.Add(1)
				return futureDeadlineNilDoneReplayContext{}
			},
			material,
			replayRuntimeFactories{
				newDisabled: func() dkim2.ManagedReplayStore { return store },
			},
		)
		if runtime != nil || !IsReplayRuntimeError(err) || calls.Load() != 1 {
			t.Fatalf("malformed rollback returned runtime=%v err=%v calls=%d", runtime, err, calls.Load())
		}
		if store.closeCalls != 0 {
			t.Fatal("malformed rollback context entered child cleanup")
		}
	})
	t.Run("typed-nil-rollback-context-never-starts-owner-cleanup", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeDisabledYAML())
		store := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady}
		var typedNil *hostileReplayContext
		runtime, err := newReplayRuntimeWithRollback(
			context.Background(),
			func() context.Context { return typedNil },
			material,
			replayRuntimeFactories{
				newDisabled: func() dkim2.ManagedReplayStore { return store },
			},
		)
		if runtime != nil || !IsReplayRuntimeError(err) || store.closeCalls != 0 {
			t.Fatalf(
				"typed-nil rollback returned runtime=%v err=%v calls=%d",
				runtime,
				err,
				store.closeCalls,
			)
		}
	})
	t.Run("rollback-snapshots-context-before-owner-cleanup", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeDisabledYAML())
		store := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady}
		ctx := newSingleSnapshotReplayContext(true)
		runtime, err := newReplayRuntimeWithRollback(
			context.Background(),
			func() context.Context { return ctx },
			material,
			replayRuntimeFactories{
				newDisabled: func() dkim2.ManagedReplayStore { return store },
			},
		)
		if runtime != nil || !IsReplayRuntimeError(err) {
			t.Fatalf("stateful rollback returned runtime=%v err=%v", runtime, err)
		}
		if store.closeCalls != 1 ||
			ctx.deadlineCalls.Load() != 1 ||
			ctx.doneCalls.Load() != 1 {
			t.Fatalf(
				"rollback ownership=%d deadline=%d done=%d",
				store.closeCalls,
				ctx.deadlineCalls.Load(),
				ctx.doneCalls.Load(),
			)
		}
	})
	t.Run("rollback-deadline-does-not-trust-unsignaled-done", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeDisabledYAML())
		entered := make(chan struct{})
		release := make(chan struct{})
		store := &runtimeAuthorityFake{
			state: dkim2.ReplayStoreReady,
			closeHook: func() {
				close(entered)
				<-release
			},
		}
		ctx := newSingleSnapshotReplayContext(false)
		ctx.deadline = time.Now().Add(40 * time.Millisecond)
		result := make(chan error, 1)
		go func() {
			_, err := newReplayRuntimeWithRollback(
				context.Background(),
				func() context.Context { return ctx },
				material,
				replayRuntimeFactories{
					newDisabled: func() dkim2.ManagedReplayStore { return store },
				},
			)
			result <- err
		}()
		<-entered
		select {
		case err := <-result:
			if !IsReplayRuntimeError(err) {
				t.Fatalf("blocking rollback returned %v", err)
			}
		case <-time.After(250 * time.Millisecond):
			t.Fatal("rollback trusted a never-signaled Done channel")
		}
		close(release)
	})
}

// closedDoneReplayContext reports one already-signaled deadline edge.
type closedDoneReplayContext struct {
	done <-chan struct{}
}

// Deadline returns one future bound while Done is already signaled.
func (c closedDoneReplayContext) Deadline() (time.Time, bool) {
	return time.Now().Add(time.Second), true
}

// Done returns the injected already-signaled channel.
func (c closedDoneReplayContext) Done() <-chan struct{} { return c.done }

// Err reports deadline expiry for the synthetic deadline edge.
func (closedDoneReplayContext) Err() error { return context.DeadlineExceeded }

// Value returns no context value.
func (closedDoneReplayContext) Value(any) any { return nil }

// futureDeadlineNilDoneReplayContext violates the bounded context contract.
type futureDeadlineNilDoneReplayContext struct{}

// Deadline reports a future deadline that has no corresponding Done channel.
func (futureDeadlineNilDoneReplayContext) Deadline() (time.Time, bool) {
	return time.Now().Add(time.Second), true
}

// Done returns nil despite the reported deadline.
func (futureDeadlineNilDoneReplayContext) Done() <-chan struct{} { return nil }

// Err reports no terminal state.
func (futureDeadlineNilDoneReplayContext) Err() error { return nil }

// Value returns no context value.
func (futureDeadlineNilDoneReplayContext) Value(any) any { return nil }

// closedDoneNilErrorReplayContext contradicts its terminal signal.
type closedDoneNilErrorReplayContext struct {
	done <-chan struct{}
}

// newClosedDoneNilErrorReplayContext constructs one closed-signal contradiction.
func newClosedDoneNilErrorReplayContext() closedDoneNilErrorReplayContext {
	done := make(chan struct{})
	close(done)
	return closedDoneNilErrorReplayContext{done: done}
}

// Deadline returns one future bound.
func (closedDoneNilErrorReplayContext) Deadline() (time.Time, bool) {
	return time.Now().Add(time.Second), true
}

// Done returns an already-closed channel.
func (c closedDoneNilErrorReplayContext) Done() <-chan struct{} { return c.done }

// Err incorrectly reports no terminal state.
func (closedDoneNilErrorReplayContext) Err() error { return nil }

// Value returns no context value.
func (closedDoneNilErrorReplayContext) Value(any) any { return nil }

// singleSnapshotReplayContext panics if cleanup re-reads frozen bound methods.
type singleSnapshotReplayContext struct {
	deadline      time.Time
	done          chan struct{}
	cancelOnRead  bool
	errCalls      atomic.Int32
	deadlineCalls atomic.Int32
	doneCalls     atomic.Int32
}

// newSingleSnapshotReplayContext constructs one live single-snapshot bound.
func newSingleSnapshotReplayContext(cancelOnRead bool) *singleSnapshotReplayContext {
	return &singleSnapshotReplayContext{
		deadline:     time.Now().Add(time.Second),
		done:         make(chan struct{}),
		cancelOnRead: cancelOnRead,
	}
}

// Deadline returns the bound once and panics on every re-read.
func (c *singleSnapshotReplayContext) Deadline() (time.Time, bool) {
	if c.deadlineCalls.Add(1) != 1 {
		panic("single-snapshot-deadline-reread")
	}
	return c.deadline, true
}

// Done returns the signal once and panics on every re-read.
func (c *singleSnapshotReplayContext) Done() <-chan struct{} {
	if c.doneCalls.Add(1) != 1 {
		panic("single-snapshot-done-reread")
	}
	return c.done
}

// Err changes from live to canceled after the initial frozen snapshot.
func (c *singleSnapshotReplayContext) Err() error {
	if c.errCalls.Add(1) == 1 || !c.cancelOnRead {
		return nil
	}
	return context.Canceled
}

// Value returns no context value.
func (*singleSnapshotReplayContext) Value(any) any { return nil }

// runtimeMaterial loads one immutable snapshot and installs valid fake secrets.
func runtimeMaterial(t *testing.T, document string) *runtimeMaterialFake {
	t.Helper()
	snapshot, err := config.Load([]byte(document), config.FlagValues{})
	if err != nil {
		t.Fatalf("config.Load() failed: %v", err)
	}
	return &runtimeMaterialFake{
		snapshot:         snapshot,
		hmac:             []byte("0123456789abcdef0123456789abcdef"),
		password:         []byte("application-secret"),
		sentinelPassword: []byte("sentinel-secret"),
		certificatePEM:   []byte("certificate-pem"),
		keyPEM:           []byte("key-pem"),
		roots:            [][]byte{{1, 2, 3, 4}},
	}
}

// runtimeWithAuthority constructs one Redis runtime around a supplied fake authority.
func runtimeWithAuthority(
	t *testing.T,
	material *runtimeMaterialFake,
	authority *runtimeAuthorityFake,
) *ReplayRuntime {
	t.Helper()
	runtime, err := newReplayRuntime(context.Background(), material, replayRuntimeFactories{
		newDeriver: dkim2.NewReplayDeriver,
		newProduction: func(
			context.Context,
			redisstore.Config,
			redisstore.Secrets,
		) (replayAuthorityStore, error) {
			return authority, nil
		},
	})
	if err != nil {
		t.Fatalf("newReplayRuntime() failed: %v", err)
	}
	return runtime
}

// runtimeDisabledYAML returns a minimal explicit-disabled snapshot.
func runtimeDisabledYAML() string {
	return `config:
  version: dkim2d-config-v1
protected:
  generation: ` + runtimeTestGeneration + `
server:
  capability_file: /secure/` + runtimeTestGeneration + `/capability
replay:
  backend: disabled
`
}

// runtimeMemoryYAML returns a valid memory snapshot.
func runtimeMemoryYAML() string {
	return `config:
  version: dkim2d-config-v1
protected:
  generation: ` + runtimeTestGeneration + `
server:
  capability_file: /secure/` + runtimeTestGeneration + `/capability
replay:
  backend: memory
  hmac_key_file: /secure/` + runtimeTestGeneration + `/hmac
  epoch: 7
  retention: 2h
  limits:
    max_entries: 17
    max_waiters: 3
    prune_budget: 5
    max_in_flight: 2
    max_admission_waiters: 4
`
}

// runtimeRedisDocument wraps one replay.redis block in a complete snapshot
// that relies on the default redis backend.
func runtimeRedisDocument(block string) string {
	return `config:
  version: dkim2d-config-v1
protected:
  generation: ` + runtimeTestGeneration + `
server:
  capability_file: /secure/` + runtimeTestGeneration + `/capability
replay:
  hmac_key_file: /secure/` + runtimeTestGeneration + `/hmac
  epoch: 11
  retention: 2h
  limits:
    max_in_flight: 2
    max_admission_waiters: 4
  redis:
` + block
}

// runtimeRedisYAML returns a complete standalone TLS snapshot with ACL credentials.
func runtimeRedisYAML() string {
	return runtimeRedisDocument(`    standalone:
      address: 127.0.0.1:6379
    auth:
      username: application
      password_file: /secure/` + runtimeTestGeneration + `/redis-password
    key_prefix: "tenant:"
    tls:
      ca_file: /secure/` + runtimeTestGeneration + `/ca
      server_name: replay.example
`)
}

// runtimeRedisSentinelYAML returns a plaintext Sentinel snapshot with tuned pool and health values.
func runtimeRedisSentinelYAML() string {
	return runtimeRedisDocument(`    mode: sentinel
    sentinel:
      master_name: mymaster
      addresses: "10.0.0.1:26379,10.0.0.2:26379"
    database_number: 3
    protocol: 2
    pool_size: 9
    min_idle_connections: 1
    retries:
      max_attempts: 1
    health:
      interval: 7s
      timeout: 1s
      failure_threshold: 2
    require_noeviction: false
    tls:
      enabled: false
`)
}

// runtimeRedisClusterYAML returns a TLS 1.3 cluster snapshot using system roots.
func runtimeRedisClusterYAML() string {
	return runtimeRedisDocument(`    mode: cluster
    cluster:
      addresses: "10.0.0.1:7000,10.0.0.2:7000,10.0.0.3:7000"
      max_redirects: 4
    tls:
      min_tls_version: TLS1.3
`)
}

// runtimeCloneDER creates one independent nested clone.
func runtimeCloneDER(input [][]byte) [][]byte {
	output := make([][]byte, len(input))
	for index := range input {
		output[index] = append([]byte(nil), input[index]...)
	}
	return output
}

// runtimeClearDER releases one nested byte owner.
func runtimeClearDER(input [][]byte) {
	for index := range input {
		clear(input[index])
		input[index] = nil
	}
}

// runtimeMemoryClearCount returns exact test-only release evidence.
func runtimeMemoryClearCount(store *dkim2.ReplayMemoryStore) int {
	if store == nil {
		return 0
	}
	value := reflect.ValueOf(store)
	if value.IsNil() {
		return 0
	}
	state := value.Elem().FieldByName("state")
	if state.IsNil() {
		return 0
	}
	count := state.Elem().FieldByName("clearCount")
	if !count.IsValid() {
		return 0
	}
	return int(count.Int())
}

// TestReplayRuntimeRedisConfigBoundariesAreAdmittedByTheProvider proves the
// loader and the provider share one grammar: every boundary value that the
// typed configuration accepts also passes provider validation, so a
// configuration that loads never fails provider admission at startup.
func TestReplayRuntimeRedisConfigBoundariesAreAdmittedByTheProvider(t *testing.T) {
	username := strings.Repeat("u", 124) + "@!~%"
	master := strings.Repeat("M", 127) + "_"
	prefix := strings.Repeat("K", 60) + "_.:-"
	sentinels := make([]string, 32)
	for index := range sentinels {
		sentinels[index] = fmt.Sprintf("swarm_sentinel-%d.internal:26379", index)
	}
	documents := map[string]string{
		"standalone-underscore-host": runtimeRedisDocument(`    standalone:
      address: mailstack_valkey:6379
    auth:
      username: "` + username + `"
      password_file: /secure/` + runtimeTestGeneration + `/redis-password
    key_prefix: "` + prefix + `"
    tls:
      enabled: false
`),
		"sentinel-maximum-list": runtimeRedisDocument(`    mode: sentinel
    sentinel:
      master_name: "` + master + `"
      addresses: "` + strings.Join(sentinels, ",") + `"
      username: "` + username + `"
      password_file: /secure/` + runtimeTestGeneration + `/sentinel-password
    tls:
      server_name: localhost
`),
	}
	for name, document := range documents {
		t.Run(name, func(t *testing.T) {
			material := runtimeMaterial(t, document)
			redisConfig, present := material.snapshot.Replay().Redis()
			if !present {
				t.Fatal("boundary document omitted Redis config")
			}
			if err := redisStoreConfig(redisConfig, replayLimits(material.snapshot.Replay())).Validate(); err != nil {
				t.Fatalf("provider refused a loadable boundary configuration: %v", err)
			}
		})
	}
}

// TestReplayRuntimeRedisEmitsBoundedConfigWarnings proves that disabled TLS
// verification and a disabled noeviction check each emit exactly one
// bounded startup warning through the central logger, that a secure
// configuration emits none, and that no record carries the configured
// address, username, verification name, key prefix, or secret material.
func TestReplayRuntimeRedisEmitsBoundedConfigWarnings(t *testing.T) {
	const address = "replay-warning.example:6390"
	weakened := runtimeRedisDocument(`    standalone:
      address: ` + address + `
    auth:
      username: warning-user
      password_file: /secure/` + runtimeTestGeneration + `/redis-password
    key_prefix: "warning-tenant:"
    require_noeviction: false
    tls:
      server_name: warning-verify.example
      insecure_skip_verify: true
`)
	secure := strings.Replace(runtimeRedisYAML(), "127.0.0.1:6379", address, 1)
	for _, test := range []struct {
		name     string
		document string
		want     []string
	}{
		{name: "weakened", document: weakened, want: []string{"tls_insecure_skip_verify", "noeviction_unchecked"}},
		{name: "secure", document: secure},
	} {
		t.Run(test.name, func(t *testing.T) {
			material := runtimeMaterial(t, test.document)
			var logs strings.Builder
			telemetry, err := observability.NewRuntime(
				context.Background(), material.snapshot.Observability(), &logs, config.TracingStartupMaterial{},
			)
			if err != nil {
				t.Fatalf("observability.NewRuntime() error = %v", err)
			}
			t.Cleanup(func() { _ = telemetry.Shutdown(context.Background()) })
			factories := productionReplayRuntimeFactories(telemetry)
			factories.newProduction = func(
				context.Context,
				redisstore.Config,
				redisstore.Secrets,
			) (replayAuthorityStore, error) {
				return &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: true}, nil
			}
			runtime, err := newReplayRuntime(context.Background(), material, factories)
			if err != nil || runtime == nil {
				t.Fatalf("newReplayRuntime() = (%v, %v)", runtime, err)
			}
			t.Cleanup(func() { _ = closeReplayRuntimeBounded(runtime) })
			var got []string
			for line := range strings.Lines(logs.String()) {
				var record map[string]any
				if err := json.Unmarshal([]byte(line), &record); err != nil {
					t.Fatal("central logger wrote a non-JSON record")
				}
				if record["event_id"] != "replay.config.warning" {
					continue
				}
				if record["level"] != "WARN" || record["operation"] != "config" || len(record) != 7 {
					t.Fatalf("warning record has unexpected shape: %v", record)
				}
				warning, _ := record["config_warning"].(string)
				got = append(got, warning)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("warnings = %q, want %q", got, test.want)
			}
			for _, forbidden := range []string{
				"replay-warning.example", "6390", "warning-user", "warning-verify.example",
				"warning-tenant", "application-secret", "redis-password",
			} {
				if strings.Contains(logs.String(), forbidden) {
					t.Fatalf("startup logs exposed %q", forbidden)
				}
			}
		})
	}
}

// TestNewReplayRuntimeRequiresTelemetry proves production composition fails
// closed without the central observability runtime.
func TestNewReplayRuntimeRequiresTelemetry(t *testing.T) {
	runtime, err := NewReplayRuntime(context.Background(), func() context.Context {
		return context.Background()
	}, &config.RuntimePreparation{}, nil)
	if runtime != nil || !errors.Is(err, &ReplayRuntimeError{}) {
		t.Fatalf("NewReplayRuntime(nil telemetry) = (%v, %v)", runtime, err)
	}
}
