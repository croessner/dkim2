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
	"github.com/croessner/dkim2/cmd/dkim2d/internal/replay/valkey"
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
	snapshot config.Snapshot
	hmac     []byte
	app      []byte
	auditor  []byte
	roots    [][]byte

	mu                 sync.Mutex
	materialCalls      int
	auditorCalls       int
	materialErr        error
	auditorErr         error
	afterMaterial      func()
	afterAuditor       func()
	auditorBorrowSizes []int
}

// Snapshot returns the immutable effective configuration.
func (f *runtimeMaterialFake) Snapshot() config.Snapshot { return f.snapshot }

// UseReplayMaterial lends independent complete startup material.
func (f *runtimeMaterialFake) UseReplayMaterial(
	use func([]byte, []byte, []byte, [][]byte) error,
) error {
	f.mu.Lock()
	f.materialCalls++
	borrowErr := f.materialErr
	hmac := append([]byte(nil), f.hmac...)
	app := append([]byte(nil), f.app...)
	auditor := append([]byte(nil), f.auditor...)
	roots := runtimeCloneDER(f.roots)
	after := f.afterMaterial
	f.mu.Unlock()
	if borrowErr != nil {
		return borrowErr
	}
	err := use(hmac, app, auditor, roots)
	clear(hmac)
	clear(app)
	clear(auditor)
	runtimeClearDER(roots)
	if after != nil {
		after()
	}
	return err
}

// UseReplayAuditorPassword lends one fresh least-authority clone.
func (f *runtimeMaterialFake) UseReplayAuditorPassword(use func([]byte) error) error {
	f.mu.Lock()
	f.auditorCalls++
	borrowErr := f.auditorErr
	auditor := append([]byte(nil), f.auditor...)
	f.auditorBorrowSizes = append(f.auditorBorrowSizes, len(auditor))
	after := f.afterAuditor
	f.mu.Unlock()
	if borrowErr != nil {
		return borrowErr
	}
	err := use(auditor)
	clear(auditor)
	if after != nil {
		after()
	}
	return err
}

// ReplayAuditorSource returns a least-authority view of the test material.
func (f *runtimeMaterialFake) ReplayAuditorSource() replayAuditorSource {
	return runtimeAuditorMaterialFake{owner: f}
}

// runtimeAuditorMaterialFake exposes only the periodic auditor test seam.
type runtimeAuditorMaterialFake struct {
	owner *runtimeMaterialFake
}

// UseReplayAuditorPassword delegates one least-authority test borrow.
func (f runtimeAuditorMaterialFake) UseReplayAuditorPassword(use func([]byte) error) error {
	if f.owner == nil {
		return errors.New("missing auditor owner")
	}
	return f.owner.UseReplayAuditorPassword(use)
}

// Calls returns synchronized borrow counts.
func (f *runtimeMaterialFake) Calls() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.materialCalls, f.auditorCalls
}

// runtimeAuthorityFake is one deterministic production-authority double.
type runtimeAuthorityFake struct {
	mu                  sync.Mutex
	state               dkim2.ReplayStoreState
	ready               bool
	closeCalls          int
	readyCalls          int
	revalidateCalls     int
	revalidateResponses []error
	auditors            []valkey.AuditorConfig
	auditorPointers     []uintptr
	openAuditorInputs   []bool
	auditorUsers        []string
	auditorPasswords    [][]byte
	closeErr            error
	closeHook           func()
	closeContextHook    func(context.Context)
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
			material := runtimeMaterial(t, runtimeValkeyYAML())
			authority := &runtimeAuthorityFake{
				state:               dkim2.ReplayStoreReady,
				ready:               true,
				revalidateResponses: []error{response},
			}
			runtime := runtimeWithAuthority(t, material, authority)
			ctx, cancel := context.WithCancel(context.Background())
			material.afterAuditor = cancel
			if err := runtime.Revalidate(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("post-call cancellation returned %v", err)
			}
			_ = closeReplayRuntimeBounded(runtime)
		})
	}
	t.Run("deadline-after-unknown-result", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeValkeyYAML())
		authority := &runtimeAuthorityFake{
			state:               dkim2.ReplayStoreReady,
			ready:               true,
			revalidateResponses: []error{errors.New("protected provider result marker")},
		}
		runtime := runtimeWithAuthority(t, material, authority)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		material.afterAuditor = func() { <-ctx.Done() }
		if err := runtime.Revalidate(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("post-call deadline returned %v", err)
		}
		if authority.revalidateCalls != 1 {
			t.Fatal("deadline case did not exercise post-auditor precedence")
		}
		_ = closeReplayRuntimeBounded(runtime)
	})
}

// TestReplayRuntimeCloseCollapsesErrorsAndPreservesContextPrecedence proves release semantics.
func TestReplayRuntimeCloseCollapsesErrorsAndPreservesContextPrecedence(t *testing.T) {
	t.Run("store-error-still-closes-deriver", func(t *testing.T) {
		material := runtimeMaterial(t, runtimeValkeyYAML())
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
		material := runtimeMaterial(t, runtimeValkeyYAML())
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
		material := runtimeMaterial(t, runtimeValkeyYAML())
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
		material := runtimeMaterial(t, runtimeValkeyYAML())
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
		material := runtimeMaterial(t, runtimeValkeyYAML())
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
		material := runtimeMaterial(t, runtimeValkeyYAML())
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
		material := runtimeMaterial(t, runtimeValkeyYAML())
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
		material := runtimeMaterial(t, runtimeValkeyYAML())
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
		material := runtimeMaterial(t, runtimeValkeyYAML())
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

// Revalidate captures only bounded evidence from the ephemeral auditor input.
func (s *runtimeAuthorityFake) Revalidate(_ context.Context, auditor valkey.AuditorConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revalidateCalls++
	s.auditors = append(s.auditors, auditor)
	s.auditorPointers = append(s.auditorPointers, runtimeOpaquePointer(auditor))
	open, username, password := runtimeAuditorSnapshot(auditor)
	s.openAuditorInputs = append(s.openAuditorInputs, open)
	s.auditorUsers = append(s.auditorUsers, username)
	s.auditorPasswords = append(s.auditorPasswords, password)
	index := s.revalidateCalls - 1
	if index < len(s.revalidateResponses) {
		return s.revalidateResponses[index]
	}
	return nil
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

// runtimeClientEvidence is bounded test-only normalized client input evidence.
type runtimeClientEvidence struct {
	open       bool
	endpoint   string
	serverName string
	username   string
	password   []byte
	roots      [][]byte
	epoch      uint32
	limits     dkim2.ReplayLimits
	dial       time.Duration
	keepalive  time.Duration
	write      time.Duration
}

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
			valkey.ClientConfig,
			valkey.OperatorAttestation,
			valkey.AuditorConfig,
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
	if materialCalls, auditorCalls := material.Calls(); materialCalls != 0 || auditorCalls != 0 {
		t.Fatal("disabled backend borrowed protected material")
	}
	if !runtime.AuthorityReady() || runtime.RevalidationInterval() != 0 {
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
	if materialCalls, auditorCalls := material.Calls(); materialCalls != 1 || auditorCalls != 0 {
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

// TestReplayRuntimeValkeyUsesOneStartupBorrowAndFreshAuditBorrows proves authority separation.
func TestReplayRuntimeValkeyUsesOneStartupBorrowAndFreshAuditBorrows(t *testing.T) {
	material := runtimeMaterial(t, runtimeValkeyYAML())
	authority := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: true}
	expectedAttestation, expectedAttestationPresent := material.snapshot.Replay().OperatorAttestation()
	if !expectedAttestationPresent {
		t.Fatal("fixture omitted operator attestation")
	}
	var factoryCalls atomic.Int32
	var retainedClient valkey.ClientConfig
	var retainedAuditor valkey.AuditorConfig
	var clientOpen, auditorOpen, attestationExact bool
	var clientEvidence runtimeClientEvidence
	factories := replayRuntimeFactories{
		newDeriver:  dkim2.NewReplayDeriver,
		newDisabled: newDisabledReplayStore,
		newProduction: func(
			_ context.Context,
			client valkey.ClientConfig,
			attestation valkey.OperatorAttestation,
			auditor valkey.AuditorConfig,
		) (replayAuthorityStore, error) {
			factoryCalls.Add(1)
			retainedClient = client
			retainedAuditor = auditor
			clientOpen = runtimeOpaqueOpen(client)
			clientEvidence = runtimeReadClientEvidence(client)
			auditorOpen, _, _ = runtimeAuditorSnapshot(auditor)
			attestationExact = reflect.DeepEqual(attestation, expectedAttestation)
			return authority, nil
		},
	}
	runtime, err := newReplayRuntime(context.Background(), material, factories)
	if err != nil || runtime == nil {
		t.Fatalf("newReplayRuntime() = (%v, %v)", runtime, err)
	}
	assertRuntimeValkeyStartup(
		t, material, authority, runtime, factoryCalls.Load(), clientOpen, auditorOpen,
		attestationExact, clientEvidence, retainedClient, retainedAuditor,
	)
	assertRuntimeFreshAuditorBorrows(t, material, authority, runtime)
	if err := closeReplayRuntimeBounded(runtime); err != nil || authority.closeCalls != 1 {
		t.Fatal("Valkey runtime did not close its authority")
	}
}

// assertRuntimeValkeyStartup verifies exact normalized inputs and post-call release.
func assertRuntimeValkeyStartup(
	t *testing.T,
	material *runtimeMaterialFake,
	authority *runtimeAuthorityFake,
	runtime *ReplayRuntime,
	factoryCalls int32,
	clientOpen bool,
	auditorOpen bool,
	attestationExact bool,
	clientEvidence runtimeClientEvidence,
	retainedClient valkey.ClientConfig,
	retainedAuditor valkey.AuditorConfig,
) {
	t.Helper()
	replayConfig := material.snapshot.Replay()
	valkeyConfig, valkeyPresent := replayConfig.Valkey()
	if !valkeyPresent {
		t.Fatal("fixture omitted Valkey config")
	}
	if factoryCalls != 1 || !clientOpen || !auditorOpen || !attestationExact {
		t.Fatal("Valkey production factory did not receive exactly one live input pair")
	}
	if !clientEvidence.open ||
		clientEvidence.endpoint != valkeyConfig.Address() ||
		clientEvidence.serverName != valkeyConfig.ServerName() ||
		clientEvidence.username != valkeyConfig.ApplicationUsername() ||
		string(clientEvidence.password) != "application-secret" ||
		clientEvidence.epoch != replayConfig.Epoch() ||
		clientEvidence.limits != replayLimits(replayConfig) ||
		clientEvidence.dial != valkeyConfig.DialTimeout() ||
		clientEvidence.keepalive != valkeyConfig.TCPKeepalive() ||
		clientEvidence.write != valkeyConfig.ConnectionWriteTimeout() ||
		!reflect.DeepEqual(clientEvidence.roots, material.roots) {
		t.Fatal("Valkey production factory received changed client authority inputs")
	}
	if runtimeOpaqueOpen(retainedClient) || runtimeOpaqueOpen(retainedAuditor) {
		t.Fatal("caller-owned startup config copies remained live after factory return")
	}
	if materialCalls, auditorCalls := material.Calls(); materialCalls != 1 || auditorCalls != 0 {
		t.Fatal("Valkey startup borrowed material more than once")
	}
	if !runtime.AuthorityReady() || authority.readyCalls != 1 ||
		runtime.RevalidationInterval() != replayConfig.RevalidateInterval() {
		t.Fatal("Valkey readiness delegation or interval is wrong")
	}
}

// assertRuntimeFreshAuditorBorrows proves one distinct least-authority owner per audit.
func assertRuntimeFreshAuditorBorrows(
	t *testing.T,
	material *runtimeMaterialFake,
	authority *runtimeAuthorityFake,
	runtime *ReplayRuntime,
) {
	t.Helper()
	for range 2 {
		if err := runtime.Revalidate(context.Background()); err != nil {
			t.Fatalf("Revalidate() failed: %v", err)
		}
	}
	if materialCalls, auditorCalls := material.Calls(); materialCalls != 1 || auditorCalls != 2 {
		t.Fatal("periodic revalidation did not use only fresh auditor borrows")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.revalidateCalls != 2 ||
		authority.auditorPointers[0] == authority.auditorPointers[1] {
		t.Fatal("Revalidate() reused an auditor owner")
	}
	for index := range authority.auditors {
		if !authority.openAuditorInputs[index] ||
			authority.auditorUsers[index] != "auditor" ||
			string(authority.auditorPasswords[index]) != "auditor-secret" ||
			runtimeOpaqueOpen(authority.auditors[index]) {
			t.Fatal("Revalidate() violated ephemeral auditor ownership")
		}
	}
}

// TestReplayRuntimeReadinessNeverUsesRevalidationAsAHealthTimestamp proves delegation.
func TestReplayRuntimeReadinessNeverUsesRevalidationAsAHealthTimestamp(t *testing.T) {
	material := runtimeMaterial(t, runtimeValkeyYAML())
	authority := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: false}
	runtime, err := newReplayRuntime(context.Background(), material, replayRuntimeFactories{
		newDeriver: dkim2.NewReplayDeriver,
		newProduction: func(
			context.Context,
			valkey.ClientConfig,
			valkey.OperatorAttestation,
			valkey.AuditorConfig,
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
	if runtime.AuthorityReady() {
		t.Fatal("unready authority reported ready before audit")
	}
	if err := runtime.Revalidate(context.Background()); err != nil {
		t.Fatalf("successful Revalidate() failed: %v", err)
	}
	if runtime.AuthorityReady() || authority.readyCalls != 2 {
		t.Fatal("successful audit replaced delegated readiness with a timestamp")
	}
}

// TestReplayRuntimeUsesTheValidatedDefaultRevalidationInterval proves default projection.
func TestReplayRuntimeUsesTheValidatedDefaultRevalidationInterval(t *testing.T) {
	document := strings.Replace(runtimeValkeyYAML(), "  revalidate_interval: 10s\n", "", 1)
	material := runtimeMaterial(t, document)
	authority := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: true}
	runtime, err := newReplayRuntime(context.Background(), material, replayRuntimeFactories{
		newDeriver: dkim2.NewReplayDeriver,
		newProduction: func(
			context.Context,
			valkey.ClientConfig,
			valkey.OperatorAttestation,
			valkey.AuditorConfig,
		) (replayAuthorityStore, error) {
			return authority, nil
		},
	})
	if err != nil {
		t.Fatalf("newReplayRuntime() failed: %v", err)
	}
	if runtime.RevalidationInterval() != 30*time.Second {
		t.Fatalf("default interval = %s", runtime.RevalidationInterval())
	}
	if err := closeReplayRuntimeBounded(runtime); err != nil {
		t.Fatalf("Close() failed: %v", err)
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
				material := runtimeMaterial(t, runtimeValkeyYAML())
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
						valkey.ClientConfig,
						valkey.OperatorAttestation,
						valkey.AuditorConfig,
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
		material := runtimeMaterial(t, runtimeValkeyYAML())
		var deriver *dkim2.ReplayDeriver
		var constructorErr error
		runtime, err := newReplayRuntime(context.Background(), material, replayRuntimeFactories{
			newDeriver: func(secret []byte, epoch uint32) (*dkim2.ReplayDeriver, error) {
				deriver, constructorErr = dkim2.NewReplayDeriver(secret, epoch)
				return deriver, constructorErr
			},
			newProduction: func(
				context.Context,
				valkey.ClientConfig,
				valkey.OperatorAttestation,
				valkey.AuditorConfig,
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

// TestReplayRuntimeUsesExactAllowedRevalidationErrorTaxonomy proves every code.
func TestReplayRuntimeUsesExactAllowedRevalidationErrorTaxonomy(t *testing.T) {
	allowed := map[dkim2.ReplayErrorCode]bool{
		dkim2.ReplayErrorLimitExceeded:     true,
		dkim2.ReplayErrorUnavailable:       true,
		dkim2.ReplayErrorInconsistent:      true,
		dkim2.ReplayErrorInternalInvariant: true,
	}
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
			material := runtimeMaterial(t, runtimeValkeyYAML())
			authority := &runtimeAuthorityFake{
				state:               dkim2.ReplayStoreReady,
				ready:               true,
				revalidateResponses: []error{dkim2.NewReplayError(code)},
			}
			runtime, err := newReplayRuntime(context.Background(), material, replayRuntimeFactories{
				newDeriver: dkim2.NewReplayDeriver,
				newProduction: func(
					context.Context,
					valkey.ClientConfig,
					valkey.OperatorAttestation,
					valkey.AuditorConfig,
				) (replayAuthorityStore, error) {
					return authority, nil
				},
			})
			if err != nil {
				t.Fatalf("newReplayRuntime() failed: %v", err)
			}
			err = runtime.Revalidate(context.Background())
			if allowed[code] {
				if dkim2.ReplayErrorCodeOf(err) != code {
					t.Fatalf("allowed %q returned %v", code, err)
				}
			} else if !IsReplayRuntimeError(err) {
				t.Fatalf("forbidden %q returned %v", code, err)
			}
			if closeErr := closeReplayRuntimeBounded(runtime); closeErr != nil {
				t.Fatalf("Close() failed: %v", closeErr)
			}
		})
	}
}

// TestReplayRuntimeErrorsContextAndPrivacyRemainBounded proves public surfaces.
func TestReplayRuntimeErrorsContextAndPrivacyRemainBounded(t *testing.T) {
	material := runtimeMaterial(t, runtimeValkeyYAML())
	authority := &runtimeAuthorityFake{
		state: dkim2.ReplayStoreReady,
		ready: true,
		revalidateResponses: []error{
			dkim2.NewReplayError(dkim2.ReplayErrorUnavailable),
			errors.New("protected authority marker"),
			dkim2.NewReplayError(dkim2.ReplayErrorCancelled),
		},
	}
	runtime, err := newReplayRuntime(context.Background(), material, replayRuntimeFactories{
		newDeriver: dkim2.NewReplayDeriver,
		newProduction: func(
			context.Context,
			valkey.ClientConfig,
			valkey.OperatorAttestation,
			valkey.AuditorConfig,
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
	if err := runtime.Revalidate(context.Background()); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorUnavailable {
		t.Fatal("ordinary typed replay error did not survive")
	}
	if err := runtime.Revalidate(context.Background()); !IsReplayRuntimeError(err) {
		t.Fatal("unknown provider error did not collapse")
	}
	if err := runtime.Revalidate(context.Background()); !IsReplayRuntimeError(err) {
		t.Fatal("provider context taxonomy escaped without caller context proof")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.Revalidate(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("terminal caller context lost precedence")
	}
	material.auditorErr = errors.New("protected borrow marker")
	if err := runtime.Revalidate(context.Background()); !IsReplayRuntimeError(err) {
		t.Fatal("borrow error did not collapse")
	}
	const marker = "runtime-protected-marker"
	material.auditor = []byte(marker)
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

// TestReplayRuntimeSupportsConcurrentReadinessRevalidationAndClose proves race safety.
func TestReplayRuntimeSupportsConcurrentReadinessRevalidationAndClose(t *testing.T) {
	material := runtimeMaterial(t, runtimeValkeyYAML())
	authority := &runtimeAuthorityFake{state: dkim2.ReplayStoreReady, ready: true}
	runtime, err := newReplayRuntime(context.Background(), material, replayRuntimeFactories{
		newDeriver: dkim2.NewReplayDeriver,
		newProduction: func(
			context.Context,
			valkey.ClientConfig,
			valkey.OperatorAttestation,
			valkey.AuditorConfig,
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
			_ = runtime.Revalidate(context.Background())
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
	material := runtimeMaterial(t, runtimeValkeyYAML())
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
	material := runtimeMaterial(t, runtimeValkeyYAML())
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
		material := runtimeMaterial(t, runtimeValkeyYAML())
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
		material := runtimeMaterial(t, runtimeValkeyYAML())
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
		snapshot: snapshot,
		hmac:     []byte("0123456789abcdef0123456789abcdef"),
		app:      []byte("application-secret"),
		auditor:  []byte("auditor-secret"),
		roots:    [][]byte{{1, 2, 3, 4}},
	}
}

// runtimeWithAuthority constructs one Valkey runtime around a supplied fake authority.
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
			valkey.ClientConfig,
			valkey.OperatorAttestation,
			valkey.AuditorConfig,
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

// runtimeValkeyYAML returns a complete direct-authority snapshot.
func runtimeValkeyYAML() string {
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
  revalidate_interval: 10s
  valkey:
    address: 127.0.0.1:6379
    server_name: replay.example
    ca_file: /secure/` + runtimeTestGeneration + `/ca
    application_username: application
    application_password_file: /secure/` + runtimeTestGeneration + `/application-password
    auditor_username: auditor
    auditor_password_file: /secure/` + runtimeTestGeneration + `/auditor-password
    attestation:
      persistence_mode: rdb
      append_fsync_policy: inactive
      save_schedule: "60 1"
      min_replicas_to_write: 0
      min_replicas_max_lag_seconds: 30
      loss_window_acceptance: asynchronous_acknowledged
      rotation_state: unchanged
      no_global_exactly_once_claim: true
      dedicated_deployment: true
      dedicated_database_zero: true
      direct_ip_authority: true
      no_endpoint_substitution: true
      standalone_authority: true
      shared_draft: true
      shared_algorithm: true
      shared_namespace: true
      shared_epoch: true
      shared_secret_set: true
      shared_retention: true
`
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

// runtimeOpaquePointer returns the protected config owner identity.
func runtimeOpaquePointer(input any) uintptr {
	value := reflect.ValueOf(input)
	if value.Kind() != reflect.Struct || value.NumField() != 1 {
		return 0
	}
	field := value.Field(0)
	if field.Kind() != reflect.Pointer || field.IsNil() {
		return 0
	}
	return field.Pointer()
}

// runtimeOpaqueOpen reports whether one opaque Valkey config remains live.
func runtimeOpaqueOpen(input any) bool {
	value := reflect.ValueOf(input)
	if value.Kind() != reflect.Struct || value.NumField() != 1 {
		return false
	}
	values := value.Field(0)
	if values.Kind() != reflect.Pointer || values.IsNil() {
		return false
	}
	closed := values.Elem().FieldByName("closed")
	return closed.IsValid() && !closed.Bool()
}

// runtimeAuditorSnapshot reads bounded test evidence while the config is live.
func runtimeAuditorSnapshot(input valkey.AuditorConfig) (bool, string, []byte) {
	value := reflect.ValueOf(input).Field(0)
	if value.IsNil() {
		return false, "", nil
	}
	values := value.Elem()
	if values.FieldByName("closed").Bool() {
		return false, "", nil
	}
	username := values.FieldByName("Username").String()
	passwordField := values.FieldByName("Password")
	password := make([]byte, passwordField.Len())
	for index := range password {
		password[index] = byte(passwordField.Index(index).Uint())
	}
	return true, username, password
}

// runtimeReadClientEvidence reads normalized fields while the owned config is live.
func runtimeReadClientEvidence(input valkey.ClientConfig) runtimeClientEvidence {
	value := reflect.ValueOf(input).Field(0)
	if value.IsNil() {
		return runtimeClientEvidence{}
	}
	values := value.Elem()
	if values.FieldByName("closed").Bool() {
		return runtimeClientEvidence{}
	}
	evidence := runtimeClientEvidence{
		open:       true,
		endpoint:   values.FieldByName("Endpoint").String(),
		serverName: values.FieldByName("TLSServerName").String(),
		username:   values.FieldByName("Username").String(),
		password:   runtimeReflectBytes(values.FieldByName("Password")),
		epoch:      uint32(values.FieldByName("Epoch").Uint()),
		dial:       time.Duration(values.FieldByName("DialTimeout").Int()),
		keepalive:  time.Duration(values.FieldByName("TCPKeepAlive").Int()),
		write:      time.Duration(values.FieldByName("ConnWriteTimeout").Int()),
	}
	roots := values.FieldByName("RootCertificatesDER")
	evidence.roots = make([][]byte, roots.Len())
	for index := range evidence.roots {
		evidence.roots[index] = runtimeReflectBytes(roots.Index(index))
	}
	limits := values.FieldByName("Limits")
	evidence.limits = dkim2.ReplayLimits{
		MaxEntries:          int(limits.FieldByName("MaxEntries").Int()),
		MaxWaiters:          int(limits.FieldByName("MaxWaiters").Int()),
		PruneBudget:         int(limits.FieldByName("PruneBudget").Int()),
		MaxInFlight:         int(limits.FieldByName("MaxInFlight").Int()),
		MaxAdmissionWaiters: int(limits.FieldByName("MaxAdmissionWaiters").Int()),
	}
	return evidence
}

// runtimeReflectBytes copies one reflected byte slice without exposing ownership.
func runtimeReflectBytes(value reflect.Value) []byte {
	output := make([]byte, value.Len())
	for index := range output {
		output[index] = byte(value.Index(index).Uint())
	}
	return output
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
