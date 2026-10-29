package redisstore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	dkim2 "github.com/croessner/dkim2"
	"github.com/redis/go-redis/v9"
)

// TestCheckAndRememberPinsNonceBearingSetWithPrefix proves the exact pinned
// argument vector, the configured key prefix, and PX milliseconds.
func TestCheckAndRememberPinsNonceBearingSetWithPrefix(t *testing.T) {
	fake := newFakeBackend()
	store := newTestStore(t, fake)
	key, storage := testReplayKey(t, false)
	check, err := store.CheckAndRemember(context.Background(), key, testRetention(t))
	if err != nil || check != dkim2.ReplayCheckFirstSeen {
		t.Fatalf("first check=%v err=%v", check, err)
	}
	want := []any{commandSet, storage, firstTestValue, "nx", commandGet, "px", int64(1500)}
	if got := fake.lastArgs(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("pinned args=%v, want %v", got, want)
	}
	if !strings.HasPrefix(storage, testKeyPrefix+"dkim2:replay:v1:") {
		t.Fatal("storage key lacks the configured prefix")
	}
	check, err = store.CheckAndRemember(context.Background(), key, testRetention(t))
	if err != nil || check != dkim2.ReplayCheckReplayed {
		t.Fatalf("second check=%v err=%v", check, err)
	}
	if !store.AuthorityReady() || store.State() != dkim2.ReplayStoreReady {
		t.Fatal("successful operations degraded the store")
	}
}

// TestCheckAndRememberRecognizesOwnRetriedCommit is the reproducer for the
// lost-reply retry: the first attempt commits, its reply is lost, and the
// retried attempt observes the store's own value. That must be first seen,
// never replayed.
func TestCheckAndRememberRecognizesOwnRetriedCommit(t *testing.T) {
	fake := newFakeBackend()
	fake.lostReplies = 1
	store := newTestStore(t, fake)
	key, storage := testReplayKey(t, false)
	check, err := store.CheckAndRemember(context.Background(), key, testRetention(t))
	if err != nil || check != dkim2.ReplayCheckFirstSeen {
		t.Fatalf("own retried commit check=%v err=%v, want first_seen", check, err)
	}
	if value, _ := fake.stored(storage); value != firstTestValue {
		t.Fatal("own value was not retained")
	}
}

// TestCheckAndRememberReplyMatrix proves the full previous-value mapping.
func TestCheckAndRememberReplyMatrix(t *testing.T) {
	cases := []struct {
		name     string
		reply    *redis.Cmd
		check    dkim2.ReplayCheck
		code     dkim2.ReplayErrorCode
		recovery recoveryClass
	}{
		{name: "nil", reply: redis.NewCmdResult(nil, redis.Nil), check: dkim2.ReplayCheckFirstSeen},
		{name: "own", reply: redis.NewCmdResult(firstTestValue, nil), check: dkim2.ReplayCheckFirstSeen},
		{name: "foreign v2", reply: redis.NewCmdResult(foreignV2Value, nil), check: dkim2.ReplayCheckReplayed},
		{name: "legacy v1", reply: redis.NewCmdResult(dkim2.ReplayStoredValue, nil), check: dkim2.ReplayCheckReplayed},
		{name: "pending value", reply: redis.NewCmdResult("pending:1", nil), code: dkim2.ReplayErrorInconsistent, recovery: recoveryRestart},
		{name: "uppercase nonce", reply: redis.NewCmdResult("v2:FFFFFFFFFFFFFFFF", nil), code: dkim2.ReplayErrorInconsistent, recovery: recoveryRestart},
		{name: "integer", reply: redis.NewCmdResult(int64(1), nil), code: dkim2.ReplayErrorInconsistent, recovery: recoveryRestart},
		{name: "array", reply: redis.NewCmdResult([]any{"v1"}, nil), code: dkim2.ReplayErrorInconsistent, recovery: recoveryRestart},
		{name: "oversized", reply: redis.NewCmdResult(strings.Repeat("x", maximumReplyBytes+1), nil), code: dkim2.ReplayErrorInconsistent, recovery: recoveryRestart},
		{name: "nil with value", reply: redis.NewCmdResult("v1", redis.Nil), code: dkim2.ReplayErrorInternalInvariant, recovery: recoveryRestart},
		{name: caseEOF, reply: redis.NewCmdResult(nil, syntheticNetworkError), code: dkim2.ReplayErrorIndeterminate, recovery: recoveryTransient},
		{name: "plain error", reply: redis.NewCmdResult(nil, errSynthetic), code: dkim2.ReplayErrorIndeterminate, recovery: recoveryTransient},
		{name: "context", reply: redis.NewCmdResult(nil, context.DeadlineExceeded), code: dkim2.ReplayErrorIndeterminate, recovery: recoveryTransient},
		{name: "pool timeout", reply: redis.NewCmdResult(nil, redis.ErrPoolTimeout), code: dkim2.ReplayErrorIndeterminate, recovery: recoveryTransient},
		{name: "closed client", reply: redis.NewCmdResult(nil, redis.ErrClosed), code: dkim2.ReplayErrorIndeterminate, recovery: recoveryTransient},
		{name: caseDial, reply: redis.NewCmdResult(nil, &net.OpError{Op: caseDial, Err: errSynthetic}), code: dkim2.ReplayErrorIndeterminate, recovery: recoveryTransient},
		{name: "wrapped server", reply: redis.NewCmdResult(nil, fmt.Errorf("wrapped: %w", syntheticServerError("READONLY replica"))), code: dkim2.ReplayErrorIndeterminate, recovery: recoveryTransient},
		{name: "nil reply object", reply: nil, code: dkim2.ReplayErrorInternalInvariant, recovery: recoveryRestart},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeBackend()
			fake.reply = func([]any) *redis.Cmd { return test.reply }
			store := newTestStore(t, fake)
			key, _ := testReplayKey(t, false)
			check, err := store.CheckAndRemember(context.Background(), key, testRetention(t))
			if test.code != "" {
				requireCode(t, err, test.code)
				if check != 0 || store.facts.strongest() != test.recovery {
					t.Fatalf("check=%v recovery=%d, want %d", check, store.facts.strongest(), test.recovery)
				}
				return
			}
			if err != nil || check != test.check {
				t.Fatalf("check=%v err=%v, want %v", check, err, test.check)
			}
		})
	}
}

// TestServerErrorMapping proves server error kinds and the single-attempt rule.
func TestServerErrorMapping(t *testing.T) {
	cases := []struct {
		text     string
		single   dkim2.ReplayErrorCode
		retried  dkim2.ReplayErrorCode
		recovery recoveryClass
	}{
		{"NOAUTH Authentication required.", dkim2.ReplayErrorUnavailable, dkim2.ReplayErrorIndeterminate, recoveryRestart},
		{"WRONGPASS invalid username-password pair", dkim2.ReplayErrorUnavailable, dkim2.ReplayErrorIndeterminate, recoveryRestart},
		{"NOPERM this user has no permissions", dkim2.ReplayErrorUnavailable, dkim2.ReplayErrorIndeterminate, recoveryRestart},
		{"OOM command not allowed", dkim2.ReplayErrorUnavailable, dkim2.ReplayErrorIndeterminate, recoveryTransient},
		{"READONLY You can't write against a read only replica.", dkim2.ReplayErrorUnavailable, dkim2.ReplayErrorIndeterminate, recoveryTransient},
		{"MASTERDOWN Link with MASTER is down", dkim2.ReplayErrorUnavailable, dkim2.ReplayErrorIndeterminate, recoveryTransient},
		{"CLUSTERDOWN The cluster is down", dkim2.ReplayErrorUnavailable, dkim2.ReplayErrorIndeterminate, recoveryTransient},
		{"LOADING Redis is loading the dataset in memory", dkim2.ReplayErrorUnavailable, dkim2.ReplayErrorIndeterminate, recoveryTransient},
		{"NOREPLICAS Not enough good replicas to write.", dkim2.ReplayErrorUnavailable, dkim2.ReplayErrorIndeterminate, recoveryTransient},
		{"MISCONF Errors writing to the AOF file", dkim2.ReplayErrorUnavailable, dkim2.ReplayErrorIndeterminate, recoveryTransient},
		{"TRYAGAIN Multiple keys request during rehashing of slot", dkim2.ReplayErrorUnavailable, dkim2.ReplayErrorIndeterminate, recoveryTransient},
		{"BUSY Redis is busy running a script.", dkim2.ReplayErrorUnavailable, dkim2.ReplayErrorIndeterminate, recoveryTransient},
		{"MOVED 3999 127.0.0.1:6381", dkim2.ReplayErrorUnavailable, dkim2.ReplayErrorIndeterminate, recoveryTransient},
		{"ASK 3999 127.0.0.1:6381", dkim2.ReplayErrorUnavailable, dkim2.ReplayErrorIndeterminate, recoveryTransient},
		{"NOSCRIPT No matching script.", dkim2.ReplayErrorInconsistent, dkim2.ReplayErrorInconsistent, recoveryRestart},
		{"ERR max number of clients reached", dkim2.ReplayErrorUnavailable, dkim2.ReplayErrorIndeterminate, recoveryTransient},
		{"ERR max number of clients reached on this node", dkim2.ReplayErrorUnavailable, dkim2.ReplayErrorIndeterminate, recoveryTransient},
		{"ERR max number of clients", dkim2.ReplayErrorInconsistent, dkim2.ReplayErrorInconsistent, recoveryRestart},
		{"ERR syntax error", dkim2.ReplayErrorInconsistent, dkim2.ReplayErrorInconsistent, recoveryRestart},
		{"CROSSSLOT Keys in request don't hash to the same slot", dkim2.ReplayErrorInconsistent, dkim2.ReplayErrorInconsistent, recoveryRestart},
		{"", dkim2.ReplayErrorInconsistent, dkim2.ReplayErrorInconsistent, recoveryRestart},
		{"lowercase kind", dkim2.ReplayErrorInconsistent, dkim2.ReplayErrorInconsistent, recoveryRestart},
		{"1BAD kind", dkim2.ReplayErrorInconsistent, dkim2.ReplayErrorInconsistent, recoveryRestart},
		{strings.Repeat("A", maximumKindBytes+1), dkim2.ReplayErrorInconsistent, dkim2.ReplayErrorInconsistent, recoveryRestart},
	}
	for _, test := range cases {
		single := mapCommandError(syntheticServerError(test.text), true)
		retried := mapCommandError(syntheticServerError(test.text), false)
		if dkim2.ReplayErrorCodeOf(single.err) != test.single || single.recovery != test.recovery ||
			dkim2.ReplayErrorCodeOf(retried.err) != test.retried || retried.recovery != test.recovery {
			t.Fatalf("%q mapped single=%q/%d retried=%q/%d", test.text,
				dkim2.ReplayErrorCodeOf(single.err), single.recovery,
				dkim2.ReplayErrorCodeOf(retried.err), retried.recovery)
		}
	}
}

// TestSingleAttemptRequiresOneAttemptOutsideCluster proves only a
// non-cluster client with max_attempts 1 treats server errors as proof of
// non-execution.
func TestSingleAttemptRequiresOneAttemptOutsideCluster(t *testing.T) {
	for _, test := range []struct {
		mode     Mode
		attempts int
		want     bool
	}{
		{ModeStandalone, 1, true}, {ModeSentinel, 1, true}, {ModeCluster, 1, false},
		{ModeStandalone, 2, false}, {ModeSentinel, 3, false},
	} {
		config := validatedConfig{mode: test.mode, maxAttempts: test.attempts}
		if config.singleAttempt() != test.want {
			t.Fatalf("mode=%d attempts=%d singleAttempt=%t", test.mode, test.attempts, !test.want)
		}
		if test.attempts == 1 && config.clientMaxRetries() != -1 ||
			test.attempts > 1 && config.clientMaxRetries() != test.attempts-1 {
			t.Fatalf("attempts=%d encoded as MaxRetries=%d", test.attempts, config.clientMaxRetries())
		}
	}
}

// TestSuccessClearsTransientButNotRestartFacts proves fact precedence.
func TestSuccessClearsTransientButNotRestartFacts(t *testing.T) {
	fake := newFakeBackend()
	failures := 1
	fake.reply = func([]any) *redis.Cmd {
		if failures > 0 {
			failures--
			return redis.NewCmdResult(nil, syntheticNetworkError)
		}
		return redis.NewCmdResult(nil, redis.Nil)
	}
	store := newTestStore(t, fake)
	key, _ := testReplayKey(t, false)
	_, err := store.CheckAndRemember(context.Background(), key, testRetention(t))
	requireCode(t, err, dkim2.ReplayErrorIndeterminate)
	if store.State() != dkim2.ReplayStoreDegraded || store.AuthorityReady() {
		t.Fatal("transient failure did not degrade")
	}
	if _, err := store.CheckAndRemember(context.Background(), key, testRetention(t)); err != nil {
		t.Fatal(err)
	}
	if store.State() != dkim2.ReplayStoreReady || !store.AuthorityReady() {
		t.Fatal("authoritative success did not clear the transient fact")
	}
	store.publishFailure(recoveryRestart)
	if _, err := store.CheckAndRemember(context.Background(), key, testRetention(t)); err != nil {
		t.Fatal(err)
	}
	if store.State() != dkim2.ReplayStoreDegraded || store.AuthorityReady() {
		t.Fatal("restart fact was cleared by success")
	}
}

// TestMaxClientsRejectionIsTransientAndProbeRecovers proves the connection
// limit rejection degrades only transiently and a successful health probe
// restores readiness without a restart.
func TestMaxClientsRejectionIsTransientAndProbeRecovers(t *testing.T) {
	fake := newFakeBackend()
	fake.reply = func([]any) *redis.Cmd {
		return redis.NewCmdResult(nil, syntheticServerError("ERR max number of clients reached"))
	}
	store := newTestStore(t, fake)
	key, _ := testReplayKey(t, false)
	_, err := store.CheckAndRemember(context.Background(), key, testRetention(t))
	requireCode(t, err, dkim2.ReplayErrorIndeterminate)
	if store.facts.strongest() != recoveryTransient || store.AuthorityReady() {
		t.Fatalf("max-clients recovery=%d, want transient degradation", store.facts.strongest())
	}
	if err := store.Probe(context.Background()); err != nil || !store.AuthorityReady() {
		t.Fatalf("probe err=%v did not restore readiness after max-clients", err)
	}
}

// TestDispatchPanicIsIndeterminateAndSticky proves post-dispatch panic containment.
func TestDispatchPanicIsIndeterminateAndSticky(t *testing.T) {
	fake := newFakeBackend()
	fake.panicOnDo = true
	store := newTestStore(t, fake)
	key, _ := testReplayKey(t, false)
	_, err := store.CheckAndRemember(context.Background(), key, testRetention(t))
	requireCode(t, err, dkim2.ReplayErrorIndeterminate)
	if store.facts.strongest() != recoveryRestart {
		t.Fatal("dispatch panic was not restart-sticky")
	}
	if len(store.gate.slots) != cap(store.gate.slots) {
		t.Fatal("dispatch panic leaked an admission slot")
	}
}

// TestPreflightRefusalsNeverDispatch proves context, lifecycle, and input refusals precede I/O.
func TestPreflightRefusalsNeverDispatch(t *testing.T) {
	fake := newFakeBackend()
	store := newTestStore(t, fake)
	key, _ := testReplayKey(t, false)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	for name, test := range map[string]struct {
		ctx  context.Context
		key  dkim2.ReplayKey
		code dkim2.ReplayErrorCode
	}{
		"nil context": {ctx: nil, key: key, code: dkim2.ReplayErrorInvalidRequest},
		"cancelled":   {ctx: cancelled, key: key, code: dkim2.ReplayErrorCancelled},
		"deadline":    {ctx: expired, key: key, code: dkim2.ReplayErrorDeadlineExceeded},
		"zero key":    {ctx: context.Background(), key: dkim2.ReplayKey{}, code: dkim2.ReplayErrorInvalidRequest},
	} {
		_, err := store.CheckAndRemember(test.ctx, test.key, testRetention(t)) //nolint:staticcheck // Nil context is an intentional hostile input.
		requireCode(t, err, test.code)
		if len(fake.doArgs) != 0 {
			t.Fatalf("%s dispatched a command", name)
		}
	}
	_, err := store.CheckAndRemember(context.Background(), key, dkim2.ReplayRetention{})
	requireCode(t, err, dkim2.ReplayErrorInvalidRequest)
	var nilStore *Store
	_, err = nilStore.CheckAndRemember(context.Background(), key, testRetention(t))
	requireCode(t, err, dkim2.ReplayErrorInvalidRequest)
	if len(fake.doArgs) != 0 {
		t.Fatal("refusal dispatched a command")
	}
}

// TestRetentionBoundsAreEnforced proves the configured retention window.
func TestRetentionBoundsAreEnforced(t *testing.T) {
	fake := newFakeBackend()
	store := newTestStore(t, fake, func(config *Config) {
		config.MinimumRetention = 2 * time.Second
		config.MaximumRetention = time.Hour
	})
	key, _ := testReplayKey(t, false)
	_, err := store.CheckAndRemember(context.Background(), key, testRetention(t))
	requireCode(t, err, dkim2.ReplayErrorInvalidRequest)
	if len(fake.doArgs) != 0 {
		t.Fatal("out-of-bound retention dispatched")
	}
}

// TestNonceSourceFailureFailsClosed proves an exhausted nonce source never writes.
func TestNonceSourceFailureFailsClosed(t *testing.T) {
	fake := newFakeBackend()
	config := testConfig()
	deps := fakeDependencies(fake)
	deps.nonceSource = strings.NewReader("short")
	store, err := newStoreWithDependencies(context.Background(), config, Secrets{}, deps)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := testReplayKey(t, false)
	_, err = store.CheckAndRemember(context.Background(), key, testRetention(t))
	requireCode(t, err, dkim2.ReplayErrorInternalInvariant)
	if len(fake.doArgs) != 0 || store.facts.strongest() != recoveryRestart {
		t.Fatal("nonce failure dispatched or was not restart-sticky")
	}
}

// TestAdmissionLimitsAndCloseDrain proves bounded admission and drain-before-release.
func TestAdmissionLimitsAndCloseDrain(t *testing.T) {
	fake := newFakeBackend()
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	fake.reply = func([]any) *redis.Cmd {
		entered <- struct{}{}
		<-release
		return redis.NewCmdResult(nil, redis.Nil)
	}
	store := newTestStore(t, fake, func(config *Config) {
		config.Limits.MaxInFlight = 1
		config.Limits.MaxAdmissionWaiters = 1
	})
	key, _ := testReplayKey(t, false)
	results := make(chan error, 2)
	go func() {
		_, err := store.CheckAndRemember(context.Background(), key, testRetention(t))
		results <- err
	}()
	<-entered
	go func() {
		_, err := store.CheckAndRemember(context.Background(), key, testRetention(t))
		results <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for store.gate.waiters.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("second operation did not wait")
		}
		time.Sleep(time.Millisecond)
	}
	_, err := store.CheckAndRemember(context.Background(), key, testRetention(t))
	requireCode(t, err, dkim2.ReplayErrorLimitExceeded)

	closed := make(chan error, 1)
	go func() { closed <- store.Close(context.Background()) }()
	for store.State() != dkim2.ReplayStoreClosing {
		if time.Now().After(deadline) {
			t.Fatal("close did not publish closing")
		}
		time.Sleep(time.Millisecond)
	}
	requireCode(t, <-results, dkim2.ReplayErrorClosed)
	_, err = store.CheckAndRemember(context.Background(), key, testRetention(t))
	requireCode(t, err, dkim2.ReplayErrorClosed)
	if fake.closeCalls != 0 {
		t.Fatal("client released before drain")
	}
	close(release)
	if err := <-results; err != nil {
		t.Fatalf("in-flight operation err=%v", err)
	}
	if err := <-closed; err != nil {
		t.Fatalf("close err=%v", err)
	}
	if store.State() != dkim2.ReplayStoreClosed || fake.closeCalls != 1 || store.AuthorityReady() {
		t.Fatal("close did not release exactly once")
	}
	if err := store.Close(context.Background()); err != nil || fake.closeCalls != 1 {
		t.Fatal("repeated close was not idempotent")
	}
	if _, _, err := store.vault.provide(context.Background()); !errors.Is(err, dkim2.NewReplayError(dkim2.ReplayErrorClosed)) &&
		dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorClosed {
		t.Fatal("credentials remained available after close")
	}
}

// TestCloseHonoursCallerDeadlineWhileDraining proves Close does not block past its context.
func TestCloseHonoursCallerDeadlineWhileDraining(t *testing.T) {
	fake := newFakeBackend()
	release := make(chan struct{})
	entered := make(chan struct{})
	fake.reply = func([]any) *redis.Cmd {
		close(entered)
		<-release
		return redis.NewCmdResult(nil, redis.Nil)
	}
	store := newTestStore(t, fake)
	key, _ := testReplayKey(t, false)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = store.CheckAndRemember(context.Background(), key, testRetention(t))
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	requireCode(t, store.Close(ctx), dkim2.ReplayErrorDeadlineExceeded)
	close(release)
	<-done
	if err := store.Close(context.Background()); err != nil || fake.closeCalls != 1 {
		t.Fatalf("second close err=%v calls=%d", err, fake.closeCalls)
	}
}

// TestCloseMapsReleaseFailures proves client release errors and panics are content-free.
func TestCloseMapsReleaseFailures(t *testing.T) {
	fake := newFakeBackend()
	fake.closeErr = errors.New("raw 10.0.0.1:6379 failure")
	store := newTestStore(t, fake)
	err := store.Close(context.Background())
	requireCode(t, err, dkim2.ReplayErrorUnavailable)
	if strings.Contains(err.Error(), "10.0.0.1") {
		t.Fatal("close error leaked raw detail")
	}
}

// TestConstructionContainsFactoryFailures proves panics, nil clients, and
// invalid input never yield a store and never leave credentials live.
func TestConstructionContainsFactoryFailures(t *testing.T) {
	var captured *credentialVault
	deps := fakeDependencies(nil)
	deps.newBackend = func(_ validatedConfig, vault *credentialVault, _ *constructionMaterial) backend {
		captured = vault
		panic("synthetic factory panic")
	}
	store, err := newStoreWithDependencies(context.Background(), testConfig(), Secrets{Password: []byte("pw")}, deps)
	requireCode(t, err, dkim2.ReplayErrorInternalInvariant)
	if store != nil || captured == nil {
		t.Fatal("factory panic produced a store")
	}
	if _, _, err := captured.provide(context.Background()); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorClosed {
		t.Fatal("factory panic left credentials live")
	}

	deps.newBackend = func(validatedConfig, *credentialVault, *constructionMaterial) backend {
		var typedNil *fakeBackend
		return typedNil
	}
	_, err = newStoreWithDependencies(context.Background(), testConfig(), Secrets{}, deps)
	requireCode(t, err, dkim2.ReplayErrorMisconfigured)

	invalid := testConfig()
	invalid.Mode = 0
	_, err = NewStore(context.Background(), invalid, Secrets{})
	requireCode(t, err, dkim2.ReplayErrorMisconfigured)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = NewStore(cancelled, testConfig(), Secrets{})
	requireCode(t, err, dkim2.ReplayErrorCancelled)
}

// TestStoreSeamRemainsNarrow prevents accidental growth of the backend seam.
func TestStoreSeamRemainsNarrow(t *testing.T) {
	if got := reflectMethodCount[backend](); got != 10 {
		t.Fatalf("backend methods=%d, want 10 (six scripting, Do, two topology probes, Close)", got)
	}
}
