package redisstore

import (
	"context"
	"errors"
	"strings"
	"testing"

	dkim2 "github.com/croessner/dkim2"
)

// newStoreResult constructs one store over fake and returns the raw error.
func newStoreResult(fake *fakeBackend, mutate ...func(*Config)) (*Store, error) {
	config := testConfig()
	for _, apply := range mutate {
		apply(&config)
	}
	return newStoreWithDependencies(context.Background(), config, Secrets{}, fakeDependencies(fake))
}

// TestStartupChecksPassAndPublishAuthority proves a constructed store is ready without I/O.
func TestStartupChecksPassAndPublishAuthority(t *testing.T) {
	fake := newFakeBackend()
	store, err := newStoreResult(fake)
	if err != nil || !store.AuthorityReady() || store.State() != dkim2.ReplayStoreReady {
		t.Fatalf("store err=%v ready=%t", err, err == nil && store.AuthorityReady())
	}
	fake.pingErr = errSynthetic
	if !store.AuthorityReady() {
		t.Fatal("AuthorityReady performed I/O")
	}
}

// TestStartupChecksRejectViolationsAndCountPrimaries proves fail-start
// semantics, deterministic violation counts, and client release.
func TestStartupChecksRejectViolationsAndCountPrimaries(t *testing.T) {
	old := fakePrimary{server: "redis_version:6.2.14\r\n", memory: "maxmemory_policy:noeviction\r\n"}
	evicting := fakePrimary{server: "redis_version:8.0.2\r\n", memory: "maxmemory_policy:allkeys-lru\r\n"}
	cases := []struct {
		name       string
		primaries  []fakePrimary
		pingErr    error
		reason     StartupReason
		violations int
		code       dkim2.ReplayErrorCode
		mutate     func(*Config)
	}{
		{name: "ping refused", pingErr: errSynthetic, reason: StartupUnavailable, code: dkim2.ReplayErrorUnavailable},
		{name: "ping noauth", pingErr: syntheticServerError("NOAUTH Authentication required."), reason: StartupAuthentication, code: dkim2.ReplayErrorMisconfigured},
		{name: "ping wrongpass", pingErr: syntheticServerError("WRONGPASS invalid"), reason: StartupAuthentication, code: dkim2.ReplayErrorMisconfigured},
		{name: "info noperm", primaries: []fakePrimary{{err: syntheticServerError("NOPERM User has no permissions to run the 'info' command")}}, reason: StartupPermission, code: dkim2.ReplayErrorMisconfigured},
		{name: "old versions", primaries: []fakePrimary{old, healthyPrimary(), old}, reason: StartupUnsupportedVersion, violations: 2, code: dkim2.ReplayErrorMisconfigured},
		{name: "eviction", primaries: []fakePrimary{evicting, evicting, healthyPrimary()}, reason: StartupEvictionPolicy, violations: 2, code: dkim2.ReplayErrorMisconfigured},
		{name: "missing version", primaries: []fakePrimary{{server: "redis_mode:standalone\r\n"}}, reason: StartupMalformedReply, code: dkim2.ReplayErrorMisconfigured},
		{name: "malformed version", primaries: []fakePrimary{{server: "redis_version:7.x.0\r\n"}}, reason: StartupMalformedReply, code: dkim2.ReplayErrorMisconfigured},
		{name: "missing policy", primaries: []fakePrimary{{server: "redis_version:7.0.0\r\n", memory: "used_memory:1\r\n"}}, reason: StartupMalformedReply, code: dkim2.ReplayErrorMisconfigured},
		{name: "oversized info", primaries: []fakePrimary{{server: "redis_version:7.0.0\r\n" + strings.Repeat("x", maximumInfoBytes)}}, reason: StartupMalformedReply, code: dkim2.ReplayErrorMisconfigured},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeBackend()
			fake.pingErr = test.pingErr
			if test.primaries != nil {
				fake.primaries = test.primaries
			}
			store, err := newStoreResult(fake)
			if store != nil {
				t.Fatal("violating backend produced a store")
			}
			var startup *StartupError
			if !errors.As(err, &startup) || startup.Reason() != test.reason || startup.Violations() != test.violations {
				t.Fatalf("err=%v", err)
			}
			if dkim2.ReplayErrorCodeOf(errors.Unwrap(err)) != test.code {
				t.Fatalf("unwrapped code=%q", dkim2.ReplayErrorCodeOf(errors.Unwrap(err)))
			}
			if fake.closeCalls != 1 {
				t.Fatalf("client release calls=%d", fake.closeCalls)
			}
			for _, forbidden := range []string{"6.2.14", "allkeys-lru", "NOPERM User", "Authentication required", "synthetic"} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatalf("startup error leaked server text %q", forbidden)
				}
			}
		})
	}
}

// TestStartupNoEvictionCanBeDisabled proves require_noeviction=false skips only the policy check.
func TestStartupNoEvictionCanBeDisabled(t *testing.T) {
	fake := newFakeBackend()
	fake.primaries = []fakePrimary{{server: "redis_version:7.0.0\r\n", memory: "maxmemory_policy:allkeys-lru\r\n"}}
	if _, err := newStoreResult(fake, func(config *Config) { config.RequireNoEviction = false }); err != nil {
		t.Fatalf("disabled noeviction check err=%v", err)
	}
}

// TestStartupPermissionErrorNamesRequiredACL proves the operator guidance.
func TestStartupPermissionErrorNamesRequiredACL(t *testing.T) {
	text := (&StartupError{reason: StartupPermission}).Error()
	for _, required := range []string{"+hello", "+auth", "+ping", "+info", "+set", "+get", "+eval", "+evalsha", "+select", "+cluster|slots", "dkim2:replay:*"} {
		if !strings.Contains(text, required) {
			t.Fatalf("permission guidance lacks %q", required)
		}
	}
}

// TestSupportedServerVersionGrammar proves the bounded version parser.
func TestSupportedServerVersionGrammar(t *testing.T) {
	for _, test := range []struct {
		version   string
		supported bool
		ok        bool
	}{
		{"7.0.0", true, true}, {"7.2.4", true, true}, {"9.1.2", true, true}, {"6.2.14", false, true},
		{"7.0", false, false}, {"07.0.0", false, false}, {"7.0.0-rc1", false, false}, {"", false, false},
		{"-7.0.0", false, false}, {"7..0", false, false}, {"1234567.0.0", false, false},
	} {
		supported, ok := supportedServerVersion("redis_version:" + test.version + "\r\n")
		if supported != test.supported || ok != test.ok {
			t.Fatalf("%q supported=%t ok=%t", test.version, supported, ok)
		}
	}
}

// TestProbeThresholdSemantics proves N consecutive failures set the transient
// fact, one success clears it, and sticky restart facts remain.
func TestProbeThresholdSemantics(t *testing.T) {
	fake := newFakeBackend()
	store := newTestStore(t, fake, func(config *Config) { config.Health.FailureThreshold = 3 })
	fake.pingErr = errSynthetic
	for attempt := 1; attempt <= 2; attempt++ {
		requireCode(t, store.Probe(context.Background()), dkim2.ReplayErrorUnavailable)
		if !store.AuthorityReady() {
			t.Fatalf("failure %d below threshold degraded readiness", attempt)
		}
	}
	requireCode(t, store.Probe(context.Background()), dkim2.ReplayErrorUnavailable)
	if store.AuthorityReady() || store.State() != dkim2.ReplayStoreDegraded {
		t.Fatal("threshold failures did not degrade readiness")
	}
	fake.pingErr = nil
	if err := store.Probe(context.Background()); err != nil || !store.AuthorityReady() {
		t.Fatalf("successful probe err=%v did not restore readiness", err)
	}
	fake.pingErr = errSynthetic
	for range 2 {
		_ = store.Probe(context.Background())
	}
	if !store.AuthorityReady() {
		t.Fatal("success did not reset the consecutive failure count")
	}
	fake.pingErr = nil
	store.publishFailure(recoveryRestart)
	if err := store.Probe(context.Background()); err != nil || store.AuthorityReady() {
		t.Fatal("probe success cleared a sticky restart fact")
	}
}

// TestProbeClearsTransientWriteFailure proves recovery without restart.
func TestProbeClearsTransientWriteFailure(t *testing.T) {
	fake := newFakeBackend()
	store := newTestStore(t, fake)
	store.publishFailure(recoveryTransient)
	if store.AuthorityReady() {
		t.Fatal("transient fact did not degrade")
	}
	if err := store.Probe(context.Background()); err != nil || !store.AuthorityReady() {
		t.Fatal("probe success did not clear the transient fact")
	}
}

// TestProbeRespectsCallerAndLifecycle proves cancellation precedence, panic
// containment as a sticky internal invariant, bounded probe time, and
// closed-store refusal.
func TestProbeRespectsCallerAndLifecycle(t *testing.T) {
	fake := newFakeBackend()
	store := newTestStore(t, fake, func(config *Config) { config.Health.FailureThreshold = 1 })
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	requireCode(t, store.Probe(cancelled), dkim2.ReplayErrorCancelled)
	if !store.AuthorityReady() {
		t.Fatal("caller cancellation counted as a probe failure")
	}
	fake.pingPanic = true
	requireCode(t, store.Probe(context.Background()), dkim2.ReplayErrorInternalInvariant)
	if store.AuthorityReady() || store.facts.strongest() != recoveryRestart {
		t.Fatalf("panicking probe recovery=%d, want sticky restart", store.facts.strongest())
	}
	fake.pingPanic = false
	if err := store.Probe(context.Background()); err != nil || store.AuthorityReady() {
		t.Fatalf("probe success err=%v cleared the panic restart fact", err)
	}
	if store.healthTimeout != defaultHealthTimeout || store.healthTimeout >= defaultHealthInterval {
		t.Fatal("probe timeout is not the bounded health timeout")
	}
	if err := store.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireCode(t, store.Probe(context.Background()), dkim2.ReplayErrorClosed)
	var nilStore *Store
	requireCode(t, nilStore.Probe(context.Background()), dkim2.ReplayErrorMisconfigured)
}
