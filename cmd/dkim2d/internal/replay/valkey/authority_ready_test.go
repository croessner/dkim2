package valkey

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	dkim2 "github.com/croessner/dkim2"
	valkeygo "github.com/valkey-io/valkey-go"
)

// TestAuthorityReadyOwnsExactFreshnessAndRevalidation proves the provider-owned deadline.
func TestAuthorityReadyOwnsExactFreshnessAndRevalidation(t *testing.T) {
	start := time.Unix(20_000, 0)
	clock := &mutableSecurityClock{now: start}
	dependencies := validProductionDependencies(t, &fakeOwnedApplicationClient{
		mode: valkeygo.ClientModeStandalone,
	})
	dependencies.clock = clock
	store := mustProductionStore(t, dependencies)
	t.Cleanup(func() { _ = store.Close(context.Background()) })

	if !store.AuthorityReady() {
		t.Fatal("fresh construction evidence was not ready")
	}
	clock.set(start.Add(securityEvidenceValidity - time.Nanosecond))
	if !store.AuthorityReady() {
		t.Fatal("strictly sub-deadline evidence was not ready")
	}
	clock.set(start.Add(securityEvidenceValidity))
	if store.AuthorityReady() ||
		store.facts.load()&recoveryStaleEvidenceBit == 0 ||
		store.strongestRecovery() != recoveryRevalidation {
		t.Fatal("exact-deadline evidence did not publish stale revalidation state")
	}

	refreshed := start.Add(securityEvidenceValidity + time.Minute)
	clock.set(refreshed)
	if err := store.Revalidate(context.Background(), validAuditorConfig()); err != nil {
		t.Fatal(err)
	}
	if !store.AuthorityReady() ||
		store.facts.load()&recoveryStaleEvidenceBit != 0 ||
		store.facts.has(recoveryRevalidation) {
		t.Fatal("successful revalidation did not refresh and heal authority")
	}
	clock.set(refreshed.Add(securityEvidenceValidity))
	if store.AuthorityReady() {
		t.Fatal("refreshed evidence remained ready at its exact deadline")
	}
}

// TestAuthorityReadyIsLocalAndRequiresUndegradedReadyState proves the side-effect boundary.
func TestAuthorityReadyIsLocalAndRequiresUndegradedReadyState(t *testing.T) {
	var auditCalls atomic.Int32
	dependencies := validProductionDependencies(t, &fakeOwnedApplicationClient{
		mode: valkeygo.ClientModeStandalone,
	})
	baseAudit := dependencies.newAuditWire
	dependencies.newAuditWire = func(
		ctx context.Context,
		authority auditAuthority,
		publish func(auditWire),
	) error {
		auditCalls.Add(1)
		return baseAudit(ctx, authority, publish)
	}
	store := mustProductionStore(t, dependencies)
	commandProbe := &fakeCommandClient{}
	store.client = commandProbe
	if auditCalls.Load() != 1 || !store.AuthorityReady() || !store.AuthorityReady() {
		t.Fatal("local readiness did not preserve fresh construction authority")
	}
	if auditCalls.Load() != 1 {
		t.Fatal("readiness performed a live audit")
	}
	if builds, dispatches := commandProbe.counts(); builds != 0 || dispatches != 0 {
		t.Fatal("readiness performed datastore command I/O")
	}

	for _, recovery := range []recoveryClass{
		recoveryTransient,
		recoveryRevalidation,
		recoveryRestart,
	} {
		candidate := mustProductionStore(t, validProductionDependencies(
			t,
			&fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone},
		))
		candidate.publishFailure(recovery)
		if candidate.AuthorityReady() {
			t.Fatal("degraded recovery state was reported ready")
		}
		_ = candidate.Close(context.Background())
	}
	if (&Store{}).AuthorityReady() || (*Store)(nil).AuthorityReady() {
		t.Fatal("zero or nil provider was reported ready")
	}
	store.securityEnforced = false
	if store.AuthorityReady() {
		t.Fatal("non-production provider was reported authority-ready")
	}
	store.securityEnforced = true
	store.gate.state.Store(uint32(lifecycleClosing))
	if store.AuthorityReady() {
		t.Fatal("closing provider was reported ready")
	}
	store.gate.state.Store(uint32(lifecycleClosed))
	if store.AuthorityReady() {
		t.Fatal("closed provider was reported ready")
	}
}

// TestAuthorityReadyFailsClosedOnImpossibleClock proves restart-only timer degradation.
func TestAuthorityReadyFailsClosedOnImpossibleClock(t *testing.T) {
	for _, clock := range []securityClock{
		fixedSecurityClock{},
		fixedSecurityClock{now: time.Unix(9_999, 0)},
		panicSecurityClock{},
	} {
		store := mustProductionStore(t, validProductionDependencies(t, &fakeOwnedApplicationClient{
			mode: valkeygo.ClientModeStandalone,
		}))
		store.clock = newSerializedSecurityClock(clock)
		if store.AuthorityReady() || !store.facts.has(recoveryRestart) {
			t.Fatal("impossible clock did not fail closed with restart recovery")
		}
		_ = store.Close(context.Background())
	}
}

// TestRejectedRevalidationPreservesFreshAuthority freezes token and caller cancellation semantics.
func TestRejectedRevalidationPreservesFreshAuthority(t *testing.T) {
	store := mustProductionStore(t, validProductionDependencies(t, &fakeOwnedApplicationClient{
		mode: valkeygo.ClientModeStandalone,
	}))
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	deadline := store.evidence.deadlineSnapshot()

	store.revalidation.Store(true)
	limited := validAuditorConfig()
	err := store.Revalidate(context.Background(), limited)
	store.revalidation.Store(false)
	if dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorLimitExceeded ||
		store.evidence.deadlineSnapshot() != deadline ||
		store.facts.load() != 0 ||
		!store.AuthorityReady() {
		t.Fatal("exclusive-token refusal changed fresh authority")
	}
	if _, live := limited.snapshot(); !live {
		t.Fatal("provider consumed caller-owned auditor credentials")
	}
	limited.Close()

	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled := validAuditorConfig()
	err = store.Revalidate(cancelledContext, cancelled)
	if dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorCancelled ||
		store.evidence.deadlineSnapshot() != deadline ||
		store.facts.load() != 0 ||
		!store.AuthorityReady() {
		t.Fatal("caller cancellation changed fresh authority")
	}
	if _, live := cancelled.snapshot(); !live {
		t.Fatal("provider consumed cancelled caller credentials")
	}
	cancelled.Close()
}

// TestProviderBorrowsOpaqueConfigsWithoutConsumingCallerOwnership freezes M12 ownership.
func TestProviderBorrowsOpaqueConfigsWithoutConsumingCallerOwnership(t *testing.T) {
	clientConfig := validClientConfig(t)
	auditorConfig := validAuditorConfig()
	dependencies := validProductionDependencies(t, &fakeOwnedApplicationClient{
		mode: valkeygo.ClientModeStandalone,
	})
	store, err := newProductionStoreWithDependencies(
		context.Background(),
		clientConfig,
		mustOperatorAttestation(t),
		auditorConfig,
		dependencies,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close(context.Background()) }()
	if _, live := clientConfig.snapshot(); !live {
		t.Fatal("construction consumed caller-owned client input")
	}
	if _, live := auditorConfig.snapshot(); !live {
		t.Fatal("construction consumed caller-owned auditor input")
	}

	runtimeAuditor := validAuditorConfig()
	if err := store.Revalidate(context.Background(), runtimeAuditor); err != nil {
		t.Fatal(err)
	}
	if _, live := runtimeAuditor.snapshot(); !live {
		t.Fatal("revalidation consumed caller-owned auditor input")
	}
	clientConfig.Close()
	auditorConfig.Close()
	runtimeAuditor.Close()
}
