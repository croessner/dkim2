package domainadmin

import (
	"context"
	"crypto/sha256"
	"sync"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

const planAuthorityID = "aebagbafaydqqcikbmga2dqpca"

// TestNewPlanDerivesIntentSourceAndClaimFromAllocation freezes the single-owner plan boundary.
func TestNewPlanDerivesIntentSourceAndClaimFromAllocation(t *testing.T) {
	allocation, lock := allocatePlanFixture(t)
	defer allocation.Close() //nolint:errcheck // Test cleanup has no recovery.
	plan, err := NewPlan(t.Context(), datasourceadmin.BackendLDAP, planAuthority(), allocation, planDNSPolicy())
	if err != nil {
		t.Fatal("allocation-bound plan rejected")
	}
	defer plan.Close() //nolint:errcheck // Test cleanup has no recovery.
	other := testIntent(t, provider.AlgorithmEd25519SHA256)
	other.domain = "other.example.test"
	if plan.intent.Domain() != allocation.intent.Domain() || plan.intent.Domain() == other.Domain() ||
		plan.expectedCurrent != 1 || plan.lockRevision != lock.Revision() || !lock.ValidFor(plan.operation) {
		t.Fatal("plan did not derive its exact intent, source generation, and claim from allocation")
	}
	fresh := currentCollisionViewForPlan(t, lock, "current-profile", "current-handle", "current-selector")
	defer fresh.Close() //nolint:errcheck // Test cleanup has no recovery.
	if err := plan.VerifyFresh(t.Context(), lock, fresh, planAuthority()); err != nil {
		t.Fatal("exact fresh lock-bound source did not reproduce the plan digest")
	}
}

// TestPlanVerifyFreshRejectsSameGenerationSubstitution freezes full-source digest binding.
func TestPlanVerifyFreshRejectsSameGenerationSubstitution(t *testing.T) {
	allocation, lock := allocatePlanFixture(t)
	defer allocation.Close() //nolint:errcheck // Test cleanup has no recovery.
	plan, err := NewPlan(t.Context(), datasourceadmin.BackendLDAP, planAuthority(), allocation, planDNSPolicy())
	if err != nil {
		t.Fatal("allocation-bound plan rejected")
	}
	defer plan.Close() //nolint:errcheck // Test cleanup has no recovery.
	substitute := currentCollisionViewForPlan(t, lock, "different-profile", "different-handle", "different-selector")
	defer substitute.Close() //nolint:errcheck // Test cleanup has no recovery.
	if CodeOf(plan.VerifyFresh(t.Context(), lock, substitute, planAuthority())) != CodeConflict {
		t.Fatal("different valid source with the same generation reproduced the plan")
	}
}

// TestPlanVerifyFreshDoesNotConsumeBeforeContextAndClaimValidation freezes retry ownership.
func TestPlanVerifyFreshDoesNotConsumeBeforeContextAndClaimValidation(t *testing.T) {
	allocation, lock := allocatePlanFixture(t)
	defer allocation.Close() //nolint:errcheck // Test cleanup has no recovery.
	plan, err := NewPlan(t.Context(), datasourceadmin.BackendLDAP, planAuthority(), allocation, planDNSPolicy())
	if err != nil {
		t.Fatal("allocation-bound plan rejected")
	}
	defer plan.Close() //nolint:errcheck // Test cleanup has no recovery.
	fresh := currentCollisionViewForPlan(t, lock, "current-profile", "current-handle", "current-selector")
	defer fresh.Close() //nolint:errcheck // Test cleanup has no recovery.
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if CodeOf(plan.VerifyFresh(cancelled, lock, fresh, planAuthority())) != CodeConflict {
		t.Fatal("cancelled verification request accepted")
	}
	wrongRevision, _ := datasourceadmin.NewAdministrationLock(lock.Owner(), lock.Revision()+1)
	if CodeOf(plan.VerifyFresh(t.Context(), wrongRevision, fresh, planAuthority())) != CodeConflict {
		t.Fatal("same-owner different-revision verification accepted")
	}
	if err := plan.VerifyFresh(t.Context(), lock, fresh, planAuthority()); err != nil {
		t.Fatal("precondition rejection consumed the fresh source")
	}
}

// TestNewPlanIssuesExactlyOnceUnderConcurrency freezes allocation lifecycle ownership.
func TestNewPlanIssuesExactlyOnceUnderConcurrency(t *testing.T) {
	allocation, _ := allocatePlanFixture(t)
	defer allocation.Close() //nolint:errcheck // Test cleanup has no recovery.
	var wait sync.WaitGroup
	wait.Add(2)
	results := make(chan *Plan, 2)
	errors := make(chan error, 2)
	for range 2 {
		go func() {
			defer wait.Done()
			plan, err := NewPlan(t.Context(), datasourceadmin.BackendLDAP, planAuthority(), allocation, planDNSPolicy())
			results <- plan
			errors <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errors)
	successes := 0
	for plan := range results {
		if plan != nil {
			successes++
			_ = plan.Close()
		}
	}
	conflicts := 0
	for err := range errors {
		if CodeOf(err) == CodeConflict {
			conflicts++
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatal("allocation issued more or fewer than one plan under concurrency")
	}
	if repeated, err := NewPlan(t.Context(), datasourceadmin.BackendLDAP, planAuthority(), allocation, planDNSPolicy()); CodeOf(err) != CodeConflict || repeated != nil {
		t.Fatal("allocation issued a repeated plan")
	}
}

// TestFailedPlanIssuancePermanentlyConsumesPlanRight freezes divergent retry prevention.
func TestFailedPlanIssuancePermanentlyConsumesPlanRight(t *testing.T) {
	allocation, _ := allocatePlanFixture(t)
	defer allocation.Close() //nolint:errcheck // Test cleanup has no recovery.
	invalidAuthority := planAuthority()
	invalidAuthority.TrustFingerprints = nil
	if plan, err := NewPlan(t.Context(), datasourceadmin.BackendLDAP, invalidAuthority, allocation, planDNSPolicy()); CodeOf(err) != CodeConflict || plan != nil {
		t.Fatal("invalid plan issuance did not fail closed")
	}
	if plan, err := NewPlan(t.Context(), datasourceadmin.BackendLDAP, planAuthority(), allocation, planDNSPolicy()); CodeOf(err) != CodeConflict || plan != nil {
		t.Fatal("failed issuance allowed a divergent retry")
	}
	generator, _ := newKeyGenerator(DefaultKeyPolicy(), DefaultLimits(), &incrementingEntropy{})
	if keys, err := generator.Generate(t.Context(), allocation); CodeOf(err) != CodeConflict || keys != nil {
		t.Fatal("failed plan issuance enabled key generation")
	}
}

// allocatePlanFixture constructs one real allocation from an exact atomic collision view.
func allocatePlanFixture(t *testing.T) (*IdentityAllocation, datasourceadmin.AdministrationLock) {
	t.Helper()
	allocator, err := newIdentityAllocator(DefaultLimits(), &incrementingEntropy{})
	if err != nil {
		t.Fatal("allocator fixture rejected")
	}
	locker := &administrationLockerFake{revision: 23}
	reader := &collisionReaderFake{build: func(
		ctx context.Context,
		lock datasourceadmin.AdministrationLock,
		limits datasourceadmin.GenerationLimits,
	) (*datasourceadmin.CollisionInventory, error) {
		return currentCollisionView(ctx, t, lock, limits, datasourceadmin.OperationBinding{}, "current-profile", "current-handle", "current-selector")
	}}
	allocation, lock, err := allocator.allocateForTest(
		t.Context(), testIntent(t, provider.AlgorithmEd25519SHA256), reader, locker, 23, testAdminGenerationLimits(),
	)
	if err != nil {
		t.Fatal("allocation fixture rejected")
	}
	return allocation, lock
}

// currentCollisionViewForPlan constructs one fresh exact current view for digest verification.
func currentCollisionViewForPlan(
	t *testing.T,
	lock datasourceadmin.AdministrationLock,
	profileID string,
	handleID string,
	selector string,
) *datasourceadmin.CollisionInventory {
	t.Helper()
	view, err := currentCollisionView(
		t.Context(), t, lock, testAdminGenerationLimits(), datasourceadmin.OperationBinding{}, profileID, handleID, selector,
	)
	if err != nil {
		t.Fatal("fresh plan source fixture rejected")
	}
	return view
}

// planAuthority returns one complete verified-TLS LDAP authority descriptor.
func planAuthority() datasourceadmin.AuthorityDescriptor {
	var trust [sha256.Size]byte
	trust[0] = 1
	return datasourceadmin.AuthorityDescriptor{
		AuthorityID: planAuthorityID,
		Endpoints: []datasourceadmin.AuthorityEndpoint{{
			Scheme: "ldaps", Host: testLDAPServerName, Port: 636, TLSServerName: testLDAPServerName,
		}},
		LDAP: &datasourceadmin.LDAPAuthority{
			BaseDN: "dc=example,dc=test", SnapshotPrincipal: "snapshot",
			StagingPrincipal: "staging", ActivationPrincipal: "activation",
		},
		TrustFingerprints: [][sha256.Size]byte{trust},
	}
}

// planDNSPolicy returns one exact bounded system-resolver policy.
func planDNSPolicy() datasourceadmin.DNSPolicy {
	return datasourceadmin.DNSPolicy{ResolverClass: resolverClassSystem, ExportTTLSeconds: 300, ProofLifetimeSeconds: 60}
}
