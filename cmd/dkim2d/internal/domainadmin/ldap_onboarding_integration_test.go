//go:build datasourceintegration

package domainadmin

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	ldapdatasource "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/ldap"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

const ldapIntegrationPassword = "synthetic-role-password"

// TestLDAPOnboardingRealActivationAndReconcile runs bootstrap and established
// activation through real role-separated LDAP connections and domain recovery.
func TestLDAPOnboardingRealActivationAndReconcile(t *testing.T) {
	address := os.Getenv("DKIM2_LDAP_INTEGRATION_ADDRESS")
	caPath := os.Getenv("DKIM2_LDAP_INTEGRATION_CA")
	if address == "" || caPath == "" {
		t.Skip("disposable LDAP integration environment is not configured")
	}
	serverName := os.Getenv("DKIM2_LDAP_INTEGRATION_SERVER_NAME")
	if serverName == "" {
		serverName = "localhost"
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal("read disposable LDAP trust root")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("parse disposable LDAP trust root")
	}
	connectorDN := func(bindDN string) *ldapdatasource.GoLDAPConnector {
		value, connectorErr := ldapdatasource.NewGoLDAPConnector(ldapdatasource.ConnectionConfig{
			Address: address, ServerName: serverName, BaseDN: "ou=dkim2,dc=example,dc=test",
			BindDN:   bindDN,
			Password: []byte(ldapIntegrationPassword), RootCAs: pool,
		})
		if connectorErr != nil {
			t.Fatal("construct disposable LDAP role connector")
		}
		return value
	}
	connector := func(role string) *ldapdatasource.GoLDAPConnector {
		return connectorDN("cn=dkim2-" + role + ",ou=services,dc=example,dc=test")
	}
	limits := testAdminGenerationLimits()
	snapshot := connector("snapshot")
	stager := connector("stager")
	activator := connector("activator")
	oidAlias := connectorDN("2.5.4.3=dkim2-snapshot,ou=services,dc=example,dc=test")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	aliasClient, aliasConnectErr := oidAlias.Connect(ctx)
	cancel()
	if aliasConnectErr != nil || aliasClient == nil {
		t.Fatal("bind disposable snapshot role through its attribute OID alias")
	}
	if closeErr := aliasClient.Close(); closeErr != nil {
		t.Fatal("close disposable OID-alias LDAP connection")
	}
	if aliased, aliasErr := ldapdatasource.NewAdministrator(
		snapshot, oidAlias, activator, provider.DefaultLimits(), limits,
	); aliased != nil || datasourceadmin.CodeOf(aliasErr) != datasourceadmin.CodeInvalid {
		t.Fatal("real LDAP OID-alias authority was accepted")
	}
	administrator, err := ldapdatasource.NewAdministrator(
		snapshot, stager, activator,
		provider.DefaultLimits(), limits,
	)
	if err != nil {
		t.Fatal("construct real LDAP administrator")
	}
	runtimeConnector := connector("runtime")
	loader, err := ldapdatasource.NewLoader(
		runtimeConnector, provider.DefaultLimits(), 1, 4<<20, 10*time.Second,
	)
	if err != nil {
		t.Fatal("construct real LDAP runtime loader")
	}
	first := testIntent(t, provider.AlgorithmEd25519SHA256)
	firstPlan := runRealLDAPOnboarding(t, administrator, limits, first, 0, false)
	_ = firstPlan.Close()
	second, err := newIntent(intentDocument{
		Version: intentVersion, Domain: "second.example.test", TenantID: testAdminTenant,
		ProfileUse: testAdminProfileUse, Algorithms: []string{string(provider.AlgorithmEd25519SHA256)},
		Rollout: testAdminRollout, Compatibility: testAdminCompat,
	})
	if err != nil {
		t.Fatal("construct second real LDAP intent")
	}
	secondPlan := runRealLDAPOnboarding(t, administrator, limits, second, 1, true)
	defer secondPlan.Close() //nolint:errcheck // Test cleanup has no recovery action.
	proveDisposableActivatedRuntimeSigning(t, administrator, loader, secondPlan, second)
	assertRealLDAPResourceGuards(t, administrator, limits)
}

// assertRealLDAPResourceGuards proves that real transport reads fail closed
// before returning partial inventories under count, byte, or context bounds.
func assertRealLDAPResourceGuards(
	t *testing.T,
	administrator *ldapdatasource.Administrator,
	limits datasourceadmin.GenerationLimits,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	countLimited := limits
	countLimited.MaxGenerations = 1
	inventory, err := administrator.Inventory(ctx, countLimited)
	if datasourceadmin.CodeOf(err) != datasourceadmin.CodeUnavailable ||
		inventory.Current != 0 || len(inventory.Generations) != 0 {
		t.Fatalf(
			"real LDAP count bound failed closed incorrectly: code=%s nonempty=%t",
			datasourceadmin.CodeOf(err), inventory.Current != 0 || len(inventory.Generations) != 0,
		)
	}
	byteLimited := limits
	byteLimited.MaxSnapshotBytes = 1
	inventory, err = administrator.Inventory(ctx, byteLimited)
	if datasourceadmin.CodeOf(err) != datasourceadmin.CodeUnavailable ||
		inventory.Current != 0 || len(inventory.Generations) != 0 {
		t.Fatalf(
			"real LDAP byte bound failed closed incorrectly: code=%s nonempty=%t",
			datasourceadmin.CodeOf(err), inventory.Current != 0 || len(inventory.Generations) != 0,
		)
	}
	canceled, cancelCanceled := context.WithCancel(context.Background())
	cancelCanceled()
	inventory, err = administrator.Inventory(canceled, limits)
	if datasourceadmin.CodeOf(err) != datasourceadmin.CodeInvalid ||
		inventory.Current != 0 || len(inventory.Generations) != 0 {
		t.Fatalf(
			"real LDAP canceled read failed closed incorrectly: code=%s nonempty=%t",
			datasourceadmin.CodeOf(err), inventory.Current != 0 || len(inventory.Generations) != 0,
		)
	}
}

// runRealLDAPOnboarding executes one complete journaled operation and exact
// terminal reconciliation against the supplied real administrator.
func runRealLDAPOnboarding(
	t *testing.T,
	administrator *ldapdatasource.Administrator,
	limits datasourceadmin.GenerationLimits,
	intent Intent,
	expectedCurrent uint64,
	wantOldHistory bool,
) *Plan {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(root, 0o700) != nil {
		t.Fatal("protect real LDAP journal directory")
	}
	store, err := OpenJournalStore(t.Context(), filepath.Join(root, "operation.json"), DefaultLimits())
	if err != nil {
		t.Fatal("open real LDAP journal")
	}
	defer store.Close() //nolint:errcheck // Test cleanup has no recovery.
	onboarding := realLDAPOnboardingCoordinator(t, administrator, store, byte(expectedCurrent*40))
	result, err := onboarding.Plan(t.Context(), store, intent, planDNSPolicy())
	if err != nil || result.State != StatePlanned {
		t.Fatalf("real LDAP plan failed: code=%s state=%s", CodeOf(err), result.State)
	}
	result, err = onboarding.Plan(t.Context(), store, intent, planDNSPolicy())
	if err != nil || result.State != StatePlanned {
		t.Fatalf("real LDAP idempotent plan failed: code=%s state=%s", CodeOf(err), result.State)
	}
	result, err = onboarding.Prepare(t.Context(), store)
	if err != nil || result.State != StateStaged {
		t.Fatalf("real LDAP prepare failed: code=%s state=%s", CodeOf(err), result.State)
	}
	result, err = onboarding.Prepare(t.Context(), store)
	if err != nil || result.State != StateStaged {
		t.Fatalf("real LDAP idempotent prepare failed: code=%s state=%s", CodeOf(err), result.State)
	}
	exportPath := protectedOnboardingPath(t, "dns.txt")
	result, err = onboarding.DNSExport(t.Context(), store, exportPath)
	if err != nil || result.State != StateDNSExported {
		t.Fatalf("real LDAP DNS export failed: code=%s state=%s", CodeOf(err), result.State)
	}
	result, err = onboarding.DNSExport(t.Context(), store, exportPath)
	if err != nil || result.State != StateDNSExported {
		t.Fatalf("real LDAP idempotent DNS export failed: code=%s state=%s", CodeOf(err), result.State)
	}
	result, err = onboarding.Prove(t.Context(), store)
	if err != nil || result.State != StateDNSProven {
		t.Fatalf("real LDAP DNS proof failed: code=%s state=%s", CodeOf(err), result.State)
	}
	result, err = onboarding.Prove(t.Context(), store)
	if err != nil || result.State != StateDNSProven {
		t.Fatalf("real LDAP idempotent DNS proof failed: code=%s state=%s", CodeOf(err), result.State)
	}
	result, err = onboarding.Reconcile(t.Context(), store)
	if err != nil || result.State != StateDNSProven {
		t.Fatalf("real LDAP bounded pre-activation reconcile failed: code=%s state=%s", CodeOf(err), result.State)
	}
	staleActivation := loadDisposableActivation(t, store)
	result, err = onboarding.Activate(t.Context(), store)
	if err != nil || result.State != StateActivated {
		t.Fatalf("real LDAP activation failed: code=%s state=%s failure=%s", CodeOf(err), result.State, result.Failure)
	}
	conflictCtx, conflictCancel := context.WithTimeout(context.Background(), 5*time.Second)
	conflictErr := administrator.Activate(conflictCtx, staleActivation)
	conflictCancel()
	if datasourceadmin.CodeOf(conflictErr) != datasourceadmin.CodeConflict {
		t.Fatalf("real LDAP stale exact-current activation code=%s", datasourceadmin.CodeOf(conflictErr))
	}
	result, err = onboarding.Activate(t.Context(), store)
	if err != nil || result.State != StateActivated {
		t.Fatalf("real LDAP idempotent activation failed: code=%s state=%s", CodeOf(err), result.State)
	}
	plan := loadRealLDAPPlan(t, store)
	if plan.expectedCurrent != expectedCurrent {
		t.Fatal("real LDAP operation observed wrong expected current")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	observation, err := administrator.Observe(
		ctx, plan.operation, plan.candidateGeneration, plan.expectedCurrent, limits,
	)
	if err != nil || observation.CurrentGeneration() != plan.candidateGeneration ||
		observation.OldCurrentWasActive() != wantOldHistory {
		t.Fatal("real LDAP post-activation observation lost lifecycle evidence")
	}
	candidate, info, err := administrator.Inspect(
		ctx, plan.operation, plan.candidateGeneration, plan.expectedCurrent, limits,
	)
	if candidate != nil {
		defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	}
	if err != nil || candidate == nil || !info.Current || info.State != datasourceadmin.StateCommitted {
		t.Fatal("real LDAP inspection did not prove exact current candidate")
	}
	result, err = onboarding.Reconcile(t.Context(), store)
	if err != nil || result.State != StateActivated {
		t.Fatalf("real LDAP terminal reconcile failed: code=%s state=%s", CodeOf(err), result.State)
	}
	result, err = onboarding.Reconcile(t.Context(), store)
	if err != nil || result.State != StateActivated {
		t.Fatalf("real LDAP idempotent terminal reconcile failed: code=%s state=%s", CodeOf(err), result.State)
	}
	return plan
}

// realLDAPOnboardingCoordinator builds a deterministic test coordinator whose
// DNS answers are derived from independent real LDAP candidate inspection.
func realLDAPOnboardingCoordinator(
	t *testing.T,
	administrator *ldapdatasource.Administrator,
	store *JournalStore,
	entropyOffset byte,
) *Onboarding {
	t.Helper()
	limits := DefaultLimits()
	allocator, err := newIdentityAllocator(limits, &incrementingEntropy{value: entropyOffset})
	if err != nil {
		t.Fatal("construct real LDAP identity allocator")
	}
	generator, err := newKeyGenerator(DefaultKeyPolicy(), limits, &incrementingEntropy{value: entropyOffset + 10})
	if err != nil {
		t.Fatal("construct real LDAP key generator")
	}
	engine, err := newDNSProofEngine(limits, time.Now, func(
		ctx context.Context,
		_ datasourceadmin.DNSPolicy,
	) (dkim2.PublicKeyProvider, error) {
		plan := loadRealLDAPPlan(t, store)
		defer plan.Close() //nolint:errcheck // DNS lookup owns only detached plan state.
		candidate, _, inspectErr := administrator.Inspect(
			ctx, plan.operation, plan.candidateGeneration, plan.expectedCurrent, testAdminGenerationLimits(),
		)
		if inspectErr != nil || candidate == nil {
			return nil, errors.New("candidate inspection unavailable")
		}
		defer candidate.Close() //nolint:errcheck // DNS answer derivation cleanup has no recovery.
		answers := candidateDNSAnswersForOnboardingTest(t, candidate)
		transport := &proofTransport{lookup: func(_ context.Context, owner string) (dkim2.TXTLookupResult, error) {
			payload, found := answers[owner]
			if !found {
				return dkim2.TXTLookupResult{}, errors.New("unexpected DNS owner")
			}
			return dkim2.NewFoundTXTLookupResult(
				[][]byte{payload}, time.Minute, dkim2.DNSSECStatusUnavailable,
			)
		}}
		return dkim2.NewDNSPublicKeyProvider(transport)
	})
	if err != nil {
		t.Fatal("construct real LDAP DNS proof engine")
	}
	onboarding, err := NewOnboarding(
		limits, testAdminGenerationLimits(), allocator, generator, engine, administrator,
		datasourceadmin.BackendLDAP, planAuthority(), time.Now, nil,
	)
	if err != nil {
		t.Fatal("construct real LDAP onboarding coordinator")
	}
	return onboarding
}

// loadRealLDAPPlan returns one detached complete journal plan.
func loadRealLDAPPlan(t *testing.T, store *JournalStore) *Plan {
	t.Helper()
	receipt, journal, exists, err := store.LoadOperation(t.Context())
	if receipt != nil {
		defer receipt.Close() //nolint:errcheck // Unexpected receipt cleanup has no recovery.
	}
	if err != nil || !exists || journal == nil || receipt != nil {
		_ = journal.Close()
		t.Fatal("load real LDAP journal plan")
	}
	defer journal.Close() //nolint:errcheck // Detached plan survives journal cleanup.
	plan, err := journal.clonePlan()
	if err != nil {
		t.Fatal("clone real LDAP journal plan")
	}
	return plan
}
