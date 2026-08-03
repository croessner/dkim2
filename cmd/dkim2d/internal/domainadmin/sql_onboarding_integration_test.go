//go:build datasourceintegration

package domainadmin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	datasourcemysql "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/mysql"
	datasourcepostgresql "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/postgresql"
	datasourceruntime "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/runtime"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/sqlsnapshot"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

type disposableRuntimeLoader interface {
	Load(context.Context) (datasourceruntime.Candidate, error)
}

type disposableSQLCase struct {
	backend   datasourceadmin.BackendClass
	authority datasourceadmin.AuthorityDescriptor
	openAdmin func(context.Context) (*sqlsnapshot.Administrator, error)
	openLoad  func() disposableRuntimeLoader
}

type disposableSigningAuthorizer struct {
	recipients [][]byte
}

// Authorize approves only the exact query already bounded by the disposable
// route, policy, publication, and provider-current test state.
func (a disposableSigningAuthorizer) Authorize(
	ctx context.Context,
	query dkim2.SigningAuthorizationQuery,
) (dkim2.SigningAuthorizationResult, error) {
	if err := ctx.Err(); err != nil {
		return dkim2.SigningAuthorizationResult{}, err
	}
	if !query.Valid() ||
		(query.Purpose() != dkim2.SigningAuthorizationPolicy &&
			query.Purpose() != dkim2.SigningAuthorizationRecipientDisclosure) ||
		(query.Purpose() == dkim2.SigningAuthorizationRecipientDisclosure &&
			!sameDisposableRecipients(a.recipients, query.Recipients())) {
		return dkim2.DenySigning(query), nil
	}
	return dkim2.AuthorizeSigning(query), nil
}

// sameDisposableRecipients compares exact ordered envelope recipients.
func sameDisposableRecipients(expected, actual [][]byte) bool {
	if len(expected) != len(actual) {
		return false
	}
	for index := range expected {
		if !bytes.Equal(expected[index], actual[index]) {
			return false
		}
	}
	return true
}

// TestDisposableSQLDomainOnboardingAndRuntimeSigning proves the complete
// journaled workflow and exact activated-generation signing on every SQL backend.
func TestDisposableSQLDomainOnboardingAndRuntimeSigning(t *testing.T) {
	rootCAs, trust := disposableIntegrationTrust(t)
	for name, testCase := range disposableSQLCases(t, rootCAs, trust) {
		current := testCase
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			administrator, err := current.openAdmin(ctx)
			cancel()
			if err != nil {
				t.Fatal("open disposable SQL administrator")
			}
			defer administrator.Close()
			intent := testIntent(t, provider.AlgorithmEd25519SHA256)
			plan := runDisposableJournaledOnboarding(
				t, administrator, current.backend, current.authority, intent,
			)
			defer plan.Close() //nolint:errcheck // Test cleanup has no recovery action.
			proveDisposableActivatedRuntimeSigning(
				t, administrator, current.openLoad(), plan, intent,
			)
		})
	}
}

// disposableSQLCases constructs exact role-separated administration and
// runtime loader factories from invocation-owned service material.
func disposableSQLCases(
	t *testing.T,
	rootCAs *x509.CertPool,
	trust [sha256.Size]byte,
) map[string]disposableSQLCase {
	t.Helper()
	return map[string]disposableSQLCase{
		"postgresql": disposablePostgreSQLCase(t, rootCAs, trust),
		"mysql": disposableMySQLCase(
			t, rootCAs, trust, datasourceadmin.BackendMySQL,
			"DKIM2_MYSQL_PORT", "DKIM2_MYSQL_SERVER_NAME", "DKIM2_MYSQL_PASSWORD",
			"aibqibiga4eascqlbqgy3dymc4",
		),
		"mariadb": disposableMySQLCase(
			t, rootCAs, trust, datasourceadmin.BackendMariaDB,
			"DKIM2_MARIADB_PORT", "DKIM2_MARIADB_SERVER_NAME", "DKIM2_MARIADB_PASSWORD",
			"aibqibiga4eascqlbqgzav3y4m",
		),
	}
}

// disposablePostgreSQLCase constructs one PostgreSQL integration case.
func disposablePostgreSQLCase(
	t *testing.T,
	rootCAs *x509.CertPool,
	trust [sha256.Size]byte,
) disposableSQLCase {
	t.Helper()
	port := disposableIntegrationPort(t, "DKIM2_POSTGRESQL_PORT")
	serverName := disposableIntegrationEnvironment(t, "DKIM2_POSTGRESQL_SERVER_NAME")
	config := func(user, password string) datasourcepostgresql.ConnectionConfig {
		return datasourcepostgresql.ConnectionConfig{
			Address: "127.0.0.1:" + strconv.Itoa(int(port)), ServerName: serverName,
			Database: "dkim2", User: user, Password: []byte(password), RootCAs: rootCAs,
			ConnectTimeout: 5 * time.Second, MaxConnections: 2,
		}
	}
	return disposableSQLCase{
		backend: datasourceadmin.BackendPostgreSQL,
		authority: disposableSQLAuthority(
			datasourceadmin.BackendPostgreSQL, "aebagbafaydqqcikbmga2dqpca",
			port, serverName, "dkim2_datasource", trust,
		),
		openAdmin: func(ctx context.Context) (*sqlsnapshot.Administrator, error) {
			return datasourcepostgresql.OpenAdministrator(
				ctx,
				config("dkim2_snapshot_login", disposableIntegrationEnvironment(t, "DKIM2_SQL_SNAPSHOT_PASSWORD")),
				config("dkim2_staging_login", disposableIntegrationEnvironment(t, "DKIM2_SQL_STAGING_PASSWORD")),
				config("dkim2_activation_login", disposableIntegrationEnvironment(t, "DKIM2_SQL_ACTIVATION_PASSWORD")),
				provider.DefaultLimits(), testAdminGenerationLimits(), 2,
			)
		},
		openLoad: func() disposableRuntimeLoader {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			pool, err := datasourcepostgresql.OpenPool(ctx, config(
				"dkim2_runtime_login", disposableIntegrationEnvironment(t, "DKIM2_POSTGRESQL_PASSWORD"),
			))
			if err != nil {
				t.Fatal("open disposable PostgreSQL runtime pool")
			}
			loader, err := datasourcepostgresql.NewLoader(
				pool, provider.DefaultLimits(), 1, 4<<20, 10*time.Second,
			)
			if err != nil {
				pool.Close()
				t.Fatal("construct disposable PostgreSQL runtime loader")
			}
			t.Cleanup(loader.Close)
			return loader
		},
	}
}

// disposableMySQLCase constructs one MySQL-family integration case.
func disposableMySQLCase(
	t *testing.T,
	rootCAs *x509.CertPool,
	trust [sha256.Size]byte,
	backend datasourceadmin.BackendClass,
	portName string,
	serverNameName string,
	runtimePasswordName string,
	authorityID string,
) disposableSQLCase {
	t.Helper()
	port := disposableIntegrationPort(t, portName)
	serverName := disposableIntegrationEnvironment(t, serverNameName)
	config := func(user, password string) datasourcemysql.ConnectionConfig {
		return datasourcemysql.ConnectionConfig{
			Address: "127.0.0.1:" + strconv.Itoa(int(port)), ServerName: serverName,
			Database: "dkim2", User: user, Password: []byte(password), RootCAs: rootCAs,
			ConnectTimeout: 5 * time.Second, MaxConnections: 2,
		}
	}
	return disposableSQLCase{
		backend: backend,
		authority: disposableSQLAuthority(
			backend, authorityID, port, serverName, "dkim2", trust,
		),
		openAdmin: func(ctx context.Context) (*sqlsnapshot.Administrator, error) {
			return datasourcemysql.OpenAdministrator(
				ctx,
				config("dkim2_snapshot_login", disposableIntegrationEnvironment(t, "DKIM2_SQL_SNAPSHOT_PASSWORD")),
				config("dkim2_staging_login", disposableIntegrationEnvironment(t, "DKIM2_SQL_STAGING_PASSWORD")),
				config("dkim2_activation_login", disposableIntegrationEnvironment(t, "DKIM2_SQL_ACTIVATION_PASSWORD")),
				provider.DefaultLimits(), testAdminGenerationLimits(), 2,
			)
		},
		openLoad: func() disposableRuntimeLoader {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			pool, err := datasourcemysql.OpenPool(ctx, config(
				"dkim2_runtime_login", disposableIntegrationEnvironment(t, runtimePasswordName),
			))
			if err != nil {
				t.Fatal("open disposable MySQL-family runtime pool")
			}
			loader, err := datasourcemysql.NewLoader(
				pool, provider.DefaultLimits(), 1, 4<<20, 10*time.Second,
			)
			if err != nil {
				pool.Close()
				t.Fatal("construct disposable MySQL-family runtime loader")
			}
			t.Cleanup(loader.Close)
			return loader
		},
	}
}

// disposableSQLAuthority binds the exact disposable endpoint, role set, and CA.
func disposableSQLAuthority(
	backend datasourceadmin.BackendClass,
	authorityID string,
	port uint16,
	serverName string,
	schema string,
	trust [sha256.Size]byte,
) datasourceadmin.AuthorityDescriptor {
	return datasourceadmin.AuthorityDescriptor{
		AuthorityID: authorityID,
		Endpoints: []datasourceadmin.AuthorityEndpoint{{
			Scheme: string(backend), Host: "127.0.0.1", Port: port, TLSServerName: serverName,
		}},
		SQL: &datasourceadmin.SQLAuthority{
			Database: "dkim2", Schema: schema,
			SnapshotRole: "dkim2_snapshot_login", StagingRole: "dkim2_staging_login",
			ActivationRole: "dkim2_activation_login",
		},
		TrustFingerprints: [][sha256.Size]byte{trust},
	}
}

// runDisposableJournaledOnboarding runs every public offline phase twice,
// proves bounded nonmutating reconcile, and returns the activated journal plan.
func runDisposableJournaledOnboarding(
	t *testing.T,
	backend OnboardingBackend,
	backendClass datasourceadmin.BackendClass,
	authority datasourceadmin.AuthorityDescriptor,
	intent Intent,
) *Plan {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(root, 0o700) != nil {
		t.Fatal("protect disposable SQL journal directory")
	}
	store, err := OpenJournalStore(t.Context(), filepath.Join(root, "operation.json"), DefaultLimits())
	if err != nil {
		t.Fatal("open disposable SQL journal")
	}
	defer store.Close() //nolint:errcheck // Test cleanup has no recovery action.
	onboarding := newDisposableOnboarding(t, backend, backendClass, authority, store)
	assertDisposableOnboardingCommand(t, StatePlanned, func() (OnboardingResult, error) {
		return onboarding.Plan(t.Context(), store, intent, planDNSPolicy())
	})
	assertDisposableOnboardingCommand(t, StatePlanned, func() (OnboardingResult, error) {
		return onboarding.Plan(t.Context(), store, intent, planDNSPolicy())
	})
	assertDisposableOnboardingCommand(t, StateStaged, func() (OnboardingResult, error) {
		return onboarding.Prepare(t.Context(), store)
	})
	assertDisposableOnboardingCommand(t, StateStaged, func() (OnboardingResult, error) {
		return onboarding.Prepare(t.Context(), store)
	})
	exportPath := protectedOnboardingPath(t, "dns.txt")
	assertDisposableOnboardingCommand(t, StateDNSExported, func() (OnboardingResult, error) {
		return onboarding.DNSExport(t.Context(), store, exportPath)
	})
	assertDisposableOnboardingCommand(t, StateDNSExported, func() (OnboardingResult, error) {
		return onboarding.DNSExport(t.Context(), store, exportPath)
	})
	assertDisposableOnboardingCommand(t, StateDNSProven, func() (OnboardingResult, error) {
		return onboarding.Prove(t.Context(), store)
	})
	assertDisposableOnboardingCommand(t, StateDNSProven, func() (OnboardingResult, error) {
		return onboarding.Prove(t.Context(), store)
	})
	assertDisposableOnboardingCommand(t, StateDNSProven, func() (OnboardingResult, error) {
		return onboarding.Reconcile(t.Context(), store)
	})
	staleActivation := loadDisposableActivation(t, store)
	assertDisposableOnboardingCommand(t, StateActivated, func() (OnboardingResult, error) {
		return onboarding.Activate(t.Context(), store)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = backend.Activate(ctx, staleActivation)
	cancel()
	if datasourceadmin.CodeOf(err) != datasourceadmin.CodeConflict {
		t.Fatalf("stale exact-current activation code=%s", datasourceadmin.CodeOf(err))
	}
	assertDisposableOnboardingCommand(t, StateActivated, func() (OnboardingResult, error) {
		return onboarding.Activate(t.Context(), store)
	})
	assertDisposableOnboardingCommand(t, StateActivated, func() (OnboardingResult, error) {
		return onboarding.Reconcile(t.Context(), store)
	})
	assertDisposableOnboardingCommand(t, StateActivated, func() (OnboardingResult, error) {
		return onboarding.Reconcile(t.Context(), store)
	})
	return loadRealLDAPPlan(t, store)
}

// loadDisposableActivation detaches the exact pre-activation fence and digest evidence.
func loadDisposableActivation(t *testing.T, store *JournalStore) datasourceadmin.Activation {
	t.Helper()
	receipt, journal, exists, err := store.LoadOperation(t.Context())
	if receipt != nil {
		_ = receipt.Close()
	}
	if err != nil || !exists || receipt != nil || journal == nil {
		_ = journal.Close()
		t.Fatal("load disposable activation journal")
	}
	defer journal.Close() //nolint:errcheck // Detached activation has no recovery action.
	plan, err := journal.clonePlan()
	if err != nil {
		t.Fatal("clone disposable activation plan")
	}
	defer plan.Close() //nolint:errcheck // Detached activation owns copied evidence.
	lock, err := journal.AdministrationLock()
	if err != nil {
		t.Fatal("load disposable activation lock")
	}
	prepared, staged, err := journal.Evidence()
	if err != nil {
		t.Fatal("load disposable activation evidence")
	}
	activation, err := datasourceadmin.NewActivation(
		lock, plan.operation, plan.expectedCurrent, plan.candidateGeneration, prepared, staged,
	)
	if err != nil {
		t.Fatal("construct disposable activation fence")
	}
	return activation
}

// assertDisposableOnboardingCommand requires one exact successful bounded state.
func assertDisposableOnboardingCommand(
	t *testing.T,
	want OperationState,
	call func() (OnboardingResult, error),
) {
	t.Helper()
	result, err := call()
	if err != nil || result.Result != OnboardingResultSuccess || result.State != want {
		t.Fatalf("disposable onboarding state=%s result=%s code=%s", result.State, result.Result, CodeOf(err))
	}
}

// newDisposableOnboarding builds deterministic injected-DNS coordination over
// one real provider without granting any DNS mutation authority.
func newDisposableOnboarding(
	t *testing.T,
	backend OnboardingBackend,
	backendClass datasourceadmin.BackendClass,
	authority datasourceadmin.AuthorityDescriptor,
	store *JournalStore,
) *Onboarding {
	t.Helper()
	limits := DefaultLimits()
	allocator, err := newIdentityAllocator(limits, &incrementingEntropy{})
	if err != nil {
		t.Fatal("construct disposable identity allocator")
	}
	generator, err := newKeyGenerator(DefaultKeyPolicy(), limits, &incrementingEntropy{value: 10})
	if err != nil {
		t.Fatal("construct disposable key generator")
	}
	engine, err := newDNSProofEngine(limits, time.Now, func(
		ctx context.Context,
		_ datasourceadmin.DNSPolicy,
	) (dkim2.PublicKeyProvider, error) {
		plan := loadRealLDAPPlan(t, store)
		defer plan.Close() //nolint:errcheck // Detached DNS derivation has no recovery action.
		candidate, _, inspectErr := backend.Inspect(
			ctx, plan.operation, plan.candidateGeneration, plan.expectedCurrent,
			testAdminGenerationLimits(),
		)
		if inspectErr != nil || candidate == nil {
			return nil, errors.New("candidate inspection unavailable")
		}
		defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery action.
		return disposableCandidatePublicKeys(t, candidate)
	})
	if err != nil {
		t.Fatal("construct disposable DNS proof engine")
	}
	onboarding, err := NewOnboarding(
		limits, testAdminGenerationLimits(), allocator, generator, engine, backend,
		backendClass, authority, time.Now, nil,
	)
	if err != nil {
		t.Fatal("construct disposable onboarding coordinator")
	}
	return onboarding
}

// proveDisposableActivatedRuntimeSigning loads the exact activated current,
// proves readiness and lease generation, then signs and verifies with its key.
func proveDisposableActivatedRuntimeSigning(
	t *testing.T,
	backend OnboardingBackend,
	loader disposableRuntimeLoader,
	plan *Plan,
	intent Intent,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	candidate, info, err := backend.Inspect(
		ctx, plan.operation, plan.candidateGeneration, plan.expectedCurrent,
		testAdminGenerationLimits(),
	)
	cancel()
	if err != nil || candidate == nil || !info.Current {
		if candidate != nil {
			_ = candidate.Close()
		}
		t.Fatal("inspect activated disposable candidate")
	}
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery action.
	publicKeys, err := disposableCandidatePublicKeys(t, candidate)
	if err != nil {
		t.Fatal("construct activated candidate public-key provider")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	runtime, err := datasourceruntime.New(ctx, loader, 10*time.Second)
	cancel()
	if err != nil || !runtime.Ready() {
		t.Fatal("activated datasource runtime is not ready")
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		if closeErr := runtime.Close(closeCtx); closeErr != nil {
			t.Error("close activated datasource runtime")
		}
	}()
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	lease, err := runtime.Acquire(ctx)
	cancel()
	if err != nil {
		t.Fatal("acquire activated datasource runtime lease")
	}
	dataset, generation, err := lease.Dataset()
	if err != nil || dataset == nil || generation != plan.candidateGeneration {
		lease.Release()
		t.Fatal("runtime lease did not pin the activated generation")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	profile, err := lease.ResolvePolicy(
		ctx, testAdminTenant, intent.domain, provider.ProfileUseOriginator, time.Now().UTC(),
	)
	cancel()
	if err != nil || !profile.Valid() {
		lease.Release()
		t.Fatal("runtime lease did not resolve the onboarded policy")
	}
	defer lease.Release()
	raw := []byte("From: sender@" + intent.domain + "\r\nTo: recipient@example.net\r\nSubject: disposable runtime\r\n\r\nbody\r\n")
	reverse := []byte("<sender@" + intent.domain + ">")
	recipients := [][]byte{[]byte("<recipient@example.net>")}
	signer, err := dkim2.NewSigner(
		publicKeys,
		dkim2.NewRequestRouteAuthority(),
		disposableSigningAuthorizer{recipients: recipients},
		lease,
	)
	if err != nil {
		t.Fatal("construct activated datasource signer")
	}
	source, err := dkim2.NewSigningSource(raw)
	if err != nil {
		t.Fatal("construct activated signing source")
	}
	entry, err := dkim2.NewOriginatorRouteEntry(
		source, reverse, recipients, dkim2.RouteDisclosureSingle,
		[]byte("disposable-domain-onboarding"),
	)
	if err != nil {
		t.Fatal("construct activated signing route")
	}
	fanout, err := dkim2.NewRouteFanoutRequest([]dkim2.RouteEntry{entry})
	if err != nil {
		t.Fatal("construct activated route fanout")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	_, tickets, err := signer.PlanRouteFanout(ctx, fanout)
	cancel()
	if err != nil || len(tickets) != 1 {
		t.Fatal("plan activated route fanout")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	result, recovery, err := signer.SignOriginator(
		ctx,
		dkim2.NewOriginatorSigningRequest(
			raw, reverse, recipients, tickets[0], profile, dkim2.SigningMetadata{},
			dkim2.SigningTransportFinalNetworkPreDotStuffing,
		),
	)
	cancel()
	signed, ok := result.Unrestricted()
	if err != nil || recovery.Valid() || !ok || !signed.Valid() {
		t.Fatal("activated datasource signing failed")
	}
	verifier, err := dkim2.NewVerifier(publicKeys)
	if err != nil {
		t.Fatal("construct activated datasource verifier")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	verification, err := verifier.Verify(
		ctx, dkim2.NewVerifyRequest(signed.Bytes(), reverse, recipients),
	)
	cancel()
	if err != nil || verification.State() != dkim2.ResultStatePASS {
		t.Fatal("activated datasource signature did not verify")
	}
}

// disposableCandidatePublicKeys returns an injected provider over exact
// candidate-derived DNS records without exposing record identities.
func disposableCandidatePublicKeys(
	t *testing.T,
	candidate *datasourceadmin.PublicationEnvelope,
) (dkim2.PublicKeyProvider, error) {
	t.Helper()
	answers := candidateDNSAnswersForOnboardingTest(t, candidate)
	transport := &proofTransport{lookup: func(
		_ context.Context,
		owner string,
	) (dkim2.TXTLookupResult, error) {
		payload, found := answers[owner]
		if !found {
			return dkim2.TXTLookupResult{}, errors.New("unexpected DNS owner")
		}
		return dkim2.NewFoundTXTLookupResult(
			[][]byte{payload}, time.Minute, dkim2.DNSSECStatusUnavailable,
		)
	}}
	return dkim2.NewDNSPublicKeyProvider(transport)
}

// disposableIntegrationTrust loads the invocation-owned CA and exact leaf fingerprint.
func disposableIntegrationTrust(t *testing.T) (*x509.CertPool, [sha256.Size]byte) {
	t.Helper()
	content, err := os.ReadFile(disposableIntegrationEnvironment(t, "DKIM2_DATASOURCE_CA"))
	if err != nil {
		t.Fatal("read disposable integration CA")
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(content) {
		t.Fatal("parse disposable integration CA")
	}
	block, _ := pem.Decode(content)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("decode disposable integration CA")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("parse disposable integration certificate")
	}
	return rootCAs, sha256.Sum256(certificate.Raw)
}

// disposableIntegrationPort returns one finite invocation-owned local port.
func disposableIntegrationPort(t *testing.T, name string) uint16 {
	t.Helper()
	value, err := strconv.ParseUint(disposableIntegrationEnvironment(t, name), 10, 16)
	if err != nil || value == 0 {
		t.Fatal("invalid disposable integration port")
	}
	return uint16(value)
}

// disposableIntegrationEnvironment requires one harness-owned nonempty scalar.
func disposableIntegrationEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("missing disposable integration environment %s", name)
	}
	return value
}
