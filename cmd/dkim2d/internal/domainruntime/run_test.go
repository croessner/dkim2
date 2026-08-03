package domainruntime

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/domainadmin"
	serviceobservability "github.com/croessner/dkim2/cmd/dkim2d/internal/observability"
)

// observedCoordinatorFake emits through the same observer injected into the production coordinator seam.
type observedCoordinatorFake struct {
	observer *serviceobservability.LocalDomainObserver
	backend  datasourceadmin.BackendClass
	result   domainadmin.OnboardingResult
	status   domainadmin.StatusResult
	err      error
	emit     bool
	calls    []domainadmin.Command
}

// workflow emits one configured bounded result for the selected workflow command.
func (f *observedCoordinatorFake) workflow(ctx context.Context, command domainadmin.Command) (domainadmin.OnboardingResult, error) {
	f.calls = append(f.calls, command)
	if f.emit {
		f.observer.ObserveOnboarding(ctx, domainadmin.OnboardingObservation{
			Command: command, State: f.result.State, Backend: f.backend,
			Result: f.result.Result, Failure: f.result.Failure, Receipt: f.result.ReceiptPhase,
		})
	}
	return f.result, f.err
}

// Plan emits one configured plan result.
func (f *observedCoordinatorFake) Plan(ctx context.Context, _ *domainadmin.JournalStore, _ domainadmin.Intent, _ datasourceadmin.DNSPolicy) (domainadmin.OnboardingResult, error) {
	return f.workflow(ctx, domainadmin.CommandPlan)
}

// Prepare emits one configured prepare result.
func (f *observedCoordinatorFake) Prepare(ctx context.Context, _ *domainadmin.JournalStore) (domainadmin.OnboardingResult, error) {
	return f.workflow(ctx, domainadmin.CommandPrepare)
}

// DNSExport emits one configured DNS-export result.
func (f *observedCoordinatorFake) DNSExport(ctx context.Context, _ *domainadmin.JournalStore, _ string) (domainadmin.OnboardingResult, error) {
	return f.workflow(ctx, domainadmin.CommandDNSExport)
}

// Prove emits one configured proof result.
func (f *observedCoordinatorFake) Prove(ctx context.Context, _ *domainadmin.JournalStore) (domainadmin.OnboardingResult, error) {
	return f.workflow(ctx, domainadmin.CommandProve)
}

// Activate emits one configured activation result.
func (f *observedCoordinatorFake) Activate(ctx context.Context, _ *domainadmin.JournalStore) (domainadmin.OnboardingResult, error) {
	return f.workflow(ctx, domainadmin.CommandActivate)
}

// Status emits one configured status result through the production observer.
func (f *observedCoordinatorFake) Status(ctx context.Context, _ *domainadmin.JournalStore) (domainadmin.StatusResult, error) {
	f.calls = append(f.calls, domainadmin.CommandStatus)
	if f.emit {
		f.observer.ObserveOnboarding(ctx, domainadmin.OnboardingObservation{
			Command: domainadmin.CommandStatus, State: f.status.State, Backend: f.backend,
			Result: domainadmin.OnboardingResultSuccess, Failure: f.status.Failure,
			Receipt: f.status.ReceiptPhase,
		})
	}
	return f.status, f.err
}

// Reconcile emits one configured reconciliation result.
func (f *observedCoordinatorFake) Reconcile(ctx context.Context, _ *domainadmin.JournalStore) (domainadmin.OnboardingResult, error) {
	return f.workflow(ctx, domainadmin.CommandReconcile)
}

// Abort emits one configured abort result.
func (f *observedCoordinatorFake) Abort(ctx context.Context, _ *domainadmin.JournalStore) (domainadmin.OnboardingResult, error) {
	return f.workflow(ctx, domainadmin.CommandAbort)
}

// TestProductionLocalObserverGatesSuccessFailureAndStatus freezes mandatory runner consumption.
func TestProductionLocalObserverGatesSuccessFailureAndStatus(t *testing.T) {
	backend := datasourceadmin.BackendLDAP
	for _, test := range []struct {
		name   string
		result *domainadmin.OnboardingResult
		status *domainadmin.StatusResult
		err    error
	}{
		{"success", &domainadmin.OnboardingResult{State: domainadmin.StateStaged, Result: domainadmin.OnboardingResultSuccess, Failure: domainadmin.CodeNone, PlanComplete: true}, nil, nil},
		{"failure", &domainadmin.OnboardingResult{State: domainadmin.StateConflict, Result: domainadmin.OnboardingResultFailure, Failure: domainadmin.CodeConflict, PlanComplete: true}, nil, errors.New("synthetic bounded failure")},
		{"status", nil, &domainadmin.StatusResult{State: domainadmin.StateReconcileRequired, Failure: domainadmin.CodeNone, PlanComplete: true}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			observer := serviceobservability.NewLocalDomainObserver()
			coordinator := &observedCoordinatorFake{
				observer: observer, backend: backend, emit: true, err: test.err,
			}
			if test.result != nil {
				coordinator.result = *test.result
				request := domainadmin.CommandRequest{Command: domainadmin.CommandPrepare}
				result, err := executeObservedWorkflow(
					t.Context(), coordinator, observer, backend, nil, request,
					domainadmin.Intent{}, datasourceadmin.DNSPolicy{},
				)
				if result != *test.result || !errors.Is(err, test.err) || len(coordinator.calls) != 1 {
					t.Fatal("production workflow seam did not execute and consume exact observation")
				}
			} else {
				coordinator.status = *test.status
				status, err := executeObservedStatus(t.Context(), coordinator, observer, backend, nil)
				if err != nil || status != *test.status || len(coordinator.calls) != 1 {
					t.Fatal("production status seam did not execute and consume exact observation")
				}
			}
		})
	}
	missing := serviceobservability.NewLocalDomainObserver()
	coordinator := &observedCoordinatorFake{
		observer: missing, backend: backend, emit: false,
		result: domainadmin.OnboardingResult{
			State: domainadmin.StateStaged, Result: domainadmin.OnboardingResultSuccess,
			Failure: domainadmin.CodeNone, PlanComplete: true,
		},
	}
	if result, err := executeObservedWorkflow(
		t.Context(), coordinator, missing, backend, nil,
		domainadmin.CommandRequest{Command: domainadmin.CommandPrepare}, domainadmin.Intent{}, datasourceadmin.DNSPolicy{},
	); err == nil || result != (domainadmin.OnboardingResult{}) || len(coordinator.calls) != 1 {
		t.Fatal("production workflow seam accepted missing local evidence")
	}
}

// TestOpenBackendWithinDeadlineCancelsBlockedConstruction freezes bounded offline setup.
func TestOpenBackendWithinDeadlineCancelsBlockedConstruction(t *testing.T) {
	started := time.Now()
	owner, err := openBackendWithinDeadline(
		t.Context(), 20*time.Millisecond, &domainadmin.AdminConfig{},
		func(ctx context.Context, _ *domainadmin.AdminConfig) (*backendOwner, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	)
	if err == nil || owner != nil || time.Since(started) > time.Second {
		t.Fatal("blocked backend construction escaped its finite deadline")
	}
}

// TestFourBackendClassesSelectOnlyOfflineConcreteConstructors freezes the production switch matrix.
func TestFourBackendClassesSelectOnlyOfflineConcreteConstructors(t *testing.T) {
	for _, backend := range []datasourceadmin.BackendClass{
		datasourceadmin.BackendLDAP, datasourceadmin.BackendPostgreSQL,
		datasourceadmin.BackendMySQL, datasourceadmin.BackendMariaDB,
	} {
		t.Run(string(backend), func(t *testing.T) {
			calls := map[string]int{}
			marker := &backendOwner{close: func() {}}
			constructors := backendConstructors{
				ldap: func(*domainadmin.AdminConnectionMaterial, datasourceadmin.GenerationLimits) (*backendOwner, error) {
					calls["ldap"]++
					return marker, nil
				},
				postgresql: func(context.Context, *domainadmin.AdminConnectionMaterial, datasourceadmin.GenerationLimits) (*backendOwner, error) {
					calls["postgresql"]++
					return marker, nil
				},
				mysqlFamily: func(context.Context, *domainadmin.AdminConnectionMaterial, datasourceadmin.GenerationLimits) (*backendOwner, error) {
					calls["mysql-family"]++
					return marker, nil
				},
			}
			owner, err := openMaterialBackend(t.Context(), &domainadmin.AdminConnectionMaterial{Backend: backend}, datasourceadmin.GenerationLimits{}, constructors)
			if err != nil || owner != marker {
				t.Fatal("backend class did not select its offline constructor")
			}
			want := map[datasourceadmin.BackendClass]string{
				datasourceadmin.BackendLDAP: "ldap", datasourceadmin.BackendPostgreSQL: "postgresql",
				datasourceadmin.BackendMySQL: "mysql-family", datasourceadmin.BackendMariaDB: "mysql-family",
			}[backend]
			if calls[want] != 1 || len(calls) != 1 {
				t.Fatal("backend construction crossed provider authority")
			}
		})
	}
}

// TestLDAPOfflineConstructionRequiresNoNetworkAndCloses proves the real three-role constructor path.
func TestLDAPOfflineConstructionRequiresNoNetworkAndCloses(t *testing.T) {
	material := testConnectionMaterial(datasourceadmin.BackendLDAP)
	material.Address = "192.0.2.10:636"
	material.BaseDN = "ou=dkim2,dc=example,dc=test"
	material.Snapshot.Identity = "cn=snapshot,ou=services,dc=example,dc=test"
	material.Staging.Identity = "cn=stager,ou=services,dc=example,dc=test"
	material.Activation.Identity = "cn=activator,ou=services,dc=example,dc=test"
	owner, err := openLDAPBackend(material, testGenerationLimits())
	if err != nil || owner == nil || owner.backend == nil {
		t.Fatal("real LDAP offline constructor failed before network I/O")
	}
	owner.Close()
	owner.Close()
}

// TestDomainRuntimeImportsExcludeOnlineSubsystems freezes the no-daemon/no-exporter boundary.
func TestDomainRuntimeImportsExcludeOnlineSubsystems(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve domainruntime test location")
	}
	directory := filepath.Dir(filename)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal("read domainruntime package")
	}
	observabilityImports := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		parsed, parseErr := parser.ParseFile(token.NewFileSet(), filepath.Join(directory, entry.Name()), nil, parser.ImportsOnly)
		if parseErr != nil {
			t.Fatal("parse domainruntime imports")
		}
		for _, declaration := range parsed.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, specification := range general.Specs {
				importSpec, ok := specification.(*ast.ImportSpec)
				if !ok {
					continue
				}
				path, _ := strconv.Unquote(importSpec.Path.Value)
				if path == "github.com/croessner/dkim2/cmd/dkim2d/internal/observability" {
					observabilityImports++
				}
				for _, forbidden := range []string{"/app", "/httpjson", "/openapi", "/generated"} {
					if containsImportFragment(path, forbidden) {
						t.Fatal("offline runtime imported online subsystem")
					}
				}
			}
		}
	}
	if observabilityImports != 1 {
		t.Fatal("offline runtime did not import exactly one central local-observability boundary")
	}
}

// containsImportFragment checks one slash-delimited package boundary.
func containsImportFragment(path, fragment string) bool {
	return strings.HasSuffix(path, fragment) || strings.Contains(path, fragment+"/")
}

// testConnectionMaterial returns one detached three-role protected construction fixture.
func testConnectionMaterial(backend datasourceadmin.BackendClass) *domainadmin.AdminConnectionMaterial {
	return &domainadmin.AdminConnectionMaterial{
		Backend: backend, Address: "192.0.2.10:5432", ServerName: "sql.example.test",
		Database: "dkim2", Schema: "dkim2_datasource", RootCAs: x509.NewCertPool(),
		Deadline:   2 * time.Second,
		Snapshot:   domainadmin.AdminRoleMaterial{Identity: "dkim2_snapshot", Password: []byte("snapshot-secret")},
		Staging:    domainadmin.AdminRoleMaterial{Identity: "dkim2_stager", Password: []byte("staging-secret")},
		Activation: domainadmin.AdminRoleMaterial{Identity: "dkim2_activator", Password: []byte("activation-secret")},
	}
}

// testGenerationLimits returns one finite provider construction fixture.
func testGenerationLimits() datasourceadmin.GenerationLimits {
	return datasourceadmin.GenerationLimits{
		MaxGenerations: 256, MaxOutstandingCandidates: 8, MaxSnapshotRows: 4096,
		MaxSnapshotBytes: 32 << 20, BackendDeadline: 2 * time.Second,
	}
}

// TestBackendOwnerCloseIsIdempotent proves panic-path defers cannot duplicate cleanup.
func TestBackendOwnerCloseIsIdempotent(t *testing.T) {
	calls := 0
	owner := &backendOwner{close: func() { calls++ }}
	owner.Close()
	owner.Close()
	if calls != 1 {
		t.Fatal("backend cleanup was not exact-once")
	}
}

// TestTypedSQLConstructionUsesThreeSeparatedOfflineRoles freezes provider inputs without daemon assembly.
func TestTypedSQLConstructionUsesThreeSeparatedOfflineRoles(t *testing.T) {
	material := &domainadmin.AdminConnectionMaterial{
		Backend: datasourceadmin.BackendPostgreSQL, Address: "192.0.2.10:5432",
		ServerName: "sql.example.test", Database: "dkim2", Schema: "dkim2_datasource",
		RootCAs: x509.NewCertPool(), Deadline: 2 * time.Second,
		Snapshot:   domainadmin.AdminRoleMaterial{Identity: "dkim2_snapshot", Password: []byte("snapshot-secret")},
		Staging:    domainadmin.AdminRoleMaterial{Identity: "dkim2_stager", Password: []byte("staging-secret")},
		Activation: domainadmin.AdminRoleMaterial{Identity: "dkim2_activator", Password: []byte("activation-secret")},
	}
	postgres := postgresqlAdminConnections(material)
	for index := range postgres {
		if postgres[index].Validate() != nil {
			t.Fatal("typed PostgreSQL administration role was invalid")
		}
	}
	postgresSecrets := [3][]byte{postgres[0].Password, postgres[1].Password, postgres[2].Password}
	clearPostgreSQLConnections(&postgres)
	for _, secret := range postgresSecrets {
		if !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Fatal("temporary PostgreSQL role credential was not cleared")
		}
	}

	material.Backend = datasourceadmin.BackendMySQL
	material.Address = "192.0.2.10:3306"
	material.Schema = material.Database
	mysqlFamily := mysqlAdminConnections(material)
	for index := range mysqlFamily {
		if mysqlFamily[index].Validate() != nil {
			t.Fatal("typed MySQL-family administration role was invalid")
		}
	}
	mysqlSecrets := [3][]byte{mysqlFamily[0].Password, mysqlFamily[1].Password, mysqlFamily[2].Password}
	clearMySQLConnections(&mysqlFamily)
	for _, secret := range mysqlSecrets {
		if !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Fatal("temporary MySQL-family role credential was not cleared")
		}
	}
}
