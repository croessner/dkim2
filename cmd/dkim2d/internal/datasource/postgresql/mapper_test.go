package postgresql

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/sqlsnapshot"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	mapperTestProfileID = "profile"
	mapperTestHandleID  = "handle"
	mapperTestDomain    = "example.test"
	serializationState  = "serialization"
)

// TestDDLDefinesExactContract proves the durable DDL contains the full uint64
// bound, native key table, immutable triggers, and role split.
func TestDDLDefinesExactContract(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "..", "..", "..", "contrib", "schema", "postgresql", "001_dkim2_datasource.sql")
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read PostgreSQL DDL")
	}
	text := string(document)
	required := []string{
		"18446744073709551615", "dataset_generations", "current_generation",
		"handles", "profiles", "credentials", "policies", "key_material",
		"deny_committed_mutation", "enforce_generation_transition",
		"current_generation_forward_only", "dkim2_runtime", "dkim2_publisher",
		"FOREIGN KEY (generation, profile_id, signing_domain)",
	}
	for _, value := range required {
		if !strings.Contains(text, value) {
			t.Fatal("PostgreSQL DDL contract incomplete")
		}
	}
	migrationPath := filepath.Join(
		"..", "..", "..", "..", "..", "contrib", "schema", "postgresql",
		"002_native_key_custody.sql",
	)
	migration, err := os.ReadFile(migrationPath)
	if err != nil || !strings.Contains(string(migration), "private_key_pkcs8") ||
		!strings.Contains(string(migration), "credentials_native_key_reference") ||
		!strings.Contains(string(migration), "GRANT SELECT ON dkim2_datasource.key_material TO dkim2_runtime") {
		t.Fatal("PostgreSQL v1-to-v2 migration contract incomplete")
	}
}

// TestNativeDomainOnboardingUpgradeDefinesV3Contract proves deployed v2
// PostgreSQL databases receive the complete forward-only administration model.
func TestNativeDomainOnboardingUpgradeDefinesV3Contract(t *testing.T) {
	t.Parallel()
	path := filepath.Join(
		"..", "..", "..", "..", "..", "contrib", "schema", "postgresql",
		"003_native_domain_onboarding.sql",
	)
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read PostgreSQL native-domain onboarding upgrade")
	}
	text := string(document)
	for _, required := range []string{
		"dkim2-datasource-v3", "operation_id", "candidate_digest", "was_active",
		"administration_lock", "lock_revision", "lock_operation_id",
		"SERIALIZABLE", "dkim2_snapshot", "dkim2_stager", "dkim2_activator",
		"administration_lock_observe", "administration_lock_for_update",
		"candidate_root_for_update",
		"administration_lock_claim", "administration_lock_release",
		"LANGUAGE plpgsql SECURITY DEFINER",
		"GRANT UPDATE (dataset_state)", "GRANT UPDATE (was_active)",
		"GRANT UPDATE (generation, candidate_digest)",
	} {
		if !strings.Contains(text, required) {
			t.Fatal("PostgreSQL v3 upgrade contract incomplete")
		}
	}
	for _, required := range []string{
		"LANGUAGE sql SECURITY DEFINER\nSET search_path = pg_catalog, dkim2_datasource",
		"candidate.schema_version = 'dkim2-datasource-v3'",
		"candidate.dataset_state = 'committed'",
		"candidate.operation_id = selected_operation",
		"candidate.candidate_digest = selected_digest",
		"REVOKE ALL ON FUNCTION dkim2_datasource.candidate_root_for_update(",
		") TO dkim2_activator;",
	} {
		if !strings.Contains(text, required) {
			t.Fatal("PostgreSQL candidate-root lock contract incomplete")
		}
	}
	if strings.Contains(text, "GRANT SELECT ON dkim2_datasource.administration_lock") ||
		strings.Contains(text, "GRANT UPDATE (lock_revision, lock_operation_id)") {
		t.Fatal("PostgreSQL administration roles received direct singleton-table authority")
	}
	if strings.Count(text, "ALTER TABLE dkim2_datasource.key_material ENABLE ROW LEVEL SECURITY;") != 1 {
		t.Fatal("PostgreSQL key-material RLS enablement is not singular")
	}
}

// TestRotationCampaignUpgradeDefinesForwardCandidateFence proves the
// forward-only campaign upgrade preserves immutable v3 authority and rejects
// candidates that are not strictly above the current generation.
func TestRotationCampaignUpgradeDefinesForwardCandidateFence(t *testing.T) {
	t.Parallel()
	path := filepath.Join(
		"..", "..", "..", "..", "..", "contrib", "schema", "postgresql",
		"004_rotation_campaign_retention.sql",
	)
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read PostgreSQL rotation campaign upgrade")
	}
	text := string(document)
	for _, required := range []string{
		"Forward-only", "campaign_candidate_generation_is_forward", "dataset_stage_v3",
		"administration_lock_owned_by(operation_id)",
		"dkim2-datasource-v3", "dataset_state = 'staging'", "candidate_digest",
	} {
		if !strings.Contains(text, required) {
			t.Fatal("PostgreSQL rotation campaign upgrade contract incomplete")
		}
	}
	for _, required := range []string{
		"CREATE TABLE dkim2_datasource.purge_audit_receipts", "CREATE PROCEDURE dkim2_datasource.purge_generation",
		"lock_operation_id IS NULL", "selected_generation = selected_current", "DELETE FROM dkim2_datasource.key_material",
		"DELETE FROM dkim2_datasource.dataset_generations", "GRANT EXECUTE ON PROCEDURE dkim2_datasource.purge_generation",
		"TO dkim2_purger",
	} {
		if !strings.Contains(text, required) {
			t.Fatal("PostgreSQL purge authority contract incomplete")
		}
	}
	upper := strings.ToUpper(text)
	for _, forbidden := range []string{"DROP TABLE", "GRANT DELETE", "UPDATE DKIM2_DATASOURCE.DATASET_GENERATIONS"} {
		if strings.Contains(upper, forbidden) {
			t.Fatal("PostgreSQL campaign upgrade widened mutation authority")
		}
	}
}

// TestCampaignSourceBindingMigrationKeepsFrozenSourceInProviderMetadata proves
// the forward migration carries the recovery binding through SQL primitives.
func TestCampaignSourceBindingMigrationKeepsFrozenSourceInProviderMetadata(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "..", "..", "..", "contrib", "schema", "postgresql", "006_campaign_source_binding.sql")
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read PostgreSQL source-binding migration")
	}
	for _, required := range []string{"source_generation", "source_generation < generation", "candidate_root_for_update", "source_generation::text", "TO dkim2_activator"} {
		if !strings.Contains(string(document), required) {
			t.Fatal("PostgreSQL source-binding migration contract incomplete")
		}
	}
}

// TestActivationQueriesFenceCurrentPointerAndCandidateRoot proves activation
// locks exact candidate metadata and compares the previously read pointer.
func TestActivationQueriesFenceCurrentPointerAndCandidateRoot(t *testing.T) {
	t.Parallel()
	if !strings.Contains(queryAdminCandidateRootForUpdate, "FROM dkim2_datasource.candidate_root_for_update($1, $2, $3)") ||
		!strings.Contains(queryAdminCandidateRootForUpdate, "source_generation::text") {
		t.Fatal("PostgreSQL adapter does not use the exact candidate-root primitive")
	}
	if !strings.Contains(queryAdminUpdateCurrent, "candidate_digest IS NOT DISTINCT FROM $4") {
		t.Fatal("PostgreSQL current update omits the locked old pointer digest")
	}
}

// TestCandidateRootLockClassifiesAbsenceAndBackendFailure proves only an
// authoritative empty root lookup is a conflict.
func TestCandidateRootLockClassifiesAbsenceAndBackendFailure(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want datasourceadmin.ErrorCode
	}{
		{name: "no row", err: pgx.ErrNoRows, want: datasourceadmin.CodeConflict},
		{name: serializationState, err: &pgconn.PgError{Code: "40001"}, want: datasourceadmin.CodeUnavailable},
		{name: "deadlock", err: &pgconn.PgError{Code: "40P01"}, want: datasourceadmin.CodeUnavailable},
		{name: "cancellation", err: context.Canceled, want: datasourceadmin.CodeUnavailable},
		{name: "backend failure", err: errors.New("synthetic backend failure"), want: datasourceadmin.CodeUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := datasourceadmin.CodeOf(candidateRootPGError(test.err)); got != test.want {
				t.Fatalf("candidate-root error class = %s, want %s", got, test.want)
			}
		})
	}
}

// TestAdministrationFenceReadsClassifyOnlyLiveLockedActivationSerialization
// proves the complete mode, lock, SQLSTATE, and context boundary at both reads.
func TestAdministrationFenceReadsClassifyOnlyLiveLockedActivationSerialization(t *testing.T) {
	readers := map[string]func(context.Context, sqlsnapshot.AdministrationMode, bool, error) error{
		"administration lock": administrationLockReadPGError,
		"current fence":       currentFenceReadPGError,
	}
	modes := []sqlsnapshot.AdministrationMode{
		sqlsnapshot.AdministrationSnapshot,
		sqlsnapshot.AdministrationStaging,
		sqlsnapshot.AdministrationActivation,
	}
	states := []struct {
		name string
		err  error
	}{
		{name: serializationState, err: &pgconn.PgError{Code: "40001"}},
		{name: "deadlock", err: &pgconn.PgError{Code: "40P01"}},
		{name: "backend", err: errors.New("synthetic backend failure")},
	}
	for readerName, reader := range readers {
		for _, mode := range modes {
			for _, locked := range []bool{false, true} {
				for _, state := range states {
					want := datasourceadmin.CodeUnavailable
					if mode == sqlsnapshot.AdministrationActivation && locked && state.name == serializationState {
						want = datasourceadmin.CodeConflict
					}
					name := fmt.Sprintf("%s/mode_%d/locked_%t/%s", readerName, mode, locked, state.name)
					t.Run(name, func(t *testing.T) {
						if got := datasourceadmin.CodeOf(reader(context.Background(), mode, locked, state.err)); got != want {
							t.Fatalf("administration fence error class = %s, want %s", got, want)
						}
					})
				}
			}
		}
	}
	for _, reader := range readers {
		for _, contextState := range []struct {
			name string
			ctx  func() context.Context
		}{
			{name: "canceled", ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			}},
			{name: "deadline", ctx: func() context.Context {
				ctx, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
				defer cancel()
				return ctx
			}},
		} {
			if got := datasourceadmin.CodeOf(reader(
				contextState.ctx(), sqlsnapshot.AdministrationActivation, true,
				&pgconn.PgError{Code: "40001"},
			)); got != datasourceadmin.CodeUnavailable {
				t.Fatalf("%s activation serialization class = %s, want unavailable", contextState.name, got)
			}
		}
	}
}

// TestMapDatasetPreservesFullUint64Generation proves decimal conversion never
// narrows the datasource generation contract to signed bigint.
func TestMapDatasetPreservesFullUint64Generation(t *testing.T) {
	t.Parallel()
	rows := minimalRows(t)
	maximum := "18446744073709551615"
	rows.Current.Generation = maximum
	rows.Final.Generation = maximum
	rows.Handles[0].Generation = maximum
	rows.Profiles[0].Generation = maximum
	rows.Credentials[0].Generation = maximum
	rows.Policies[0].Generation = maximum
	rows.KeyMaterial[0].Generation = maximum
	dataset, err := MapDataset(rows, provider.DefaultLimits())
	if err != nil || dataset.Generation() != math.MaxUint64 {
		t.Fatal("full uint64 generation was not preserved")
	}
}

// TestMapDatasetRejectsVersionOne prevents runtime fallback to the former
// public-only SQL schema.
func TestMapDatasetRejectsVersionOne(t *testing.T) {
	rows := minimalRows(t)
	rows.Current.SchemaVersion = "dkim2-datasource-v1"
	rows.Final.SchemaVersion = "dkim2-datasource-v1"
	if _, err := MapDataset(rows, provider.DefaultLimits()); provider.ErrorCodeOf(err) != provider.ErrorCodeMalformedData {
		t.Fatal("PostgreSQL runtime accepted a v1 public-only generation")
	}
}

// TestQueriesAreFixedKeysetProjections rejects accidental offset or wildcard queries.
func TestQueriesAreFixedKeysetProjections(t *testing.T) {
	t.Parallel()
	queries := []string{queryCurrent, queryHandles, queryProfiles, queryCredentials, queryPolicies, queryKeyMaterial}
	for _, query := range queries {
		if strings.Contains(query, "SELECT *") || strings.Contains(strings.ToUpper(query), "OFFSET") {
			t.Fatal("query must use explicit keyset projection")
		}
	}
}

// minimalRows constructs one complete synthetic SQL snapshot.
func minimalRows(t *testing.T) DatasetRows {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate key")
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal("marshal key")
	}
	privatePKCS8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal("marshal private key")
	}
	metadata := MetadataRow{
		Generation: "1", SchemaVersion: schemaVersion, DatasetState: "committed",
	}
	return DatasetRows{
		Current: metadata, Final: metadata,
		Handles: []HandleRow{{Generation: "1", HandleID: mapperTestHandleID}},
		Profiles: []ProfileRow{{
			Generation: "1", ProfileID: mapperTestProfileID, Domain: mapperTestDomain, Status: "active",
		}},
		Credentials: []CredentialRow{{
			Generation: "1", ProfileID: mapperTestProfileID, Algorithm: "ed25519-sha256",
			Selector: "selector", PublicKeySPKI: spki, HandleID: mapperTestHandleID,
		}},
		Policies: []PolicyRow{{
			Generation: "1", TenantID: "tenant", Domain: mapperTestDomain,
			Use: "originator", ProfileID: mapperTestProfileID, Status: "active",
			Rollout: "enforce", Compatibility: "strict",
		}},
		KeyMaterial: []KeyMaterialRow{{
			Generation: "1", TenantID: "tenant", Domain: mapperTestDomain,
			Use: "originator", HandleID: mapperTestHandleID, Algorithm: "ed25519-sha256",
			PublicSPKI: spki, PrivatePKCS8: privatePKCS8,
		}},
	}
}
