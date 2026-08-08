package mysql

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	driver "github.com/go-sql-driver/mysql"
)

// TestDriverConfigIsSingleAuthorityVerifiedTLS proves the driver is built from
// typed fields without unsafe DSN features or transport fallback.
func TestDriverConfigIsSingleAuthorityVerifiedTLS(t *testing.T) {
	t.Parallel()
	config := ConnectionConfig{
		Address: "192.0.2.10:3306", ServerName: "mysql.example.test",
		Database: "dkim2", User: "runtime", Password: []byte("synthetic"),
		RootCAs: x509.NewCertPool(), ConnectTimeout: 5 * time.Second,
		MaxConnections: 2, IdleConnections: 1,
	}
	driverConfig, err := newDriverConfig(config)
	if err != nil {
		t.Fatal("construct typed MySQL driver configuration")
	}
	if driverConfig.Net != "tcp" || driverConfig.Addr != config.Address ||
		driverConfig.DBName != config.Database || driverConfig.User != config.User ||
		driverConfig.TLS == nil || driverConfig.TLS.ServerName != config.ServerName ||
		driverConfig.TLS.MinVersion == 0 || driverConfig.AllowAllFiles ||
		driverConfig.AllowCleartextPasswords || driverConfig.AllowFallbackToPlaintext ||
		driverConfig.AllowOldPasswords || driverConfig.InterpolateParams ||
		driverConfig.MultiStatements || driverConfig.Params != nil {
		t.Fatal("typed MySQL driver configuration widened its authority")
	}
}

// TestLeastPrivilegeGrantTemplateMatchesPublisherContract proves the operator
// grant example separates runtime, legacy-v2, snapshot, staging, and activation.
func TestLeastPrivilegeGrantTemplateMatchesPublisherContract(t *testing.T) {
	t.Parallel()
	path := filepath.Join(
		"..", "..", "..", "..", "..", "contrib", "schema", "mysql",
		"002_least_privilege_grants.sql.example",
	)
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read committed MySQL grant template")
	}
	text := string(document)
	datasetTables := []string{
		"dkim2_dataset_generations", "dkim2_current_generation", "dkim2_handles",
		"dkim2_profiles", "dkim2_credentials", "dkim2_policies", "dkim2_key_material",
	}
	for _, table := range datasetTables {
		if !strings.Contains(text, "GRANT SELECT ON __DATABASE__."+table+" TO __RUNTIME_ACCOUNT__;") {
			t.Fatal("MySQL runtime grant template is incomplete")
		}
	}
	for _, required := range []string{
		"GRANT EXECUTE ON PROCEDURE __DATABASE__.dkim2_v3_lock_observe TO __SNAPSHOT_ACCOUNT__;",
		"GRANT EXECUTE ON PROCEDURE __DATABASE__.dkim2_v3_claim_lock TO __STAGING_ACCOUNT__;",
		"GRANT EXECUTE ON PROCEDURE __DATABASE__.dkim2_v3_lock_for_update TO __STAGING_ACCOUNT__;",
		"GRANT EXECUTE ON PROCEDURE __DATABASE__.dkim2_v3_insert_generation TO __STAGING_ACCOUNT__;",
		"GRANT EXECUTE ON PROCEDURE __DATABASE__.dkim2_v3_lock_for_update TO __ACTIVATION_ACCOUNT__;",
		"GRANT EXECUTE ON PROCEDURE __DATABASE__.dkim2_v3_current_for_update TO __ACTIVATION_ACCOUNT__;",
		"GRANT EXECUTE ON PROCEDURE __DATABASE__.dkim2_v3_lock_candidate_root TO __ACTIVATION_ACCOUNT__;",
		"GRANT EXECUTE ON PROCEDURE __DATABASE__.dkim2_v3_activate TO __ACTIVATION_ACCOUNT__;",
		"GRANT EXECUTE ON PROCEDURE __DATABASE__.dkim2_v3_purge_generation TO __PURGE_ACCOUNT__;",
	} {
		if !strings.Contains(text, required) {
			t.Fatal("MySQL publisher grant template is incomplete")
		}
	}
	if strings.Contains(text, "REVOKE ") {
		t.Fatal("fresh MySQL-family grant template revokes nonexistent privileges")
	}
	for _, role := range []string{"__SNAPSHOT_ACCOUNT__", "__STAGING_ACCOUNT__", "__ACTIVATION_ACCOUNT__", "__PURGE_ACCOUNT__"} {
		if strings.Contains(text, "GRANT SELECT ON __DATABASE__.dkim2_publication_lock TO "+role) {
			t.Fatal("MySQL administration roles received direct singleton-table authority")
		}
	}
	legacyPath := filepath.Join(
		"..", "..", "..", "..", "..", "contrib", "schema", "mysql",
		"003_legacy_publisher_transition.sql.example",
	)
	legacy, err := os.ReadFile(legacyPath)
	if err != nil {
		t.Fatal("read legacy MySQL-family publisher transition")
	}
	for _, required := range []string{
		"REVOKE INSERT, UPDATE ON __DATABASE__.dkim2_dataset_generations FROM __PUBLISHER_ACCOUNT__;",
		"GRANT UPDATE (singleton) ON __DATABASE__.dkim2_publication_lock TO __PUBLISHER_ACCOUNT__;",
		"GRANT EXECUTE ON PROCEDURE __DATABASE__.dkim2_v2_insert_generation TO __PUBLISHER_ACCOUNT__;",
	} {
		if !strings.Contains(string(legacy), required) {
			t.Fatal("legacy MySQL-family publisher transition is incomplete")
		}
	}
	if strings.Contains(text, "GRANT UPDATE ON __DATABASE__.dkim2_publication_lock") ||
		strings.Contains(string(legacy), "GRANT UPDATE ON __DATABASE__.dkim2_publication_lock") {
		t.Fatal("MySQL compatibility publisher received broad lock-table update authority")
	}
	upper := strings.ToUpper(text)
	for _, forbidden := range []string{
		"GRANT ALL", "GRANT DELETE", " ON *.* ", " FILE ", "CREATE USER", "IDENTIFIED BY",
	} {
		if strings.Contains(upper, forbidden) {
			t.Fatal("MySQL grant template widens authority or owns credentials")
		}
	}
}

// TestConnectionConfigRedactsAllFormatting proves backend facts cannot escape
// through common formatting or JSON paths.
func TestConnectionConfigRedactsAllFormatting(t *testing.T) {
	t.Parallel()
	config := ConnectionConfig{
		Address: "192.0.2.10:3306", ServerName: "secret.example.test",
		Database: "secret_database", User: "secret_user", Password: []byte("secret_password"),
		RootCAs: x509.NewCertPool(), ConnectTimeout: time.Second,
		MaxConnections: 1,
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal("marshal redacted connection configuration")
	}
	output := fmt.Sprintf("%v %#v %s", config, config, encoded)
	for _, secret := range []string{
		config.Address, config.ServerName, config.Database, config.User, string(config.Password),
	} {
		if strings.Contains(output, secret) {
			t.Fatal("connection formatting exposed protected configuration")
		}
	}
}

// TestQueriesAreFixedKeysetProjections rejects wildcard, offset, and
// multi-statement runtime queries.
func TestQueriesAreFixedKeysetProjections(t *testing.T) {
	t.Parallel()
	queries := []string{
		querySessionIsolation, querySessionReadOnly, queryIsolation,
		queryLegacyIsolation, queryCurrent, queryHandles, queryProfiles,
		queryCredentials, queryPolicies, queryKeyMaterial,
	}
	for _, query := range queries {
		upper := strings.ToUpper(query)
		if strings.Contains(query, "SELECT *") || strings.Contains(upper, "OFFSET") ||
			strings.Contains(query, ";") {
			t.Fatal("runtime query is not one fixed keyset projection")
		}
	}
}

// TestNormalizeIsolationAcceptsOnlyRepeatableRead proves server spelling is
// normalized without accepting weaker isolation.
func TestNormalizeIsolationAcceptsOnlyRepeatableRead(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"REPEATABLE-READ", "REPEATABLE READ", "repeatable-read"} {
		if normalizeIsolation(value) != repeatableReadIsolation {
			t.Fatal("repeatable-read spelling was not normalized")
		}
	}
	for _, value := range []string{"READ-COMMITTED", "SERIALIZABLE", ""} {
		if normalizeIsolation(value) != "" {
			t.Fatal("unsupported isolation was accepted")
		}
	}
}

// TestDDLDefinesMySQLAndMariaDBContract proves the installable schema retains
// full generations, native keys, exact collation, immutable triggers, and the
// permanent publisher lock.
func TestDDLDefinesMySQLAndMariaDBContract(t *testing.T) {
	t.Parallel()
	path := filepath.Join(
		"..", "..", "..", "..", "..", "contrib", "schema", "mysql",
		"001_dkim2_datasource.sql",
	)
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read MySQL and MariaDB DDL")
	}
	text := string(document)
	for _, required := range []string{
		"18446744073709551615", "ENGINE=InnoDB", "utf8mb4_bin",
		"'next_domain_transit'", "'disabled'", "'observe'", "'off'",
		"BETWEEN 1 AND 2048", "BETWEEN 1 AND 65536",
		"dkim2_publication_lock", "dkim2_dataset_generations",
		"dkim2_current_generation", "dkim2_handles", "dkim2_profiles",
		"dkim2_credentials", "dkim2_policies", "dkim2_key_material",
		"private_key_pkcs8", "SIGNAL SQLSTATE '45000'",
		"dkim2_runtime", "dkim2_publisher",
	} {
		if !strings.Contains(text, required) {
			t.Fatal("MySQL and MariaDB DDL contract incomplete")
		}
	}
}

// TestNativeDomainOnboardingUpgradeDefinesV3Contract proves deployed v2
// MySQL-family databases receive exact metadata and three-role authority.
func TestNativeDomainOnboardingUpgradeDefinesV3Contract(t *testing.T) {
	t.Parallel()
	path := filepath.Join(
		"..", "..", "..", "..", "..", "contrib", "schema", "mysql",
		"003_native_domain_onboarding.sql",
	)
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read MySQL-family native-domain onboarding upgrade")
	}
	text := string(document)
	for _, required := range []string{
		"dkim2-datasource-v3", "operation_id", "candidate_digest", "was_active",
		"lock_revision", "lock_operation_id", "dkim2_dataset_update",
		"forward-only", "implicit commit", "CREATE PROCEDURE dkim2_v3_lock_candidate_root(",
		"SQL SECURITY DEFINER MODIFIES SQL DATA",
		"lock_revision = selected_revision",
		"lock_operation_id = selected_operation FOR UPDATE",
		"schema_version = 'dkim2-datasource-v3'",
		"dataset_state = 'committed'",
		"candidate_digest = selected_digest FOR UPDATE",
	} {
		if !strings.Contains(text, required) {
			t.Fatal("MySQL-family v3 upgrade contract incomplete")
		}
	}
	grantsPath := filepath.Join(
		"..", "..", "..", "..", "..", "contrib", "schema", "mysql",
		"002_least_privilege_grants.sql.example",
	)
	grants, err := os.ReadFile(grantsPath)
	if err != nil {
		t.Fatal("read MySQL-family least-privilege grants")
	}
	grantText := string(grants)
	for _, required := range []string{
		"__SNAPSHOT_ACCOUNT__", "__STAGING_ACCOUNT__", "__ACTIVATION_ACCOUNT__",
		"dkim2_v3_insert_generation", "dkim2_v3_seal_generation",
		"dkim2_v3_lock_candidate_root", "dkim2_v3_activate",
	} {
		if !strings.Contains(grantText, required) {
			t.Fatal("MySQL-family v3 role grant contract incomplete")
		}
	}
}

// TestRotationCampaignUpgradeDefinesForwardCandidateFence proves the
// forward-only campaign upgrade preserves immutable v3 rows and rejects a
// candidate that is not strictly above the current generation.
func TestRotationCampaignUpgradeDefinesForwardCandidateFence(t *testing.T) {
	t.Parallel()
	path := filepath.Join(
		"..", "..", "..", "..", "..", "contrib", "schema", "mysql",
		"004_rotation_campaign_retention.sql",
	)
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read MySQL-family rotation campaign upgrade")
	}
	text := string(document)
	for _, required := range []string{
		"Forward-only", "dkim2_campaign_upgrade_requires_v3", "dkim2_v3_insert_generation",
		"dkim2 v3 candidate generation denied", "selected_generation <= generation",
		"dkim2-datasource-v3", "dataset_state NOT IN ('staging', 'committed')", "candidate_digest",
	} {
		if !strings.Contains(text, required) {
			t.Fatal("MySQL-family rotation campaign upgrade contract incomplete")
		}
	}
	upper := strings.ToUpper(text)
	for _, required := range []string{
		"CREATE TABLE dkim2_purge_audit_receipts", "CREATE PROCEDURE dkim2_v3_purge_generation",
		"selected_generation = selected_current", "lock_operation_id", "DELETE FROM dkim2_key_material",
		"DELETE FROM dkim2_dataset_generations",
	} {
		if !strings.Contains(text, required) {
			t.Fatal("MySQL-family purge authority contract incomplete")
		}
	}
	for _, forbidden := range []string{"DROP TABLE", "GRANT DELETE", "UPDATE DKIM2_DATASET_GENERATIONS"} {
		if strings.Contains(upper, forbidden) {
			t.Fatal("MySQL-family campaign upgrade widened mutation authority")
		}
	}
}

// TestCampaignSourceBindingMigrationKeepsFrozenSourceInProviderMetadata proves
// the MySQL-family routines cannot stage a candidate without its frozen source.
func TestCampaignSourceBindingMigrationKeepsFrozenSourceInProviderMetadata(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "..", "..", "..", "contrib", "schema", "mysql", "006_campaign_source_binding.sql")
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read MySQL-family source-binding migration")
	}
	for _, required := range []string{"source_generation", "selected_source", "selected_source = 0", "source_generation < generation", "dkim2_v3_lock_candidate_root", "REVOKE EXECUTE ON PROCEDURE dkim2_v3_lock_candidate_root FROM PUBLIC", "GRANT EXECUTE ON PROCEDURE dkim2_v3_lock_candidate_root TO dkim2_activator", "REVOKE EXECUTE ON PROCEDURE dkim2_v3_insert_generation FROM PUBLIC", "GRANT EXECUTE ON PROCEDURE dkim2_v3_insert_generation TO dkim2_stager"} {
		if !strings.Contains(string(document), required) {
			t.Fatal("MySQL-family source-binding migration contract incomplete")
		}
	}
}

// TestCandidateRootLockClassifiesAbsenceAndBackendFailure proves only an
// authoritative empty result or exact denial signal is a conflict.
func TestCandidateRootLockClassifiesAbsenceAndBackendFailure(t *testing.T) {
	denied := &driver.MySQLError{
		Number: 1644, SQLState: [5]byte{'4', '5', '0', '0', '0'},
		Message: candidateRootDeniedMessage,
	}
	for _, test := range []struct {
		name string
		err  error
		want datasourceadmin.ErrorCode
	}{
		{name: "no row", err: sql.ErrNoRows, want: datasourceadmin.CodeConflict},
		{name: "exact denial", err: denied, want: datasourceadmin.CodeConflict},
		{name: "cancellation", err: context.Canceled, want: datasourceadmin.CodeUnavailable},
		{name: "backend failure", err: errors.New("synthetic backend failure"), want: datasourceadmin.CodeUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := datasourceadmin.CodeOf(candidateRootMySQLError(test.err)); got != test.want {
				t.Fatalf("candidate-root error class = %s, want %s", got, test.want)
			}
		})
	}
}
