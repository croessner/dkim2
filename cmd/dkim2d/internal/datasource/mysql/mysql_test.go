package mysql

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
// grant example gives runtime only dataset reads and gives the publisher only
// the fixed staging and singleton-lock privileges.
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
	requiredPublisher := []string{
		"GRANT SELECT ON __DATABASE__.dkim2_publication_lock TO __PUBLISHER_ACCOUNT__;",
		"GRANT SELECT, INSERT, UPDATE ON __DATABASE__.dkim2_dataset_generations TO __PUBLISHER_ACCOUNT__;",
		"GRANT SELECT, INSERT, UPDATE ON __DATABASE__.dkim2_current_generation TO __PUBLISHER_ACCOUNT__;",
		"GRANT UPDATE ON __DATABASE__.dkim2_publication_lock TO __PUBLISHER_ACCOUNT__;",
	}
	for _, table := range datasetTables[2:] {
		requiredPublisher = append(requiredPublisher,
			"GRANT SELECT, INSERT ON __DATABASE__."+table+" TO __PUBLISHER_ACCOUNT__;",
		)
	}
	for _, required := range requiredPublisher {
		if !strings.Contains(text, required) {
			t.Fatal("MySQL publisher grant template is incomplete")
		}
	}
	statements := make([]string, 0)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "--") {
			continue
		}
		statements = append(statements, line)
	}
	if len(statements) != len(datasetTables)+len(requiredPublisher) {
		t.Fatal("MySQL grant template contains an unexpected executable statement")
	}
	upper := strings.ToUpper(strings.Join(statements, "\n"))
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
		if normalizeIsolation(value) != "repeatable read" {
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
