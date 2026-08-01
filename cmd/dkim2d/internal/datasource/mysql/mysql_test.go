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
