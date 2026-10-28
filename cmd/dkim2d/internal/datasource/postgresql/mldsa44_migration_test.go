package postgresql

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMLDSA44MigrationAdmitsExactlyThreeAlgorithms proves the forward
// migration 010 locks both tables and widens both algorithm constraints to
// exactly rsa-sha256, ed25519-sha256, and mldsa44 in one transaction without
// data or authority changes.
func TestMLDSA44MigrationAdmitsExactlyThreeAlgorithms(t *testing.T) {
	t.Parallel()
	document, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "contrib", "schema", "postgresql", "010_mldsa44_algorithm.sql"))
	if err != nil {
		t.Fatal("read PostgreSQL mldsa44 migration")
	}
	text := string(document)
	if !strings.Contains(text, "Forward-only") || !strings.Contains(text, "BEGIN;") || !strings.Contains(text, "COMMIT;") ||
		!strings.Contains(text, "LOCK TABLE dkim2_datasource.credentials,\n  dkim2_datasource.key_material IN ACCESS EXCLUSIVE MODE;") {
		t.Fatal("PostgreSQL mldsa44 migration is not one locked forward transaction")
	}
	for _, required := range []string{
		"ADD CONSTRAINT credentials_algorithm_check\n  CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256', 'mldsa44'));",
		"ADD CONSTRAINT key_material_algorithm_check\n  CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256', 'mldsa44'));",
	} {
		if !strings.Contains(text, required) {
			t.Fatal("PostgreSQL mldsa44 migration does not admit exactly three algorithms")
		}
	}
	upper := strings.ToUpper(text)
	for _, forbidden := range compositeRemovalForbiddenStatements {
		if strings.Contains(upper, forbidden) || strings.Contains(text, "mldsa44-ed25519") {
			t.Fatal("PostgreSQL mldsa44 migration mutates data or authority or admits the composite")
		}
	}
}
