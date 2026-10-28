package mysql

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMLDSA44MigrationAdmitsExactlyThreeAlgorithms proves the MySQL-family
// forward migration 010 widens both algorithm constraints to exactly
// rsa-sha256, ed25519-sha256, and mldsa44 without data or authority changes.
func TestMLDSA44MigrationAdmitsExactlyThreeAlgorithms(t *testing.T) {
	t.Parallel()
	document, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "contrib", "schema", "mysql", "010_mldsa44_algorithm.sql"))
	if err != nil {
		t.Fatal("read MySQL-family mldsa44 migration")
	}
	text := string(document)
	if !strings.Contains(text, "Forward-only") {
		t.Fatal("MySQL-family mldsa44 migration is not marked forward-only")
	}
	for _, required := range []string{
		"ADD CONSTRAINT dkim2_credential_algorithm\n    CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256', 'mldsa44'));",
		"ADD CONSTRAINT dkim2_key_algorithm\n    CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256', 'mldsa44'));",
	} {
		if !strings.Contains(text, required) {
			t.Fatal("MySQL-family mldsa44 migration does not admit exactly three algorithms")
		}
	}
	upper := strings.ToUpper(text)
	for _, forbidden := range compositeRemovalForbiddenStatements {
		if strings.Contains(upper, forbidden) || strings.Contains(text, "mldsa44-ed25519") {
			t.Fatal("MySQL-family mldsa44 migration mutates data or authority or admits the composite")
		}
	}
}
