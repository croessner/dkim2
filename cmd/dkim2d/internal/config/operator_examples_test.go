package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOperatorDatasourceExamplesValidate proves every committed network
// datasource example is accepted by the authoritative typed configuration
// loader and selects only its declared backend.
func TestOperatorDatasourceExamplesValidate(t *testing.T) {
	clearStableEnvironment(t)
	root := filepath.Join("..", "..", "..", "..")
	cases := []struct {
		name    string
		file    string
		backend SigningBackend
	}{
		{name: "ldap", file: "dkim2d-signing-ldap.yaml", backend: SigningLDAP},
		{name: "postgresql", file: "dkim2d-signing-postgresql.yaml", backend: SigningPostgreSQL},
		{name: "mysql", file: "dkim2d-signing-mysql.yaml", backend: SigningMySQL},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(root, "docs", "operator", "examples", testCase.file)
			document, err := os.ReadFile(path)
			if err != nil {
				t.Fatal("read committed operator configuration example")
			}
			snapshot, err := Load(document, FlagValues{})
			if err != nil {
				t.Fatalf("operator configuration example failed with code %s", CodeOf(err))
			}
			if snapshot.Signing().Backend() != testCase.backend {
				t.Fatal("operator configuration example selected the wrong backend")
			}
		})
	}
}
