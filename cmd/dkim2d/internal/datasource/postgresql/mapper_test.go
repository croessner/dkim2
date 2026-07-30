package postgresql

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/croessner/dkim2/provider"
)

const mapperTestProfileID = "profile"

// TestDDLDefinesExactContract proves the durable DDL contains the full uint64
// bound, six table sets, immutable triggers, and role split.
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
		"handles", "profiles", "credentials", "policies",
		"deny_committed_mutation", "enforce_generation_transition",
		"current_generation_forward_only", "dkim2_runtime", "dkim2_publisher",
		"FOREIGN KEY (generation, profile_id, signing_domain)",
	}
	for _, value := range required {
		if !strings.Contains(text, value) {
			t.Fatal("PostgreSQL DDL contract incomplete")
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
	dataset, err := MapDataset(rows, provider.DefaultLimits())
	if err != nil || dataset.Generation() != math.MaxUint64 {
		t.Fatal("full uint64 generation was not preserved")
	}
}

// TestQueriesAreFixedKeysetProjections rejects accidental offset or wildcard queries.
func TestQueriesAreFixedKeysetProjections(t *testing.T) {
	t.Parallel()
	queries := []string{queryCurrent, queryHandles, queryProfiles, queryCredentials, queryPolicies}
	for _, query := range queries {
		if strings.Contains(query, "SELECT *") || strings.Contains(strings.ToUpper(query), "OFFSET") {
			t.Fatal("query must use explicit keyset projection")
		}
	}
}

// minimalRows constructs one complete synthetic SQL snapshot.
func minimalRows(t *testing.T) DatasetRows {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate key")
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal("marshal key")
	}
	metadata := MetadataRow{
		Generation: "1", SchemaVersion: schemaVersion, DatasetState: "committed",
	}
	return DatasetRows{
		Current: metadata, Final: metadata,
		Handles: []HandleRow{{Generation: "1", HandleID: "handle"}},
		Profiles: []ProfileRow{{
			Generation: "1", ProfileID: mapperTestProfileID, Domain: "example.test", Status: "active",
		}},
		Credentials: []CredentialRow{{
			Generation: "1", ProfileID: mapperTestProfileID, Algorithm: "ed25519-sha256",
			Selector: "selector", PublicKeySPKI: spki, HandleID: "handle",
		}},
		Policies: []PolicyRow{{
			Generation: "1", TenantID: "tenant", Domain: "example.test",
			Use: "originator", ProfileID: mapperTestProfileID, Status: "active",
			Rollout: "enforce", Compatibility: "strict",
		}},
	}
}
