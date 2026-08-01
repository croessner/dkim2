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

const (
	mapperTestProfileID = "profile"
	mapperTestHandleID  = "handle"
	mapperTestDomain    = "example.test"
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
