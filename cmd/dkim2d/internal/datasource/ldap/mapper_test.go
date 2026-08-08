package ldap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

const (
	testHandleID = "handle"
	testDomain   = "example.test"
	testProfile  = "profile"
)

// TestMapDatasetRejectsMixedGenerationAndUnknownFields proves strict fenced
// mapping without attribute or generation fallback.
func TestMapDatasetRejectsMixedGenerationAndUnknownFields(t *testing.T) {
	t.Parallel()
	records := minimalRecords(t)
	records.Root.Attributes[attrGeneration] = [][]byte{[]byte("2")}
	if _, err := MapDataset(records, provider.DefaultLimits()); provider.ErrorCodeOf(err) != provider.ErrorCodeMalformedData {
		t.Fatal("mixed metadata generations must reject")
	}
	records = minimalRecords(t)
	records.Handles[0].Attributes["legacyAlias"] = [][]byte{[]byte("toxic")}
	if _, err := MapDataset(records, provider.DefaultLimits()); provider.ErrorCodeOf(err) != provider.ErrorCodeMalformedData {
		t.Fatal("unknown attributes must reject")
	}
}

// TestMapDatasetConstructsImmutableNeutralSnapshot proves a complete exact
// mapping resolves through the public provider bridge.
func TestMapDatasetConstructsImmutableNeutralSnapshot(t *testing.T) {
	t.Parallel()
	dataset, err := MapDataset(minimalRecords(t), provider.DefaultLimits())
	if err != nil || !dataset.Valid() || dataset.Generation() != 1 {
		t.Fatal("map complete dataset")
	}
}

// TestMapDatasetRejectsVersionOne prevents a normal runtime fallback to the
// former public-only network datasource schema.
func TestMapDatasetRejectsVersionOne(t *testing.T) {
	records := minimalRecords(t)
	records.Current.Attributes[attrSchemaVersion] = [][]byte{[]byte("dkim2-datasource-v1")}
	records.Root.Attributes[attrSchemaVersion] = [][]byte{[]byte("dkim2-datasource-v1")}
	if _, err := MapDataset(records, provider.DefaultLimits()); provider.ErrorCodeOf(err) != provider.ErrorCodeMalformedData {
		t.Fatal("LDAP runtime accepted a v1 public-only generation")
	}
}

// TestInventoryMapperRetainsV1WithoutAdmittingItAsCurrent freezes the narrow
// legacy-history exception used only by bounded inventory and retention.
func TestInventoryMapperRetainsV1WithoutAdmittingItAsCurrent(t *testing.T) {
	records := minimalRecords(t)
	records.Root.Attributes[attrSchemaVersion] = [][]byte{[]byte(datasourceadmin.SchemaVersionV1)}
	metadata, err := mapInventoryGenerationMetadata(records.Root)
	if err != nil || metadata.schema != datasourceadmin.SchemaVersionV1 || metadata.state != datasourceadmin.StateCommitted {
		t.Fatal("v1 history root was not retained conservatively")
	}
	if _, err := mapGenerationMetadata(records.Root); err == nil {
		t.Fatal("v1 history was admitted as a usable source generation")
	}
}

// TestMapDatasetAcceptsOnlyExactV3Metadata freezes runtime digest and version fencing.
func TestMapDatasetAcceptsOnlyExactV3Metadata(t *testing.T) {
	records := minimalRecords(t)
	rows := datasourceadmin.Rows{
		Handles: []datasourceadmin.HandleRow{{ID: testHandleID}},
		Profiles: []datasourceadmin.ProfileRow{{
			ID: testProfile, Domain: testDomain, Status: "active",
		}},
		Credentials: []datasourceadmin.CredentialRow{{
			ProfileID: testProfile, Algorithm: "ed25519-sha256", Selector: "selector",
			PublicSPKI: bytes.Clone(records.Credentials[0].Attributes[attrPublicSPKI][0]), HandleID: testHandleID,
		}},
		Policies: []datasourceadmin.PolicyRow{{
			TenantID: "tenant", Domain: testDomain, Use: "originator", ProfileID: testProfile,
			Status: "active", Rollout: "enforce", Compatibility: "strict",
		}},
		KeyMaterial: []datasourceadmin.KeyMaterialRow{{
			TenantID: "tenant", Domain: testDomain, Use: "originator", HandleID: testHandleID,
			Algorithm:    "ed25519-sha256",
			PublicSPKI:   bytes.Clone(records.KeyMaterial[0].Attributes[attrPublicSPKI][0]),
			PrivatePKCS8: bytes.Clone(records.KeyMaterial[0].Attributes[attrPrivatePKCS8][0]),
		}},
	}
	snapshot, err := datasourceadmin.NewSnapshot(datasourceadmin.SchemaVersionV3, 1, rows)
	if err != nil {
		t.Fatal("construct v3 runtime fixture")
	}
	content, err := datasourceadmin.NewCandidateContent(snapshot)
	if err != nil {
		_ = snapshot.Close()
		t.Fatal("construct v3 candidate content fixture")
	}
	candidate, err := datasourceadmin.NewPublicationEnvelope("aibqibiga4eascqlbqgzav3y4m", content)
	if err != nil {
		_ = content.Close()
		t.Fatal("construct v3 publication envelope fixture")
	}
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	digest := candidate.Digest().Bytes()
	defer clear(digest)
	current := Entry{Class: RecordClassDataset, Attributes: map[string][][]byte{
		attrSchemaVersion: {[]byte(datasourceadmin.SchemaVersionV3)},
		attrGeneration:    {[]byte("1")}, attrDatasetState: {[]byte("committed")},
		"dkim2CandidateDigest": {bytes.Clone(digest)},
	}}
	root := cloneEntry(current)
	root.Attributes["dkim2OperationID"] = [][]byte{[]byte("aibqibiga4eascqlbqgzav3y4m")}
	records.Current, records.Root = current, root
	dataset, err := MapDataset(records, provider.DefaultLimits())
	if err != nil || dataset == nil || !dataset.Valid() {
		t.Fatal("exact v3 runtime generation rejected")
	}

	records.Root.Attributes["dkim2CandidateDigest"][0][0] ^= 0xff
	if _, err := MapDataset(records, provider.DefaultLimits()); provider.ErrorCodeOf(err) != provider.ErrorCodeMalformedData {
		t.Fatal("v3 runtime accepted mismatched protected digest")
	}
	records.Root = cloneEntry(current)
	records.Root.Attributes["dkim2OperationID"] = [][]byte{[]byte("aibqibiga4eascqlbqgzav3y4m")}
	records.Current.Attributes[attrSchemaVersion] = [][]byte{[]byte(datasourceadmin.SchemaVersionV2)}
	if _, err := MapDataset(records, provider.DefaultLimits()); provider.ErrorCodeOf(err) != provider.ErrorCodeMalformedData {
		t.Fatal("runtime silently mixed v2 current with v3 root")
	}
}

// minimalRecords constructs a complete synthetic LDAP record set.
func minimalRecords(t *testing.T) DatasetRecords {
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
	metadata := Entry{Class: RecordClassDataset, Attributes: map[string][][]byte{
		attrSchemaVersion: {[]byte(schemaVersion)},
		attrGeneration:    {[]byte("1")},
		attrDatasetState:  {[]byte("committed")},
	}}
	return DatasetRecords{
		Current: metadata,
		Root:    metadata,
		Handles: []Entry{{Class: RecordClassHandle, Attributes: map[string][][]byte{
			attrGeneration: {[]byte("1")}, attrHandleID: {[]byte(testHandleID)},
		}}},
		Profiles: []Entry{{Class: RecordClassProfile, Attributes: map[string][][]byte{
			attrGeneration: {[]byte("1")}, attrProfileID: {[]byte(testProfile)},
			attrSigningDomain: {[]byte(testDomain)}, attrRecordStatus: {[]byte("active")},
		}}},
		Credentials: []Entry{{Class: RecordClassCredential, Attributes: map[string][][]byte{
			attrGeneration: {[]byte("1")}, attrProfileID: {[]byte(testProfile)},
			attrAlgorithm: {[]byte("ed25519-sha256")}, attrSelector: {[]byte("selector")},
			attrPublicSPKI: {spki}, attrHandleID: {[]byte(testHandleID)},
		}}},
		Policies: []Entry{{Class: RecordClassPolicy, Attributes: map[string][][]byte{
			attrGeneration: {[]byte("1")}, attrTenantID: {[]byte("tenant")},
			attrSigningDomain: {[]byte(testDomain)}, attrProfileUse: {[]byte("originator")},
			attrProfileID: {[]byte(testProfile)}, attrRecordStatus: {[]byte("active")},
			attrRollout: {[]byte("enforce")}, attrCompatibility: {[]byte("strict")},
		}}},
		KeyMaterial: []Entry{{Class: RecordClassKeyMaterial, Attributes: map[string][][]byte{
			attrGeneration: {[]byte("1")}, attrTenantID: {[]byte("tenant")},
			attrSigningDomain: {[]byte(testDomain)}, attrProfileUse: {[]byte("originator")},
			attrHandleID: {[]byte(testHandleID)}, attrAlgorithm: {[]byte("ed25519-sha256")},
			attrPublicSPKI: {spki}, attrPrivatePKCS8: {privatePKCS8},
		}}},
	}
}
