package ldap

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/croessner/dkim2/provider"
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
			attrGeneration: {[]byte("1")}, attrHandleID: {[]byte("handle")},
		}}},
		Profiles: []Entry{{Class: RecordClassProfile, Attributes: map[string][][]byte{
			attrGeneration: {[]byte("1")}, attrProfileID: {[]byte("profile")},
			attrSigningDomain: {[]byte("example.test")}, attrRecordStatus: {[]byte("active")},
		}}},
		Credentials: []Entry{{Class: RecordClassCredential, Attributes: map[string][][]byte{
			attrGeneration: {[]byte("1")}, attrProfileID: {[]byte("profile")},
			attrAlgorithm: {[]byte("ed25519-sha256")}, attrSelector: {[]byte("selector")},
			attrPublicSPKI: {spki}, attrHandleID: {[]byte("handle")},
		}}},
		Policies: []Entry{{Class: RecordClassPolicy, Attributes: map[string][][]byte{
			attrGeneration: {[]byte("1")}, attrTenantID: {[]byte("tenant")},
			attrSigningDomain: {[]byte("example.test")}, attrProfileUse: {[]byte("originator")},
			attrProfileID: {[]byte("profile")}, attrRecordStatus: {[]byte("active")},
			attrRollout: {[]byte("enforce")}, attrCompatibility: {[]byte("strict")},
		}}},
		KeyMaterial: []Entry{{Class: RecordClassKeyMaterial, Attributes: map[string][][]byte{
			attrGeneration: {[]byte("1")}, attrTenantID: {[]byte("tenant")},
			attrSigningDomain: {[]byte("example.test")}, attrProfileUse: {[]byte("originator")},
			attrHandleID: {[]byte("handle")}, attrAlgorithm: {[]byte("ed25519-sha256")},
			attrPublicSPKI: {spki}, attrPrivatePKCS8: {privatePKCS8},
		}}},
	}
}
