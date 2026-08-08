package datasourceadmin

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/croessner/dkim2/admincontract"
)

// TestJoinTerminalRecoveryRequiresExactFrozenCampaignBinding proves recovery
// cannot infer terminal closure from a current pointer or a near-match record.
func TestJoinTerminalRecoveryRequiresExactFrozenCampaignBinding(t *testing.T) {
	operation, err := NewOperationBinding("aebagbafaydqqcikbmga2dqpca")
	if err != nil {
		t.Fatal(err)
	}
	digestBytes := make([]byte, 32)
	digestBytes[0] = 7
	digest, err := ParseCandidateContentDigest(digestBytes)
	if err != nil {
		t.Fatal(err)
	}
	contractDigest, err := admincontract.ParseDigest(digest.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	row := RetentionGeneration{Generation: 8, Operation: operation, SourceGeneration: 7, Schema: SchemaVersionV3, State: StateCommitted, Complete: true, Ownership: RetentionOwnershipTrusted, ContentDigest: contractDigest}
	when := time.Unix(2_000_000_000, 0).UTC()
	closed, err := NewTerminalRecord(operation, SchemaVersionV3, SchemaVersionV3, 7, 8, 8, digest, TerminalClosed, "activated", when)
	if err != nil {
		t.Fatal(err)
	}
	aborted, err := NewTerminalRecord(operation, SchemaVersionV3, SchemaVersionV3, 7, 8, 7, digest, TerminalAborted, "operator_abort", when)
	if err != nil {
		t.Fatal(err)
	}
	if result := JoinTerminalRecovery([]RetentionGeneration{row}, []TerminalRecord{closed}); !result[0].Closed || result[0].Ownership != RetentionOwnershipTrusted {
		t.Fatal("exact close did not become recoverable closure")
	}
	if result := JoinTerminalRecovery([]RetentionGeneration{row}, []TerminalRecord{aborted}); !result[0].Closed || result[0].Ownership != RetentionOwnershipTrusted {
		t.Fatal("exact abort did not become recoverable closure")
	}
	foreign, err := NewOperationBinding("aebagbafaydqqcikbmga2dqpce")
	if err != nil {
		t.Fatal(err)
	}
	foreignRecord, err := NewTerminalRecord(foreign, SchemaVersionV3, SchemaVersionV3, 7, 8, 8, digest, TerminalClosed, "activated", when)
	if err != nil {
		t.Fatal(err)
	}
	for _, terminals := range [][]TerminalRecord{nil, []TerminalRecord{foreignRecord}} {
		result := JoinTerminalRecovery([]RetentionGeneration{row}, terminals)
		if result[0].Closed || result[0].Ownership != RetentionOwnershipUnknown {
			t.Fatal("missing or foreign terminal was accepted")
		}
	}
	legacy := RetentionGeneration{Generation: 4, Schema: SchemaVersionV2, State: StateCommitted, Ownership: RetentionOwnershipTrusted}
	if result := JoinTerminalRecovery([]RetentionGeneration{legacy}, nil); result[0].Ownership != RetentionOwnershipTrusted {
		t.Fatal("legacy generation was reclassified without immutable campaign binding")
	}
}

type retentionReaderFake struct{ inventory Inventory }

// Inventory returns one test-owned metadata-only provider view.
func (f retentionReaderFake) Inventory(context.Context, GenerationLimits) (Inventory, error) {
	return f.inventory, nil
}

type recoveryReaderFake struct{ rows []RetentionGeneration; current uint64 }

// RetentionCurrent returns the stable synthetic current pointer.
func (f recoveryReaderFake) RetentionCurrent(context.Context) (uint64, error) { return f.current, nil }

// RetentionPage returns one ordered synthetic evidence page after the cursor.
func (f recoveryReaderFake) RetentionPage(_ context.Context, after uint64, limit uint32) ([]RetentionGeneration, error) {
	result := make([]RetentionGeneration, 0, limit)
	for _, row := range f.rows { if row.Generation > after { result = append(result, row); if len(result) == int(limit) { break } } }
	return result, nil
}

// TestReadRetentionRecoveryInventoryExceedsAllocationHistory freezes the separate 10k recovery window.
func TestReadRetentionRecoveryInventoryExceedsAllocationHistory(t *testing.T) {
	rows := make([]RetentionGeneration, 0, 16384)
	for generation := uint64(1); generation <= 16384; generation++ { rows = append(rows, retentionGeneration(t, generation, true)) }
	view, err := ReadRetentionRecoveryInventory(t.Context(), recoveryReaderFake{rows: rows, current: 16384}, DefaultRetentionRecoveryLimits())
	if err != nil || len(view.Generations) != 16384 || view.Current != 16384 { t.Fatal("separate recovery reader retained allocation ceiling") }
}

func TestReadRetentionRecoveryInventoryRejectsOverLimitHistory(t *testing.T) {
	rows := make([]RetentionGeneration, 0, 16385)
	for generation := uint64(1); generation <= 16385; generation++ { rows = append(rows, retentionGeneration(t, generation, true)) }
	if _, err := ReadRetentionRecoveryInventory(t.Context(), recoveryReaderFake{rows: rows, current: 16385}, DefaultRetentionRecoveryLimits()); err == nil { t.Fatal("over-limit recovery history was accepted") }
}

// TestReadRetentionInventoryPreservesOnlyProviderProvenFacts freezes metadata projection.
func TestReadRetentionInventoryPreservesOnlyProviderProvenFacts(t *testing.T) {
	info := GenerationInfo{Generation: 1, Current: true, State: StateCommitted, WasActive: true, Schema: SchemaVersionV3}
	bytes := make([]byte, 32)
	bytes[0] = 1
	var err error
	info.ContentDigest, err = ParseCandidateContentDigest(bytes)
	if err != nil {
		t.Fatal(err)
	}
	view, err := ReadRetentionInventory(t.Context(), retentionReaderFake{inventory: Inventory{Current: 1, Generations: []GenerationInfo{info}}}, testGenerationLimits())
	if err != nil || len(view.Generations) != 1 || !view.Generations[0].Complete || !view.Generations[0].ContentDigest.Valid() || view.Generations[0].Closed {
		t.Fatal("reader invented or lost historical facts")
	}
}

// TestRetentionAuthorityRequiresDedicatedPurger freezes the fourth authority
// boundary so planning cannot accidentally reuse a publication identity.
func TestRetentionAuthorityRequiresDedicatedPurger(t *testing.T) {
	var trust [sha256.Size]byte
	trust[0] = 1
	authority := AuthorityDescriptor{
		AuthorityID:       "aebagbafaydqqcikbmga2dqpca",
		Endpoints:         []AuthorityEndpoint{{Scheme: "ldaps", Host: "ldap.example.test", Port: 636, TLSServerName: "ldap.example.test"}},
		LDAP:              &LDAPAuthority{BaseDN: "dc=example,dc=test", SnapshotPrincipal: "snapshot", StagingPrincipal: "staging", ActivationPrincipal: "activation"},
		TrustFingerprints: [][sha256.Size]byte{trust},
	}
	if _, err := RetentionAuthorityCommitment(BackendLDAP, authority); err == nil {
		t.Fatal("three-role authority unexpectedly authorized purge planning")
	}
	authority.LDAP.PurgePrincipal = "staging"
	if _, err := RetentionAuthorityCommitment(BackendLDAP, authority); err == nil {
		t.Fatal("reused staging principal unexpectedly authorized purge planning")
	}
	authority.LDAP.PurgePrincipal = "purger"
	if _, err := RetentionAuthorityCommitment(BackendLDAP, authority); err != nil {
		t.Fatal("dedicated purger authority rejected")
	}
}

// TestClassifyRetentionProtectsCurrentAndSelectsOldestRecoverableHistory freezes the capacity-recovery policy.
func TestClassifyRetentionProtectsCurrentAndSelectsOldestRecoverableHistory(t *testing.T) {
	policy := DefaultRetentionPolicy()
	policy.MaxTotalGenerations = 2
	policy.MinActiveRollbackGenerations = 1
	policy.MaxClosedNeverActiveGenerations = 0
	policy.MaxPurgeBatch = 2
	policy.Version = "retention-v1"

	classification, err := ClassifyRetention(RetentionInventory{
		Version: "inventory-v1", Current: 4,
		Generations: []RetentionGeneration{
			retentionGeneration(t, 1, true), retentionGeneration(t, 2, true),
			retentionGeneration(t, 3, false), retentionGeneration(t, 4, true),
		},
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if classification.EligibleCount() != 2 || !classification.Eligible(1) || !classification.Eligible(3) {
		t.Fatal("oldest active and closed never-active generations were not selected")
	}
	if classification.Eligible(4) || classification.Reason(4) != RetentionReasonCurrent {
		t.Fatal("current generation entered retention eligibility")
	}
}

// TestClassifyRetentionFailsClosedForAmbiguousLifecycle freezes never-eligible ambiguity handling.
func TestClassifyRetentionFailsClosedForAmbiguousLifecycle(t *testing.T) {
	policy := DefaultRetentionPolicy()
	classification, err := ClassifyRetention(RetentionInventory{
		Version: "inventory-v1", Current: 4,
		Generations: []RetentionGeneration{
			retentionGeneration(t, 1, true),
			{Generation: 2, Schema: "dkim2-datasource-v3", State: StateStaging, Complete: true, Ownership: RetentionOwnershipTrusted},
			{Generation: 3, Schema: "dkim2-datasource-v3", State: StateCommitted, Complete: false, Ownership: RetentionOwnershipTrusted},
			retentionGeneration(t, 4, true),
		},
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if classification.EligibleCount() != 0 || classification.Reason(2) != RetentionReasonOpenCampaign || classification.Reason(3) != RetentionReasonPartial {
		t.Fatal("ambiguous lifecycle state entered purge eligibility")
	}
}

// TestClassifyRetentionPagesRecoversPastAllocationCeilings freezes paged read-only recovery.
func TestClassifyRetentionPagesRecoversPastAllocationCeilings(t *testing.T) {
	policy := DefaultRetentionPolicy()
	policy.MaxTotalGenerations, policy.MinActiveRollbackGenerations, policy.MaxClosedNeverActiveGenerations, policy.MaxPurgeBatch = 2, 1, 0, 8
	pages := make([][]RetentionGeneration, 3)
	for generation := uint64(1); generation <= 300; generation++ {
		row := retentionGeneration(t, generation, true)
		row.ContentDigest = retentionDigest(t, generation)
		pages[(generation-1)/100] = append(pages[(generation-1)/100], row)
	}
	classification, err := ClassifyRetentionPages("inventory-v1", 300, pages, policy)
	if err != nil {
		t.Fatal(err)
	}
	if classification.EligibleCount() != 8 || !classification.Eligible(1) || classification.Eligible(300) {
		t.Fatal("paged capacity recovery lost deterministic retention selection")
	}
}

// retentionGeneration constructs detached, content-free trusted test evidence.
func retentionGeneration(t *testing.T, generation uint64, active bool) RetentionGeneration {
	t.Helper()
	digest, err := admincontract.ParseDigest(make([]byte, 32))
	if err == nil || digest.Valid() {
		t.Fatal("zero digest accepted")
	}
	digest = retentionDigest(t, generation)
	return RetentionGeneration{Generation: generation, Schema: "dkim2-datasource-v3", State: StateCommitted, WasActive: active, Complete: true, Ownership: RetentionOwnershipTrusted, ContentDigest: digest, Closed: !active}
}

// retentionDigest creates a nonzero detached test digest for arbitrary generation values.
func retentionDigest(t *testing.T, generation uint64) admincontract.Digest {
	t.Helper()
	bytes := make([]byte, 32)
	for index := range bytes {
		bytes[index] = byte(generation >> (uint(index%8) * 8))
	}
	digest, err := admincontract.ParseDigest(bytes)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
