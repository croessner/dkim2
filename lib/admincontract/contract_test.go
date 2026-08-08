package admincontract

import (
	"encoding/hex"
	"testing"
	"time"
)

const (
	testRetentionPolicy  = "retention-v1"
	testInventoryVersion = "inventory-v1"
)

// TestCampaignContractGolden freezes every public lifecycle commitment.
func TestCampaignContractGolden(t *testing.T) {
	work := []WorkItem{
		{Tenant: "tenant-a", Domain: "a.example.test", Use: useOriginator, Profile: "profile-a", Algorithms: []string{algorithmEd25519, algorithmRSA}},
		{Tenant: "tenant-b", Domain: "b.example.test", Use: useOriginator, Profile: "profile-b", Algorithms: []string{algorithmEd25519, algorithmRSA}},
	}
	frozen, err := FrozenWorkDigest(work)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := CampaignPlanDigest(CampaignPlan{
		Version: ContractVersion, Mode: ModeNormal, SourceSchema: schemaV3,
		SourceGeneration: 7, CandidateGeneration: 8, OperationID: "aebagbafaydqqcikbmga2dqpca",
		Work: work, RotationPolicyVersion: "rotation-v1", DNSPolicyVersion: "dns-v1",
		RetentionPolicyVersion: testRetentionPolicy, LimitProfileVersion: "production-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate := mustDigest(t, "df6f03fc47b8f22a8ac3bf8312dda6f364de0ad21827f6e24e0363f14f14d6df")
	batch, err := DNSBatchDigest(DNSBatch{CandidateDigest: candidate, FrozenWorkDigest: frozen, Ordinal: 1, Start: 0, End: 2, Total: 2})
	if err != nil {
		t.Fatal(err)
	}
	purge, err := PurgePlanDigest(PurgePlan{
		Version: ContractVersion, CurrentGeneration: 8, InventoryVersion: testInventoryVersion,
		PolicyVersion: testRetentionPolicy, Targets: []PurgeTarget{{Generation: 2, Schema: schemaV3, Lifecycle: lifecycleActiveHistory, ContentDigest: mustDigest(t, "15f765eaa2e2b99b3f5b454d05072c10f93c70ac5c2c54cddc21b877ebaf7e2a")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := AuditCommitment(AuditReceipt{
		Version: ContractVersion, Generation: 2, Schema: schemaV3, Lifecycle: lifecycleActiveHistory,
		OperationClass: operationNormal, ContentDigest: mustDigest(t, "15f765eaa2e2b99b3f5b454d05072c10f93c70ac5c2c54cddc21b877ebaf7e2a"),
		DestroyedAt: time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), Result: receiptPurged, PolicyVersion: testRetentionPolicy, PurgePlanDigest: purge,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := []string{frozen.Hex(), plan.Hex(), batch.Hex(), purge.Hex(), audit.Hex()}
	want := []string{
		"ca4d375d4a2a90d4871391a0f79bfb5bbe5ec5db9590c97ba3a0d6f9ff0b9a50", "487d2eae00a6b2d1efc2c866ef14376f4a1ff814a7b41e72d11573d0d0ceb9db", "1bd32c6f89a1a6e844ddc9fa2c078a2f6845740623fe3490c827d6a262dcdadb", "a3a032b14018c577a7cda689996bc18194150f9947a8344c2df8bef7dcf4f0f1", "1c7cf31e4a77050ef2ba412c7ae4e10e972747b1dd9e96f2904695640812be8e",
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("golden %d mismatch: got %s", index, got[index])
		}
	}
}

// TestCampaignContractRejectsSemanticDrift covers unsafe cross-repository variants.
func TestCampaignContractRejectsSemanticDrift(t *testing.T) {
	base := WorkItem{Tenant: "tenant", Domain: "example.test", Use: useOriginator, Profile: "profile", Algorithms: []string{algorithmEd25519, algorithmRSA}}
	tests := []struct {
		name string
		work []WorkItem
	}{
		{name: "duplicate", work: []WorkItem{base, base}},
		{name: "reordered", work: []WorkItem{{Tenant: "z", Domain: "z.example.test", Use: useOriginator, Profile: "z", Algorithms: []string{algorithmRSA}}, base}},
		{name: "algorithm reordered", work: []WorkItem{{Tenant: base.Tenant, Domain: base.Domain, Use: base.Use, Profile: base.Profile, Algorithms: []string{algorithmRSA, algorithmEd25519}}}},
		{name: "unknown algorithm", work: []WorkItem{{Tenant: base.Tenant, Domain: base.Domain, Use: base.Use, Profile: base.Profile, Algorithms: []string{"unknown"}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := FrozenWorkDigest(test.work); err == nil {
				t.Fatal("unsafe work set accepted")
			}
		})
	}
	if _, err := CampaignPlanDigest(CampaignPlan{Version: ContractVersion, Mode: ModeEmergency, SourceSchema: schemaV3, SourceGeneration: 7, CandidateGeneration: 7, OperationID: "aebagbafaydqqcikbmga2dqpca", Work: []WorkItem{base}, EmergencyReason: "compromise", RotationPolicyVersion: "rotation-v1", DNSPolicyVersion: "dns-v1", RetentionPolicyVersion: testRetentionPolicy, LimitProfileVersion: "production-v1"}); err == nil {
		t.Fatal("non-forward candidate accepted")
	}
	if _, err := DNSBatchDigest(DNSBatch{CandidateDigest: mustDigest(t, "df6f03fc47b8f22a8ac3bf8312dda6f364de0ad21827f6e24e0363f14f14d6df"), FrozenWorkDigest: mustDigest(t, "15f765eaa2e2b99b3f5b454d05072c10f93c70ac5c2c54cddc21b877ebaf7e2a"), Ordinal: 1, Start: 1, End: 2, Total: 2}); err == nil {
		t.Fatal("batch gap accepted")
	}
	if _, err := PurgePlanDigest(PurgePlan{Version: ContractVersion, CurrentGeneration: 8, InventoryVersion: testInventoryVersion, PolicyVersion: testRetentionPolicy, Targets: []PurgeTarget{{Generation: 8, Schema: schemaV3, Lifecycle: lifecycleActiveHistory, ContentDigest: mustDigest(t, "15f765eaa2e2b99b3f5b454d05072c10f93c70ac5c2c54cddc21b877ebaf7e2a")}}}); err == nil {
		t.Fatal("current generation entered purge plan")
	}
}

// mustDigest decodes one exact nonzero SHA-256 test commitment.
func mustDigest(t *testing.T, value string) Digest {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := ParseDigest(decoded)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
