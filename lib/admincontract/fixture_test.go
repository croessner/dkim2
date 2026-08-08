package admincontract

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"slices"
	"testing"
	"time"
)

type contractFixture struct {
	Schema                 string            `json:"schema"`
	ContractVersion        string            `json:"contract_version"`
	Work                   []fixtureWorkItem `json:"work"`
	SourceSchema           string            `json:"source_schema"`
	SourceGeneration       uint64            `json:"source_generation"`
	CandidateGeneration    uint64            `json:"candidate_generation"`
	OperationID            string            `json:"operation_id"`
	CandidateDigest        string            `json:"candidate_digest"`
	RotationPolicyVersion  string            `json:"rotation_policy_version"`
	DNSPolicyVersion       string            `json:"dns_policy_version"`
	RetentionPolicyVersion string            `json:"retention_policy_version"`
	LimitProfileVersion    string            `json:"limit_profile_version"`
	PurgeContentDigest     string            `json:"purge_content_digest"`
	DestroyedAt            string            `json:"destroyed_at"`
	Expected               map[string]string `json:"expected"`
	NegativeCases          []string          `json:"negative_cases"`
}

type fixtureWorkItem struct {
	Tenant     string   `json:"tenant"`
	Domain     string   `json:"domain"`
	Use        string   `json:"use"`
	Profile    string   `json:"profile"`
	Algorithms []string `json:"algorithms"`
}

// TestPublicContractFixture executes the exact repository-owned consumer contract.
func TestPublicContractFixture(t *testing.T) {
	input, err := os.ReadFile("testdata/v1/contract.json")
	if err != nil {
		t.Fatal("fixture unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var fixture contractFixture
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal("fixture is not strict JSON")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatal("fixture is not one strict JSON document")
	}
	if fixture.Schema != "dkim2.admin-contract-fixture.v1" || fixture.ContractVersion != ContractVersion {
		t.Fatal("fixture version drift")
	}
	work := make([]WorkItem, len(fixture.Work))
	for index, item := range fixture.Work {
		work[index] = WorkItem{Tenant: item.Tenant, Domain: item.Domain, Use: item.Use, Profile: item.Profile, Algorithms: append([]string(nil), item.Algorithms...)}
	}
	frozen, err := FrozenWorkDigest(work)
	if err != nil {
		t.Fatal("fixture work rejected")
	}
	plan, err := CampaignPlanDigest(CampaignPlan{
		Version: ContractVersion, Mode: ModeNormal, SourceSchema: fixture.SourceSchema,
		SourceGeneration: fixture.SourceGeneration, CandidateGeneration: fixture.CandidateGeneration,
		OperationID: fixture.OperationID, Work: work, RotationPolicyVersion: fixture.RotationPolicyVersion,
		DNSPolicyVersion: fixture.DNSPolicyVersion, RetentionPolicyVersion: fixture.RetentionPolicyVersion,
		LimitProfileVersion: fixture.LimitProfileVersion,
	})
	if err != nil {
		t.Fatal("fixture plan rejected")
	}
	candidate, err := ParseDigestHex(fixture.CandidateDigest)
	if err != nil {
		t.Fatal("fixture candidate digest rejected")
	}
	batch, err := DNSBatchDigest(DNSBatch{CandidateDigest: candidate, FrozenWorkDigest: frozen, Ordinal: 1, Start: 0, End: uint32(len(work)), Total: uint32(len(work))})
	if err != nil {
		t.Fatal("fixture batch rejected")
	}
	content, err := ParseDigestHex(fixture.PurgeContentDigest)
	if err != nil {
		t.Fatal("fixture purge content rejected")
	}
	purge, err := PurgePlanDigest(PurgePlan{Version: ContractVersion, CurrentGeneration: fixture.CandidateGeneration, InventoryVersion: testInventoryVersion, PolicyVersion: fixture.RetentionPolicyVersion, Targets: []PurgeTarget{{Generation: 2, Schema: fixture.SourceSchema, Lifecycle: lifecycleActiveHistory, ContentDigest: content}}})
	if err != nil {
		t.Fatal("fixture purge plan rejected")
	}
	destroyed, err := time.Parse(time.RFC3339Nano, fixture.DestroyedAt)
	if err != nil {
		t.Fatal("fixture destruction time rejected")
	}
	audit, err := AuditCommitment(AuditReceipt{Version: ContractVersion, Generation: 2, Schema: fixture.SourceSchema, Lifecycle: lifecycleActiveHistory, OperationClass: operationNormal, ContentDigest: content, DestroyedAt: destroyed, Result: receiptPurged, PolicyVersion: fixture.RetentionPolicyVersion, PurgePlanDigest: purge})
	if err != nil {
		t.Fatal("fixture audit rejected")
	}
	got := map[string]string{"frozen_work_digest": frozen.Hex(), "campaign_plan_digest": plan.Hex(), "dns_batch_digest": batch.Hex(), "purge_plan_digest": purge.Hex(), "audit_commitment": audit.Hex()}
	if len(fixture.Expected) != len(got) {
		t.Fatal("fixture expected set drift")
	}
	for name, value := range got {
		if fixture.Expected[name] != value {
			t.Fatal("fixture commitment drift")
		}
	}
	wantNegative := []string{"duplicate_work", "foreign_operation", "invalid_lifecycle", "missing_work", "reordered_work", "stale_candidate_digest", "unsafe_current_purge_target", "wrong_candidate_generation"}
	slices.Sort(fixture.NegativeCases)
	if !slices.Equal(fixture.NegativeCases, wantNegative) {
		t.Fatal("fixture negative set drift")
	}
}
