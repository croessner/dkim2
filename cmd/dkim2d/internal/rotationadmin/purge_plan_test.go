package rotationadmin

import (
	"testing"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// TestPurgePlanRequiresExactAuthorityAndDestructiveIntent freezes the read-only apply fence.
func TestPurgePlanRequiresExactAuthorityAndDestructiveIntent(t *testing.T) {
	policy := datasourceadmin.DefaultRetentionPolicy()
	policy.MaxTotalGenerations, policy.MinActiveRollbackGenerations, policy.MaxClosedNeverActiveGenerations, policy.MaxPurgeBatch = 1, 0, 0, 1
	classification, err := datasourceadmin.ClassifyRetention(datasourceadmin.RetentionInventory{Version: testInventoryVersion, Current: 2, Generations: []datasourceadmin.RetentionGeneration{purgeGeneration(t, 1), purgeGeneration(t, 2)}}, policy)
	if err != nil {
		t.Fatal(err)
	}
	authority := purgeAuthority()
	plan, err := NewPurgePlan(datasourceadmin.BackendLDAP, authority, classification)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close() //nolint:errcheck // Test cleanup has no recovery.
	if _, err := NewPurgeApplyRequest(plan, false); err == nil {
		t.Fatal("apply accepted without explicit destructive intent")
	}
	request, err := NewPurgeApplyRequest(plan, true)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := request.VerifyReadback(datasourceadmin.BackendLDAP, authority, policy, datasourceadmin.RetentionInventory{Version: testInventoryVersion, Current: 2, Generations: []datasourceadmin.RetentionGeneration{purgeGeneration(t, 1), purgeGeneration(t, 2)}})
	if err != nil || !fence.Ready() {
		t.Fatal("exact protected plan did not survive readback")
	}
	changedPolicy := policy
	changedPolicy.MaxPurgeBatch = 2
	if _, err := request.VerifyReadback(datasourceadmin.BackendLDAP, authority, changedPolicy, datasourceadmin.RetentionInventory{Version: testInventoryVersion, Current: 2, Generations: []datasourceadmin.RetentionGeneration{purgeGeneration(t, 1), purgeGeneration(t, 2)}}); err == nil {
		t.Fatal("policy change between plan and apply accepted")
	}
	if _, err := request.VerifyReadback(datasourceadmin.BackendLDAP, authority, policy, datasourceadmin.RetentionInventory{Version: "inventory-v2", Current: 2, Generations: []datasourceadmin.RetentionGeneration{purgeGeneration(t, 1), purgeGeneration(t, 2)}}); err == nil {
		t.Fatal("stale inventory version accepted")
	}
	fence, err = request.VerifyReadback(datasourceadmin.BackendLDAP, authority, policy, datasourceadmin.RetentionInventory{Version: testInventoryVersion, Current: 2, Generations: []datasourceadmin.RetentionGeneration{purgeGeneration(t, 2)}})
	if err != nil || !fence.IdempotentAbsent() {
		t.Fatal("exact all-absent retry was not idempotent")
	}
}

// purgeGeneration creates safe committed generation evidence.
func purgeGeneration(t *testing.T, generation uint64) datasourceadmin.RetentionGeneration {
	t.Helper()
	bytes := make([]byte, 32)
	bytes[0] = byte(generation)
	digest, err := admincontract.ParseDigest(bytes)
	if err != nil {
		t.Fatal(err)
	}
	return datasourceadmin.RetentionGeneration{Generation: generation, Schema: "dkim2-datasource-v3", State: datasourceadmin.StateCommitted, WasActive: true, Complete: true, Ownership: datasourceadmin.RetentionOwnershipTrusted, ContentDigest: digest}
}

// purgeAuthority creates a complete synthetic LDAPS authority descriptor.
func purgeAuthority() datasourceadmin.AuthorityDescriptor {
	var trust [32]byte
	trust[0] = 1
	return datasourceadmin.AuthorityDescriptor{AuthorityID: "aebagbafaydqqcikbmga2dqpca", Endpoints: []datasourceadmin.AuthorityEndpoint{{Scheme: "ldaps", Host: "ldap.example.test", Port: 636, TLSServerName: "ldap.example.test"}}, LDAP: &datasourceadmin.LDAPAuthority{BaseDN: "dc=example,dc=test", SnapshotPrincipal: "snapshot", StagingPrincipal: "staging", ActivationPrincipal: "activation", PurgePrincipal: "purger"}, TrustFingerprints: [][32]byte{trust}}
}
