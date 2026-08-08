package datasourceadmin

import (
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/admincontract"
)

// TestAuditLogRetainsOnlyFiniteKeyFreeCommitments freezes compact receipt retention.
func TestAuditLogRetainsOnlyFiniteKeyFreeCommitments(t *testing.T) {
	log, err := NewAuditLog(1)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close() //nolint:errcheck // Test cleanup has no recovery.
	target := admincontract.PurgeTarget{Generation: 1, Schema: "dkim2-datasource-v3", Lifecycle: "active_history", ContentDigest: retentionGeneration(t, 1, true).ContentDigest}
	plan, err := admincontract.PurgePlanDigest(admincontract.PurgePlan{Version: admincontract.ContractVersion, CurrentGeneration: 2, InventoryVersion: "inventory-v1", PolicyVersion: "retention-v1", Targets: []admincontract.PurgeTarget{target}})
	if err != nil {
		t.Fatal(err)
	}
	for generation := uint64(1); generation <= 2; generation++ {
		target.Generation = generation
		receipt, err := NewAuditReceipt(target, "normal", time.Date(2026, 8, int(generation), 0, 0, 0, 0, time.UTC), "retention-v1", plan)
		if err != nil {
			t.Fatal(err)
		}
		if err := log.Append(receipt); err != nil {
			t.Fatal(err)
		}
	}
	if log.Count() != 1 {
		t.Fatal("unbounded audit receipt retention")
	}
	if strings.Contains(log.String(), "example") {
		t.Fatal("audit log exposed identity")
	}
}
