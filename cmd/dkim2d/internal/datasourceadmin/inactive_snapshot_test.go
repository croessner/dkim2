package datasourceadmin

import (
	"testing"

	"github.com/croessner/dkim2/provider"
)

const inactiveSnapshotStatus = "disabled"

// TestSnapshotAcceptsInactivePolicyWithoutAuthorizingIt reproduces complete
// administrative snapshots containing disabled profiles awaiting activation.
func TestSnapshotAcceptsInactivePolicyWithoutAuthorizingIt(t *testing.T) {
	for _, schema := range []string{SchemaVersionV2, SchemaVersionV3} {
		t.Run(schema, func(t *testing.T) {
			rows := validRows(t, 7)
			defer clearRows(&rows)
			rows.Profiles[0].Status = inactiveSnapshotStatus
			rows.Policies[0].Status = inactiveSnapshotStatus
			rows.Policies[0].Rollout = "off"
			snapshot, err := NewSnapshot(schema, 7, rows)
			if err != nil || snapshot == nil {
				t.Fatal("complete inactive native snapshot was rejected")
			}
			if err := snapshot.Close(); err != nil {
				t.Fatal("close inactive native snapshot")
			}
		})
	}
}

// TestSnapshotValidatesInactiveNativeKeys rejects malformed inactive material
// before any content digest or immutable snapshot can be accepted.
func TestSnapshotValidatesInactiveNativeKeys(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Rows)
	}{
		{name: "missing keys", mutate: func(rows *Rows) { clearRows(&Rows{KeyMaterial: rows.KeyMaterial}); rows.KeyMaterial = nil }},
		{name: "bad private key", mutate: func(rows *Rows) { rows.KeyMaterial[0].PrivatePKCS8[0] ^= 0xff }},
		{name: "foreign tenant", mutate: func(rows *Rows) { rows.KeyMaterial[0].TenantID = "foreign" }},
		{name: "foreign domain", mutate: func(rows *Rows) { rows.KeyMaterial[0].Domain = "foreign.test" }},
		{name: "foreign use", mutate: func(rows *Rows) { rows.KeyMaterial[0].Use = "ordinary_transit" }},
		{name: "foreign handle", mutate: func(rows *Rows) { rows.KeyMaterial[0].HandleID = "foreign" }},
		{name: "wrong algorithm", mutate: func(rows *Rows) { rows.KeyMaterial[0].Algorithm = string(provider.AlgorithmRSASHA256) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			rows := validRows(t, 7)
			defer clearRows(&rows)
			rows.Profiles[0].Status = inactiveSnapshotStatus
			rows.Policies[0].Status, rows.Policies[0].Rollout = inactiveSnapshotStatus, "off"
			test.mutate(&rows)
			if snapshot, err := NewSnapshot(SchemaVersionV3, 7, rows); err == nil || snapshot != nil {
				t.Fatal("invalid inactive key bypassed native snapshot validation")
			}
		})
	}
}
