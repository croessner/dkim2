package ldap

import (
	"context"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// purgeOrderClient is a no-transport seam for destructive DN-order tests.
type purgeOrderClient struct{ *fakeClient }

// ReadCurrentOptional is unreachable in DN-order tests.
func (*purgeOrderClient) ReadCurrentOptional(context.Context) (Entry, bool, error) {
	return Entry{}, false, nil
}

// ReadGenerationRootOptional is unreachable in DN-order tests.
func (*purgeOrderClient) ReadGenerationRootOptional(context.Context, uint64) (Entry, bool, error) {
	return Entry{}, false, nil
}

// ReadAdministrationLock is unreachable in DN-order tests.
func (*purgeOrderClient) ReadAdministrationLock(context.Context) (datasourceadmin.AdministrationLockObservation, error) {
	return datasourceadmin.AdministrationLockObservation{}, nil
}

// ListPurgeEntries is unreachable in DN-order tests.
func (*purgeOrderClient) ListPurgeEntries(context.Context, uint64, datasourceadmin.GenerationLimits) ([]string, error) {
	return nil, nil
}

// DeletePurgeEntry is unreachable in DN-order tests.
func (*purgeOrderClient) DeletePurgeEntry(context.Context, string) error { return nil }

// PurgeGenerationRoot provides the one fixed test-owned generation root.
func (*purgeOrderClient) PurgeGenerationRoot(generation uint64) string {
	return purgeGenerationRootDN("dc=example,dc=test", generation)
}

// TestOrderPurgeEntriesRejectsForeignAndOrdersRootLast reproduces a malicious
// page containing an unrelated DN and freezes leaf-first exact-subtree order.
func TestOrderPurgeEntriesRejectsForeignAndOrdersRootLast(t *testing.T) {
	client := &purgeOrderClient{fakeClient: &fakeClient{}}
	entries := []string{
		"cn=key-1,ou=key-material,dkim2Generation=7,ou=generations,dc=example,dc=test",
		"dkim2Generation=7,ou=generations,dc=example,dc=test",
		"ou=key-material,dkim2Generation=7,ou=generations,dc=example,dc=test",
	}
	if err := orderPurgeEntries(entries, 7, client); err != nil {
		t.Fatal("exact purge subtree rejected")
	}
	if entries[0][:3] != "cn=" || entries[len(entries)-1][:16] != "dkim2Generation=" {
		t.Fatal("purge order does not remove leaves before root")
	}
	foreign := append([]string(nil), entries...)
	foreign[0] = "cn=unrelated,dc=example,dc=test"
	if err := orderPurgeEntries(foreign, 7, client); err == nil {
		t.Fatal("foreign DN accepted for purge")
	}
}
