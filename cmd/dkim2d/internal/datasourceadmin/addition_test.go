package datasourceadmin

import "testing"

// TestAddDomainClonesCompleteSourceWithoutMutation freezes the domain operation boundary.
func TestAddDomainClonesCompleteSourceWithoutMutation(t *testing.T) {
	source, err := NewSnapshot(SchemaVersionV2, 7, validRows(t, 7))
	if err != nil {
		t.Fatal("source fixture rejected")
	}
	defer source.Close() //nolint:errcheck // Test cleanup has no recovery.
	addition := domainAdditionFixture(t, "added.example.test", "profile-added", "handle-added")
	defer addition.Close() //nolint:errcheck // Test cleanup has no recovery.
	candidate, err := source.AddDomain(SchemaVersionV3, 9, addition)
	if err != nil {
		t.Fatal("complete domain append rejected")
	}
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	if source.Generation() != 7 || candidate.Generation() != 9 {
		t.Fatal("domain append mutated the source generation")
	}
	if err := source.WithRows(t.Context(), func(rows Rows) error {
		if len(rows.Profiles) != 1 {
			t.Fatal("domain append mutated source rows")
		}
		return nil
	}); err != nil {
		t.Fatal("source projection unavailable")
	}
	if err := candidate.WithRows(t.Context(), func(rows Rows) error {
		if len(rows.Profiles) != 2 || len(rows.KeyMaterial) != 2 {
			t.Fatal("candidate omitted source or appended domain rows")
		}
		return nil
	}); err != nil {
		t.Fatal("candidate projection unavailable")
	}
}

// TestDomainAdditionRejectsPartialAndCollidingRows freezes all-or-nothing append validation.
func TestDomainAdditionRejectsPartialAndCollidingRows(t *testing.T) {
	rows := deterministicRows(t)
	intent := PlanIntent{
		Version: domainIntentVersionV1, Domain: "added.example.test", TenantID: testTenant,
		ProfileUse: profileUseOriginator, Algorithms: []string{algorithmEd25519SHA256},
		Rollout: rolloutEnforce, Compatibility: compatibilityStrict,
	}
	partial := DomainCredential{
		Algorithm: algorithmEd25519SHA256, HandleID: "handle-added", Selector: "selector-added",
		PublicSPKI: rows.Credentials[0].PublicSPKI,
	}
	if addition, err := NewDomainAddition(intent, "profile-added", []DomainCredential{partial}); err == nil || addition != nil {
		t.Fatal("partial domain addition accepted")
	}
	source, err := NewSnapshot(SchemaVersionV2, 7, validRows(t, 7))
	if err != nil {
		t.Fatal("source fixture rejected")
	}
	defer source.Close() //nolint:errcheck // Test cleanup has no recovery.
	collision := domainAdditionFixture(t, "added.example.test", "profile-one", "handle-added")
	defer collision.Close() //nolint:errcheck // Test cleanup has no recovery.
	if candidate, err := source.AddDomain(SchemaVersionV3, 9, collision); err == nil || candidate != nil {
		t.Fatal("profile collision accepted")
	}
}

// TestDomainAdditionErasesOwnedPrivateBytes freezes deterministic cleanup.
func TestDomainAdditionErasesOwnedPrivateBytes(t *testing.T) {
	addition := domainAdditionFixture(t, "added.example.test", "profile-added", "handle-added")
	retained := addition.rows.KeyMaterial[0].PrivatePKCS8
	if err := addition.Close(); err != nil {
		t.Fatal("close domain addition")
	}
	for _, octet := range retained {
		if octet != 0 {
			t.Fatal("domain addition retained private bytes after close")
		}
	}
}

// domainAdditionFixture constructs one complete deterministic domain operation.
func domainAdditionFixture(t *testing.T, domain, profileID, handleID string) *DomainAddition {
	t.Helper()
	rows := deterministicRows(t)
	addition, err := NewDomainAddition(PlanIntent{
		Version: domainIntentVersionV1, Domain: domain, TenantID: testTenant,
		ProfileUse: profileUseOriginator, Algorithms: []string{algorithmEd25519SHA256},
		Rollout: rolloutEnforce, Compatibility: compatibilityStrict,
	}, profileID, []DomainCredential{{
		Algorithm: algorithmEd25519SHA256, HandleID: handleID, Selector: "selector-added",
		PublicSPKI:   rows.Credentials[0].PublicSPKI,
		PrivatePKCS8: rows.KeyMaterial[0].PrivatePKCS8,
	}})
	clearRows(&rows)
	if err != nil {
		t.Fatal("domain addition fixture rejected")
	}
	return addition
}
