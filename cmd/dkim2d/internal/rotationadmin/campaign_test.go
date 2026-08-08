package rotationadmin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

const campaignOperation = "aebagbafaydqqcikbmga2dqpca"

type deterministicKeyFactory struct{ next byte }

// Generate returns one deterministic valid Ed25519 fixture key.
func (f *deterministicKeyFactory) Generate(_ context.Context, algorithm string) (GeneratedKey, error) {
	if algorithm != string(provider.AlgorithmEd25519SHA256) {
		return GeneratedKey{}, errInvalid
	}
	f.next++
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{f.next}, ed25519.SeedSize))
	privatePKCS8, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return GeneratedKey{}, err
	}
	publicSPKI, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		clear(privatePKCS8)
		return GeneratedKey{}, err
	}
	return GeneratedKey{PublicSPKI: publicSPKI, PrivatePKCS8: privatePKCS8}, nil
}

// TestNormalCampaignPreparesOneCompleteCandidateOnce covers all-binding replacement.
func TestNormalCampaignPreparesOneCompleteCandidateOnce(t *testing.T) {
	source := campaignSource(t, 2)
	defer source.Close() //nolint:errcheck // Test cleanup has no recovery.
	intent, err := NewIntent(admincontract.ModeNormal, campaignOperation, "")
	if err != nil {
		t.Fatal("normal intent rejected")
	}
	plan, err := Freeze(t.Context(), source, 8, intent, DefaultLimits())
	if err != nil || plan.WorkCount() != 2 || !plan.Digest().Valid() || !plan.FrozenDigest().Valid() {
		t.Fatal("complete work inventory not frozen")
	}
	defer plan.Close() //nolint:errcheck // Test cleanup has no recovery.
	preparer, err := NewPreparer(&deterministicKeyFactory{}, provider.ProductionLimits())
	if err != nil {
		t.Fatal("preparer rejected")
	}
	prepared, err := preparer.Prepare(t.Context(), plan, source)
	if err != nil || prepared.WorkCount() != 2 {
		t.Fatalf("complete candidate not prepared: %v", err)
	}
	defer prepared.Close() //nolint:errcheck // Test cleanup has no recovery.
	if _, err := preparer.Prepare(t.Context(), plan, source); err == nil {
		t.Fatal("same plan generated a second nondurable candidate")
	}
	if !mustCandidateDigest(t, prepared).Valid() {
		t.Fatal("prepared candidate digest missing")
	}
	err = prepared.WithEnvelope(t.Context(), func(envelope *datasourceadmin.PublicationEnvelope) error {
		if envelope.Generation() != 8 {
			return errConflict
		}
		return envelope.WithRows(t.Context(), func(rows datasourceadmin.Rows) error {
			if len(rows.Policies) != 2 || len(rows.Profiles) != 2 || len(rows.Credentials) != 2 ||
				len(rows.Handles) != 2 || len(rows.KeyMaterial) != 2 {
				return errConflict
			}
			for _, policy := range rows.Policies {
				if policy.ProfileID == "profile-0" || policy.ProfileID == "profile-1" {
					return errConflict
				}
			}
			return nil
		})
	})
	if err != nil {
		t.Fatal("candidate retained old or duplicate generation rows")
	}
	if source.Generation() != 7 {
		t.Fatal("source generation mutated")
	}
}

// TestEmergencyCampaignRotatesOnlyTheExactSelectedBinding covers explicit separation.
func TestEmergencyCampaignRotatesOnlyTheExactSelectedBinding(t *testing.T) {
	source := campaignSource(t, 2)
	defer source.Close() //nolint:errcheck // Test cleanup has no recovery.
	selector := BindingSelector{Tenant: "tenant", Domain: "d00001.example.test", Use: "originator", Profile: "profile-1"}
	intent, err := NewEmergencyIntent(campaignOperation, "compromise", selector)
	if err != nil {
		t.Fatal("emergency intent rejected")
	}
	plan, err := Freeze(t.Context(), source, 8, intent, DefaultLimits())
	if err != nil || plan.WorkCount() != 1 || plan.intent.Mode() != admincontract.ModeEmergency {
		t.Fatal("emergency work was not exact")
	}
	defer plan.Close() //nolint:errcheck // Test cleanup has no recovery.
	preparer, _ := NewPreparer(&deterministicKeyFactory{}, provider.ProductionLimits())
	prepared, err := preparer.Prepare(t.Context(), plan, source)
	if err != nil {
		t.Fatalf("emergency candidate rejected: %v", err)
	}
	defer prepared.Close() //nolint:errcheck // Test cleanup has no recovery.
	err = prepared.WithEnvelope(t.Context(), func(envelope *datasourceadmin.PublicationEnvelope) error {
		return envelope.WithRows(t.Context(), func(rows datasourceadmin.Rows) error {
			unchanged, changed := false, false
			for _, policy := range rows.Policies {
				unchanged = unchanged || policy.Domain == "d00000.example.test" && policy.ProfileID == "profile-0"
				changed = changed || policy.Domain == selector.Domain && policy.ProfileID != selector.Profile
			}
			if !unchanged || !changed || len(rows.Profiles) != 2 {
				return errConflict
			}
			return nil
		})
	})
	if err != nil {
		t.Fatal("emergency candidate changed the wrong binding")
	}
}

// TestCampaignProtectedOwnersRejectGenericSerialization covers identity privacy.
func TestCampaignProtectedOwnersRejectGenericSerialization(t *testing.T) {
	source := campaignSource(t, 1)
	defer source.Close() //nolint:errcheck // Test cleanup has no recovery.
	intent, _ := NewIntent(admincontract.ModeNormal, campaignOperation, "")
	plan, err := Freeze(t.Context(), source, 8, intent, DefaultLimits())
	if err != nil {
		t.Fatal("plan fixture rejected")
	}
	defer plan.Close() //nolint:errcheck // Test cleanup has no recovery.
	for _, value := range []any{intent, plan} {
		if _, err := json.Marshal(value); err == nil || !bytes.Contains([]byte(fmt.Sprintf("%+v", value)), []byte(redacted)) {
			t.Fatal("protected campaign value reached a generic sink")
		}
	}
}

// mustCandidateDigest obtains one prepared commitment for assertions.
func mustCandidateDigest(t *testing.T, prepared *Prepared) admincontract.Digest {
	t.Helper()
	digest, err := prepared.CandidateDigest()
	if err != nil {
		t.Fatal("candidate digest unavailable")
	}
	return digest
}

// campaignSource constructs one complete valid native source generation.
func campaignSource(t *testing.T, count int) *datasourceadmin.Snapshot {
	t.Helper()
	rows := datasourceadmin.Rows{}
	for index := 0; index < count; index++ {
		domain := fmt.Sprintf("d%05d.example.test", index)
		profileID, handleID := fmt.Sprintf("profile-%d", index), fmt.Sprintf("handle-%d", index)
		private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(index + 100)}, ed25519.SeedSize))
		privatePKCS8, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatal("marshal source private key")
		}
		publicSPKI, err := x509.MarshalPKIXPublicKey(private.Public())
		if err != nil {
			t.Fatal("marshal source public key")
		}
		rows.Handles = append(rows.Handles, datasourceadmin.HandleRow{ID: handleID})
		rows.Profiles = append(rows.Profiles, datasourceadmin.ProfileRow{ID: profileID, Domain: domain, Status: "active"})
		rows.Credentials = append(rows.Credentials, datasourceadmin.CredentialRow{ProfileID: profileID, Algorithm: "ed25519-sha256", Selector: fmt.Sprintf("s%d", index), PublicSPKI: publicSPKI, HandleID: handleID})
		rows.Policies = append(rows.Policies, datasourceadmin.PolicyRow{TenantID: "tenant", Domain: domain, Use: "originator", ProfileID: profileID, Status: "active", Rollout: "enforce", Compatibility: "strict"})
		rows.KeyMaterial = append(rows.KeyMaterial, datasourceadmin.KeyMaterialRow{TenantID: "tenant", Domain: domain, Use: "originator", HandleID: handleID, Algorithm: "ed25519-sha256", PublicSPKI: append([]byte(nil), publicSPKI...), PrivatePKCS8: privatePKCS8})
	}
	snapshot, err := datasourceadmin.NewSnapshotWithLimits(datasourceadmin.SchemaVersionV3, 7, rows, provider.ProductionLimits())
	clearAdminRows(&rows)
	if err != nil {
		t.Fatal("source fixture rejected")
	}
	return snapshot
}
