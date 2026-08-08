package datasourceadmin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/croessner/dkim2/provider"
)

const (
	testHandleEd  = "handle-ed"
	testProfileID = "profile-one"
	testDomain    = "example.test"
	testTenant    = "tenant"
	testSelector  = "selector"
)

// TestSnapshotOwnsAndErasesCompleteNativeRows freezes protected ownership.
func TestSnapshotOwnsAndErasesCompleteNativeRows(t *testing.T) {
	rows := validRows(t, 7)
	original := append([]byte(nil), rows.KeyMaterial[0].PrivatePKCS8...)
	snapshot, err := NewSnapshot("dkim2-datasource-v2", 7, rows)
	if err != nil {
		t.Fatal("valid snapshot rejected")
	}
	clear(rows.KeyMaterial[0].PrivatePKCS8)
	if len(snapshot.rows.KeyMaterial[0].PrivatePKCS8) == 0 || snapshot.rows.KeyMaterial[0].PrivatePKCS8[0] != original[0] {
		t.Fatal("snapshot retained caller ownership")
	}
	retained := snapshot.rows.KeyMaterial[0].PrivatePKCS8
	if err := snapshot.Close(); err != nil || !snapshot.closed || len(snapshot.rows.KeyMaterial) != 0 {
		t.Fatal("snapshot did not erase protected bytes")
	}
	for _, octet := range retained {
		if octet != 0 {
			t.Fatal("snapshot release retained private bytes")
		}
	}
}

// TestCandidateDigestIsPermutationIndependentAndContentSensitive freezes canonical encoding.
func TestCandidateDigestIsPermutationIndependentAndContentSensitive(t *testing.T) {
	first := validRows(t, 9)
	second := cloneRows(first)
	first.Handles = append(first.Handles, HandleRow{ID: "handle-second"})
	second.Handles = append([]HandleRow{{ID: "handle-second"}}, second.Handles...)
	one := mustCandidate(t, first)
	two := mustCandidate(t, second)
	defer one.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer two.Close() //nolint:errcheck // Test cleanup has no recovery.
	if !one.Digest().Equal(two.Digest()) {
		t.Fatal("row permutation changed candidate digest")
	}
	changed := cloneRows(first)
	changed.Credentials[0].Selector = "selectos"
	three := mustCandidate(t, changed)
	defer three.Close() //nolint:errcheck // Test cleanup has no recovery.
	if one.Digest().Equal(three.Digest()) {
		t.Fatal("valid one-byte semantic change retained candidate digest")
	}
}

// TestPreparedAndStagedEvidenceUseDistinctTypesWithEqualDigest freezes phases.
func TestPreparedAndStagedEvidenceUseDistinctTypesWithEqualDigest(t *testing.T) {
	candidate := mustCandidate(t, validRows(t, 11))
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	prepared := candidate.PreparedEvidence()
	staged := NewStagedEvidence(candidate.Digest())
	if !prepared.Matches(staged) {
		t.Fatal("equal canonical readback digest did not match")
	}
}

// TestSnapshotRejectsDuplicateNativeIdentityBeyondRowMapping freezes registry validation.
func TestSnapshotRejectsDuplicateNativeIdentityBeyondRowMapping(t *testing.T) {
	rows := validRows(t, 7)
	rows.Handles = append(rows.Handles, HandleRow{ID: "other-handle"})
	duplicate := rows.KeyMaterial[0]
	duplicate.HandleID = "other-handle"
	duplicate.PublicSPKI = append([]byte(nil), duplicate.PublicSPKI...)
	duplicate.PrivatePKCS8 = append([]byte(nil), duplicate.PrivatePKCS8...)
	rows.KeyMaterial = append(rows.KeyMaterial, duplicate)
	materials, err := mapNativeMaterials(7, rows.KeyMaterial, provider.DefaultLimits())
	if err != nil {
		t.Fatal("row-level native mapping did not isolate registry-level duplicate")
	}
	for _, material := range materials {
		_ = material.Close()
	}
	if _, err := NewSnapshot(SchemaVersionV2, 7, rows); err == nil {
		t.Fatal("duplicate native public identity passed shared registry validation")
	}
}

// TestProtectedOwnersRejectGenericJSONAndPreserveFailureOwnership freezes privacy.
func TestProtectedOwnersRejectGenericJSONAndPreserveFailureOwnership(t *testing.T) {
	snapshot, err := NewSnapshot(SchemaVersionV2, 7, validRows(t, 7))
	if err != nil {
		t.Fatal("snapshot fixture rejected")
	}
	if _, err := json.Marshal(snapshot); err == nil {
		t.Fatal("protected snapshot serialized")
	}
	content, err := NewCandidateContent(snapshot)
	if err != nil {
		t.Fatal("neutral candidate content rejected")
	}
	if _, err := NewPublicationEnvelope("invalid", content); err == nil || content.Generation() != 7 {
		t.Fatal("publication-envelope failure consumed neutral content ownership")
	}
	if err := content.Close(); err != nil {
		t.Fatal("release failed candidate input")
	}
}

// TestProtectedRowsRejectDirectAndNestedGenericSinks freezes callback-value privacy.
func TestProtectedRowsRejectDirectAndNestedGenericSinks(t *testing.T) {
	marker := "toxic-private-key-marker"
	markerHandle, markerDomain := "handle.marker", "marker.example.test"
	markerProfile, markerTenant := "profile.marker", "tenant.marker"
	rows := Rows{
		Handles:  []HandleRow{{ID: markerHandle}},
		Profiles: []ProfileRow{{ID: markerProfile, Domain: markerDomain}},
		Credentials: []CredentialRow{{
			ProfileID: markerProfile, Selector: "selector-marker", PublicSPKI: []byte(marker), HandleID: markerHandle,
		}},
		Policies: []PolicyRow{{TenantID: markerTenant, Domain: markerDomain}},
		KeyMaterial: []KeyMaterialRow{{
			TenantID: markerTenant, Domain: markerDomain, HandleID: markerHandle,
			PublicSPKI: []byte(marker), PrivatePKCS8: []byte(marker),
		}},
	}
	values := []any{
		rows, rows.Handles[0], rows.Profiles[0], rows.Credentials[0], rows.Policies[0], rows.KeyMaterial[0],
		struct{ Rows Rows }{Rows: rows}, struct{ Material KeyMaterialRow }{Material: rows.KeyMaterial[0]},
	}
	for _, value := range values {
		rendered := fmt.Sprintf("%+v", value)
		if !strings.Contains(rendered, redacted) || strings.Contains(rendered, marker) || strings.Contains(rendered, rows.Profiles[0].Domain) {
			t.Fatal("protected row reached a formatting sink")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("protected row reached a JSON sink")
		}
	}
}

// TestV2SnapshotClonesToV3Candidate freezes forward-only schema publication.
func TestV2SnapshotClonesToV3Candidate(t *testing.T) {
	current, err := NewSnapshot(SchemaVersionV2, 7, validRows(t, 7))
	if err != nil {
		t.Fatal("v2 fixture rejected")
	}
	defer current.Close() //nolint:errcheck // Test cleanup has no recovery.
	clone, err := current.CloneTo(SchemaVersionV3, 9)
	if err != nil || clone.SchemaVersion() != SchemaVersionV3 || clone.Generation() != 9 {
		t.Fatal("v2 current did not clone into a higher v3 generation")
	}
	content, err := NewCandidateContent(clone)
	if err != nil {
		t.Fatal("v3 clone did not become neutral candidate content")
	}
	candidate, err := NewPublicationEnvelope("aebagbafaydqqcikbmga2dqpca", content)
	if err != nil {
		_ = content.Close()
		t.Fatal("v3 clone did not become publication envelope")
	}
	_ = candidate.Close()
}

// TestCandidateRowsCallbackAndConcurrentCloseDoNotDeadlock freezes lock ordering.
func TestCandidateRowsCallbackAndConcurrentCloseDoNotDeadlock(t *testing.T) {
	candidate := mustCandidate(t, validRows(t, 9))
	entered := make(chan struct{})
	release := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		_ = candidate.WithRows(context.Background(), func(Rows) error {
			close(entered)
			_ = candidate.Digest()
			<-release
			return nil
		})
	}()
	go func() {
		defer wait.Done()
		<-entered
		_ = candidate.Close()
		close(release)
	}()
	wait.Wait()
}

// mustCandidate constructs one complete operation-bound v3 candidate fixture.
func mustCandidate(t *testing.T, rows Rows) *PublicationEnvelope {
	t.Helper()
	snapshot, err := NewSnapshot("dkim2-datasource-v3", 9, rows)
	if err != nil {
		t.Fatal("snapshot fixture rejected")
	}
	content, err := NewCandidateContent(snapshot)
	if err != nil {
		t.Fatal("candidate-content fixture rejected")
	}
	candidate, err := NewPublicationEnvelope("aebagbafaydqqcikbmga2dqpca", content)
	if err != nil {
		_ = content.Close()
		t.Fatal("publication-envelope fixture rejected")
	}
	return candidate
}

// validRows constructs one complete canonical Ed25519 generation.
func validRows(t *testing.T, _ uint64) Rows {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate fixture key")
	}
	privatePKCS8, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal("marshal fixture private key")
	}
	publicSPKI, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal("marshal fixture public key")
	}
	return Rows{
		Handles:     []HandleRow{{ID: testHandleEd}},
		Profiles:    []ProfileRow{{ID: testProfileID, Domain: testDomain, Status: recordStatusActive}},
		Credentials: []CredentialRow{{ProfileID: testProfileID, Algorithm: algorithmEd25519SHA256, Selector: testSelector, PublicSPKI: publicSPKI, HandleID: testHandleEd}},
		Policies:    []PolicyRow{{TenantID: testTenant, Domain: testDomain, Use: profileUseOriginator, ProfileID: testProfileID, Status: recordStatusActive, Rollout: rolloutEnforce, Compatibility: compatibilityStrict}},
		KeyMaterial: []KeyMaterialRow{{TenantID: testTenant, Domain: testDomain, Use: profileUseOriginator, HandleID: testHandleEd, Algorithm: algorithmEd25519SHA256, PublicSPKI: append([]byte(nil), publicSPKI...), PrivatePKCS8: privatePKCS8}},
	}
}

// deterministicRows constructs stable canonical Ed25519 rows for digest goldens.
func deterministicRows(t *testing.T) Rows {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	privatePKCS8, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal("marshal deterministic private key")
	}
	publicSPKI, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal("marshal deterministic public key")
	}
	before, after := "2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"
	feedback := "feedback"
	return Rows{
		Handles:     []HandleRow{{ID: testHandleEd}},
		Profiles:    []ProfileRow{{ID: testProfileID, Domain: testDomain, Status: recordStatusActive, NotBeforeUTC: &before, NotAfterUTC: &after}},
		Credentials: []CredentialRow{{ProfileID: testProfileID, Algorithm: algorithmEd25519SHA256, Selector: testSelector, PublicSPKI: publicSPKI, HandleID: testHandleEd}},
		Policies:    []PolicyRow{{TenantID: testTenant, Domain: testDomain, Use: profileUseOriginator, ProfileID: testProfileID, Status: recordStatusActive, Rollout: rolloutEnforce, Compatibility: compatibilityStrict, FeedbackRouteID: &feedback}},
		KeyMaterial: []KeyMaterialRow{{TenantID: testTenant, Domain: testDomain, Use: profileUseOriginator, HandleID: testHandleEd, Algorithm: algorithmEd25519SHA256, PublicSPKI: append([]byte(nil), publicSPKI...), PrivatePKCS8: privatePKCS8}},
	}
}
