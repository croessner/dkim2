package datasourceadmin

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const secondDigestTestID = "aibqibiga4eascqlbqgy3dymc4"

// TestLockAndActivationRequireExactInitializedEvidence freezes the provider fence.
func TestLockAndActivationRequireExactInitializedEvidence(t *testing.T) {
	operation, err := NewOperationBinding(digestTestID)
	if err != nil {
		t.Fatal("operation binding rejected")
	}
	if lock, err := NewAdministrationLock(operation, 0); err == nil || lock.ValidFor(operation) {
		t.Fatal("zero-revision lock accepted")
	}
	lock, err := NewAdministrationLock(operation, 7)
	if err != nil || !lock.ValidFor(operation) {
		t.Fatal("exact operation lock rejected")
	}
	other, err := NewOperationBinding(secondDigestTestID)
	if err != nil || lock.ValidFor(other) {
		t.Fatal("different operation satisfied lock")
	}
	if activation, err := NewActivation(lock, operation, 7, 9, PreparedEvidence{}, StagedEvidence{}); err == nil || activation.Valid() {
		t.Fatal("zero digest evidence satisfied activation")
	}
	candidate := mustCandidate(t, deterministicRows(t))
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	prepared := candidate.PreparedEvidence()
	staged := NewStagedEvidence(candidate.Digest())
	activation, err := NewActivation(lock, operation, 7, 9, prepared, staged)
	if err != nil || !activation.Valid() || activation.Lock().Revision() != 7 {
		t.Fatal("exact lock-bound activation rejected")
	}
	if invalid, err := NewActivation(lock, other, 7, 9, prepared, staged); err == nil || invalid.Valid() {
		t.Fatal("mismatched operation activation accepted")
	}
}

// TestStoredDigestParsingAndMetadataAccessFreezeProviderRoundTrip freezes v3 seams.
func TestStoredDigestParsingAndMetadataAccessFreezeProviderRoundTrip(t *testing.T) {
	candidate := mustCandidate(t, deterministicRows(t))
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	stored := candidate.Digest().Bytes()
	parsed, err := ParseCandidateContentDigest(stored)
	if err != nil || !parsed.Equal(candidate.Digest()) {
		t.Fatal("stored candidate digest did not round-trip")
	}
	staged, err := ParseStagedEvidence(stored)
	if err != nil || !candidate.PreparedEvidence().Matches(staged) {
		t.Fatal("stored staged evidence did not round-trip")
	}
	for _, invalid := range [][]byte{nil, make([]byte, 31), make([]byte, 32), make([]byte, 33)} {
		if _, err := ParseCandidateContentDigest(invalid); err == nil {
			t.Fatal("invalid stored digest accepted")
		}
	}
	called := false
	if err := candidate.WithMetadata(t.Context(), func(operation OperationBinding, digest CandidateContentDigest) error {
		called = operation.Equal(candidate.Binding()) && digest.Equal(candidate.Digest())
		return nil
	}); err != nil || !called {
		t.Fatal("provider metadata callback lacked exact operation or digest")
	}
}

// TestProviderFenceTypesRejectGenericSinks freezes token and evidence privacy.
func TestProviderFenceTypesRejectGenericSinks(t *testing.T) {
	operation, _ := NewOperationBinding(digestTestID)
	lock, _ := NewAdministrationLock(operation, 7)
	candidate := mustCandidate(t, deterministicRows(t))
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	activation, _ := NewActivation(lock, operation, 7, 9, candidate.PreparedEvidence(), NewStagedEvidence(candidate.Digest()))
	values := []any{operation, lock, activation, struct{ Lock AdministrationLock }{Lock: lock}}
	for _, value := range values {
		rendered := fmt.Sprintf("%+v", value)
		if !strings.Contains(rendered, redacted) || strings.Contains(rendered, digestTestID) {
			t.Fatal("provider fence reached formatting sink")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("provider fence reached JSON sink")
		}
	}
}
