package datasourceadmin

import "testing"

// TestCandidateContentIsVersionNeutral freezes the operation-free protected owner.
func TestCandidateContentIsVersionNeutral(t *testing.T) {
	for _, schema := range []string{SchemaVersionV2, SchemaVersionV3} {
		snapshot, err := NewSnapshot(schema, 9, deterministicRows(t))
		if err != nil {
			t.Fatal("snapshot fixture rejected")
		}
		content, err := NewCandidateContent(snapshot)
		if err != nil || content.Generation() != 9 {
			t.Fatal("version-neutral candidate content rejected")
		}
		if err := content.Close(); err != nil {
			t.Fatal("candidate content cleanup failed")
		}
	}
}

// TestPublicationEnvelopeRequiresV3AndExactOperation freezes the publication boundary.
func TestPublicationEnvelopeRequiresV3AndExactOperation(t *testing.T) {
	v2Snapshot, err := NewSnapshot(SchemaVersionV2, 9, deterministicRows(t))
	if err != nil {
		t.Fatal("v2 snapshot fixture rejected")
	}
	v2Content, err := NewCandidateContent(v2Snapshot)
	if err != nil {
		t.Fatal("v2 candidate content rejected")
	}
	if envelope, err := NewPublicationEnvelope(digestTestID, v2Content); err == nil || envelope != nil {
		t.Fatal("v2 content entered the v3 publication envelope")
	}
	if v2Content.Generation() != 9 {
		t.Fatal("rejected envelope consumed neutral content")
	}
	_ = v2Content.Close()

	v3Snapshot, err := NewSnapshot(SchemaVersionV3, 9, deterministicRows(t))
	if err != nil {
		t.Fatal("v3 snapshot fixture rejected")
	}
	v3Content, err := NewCandidateContent(v3Snapshot)
	if err != nil {
		t.Fatal("v3 candidate content rejected")
	}
	if envelope, err := NewPublicationEnvelope("invalid", v3Content); err == nil || envelope != nil {
		t.Fatal("invalid operation entered the publication envelope")
	}
	if v3Content.Generation() != 9 {
		t.Fatal("rejected operation consumed neutral content")
	}
	envelope, err := NewPublicationEnvelope(digestTestID, v3Content)
	if err != nil || !envelope.Binding().Initialized() || !envelope.Digest().Valid() {
		t.Fatal("valid v3 publication envelope rejected")
	}
	defer envelope.Close() //nolint:errcheck // Test cleanup has no recovery action.
	if !envelope.PreparedEvidence().Matches(NewStagedEvidence(envelope.Digest())) {
		t.Fatal("prepared and staged envelope bytes differ")
	}
}
