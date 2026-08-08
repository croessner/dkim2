package datasourceadmin

import (
	"testing"
	"time"
)

// TestTerminalRecordRejectsMismatchedCurrent reproduces a false closure record.
func TestTerminalRecordRejectsMismatchedCurrent(t *testing.T) {
	operation, err := NewOperationBinding("aebagbafaydqqcikbmga2dqpca")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := ParseCandidateContentDigest([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	when := time.Unix(2_000_000_000, 0).UTC()
	if _, err := NewTerminalRecord(operation, SchemaVersionV3, SchemaVersionV3, 7, 8, 7, digest, TerminalClosed, "activated", when); err == nil {
		t.Fatal("mismatched closure current accepted")
	}
	if _, err := NewTerminalRecord(operation, SchemaVersionV3, SchemaVersionV3, 7, 8, 7, digest, TerminalAborted, "operator_abort", when); err != nil {
		t.Fatal("exact staged abort rejected")
	}
	if _, err := NewTerminalRecord(operation, SchemaVersionV3, SchemaVersionV2, 7, 8, 8, digest, TerminalClosed, "activated", when); err != nil {
		t.Fatal("v2 source to v3 candidate closure rejected")
	}
}
