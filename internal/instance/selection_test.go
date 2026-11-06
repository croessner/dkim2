package instance

import "testing"

// TestSHA256HashSetSelection verifies selected, missing, unsupported, and mixed states.
func TestSHA256HashSetSelection(t *testing.T) {
	selected := mustSelectionInstance(t, "m=1; h=sha256:"+base64OfByte(1, 32)+":"+base64OfByte(2, 32))
	set, status := selected.SHA256HashSet()
	if status != HashSelectionStatusSelected || !set.Known() || set.Name() != HashAlgorithmSHA256 {
		t.Fatalf("selected mismatch: status=%s", status)
	}
	unsupported := mustSelectionInstance(t, "m=1; h=future:"+base64OfByte(1, 32)+":"+base64OfByte(2, 32))
	if set, status = unsupported.SHA256HashSet(); status != HashSelectionStatusUnsupported || set.Known() || set.Name() != "" {
		t.Fatalf("unsupported mismatch: status=%s", status)
	}
	mixed := mustSelectionInstance(t, "m=1; h=future:"+base64OfByte(1, 32)+":"+base64OfByte(2, 32)+",sha256:"+base64OfByte(3, 32)+":"+base64OfByte(4, 32))
	if set, status = mixed.SHA256HashSet(); status != HashSelectionStatusSelected || !set.Known() {
		t.Fatalf("mixed mismatch: status=%s", status)
	}
	if set, status = (MessageInstance{}).SHA256HashSet(); status != HashSelectionStatusMissing || set.Known() || set.Name() != "" {
		t.Fatalf("missing mismatch: status=%s", status)
	}
}

// TestSupportedHashSetSelection distinguishes supported, unknown-only, and empty states.
func TestSupportedHashSetSelection(t *testing.T) {
	dual := mustSelectionInstance(t, "m=1; h=sha256:"+base64OfByte(1, 32)+":"+base64OfByte(2, 32)+",sha512:"+base64OfByte(3, 64)+":"+base64OfByte(4, 64))
	sets, status := dual.SupportedHashSets()
	if status != HashSelectionStatusSelected || len(sets) != 2 {
		t.Fatalf("dual selection status=%s sets=%d", status, len(sets))
	}
	unknown := mustSelectionInstance(t, "m=1; h=future:"+base64OfByte(1, 8)+":"+base64OfByte(2, 8))
	if sets, status = unknown.SupportedHashSets(); status != HashSelectionStatusUnsupported || len(sets) != 0 {
		t.Fatalf("unknown selection status=%s sets=%d", status, len(sets))
	}
	if sets, status = (MessageInstance{}).SupportedHashSets(); status != HashSelectionStatusMissing || len(sets) != 0 {
		t.Fatalf("empty selection status=%s sets=%d", status, len(sets))
	}
}

// mustSelectionInstance parses one selector fixture.
func mustSelectionInstance(t *testing.T, value string) MessageInstance {
	t.Helper()
	parsed, err := Parse(messageInstanceField(t, 0, value))
	if err != nil {
		t.Fatalf("selection fixture failed: %v", err)
	}
	return parsed
}
