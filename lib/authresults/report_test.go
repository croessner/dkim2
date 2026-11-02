package authresults

import "testing"

// TestReportRejectsForgedOrUnboundedDiagnostics locks the shared adapter boundary.
func TestReportRejectsForgedOrUnboundedDiagnostics(t *testing.T) {
	for _, value := range []string{
		"mx.example; dkim2=fail (reason=signature_mismatch)",
		"mx.example; dkim2=pass",
	} {
		if _, ok := Parse(value); !ok {
			t.Fatalf("valid report rejected: %q", value)
		}
	}
	for _, value := range []string{
		"mx.example; dkim2=neutral", "mx.example; dkim2=fail (reason=secret_token)",
		"mx.example; dkim2=pass (reason=signature_mismatch)",
		"mx.example; dkim2=fail (reason=signature_mismatch) header.d=victim.example",
		"mx.example; dkim2=fail\r\nX-Forged: yes", "mx.example; dkim2=pass; dmarc=pass",
	} {
		if _, ok := Parse(value); ok {
			t.Fatal("unsafe report accepted")
		}
	}
	r, ok := Parse("mx.example; dkim2=fail (reason=signature_mismatch)")
	if !ok || !r.Matches("mx.example", "fail") || r.Matches("other.example", "fail") || r.Matches("mx.example", "pass") {
		t.Fatal("authority or outcome binding lost")
	}
	if !r.MatchesReason("signature_mismatch") || r.MatchesReason("hash_mismatch") {
		t.Fatal("reason binding lost")
	}
}

// TestReportConstructorBoundsReason proves input never reaches a header unchecked.
func TestReportConstructorBoundsReason(t *testing.T) {
	r, ok := New("mx.example", "fail", "signature_mismatch")
	if !ok || r.Value() != "mx.example; dkim2=fail (reason=signature_mismatch)" {
		t.Fatal("wrong diagnostic")
	}
	if _, ok := New("mx.example", "fail", "recipient@example.test"); ok {
		t.Fatal("address accepted")
	}
}

// TestReportAdmitsReasonlessNone proves the Draft-09 Section 14.1 NONE state
// reports as the bare dkim2=none result and never carries a diagnostic.
func TestReportAdmitsReasonlessNone(t *testing.T) {
	r, ok := New("mx.example", "none", "")
	if !ok || r.Value() != "mx.example; dkim2=none" {
		t.Fatal("reasonless none report rejected or noncanonical")
	}
	if sentinel, ok := New("mx.example", "none", "none"); !ok || sentinel.Value() != r.Value() {
		t.Fatal("none reason sentinel did not normalize to the bare report")
	}
	parsed, ok := Parse("mx.example; dkim2=none")
	if !ok || parsed.Value() != "mx.example; dkim2=none" || !parsed.Matches("mx.example", "none") ||
		parsed.Matches("mx.example", "pass") || !parsed.MatchesReason("none") {
		t.Fatal("none report did not round-trip canonically")
	}
	for _, reason := range []string{"signature_mismatch", "missing_protocol", "replay_indeterminate"} {
		if _, ok := New("mx.example", "none", reason); ok {
			t.Fatalf("none report admitted reason %q", reason)
		}
	}
	for _, value := range []string{
		"mx.example; dkim2=none (reason=none)",
		"mx.example; dkim2=none (reason=missing_protocol)",
		"mx.example; dkim2=NONE", "mx.example; dkim2=none ",
	} {
		if _, ok := Parse(value); ok {
			t.Fatalf("noncanonical none report accepted: %q", value)
		}
	}
}

// FuzzReportRoundTrip requires admitted reports to retain exact canonical bytes.
func FuzzReportRoundTrip(f *testing.F) {
	f.Add("mx.example; dkim2=fail (reason=signature_mismatch)")
	f.Fuzz(func(t *testing.T, value string) {
		if report, ok := Parse(value); ok && report.Value() != value {
			t.Fatal("noncanonical report accepted")
		}
	})
}
