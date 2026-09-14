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

// FuzzReportRoundTrip requires admitted reports to retain exact canonical bytes.
func FuzzReportRoundTrip(f *testing.F) {
	f.Add("mx.example; dkim2=fail (reason=signature_mismatch)")
	f.Fuzz(func(t *testing.T, value string) {
		if report, ok := Parse(value); ok && report.Value() != value {
			t.Fatal("noncanonical report accepted")
		}
	})
}
