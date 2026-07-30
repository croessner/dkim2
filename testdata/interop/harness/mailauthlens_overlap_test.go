package dkim2

import "testing"

// TestDNSKeyFWS verifies the peer accepts DNS-04 FWS with a DKIM1-compatible record.
func TestDNSKeyFWS(t *testing.T) {
	record, err := ParseKeyRecord(
		"v = DKIM1; k = ed25519; p = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=;",
	)
	if err != nil || record.Version != "DKIM1" || record.KeyType != "ed25519" {
		t.Fatal("peer result did not match the closed accepted state")
	}
}

// TestSignatureFWS verifies the peer accepts Draft-04 FWS around tag separators.
func TestSignatureFWS(t *testing.T) {
	signature, err := Parse(
		"i = 1; m = 1; n = peer-case; t = 1720000000; " +
			"mf = PHNlbmRlckBzZW5kZXIuZXhhbXBsZS50ZXN0Pg==; " +
			"rt = PHVzZXJAZXhhbXBsZS50ZXN0Pg==; " +
			"d = sender.example.test; s = selector:rsa-sha256:AA==;",
	)
	if err != nil || signature.SequenceNumber != 1 ||
		signature.Domain != "sender.example.test" {
		t.Fatal("peer result did not match the closed accepted state")
	}
}

// TestSignatureMixedCaseObservation records this peer's exact case behavior.
func TestSignatureMixedCaseObservation(t *testing.T) {
	if _, err := Parse(
		"I=1; m=1; n=peer-case; t=1720000000; " +
			"mf=PHNlbmRlckBzZW5kZXIuZXhhbXBsZS50ZXN0Pg==; " +
			"rt=PHVzZXJAZXhhbXBsZS50ZXN0Pg==; " +
			"d=sender.example.test; s=selector:rsa-sha256:AA==;",
	); err == nil {
		t.Fatal("peer behavior changed from its reviewed case-sensitive result")
	}
}
