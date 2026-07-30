package dkim2

import "testing"

const interopSignature = "i = 1; m = 1; n = peer-case; t = 1720000000; " +
	"mf = PHNlbmRlckBzZW5kZXIuZXhhbXBsZS50ZXN0Pg==; " +
	"rt = PHVzZXJAZXhhbXBsZS50ZXN0Pg==; " +
	"d = sender.example.test; s = selector:rsa-sha256:AA==;"

// TestSignatureFWS verifies the peer's exact overlapping tag-list behavior.
func TestSignatureFWS(t *testing.T) {
	signature, err := ParseSignature(interopSignature)
	if err != nil || signature.Sequence != 1 || signature.Domain != "sender.example.test" {
		t.Fatal("peer result did not match the closed accepted state")
	}
}

// TestSignatureMixedCase records the peer's case-insensitive tag interpretation.
func TestSignatureMixedCase(t *testing.T) {
	signature, err := ParseSignature("I" + interopSignature[1:])
	if err != nil || signature.Sequence != 1 {
		t.Fatal("peer behavior changed from its reviewed case-insensitive result")
	}
}
