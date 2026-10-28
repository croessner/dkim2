package testclient

import (
	"encoding/json"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2ctl/internal/testclient/generated"
)

// TestGeneratedClientAdmitsMLDSA44Vocabulary proves the generated client
// admits the Draft-08 Section 3.4 mldsa44 algorithm in both closed response
// vocabularies (signature-set results and verifier-projection hops) while the
// removed Draft-07 composite stays outside them.
func TestGeneratedClientAdmitsMLDSA44Vocabulary(t *testing.T) {
	var verification generated.VerificationResult
	payload := `{"state":"PASS","primary_reason":"none","scope":"chain","historical_content":"complete",` +
		`"historical_signatures":"complete","custody_structure":"not_present","checks":[{"class":"signature","reason":"none"}],` +
		`"signature_sets":[{"algorithm":"rsa-sha256","status":"pass","reason":"none"},` +
		`{"algorithm":"ed25519-sha256","status":"pass","reason":"none"},{"algorithm":"mldsa44","status":"pass","reason":"none"}],` +
		`"target":{"sequence":"1","instance":"1"}}`
	if err := json.Unmarshal([]byte(payload), &verification); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if !validVerificationProjection(verification) {
		t.Fatal("verification with an mldsa44 signature set was rejected")
	}
	verification.SignatureSets[2].Algorithm = "mldsa44-ed25519-sha512"
	if validVerificationProjection(verification) {
		t.Fatal("verification with the removed composite was admitted")
	}
	algorithms, ok := verifierAlgorithmStrings([]generated.VerifierHopSignatureAlgorithms{
		generated.VerifierAlgorithmEd25519SHA256, generated.VerifierAlgorithmMLDSA44, generated.VerifierAlgorithmRSASHA256,
	})
	if !ok || len(algorithms) != 3 || algorithms[1] != "mldsa44" {
		t.Fatalf("verifierAlgorithmStrings() = %v, %t", algorithms, ok)
	}
	if _, ok := verifierAlgorithmStrings([]generated.VerifierHopSignatureAlgorithms{"mldsa44-ed25519-sha512"}); ok {
		t.Fatal("hop with the removed composite was admitted")
	}
}

// TestGeneratedClientRejectsUnproducedSHA512Vocabulary proves the verifier
// projection hop vocabulary is exactly the Draft-08 Section 3 signature
// algorithms the daemon can verify. rsa-sha512 and ed25519-sha512 appear only
// in the DNS-02 registry listing; no verifier projection can carry them.
func TestGeneratedClientRejectsUnproducedSHA512Vocabulary(t *testing.T) {
	for _, algorithm := range []generated.VerifierHopSignatureAlgorithms{"rsa-sha512", "ed25519-sha512"} {
		if algorithm.Valid() {
			t.Fatalf("generated hop vocabulary admits unproduced %q", algorithm)
		}
		if _, ok := verifierAlgorithmStrings([]generated.VerifierHopSignatureAlgorithms{algorithm}); ok {
			t.Fatalf("hop with unproduced %q was admitted", algorithm)
		}
	}
}
