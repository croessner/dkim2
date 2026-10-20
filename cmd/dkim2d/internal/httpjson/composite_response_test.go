package httpjson

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
)

type compositeResponseFixture struct {
	Draft     string `json:"draft"`
	Raw       string `json:"raw_base64"`
	Reverse   string `json:"reverse_path_base64"`
	Forward   string `json:"forward_path_base64"`
	DNSRecord string `json:"dns_txt_record"`
}

// loadCompositeResponseFixture loads the deterministic Draft-07
// mldsa44-ed25519-sha512 message and its DNS-01 key record.
func loadCompositeResponseFixture(t *testing.T) compositeResponseFixture {
	t.Helper()
	content, err := os.ReadFile("testdata/mldsa44-ed25519-sha512-pass.json")
	if err != nil {
		t.Fatal("composite verification fixture unavailable")
	}
	var fixture compositeResponseFixture
	if json.Unmarshal(content, &fixture) != nil || fixture.Draft != dkim2.DraftIdentifier {
		t.Fatal("composite verification fixture was invalid")
	}
	return fixture
}

// decodeCompositeFixtureValue decodes one base64 fixture field.
func decodeCompositeFixtureValue(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal("composite fixture field was not base64")
	}
	return decoded
}

// TestMapDomainResultMapsCompositeSignaturePass proves a DNS-resolved
// composite PASS reaches the REST projection with the composite algorithm
// enum instead of an internal contract failure.
func TestMapDomainResultMapsCompositeSignaturePass(t *testing.T) {
	fixture := loadCompositeResponseFixture(t)
	provider, err := dkim2.NewDNSPublicKeyProvider(fixedTXTTransport{payload: []byte(fixture.DNSRecord)})
	if err != nil {
		t.Fatal("DNS provider construction failed")
	}
	verifier, err := dkim2.NewVerifier(provider, dkim2.WithVerificationClock(func() time.Time {
		return time.Unix(1_700_000_000, 0)
	}))
	if err != nil {
		t.Fatal("verifier construction failed")
	}
	result, err := verifier.Verify(context.Background(), dkim2.NewVerifyRequest(
		decodeCompositeFixtureValue(t, fixture.Raw),
		decodeCompositeFixtureValue(t, fixture.Reverse),
		[][]byte{decodeCompositeFixtureValue(t, fixture.Forward)},
	))
	if err != nil || !result.Valid() || result.State() != dkim2.ResultStatePASS {
		t.Fatalf("composite verification = %q/%q", result.State(), result.PrimaryReason())
	}
	decision, err := dkim2.EvaluatePolicy(result, dkim2.WithPolicyMode(dkim2.PolicyModeStrict))
	if err != nil || !decision.Valid() {
		t.Fatal("composite policy decision failed")
	}
	projection, err := MapDomainResult(result, decision)
	if err != nil {
		t.Fatal("composite result did not map")
	}
	verification, _, ok := projection.domainValues()
	if !ok || verification.State != generated.PASS || len(verification.SignatureSets) != 1 ||
		verification.SignatureSets[0].Algorithm != generated.Mldsa44Ed25519Sha512 ||
		verification.SignatureSets[0].Status != generated.SignatureSetResultStatusPass ||
		verification.SignatureSets[0].Reason != generated.VerificationReasonNone {
		t.Fatal("composite signature set was not mapped exactly")
	}
}
