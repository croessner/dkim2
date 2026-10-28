package dkim2

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

// diagnosticSelector is the selector of the signed fixture.
const diagnosticSelector = "selector.test"

// TestNonPassingSignatureSetsNameTheirSelector reproduces Draft-08 Section
// 14.6 step 8 at the per-set result level: every non-passing set names its
// parsed selector, whether it failed, hit a key error, met a temporary
// provider failure, or used an unknown algorithm, while a passing set names
// none.
func TestNonPassingSignatureSetsNameTheirSelector(t *testing.T) {
	const timestamp = int64(1700000000)
	raw, key := signedPublicFlaggedPolicyMessage(t, timestamp)
	other, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	tests := []struct {
		name     string
		raw      []byte
		result   PublicKeyResult
		err      error
		status   SignatureStatus
		reason   ReasonCode
		selector string
	}{
		{name: "pass", raw: raw, result: FoundRSAPublicKey(key), status: SignatureStatusPASS, reason: ReasonNone},
		{name: "signature mismatch", raw: raw, result: FoundRSAPublicKey(&other.PublicKey), status: SignatureStatusFAIL, reason: ReasonSignatureMismatch, selector: diagnosticSelector},
		{name: "key error", raw: raw, result: MissingPublicKey(AlgorithmRSASHA256), status: SignatureStatusPERMERROR, reason: ReasonMissingKey, selector: diagnosticSelector},
		{name: "temporary provider", raw: raw, err: toxicTemporaryProviderError{}, status: SignatureStatusTEMPERROR, reason: ReasonProviderTemporary, selector: diagnosticSelector},
		{name: "unknown algorithm", raw: bytes.Replace(raw, []byte(":rsa-sha256:"), []byte(":x-future:"), 1), result: FoundRSAPublicKey(key), status: SignatureStatusIgnored, reason: ReasonUnsupportedAlgorithm, selector: diagnosticSelector},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
				return test.result, test.err
			}), WithVerificationClock(func() time.Time { return time.Unix(timestamp, 0) }))
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}
			result, err := verifier.Verify(context.Background(), NewVerifyRequest(test.raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
			sets := result.SignatureSets()
			if err != nil || !result.Valid() || len(sets) != 1 {
				t.Fatalf("Verify() valid=%t sets=%d error=%v", result.Valid(), len(sets), err)
			}
			selector, present := sets[0].Selector()
			if sets[0].Status() != test.status || sets[0].Reason() != test.reason || selector != test.selector || present != (test.selector != "") {
				t.Fatalf("set = %q/%q selector=%q present=%t", sets[0].Status(), sets[0].Reason(), selector, present)
			}
		})
	}
}
