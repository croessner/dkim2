package httpjson

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/croessner/dkim2"
)

// selectorTestProvider answers every key lookup with one fixed outcome.
type selectorTestProvider struct {
	result dkim2.PublicKeyResult
	err    error
}

// LookupPublicKey returns the fixed lookup outcome.
func (p selectorTestProvider) LookupPublicKey(context.Context, dkim2.PublicKeyQuery) (dkim2.PublicKeyResult, error) {
	return p.result, p.err
}

// TestSignatureSetJSONNamesSelectorForEveryNonPassingSet pins the REST
// shape of Draft-08 Section 14.6 step 8: the selector member is present for
// fail, permerror, and temperror sets and absent for pass.
func TestSignatureSetJSONNamesSelectorForEveryNonPassingSet(t *testing.T) {
	const timestamp = int64(1700000000)
	raw, key := signedMultiInstanceResponseMessage(t, timestamp)
	tests := []struct {
		name     string
		provider selectorTestProvider
		want     string
	}{
		{name: "pass", provider: selectorTestProvider{result: dkim2.FoundRSAPublicKey(key)},
			want: `[{"algorithm":"rsa-sha256","reason":"none","status":"pass"}]`},
		{name: "key error", provider: selectorTestProvider{result: dkim2.MissingPublicKey(dkim2.AlgorithmRSASHA256)},
			want: `[{"algorithm":"rsa-sha256","reason":"missing_key","selector":"selector.test","status":"permerror"}]`},
		{name: "temporary", provider: selectorTestProvider{err: dkim2.NewTemporaryProviderError()},
			want: `[{"algorithm":"rsa-sha256","reason":"provider_temporary","selector":"selector.test","status":"temperror"}]`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := dkim2.NewVerifier(test.provider, dkim2.WithVerificationClock(func() time.Time { return time.Unix(timestamp, 0) }))
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}
			result, err := verifier.Verify(context.Background(), dkim2.NewVerifyRequest(raw, []byte("<sender@example.test>"), [][]byte{[]byte("<rcpt@example.test>")}))
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			mapped, err := mapVerificationSnapshot(captureVerification(result))
			if err != nil {
				t.Fatalf("mapVerificationSnapshot() error = %v", err)
			}
			encoded, err := json.Marshal(mapped.SignatureSets)
			if err != nil || string(encoded) != test.want {
				t.Fatalf("signature_sets = %s, want %s (error %v)", encoded, test.want, err)
			}
		})
	}
}
