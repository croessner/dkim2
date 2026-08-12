package dkim2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

type publicFuzzSnapshot struct {
	draft      string
	state      ResultState
	scope      VerificationScope
	historical HistoricalState
	custody    CustodyStructure
	reason     ReasonCode
	target     VerificationTarget
	checks     []CheckFact
	signatures []SignatureSetFact
}

// FuzzPublicVerify exercises the public raw-message boundary with bounded synthetic input.
func FuzzPublicVerify(f *testing.F) {
	valid := publicProviderFixture(f)
	f.Add(valid, []byte("<>"), []byte("<rcpt@example.test>"), false)
	f.Add(bytes.Replace(valid, []byte("i=1; m=1;"), []byte("i=1; m=1; m=1;"), 1), []byte("<>"), []byte("<rcpt@example.test>"), false)
	f.Add(bytes.Replace(valid, []byte("i=1;"), []byte("i=2;"), 1), []byte("<>"), []byte("<rcpt@example.test>"), false)
	f.Add(bytes.Replace(valid, []byte("rsa-sha256"), []byte("future-sha999"), 1), []byte("<>"), []byte("<rcpt@example.test>"), false)
	f.Add(bytes.Replace(valid, []byte("t=1700000000"), []byte("t=18446744073709551615"), 1), []byte("<>"), []byte("<rcpt@example.test>"), false)
	f.Add(bytes.Replace(valid, []byte("mf=PD4=; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==;"), []byte("nd=next.example.test;"), 1), []byte(nil), []byte(nil), false)
	f.Add([]byte("From: fuzz@example.test\r\nDKIM2-Signature: i=1; m=1; s=bad:future:not-base64;\r\n\r\n"), []byte("<>"), []byte("<fuzz@example.test>"), false)
	f.Add([]byte("From: PUBLIC-FUZZ-TOXIC-MARKER@example.test\r\n\r\nPUBLIC-FUZZ-TOXIC-MARKER\r\n"), []byte("<PUBLIC-FUZZ-TOXIC-MARKER@example.test>"), []byte("<PUBLIC-FUZZ-TOXIC-MARKER@example.test>"), false)
	f.Add([]byte("From: fuzz@example.test\r\n\r\n"), []byte("<>"), []byte("<fuzz@example.test>"), true)

	provider := publicProviderFunc(func(_ context.Context, query PublicKeyQuery) (PublicKeyResult, error) {
		return MissingPublicKey(query.Algorithm()), nil
	})
	verifier, err := NewVerifier(provider, WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
	if err != nil {
		f.Fatal("fuzz verifier construction failed")
	}
	f.Fuzz(func(t *testing.T, raw, reverse, forward []byte, canceled bool) {
		if len(raw) > 64<<10 || len(reverse) > 512 || len(forward) > 512 {
			t.Skip()
		}
		rawBefore := bytes.Clone(raw)
		reverseBefore := bytes.Clone(reverse)
		forwardBefore := bytes.Clone(forward)
		ctx := context.Background()
		if canceled {
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
		}
		first, firstErr := verifier.Verify(ctx, NewVerifyRequest(raw, reverse, [][]byte{forward}))
		second, secondErr := verifier.Verify(ctx, NewVerifyRequest(raw, reverse, [][]byte{forward}))
		if !bytes.Equal(raw, rawBefore) || !bytes.Equal(reverse, reverseBefore) || !bytes.Equal(forward, forwardBefore) {
			t.Fatal("public verification mutated fuzz input")
		}
		if canceled {
			if !errors.Is(firstErr, context.Canceled) || !errors.Is(secondErr, context.Canceled) || first.State() != "" || second.State() != "" {
				t.Fatal("caller cancellation violated result-error disjointness")
			}
			return
		}
		if firstErr != nil || secondErr != nil {
			t.Fatal("message-derived fuzz input escaped as Go error")
		}
		if bytes.Contains(raw, []byte("PUBLIC-FUZZ-TOXIC-MARKER")) {
			formatted := fmt.Sprintf("%v %#v %v", first, first, firstErr)
			if strings.Contains(formatted, "PUBLIC-FUZZ-TOXIC-MARKER") {
				t.Fatal("public fuzz result leaked toxic input")
			}
		}
		if !reflect.DeepEqual(snapshotPublicFuzzResult(first), snapshotPublicFuzzResult(second)) {
			t.Fatal("public verification was nondeterministic")
		}
		assertBoundedPublicFuzzResult(t, first)
	})
}

// snapshotPublicFuzzResult copies every public result dimension for deterministic comparison.
func snapshotPublicFuzzResult(result VerifyResult) publicFuzzSnapshot {
	return publicFuzzSnapshot{
		draft: result.Draft(), state: result.State(), scope: result.Scope(),
		historical: result.HistoricalContent(), custody: result.CustodyStructure(),
		reason: result.PrimaryReason(), target: result.Target(),
		checks: result.Checks(), signatures: result.SignatureSets(),
	}
}

// assertBoundedPublicFuzzResult checks closed vocabularies, coverage, and fact caps.
func assertBoundedPublicFuzzResult(t *testing.T, result VerifyResult) {
	t.Helper()
	coverageValid := result.Scope() == VerificationScopeCurrent && result.HistoricalContent() == HistoricalStateNotEvaluated && result.HistoricalSignatures() == HistoricalStateNotEvaluated
	if result.State() == ResultStatePASS {
		coverageValid = result.Scope() == VerificationScopeChain &&
			(result.HistoricalContent() == HistoricalStateComplete || result.HistoricalContent() == HistoricalStatePartial) &&
			result.HistoricalSignatures() == HistoricalStateComplete
	}
	if result.Draft() != DraftIdentifier || !result.State().Known() || !coverageValid ||
		!result.CustodyStructure().Known() || !result.PrimaryReason().Known() ||
		result.CheckCount() > HardMaxCheckFacts || result.SignatureSetCount() > HardMaxSignatureFacts {
		t.Fatal("public fuzz result violated bounded contract")
	}
	for _, fact := range result.Checks() {
		if !fact.Class().Known() || !fact.Reason().Known() {
			t.Fatal("public fuzz result contained unknown check fact")
		}
	}
	for _, fact := range result.SignatureSets() {
		if !fact.Algorithm().Known() || !fact.Status().Known() || !fact.Reason().Known() {
			t.Fatal("public fuzz result contained unknown signature fact")
		}
	}
}
