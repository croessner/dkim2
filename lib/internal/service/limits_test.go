package service

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/verify"
)

type countingFailureProvider struct{ calls int }

// LookupKey records calls and returns typed temporary state.
func (p *countingFailureProvider) LookupKey(context.Context, verify.KeyQuery) (verify.PublicKey, error) {
	p.calls++
	return verify.PublicKey{}, verify.NewProviderFailure(verify.ProviderFailureTemporary)
}

// TestVerifierEnforcesExactAndOverPreProviderLimits verifies parser-owned resource seams.
func TestVerifierEnforcesExactAndOverPreProviderLimits(t *testing.T) {
	const timestamp = uint64(1700000000)
	baseRaw := syntheticCurrentMessage(t, timestamp, 1, 1)
	tests := []struct {
		name       string
		configure  func(*Limits)
		raw        []byte
		recipients [][]byte
		wantCalls  int
	}{
		{name: "raw exact", configure: func(l *Limits) { l.MaxRawMessageBytes = len(baseRaw) }, raw: baseRaw, recipients: [][]byte{[]byte("<rcpt@example.test>")}, wantCalls: 1},
		{name: "raw over", configure: func(l *Limits) { l.MaxRawMessageBytes = len(baseRaw) - 1 }, raw: baseRaw, recipients: [][]byte{[]byte("<rcpt@example.test>")}},
		{name: "recipients exact", configure: func(l *Limits) { l.MaxRecipients = 1 }, raw: baseRaw, recipients: [][]byte{[]byte("<rcpt@example.test>")}, wantCalls: 1},
		{name: "recipients over", configure: func(l *Limits) { l.MaxRecipients = 1 }, raw: baseRaw, recipients: [][]byte{[]byte("<rcpt@example.test>"), []byte("<other@example.test>")}},
		{name: "hash sets exact", configure: func(l *Limits) { l.MaxInstanceHashSets = 1 }, raw: syntheticCurrentMessage(t, timestamp, 1, 1), recipients: [][]byte{[]byte("<rcpt@example.test>")}, wantCalls: 1},
		{name: "hash sets over", configure: func(l *Limits) { l.MaxInstanceHashSets = 1 }, raw: syntheticCurrentMessage(t, timestamp, 2, 1), recipients: [][]byte{[]byte("<rcpt@example.test>")}},
		{name: "signature sets exact", configure: func(l *Limits) { l.MaxSignatureSets = 1 }, raw: syntheticCurrentMessage(t, timestamp, 1, 1), recipients: [][]byte{[]byte("<rcpt@example.test>")}, wantCalls: 1},
		{name: "signature sets over", configure: func(l *Limits) { l.MaxSignatureSets = 1 }, raw: syntheticCurrentMessage(t, timestamp, 1, 2), recipients: [][]byte{[]byte("<rcpt@example.test>")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &countingFailureProvider{}
			config := DefaultConfig()
			config.Clock = func() time.Time { return time.Unix(int64(timestamp), 0) }
			tt.configure(&config.Limits)
			verifier, err := NewVerifier(provider, config)
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}
			result, err := verifier.Verify(context.Background(), NewRequest(tt.raw, []byte("<>"), tt.recipients))
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if provider.calls != tt.wantCalls {
				t.Fatalf("provider calls = %d, want %d; result=%q/%q", provider.calls, tt.wantCalls, result.State(), result.PrimaryReason())
			}
			if tt.wantCalls == 0 && (result.State() != StatePERMERROR || result.PrimaryReason() != ReasonLimitExceeded || result.Custody() != CustodyNotEvaluated) {
				t.Fatalf("over-limit result = %q/%q/%q", result.State(), result.PrimaryReason(), result.Custody())
			}
		})
	}
}

// TestMappingCapsRetainedFactsAtExactAndOverBoundaries verifies bounded allocation.
func TestMappingCapsRetainedFactsAtExactAndOverBoundaries(t *testing.T) {
	target := verify.Target{Sequence: 1, InstanceNumber: 1}
	limits := DefaultLimits()
	limits.MaxCheckFacts = len(requiredPassChecks(target))
	valid := mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusPass, requiredPassChecks(target), []verify.SignatureSetResult{{Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}}), limits)
	if len(valid.Checks()) != limits.MaxCheckFacts || valid.State() != StatePASS {
		t.Fatalf("valid exact-cap result = len %d state %q", len(valid.Checks()), valid.State())
	}

	checks := requiredPassChecks(target)
	checks = slices.DeleteFunc(checks, func(check verify.CheckResult) bool { return check.Kind == verify.CheckKindNextDomain })
	checks = append(checks, checks[0], checks[1])
	limits.MaxCheckFacts = len(checks)
	result := mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusPass, checks, []verify.SignatureSetResult{{Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}}), limits)
	if len(result.Checks()) > limits.MaxCheckFacts || result.State() != StatePERMERROR || result.PrimaryReason() != ReasonInternalContract {
		t.Fatalf("exact-cap result = len %d state/reason %q/%q", len(result.Checks()), result.State(), result.PrimaryReason())
	}

	limits = DefaultLimits()
	limits.MaxSignatureFacts = 2
	overSets := []verify.SignatureSetResult{
		{Index: 0, Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound},
		{Index: 1, Algorithm: verify.AlgorithmEd25519SHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound},
	}
	twoChecks := requiredChecksWithSignatures(target,
		verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusPass, Algorithm: verify.AlgorithmRSASHA256, Target: target},
		verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusPass, Algorithm: verify.AlgorithmEd25519SHA256, Target: target},
	)
	exact := mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusPass, twoChecks, overSets), limits)
	if len(exact.SignatureSets()) != 2 || exact.State() != StatePASS {
		t.Fatalf("exact signature-cap result = len %d state %q", len(exact.SignatureSets()), exact.State())
	}
	limits.MaxSignatureFacts = 1
	over := mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusPass, twoChecks, overSets), limits)
	if len(over.SignatureSets()) > limits.MaxSignatureFacts || over.State() != StatePASS || over.PrimaryReason() != ReasonNone {
		t.Fatalf("over signature-cap result = len %d state/reason %q/%q", len(over.SignatureSets()), over.State(), over.PrimaryReason())
	}
}

// TestMappingPreservesOutcomeAcrossCoherentCheckRetention verifies presentation caps do not rewrite protocol state.
func TestMappingPreservesOutcomeAcrossCoherentCheckRetention(t *testing.T) {
	target := verify.Target{Sequence: 1, InstanceNumber: 1}
	checks := requiredPassChecks(target)
	sets := []verify.SignatureSetResult{{Index: 0, Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}}
	limits := DefaultLimits()
	limits.MaxCheckFacts = len(checks) - 1
	var retained []CheckFact
	for _, ordered := range [][]verify.CheckResult{checks, reverseCheckResults(checks)} {
		result := mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusPass, ordered, sets), limits)
		if result.State() != StatePASS || result.PrimaryReason() != ReasonNone || len(result.Checks()) > limits.MaxCheckFacts {
			t.Fatalf("coherent capped result = %q/%q len=%d", result.State(), result.PrimaryReason(), len(result.Checks()))
		}
		if retained == nil {
			retained = result.Checks()
		} else if !slices.Equal(retained, result.Checks()) {
			t.Fatal("coherent capped check details depended on input order")
		}
	}
}

// TestMappingCapsDoNotSuppressSignatureCorrelationDefects verifies retention overflow cannot hide mismatched facts.
func TestMappingCapsDoNotSuppressSignatureCorrelationDefects(t *testing.T) {
	target := verify.Target{Sequence: 1, InstanceNumber: 1}
	passSet := verify.SignatureSetResult{Index: 0, Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}
	extraSet := verify.SignatureSetResult{Index: 1, Algorithm: verify.AlgorithmEd25519SHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}
	extraCheck := verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusFail, Code: verify.ErrorCodeSignatureMismatch, Algorithm: verify.AlgorithmEd25519SHA256, Target: target}

	checks := append(requiredPassChecks(target), extraCheck)
	checkLimits := DefaultLimits()
	checkLimits.MaxCheckFacts = len(checks) - 1
	for _, ordered := range [][]verify.CheckResult{checks, reverseCheckResults(checks)} {
		result := mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusMixed, ordered, []verify.SignatureSetResult{passSet}), checkLimits)
		if result.State() != StatePERMERROR || result.PrimaryReason() != ReasonInternalContract {
			t.Fatal("over-cap extra signature check was not rejected as contract corruption")
		}
	}

	setLimits := DefaultLimits()
	setLimits.MaxSignatureFacts = 1
	sets := []verify.SignatureSetResult{passSet, extraSet}
	for _, ordered := range [][]verify.SignatureSetResult{sets, reverseSignatureSets(sets)} {
		result := mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusPass, requiredPassChecks(target), ordered), setLimits)
		if result.State() != StatePERMERROR || result.PrimaryReason() != ReasonInternalContract {
			t.Fatal("over-cap extra signature set was not rejected as contract corruption")
		}
	}
}

// TestMappingSignatureRetentionIsDeterministicAcrossPermutations verifies coherent top-N detail selection.
func TestMappingSignatureRetentionIsDeterministicAcrossPermutations(t *testing.T) {
	target := verify.Target{Sequence: 1, InstanceNumber: 1}
	sets := []verify.SignatureSetResult{
		{Index: 0, Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound},
		{Index: 1, Algorithm: verify.AlgorithmEd25519SHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound},
	}
	checks := requiredChecksWithSignatures(target,
		verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusPass, Algorithm: verify.AlgorithmRSASHA256, Target: target},
		verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusPass, Algorithm: verify.AlgorithmEd25519SHA256, Target: target},
	)
	limits := DefaultLimits()
	limits.MaxSignatureFacts = 1
	var retained []SignatureSetFact
	for _, orderedChecks := range [][]verify.CheckResult{checks, reverseCheckResults(checks)} {
		for _, orderedSets := range [][]verify.SignatureSetResult{sets, reverseSignatureSets(sets)} {
			result := mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusPass, orderedChecks, orderedSets), limits)
			if result.State() != StatePASS || result.PrimaryReason() != ReasonNone || len(result.SignatureSets()) != 1 {
				t.Fatal("coherent signature retention rewrote protocol state")
			}
			if retained == nil {
				retained = result.SignatureSets()
			} else if !slices.Equal(retained, result.SignatureSets()) {
				t.Fatal("retained signature detail depended on check or set order")
			}
		}
	}
}

// TestMappingDoesNotMaskContractDefectsWithInputCaps verifies permanent reason precedence.
func TestMappingDoesNotMaskContractDefectsWithInputCaps(t *testing.T) {
	target := verify.Target{Sequence: 1, InstanceNumber: 1}
	limits := DefaultLimits()
	limits.MaxCheckFacts = 1
	checks := []verify.CheckResult{
		{Kind: verify.CheckKind("future"), Status: verify.CheckStatusPass, Target: target},
		{Kind: verify.CheckKindBodyHash, Status: verify.CheckStatusPass, HashStatus: verify.HashStatusPass, Target: target},
	}
	for _, permutation := range [][]verify.CheckResult{checks, {checks[1], checks[0]}} {
		result := mapVerificationResult(verify.NewResult(target, verify.TargetStatusPass, permutation, nil), limits)
		if result.State() != StatePERMERROR || result.PrimaryReason() != ReasonInternalContract || len(result.Checks()) > limits.MaxCheckFacts {
			t.Fatalf("combined check cap/contract result = %q/%q len=%d", result.State(), result.PrimaryReason(), len(result.Checks()))
		}
	}

	limits = DefaultLimits()
	limits.MaxSignatureFacts = 1
	valid := verify.SignatureSetResult{Index: 0, Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}
	invalid := verify.SignatureSetResult{Index: 1, Algorithm: verify.AlgorithmUnknown, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}
	for _, permutation := range [][]verify.SignatureSetResult{{valid, invalid}, {invalid, valid}} {
		result := mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusPass, requiredPassChecks(target), permutation), limits)
		if result.State() != StatePERMERROR || result.PrimaryReason() != ReasonInternalContract || len(result.SignatureSets()) > limits.MaxSignatureFacts {
			t.Fatalf("combined set cap/contract result = %q/%q len=%d", result.State(), result.PrimaryReason(), len(result.SignatureSets()))
		}
	}
}

// TestMappingChecksNonRetainedSetIndicesWithFixedBounds verifies cap-independent index coherence.
func TestMappingChecksNonRetainedSetIndicesWithFixedBounds(t *testing.T) {
	target := verify.Target{Sequence: 1, InstanceNumber: 1}
	limits := DefaultLimits()
	limits.MaxSignatureFacts = 1
	checks := requiredChecksWithSignatures(target,
		verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusPass, Algorithm: verify.AlgorithmRSASHA256, Target: target},
		verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusPass, Algorithm: verify.AlgorithmEd25519SHA256, Target: target},
	)
	tests := [][]verify.SignatureSetResult{
		{{Index: 0, Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}, {Index: 2, Algorithm: verify.AlgorithmEd25519SHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}},
		{{Index: 2, Algorithm: verify.AlgorithmEd25519SHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}, {Index: 0, Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}},
		{{Index: 0, Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}, {Index: 0, Algorithm: verify.AlgorithmEd25519SHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}},
	}
	for _, sets := range tests {
		result := mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusPass, checks, sets), limits)
		if result.State() != StatePERMERROR || result.PrimaryReason() != ReasonInternalContract || len(result.SignatureSets()) > limits.MaxSignatureFacts {
			t.Fatalf("sets %#v mapped to %q/%q len=%d", sets, result.State(), result.PrimaryReason(), len(result.SignatureSets()))
		}
	}
}
