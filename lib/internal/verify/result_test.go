package verify

import (
	"strings"
	"testing"
)

// TestStatusVocabularyIsStable verifies status constants are recognized.
func TestStatusVocabularyIsStable(t *testing.T) {
	tests := []struct {
		name string
		ok   bool
	}{
		{name: "check", ok: CheckStatusPass.Known() && CheckStatusFail.Known() && !CheckStatus("raw secret").Known()},
		{name: "signature set", ok: SignatureSetStatusMissingKey.Known() && SignatureSetStatusInvalidKey.Known() && SignatureSetStatusWrongKeyType.Known() && SignatureSetStatusKeyPolicyRejected.Known() && SignatureSetStatusProviderError.Known() && !SignatureSetStatus("private-key").Known()},
		{name: "key", ok: KeyStatusFound.Known() && KeyStatusDisabledAlgorithm.Known() && KeyStatusAmbiguous.Known() && KeyStatusWrongType.Known() && KeyStatusPolicyRejected.Known() && KeyStatusProviderError.Known() && !KeyStatus("selector.example").Known()},
		{name: "timestamp", ok: TimestampStatusNoMaxAge.Known() && TimestampStatusFuture.Known() && TimestampStatusNotApplicable.Known() && !TimestampStatus("2026-raw").Known()},
		{name: "envelope", ok: EnvelopeStatusMismatch.Known() && EnvelopeStatusRecipientValueMismatch.Known() && EnvelopeStatusNotApplicable.Known() && !EnvelopeStatus("<user@example.test>").Known()},
		{name: "domain alignment", ok: DomainAlignmentStatusPass.Known() && DomainAlignmentStatusNotApplicable.Known() && !DomainAlignmentStatus("<user@example.test>").Known()},
		{name: "hash", ok: HashStatusMissingSHA256.Known() && HashStatusMismatch.Known() && !HashStatus("raw-hash").Known()},
		{name: "target", ok: TargetStatusMixed.Known() && TargetStatusUnsupported.Known() && !TargetStatus("full-result").Known()},
	}
	for _, tt := range tests {
		if !tt.ok {
			t.Fatalf("%s status vocabulary is not stable", tt.name)
		}
	}
}

// TestDNSKeyStatusVocabularyIsStable verifies DNS provider states are closed and known.
func TestDNSKeyStatusVocabularyIsStable(t *testing.T) {
	for _, status := range []SignatureSetStatus{SignatureSetStatusRevokedKey, SignatureSetStatusUnsupportedKeyType, SignatureSetStatusKeyAlgorithmMismatch} {
		if !status.Known() {
			t.Fatalf("signature status %q unknown", status)
		}
	}
	for _, status := range []KeyStatus{KeyStatusRevoked, KeyStatusUnsupportedKeyType, KeyStatusAlgorithmMismatch} {
		if !status.Known() {
			t.Fatalf("key status %q unknown", status)
		}
	}
}

// TestResultAccessorsAreImmutable verifies result slices are copied.
func TestResultAccessorsAreImmutable(t *testing.T) {
	checks := []CheckResult{{
		Kind:      CheckKindSignature,
		Status:    CheckStatusPass,
		Algorithm: AlgorithmRSASHA256,
		Target: Target{
			Sequence:       2,
			InstanceNumber: 1,
		},
	}}
	signatureSets := []SignatureSetResult{{
		Index:     0,
		Algorithm: AlgorithmRSASHA256,
		Status:    SignatureSetStatusPass,
		KeyStatus: KeyStatusFound,
	}}

	result := NewResult(Target{Sequence: 2, InstanceNumber: 1}, TargetStatusPass, checks, signatureSets)
	checks[0].Status = CheckStatusFail
	signatureSets[0].Status = SignatureSetStatusFail

	gotChecks := result.Checks()
	gotSets := result.SignatureSets()
	gotChecks[0].Status = CheckStatusUnsupported
	gotSets[0].Status = SignatureSetStatusMissingKey

	if result.Draft() != DraftBaseline {
		t.Fatalf("Draft() = %q, want baseline", result.Draft())
	}
	if result.Target().Sequence != 2 || result.Target().InstanceNumber != 1 {
		t.Fatalf("Target() = %#v, want sequence 2 instance 1", result.Target())
	}
	if result.Status() != TargetStatusPass {
		t.Fatalf("Status() = %q, want pass", result.Status())
	}
	if result.CustodyStatus().Known() {
		t.Fatalf("CustodyStatus() = %q, base constructor must not claim evaluated custody", result.CustodyStatus())
	}
	if result.Checks()[0].Status != CheckStatusPass {
		t.Fatalf("Checks()[0].Status = %q, want pass", result.Checks()[0].Status)
	}
	if result.SignatureSets()[0].Status != SignatureSetStatusPass {
		t.Fatalf("SignatureSets()[0].Status = %q, want pass", result.SignatureSets()[0].Status)
	}
}

// TestResultWithCustodyRequiresAnExplicitKnownState verifies evaluated custody is opt-in.
func TestResultWithCustodyRequiresAnExplicitKnownState(t *testing.T) {
	target := Target{Sequence: 1, InstanceNumber: 1}
	result := NewResultWithCustody(target, TargetStatusPass, nil, nil, CustodyStatusNotPresent)
	if result.CustodyStatus() != CustodyStatusNotPresent {
		t.Fatalf("CustodyStatus() = %q, want not_present", result.CustodyStatus())
	}
	unknown := NewResultWithCustody(target, TargetStatusPass, nil, nil, CustodyStatus("future"))
	if unknown.CustodyStatus().Known() {
		t.Fatalf("unknown custody became known: %q", unknown.CustodyStatus())
	}
}

// TestResultBoundsUnknownTargetStatus verifies unknown overall state remains detectable and secret-safe.
func TestResultBoundsUnknownTargetStatus(t *testing.T) {
	result := NewResult(Target{}, TargetStatus("raw body secret"), nil, nil)
	if result.Status() != TargetStatusUnknown {
		t.Fatalf("Status() = %q, want unknown", result.Status())
	}
}

// TestResultSanitizesUnknownAlgorithms verifies result facts never retain attacker-controlled algorithm tokens.
func TestResultSanitizesUnknownAlgorithms(t *testing.T) {
	toxic := Algorithm("future-" + strings.Repeat("toxic-marker-", 128))
	result := NewResult(Target{}, TargetStatusUnsupported, []CheckResult{{
		Kind:      CheckKindSignature,
		Status:    CheckStatusUnsupported,
		Algorithm: toxic,
	}}, []SignatureSetResult{{
		Algorithm: toxic,
		Status:    SignatureSetStatusUnsupportedAlgorithm,
		KeyStatus: KeyStatusUnsupportedAlgorithm,
	}})

	if got := result.Checks()[0].Algorithm; got != AlgorithmUnknown {
		t.Fatalf("Checks()[0].Algorithm = %q, want %q", got, AlgorithmUnknown)
	}
	if got := result.SignatureSets()[0].Algorithm; got != AlgorithmUnknown {
		t.Fatalf("SignatureSets()[0].Algorithm = %q, want %q", got, AlgorithmUnknown)
	}
}
