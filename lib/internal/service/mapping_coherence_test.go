package service

import (
	"testing"

	"github.com/croessner/dkim2/internal/verify"
)

// TestSignatureKeyStatusCoherenceMatrix verifies every known legal pair and adjacent illegal pairs.
func TestSignatureKeyStatusCoherenceMatrix(t *testing.T) {
	legal := []struct {
		status       verify.SignatureSetStatus
		key          verify.KeyStatus
		wantStatus   SignatureStatus
		wantReason   Reason
		wantSeverity outcomeSeverity
	}{
		{verify.SignatureSetStatusNotChecked, verify.KeyStatusNotChecked, SignaturePERMERROR, ReasonUnsupportedAlgorithm, severityPermanent},
		{verify.SignatureSetStatusPass, verify.KeyStatusFound, SignaturePASS, ReasonNone, severityPass},
		{verify.SignatureSetStatusFail, verify.KeyStatusFound, SignatureFAIL, ReasonSignatureMismatch, severityFailure},
		{verify.SignatureSetStatusUnsupportedAlgorithm, verify.KeyStatusUnsupportedAlgorithm, SignatureIgnored, ReasonUnsupportedAlgorithm, severityPass},
		{verify.SignatureSetStatusDisabledAlgorithm, verify.KeyStatusDisabledAlgorithm, SignaturePERMERROR, ReasonUnsupportedAlgorithm, severityPermanent},
		{verify.SignatureSetStatusMissingKey, verify.KeyStatusMissing, SignaturePERMERROR, ReasonMissingKey, severityPermanent},
		{verify.SignatureSetStatusInvalidKey, verify.KeyStatusInvalid, SignaturePERMERROR, ReasonInvalidKey, severityPermanent},
		{verify.SignatureSetStatusAmbiguousKey, verify.KeyStatusAmbiguous, SignaturePERMERROR, ReasonAmbiguousKey, severityPermanent},
		{verify.SignatureSetStatusRevokedKey, verify.KeyStatusRevoked, SignaturePERMERROR, ReasonRevokedKey, severityPermanent},
		{verify.SignatureSetStatusUnsupportedKeyType, verify.KeyStatusUnsupportedKeyType, SignaturePERMERROR, ReasonUnsupportedKeyType, severityPermanent},
		{verify.SignatureSetStatusKeyAlgorithmMismatch, verify.KeyStatusAlgorithmMismatch, SignaturePERMERROR, ReasonKeyAlgorithmMismatch, severityPermanent},
		{verify.SignatureSetStatusWrongKeyType, verify.KeyStatusWrongType, SignaturePERMERROR, ReasonInvalidKey, severityPermanent},
		{verify.SignatureSetStatusKeyPolicyRejected, verify.KeyStatusPolicyRejected, SignaturePERMERROR, ReasonInvalidKey, severityPermanent},
		{verify.SignatureSetStatusProviderError, verify.KeyStatusProviderError, SignaturePERMERROR, ReasonProviderContract, severityPermanent},
		{verify.SignatureSetStatusProviderTemporary, verify.KeyStatusProviderTemporary, SignatureTEMPERROR, ReasonProviderTemporary, severityTemporary},
		{verify.SignatureSetStatusProviderPermanent, verify.KeyStatusProviderPermanent, SignaturePERMERROR, ReasonProviderPermanent, severityPermanent},
		{verify.SignatureSetStatusProviderContract, verify.KeyStatusProviderContract, SignaturePERMERROR, ReasonProviderContract, severityPermanent},
	}
	for _, pair := range legal {
		if !signatureKeyPairValid(pair.status, pair.key) {
			t.Fatalf("legal pair %q/%q rejected", pair.status, pair.key)
		}
		if signatureKeyPairValid(pair.status, verify.KeyStatus("future")) {
			t.Fatalf("unknown key accepted for %q", pair.status)
		}
		if pair.key != verify.KeyStatusFound && signatureKeyPairValid(pair.status, verify.KeyStatusFound) {
			t.Fatalf("found key incorrectly accepted for %q", pair.status)
		}
		algorithm := verify.AlgorithmRSASHA256
		if pair.status == verify.SignatureSetStatusUnsupportedAlgorithm {
			algorithm = verify.AlgorithmUnknown
		}
		accumulator := testAccumulator()
		accumulator.mapSignatureSet(verify.SignatureSetResult{Algorithm: algorithm, Status: pair.status, KeyStatus: pair.key})
		if len(accumulator.signatures) != 1 || accumulator.signatures[0].Status != pair.wantStatus || accumulator.signatures[0].Reason != pair.wantReason || accumulator.severity != pair.wantSeverity {
			t.Fatalf("known pair %q/%q mapped to %#v severity=%d", pair.status, pair.key, accumulator.signatures, accumulator.severity)
		}
	}
	if signatureKeyPairValid("", "") || signatureKeyPairValid(verify.SignatureSetStatus("future"), verify.KeyStatusFound) {
		t.Fatal("zero or unknown signature/key pair accepted")
	}
}

// TestSignatureKeyPolicyMetadataCoherence verifies exact propagation and illegal status pairs.
func TestSignatureKeyPolicyMetadataCoherence(t *testing.T) {
	metadata := verify.KeyPolicyMetadata{TestingDeclared: true, StrictIdentityDeclared: true}
	allowed := []struct {
		status verify.SignatureSetStatus
		key    verify.KeyStatus
	}{
		{verify.SignatureSetStatusPass, verify.KeyStatusFound},
		{verify.SignatureSetStatusFail, verify.KeyStatusFound},
		{verify.SignatureSetStatusInvalidKey, verify.KeyStatusInvalid},
		{verify.SignatureSetStatusRevokedKey, verify.KeyStatusRevoked},
		{verify.SignatureSetStatusUnsupportedKeyType, verify.KeyStatusUnsupportedKeyType},
		{verify.SignatureSetStatusKeyAlgorithmMismatch, verify.KeyStatusAlgorithmMismatch},
		{verify.SignatureSetStatusWrongKeyType, verify.KeyStatusWrongType},
		{verify.SignatureSetStatusKeyPolicyRejected, verify.KeyStatusPolicyRejected},
	}
	for _, pair := range allowed {
		accumulator := testAccumulator()
		accumulator.mapSignatureSet(verify.SignatureSetResult{Algorithm: verify.AlgorithmRSASHA256, Status: pair.status, KeyStatus: pair.key, KeyPolicy: metadata})
		if len(accumulator.signatures) != 1 || accumulator.signatures[0].KeyPolicy != (KeyPolicyMetadata{TestingDeclared: true, StrictIdentityDeclared: true}) {
			t.Fatalf("metadata for %q/%q = %#v", pair.status, pair.key, accumulator.signatures)
		}
	}
	for _, status := range []verify.SignatureSetStatus{
		verify.SignatureSetStatusNotChecked, verify.SignatureSetStatusDisabledAlgorithm,
		verify.SignatureSetStatusMissingKey, verify.SignatureSetStatusAmbiguousKey,
		verify.SignatureSetStatusProviderError,
		verify.SignatureSetStatusProviderTemporary, verify.SignatureSetStatusProviderPermanent,
		verify.SignatureSetStatusProviderContract, verify.SignatureSetStatusUnsupportedAlgorithm,
	} {
		if signatureKeyPolicyCoherent(status, metadata) {
			t.Fatalf("metadata accepted for %q", status)
		}
	}
	bad := verify.SignatureSetResult{Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound, KeyPolicy: verify.KeyPolicyMetadata{StrictIdentityApplicable: true}}
	result := mapVerificationResult(newVerifyResultWithDefaultCustody(verify.Target{Sequence: 1, InstanceNumber: 1}, verify.TargetStatusPass, requiredPassChecks(verify.Target{Sequence: 1, InstanceNumber: 1}), []verify.SignatureSetResult{bad}), DefaultLimits())
	if result.State() != StatePERMERROR || result.PrimaryReason() != ReasonInternalContract {
		t.Fatalf("invalid applicable metadata mapped to %q/%q", result.State(), result.PrimaryReason())
	}
}

// TestMappingRejectsDuplicateAndInconsistentFacts verifies synthetic M4 corruption fails closed.
func TestMappingRejectsDuplicateAndInconsistentFacts(t *testing.T) {
	target := verify.Target{Sequence: 1, InstanceNumber: 1}
	passSet := verify.SignatureSetResult{Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}
	tests := []struct {
		name   string
		checks []verify.CheckResult
		sets   []verify.SignatureSetResult
	}{
		{name: "duplicate required check", checks: append(requiredPassChecks(target), requiredPassChecks(target)[0]), sets: []verify.SignatureSetResult{passSet}},
		{name: "duplicate set index", checks: requiredChecksWithSignatures(target,
			verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusPass, Algorithm: verify.AlgorithmRSASHA256},
			verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusPass, Algorithm: verify.AlgorithmEd25519SHA256}), sets: []verify.SignatureSetResult{passSet, {Index: 0, Algorithm: verify.AlgorithmEd25519SHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}}},
		{name: "unknown success algorithm", checks: requiredChecksWithSignatures(target, verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusPass, Algorithm: verify.Algorithm("raw-secret")}), sets: []verify.SignatureSetResult{passSet}},
		{name: "provider detail on hash", checks: append(requiredPassChecks(target), verify.CheckResult{Kind: verify.CheckKindBodyHash, Status: verify.CheckStatusPass, HashStatus: verify.HashStatusPass, ProviderFailureClass: verify.ProviderFailureTemporary}), sets: []verify.SignatureSetResult{passSet}},
		{name: "missing with found key", checks: requiredPassChecks(target), sets: []verify.SignatureSetResult{{Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusMissingKey, KeyStatus: verify.KeyStatusFound}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusPass, tt.checks, tt.sets), DefaultLimits())
			if result.State() != StatePERMERROR || result.PrimaryReason() != ReasonInternalContract {
				t.Fatalf("result = %q/%q", result.State(), result.PrimaryReason())
			}
		})
	}
}

// TestMappingRejectsZeroAndForeignTargets verifies every fact belongs to one nonzero aggregate target.
func TestMappingRejectsZeroAndForeignTargets(t *testing.T) {
	validTarget := verify.Target{Sequence: 1, InstanceNumber: 1}
	for _, target := range []verify.Target{{}, {Sequence: 1}, {InstanceNumber: 1}} {
		result := mapVerificationResult(verify.NewResult(target, verify.TargetStatusPass, requiredPassChecks(target), []verify.SignatureSetResult{{Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}}), DefaultLimits())
		if result.State() != StatePERMERROR || result.PrimaryReason() != ReasonInternalContract {
			t.Fatalf("zero target %#v mapped to %q/%q", target, result.State(), result.PrimaryReason())
		}
	}
	checks := requiredPassChecks(validTarget)
	checks[0].Target = verify.Target{Sequence: 2, InstanceNumber: 1}
	result := mapVerificationResult(verify.NewResult(validTarget, verify.TargetStatusPass, checks, []verify.SignatureSetResult{{Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}}), DefaultLimits())
	if result.State() != StatePERMERROR || result.PrimaryReason() != ReasonInternalContract {
		t.Fatalf("foreign check target mapped to %q/%q", result.State(), result.PrimaryReason())
	}
}

// TestMappingRequiresContiguousSignatureSetIndices verifies zero-origin ordered set identity.
func TestMappingRequiresContiguousSignatureSetIndices(t *testing.T) {
	target := verify.Target{Sequence: 1, InstanceNumber: 1}
	checks := requiredChecksWithSignatures(target,
		verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusPass, Algorithm: verify.AlgorithmRSASHA256, Target: target},
		verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusPass, Algorithm: verify.AlgorithmEd25519SHA256, Target: target},
	)
	for _, indices := range [][2]int{{1, 2}, {0, 2}} {
		sets := []verify.SignatureSetResult{
			{Index: indices[0], Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound},
			{Index: indices[1], Algorithm: verify.AlgorithmEd25519SHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound},
		}
		result := mapVerificationResult(verify.NewResult(target, verify.TargetStatusPass, checks, sets), DefaultLimits())
		if result.State() != StatePERMERROR || result.PrimaryReason() != ReasonInternalContract {
			t.Fatalf("indices %v mapped to %q/%q", indices, result.State(), result.PrimaryReason())
		}
	}
}

// TestMappingValidatesCustodyAndCurrentCheckCoherence verifies legal and illegal coverage combinations.
func TestMappingValidatesCustodyAndCurrentCheckCoherence(t *testing.T) {
	target := verify.Target{Sequence: 1, InstanceNumber: 1}
	passSet := []verify.SignatureSetResult{{Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}}
	tests := []struct {
		name    string
		custody verify.CustodyStatus
		mutate  func([]verify.CheckResult)
		want    State
	}{
		{name: "no nd legal", custody: verify.CustodyStatusNotPresent, want: StatePASS},
		{name: "intermediate links legal", custody: verify.CustodyStatusNDLinksEvaluated, want: StatePASS},
		{name: "envelope not applicable without nd invalid", custody: verify.CustodyStatusNotPresent, mutate: func(checks []verify.CheckResult) {
			for index := range checks {
				if checks[index].Kind == verify.CheckKindEnvelope {
					checks[index].Status, checks[index].EnvelopeStatus = verify.CheckStatusNotApplicable, verify.EnvelopeStatusNotApplicable
				}
			}
		}, want: StatePERMERROR},
		{name: "next-domain pass without nd invalid", custody: verify.CustodyStatusNotPresent, mutate: func(checks []verify.CheckResult) {
			for index := range checks {
				if checks[index].Kind == verify.CheckKindNextDomain {
					checks[index].Status, checks[index].NextDomainStatus = verify.CheckStatusPass, verify.NextDomainStatusPass
				}
			}
		}, want: StatePERMERROR},
		{name: "current next-domain pass with intermediate coverage invalid", custody: verify.CustodyStatusNDLinksEvaluated, mutate: func(checks []verify.CheckResult) {
			for index := range checks {
				if checks[index].Kind == verify.CheckKindNextDomain {
					checks[index].Status, checks[index].NextDomainStatus = verify.CheckStatusPass, verify.NextDomainStatusPass
				}
			}
		}, want: StatePERMERROR},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checks := requiredPassChecks(target)
			if tt.mutate != nil {
				tt.mutate(checks)
			}
			result := mapVerificationResult(verify.NewResultWithCustody(target, verify.TargetStatusPass, checks, passSet, tt.custody), DefaultLimits())
			if result.State() != tt.want {
				t.Fatalf("result = %q/%q", result.State(), result.PrimaryReason())
			}
		})
	}
}

// TestKnownVerificationErrorCodesAreExhaustivelyRecognized verifies zero success and every current code.
func TestKnownVerificationErrorCodesAreExhaustivelyRecognized(t *testing.T) {
	codes := []verify.ErrorCode{
		"", verify.ErrorCodeInvalidOptions, verify.ErrorCodeInvalidRequest, verify.ErrorCodeLimitExceeded,
		verify.ErrorCodeUnsupportedAlgorithm, verify.ErrorCodeUnsupportedTarget, verify.ErrorCodeDisabledAlgorithm,
		verify.ErrorCodeMissingKey, verify.ErrorCodeAmbiguousKey, verify.ErrorCodeInvalidKey, verify.ErrorCodeRevokedKey,
		verify.ErrorCodeUnsupportedKeyType, verify.ErrorCodeKeyAlgorithmMismatch, verify.ErrorCodeWrongKeyType,
		verify.ErrorCodeKeyPolicyRejected, verify.ErrorCodeProviderError, verify.ErrorCodeMalformedState,
		verify.ErrorCodeSequenceInvalid, verify.ErrorCodeMissingTarget, verify.ErrorCodeDuplicateTarget,
		verify.ErrorCodeHashMismatch, verify.ErrorCodeSignatureMismatch, verify.ErrorCodeTimestampInvalid,
		verify.ErrorCodeEnvelopeMismatch, verify.ErrorCodeDomainAlignmentMismatch, verify.ErrorCodeNextDomainMismatch,
		verify.ErrorCodeMissingNextSignature, verify.ErrorCodeCustodyMismatch, verify.ErrorCodeOutOfBandRequired,
		verify.ErrorCodeInternalMisuse,
	}
	for _, code := range codes {
		if !knownErrorCode(code) {
			t.Fatalf("knownErrorCode(%q) = false", code)
		}
		reason, class, state := mapVerificationErrorCode(code)
		if !reason.Known() || !class.Known() || !state.Known() {
			t.Fatalf("error code %q produced unknown mapping %q/%q/%q", code, reason, class, state)
		}
	}
	if knownErrorCode(verify.ErrorCode("raw-secret")) {
		t.Fatal("unknown error code accepted")
	}
}

// TestAllM4DetailVocabulariesRejectZeroAndUnknown verifies mapping inputs remain closed.
func TestAllM4DetailVocabulariesRejectZeroAndUnknown(t *testing.T) {
	if verify.CheckStatus("").Known() || verify.CheckStatus("future").Known() ||
		verify.SignatureSetStatus("").Known() || verify.SignatureSetStatus("future").Known() ||
		verify.KeyStatus("").Known() || verify.KeyStatus("future").Known() ||
		verify.HashStatus("").Known() || verify.HashStatus("future").Known() ||
		verify.TimestampStatus("").Known() || verify.TimestampStatus("future-contract").Known() ||
		verify.EnvelopeStatus("").Known() || verify.EnvelopeStatus("future").Known() ||
		verify.DomainAlignmentStatus("").Known() || verify.DomainAlignmentStatus("future").Known() ||
		verify.NextDomainStatus("").Known() || verify.NextDomainStatus("future").Known() {
		t.Fatal("zero or unknown M4 detail token reported known")
	}
}

// TestEveryKnownTargetStatusIsMappedWithTypedConsistency verifies target-state exhaustiveness.
func TestEveryKnownTargetStatusIsMappedWithTypedConsistency(t *testing.T) {
	tests := []struct {
		status   verify.TargetStatus
		severity outcomeSeverity
		want     outcomeSeverity
	}{
		{verify.TargetStatusPass, severityPass, severityPass},
		{verify.TargetStatusFail, severityFailure, severityFailure},
		{verify.TargetStatusMixed, severityFailure, severityFailure},
		{verify.TargetStatusUnsupported, severityPermanent, severityPermanent},
		{verify.TargetStatusIndeterminate, severityTemporary, severityTemporary},
		{verify.TargetStatusNotEvaluated, severityPass, severityPermanent},
		{verify.TargetStatusUnknown, severityPass, severityPermanent},
	}
	for _, tt := range tests {
		accumulator := mappingAccumulator{severity: tt.severity, reason: ReasonNone, supportedPass: 1}
		accumulator.enforceTargetStatus(tt.status)
		if accumulator.severity != tt.want {
			t.Fatalf("target %q mapped severity %d, want %d", tt.status, accumulator.severity, tt.want)
		}
	}
	accumulator := mappingAccumulator{}
	accumulator.enforceTargetStatus(verify.TargetStatus("future"))
	if accumulator.severity != severityPermanent {
		t.Fatal("unknown target status did not fail closed")
	}
}

// TestEveryKnownHashStatusIsMapped verifies hash detail state and reason mapping.
func TestEveryKnownHashStatusIsMapped(t *testing.T) {
	tests := []verify.CheckResult{
		{Kind: verify.CheckKindBodyHash, Status: verify.CheckStatusNotEvaluated, HashStatus: verify.HashStatusNotChecked},
		{Kind: verify.CheckKindBodyHash, Status: verify.CheckStatusPass, HashStatus: verify.HashStatusPass},
		{Kind: verify.CheckKindBodyHash, Status: verify.CheckStatusFail, Code: verify.ErrorCodeHashMismatch, HashStatus: verify.HashStatusMismatch},
		{Kind: verify.CheckKindBodyHash, Status: verify.CheckStatusFail, Code: verify.ErrorCodeMissingTarget, HashStatus: verify.HashStatusMissingSHA256},
		{Kind: verify.CheckKindBodyHash, Status: verify.CheckStatusUnsupported, Code: verify.ErrorCodeUnsupportedAlgorithm, HashStatus: verify.HashStatusUnsupported},
		{Kind: verify.CheckKindBodyHash, Status: verify.CheckStatusFail, Code: verify.ErrorCodeMalformedState, HashStatus: verify.HashStatusInvalid},
	}
	for _, check := range tests {
		accumulator := testAccumulator()
		accumulator.mapCheck(check)
		if len(accumulator.checks) == 0 {
			t.Fatalf("hash status %q produced no bounded fact", check.HashStatus)
		}
	}
}

// TestEveryKnownTimestampAndNextDomainStatusIsMapped verifies detail exhaustiveness.
func TestEveryKnownTimestampAndNextDomainStatusIsMapped(t *testing.T) {
	checks := []verify.CheckResult{
		{Kind: verify.CheckKindTimestamp, Status: verify.CheckStatusNotEvaluated, TimestampStatus: verify.TimestampStatusNotChecked},
		{Kind: verify.CheckKindTimestamp, Status: verify.CheckStatusPass, TimestampStatus: verify.TimestampStatusPass},
		{Kind: verify.CheckKindTimestamp, Status: verify.CheckStatusFail, Code: verify.ErrorCodeTimestampInvalid, TimestampStatus: verify.TimestampStatusFuture},
		{Kind: verify.CheckKindTimestamp, Status: verify.CheckStatusFail, Code: verify.ErrorCodeTimestampInvalid, TimestampStatus: verify.TimestampStatusExpired},
		{Kind: verify.CheckKindTimestamp, Status: verify.CheckStatusPass, TimestampStatus: verify.TimestampStatusNoMaxAge},
		{Kind: verify.CheckKindTimestamp, Status: verify.CheckStatusNotApplicable, TimestampStatus: verify.TimestampStatusNotApplicable},
		{Kind: verify.CheckKindTimestamp, Status: verify.CheckStatusFail, Code: verify.ErrorCodeTimestampInvalid, TimestampStatus: verify.TimestampStatusInvalid},
	}
	for _, status := range []verify.NextDomainStatus{verify.NextDomainStatusNotChecked, verify.NextDomainStatusPass, verify.NextDomainStatusMismatch, verify.NextDomainStatusMissingNext, verify.NextDomainStatusOutOfBandRequired, verify.NextDomainStatusNotApplicable} {
		check := verify.CheckResult{Kind: verify.CheckKindNextDomain, Status: verify.CheckStatusFail, Code: verify.ErrorCodeNextDomainMismatch, NextDomainStatus: status}
		switch status {
		case verify.NextDomainStatusPass:
			check.Status, check.Code = verify.CheckStatusPass, ""
		case verify.NextDomainStatusMissingNext:
			check.Code = verify.ErrorCodeMissingNextSignature
		case verify.NextDomainStatusOutOfBandRequired:
			check.Status, check.Code = verify.CheckStatusUnsupported, verify.ErrorCodeOutOfBandRequired
		case verify.NextDomainStatusNotApplicable:
			check.Status, check.Code = verify.CheckStatusNotApplicable, ""
		}
		checks = append(checks, check)
	}
	for _, check := range checks {
		accumulator := testAccumulator()
		accumulator.mapCheck(check)
		if len(accumulator.checks) == 0 {
			t.Fatalf("detail check %#v produced no bounded fact", check)
		}
	}
}

// TestEnvelopeStatusMatrixIsClosed verifies only exact envelope status triples are accepted.
func TestEnvelopeStatusMatrixIsClosed(t *testing.T) {
	tests := []struct {
		name  string
		check verify.CheckResult
		want  CheckFact
	}{
		{name: "passing envelope", check: verify.CheckResult{Status: verify.CheckStatusPass, EnvelopeStatus: verify.EnvelopeStatusPass}, want: CheckFact{Class: CheckEnvelope, Reason: ReasonNone}},
		{name: "not applicable", check: verify.CheckResult{Status: verify.CheckStatusNotApplicable, EnvelopeStatus: verify.EnvelopeStatusNotApplicable}, want: CheckFact{Class: CheckEnvelope, Reason: ReasonNone}},
		{name: "missing", check: verify.CheckResult{Status: verify.CheckStatusFail, Code: verify.ErrorCodeEnvelopeMismatch, EnvelopeStatus: verify.EnvelopeStatusMissing}, want: CheckFact{Class: CheckEnvelope, Reason: ReasonEnvelopeMismatch}},
		{name: "mismatch", check: verify.CheckResult{Status: verify.CheckStatusFail, Code: verify.ErrorCodeEnvelopeMismatch, EnvelopeStatus: verify.EnvelopeStatusMismatch}, want: CheckFact{Class: CheckEnvelope, Reason: ReasonEnvelopeMismatch}},
		{name: "invalid", check: verify.CheckResult{Status: verify.CheckStatusFail, Code: verify.ErrorCodeEnvelopeMismatch, EnvelopeStatus: verify.EnvelopeStatusInvalid}, want: CheckFact{Class: CheckEnvelope, Reason: ReasonEnvelopeMismatch}},
		{name: "reverse path mismatch", check: verify.CheckResult{Status: verify.CheckStatusFail, Code: verify.ErrorCodeEnvelopeMismatch, EnvelopeStatus: verify.EnvelopeStatusReversePathMismatch}, want: CheckFact{Class: CheckEnvelope, Reason: ReasonEnvelopeMismatch}},
		{name: "recipient value mismatch", check: verify.CheckResult{Status: verify.CheckStatusFail, Code: verify.ErrorCodeEnvelopeMismatch, EnvelopeStatus: verify.EnvelopeStatusRecipientValueMismatch}, want: CheckFact{Class: CheckEnvelope, Reason: ReasonEnvelopeMismatch}},
		{name: "not checked", check: verify.CheckResult{Status: verify.CheckStatusNotEvaluated, EnvelopeStatus: verify.EnvelopeStatusNotChecked}, want: CheckFact{Class: CheckInternalContract, Reason: ReasonInternalContract}},
		{name: "pass reported as failure", check: verify.CheckResult{Status: verify.CheckStatusFail, Code: verify.ErrorCodeEnvelopeMismatch, EnvelopeStatus: verify.EnvelopeStatusPass}, want: CheckFact{Class: CheckInternalContract, Reason: ReasonInternalContract}},
		{name: "not applicable reported as failure", check: verify.CheckResult{Status: verify.CheckStatusFail, Code: verify.ErrorCodeEnvelopeMismatch, EnvelopeStatus: verify.EnvelopeStatusNotApplicable}, want: CheckFact{Class: CheckInternalContract, Reason: ReasonInternalContract}},
		{name: "failure reported as pass", check: verify.CheckResult{Status: verify.CheckStatusPass, EnvelopeStatus: verify.EnvelopeStatusMismatch}, want: CheckFact{Class: CheckInternalContract, Reason: ReasonInternalContract}},
		{name: "failure with wrong code", check: verify.CheckResult{Status: verify.CheckStatusFail, Code: verify.ErrorCodeMalformedState, EnvelopeStatus: verify.EnvelopeStatusMissing}, want: CheckFact{Class: CheckInternalContract, Reason: ReasonInternalContract}},
		{name: "pass with code", check: verify.CheckResult{Status: verify.CheckStatusPass, Code: verify.ErrorCodeEnvelopeMismatch, EnvelopeStatus: verify.EnvelopeStatusPass}, want: CheckFact{Class: CheckInternalContract, Reason: ReasonInternalContract}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accumulator := testAccumulator()
			accumulator.mapEnvelopeCheck(CheckEnvelope, tt.check)
			if len(accumulator.checks) != 1 || accumulator.checks[0] != tt.want {
				t.Fatalf("mapping = %#v, want %#v", accumulator.checks, tt.want)
			}
		})
	}
}

// TestDomainAlignmentStatusMatrixIsClosed verifies only exact alignment status triples are accepted.
func TestDomainAlignmentStatusMatrixIsClosed(t *testing.T) {
	tests := []struct {
		name  string
		check verify.CheckResult
		want  CheckFact
	}{
		{name: "pass", check: verify.CheckResult{Status: verify.CheckStatusPass, DomainAlignmentStatus: verify.DomainAlignmentStatusPass}, want: CheckFact{Class: CheckDomainAlignment, Reason: ReasonNone}},
		{name: "not applicable", check: verify.CheckResult{Status: verify.CheckStatusNotApplicable, DomainAlignmentStatus: verify.DomainAlignmentStatusNotApplicable}, want: CheckFact{Class: CheckDomainAlignment, Reason: ReasonNone}},
		{name: "mismatch", check: verify.CheckResult{Status: verify.CheckStatusFail, Code: verify.ErrorCodeDomainAlignmentMismatch, DomainAlignmentStatus: verify.DomainAlignmentStatusMismatch}, want: CheckFact{Class: CheckDomainAlignment, Reason: ReasonDomainAlignmentMismatch}},
		{name: "invalid", check: verify.CheckResult{Status: verify.CheckStatusFail, Code: verify.ErrorCodeMalformedState, DomainAlignmentStatus: verify.DomainAlignmentStatusInvalid}, want: CheckFact{Class: CheckDomainAlignment, Reason: ReasonDomainAlignmentMismatch}},
		{name: "not checked", check: verify.CheckResult{Status: verify.CheckStatusNotEvaluated, DomainAlignmentStatus: verify.DomainAlignmentStatusNotChecked}, want: CheckFact{Class: CheckInternalContract, Reason: ReasonInternalContract}},
		{name: "pass reported as mismatch", check: verify.CheckResult{Status: verify.CheckStatusFail, Code: verify.ErrorCodeDomainAlignmentMismatch, DomainAlignmentStatus: verify.DomainAlignmentStatusPass}, want: CheckFact{Class: CheckInternalContract, Reason: ReasonInternalContract}},
		{name: "not applicable reported as mismatch", check: verify.CheckResult{Status: verify.CheckStatusFail, Code: verify.ErrorCodeDomainAlignmentMismatch, DomainAlignmentStatus: verify.DomainAlignmentStatusNotApplicable}, want: CheckFact{Class: CheckInternalContract, Reason: ReasonInternalContract}},
		{name: "invalid with mismatch code", check: verify.CheckResult{Status: verify.CheckStatusFail, Code: verify.ErrorCodeDomainAlignmentMismatch, DomainAlignmentStatus: verify.DomainAlignmentStatusInvalid}, want: CheckFact{Class: CheckInternalContract, Reason: ReasonInternalContract}},
		{name: "mismatch with malformed code", check: verify.CheckResult{Status: verify.CheckStatusFail, Code: verify.ErrorCodeMalformedState, DomainAlignmentStatus: verify.DomainAlignmentStatusMismatch}, want: CheckFact{Class: CheckInternalContract, Reason: ReasonInternalContract}},
		{name: "mismatch reported as pass", check: verify.CheckResult{Status: verify.CheckStatusPass, DomainAlignmentStatus: verify.DomainAlignmentStatusMismatch}, want: CheckFact{Class: CheckInternalContract, Reason: ReasonInternalContract}},
		{name: "pass with code", check: verify.CheckResult{Status: verify.CheckStatusPass, Code: verify.ErrorCodeDomainAlignmentMismatch, DomainAlignmentStatus: verify.DomainAlignmentStatusPass}, want: CheckFact{Class: CheckInternalContract, Reason: ReasonInternalContract}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accumulator := testAccumulator()
			accumulator.mapAlignmentCheck(CheckDomainAlignment, tt.check)
			if len(accumulator.checks) != 1 || accumulator.checks[0] != tt.want {
				t.Fatalf("mapping = %#v, want %#v", accumulator.checks, tt.want)
			}
		})
	}
}

// TestEveryKnownCheckStatusIsMapped verifies all generic status tokens reach a typed branch.
func TestEveryKnownCheckStatusIsMapped(t *testing.T) {
	tests := []struct {
		check        verify.CheckResult
		wantReason   Reason
		wantSeverity outcomeSeverity
	}{
		{verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusNotEvaluated, Algorithm: verify.AlgorithmRSASHA256}, ReasonInternalContract, severityPermanent},
		{verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusPass, Algorithm: verify.AlgorithmRSASHA256}, ReasonNone, severityPass},
		{verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusFail, Code: verify.ErrorCodeSignatureMismatch, Algorithm: verify.AlgorithmRSASHA256}, ReasonSignatureMismatch, severityFailure},
		{verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusUnsupported, Code: verify.ErrorCodeUnsupportedAlgorithm, Algorithm: verify.AlgorithmUnknown}, ReasonUnsupportedAlgorithm, severityPass},
		{verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusSkipped, Algorithm: verify.AlgorithmRSASHA256}, ReasonInternalContract, severityPermanent},
		{verify.CheckResult{Kind: verify.CheckKindNextDomain, Status: verify.CheckStatusNotApplicable, NextDomainStatus: verify.NextDomainStatusNotApplicable}, ReasonNone, severityPass},
		{verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusIndeterminate, Algorithm: verify.AlgorithmRSASHA256}, ReasonInternalContract, severityPermanent},
	}
	for _, tt := range tests {
		accumulator := testAccumulator()
		accumulator.mapCheck(tt.check)
		if len(accumulator.checks) == 0 || accumulator.checks[len(accumulator.checks)-1].Reason != tt.wantReason || accumulator.severity != tt.wantSeverity {
			t.Fatalf("check status %q mapped facts=%#v severity=%d", tt.check.Status, accumulator.checks, accumulator.severity)
		}
	}
}

// testAccumulator returns a cap-aware isolated mapping accumulator.
func testAccumulator() mappingAccumulator {
	return mappingAccumulator{
		reason: ReasonNone, required: make(map[verify.CheckKind]bool), setIndices: [hardMaxSignatureFacts]bool{},
		signatureChecks: make(map[Algorithm]int), signatureSets: make(map[Algorithm]int), maxChecks: 128, maxSignatures: 16,
	}
}
