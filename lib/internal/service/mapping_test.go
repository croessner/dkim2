package service

import (
	"slices"
	"testing"

	"github.com/croessner/dkim2/internal/verify"
)

// TestMapVerificationResultAppliesBindingPrecedence verifies order-independent aggregation.
func TestMapVerificationResultAppliesBindingPrecedence(t *testing.T) {
	target := verify.Target{Sequence: 2, InstanceNumber: 2}
	passChecks := requiredPassChecks(target)
	passSet := verify.SignatureSetResult{Index: 0, Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}
	failSet := verify.SignatureSetResult{Index: 1, Algorithm: verify.AlgorithmEd25519SHA256, Status: verify.SignatureSetStatusFail, KeyStatus: verify.KeyStatusFound}
	temporarySet := verify.SignatureSetResult{Index: 0, Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusProviderTemporary, KeyStatus: verify.KeyStatusProviderTemporary}
	permanentCheck := verify.CheckResult{Kind: verify.CheckKindTimestamp, Status: verify.CheckStatusFail, Code: verify.ErrorCodeTimestampInvalid, TimestampStatus: verify.TimestampStatusExpired, Target: target}
	failAndTemporaryChecks := requiredChecksWithSignatures(target,
		verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusFail, Code: verify.ErrorCodeProviderError, Algorithm: verify.AlgorithmRSASHA256, ProviderFailureClass: verify.ProviderFailureTemporary, Target: target},
		verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusFail, Code: verify.ErrorCodeSignatureMismatch, Algorithm: verify.AlgorithmEd25519SHA256, Target: target},
	)
	temporaryChecks := requiredChecksWithSignatures(target,
		verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusFail, Code: verify.ErrorCodeProviderError, Algorithm: verify.AlgorithmRSASHA256, ProviderFailureClass: verify.ProviderFailureTemporary, Target: target},
	)
	permanentChecks := slices.Clone(failAndTemporaryChecks)
	for index := range permanentChecks {
		if permanentChecks[index].Kind == verify.CheckKindTimestamp {
			permanentChecks[index] = permanentCheck
		}
	}

	tests := []struct {
		name   string
		status verify.TargetStatus
		checks []verify.CheckResult
		sets   []verify.SignatureSetResult
		want   State
		reason Reason
	}{
		{name: "passing target", status: verify.TargetStatusPass, checks: passChecks, sets: []verify.SignatureSetResult{passSet}, want: StatePASS, reason: ReasonNone},
		{name: "supported failure outranks temporary", status: verify.TargetStatusMixed, checks: failAndTemporaryChecks, sets: []verify.SignatureSetResult{temporarySet, failSet}, want: StateFAIL, reason: ReasonSignatureMismatch},
		{name: "permanent outranks failure and temporary", status: verify.TargetStatusFail, checks: permanentChecks, sets: []verify.SignatureSetResult{temporarySet, failSet}, want: StatePERMERROR, reason: ReasonTimestampInvalid},
		{name: "temporary without higher fact", status: verify.TargetStatusIndeterminate, checks: temporaryChecks, sets: []verify.SignatureSetResult{temporarySet}, want: StateTEMPERROR, reason: ReasonProviderTemporary},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, checks := range [][]verify.CheckResult{tt.checks, reverseCheckResults(tt.checks)} {
				for _, sets := range [][]verify.SignatureSetResult{tt.sets, reverseSignatureSets(tt.sets)} {
					mapped := mapVerificationResult(newVerifyResultWithDefaultCustody(target, tt.status, checks, sets), DefaultLimits())
					if mapped.State() != tt.want {
						t.Fatalf("State() = %q, want %q", mapped.State(), tt.want)
					}
					if mapped.PrimaryReason() != tt.reason {
						t.Fatalf("PrimaryReason() = %q, want %q", mapped.PrimaryReason(), tt.reason)
					}
					if mapped.Draft() != DraftIdentifier || mapped.Scope() != ScopeCurrent || mapped.HistoricalContent() != HistoricalNotEvaluated || mapped.HistoricalSignatures() != HistoricalNotEvaluated {
						t.Fatal("mapping omitted binding draft or verification coverage")
					}
				}
			}
		})
	}
}

// reverseCheckResults returns an independent reversed check permutation.
func reverseCheckResults(input []verify.CheckResult) []verify.CheckResult {
	reversed := slices.Clone(input)
	slices.Reverse(reversed)
	return reversed
}

// TestMapVerificationResultFailsClosedOnUnknownFacts verifies every ambiguous dimension is permanent.
func TestMapVerificationResultFailsClosedOnUnknownFacts(t *testing.T) {
	target := verify.Target{Sequence: 1, InstanceNumber: 1}
	tests := []struct {
		name  string
		check verify.CheckResult
		set   verify.SignatureSetResult
	}{
		{name: "zero check kind", check: verify.CheckResult{Status: verify.CheckStatusPass}},
		{name: "check kind", check: verify.CheckResult{Kind: verify.CheckKind("future"), Status: verify.CheckStatusPass}},
		{name: "zero check status", check: verify.CheckResult{Kind: verify.CheckKindBodyHash, HashStatus: verify.HashStatusPass}},
		{name: "check status", check: verify.CheckResult{Kind: verify.CheckKindBodyHash, Status: verify.CheckStatus("future"), HashStatus: verify.HashStatusPass}},
		{name: "zero hash status", check: verify.CheckResult{Kind: verify.CheckKindBodyHash, Status: verify.CheckStatusPass}},
		{name: "hash status", check: verify.CheckResult{Kind: verify.CheckKindBodyHash, Status: verify.CheckStatusPass, HashStatus: verify.HashStatus("future")}},
		{name: "zero timestamp status", check: verify.CheckResult{Kind: verify.CheckKindTimestamp, Status: verify.CheckStatusPass}},
		{name: "timestamp status", check: verify.CheckResult{Kind: verify.CheckKindTimestamp, Status: verify.CheckStatusPass, TimestampStatus: verify.TimestampStatus("future-contract")}},
		{name: "zero envelope status", check: verify.CheckResult{Kind: verify.CheckKindEnvelope, Status: verify.CheckStatusPass}},
		{name: "envelope status", check: verify.CheckResult{Kind: verify.CheckKindEnvelope, Status: verify.CheckStatusPass, EnvelopeStatus: verify.EnvelopeStatus("future")}},
		{name: "zero alignment status", check: verify.CheckResult{Kind: verify.CheckKindDomainAlignment, Status: verify.CheckStatusPass}},
		{name: "alignment status", check: verify.CheckResult{Kind: verify.CheckKindDomainAlignment, Status: verify.CheckStatusPass, DomainAlignmentStatus: verify.DomainAlignmentStatus("future")}},
		{name: "zero next-domain status", check: verify.CheckResult{Kind: verify.CheckKindNextDomain, Status: verify.CheckStatusPass}},
		{name: "next-domain status", check: verify.CheckResult{Kind: verify.CheckKindNextDomain, Status: verify.CheckStatusPass, NextDomainStatus: verify.NextDomainStatus("future")}},
		{name: "unknown error code", check: verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusPass, Code: verify.ErrorCode("future")}},
		{name: "zero signature status", set: verify.SignatureSetResult{Algorithm: verify.AlgorithmRSASHA256, KeyStatus: verify.KeyStatusFound}},
		{name: "signature status", set: verify.SignatureSetResult{Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatus("future"), KeyStatus: verify.KeyStatusFound}},
		{name: "zero key status", set: verify.SignatureSetResult{Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass}},
		{name: "key status", set: verify.SignatureSetResult{Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatus("future")}},
		{name: "zero algorithm", set: verify.SignatureSetResult{Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var checks []verify.CheckResult
			var sets []verify.SignatureSetResult
			if tt.check != (verify.CheckResult{}) {
				checks = []verify.CheckResult{tt.check}
			}
			if tt.set != (verify.SignatureSetResult{}) {
				sets = []verify.SignatureSetResult{tt.set}
			}
			mapped := mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusPass, checks, sets), DefaultLimits())
			if mapped.State() != StatePERMERROR || mapped.PrimaryReason() != ReasonInternalContract {
				t.Fatalf("result = %q/%q, want PERMERROR/internal_contract", mapped.State(), mapped.PrimaryReason())
			}
		})
	}

	zeroTarget := mapVerificationResult(verify.Result{}, DefaultLimits())
	if zeroTarget.State() != StatePERMERROR || zeroTarget.PrimaryReason() != ReasonInternalContract || zeroTarget.Custody() != CustodyNotEvaluated {
		t.Fatalf("zero target result = %q/%q/%q", zeroTarget.State(), zeroTarget.PrimaryReason(), zeroTarget.Custody())
	}
}

// TestMapVerificationResultHandlesUnknownAlgorithmCombinations verifies draft-05 ignore semantics.
func TestMapVerificationResultHandlesUnknownAlgorithmCombinations(t *testing.T) {
	target := verify.Target{Sequence: 1, InstanceNumber: 1}
	unknownCheck := verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusUnsupported, Code: verify.ErrorCodeUnsupportedAlgorithm, Algorithm: verify.AlgorithmUnknown, Target: target}
	passCheck := verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusPass, Algorithm: verify.AlgorithmRSASHA256, Target: target}
	unknownOnlySet := verify.SignatureSetResult{Index: 0, Algorithm: verify.AlgorithmUnknown, Status: verify.SignatureSetStatusUnsupportedAlgorithm, KeyStatus: verify.KeyStatusUnsupportedAlgorithm}
	unknown := verify.SignatureSetResult{Index: 0, Algorithm: verify.AlgorithmUnknown, Status: verify.SignatureSetStatusUnsupportedAlgorithm, KeyStatus: verify.KeyStatusUnsupportedAlgorithm}
	pass := verify.SignatureSetResult{Index: 1, Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}

	unknownOnly := mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusUnsupported, requiredChecksWithSignatures(target, unknownCheck), []verify.SignatureSetResult{unknownOnlySet}), DefaultLimits())
	if unknownOnly.State() != StatePERMERROR || unknownOnly.PrimaryReason() != ReasonUnsupportedAlgorithm {
		t.Fatalf("unknown-only = %q/%q", unknownOnly.State(), unknownOnly.PrimaryReason())
	}
	mixed := mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusPass, requiredChecksWithSignatures(target, unknownCheck, passCheck), []verify.SignatureSetResult{unknown, pass}), DefaultLimits())
	if mixed.State() != StatePASS {
		t.Fatalf("supported pass plus unknown = %q, want PASS", mixed.State())
	}

	missingRequired := mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusPass, nil, []verify.SignatureSetResult{pass}), DefaultLimits())
	if missingRequired.State() != StatePERMERROR || missingRequired.PrimaryReason() != ReasonInternalContract {
		t.Fatalf("missing required checks = %q/%q", missingRequired.State(), missingRequired.PrimaryReason())
	}
}

// TestMapVerificationResultReportsAllCustodyStates verifies truthful separate coverage.
func TestMapVerificationResultReportsAllCustodyStates(t *testing.T) {
	target := verify.Target{Sequence: 1, InstanceNumber: 1}
	passSet := []verify.SignatureSetResult{{Algorithm: verify.AlgorithmRSASHA256, Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound}}
	for _, custody := range []verify.CustodyStatus{verify.CustodyStatusNotPresent, verify.CustodyStatusNDLinksEvaluated} {
		result := mapVerificationResult(verify.NewResultWithCustody(target, verify.TargetStatusPass, requiredPassChecks(target), passSet, custody), DefaultLimits())
		if result.State() != StatePASS || result.Custody() != Custody(custody) {
			t.Fatalf("custody %q mapped to %q/%q", custody, result.State(), result.Custody())
		}
	}

	terminalChecks := requiredPassChecks(target)
	for index := range terminalChecks {
		switch terminalChecks[index].Kind {
		case verify.CheckKindNextDomain:
			terminalChecks[index].Status = verify.CheckStatusUnsupported
			terminalChecks[index].Code = verify.ErrorCodeOutOfBandRequired
			terminalChecks[index].NextDomainStatus = verify.NextDomainStatusOutOfBandRequired
		case verify.CheckKindEnvelope:
			terminalChecks[index].Status = verify.CheckStatusNotApplicable
			terminalChecks[index].EnvelopeStatus = verify.EnvelopeStatusNotApplicable
		case verify.CheckKindDomainAlignment:
			terminalChecks[index].Status = verify.CheckStatusNotApplicable
			terminalChecks[index].DomainAlignmentStatus = verify.DomainAlignmentStatusNotApplicable
		}
	}
	terminal := mapVerificationResult(verify.NewResultWithCustody(target, verify.TargetStatusUnsupported, terminalChecks, passSet, verify.CustodyStatusTerminalNDRequiresOOB), DefaultLimits())
	if terminal.State() != StatePERMERROR || terminal.Custody() != CustodyTerminalNDRequiresOOB || terminal.PrimaryReason() != ReasonOutOfBandRequired {
		t.Fatalf("terminal custody = %q/%q/%q", terminal.State(), terminal.Custody(), terminal.PrimaryReason())
	}

	indeterminate := mapVerificationResult(verify.Result{}, DefaultLimits())
	if indeterminate.State() != StatePERMERROR || indeterminate.Custody() != CustodyNotEvaluated {
		t.Fatalf("pre-extraction custody = %q/%q", indeterminate.State(), indeterminate.Custody())
	}
}

// requiredChecksWithSignatures returns all singular checks plus supplied per-set signature checks.
func requiredChecksWithSignatures(target verify.Target, signatureChecks ...verify.CheckResult) []verify.CheckResult {
	checks := requiredPassChecks(target)
	checks = slices.DeleteFunc(checks, func(check verify.CheckResult) bool { return check.Kind == verify.CheckKindSignature })
	return append(checks, signatureChecks...)
}

// requiredPassChecks returns the complete current-check set required for PASS.
func requiredPassChecks(target verify.Target) []verify.CheckResult {
	return []verify.CheckResult{
		{Kind: verify.CheckKindBodyHash, Status: verify.CheckStatusPass, HashStatus: verify.HashStatusPass, Target: target},
		{Kind: verify.CheckKindHeaderHash, Status: verify.CheckStatusPass, HashStatus: verify.HashStatusPass, Target: target},
		{Kind: verify.CheckKindSignature, Status: verify.CheckStatusPass, Algorithm: verify.AlgorithmRSASHA256, Target: target},
		{Kind: verify.CheckKindTimestamp, Status: verify.CheckStatusPass, TimestampStatus: verify.TimestampStatusPass, Target: target},
		{Kind: verify.CheckKindEnvelope, Status: verify.CheckStatusPass, EnvelopeStatus: verify.EnvelopeStatusPass, Target: target},
		{Kind: verify.CheckKindDomainAlignment, Status: verify.CheckStatusPass, DomainAlignmentStatus: verify.DomainAlignmentStatusPass, Target: target},
		{Kind: verify.CheckKindNextDomain, Status: verify.CheckStatusNotApplicable, NextDomainStatus: verify.NextDomainStatusNotApplicable, Target: target},
	}
}

// newVerifyResultWithDefaultCustody constructs synthetic facts with explicit established nd= absence.
func newVerifyResultWithDefaultCustody(target verify.Target, status verify.TargetStatus, checks []verify.CheckResult, sets []verify.SignatureSetResult) verify.Result {
	return verify.NewResultWithCustody(target, status, checks, sets, verify.CustodyStatusNotPresent)
}

// reverseSignatureSets returns an independent reversed permutation.
func reverseSignatureSets(input []verify.SignatureSetResult) []verify.SignatureSetResult {
	result := slices.Clone(input)
	slices.Reverse(result)

	return result
}
