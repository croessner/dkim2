package service

import (
	"testing"

	"github.com/croessner/dkim2/internal/verify"
)

// TestLocallyDisabledAlgorithmMapsToUnsupportedAlgorithm pins the Draft-08
// result for an implemented algorithm that local policy disables: a
// PERMERROR unsupported_algorithm (the former internal_contract outcome came
// from the mismatched policy_rejected key status), marked as locally
// disabled so observation can separate it from an unknown algorithm.
func TestLocallyDisabledAlgorithmMapsToUnsupportedAlgorithm(t *testing.T) {
	target := verify.Target{Sequence: 1, InstanceNumber: 1}
	disabledCheck := verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusFail, Code: verify.ErrorCodeDisabledAlgorithm, Algorithm: verify.AlgorithmEd25519SHA256, Target: target}
	disabled := verify.SignatureSetResult{Index: 0, Algorithm: verify.AlgorithmEd25519SHA256, Status: verify.SignatureSetStatusDisabledAlgorithm, KeyStatus: verify.KeyStatusDisabledAlgorithm}
	mapped := mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusUnsupported, requiredChecksWithSignatures(target, disabledCheck), []verify.SignatureSetResult{disabled}), DefaultLimits())
	if mapped.State() != StatePERMERROR || mapped.PrimaryReason() != ReasonUnsupportedAlgorithm || !mapped.LocallyDisabledAlgorithm() {
		t.Fatalf("disabled = %q/%q locally=%t", mapped.State(), mapped.PrimaryReason(), mapped.LocallyDisabledAlgorithm())
	}

	unknownCheck := verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusUnsupported, Code: verify.ErrorCodeUnsupportedAlgorithm, Algorithm: verify.AlgorithmUnknown, Target: target}
	unknown := verify.SignatureSetResult{Index: 0, Algorithm: verify.AlgorithmUnknown, Status: verify.SignatureSetStatusUnsupportedAlgorithm, KeyStatus: verify.KeyStatusUnsupportedAlgorithm}
	mapped = mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusUnsupported, requiredChecksWithSignatures(target, unknownCheck), []verify.SignatureSetResult{unknown}), DefaultLimits())
	if mapped.State() != StatePERMERROR || mapped.PrimaryReason() != ReasonUnsupportedAlgorithm || mapped.LocallyDisabledAlgorithm() {
		t.Fatalf("unknown = %q/%q locally=%t", mapped.State(), mapped.PrimaryReason(), mapped.LocallyDisabledAlgorithm())
	}
}
