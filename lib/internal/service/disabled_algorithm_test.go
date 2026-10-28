package service

import (
	"testing"

	"github.com/croessner/dkim2/internal/combine"
	"github.com/croessner/dkim2/internal/policy"
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
	disabled := verify.SignatureSetResult{Index: 0, Selector: failedSelector, Algorithm: verify.AlgorithmEd25519SHA256, Status: verify.SignatureSetStatusDisabledAlgorithm, KeyStatus: verify.KeyStatusDisabledAlgorithm}
	mapped := mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusUnsupported, requiredChecksWithSignatures(target, disabledCheck), []verify.SignatureSetResult{disabled}), DefaultLimits())
	if mapped.State() != StatePERMERROR || mapped.PrimaryReason() != ReasonUnsupportedAlgorithm || !mapped.LocallyDisabledAlgorithm() {
		t.Fatalf("disabled = %q/%q locally=%t", mapped.State(), mapped.PrimaryReason(), mapped.LocallyDisabledAlgorithm())
	}
	assertUnsupportedAlgorithmSetFact(t, mapped)

	unknownCheck := verify.CheckResult{Kind: verify.CheckKindSignature, Status: verify.CheckStatusUnsupported, Code: verify.ErrorCodeUnsupportedAlgorithm, Algorithm: verify.AlgorithmUnknown, Target: target}
	unknown := verify.SignatureSetResult{Index: 0, Selector: failedSelector, Algorithm: verify.AlgorithmUnknown, Status: verify.SignatureSetStatusUnsupportedAlgorithm, KeyStatus: verify.KeyStatusUnsupportedAlgorithm}
	mapped = mapVerificationResult(newVerifyResultWithDefaultCustody(target, verify.TargetStatusUnsupported, requiredChecksWithSignatures(target, unknownCheck), []verify.SignatureSetResult{unknown}), DefaultLimits())
	if mapped.State() != StatePERMERROR || mapped.PrimaryReason() != ReasonUnsupportedAlgorithm || mapped.LocallyDisabledAlgorithm() {
		t.Fatalf("unknown = %q/%q locally=%t", mapped.State(), mapped.PrimaryReason(), mapped.LocallyDisabledAlgorithm())
	}
	assertUnsupportedAlgorithmSetFact(t, mapped)
}

// assertUnsupportedAlgorithmSetFact pins Draft-08 Section 14.6 step 4 for
// both unknown and locally disabled algorithms: the per-set fact is the
// PERMERROR intermediate unsupported_algorithm with its selector, and the
// policy layer seals it into a PERMERROR projection instead of failing
// closed on an incoherent fact.
func assertUnsupportedAlgorithmSetFact(t *testing.T, mapped Result) {
	t.Helper()
	sets := mapped.SignatureSets()
	if len(sets) != 1 || sets[0].Status != SignaturePERMERROR || sets[0].Reason != ReasonUnsupportedAlgorithm || sets[0].Selector != failedSelector {
		t.Fatalf("signature sets = %#v", sets)
	}
	fact, err := policySignatureFact(sets[0])
	if err != nil {
		t.Fatalf("policySignatureFact() error = %v", err)
	}
	layout, _ := combine.NewLayout(1)
	projection, err := policy.NewGroupedSelectedProjection(policy.ProtocolPERMERROR, policy.VerificationReasonUnsupportedAlgorithm, 1, nil, []policy.SignatureFact{fact}, layout, policy.DefaultLimits())
	if err != nil || !projection.Valid() {
		t.Fatalf("NewGroupedSelectedProjection() error = %v", err)
	}
}
