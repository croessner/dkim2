package policy

import (
	"slices"
	"testing"
)

// TestClosedVocabularies verifies every policy enum accepts only frozen tokens.
func TestClosedVocabularies(t *testing.T) {
	tests := []struct {
		name    string
		known   []bool
		unknown []bool
	}{
		{name: "mode", known: []bool{ModeStrict.Known(), ModePermissive.Known(), ModeTesting.Known()}, unknown: []bool{Mode("").Known(), Mode("future").Known()}},
		{name: "protocol", known: []bool{ProtocolPASS.Known(), ProtocolFAIL.Known(), ProtocolPERMERROR.Known(), ProtocolTEMPERROR.Known()}, unknown: []bool{ProtocolClass("").Known(), ProtocolClass("future").Known()}},
		{name: "verification reason", known: []bool{VerificationReasonNone.Known(), VerificationReasonHashMismatch.Known(), VerificationReasonSignatureMismatch.Known(), VerificationReasonInvalidKey.Known(), VerificationReasonProviderTemporary.Known(), VerificationReasonInternalContract.Known()}, unknown: []bool{VerificationReason("").Known(), VerificationReason("future").Known()}},
		{name: "verdict", known: []bool{VerdictAccept.Known(), VerdictReject.Known(), VerdictTempfail.Known(), VerdictContinue.Known()}, unknown: []bool{Verdict("").Known(), Verdict("future").Known()}},
		{name: "action", known: []bool{ActionAccept.Known(), ActionReject.Known(), ActionTempfail.Known(), ActionContinue.Known()}, unknown: []bool{ActionKind("").Known(), ActionKind("future").Known()}},
		{name: "compliance", known: []bool{ComplianceNotRequested.Known(), ComplianceHonored.Known(), ComplianceViolated.Known(), ComplianceIndeterminate.Known(), ComplianceNotEvaluated.Known()}, unknown: []bool{ComplianceState("").Known(), ComplianceState("future").Known()}},
		{name: "transition", known: []bool{TransitionOrigin.Known(), TransitionUnchanged.Known(), TransitionBodyChanged.Known(), TransitionHeadersChanged.Known(), TransitionBodyAndHeadersChanged.Known(), TransitionHeaderAdditionOnly.Known(), TransitionIndeterminate.Known(), TransitionNotEvaluated.Known()}, unknown: []bool{TransitionState("").Known(), TransitionState("future").Known()}},
		{name: "target form", known: []bool{TargetSelected.Known(), TargetUnavailable.Known()}, unknown: []bool{TargetForm("").Known(), TargetForm("future").Known()}},
		{name: "severity", known: []bool{SeverityInfo.Known(), SeverityWarning.Known(), SeverityPermanent.Known(), SeverityTemporary.Known()}, unknown: []bool{FindingSeverity("").Known(), FindingSeverity("future").Known()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, known := range tt.known {
				if !known {
					t.Fatal("closed vocabulary rejected a known value")
				}
			}
			for _, unknown := range tt.unknown {
				if unknown {
					t.Fatal("closed vocabulary accepted an unknown value")
				}
			}
		})
	}
}

// TestPolicyReasonVocabulary verifies the exact frozen reason set.
func TestPolicyReasonVocabulary(t *testing.T) {
	expected := []PolicyReason{
		"invalid_input", "limit_exceeded", "internal_contract", "protocol_pass", "protocol_fail", "protocol_permerror", "protocol_temperror",
		"permissive_override", "testing_mode_observe", "dns_testing_effective", "dns_testing_mixed", "dns_testing_ineligible",
		"donotmodify_honored", "donotmodify_violated", "donotmodify_indeterminate", "donotmodify_not_evaluated",
		"donotexplode_violated", "donotexplode_indeterminate", "donotexplode_not_evaluated", "feedback_requested",
		"feedback_relay_selected", "feedhere_inert", "exploded_reported",
	}
	actual := []PolicyReason{
		ReasonInvalidInput, ReasonLimitExceeded, ReasonInternalContract,
		ReasonProtocolPass, ReasonProtocolFail, ReasonProtocolPermerror, ReasonProtocolTemperror,
		ReasonPermissiveOverride, ReasonTestingModeObserve,
		ReasonDNSTestingEffective, ReasonDNSTestingMixed, ReasonDNSTestingIneligible,
		ReasonDoNotModifyHonored, ReasonDoNotModifyViolated, ReasonDoNotModifyIndeterminate,
		ReasonDoNotModifyNotEvaluated, ReasonDoNotExplodeViolated, ReasonDoNotExplodeIndeterminate,
		ReasonDoNotExplodeNotEvaluated, ReasonFeedbackRequested, ReasonFeedbackRelaySelected,
		ReasonFeedHereInert, ReasonExplodedReported,
	}
	if !slices.Equal(actual, expected) {
		t.Fatalf("policy reasons = %v, want %v", actual, expected)
	}
	seen := make(map[PolicyReason]struct{}, len(actual))
	for _, reason := range actual {
		if !reason.Known() {
			t.Fatalf("known reason %q rejected", reason)
		}
		if _, duplicate := seen[reason]; duplicate {
			t.Fatalf("duplicate policy reason %q", reason)
		}
		seen[reason] = struct{}{}
	}
	if len(actual) != 23 {
		t.Fatalf("reason count = %d, want 23", len(actual))
	}
	if PolicyReason("").Known() || PolicyReason("future").Known() {
		t.Fatal("unknown policy reason accepted")
	}
}

// TestFindingSequenceContract verifies exact reason-to-sequence presence rules.
func TestFindingSequenceContract(t *testing.T) {
	for _, reason := range []PolicyReason{
		ReasonProtocolPass, ReasonProtocolFail, ReasonProtocolPermerror, ReasonProtocolTemperror,
		ReasonPermissiveOverride, ReasonTestingModeObserve,
		ReasonDNSTestingEffective, ReasonDNSTestingMixed, ReasonDNSTestingIneligible,
	} {
		finding, err := newFinding(reason, 0, false)
		if err != nil || !finding.Valid() {
			t.Fatalf("unsequenced reason %q rejected: %v", reason, err)
		}
		if _, err := newFinding(reason, 1, true); !IsErrorCode(err, ErrorInternalContract) {
			t.Fatalf("unsequenced reason %q accepted sequence", reason)
		}
	}
	for _, reason := range []PolicyReason{
		ReasonDoNotModifyHonored, ReasonDoNotModifyViolated, ReasonDoNotModifyIndeterminate,
		ReasonDoNotModifyNotEvaluated, ReasonDoNotExplodeViolated, ReasonDoNotExplodeIndeterminate,
		ReasonDoNotExplodeNotEvaluated, ReasonFeedbackRequested, ReasonFeedbackRelaySelected,
		ReasonFeedHereInert, ReasonExplodedReported,
	} {
		finding, err := newFinding(reason, 1, true)
		if err != nil || !finding.Valid() {
			t.Fatalf("sequenced reason %q rejected: %v", reason, err)
		}
		if _, err := newFinding(reason, 0, false); !IsErrorCode(err, ErrorInternalContract) {
			t.Fatalf("sequenced reason %q accepted missing sequence", reason)
		}
	}
}

// TestFindingSeverityVocabulary verifies the exact frozen severity set.
func TestFindingSeverityVocabulary(t *testing.T) {
	expected := []FindingSeverity{"info", "warning", "permanent", "temporary"}
	actual := []FindingSeverity{SeverityInfo, SeverityWarning, SeverityPermanent, SeverityTemporary}
	if !slices.Equal(actual, expected) {
		t.Fatalf("severities = %v, want %v", actual, expected)
	}
	for _, severity := range actual {
		if !severity.Known() {
			t.Fatalf("known severity %q rejected", severity)
		}
	}
}

// TestPolicyReasonSeverityMatrix verifies every frozen reason-to-severity row independently.
func TestPolicyReasonSeverityMatrix(t *testing.T) {
	tests := []struct {
		reason   PolicyReason
		severity FindingSeverity
	}{
		{ReasonInvalidInput, SeverityPermanent},
		{ReasonLimitExceeded, SeverityPermanent},
		{ReasonInternalContract, SeverityPermanent},
		{ReasonProtocolPass, SeverityInfo},
		{ReasonProtocolFail, SeverityPermanent},
		{ReasonProtocolPermerror, SeverityPermanent},
		{ReasonProtocolTemperror, SeverityTemporary},
		{ReasonPermissiveOverride, SeverityWarning},
		{ReasonTestingModeObserve, SeverityWarning},
		{ReasonDNSTestingEffective, SeverityWarning},
		{ReasonDNSTestingMixed, SeverityWarning},
		{ReasonDNSTestingIneligible, SeverityWarning},
		{ReasonDoNotModifyHonored, SeverityInfo},
		{ReasonDoNotModifyViolated, SeverityPermanent},
		{ReasonDoNotModifyIndeterminate, SeverityWarning},
		{ReasonDoNotModifyNotEvaluated, SeverityWarning},
		{ReasonDoNotExplodeViolated, SeverityPermanent},
		{ReasonDoNotExplodeIndeterminate, SeverityWarning},
		{ReasonDoNotExplodeNotEvaluated, SeverityWarning},
		{ReasonFeedbackRequested, SeverityInfo},
		{ReasonFeedbackRelaySelected, SeverityInfo},
		{ReasonFeedHereInert, SeverityInfo},
		{ReasonExplodedReported, SeverityInfo},
	}
	if len(tests) != 23 {
		t.Fatalf("severity row count = %d, want 23", len(tests))
	}
	for _, tt := range tests {
		if got := severityForReason(tt.reason); got != tt.severity {
			t.Fatalf("severityForReason(%q) = %q, want %q", tt.reason, got, tt.severity)
		}
	}
}
