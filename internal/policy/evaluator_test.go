package policy

import (
	"errors"
	"slices"
	"testing"
)

// TestBasePolicyMatrix verifies the exact four-by-three local decision table.
func TestBasePolicyMatrix(t *testing.T) {
	tests := []struct {
		protocol ProtocolClass
		mode     Mode
		verdict  Verdict
		primary  PolicyReason
		findings []PolicyReason
		severity []FindingSeverity
	}{
		{ProtocolPASS, ModeStrict, VerdictAccept, ReasonProtocolPass, []PolicyReason{ReasonProtocolPass}, []FindingSeverity{SeverityInfo}},
		{ProtocolFAIL, ModeStrict, VerdictReject, ReasonProtocolFail, []PolicyReason{ReasonProtocolFail}, []FindingSeverity{SeverityPermanent}},
		{ProtocolPERMERROR, ModeStrict, VerdictReject, ReasonProtocolPermerror, []PolicyReason{ReasonProtocolPermerror}, []FindingSeverity{SeverityPermanent}},
		{ProtocolTEMPERROR, ModeStrict, VerdictTempfail, ReasonProtocolTemperror, []PolicyReason{ReasonProtocolTemperror}, []FindingSeverity{SeverityTemporary}},
		{ProtocolPASS, ModePermissive, VerdictAccept, ReasonProtocolPass, []PolicyReason{ReasonProtocolPass}, []FindingSeverity{SeverityInfo}},
		{ProtocolFAIL, ModePermissive, VerdictAccept, ReasonPermissiveOverride, []PolicyReason{ReasonProtocolFail, ReasonPermissiveOverride}, []FindingSeverity{SeverityPermanent, SeverityWarning}},
		{ProtocolPERMERROR, ModePermissive, VerdictAccept, ReasonPermissiveOverride, []PolicyReason{ReasonProtocolPermerror, ReasonPermissiveOverride}, []FindingSeverity{SeverityPermanent, SeverityWarning}},
		{ProtocolTEMPERROR, ModePermissive, VerdictTempfail, ReasonProtocolTemperror, []PolicyReason{ReasonProtocolTemperror}, []FindingSeverity{SeverityTemporary}},
		{ProtocolPASS, ModeTesting, VerdictContinue, ReasonTestingModeObserve, []PolicyReason{ReasonProtocolPass, ReasonTestingModeObserve}, []FindingSeverity{SeverityInfo, SeverityWarning}},
		{ProtocolFAIL, ModeTesting, VerdictContinue, ReasonTestingModeObserve, []PolicyReason{ReasonProtocolFail, ReasonTestingModeObserve}, []FindingSeverity{SeverityPermanent, SeverityWarning}},
		{ProtocolPERMERROR, ModeTesting, VerdictContinue, ReasonTestingModeObserve, []PolicyReason{ReasonProtocolPermerror, ReasonTestingModeObserve}, []FindingSeverity{SeverityPermanent, SeverityWarning}},
		{ProtocolTEMPERROR, ModeTesting, VerdictContinue, ReasonTestingModeObserve, []PolicyReason{ReasonProtocolTemperror, ReasonTestingModeObserve}, []FindingSeverity{SeverityTemporary, SeverityWarning}},
	}
	for _, tt := range tests {
		t.Run(string(tt.protocol)+"/"+string(tt.mode), func(t *testing.T) {
			config := DefaultConfig()
			config.Mode = tt.mode
			evaluator, err := NewEvaluator(config)
			if err != nil {
				t.Fatalf("NewEvaluator() error = %v", err)
			}
			decision, err := evaluator.evaluateBase(tt.protocol)
			if err != nil {
				t.Fatalf("EvaluateBase() error = %v", err)
			}
			if decision.Protocol() != tt.protocol || decision.Mode() != tt.mode || decision.Verdict() != tt.verdict || decision.PrimaryReason() != tt.primary || !decision.Valid() {
				t.Fatalf("decision = protocol %q mode %q verdict %q primary %q valid=%v", decision.Protocol(), decision.Mode(), decision.Verdict(), decision.PrimaryReason(), decision.Valid())
			}
			if got := decision.Actions(); len(got) != 1 || got[0].Kind() != actionForVerdict(tt.verdict) {
				t.Fatalf("actions = %#v", got)
			}
			gotReasons := findingReasons(decision.Findings())
			if !slices.Equal(gotReasons, tt.findings) {
				t.Fatalf("findings = %v, want %v", gotReasons, tt.findings)
			}
			for index, finding := range decision.Findings() {
				if finding.Severity() != tt.severity[index] || !finding.Valid() {
					t.Fatalf("finding = %#v", finding)
				}
			}
		})
	}
}

// TestDecisionRejectsActionVerdictMismatch verifies fail-closed action coherence.
func TestDecisionRejectsActionVerdictMismatch(t *testing.T) {
	finding, err := newFinding(ReasonProtocolPass, 0, false)
	if err != nil {
		t.Fatalf("newFinding() error = %v", err)
	}
	decision := Decision{
		protocol: ProtocolPASS, mode: ModeStrict, verdict: VerdictAccept,
		primaryReason: ReasonProtocolPass, findings: []Finding{finding},
		actions: []Action{{kind: ActionReject}}, initialized: true,
	}
	if decision.Valid() {
		t.Fatal("decision accepted mismatched action and verdict")
	}
}

// TestDecisionRejectsBaseCoherenceCorruption verifies exact primary and finding invariants.
func TestDecisionRejectsBaseCoherenceCorruption(t *testing.T) {
	pass := mustTestFinding(t, ReasonProtocolPass)
	override := mustTestFinding(t, ReasonPermissiveOverride)
	tests := []struct {
		name     string
		decision Decision
	}{
		{name: "wrong primary", decision: Decision{protocol: ProtocolPASS, mode: ModeStrict, verdict: VerdictAccept, primaryReason: ReasonProtocolFail, findings: []Finding{pass}, actions: []Action{{kind: ActionAccept}}, initialized: true}},
		{name: "primary absent", decision: Decision{protocol: ProtocolPASS, mode: ModePermissive, verdict: VerdictAccept, primaryReason: ReasonPermissiveOverride, findings: []Finding{pass}, actions: []Action{{kind: ActionAccept}}, initialized: true}},
		{name: "extra finding", decision: Decision{protocol: ProtocolPASS, mode: ModeStrict, verdict: VerdictAccept, primaryReason: ReasonProtocolPass, findings: []Finding{pass, override}, actions: []Action{{kind: ActionAccept}}, initialized: true}},
		{name: "wrong order", decision: Decision{protocol: ProtocolFAIL, mode: ModePermissive, verdict: VerdictAccept, primaryReason: ReasonPermissiveOverride, findings: []Finding{override, mustTestFinding(t, ReasonProtocolFail)}, actions: []Action{{kind: ActionAccept}}, initialized: true}},
		{name: "error primary", decision: Decision{protocol: ProtocolPASS, mode: ModeStrict, verdict: VerdictAccept, primaryReason: ReasonInvalidInput, findings: []Finding{pass}, actions: []Action{{kind: ActionAccept}}, initialized: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.decision.Valid() {
				t.Fatal("corrupt decision accepted")
			}
		})
	}
}

// TestBaseEvaluationIsDeterministic verifies repeated ordered output equality.
func TestBaseEvaluationIsDeterministic(t *testing.T) {
	config := DefaultConfig()
	config.Mode = ModeTesting
	evaluator, err := NewEvaluator(config)
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}
	first, err := evaluator.evaluateBase(ProtocolTEMPERROR)
	if err != nil {
		t.Fatalf("first EvaluateBase() error = %v", err)
	}
	second, err := evaluator.evaluateBase(ProtocolTEMPERROR)
	if err != nil {
		t.Fatalf("second EvaluateBase() error = %v", err)
	}
	if first.Protocol() != second.Protocol() || first.Mode() != second.Mode() || first.Verdict() != second.Verdict() || first.PrimaryReason() != second.PrimaryReason() ||
		!slices.Equal(first.Findings(), second.Findings()) || !slices.Equal(first.Actions(), second.Actions()) {
		t.Fatal("repeated base evaluation was nondeterministic")
	}
}

// TestBaseEvaluationRejectsInvalidProtocol verifies fail-closed input handling.
func TestBaseEvaluationRejectsInvalidProtocol(t *testing.T) {
	evaluator, err := NewEvaluator(DefaultConfig())
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}
	decision, err := evaluator.evaluateBase(ProtocolClass("future"))
	if !IsErrorCode(err, ErrorInvalidInput) || !decision.IsZero() {
		t.Fatalf("invalid evaluation = decision %#v error %v", decision, err)
	}
}

// TestFindingLimitFailsWithoutPartialDecision verifies exact pre-count behavior.
func TestFindingLimitFailsWithoutPartialDecision(t *testing.T) {
	config := DefaultConfig()
	config.Mode = ModeTesting
	config.Limits.MaxFindings = 1
	evaluator, err := NewEvaluator(config)
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}
	decision, err := evaluator.evaluateBase(ProtocolPASS)
	if !IsErrorCode(err, ErrorLimitExceeded) || !decision.IsZero() {
		t.Fatalf("one-below evaluation = decision %#v error %v", decision, err)
	}
	var typed *Error
	if !errorsAs(err, &typed) || typed.LimitName() != limitNameFindings || typed.ConfiguredLimit() != 1 || typed.ObservedCount() != 2 {
		t.Fatalf("limit error = %#v", typed)
	}

	config.Mode = ModeStrict
	evaluator, err = NewEvaluator(config)
	if err != nil {
		t.Fatalf("NewEvaluator(strict) error = %v", err)
	}
	decision, err = evaluator.evaluateBase(ProtocolPASS)
	if err != nil || !decision.Valid() || len(decision.Findings()) != 1 {
		t.Fatalf("exact-limit decision = %#v error %v", decision, err)
	}
}

// TestDecisionAccessorsReturnCopies verifies immutable slice ownership.
func TestDecisionAccessorsReturnCopies(t *testing.T) {
	config := DefaultConfig()
	config.Mode = ModeTesting
	evaluator, err := NewEvaluator(config)
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}
	decision, err := evaluator.evaluateBase(ProtocolPASS)
	if err != nil {
		t.Fatalf("EvaluateBase() error = %v", err)
	}
	findings := decision.Findings()
	actions := decision.Actions()
	findings[0] = Finding{}
	actions[0] = Action{}
	if !decision.Findings()[0].Valid() || !decision.Actions()[0].Valid() || !decision.Valid() {
		t.Fatal("decision accessors exposed mutable storage")
	}
}

// findingReasons returns ordered reasons for matrix assertions.
func findingReasons(findings []Finding) []PolicyReason {
	reasons := make([]PolicyReason, len(findings))
	for index, finding := range findings {
		reasons[index] = finding.Reason()
	}
	return reasons
}

// errorsAs isolates standard error unwrapping for concise assertions.
func errorsAs(err error, target any) bool {
	return errors.As(err, target)
}

// mustTestFinding constructs one unsequenced test finding.
func mustTestFinding(t *testing.T, reason PolicyReason) Finding {
	t.Helper()
	finding, err := newFinding(reason, 0, false)
	if err != nil {
		t.Fatalf("newFinding(%q) error = %v", reason, err)
	}
	return finding
}
