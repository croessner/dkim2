package domainadmin

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

const (
	reportForbiddenCount      = "count"
	reportForbiddenGeneration = "generation"
	reportForbiddenRevision   = "revision"
)

// TestDomainReportsHaveClosedBoundedMachineAndHumanSchemas freezes the operator output vocabulary.
func TestDomainReportsHaveClosedBoundedMachineAndHumanSchemas(t *testing.T) {
	report, err := NewCommandReport("test-version", CommandActivate, datasourceadmin.BackendLDAP, OnboardingResult{
		State: StateActivated, Result: OnboardingResultSuccess, Failure: CodeNone,
		ExpectedCurrentGeneration: 7, CurrentGeneration: 8, CurrentGenerationKnown: true, CandidateGeneration: 8,
		CredentialCount: 2, RSACredentialCount: 1, Ed25519CredentialCount: 1,
		RuntimeVerificationRequired: true, PlanComplete: true,
	})
	if err != nil {
		t.Fatal("construct bounded command report")
	}
	machine, err := EncodeReport(report, true, 4096)
	if err != nil {
		t.Fatal("encode bounded machine report")
	}
	want := "{\"schema\":\"dkim2-domain-report-v1\",\"tool_version\":\"test-version\",\"command\":\"activate\",\"state\":\"activated\",\"backend\":\"ldap\",\"expected_current_generation\":7,\"current_generation\":8,\"candidate_generation\":8,\"credential_count\":2,\"rsa_credential_count\":1,\"ed25519_credential_count\":1,\"plan_complete\":true,\"runtime_smoke_required\":true,\"result\":\"success\",\"failure\":\"none\"}\n"
	if string(machine) != want {
		t.Fatal("machine report schema drifted")
	}
	var decoded map[string]any
	if json.Unmarshal(machine, &decoded) != nil || len(decoded) != 15 {
		t.Fatal("machine report admitted an unknown field")
	}
	human, err := EncodeReport(report, false, 4096)
	if err != nil || !bytes.Contains(human, []byte("runtime_smoke_required=true")) ||
		bytes.Contains(human, []byte("verified")) {
		t.Fatal("human report made an unsupported runtime verification claim")
	}
}

// TestReceiptStatusReportExposesOnlyBoundedRecoveryClasses freezes identity-free pre-plan output.
func TestReceiptStatusReportExposesOnlyBoundedRecoveryClasses(t *testing.T) {
	report, err := NewStatusReport("test-version", datasourceadmin.BackendPostgreSQL, StatusResult{
		PlanComplete: false, ReceiptPresent: true, ReceiptPhase: ReceiptPhaseReleaseRequired,
		LockRelation: LockRelationOwnedExact, Failure: CodeReconcileRequired,
	})
	if err != nil {
		t.Fatal("construct receipt status report")
	}
	encoded, err := EncodeReport(report, true, 4096)
	if err != nil {
		t.Fatal("encode receipt status report")
	}
	var decoded map[string]any
	if json.Unmarshal(encoded, &decoded) != nil {
		t.Fatal("decode receipt status report")
	}
	allowed := map[string]bool{
		"schema": true, "tool_version": true, "command": true, "backend": true,
		"plan_complete": true, "receipt_present": true, "receipt_phase": true,
		"lock_relation": true, "result": true, "failure": true,
	}
	for key := range decoded {
		if !allowed[key] {
			t.Fatal("receipt status exposed an unapproved field")
		}
	}
	for _, required := range []string{"\"receipt_present\":true", "\"receipt_phase\":\"release_required\"", "\"lock_relation\":\"owned_exact\""} {
		if !bytes.Contains(encoded, []byte(required)) {
			t.Fatal("receipt status omitted a bounded recovery class")
		}
	}
	human, err := EncodeReport(report, false, 4096)
	if err != nil {
		t.Fatal("encode human receipt status report")
	}
	for _, forbidden := range []string{"state=", reportForbiddenGeneration, reportForbiddenCount, reportForbiddenRevision} {
		if bytes.Contains(human, []byte(forbidden)) {
			t.Fatal("receipt-only human status exposed public operation facts")
		}
	}
}

// TestWorkflowReceiptHumanReportOmitsPublicOperationFacts freezes the receipt union in both encodings.
func TestWorkflowReceiptHumanReportOmitsPublicOperationFacts(t *testing.T) {
	report, err := NewCommandReport("test-version", CommandAbort, datasourceadmin.BackendLDAP, OnboardingResult{
		Result: OnboardingResultSuccess, Failure: CodeNone,
		ReceiptPresent: true, ReceiptPhase: ReceiptPhaseClosed,
	})
	if err != nil {
		t.Fatal("construct workflow receipt report")
	}
	human, err := EncodeReport(report, false, 4096)
	if err != nil {
		t.Fatal("encode workflow receipt report")
	}
	for _, forbidden := range []string{"state=", reportForbiddenGeneration, reportForbiddenCount, reportForbiddenRevision} {
		if bytes.Contains(human, []byte(forbidden)) {
			t.Fatal("workflow receipt human output exposed public operation facts")
		}
	}
	machine, err := EncodeReport(report, true, 4096)
	if err != nil {
		t.Fatal("encode workflow receipt machine report")
	}
	for _, forbidden := range []string{"\"state\"", reportForbiddenGeneration, reportForbiddenCount, reportForbiddenRevision} {
		if bytes.Contains(machine, []byte(forbidden)) {
			t.Fatal("workflow receipt machine output exposed public operation facts")
		}
	}
}

// TestEmptyBackendReportKeepsAuthoritativeZeroGenerations freezes full-operation presence semantics.
func TestEmptyBackendReportKeepsAuthoritativeZeroGenerations(t *testing.T) {
	report, err := NewCommandReport("test-version", CommandPrepare, datasourceadmin.BackendLDAP, OnboardingResult{
		State: StateStaged, Result: OnboardingResultSuccess, Failure: CodeNone,
		ExpectedCurrentGeneration: 0, CurrentGeneration: 0, CurrentGenerationKnown: true, CandidateGeneration: 1,
		CredentialCount: 1, Ed25519CredentialCount: 1, PlanComplete: true,
	})
	if err != nil {
		t.Fatal("construct empty-backend full-operation report")
	}
	machine, err := EncodeReport(report, true, 4096)
	if err != nil || !bytes.Contains(machine, []byte("\"expected_current_generation\":0")) ||
		!bytes.Contains(machine, []byte("\"current_generation\":0")) {
		t.Fatal("full-operation report omitted authoritative zero generations")
	}
}

// TestUnknownWorkflowCurrentGenerationIsOmitted reproduces unknown-current laundering as zero.
func TestUnknownWorkflowCurrentGenerationIsOmitted(t *testing.T) {
	tests := []OnboardingResult{
		{
			State: StateStaged, Result: OnboardingResultFailure, Failure: CodeUnavailable,
			ExpectedCurrentGeneration: 7, CandidateGeneration: 8,
			CredentialCount: 1, Ed25519CredentialCount: 1, PlanComplete: true,
		},
		{
			State: StateConflict, Result: OnboardingResultReconcile, Failure: CodeReconcileRequired,
			ExpectedCurrentGeneration: 7, CandidateGeneration: 8,
			CredentialCount: 1, Ed25519CredentialCount: 1, PlanComplete: true,
		},
	}
	for _, result := range tests {
		report, err := NewCommandReport("test-version", CommandReconcile, datasourceadmin.BackendLDAP, result)
		if err != nil {
			t.Fatal("construct unknown-current workflow report")
		}
		machine, machineErr := EncodeReport(report, true, 4096)
		human, humanErr := EncodeReport(report, false, 4096)
		if machineErr != nil || humanErr != nil {
			t.Fatal("encode unknown-current workflow report")
		}
		if bytes.Contains(machine, []byte("\"current_generation\":")) ||
			bytes.Contains(human, []byte(" current_generation=")) {
			t.Fatal("unknown workflow current generation was laundered as authoritative zero")
		}
	}
}

// TestStatusReportPreservesKnownZeroAndThirdPartyCurrent freezes authoritative status values.
func TestStatusReportPreservesKnownZeroAndThirdPartyCurrent(t *testing.T) {
	tests := []struct {
		status StatusResult
		want   string
	}{
		{
			status: StatusResult{
				State: StatePlanned, Failure: CodeNone, ExpectedCurrentGeneration: 0,
				CurrentGeneration: 0, CurrentGenerationKnown: true, CandidateGeneration: 1,
				CredentialCount: 1, Ed25519CredentialCount: 1, PlanComplete: true,
			},
			want: "\"current_generation\":0",
		},
		{
			status: StatusResult{
				State: StatePlanned, Failure: CodeNone, ExpectedCurrentGeneration: 7,
				CurrentGeneration: 99, CurrentGenerationKnown: true, CandidateGeneration: 8,
				CredentialCount: 1, Ed25519CredentialCount: 1, PlanComplete: true,
			},
			want: "\"current_generation\":99",
		},
	}
	for _, test := range tests {
		report, err := NewStatusReport("test-version", datasourceadmin.BackendLDAP, test.status)
		if err != nil {
			t.Fatal("construct authoritative status report")
		}
		machine, err := EncodeReport(report, true, 4096)
		if err != nil || !bytes.Contains(machine, []byte(test.want)) {
			t.Fatal("status report omitted its authoritative current generation")
		}
	}
}

// TestReconcileConflictSuccessRequiresKnownThirdPartyCurrent freezes its unique success relation.
func TestReconcileConflictSuccessRequiresKnownThirdPartyCurrent(t *testing.T) {
	base := OnboardingResult{
		State: StateConflict, Result: OnboardingResultSuccess, Failure: CodeNone,
		ExpectedCurrentGeneration: 7, CurrentGenerationKnown: true, CandidateGeneration: 8,
		CredentialCount: 1, Ed25519CredentialCount: 1, PlanComplete: true,
	}
	for _, current := range []uint64{7, 8} {
		candidate := base
		candidate.CurrentGeneration = current
		if report, err := NewCommandReport(
			"test-version", CommandReconcile, datasourceadmin.BackendLDAP, candidate,
		); err == nil || report.initialized {
			t.Fatal("terminal-conflict reconciliation accepted a non-third-party current")
		}
	}
	base.CurrentGeneration = 99
	if report, err := NewCommandReport(
		"test-version", CommandReconcile, datasourceadmin.BackendLDAP, base,
	); err != nil || !report.valid() {
		t.Fatal("terminal-conflict reconciliation rejected its known third-party current")
	}
	for _, command := range []Command{
		CommandPlan, CommandPrepare, CommandDNSExport, CommandProve,
		CommandActivate, CommandReconcile, CommandAbort,
	} {
		candidate := base
		candidate.State = StateStaged
		if report, err := NewCommandReport(
			"test-version", command, datasourceadmin.BackendLDAP, candidate,
		); err == nil || report.initialized {
			t.Fatal("ordinary pre-activation success admitted a third-party current")
		}
	}
}

// TestRuntimeSmokeRequiredIsExactActivatedWorkflowInvariant freezes the post-activation duty.
func TestRuntimeSmokeRequiredIsExactActivatedWorkflowInvariant(t *testing.T) {
	activated := OnboardingResult{
		State: StateActivated, Result: OnboardingResultSuccess, Failure: CodeNone,
		ExpectedCurrentGeneration: 7, CurrentGeneration: 8, CurrentGenerationKnown: true,
		CandidateGeneration: 8, CredentialCount: 1, Ed25519CredentialCount: 1,
		RuntimeVerificationRequired: true, PlanComplete: true,
	}
	for _, command := range []Command{CommandActivate, CommandReconcile} {
		if report, err := NewCommandReport(
			"test-version", command, datasourceadmin.BackendLDAP, activated,
		); err != nil || !report.valid() {
			t.Fatal("activated workflow rejected mandatory runtime smoke")
		}
		missing := activated
		missing.RuntimeVerificationRequired = false
		if report, err := NewCommandReport(
			"test-version", command, datasourceadmin.BackendLDAP, missing,
		); err == nil || report.initialized {
			t.Fatal("activated workflow accepted missing runtime smoke")
		}
	}
	nonactivated := activated
	nonactivated.State = StateStaged
	nonactivated.CurrentGeneration = nonactivated.ExpectedCurrentGeneration
	for _, command := range []Command{
		CommandPlan, CommandPrepare, CommandDNSExport, CommandProve,
		CommandActivate, CommandReconcile, CommandAbort,
	} {
		if report, err := NewCommandReport(
			"test-version", command, datasourceadmin.BackendLDAP, nonactivated,
		); err == nil || report.initialized {
			t.Fatal("nonactivated workflow admitted runtime smoke")
		}
	}
}

// TestDomainReportsRejectToxicAndGenericSinks proves identity-bearing strings cannot enter output.
func TestDomainReportsRejectToxicAndGenericSinks(t *testing.T) {
	toxic := []string{
		"tenant@example.test", "selector/toxic", "operation=toxic", "/protected/op.json",
		"sha256:deadbeef", "cn=admin,dc=example", "SELECT toxic", "ldaps://toxic",
		"password=toxic", "-----BEGIN PRIVATE KEY-----", "v=DKIM1; p=toxic",
	}
	for _, marker := range toxic {
		if report, err := NewCommandReport(marker, CommandActivate, datasourceadmin.BackendLDAP, OnboardingResult{
			State: StateActivated, PlanComplete: true, RuntimeVerificationRequired: true,
			ExpectedCurrentGeneration: 7, CurrentGeneration: 8, CurrentGenerationKnown: true, CandidateGeneration: 8,
			CredentialCount: 2, RSACredentialCount: 1, Ed25519CredentialCount: 1,
			Result: OnboardingResultSuccess, Failure: CodeNone,
		}); err == nil || report.initialized {
			t.Fatal("toxic tool version entered a report")
		}
	}
	valid, err := NewCommandReport("v1.2.3", CommandActivate, datasourceadmin.BackendLDAP, OnboardingResult{
		State: StateActivated, PlanComplete: true, RuntimeVerificationRequired: true,
		ExpectedCurrentGeneration: 7, CurrentGeneration: 8, CurrentGenerationKnown: true, CandidateGeneration: 8,
		CredentialCount: 2, RSACredentialCount: 1, Ed25519CredentialCount: 1,
		Result: OnboardingResultSuccess, Failure: CodeNone,
	})
	if err != nil {
		t.Fatal("construct valid generic-sink fixture")
	}
	for _, rendered := range []string{valid.String(), valid.GoString()} {
		if strings.Contains(rendered, "v1.2.3") || rendered != redacted {
			t.Fatal("generic report formatting exposed report facts")
		}
	}
	if encoded, err := json.Marshal(valid); err == nil || len(encoded) != 0 {
		t.Fatal("generic report JSON bypassed the bounded encoder")
	}
}

// TestStatusReportAcceptsExactPersistedJournalFailureInvariants uses real journal fixtures.
func TestStatusReportAcceptsExactPersistedJournalFailureInvariants(t *testing.T) {
	reconcileJournal, reconcilePlan := plannedJournalFixture(t)
	defer reconcileJournal.Close() //nolint:errcheck // Test cleanup has no recovery action.
	defer reconcilePlan.Close()    //nolint:errcheck // Test cleanup has no recovery action.
	reconcileJournal.mu.Lock()
	reconcileJournal.state = StateReconcileRequired
	reconcileJournal.reconcileFrom = StatePlanned
	reconcileJournal.failure = CodeNone
	reconcileJournal.mu.Unlock()
	if !journalRecordValid(reconcileJournal, 2) {
		t.Fatal("real reconcile journal fixture is invalid")
	}
	if report, err := NewStatusReport("v1", datasourceadmin.BackendLDAP, StatusResult{
		State: StateReconcileRequired, PlanComplete: true, Failure: CodeNone,
		ExpectedCurrentGeneration: 7, CurrentGeneration: 7, CurrentGenerationKnown: true, CandidateGeneration: 8,
		CredentialCount: 2, RSACredentialCount: 1, Ed25519CredentialCount: 1,
	}); err != nil || !report.valid() {
		t.Fatal("valid reconcile-required journal status was rejected")
	}

	failedJournal, failedPlan := preparedJournalFixture(t)
	defer failedJournal.Close() //nolint:errcheck // Test cleanup has no recovery action.
	defer failedPlan.Close()    //nolint:errcheck // Test cleanup has no recovery action.
	failedJournal.mu.Lock()
	failedJournal.state = StateFailed
	failedJournal.reconcileFrom = StatePrepared
	failedJournal.failure = CodeKeyRecoveryUnavailable
	failedJournal.mu.Unlock()
	if !journalRecordValid(failedJournal, 2) {
		t.Fatal("real failed journal fixture is invalid")
	}
	if report, err := NewStatusReport("v1", datasourceadmin.BackendLDAP, StatusResult{
		State: StateFailed, PlanComplete: true, Failure: CodeKeyRecoveryUnavailable,
		ExpectedCurrentGeneration: 7, CurrentGeneration: 7, CurrentGenerationKnown: true, CandidateGeneration: 8,
		CredentialCount: 2, RSACredentialCount: 1, Ed25519CredentialCount: 1,
	}); err != nil || !report.valid() {
		t.Fatal("valid key-recovery journal status was rejected")
	}
}

// TestDomainReportRejectsCrossFieldContradictions freezes result, state, and receipt consistency.
func TestDomainReportRejectsCrossFieldContradictions(t *testing.T) {
	tests := []Report{
		{toolVersion: "v1", command: CommandPrepare, backend: testBackendLDAP, result: OnboardingResultSuccess, failure: CodeConflict, initialized: true},
		{toolVersion: "v1", command: CommandPrepare, backend: testBackendLDAP, result: OnboardingResultFailure, failure: CodeNone, initialized: true},
		{toolVersion: "v1", command: CommandPrepare, backend: testBackendLDAP, result: OnboardingResultReconcile, failure: CodeConflict, initialized: true},
		{toolVersion: "v1", command: CommandStatus, backend: testBackendLDAP, result: OnboardingResultSuccess, failure: CodeNone, initialized: true},
		{toolVersion: "v1", command: CommandStatus, backend: testBackendLDAP, planComplete: true, state: StatePlanned, lockRelation: LockRelationOther, result: OnboardingResultSuccess, failure: CodeNone, initialized: true},
		{toolVersion: "v1", command: CommandAbort, backend: testBackendLDAP, receiptPresent: true, receiptPhase: ReceiptPhaseClosed, lockRelation: LockRelationOwnerlessExact, result: OnboardingResultSuccess, failure: CodeNone, initialized: true},
		{toolVersion: "v1", command: CommandAbort, backend: testBackendLDAP, receiptPresent: true, receiptPhase: ReceiptPhaseClosed, candidate: 8, credentialCount: 1, ed25519CredentialCount: 1, result: OnboardingResultSuccess, failure: CodeNone, initialized: true},
		{toolVersion: "v1", command: CommandPrepare, backend: testBackendLDAP, planComplete: true, state: StateStaged, expectedCurrent: 7, current: 7, currentKnown: true, candidate: 8, credentialCount: 2, rsaCredentialCount: 2, result: OnboardingResultSuccess, failure: CodeNone, initialized: true},
		{toolVersion: "v1", command: CommandPrepare, backend: testBackendLDAP, planComplete: true, state: StateStaged, expectedCurrent: 7, current: 0, currentKnown: true, candidate: 8, credentialCount: 1, ed25519CredentialCount: 1, result: OnboardingResultSuccess, failure: CodeNone, initialized: true},
		{toolVersion: "v1", command: CommandActivate, backend: testBackendLDAP, planComplete: true, state: StateActivated, expectedCurrent: 7, current: 7, currentKnown: true, candidate: 8, credentialCount: 1, ed25519CredentialCount: 1, result: OnboardingResultSuccess, failure: CodeNone, initialized: true},
		{toolVersion: "v1", command: CommandPrepare, backend: testBackendLDAP, planComplete: true, state: StateStaged, expectedCurrent: 7, current: 7, candidate: 8, credentialCount: 1, ed25519CredentialCount: 1, result: OnboardingResultSuccess, failure: CodeNone, initialized: true},
		{toolVersion: "v1", command: CommandPrepare, backend: testBackendLDAP, planComplete: true, state: StateStaged, expectedCurrent: 7, current: 9, currentKnown: true, candidate: 8, credentialCount: 1, ed25519CredentialCount: 1, result: OnboardingResultSuccess, failure: CodeNone, initialized: true},
		{toolVersion: "v1", command: CommandStatus, backend: testBackendLDAP, planComplete: true, state: StateStaged, expectedCurrent: 7, current: 7, candidate: 8, credentialCount: 1, ed25519CredentialCount: 1, result: OnboardingResultSuccess, failure: CodeNone, initialized: true},
		{toolVersion: "v1", command: CommandReconcile, backend: testBackendLDAP, planComplete: true, state: StateConflict, expectedCurrent: 7, current: 9, candidate: 8, credentialCount: 1, ed25519CredentialCount: 1, result: OnboardingResultReconcile, failure: CodeReconcileRequired, initialized: true},
	}
	for _, report := range tests {
		if report.valid() {
			t.Fatal("semantically contradictory report was accepted")
		}
	}
	if report, err := NewCommandReport("v1", CommandStatus, datasourceadmin.BackendLDAP, OnboardingResult{Result: OnboardingResultSuccess, Failure: CodeNone}); err == nil || report.initialized {
		t.Fatal("status bypassed its dedicated constructor")
	}
	unknownSuccess := OnboardingResult{
		State: StateStaged, Result: OnboardingResultSuccess, Failure: CodeNone,
		ExpectedCurrentGeneration: 7, CurrentGeneration: 7, CandidateGeneration: 8,
		CredentialCount: 1, Ed25519CredentialCount: 1, PlanComplete: true,
	}
	if report, err := NewCommandReport("v1", CommandPrepare, datasourceadmin.BackendLDAP, unknownSuccess); err == nil || report.initialized {
		t.Fatal("successful workflow admitted an unknown current generation")
	}
	unknownSuccess.CurrentGenerationKnown = true
	unknownSuccess.CurrentGeneration = 9
	if report, err := NewCommandReport("v1", CommandPrepare, datasourceadmin.BackendLDAP, unknownSuccess); err == nil || report.initialized {
		t.Fatal("successful workflow admitted a contradictory known current generation")
	}
	if report, err := NewStatusReport("v1", datasourceadmin.BackendLDAP, StatusResult{
		State: StateStaged, Failure: CodeNone, ExpectedCurrentGeneration: 7,
		CurrentGeneration: 7, CandidateGeneration: 8,
		CredentialCount: 1, Ed25519CredentialCount: 1, PlanComplete: true,
	}); err == nil || report.initialized {
		t.Fatal("full status admitted an unknown current generation")
	}
}
