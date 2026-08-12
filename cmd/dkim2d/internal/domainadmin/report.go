package domainadmin

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

const reportSchema = "dkim2-domain-report-v1"

// Report is one opaque validated bounded operator result.
type Report struct {
	toolVersion            string
	command                Command
	state                  OperationState
	backend                string
	expectedCurrent        uint64
	current                uint64
	currentKnown           bool
	candidate              uint64
	credentialCount        uint32
	rsaCredentialCount     uint32
	ed25519CredentialCount uint32
	planComplete           bool
	receiptPresent         bool
	receiptPhase           ReceiptPhase
	lockRelation           LockRelation
	runtimeSmokeRequired   bool
	result                 OnboardingResultClass
	failure                ErrorCode
	initialized            bool
}

// reportDocument is the sole closed machine-output schema.
type reportDocument struct {
	Schema                    string                `json:"schema"`
	ToolVersion               string                `json:"tool_version"`
	Command                   Command               `json:"command"`
	State                     OperationState        `json:"state,omitempty"`
	Backend                   string                `json:"backend"`
	ExpectedCurrentGeneration *uint64               `json:"expected_current_generation,omitempty"`
	CurrentGeneration         *uint64               `json:"current_generation,omitempty"`
	CandidateGeneration       *uint64               `json:"candidate_generation,omitempty"`
	CredentialCount           *uint32               `json:"credential_count,omitempty"`
	RSACredentialCount        *uint32               `json:"rsa_credential_count,omitempty"`
	Ed25519CredentialCount    *uint32               `json:"ed25519_credential_count,omitempty"`
	PlanComplete              bool                  `json:"plan_complete"`
	ReceiptPresent            bool                  `json:"receipt_present,omitempty"`
	ReceiptPhase              ReceiptPhase          `json:"receipt_phase,omitempty"`
	LockRelation              LockRelation          `json:"lock_relation,omitempty"`
	RuntimeSmokeRequired      bool                  `json:"runtime_smoke_required,omitempty"`
	Result                    OnboardingResultClass `json:"result"`
	Failure                   ErrorCode             `json:"failure"`
}

// NewCommandReport validates one bounded mutating or status command result.
func NewCommandReport(
	toolVersion string,
	command Command,
	backend datasourceadmin.BackendClass,
	result OnboardingResult,
) (Report, error) {
	if command == CommandStatus {
		return Report{}, newError(CodeProtectedInput)
	}
	backendClass := string(backend)
	report := Report{
		toolVersion: toolVersion, command: command, state: result.State,
		backend: backendClass, planComplete: result.PlanComplete,
		receiptPresent: result.ReceiptPresent, receiptPhase: result.ReceiptPhase,
		expectedCurrent: result.ExpectedCurrentGeneration, current: result.CurrentGeneration,
		currentKnown: result.CurrentGenerationKnown,
		candidate:    result.CandidateGeneration, credentialCount: result.CredentialCount,
		rsaCredentialCount: result.RSACredentialCount, ed25519CredentialCount: result.Ed25519CredentialCount,
		runtimeSmokeRequired: result.RuntimeVerificationRequired,
		result:               result.Result, failure: result.Failure, initialized: true,
	}
	if !report.valid() {
		return Report{}, newError(CodeProtectedInput)
	}
	return report, nil
}

// NewStatusReport validates one bounded read-only status observation.
func NewStatusReport(
	toolVersion string,
	backend datasourceadmin.BackendClass,
	status StatusResult,
) (Report, error) {
	report := Report{
		toolVersion: toolVersion, command: CommandStatus, state: status.State,
		backend: string(backend), planComplete: status.PlanComplete,
		receiptPresent: status.ReceiptPresent, receiptPhase: status.ReceiptPhase,
		expectedCurrent: status.ExpectedCurrentGeneration, current: status.CurrentGeneration,
		currentKnown: status.CurrentGenerationKnown,
		candidate:    status.CandidateGeneration, credentialCount: status.CredentialCount,
		rsaCredentialCount: status.RSACredentialCount, ed25519CredentialCount: status.Ed25519CredentialCount,
		lockRelation: status.LockRelation, result: OnboardingResultSuccess,
		failure: status.Failure, initialized: true,
	}
	if !report.valid() {
		return Report{}, newError(CodeProtectedInput)
	}
	return report, nil
}

// EncodeReport emits only the stable machine schema or identity-free human summary.
func EncodeReport(report Report, machine bool, maximum uint32) ([]byte, error) {
	if !report.valid() || maximum == 0 || maximum > DefaultLimits().MaxDocumentBytes {
		return nil, newError(CodeProtectedInput)
	}
	document := report.document()
	var encoded []byte
	var err error
	if machine {
		encoded, err = json.Marshal(document)
		if err == nil {
			encoded = append(encoded, '\n')
		}
	} else if report.planComplete && report.currentKnown {
		encoded = fmt.Appendf(nil,
			"schema=%s tool_version=%s command=%s state=%s backend=%s expected_current_generation=%d current_generation=%d candidate_generation=%d credential_count=%d rsa_credential_count=%d ed25519_credential_count=%d plan_complete=%t receipt_present=%t receipt_phase=%s lock_relation=%s runtime_smoke_required=%t result=%s failure=%s\n",
			document.Schema, document.ToolVersion, document.Command, document.State,
			document.Backend, report.expectedCurrent, report.current,
			report.candidate, report.credentialCount, report.rsaCredentialCount,
			report.ed25519CredentialCount, document.PlanComplete, document.ReceiptPresent,
			document.ReceiptPhase, document.LockRelation, document.RuntimeSmokeRequired,
			document.Result, document.Failure,
		)
	} else if report.planComplete {
		encoded = fmt.Appendf(nil,
			"schema=%s tool_version=%s command=%s state=%s backend=%s expected_current_generation=%d candidate_generation=%d credential_count=%d rsa_credential_count=%d ed25519_credential_count=%d plan_complete=%t receipt_present=%t receipt_phase=%s lock_relation=%s runtime_smoke_required=%t result=%s failure=%s\n",
			document.Schema, document.ToolVersion, document.Command, document.State,
			document.Backend, report.expectedCurrent, report.candidate,
			report.credentialCount, report.rsaCredentialCount,
			report.ed25519CredentialCount, document.PlanComplete, document.ReceiptPresent,
			document.ReceiptPhase, document.LockRelation, document.RuntimeSmokeRequired,
			document.Result, document.Failure,
		)
	} else {
		encoded = fmt.Appendf(nil,
			"schema=%s tool_version=%s command=%s backend=%s plan_complete=%t receipt_present=%t receipt_phase=%s lock_relation=%s result=%s failure=%s\n",
			document.Schema, document.ToolVersion, document.Command, document.Backend,
			document.PlanComplete, document.ReceiptPresent, document.ReceiptPhase,
			document.LockRelation, document.Result, document.Failure,
		)
	}
	if err != nil || len(encoded) == 0 || len(encoded) > int(maximum) {
		clear(encoded)
		return nil, newError(CodeProtectedInput)
	}
	return encoded, nil
}

// document projects one already validated report into its sole serializable form.
func (r Report) document() reportDocument {
	document := reportDocument{
		Schema: reportSchema, ToolVersion: r.toolVersion, Command: r.command,
		State: r.state, Backend: r.backend, PlanComplete: r.planComplete,
		ReceiptPresent: r.receiptPresent, ReceiptPhase: r.receiptPhase,
		LockRelation: r.lockRelation, RuntimeSmokeRequired: r.runtimeSmokeRequired,
		Result: r.result, Failure: r.failure,
	}
	if r.planComplete {
		document.ExpectedCurrentGeneration = &r.expectedCurrent
		if r.currentKnown {
			document.CurrentGeneration = &r.current
		}
		document.CandidateGeneration = &r.candidate
		document.CredentialCount = &r.credentialCount
		document.RSACredentialCount = &r.rsaCredentialCount
		document.Ed25519CredentialCount = &r.ed25519CredentialCount
	}
	return document
}

// valid enforces closed enums and prevents identity-shaped free text.
func (r Report) valid() bool {
	if !r.initialized || !validReportToolVersion(r.toolVersion) || !r.command.Known() ||
		!knownAdminBackendString(r.backend) || r.state != "" && !r.state.Known() ||
		!knownOnboardingResult(r.result) || !knownErrorCode(r.failure) {
		return false
	}
	if r.command == CommandStatus {
		return r.validStatus()
	}
	return r.validWorkflow()
}

// validStatus enforces the dedicated read-only receipt or public-state report union.
func (r Report) validStatus() bool {
	if r.result != OnboardingResultSuccess {
		return false
	}
	if r.receiptPresent {
		return !r.planComplete && !r.hasOperationFacts() && knownReceiptPhase(r.receiptPhase) && r.state == "" &&
			knownLockRelation(r.lockRelation) && !r.runtimeSmokeRequired &&
			validReceiptStatusFailure(r.receiptPhase, r.failure)
	}
	return r.planComplete && r.currentKnown && r.validOperationFacts() && r.state.Known() && r.receiptPhase == "" && r.lockRelation == "" &&
		!r.runtimeSmokeRequired && validOperationStatusFailure(r.state, r.failure)
}

// validWorkflow enforces strict result/failure and receipt/public-state separation.
func (r Report) validWorkflow() bool {
	if !validReportResultFailure(r.result, r.failure) {
		return false
	}
	if r.lockRelation != "" {
		return false
	}
	if r.receiptPresent {
		if r.planComplete || r.hasOperationFacts() || !knownReceiptPhase(r.receiptPhase) || r.state != "" || r.runtimeSmokeRequired {
			return false
		}
	} else if r.receiptPhase != "" || r.planComplete != (r.state != "") || r.planComplete && !r.validOperationFacts() ||
		!r.planComplete && r.hasOperationFacts() {
		return false
	}
	runtimeSmokeRequired := r.result == OnboardingResultSuccess && r.planComplete &&
		(r.command == CommandActivate || r.command == CommandReconcile) && r.state == StateActivated
	if r.runtimeSmokeRequired != runtimeSmokeRequired {
		return false
	}
	if r.result == OnboardingResultSuccess && r.planComplete {
		if !r.currentKnown {
			return false
		}
		switch {
		case r.state == StateActivated:
			if r.current != r.candidate {
				return false
			}
		case r.command == CommandReconcile && r.state == StateConflict:
			if r.current == r.expectedCurrent || r.current == r.candidate {
				return false
			}
		default:
			if r.current != r.expectedCurrent {
				return false
			}
		}
	}
	return true
}

// hasOperationFacts reports whether any public plan-derived fact is present.
func (r Report) hasOperationFacts() bool {
	return r.expectedCurrent != 0 || r.current != 0 || r.currentKnown || r.candidate != 0 || r.credentialCount != 0 ||
		r.rsaCredentialCount != 0 || r.ed25519CredentialCount != 0
}

// validOperationFacts enforces bounded exact generation and credential relationships.
func (r Report) validOperationFacts() bool {
	return (r.currentKnown || r.current == 0) && r.candidate > r.expectedCurrent &&
		r.credentialCount >= 1 && r.credentialCount <= 2 &&
		r.rsaCredentialCount <= 1 && r.ed25519CredentialCount <= 1 &&
		r.rsaCredentialCount+r.ed25519CredentialCount == r.credentialCount
}

// validReportResultFailure enforces one exact result-to-failure correspondence.
func validReportResultFailure(result OnboardingResultClass, failure ErrorCode) bool {
	switch result {
	case OnboardingResultSuccess:
		return failure == CodeNone
	case OnboardingResultReconcile:
		return failure == CodeReconcileRequired
	case OnboardingResultFailure:
		return failure != CodeNone && failure != CodeReconcileRequired && knownErrorCode(failure)
	default:
		return false
	}
}

// validReceiptStatusFailure binds internal recovery phases to their exact observed failure class.
func validReceiptStatusFailure(phase ReceiptPhase, failure ErrorCode) bool {
	if phase == ReceiptPhaseReleaseRequired || phase == ReceiptPhaseUnresolved {
		return failure == CodeReconcileRequired
	}
	return failure == CodeNone
}

// validOperationStatusFailure binds public terminal/recovery states to persisted failure classes.
func validOperationStatusFailure(state OperationState, failure ErrorCode) bool {
	switch state {
	case StateConflict:
		return failure == CodeConflict
	case StateFailed:
		return failure == CodeKeyRecoveryUnavailable
	case StateReconcileRequired:
		return failure == CodeNone
	default:
		return failure == CodeNone
	}
}

// validReportToolVersion accepts one bounded build-owned ASCII token.
func validReportToolVersion(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '.' || character == '_' ||
			character == '+' || character == '-' {
			continue
		}
		return false
	}
	return true
}

// knownAdminBackendString accepts the four bounded output classes.
func knownAdminBackendString(value string) bool {
	return value == string(datasourceadmin.BackendLDAP) ||
		value == string(datasourceadmin.BackendPostgreSQL) ||
		value == string(datasourceadmin.BackendMySQL) ||
		value == string(datasourceadmin.BackendMariaDB)
}

// knownOnboardingResult accepts the closed command outcome classes.
func knownOnboardingResult(value OnboardingResultClass) bool {
	return value == OnboardingResultSuccess || value == OnboardingResultFailure || value == OnboardingResultReconcile
}

// knownReceiptPhase accepts the closed internal recovery phase classes.
func knownReceiptPhase(value ReceiptPhase) bool {
	return value == ReceiptPhaseClaimPending || value == ReceiptPhaseAllocating ||
		value == ReceiptPhaseReleaseRequired || value == ReceiptPhaseUnresolved || value == ReceiptPhaseClosed
}

// knownLockRelation accepts the closed receipt-to-lock classes.
func knownLockRelation(value LockRelation) bool {
	return value == LockRelationOwnerlessExact || value == LockRelationOwnedExact ||
		value == LockRelationReleasedNext || value == LockRelationOther || value == LockRelationUnavailable
}

// knownErrorCode accepts every closed administrative failure class.
func knownErrorCode(value ErrorCode) bool {
	switch value {
	case CodeNone, CodeProtectedInput, CodeInvalidIntent, CodeInvalidLimits, CodeConflict,
		CodeUnavailable, CodeReconcileRequired, CodeKeyRecoveryUnavailable, CodeDNSMissing,
		CodeDNSAmbiguous, CodeDNSInvalid, CodeDNSUnsupported, CodeDNSAlgorithmMismatch,
		CodeDNSSPKIMismatch, CodeDNSLimitExceeded, CodeDNSProofExpired:
		return true
	default:
		return false
	}
}

// String returns a constant protected report representation.
func (Report) String() string { return redacted }

// GoString returns a constant protected report representation.
func (Report) GoString() string { return redacted }

// Format prevents generic formatting from bypassing the bounded report encoder.
func (Report) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic report serialization outside EncodeReport.
func (Report) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }
