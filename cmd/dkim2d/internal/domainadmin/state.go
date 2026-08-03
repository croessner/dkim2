package domainadmin

// OperationState identifies one persisted onboarding phase.
type OperationState string

const (
	// StatePlanned records a complete key-free plan.
	StatePlanned OperationState = "planned"
	// StatePreparing records key-generation write-ahead evidence.
	StatePreparing OperationState = "preparing"
	// StatePrepared records protected candidate-content evidence before staging.
	StatePrepared OperationState = "prepared"
	// StateStaged records exact sealed backend readback.
	StateStaged OperationState = "staged"
	// StateDNSExported records creation of the protected DNS artifact.
	StateDNSExported OperationState = "dns_exported"
	// StateDNSProven records one fresh resolver-path proof attempt.
	StateDNSProven OperationState = "dns_proven"
	// StateActivating records activation write-ahead evidence.
	StateActivating OperationState = "activating"
	// StateActivated records an exactly read-back current generation.
	StateActivated OperationState = "activated"
	// StateConflict records authoritative disagreement.
	StateConflict OperationState = "conflict"
	// StateFailed records a terminal closed workflow failure.
	StateFailed OperationState = "failed"
	// StateAborted records an authorized non-destructive stop.
	StateAborted OperationState = "aborted"
	// StateReconcileRequired records an ambiguous outcome.
	StateReconcileRequired OperationState = "reconcile_required"
)

var commands = [...]Command{
	CommandPlan, CommandPrepare, CommandDNSExport, CommandProve,
	CommandActivate, CommandStatus, CommandReconcile, CommandAbort,
}

// Known reports whether the command belongs to the closed offline vocabulary.
func (c Command) Known() bool {
	for _, candidate := range commands {
		if c == candidate {
			return true
		}
	}
	return false
}

var operationStates = [...]OperationState{
	StatePlanned, StatePreparing, StatePrepared, StateStaged, StateDNSExported,
	StateDNSProven, StateActivating, StateActivated, StateConflict, StateFailed,
	StateAborted, StateReconcileRequired,
}

// Known reports whether the state belongs to the closed vocabulary.
func (s OperationState) Known() bool {
	for _, candidate := range operationStates {
		if s == candidate {
			return true
		}
	}
	return false
}

// Terminal reports whether no workflow transition may leave the state.
func (s OperationState) Terminal() bool {
	return s == StateActivated || s == StateConflict || s == StateFailed || s == StateAborted
}

// OperationStates returns a detached closed state vocabulary.
func OperationStates() []OperationState { return append([]OperationState(nil), operationStates[:]...) }

// Command identifies one stable offline operator action.
type Command string

const (
	// CommandPlan creates key-free operation evidence.
	CommandPlan Command = "plan"
	// CommandPrepare generates and stages one complete candidate.
	CommandPrepare Command = "prepare"
	// CommandDNSExport creates a protected deterministic DNS artifact.
	CommandDNSExport Command = "dns_export"
	// CommandProve performs one fresh resolver-path proof.
	CommandProve Command = "prove"
	// CommandActivate performs an explicitly authorized pointer activation.
	CommandActivate Command = "activate"
	// CommandStatus observes journal and backend state without mutation.
	CommandStatus Command = "status"
	// CommandReconcile repairs journal knowledge from exact backend inspection.
	CommandReconcile Command = "reconcile"
	// CommandAbort records an authorized non-destructive stop.
	CommandAbort Command = "abort"
)

// MutatesJournal reports whether the command may durably advance journal knowledge.
func (c Command) MutatesJournal() bool { return c != CommandStatus }
