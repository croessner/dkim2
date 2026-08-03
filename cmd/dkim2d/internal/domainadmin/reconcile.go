package domainadmin

import (
	"fmt"
	"io"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// CandidateObservationClass identifies one closed authoritative candidate readback result.
type CandidateObservationClass = datasourceadmin.PublicationState

const (
	// CandidateAbsent proves the requested candidate generation does not exist.
	CandidateAbsent CandidateObservationClass = datasourceadmin.PublicationAbsent
	// CandidateExactStaging proves complete same-operation content remains writable and noncurrent.
	CandidateExactStaging CandidateObservationClass = datasourceadmin.PublicationExactStaging
	// CandidateExactCommitted proves complete same-operation content is sealed.
	CandidateExactCommitted CandidateObservationClass = datasourceadmin.PublicationExactCommitted
	// CandidatePartial reports an incomplete requested candidate.
	CandidatePartial CandidateObservationClass = datasourceadmin.PublicationPartial
	// CandidateMismatch reports complete content or ownership that differs from the operation.
	CandidateMismatch CandidateObservationClass = datasourceadmin.PublicationMismatch
	// CandidateUnknown reports an observation that cannot be authoritatively classified.
	CandidateUnknown CandidateObservationClass = datasourceadmin.PublicationUnknown
)

// BackendObservation owns one bounded exact current and requested-candidate classification.
type BackendObservation struct {
	currentGeneration   uint64
	candidateGeneration uint64
	candidateClass      CandidateObservationClass
	operation           datasourceadmin.OperationBinding
	staged              datasourceadmin.StagedEvidence
	oldCurrentWasActive bool
}

// NewBackendObservation constructs one closed authoritative reconciliation input.
func NewBackendObservation(
	currentGeneration uint64,
	candidateGeneration uint64,
	candidateClass CandidateObservationClass,
	operation datasourceadmin.OperationBinding,
	staged datasourceadmin.StagedEvidence,
	oldCurrentWasActive bool,
) (BackendObservation, error) {
	observation := BackendObservation{
		currentGeneration: currentGeneration, candidateGeneration: candidateGeneration,
		candidateClass: candidateClass, operation: operation, staged: staged,
		oldCurrentWasActive: oldCurrentWasActive,
	}
	if !observation.valid() {
		return BackendObservation{}, newError(CodeConflict)
	}
	return observation, nil
}

// backendObservationFromPublication maps one validated provider-neutral observation without weakening evidence.
func backendObservationFromPublication(value datasourceadmin.PublicationObservation) (BackendObservation, error) {
	if !value.Valid() {
		return BackendObservation{}, newError(CodeConflict)
	}
	return NewBackendObservation(
		value.CurrentGeneration(), value.CandidateGeneration(), value.State(), value.Operation(),
		value.Staged(), value.OldCurrentWasActive(),
	)
}

// valid enforces the closed relationship between classification and exact evidence.
func (o BackendObservation) valid() bool {
	if o.candidateGeneration == 0 || o.currentGeneration == 0 && o.oldCurrentWasActive {
		return false
	}
	exact := o.candidateClass == CandidateExactStaging || o.candidateClass == CandidateExactCommitted
	knownNonexact := o.candidateClass == CandidateAbsent || o.candidateClass == CandidatePartial ||
		o.candidateClass == CandidateMismatch || o.candidateClass == CandidateUnknown
	if exact {
		return o.operation.Initialized() && o.staged.Digest().Valid()
	}
	return knownNonexact && !o.operation.Initialized() && !o.staged.Digest().Valid() && !o.oldCurrentWasActive
}

// String returns a constant protected backend-observation representation.
func (BackendObservation) String() string { return redacted }

// GoString returns a constant protected backend-observation representation.
func (BackendObservation) GoString() string { return redacted }

// Format prevents protected reconciliation evidence from reaching formatting sinks.
func (BackendObservation) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic backend-observation serialization.
func (BackendObservation) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }

// CurrentRelation is one bounded status relationship to the journal plan.
type CurrentRelation string

const (
	// CurrentExpected reports that the backend pointer still equals the plan fence.
	CurrentExpected CurrentRelation = "expected"
	// CurrentCandidate reports that the candidate is current.
	CurrentCandidate CurrentRelation = "candidate"
	// CurrentThirdParty reports a different current generation.
	CurrentThirdParty CurrentRelation = "third_party"
)

// StatusResult contains identity-free bounded journal and backend observation classes.
type StatusResult struct {
	State                     OperationState
	Revision                  uint64
	Candidate                 CandidateObservationClass
	Current                   CurrentRelation
	Failure                   ErrorCode
	ExpectedCurrentGeneration uint64
	CurrentGeneration         uint64
	CurrentGenerationKnown    bool
	CandidateGeneration       uint64
	CredentialCount           uint32
	RSACredentialCount        uint32
	Ed25519CredentialCount    uint32
	PlanComplete              bool
	ReceiptPresent            bool
	ReceiptPhase              ReceiptPhase
	LockRelation              LockRelation
}

// ReceiptPhase is one bounded internal pre-plan recovery phase.
type ReceiptPhase string

const (
	// ReceiptPhaseClaimPending reports durable pre-claim evidence.
	ReceiptPhaseClaimPending ReceiptPhase = "claim_pending"
	// ReceiptPhaseAllocating reports an exact durably acknowledged claim.
	ReceiptPhaseAllocating ReceiptPhase = "allocating"
	// ReceiptPhaseReleaseRequired reports cleanup gated on explicit reconciliation.
	ReceiptPhaseReleaseRequired ReceiptPhase = "release_required"
	// ReceiptPhaseUnresolved reports foreign, malformed, skipped, or unavailable evidence.
	ReceiptPhaseUnresolved ReceiptPhase = "unresolved"
	// ReceiptPhaseClosed reports a retained ownerless tombstone.
	ReceiptPhaseClosed ReceiptPhase = "closed"
)

// LockRelation is one bounded receipt-to-administration-lock relationship.
type LockRelation string

const (
	// LockRelationOwnerlessExact reports ownerless receipt revision R.
	LockRelationOwnerlessExact LockRelation = "ownerless_exact"
	// LockRelationOwnedExact reports exact receipt operation ownership at R.
	LockRelationOwnedExact LockRelation = "owned_exact"
	// LockRelationReleasedNext reports ownerless R+1 cleanup evidence.
	LockRelationReleasedNext LockRelation = "released_next"
	// LockRelationOther reports any foreign or skipped exact observation.
	LockRelationOther LockRelation = "other"
	// LockRelationUnavailable reports unavailable or malformed authority evidence.
	LockRelationUnavailable LockRelation = "unavailable"
)

// ObserveStatus returns a nonmutating bounded journal/backend classification.
func ObserveStatus(
	journal *Journal,
	authority datasourceadmin.AuthorityDescriptor,
	observation BackendObservation,
) (StatusResult, error) {
	if journal == nil || !observation.valid() {
		return StatusResult{}, newError(CodeConflict)
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.closed || !authorityEqual(journal.plan.authority, authority) ||
		observation.candidateGeneration != journal.plan.candidateGeneration {
		return StatusResult{}, newError(CodeConflict)
	}
	facts, ok := planReportFactsLocked(journal.plan)
	if !ok {
		return StatusResult{}, newError(CodeConflict)
	}
	return StatusResult{
		State: journal.state, Revision: journal.revision, Candidate: observation.candidateClass,
		Current: currentRelation(journal.plan, observation.currentGeneration), Failure: journal.failure,
		ExpectedCurrentGeneration: facts.expected, CurrentGeneration: observation.currentGeneration,
		CurrentGenerationKnown: true,
		CandidateGeneration:    facts.candidate, CredentialCount: facts.credentials,
		RSACredentialCount: facts.rsa, Ed25519CredentialCount: facts.ed25519,
		PlanComplete: true,
	}, nil
}

// ReconcileOutcome is one bounded explicit recovery result.
type ReconcileOutcome string

const (
	// ReconcileUnchanged reports an idempotent observation with no knowledge change.
	ReconcileUnchanged ReconcileOutcome = "unchanged"
	// ReconcileAdvanced reports journal knowledge advanced from exact readback.
	ReconcileAdvanced ReconcileOutcome = "advanced"
	// ReconcileAmbiguous reports retained uncertainty.
	ReconcileAmbiguous ReconcileOutcome = "ambiguous"
	// ReconcileConflicted reports an authoritative third-party disagreement.
	ReconcileConflicted ReconcileOutcome = "conflicted"
)

// ReconcileResult contains bounded follow-up requirements but performs no backend mutation.
type ReconcileResult struct {
	State            OperationState
	Outcome          ReconcileOutcome
	ReleaseClaim     bool
	RequiresDNSProof bool
}

// Reconcile updates journal knowledge only from exact authoritative readback and never retries mutation.
func Reconcile(
	journal *Journal,
	authority datasourceadmin.AuthorityDescriptor,
	observation BackendObservation,
) (ReconcileResult, error) {
	if journal == nil || !observation.valid() {
		return ReconcileResult{}, newError(CodeConflict)
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.closed || !authorityEqual(journal.plan.authority, authority) ||
		observation.candidateGeneration != journal.plan.candidateGeneration {
		return ReconcileResult{}, newError(CodeConflict)
	}
	if journal.state.Terminal() {
		return reconcileTerminalLocked(journal, observation)
	}
	relation := currentRelation(journal.plan, observation.currentGeneration)
	switch relation {
	case CurrentCandidate:
		return reconcileCurrentCandidateLocked(journal, observation), nil
	case CurrentExpected:
		return reconcileExpectedCurrentLocked(journal, observation), nil
	case CurrentThirdParty:
		origin := journal.state
		if origin == StateReconcileRequired {
			origin = journal.reconcileFrom
		}
		journal.state = StateConflict
		journal.failure = CodeConflict
		journal.reconcileFrom = origin
		return ReconcileResult{State: StateConflict, Outcome: ReconcileConflicted}, nil
	default:
		return ReconcileResult{}, newError(CodeConflict)
	}
}

// reconcileTerminalLocked proves idempotent terminal observations without changing journal state.
func reconcileTerminalLocked(journal *Journal, observation BackendObservation) (ReconcileResult, error) {
	if journal.state == StateActivated && currentRelation(journal.plan, observation.currentGeneration) == CurrentCandidate &&
		exactCandidateMatches(journal, observation, CandidateExactCommitted) &&
		journal.activation.validFor(journal.plan, journal.staged) &&
		activationHistoryMatches(journal.plan, observation) {
		return ReconcileResult{State: StateActivated, Outcome: ReconcileUnchanged}, nil
	}
	if journal.state == StateConflict && currentRelation(journal.plan, observation.currentGeneration) == CurrentThirdParty {
		return ReconcileResult{State: journal.state, Outcome: ReconcileUnchanged}, nil
	}
	if journal.state == StateFailed && currentRelation(journal.plan, observation.currentGeneration) == CurrentExpected &&
		observation.candidateClass == CandidateAbsent {
		return ReconcileResult{State: journal.state, Outcome: ReconcileUnchanged}, nil
	}
	if journal.state == StateAborted && currentRelation(journal.plan, observation.currentGeneration) == CurrentExpected &&
		(observation.candidateClass == CandidateAbsent || exactCandidateMatches(journal, observation, CandidateExactStaging)) {
		return ReconcileResult{State: journal.state, Outcome: ReconcileUnchanged}, nil
	}
	return ReconcileResult{}, newError(CodeConflict)
}

// reconcileCurrentCandidateLocked accepts activation only from exact write-ahead lineage.
func reconcileCurrentCandidateLocked(journal *Journal, observation BackendObservation) ReconcileResult {
	fromActivating := journal.state == StateActivating ||
		journal.state == StateReconcileRequired && journal.reconcileFrom == StateActivating
	if fromActivating && exactCandidateMatches(journal, observation, CandidateExactCommitted) &&
		journal.activation.validFor(journal.plan, journal.staged) &&
		activationHistoryMatches(journal.plan, observation) {
		journal.state = StateActivated
		journal.reconcileFrom = ""
		return ReconcileResult{State: StateActivated, Outcome: ReconcileAdvanced}
	}
	markReconcileRequiredLocked(journal)
	return ReconcileResult{State: StateReconcileRequired, Outcome: ReconcileAmbiguous}
}

// reconcileExpectedCurrentLocked classifies noncurrent candidate crash windows without mutation retry.
func reconcileExpectedCurrentLocked(journal *Journal, observation BackendObservation) ReconcileResult {
	origin := journal.state
	if origin == StateReconcileRequired {
		origin = journal.reconcileFrom
	}
	switch observation.candidateClass {
	case CandidateExactCommitted:
		if exactCandidateMatches(journal, observation, CandidateExactCommitted) {
			switch origin {
			case StatePrepared, StateActivating:
				journal.staged = observation.staged
				journal.state = StateStaged
				journal.reconcileFrom = ""
				journal.activation = nil
				journal.failure = CodeNone
				return ReconcileResult{
					State: StateStaged, Outcome: ReconcileAdvanced, ReleaseClaim: true, RequiresDNSProof: true,
				}
			case StateStaged, StateDNSExported, StateDNSProven:
				wasReconcile := journal.state == StateReconcileRequired
				journal.state = origin
				journal.reconcileFrom = ""
				journal.failure = CodeNone
				outcome := ReconcileUnchanged
				if wasReconcile {
					outcome = ReconcileAdvanced
				}
				return ReconcileResult{State: origin, Outcome: outcome}
			}
		}
	case CandidateExactStaging:
		if origin == StatePrepared && exactCandidateMatches(journal, observation, CandidateExactStaging) {
			journal.staged = datasourceadmin.StagedEvidence{}
			journal.state = StatePrepared
			journal.reconcileFrom = ""
			journal.activation = nil
			journal.failure = CodeNone
			return ReconcileResult{State: StatePrepared, Outcome: ReconcileAdvanced, ReleaseClaim: true}
		}
	case CandidateAbsent:
		if origin == StatePrepared {
			journal.reconcileFrom = origin
			if journal.recordKeyRecoveryFailureLocked() == nil {
				return ReconcileResult{State: StateFailed, Outcome: ReconcileAdvanced, ReleaseClaim: true}
			}
		}
		if origin == StatePlanned || origin == StatePreparing {
			wasReconcile := journal.state == StateReconcileRequired
			journal.state = origin
			journal.reconcileFrom = ""
			outcome := ReconcileUnchanged
			if wasReconcile {
				outcome = ReconcileAdvanced
			}
			return ReconcileResult{State: origin, Outcome: outcome}
		}
	}
	markReconcileRequiredLocked(journal)
	return ReconcileResult{State: StateReconcileRequired, Outcome: ReconcileAmbiguous}
}

// activationHistoryMatches enforces the exact empty-bootstrap or durable old-current branch.
func activationHistoryMatches(plan *Plan, observation BackendObservation) bool {
	return plan.expectedCurrent == 0 && !observation.oldCurrentWasActive ||
		plan.expectedCurrent != 0 && observation.oldCurrentWasActive
}

// exactCandidateMatches proves operation, generation, phase, and digest equality.
func exactCandidateMatches(
	journal *Journal,
	observation BackendObservation,
	want CandidateObservationClass,
) bool {
	return observation.candidateClass == want && observation.candidateGeneration == journal.plan.candidateGeneration &&
		observation.operation.Equal(journal.plan.operation) && journal.prepared.Matches(observation.staged)
}

// markReconcileRequiredLocked retains the first exact ambiguous origin phase.
func markReconcileRequiredLocked(journal *Journal) {
	if journal.state != StateReconcileRequired {
		journal.reconcileFrom = journal.state
	}
	journal.state = StateReconcileRequired
	journal.failure = CodeNone
}

// currentRelation compares only bounded generation numbers from exact readback.
func currentRelation(plan *Plan, current uint64) CurrentRelation {
	if current == plan.candidateGeneration {
		return CurrentCandidate
	}
	if current == plan.expectedCurrent {
		return CurrentExpected
	}
	return CurrentThirdParty
}
