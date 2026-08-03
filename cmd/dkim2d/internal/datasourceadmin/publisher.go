package datasourceadmin

import (
	"context"
	"fmt"
)

// PublicationState classifies one requested candidate from authoritative readback.
type PublicationState string

const (
	// PublicationAbsent proves the candidate generation does not exist.
	PublicationAbsent PublicationState = "absent"
	// PublicationExactStaging proves exact complete operation-bound staging content.
	PublicationExactStaging PublicationState = "exact_staging"
	// PublicationExactCommitted proves exact complete operation-bound committed content.
	PublicationExactCommitted PublicationState = "exact_committed"
	// PublicationPartial reports incomplete candidate content.
	PublicationPartial PublicationState = "partial"
	// PublicationMismatch reports complete content with mismatched ownership or digest.
	PublicationMismatch PublicationState = "mismatch"
	// PublicationUnknown reports an authority result that cannot be classified safely.
	PublicationUnknown PublicationState = "unknown"
)

// PublicationObservation owns one bounded provider-neutral current and candidate classification.
type PublicationObservation struct {
	currentGeneration   uint64
	candidateGeneration uint64
	state               PublicationState
	operation           OperationBinding
	staged              StagedEvidence
	oldCurrentWasActive bool
}

// NewPublicationObservation validates one exact provider readback classification.
func NewPublicationObservation(
	currentGeneration uint64,
	candidateGeneration uint64,
	state PublicationState,
	operation OperationBinding,
	staged StagedEvidence,
	oldCurrentWasActive bool,
) (PublicationObservation, error) {
	value := PublicationObservation{
		currentGeneration: currentGeneration, candidateGeneration: candidateGeneration,
		state: state, operation: operation, staged: staged, oldCurrentWasActive: oldCurrentWasActive,
	}
	if !value.Valid() {
		return PublicationObservation{}, newError(CodeInvalid)
	}
	return value, nil
}

// Valid reports whether classification and exact evidence agree.
func (o PublicationObservation) Valid() bool {
	if o.candidateGeneration == 0 || o.currentGeneration == 0 && o.oldCurrentWasActive {
		return false
	}
	exact := o.state == PublicationExactStaging || o.state == PublicationExactCommitted
	knownNonexact := o.state == PublicationAbsent || o.state == PublicationPartial ||
		o.state == PublicationMismatch || o.state == PublicationUnknown
	if exact {
		return o.operation.Initialized() && o.staged.Digest().Valid()
	}
	return knownNonexact && !o.operation.Initialized() && !o.staged.Digest().Valid() && !o.oldCurrentWasActive
}

// CurrentGeneration returns the exact observed current or zero for proven empty state.
func (o PublicationObservation) CurrentGeneration() uint64 { return o.currentGeneration }

// CandidateGeneration returns the exact requested candidate generation.
func (o PublicationObservation) CandidateGeneration() uint64 { return o.candidateGeneration }

// State returns the closed candidate classification.
func (o PublicationObservation) State() PublicationState { return o.state }

// Operation returns exact operation evidence for an exact candidate.
func (o PublicationObservation) Operation() OperationBinding { return o.operation }

// Staged returns exact candidate digest evidence for an exact candidate.
func (o PublicationObservation) Staged() StagedEvidence { return o.staged }

// OldCurrentWasActive reports backend-durable established-current history.
func (o PublicationObservation) OldCurrentWasActive() bool { return o.oldCurrentWasActive }

// String returns a constant protected publication-observation representation.
func (PublicationObservation) String() string { return redacted }

// GoString returns a constant protected publication-observation representation.
func (PublicationObservation) GoString() string { return redacted }

// Format prevents publication evidence from reaching formatting sinks.
func (PublicationObservation) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected publication-observation serialization.
func (PublicationObservation) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// AdministrationLockObservation is one read-only backend lock owner and revision sight.
type AdministrationLockObservation struct {
	revision uint64
	owner    OperationBinding
	claimed  bool
}

// NewAdministrationLockObservation constructs one exact claimed or ownerless lock sight.
func NewAdministrationLockObservation(
	revision uint64,
	owner OperationBinding,
	claimed bool,
) (AdministrationLockObservation, error) {
	value := AdministrationLockObservation{revision: revision, owner: owner, claimed: claimed}
	if !value.Valid() {
		return AdministrationLockObservation{}, newError(CodeInvalid)
	}
	return value, nil
}

// Valid reports whether revision and optional owner form one exact lock sight.
func (o AdministrationLockObservation) Valid() bool {
	return o.revision != 0 && o.claimed == o.owner.Initialized()
}

// Revision returns the exact backend administration revision.
func (o AdministrationLockObservation) Revision() uint64 { return o.revision }

// Claimed reports whether the observed revision has an owner.
func (o AdministrationLockObservation) Claimed() bool { return o.claimed }

// Owner returns the protected exact owner or zero for ownerless state.
func (o AdministrationLockObservation) Owner() OperationBinding { return o.owner }

// String returns a constant protected lock-observation representation.
func (AdministrationLockObservation) String() string { return redacted }

// GoString returns a constant protected lock-observation representation.
func (AdministrationLockObservation) GoString() string { return redacted }

// Format prevents lock observation evidence from reaching formatting sinks.
func (AdministrationLockObservation) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected lock-observation serialization.
func (AdministrationLockObservation) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// SnapshotReader reads one stable complete current generation and inventory.
type SnapshotReader interface {
	ReadCurrent(context.Context, GenerationLimits) (*Snapshot, error)
	Inventory(context.Context, GenerationLimits) (Inventory, error)
	// ReadCollisionInventory returns one atomic complete view bound to the exact supplied claim.
	ReadCollisionInventory(context.Context, AdministrationLock, GenerationLimits) (*CollisionInventory, error)
}

// AdministrationLock is one protected exact owner-and-revision claim.
type AdministrationLock struct {
	owner    OperationBinding
	revision uint64
}

// NewAdministrationLock constructs one claimed lock bound to an operation and revision.
func NewAdministrationLock(owner OperationBinding, revision uint64) (AdministrationLock, error) {
	if !validOperationID(owner.value) || revision == 0 {
		return AdministrationLock{}, newError(CodeInvalid)
	}
	return AdministrationLock{owner: owner, revision: revision}, nil
}

// Owner returns the protected exact operation owner.
func (l AdministrationLock) Owner() OperationBinding { return l.owner }

// Revision returns the exact claimed backend revision.
func (l AdministrationLock) Revision() uint64 { return l.revision }

// ValidFor reports whether this initialized claim belongs to the operation.
func (l AdministrationLock) ValidFor(operation OperationBinding) bool {
	return l.revision != 0 && l.owner.Equal(operation)
}

// String returns a constant protected administration-lock representation.
func (AdministrationLock) String() string { return redacted }

// GoString returns a constant protected administration-lock representation.
func (AdministrationLock) GoString() string { return redacted }

// Format prevents lock ownership and revision from reaching formatting sinks.
func (AdministrationLock) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected administration-lock serialization.
func (AdministrationLock) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// Activation owns one exact expected-current move under the same operation lock.
type Activation struct {
	lock            AdministrationLock
	operation       OperationBinding
	expectedCurrent uint64
	candidate       uint64
	prepared        PreparedEvidence
	staged          StagedEvidence
}

// NewActivation validates one exact lock-bound activation request.
func NewActivation(
	lock AdministrationLock,
	operation OperationBinding,
	expectedCurrent uint64,
	candidate uint64,
	prepared PreparedEvidence,
	staged StagedEvidence,
) (Activation, error) {
	activation := Activation{
		lock: lock, operation: operation, expectedCurrent: expectedCurrent,
		candidate: candidate, prepared: prepared, staged: staged,
	}
	if !activation.Valid() {
		return Activation{}, newError(CodeInvalid)
	}
	return activation, nil
}

// Valid reports whether the activation is monotonic, same-operation, and digest-equal.
func (a Activation) Valid() bool {
	return a.candidate != 0 && a.candidate > a.expectedCurrent &&
		a.lock.ValidFor(a.operation) && a.prepared.Matches(a.staged)
}

// Lock returns the protected exact backend lock claim.
func (a Activation) Lock() AdministrationLock { return a.lock }

// Operation returns the protected exact operation binding.
func (a Activation) Operation() OperationBinding { return a.operation }

// ExpectedCurrent returns the exact fenced current generation.
func (a Activation) ExpectedCurrent() uint64 { return a.expectedCurrent }

// CandidateGeneration returns the exact committed candidate generation.
func (a Activation) CandidateGeneration() uint64 { return a.candidate }

// Prepared returns the protected pre-stage evidence.
func (a Activation) Prepared() PreparedEvidence { return a.prepared }

// Staged returns the protected canonical readback evidence.
func (a Activation) Staged() StagedEvidence { return a.staged }

// String returns a constant protected activation representation.
func (Activation) String() string { return redacted }

// GoString returns a constant protected activation representation.
func (Activation) GoString() string { return redacted }

// Format prevents activation evidence from reaching formatting sinks.
func (Activation) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected activation serialization.
func (Activation) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// GenerationPublisher stages, inspects, and atomically activates generations.
type GenerationPublisher interface {
	Current(context.Context, GenerationLimits) (GenerationInfo, error)
	Stage(context.Context, AdministrationLock, OperationBinding, *PublicationEnvelope) (StagedEvidence, error)
	Inspect(context.Context, OperationBinding, uint64, uint64, GenerationLimits) (*PublicationEnvelope, GenerationInfo, error)
	Observe(context.Context, OperationBinding, uint64, uint64, GenerationLimits) (PublicationObservation, error)
	Activate(context.Context, Activation) error
}

// AdministrationLocker serializes allocation plus stage and activation against backend state.
type AdministrationLocker interface {
	Claim(context.Context, OperationBinding, uint64) (AdministrationLock, error)
	Release(context.Context, AdministrationLock) (uint64, error)
	ObserveAdministrationLock(context.Context) (AdministrationLockObservation, error)
}
