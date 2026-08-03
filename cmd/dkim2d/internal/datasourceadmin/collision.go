package datasourceadmin

import (
	"context"
	"fmt"
	"sync"
)

// CollisionSnapshot transfers one complete current or outstanding generation.
type CollisionSnapshot struct {
	Info     GenerationInfo
	Snapshot *Snapshot
}

// String returns a constant protected collision-snapshot representation.
func (CollisionSnapshot) String() string { return redacted }

// GoString returns a constant protected collision-snapshot representation.
func (CollisionSnapshot) GoString() string { return redacted }

// Format prevents collision snapshot data from reaching formatting sinks.
func (CollisionSnapshot) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected collision-snapshot serialization.
func (CollisionSnapshot) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// CollisionInventory owns one lock-revision-bound complete identity view.
type CollisionInventory struct {
	mu                  sync.Mutex
	lock                AdministrationLock
	identities          *IdentityProjection
	planSource          *PlanSource
	planSourceTaken     bool
	operations          []OperationBinding
	candidateGeneration uint64
	closed              bool
}

// NewCollisionInventory consumes complete snapshots into one protected collision view.
func NewCollisionInventory(
	ctx context.Context,
	lock AdministrationLock,
	inventory Inventory,
	snapshots []CollisionSnapshot,
	limits GenerationLimits,
) (*CollisionInventory, error) {
	defer closeCollisionSnapshots(snapshots)
	if ctx == nil || ctx.Err() != nil || !lock.ValidFor(lock.Owner()) {
		return nil, newError(CodeInvalid)
	}
	canonical := inventory.Canonicalize()
	candidate, err := AllocateGeneration(canonical, limits)
	if err != nil {
		return nil, err
	}
	expected := make(map[uint64]GenerationInfo)
	operations := make([]OperationBinding, 0, len(canonical.Generations))
	for _, info := range canonical.Generations {
		if info.Current || info.Outstanding() {
			expected[info.Generation] = info
		}
		if info.Operation.Initialized() {
			for _, existing := range operations {
				if existing.Equal(info.Operation) {
					return nil, newError(CodeConflict)
				}
			}
			operations = append(operations, info.Operation)
		}
	}
	if len(snapshots) != len(expected) {
		return nil, newError(CodeConflict)
	}
	identities := newIdentityProjection()
	var planSource *PlanSource
	for _, supplied := range snapshots {
		exact, found := expected[supplied.Info.Generation]
		if !found || !generationInfoEqual(exact, supplied.Info) || supplied.Snapshot == nil ||
			supplied.Snapshot.Generation() != supplied.Info.Generation {
			_ = identities.Close()
			_ = planSource.Close()
			return nil, newError(CodeConflict)
		}
		delete(expected, supplied.Info.Generation)
		if supplied.Info.Current {
			planSource, err = supplied.Snapshot.PlanSource(ctx)
			if err != nil {
				_ = identities.Close()
				return nil, newError(CodeUnavailable)
			}
		}
		projection, projectionErr := supplied.Snapshot.IdentityProjection(ctx)
		if projectionErr != nil || identities.Merge(projection) != nil {
			_ = projection.Close()
			_ = identities.Close()
			_ = planSource.Close()
			return nil, newError(CodeUnavailable)
		}
		_ = projection.Close()
	}
	if len(expected) != 0 {
		_ = identities.Close()
		_ = planSource.Close()
		return nil, newError(CodeConflict)
	}
	return &CollisionInventory{
		lock: lock, identities: identities, planSource: planSource,
		operations: operations, candidateGeneration: candidate,
	}, nil
}

// generationInfoEqual compares exact protected inventory evidence.
func generationInfoEqual(left, right GenerationInfo) bool {
	return left.Generation == right.Generation && left.Current == right.Current &&
		left.State == right.State && left.WasActive == right.WasActive &&
		left.Operation.Initialized() == right.Operation.Initialized() &&
		(!left.Operation.Initialized() || left.Operation.Equal(right.Operation))
}

// closeCollisionSnapshots erases every transferred complete snapshot.
func closeCollisionSnapshots(snapshots []CollisionSnapshot) {
	for index := range snapshots {
		if snapshots[index].Snapshot != nil {
			_ = snapshots[index].Snapshot.Close()
			snapshots[index].Snapshot = nil
		}
	}
}

// CandidateGeneration returns the bounded first unused higher generation.
func (i *CollisionInventory) CandidateGeneration() uint64 {
	if i == nil {
		return 0
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return 0
	}
	return i.candidateGeneration
}

// ValidFor reports whether this view was constructed under the exact claim.
func (i *CollisionInventory) ValidFor(lock AdministrationLock) bool {
	if i == nil {
		return false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return !i.closed && i.lock.Revision() == lock.Revision() && i.lock.Owner().Equal(lock.Owner())
}

// TakePlanSource transfers the exact lock-bound key-free current projection once.
func (i *CollisionInventory) TakePlanSource(lock AdministrationLock) (*PlanSource, error) {
	if i == nil {
		return nil, newError(CodeInvalid)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed || i.planSourceTaken || i.lock.Revision() != lock.Revision() || !i.lock.Owner().Equal(lock.Owner()) {
		return nil, newError(CodeConflict)
	}
	source := i.planSource
	i.planSource = nil
	i.planSourceTaken = true
	return source, nil
}

// SelectorUsed reports an exact collision across current and outstanding snapshots.
func (i *CollisionInventory) SelectorUsed(value string) bool {
	if i == nil {
		return true
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.closed || i.identities.SelectorUsed(value)
}

// ProfileIDUsed reports an exact collision across current and outstanding snapshots.
func (i *CollisionInventory) ProfileIDUsed(value string) bool {
	if i == nil {
		return true
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.closed || i.identities.ProfileIDUsed(value)
}

// HandleIDUsed reports an exact collision across current and outstanding snapshots.
func (i *CollisionInventory) HandleIDUsed(value string) bool {
	if i == nil {
		return true
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.closed || i.identities.HandleIDUsed(value)
}

// OperationUsed reports an exact retained operation-binding collision.
func (i *CollisionInventory) OperationUsed(value OperationBinding) bool {
	if i == nil || !value.Initialized() {
		return true
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return true
	}
	for _, operation := range i.operations {
		if operation.Equal(value) {
			return true
		}
	}
	return false
}

// PolicyUsed reports an exact tenant, signing-domain, and profile-use collision.
func (i *CollisionInventory) PolicyUsed(tenantID, domain, use string) bool {
	if i == nil {
		return true
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.closed || i.identities.PolicyUsed(tenantID, domain, use)
}

// Close releases every protected identity and operation binding.
func (i *CollisionInventory) Close() error {
	if i == nil {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return nil
	}
	_ = i.identities.Close()
	i.identities = nil
	_ = i.planSource.Close()
	i.planSource = nil
	i.planSourceTaken = false
	i.lock = AdministrationLock{}
	clear(i.operations)
	i.operations = nil
	i.candidateGeneration = 0
	i.closed = true
	return nil
}

// String returns a constant protected collision-inventory representation.
func (*CollisionInventory) String() string { return redacted }

// GoString returns a constant protected collision-inventory representation.
func (*CollisionInventory) GoString() string { return redacted }

// Format prevents collision inventory data from reaching formatting sinks.
func (*CollisionInventory) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected collision-inventory serialization.
func (*CollisionInventory) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }
