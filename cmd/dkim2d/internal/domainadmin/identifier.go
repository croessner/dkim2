package domainadmin

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

// AllocatedIdentity is one protected algorithm-specific selector and handle pair.
type AllocatedIdentity struct {
	algorithm provider.Algorithm
	handleID  string
	selector  string
}

// String returns a constant protected allocated-identity representation.
func (AllocatedIdentity) String() string { return redacted }

// GoString returns a constant protected allocated-identity representation.
func (AllocatedIdentity) GoString() string { return redacted }

// Format prevents allocated selectors and handles from reaching formatting sinks.
func (AllocatedIdentity) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic allocated-identity serialization.
func (AllocatedIdentity) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }

// IdentityAllocation owns one complete lock-bound collision-free plan allocation.
type IdentityAllocation struct {
	mu                  sync.Mutex
	operation           datasourceadmin.OperationBinding
	lock                datasourceadmin.AdministrationLock
	intent              Intent
	planSource          *datasourceadmin.PlanSource
	profileID           string
	credentials         []AllocatedIdentity
	candidateGeneration uint64
	planState           allocationPlanState
	consumed            bool
	closed              bool
}

type allocationPlanState uint8

const (
	allocationPlanAllocated allocationPlanState = iota
	allocationPlanReserved
	allocationPlanReady
)

// reservePlanIssuance permanently reserves the allocation's sole plan right.
func (a *IdentityAllocation) reservePlanIssuance() error {
	if a == nil {
		return newError(CodeConflict)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.planState != allocationPlanAllocated {
		return newError(CodeConflict)
	}
	a.planState = allocationPlanReserved
	return nil
}

// completePlanIssuance makes key generation eligible only after successful digest construction.
func (a *IdentityAllocation) completePlanIssuance() error {
	if a == nil {
		return newError(CodeConflict)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.planState != allocationPlanReserved {
		return newError(CodeConflict)
	}
	a.planState = allocationPlanReady
	return nil
}

// IdentityAllocator owns bounded random identity construction.
type IdentityAllocator struct {
	limits  Limits
	entropy entropyReader
}

// NewIdentityAllocator constructs the production crypto/rand allocator.
func NewIdentityAllocator(limits Limits) (*IdentityAllocator, error) {
	return newIdentityAllocator(limits, rand.Reader)
}

// newIdentityAllocator constructs one allocator over the smallest entropy seam.
func newIdentityAllocator(limits Limits, entropy entropyReader) (*IdentityAllocator, error) {
	if limits.Validate() != nil || entropy == nil {
		return nil, newError(CodeInvalidLimits)
	}
	return &IdentityAllocator{limits: limits, entropy: entropy}, nil
}

// NewOperation allocates one bounded canonical operation identity before any backend claim.
func (a *IdentityAllocator) NewOperation(ctx context.Context) (datasourceadmin.OperationBinding, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || a.limits.Validate() != nil {
		return datasourceadmin.OperationBinding{}, newError(CodeInvalidLimits)
	}
	bounded, cancel := context.WithTimeout(ctx, a.limits.BackendDeadline)
	defer cancel()
	return a.allocateOperation(bounded)
}

// AllocateClaimed derives identities only under an already exact persisted administration claim.
func (a *IdentityAllocator) AllocateClaimed(
	ctx context.Context,
	intent Intent,
	lock datasourceadmin.AdministrationLock,
	reader datasourceadmin.SnapshotReader,
	generationLimits datasourceadmin.GenerationLimits,
) (*IdentityAllocation, datasourceadmin.AdministrationLock, error) {
	if a == nil || ctx == nil || reader == nil ||
		a.limits.Validate() != nil || generationLimits.Validate() != nil || ctx.Err() != nil {
		return nil, datasourceadmin.AdministrationLock{}, newError(CodeInvalidLimits)
	}
	operation := lock.Owner()
	if !intent.valid() || !lock.ValidFor(operation) {
		return nil, datasourceadmin.AdministrationLock{}, newError(CodeInvalidIntent)
	}
	bounded, cancel := context.WithTimeout(ctx, a.limits.BackendDeadline)
	defer cancel()
	collisions, err := reader.ReadCollisionInventory(bounded, lock, generationLimits)
	if err != nil || collisions == nil || !collisions.ValidFor(lock) {
		if collisions != nil {
			_ = collisions.Close()
		}
		return nil, lock, newError(CodeReconcileRequired)
	}
	defer collisions.Close() //nolint:errcheck // Allocation transfers only the plan source.
	if collisions.OperationUsed(operation) ||
		collisions.PolicyUsed(intent.TenantID(), intent.Domain(), intent.ProfileUse().String()) {
		return nil, lock, newError(CodeConflict)
	}
	profileID, err := a.allocateProfileID(bounded, intent, collisions)
	if err != nil {
		return nil, lock, err
	}
	credentials, err := a.allocateCredentials(bounded, intent, collisions)
	if err != nil {
		return nil, lock, err
	}
	candidate := collisions.CandidateGeneration()
	planSource, sourceErr := collisions.TakePlanSource(lock)
	if candidate == 0 || sourceErr != nil {
		clearAllocatedIdentities(credentials)
		_ = planSource.Close()
		return nil, lock, newError(CodeReconcileRequired)
	}
	return &IdentityAllocation{
		operation: operation, lock: lock, intent: intent.clone(), planSource: planSource,
		profileID: profileID, credentials: credentials, candidateGeneration: candidate,
	}, lock, nil
}

// allocateOperation creates one exact 128-bit nonzero operation binding.
func (a *IdentityAllocator) allocateOperation(ctx context.Context) (datasourceadmin.OperationBinding, error) {
	for attempt := uint32(0); attempt < a.limits.MaxAllocationAttempts; attempt++ {
		token, err := randomToken(ctx, a.entropy)
		if err != nil {
			return datasourceadmin.OperationBinding{}, err
		}
		operation, bindingErr := datasourceadmin.NewOperationBinding(token)
		if bindingErr == nil {
			return operation, nil
		}
	}
	return datasourceadmin.OperationBinding{}, newError(CodeConflict)
}

// allocateProfileID selects one authoritative collision-free opaque profile identifier.
func (a *IdentityAllocator) allocateProfileID(
	ctx context.Context,
	intent Intent,
	collisions *datasourceadmin.CollisionInventory,
) (string, error) {
	for attempt := uint32(0); attempt < a.limits.MaxAllocationAttempts; attempt++ {
		token, err := randomToken(ctx, a.entropy)
		if err != nil {
			return "", err
		}
		candidate := "p-" + token
		if collisions.ProfileIDUsed(candidate) || !validAllocatedProfile(intent, candidate) {
			continue
		}
		return candidate, nil
	}
	return "", newError(CodeConflict)
}

// validAllocatedProfile reuses the authoritative policy and profile-ID grammar.
func validAllocatedProfile(intent Intent, profileID string) bool {
	_, err := provider.NewPolicy(
		intent.TenantID(), intent.Domain(), intent.ProfileUse(), profileID,
		provider.RecordStatusActive, intent.Rollout(), intent.Compatibility(), "", provider.DefaultLimits(),
	)
	return err == nil
}

// allocateCredentials creates algorithm-separated selectors and opaque handles.
func (a *IdentityAllocator) allocateCredentials(
	ctx context.Context,
	intent Intent,
	collisions *datasourceadmin.CollisionInventory,
) ([]AllocatedIdentity, error) {
	result := make([]AllocatedIdentity, 0, len(intent.Algorithms()))
	usedHandles := make(map[string]struct{})
	usedSelectors := make(map[string]struct{})
	for _, algorithm := range intent.Algorithms() {
		allocated := false
		prefix, err := selectorPrefix(algorithm)
		if err != nil {
			return nil, err
		}
		for attempt := uint32(0); attempt < a.limits.MaxAllocationAttempts; attempt++ {
			handleToken, handleErr := randomToken(ctx, a.entropy)
			selectorToken, selectorErr := randomToken(ctx, a.entropy)
			if handleErr != nil || selectorErr != nil {
				return nil, newError(CodeUnavailable)
			}
			handleID, selector := "h-"+handleToken, prefix+selectorToken
			_, handleDuplicate := usedHandles[handleID]
			_, selectorDuplicate := usedSelectors[selector]
			if handleDuplicate || selectorDuplicate || collisions.HandleIDUsed(handleID) ||
				collisions.SelectorUsed(selector) ||
				datasourceadmin.ValidateHandleDeclaration(handleID) != nil ||
				provider.ValidateDomainSelector(intent.Domain(), selector, algorithm) != nil {
				continue
			}
			usedHandles[handleID], usedSelectors[selector] = struct{}{}, struct{}{}
			result = append(result, AllocatedIdentity{algorithm: algorithm, handleID: handleID, selector: selector})
			allocated = true
			break
		}
		if !allocated {
			clearAllocatedIdentities(result)
			return nil, newError(CodeConflict)
		}
	}
	return result, nil
}

// Operation returns the protected exact operation binding.
func (a *IdentityAllocation) Operation() datasourceadmin.OperationBinding {
	if a == nil {
		return datasourceadmin.OperationBinding{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return datasourceadmin.OperationBinding{}
	}
	return a.operation
}

// CandidateGeneration returns the bounded selected higher generation.
func (a *IdentityAllocation) CandidateGeneration() uint64 {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return 0
	}
	return a.candidateGeneration
}

// WithValues supplies detached protected allocation values to a bounded callback.
func (a *IdentityAllocation) WithValues(
	ctx context.Context,
	use func(string, []AllocatedIdentity) error,
) error {
	if a == nil || ctx == nil || use == nil || ctx.Err() != nil {
		return newError(CodeConflict)
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return newError(CodeConflict)
	}
	profileID := a.profileID
	credentials := append([]AllocatedIdentity(nil), a.credentials...)
	a.mu.Unlock()
	defer clearAllocatedIdentities(credentials)
	if err := use(profileID, credentials); err != nil {
		return newError(CodeUnavailable)
	}
	return nil
}

// clearAllocatedIdentities drops every retained identity string reference.
func clearAllocatedIdentities(values []AllocatedIdentity) {
	for index := range values {
		values[index] = AllocatedIdentity{}
	}
	clear(values)
}

// Close releases every protected derived identity.
func (a *IdentityAllocation) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.operation = datasourceadmin.OperationBinding{}
	a.lock = datasourceadmin.AdministrationLock{}
	a.intent = Intent{}
	_ = a.planSource.Close()
	a.planSource = nil
	a.profileID = ""
	clearAllocatedIdentities(a.credentials)
	a.credentials = nil
	a.candidateGeneration = 0
	a.planState = allocationPlanAllocated
	a.consumed = false
	a.closed = true
	return nil
}

// String returns a constant protected allocation representation.
func (*IdentityAllocation) String() string { return redacted }

// GoString returns a constant protected allocation representation.
func (*IdentityAllocation) GoString() string { return redacted }

// Format prevents allocated identities from reaching formatting sinks.
func (*IdentityAllocation) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic protected allocation serialization.
func (*IdentityAllocation) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }

// String returns a constant protected allocator representation.
func (*IdentityAllocator) String() string { return redacted }

// GoString returns a constant protected allocator representation.
func (*IdentityAllocator) GoString() string { return redacted }

// Format prevents allocator policy and entropy state from reaching formatting sinks.
func (*IdentityAllocator) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic allocator serialization.
func (*IdentityAllocator) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }
