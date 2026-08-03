package domainadmin

import (
	"context"
	"math"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// allocateForTest retains claim-first behavior solely for lower-layer legacy fixtures.
func (a *IdentityAllocator) allocateForTest(
	ctx context.Context,
	intent Intent,
	reader datasourceadmin.SnapshotReader,
	locker datasourceadmin.AdministrationLocker,
	expectedRevision uint64,
	generationLimits datasourceadmin.GenerationLimits,
) (*IdentityAllocation, datasourceadmin.AdministrationLock, error) {
	if a == nil || ctx == nil || reader == nil || locker == nil || expectedRevision == 0 ||
		a.limits.Validate() != nil || generationLimits.Validate() != nil || ctx.Err() != nil {
		return nil, datasourceadmin.AdministrationLock{}, newError(CodeInvalidLimits)
	}
	if !intent.valid() {
		return nil, datasourceadmin.AdministrationLock{}, newError(CodeInvalidIntent)
	}
	bounded, cancel := context.WithTimeout(ctx, a.limits.BackendDeadline)
	defer cancel()
	revision := expectedRevision
	for attempt := uint32(0); attempt < a.limits.MaxAllocationAttempts; attempt++ {
		operation, err := a.allocateOperation(bounded)
		if err != nil {
			return nil, datasourceadmin.AdministrationLock{}, err
		}
		lock, err := locker.Claim(bounded, operation, revision)
		if err != nil {
			return nil, datasourceadmin.AdministrationLock{}, newError(CodeConflict)
		}
		if !lock.ValidFor(operation) || lock.Revision() != revision {
			return nil, datasourceadmin.AdministrationLock{}, newError(CodeReconcileRequired)
		}
		collisions, err := reader.ReadCollisionInventory(bounded, lock, generationLimits)
		if err != nil || collisions == nil || !collisions.ValidFor(lock) {
			if collisions != nil {
				_ = collisions.Close()
			}
			return nil, datasourceadmin.AdministrationLock{}, a.releaseAfterFailureForTest(ctx, locker, lock, newError(CodeUnavailable))
		}
		if collisions.OperationUsed(operation) {
			_ = collisions.Close()
			next, releaseErr := a.releaseClaimForTest(ctx, locker, lock)
			if releaseErr != nil {
				return nil, datasourceadmin.AdministrationLock{}, newError(CodeReconcileRequired)
			}
			revision = next
			continue
		}
		if collisions.PolicyUsed(intent.TenantID(), intent.Domain(), intent.ProfileUse().String()) {
			_ = collisions.Close()
			return nil, datasourceadmin.AdministrationLock{}, a.releaseAfterFailureForTest(ctx, locker, lock, newError(CodeConflict))
		}
		profileID, err := a.allocateProfileID(bounded, intent, collisions)
		if err != nil {
			_ = collisions.Close()
			return nil, datasourceadmin.AdministrationLock{}, a.releaseAfterFailureForTest(ctx, locker, lock, err)
		}
		credentials, err := a.allocateCredentials(bounded, intent, collisions)
		if err != nil {
			_ = collisions.Close()
			return nil, datasourceadmin.AdministrationLock{}, a.releaseAfterFailureForTest(ctx, locker, lock, err)
		}
		candidate := collisions.CandidateGeneration()
		planSource, sourceErr := collisions.TakePlanSource(lock)
		_ = collisions.Close()
		if candidate == 0 || sourceErr != nil {
			clearAllocatedIdentities(credentials)
			_ = planSource.Close()
			return nil, datasourceadmin.AdministrationLock{}, a.releaseAfterFailureForTest(ctx, locker, lock, newError(CodeConflict))
		}
		return &IdentityAllocation{
			operation: operation, lock: lock, intent: intent.clone(), planSource: planSource, profileID: profileID,
			credentials: credentials, candidateGeneration: candidate,
		}, lock, nil
	}
	return nil, datasourceadmin.AdministrationLock{}, newError(CodeConflict)
}

// releaseAfterFailureForTest preserves historical fixture cleanup semantics.
func (a *IdentityAllocator) releaseAfterFailureForTest(
	ctx context.Context,
	locker datasourceadmin.AdministrationLocker,
	lock datasourceadmin.AdministrationLock,
	cause error,
) error {
	if _, err := a.releaseClaimForTest(ctx, locker, lock); err != nil {
		return newError(CodeReconcileRequired)
	}
	return cause
}

// releaseClaimForTest performs the legacy exact revision-increment assertion.
func (a *IdentityAllocator) releaseClaimForTest(
	ctx context.Context,
	locker datasourceadmin.AdministrationLocker,
	lock datasourceadmin.AdministrationLock,
) (uint64, error) {
	if lock.Revision() == math.MaxUint64 {
		return 0, newError(CodeReconcileRequired)
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.limits.BackendDeadline)
	defer cancel()
	next, err := locker.Release(cleanup, lock)
	if err != nil || cleanup.Err() != nil || next != lock.Revision()+1 {
		return 0, newError(CodeReconcileRequired)
	}
	return next, nil
}
