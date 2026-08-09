package rotationadmin

import (
	"context"
	"errors"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

var errPurgeUnavailable = errors.New("purge execution unavailable")

// PurgeExecutor is a provider-owned destruction authority. It receives an
// exact verified command and must never retry an unknown backend outcome.
type PurgeExecutor interface {
	Purge(context.Context, PurgeCommand) (PurgeExecutionResult, error)
}

// PurgeReconciler verifies an unknown destructive outcome using only exact
// provider readback. It must not invoke the destructive path during reconcile.
type PurgeReconciler interface {
	PurgeExecutor
	Reconcile(context.Context, PurgeCommand) (PurgeExecutionResult, error)
}

// PurgeCommand is an ephemeral, exact target set available only after the
// protected plan and fresh inventory fences have both been verified.
type PurgeCommand struct {
	current          uint64
	planDigest       admincontract.Digest
	authority        admincontract.Digest
	policyVersion    string
	targets          []admincontract.PurgeTarget
	protectedPresent bool
}

// CurrentGeneration returns the current-pointer fence that no target may equal.
func (c PurgeCommand) CurrentGeneration() uint64 { return c.current }

// PlanDigest returns the exact provider-neutral target commitment.
func (c PurgeCommand) PlanDigest() admincontract.Digest { return c.planDigest }

// AuthorityCommitment returns the exact dedicated destructive authority commitment.
func (c PurgeCommand) AuthorityCommitment() admincontract.Digest { return c.authority }

// PolicyVersion returns the closed retention policy version bound to the plan.
func (c PurgeCommand) PolicyVersion() string { return c.policyVersion }

// WithTargets supplies detached exact targets to one bounded provider callback.
func (c PurgeCommand) WithTargets(ctx context.Context, use func([]admincontract.PurgeTarget) error) error {
	if ctx == nil || ctx.Err() != nil || use == nil || !c.protectedPresent || !c.planDigest.Valid() || !c.authority.Valid() || c.current == 0 || len(c.targets) == 0 {
		return errPurgeUnavailable
	}
	targets := append([]admincontract.PurgeTarget(nil), c.targets...)
	if err := use(targets); err != nil {
		return errPurgeUnavailable
	}
	return nil
}

// PurgeExecutionResult classifies only a conclusively committed destruction or
// an unknown outcome requiring provider-specific read-only reconciliation.
type PurgeExecutionResult struct {
	Committed bool
	Unknown   bool
}

// ExecutePurge verifies all protected fences and delegates one exact batch to
// the dedicated provider authority. Unknown outcomes are never retried here.
func ExecutePurge(
	ctx context.Context,
	request *PurgeApplyRequest,
	backend datasourceadmin.BackendClass,
	authority datasourceadmin.AuthorityDescriptor,
	policy datasourceadmin.RetentionPolicy,
	inventory datasourceadmin.RetentionInventory,
	executor PurgeExecutor,
) (PurgeExecutionResult, error) {
	if ctx == nil || ctx.Err() != nil || request == nil || executor == nil {
		return PurgeExecutionResult{}, errInvalid
	}
	fence, err := request.VerifyReadback(backend, authority, policy, inventory)
	if err != nil {
		return PurgeExecutionResult{}, err
	}
	if !fence.Ready() || request.plan == nil || request.plan.closed {
		if !fence.IdempotentAbsent() {
			return PurgeExecutionResult{}, errConflict
		}
		return reconcileAbsent(ctx, request, executor)
	}
	command := newPurgeCommand(request)
	result, executeErr := executor.Purge(ctx, command)
	clear(command.targets)
	if executeErr != nil || result.Unknown || !result.Committed {
		return PurgeExecutionResult{Unknown: true}, errPurgeUnavailable
	}
	return PurgeExecutionResult{Committed: true}, nil
}

// ReconcilePurge verifies one explicitly requested uncertain provider outcome.
// It is intentionally separate from apply and never retries destructive work.
func ReconcilePurge(
	ctx context.Context,
	request *PurgeApplyRequest,
	backend datasourceadmin.BackendClass,
	authority datasourceadmin.AuthorityDescriptor,
	policy datasourceadmin.RetentionPolicy,
	inventory datasourceadmin.RetentionInventory,
	executor PurgeReconciler,
) (PurgeExecutionResult, error) {
	if ctx == nil || ctx.Err() != nil || request == nil || executor == nil {
		return PurgeExecutionResult{}, errInvalid
	}
	fence, err := request.VerifyReadback(backend, authority, policy, inventory)
	if err != nil || (!fence.Ready() && !fence.IdempotentAbsent()) || request.plan == nil || request.plan.closed {
		return PurgeExecutionResult{}, errConflict
	}
	command := newPurgeCommand(request)
	result, reconcileErr := executor.Reconcile(ctx, command)
	clear(command.targets)
	if reconcileErr != nil || result.Unknown || !result.Committed {
		return PurgeExecutionResult{Unknown: true}, errPurgeUnavailable
	}
	return PurgeExecutionResult{Committed: true}, nil
}

// reconcileAbsent requires provider receipt readback before treating an exact
// all-absent plan as idempotent completion.
func reconcileAbsent(ctx context.Context, request *PurgeApplyRequest, executor PurgeExecutor) (PurgeExecutionResult, error) {
	reconciler, ok := executor.(PurgeReconciler)
	if !ok {
		return PurgeExecutionResult{Unknown: true}, errPurgeUnavailable
	}
	command := newPurgeCommand(request)
	result, err := reconciler.Reconcile(ctx, command)
	clear(command.targets)
	if err != nil || result.Unknown || !result.Committed {
		return PurgeExecutionResult{Unknown: true}, errPurgeUnavailable
	}
	return PurgeExecutionResult{Committed: true}, nil
}

// newPurgeCommand creates the only provider-facing projection of one verified
// protected plan after the caller has passed all fresh inventory fences.
func newPurgeCommand(request *PurgeApplyRequest) PurgeCommand {
	return PurgeCommand{
		current: request.plan.current, planDigest: request.digest, authority: request.authorityCommitment,
		policyVersion: request.plan.policyVersion, targets: append([]admincontract.PurgeTarget(nil), request.plan.targets...), protectedPresent: true,
	}
}
