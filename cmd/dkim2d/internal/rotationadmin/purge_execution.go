package rotationadmin

import (
	"context"
	"errors"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

var errPurgeUnavailable = errors.New("purge execution unavailable")

// ExecutePurge verifies all protected fences and delegates one exact batch to
// the dedicated provider authority. Unknown outcomes are never retried here.
func ExecutePurge(
	ctx context.Context,
	request *PurgeApplyRequest,
	backend datasourceadmin.BackendClass,
	authority datasourceadmin.AuthorityDescriptor,
	policy datasourceadmin.RetentionPolicy,
	inventory datasourceadmin.RetentionInventory,
	executor datasourceadmin.PurgeExecutor,
) (datasourceadmin.PurgeExecutionResult, error) {
	if ctx == nil || ctx.Err() != nil || request == nil || executor == nil {
		return datasourceadmin.PurgeExecutionResult{}, errInvalid
	}
	fence, err := request.VerifyReadback(backend, authority, policy, inventory)
	if err != nil {
		return datasourceadmin.PurgeExecutionResult{}, err
	}
	if !fence.Ready() || request.plan == nil || request.plan.closed {
		if !fence.IdempotentAbsent() {
			return datasourceadmin.PurgeExecutionResult{}, errConflict
		}
		return reconcileAbsent(ctx, request, executor)
	}
	command := newPurgeCommand(request)
	result, executeErr := executor.Purge(ctx, command)
	command.Clear()
	if executeErr != nil || result.Unknown || !result.Committed {
		return datasourceadmin.PurgeExecutionResult{Unknown: true}, errPurgeUnavailable
	}
	return datasourceadmin.PurgeExecutionResult{Committed: true}, nil
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
	executor datasourceadmin.PurgeReconciler,
) (datasourceadmin.PurgeExecutionResult, error) {
	if ctx == nil || ctx.Err() != nil || request == nil || executor == nil {
		return datasourceadmin.PurgeExecutionResult{}, errInvalid
	}
	fence, err := request.VerifyReadback(backend, authority, policy, inventory)
	if err != nil || (!fence.Ready() && !fence.IdempotentAbsent()) || request.plan == nil || request.plan.closed {
		return datasourceadmin.PurgeExecutionResult{}, errConflict
	}
	command := newPurgeCommand(request)
	result, reconcileErr := executor.Reconcile(ctx, command)
	command.Clear()
	if reconcileErr != nil || result.Unknown || !result.Committed {
		return datasourceadmin.PurgeExecutionResult{Unknown: true}, errPurgeUnavailable
	}
	return datasourceadmin.PurgeExecutionResult{Committed: true}, nil
}

// reconcileAbsent requires provider receipt readback before treating an exact
// all-absent plan as idempotent completion.
func reconcileAbsent(ctx context.Context, request *PurgeApplyRequest, executor datasourceadmin.PurgeExecutor) (datasourceadmin.PurgeExecutionResult, error) {
	reconciler, ok := executor.(datasourceadmin.PurgeReconciler)
	if !ok {
		return datasourceadmin.PurgeExecutionResult{Unknown: true}, errPurgeUnavailable
	}
	command := newPurgeCommand(request)
	result, err := reconciler.Reconcile(ctx, command)
	command.Clear()
	if err != nil || result.Unknown || !result.Committed {
		return datasourceadmin.PurgeExecutionResult{Unknown: true}, errPurgeUnavailable
	}
	return datasourceadmin.PurgeExecutionResult{Committed: true}, nil
}

// newPurgeCommand creates the only provider-facing projection of one verified
// protected plan after the caller has passed all fresh inventory fences.
func newPurgeCommand(request *PurgeApplyRequest) datasourceadmin.PurgeCommand {
	return datasourceadmin.NewVerifiedPurgeCommand(
		request.plan.current, request.digest, request.authorityCommitment,
		request.plan.policyVersion, request.plan.targets,
	)
}
