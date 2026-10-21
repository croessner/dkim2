package datasourceadmin

import (
	"context"
	"errors"

	"github.com/croessner/dkim2/admincontract"
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
// protected plan and fresh inventory fences have both been verified. The zero
// value carries no targets and refuses every provider callback.
type PurgeCommand struct {
	current          uint64
	planDigest       admincontract.Digest
	authority        admincontract.Digest
	policyVersion    string
	targets          []admincontract.PurgeTarget
	protectedPresent bool
}

// NewVerifiedPurgeCommand projects one protected purge plan into the
// provider-facing command. Only the rotation purge fence may call it, after
// the plan digest, authority commitment, and fresh inventory readback have
// all been verified; the targets are copied so the caller's plan stays owned
// by the caller.
func NewVerifiedPurgeCommand(
	current uint64,
	planDigest admincontract.Digest,
	authority admincontract.Digest,
	policyVersion string,
	targets []admincontract.PurgeTarget,
) PurgeCommand {
	return PurgeCommand{
		current: current, planDigest: planDigest, authority: authority,
		policyVersion: policyVersion, targets: append([]admincontract.PurgeTarget(nil), targets...), protectedPresent: true,
	}
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

// Clear zeroes the command's private target copy once the provider call has
// returned, so verified target identities do not outlive one execution.
func (c PurgeCommand) Clear() { clear(c.targets) }

// PurgeExecutionResult classifies only a conclusively committed destruction or
// an unknown outcome requiring provider-specific read-only reconciliation.
type PurgeExecutionResult struct {
	Committed bool
	Unknown   bool
}
