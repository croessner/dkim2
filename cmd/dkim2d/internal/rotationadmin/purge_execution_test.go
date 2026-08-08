package rotationadmin

import (
	"context"
	"testing"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// TestExecutePurgeRejectsUnknownResultWithoutRetry freezes no-blind-retry handling.
func TestExecutePurgeRejectsUnknownResultWithoutRetry(t *testing.T) {
	request, authority, inventory := purgeExecutionFixture(t)
	executor := &purgeExecutionFake{result: PurgeExecutionResult{Unknown: true}}
	if _, err := ExecutePurge(t.Context(), request, datasourceadmin.BackendLDAP, authority, inventory, executor); err == nil {
		t.Fatal("unknown destruction result was accepted")
	}
	if executor.calls != 1 {
		t.Fatal("unknown destruction result was retried")
	}
}

// TestExecutePurgePassesOnlyExactProtectedTargets freezes the provider command fence.
func TestExecutePurgePassesOnlyExactProtectedTargets(t *testing.T) {
	request, authority, inventory := purgeExecutionFixture(t)
	executor := &purgeExecutionFake{result: PurgeExecutionResult{Committed: true}}
	result, err := ExecutePurge(context.Background(), request, datasourceadmin.BackendLDAP, authority, inventory, executor)
	if err != nil || !result.Committed || executor.calls != 1 || executor.targets != 1 || executor.current != 2 {
		t.Fatal("exact protected purge command was not dispatched")
	}
}

// TestExecutePurgeRequiresReceiptReconciliationForAbsentTargets reproduces an
// interrupted backend outcome: absence alone is not accepted without receipt proof.
func TestExecutePurgeRequiresReceiptReconciliationForAbsentTargets(t *testing.T) {
	request, authority, inventory := purgeExecutionFixture(t)
	absent := datasourceadmin.RetentionInventory{Version: inventory.Version, Current: inventory.Current, Generations: []datasourceadmin.RetentionGeneration{purgeGeneration(t, 2)}}
	executor := &purgeExecutionFake{result: PurgeExecutionResult{Committed: true}, reconcileResult: PurgeExecutionResult{Committed: true}}
	result, err := ExecutePurge(t.Context(), request, datasourceadmin.BackendLDAP, authority, absent, executor)
	if err != nil || !result.Committed || executor.calls != 0 || executor.reconcileCalls != 1 {
		t.Fatal("absent target bypassed provider receipt reconciliation")
	}
}

type purgeExecutionFake struct {
	result          PurgeExecutionResult
	calls           int
	targets         int
	current         uint64
	reconcileResult PurgeExecutionResult
	reconcileCalls  int
}

// Reconcile records the explicit receipt-readback path without mutation.
func (f *purgeExecutionFake) Reconcile(ctx context.Context, command PurgeCommand) (PurgeExecutionResult, error) {
	f.reconcileCalls++
	if err := command.WithTargets(ctx, func(targets []admincontract.PurgeTarget) error {
		f.targets = len(targets)
		return nil
	}); err != nil {
		return PurgeExecutionResult{}, err
	}
	return f.reconcileResult, nil
}

// Purge records only bounded command facts for the execution-fence reproducer.
func (f *purgeExecutionFake) Purge(ctx context.Context, command PurgeCommand) (PurgeExecutionResult, error) {
	f.calls++
	f.current = command.CurrentGeneration()
	if err := command.WithTargets(ctx, func(targets []admincontract.PurgeTarget) error {
		f.targets = len(targets)
		return nil
	}); err != nil {
		return PurgeExecutionResult{}, err
	}
	return f.result, nil
}

// purgeExecutionFixture constructs one exact eligible committed target.
func purgeExecutionFixture(t *testing.T) (*PurgeApplyRequest, datasourceadmin.AuthorityDescriptor, datasourceadmin.RetentionInventory) {
	t.Helper()
	policy := datasourceadmin.DefaultRetentionPolicy()
	policy.MaxTotalGenerations, policy.MinActiveRollbackGenerations, policy.MaxClosedNeverActiveGenerations, policy.MaxPurgeBatch = 1, 0, 0, 1
	inventory := datasourceadmin.RetentionInventory{Version: testInventoryVersion, Current: 2, Generations: []datasourceadmin.RetentionGeneration{purgeGeneration(t, 1), purgeGeneration(t, 2)}}
	classification, err := datasourceadmin.ClassifyRetention(inventory, policy)
	if err != nil {
		t.Fatal(err)
	}
	authority := purgeAuthority()
	plan, err := NewPurgePlan(datasourceadmin.BackendLDAP, authority, classification)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewPurgeApplyRequest(plan, true)
	if err != nil {
		t.Fatal(err)
	}
	return request, authority, inventory
}
