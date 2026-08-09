package rotationruntime

import (
	"context"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/rotationadmin"
)

// providerContext bounds one backend interaction without shortening the
// campaign-wide context used for key preparation and DNS proof progress.
func providerContext(parent context.Context, maximum time.Duration) (context.Context, context.CancelFunc, error) {
	if parent == nil || parent.Err() != nil || maximum <= 0 {
		return nil, nil, errUnavailable
	}
	if deadline, ok := parent.Deadline(); ok && time.Until(deadline) <= maximum {
		child, cancel := context.WithCancel(parent)
		return child, cancel, nil
	}
	child, cancel := context.WithTimeout(parent, maximum)
	return child, cancel, nil
}

// deadlineCampaignBackend gives every LDAP or SQL call its own finite child
// context while retaining the original provider as the sole state owner.
type deadlineCampaignBackend struct {
	backend campaignBackend
	maximum time.Duration
}

func (b *deadlineCampaignBackend) ReadCurrent(ctx context.Context, limits datasourceadmin.GenerationLimits) (*datasourceadmin.Snapshot, error) {
	child, cancel, err := providerContext(ctx, b.maximum)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return b.backend.ReadCurrent(child, limits)
}

func (b *deadlineCampaignBackend) Inventory(ctx context.Context, limits datasourceadmin.GenerationLimits) (datasourceadmin.Inventory, error) {
	child, cancel, err := providerContext(ctx, b.maximum)
	if err != nil {
		return datasourceadmin.Inventory{}, err
	}
	defer cancel()
	return b.backend.Inventory(child, limits)
}

func (b *deadlineCampaignBackend) ReadCollisionInventory(ctx context.Context, lock datasourceadmin.AdministrationLock, limits datasourceadmin.GenerationLimits) (*datasourceadmin.CollisionInventory, error) {
	child, cancel, err := providerContext(ctx, b.maximum)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return b.backend.ReadCollisionInventory(child, lock, limits)
}

func (b *deadlineCampaignBackend) Current(ctx context.Context, limits datasourceadmin.GenerationLimits) (datasourceadmin.GenerationInfo, error) {
	child, cancel, err := providerContext(ctx, b.maximum)
	if err != nil {
		return datasourceadmin.GenerationInfo{}, err
	}
	defer cancel()
	return b.backend.Current(child, limits)
}

func (b *deadlineCampaignBackend) Stage(ctx context.Context, lock datasourceadmin.AdministrationLock, operation datasourceadmin.OperationBinding, candidate *datasourceadmin.PublicationEnvelope) (datasourceadmin.StagedEvidence, error) {
	child, cancel, err := providerContext(ctx, b.maximum)
	if err != nil {
		return datasourceadmin.StagedEvidence{}, err
	}
	defer cancel()
	return b.backend.Stage(child, lock, operation, candidate)
}

func (b *deadlineCampaignBackend) Inspect(ctx context.Context, operation datasourceadmin.OperationBinding, generation, expectedCurrent uint64, limits datasourceadmin.GenerationLimits) (*datasourceadmin.PublicationEnvelope, datasourceadmin.GenerationInfo, error) {
	child, cancel, err := providerContext(ctx, b.maximum)
	if err != nil {
		return nil, datasourceadmin.GenerationInfo{}, err
	}
	defer cancel()
	return b.backend.Inspect(child, operation, generation, expectedCurrent, limits)
}

func (b *deadlineCampaignBackend) Observe(ctx context.Context, operation datasourceadmin.OperationBinding, generation, expectedCurrent uint64, limits datasourceadmin.GenerationLimits) (datasourceadmin.PublicationObservation, error) {
	child, cancel, err := providerContext(ctx, b.maximum)
	if err != nil {
		return datasourceadmin.PublicationObservation{}, err
	}
	defer cancel()
	return b.backend.Observe(child, operation, generation, expectedCurrent, limits)
}

func (b *deadlineCampaignBackend) Activate(ctx context.Context, activation datasourceadmin.Activation) error {
	child, cancel, err := providerContext(ctx, b.maximum)
	if err != nil {
		return err
	}
	defer cancel()
	return b.backend.Activate(child, activation)
}

func (b *deadlineCampaignBackend) Claim(ctx context.Context, operation datasourceadmin.OperationBinding, revision uint64) (datasourceadmin.AdministrationLock, error) {
	child, cancel, err := providerContext(ctx, b.maximum)
	if err != nil {
		return datasourceadmin.AdministrationLock{}, err
	}
	defer cancel()
	return b.backend.Claim(child, operation, revision)
}

func (b *deadlineCampaignBackend) Release(ctx context.Context, lock datasourceadmin.AdministrationLock) (uint64, error) {
	child, cancel, err := providerContext(ctx, b.maximum)
	if err != nil {
		return 0, err
	}
	defer cancel()
	return b.backend.Release(child, lock)
}

func (b *deadlineCampaignBackend) ObserveAdministrationLock(ctx context.Context) (datasourceadmin.AdministrationLockObservation, error) {
	child, cancel, err := providerContext(ctx, b.maximum)
	if err != nil {
		return datasourceadmin.AdministrationLockObservation{}, err
	}
	defer cancel()
	return b.backend.ObserveAdministrationLock(child)
}

func (b *deadlineCampaignBackend) Close() error {
	if closer, ok := b.backend.(interface{ Close() error }); ok {
		return closer.Close()
	}
	if closer, ok := b.backend.(interface{ Close() }); ok {
		closer.Close()
	}
	return nil
}

type deadlinePurgeExecutor struct {
	executor rotationadmin.PurgeExecutor
	maximum  time.Duration
}

func (e *deadlinePurgeExecutor) Purge(ctx context.Context, command rotationadmin.PurgeCommand) (rotationadmin.PurgeExecutionResult, error) {
	child, cancel, err := providerContext(ctx, e.maximum)
	if err != nil {
		return rotationadmin.PurgeExecutionResult{}, err
	}
	defer cancel()
	return e.executor.Purge(child, command)
}

func (e *deadlinePurgeExecutor) Reconcile(ctx context.Context, command rotationadmin.PurgeCommand) (rotationadmin.PurgeExecutionResult, error) {
	reconciler, ok := e.executor.(rotationadmin.PurgeReconciler)
	if !ok {
		return rotationadmin.PurgeExecutionResult{}, errUnavailable
	}
	child, cancel, err := providerContext(ctx, e.maximum)
	if err != nil {
		return rotationadmin.PurgeExecutionResult{}, err
	}
	defer cancel()
	return reconciler.Reconcile(child, command)
}

func (e *deadlinePurgeExecutor) Close() {
	if closer, ok := e.executor.(interface{ Close() }); ok {
		closer.Close()
	}
}

type deadlineTerminalRecorder struct {
	recorder datasourceadmin.TerminalRecorder
	maximum  time.Duration
}

func (r *deadlineTerminalRecorder) RecordTerminal(ctx context.Context, record datasourceadmin.TerminalRecord) error {
	child, cancel, err := providerContext(ctx, r.maximum)
	if err != nil {
		return err
	}
	defer cancel()
	return r.recorder.RecordTerminal(child, record)
}

func (r *deadlineTerminalRecorder) ReadTerminal(ctx context.Context, operation datasourceadmin.OperationBinding) (datasourceadmin.TerminalRecord, bool, error) {
	child, cancel, err := providerContext(ctx, r.maximum)
	if err != nil {
		return datasourceadmin.TerminalRecord{}, false, err
	}
	defer cancel()
	return r.recorder.ReadTerminal(child, operation)
}

func (r *deadlineTerminalRecorder) Close() {
	if closer, ok := r.recorder.(interface{ Close() }); ok {
		closer.Close()
	}
}

type deadlineRetentionRecoveryReader struct {
	reader  datasourceadmin.RetentionRecoveryReader
	maximum time.Duration
}

func (r *deadlineRetentionRecoveryReader) RetentionCurrent(ctx context.Context) (uint64, error) {
	if ctx == nil || ctx.Err() != nil || r.maximum <= 0 {
		return 0, errUnavailable
	}
	// A recovery inventory can contain 16,384 fully verified generations. Keep
	// the campaign-wide deadline here; the concrete provider gives each network
	// or database interaction its own bounded child context.
	return r.reader.RetentionCurrent(ctx)
}

func (r *deadlineRetentionRecoveryReader) RetentionPage(ctx context.Context, after uint64, limit uint32) ([]datasourceadmin.RetentionGeneration, error) {
	child, cancel, err := providerContext(ctx, r.maximum)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return r.reader.RetentionPage(child, after, limit)
}
