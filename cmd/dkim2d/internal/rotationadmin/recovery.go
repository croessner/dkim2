package rotationadmin

import (
	"context"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// RecoverStaged reopens only the exact durable candidate bound to a post-stage
// journal. It deliberately has no key-generation or pointer-mutation path.
func RecoverStaged(ctx context.Context, journal *Journal, backend datasourceadmin.GenerationPublisher, limits datasourceadmin.GenerationLimits) (*Prepared, error) {
	if ctx == nil || ctx.Err() != nil || journal == nil || backend == nil || limits.Validate() != nil {
		return nil, errInvalid
	}
	journal.mu.Lock()
	if journal.closed || (journal.state != StateStaged && journal.state != StateDNSInProgress && journal.state != StateDNSComplete && journal.state != StateActivating && journal.state != StateActivated) {
		journal.mu.Unlock()
		return nil, errConflict
	}
	operation, candidate, expected := journal.operation, journal.candidateGeneration, journal.sourceGeneration
	journal.mu.Unlock()
	binding, err := datasourceadmin.NewOperationBinding(operation)
	if err != nil {
		return nil, errConflict
	}
	envelope, info, err := backend.Inspect(ctx, binding, candidate, expected, limits)
	if err != nil || envelope == nil || info.Generation != candidate || !info.Operation.Equal(binding) {
		return nil, errBackend
	}
	prepared, err := RecoverPrepared(ctx, journal, envelope)
	if err != nil {
		_ = envelope.Close()
		return nil, err
	}
	return prepared, nil
}
