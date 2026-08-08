package rotationadmin

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// Published owns exact backend evidence for one immutable committed candidate.
type Published struct {
	mu              sync.Mutex
	lock            datasourceadmin.AdministrationLock
	operation       datasourceadmin.OperationBinding
	expectedCurrent uint64
	candidate       uint64
	prepared        datasourceadmin.PreparedEvidence
	staged          datasourceadmin.StagedEvidence
	currentMoved    bool
	closed          bool
}

// Publish stages and independently reads back the one complete campaign candidate.
func Publish(
	ctx context.Context,
	plan *Plan,
	prepared *Prepared,
	journal *Journal,
	backend datasourceadmin.GenerationPublisher,
	lock datasourceadmin.AdministrationLock,
	limits datasourceadmin.GenerationLimits,
) (*Published, error) {
	if ctx == nil || ctx.Err() != nil || plan == nil || prepared == nil || journal == nil ||
		backend == nil || limits.Validate() != nil || journal.State() != StatePrepared {
		return nil, errInvalid
	}
	plan.mu.Lock()
	if plan.closed || !lock.ValidFor(plan.intent.operation) {
		plan.mu.Unlock()
		return nil, errConflict
	}
	operation, expectedCurrent, candidate := plan.intent.operation, plan.sourceGeneration, plan.candidateGeneration
	planDigest := plan.planDigest
	plan.mu.Unlock()
	prepared.mu.Lock()
	if prepared.closed || prepared.envelope == nil || !prepared.planDigest.Equal(planDigest) {
		prepared.mu.Unlock()
		return nil, errConflict
	}
	envelope := prepared.envelope
	preparedEvidence := envelope.PreparedEvidence()
	staged, publishErr := backend.Stage(ctx, lock, operation, envelope)
	prepared.mu.Unlock()
	if publishErr != nil {
		requireBackendReconciliation(journal, "stage_outcome")
		return nil, errBackend
	}
	readback, info, inspectErr := backend.Inspect(ctx, operation, candidate, expectedCurrent, limits)
	if inspectErr != nil || readback == nil {
		requireBackendReconciliation(journal, "stage_readback")
		return nil, errBackend
	}
	defer readback.Close() //nolint:errcheck // Readback cleanup has no recovery action.
	if info.Generation != candidate || info.Current || info.State != datasourceadmin.StateCommitted ||
		!info.Operation.Equal(operation) || !preparedEvidence.Matches(staged) ||
		!readback.Digest().Equal(staged.Digest()) {
		requireBackendReconciliation(journal, "stage_mismatch")
		return nil, errConflict
	}
	digestBytes := staged.Digest().Bytes()
	digest, err := admincontract.ParseDigest(digestBytes)
	clear(digestBytes)
	if err != nil || journal.RecordStaged(digest) != nil {
		return nil, errConflict
	}
	return &Published{lock: lock, operation: operation, expectedCurrent: expectedCurrent, candidate: candidate, prepared: preparedEvidence, staged: staged}, nil
}

// Activate performs one exact expected-current move and independently confirms authoritative state.
func Activate(
	ctx context.Context,
	journal *Journal,
	backend datasourceadmin.GenerationPublisher,
	published *Published,
	limits datasourceadmin.GenerationLimits,
) error {
	if ctx == nil || ctx.Err() != nil || journal == nil || backend == nil || published == nil || limits.Validate() != nil ||
		journal.State() != StateActivating {
		return errInvalid
	}
	published.mu.Lock()
	defer published.mu.Unlock()
	if published.closed {
		return errConflict
	}
	activation, err := datasourceadmin.NewActivation(
		published.lock, published.operation, published.expectedCurrent, published.candidate,
		published.prepared, published.staged,
	)
	if err != nil {
		return errConflict
	}
	if !published.currentMoved {
		if err := backend.Activate(ctx, activation); err != nil {
			requireBackendReconciliation(journal, "activation_outcome")
			return errBackend
		}
	}
	observation, err := backend.Observe(
		ctx, published.operation, published.candidate, published.expectedCurrent, limits,
	)
	if err != nil || observation.State() != datasourceadmin.PublicationExactCommitted ||
		observation.CurrentGeneration() != published.candidate ||
		!observation.Operation().Equal(published.operation) ||
		!published.prepared.Matches(observation.Staged()) {
		requireBackendReconciliation(journal, "activation_readback")
		return errConflict
	}
	if recorder, ok := backend.(datasourceadmin.TerminalRecorder); ok {
		record, recordErr := terminalRecordForActivation(journal, published)
		if recordErr != nil || recorder.RecordTerminal(ctx, record) != nil {
			requireBackendReconciliation(journal, "terminal_close")
			return errBackend
		}
	}
	if err := journal.RecordActivated(); err != nil {
		return errConflict
	}
	return nil
}

// terminalRecordForActivation derives immutable closure evidence only while
// Activate holds the published lock after authoritative current readback.
func terminalRecordForActivation(journal *Journal, published *Published) (datasourceadmin.TerminalRecord, error) {
	if journal == nil || published == nil {
		return datasourceadmin.TerminalRecord{}, errInvalid
	}
	journal.mu.Lock()
	schema, source, candidate, activationUnix := journal.sourceSchema, journal.sourceGeneration, journal.candidateGeneration, journal.activationUnix
	journal.mu.Unlock()
	if activationUnix <= 0 {
		return datasourceadmin.TerminalRecord{}, errInvalid
	}
	when := time.Unix(activationUnix, 0).UTC()
	operation, current, digest := published.operation, published.candidate, published.staged.Digest()
	return datasourceadmin.NewTerminalRecord(operation, datasourceadmin.SchemaVersionV3, schema, source, candidate, current, digest, datasourceadmin.TerminalClosed, "activated", when)
}

// RehydratePublished rebuilds activation evidence only from a fresh lock and
// exact durable candidate readback. It never accepts an in-memory prior lock.
func RehydratePublished(ctx context.Context, journal *Journal, backend datasourceadmin.GenerationPublisher, lock datasourceadmin.AdministrationLock, limits datasourceadmin.GenerationLimits) (*Published, error) {
	if ctx == nil || ctx.Err() != nil || journal == nil || backend == nil || limits.Validate() != nil {
		return nil, errInvalid
	}
	journal.mu.Lock()
	if journal.closed || journal.state != StateActivating || !journal.candidateDigest.Valid() {
		journal.mu.Unlock()
		return nil, errConflict
	}
	operationText, expected, candidate, digest := journal.operation, journal.sourceGeneration, journal.candidateGeneration, journal.candidateDigest
	journal.mu.Unlock()
	operation, err := datasourceadmin.NewOperationBinding(operationText)
	if err != nil || !lock.ValidFor(operation) {
		return nil, errConflict
	}
	envelope, info, err := backend.Inspect(ctx, operation, candidate, expected, limits)
	if err != nil || envelope == nil || info.Generation != candidate || info.State != datasourceadmin.StateCommitted || !info.Operation.Equal(operation) {
		return nil, errBackend
	}
	actualBytes := envelope.Digest().Bytes()
	actual, parseErr := admincontract.ParseDigest(actualBytes)
	clear(actualBytes)
	if parseErr != nil || !digest.Equal(actual) {
		_ = envelope.Close()
		return nil, errConflict
	}
	prepared := envelope.PreparedEvidence()
	staged := datasourceadmin.NewStagedEvidence(envelope.Digest())
	_ = envelope.Close()
	return &Published{lock: lock, operation: operation, expectedCurrent: expected, candidate: candidate, prepared: prepared, staged: staged, currentMoved: info.Current}, nil
}

// Close erases protected backend evidence.
func (p *Published) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lock = datasourceadmin.AdministrationLock{}
	p.operation = datasourceadmin.OperationBinding{}
	p.prepared = datasourceadmin.PreparedEvidence{}
	p.staged = datasourceadmin.StagedEvidence{}
	p.currentMoved = false
	p.closed = true
	return nil
}

// String returns a constant protected publication representation.
func (*Published) String() string { return redacted }

// GoString returns a constant protected publication representation.
func (*Published) GoString() string { return redacted }

// Format prevents backend evidence from reaching output.
func (*Published) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic publication serialization.
func (*Published) MarshalJSON() ([]byte, error) { return nil, errInvalid }

// requireBackendReconciliation moves every possibly mutated backend outcome into read-only recovery.
func requireBackendReconciliation(journal *Journal, failureClass string) {
	if journal != nil {
		_ = journal.RequireReconciliation(failureClass)
	}
}
