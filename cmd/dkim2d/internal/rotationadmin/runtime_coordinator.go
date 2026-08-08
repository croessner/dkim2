package rotationadmin

import (
	"context"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

// BatchDNSProver proves one deterministic immutable candidate batch. It has no
// authority to alter the candidate, journal, or current pointer.
type BatchDNSProver interface {
	ProveBatch(context.Context, *Prepared, Batch) (time.Time, error)
}

// Coordinator is the sole campaign lifecycle owner above provider primitives.
type Coordinator struct {
	backend         datasourceadmin.SnapshotReader
	publisher       datasourceadmin.GenerationPublisher
	locker          datasourceadmin.AdministrationLocker
	keys            KeyFactory
	proof           BatchDNSProver
	limits          Limits
	generations     datasourceadmin.GenerationLimits
	maximumProofAge time.Duration
}

// NewCoordinator constructs one complete campaign coordinator with an explicit
// DNS proof boundary. Nil proof is rejected, so mutation cannot be accidental.
func NewCoordinator(backend datasourceadmin.SnapshotReader, publisher datasourceadmin.GenerationPublisher, locker datasourceadmin.AdministrationLocker, keys KeyFactory, proof BatchDNSProver, limits Limits, generations datasourceadmin.GenerationLimits, maximumProofAge time.Duration) (*Coordinator, error) {
	if backend == nil || publisher == nil || locker == nil || keys == nil || proof == nil || limits.Validate() != nil || generations.Validate() != nil || maximumProofAge <= 0 || maximumProofAge > 24*time.Hour {
		return nil, errInvalid
	}
	return &Coordinator{backend: backend, publisher: publisher, locker: locker, keys: keys, proof: proof, limits: limits, generations: generations, maximumProofAge: maximumProofAge}, nil
}

// Limits returns the validated finite campaign bounds shared by mutation and dry-run planning.
func (c *Coordinator) Limits() Limits {
	if c == nil {
		return Limits{}
	}
	return c.limits
}

// Run starts or resumes exactly one normal/emergency campaign under the
// protected journal lock. Every durable state edge is saved before the next.
func (c *Coordinator) Run(ctx context.Context, store *JournalStore, intent Intent) (Report, error) { //nolint:gocyclo // The sole lifecycle owner keeps crash edges explicit and serial.
	if c == nil || ctx == nil || ctx.Err() != nil || store == nil || !intent.operation.Initialized() {
		return Report{}, errInvalid
	}
	journal, exists, err := store.Load(ctx)
	if err != nil {
		return Report{}, errBackend
	}
	if !exists {
		lock, claimErr := c.locker.Claim(ctx, intent.operation, 0)
		if claimErr != nil {
			return Report{}, errBackend
		}
		defer c.locker.Release(ctx, lock) //nolint:errcheck // A release failure cannot authorize retry.
		inventory, inventoryErr := c.backend.Inventory(ctx, c.generations)
		if inventoryErr != nil {
			return Report{}, errBackend
		}
		candidate, allocationErr := datasourceadmin.AllocateGeneration(inventory, c.generations)
		if allocationErr != nil {
			return Report{}, errConflict
		}
		source, sourceErr := c.backend.ReadCurrent(ctx, c.generations)
		if sourceErr != nil {
			return Report{}, errBackend
		}
		defer source.Close() //nolint:errcheck
		plan, freezeErr := Freeze(ctx, source, candidate, intent, c.limits)
		if freezeErr != nil {
			return Report{}, freezeErr
		}
		defer plan.Close() //nolint:errcheck
		journal, err = NewJournal(plan)
		if err != nil {
			return Report{}, errConflict
		}
		if err = store.Save(ctx, journal); err != nil {
			return Report{}, errBackend
		}
		if err = journal.BeginPreparing(); err != nil || store.Save(ctx, journal) != nil {
			return Report{}, errBackend
		}
		preparer, prepErr := NewPreparer(c.keys, provider.ProductionLimits())
		if prepErr != nil {
			return Report{}, errInvalid
		}
		prepared, prepErr := preparer.Prepare(ctx, plan, source)
		if prepErr != nil {
			return journal.Report(), errBackend
		}
		defer prepared.Close() //nolint:errcheck
		if err = journal.RecordPrepared(prepared); err != nil || store.Save(ctx, journal) != nil {
			return journal.Report(), errBackend
		}
		published, publishErr := Publish(ctx, plan, prepared, journal, c.publisher, lock, c.generations)
		if publishErr != nil {
			return journal.Report(), publishErr
		}
		defer published.Close() //nolint:errcheck
		if err = store.Save(ctx, journal); err != nil {
			return journal.Report(), errBackend
		}
		return c.proveAndActivate(ctx, store, journal, prepared, published, lock)
	}
	defer journal.Close() //nolint:errcheck
	if !journal.MatchesResumeRequest(intent) {
		return journal.Report(), errConflict
	}
	if journal.State() != StateStaged && journal.State() != StateDNSInProgress && journal.State() != StateDNSComplete && journal.State() != StateActivating {
		return journal.Report(), errConflict
	}
	operation, operationErr := journalOperation(journal)
	if operationErr != nil {
		return journal.Report(), errConflict
	}
	// A restart must reclaim the datasource fence before it consumes the
	// candidate or records another DNS proof. The journal lock is local only.
	lock, claimErr := c.locker.Claim(ctx, operation, 0)
	if claimErr != nil {
		return journal.Report(), errBackend
	}
	defer c.locker.Release(ctx, lock) //nolint:errcheck // Release ambiguity never authorizes reuse.
	if currentErr := c.verifyExpectedCurrent(ctx, journal); currentErr != nil {
		_ = journal.RequireReconciliation("foreign_current")
		_ = store.Save(ctx, journal)
		return journal.Report(), currentErr
	}
	publishedPrepared, recoverErr := RecoverStaged(ctx, journal, c.publisher, c.generations)
	if recoverErr != nil {
		_ = journal.RequireReconciliation("candidate_recovery")
		_ = store.Save(ctx, journal)
		return journal.Report(), recoverErr
	}
	defer publishedPrepared.Close() //nolint:errcheck
	return c.resumeAndActivate(ctx, store, journal, publishedPrepared, lock)
}

// resumeAndActivate uses one freshly claimed lock for all post-crash work.
func (c *Coordinator) resumeAndActivate(ctx context.Context, store *JournalStore, journal *Journal, prepared *Prepared, lock datasourceadmin.AdministrationLock) (Report, error) {
	operation, operationErr := journalOperation(journal)
	if operationErr != nil || !lock.ValidFor(operation) {
		return journal.Report(), errConflict
	}
	if journal.State() != StateDNSComplete && journal.State() != StateActivating {
		return c.proveAndActivate(ctx, store, journal, prepared, nil, lock)
	}
	if journal.State() == StateDNSComplete {
		if err := journal.BeginActivation(time.Now().UTC(), c.maximumProofAge); err != nil || store.Save(ctx, journal) != nil {
			return journal.Report(), errBackend
		}
	}
	published, err := RehydratePublished(ctx, journal, c.publisher, lock, c.generations)
	if err != nil {
		_ = journal.RequireReconciliation("activation_rehydrate")
		_ = store.Save(ctx, journal)
		return journal.Report(), err
	}
	defer published.Close() //nolint:errcheck
	if err := Activate(ctx, journal, c.publisher, published, c.generations); err != nil {
		_ = store.Save(ctx, journal)
		return journal.Report(), err
	}
	if err := store.Save(ctx, journal); err != nil {
		return journal.Report(), errBackend
	}
	return journal.Report(), nil
}

func (c *Coordinator) proveAndActivate(ctx context.Context, store *JournalStore, journal *Journal, prepared *Prepared, published *Published, lock datasourceadmin.AdministrationLock) (Report, error) {
	operation, operationErr := journalOperation(journal)
	if operationErr != nil || !lock.ValidFor(operation) {
		return journal.Report(), errConflict
	}
	batches, err := BuildDNSBatches(ctx, prepared, c.limits.MaxDNSBatchRecords, c.limits)
	if err != nil {
		return journal.Report(), err
	}
	done := int(journal.Report().BatchCount)
	if done > len(batches) {
		return journal.Report(), errConflict
	}
	for _, batch := range batches[done:] {
		if journal.State() == StateDNSComplete {
			break
		}
		completed, proofErr := c.proof.ProveBatch(ctx, prepared, batch)
		if proofErr != nil || journal.RecordBatchProof(batch, completed.UTC(), "dns-v1") != nil || store.Save(ctx, journal) != nil {
			return journal.Report(), errBackend
		}
	}
	if published == nil {
		return c.resumeAndActivate(ctx, store, journal, prepared, lock)
	}
	if err := journal.BeginActivation(time.Now().UTC(), c.maximumProofAge); err != nil || store.Save(ctx, journal) != nil {
		return journal.Report(), errBackend
	}
	if err := Activate(ctx, journal, c.publisher, published, c.generations); err != nil {
		_ = store.Save(ctx, journal)
		return journal.Report(), err
	}
	if err := store.Save(ctx, journal); err != nil {
		return journal.Report(), errBackend
	}
	return journal.Report(), nil
}

// journalOperation returns the sole operation entitled to reacquire a campaign lock.
func journalOperation(journal *Journal) (datasourceadmin.OperationBinding, error) {
	if journal == nil {
		return datasourceadmin.OperationBinding{}, errInvalid
	}
	journal.mu.Lock()
	operation, closed := journal.operation, journal.closed
	journal.mu.Unlock()
	if closed {
		return datasourceadmin.OperationBinding{}, errConflict
	}
	return datasourceadmin.NewOperationBinding(operation)
}

// verifyExpectedCurrent rejects a changed current pointer before any resumed
// proof work can be recorded against an obsolete frozen source generation.
func (c *Coordinator) verifyExpectedCurrent(ctx context.Context, journal *Journal) error {
	if c == nil || journal == nil {
		return errInvalid
	}
	journal.mu.Lock()
	expected, closed := journal.sourceGeneration, journal.closed
	journal.mu.Unlock()
	if closed || expected == 0 {
		return errConflict
	}
	current, err := c.publisher.Current(ctx, c.generations)
	if err != nil || !current.Current || current.State != datasourceadmin.StateCommitted || current.Generation != expected {
		return errConflict
	}
	return nil
}
