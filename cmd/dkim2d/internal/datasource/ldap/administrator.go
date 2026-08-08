package ldap

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

var (
	errLDAPConflict  = errors.New("ldap administration conflict")
	errLDAPPartial   = errors.New("ldap administration partial")
	errLDAPReconcile = errors.New("ldap administration outcome unknown")
)

// administrationClient is one role-scoped LDAP administrative transport session.
type administrationClient interface {
	Client
	ReadCurrentOptional(context.Context) (Entry, bool, error)
	ListGenerationRoots(context.Context, datasourceadmin.GenerationLimits) ([]Entry, error)
	ListRetentionGenerationRoots(context.Context, datasourceadmin.RetentionRecoveryLimits) ([]Entry, error)
	ReadGenerationRecords(
		context.Context,
		uint64,
		provider.Limits,
		datasourceadmin.GenerationLimits,
	) (DatasetRecords, bool, error)
	ReadAdministrationLock(context.Context) (datasourceadmin.AdministrationLockObservation, error)
	ClaimAdministrationLock(context.Context, datasourceadmin.OperationBinding, uint64) error
	ReleaseAdministrationLock(context.Context, datasourceadmin.AdministrationLock) error
	AddCandidate(context.Context, *datasourceadmin.PublicationEnvelope) error
	SealCandidate(
		context.Context,
		uint64,
		datasourceadmin.OperationBinding,
		datasourceadmin.CandidateContentDigest,
	) error
	MarkWasActive(context.Context, datasetMetadata) error
	ReplaceCurrent(context.Context, datasetMetadata, datasetMetadata) error
	AddCurrent(context.Context, datasetMetadata) error
}

// RetentionRecoveryInventory reads complete historical LDAP evidence without allocation ceilings.
func (a *Administrator) RetentionRecoveryInventory(ctx context.Context) (datasourceadmin.RetentionInventory, error) {
	limits := datasourceadmin.DefaultRetentionRecoveryLimits()
	client, closeClient, err := a.connect(ctx, a.snapshot, a.generations)
	if err != nil {
		return datasourceadmin.RetentionInventory{}, err
	}
	defer closeClient()
	first, present, err := client.ReadCurrentOptional(ctx)
	if err != nil || !present {
		return datasourceadmin.RetentionInventory{}, datasourceadminError(datasourceadmin.CodeUnavailable)
	}
	defer clearEntry(&first)
	current, err := mapCurrentMetadata(first)
	if err != nil {
		return datasourceadmin.RetentionInventory{}, datasourceadminError(datasourceadmin.CodeConflict)
	}
	roots, err := client.ListRetentionGenerationRoots(ctx, limits)
	if err != nil {
		return datasourceadmin.RetentionInventory{}, datasourceadminError(datasourceadmin.CodeUnavailable)
	}
	defer clearEntries(roots)
	rows := make([]datasourceadmin.RetentionGeneration, 0, len(roots))
	bytesRead := 0
	currentMatches := 0
	for _, root := range roots {
		metadata, mapErr := mapInventoryGenerationMetadata(root)
		if mapErr != nil {
			return datasourceadmin.RetentionInventory{}, datasourceadminError(datasourceadmin.CodeConflict)
		}
		if metadata.schema == datasourceadmin.SchemaVersionV1 {
			rows = append(rows, datasourceadmin.RetentionGeneration{
				Generation: metadata.generation, Schema: metadata.schema, State: metadata.state,
				Ownership: datasourceadmin.RetentionOwnershipUnknown,
			})
			continue
		}
		records, recordPresent, readErr := client.ReadGenerationRecords(ctx, metadata.generation, a.limits, a.generations)
		if readErr != nil || !recordPresent {
			clearDatasetRecords(&records)
			return datasourceadmin.RetentionInventory{}, datasourceadminError(datasourceadmin.CodeUnavailable)
		}
		readBytes := datasetRecordsDecodedBytes(records)
		if readBytes > int(limits.MaxReadBytes) || bytesRead > int(limits.MaxReadBytes)-readBytes {
			clearDatasetRecords(&records)
			return datasourceadmin.RetentionInventory{}, datasourceadminError(datasourceadmin.CodeLimitExceeded)
		}
		bytesRead += readBytes
		snapshot, verified, verifyErr := snapshotFromRecords(records)
		clearDatasetRecords(&records)
		if verifyErr != nil || !metadata.equal(verified) {
			_ = snapshot.Close()
			return datasourceadmin.RetentionInventory{}, datasourceadminError(datasourceadmin.CodeConflict)
		}
		_ = snapshot.Close()
		row := datasourceadmin.RetentionGeneration{Generation: verified.generation, Operation: verified.operation, SourceGeneration: verified.sourceGeneration, Schema: verified.schema, State: verified.state, WasActive: verified.wasActive, Ownership: datasourceadmin.RetentionOwnershipTrusted}
		if verified.schema == datasourceadmin.SchemaVersionV3 && verified.digest.Valid() {
			digest, digestErr := admincontract.ParseDigest(verified.digest.Bytes())
			if digestErr != nil {
				return datasourceadmin.RetentionInventory{}, datasourceadminError(datasourceadmin.CodeConflict)
			}
			row.ContentDigest, row.Complete = digest, true
		}
		if verified.generation == current.generation {
			if !current.matchesRoot(verified) {
				return datasourceadmin.RetentionInventory{}, datasourceadminError(datasourceadmin.CodeConflict)
			}
			currentMatches++
		}
		rows = append(rows, row)
	}
	if currentMatches != 1 {
		return datasourceadmin.RetentionInventory{}, datasourceadminError(datasourceadmin.CodeConflict)
	}
	final, finalPresent, finalErr := client.ReadCurrentOptional(ctx)
	if finalErr != nil || !finalPresent {
		return datasourceadmin.RetentionInventory{}, datasourceadminError(datasourceadmin.CodeUnavailable)
	}
	defer clearEntry(&final)
	finalMetadata, finalMapErr := mapCurrentMetadata(final)
	if finalMapErr != nil || !current.equal(finalMetadata) {
		return datasourceadmin.RetentionInventory{}, datasourceadminError(datasourceadmin.CodeConflict)
	}
	return datasourceadmin.RetentionInventory{Version: "ldap-recovery-v1", Current: current.generation, Generations: rows}, nil
}

// AdministrationConnector opens one LDAP session and exposes only an opaque
// bind identity for construction-time role separation.
type AdministrationConnector interface {
	Connector
	AdministrationAuthority() AdministrationAuthority
}

// Administrator owns bounded LDAP snapshot, staging, activation, and lock coordination.
type Administrator struct {
	snapshot    AdministrationConnector
	stager      AdministrationConnector
	activator   AdministrationConnector
	limits      provider.Limits
	generations datasourceadmin.GenerationLimits
}

// Close clears role-scoped connector material after the one-shot administration workflow.
func (a *Administrator) Close() error {
	if a == nil {
		return nil
	}
	var result error
	for _, connector := range []AdministrationConnector{a.snapshot, a.stager, a.activator} {
		if closer, ok := connector.(interface{ Close() error }); ok {
			if err := closer.Close(); result == nil && err != nil {
				result = err
			}
		}
	}
	a.snapshot, a.stager, a.activator = nil, nil, nil
	return result
}

// NewAdministrator validates three distinct role connectors and finite LDAP bounds.
func NewAdministrator(
	snapshot AdministrationConnector,
	stager AdministrationConnector,
	activator AdministrationConnector,
	limits provider.Limits,
	generations datasourceadmin.GenerationLimits,
) (*Administrator, error) {
	if snapshot == nil || stager == nil || activator == nil || limits.Validate() != nil ||
		generations.Validate() != nil {
		return nil, datasourceadminError(datasourceadmin.CodeInvalid)
	}
	snapshotAuthority := snapshot.AdministrationAuthority()
	stagerAuthority := stager.AdministrationAuthority()
	activatorAuthority := activator.AdministrationAuthority()
	if !snapshotAuthority.Valid() || !stagerAuthority.Valid() || !activatorAuthority.Valid() ||
		snapshotAuthority.Equal(stagerAuthority) ||
		snapshotAuthority.Equal(activatorAuthority) ||
		stagerAuthority.Equal(activatorAuthority) {
		return nil, datasourceadminError(datasourceadmin.CodeInvalid)
	}
	return &Administrator{
		snapshot: snapshot, stager: stager, activator: activator, limits: limits,
		generations: generations,
	}, nil
}

// ReadCurrent returns one stable complete protected current generation.
func (a *Administrator) ReadCurrent(
	ctx context.Context,
	limits datasourceadmin.GenerationLimits,
) (*datasourceadmin.Snapshot, error) {
	client, closeClient, err := a.connect(ctx, a.snapshot, limits)
	if err != nil {
		return nil, err
	}
	defer closeClient()
	inventory, err := a.readStableInventory(ctx, client, limits)
	if err != nil {
		return nil, err
	}
	if _, err := datasourceadmin.AllocateGeneration(inventory, limits); err != nil {
		return nil, err
	}
	current, present, err := client.ReadCurrentOptional(ctx)
	if err != nil || !present {
		return nil, datasourceadminError(datasourceadmin.CodeUnavailable)
	}
	defer clearEntry(&current)
	metadata, err := mapCurrentMetadata(current)
	if err != nil {
		return nil, datasourceadminError(datasourceadmin.CodeConflict)
	}
	records, present, err := client.ReadGenerationRecords(ctx, metadata.generation, a.limits, limits)
	if err != nil || !present {
		return nil, datasourceadminError(datasourceadmin.CodeUnavailable)
	}
	defer clearDatasetRecords(&records)
	snapshot, root, err := snapshotFromRecords(records)
	if err != nil || !metadata.matchesRoot(root) {
		_ = snapshot.Close()
		return nil, datasourceadminError(datasourceadmin.CodeConflict)
	}
	finalCurrent, finalPresent, err := client.ReadCurrentOptional(ctx)
	if err != nil || !finalPresent {
		_ = snapshot.Close()
		return nil, datasourceadminError(datasourceadmin.CodeUnavailable)
	}
	defer clearEntry(&finalCurrent)
	finalMetadata, err := mapCurrentMetadata(finalCurrent)
	if err != nil || !metadata.equal(finalMetadata) || inventory.Current != metadata.generation {
		_ = snapshot.Close()
		return nil, datasourceadminError(datasourceadmin.CodeConflict)
	}
	return snapshot, nil
}

// Inventory returns one stable bounded current pointer and generation inventory.
func (a *Administrator) Inventory(
	ctx context.Context,
	limits datasourceadmin.GenerationLimits,
) (datasourceadmin.Inventory, error) {
	client, closeClient, err := a.connect(ctx, a.snapshot, limits)
	if err != nil {
		return datasourceadmin.Inventory{}, err
	}
	defer closeClient()
	return a.readStableInventory(ctx, client, limits)
}

// ReadCollisionInventory returns one complete identity view under an unchanged exact lock.
func (a *Administrator) ReadCollisionInventory(
	ctx context.Context,
	lock datasourceadmin.AdministrationLock,
	limits datasourceadmin.GenerationLimits,
) (*datasourceadmin.CollisionInventory, error) {
	if !lock.ValidFor(lock.Owner()) {
		return nil, datasourceadminError(datasourceadmin.CodeInvalid)
	}
	client, closeClient, err := a.connect(ctx, a.snapshot, limits)
	if err != nil {
		return nil, err
	}
	defer closeClient()
	if err := requireObservedLock(ctx, client, lock); err != nil {
		return nil, err
	}
	inventory, err := a.readStableInventory(ctx, client, limits)
	if err != nil {
		return nil, err
	}
	if _, err := datasourceadmin.AllocateGeneration(inventory, limits); err != nil {
		return nil, err
	}
	snapshots := make([]datasourceadmin.CollisionSnapshot, 0, len(inventory.Generations))
	aggregateBytes := 0
	for _, info := range inventory.Generations {
		if !info.Current && !info.Outstanding() {
			continue
		}
		records, present, readErr := client.ReadGenerationRecords(ctx, info.Generation, a.limits, limits)
		if readErr != nil || !present {
			clearDatasetRecords(&records)
			closeCollisionSnapshotValues(snapshots)
			return nil, datasourceadminError(datasourceadmin.CodeUnavailable)
		}
		readBytes := datasetRecordsDecodedBytes(records)
		if readBytes > int(limits.MaxSnapshotBytes) || aggregateBytes > int(limits.MaxSnapshotBytes)-readBytes {
			clearDatasetRecords(&records)
			closeCollisionSnapshotValues(snapshots)
			return nil, datasourceadminError(datasourceadmin.CodeLimitExceeded)
		}
		aggregateBytes += readBytes
		snapshot, metadata, mapErr := snapshotFromRecords(records)
		clearDatasetRecords(&records)
		if mapErr != nil || !generationInfoMatches(info, metadata) {
			_ = snapshot.Close()
			closeCollisionSnapshotValues(snapshots)
			return nil, datasourceadminError(datasourceadmin.CodeConflict)
		}
		snapshots = append(snapshots, datasourceadmin.CollisionSnapshot{Info: info, Snapshot: snapshot})
	}
	if err := requireObservedLock(ctx, client, lock); err != nil {
		closeCollisionSnapshotValues(snapshots)
		return nil, err
	}
	return datasourceadmin.NewCollisionInventory(ctx, lock, inventory, snapshots, limits)
}

// Current returns one stable current generation classification or proven empty state.
func (a *Administrator) Current(
	ctx context.Context,
	limits datasourceadmin.GenerationLimits,
) (datasourceadmin.GenerationInfo, error) {
	inventory, err := a.Inventory(ctx, limits)
	if err != nil {
		return datasourceadmin.GenerationInfo{}, err
	}
	if inventory.Current == 0 {
		return datasourceadmin.GenerationInfo{}, nil
	}
	for _, info := range inventory.Generations {
		if info.Current {
			return info, nil
		}
	}
	return datasourceadmin.GenerationInfo{}, datasourceadminError(datasourceadmin.CodeConflict)
}

// Claim atomically acquires or confirms one exact ownerless LDAP revision.
func (a *Administrator) Claim(
	ctx context.Context,
	operation datasourceadmin.OperationBinding,
	revision uint64,
) (datasourceadmin.AdministrationLock, error) {
	if !operation.Initialized() || revision == 0 {
		return datasourceadmin.AdministrationLock{}, datasourceadminError(datasourceadmin.CodeInvalid)
	}
	client, closeClient, err := a.connectWithoutGenerationLimits(ctx, a.stager)
	if err != nil {
		return datasourceadmin.AdministrationLock{}, err
	}
	defer closeClient()
	observed, err := client.ReadAdministrationLock(ctx)
	if err != nil || !observed.Valid() {
		return datasourceadmin.AdministrationLock{}, datasourceadminError(datasourceadmin.CodeUnavailable)
	}
	if observed.Claimed() {
		if observed.Revision() == revision && observed.Owner().Equal(operation) {
			return datasourceadmin.NewAdministrationLock(operation, revision)
		}
		return datasourceadmin.AdministrationLock{}, datasourceadminError(datasourceadmin.CodeConflict)
	}
	if observed.Revision() != revision {
		return datasourceadmin.AdministrationLock{}, datasourceadminError(datasourceadmin.CodeConflict)
	}
	if err := client.ClaimAdministrationLock(ctx, operation, revision); err != nil {
		return datasourceadmin.AdministrationLock{}, datasourceadminError(datasourceadmin.CodeReconcileRequired)
	}
	confirmed, err := client.ReadAdministrationLock(ctx)
	if err != nil || !confirmed.Valid() || !confirmed.Claimed() ||
		confirmed.Revision() != revision || !confirmed.Owner().Equal(operation) {
		return datasourceadmin.AdministrationLock{}, datasourceadminError(datasourceadmin.CodeReconcileRequired)
	}
	return datasourceadmin.NewAdministrationLock(operation, revision)
}

// Release atomically clears only the exact owner and advances revision once.
func (a *Administrator) Release(
	ctx context.Context,
	lock datasourceadmin.AdministrationLock,
) (uint64, error) {
	if !lock.ValidFor(lock.Owner()) || lock.Revision() == ^uint64(0) {
		return 0, datasourceadminError(datasourceadmin.CodeInvalid)
	}
	client, closeClient, err := a.connectWithoutGenerationLimits(ctx, a.stager)
	if err != nil {
		return 0, err
	}
	defer closeClient()
	observed, err := client.ReadAdministrationLock(ctx)
	if err != nil || !observed.Valid() {
		return 0, datasourceadminError(datasourceadmin.CodeUnavailable)
	}
	next := lock.Revision() + 1
	if !observed.Claimed() {
		if observed.Revision() == next {
			return next, nil
		}
		return 0, datasourceadminError(datasourceadmin.CodeConflict)
	}
	if observed.Revision() != lock.Revision() || !observed.Owner().Equal(lock.Owner()) {
		return 0, datasourceadminError(datasourceadmin.CodeConflict)
	}
	if err := client.ReleaseAdministrationLock(ctx, lock); err != nil {
		return 0, datasourceadminError(datasourceadmin.CodeReconcileRequired)
	}
	confirmed, err := client.ReadAdministrationLock(ctx)
	if err != nil || !confirmed.Valid() || confirmed.Claimed() || confirmed.Revision() != next {
		return 0, datasourceadminError(datasourceadmin.CodeReconcileRequired)
	}
	return next, nil
}

// ObserveAdministrationLock reads one bounded owner/revision sight without mutation.
func (a *Administrator) ObserveAdministrationLock(
	ctx context.Context,
) (datasourceadmin.AdministrationLockObservation, error) {
	client, closeClient, err := a.connectWithoutGenerationLimits(ctx, a.snapshot)
	if err != nil {
		return datasourceadmin.AdministrationLockObservation{}, err
	}
	defer closeClient()
	observation, err := client.ReadAdministrationLock(ctx)
	if err != nil || !observation.Valid() {
		return datasourceadmin.AdministrationLockObservation{}, datasourceadminError(datasourceadmin.CodeUnavailable)
	}
	return observation, nil
}

// Stage writes, fully rereads, and seals one exact operation-bound generation.
func (a *Administrator) Stage(
	ctx context.Context,
	lock datasourceadmin.AdministrationLock,
	operation datasourceadmin.OperationBinding,
	candidate *datasourceadmin.PublicationEnvelope,
) (datasourceadmin.StagedEvidence, error) {
	if candidate == nil || !lock.ValidFor(operation) || !candidate.Binding().Equal(operation) ||
		candidate.Generation() == 0 || !candidate.Digest().Valid() {
		return datasourceadmin.StagedEvidence{}, datasourceadminError(datasourceadmin.CodeInvalid)
	}
	limits := a.generations
	client, closeClient, err := a.connect(ctx, a.stager, limits)
	if err != nil {
		return datasourceadmin.StagedEvidence{}, err
	}
	defer closeClient()
	if err := requireObservedLock(ctx, client, lock); err != nil {
		return datasourceadmin.StagedEvidence{}, err
	}
	inventory, err := a.readStableInventory(ctx, client, limits)
	if err != nil {
		return datasourceadmin.StagedEvidence{}, err
	}
	existing, existingFound := generationByNumber(inventory, candidate.Generation())
	if existingFound {
		if existing.Current || !existing.Outstanding() || !existing.Operation.Initialized() ||
			!existing.Operation.Equal(operation) {
			return datasourceadmin.StagedEvidence{}, datasourceadminError(datasourceadmin.CodeReconcileRequired)
		}
	} else {
		allocated, allocateErr := datasourceadmin.AllocateGeneration(inventory, limits)
		if allocateErr != nil || allocated != candidate.Generation() {
			return datasourceadmin.StagedEvidence{}, datasourceadminError(datasourceadmin.CodeConflict)
		}
		if err := requireObservedLock(ctx, client, lock); err != nil {
			return datasourceadmin.StagedEvidence{}, err
		}
		if err := client.AddCandidate(ctx, candidate); err != nil {
			return datasourceadmin.StagedEvidence{}, datasourceadminError(datasourceadmin.CodeReconcileRequired)
		}
	}
	readback, metadata, err := a.readCandidate(ctx, client, operation, candidate.Generation(), limits)
	if err != nil {
		return datasourceadmin.StagedEvidence{}, datasourceadminError(datasourceadmin.CodeReconcileRequired)
	}
	defer readback.Close() //nolint:errcheck // Readback cleanup has no recovery action.
	if !readback.Digest().Equal(candidate.Digest()) {
		return datasourceadmin.StagedEvidence{}, datasourceadminError(datasourceadmin.CodeReconcileRequired)
	}
	if metadata.state == datasourceadmin.StateCommitted {
		return datasourceadmin.NewStagedEvidence(readback.Digest()), nil
	}
	if metadata.state != datasourceadmin.StateStaging {
		return datasourceadmin.StagedEvidence{}, datasourceadminError(datasourceadmin.CodeReconcileRequired)
	}
	if err := requireObservedLock(ctx, client, lock); err != nil {
		return datasourceadmin.StagedEvidence{}, err
	}
	if err := client.SealCandidate(ctx, candidate.Generation(), operation, candidate.Digest()); err != nil {
		return datasourceadmin.StagedEvidence{}, datasourceadminError(datasourceadmin.CodeReconcileRequired)
	}
	sealed, sealedMetadata, err := a.readCandidate(ctx, client, operation, candidate.Generation(), limits)
	if err != nil {
		return datasourceadmin.StagedEvidence{}, datasourceadminError(datasourceadmin.CodeReconcileRequired)
	}
	defer sealed.Close() //nolint:errcheck // Readback cleanup has no recovery action.
	if sealedMetadata.state != datasourceadmin.StateCommitted ||
		!sealed.Digest().Equal(candidate.Digest()) {
		return datasourceadmin.StagedEvidence{}, datasourceadminError(datasourceadmin.CodeReconcileRequired)
	}
	return datasourceadmin.NewStagedEvidence(sealed.Digest()), nil
}

// generationByNumber returns one exact bounded inventory item without inference.
func generationByNumber(
	inventory datasourceadmin.Inventory,
	generation uint64,
) (datasourceadmin.GenerationInfo, bool) {
	for _, info := range inventory.Generations {
		if info.Generation == generation {
			return info, true
		}
	}
	return datasourceadmin.GenerationInfo{}, false
}

// Inspect returns one complete exact staging or committed candidate readback.
func (a *Administrator) Inspect(
	ctx context.Context,
	operation datasourceadmin.OperationBinding,
	generation uint64,
	expectedCurrent uint64,
	limits datasourceadmin.GenerationLimits,
) (*datasourceadmin.PublicationEnvelope, datasourceadmin.GenerationInfo, error) {
	if !operation.Initialized() || generation == 0 || generation <= expectedCurrent {
		return nil, datasourceadmin.GenerationInfo{}, datasourceadminError(datasourceadmin.CodeInvalid)
	}
	client, closeClient, err := a.connect(ctx, a.snapshot, limits)
	if err != nil {
		return nil, datasourceadmin.GenerationInfo{}, err
	}
	defer closeClient()
	inventory, err := a.readStableInventory(ctx, client, limits)
	if err != nil {
		return nil, datasourceadmin.GenerationInfo{}, err
	}
	if inventory.Current != expectedCurrent && inventory.Current != generation {
		return nil, datasourceadmin.GenerationInfo{}, datasourceadminError(datasourceadmin.CodeConflict)
	}
	info, found := generationByNumber(inventory, generation)
	if !found {
		return nil, datasourceadmin.GenerationInfo{}, datasourceadminError(datasourceadmin.CodeUnavailable)
	}
	candidate, metadata, err := a.readCandidate(ctx, client, operation, generation, limits)
	if err != nil {
		return nil, datasourceadmin.GenerationInfo{}, err
	}
	if !generationInfoMatches(info, metadata) {
		_ = candidate.Close()
		return nil, datasourceadmin.GenerationInfo{}, datasourceadminError(datasourceadmin.CodeConflict)
	}
	return candidate, info, nil
}

// Observe classifies one candidate and current pointer from fresh bounded readback.
func (a *Administrator) Observe(
	ctx context.Context,
	operation datasourceadmin.OperationBinding,
	generation uint64,
	expectedCurrent uint64,
	limits datasourceadmin.GenerationLimits,
) (datasourceadmin.PublicationObservation, error) {
	if !operation.Initialized() || generation == 0 || generation <= expectedCurrent {
		return datasourceadmin.PublicationObservation{}, datasourceadminError(datasourceadmin.CodeInvalid)
	}
	client, closeClient, err := a.connect(ctx, a.snapshot, limits)
	if err != nil {
		return datasourceadmin.PublicationObservation{}, err
	}
	defer closeClient()
	inventory, err := a.readStableInventory(ctx, client, limits)
	if err != nil {
		return datasourceadmin.PublicationObservation{}, err
	}
	currentGeneration := inventory.Current
	if currentGeneration != expectedCurrent && currentGeneration != generation {
		return datasourceadmin.PublicationObservation{}, datasourceadminError(datasourceadmin.CodeConflict)
	}
	records, candidatePresent, readErr := client.ReadGenerationRecords(ctx, generation, a.limits, limits)
	if readErr != nil {
		state := datasourceadmin.PublicationUnknown
		if errors.Is(readErr, errLDAPPartial) {
			state = datasourceadmin.PublicationPartial
		}
		return datasourceadmin.NewPublicationObservation(
			currentGeneration, generation, state,
			datasourceadmin.OperationBinding{}, datasourceadmin.StagedEvidence{}, false,
		)
	}
	if !candidatePresent {
		return datasourceadmin.NewPublicationObservation(
			currentGeneration, generation, datasourceadmin.PublicationAbsent,
			datasourceadmin.OperationBinding{}, datasourceadmin.StagedEvidence{}, false,
		)
	}
	defer clearDatasetRecords(&records)
	candidate, metadata, mapErr := candidateFromRecords(ctx, records)
	if mapErr != nil {
		return datasourceadmin.NewPublicationObservation(
			currentGeneration, generation, datasourceadmin.PublicationMismatch,
			datasourceadmin.OperationBinding{}, datasourceadmin.StagedEvidence{}, false,
		)
	}
	defer candidate.Close() //nolint:errcheck // Observation cleanup has no recovery action.
	if !metadata.operation.Equal(operation) {
		return datasourceadmin.NewPublicationObservation(
			currentGeneration, generation, datasourceadmin.PublicationMismatch,
			datasourceadmin.OperationBinding{}, datasourceadmin.StagedEvidence{}, false,
		)
	}
	state := datasourceadmin.PublicationExactStaging
	if metadata.state == datasourceadmin.StateCommitted {
		state = datasourceadmin.PublicationExactCommitted
	}
	oldWasActive := false
	if expectedCurrent != 0 {
		oldInfo, found := generationByNumber(inventory, expectedCurrent)
		if !found {
			return datasourceadmin.PublicationObservation{}, datasourceadminError(datasourceadmin.CodeConflict)
		}
		oldWasActive = oldInfo.WasActive
	}
	return datasourceadmin.NewPublicationObservation(
		currentGeneration, generation, state, metadata.operation,
		datasourceadmin.NewStagedEvidence(candidate.Digest()), oldWasActive,
	)
}

// Activate advances only an exactly inspected committed candidate and current fence.
func (a *Administrator) Activate(ctx context.Context, activation datasourceadmin.Activation) error {
	if !activation.Valid() {
		return datasourceadminError(datasourceadmin.CodeInvalid)
	}
	limits := a.generations
	client, closeClient, err := a.connect(ctx, a.activator, limits)
	if err != nil {
		return err
	}
	defer closeClient()
	if err := requireObservedLock(ctx, client, activation.Lock()); err != nil {
		return err
	}
	inventory, err := a.readStableInventory(ctx, client, limits)
	if err != nil {
		return err
	}
	if inventory.Current != activation.ExpectedCurrent() {
		return datasourceadminError(datasourceadmin.CodeConflict)
	}
	candidateInfo, found := generationByNumber(inventory, activation.CandidateGeneration())
	if !found || candidateInfo.Current {
		return datasourceadminError(datasourceadmin.CodeConflict)
	}
	candidate, candidateMetadata, err := a.readCandidate(
		ctx, client, activation.Operation(), activation.CandidateGeneration(), limits,
	)
	if err != nil {
		return err
	}
	defer candidate.Close() //nolint:errcheck // Activation readback cleanup has no recovery action.
	if candidateMetadata.state != datasourceadmin.StateCommitted ||
		!generationInfoMatches(candidateInfo, candidateMetadata) ||
		!activation.Prepared().Matches(datasourceadmin.NewStagedEvidence(candidate.Digest())) ||
		!activation.Staged().Digest().Equal(candidate.Digest()) {
		return datasourceadminError(datasourceadmin.CodeConflict)
	}
	currentEntry, currentPresent, err := client.ReadCurrentOptional(ctx)
	if err != nil {
		return datasourceadminError(datasourceadmin.CodeUnavailable)
	}
	if currentPresent {
		defer clearEntry(&currentEntry)
	}
	if activation.ExpectedCurrent() == 0 {
		return activateBootstrap(ctx, client, activation, candidateMetadata, currentPresent)
	}
	return a.activateEstablished(ctx, client, activation, candidateMetadata, currentEntry, currentPresent, limits)
}

// activateBootstrap creates the sole absent-current v3 fence and confirms it.
func activateBootstrap(
	ctx context.Context,
	client administrationClient,
	activation datasourceadmin.Activation,
	candidate datasetMetadata,
	currentPresent bool,
) error {
	if currentPresent || activation.CandidateGeneration() != 1 {
		return datasourceadminError(datasourceadmin.CodeConflict)
	}
	if err := requireObservedLock(ctx, client, activation.Lock()); err != nil {
		return err
	}
	if err := client.AddCurrent(ctx, candidate); err != nil {
		return datasourceadminError(datasourceadmin.CodeReconcileRequired)
	}
	return confirmCurrent(ctx, client, candidate)
}

// activateEstablished marks exact history and advances one existing current fence.
func (a *Administrator) activateEstablished(
	ctx context.Context,
	client administrationClient,
	activation datasourceadmin.Activation,
	candidate datasetMetadata,
	currentEntry Entry,
	currentPresent bool,
	limits datasourceadmin.GenerationLimits,
) error {
	if !currentPresent {
		return datasourceadminError(datasourceadmin.CodeConflict)
	}
	currentMetadata, err := mapCurrentMetadata(currentEntry)
	if err != nil || currentMetadata.generation != activation.ExpectedCurrent() {
		return datasourceadminError(datasourceadmin.CodeConflict)
	}
	oldRecords, present, err := client.ReadGenerationRecords(ctx, currentMetadata.generation, a.limits, limits)
	if err != nil || !present {
		return datasourceadminError(datasourceadmin.CodeUnavailable)
	}
	defer clearDatasetRecords(&oldRecords)
	oldMetadata, err := mapGenerationMetadata(oldRecords.Root)
	if err != nil || !currentMetadata.matchesRoot(oldMetadata) {
		return datasourceadminError(datasourceadmin.CodeConflict)
	}
	if err := a.markWasActive(ctx, client, activation.Lock(), oldMetadata, limits); err != nil {
		return err
	}
	if err := requireObservedLock(ctx, client, activation.Lock()); err != nil {
		return err
	}
	if err := client.ReplaceCurrent(ctx, currentMetadata, candidate); err != nil {
		return datasourceadminError(datasourceadmin.CodeReconcileRequired)
	}
	return confirmCurrent(ctx, client, candidate)
}

// markWasActive applies and confirms only the monotonic exact old-root marker.
func (a *Administrator) markWasActive(
	ctx context.Context,
	client administrationClient,
	lock datasourceadmin.AdministrationLock,
	old datasetMetadata,
	limits datasourceadmin.GenerationLimits,
) error {
	if old.wasActive {
		return nil
	}
	if err := requireObservedLock(ctx, client, lock); err != nil {
		return err
	}
	if err := client.MarkWasActive(ctx, old); err != nil {
		return datasourceadminError(datasourceadmin.CodeReconcileRequired)
	}
	confirmedRecords, confirmed, err := client.ReadGenerationRecords(ctx, old.generation, a.limits, limits)
	if err != nil || !confirmed {
		return datasourceadminError(datasourceadmin.CodeReconcileRequired)
	}
	defer clearDatasetRecords(&confirmedRecords)
	confirmedMetadata, err := mapGenerationMetadata(confirmedRecords.Root)
	if err != nil || !confirmedMetadata.wasActive || !old.equalExceptHistory(confirmedMetadata) {
		return datasourceadminError(datasourceadmin.CodeReconcileRequired)
	}
	return nil
}

// readCandidate returns exact operation-bound canonical generation content.
func (a *Administrator) readCandidate(
	ctx context.Context,
	client administrationClient,
	operation datasourceadmin.OperationBinding,
	generation uint64,
	limits datasourceadmin.GenerationLimits,
) (*datasourceadmin.PublicationEnvelope, datasetMetadata, error) {
	records, present, err := client.ReadGenerationRecords(ctx, generation, a.limits, limits)
	if err != nil || !present {
		return nil, datasetMetadata{}, datasourceadminError(datasourceadmin.CodeUnavailable)
	}
	defer clearDatasetRecords(&records)
	candidate, metadata, err := candidateFromRecords(ctx, records)
	if err != nil || !metadata.operation.Equal(operation) || metadata.generation != generation {
		_ = candidate.Close()
		return nil, datasetMetadata{}, datasourceadminError(datasourceadmin.CodeConflict)
	}
	return candidate, metadata, nil
}

// candidateFromRecords reconstructs one v3 candidate only from exact complete readback.
func candidateFromRecords(
	ctx context.Context,
	records DatasetRecords,
) (*datasourceadmin.PublicationEnvelope, datasetMetadata, error) {
	metadata, err := mapGenerationMetadata(records.Root)
	if err != nil || metadata.schema != datasourceadmin.SchemaVersionV3 ||
		!metadata.operation.Initialized() || !metadata.digest.Valid() {
		return nil, datasetMetadata{}, provider.NewError(provider.ErrorCodeMalformedData)
	}
	rows, err := mapAdministrativeRows(records, metadata.generation)
	if err != nil {
		return nil, datasetMetadata{}, err
	}
	defer clearAdministrativeRows(&rows)
	snapshot, err := datasourceadmin.NewSnapshot(metadata.schema, metadata.generation, rows)
	if err != nil {
		return nil, datasetMetadata{}, provider.NewError(provider.ErrorCodeMalformedData)
	}
	content, err := datasourceadmin.NewCandidateContent(snapshot)
	if err != nil {
		_ = snapshot.Close()
		return nil, datasetMetadata{}, provider.NewError(provider.ErrorCodeMalformedData)
	}
	var candidate *datasourceadmin.PublicationEnvelope
	if err := metadata.operation.WithValue(ctx, func(value string) error {
		var candidateErr error
		if metadata.sourceGeneration != 0 {
			candidate, candidateErr = datasourceadmin.NewCampaignPublicationEnvelope(value, metadata.sourceGeneration, content)
		} else {
			candidate, candidateErr = datasourceadmin.NewPublicationEnvelope(value, content)
		}
		return candidateErr
	}); err != nil || candidate == nil {
		_ = content.Close()
		return nil, datasetMetadata{}, provider.NewError(provider.ErrorCodeMalformedData)
	}
	if !candidate.Digest().Equal(metadata.digest) {
		_ = candidate.Close()
		return nil, datasetMetadata{}, provider.NewError(provider.ErrorCodeMalformedData)
	}
	return candidate, metadata, nil
}

// snapshotFromRecords constructs one exact protected v2 or v3 generation snapshot.
func snapshotFromRecords(records DatasetRecords) (*datasourceadmin.Snapshot, datasetMetadata, error) {
	metadata, err := mapGenerationMetadata(records.Root)
	if err != nil {
		return nil, datasetMetadata{}, err
	}
	rows, err := mapAdministrativeRows(records, metadata.generation)
	if err != nil {
		return nil, datasetMetadata{}, err
	}
	defer clearAdministrativeRows(&rows)
	snapshot, err := datasourceadmin.NewSnapshot(metadata.schema, metadata.generation, rows)
	if err != nil {
		return nil, datasetMetadata{}, err
	}
	if metadata.schema == datasourceadmin.SchemaVersionV3 {
		candidate, _, candidateErr := candidateFromRecords(context.Background(), records)
		if candidateErr != nil {
			_ = snapshot.Close()
			return nil, datasetMetadata{}, candidateErr
		}
		_ = candidate.Close()
	}
	return snapshot, metadata, nil
}

// info projects exact protected LDAP root metadata into the neutral inventory contract.
func (m datasetMetadata) info(current bool) datasourceadmin.GenerationInfo {
	return datasourceadmin.GenerationInfo{
		Generation: m.generation, Current: current, State: m.state,
		WasActive: m.wasActive, Operation: m.operation, SourceGeneration: m.sourceGeneration, Schema: m.schema, ContentDigest: m.digest,
	}
}

// equalExceptHistory proves that only the monotonic was-active bit changed.
func (m datasetMetadata) equalExceptHistory(other datasetMetadata) bool {
	m.wasActive = other.wasActive
	return m.equal(other)
}

// confirmCurrent converts every ambiguous post-mutation read into reconciliation.
func confirmCurrent(
	ctx context.Context,
	client administrationClient,
	candidate datasetMetadata,
) error {
	entry, present, err := client.ReadCurrentOptional(ctx)
	if err != nil || !present {
		return datasourceadminError(datasourceadmin.CodeReconcileRequired)
	}
	defer clearEntry(&entry)
	current, err := mapCurrentMetadata(entry)
	if err != nil || !current.matchesRoot(candidate) {
		return datasourceadminError(datasourceadmin.CodeReconcileRequired)
	}
	return nil
}

// readStableInventory fences root enumeration with exact current reread.
func (a *Administrator) readStableInventory(
	ctx context.Context,
	client administrationClient,
	limits datasourceadmin.GenerationLimits,
) (datasourceadmin.Inventory, error) {
	first, firstPresent, err := client.ReadCurrentOptional(ctx)
	if err != nil {
		return datasourceadmin.Inventory{}, datasourceadminError(datasourceadmin.CodeUnavailable)
	}
	if firstPresent {
		defer clearEntry(&first)
	}
	var current datasetMetadata
	if firstPresent {
		current, err = mapCurrentMetadata(first)
		if err != nil {
			return datasourceadmin.Inventory{}, datasourceadminError(datasourceadmin.CodeConflict)
		}
	}
	roots, err := client.ListGenerationRoots(ctx, limits)
	if err != nil || len(roots) > int(limits.MaxGenerations) {
		return datasourceadmin.Inventory{}, datasourceadminError(datasourceadmin.CodeUnavailable)
	}
	defer clearEntries(roots)
	inventory := datasourceadmin.Inventory{}
	if firstPresent {
		inventory.Current = current.generation
	}
	currentMatches := 0
	seen := make(map[uint64]struct{}, len(roots))
	for _, entry := range roots {
		metadata, mapErr := mapInventoryGenerationMetadata(entry)
		if mapErr != nil {
			return datasourceadmin.Inventory{}, datasourceadminError(datasourceadmin.CodeConflict)
		}
		if _, duplicate := seen[metadata.generation]; duplicate {
			return datasourceadmin.Inventory{}, datasourceadminError(datasourceadmin.CodeConflict)
		}
		seen[metadata.generation] = struct{}{}
		isCurrent := firstPresent && metadata.generation == current.generation
		if isCurrent {
			if !current.matchesRoot(metadata) {
				return datasourceadmin.Inventory{}, datasourceadminError(datasourceadmin.CodeConflict)
			}
			currentMatches++
		}
		inventory.Generations = append(inventory.Generations, metadata.info(isCurrent))
	}
	if firstPresent && currentMatches != 1 {
		return datasourceadmin.Inventory{}, datasourceadminError(datasourceadmin.CodeConflict)
	}
	final, finalPresent, err := client.ReadCurrentOptional(ctx)
	if err != nil || finalPresent != firstPresent {
		return datasourceadmin.Inventory{}, datasourceadminError(datasourceadmin.CodeUnavailable)
	}
	if finalPresent {
		defer clearEntry(&final)
	}
	if finalPresent {
		finalMetadata, mapErr := mapCurrentMetadata(final)
		if mapErr != nil || !current.equal(finalMetadata) {
			return datasourceadmin.Inventory{}, datasourceadminError(datasourceadmin.CodeConflict)
		}
	}
	canonical := inventory.Canonicalize()
	if err := datasourceadmin.ValidateInventory(canonical, limits); err != nil {
		if datasourceadmin.CodeOf(err) == datasourceadmin.CodeLimitExceeded {
			return datasourceadmin.Inventory{}, datasourceadminError(datasourceadmin.CodeLimitExceeded)
		}
		return datasourceadmin.Inventory{}, datasourceadminError(datasourceadmin.CodeConflict)
	}
	return canonical, nil
}

// generationInfoMatches compares exact root metadata with neutral inventory evidence.
func generationInfoMatches(info datasourceadmin.GenerationInfo, metadata datasetMetadata) bool {
	return info.Generation == metadata.generation && info.State == metadata.state &&
		info.WasActive == metadata.wasActive &&
		info.Operation.Initialized() == metadata.operation.Initialized() &&
		(!info.Operation.Initialized() || info.Operation.Equal(metadata.operation))
}

// requireObservedLock proves one exact LDAP owner/revision sight before mutation.
func requireObservedLock(
	ctx context.Context,
	client administrationClient,
	lock datasourceadmin.AdministrationLock,
) error {
	observed, err := client.ReadAdministrationLock(ctx)
	if err != nil {
		return datasourceadminError(datasourceadmin.CodeUnavailable)
	}
	if !observed.Valid() || !observed.Claimed() || observed.Revision() != lock.Revision() ||
		!observed.Owner().Equal(lock.Owner()) {
		return datasourceadminError(datasourceadmin.CodeConflict)
	}
	return nil
}

// connect validates bounds and opens one role-scoped administration session.
func (a *Administrator) connect(
	ctx context.Context,
	connector Connector,
	limits datasourceadmin.GenerationLimits,
) (administrationClient, func(), error) {
	if limits.Validate() != nil {
		return nil, func() {}, datasourceadminError(datasourceadmin.CodeLimitExceeded)
	}
	return a.connectWithoutGenerationLimits(ctx, connector)
}

// connectWithoutGenerationLimits opens one finite role-scoped administration session.
func (a *Administrator) connectWithoutGenerationLimits(
	ctx context.Context,
	connector Connector,
) (administrationClient, func(), error) {
	if a == nil || connector == nil || validateLoadContext(ctx, a.generations.BackendDeadline) != nil {
		return nil, func() {}, datasourceadminError(datasourceadmin.CodeInvalid)
	}
	client, err := connector.Connect(ctx)
	if err != nil || client == nil {
		return nil, func() {}, datasourceadminError(datasourceadmin.CodeUnavailable)
	}
	admin, ok := client.(administrationClient)
	if !ok || admin == nil {
		_ = client.Close()
		return nil, func() {}, datasourceadminError(datasourceadmin.CodeUnavailable)
	}
	return admin, func() { _ = admin.Close() }, nil
}

// datasetRecordsDecodedBytes returns the aggregate detached LDAP value bytes
// retained by one complete readback.
func datasetRecordsDecodedBytes(records DatasetRecords) int {
	total := entryBytes(records.Root)
	for _, entries := range [][]Entry{
		records.Handles, records.Profiles, records.Credentials, records.Policies, records.KeyMaterial,
	} {
		for _, entry := range entries {
			total += entryBytes(entry)
		}
	}
	return total
}

// closeCollisionSnapshotValues destroys locally retained collision snapshots.
func closeCollisionSnapshotValues(values []datasourceadmin.CollisionSnapshot) {
	for index := range values {
		_ = values[index].Snapshot.Close()
		values[index].Snapshot = nil
	}
}

// clearEntry destroys detached LDAP values after they cross the mapper boundary.
func clearEntry(entry *Entry) {
	if entry == nil {
		return
	}
	clearEntries([]Entry{*entry})
	*entry = Entry{}
}

// clearDatasetRecords destroys every detached LDAP value retained by a readback.
func clearDatasetRecords(records *DatasetRecords) {
	if records == nil {
		return
	}
	clearEntry(&records.Current)
	clearEntry(&records.Root)
	clearEntries(records.Handles)
	clearEntries(records.Profiles)
	clearEntries(records.Credentials)
	clearEntries(records.Policies)
	clearEntries(records.KeyMaterial)
	*records = DatasetRecords{}
}

// datasourceadminError creates one typed content-free administration error.
func datasourceadminError(code datasourceadmin.ErrorCode) error {
	return datasourceadmin.NewError(code)
}

// String returns a constant protected administrator representation.
func (*Administrator) String() string { return loaderRedacted }

// GoString returns a constant protected administrator representation.
func (*Administrator) GoString() string { return loaderRedacted }

// Format prevents formatting verbs from traversing administrator connectors.
func (*Administrator) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, loaderRedacted) }

// MarshalJSON emits no connector, authority, operation, or key facts.
func (*Administrator) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

var (
	_ datasourceadmin.SnapshotReader       = (*Administrator)(nil)
	_ datasourceadmin.GenerationPublisher  = (*Administrator)(nil)
	_ datasourceadmin.AdministrationLocker = (*Administrator)(nil)
)
