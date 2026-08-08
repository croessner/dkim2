package rotationadmin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

type publicationBackendFake struct {
	readback      *datasourceadmin.PublicationEnvelope
	operation     datasourceadmin.OperationBinding
	staged        datasourceadmin.StagedEvidence
	current       uint64
	stageCalls    int
	activateCalls int
	terminalCalls int
	failStage     bool
}

// ReadCurrent is unused by resume tests and rejects accidental new-campaign work.
func (*publicationBackendFake) ReadCurrent(context.Context, datasourceadmin.GenerationLimits) (*datasourceadmin.Snapshot, error) {
	return nil, errConflict
}

// Inventory is unused by resume tests and rejects accidental new-campaign work.
func (*publicationBackendFake) Inventory(context.Context, datasourceadmin.GenerationLimits) (datasourceadmin.Inventory, error) {
	return datasourceadmin.Inventory{}, errConflict
}

// ReadCollisionInventory is unused by resume tests and rejects accidental work.
func (*publicationBackendFake) ReadCollisionInventory(context.Context, datasourceadmin.AdministrationLock, datasourceadmin.GenerationLimits) (*datasourceadmin.CollisionInventory, error) {
	return nil, errConflict
}

type resumeLockerFake struct {
	claims        int
	claimRevision uint64
	fail          bool
	observed      datasourceadmin.AdministrationLockObservation
}

// Claim returns one fresh unique lock or simulates an unavailable post-crash fence.
func (f *resumeLockerFake) Claim(_ context.Context, operation datasourceadmin.OperationBinding, revision uint64) (datasourceadmin.AdministrationLock, error) {
	f.claims++
	f.claimRevision = revision
	if f.fail {
		return datasourceadmin.AdministrationLock{}, errors.New("claim unavailable")
	}
	return datasourceadmin.NewAdministrationLock(operation, revision)
}

// Release has no test-side authority.
func (*resumeLockerFake) Release(context.Context, datasourceadmin.AdministrationLock) (uint64, error) {
	return 0, nil
}

// ObserveAdministrationLock returns the exact ownerless backend revision.
func (f *resumeLockerFake) ObserveAdministrationLock(context.Context) (datasourceadmin.AdministrationLockObservation, error) {
	if f.observed.Valid() {
		return f.observed, nil
	}
	return datasourceadmin.NewAdministrationLockObservation(7, datasourceadmin.OperationBinding{}, false)
}

// TestCoordinatorClaimObservedLockUsesExactRevision freezes the provider fence
// and rejects a foreign owner before any claim mutation.
func TestCoordinatorClaimObservedLockUsesExactRevision(t *testing.T) {
	operation, _ := datasourceadmin.NewOperationBinding("aibqibiga4eascqlbqgzav3y4m")
	locker := &resumeLockerFake{}
	coordinator := &Coordinator{locker: locker}
	lock, err := coordinator.claimObservedLock(t.Context(), operation)
	if err != nil || !lock.ValidFor(operation) || locker.claims != 1 || locker.claimRevision != 7 {
		t.Fatal("claim did not use the exact observed positive revision")
	}
	foreign, _ := datasourceadmin.NewOperationBinding("aebagbafaydqqcikbmga2dqpca")
	locker.observed, _ = datasourceadmin.NewAdministrationLockObservation(8, foreign, true)
	if _, err := coordinator.claimObservedLock(t.Context(), operation); err == nil || locker.claims != 1 {
		t.Fatal("foreign owner reached the mutating claim")
	}
}

type resumeProofFake struct {
	calls int
	now   time.Time
}

// ProveBatch records a bounded successful proof completion.
func (f *resumeProofFake) ProveBatch(_ context.Context, _ *Prepared, _ Batch) (time.Time, error) {
	f.calls++
	return f.now, nil
}

// Current returns the exact fake current generation.
func (b *publicationBackendFake) Current(context.Context, datasourceadmin.GenerationLimits) (datasourceadmin.GenerationInfo, error) {
	return datasourceadmin.GenerationInfo{Generation: b.current, Current: true, State: datasourceadmin.StateCommitted}, nil
}

// Stage records one complete candidate and returns canonical evidence.
func (b *publicationBackendFake) Stage(ctx context.Context, _ datasourceadmin.AdministrationLock, operation datasourceadmin.OperationBinding, candidate *datasourceadmin.PublicationEnvelope) (datasourceadmin.StagedEvidence, error) {
	b.stageCalls++
	if b.failStage {
		return datasourceadmin.StagedEvidence{}, errBackend
	}
	clone, err := clonePublicationEnvelope(ctx, candidate, operation)
	if err != nil {
		return datasourceadmin.StagedEvidence{}, err
	}
	b.readback, b.operation, b.staged = clone, operation, datasourceadmin.NewStagedEvidence(clone.Digest())
	return b.staged, nil
}

// Inspect returns a fresh exact committed noncurrent clone.
func (b *publicationBackendFake) Inspect(ctx context.Context, operation datasourceadmin.OperationBinding, generation uint64, _ uint64, _ datasourceadmin.GenerationLimits) (*datasourceadmin.PublicationEnvelope, datasourceadmin.GenerationInfo, error) {
	if b.readback == nil || !operation.Equal(b.operation) || generation != b.readback.Generation() {
		return nil, datasourceadmin.GenerationInfo{}, errConflict
	}
	clone, err := clonePublicationEnvelope(ctx, b.readback, operation)
	if err != nil {
		return nil, datasourceadmin.GenerationInfo{}, err
	}
	return clone, datasourceadmin.GenerationInfo{Generation: generation, Current: b.current == generation, State: datasourceadmin.StateCommitted, Operation: operation}, nil
}

// Observe returns exact candidate-current state after activation.
func (b *publicationBackendFake) Observe(_ context.Context, operation datasourceadmin.OperationBinding, generation uint64, _ uint64, _ datasourceadmin.GenerationLimits) (datasourceadmin.PublicationObservation, error) {
	if b.current != generation || !operation.Equal(b.operation) {
		return datasourceadmin.PublicationObservation{}, errConflict
	}
	return datasourceadmin.NewPublicationObservation(generation, generation, datasourceadmin.PublicationExactCommitted, operation, b.staged, false)
}

// Activate performs one exact fake pointer move.
func (b *publicationBackendFake) Activate(_ context.Context, activation datasourceadmin.Activation) error {
	b.activateCalls++
	if activation.ExpectedCurrent() != b.current || !activation.Staged().Digest().Equal(b.staged.Digest()) {
		return errConflict
	}
	b.current = activation.CandidateGeneration()
	return nil
}

// RecordTerminal records one immutable close receipt after current readback.
func (b *publicationBackendFake) RecordTerminal(_ context.Context, record datasourceadmin.TerminalRecord) error {
	if !record.Valid() || record.CurrentGeneration() != b.current {
		return errConflict
	}
	b.terminalCalls++
	return nil
}

// ReadTerminal is unused by campaign activation tests.
func (*publicationBackendFake) ReadTerminal(context.Context, datasourceadmin.OperationBinding) (datasourceadmin.TerminalRecord, bool, error) {
	return datasourceadmin.TerminalRecord{}, false, nil
}

// Close erases the fake backend candidate.
func (b *publicationBackendFake) Close() error {
	if b.readback != nil {
		return b.readback.Close()
	}
	return nil
}

// TestCoordinatorPublishesOneCompleteCandidateAndMovesCurrentOnce freezes backend composition.
func TestCoordinatorPublishesOneCompleteCandidateAndMovesCurrentOnce(t *testing.T) {
	plan, prepared := preparedCampaign(t, 4)
	defer plan.Close()     //nolint:errcheck // Test cleanup has no recovery.
	defer prepared.Close() //nolint:errcheck // Test cleanup has no recovery.
	journal, _ := NewJournal(plan)
	_ = journal.BeginPreparing()
	_ = journal.RecordPrepared(prepared)
	lock, err := datasourceadmin.NewAdministrationLock(plan.intent.operation, 7)
	if err != nil {
		t.Fatal("lock fixture rejected")
	}
	backend := &publicationBackendFake{current: 7}
	defer backend.Close() //nolint:errcheck // Test cleanup has no recovery.
	published, err := Publish(t.Context(), plan, prepared, journal, backend, lock, campaignGenerationLimits())
	if err != nil || journal.State() != StateStaged || backend.stageCalls != 1 {
		t.Fatal("one complete candidate publication rejected")
	}
	defer published.Close() //nolint:errcheck // Test cleanup has no recovery.
	batches, _ := BuildDNSBatches(t.Context(), prepared, 2, DefaultLimits())
	now := time.Unix(2_000_000_000, 0).UTC()
	for _, batch := range batches {
		if journal.RecordBatchProof(batch, now, "dns-v1") != nil {
			t.Fatal("batch proof fixture rejected")
		}
	}
	if journal.BeginActivation(now, time.Minute) != nil ||
		Activate(t.Context(), journal, backend, published, campaignGenerationLimits()) != nil ||
		backend.activateCalls != 1 || journal.State() != StateActivated {
		t.Fatal("one exact current transition rejected")
	}
	if Activate(t.Context(), journal, backend, published, campaignGenerationLimits()) == nil || backend.activateCalls != 1 {
		t.Fatal("coordinator moved current more than once")
	}
}

// TestCoordinatorStageAmbiguityRequiresReconciliation freezes no-blind-retry behavior.
func TestCoordinatorStageAmbiguityRequiresReconciliation(t *testing.T) {
	plan, prepared := preparedCampaign(t, 1)
	defer plan.Close()     //nolint:errcheck // Test cleanup has no recovery.
	defer prepared.Close() //nolint:errcheck // Test cleanup has no recovery.
	journal, _ := NewJournal(plan)
	_ = journal.BeginPreparing()
	_ = journal.RecordPrepared(prepared)
	lock, _ := datasourceadmin.NewAdministrationLock(plan.intent.operation, 7)
	backend := &publicationBackendFake{current: 7, failStage: true}
	if published, err := Publish(t.Context(), plan, prepared, journal, backend, lock, campaignGenerationLimits()); err == nil || published != nil || journal.State() != StateReconcileRequired {
		t.Fatal("ambiguous stage did not enter reconciliation")
	}
	if published, err := Publish(t.Context(), plan, prepared, journal, backend, lock, campaignGenerationLimits()); err == nil || published != nil || backend.stageCalls != 1 {
		t.Fatal("reconciliation state permitted blind stage retry")
	}
}

// TestRecoverPreparedRequiresDurableCandidate proves resume reconstructs DNS
// inputs from an exact staged candidate and never invokes key generation.
func TestRecoverPreparedRequiresDurableCandidate(t *testing.T) {
	plan, prepared := preparedCampaign(t, 2)
	defer plan.Close()     //nolint:errcheck // Test cleanup cannot recover campaign state.
	defer prepared.Close() //nolint:errcheck // Test cleanup cannot recover campaign state.
	journal, err := NewJournal(plan)
	if err != nil || journal.BeginPreparing() != nil || journal.RecordPrepared(prepared) != nil {
		t.Fatal("prepared journal fixture rejected")
	}
	if err := prepared.WithEnvelope(t.Context(), func(envelope *datasourceadmin.PublicationEnvelope) error {
		digest, parseErr := admincontract.ParseDigest(envelope.Digest().Bytes())
		if parseErr != nil {
			return parseErr
		}
		return journal.RecordStaged(digest)
	}); err != nil {
		t.Fatal("staged journal fixture rejected")
	}
	err = prepared.WithEnvelope(t.Context(), func(envelope *datasourceadmin.PublicationEnvelope) error {
		recovered, recoverErr := RecoverPrepared(t.Context(), journal, envelope)
		if recoverErr != nil {
			return recoverErr
		}
		defer recovered.Close() //nolint:errcheck // Test cleanup cannot recover protected state.
		return nil
	})
	if err != nil {
		t.Fatal("exact staged candidate did not recover DNS inputs")
	}
}

// TestCoordinatorResumeReclaimsFenceBeforeProof proves a crash after durable
// publication cannot reuse the dead process lock, duplicate stage, or activate twice.
func TestCoordinatorResumeReclaimsFenceBeforeProof(t *testing.T) {
	plan, prepared := preparedCampaign(t, 2)
	defer plan.Close()     //nolint:errcheck
	defer prepared.Close() //nolint:errcheck
	journal, _ := NewJournal(plan)
	_ = journal.BeginPreparing()
	_ = journal.RecordPrepared(prepared)
	backend := &publicationBackendFake{current: 7}
	defer backend.Close() //nolint:errcheck
	original, _ := datasourceadmin.NewAdministrationLock(plan.intent.operation, 7)
	published, err := Publish(t.Context(), plan, prepared, journal, backend, original, campaignGenerationLimits())
	if err != nil {
		t.Fatal("stage fixture rejected")
	}
	_ = published.Close()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(directory, 0o700) != nil {
		t.Fatal("protect journal directory")
	}
	store, err := OpenJournalStore(t.Context(), filepath.Join(directory, "campaign.json"))
	if err != nil {
		t.Fatal("open journal fixture")
	}
	if _, exists, loadErr := store.Load(t.Context()); loadErr != nil || exists {
		t.Fatal("load empty journal fixture")
	}
	if err := store.Save(t.Context(), journal); err != nil {
		t.Fatal("persist staged journal")
	}
	locker := &resumeLockerFake{}
	proof := &resumeProofFake{now: time.Now().UTC()}
	coordinator, err := NewCoordinator(backend, backend, locker, &deterministicKeyFactory{}, proof, DefaultLimits(), campaignGenerationLimits(), time.Minute)
	if err != nil {
		t.Fatal("resume coordinator rejected")
	}
	report, err := coordinator.Run(t.Context(), store, plan.intent)
	if err != nil || report.State != StateActivated || locker.claims != 1 || locker.claimRevision != 7 || proof.calls != 1 || backend.stageCalls != 1 || backend.activateCalls != 1 {
		t.Fatal("resume did not use one fresh fence and one existing candidate")
	}
	if _, err := coordinator.Run(t.Context(), store, plan.intent); err == nil || backend.stageCalls != 1 || backend.activateCalls != 1 {
		t.Fatal("activated journal permitted duplicate publication or activation")
	}
}

// TestCoordinatorResumeAfterCurrentMoveClosesWithoutSecondActivation proves a
// crash after authoritative current movement resumes with exact readback and
// terminal closure, never a second pointer mutation.
func TestCoordinatorResumeAfterCurrentMoveClosesWithoutSecondActivation(t *testing.T) {
	plan, prepared := preparedCampaign(t, 2)
	defer plan.Close()     //nolint:errcheck
	defer prepared.Close() //nolint:errcheck
	journal, _ := NewJournal(plan)
	_ = journal.BeginPreparing()
	_ = journal.RecordPrepared(prepared)
	backend := &publicationBackendFake{current: 7}
	defer backend.Close() //nolint:errcheck
	lock, _ := datasourceadmin.NewAdministrationLock(plan.intent.operation, 7)
	published, err := Publish(t.Context(), plan, prepared, journal, backend, lock, campaignGenerationLimits())
	if err != nil {
		t.Fatal("stage fixture rejected")
	}
	_ = published.Close()
	batches, _ := BuildDNSBatches(t.Context(), prepared, 2, DefaultLimits())
	now := time.Now().UTC()
	for _, batch := range batches {
		if journal.RecordBatchProof(batch, now, "dns-v1") != nil {
			t.Fatal("proof fixture rejected")
		}
	}
	if journal.BeginActivation(now, time.Minute) != nil {
		t.Fatal("activation checkpoint rejected")
	}
	backend.current = plan.candidateGeneration
	directory, directoryErr := filepath.EvalSymlinks(t.TempDir())
	if directoryErr != nil || os.Chmod(directory, 0o700) != nil {
		t.Fatal("protect journal directory")
	}
	store, storeErr := OpenJournalStore(t.Context(), filepath.Join(directory, "campaign.json"))
	if storeErr != nil {
		t.Fatal("open journal fixture")
	}
	if _, exists, loadErr := store.Load(t.Context()); loadErr != nil || exists || store.Save(t.Context(), journal) != nil {
		t.Fatal("persist activating journal")
	}
	coordinator, coordinatorErr := NewCoordinator(backend, backend, &resumeLockerFake{}, &deterministicKeyFactory{}, &resumeProofFake{now: now}, DefaultLimits(), campaignGenerationLimits(), time.Minute)
	if coordinatorErr != nil {
		t.Fatal("resume coordinator rejected")
	}
	report, runErr := coordinator.Run(t.Context(), store, plan.intent)
	if runErr != nil || report.State != StateActivated || backend.activateCalls != 0 || backend.terminalCalls != 1 {
		t.Fatal("post-current resume repeated activation or missed terminal closure")
	}
}

// TestCoordinatorResumeRejectsMissingFreshFence proves DNS proof is not spent
// after a restart when the datasource lock cannot be freshly claimed.
func TestCoordinatorResumeRejectsMissingFreshFence(t *testing.T) {
	plan, prepared := preparedCampaign(t, 1)
	defer plan.Close()     //nolint:errcheck
	defer prepared.Close() //nolint:errcheck
	journal, _ := NewJournal(plan)
	_ = journal.BeginPreparing()
	_ = journal.RecordPrepared(prepared)
	backend := &publicationBackendFake{current: 7}
	defer backend.Close() //nolint:errcheck
	lock, _ := datasourceadmin.NewAdministrationLock(plan.intent.operation, 7)
	published, _ := Publish(t.Context(), plan, prepared, journal, backend, lock, campaignGenerationLimits())
	_ = published.Close()
	directory, directoryErr := filepath.EvalSymlinks(t.TempDir())
	if directoryErr != nil || os.Chmod(directory, 0o700) != nil {
		t.Fatal("protect journal directory")
	}
	store, _ := OpenJournalStore(t.Context(), filepath.Join(directory, "campaign.json"))
	_, _, _ = store.Load(t.Context())
	if store.Save(t.Context(), journal) != nil {
		t.Fatal("persist staged journal")
	}
	proof := &resumeProofFake{now: time.Now().UTC()}
	coordinator, _ := NewCoordinator(backend, backend, &resumeLockerFake{fail: true}, &deterministicKeyFactory{}, proof, DefaultLimits(), campaignGenerationLimits(), time.Minute)
	if _, err := coordinator.Run(t.Context(), store, plan.intent); err == nil || proof.calls != 0 || backend.stageCalls != 1 || backend.activateCalls != 0 {
		t.Fatal("unclaimed restart consumed proof or republished candidate")
	}
}

// TestCoordinatorResumeRejectsForeignCurrentBeforeProof proves a campaign
// frozen from an older current generation cannot spend fresh DNS proof work.
func TestCoordinatorResumeRejectsForeignCurrentBeforeProof(t *testing.T) {
	plan, prepared := preparedCampaign(t, 1)
	defer plan.Close()     //nolint:errcheck
	defer prepared.Close() //nolint:errcheck
	journal, _ := NewJournal(plan)
	_ = journal.BeginPreparing()
	_ = journal.RecordPrepared(prepared)
	backend := &publicationBackendFake{current: 7}
	defer backend.Close() //nolint:errcheck
	lock, _ := datasourceadmin.NewAdministrationLock(plan.intent.operation, 7)
	published, _ := Publish(t.Context(), plan, prepared, journal, backend, lock, campaignGenerationLimits())
	_ = published.Close()
	backend.current = 9
	directory, directoryErr := filepath.EvalSymlinks(t.TempDir())
	if directoryErr != nil || os.Chmod(directory, 0o700) != nil {
		t.Fatal("protect journal directory")
	}
	store, _ := OpenJournalStore(t.Context(), filepath.Join(directory, "campaign.json"))
	_, _, _ = store.Load(t.Context())
	if store.Save(t.Context(), journal) != nil {
		t.Fatal("persist staged journal")
	}
	proof := &resumeProofFake{now: time.Now().UTC()}
	coordinator, _ := NewCoordinator(backend, backend, &resumeLockerFake{}, &deterministicKeyFactory{}, proof, DefaultLimits(), campaignGenerationLimits(), time.Minute)
	if _, err := coordinator.Run(t.Context(), store, plan.intent); err == nil || proof.calls != 0 || backend.stageCalls != 1 || backend.activateCalls != 0 {
		t.Fatal("foreign current reached proof, stage, or activation")
	}
}

// clonePublicationEnvelope constructs one separately owned exact backend readback.
func clonePublicationEnvelope(ctx context.Context, source *datasourceadmin.PublicationEnvelope, operation datasourceadmin.OperationBinding) (*datasourceadmin.PublicationEnvelope, error) {
	var rows datasourceadmin.Rows
	if err := source.WithRows(ctx, func(value datasourceadmin.Rows) error {
		rows = cloneAdminRows(value)
		return nil
	}); err != nil {
		return nil, err
	}
	snapshot, err := datasourceadmin.NewSnapshotWithLimits(datasourceadmin.SchemaVersionV3, source.Generation(), rows, provider.ProductionLimits())
	clearAdminRows(&rows)
	if err != nil {
		return nil, err
	}
	content, err := datasourceadmin.NewCandidateContent(snapshot)
	if err != nil {
		_ = snapshot.Close()
		return nil, err
	}
	var operationValue string
	if err := operation.WithValue(ctx, func(value string) error { operationValue = value; return nil }); err != nil {
		_ = content.Close()
		return nil, err
	}
	return datasourceadmin.NewCampaignPublicationEnvelope(operationValue, 7, content)
}

// campaignGenerationLimits returns finite provider administration test limits.
func campaignGenerationLimits() datasourceadmin.GenerationLimits {
	return datasourceadmin.GenerationLimits{MaxGenerations: 256, MaxOutstandingCandidates: 8, MaxSnapshotRows: 1 << 20, MaxSnapshotBytes: 128 << 20, BackendDeadline: 2 * time.Second}
}
