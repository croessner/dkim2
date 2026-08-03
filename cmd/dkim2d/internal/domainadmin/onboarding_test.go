package domainadmin

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

// onboardingBackendFake models only provider-neutral publication and lock evidence.
type onboardingBackendFake struct {
	t                       *testing.T
	current                 *datasourceadmin.Snapshot
	currentOverride         uint64
	candidate               *datasourceadmin.PublicationEnvelope
	candidateState          datasourceadmin.PublicationState
	candidateCurrent        bool
	oldCurrentWasActive     bool
	lockOwner               datasourceadmin.OperationBinding
	lockRevision            uint64
	lockClaimed             bool
	readCurrentSubstituted  bool
	stageState              datasourceadmin.PublicationState
	stageErr                error
	activateErr             error
	activateUnknown         bool
	activateProducesUnknown bool
	activateProducesThird   bool
	stageCalls              int
	inspectCalls            int
	observeCalls            int
	activateCalls           int
	claimCalls              int
	releaseCalls            int
	readCurrentCalls        int
	readCurrentErr          error
	readCurrentNil          bool
	collisionCalls          int
	events                  []string
	beforeClaim             func()
	beforeRelease           func()
	afterCollision          func()
	observeLockErr          error
	claimErr                error
	claimPostMutationErr    error
	releaseErr              error
	releasePostMutationErr  error
	collisionErr            error
	invalidLockObservation  bool
	observeErr              error
	observeInvalid          bool
	inspectErr              error
	inspectNil              bool
	inspectMismatch         bool
}

// ReadCurrent returns one detached source snapshot, optionally substituting a valid drifted source.
func (f *onboardingBackendFake) ReadCurrent(context.Context, datasourceadmin.GenerationLimits) (*datasourceadmin.Snapshot, error) {
	f.readCurrentCalls++
	if f.readCurrentErr != nil {
		return nil, f.readCurrentErr
	}
	if f.readCurrentNil {
		return nil, nil
	}
	if f.readCurrentSubstituted {
		return collisionSnapshot(f.t, 1, "substituted-profile", "substituted-handle", "substituted-selector"), nil
	}
	return cloneSnapshotForOnboardingTest(f.t, f.current), nil
}

// Inventory returns the bounded provider generation projection.
func (f *onboardingBackendFake) Inventory(context.Context, datasourceadmin.GenerationLimits) (datasourceadmin.Inventory, error) {
	current := f.lockedCurrentGeneration()
	result := datasourceadmin.Inventory{Current: current, Generations: []datasourceadmin.GenerationInfo{{
		Generation: 1, Current: current == 1, State: datasourceadmin.StateCommitted,
	}}}
	if f.candidate != nil {
		result.Generations = append(result.Generations, f.candidateInfo())
	}
	return result, nil
}

// ReadCollisionInventory returns the exact source view under the supplied claim.
func (f *onboardingBackendFake) ReadCollisionInventory(
	ctx context.Context,
	lock datasourceadmin.AdministrationLock,
	limits datasourceadmin.GenerationLimits,
) (*datasourceadmin.CollisionInventory, error) {
	f.collisionCalls++
	f.events = append(f.events, "allocate")
	if f.collisionErr != nil {
		return nil, f.collisionErr
	}
	info := datasourceadmin.GenerationInfo{Generation: 1, Current: true, State: datasourceadmin.StateCommitted}
	inventory, err := datasourceadmin.NewCollisionInventory(
		ctx, lock, datasourceadmin.Inventory{Current: 1, Generations: []datasourceadmin.GenerationInfo{info}},
		[]datasourceadmin.CollisionSnapshot{{Info: info, Snapshot: cloneSnapshotForOnboardingTest(f.t, f.current)}}, limits,
	)
	if f.afterCollision != nil {
		f.afterCollision()
	}
	return inventory, err
}

// Current returns the exact current generation metadata.
func (f *onboardingBackendFake) Current(context.Context, datasourceadmin.GenerationLimits) (datasourceadmin.GenerationInfo, error) {
	if f.candidateCurrent {
		return f.candidateInfo(), nil
	}
	return datasourceadmin.GenerationInfo{Generation: 1, Current: true, State: datasourceadmin.StateCommitted}, nil
}

// Stage retains a detached candidate and exposes scripted authoritative readback.
func (f *onboardingBackendFake) Stage(
	_ context.Context,
	lock datasourceadmin.AdministrationLock,
	operation datasourceadmin.OperationBinding,
	candidate *datasourceadmin.PublicationEnvelope,
) (datasourceadmin.StagedEvidence, error) {
	f.stageCalls++
	if !f.lockClaimed || lock.Revision() != f.lockRevision || !lock.Owner().Equal(f.lockOwner) ||
		!operation.Equal(f.lockOwner) {
		return datasourceadmin.StagedEvidence{}, errors.New("wrong lock")
	}
	if f.stageState != datasourceadmin.PublicationAbsent {
		owned := cloneCandidateForOnboardingTest(f.t, candidate)
		if f.candidate != nil {
			_ = f.candidate.Close()
		}
		f.candidate = owned
		f.candidateState = f.stageState
	}
	return datasourceadmin.NewStagedEvidence(candidate.Digest()), f.stageErr
}

// Inspect returns one detached exact candidate content readback.
func (f *onboardingBackendFake) Inspect(
	_ context.Context,
	operation datasourceadmin.OperationBinding,
	generation uint64,
	_ uint64,
	_ datasourceadmin.GenerationLimits,
) (*datasourceadmin.PublicationEnvelope, datasourceadmin.GenerationInfo, error) {
	f.inspectCalls++
	if f.inspectErr != nil {
		return nil, datasourceadmin.GenerationInfo{}, f.inspectErr
	}
	if f.inspectNil {
		if f.candidate == nil {
			return nil, datasourceadmin.GenerationInfo{}, nil
		}
		return nil, f.candidateInfo(), nil
	}
	if f.candidate == nil || generation != f.candidate.Generation() || !operation.Equal(f.candidate.Binding()) {
		return nil, datasourceadmin.GenerationInfo{}, errors.New("candidate absent")
	}
	info := f.candidateInfo()
	if f.inspectMismatch {
		info.Current = !info.Current
	}
	return cloneCandidateForOnboardingTest(f.t, f.candidate), info, nil
}

// Observe returns one closed publication classification.
func (f *onboardingBackendFake) Observe(
	_ context.Context,
	_ datasourceadmin.OperationBinding,
	generation uint64,
	_ uint64,
	_ datasourceadmin.GenerationLimits,
) (datasourceadmin.PublicationObservation, error) {
	f.observeCalls++
	if f.observeErr != nil {
		return datasourceadmin.PublicationObservation{}, f.observeErr
	}
	if f.observeInvalid {
		return datasourceadmin.PublicationObservation{}, nil
	}
	state := f.candidateState
	if f.activateUnknown {
		state = datasourceadmin.PublicationUnknown
	}
	if f.candidate == nil || state == datasourceadmin.PublicationAbsent ||
		state == datasourceadmin.PublicationPartial || state == datasourceadmin.PublicationMismatch ||
		state == datasourceadmin.PublicationUnknown {
		return datasourceadmin.NewPublicationObservation(
			f.lockedCurrentGeneration(), generation, state,
			datasourceadmin.OperationBinding{}, datasourceadmin.StagedEvidence{}, false,
		)
	}
	return datasourceadmin.NewPublicationObservation(
		f.lockedCurrentGeneration(), generation, state, f.candidate.Binding(),
		datasourceadmin.NewStagedEvidence(f.candidate.Digest()), f.oldCurrentWasActive,
	)
}

// Activate applies or scripts one exact pointer move under the retained claim.
func (f *onboardingBackendFake) Activate(_ context.Context, activation datasourceadmin.Activation) error {
	f.activateCalls++
	if !f.lockClaimed || !activation.Valid() || activation.Lock().Revision() != f.lockRevision ||
		!activation.Operation().Equal(f.lockOwner) {
		return errors.New("wrong activation fence")
	}
	if !f.activateUnknown && f.activateErr == nil {
		f.candidateCurrent = true
		f.oldCurrentWasActive = activation.ExpectedCurrent() != 0
	}
	if f.activateProducesUnknown {
		f.activateUnknown = true
	}
	if f.activateProducesThird {
		f.candidateCurrent = false
		f.currentOverride = 99
	}
	return f.activateErr
}

// Claim acquires only the exact ownerless current revision.
func (f *onboardingBackendFake) Claim(
	ctx context.Context,
	operation datasourceadmin.OperationBinding,
	expected uint64,
) (datasourceadmin.AdministrationLock, error) {
	f.claimCalls++
	f.events = append(f.events, "claim")
	if f.beforeClaim != nil {
		f.beforeClaim()
	}
	if f.claimErr != nil {
		return datasourceadmin.AdministrationLock{}, f.claimErr
	}
	if ctx.Err() != nil {
		return datasourceadmin.AdministrationLock{}, ctx.Err()
	}
	if f.lockClaimed || expected != f.lockRevision {
		return datasourceadmin.AdministrationLock{}, errors.New("claim conflict")
	}
	f.lockClaimed = true
	f.lockOwner = operation
	if f.claimPostMutationErr != nil {
		return datasourceadmin.AdministrationLock{}, f.claimPostMutationErr
	}
	return datasourceadmin.NewAdministrationLock(operation, expected)
}

// Release advances one exact same-operation claim revision.
func (f *onboardingBackendFake) Release(_ context.Context, lock datasourceadmin.AdministrationLock) (uint64, error) {
	f.releaseCalls++
	f.events = append(f.events, "release")
	if f.beforeRelease != nil {
		f.beforeRelease()
	}
	if f.releaseErr != nil {
		return 0, f.releaseErr
	}
	if !f.lockClaimed || lock.Revision() != f.lockRevision || !lock.Owner().Equal(f.lockOwner) {
		return 0, errors.New("release conflict")
	}
	f.lockClaimed = false
	f.lockOwner = datasourceadmin.OperationBinding{}
	f.lockRevision++
	if f.releasePostMutationErr != nil {
		return f.lockRevision, f.releasePostMutationErr
	}
	return f.lockRevision, nil
}

// ObserveAdministrationLock returns exact owner and revision evidence.
func (f *onboardingBackendFake) ObserveAdministrationLock(context.Context) (datasourceadmin.AdministrationLockObservation, error) {
	if f.observeLockErr != nil {
		return datasourceadmin.AdministrationLockObservation{}, f.observeLockErr
	}
	if f.invalidLockObservation {
		return datasourceadmin.AdministrationLockObservation{}, nil
	}
	return datasourceadmin.NewAdministrationLockObservation(f.lockRevision, f.lockOwner, f.lockClaimed)
}

// candidateInfo constructs exact bounded candidate metadata.
func (f *onboardingBackendFake) candidateInfo() datasourceadmin.GenerationInfo {
	state := datasourceadmin.StateCommitted
	if f.candidateState == datasourceadmin.PublicationExactStaging {
		state = datasourceadmin.StateStaging
	}
	return datasourceadmin.GenerationInfo{
		Generation: f.candidate.Generation(), Current: f.candidateCurrent, State: state,
		WasActive: f.candidateCurrent, Operation: f.candidate.Binding(),
	}
}

// lockedCurrentGeneration returns the fake's authoritative current pointer.
func (f *onboardingBackendFake) lockedCurrentGeneration() uint64 {
	if f.currentOverride != 0 {
		return f.currentOverride
	}
	if f.candidateCurrent && f.candidate != nil {
		return f.candidate.Generation()
	}
	return 1
}

// TestOnboardingCompletesRestartableHappyPathWithFreshActivationProof freezes the cumulative flow.
func TestOnboardingCompletesRestartableHappyPathWithFreshActivationProof(t *testing.T) {
	onboarding, backend, store, plan, proofCalls := onboardingCoordinatorFixture(t)
	defer closeOnboardingFixture(store, backend, plan)
	if result, err := planOnboarding(t, onboarding, store); err != nil || result.State != StatePlanned {
		t.Fatal("fresh plan was not persisted")
	}
	if result, err := onboarding.Prepare(t.Context(), store); err != nil || result.State != StateStaged || backend.releaseCalls != 1 {
		t.Fatalf("persisted plan was not independently staged and released: code=%s state=%s failure=%s stage=%d inspect=%d release=%d current=%d collisions=%d", CodeOf(err), result.State, result.Failure, backend.stageCalls, backend.inspectCalls, backend.releaseCalls, backend.readCurrentCalls, backend.collisionCalls)
	}
	exportPath := protectedOnboardingPath(t, "dns.txt")
	if result, err := onboarding.DNSExport(t.Context(), store, exportPath); err != nil || result.State != StateDNSExported {
		t.Fatalf("exact staged DNS artifact was not exported: code=%s state=%s failure=%s", CodeOf(err), result.State, result.Failure)
	}
	if result, err := onboarding.Prove(t.Context(), store); err != nil || result.State != StateDNSProven || *proofCalls != 1 {
		t.Fatal("fresh DNS proof was not recorded as non-authoritative phase knowledge")
	}
	result, err := onboarding.Activate(t.Context(), store)
	if err != nil || result.State != StateActivated || !result.RuntimeVerificationRequired ||
		*proofCalls != 2 || backend.activateCalls != 1 || backend.lockClaimed {
		t.Fatal("activation did not repeat proof, read back, and release terminal claim")
	}
	if result.ExpectedCurrentGeneration == 0 || !result.CurrentGenerationKnown ||
		result.CurrentGeneration != result.CandidateGeneration ||
		result.CandidateGeneration <= result.ExpectedCurrentGeneration || result.CredentialCount == 0 ||
		result.RSACredentialCount+result.Ed25519CredentialCount != result.CredentialCount {
		t.Fatal("activation result omitted exact durable generation or credential facts")
	}
}

// TestOnboardingDNSExportConflictLeavesForeignFileAndJournalUnchanged freezes workflow atomicity.
func TestOnboardingDNSExportConflictLeavesForeignFileAndJournalUnchanged(t *testing.T) {
	onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
	defer closeOnboardingFixture(store, backend, plan)
	if _, err := planOnboarding(t, onboarding, store); err != nil {
		t.Fatal("plan foreign DNS export fixture")
	}
	if _, err := onboarding.Prepare(t.Context(), store); err != nil {
		t.Fatal("prepare foreign DNS export fixture")
	}
	intentPath := writeIntentFixture(t, "version: dkim2-domain-intent-v1\ndomain: example.test\ntenant_id: outbound\nprofile_use: originator\nalgorithms: [ed25519-sha256]\nrollout: enforce\ncompatibility: strict\n")
	journalBefore, journalInfoBefore, _ := protectedArtifactSnapshot(t, store.path)
	intentBefore, intentInfoBefore, intentEntriesBefore := protectedArtifactSnapshot(t, intentPath)
	result, err := onboarding.DNSExport(t.Context(), store, intentPath)
	if CodeOf(err) != CodeConflict || result.State != StateStaged || result.Failure != CodeConflict {
		t.Fatal("foreign DNS artifact did not fail closed from staged state")
	}
	journalAfter, journalInfoAfter, _ := protectedArtifactSnapshot(t, store.path)
	intentAfter, intentInfoAfter, intentEntriesAfter := protectedArtifactSnapshot(t, intentPath)
	if !bytes.Equal(journalBefore, journalAfter) || !os.SameFile(journalInfoBefore, journalInfoAfter) ||
		!bytes.Equal(intentBefore, intentAfter) || !os.SameFile(intentInfoBefore, intentInfoAfter) ||
		!slices.Equal(intentEntriesBefore, intentEntriesAfter) {
		t.Fatal("foreign DNS export conflict mutated journal or target")
	}
	clear(journalBefore)
	clear(journalAfter)
	clear(intentBefore)
	clear(intentAfter)
}

// TestOnboardingRejectsConfiguredAuthorityAndClonedSourceSubstitution freezes both authority fences.
func TestOnboardingRejectsConfiguredAuthorityAndClonedSourceSubstitution(t *testing.T) {
	onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
	defer closeOnboardingFixture(store, backend, plan)
	other := planAuthority()
	other.AuthorityID = "other-authority"
	wrong := newOnboardingForTest(t, backend, other, nil)
	if _, err := planOnboarding(t, onboarding, store); err != nil {
		t.Fatal("fresh exact plan rejected")
	}
	if result, err := planOnboarding(t, wrong, store); CodeOf(err) != CodeConflict || result.Failure != CodeConflict || backend.observeCalls != 0 {
		t.Fatal("plan reached a differently configured authority")
	}
	backend.readCurrentSubstituted = true
	result, err := onboarding.Prepare(t.Context(), store)
	if CodeOf(err) != CodeConflict || result.Failure != CodeConflict || backend.stageCalls != 0 {
		t.Fatal("source snapshot substituted between collision view and clone reached staging")
	}
}

// TestOnboardingTreatsStageReturnAsNonAuthoritativeAndRequiresExplicitStagingRecovery freezes stage windows.
func TestOnboardingTreatsStageReturnAsNonAuthoritativeAndRequiresExplicitStagingRecovery(t *testing.T) {
	t.Run("committed readback wins", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		backend.stageErr = errors.New("ambiguous stage return")
		if _, err := planOnboarding(t, onboarding, store); err != nil {
			t.Fatal("plan rejected")
		}
		if result, err := onboarding.Prepare(t.Context(), store); err != nil || result.State != StateStaged || backend.inspectCalls == 0 {
			t.Fatalf("exact independent committed readback did not override stage return: code=%s state=%s failure=%s stage=%d inspect=%d", CodeOf(err), result.State, result.Failure, backend.stageCalls, backend.inspectCalls)
		}
	})
	t.Run("staging needs reconcile then reclaim", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		backend.stageState = datasourceadmin.PublicationExactStaging
		backend.stageErr = errors.New("stage interrupted")
		_, _ = planOnboarding(t, onboarding, store)
		result, err := onboarding.Prepare(t.Context(), store)
		if CodeOf(err) != CodeReconcileRequired || result.State != StatePrepared || !backend.lockClaimed {
			t.Fatalf("exact staging crash window did not preserve claimed prepared lineage: code=%s state=%s failure=%s claimed=%v", CodeOf(err), result.State, result.Failure, backend.lockClaimed)
		}
		if result, err = onboarding.Reconcile(t.Context(), store); err != nil || result.State != StatePrepared || backend.lockClaimed {
			t.Fatal("explicit reconciliation did not release exact staging lineage")
		}
		backend.stageState = datasourceadmin.PublicationExactCommitted
		backend.stageErr = nil
		if result, err = onboarding.Prepare(t.Context(), store); err != nil || result.State != StateStaged || backend.claimCalls == 0 {
			t.Fatal("released exact staging lineage could not be safely reclaimed and sealed")
		}
	})
}

// TestOnboardingPreparedAbsentRequiresExplicitReconcileAndRetainsKeyRecoveryFailure freezes lost-key recovery.
func TestOnboardingPreparedAbsentRequiresExplicitReconcileAndRetainsKeyRecoveryFailure(t *testing.T) {
	onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
	defer closeOnboardingFixture(store, backend, plan)
	backend.stageState = datasourceadmin.PublicationAbsent
	backend.stageErr = errors.New("stage did not publish")
	_, _ = planOnboarding(t, onboarding, store)
	result, err := onboarding.Prepare(t.Context(), store)
	if CodeOf(err) != CodeKeyRecoveryUnavailable || result.State != StateFailed || result.Failure == CodeNone || !backend.lockClaimed {
		t.Fatalf("prepared-absent crash window lost bounded failure or released implicitly: code=%s state=%s failure=%s claimed=%v", CodeOf(err), result.State, result.Failure, backend.lockClaimed)
	}
	if result, err = onboarding.Reconcile(t.Context(), store); err != nil || result.State != StateFailed || backend.lockClaimed {
		t.Fatal("explicit failed-state reconciliation did not release the same-operation claim")
	}
	if _, err = onboarding.Prepare(t.Context(), store); CodeOf(err) != CodeKeyRecoveryUnavailable {
		t.Fatal("terminal prepared-key loss was not retained across commands")
	}
}

// TestOnboardingActivationFallbackReleasesButUnknownPreservesClaim freezes activation ambiguity policy.
func TestOnboardingActivationFallbackReleasesButUnknownPreservesClaim(t *testing.T) {
	t.Run("exact fallback", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingReadyToActivateFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		backend.activateErr = errors.New("pointer update failed")
		result, err := onboarding.Activate(t.Context(), store)
		if CodeOf(err) != CodeUnavailable || result.State != StateStaged || backend.lockClaimed {
			t.Fatal("exact current-expected activation fallback was not reconciled and released")
		}
	})
	t.Run("unknown readback", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingReadyToActivateFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		backend.activateProducesUnknown = true
		result, err := onboarding.Activate(t.Context(), store)
		if CodeOf(err) != CodeReconcileRequired || result.State != StateReconcileRequired || !backend.lockClaimed {
			t.Fatalf("unknown activation readback did not preserve exact claim and write-ahead state: code=%s state=%s failure=%s claimed=%v", CodeOf(err), result.State, result.Failure, backend.lockClaimed)
		}
		if _, err = onboarding.Reconcile(t.Context(), store); CodeOf(err) != CodeReconcileRequired || !backend.lockClaimed {
			t.Fatal("unresolved explicit reconciliation released an ambiguous activation claim")
		}
	})
}

// TestOnboardingReconcileActivationRecoveryReportsRuntimeSmoke freezes its complete operator result.
func TestOnboardingReconcileActivationRecoveryReportsRuntimeSmoke(t *testing.T) {
	onboarding, backend, store, plan, _ := onboardingReadyToActivateFixture(t)
	defer closeOnboardingFixture(store, backend, plan)
	backend.activateProducesUnknown = true
	result, err := onboarding.Activate(t.Context(), store)
	if CodeOf(err) != CodeReconcileRequired || result.State != StateReconcileRequired || !backend.lockClaimed {
		t.Fatal("activation ambiguity did not retain reconciliation authority")
	}
	backend.activateProducesUnknown = false
	backend.activateUnknown = false
	result, err = onboarding.Reconcile(t.Context(), store)
	if err != nil || result.State != StateActivated || !result.CurrentGenerationKnown ||
		result.CurrentGeneration != result.CandidateGeneration || !result.RuntimeVerificationRequired {
		t.Fatal("activation recovery omitted its authoritative activated result")
	}
	report, err := NewCommandReport("test-version", CommandReconcile, datasourceadmin.BackendLDAP, result)
	if err != nil {
		t.Fatal("construct activation-recovery reconciliation report")
	}
	machine, machineErr := EncodeReport(report, true, 4096)
	human, humanErr := EncodeReport(report, false, 4096)
	if machineErr != nil || humanErr != nil ||
		!bytes.Contains(machine, []byte("\"runtime_smoke_required\":true")) ||
		!bytes.Contains(human, []byte(" runtime_smoke_required=true")) {
		t.Fatal("activation-recovery reconciliation omitted mandatory runtime smoke")
	}
}

// TestOnboardingThirdCurrentConflictRequiresReconcileUntilClaimCleanup freezes terminal cleanup signaling.
func TestOnboardingThirdCurrentConflictRequiresReconcileUntilClaimCleanup(t *testing.T) {
	onboarding, backend, store, plan, _ := onboardingReadyToActivateFixture(t)
	defer closeOnboardingFixture(store, backend, plan)
	backend.activateProducesThird = true
	backend.activateErr = errors.New("concurrent pointer move")
	result, err := onboarding.Activate(t.Context(), store)
	if CodeOf(err) != CodeReconcileRequired || result.State != StateConflict || !backend.lockClaimed ||
		backend.releaseCalls != 1 || result.CurrentGenerationKnown {
		t.Fatalf("third-current conflict hid outstanding claim cleanup: code=%s state=%s claimed=%v releases=%d", CodeOf(err), result.State, backend.lockClaimed, backend.releaseCalls)
	}
	backend.observeErr = errors.New("foreign current observation unavailable")
	result, err = onboarding.Reconcile(t.Context(), store)
	if CodeOf(err) != CodeConflict || result.State != StateConflict || result.CurrentGenerationKnown {
		t.Fatal("foreign-current reconcile failure invented an authoritative current generation")
	}
	report, reportErr := NewCommandReport("test-version", CommandReconcile, datasourceadmin.BackendLDAP, result)
	if reportErr != nil {
		t.Fatal("construct foreign-current reconcile failure report")
	}
	machine, machineErr := EncodeReport(report, true, 4096)
	human, humanErr := EncodeReport(report, false, 4096)
	if machineErr != nil || humanErr != nil || bytes.Contains(machine, []byte("\"current_generation\":")) ||
		bytes.Contains(human, []byte(" current_generation=")) {
		t.Fatal("foreign-current reconcile failure laundered unknown current as zero")
	}
	backend.observeErr = nil
	result, err = onboarding.Reconcile(t.Context(), store)
	if err != nil || result.State != StateConflict || !result.CurrentGenerationKnown ||
		result.CurrentGeneration != 99 ||
		backend.lockClaimed || backend.releaseCalls != 2 {
		t.Fatal("explicit conflict reconciliation did not preserve the authoritative third-party current")
	}
	report, reportErr = NewCommandReport("test-version", CommandReconcile, datasourceadmin.BackendLDAP, result)
	if reportErr != nil {
		t.Fatal("construct successful terminal-conflict reconciliation report")
	}
	machine, machineErr = EncodeReport(report, true, 4096)
	human, humanErr = EncodeReport(report, false, 4096)
	if machineErr != nil || humanErr != nil || !bytes.Contains(machine, []byte("\"current_generation\":99")) ||
		!bytes.Contains(human, []byte(" current_generation=99")) {
		t.Fatal("successful terminal-conflict reconciliation omitted the authoritative third-party current")
	}
}

// TestOnboardingAbortReconcileRequiredAndAbortedAreStrictNoWrite freezes abort idempotency.
func TestOnboardingAbortReconcileRequiredAndAbortedAreStrictNoWrite(t *testing.T) {
	t.Run("reconcile required", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingReadyToActivateFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		backend.activateProducesUnknown = true
		_, _ = onboarding.Activate(t.Context(), store)
		before, _ := os.ReadFile(store.path)
		stageCalls, activateCalls, releaseCalls := backend.stageCalls, backend.activateCalls, backend.releaseCalls
		result, err := onboarding.Abort(t.Context(), store)
		after, _ := os.ReadFile(store.path)
		if CodeOf(err) != CodeReconcileRequired || result.State != StateReconcileRequired ||
			!bytes.Equal(before, after) || backend.stageCalls != stageCalls || backend.activateCalls != activateCalls ||
			backend.releaseCalls != releaseCalls {
			t.Fatal("abort retried or wrote an already reconcile_required journal")
		}
		clear(before)
		clear(after)
	})
	t.Run("aborted", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		_, _ = planOnboarding(t, onboarding, store)
		first, err := onboarding.Abort(t.Context(), store)
		if err != nil || first.State != StateAborted {
			t.Fatal("create aborted journal fixture")
		}
		before, _ := os.ReadFile(store.path)
		releases := backend.releaseCalls
		second, err := onboarding.Abort(t.Context(), store)
		after, _ := os.ReadFile(store.path)
		if err != nil || second.State != StateAborted || !bytes.Equal(before, after) || backend.releaseCalls != releases {
			t.Fatal("terminal aborted retry wrote or retried cleanup")
		}
		clear(before)
		clear(after)
	})
}

// TestOnboardingAbortedJournalCrashRecoveryFreezesHeldAndResponseLostReleaseWindows.
func TestOnboardingAbortedJournalCrashRecovery(t *testing.T) {
	for _, responseLost := range []bool{false, true} {
		t.Run(map[bool]string{false: "held claim", true: "response lost"}[responseLost], func(t *testing.T) {
			onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
			defer closeOnboardingFixture(store, backend, plan)
			_, _ = planOnboarding(t, onboarding, store)
			journal, exists, err := store.Load(t.Context())
			if err != nil || !exists || journal.RecordAborted(CandidateAbsent, datasourceadmin.StagedEvidence{}) != nil ||
				store.Save(t.Context(), journal) != nil {
				_ = journal.Close()
				t.Fatal("persist aborted crash fixture")
			}
			lock, _ := journal.AdministrationLock()
			_ = journal.Close()
			if responseLost {
				backend.releasePostMutationErr = errors.New("response lost")
				_, _ = backend.Release(t.Context(), lock)
				backend.releasePostMutationErr = nil
			}
			releases := backend.releaseCalls
			result, err := onboarding.Abort(t.Context(), store)
			if CodeOf(err) != CodeReconcileRequired || result.State != StateAborted || backend.releaseCalls != releases {
				t.Fatal("aborted retry released or accepted outstanding cleanup")
			}
			result, err = onboarding.Reconcile(t.Context(), store)
			if err != nil || result.State != StateAborted || backend.lockClaimed ||
				backend.releaseCalls != releases+map[bool]int{false: 1, true: 0}[responseLost] {
				t.Fatal("explicit reconcile did not settle aborted crash cleanup exactly once")
			}
		})
	}
}

// TestOnboardingJournalStatusFailsClosedOnLockEvidence freezes read-only authority validation.
func TestOnboardingJournalStatusFailsClosedOnLockEvidence(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*onboardingBackendFake)
		want      ErrorCode
	}{
		{name: "lock transport unavailable", configure: func(backend *onboardingBackendFake) {
			backend.observeLockErr = errors.New("lock backend offline")
		}, want: CodeUnavailable},
		{name: "invalid", configure: func(backend *onboardingBackendFake) {
			backend.invalidLockObservation = true
		}, want: CodeConflict},
		{name: "foreign", configure: func(backend *onboardingBackendFake) {
			foreign, _ := datasourceadmin.NewOperationBinding("aebagbafaydqqcikbmga2dqpca")
			backend.lockOwner, backend.lockClaimed = foreign, true
		}, want: CodeReconcileRequired},
		{name: "publication unavailable", configure: func(backend *onboardingBackendFake) {
			backend.observeErr = errors.New("publication backend offline")
		}, want: CodeUnavailable},
		{name: "publication invalid", configure: func(backend *onboardingBackendFake) {
			backend.observeInvalid = true
		}, want: CodeConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
			defer closeOnboardingFixture(store, backend, plan)
			_, _ = planOnboarding(t, onboarding, store)
			before, _ := os.ReadFile(store.path)
			test.configure(backend)
			_, err := onboarding.Status(t.Context(), store)
			after, _ := os.ReadFile(store.path)
			if CodeOf(err) != test.want || !bytes.Equal(before, after) || backend.releaseCalls != 0 {
				t.Fatal("journal status accepted or mutated invalid lock authority")
			}
			clear(before)
			clear(after)
		})
	}
}

// TestOnboardingAbortDistinguishesLockTransportFromInvalidEvidence freezes fail-closed classification.
func TestOnboardingAbortDistinguishesLockTransportFromInvalidEvidence(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*onboardingBackendFake)
		want      ErrorCode
	}{
		{name: "transport error", configure: func(backend *onboardingBackendFake) {
			backend.observeLockErr = errors.New("lock backend offline")
		}, want: CodeUnavailable},
		{name: "invalid evidence", configure: func(backend *onboardingBackendFake) {
			backend.invalidLockObservation = true
		}, want: CodeConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
			defer closeOnboardingFixture(store, backend, plan)
			_, _ = planOnboarding(t, onboarding, store)
			before, _ := os.ReadFile(store.path)
			test.configure(backend)
			result, err := onboarding.Abort(t.Context(), store)
			after, _ := os.ReadFile(store.path)
			if CodeOf(err) != test.want || result.Failure != test.want ||
				!bytes.Equal(before, after) || backend.releaseCalls != 0 {
				t.Fatal("abort lock classification mutated state or reported the wrong bounded failure")
			}
			clear(before)
			clear(after)
		})
	}
}

// TestOnboardingAuthorityReadsDistinguishTransportFromEvidence freezes bounded failure classes.
func TestOnboardingAuthorityReadsDistinguishTransportFromEvidence(t *testing.T) {
	t.Run("current snapshot", func(t *testing.T) {
		for _, test := range []struct {
			name      string
			configure func(*onboardingBackendFake)
			want      ErrorCode
		}{
			{name: "current read error", configure: func(backend *onboardingBackendFake) {
				backend.readCurrentErr = errors.New("current backend offline")
			}, want: CodeUnavailable},
			{name: "missing successful result", configure: func(backend *onboardingBackendFake) {
				backend.readCurrentNil = true
			}, want: CodeConflict},
			{name: "mismatched successful result", configure: func(backend *onboardingBackendFake) {
				backend.readCurrentSubstituted = true
			}, want: CodeConflict},
		} {
			t.Run(test.name, func(t *testing.T) {
				onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
				defer closeOnboardingFixture(store, backend, plan)
				_, _ = planOnboarding(t, onboarding, store)
				test.configure(backend)
				_, err := onboarding.Prepare(t.Context(), store)
				if CodeOf(err) != test.want {
					t.Fatalf("current snapshot class = %s, want %s", CodeOf(err), test.want)
				}
			})
		}
	})

	t.Run("claimed lock", func(t *testing.T) {
		for _, test := range []struct {
			name      string
			configure func(*onboardingBackendFake)
			want      ErrorCode
		}{
			{name: "claimed-lock read error", configure: func(backend *onboardingBackendFake) {
				backend.observeLockErr = errors.New("claim backend offline")
			}, want: CodeUnavailable},
			{name: "invalid", configure: func(backend *onboardingBackendFake) {
				backend.invalidLockObservation = true
			}, want: CodeConflict},
			{name: "ownerless mismatch", configure: func(backend *onboardingBackendFake) {
				backend.lockClaimed = false
				backend.lockOwner = datasourceadmin.OperationBinding{}
			}, want: CodeConflict},
		} {
			t.Run(test.name, func(t *testing.T) {
				onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
				defer closeOnboardingFixture(store, backend, plan)
				_, _ = planOnboarding(t, onboarding, store)
				journal, exists, loadErr := store.Load(t.Context())
				if loadErr != nil || !exists {
					t.Fatal("load claimed-lock journal")
				}
				defer journal.Close() //nolint:errcheck // Test cleanup has no recovery action.
				lock, lockErr := journal.AdministrationLock()
				if lockErr != nil {
					t.Fatal("load claimed-lock evidence")
				}
				test.configure(backend)
				if err := onboarding.requireClaimed(t.Context(), lock); CodeOf(err) != test.want {
					t.Fatalf("claimed-lock class = %s, want %s", CodeOf(err), test.want)
				}
			})
		}
	})

	t.Run("candidate inspection", func(t *testing.T) {
		for _, test := range []struct {
			name      string
			configure func(*onboardingBackendFake)
			want      ErrorCode
		}{
			{name: "observation unavailable", configure: func(backend *onboardingBackendFake) {
				backend.observeErr = errors.New("observation backend offline")
			}, want: CodeUnavailable},
			{name: "observation invalid", configure: func(backend *onboardingBackendFake) {
				backend.observeInvalid = true
			}, want: CodeConflict},
			{name: "inspection unavailable", configure: func(backend *onboardingBackendFake) {
				backend.inspectErr = errors.New("inspection backend offline")
			}, want: CodeUnavailable},
			{name: "inspection missing", configure: func(backend *onboardingBackendFake) {
				backend.inspectNil = true
			}, want: CodeConflict},
			{name: "inspection mismatch", configure: func(backend *onboardingBackendFake) {
				backend.inspectMismatch = true
			}, want: CodeConflict},
		} {
			t.Run(test.name, func(t *testing.T) {
				onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
				defer closeOnboardingFixture(store, backend, plan)
				_, _ = planOnboarding(t, onboarding, store)
				if _, err := onboarding.Prepare(t.Context(), store); err != nil {
					t.Fatal("prepare candidate-inspection fixture")
				}
				journal, exists, loadErr := store.Load(t.Context())
				if loadErr != nil || !exists {
					t.Fatal("load candidate-inspection journal")
				}
				defer journal.Close() //nolint:errcheck // Test cleanup has no recovery action.
				test.configure(backend)
				candidate, _, err := onboarding.inspectExact(
					t.Context(), journal, datasourceadmin.PublicationExactCommitted, false,
				)
				_ = candidate.Close()
				if CodeOf(err) != test.want {
					t.Fatalf("candidate inspection class = %s, want %s", CodeOf(err), test.want)
				}
			})
		}
	})
}

// TestOnboardingDirectPreparedAbsentAbortIsNonDestructive freezes the documented pre-stage stop.
func TestOnboardingDirectPreparedAbsentAbortIsNonDestructive(t *testing.T) {
	onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
	defer closeOnboardingFixture(store, backend, plan)
	_, _ = planOnboarding(t, onboarding, store)
	journal, exists, err := store.Load(t.Context())
	if err != nil || !exists || journal == nil {
		t.Fatal("load planned journal")
	}
	prepared, _ := candidateEvidenceFixture(t)
	if journal.BeginPreparing() != nil || journal.RecordPrepared(prepared) != nil || store.Save(t.Context(), journal) != nil {
		_ = journal.Close()
		t.Fatal("persist prepared abort fixture")
	}
	_ = journal.Close()
	result, err := onboarding.Abort(t.Context(), store)
	if err != nil || result.State != StateAborted || backend.stageCalls != 0 || backend.activateCalls != 0 || backend.lockClaimed {
		t.Fatal("direct prepared-absent abort mutated candidate data or failed to release")
	}
}

// TestOnboardingReconcileReleasedPlannedAndPreparingStatesResumeWithExactReclaim freezes restartability.
func TestOnboardingReconcileReleasedPlannedAndPreparingStatesResumeWithExactReclaim(t *testing.T) {
	for _, state := range []OperationState{StatePlanned, StatePreparing} {
		t.Run(string(state), func(t *testing.T) {
			onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
			defer closeOnboardingFixture(store, backend, plan)
			if _, err := planOnboarding(t, onboarding, store); err != nil {
				t.Fatal("persist resume plan")
			}
			if state == StatePreparing {
				journal, _, err := store.Load(t.Context())
				if err != nil || journal.BeginPreparing() != nil || store.Save(t.Context(), journal) != nil {
					_ = journal.Close()
					t.Fatal("persist preparing resume state")
				}
				_ = journal.Close()
			}
			if result, err := onboarding.Reconcile(t.Context(), store); err != nil || result.State != state || backend.lockClaimed {
				t.Fatal("explicit reconcile did not safely release restartable pre-key state")
			}
			if result, err := onboarding.Prepare(t.Context(), store); err != nil || result.State != StateStaged || backend.claimCalls == 0 {
				t.Fatal("ownerless reconciled state did not reacquire exact revision and resume")
			}
		})
	}
}

// TestOnboardingReconcileRepairsReleaseSaveLossAndStatusIsStrictlyReadOnly freezes lock metadata recovery.
func TestOnboardingReconcileRepairsReleaseSaveLossAndStatusIsStrictlyReadOnly(t *testing.T) {
	onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
	defer closeOnboardingFixture(store, backend, plan)
	_, _ = planOnboarding(t, onboarding, store)
	if _, err := onboarding.Prepare(t.Context(), store); err != nil {
		t.Fatal("prepare release-loss fixture")
	}
	journal, _, err := store.Load(t.Context())
	if err != nil {
		t.Fatal("load release-loss journal")
	}
	journal.mu.Lock()
	journal.plan.lockRevision--
	journal.mu.Unlock()
	if err := store.Save(t.Context(), journal); err != nil {
		_ = journal.Close()
		t.Fatal("persist simulated stale release revision")
	}
	_ = journal.Close()
	if result, err := onboarding.Reconcile(t.Context(), store); err != nil || result.State != StateStaged {
		t.Fatal("explicit reconcile did not repair exact ownerless R+1 observation")
	}
	stageCalls, activateCalls, releaseCalls := backend.stageCalls, backend.activateCalls, backend.releaseCalls
	first, err := onboarding.Status(t.Context(), store)
	if err != nil {
		t.Fatal("first read-only status")
	}
	second, err := onboarding.Status(t.Context(), store)
	if err != nil || first != second || backend.stageCalls != stageCalls ||
		backend.activateCalls != activateCalls || backend.releaseCalls != releaseCalls {
		t.Fatal("status changed journal or backend mutation counters")
	}
	if first.CandidateGeneration <= first.ExpectedCurrentGeneration || !first.CurrentGenerationKnown ||
		first.CurrentGeneration != first.ExpectedCurrentGeneration || first.CredentialCount == 0 ||
		first.RSACredentialCount+first.Ed25519CredentialCount != first.CredentialCount {
		t.Fatal("status omitted authoritative current and protected plan count facts")
	}
}

// TestOnboardingCommittedCandidateAbortRequiresReconciliationWithoutDeletion freezes abort safety.
func TestOnboardingCommittedCandidateAbortRequiresReconciliationWithoutDeletion(t *testing.T) {
	onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
	defer closeOnboardingFixture(store, backend, plan)
	_, _ = planOnboarding(t, onboarding, store)
	if _, err := onboarding.Prepare(t.Context(), store); err != nil {
		t.Fatal("prepare committed abort fixture")
	}
	stageCalls := backend.stageCalls
	result, err := onboarding.Abort(t.Context(), store)
	if CodeOf(err) != CodeReconcileRequired || result.State != StateReconcileRequired ||
		backend.candidate == nil || backend.stageCalls != stageCalls || backend.activateCalls != 0 {
		t.Fatal("committed noncurrent candidate abort was destructive or not reconciliation-gated")
	}
}

// TestOnboardingPlanFailureBeforeReceiptDoesNotClaim freezes the pre-receipt failure window.
func TestOnboardingPlanFailureBeforeReceiptDoesNotClaim(t *testing.T) {
	onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
	defer closeOnboardingFixture(store, backend, plan)
	if err := store.Close(); err != nil {
		t.Fatal("close plan-failure store")
	}
	result, err := planOnboarding(t, onboarding, store)
	if CodeOf(err) != CodeProtectedInput || result.State != "" || result.Failure == CodeNone ||
		backend.lockClaimed || backend.claimCalls != 0 || backend.releaseCalls != 0 {
		t.Fatalf("pre-receipt plan failure mutated lock authority or synthesized state: code=%s state=%s failure=%s claimed=%v claims=%d releases=%d", CodeOf(err), result.State, result.Failure, backend.lockClaimed, backend.claimCalls, backend.releaseCalls)
	}
}

// onboardingCoordinatorFixture constructs one plan-bound coordinator and protected journal store.
func onboardingCoordinatorFixture(
	t *testing.T,
) (*Onboarding, *onboardingBackendFake, *JournalStore, *Plan, *int) {
	t.Helper()
	current := collisionSnapshot(t, 1, "current-profile", "current-handle", "current-selector")
	backend := &onboardingBackendFake{
		t: t, current: current, candidateState: datasourceadmin.PublicationAbsent,
		stageState:   datasourceadmin.PublicationExactCommitted,
		lockRevision: 23,
	}
	proofCalls := 0
	onboarding := newOnboardingForTest(t, backend, planAuthority(), &proofCalls)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("resolve onboarding journal directory")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal("protect onboarding journal directory")
	}
	store, err := OpenJournalStore(t.Context(), filepath.Join(root, "operation.json"), DefaultLimits())
	if err != nil {
		t.Fatal("open onboarding journal store")
	}
	return onboarding, backend, store, nil, &proofCalls
}

// onboardingReadyToActivateFixture advances one coordinator through fresh DNS proof.
func onboardingReadyToActivateFixture(
	t *testing.T,
) (*Onboarding, *onboardingBackendFake, *JournalStore, *Plan, *int) {
	t.Helper()
	onboarding, backend, store, plan, calls := onboardingCoordinatorFixture(t)
	if _, err := planOnboarding(t, onboarding, store); err != nil {
		t.Fatal("plan activation fixture")
	}
	if _, err := onboarding.Prepare(t.Context(), store); err != nil {
		t.Fatal("prepare activation fixture")
	}
	path := protectedOnboardingPath(t, "dns.txt")
	if _, err := onboarding.DNSExport(t.Context(), store, path); err != nil {
		t.Fatal("export activation fixture")
	}
	if _, err := onboarding.Prove(t.Context(), store); err != nil {
		t.Fatal("prove activation fixture")
	}
	return onboarding, backend, store, plan, calls
}

// newOnboardingForTest constructs one limit-aligned coordinator with dynamic exact DNS answers.
func newOnboardingForTest(
	t *testing.T,
	backend *onboardingBackendFake,
	authority datasourceadmin.AuthorityDescriptor,
	proofCalls *int,
) *Onboarding {
	t.Helper()
	limits := DefaultLimits()
	allocator, err := newIdentityAllocator(limits, &incrementingEntropy{})
	if err != nil {
		t.Fatal("construct onboarding identity allocator")
	}
	generator, err := newKeyGenerator(DefaultKeyPolicy(), limits, &incrementingEntropy{value: 10})
	if err != nil {
		t.Fatal("construct onboarding key generator")
	}
	engine, err := newDNSProofEngine(limits, time.Now, func(
		context.Context,
		datasourceadmin.DNSPolicy,
	) (dkim2.PublicKeyProvider, error) {
		if proofCalls != nil {
			*proofCalls++
		}
		answers := candidateDNSAnswersForOnboardingTest(t, backend.candidate)
		transport := &proofTransport{lookup: func(_ context.Context, owner string) (dkim2.TXTLookupResult, error) {
			payload, found := answers[owner]
			if !found {
				return dkim2.TXTLookupResult{}, errors.New("unexpected DNS owner")
			}
			return dkim2.NewFoundTXTLookupResult([][]byte{payload}, time.Minute, dkim2.DNSSECStatusUnavailable)
		}}
		return dkim2.NewDNSPublicKeyProvider(transport)
	})
	if err != nil {
		t.Fatal("construct onboarding DNS proof engine")
	}
	onboarding, err := NewOnboarding(
		limits, testAdminGenerationLimits(), allocator, generator, engine, backend,
		datasourceadmin.BackendLDAP, authority, time.Now, nil,
	)
	if err != nil {
		t.Fatal("construct onboarding coordinator")
	}
	return onboarding
}

// planOnboarding submits the canonical test intent through the public planning boundary.
func planOnboarding(
	t *testing.T,
	onboarding *Onboarding,
	store *JournalStore,
) (OnboardingResult, error) {
	t.Helper()
	return onboarding.Plan(t.Context(), store, testIntent(t, provider.AlgorithmEd25519SHA256), planDNSPolicy())
}

// candidateDNSAnswersForOnboardingTest derives exact DNS records from canonical candidate readback.
func candidateDNSAnswersForOnboardingTest(
	t *testing.T,
	candidate *datasourceadmin.PublicationEnvelope,
) map[string][]byte {
	t.Helper()
	answers := make(map[string][]byte)
	if candidate == nil {
		return answers
	}
	if err := candidate.WithRows(t.Context(), func(rows datasourceadmin.Rows) error {
		domains := make(map[string]string)
		for _, profile := range rows.Profiles {
			domains[profile.ID] = profile.Domain
		}
		for _, credential := range rows.Credentials {
			record, err := newDNSRecord(
				t.Context(), domains[credential.ProfileID], credential.Selector,
				provider.Algorithm(credential.Algorithm), credential.PublicSPKI,
			)
			if err != nil {
				return err
			}
			answers[string(record.owner)] = append([]byte(nil), record.payload...)
			clearDNSRecord(&record)
		}
		return nil
	}); err != nil {
		t.Fatal("derive onboarding DNS answers")
	}
	return answers
}

// cloneSnapshotForOnboardingTest detaches one complete snapshot.
func cloneSnapshotForOnboardingTest(t *testing.T, source *datasourceadmin.Snapshot) *datasourceadmin.Snapshot {
	t.Helper()
	var clone *datasourceadmin.Snapshot
	if err := source.WithRows(t.Context(), func(rows datasourceadmin.Rows) error {
		var err error
		clone, err = datasourceadmin.NewSnapshot(source.SchemaVersion(), source.Generation(), rows)
		return err
	}); err != nil || clone == nil {
		t.Fatal("clone onboarding snapshot")
	}
	return clone
}

// cloneCandidateForOnboardingTest detaches one complete operation-bound candidate.
func cloneCandidateForOnboardingTest(
	t *testing.T,
	source *datasourceadmin.PublicationEnvelope,
) *datasourceadmin.PublicationEnvelope {
	t.Helper()
	var snapshot *datasourceadmin.Snapshot
	if err := source.WithRows(t.Context(), func(rows datasourceadmin.Rows) error {
		var err error
		snapshot, err = datasourceadmin.NewSnapshot(
			datasourceadmin.SchemaVersionV3, source.Generation(), rows,
		)
		return err
	}); err != nil {
		t.Fatal("clone onboarding candidate snapshot")
	}
	operation := ""
	if err := source.Binding().WithValue(t.Context(), func(value string) error {
		operation = value
		return nil
	}); err != nil {
		t.Fatal("read onboarding operation binding")
	}
	content, err := datasourceadmin.NewCandidateContent(snapshot)
	if err != nil {
		_ = snapshot.Close()
		t.Fatal("clone onboarding candidate content")
	}
	clone, err := datasourceadmin.NewPublicationEnvelope(operation, content)
	if err != nil {
		_ = content.Close()
		t.Fatal("clone onboarding publication envelope")
	}
	return clone
}

// closeOnboardingFixture releases every protected fake and store owner.
func closeOnboardingFixture(store *JournalStore, backend *onboardingBackendFake, plan *Plan) {
	_ = store.Close()
	if backend.candidate != nil {
		_ = backend.candidate.Close()
	}
	if backend.current != nil {
		_ = backend.current.Close()
	}
	_ = plan.Close()
}

// protectedOnboardingPath returns one symlink-resolved owner-only test artifact path.
func protectedOnboardingPath(t *testing.T, name string) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("resolve onboarding artifact directory")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal("protect onboarding artifact directory")
	}
	return filepath.Join(root, name)
}
