package domainadmin

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// OnboardingBackend is the provider-neutral offline publication authority.
type OnboardingBackend interface {
	datasourceadmin.SnapshotReader
	datasourceadmin.GenerationPublisher
	datasourceadmin.AdministrationLocker
}

// OnboardingResultClass is one bounded command outcome.
type OnboardingResultClass string

const (
	// OnboardingResultSuccess reports a completed or exact idempotent command.
	OnboardingResultSuccess OnboardingResultClass = "success"
	// OnboardingResultFailure reports a closed non-ambiguous failure.
	OnboardingResultFailure OnboardingResultClass = "failure"
	// OnboardingResultReconcile reports an outcome requiring explicit reconciliation.
	OnboardingResultReconcile OnboardingResultClass = "reconcile_required"
)

// OnboardingResult contains only bounded identity-free command evidence.
type OnboardingResult struct {
	State                       OperationState
	Result                      OnboardingResultClass
	Failure                     ErrorCode
	ExpectedCurrentGeneration   uint64
	CurrentGeneration           uint64
	CurrentGenerationKnown      bool
	CandidateGeneration         uint64
	CredentialCount             uint32
	RSACredentialCount          uint32
	Ed25519CredentialCount      uint32
	RuntimeVerificationRequired bool
	PlanComplete                bool
	ReceiptPresent              bool
	ReceiptPhase                ReceiptPhase
}

// OnboardingObservation contains only low-cardinality offline workflow facts.
type OnboardingObservation struct {
	Command Command
	State   OperationState
	Backend datasourceadmin.BackendClass
	Result  OnboardingResultClass
	Failure ErrorCode
	Receipt ReceiptPhase
}

// Valid reports whether an observation contains only closed low-cardinality classes.
func (o OnboardingObservation) Valid() bool {
	if !o.Command.Known() || !knownAdminBackend(o.Backend) || !knownOnboardingResult(o.Result) ||
		!knownErrorCode(o.Failure) || o.State != "" && !o.State.Known() ||
		o.Receipt != "" && !knownReceiptPhase(o.Receipt) {
		return false
	}
	if o.Command == CommandStatus {
		if o.Result != OnboardingResultSuccess {
			return false
		}
		if o.Receipt != "" {
			return o.State == "" && validReceiptStatusFailure(o.Receipt, o.Failure)
		}
		return o.State.Known() && validOperationStatusFailure(o.State, o.Failure)
	}
	if !validReportResultFailure(o.Result, o.Failure) {
		return false
	}
	return o.Receipt == "" || o.State == ""
}

// OnboardingObserver receives bounded local events without owning exporters.
type OnboardingObserver interface {
	ObserveOnboarding(context.Context, OnboardingObservation)
}

// Onboarding coordinates one persisted operation through provider-neutral evidence.
type Onboarding struct {
	limits           Limits
	generationLimits datasourceadmin.GenerationLimits
	allocator        *IdentityAllocator
	generator        *KeyGenerator
	proof            *DNSProofEngine
	backend          OnboardingBackend
	backendClass     datasourceadmin.BackendClass
	authority        datasourceadmin.AuthorityDescriptor
	clock            func() time.Time
	observer         OnboardingObserver
}

// NewOnboarding constructs one finite provider-neutral onboarding coordinator.
func NewOnboarding(
	limits Limits,
	generationLimits datasourceadmin.GenerationLimits,
	allocator *IdentityAllocator,
	generator *KeyGenerator,
	proof *DNSProofEngine,
	backend OnboardingBackend,
	backendClass datasourceadmin.BackendClass,
	authority datasourceadmin.AuthorityDescriptor,
	clock func() time.Time,
	observer OnboardingObserver,
) (*Onboarding, error) {
	if limits.Validate() != nil || generationLimits.Validate() != nil || allocator == nil || generator == nil ||
		proof == nil || backend == nil || clock == nil || generator.limits != limits || proof.limits != limits ||
		allocator.limits != limits ||
		datasourceadmin.ValidateAuthority(backendClass, authority) != nil {
		return nil, newError(CodeInvalidLimits)
	}
	return &Onboarding{
		limits: limits, generationLimits: generationLimits, allocator: allocator, generator: generator,
		proof: proof, backend: backend, backendClass: backendClass,
		authority: cloneAuthority(authority), clock: clock, observer: observer,
	}, nil
}

// Plan persists a pre-claim receipt, allocates under it, and atomically promotes to a full journal.
func (o *Onboarding) Plan(
	ctx context.Context,
	store *JournalStore,
	intent Intent,
	dns datasourceadmin.DNSPolicy,
) (OnboardingResult, error) {
	if o == nil || ctx == nil || ctx.Err() != nil || store == nil || !intent.valid() ||
		datasourceadmin.ValidateDNSPolicy(dns) != nil {
		return o.failure(ctx, CommandPlan, "", "", CodeConflict)
	}
	ctx, cancel := context.WithTimeout(ctx, o.limits.BackendDeadline)
	defer cancel()
	receipt, journal, exists, err := store.LoadOperation(ctx)
	if err != nil {
		return o.failure(ctx, CommandPlan, "", o.backendClass, CodeOf(err))
	}
	if !exists {
		receipt, journal, err = o.createPlanningReceipt(ctx, store, intent, dns)
		if err != nil {
			return o.failure(ctx, CommandPlan, "", o.backendClass, CodeOf(err))
		}
	}
	if journal != nil {
		defer journal.Close() //nolint:errcheck // Exact journal retry cleanup has no recovery action.
		return o.planExistingJournal(ctx, journal, intent, dns)
	}
	if receipt == nil || !receipt.MatchesAuthority(o.backendClass, o.authority) {
		return o.failure(ctx, CommandPlan, "", o.backendClass, CodeConflict)
	}
	defer receipt.Close() //nolint:errcheck // Receipt command cleanup has no recovery action.
	return o.planFromReceipt(ctx, store, receipt, intent, dns)
}

// createPlanningReceipt allocates identity before backend I/O and returns authoritative union readback.
func (o *Onboarding) createPlanningReceipt(
	ctx context.Context,
	store *JournalStore,
	intent Intent,
	dns datasourceadmin.DNSPolicy,
) (*PlanningReceipt, *Journal, error) {
	operation, err := o.allocator.NewOperation(ctx)
	if err != nil {
		return nil, nil, err
	}
	observed, err := o.backend.ObserveAdministrationLock(ctx)
	if err != nil {
		return nil, nil, newError(CodeUnavailable)
	}
	if !observed.Valid() || observed.Claimed() {
		return nil, nil, newError(CodeConflict)
	}
	receipt, err := NewPlanningReceipt(o.backendClass, o.authority, operation, observed.Revision(), intent, dns)
	if err != nil {
		return nil, nil, err
	}
	if err := store.SaveReceipt(ctx, receipt); err != nil {
		if CodeOf(err) != CodeReconcileRequired {
			_ = receipt.Close()
			return nil, nil, err
		}
		_ = receipt.Close()
		loadedReceipt, journal, exists, reloadErr := o.reloadOperationAfterAmbiguity(ctx, store)
		if reloadErr != nil || !exists || loadedReceipt == nil && journal == nil {
			_ = loadedReceipt.Close()
			_ = journal.Close()
			return nil, nil, newError(CodeReconcileRequired)
		}
		return loadedReceipt, journal, nil
	}
	_ = receipt.Close()
	loadedReceipt, journal, exists, err := store.LoadOperation(ctx)
	if err != nil || !exists || loadedReceipt == nil || journal != nil {
		_ = loadedReceipt.Close()
		_ = journal.Close()
		return nil, nil, newError(CodeReconcileRequired)
	}
	return loadedReceipt, nil, nil
}

// planExistingJournal accepts only an exact planned idempotent retry.
func (o *Onboarding) planExistingJournal(
	ctx context.Context,
	journal *Journal,
	intent Intent,
	dns datasourceadmin.DNSPolicy,
) (OnboardingResult, error) {
	if !o.journalMatchesPlanRequest(journal, intent, dns) {
		return o.failureForJournal(ctx, CommandPlan, journal, CodeConflict)
	}
	return o.success(ctx, CommandPlan, journal, false)
}

// planFromReceipt resumes one exact receipt through allocation and promotion.
func (o *Onboarding) planFromReceipt(
	ctx context.Context,
	store *JournalStore,
	receipt *PlanningReceipt,
	intent Intent,
	dns datasourceadmin.DNSPolicy,
) (OnboardingResult, error) {
	if receipt.Closed() {
		replaced, promoted, replaceErr := o.replaceClosedPlanningReceipt(ctx, store, receipt, intent, dns)
		if replaceErr != nil {
			return o.failure(ctx, CommandPlan, "", o.backendClass, CodeOf(replaceErr))
		}
		if promoted != nil {
			defer promoted.Close() //nolint:errcheck // Exact ambiguity readback cleanup has no recovery action.
			return o.success(ctx, CommandPlan, promoted, false)
		}
		receipt = replaced
		defer receipt.Close() //nolint:errcheck // Replacement cleanup has no recovery action.
	}
	if !receipt.MatchesCoordinator(o.backendClass, o.authority, intent, dns) {
		return o.failure(ctx, CommandPlan, "", o.backendClass, CodeConflict)
	}
	phase := receipt.Phase()
	if phase == ReceiptPhaseReleaseRequired || phase == ReceiptPhaseUnresolved {
		return o.failureReceipt(ctx, CommandPlan, receipt, CodeReconcileRequired)
	}
	operation, revision, persistedIntent, persistedDNS, err := receipt.AllocationInput()
	if err != nil {
		return o.failureReceipt(ctx, CommandPlan, receipt, CodeReconcileRequired)
	}
	lock, claimedReceipt, err := o.claimPlanningReceipt(ctx, store, receipt, operation, revision)
	if claimedReceipt != receipt {
		receipt = claimedReceipt
		if receipt != nil {
			defer receipt.Close() //nolint:errcheck // Fresh post-ambiguity receipt cleanup has no recovery action.
		}
	}
	if err != nil {
		return o.failureReceipt(ctx, CommandPlan, receipt, CodeReconcileRequired)
	}
	allocation, lock, err := o.allocator.AllocateClaimed(
		ctx, persistedIntent, lock, o.backend, o.generationLimits,
	)
	if err != nil || allocation == nil || !lock.ValidFor(operation) {
		_ = allocation.Close()
		return o.failPlanningReceipt(ctx, store, receipt)
	}
	defer allocation.Close() //nolint:errcheck // Plan owns detached allocated facts.
	plan, err := NewPlan(ctx, o.backendClass, o.authority, allocation, persistedDNS)
	if err != nil {
		return o.failPlanningReceipt(ctx, store, receipt)
	}
	defer plan.Close() //nolint:errcheck // Journal owns a detached plan.
	if err := o.verifyFreshPlan(ctx, plan); err != nil {
		return o.failPlanningReceipt(ctx, store, receipt)
	}
	journal, err := NewJournal(plan)
	if err != nil {
		return o.failPlanningReceipt(ctx, store, receipt)
	}
	defer journal.Close() //nolint:errcheck // Store owns durable journal truth.
	return o.promotePlanningJournal(ctx, store, receipt, journal)
}

// promotePlanningJournal resolves ambiguous receipt-versus-journal replacement through fresh union load.
func (o *Onboarding) promotePlanningJournal(
	ctx context.Context,
	store *JournalStore,
	receipt *PlanningReceipt,
	journal *Journal,
) (OnboardingResult, error) {
	if err := store.PromoteReceipt(ctx, receipt, journal); err == nil {
		return o.success(ctx, CommandPlan, journal, false)
	} else if CodeOf(err) != CodeReconcileRequired {
		return o.failureReceipt(ctx, CommandPlan, receipt, CodeReconcileRequired)
	}
	loadedReceipt, loadedJournal, loaded, err := o.reloadOperationAfterAmbiguity(ctx, store)
	if err != nil || !loaded {
		_ = loadedReceipt.Close()
		_ = loadedJournal.Close()
		return o.failureReceipt(ctx, CommandPlan, nil, CodeReconcileRequired)
	}
	if loadedJournal != nil {
		defer loadedJournal.Close() //nolint:errcheck // Exact promoted journal cleanup has no recovery action.
		if loadedJournal.matchesPromotionRecovery(journal) {
			return o.success(ctx, CommandPlan, loadedJournal, false)
		}
		return o.failureReceipt(ctx, CommandPlan, nil, CodeReconcileRequired)
	}
	if loadedReceipt != nil {
		defer loadedReceipt.Close() //nolint:errcheck // Retained receipt cleanup has no recovery action.
		if loadedReceipt.sameRecoveryPhase(receipt) {
			return o.failureReceipt(ctx, CommandPlan, loadedReceipt, CodeReconcileRequired)
		}
		return o.failureReceipt(ctx, CommandPlan, nil, CodeReconcileRequired)
	}
	return o.failureReceipt(ctx, CommandPlan, nil, CodeReconcileRequired)
}

// claimPlanningReceipt acquires or confirms only the exact persisted operation and revision.
func (o *Onboarding) claimPlanningReceipt(
	ctx context.Context,
	store *JournalStore,
	receipt *PlanningReceipt,
	operation datasourceadmin.OperationBinding,
	revision uint64,
) (datasourceadmin.AdministrationLock, *PlanningReceipt, error) {
	_, _, state, stateErr := receipt.reconciliationInput()
	if stateErr != nil || (state != planningReceiptClaimPending && state != planningReceiptAllocating) {
		return datasourceadmin.AdministrationLock{}, receipt, newError(CodeReconcileRequired)
	}
	lock, err := o.observeOrClaimPlanningLock(ctx, operation, revision, state)
	if err != nil {
		saved, persistErr := o.persistUnresolvedReceipt(ctx, store, receipt)
		authoritative := saved.receipt
		if persistErr != nil || !saved.mayContinue() {
			return datasourceadmin.AdministrationLock{}, authoritative, newError(CodeReconcileRequired)
		}
		return datasourceadmin.AdministrationLock{}, authoritative, newError(CodeReconcileRequired)
	}
	if state == planningReceiptClaimPending {
		if err := receipt.RecordAllocating(); err != nil {
			return datasourceadmin.AdministrationLock{}, receipt, newError(CodeReconcileRequired)
		}
		saved, saveErr := o.savePlanningReceipt(ctx, store, receipt)
		authoritative := saved.receipt
		if saveErr != nil || !saved.mayContinue() ||
			authoritative.Phase() != ReceiptPhaseAllocating {
			return datasourceadmin.AdministrationLock{}, authoritative, newError(CodeReconcileRequired)
		}
		return lock, authoritative, nil
	}
	return lock, receipt, nil
}

// observeOrClaimPlanningLock resolves a possibly post-mutation Claim error by exact re-observation.
func (o *Onboarding) observeOrClaimPlanningLock(
	ctx context.Context,
	operation datasourceadmin.OperationBinding,
	revision uint64,
	state planningReceiptState,
) (datasourceadmin.AdministrationLock, error) {
	observed, err := o.backend.ObserveAdministrationLock(ctx)
	if err != nil || !observed.Valid() {
		return datasourceadmin.AdministrationLock{}, newError(CodeReconcileRequired)
	}
	if observed.Claimed() {
		if observed.Revision() != revision || !observed.Owner().Equal(operation) {
			return datasourceadmin.AdministrationLock{}, newError(CodeReconcileRequired)
		}
		return datasourceadmin.NewAdministrationLock(operation, revision)
	}
	if state != planningReceiptClaimPending || observed.Revision() != revision {
		return datasourceadmin.AdministrationLock{}, newError(CodeReconcileRequired)
	}
	lock, claimErr := o.backend.Claim(ctx, operation, revision)
	if claimErr == nil && lock.ValidFor(operation) && lock.Revision() == revision {
		return lock, nil
	}
	confirmed, observeErr := o.backend.ObserveAdministrationLock(ctx)
	if observeErr != nil || !confirmed.Valid() || !confirmed.Claimed() ||
		confirmed.Revision() != revision || !confirmed.Owner().Equal(operation) {
		return datasourceadmin.AdministrationLock{}, newError(CodeReconcileRequired)
	}
	return datasourceadmin.NewAdministrationLock(operation, revision)
}

// journalMatchesPlanRequest checks exact idempotent Plan retry authority and request fields.
func (o *Onboarding) journalMatchesPlanRequest(
	journal *Journal,
	intent Intent,
	dns datasourceadmin.DNSPolicy,
) bool {
	if journal == nil || journal.State() != StatePlanned {
		return false
	}
	plan, err := journal.clonePlan()
	if err != nil {
		return false
	}
	defer plan.Close() //nolint:errcheck // Detached comparison cleanup has no recovery action.
	return plan.MatchesCoordinator(o.backendClass, o.authority) && plan.intent.equal(intent) && dnsPolicyEqual(plan.dns, dns)
}

// replaceClosedPlanningReceipt CAS-replaces only exact ownerless retained receipt evidence.
func (o *Onboarding) replaceClosedPlanningReceipt(
	ctx context.Context,
	store *JournalStore,
	closed *PlanningReceipt,
	intent Intent,
	dns datasourceadmin.DNSPolicy,
) (*PlanningReceipt, *Journal, error) {
	_, revision, state, err := closed.reconciliationInput()
	if err != nil || state != planningReceiptClosed {
		return nil, nil, newError(CodeConflict)
	}
	operation, err := o.allocator.NewOperation(ctx)
	if err != nil {
		return nil, nil, err
	}
	observed, err := o.backend.ObserveAdministrationLock(ctx)
	if err != nil {
		return nil, nil, newError(CodeUnavailable)
	}
	if !observed.Valid() || observed.Claimed() || observed.Revision() != revision {
		return nil, nil, newError(CodeReconcileRequired)
	}
	next, err := NewPlanningReceipt(o.backendClass, o.authority, operation, revision, intent, dns)
	if err != nil {
		return nil, nil, err
	}
	if err := store.ReplaceClosedReceipt(ctx, closed, next); err != nil {
		if CodeOf(err) != CodeReconcileRequired {
			_ = next.Close()
			return nil, nil, err
		}
		loadedReceipt, loadedJournal, exists, reloadErr := o.reloadOperationAfterAmbiguity(ctx, store)
		if reloadErr != nil || !exists {
			_ = next.Close()
			_ = loadedReceipt.Close()
			_ = loadedJournal.Close()
			return nil, nil, newError(CodeReconcileRequired)
		}
		if loadedJournal != nil && o.journalMatchesPlanRequest(loadedJournal, intent, dns) {
			_ = next.Close()
			return nil, loadedJournal, nil
		}
		if loadedReceipt != nil && loadedReceipt.sameRecoveryPhase(next) {
			_ = next.Close()
			return loadedReceipt, nil, nil
		}
		_ = next.Close()
		_ = loadedReceipt.Close()
		_ = loadedJournal.Close()
		return nil, nil, newError(CodeReconcileRequired)
	}
	return next, nil, nil
}

// planningReceiptSaveResult separates fresh durable truth from permission to continue mutation.
type planningReceiptSaveResult struct {
	receipt         *PlanningReceipt
	continueAllowed bool
}

// mayContinue requires both authoritative receipt presence and an exact attempted-state match.
func (r planningReceiptSaveResult) mayContinue() bool {
	return r.receipt != nil && r.continueAllowed
}

// persistUnresolvedReceipt durably closes planning after foreign or unavailable evidence.
func (o *Onboarding) persistUnresolvedReceipt(
	ctx context.Context,
	store *JournalStore,
	receipt *PlanningReceipt,
) (planningReceiptSaveResult, error) {
	if receipt == nil || receipt.RecordUnresolved() != nil {
		return planningReceiptSaveResult{receipt: receipt}, newError(CodeReconcileRequired)
	}
	return o.savePlanningReceipt(ctx, store, receipt)
}

// savePlanningReceipt returns fresh authoritative receipt truth and separately gates continuation.
func (o *Onboarding) savePlanningReceipt(
	ctx context.Context,
	store *JournalStore,
	receipt *PlanningReceipt,
) (planningReceiptSaveResult, error) {
	if err := store.SaveReceipt(ctx, receipt); err != nil {
		if CodeOf(err) != CodeReconcileRequired {
			return planningReceiptSaveResult{}, err
		}
		loadedReceipt, loadedJournal, exists, reloadErr := o.reloadOperationAfterAmbiguity(ctx, store)
		if reloadErr != nil || !exists || loadedReceipt == nil || loadedJournal != nil {
			_ = loadedReceipt.Close()
			_ = loadedJournal.Close()
			return planningReceiptSaveResult{}, newError(CodeReconcileRequired)
		}
		phaseMatch := loadedReceipt.sameRecoveryPhase(receipt)
		result := planningReceiptSaveResult{receipt: loadedReceipt, continueAllowed: phaseMatch}
		if !phaseMatch {
			return result, newError(CodeReconcileRequired)
		}
		return result, nil
	}
	return planningReceiptSaveResult{receipt: receipt, continueAllowed: true}, nil
}

// reloadOperationAfterAmbiguity uses a fresh finite cleanup context even after caller cancellation.
func (o *Onboarding) reloadOperationAfterAmbiguity(
	caller context.Context,
	store *JournalStore,
) (*PlanningReceipt, *Journal, bool, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(caller), o.limits.BackendDeadline)
	defer cancel()
	return store.ReloadOperation(ctx)
}

// failureReceipt constructs one bounded incomplete-plan result.
func (o *Onboarding) failureReceipt(
	ctx context.Context,
	command Command,
	receipt *PlanningReceipt,
	failure ErrorCode,
) (OnboardingResult, error) {
	phase := ReceiptPhase("")
	if receipt != nil {
		phase = receipt.Phase()
	}
	class := OnboardingResultFailure
	if failure == CodeReconcileRequired {
		class = OnboardingResultReconcile
	}
	result := OnboardingResult{
		Result: class, Failure: failure, ReceiptPresent: receipt != nil, ReceiptPhase: phase,
	}
	o.observe(ctx, OnboardingObservation{
		Command: command, Backend: o.backendClass, Result: class, Failure: failure, Receipt: phase,
	})
	return result, newError(failure)
}

// failPlanningReceipt gates all further planning on explicit receipt reconciliation.
func (o *Onboarding) failPlanningReceipt(
	ctx context.Context,
	store *JournalStore,
	receipt *PlanningReceipt,
) (OnboardingResult, error) {
	if receipt != nil {
		if err := receipt.RecordReleaseRequired(); err != nil {
			return o.failureReceipt(ctx, CommandPlan, receipt, CodeReconcileRequired)
		}
		saved, err := o.savePlanningReceipt(ctx, store, receipt)
		authoritative := saved.receipt
		if authoritative != nil && authoritative != receipt {
			defer authoritative.Close() //nolint:errcheck // Fresh ambiguity readback cleanup has no recovery action.
		}
		receipt = authoritative
		if err != nil || !saved.mayContinue() {
			return o.failureReceipt(ctx, CommandPlan, receipt, CodeReconcileRequired)
		}
	}
	return o.failureReceipt(ctx, CommandPlan, receipt, CodeReconcileRequired)
}

// Prepare generates fresh keys from persisted plan identifiers, stages, inspects, and records exact readback.
func (o *Onboarding) Prepare(ctx context.Context, store *JournalStore) (OnboardingResult, error) {
	ctx, cancel, err := o.commandContext(ctx)
	if err != nil {
		return OnboardingResult{}, err
	}
	defer cancel()
	journal, err := o.loadForMutation(ctx, store)
	if err != nil {
		if journal != nil {
			defer journal.Close() //nolint:errcheck // Failure report cleanup has no recovery action.
			return o.failureForJournal(ctx, CommandPrepare, journal, CodeOf(err))
		}
		return o.failure(ctx, CommandPrepare, "", o.backendClass, CodeOf(err))
	}
	defer journal.Close() //nolint:errcheck // Command cleanup has no recovery action.
	if journal.State() == StateStaged || journal.State() == StateDNSExported || journal.State() == StateDNSProven {
		if err := o.requireReleasedClaim(ctx, journal); err != nil {
			return o.failureForJournal(ctx, CommandPrepare, journal, CodeOf(err))
		}
		return o.success(ctx, CommandPrepare, journal, false)
	}
	if err := o.beginPreparation(ctx, store, journal); err != nil {
		return o.failureForJournal(ctx, CommandPrepare, journal, CodeOf(err))
	}
	candidate, err := o.generatePreparedCandidate(ctx, store, journal)
	if err != nil {
		return o.failureForJournal(ctx, CommandPrepare, journal, CodeOf(err))
	}
	defer candidate.Close() //nolint:errcheck // Optional prepared candidate cleanup has no recovery action.
	if journal.State() != StatePrepared {
		return o.failureForJournal(ctx, CommandPrepare, journal, CodeConflict)
	}
	return o.stagePreparedCandidate(ctx, store, journal, candidate)
}

// beginPreparation persists the write-ahead state before single-use key generation.
func (o *Onboarding) beginPreparation(ctx context.Context, store *JournalStore, journal *Journal) error {
	if journal.State() != StatePlanned {
		return nil
	}
	if _, err := o.acquireOrConfirmClaim(ctx, journal); err != nil {
		return err
	}
	if err := journal.BeginPreparing(); err != nil {
		return err
	}
	return store.Save(ctx, journal)
}

// generatePreparedCandidate generates and syncs candidate evidence only from preparing state.
func (o *Onboarding) generatePreparedCandidate(
	ctx context.Context,
	store *JournalStore,
	journal *Journal,
) (*datasourceadmin.PublicationEnvelope, error) {
	if journal.State() != StatePreparing {
		return nil, nil
	}
	if _, err := o.acquireOrConfirmClaim(ctx, journal); err != nil {
		return nil, err
	}
	if err := o.requireFreshPlan(ctx, journal); err != nil {
		return nil, err
	}
	input, err := journal.KeyGenerationInput()
	if err != nil {
		return nil, err
	}
	defer input.Close() //nolint:errcheck // Preparation input is single-use.
	keys, err := o.generator.GeneratePlanned(ctx, input)
	if err != nil {
		return nil, err
	}
	defer keys.Close() //nolint:errcheck // Candidate owns detached key bytes.
	candidate, err := o.buildCandidate(ctx, journal, keys)
	if err != nil {
		return nil, err
	}
	if err := o.requireFreshPlan(ctx, journal); err != nil {
		_ = candidate.Close()
		return nil, err
	}
	if err := journal.RecordPrepared(candidate.PreparedEvidence()); err != nil {
		_ = candidate.Close()
		return nil, err
	}
	if err := store.Save(ctx, journal); err != nil {
		_ = candidate.Close()
		return nil, err
	}
	return candidate, nil
}

// stagePreparedCandidate stages, independently reads back, syncs, and releases one exact candidate.
func (o *Onboarding) stagePreparedCandidate(
	ctx context.Context,
	store *JournalStore,
	journal *Journal,
	candidate *datasourceadmin.PublicationEnvelope,
) (OnboardingResult, error) {
	var err error
	if candidate == nil {
		candidate, _, err = o.inspectExact(ctx, journal, datasourceadmin.PublicationExactStaging, false)
		if err != nil {
			return o.failureForJournal(ctx, CommandPrepare, journal, CodeOf(err))
		}
		defer candidate.Close() //nolint:errcheck // Restart readback cleanup has no recovery action.
	}
	lock, err := o.acquireOrConfirmClaim(ctx, journal)
	if err != nil {
		return o.failureForJournal(ctx, CommandPrepare, journal, CodeOf(err))
	}
	plan, err := journal.clonePlan()
	if err != nil {
		return o.failureForJournal(ctx, CommandPrepare, journal, CodeOf(err))
	}
	defer plan.Close() //nolint:errcheck // Detached plan cleanup has no recovery action.
	_, _ = o.backend.Stage(ctx, lock, plan.operation, candidate)
	publication, observeErr := o.backend.Observe(
		ctx, plan.operation, plan.candidateGeneration, plan.expectedCurrent, o.generationLimits,
	)
	if observeErr != nil {
		return o.failureForJournal(ctx, CommandPrepare, journal, o.persistReconciliation(ctx, store, journal))
	}
	if publication.State() != datasourceadmin.PublicationExactCommitted ||
		publication.CurrentGeneration() != plan.expectedCurrent {
		observation, observationErr := backendObservationFromPublication(publication)
		if observationErr != nil {
			return o.failureForJournal(ctx, CommandPrepare, journal, o.persistReconciliation(ctx, store, journal))
		}
		reconciled, reconcileErr := Reconcile(journal, o.authority, observation)
		if reconcileErr != nil {
			return o.failureForJournal(ctx, CommandPrepare, journal, o.persistReconciliation(ctx, store, journal))
		}
		if reconciled.Outcome != ReconcileUnchanged {
			if saveErr := store.Save(ctx, journal); saveErr != nil {
				return o.failureForJournal(ctx, CommandPrepare, journal, CodeOf(saveErr))
			}
		}
		if reconciled.State == StateConflict {
			return o.failureForJournal(ctx, CommandPrepare, journal, CodeConflict)
		}
		if reconciled.State == StateFailed {
			return o.failureForJournal(ctx, CommandPrepare, journal, journalFailureCode(journal))
		}
		return o.failureForJournal(ctx, CommandPrepare, journal, CodeReconcileRequired)
	}
	readback, info, err := o.inspectExact(ctx, journal, datasourceadmin.PublicationExactCommitted, false)
	if err != nil {
		return o.failureForJournal(ctx, CommandPrepare, journal, o.persistReconciliation(ctx, store, journal))
	}
	defer readback.Close() //nolint:errcheck // Readback cleanup has no recovery action.
	inspected := datasourceadmin.NewStagedEvidence(readback.Digest())
	prepared, _, _ := journal.Evidence()
	if info.State != datasourceadmin.StateCommitted || info.Current || !prepared.Matches(inspected) {
		return o.failureForJournal(ctx, CommandPrepare, journal, o.persistReconciliation(ctx, store, journal))
	}
	if err := journal.RecordStaged(inspected); err != nil {
		return o.failureForJournal(ctx, CommandPrepare, journal, CodeOf(err))
	}
	if err := store.Save(ctx, journal); err != nil {
		return o.failureForJournal(ctx, CommandPrepare, journal, CodeOf(err))
	}
	if err := o.releaseClaim(ctx, store, journal, lock); err != nil {
		return o.failureForJournal(ctx, CommandPrepare, journal, CodeOf(err))
	}
	return o.success(ctx, CommandPrepare, journal, false)
}

// DNSExport writes one protected deterministic artifact from exact committed readback.
func (o *Onboarding) DNSExport(
	ctx context.Context,
	store *JournalStore,
	path string,
) (OnboardingResult, error) {
	ctx, cancel, err := o.commandContext(ctx)
	if err != nil {
		return OnboardingResult{}, err
	}
	defer cancel()
	journal, err := o.loadForMutation(ctx, store)
	if err != nil {
		if journal != nil {
			defer journal.Close() //nolint:errcheck // Failure report cleanup has no recovery action.
			return o.failureForJournal(ctx, CommandDNSExport, journal, CodeOf(err))
		}
		return o.failure(ctx, CommandDNSExport, "", o.backendClass, CodeOf(err))
	}
	defer journal.Close() //nolint:errcheck // Command cleanup has no recovery action.
	if journal.State() != StateStaged && journal.State() != StateDNSExported {
		return o.failureForJournal(ctx, CommandDNSExport, journal, CodeConflict)
	}
	if err := o.requireReleasedClaim(ctx, journal); err != nil {
		return o.failureForJournal(ctx, CommandDNSExport, journal, CodeOf(err))
	}
	set, candidate, plan, err := o.stagedDNSSet(ctx, journal)
	if err != nil {
		return o.failureForJournal(ctx, CommandDNSExport, journal, CodeOf(err))
	}
	defer set.Close()       //nolint:errcheck // Command cleanup has no recovery action.
	defer candidate.Close() //nolint:errcheck // Command cleanup has no recovery action.
	defer plan.Close()      //nolint:errcheck // Command cleanup has no recovery action.
	if _, err := ExportDNS(ctx, path, set, o.limits); err != nil {
		return o.failureForJournal(ctx, CommandDNSExport, journal, CodeOf(err))
	}
	if err := journal.RecordDNSExported(); err != nil {
		return o.failureForJournal(ctx, CommandDNSExport, journal, CodeOf(err))
	}
	if err := store.Save(ctx, journal); err != nil {
		return o.failureForJournal(ctx, CommandDNSExport, journal, CodeOf(err))
	}
	return o.success(ctx, CommandDNSExport, journal, false)
}

// Prove performs one fresh recursive-path proof and persists no reusable proof authority.
func (o *Onboarding) Prove(ctx context.Context, store *JournalStore) (OnboardingResult, error) {
	ctx, cancel, err := o.commandContext(ctx)
	if err != nil {
		return OnboardingResult{}, err
	}
	defer cancel()
	journal, err := o.loadForMutation(ctx, store)
	if err != nil {
		if journal != nil {
			defer journal.Close() //nolint:errcheck // Failure report cleanup has no recovery action.
			return o.failureForJournal(ctx, CommandProve, journal, CodeOf(err))
		}
		return o.failure(ctx, CommandProve, "", o.backendClass, CodeOf(err))
	}
	defer journal.Close() //nolint:errcheck // Command cleanup has no recovery action.
	if journal.State() != StateDNSExported && journal.State() != StateDNSProven {
		return o.failureForJournal(ctx, CommandProve, journal, CodeConflict)
	}
	if err := o.requireReleasedClaim(ctx, journal); err != nil {
		return o.failureForJournal(ctx, CommandProve, journal, CodeOf(err))
	}
	set, candidate, plan, err := o.stagedDNSSet(ctx, journal)
	if err != nil {
		return o.failureForJournal(ctx, CommandProve, journal, CodeOf(err))
	}
	defer set.Close()       //nolint:errcheck // Command cleanup has no recovery action.
	defer candidate.Close() //nolint:errcheck // Command cleanup has no recovery action.
	defer plan.Close()      //nolint:errcheck // Command cleanup has no recovery action.
	proof, err := o.proof.Prove(ctx, set)
	if err != nil {
		return o.failureForJournal(ctx, CommandProve, journal, CodeOf(err))
	}
	_ = proof.Close()
	if err := journal.RecordDNSProven(); err != nil {
		return o.failureForJournal(ctx, CommandProve, journal, CodeOf(err))
	}
	if err := store.Save(ctx, journal); err != nil {
		return o.failureForJournal(ctx, CommandProve, journal, CodeOf(err))
	}
	return o.success(ctx, CommandProve, journal, false)
}

// Activate repeats fresh DNS proof, saves write-ahead lineage, mutates, and independently reads back.
func (o *Onboarding) Activate(ctx context.Context, store *JournalStore) (OnboardingResult, error) {
	ctx, cancel, err := o.commandContext(ctx)
	if err != nil {
		return OnboardingResult{}, err
	}
	defer cancel()
	journal, err := o.loadForMutation(ctx, store)
	if err != nil {
		if journal != nil {
			defer journal.Close() //nolint:errcheck // Failure report cleanup has no recovery action.
			return o.failureForJournal(ctx, CommandActivate, journal, CodeOf(err))
		}
		return o.failure(ctx, CommandActivate, "", o.backendClass, CodeOf(err))
	}
	defer journal.Close() //nolint:errcheck // Command cleanup has no recovery action.
	if journal.State() == StateActivated {
		lock, lockErr := journal.AdministrationLock()
		if lockErr != nil || o.releaseTerminalClaim(ctx, lock, false) != nil {
			return o.failureForJournal(ctx, CommandActivate, journal, CodeReconcileRequired)
		}
		return o.success(ctx, CommandActivate, journal, true)
	}
	if journal.State() != StateDNSProven {
		return o.failureForJournal(ctx, CommandActivate, journal, CodeConflict)
	}
	if err := o.requireReleasedClaim(ctx, journal); err != nil {
		return o.failureForJournal(ctx, CommandActivate, journal, CodeOf(err))
	}
	return o.activateDNSProven(ctx, store, journal)
}

// activateDNSProven acquires exact authority, reproves DNS, and syncs activation write-ahead lineage.
func (o *Onboarding) activateDNSProven(
	ctx context.Context,
	store *JournalStore,
	journal *Journal,
) (OnboardingResult, error) {
	plan, err := journal.clonePlan()
	if err != nil {
		return o.failureForJournal(ctx, CommandActivate, journal, CodeOf(err))
	}
	defer plan.Close() //nolint:errcheck // Detached plan cleanup has no recovery action.
	lock, err := o.acquireOrConfirmClaim(ctx, journal)
	if err != nil {
		return o.failureForJournal(ctx, CommandActivate, journal, CodeOf(err))
	}
	set, candidate, info, err := o.stagedDNSSetWithPlan(ctx, journal, plan)
	if err != nil {
		return o.failClaimedMutation(ctx, store, journal, lock, err)
	}
	if info.Current {
		return o.failClaimedMutation(ctx, store, journal, lock, newError(CodeConflict))
	}
	defer set.Close()       //nolint:errcheck // Command cleanup has no recovery action.
	defer candidate.Close() //nolint:errcheck // Command cleanup has no recovery action.
	proof, err := o.proof.Prove(ctx, set)
	if err != nil {
		if releaseErr := o.releaseClaim(ctx, store, journal, lock); releaseErr != nil {
			return o.failureForJournal(ctx, CommandActivate, journal, CodeReconcileRequired)
		}
		return o.failureForJournal(ctx, CommandActivate, journal, CodeOf(err))
	}
	defer proof.Close() //nolint:errcheck // Proof is in-process only.
	now := o.clock().UTC().Truncate(time.Second)
	if err := journal.BeginActivating(proof, lock, now, plan.expectedCurrent == 0, plan.expectedCurrent != 0); err != nil {
		return o.failClaimedMutation(ctx, store, journal, lock, err)
	}
	if err := store.Save(ctx, journal); err != nil {
		return o.failClaimedMutation(ctx, store, journal, lock, newError(CodeReconcileRequired))
	}
	prepared, staged, _ := journal.Evidence()
	activation, err := datasourceadmin.NewActivation(
		lock, plan.operation, plan.expectedCurrent, plan.candidateGeneration, prepared, staged,
	)
	if err != nil {
		return o.failClaimedMutation(ctx, store, journal, lock, err)
	}
	mutationErr := o.backend.Activate(ctx, activation)
	return o.reconcileActivationReadback(ctx, store, journal, plan, lock, staged, mutationErr)
}

// reconcileActivationReadback classifies the exact post-mutation pointer and candidate evidence.
func (o *Onboarding) reconcileActivationReadback(
	ctx context.Context,
	store *JournalStore,
	journal *Journal,
	plan *Plan,
	lock datasourceadmin.AdministrationLock,
	staged datasourceadmin.StagedEvidence,
	mutationErr error,
) (OnboardingResult, error) {
	publication, observeErr := o.backend.Observe(
		ctx, plan.operation, plan.candidateGeneration, plan.expectedCurrent, o.generationLimits,
	)
	if observeErr != nil {
		return o.failureForJournal(ctx, CommandActivate, journal, o.persistReconciliation(ctx, store, journal))
	}
	observation, err := backendObservationFromPublication(publication)
	if err != nil {
		return o.failureForJournal(ctx, CommandActivate, journal, o.persistReconciliation(ctx, store, journal))
	}
	currentCandidate := publication.CurrentGeneration() == plan.candidateGeneration
	currentExpected := publication.CurrentGeneration() == plan.expectedCurrent
	if publication.State() == datasourceadmin.PublicationExactCommitted && (currentCandidate || currentExpected) {
		readback, info, inspectErr := o.inspectExact(
			ctx, journal, datasourceadmin.PublicationExactCommitted, currentCandidate,
		)
		if inspectErr != nil {
			return o.failureForJournal(ctx, CommandActivate, journal, o.persistReconciliation(ctx, store, journal))
		}
		defer readback.Close() //nolint:errcheck // Readback cleanup has no recovery action.
		validHistory := currentCandidate && (plan.expectedCurrent != 0) == publication.OldCurrentWasActive() ||
			currentExpected && (plan.expectedCurrent != 0 || !publication.OldCurrentWasActive())
		if info.Generation != plan.candidateGeneration || info.Current != currentCandidate ||
			!readback.Digest().Equal(staged.Digest()) || !validHistory {
			return o.failureForJournal(ctx, CommandActivate, journal, o.persistReconciliation(ctx, store, journal))
		}
	}
	reconciled, err := Reconcile(journal, o.authority, observation)
	if err != nil {
		return o.failureForJournal(ctx, CommandActivate, journal, CodeReconcileRequired)
	}
	if reconciled.Outcome != ReconcileUnchanged {
		if err := store.Save(ctx, journal); err != nil {
			return o.failureForJournal(ctx, CommandActivate, journal, CodeOf(err))
		}
	}
	if reconciled.State != StateActivated {
		released := false
		if reconciled.ReleaseClaim {
			if releaseErr := o.releaseClaim(ctx, store, journal, lock); releaseErr != nil {
				return o.failureForJournal(ctx, CommandActivate, journal, CodeReconcileRequired)
			}
			released = true
		}
		failure := CodeReconcileRequired
		if reconciled.State == StateConflict && released {
			failure = CodeConflict
		} else if reconciled.ReleaseClaim && mutationErr != nil {
			failure = mapDatasourceFailure(mutationErr)
		}
		return o.failureForJournal(ctx, CommandActivate, journal, failure)
	}
	if err := o.releaseTerminalClaim(ctx, lock, false); err != nil {
		return o.failureForJournal(ctx, CommandActivate, journal, CodeReconcileRequired)
	}
	return o.success(ctx, CommandActivate, journal, true)
}

// Status performs read-only journal, publication, and administration-lock observation.
func (o *Onboarding) Status(ctx context.Context, store *JournalStore) (StatusResult, error) {
	ctx, cancel, err := o.commandContext(ctx)
	if err != nil {
		return StatusResult{}, err
	}
	defer cancel()
	receipt, journal, exists, err := store.LoadOperation(ctx)
	if err != nil || !exists {
		return StatusResult{}, newError(nonNoneCode(err, CodeConflict))
	}
	if receipt != nil {
		defer receipt.Close() //nolint:errcheck // Read-only receipt cleanup has no recovery action.
		if !receipt.MatchesAuthority(o.backendClass, o.authority) {
			return StatusResult{}, newError(CodeConflict)
		}
		operation, revision, _, inputErr := receipt.reconciliationInput()
		if inputErr != nil {
			return StatusResult{}, inputErr
		}
		observed, observeErr := o.backend.ObserveAdministrationLock(ctx)
		relation := classifyReceiptLock(operation, revision, observed, observeErr)
		_, failure := receipt.ResultState()
		status := StatusResult{
			PlanComplete: false, ReceiptPresent: true, ReceiptPhase: receipt.Phase(),
			LockRelation: relation, Failure: failure,
		}
		o.observe(ctx, OnboardingObservation{
			Command: CommandStatus, Backend: o.backendClass, Result: OnboardingResultSuccess,
			Failure: failure, Receipt: receipt.Phase(),
		})
		return status, nil
	}
	if journal == nil {
		return StatusResult{}, newError(CodeConflict)
	}
	defer journal.Close() //nolint:errcheck // Read-only command cleanup has no recovery action.
	plan, err := journal.clonePlan()
	if err != nil {
		return StatusResult{}, err
	}
	defer plan.Close() //nolint:errcheck // Detached plan cleanup has no recovery action.
	publication, err := o.backend.Observe(
		ctx, plan.operation, plan.candidateGeneration, plan.expectedCurrent, o.generationLimits,
	)
	if err != nil {
		return StatusResult{}, newError(CodeUnavailable)
	}
	lock, err := journal.AdministrationLock()
	if err != nil {
		return StatusResult{}, newError(CodeConflict)
	}
	lockObservation, err := o.backend.ObserveAdministrationLock(ctx)
	if err != nil {
		return StatusResult{}, newError(CodeUnavailable)
	}
	if !lockObservation.Valid() {
		return StatusResult{}, newError(CodeConflict)
	}
	lockRelation := classifyReceiptLock(lock.Owner(), lock.Revision(), lockObservation, nil)
	if lockRelation != LockRelationOwnedExact && lockRelation != LockRelationOwnerlessExact &&
		lockRelation != LockRelationReleasedNext {
		return StatusResult{}, newError(CodeReconcileRequired)
	}
	observation, err := backendObservationFromPublication(publication)
	if err != nil {
		return StatusResult{}, err
	}
	status, err := ObserveStatus(journal, o.authority, observation)
	if err == nil {
		o.observe(ctx, OnboardingObservation{
			Command: CommandStatus, State: status.State, Backend: plan.backend, Result: OnboardingResultSuccess,
			Failure: status.Failure,
		})
	}
	return status, err
}

// classifyReceiptLock maps exact receipt authority evidence to one bounded relationship.
func classifyReceiptLock(
	operation datasourceadmin.OperationBinding,
	revision uint64,
	observed datasourceadmin.AdministrationLockObservation,
	err error,
) LockRelation {
	if err != nil || !observed.Valid() {
		return LockRelationUnavailable
	}
	if observed.Claimed() {
		if observed.Revision() == revision && observed.Owner().Equal(operation) {
			return LockRelationOwnedExact
		}
		return LockRelationOther
	}
	if observed.Revision() == revision {
		return LockRelationOwnerlessExact
	}
	if revision != ^uint64(0) && observed.Revision() == revision+1 {
		return LockRelationReleasedNext
	}
	return LockRelationOther
}

// Reconcile updates only journal knowledge and same-operation lock metadata from exact observations.
func (o *Onboarding) Reconcile(ctx context.Context, store *JournalStore) (OnboardingResult, error) {
	ctx, cancel, err := o.commandContext(ctx)
	if err != nil {
		return OnboardingResult{}, err
	}
	defer cancel()
	receipt, journal, exists, err := store.LoadOperation(ctx)
	if err != nil || !exists {
		return o.failure(ctx, CommandReconcile, "", o.backendClass, nonNoneCode(err, CodeConflict))
	}
	if receipt != nil {
		defer receipt.Close() //nolint:errcheck // Receipt reconciliation owns durable truth.
		return o.reconcilePlanningReceipt(ctx, store, receipt)
	}
	if journal == nil {
		return o.failure(ctx, CommandReconcile, "", o.backendClass, CodeConflict)
	}
	defer journal.Close() //nolint:errcheck // Command cleanup has no recovery action.
	plan, err := journal.clonePlan()
	if err != nil {
		return o.failureForJournal(ctx, CommandReconcile, journal, CodeOf(err))
	}
	defer plan.Close() //nolint:errcheck // Detached plan cleanup has no recovery action.
	publication, err := o.backend.Observe(
		ctx, plan.operation, plan.candidateGeneration, plan.expectedCurrent, o.generationLimits,
	)
	if err != nil {
		return o.failureForJournal(ctx, CommandReconcile, journal, CodeUnavailable)
	}
	observation, err := backendObservationFromPublication(publication)
	if err != nil {
		return o.failureForJournal(ctx, CommandReconcile, journal, CodeOf(err))
	}
	result, err := Reconcile(journal, o.authority, observation)
	if err != nil {
		return o.failureForJournal(ctx, CommandReconcile, journal, CodeOf(err))
	}
	if result.Outcome != ReconcileUnchanged {
		if err := store.Save(ctx, journal); err != nil {
			return o.failureForJournal(ctx, CommandReconcile, journal, CodeOf(err))
		}
	}
	if journal.State() == StateReconcileRequired {
		return o.failureForJournal(ctx, CommandReconcile, journal, CodeReconcileRequired)
	}
	if journal.State() == StateActivated || journal.State() == StateConflict {
		lock, lockErr := journal.AdministrationLock()
		if lockErr != nil || o.releaseTerminalClaim(ctx, lock, journal.State() == StateConflict) != nil {
			return o.failureForJournal(ctx, CommandReconcile, journal, CodeReconcileRequired)
		}
	} else if safeReconcileRelease(journal.State(), plan, observation, result) {
		if err := o.settleReleasedClaim(ctx, store, journal); err != nil {
			return o.failureForJournal(ctx, CommandReconcile, journal, CodeOf(err))
		}
	}
	return o.reconcileSuccess(ctx, journal, observation, journal.State() == StateActivated)
}

// safeReconcileRelease admits lock cleanup only after exact nonmutating publication proof.
func safeReconcileRelease(
	state OperationState,
	plan *Plan,
	observation BackendObservation,
	result ReconcileResult,
) bool {
	if plan == nil || result.ReleaseClaim {
		return result.ReleaseClaim
	}
	if observation.currentGeneration != plan.expectedCurrent {
		return false
	}
	switch state {
	case StatePlanned, StatePreparing, StateFailed:
		return observation.candidateClass == CandidateAbsent
	case StateStaged, StateDNSExported, StateDNSProven:
		return exactCandidateMatchesPlan(plan, observation, CandidateExactCommitted)
	case StateAborted:
		return observation.candidateClass == CandidateAbsent ||
			exactCandidateMatchesPlan(plan, observation, CandidateExactStaging)
	default:
		return false
	}
}

// exactCandidateMatchesPlan checks protected operation ownership for release policy.
func exactCandidateMatchesPlan(
	plan *Plan,
	observation BackendObservation,
	want CandidateObservationClass,
) bool {
	return plan != nil && observation.candidateClass == want &&
		observation.operation.Equal(plan.operation) && observation.staged.Digest().Valid()
}

// Abort records only a proven noncurrent non-destructive terminal stop and never deletes backend data.
func (o *Onboarding) Abort(ctx context.Context, store *JournalStore) (OnboardingResult, error) {
	ctx, cancel, err := o.commandContext(ctx)
	if err != nil {
		return OnboardingResult{}, err
	}
	defer cancel()
	receipt, journal, exists, err := store.LoadOperation(ctx)
	if err != nil || !exists {
		return o.failure(ctx, CommandAbort, "", o.backendClass, nonNoneCode(err, CodeConflict))
	}
	if receipt != nil {
		defer receipt.Close() //nolint:errcheck // Receipt abort owns durable truth.
		return o.abortPlanningReceipt(ctx, store, receipt)
	}
	if journal == nil {
		return o.failure(ctx, CommandAbort, "", o.backendClass, CodeConflict)
	}
	defer journal.Close() //nolint:errcheck // Command cleanup has no recovery action.
	plan, err := journal.clonePlan()
	if err != nil {
		return o.failureForJournal(ctx, CommandAbort, journal, CodeOf(err))
	}
	defer plan.Close() //nolint:errcheck // Detached plan cleanup has no recovery action.
	if journal.State() == StateReconcileRequired || journal.State() == StateConflict {
		return o.failureForJournal(ctx, CommandAbort, journal, CodeReconcileRequired)
	}
	if journal.State() == StateAborted {
		return o.abortTerminalJournal(ctx, journal)
	}
	return o.abortJournalPlan(ctx, store, journal, plan)
}

// abortJournalPlan proves noncurrent candidate and exact lock evidence before recording abort.
func (o *Onboarding) abortJournalPlan(
	ctx context.Context,
	store *JournalStore,
	journal *Journal,
	plan *Plan,
) (OnboardingResult, error) {
	publication, err := o.backend.Observe(
		ctx, plan.operation, plan.candidateGeneration, plan.expectedCurrent, o.generationLimits,
	)
	if err != nil {
		return o.failureForJournal(ctx, CommandAbort, journal, CodeUnavailable)
	}
	observation, err := backendObservationFromPublication(publication)
	if err != nil {
		return o.failureForJournal(ctx, CommandAbort, journal, CodeOf(err))
	}
	if observation.candidateClass == CandidatePartial ||
		observation.candidateClass == CandidateMismatch || observation.candidateClass == CandidateUnknown {
		return o.failureForJournal(ctx, CommandAbort, journal, o.persistReconciliation(ctx, store, journal))
	}
	if publication.CurrentGeneration() == plan.candidateGeneration {
		return o.failureForJournal(ctx, CommandAbort, journal, o.persistReconciliation(ctx, store, journal))
	}
	if publication.CurrentGeneration() != plan.expectedCurrent {
		if err := journal.RecordConflict(); err != nil {
			return o.failureForJournal(ctx, CommandAbort, journal, CodeConflict)
		}
		if err := store.Save(ctx, journal); err != nil {
			return o.failureForJournal(ctx, CommandAbort, journal, CodeOf(err))
		}
		return o.failureForJournal(ctx, CommandAbort, journal, CodeReconcileRequired)
	}
	allowed := observation.candidateClass == CandidateAbsent &&
		(journal.State() == StatePlanned || journal.State() == StatePreparing || journal.State() == StatePrepared) ||
		observation.candidateClass == CandidateExactStaging && journal.State() == StatePrepared
	if !allowed {
		return o.failureForJournal(ctx, CommandAbort, journal, o.persistReconciliation(ctx, store, journal))
	}
	lock, err := journal.AdministrationLock()
	if err != nil {
		return o.failureForJournal(ctx, CommandAbort, journal, CodeOf(err))
	}
	lockObservation, err := o.backend.ObserveAdministrationLock(ctx)
	if err != nil {
		return o.failureForJournal(ctx, CommandAbort, journal, CodeUnavailable)
	}
	if !lockObservation.Valid() {
		return o.failureForJournal(ctx, CommandAbort, journal, CodeConflict)
	}
	claimed := lockObservation.Claimed() && lockObservation.Revision() == lock.Revision() &&
		lockObservation.Owner().Equal(lock.Owner())
	ownerless := !lockObservation.Claimed() && lockObservation.Revision() == lock.Revision()
	if !claimed && !ownerless {
		return o.failureForJournal(ctx, CommandAbort, journal, CodeReconcileRequired)
	}
	if err := journal.RecordAborted(observation.candidateClass, observation.staged); err != nil {
		return o.failureForJournal(ctx, CommandAbort, journal, CodeOf(err))
	}
	if err := store.Save(ctx, journal); err != nil {
		return o.failureForJournal(ctx, CommandAbort, journal, CodeOf(err))
	}
	if claimed {
		if err := o.releaseClaim(ctx, store, journal, lock); err != nil {
			return o.failureForJournal(ctx, CommandAbort, journal, CodeOf(err))
		}
	}
	return o.success(ctx, CommandAbort, journal, false)
}

// abortTerminalJournal proves an aborted journal has no outstanding exact cleanup without mutating it.
func (o *Onboarding) abortTerminalJournal(
	ctx context.Context,
	journal *Journal,
) (OnboardingResult, error) {
	lock, err := journal.AdministrationLock()
	if err != nil {
		return o.failureForJournal(ctx, CommandAbort, journal, CodeReconcileRequired)
	}
	observed, err := o.backend.ObserveAdministrationLock(ctx)
	if err != nil || !observed.Valid() || observed.Claimed() || observed.Revision() != lock.Revision() {
		return o.failureForJournal(ctx, CommandAbort, journal, CodeReconcileRequired)
	}
	return o.success(ctx, CommandAbort, journal, false)
}

// reconcilePlanningReceipt resolves only exact receipt lock ownership and release evidence.
func (o *Onboarding) reconcilePlanningReceipt(
	ctx context.Context,
	store *JournalStore,
	receipt *PlanningReceipt,
) (OnboardingResult, error) {
	if !receipt.MatchesAuthority(o.backendClass, o.authority) {
		return o.failureReceipt(ctx, CommandReconcile, receipt, CodeConflict)
	}
	operation, revision, state, err := receipt.reconciliationInput()
	if err != nil {
		return o.failureReceipt(ctx, CommandReconcile, receipt, CodeOf(err))
	}
	observed, err := o.backend.ObserveAdministrationLock(ctx)
	relation := classifyReceiptLock(operation, revision, observed, err)
	if state == planningReceiptClosed {
		if relation == LockRelationOwnerlessExact {
			return o.successReceipt(ctx, CommandReconcile, receipt)
		}
		return o.failureReceipt(ctx, CommandReconcile, receipt, CodeReconcileRequired)
	}
	switch relation {
	case LockRelationUnavailable, LockRelationOther:
		return o.reconcileUncertainReceipt(ctx, store, receipt, state)
	case LockRelationOwnerlessExact:
		return o.reconcileOwnerlessReceipt(ctx, store, receipt, state)
	case LockRelationOwnedExact:
		return o.reconcileOwnedReceipt(ctx, store, receipt, operation, revision, state)
	case LockRelationReleasedNext:
		return o.reconcileReleasedReceipt(ctx, store, receipt, observed.Revision(), state)
	default:
		return o.failureReceipt(ctx, CommandReconcile, receipt, CodeReconcileRequired)
	}
}

// reconcileUncertainReceipt retains cleanup lineage or records non-cleanup ambiguity.
func (o *Onboarding) reconcileUncertainReceipt(
	ctx context.Context,
	store *JournalStore,
	receipt *PlanningReceipt,
	state planningReceiptState,
) (OnboardingResult, error) {
	if state != planningReceiptReleaseRequired && state != planningReceiptUnresolved {
		saved, err := o.persistUnresolvedReceipt(ctx, store, receipt)
		authoritative := saved.receipt
		if authoritative != nil && authoritative != receipt {
			defer authoritative.Close() //nolint:errcheck // Fresh ambiguity readback cleanup has no recovery action.
		}
		receipt = authoritative
		if err != nil || !saved.mayContinue() {
			return o.failureReceipt(ctx, CommandReconcile, receipt, CodeReconcileRequired)
		}
	}
	return o.failureReceipt(ctx, CommandReconcile, receipt, CodeReconcileRequired)
}

// reconcileOwnerlessReceipt closes only claim-pending or typed unresolved exact-R evidence.
func (o *Onboarding) reconcileOwnerlessReceipt(
	ctx context.Context,
	store *JournalStore,
	receipt *PlanningReceipt,
	state planningReceiptState,
) (OnboardingResult, error) {
	if state == planningReceiptClaimPending {
		return o.successReceipt(ctx, CommandReconcile, receipt)
	}
	if state != planningReceiptUnresolved || receipt.recordClosedOwnerlessRecovery() != nil {
		return o.failureReceipt(ctx, CommandReconcile, receipt, CodeReconcileRequired)
	}
	return o.saveClosedReceiptResult(ctx, store, receipt)
}

// reconcileOwnedReceipt syncs cleanup authority before the only permitted exact Release.
func (o *Onboarding) reconcileOwnedReceipt(
	ctx context.Context,
	store *JournalStore,
	receipt *PlanningReceipt,
	operation datasourceadmin.OperationBinding,
	revision uint64,
	state planningReceiptState,
) (OnboardingResult, error) {
	if state != planningReceiptReleaseRequired {
		if receipt.RecordReleaseRequired() != nil {
			return o.failureReceipt(ctx, CommandReconcile, receipt, CodeReconcileRequired)
		}
		saved, err := o.savePlanningReceipt(ctx, store, receipt)
		authoritative := saved.receipt
		if authoritative != nil && authoritative != receipt {
			defer authoritative.Close() //nolint:errcheck // Fresh cleanup readback has no recovery action.
		}
		receipt = authoritative
		if err != nil || !saved.mayContinue() {
			return o.failureReceipt(ctx, CommandReconcile, receipt, CodeReconcileRequired)
		}
	}
	lock, err := datasourceadmin.NewAdministrationLock(operation, revision)
	if err != nil {
		return o.failureReceipt(ctx, CommandReconcile, receipt, CodeReconcileRequired)
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), o.limits.BackendDeadline)
	next, releaseErr := o.backend.Release(cleanup, lock)
	cancel()
	if releaseErr != nil || revision == ^uint64(0) || next != revision+1 ||
		receipt.RecordAdministrationRelease(next) != nil || receipt.RecordClosed() != nil {
		return o.failureReceipt(ctx, CommandReconcile, receipt, CodeReconcileRequired)
	}
	return o.saveClosedReceiptResult(ctx, store, receipt)
}

// reconcileReleasedReceipt accepts ownerless R+1 only from durable release-required lineage.
func (o *Onboarding) reconcileReleasedReceipt(
	ctx context.Context,
	store *JournalStore,
	receipt *PlanningReceipt,
	next uint64,
	state planningReceiptState,
) (OnboardingResult, error) {
	if state != planningReceiptReleaseRequired || receipt.RecordAdministrationRelease(next) != nil ||
		receipt.RecordClosed() != nil {
		return o.failureReceipt(ctx, CommandReconcile, receipt, CodeReconcileRequired)
	}
	return o.saveClosedReceiptResult(ctx, store, receipt)
}

// saveClosedReceiptResult syncs a closed tombstone and reports bounded success.
func (o *Onboarding) saveClosedReceiptResult(
	ctx context.Context,
	store *JournalStore,
	receipt *PlanningReceipt,
) (OnboardingResult, error) {
	saved, err := o.savePlanningReceipt(ctx, store, receipt)
	authoritative := saved.receipt
	if authoritative != nil && authoritative != receipt {
		defer authoritative.Close() //nolint:errcheck // Fresh closed readback cleanup has no recovery action.
	}
	receipt = authoritative
	if err != nil || !saved.mayContinue() {
		return o.failureReceipt(ctx, CommandReconcile, receipt, CodeReconcileRequired)
	}
	return o.successReceipt(ctx, CommandReconcile, receipt)
}

// abortPlanningReceipt durably stops an exact open pre-journal operation without deletion.
func (o *Onboarding) abortPlanningReceipt(
	ctx context.Context,
	store *JournalStore,
	receipt *PlanningReceipt,
) (OnboardingResult, error) {
	if !receipt.MatchesAuthority(o.backendClass, o.authority) {
		return o.failureReceipt(ctx, CommandAbort, receipt, CodeConflict)
	}
	operation, revision, state, err := receipt.reconciliationInput()
	if err != nil {
		return o.failureReceipt(ctx, CommandAbort, receipt, CodeOf(err))
	}
	if state == planningReceiptReleaseRequired || state == planningReceiptUnresolved {
		return o.failureReceipt(ctx, CommandAbort, receipt, CodeReconcileRequired)
	}
	observed, err := o.backend.ObserveAdministrationLock(ctx)
	relation := classifyReceiptLock(operation, revision, observed, err)
	if state == planningReceiptClosed {
		if relation == LockRelationOwnerlessExact {
			return o.successReceipt(ctx, CommandAbort, receipt)
		}
		return o.failureReceipt(ctx, CommandAbort, receipt, CodeReconcileRequired)
	}
	if relation == LockRelationUnavailable || relation == LockRelationOther ||
		relation == LockRelationReleasedNext || (state == planningReceiptAllocating && relation == LockRelationOwnerlessExact) {
		saved, persistErr := o.persistUnresolvedReceipt(ctx, store, receipt)
		authoritative := saved.receipt
		if authoritative != nil && authoritative != receipt {
			defer authoritative.Close() //nolint:errcheck // Fresh ambiguity readback cleanup has no recovery action.
		}
		receipt = authoritative
		if persistErr != nil || !saved.mayContinue() {
			return o.failureReceipt(ctx, CommandAbort, receipt, CodeReconcileRequired)
		}
		return o.failureReceipt(ctx, CommandAbort, receipt, CodeReconcileRequired)
	}
	if relation == LockRelationOwnedExact {
		if receipt.RecordReleaseRequired() != nil {
			return o.failureReceipt(ctx, CommandAbort, receipt, CodeReconcileRequired)
		}
		saved, saveErr := o.savePlanningReceipt(ctx, store, receipt)
		authoritative := saved.receipt
		if authoritative != nil && authoritative != receipt {
			defer authoritative.Close() //nolint:errcheck // Fresh ambiguity readback cleanup has no recovery action.
		}
		receipt = authoritative
		if saveErr != nil || !saved.mayContinue() {
			return o.failureReceipt(ctx, CommandAbort, receipt, CodeReconcileRequired)
		}
		return o.failureReceipt(ctx, CommandAbort, receipt, CodeReconcileRequired)
	}
	if state != planningReceiptClaimPending || relation != LockRelationOwnerlessExact || receipt.RecordClosed() != nil {
		return o.failureReceipt(ctx, CommandAbort, receipt, CodeReconcileRequired)
	}
	saved, saveErr := o.savePlanningReceipt(ctx, store, receipt)
	authoritative := saved.receipt
	if authoritative != nil && authoritative != receipt {
		defer authoritative.Close() //nolint:errcheck // Fresh ambiguity readback cleanup has no recovery action.
	}
	receipt = authoritative
	if saveErr != nil || !saved.mayContinue() {
		return o.failureReceipt(ctx, CommandAbort, receipt, CodeReconcileRequired)
	}
	return o.successReceipt(ctx, CommandAbort, receipt)
}

// successReceipt constructs one bounded receipt command result.
func (o *Onboarding) successReceipt(
	ctx context.Context,
	command Command,
	receipt *PlanningReceipt,
) (OnboardingResult, error) {
	_, failure := receipt.ResultState()
	phase := receipt.Phase()
	result := OnboardingResult{
		Result: OnboardingResultSuccess, Failure: failure, PlanComplete: false,
		ReceiptPresent: true, ReceiptPhase: phase,
	}
	o.observe(ctx, OnboardingObservation{
		Command: command, Backend: o.backendClass, Result: result.Result, Failure: failure, Receipt: phase,
	})
	return result, nil
}

// loadForMutation loads, observes, and reconciles one normal command without bypassing explicit recovery.
func (o *Onboarding) loadForMutation(
	ctx context.Context,
	store *JournalStore,
) (*Journal, error) {
	journal, err := o.loadExisting(ctx, store)
	if err != nil {
		return nil, err
	}
	if journal.State() == StateReconcileRequired {
		return journal, newError(CodeReconcileRequired)
	}
	plan, err := journal.clonePlan()
	if err != nil {
		return journal, err
	}
	defer plan.Close() //nolint:errcheck // Detached plan cleanup has no recovery action.
	publication, err := o.backend.Observe(
		ctx, plan.operation, plan.candidateGeneration, plan.expectedCurrent, o.generationLimits,
	)
	if err != nil {
		return journal, newError(CodeUnavailable)
	}
	observation, err := backendObservationFromPublication(publication)
	if err != nil {
		return journal, err
	}
	result, err := Reconcile(journal, o.authority, observation)
	if err != nil {
		return journal, err
	}
	if result.Outcome != ReconcileUnchanged {
		if err := store.Save(ctx, journal); err != nil {
			return journal, err
		}
	}
	if result.ReleaseClaim {
		if err := o.requireReleasedClaim(ctx, journal); err != nil {
			failure := failureWithState(CodeReconcileRequired, journal.State())
			return journal, newError(failure)
		}
	}
	if journal.State() == StateConflict || journal.State() == StateFailed || journal.State() == StateAborted {
		failure := journalFailureCode(journal)
		if journal.State() == StateConflict {
			failure = CodeReconcileRequired
		}
		return journal, newError(failure)
	}
	return journal, nil
}

// loadExisting loads one exact persisted journal under the caller-owned stable store lock.
func (o *Onboarding) loadExisting(ctx context.Context, store *JournalStore) (*Journal, error) {
	if o == nil || ctx == nil || ctx.Err() != nil || store == nil {
		return nil, newError(CodeConflict)
	}
	journal, exists, err := store.Load(ctx)
	if err != nil {
		if journal != nil {
			_ = journal.Close()
		}
		return nil, newError(CodeOf(err))
	}
	if !exists || journal == nil {
		if journal != nil {
			_ = journal.Close()
		}
		return nil, newError(CodeConflict)
	}
	plan, planErr := journal.clonePlan()
	if planErr != nil || !plan.MatchesCoordinator(o.backendClass, o.authority) {
		_ = plan.Close()
		_ = journal.Close()
		return nil, newError(CodeConflict)
	}
	_ = plan.Close()
	return journal, nil
}

// requireFreshPlan revalidates current, ceiling, generation, and every allocated identity under the exact lock.
func (o *Onboarding) requireFreshPlan(ctx context.Context, journal *Journal) error {
	plan, err := journal.clonePlan()
	if err != nil {
		return err
	}
	defer plan.Close() //nolint:errcheck // Detached plan cleanup has no recovery action.
	return o.verifyFreshPlan(ctx, plan)
}

// verifyFreshPlan validates one exact plan against the currently bound backend authority.
func (o *Onboarding) verifyFreshPlan(ctx context.Context, plan *Plan) error {
	if plan == nil || !plan.MatchesCoordinator(o.backendClass, o.authority) {
		return newError(CodeConflict)
	}
	lock := lockFromPlan(plan)
	if !lock.ValidFor(plan.operation) {
		return newError(CodeConflict)
	}
	if err := o.requireClaimed(ctx, lock); err != nil {
		return err
	}
	collisions, err := o.backend.ReadCollisionInventory(ctx, lock, o.generationLimits)
	if err != nil || collisions == nil {
		if collisions != nil {
			_ = collisions.Close()
		}
		return newError(CodeUnavailable)
	}
	defer collisions.Close() //nolint:errcheck // Detached collision view cleanup has no recovery action.
	return plan.VerifyFresh(ctx, lock, collisions, o.authority)
}

// lockFromPlan reconstructs the protected exact administration claim bound into a detached plan.
func lockFromPlan(plan *Plan) datasourceadmin.AdministrationLock {
	if plan == nil {
		return datasourceadmin.AdministrationLock{}
	}
	lock, _ := datasourceadmin.NewAdministrationLock(plan.operation, plan.lockRevision)
	return lock
}

// buildCandidate clones current protected content and appends one generated domain.
func (o *Onboarding) buildCandidate(
	ctx context.Context,
	journal *Journal,
	keys *KeySet,
) (*datasourceadmin.PublicationEnvelope, error) {
	plan, err := journal.clonePlan()
	if err != nil {
		return nil, err
	}
	defer plan.Close() //nolint:errcheck // Detached plan cleanup has no recovery action.
	addition, err := keys.DomainAddition(ctx)
	if err != nil {
		return nil, err
	}
	defer addition.Close() //nolint:errcheck // Candidate owns detached key bytes.
	var snapshot *datasourceadmin.Snapshot
	if plan.expectedCurrent == 0 {
		snapshot, err = addition.NewSnapshot(datasourceadmin.SchemaVersionV3, plan.candidateGeneration)
	} else {
		current, readErr := o.backend.ReadCurrent(ctx, o.generationLimits)
		if readErr != nil {
			_ = current.Close()
			return nil, newError(CodeUnavailable)
		}
		if current == nil || current.Generation() != plan.expectedCurrent {
			_ = current.Close()
			return nil, newError(CodeConflict)
		}
		defer current.Close() //nolint:errcheck // Candidate owns detached cloned content.
		if err := plan.VerifyCurrentSnapshot(ctx, current, o.authority); err != nil {
			return nil, newError(CodeConflict)
		}
		if err := o.requireClaimed(ctx, lockFromPlan(plan)); err != nil {
			return nil, err
		}
		snapshot, err = current.AddDomain(datasourceadmin.SchemaVersionV3, plan.candidateGeneration, addition)
	}
	if err != nil || snapshot == nil {
		_ = snapshot.Close()
		return nil, newError(CodeUnavailable)
	}
	operationID := ""
	if err := plan.operation.WithValue(ctx, func(value string) error {
		operationID = value
		return nil
	}); err != nil {
		_ = snapshot.Close()
		return nil, err
	}
	content, err := datasourceadmin.NewCandidateContent(snapshot)
	if err != nil {
		_ = snapshot.Close()
		return nil, newError(CodeUnavailable)
	}
	candidate, err := datasourceadmin.NewPublicationEnvelope(operationID, content)
	if err != nil {
		_ = content.Close()
		return nil, newError(CodeUnavailable)
	}
	return candidate, nil
}

// inspectExact independently combines publication observation and canonical candidate inspection.
func (o *Onboarding) inspectExact(
	ctx context.Context,
	journal *Journal,
	want datasourceadmin.PublicationState,
	wantCurrent bool,
) (*datasourceadmin.PublicationEnvelope, datasourceadmin.GenerationInfo, error) {
	plan, err := journal.clonePlan()
	if err != nil {
		return nil, datasourceadmin.GenerationInfo{}, err
	}
	defer plan.Close() //nolint:errcheck // Detached plan cleanup has no recovery action.
	publication, err := o.backend.Observe(
		ctx, plan.operation, plan.candidateGeneration, plan.expectedCurrent, o.generationLimits,
	)
	if err != nil {
		return nil, datasourceadmin.GenerationInfo{}, newError(CodeUnavailable)
	}
	if !publication.Valid() || publication.State() != want ||
		publication.CurrentGeneration() != mapCurrentGeneration(plan, wantCurrent) ||
		!publication.Operation().Equal(plan.operation) {
		return nil, datasourceadmin.GenerationInfo{}, newError(CodeConflict)
	}
	candidate, info, err := o.backend.Inspect(
		ctx, plan.operation, plan.candidateGeneration, plan.expectedCurrent, o.generationLimits,
	)
	if err != nil {
		_ = candidate.Close()
		return nil, datasourceadmin.GenerationInfo{}, newError(CodeUnavailable)
	}
	if candidate == nil {
		return nil, datasourceadmin.GenerationInfo{}, newError(CodeConflict)
	}
	wantState := datasourceadmin.StateCommitted
	if want == datasourceadmin.PublicationExactStaging {
		wantState = datasourceadmin.StateStaging
	}
	if info.Generation != plan.candidateGeneration || info.Current != wantCurrent || info.State != wantState ||
		!info.Operation.Equal(plan.operation) || candidate.Generation() != plan.candidateGeneration ||
		!candidate.Binding().Equal(plan.operation) || !candidate.Digest().Equal(publication.Staged().Digest()) {
		_ = candidate.Close()
		return nil, datasourceadmin.GenerationInfo{}, newError(CodeConflict)
	}
	return candidate, info, nil
}

// mapCurrentGeneration returns the exact current value expected for candidate readback.
func mapCurrentGeneration(plan *Plan, candidateCurrent bool) uint64 {
	if candidateCurrent {
		return plan.candidateGeneration
	}
	return plan.expectedCurrent
}

// stagedDNSSet reconstructs exact committed DNS inputs from the journal's plan.
func (o *Onboarding) stagedDNSSet(
	ctx context.Context,
	journal *Journal,
) (*StagedDNSSet, *datasourceadmin.PublicationEnvelope, *Plan, error) {
	plan, err := journal.clonePlan()
	if err != nil {
		return nil, nil, nil, err
	}
	set, candidate, _, err := o.stagedDNSSetWithPlan(ctx, journal, plan)
	if err != nil {
		_ = plan.Close()
		return nil, nil, nil, err
	}
	return set, candidate, plan, nil
}

// stagedDNSSetWithPlan binds exact committed readback to one already detached plan.
func (o *Onboarding) stagedDNSSetWithPlan(
	ctx context.Context,
	journal *Journal,
	plan *Plan,
) (*StagedDNSSet, *datasourceadmin.PublicationEnvelope, datasourceadmin.GenerationInfo, error) {
	candidate, info, err := o.inspectExact(ctx, journal, datasourceadmin.PublicationExactCommitted, false)
	if err != nil {
		return nil, nil, datasourceadmin.GenerationInfo{}, err
	}
	_, staged, err := journal.Evidence()
	if err != nil {
		_ = candidate.Close()
		return nil, nil, datasourceadmin.GenerationInfo{}, err
	}
	set, err := NewStagedDNSSet(ctx, plan, candidate, info, staged, o.limits)
	if err != nil {
		_ = candidate.Close()
		return nil, nil, datasourceadmin.GenerationInfo{}, err
	}
	return set, candidate, info, nil
}

// requireClaimed proves the backend lock still has the exact persisted owner and revision.
func (o *Onboarding) requireClaimed(ctx context.Context, lock datasourceadmin.AdministrationLock) error {
	observed, err := o.backend.ObserveAdministrationLock(ctx)
	if err != nil {
		return newError(CodeUnavailable)
	}
	if !observed.Valid() || !observed.Claimed() || observed.Revision() != lock.Revision() ||
		!observed.Owner().Equal(lock.Owner()) {
		return newError(CodeConflict)
	}
	return nil
}

// acquireOrConfirmClaim confirms a retained claim or claims the exact ownerless persisted revision.
func (o *Onboarding) acquireOrConfirmClaim(
	ctx context.Context,
	journal *Journal,
) (datasourceadmin.AdministrationLock, error) {
	lock, err := journal.AdministrationLock()
	if err != nil {
		return datasourceadmin.AdministrationLock{}, err
	}
	observed, err := o.backend.ObserveAdministrationLock(ctx)
	if err != nil {
		return datasourceadmin.AdministrationLock{}, newError(CodeUnavailable)
	}
	if !observed.Valid() {
		return datasourceadmin.AdministrationLock{}, newError(CodeConflict)
	}
	if observed.Claimed() {
		if observed.Revision() == lock.Revision() && observed.Owner().Equal(lock.Owner()) {
			return lock, nil
		}
		return datasourceadmin.AdministrationLock{}, newError(CodeConflict)
	}
	if observed.Revision() != lock.Revision() {
		return datasourceadmin.AdministrationLock{}, newError(CodeConflict)
	}
	claimed, claimErr := o.backend.Claim(ctx, lock.Owner(), lock.Revision())
	if claimErr == nil && claimed.ValidFor(lock.Owner()) && claimed.Revision() == lock.Revision() {
		return claimed, nil
	}
	if claimErr == nil {
		return datasourceadmin.AdministrationLock{}, newError(CodeConflict)
	}
	confirmed, observeErr := o.backend.ObserveAdministrationLock(ctx)
	if observeErr == nil && confirmed.Valid() && confirmed.Claimed() &&
		confirmed.Revision() == lock.Revision() && confirmed.Owner().Equal(lock.Owner()) {
		return lock, nil
	}
	return datasourceadmin.AdministrationLock{}, mapDatasourceError(claimErr)
}

// requireReleasedClaim accepts only the exact ownerless journal revision for normal commands.
func (o *Onboarding) requireReleasedClaim(ctx context.Context, journal *Journal) error {
	lock, err := journal.AdministrationLock()
	if err != nil {
		return err
	}
	observed, err := o.backend.ObserveAdministrationLock(ctx)
	if err != nil {
		return newError(CodeUnavailable)
	}
	if !observed.Valid() {
		return newError(CodeConflict)
	}
	if observed.Claimed() || observed.Revision() != lock.Revision() {
		return newError(CodeReconcileRequired)
	}
	return nil
}

// settleReleasedClaim releases a retained same-operation claim or repairs exact release/save loss.
func (o *Onboarding) settleReleasedClaim(ctx context.Context, store *JournalStore, journal *Journal) error {
	lock, err := journal.AdministrationLock()
	if err != nil {
		return err
	}
	observed, err := o.backend.ObserveAdministrationLock(ctx)
	if err != nil {
		return newError(CodeUnavailable)
	}
	if !observed.Valid() {
		return newError(CodeConflict)
	}
	if observed.Claimed() {
		if observed.Revision() != lock.Revision() || !observed.Owner().Equal(lock.Owner()) {
			return newError(CodeConflict)
		}
		return o.releaseClaim(ctx, store, journal, lock)
	}
	if observed.Revision() == lock.Revision() {
		return nil
	}
	if lock.Revision() != ^uint64(0) && observed.Revision() == lock.Revision()+1 {
		if err := journal.ReconcileAdministrationRelease(observed); err != nil {
			return err
		}
		return store.Save(ctx, journal)
	}
	return newError(CodeConflict)
}

// releaseClaim clears one nonterminal exact claim and persists its next revision.
func (o *Onboarding) releaseClaim(
	caller context.Context,
	store *JournalStore,
	journal *Journal,
	lock datasourceadmin.AdministrationLock,
) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(caller), o.limits.BackendDeadline)
	defer cancel()
	if lock.Revision() == ^uint64(0) {
		return newError(CodeReconcileRequired)
	}
	next, err := o.backend.Release(ctx, lock)
	if err != nil {
		_ = o.persistReconciliation(ctx, store, journal)
		return newError(CodeReconcileRequired)
	}
	if err := journal.RecordAdministrationRelease(lock, next); err != nil {
		return newError(CodeReconcileRequired)
	}
	if err := store.Save(ctx, journal); err != nil {
		return newError(CodeReconcileRequired)
	}
	return nil
}

// releaseTerminalClaim proves activation-lock release without rewriting historical lineage.
func (o *Onboarding) releaseTerminalClaim(
	caller context.Context,
	lock datasourceadmin.AdministrationLock,
	allowOwnerlessCurrent bool,
) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(caller), o.limits.BackendDeadline)
	defer cancel()
	if lock.Revision() == ^uint64(0) {
		return newError(CodeReconcileRequired)
	}
	observed, err := o.backend.ObserveAdministrationLock(ctx)
	if err != nil || !observed.Valid() {
		return newError(CodeReconcileRequired)
	}
	if !observed.Claimed() && observed.Revision() == lock.Revision()+1 {
		return nil
	}
	if allowOwnerlessCurrent && !observed.Claimed() && observed.Revision() == lock.Revision() {
		return nil
	}
	if !observed.Claimed() || observed.Revision() != lock.Revision() || !observed.Owner().Equal(lock.Owner()) {
		return newError(CodeReconcileRequired)
	}
	next, err := o.backend.Release(ctx, lock)
	if err != nil || next != lock.Revision()+1 {
		return newError(CodeReconcileRequired)
	}
	return nil
}

// recordMutationFailure records only closed conflict or ambiguous mutation knowledge.
func (o *Onboarding) recordMutationFailure(
	ctx context.Context,
	store *JournalStore,
	journal *Journal,
	cause error,
) ErrorCode {
	var transitionErr error
	if datasourceadmin.CodeOf(cause) == datasourceadmin.CodeConflict {
		transitionErr = journal.RecordConflict()
	} else {
		transitionErr = journal.RequireReconciliation()
	}
	if transitionErr != nil {
		return CodeOf(transitionErr)
	}
	if err := store.Save(ctx, journal); err != nil {
		return CodeOf(err)
	}
	return failureWithState(mapDatasourceFailure(cause), journal.State())
}

// failClaimedMutation records ambiguity and preserves the exact claimed lock for reconciliation.
func (o *Onboarding) failClaimedMutation(
	ctx context.Context,
	store *JournalStore,
	journal *Journal,
	_ datasourceadmin.AdministrationLock,
	cause error,
) (OnboardingResult, error) {
	failure := o.recordMutationFailure(ctx, store, journal, cause)
	return o.failureForJournal(ctx, CommandActivate, journal, failureWithState(failure, StateReconcileRequired))
}

// persistReconciliation records and saves one ambiguous outcome without discarding store errors.
func (o *Onboarding) persistReconciliation(
	ctx context.Context,
	store *JournalStore,
	journal *Journal,
) ErrorCode {
	if err := journal.RequireReconciliation(); err != nil {
		return CodeOf(err)
	}
	if err := store.Save(ctx, journal); err != nil {
		return CodeOf(err)
	}
	return CodeReconcileRequired
}

// success constructs and emits one bounded successful command result.
func (o *Onboarding) success(
	ctx context.Context,
	command Command,
	journal *Journal,
	runtimeRequired bool,
) (OnboardingResult, error) {
	state := journal.State()
	backend := datasourceadmin.BackendClass("")
	if plan, err := journal.clonePlan(); err == nil {
		backend = plan.backend
		_ = plan.Close()
	}
	facts, factsOK := journalReportFacts(journal)
	if !factsOK {
		return o.failure(ctx, command, state, backend, CodeConflict)
	}
	if state == StateActivated {
		facts.current = facts.candidate
	} else {
		facts.current = facts.expected
	}
	return o.successfulResult(ctx, command, state, backend, facts, runtimeRequired)
}

// reconcileSuccess preserves the authoritative observation used by successful reconciliation.
func (o *Onboarding) reconcileSuccess(
	ctx context.Context,
	journal *Journal,
	observation BackendObservation,
	runtimeRequired bool,
) (OnboardingResult, error) {
	state := journal.State()
	backend := datasourceadmin.BackendClass("")
	if plan, err := journal.clonePlan(); err == nil {
		backend = plan.backend
		_ = plan.Close()
	}
	facts, factsOK := journalReportFacts(journal)
	if !factsOK || !observation.valid() || observation.candidateGeneration != facts.candidate {
		return o.failure(ctx, CommandReconcile, state, backend, CodeConflict)
	}
	facts.current = observation.currentGeneration
	switch state {
	case StateActivated:
		if facts.current != facts.candidate {
			return o.failure(ctx, CommandReconcile, state, backend, CodeConflict)
		}
	case StateConflict:
		if facts.current == facts.expected || facts.current == facts.candidate {
			return o.failure(ctx, CommandReconcile, state, backend, CodeConflict)
		}
	default:
		if facts.current != facts.expected {
			return o.failure(ctx, CommandReconcile, state, backend, CodeConflict)
		}
	}
	return o.successfulResult(
		ctx, CommandReconcile, state, backend, facts, runtimeRequired,
	)
}

// successfulResult constructs and emits one bounded success with a known current generation.
func (o *Onboarding) successfulResult(
	ctx context.Context,
	command Command,
	state OperationState,
	backend datasourceadmin.BackendClass,
	facts operationReportFacts,
	runtimeRequired bool,
) (OnboardingResult, error) {
	result := OnboardingResult{
		State: state, Result: OnboardingResultSuccess, Failure: CodeNone,
		ExpectedCurrentGeneration: facts.expected, CurrentGeneration: facts.current, CurrentGenerationKnown: true,
		CandidateGeneration: facts.candidate, CredentialCount: facts.credentials,
		RSACredentialCount: facts.rsa, Ed25519CredentialCount: facts.ed25519,
		RuntimeVerificationRequired: runtimeRequired, PlanComplete: true,
	}
	o.observe(ctx, OnboardingObservation{Command: command, State: state, Backend: backend, Result: result.Result})
	return result, nil
}

// failureForJournal constructs one bounded failure using only protected journal classes.
func (o *Onboarding) failureForJournal(
	ctx context.Context,
	command Command,
	journal *Journal,
	failure ErrorCode,
) (OnboardingResult, error) {
	state, backend := OperationState(""), datasourceadmin.BackendClass("")
	if journal != nil {
		state = journal.State()
		if plan, err := journal.clonePlan(); err == nil {
			backend = plan.backend
			_ = plan.Close()
		}
	}
	result, err := o.failure(ctx, command, state, backend, failureWithState(failure, state))
	if facts, ok := journalReportFacts(journal); ok {
		result.ExpectedCurrentGeneration = facts.expected
		result.CandidateGeneration = facts.candidate
		result.CredentialCount = facts.credentials
		result.RSACredentialCount = facts.rsa
		result.Ed25519CredentialCount = facts.ed25519
	}
	return result, err
}

// failure constructs and emits one bounded failed command result.
func (o *Onboarding) failure(
	ctx context.Context,
	command Command,
	state OperationState,
	backend datasourceadmin.BackendClass,
	failure ErrorCode,
) (OnboardingResult, error) {
	class := OnboardingResultFailure
	if failure == CodeReconcileRequired {
		class = OnboardingResultReconcile
	}
	result := OnboardingResult{State: state, Result: class, Failure: failure, PlanComplete: state != ""}
	o.observe(ctx, OnboardingObservation{
		Command: command, State: state, Backend: backend, Result: class, Failure: failure,
	})
	return result, newError(failure)
}

// commandContext applies the coordinator's overall I/O deadline to one command.
func (o *Onboarding) commandContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if o == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, newError(CodeConflict)
	}
	bounded, cancel := context.WithTimeout(ctx, o.limits.BackendDeadline)
	return bounded, cancel, nil
}

// mapDatasourceFailure maps provider-neutral backend failures to bounded workflow classes.
func mapDatasourceFailure(err error) ErrorCode {
	switch datasourceadmin.CodeOf(err) {
	case datasourceadmin.CodeConflict:
		return CodeConflict
	case datasourceadmin.CodeReconcileRequired:
		return CodeReconcileRequired
	default:
		return CodeUnavailable
	}
}

// mapDatasourceError returns one domain error preserving the bounded backend class.
func mapDatasourceError(err error) error { return newError(mapDatasourceFailure(err)) }

// nonNoneCode preserves a real bounded failure when an absent result has no underlying error.
func nonNoneCode(err error, fallback ErrorCode) ErrorCode {
	if code := CodeOf(err); code != CodeNone {
		return code
	}
	return fallback
}

// observe emits one bounded event through the injected local sink.
func (o *Onboarding) observe(ctx context.Context, event OnboardingObservation) {
	if o != nil && o.observer != nil && event.Valid() {
		o.observer.ObserveOnboarding(ctx, event)
	}
}

// failureWithState preserves reconciliation state as the outward failure class.
func failureWithState(failure ErrorCode, state OperationState) ErrorCode {
	if state == StateReconcileRequired {
		return CodeReconcileRequired
	}
	if state == StateConflict {
		if failure == CodeReconcileRequired {
			return CodeReconcileRequired
		}
		return CodeConflict
	}
	return failure
}

// journalFailureCode maps terminal journal state to its bounded outward class.
func journalFailureCode(journal *Journal) ErrorCode {
	if journal == nil {
		return CodeConflict
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.failure != CodeNone {
		return journal.failure
	}
	if journal.state == StateReconcileRequired {
		return CodeReconcileRequired
	}
	return CodeConflict
}

// String returns a constant protected onboarding-coordinator representation.
func (*Onboarding) String() string { return redacted }

// GoString returns a constant protected onboarding-coordinator representation.
func (*Onboarding) GoString() string { return redacted }

// Format prevents dependency and authority state from reaching formatting sinks.
func (*Onboarding) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic onboarding-coordinator serialization.
func (*Onboarding) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }
