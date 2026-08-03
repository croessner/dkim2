package domainadmin

import (
	"context"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

// TestStatusIsStrictlyNonmutating freezes the read-only operator observation boundary.
func TestStatusIsStrictlyNonmutating(t *testing.T) {
	journal, plan := preparedJournalFixture(t)
	defer journal.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()    //nolint:errcheck // Test cleanup has no recovery.
	before, err := encodeJournalForTest(journal, 1)
	if err != nil {
		t.Fatal("encode status baseline")
	}
	observation := absentObservation(t, plan.expectedCurrent, plan.candidateGeneration)
	status, err := ObserveStatus(journal, planAuthority(), observation)
	if err != nil || status.State != StatePrepared || status.Current != CurrentExpected ||
		status.Candidate != CandidateAbsent {
		t.Fatal("bounded status classification rejected")
	}
	after, err := encodeJournalForTest(journal, 1)
	if err != nil || string(before) != string(after) {
		t.Fatal("status mutated protected journal knowledge")
	}
	clear(before)
	clear(after)
}

// TestReconcileExpectedCurrentMatrix freezes absent, staging, committed, and ambiguous recovery.
func TestReconcileExpectedCurrentMatrix(t *testing.T) {
	t.Run("prepared absent loses exact keys", func(t *testing.T) {
		journal, plan := preparedJournalFixture(t)
		defer journal.Close() //nolint:errcheck // Test cleanup has no recovery.
		defer plan.Close()    //nolint:errcheck // Test cleanup has no recovery.
		result, err := Reconcile(journal, planAuthority(), absentObservation(t, 1, 2))
		if err != nil || result.State != StateFailed || !result.ReleaseClaim || journal.failure != CodeKeyRecoveryUnavailable {
			t.Fatal("prepared candidate absence did not become terminal key recovery loss")
		}
	})

	t.Run("preparing absent remains resumable", func(t *testing.T) {
		journal, plan := plannedJournalFixture(t)
		defer journal.Close() //nolint:errcheck // Test cleanup has no recovery.
		defer plan.Close()    //nolint:errcheck // Test cleanup has no recovery.
		if journal.BeginPreparing() != nil || journal.RequireReconciliation() != nil {
			t.Fatal("construct preparing ambiguity")
		}
		result, err := Reconcile(journal, planAuthority(), absentObservation(t, 1, 2))
		if err != nil || result.State != StatePreparing || result.Outcome != ReconcileAdvanced {
			t.Fatal("absent preparing candidate did not return to resumable key generation")
		}
	})

	t.Run("planned absent remains planned", func(t *testing.T) {
		journal, plan := plannedJournalFixture(t)
		defer journal.Close() //nolint:errcheck // Test cleanup has no recovery.
		defer plan.Close()    //nolint:errcheck // Test cleanup has no recovery.
		if journal.RequireReconciliation() != nil {
			t.Fatal("construct planned ambiguity")
		}
		result, err := Reconcile(journal, planAuthority(), absentObservation(t, 1, 2))
		if err != nil || result.State != StatePlanned || result.Outcome != ReconcileAdvanced {
			t.Fatal("absent planned candidate did not return to planned")
		}
	})

	for _, state := range []CandidateObservationClass{CandidatePartial, CandidateMismatch, CandidateUnknown} {
		t.Run(string(state), func(t *testing.T) {
			journal, plan := preparedJournalFixture(t)
			defer journal.Close() //nolint:errcheck // Test cleanup has no recovery.
			defer plan.Close()    //nolint:errcheck // Test cleanup has no recovery.
			observation, _ := NewBackendObservation(1, 2, state, datasourceadmin.OperationBinding{}, datasourceadmin.StagedEvidence{}, false)
			result, err := Reconcile(journal, planAuthority(), observation)
			if err != nil || result.State != StateReconcileRequired || result.Outcome != ReconcileAmbiguous || journal.reconcileFrom != StatePrepared {
				t.Fatal("partial, mismatched, or unknown candidate was overclaimed")
			}
		})
	}

	t.Run("exact staging returns prepared", func(t *testing.T) {
		journal, plan := preparedJournalFixture(t)
		defer journal.Close() //nolint:errcheck // Test cleanup has no recovery.
		defer plan.Close()    //nolint:errcheck // Test cleanup has no recovery.
		observation := exactObservation(t, journal, 1, CandidateExactStaging, false)
		result, err := Reconcile(journal, planAuthority(), observation)
		if err != nil || result.State != StatePrepared || !result.ReleaseClaim || result.RequiresDNSProof {
			t.Fatal("exact writable candidate did not return to prepared")
		}
	})

	t.Run("exact committed returns staged", func(t *testing.T) {
		journal, plan := preparedJournalFixture(t)
		defer journal.Close() //nolint:errcheck // Test cleanup has no recovery.
		defer plan.Close()    //nolint:errcheck // Test cleanup has no recovery.
		observation := exactObservation(t, journal, 1, CandidateExactCommitted, false)
		result, err := Reconcile(journal, planAuthority(), observation)
		if err != nil || result.State != StateStaged || !result.ReleaseClaim || !result.RequiresDNSProof ||
			!journal.prepared.Matches(journal.staged) {
			t.Fatal("exact committed candidate did not reconcile to staged with fresh DNS required")
		}
	})
}

// TestReconcileActivationMatrixFreezesNoOutOfBandSuccessAndHistoricalProof.
func TestReconcileActivationMatrix(t *testing.T) {
	t.Run("exact activating lineage succeeds", func(t *testing.T) {
		journal, plan := activatingJournalFixture(t)
		defer journal.Close() //nolint:errcheck // Test cleanup has no recovery.
		defer plan.Close()    //nolint:errcheck // Test cleanup has no recovery.
		result, err := Reconcile(journal, planAuthority(), exactObservation(t, journal, 2, CandidateExactCommitted, true))
		if err != nil || result.State != StateActivated {
			t.Fatal("exact activating lineage and old-current history did not reconcile")
		}
	})

	t.Run("missing old active history stays ambiguous", func(t *testing.T) {
		journal, plan := activatingJournalFixture(t)
		defer journal.Close() //nolint:errcheck // Test cleanup has no recovery.
		defer plan.Close()    //nolint:errcheck // Test cleanup has no recovery.
		result, err := Reconcile(journal, planAuthority(), exactObservation(t, journal, 2, CandidateExactCommitted, false))
		if err != nil || result.State != StateReconcileRequired || journal.activation == nil || journal.reconcileFrom != StateActivating {
			t.Fatal("missing durable old-current evidence was laundered as activation")
		}
	})

	t.Run("out of band pointer stays ambiguous", func(t *testing.T) {
		journal, plan := stagedJournalFixture(t)
		defer journal.Close() //nolint:errcheck // Test cleanup has no recovery.
		defer plan.Close()    //nolint:errcheck // Test cleanup has no recovery.
		result, err := Reconcile(journal, planAuthority(), exactObservation(t, journal, 2, CandidateExactCommitted, true))
		if err != nil || result.State != StateReconcileRequired || journal.reconcileFrom != StateStaged {
			t.Fatal("out-of-band current pointer was laundered as workflow activation")
		}
	})

	t.Run("third current conflicts and retains activation lineage", func(t *testing.T) {
		journal, plan := activatingJournalFixture(t)
		defer journal.Close() //nolint:errcheck // Test cleanup has no recovery.
		defer plan.Close()    //nolint:errcheck // Test cleanup has no recovery.
		result, err := Reconcile(journal, planAuthority(), exactObservation(t, journal, 3, CandidateExactCommitted, true))
		if err != nil || result.State != StateConflict || journal.activation == nil || !journalRecordValid(journal, 1) {
			t.Fatal("third current did not retain mandatory activation lineage in terminal conflict")
		}
	})
}

// TestBootstrapActivationRejectsContradictoryOldCurrentHistory freezes empty-source lineage.
func TestBootstrapActivationRejectsContradictoryOldCurrentHistory(t *testing.T) {
	_, staged := candidateEvidenceFixture(t)
	operation, _ := datasourceadmin.NewOperationBinding(planAuthorityID)
	if observation, err := NewBackendObservation(0, 1, CandidateExactStaging, operation, staged, true); err == nil || observation.valid() {
		t.Fatal("empty current accepted contradictory was-active history")
	}
	journal, plan := bootstrapActivatingJournalFixture(t)
	defer journal.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()    //nolint:errcheck // Test cleanup has no recovery.
	contradictory := exactObservation(t, journal, 1, CandidateExactCommitted, true)
	result, err := Reconcile(journal, planAuthority(), contradictory)
	if err != nil || result.State != StateReconcileRequired {
		t.Fatal("bootstrap activation accepted old-current was-active evidence")
	}
	exact := exactObservation(t, journal, 1, CandidateExactCommitted, false)
	result, err = Reconcile(journal, planAuthority(), exact)
	if err != nil || result.State != StateActivated {
		t.Fatal("exact empty-bootstrap lineage did not reconcile")
	}
}

// TestTerminalReconciliationRejectsContradictoryAuthority freezes immutable failure history.
func TestTerminalReconciliationRejectsContradictoryAuthority(t *testing.T) {
	journal, plan := preparedJournalFixture(t)
	defer journal.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()    //nolint:errcheck // Test cleanup has no recovery.
	if _, err := Reconcile(journal, planAuthority(), absentObservation(t, 1, 2)); err != nil || journal.state != StateFailed {
		t.Fatal("construct failed terminal fixture")
	}
	if result, err := Reconcile(journal, planAuthority(), exactObservation(t, journal, 1, CandidateExactCommitted, false)); CodeOf(err) != CodeConflict || result.State != "" || journal.state != StateFailed {
		t.Fatal("terminal key-loss history hid contradictory committed content")
	}

	aborted, abortedPlan := plannedJournalFixture(t)
	defer aborted.Close()     //nolint:errcheck // Test cleanup has no recovery.
	defer abortedPlan.Close() //nolint:errcheck // Test cleanup has no recovery.
	aborted.mu.Lock()
	aborted.state = StateAborted
	aborted.reconcileFrom = StatePlanned
	aborted.mu.Unlock()
	if _, err := Reconcile(aborted, planAuthority(), absentObservation(t, 2, 2)); CodeOf(err) != CodeConflict || aborted.state != StateAborted {
		t.Fatal("terminal abort hid a candidate that became current")
	}
}

// preparedJournalFixture constructs exact persisted prepared evidence without backend readback.
func preparedJournalFixture(t *testing.T) (*Journal, *Plan) {
	t.Helper()
	journal, plan := plannedJournalFixture(t)
	prepared, _ := candidateEvidenceFixture(t)
	if journal.BeginPreparing() != nil || journal.RecordPrepared(prepared) != nil {
		_ = journal.Close()
		_ = plan.Close()
		t.Fatal("construct prepared journal")
	}
	return journal, plan
}

// activatingJournalFixture constructs exact established activation write-ahead evidence.
func activatingJournalFixture(t *testing.T) (*Journal, *Plan) {
	t.Helper()
	journal, plan := stagedJournalFixture(t)
	journal.mu.Lock()
	journal.state = StateDNSProven
	journal.mu.Unlock()
	completed := time.Unix(1_800_000_000, 0).UTC()
	proof := activationProofForJournal(t, journal, completed)
	defer proof.Close() //nolint:errcheck // Fixture proof is no longer needed after lineage construction.
	lock, _ := journal.AdministrationLock()
	if journal.BeginActivating(proof, lock, completed, false, true) != nil {
		_ = journal.Close()
		_ = plan.Close()
		t.Fatal("construct activation lineage")
	}
	return journal, plan
}

// bootstrapActivatingJournalFixture constructs exact empty-backend activation lineage.
func bootstrapActivatingJournalFixture(t *testing.T) (*Journal, *Plan) {
	t.Helper()
	allocator, _ := newIdentityAllocator(DefaultLimits(), &incrementingEntropy{})
	locker := &administrationLockerFake{revision: 31}
	reader := &collisionReaderFake{build: func(
		ctx context.Context,
		lock datasourceadmin.AdministrationLock,
		limits datasourceadmin.GenerationLimits,
	) (*datasourceadmin.CollisionInventory, error) {
		return datasourceadmin.NewCollisionInventory(ctx, lock, datasourceadmin.Inventory{}, nil, limits)
	}}
	allocation, _, err := allocator.allocateForTest(
		t.Context(), testIntent(t, provider.AlgorithmEd25519SHA256), reader, locker, 31, testAdminGenerationLimits(),
	)
	if err != nil {
		t.Fatal("construct empty allocation")
	}
	defer allocation.Close() //nolint:errcheck // Test cleanup has no recovery.
	plan, err := NewPlan(t.Context(), datasourceadmin.BackendLDAP, planAuthority(), allocation, planDNSPolicy())
	if err != nil {
		t.Fatal("construct empty plan")
	}
	journal, err := NewJournal(plan)
	if err != nil {
		_ = plan.Close()
		t.Fatal("construct empty journal")
	}
	prepared, staged := candidateEvidenceFixture(t)
	if journal.BeginPreparing() != nil || journal.RecordPrepared(prepared) != nil || journal.RecordStaged(staged) != nil {
		t.Fatal("construct empty staged evidence")
	}
	journal.mu.Lock()
	journal.state = StateDNSProven
	journal.mu.Unlock()
	completed := time.Unix(1_800_000_000, 0).UTC()
	proof := activationProofForJournal(t, journal, completed)
	defer proof.Close() //nolint:errcheck // Fixture proof is no longer needed after lineage construction.
	lock, _ := journal.AdministrationLock()
	if journal.BeginActivating(proof, lock, completed, true, false) != nil {
		t.Fatal("construct empty activation lineage")
	}
	return journal, plan
}

// absentObservation constructs one exact authoritative negative candidate readback.
func absentObservation(t *testing.T, current, candidate uint64) BackendObservation {
	t.Helper()
	observation, err := NewBackendObservation(
		current, candidate, CandidateAbsent, datasourceadmin.OperationBinding{}, datasourceadmin.StagedEvidence{}, false,
	)
	if err != nil {
		t.Fatal("construct absent observation")
	}
	return observation
}

// exactObservation constructs one operation-bound candidate readback.
func exactObservation(
	t *testing.T,
	journal *Journal,
	current uint64,
	class CandidateObservationClass,
	oldCurrentWasActive bool,
) BackendObservation {
	t.Helper()
	journal.mu.Lock()
	operation := journal.plan.operation
	candidate := journal.plan.candidateGeneration
	staged := journal.staged
	if !staged.Digest().Valid() {
		_, staged = candidateEvidenceFixture(t)
	}
	journal.mu.Unlock()
	observation, err := NewBackendObservation(current, candidate, class, operation, staged, oldCurrentWasActive)
	if err != nil {
		t.Fatal("construct exact candidate observation")
	}
	return observation
}
