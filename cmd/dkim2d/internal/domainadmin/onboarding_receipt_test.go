package domainadmin

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

// scriptedProtectedDocument provides deterministic before/after-commit ambiguity windows.
type scriptedProtectedDocument struct {
	document          []byte
	ambiguousDocument []byte
	replaces          int
	ambiguousAt       int
	failAt            int
	commit            bool
	opens             int
	reopenErr         error
	reloadAbsent      bool
	reloadDocument    []byte
}

// scriptedProtectedTransaction is one reopenable in-memory protected transaction.
type scriptedProtectedTransaction struct {
	shared       *scriptedProtectedDocument
	readDocument []byte
	readAbsent   bool
	readOnce     bool
	read         bool
	closed       bool
}

// onboardingObservationRecorder retains the last bounded observation for result-alignment tests.
type onboardingObservationRecorder struct{ last OnboardingObservation }

// ObserveOnboarding records one bounded command observation.
func (r *onboardingObservationRecorder) ObserveOnboarding(_ context.Context, observation OnboardingObservation) {
	r.last = observation
}

// Read returns one detached exact scripted document view.
func (s *scriptedProtectedTransaction) Read(context.Context) ([]byte, bool, error) {
	if s.closed {
		return nil, false, newError(CodeProtectedInput)
	}
	s.read = true
	if s.readOnce {
		s.readOnce = false
		if s.readAbsent {
			return nil, false, nil
		}
		return append([]byte(nil), s.readDocument...), true, nil
	}
	return append([]byte(nil), s.shared.document...), len(s.shared.document) != 0, nil
}

// Replace applies one exact scripted CAS and optional ambiguous response.
func (s *scriptedProtectedTransaction) Replace(_ context.Context, document []byte) error {
	if s.closed || !s.read {
		return newError(CodeConflict)
	}
	s.shared.replaces++
	if s.shared.replaces == s.shared.failAt {
		return newError(CodeProtectedInput)
	}
	if s.shared.replaces == s.shared.ambiguousAt {
		if len(s.shared.ambiguousDocument) != 0 {
			s.shared.document = append(s.shared.document[:0], s.shared.ambiguousDocument...)
		} else if s.shared.commit {
			s.shared.document = append(s.shared.document[:0], document...)
		}
		return newError(CodeReconcileRequired)
	}
	s.shared.document = append(s.shared.document[:0], document...)
	return nil
}

// TestReceiptPostMutationClaimAndReleaseWindows freezes response-loss recovery.
func TestReceiptPostMutationClaimAndReleaseWindows(t *testing.T) {
	t.Run("Claim mutates then errors", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		backend.claimPostMutationErr = errors.New("claim response lost")
		result, err := planOnboarding(t, onboarding, store)
		if err != nil || result.State != StatePlanned || !result.PlanComplete || backend.claimCalls != 1 ||
			!backend.lockClaimed {
			t.Fatal("post-mutation Claim error did not resolve through exact owner observation")
		}
	})
	t.Run("Release mutates then errors", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		_, operation := persistReceiptFixture(t, onboarding, backend, store, planningReceiptReleaseRequired)
		backend.lockOwner, backend.lockClaimed = operation, true
		backend.releasePostMutationErr = errors.New("release response lost")
		result, err := onboarding.Reconcile(t.Context(), store)
		if CodeOf(err) != CodeReconcileRequired || result.ReceiptPhase != ReceiptPhaseReleaseRequired ||
			backend.lockClaimed || backend.releaseCalls != 1 {
			t.Fatal("post-mutation Release error did not retain release_required")
		}
		backend.releasePostMutationErr = nil
		result, err = onboarding.Reconcile(t.Context(), store)
		if err != nil || result.ReceiptPhase != ReceiptPhaseClosed || backend.releaseCalls != 1 {
			t.Fatal("ownerless R+1 did not close response-lost Release without retry")
		}
	})
}

// TestPlanInitialLockObservationDistinguishesTransportFromEvidence freezes the pre-receipt boundary.
func TestPlanInitialLockObservationDistinguishesTransportFromEvidence(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*onboardingBackendFake)
		want      ErrorCode
	}{
		{name: "initial observation error", configure: func(backend *onboardingBackendFake) {
			backend.observeLockErr = errors.New("backend offline")
		}, want: CodeUnavailable},
		{name: "invalid evidence", configure: func(backend *onboardingBackendFake) {
			backend.invalidLockObservation = true
		}, want: CodeConflict},
		{name: "already claimed", configure: func(backend *onboardingBackendFake) {
			owner, _ := datasourceadmin.NewOperationBinding("aebagbafaydqqcikbmga2dqpca")
			backend.lockOwner, backend.lockClaimed = owner, true
		}, want: CodeConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
			defer closeOnboardingFixture(store, backend, plan)
			test.configure(backend)
			result, err := planOnboarding(t, onboarding, store)
			if CodeOf(err) != test.want || result.State != "" || result.ReceiptPresent ||
				backend.claimCalls != 0 || backend.releaseCalls != 0 {
				t.Fatal("initial lock observation crossed the receipt or Claim boundary")
			}
		})
	}
}

// TestClosedReceiptCASAmbiguityMatrix freezes committed, uncommitted, and third union outcomes.
func TestClosedReceiptCASAmbiguityMatrix(t *testing.T) {
	for _, test := range []struct {
		name     string
		commit   bool
		third    bool
		wantPlan bool
	}{
		{name: "uncommitted"},
		{name: "committed", commit: true, wantPlan: true},
		{name: "third outcome", third: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			onboarding, backend, original, plan, _ := onboardingCoordinatorFixture(t)
			_ = original.Close()
			shared := &scriptedProtectedDocument{}
			opener := func(context.Context, string, int) (journalProtectedStore, error) {
				return openScriptedProtectedTransaction(shared)
			}
			store, err := openJournalStore(t.Context(), "/protected/closed-cas.json", DefaultLimits(), opener)
			if err != nil {
				t.Fatal("open closed CAS store")
			}
			defer closeOnboardingFixture(store, backend, plan)
			_, _ = persistReceiptFixture(t, onboarding, backend, store, planningReceiptClosed)
			shared.ambiguousAt = shared.replaces + 1
			shared.commit = test.commit
			if test.third {
				shared.ambiguousDocument = []byte(`{"version":"third"}` + "\n")
			}
			result, planErr := planOnboarding(t, onboarding, store)
			if test.wantPlan {
				if planErr != nil || result.State != StatePlanned || backend.claimCalls != 1 {
					t.Fatal("committed closed CAS did not resume exact new receipt")
				}
			} else if CodeOf(planErr) != CodeReconcileRequired || result.State != "" || backend.claimCalls != 0 {
				t.Fatal("uncommitted or third closed CAS outcome reached Claim")
			}
		})
	}
}

// Close invalidates only this transaction; shared durable bytes survive reopen.
func (s *scriptedProtectedTransaction) Close() error { s.closed = true; return nil }

// openScriptedProtectedTransaction applies one optional read fault only after a poisoned-store reopen.
func openScriptedProtectedTransaction(shared *scriptedProtectedDocument) (journalProtectedStore, error) {
	shared.opens++
	if shared.opens > 1 && shared.reopenErr != nil {
		return nil, shared.reopenErr
	}
	transaction := &scriptedProtectedTransaction{shared: shared}
	if shared.opens > 1 && (shared.reloadAbsent || shared.reloadDocument != nil) {
		transaction.readOnce = true
		transaction.readAbsent = shared.reloadAbsent
		transaction.readDocument = append([]byte(nil), shared.reloadDocument...)
	}
	return transaction, nil
}

// TestPlanResolvesReceiptAndPromotionAmbiguityByFreshUnionReload freezes poisoned-store recovery.
func TestPlanResolvesReceiptAndPromotionAmbiguityByFreshUnionReload(t *testing.T) {
	for _, test := range []struct {
		name        string
		ambiguousAt int
		failAt      int
		commit      bool
		wantSuccess bool
		wantClaim   int
		wantCode    ErrorCode
		wantReceipt ReceiptPhase
	}{
		{name: "initial receipt definite failure", failAt: 1, wantClaim: 0, wantCode: CodeProtectedInput},
		{name: "initial receipt not committed", ambiguousAt: 1, wantClaim: 0, wantCode: CodeReconcileRequired},
		{name: "initial receipt committed", ambiguousAt: 1, commit: true, wantSuccess: true, wantClaim: 1},
		{name: "allocating receipt committed", ambiguousAt: 2, commit: true, wantSuccess: true, wantClaim: 1},
		{name: "promotion retained receipt", ambiguousAt: 3, wantClaim: 1, wantCode: CodeReconcileRequired, wantReceipt: ReceiptPhaseAllocating},
		{name: "promotion committed journal", ambiguousAt: 3, commit: true, wantSuccess: true, wantClaim: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			onboarding, backend, original, plan, _ := onboardingCoordinatorFixture(t)
			_ = original.Close()
			shared := &scriptedProtectedDocument{
				ambiguousAt: test.ambiguousAt, failAt: test.failAt, commit: test.commit,
			}
			opener := func(context.Context, string, int) (journalProtectedStore, error) {
				return openScriptedProtectedTransaction(shared)
			}
			store, err := openJournalStore(t.Context(), "/protected/operation.json", DefaultLimits(), opener)
			if err != nil {
				t.Fatal("open scripted journal store")
			}
			defer closeOnboardingFixture(store, backend, plan)
			result, planErr := planOnboarding(t, onboarding, store)
			if test.wantSuccess {
				if planErr != nil || result.State != StatePlanned || !result.PlanComplete {
					t.Fatal("committed ambiguous write was not resolved from fresh union reload")
				}
			} else if CodeOf(planErr) != test.wantCode || result.State != "" ||
				result.ReceiptPhase != test.wantReceipt || result.ReceiptPresent != (test.wantReceipt != "") {
				t.Fatal("uncommitted ambiguous write did not stop with bounded receipt recovery")
			}
			if backend.claimCalls != test.wantClaim {
				t.Fatal("ambiguity resolution crossed the permitted Claim boundary")
			}
		})
	}
}

// TestReconcileResolvesAmbiguousReceiptSaveBeforeRelease freezes cleanup ordering across poisoned stores.
func TestReconcileResolvesAmbiguousReceiptSaveBeforeRelease(t *testing.T) {
	onboarding, backend, original, plan, _ := onboardingCoordinatorFixture(t)
	_ = original.Close()
	shared := &scriptedProtectedDocument{}
	opener := func(context.Context, string, int) (journalProtectedStore, error) {
		return openScriptedProtectedTransaction(shared)
	}
	store, err := openJournalStore(t.Context(), "/protected/reconcile.json", DefaultLimits(), opener)
	if err != nil {
		t.Fatal("open scripted reconcile store")
	}
	defer closeOnboardingFixture(store, backend, plan)
	_, operation := persistReceiptFixture(t, onboarding, backend, store, planningReceiptUnresolved)
	backend.lockOwner, backend.lockClaimed = operation, true
	backend.beforeRelease = func() {
		receipt, journal, exists, loadErr := store.LoadOperation(t.Context())
		if loadErr != nil || !exists || receipt == nil || journal != nil ||
			receipt.Phase() != ReceiptPhaseReleaseRequired {
			t.Fatal("Release ran before durable release_required union readback")
		}
		_ = receipt.Close()
	}
	shared.ambiguousAt = shared.replaces + 1
	shared.commit = true
	result, err := onboarding.Reconcile(t.Context(), store)
	if err != nil || result.ReceiptPhase != ReceiptPhaseClosed || backend.releaseCalls != 1 || backend.lockClaimed {
		t.Fatal("ambiguous release_required sync was not reloaded before exact Release")
	}
	if len(backend.events) == 0 || backend.events[len(backend.events)-1] != "release" {
		t.Fatal("cleanup ordering did not terminate in the explicitly reconciled Release")
	}
}

// TestAmbiguousReceiptSaveReportsFreshAuthoritativePhase freezes readback-owned failure reporting.
func TestAmbiguousReceiptSaveReportsFreshAuthoritativePhase(t *testing.T) {
	t.Run("unresolved save not committed", func(t *testing.T) {
		onboarding, backend, store, shared := scriptedReceiptCoordinatorFixture(t, "/protected/unresolved-save.json")
		defer closeOnboardingFixture(store, backend, nil)
		recorder := &onboardingObservationRecorder{}
		onboarding.observer = recorder
		_, _ = persistReceiptFixture(t, onboarding, backend, store, planningReceiptClaimPending)
		foreign, _ := datasourceadmin.NewOperationBinding("aebagbafaydqqcikbmga2dqpca")
		backend.lockOwner, backend.lockClaimed = foreign, true
		shared.ambiguousAt = shared.replaces + 1

		result, err := onboarding.Reconcile(t.Context(), store)
		assertAuthoritativeReceiptFailure(t, result, err, ReceiptPhaseClaimPending, recorder)
		assertDurableReceiptPhase(t, store, ReceiptPhaseClaimPending)
		if backend.claimCalls != 0 || backend.releaseCalls != 0 {
			t.Fatal("uncommitted unresolved save crossed a backend mutation boundary")
		}
	})

	t.Run("release-required save not committed", func(t *testing.T) {
		onboarding, backend, store, shared := scriptedReceiptCoordinatorFixture(t, "/protected/release-required-save.json")
		defer closeOnboardingFixture(store, backend, nil)
		recorder := &onboardingObservationRecorder{}
		onboarding.observer = recorder
		_, operation := persistReceiptFixture(t, onboarding, backend, store, planningReceiptUnresolved)
		backend.lockOwner, backend.lockClaimed = operation, true
		shared.ambiguousAt = shared.replaces + 1

		result, err := onboarding.Reconcile(t.Context(), store)
		assertAuthoritativeReceiptFailure(t, result, err, ReceiptPhaseUnresolved, recorder)
		assertDurableReceiptPhase(t, store, ReceiptPhaseUnresolved)
		if backend.releaseCalls != 0 || !backend.lockClaimed {
			t.Fatal("uncommitted release-required save authorized Release")
		}
	})
}

// TestAmbiguousReceiptSaveWithoutFreshReceiptReportsUnknownPhase freezes absence of speculative output.
func TestAmbiguousReceiptSaveWithoutFreshReceiptReportsUnknownPhase(t *testing.T) {
	journalDocument := plannedJournalDocument(t)
	defer clear(journalDocument)
	for _, test := range []struct {
		name      string
		configure func(*scriptedProtectedDocument)
		definite  bool
	}{
		{name: "reload open error", configure: func(shared *scriptedProtectedDocument) {
			shared.reopenErr = errors.New("reopen failed")
		}},
		{name: "reload absent", configure: func(shared *scriptedProtectedDocument) {
			shared.reloadAbsent = true
		}},
		{name: "reload malformed", configure: func(shared *scriptedProtectedDocument) {
			shared.reloadDocument = []byte("{")
		}},
		{name: "reload journal", configure: func(shared *scriptedProtectedDocument) {
			shared.reloadDocument = append([]byte(nil), journalDocument...)
		}},
		{name: "definite save error", definite: true, configure: func(*scriptedProtectedDocument) {}},
	} {
		t.Run(test.name, func(t *testing.T) {
			onboarding, backend, store, shared := scriptedReceiptCoordinatorFixture(t, "/protected/unknown-save.json")
			defer closeOnboardingFixture(store, backend, nil)
			recorder := &onboardingObservationRecorder{}
			onboarding.observer = recorder
			_, _ = persistReceiptFixture(t, onboarding, backend, store, planningReceiptUnresolved)
			if test.definite {
				shared.failAt = shared.replaces + 1
			} else {
				shared.ambiguousAt = shared.replaces + 1
			}
			test.configure(shared)

			result, err := onboarding.Reconcile(t.Context(), store)
			assertUnknownReceiptFailure(t, result, err, recorder)
			if backend.claimCalls != 0 || backend.releaseCalls != 0 || backend.collisionCalls != 0 {
				t.Fatal("unknown receipt readback authorized backend mutation")
			}
		})
	}
}

// TestAmbiguousPromotionWithoutFreshUnionReportsUnknownPhase freezes promotion readback authority.
func TestAmbiguousPromotionWithoutFreshUnionReportsUnknownPhase(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*scriptedProtectedDocument)
	}{
		{name: "reload open error", configure: func(shared *scriptedProtectedDocument) {
			shared.reopenErr = errors.New("reopen failed")
		}},
		{name: "reload absent", configure: func(shared *scriptedProtectedDocument) {
			shared.reloadAbsent = true
		}},
		{name: "reload invalid union", configure: func(shared *scriptedProtectedDocument) {
			shared.reloadDocument = []byte(`{"version":"invalid"}` + "\n")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			onboarding, backend, original, plan, _ := onboardingCoordinatorFixture(t)
			_ = original.Close()
			shared := &scriptedProtectedDocument{ambiguousAt: 3}
			test.configure(shared)
			opener := func(context.Context, string, int) (journalProtectedStore, error) {
				return openScriptedProtectedTransaction(shared)
			}
			store, err := openJournalStore(t.Context(), "/protected/unknown-promotion.json", DefaultLimits(), opener)
			if err != nil {
				t.Fatal("open scripted promotion store")
			}
			defer closeOnboardingFixture(store, backend, plan)
			recorder := &onboardingObservationRecorder{}
			onboarding.observer = recorder

			result, planErr := planOnboarding(t, onboarding, store)
			assertUnknownReceiptFailure(t, result, planErr, recorder)
			if backend.claimCalls != 1 || backend.releaseCalls != 0 || backend.collisionCalls != 2 {
				t.Fatal("unknown promotion readback crossed another backend mutation boundary")
			}
		})
	}
}

// TestAmbiguousPromotionRejectsMismatchedFreshIdentity freezes exact CAS recovery binding.
func TestAmbiguousPromotionRejectsMismatchedFreshIdentity(t *testing.T) {
	for _, test := range []struct {
		name     string
		document func(*testing.T) []byte
	}{
		{name: "same-request journal with changed lock revision", document: mismatchedPromotionJournalDocument},
		{name: "same-request receipt with foreign operation", document: mismatchedPromotionReceiptDocument},
	} {
		t.Run(test.name, func(t *testing.T) {
			onboarding, backend, original, plan, _ := onboardingCoordinatorFixture(t)
			_ = original.Close()
			document := test.document(t)
			defer clear(document)
			shared := &scriptedProtectedDocument{ambiguousAt: 3, reloadDocument: document}
			opener := func(context.Context, string, int) (journalProtectedStore, error) {
				return openScriptedProtectedTransaction(shared)
			}
			store, err := openJournalStore(t.Context(), "/protected/mismatched-promotion.json", DefaultLimits(), opener)
			if err != nil {
				t.Fatal("open mismatched promotion store")
			}
			defer closeOnboardingFixture(store, backend, plan)
			recorder := &onboardingObservationRecorder{}
			onboarding.observer = recorder

			result, planErr := planOnboarding(t, onboarding, store)
			assertUnknownReceiptFailure(t, result, planErr, recorder)
			if result.State != "" || backend.claimCalls != 1 || backend.releaseCalls != 0 ||
				backend.collisionCalls != 2 {
				t.Fatal("mismatched promotion identity exposed foreign state or crossed another mutation boundary")
			}
		})
	}
}

// TestReconcileResolvesClosedReceiptSaveLoss freezes cleanup after Release succeeded.
func TestReconcileResolvesClosedReceiptSaveLoss(t *testing.T) {
	for _, test := range []struct {
		name   string
		commit bool
	}{
		{name: "closed save committed", commit: true},
		{name: "closed save not committed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			onboarding, backend, original, plan, _ := onboardingCoordinatorFixture(t)
			_ = original.Close()
			shared := &scriptedProtectedDocument{}
			opener := func(context.Context, string, int) (journalProtectedStore, error) {
				return openScriptedProtectedTransaction(shared)
			}
			store, err := openJournalStore(t.Context(), "/protected/closed-save.json", DefaultLimits(), opener)
			if err != nil {
				t.Fatal("open scripted closed-save store")
			}
			defer closeOnboardingFixture(store, backend, plan)
			recorder := &onboardingObservationRecorder{}
			onboarding.observer = recorder
			_, operation := persistReceiptFixture(t, onboarding, backend, store, planningReceiptReleaseRequired)
			backend.lockOwner, backend.lockClaimed = operation, true
			shared.ambiguousAt = shared.replaces + 1
			shared.commit = test.commit

			result, reconcileErr := onboarding.Reconcile(t.Context(), store)
			if test.commit {
				if reconcileErr != nil || result.ReceiptPhase != ReceiptPhaseClosed ||
					backend.releaseCalls != 1 || backend.lockClaimed {
					t.Fatal("committed closed receipt save was not recovered from fresh union readback")
				}
				return
			}
			assertAuthoritativeReceiptFailure(t, result, reconcileErr, ReceiptPhaseReleaseRequired, recorder)
			if backend.releaseCalls != 1 || backend.lockClaimed {
				t.Fatal("uncommitted closed receipt save did not retain release lineage")
			}
			persisted, journal, exists, loadErr := store.LoadOperation(t.Context())
			if loadErr != nil || !exists || persisted == nil || journal != nil ||
				persisted.Phase() != ReceiptPhaseReleaseRequired {
				_ = persisted.Close()
				_ = journal.Close()
				t.Fatal("uncommitted closed receipt save changed durable release-required lineage")
			}
			_ = persisted.Close()
			result, reconcileErr = onboarding.Reconcile(t.Context(), store)
			if reconcileErr != nil || result.ReceiptPhase != ReceiptPhaseClosed || backend.releaseCalls != 1 {
				t.Fatal("ownerless R+1 did not repair the uncommitted closed receipt save")
			}
		})
	}
}

// scriptedReceiptCoordinatorFixture constructs one coordinator over a reopenable scripted store.
func scriptedReceiptCoordinatorFixture(
	t *testing.T,
	path string,
) (*Onboarding, *onboardingBackendFake, *JournalStore, *scriptedProtectedDocument) {
	t.Helper()
	onboarding, backend, original, plan, _ := onboardingCoordinatorFixture(t)
	_ = original.Close()
	_ = plan
	shared := &scriptedProtectedDocument{}
	opener := func(context.Context, string, int) (journalProtectedStore, error) {
		return openScriptedProtectedTransaction(shared)
	}
	store, err := openJournalStore(t.Context(), path, DefaultLimits(), opener)
	if err != nil {
		t.Fatal("open scripted receipt store")
	}
	return onboarding, backend, store, shared
}

// assertAuthoritativeReceiptFailure checks command and telemetry agreement with fresh readback.
func assertAuthoritativeReceiptFailure(
	t *testing.T,
	result OnboardingResult,
	err error,
	want ReceiptPhase,
	recorder *onboardingObservationRecorder,
) {
	t.Helper()
	if CodeOf(err) != CodeReconcileRequired || result.Result != OnboardingResultReconcile ||
		result.Failure != CodeReconcileRequired || result.ReceiptPhase != want || !result.ReceiptPresent {
		t.Fatalf("receipt result did not report authoritative phase %s", want)
	}
	if recorder == nil || recorder.last.Result != OnboardingResultReconcile ||
		recorder.last.Failure != CodeReconcileRequired || recorder.last.Receipt != want {
		t.Fatalf("receipt observation did not report authoritative phase %s", want)
	}
}

// assertUnknownReceiptFailure checks that unknown durable union state invents no receipt facts.
func assertUnknownReceiptFailure(
	t *testing.T,
	result OnboardingResult,
	err error,
	recorder *onboardingObservationRecorder,
) {
	t.Helper()
	if CodeOf(err) != CodeReconcileRequired || result.Result != OnboardingResultReconcile ||
		result.Failure != CodeReconcileRequired || result.ReceiptPhase != "" || result.ReceiptPresent {
		t.Fatal("unknown durable union state reported speculative receipt facts")
	}
	if recorder == nil || recorder.last.Result != OnboardingResultReconcile ||
		recorder.last.Failure != CodeReconcileRequired || recorder.last.Receipt != "" {
		t.Fatal("unknown durable union state emitted speculative receipt telemetry")
	}
}

// plannedJournalDocument returns one exact encoded promoted journal fixture.
func plannedJournalDocument(t *testing.T) []byte {
	t.Helper()
	onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
	if _, err := planOnboarding(t, onboarding, store); err != nil {
		closeOnboardingFixture(store, backend, plan)
		t.Fatal("plan journal document fixture")
	}
	document, err := os.ReadFile(store.path)
	closeOnboardingFixture(store, backend, plan)
	if err != nil {
		t.Fatal("read journal document fixture")
	}
	return document
}

// mismatchedPromotionJournalDocument retains the same request but changes the exact claim revision.
func mismatchedPromotionJournalDocument(t *testing.T) []byte {
	t.Helper()
	document := plannedJournalDocument(t)
	journal, err := decodeJournal(document)
	clear(document)
	if err != nil {
		t.Fatal("decode mismatched promotion journal fixture")
	}
	defer journal.Close() //nolint:errcheck // Test cleanup has no recovery action.
	journal.mu.Lock()
	journal.plan.mu.Lock()
	journal.plan.lockRevision++
	journal.plan.mu.Unlock()
	document, err = encodeJournalLocked(journal, journal.revision)
	journal.mu.Unlock()
	if err != nil {
		t.Fatal("encode mismatched promotion journal fixture")
	}
	return document
}

// mismatchedPromotionReceiptDocument retains the same request but substitutes the exact operation.
func mismatchedPromotionReceiptDocument(t *testing.T) []byte {
	t.Helper()
	operation, err := datasourceadmin.NewOperationBinding("aibqibiga4eascqlbqgzav3y4m")
	if err != nil {
		t.Fatal("construct foreign promotion operation")
	}
	receipt, err := NewPlanningReceipt(
		datasourceadmin.BackendLDAP, planAuthority(), operation, 23,
		testIntent(t, provider.AlgorithmEd25519SHA256), planDNSPolicy(),
	)
	if err != nil || receipt.RecordAllocating() != nil {
		_ = receipt.Close()
		t.Fatal("construct mismatched promotion receipt fixture")
	}
	defer receipt.Close() //nolint:errcheck // Test cleanup has no recovery action.
	receipt.mu.Lock()
	document, err := encodePlanningReceiptLocked(receipt, 3)
	receipt.mu.Unlock()
	if err != nil {
		t.Fatal("encode mismatched promotion receipt fixture")
	}
	return document
}

// assertDurableReceiptPhase checks the exact persisted receipt union phase.
func assertDurableReceiptPhase(t *testing.T, store *JournalStore, want ReceiptPhase) {
	t.Helper()
	receipt, journal, exists, err := store.LoadOperation(t.Context())
	if err != nil || !exists || receipt == nil || journal != nil || receipt.Phase() != want {
		_ = receipt.Close()
		_ = journal.Close()
		t.Fatalf("durable receipt did not retain authoritative phase %s", want)
	}
	_ = receipt.Close()
}

// TestPlanningReceiptCodecAndUnionRejectMalformedDocuments freezes the strict receipt/journal union.
func TestPlanningReceiptCodecAndUnionRejectMalformedDocuments(t *testing.T) {
	onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
	defer closeOnboardingFixture(store, backend, plan)
	receipt, _ := persistReceiptFixture(t, onboarding, backend, store, planningReceiptClaimPending)
	receipt.mu.Lock()
	document, err := encodePlanningReceiptLocked(receipt, receipt.revision)
	receipt.mu.Unlock()
	if err != nil {
		t.Fatal("encode receipt fixture")
	}
	defer clear(document)
	if decoded, err := decodePlanningReceipt(document); err != nil {
		t.Fatal("decode exact receipt")
	} else {
		_ = decoded.Close()
	}
	cases := [][]byte{
		bytes.Replace(document, []byte(`"version":`), []byte(`"unknown":1,"version":`), 1),
		bytes.Replace(document, []byte(`"revision":`), []byte(`"revision":1,"revision":`), 1),
		bytes.Replace(document, []byte(planningReceiptVersion), []byte(journalVersion), 1),
		append(append([]byte(nil), document...), []byte(`{"version":"mixed"}`)...),
	}
	for _, malformed := range cases {
		if decoded, decodeErr := decodePlanningReceipt(malformed); CodeOf(decodeErr) != CodeProtectedInput || decoded != nil {
			t.Fatal("strict receipt codec accepted malformed or mixed document")
		}
		malformedShared := &scriptedProtectedDocument{document: append([]byte(nil), malformed...)}
		malformedOpener := func(context.Context, string, int) (journalProtectedStore, error) {
			return &scriptedProtectedTransaction{shared: malformedShared}, nil
		}
		malformedUnion, openErr := openJournalStore(
			t.Context(), "/protected/malformed-union.json", DefaultLimits(), malformedOpener,
		)
		if openErr != nil {
			t.Fatal("open malformed union fixture")
		}
		if loadedReceipt, loadedJournal, exists, loadErr := malformedUnion.LoadOperation(t.Context()); CodeOf(loadErr) != CodeProtectedInput || exists || loadedReceipt != nil || loadedJournal != nil {
			t.Fatal("strict union accepted duplicate, unknown, mixed, or wrong-tag receipt bytes")
		}
		_ = malformedUnion.Close()
		clear(malformed)
	}
	shared := &scriptedProtectedDocument{document: append([]byte(nil), document...)}
	opener := func(context.Context, string, int) (journalProtectedStore, error) {
		return openScriptedProtectedTransaction(shared)
	}
	union, err := openJournalStore(t.Context(), "/protected/union.json", DefaultLimits(), opener)
	if err != nil {
		t.Fatal("open strict union store")
	}
	defer union.Close() //nolint:errcheck // Test cleanup.
	if loadedReceipt, loadedJournal, exists, loadErr := union.LoadOperation(t.Context()); loadErr != nil || !exists || loadedReceipt == nil || loadedJournal != nil {
		t.Fatal("strict union did not select the exact receipt tag")
	} else {
		_ = loadedReceipt.Close()
	}
}

// TestPlanPersistsClaimPendingBeforeClaimAndAllocatesOnlyAfterAllocatingSync freezes write ordering.
func TestPlanPersistsClaimPendingBeforeClaimAndAllocatesOnlyAfterAllocatingSync(t *testing.T) {
	onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
	defer closeOnboardingFixture(store, backend, plan)
	backend.beforeClaim = func() {
		receipt, journal, exists, err := store.LoadOperation(t.Context())
		if err != nil || !exists || receipt == nil || journal != nil || receipt.Phase() != ReceiptPhaseClaimPending ||
			backend.lockClaimed {
			t.Fatal("Claim ran without durable claim_pending receipt")
		}
		_ = receipt.Close()
	}
	result, err := planOnboarding(t, onboarding, store)
	if err != nil || result.State != StatePlanned || !result.PlanComplete || result.ReceiptPresent ||
		len(backend.events) < 2 || backend.events[0] != "claim" || backend.events[1] != "allocate" {
		t.Fatal("Plan did not preserve receipt, claim, allocation ordering")
	}
}

// TestPlanFailureAfterClaimPersistsReleaseRequiredWithoutRelease freezes the orphan-prevention gate.
func TestPlanFailureAfterClaimPersistsReleaseRequiredWithoutRelease(t *testing.T) {
	onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
	defer closeOnboardingFixture(store, backend, plan)
	backend.collisionErr = errors.New("collision read failed")
	result, err := planOnboarding(t, onboarding, store)
	if CodeOf(err) != CodeReconcileRequired || result.State != "" || result.ReceiptPhase != ReceiptPhaseReleaseRequired ||
		backend.releaseCalls != 0 || !backend.lockClaimed {
		t.Fatal("allocation failure released before durable release_required recovery authority")
	}
	receipt, journal, exists, loadErr := store.LoadOperation(t.Context())
	if loadErr != nil || !exists || receipt == nil || journal != nil || receipt.Phase() != ReceiptPhaseReleaseRequired {
		t.Fatal("allocation failure did not persist release_required receipt")
	}
	_ = receipt.Close()
}

// TestReceiptReconcileRecoveryMatrix freezes exact, unavailable, foreign, and response-lost cleanup.
func TestReceiptReconcileRecoveryMatrix(t *testing.T) {
	t.Run("unresolved exact owner releases and closes", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		_, operation := persistReceiptFixture(t, onboarding, backend, store, planningReceiptUnresolved)
		backend.lockOwner, backend.lockClaimed = operation, true
		result, err := onboarding.Reconcile(t.Context(), store)
		if err != nil || result.ReceiptPhase != ReceiptPhaseClosed || backend.releaseCalls != 1 || backend.lockClaimed {
			t.Fatal("unresolved exact owner did not pass through durable cleanup and close")
		}
	})
	t.Run("release required unavailable is retained without write", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		receipt, _ := persistReceiptFixture(t, onboarding, backend, store, planningReceiptReleaseRequired)
		revision := receipt.Revision()
		_ = receipt.Close()
		backend.observeLockErr = errors.New("backend offline")
		result, err := onboarding.Reconcile(t.Context(), store)
		if CodeOf(err) != CodeReconcileRequired || result.ReceiptPhase != ReceiptPhaseReleaseRequired || backend.releaseCalls != 0 {
			t.Fatal("unavailable observation destroyed release_required lineage")
		}
		loaded, _, _, _ := store.LoadOperation(t.Context())
		defer loaded.Close() //nolint:errcheck // Test cleanup.
		if loaded.Revision() != revision || loaded.Phase() != ReceiptPhaseReleaseRequired {
			t.Fatal("unavailable reconciliation wrote or changed release_required receipt")
		}
	})
	t.Run("release error retains release required", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		receipt, operation := persistReceiptFixture(t, onboarding, backend, store, planningReceiptReleaseRequired)
		revision := receipt.Revision()
		_ = receipt.Close()
		backend.lockOwner, backend.lockClaimed = operation, true
		backend.releaseErr = errors.New("release failed")
		result, err := onboarding.Reconcile(t.Context(), store)
		if CodeOf(err) != CodeReconcileRequired || result.ReceiptPhase != ReceiptPhaseReleaseRequired ||
			backend.releaseCalls != 1 || !backend.lockClaimed {
			t.Fatal("failed Release did not preserve durable release_required authority")
		}
		loaded, _, _, _ := store.LoadOperation(t.Context())
		defer loaded.Close() //nolint:errcheck // Test cleanup.
		if loaded.Revision() != revision || loaded.Phase() != ReceiptPhaseReleaseRequired {
			t.Fatal("failed Release changed receipt revision or phase")
		}
	})
}

// TestReceiptReconcileOwnerlessMatrix freezes exact and unattributed ownerless recovery evidence.
func TestReceiptReconcileOwnerlessMatrix(t *testing.T) {
	t.Run("unresolved ownerless exact closes without release", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		_, _ = persistReceiptFixture(t, onboarding, backend, store, planningReceiptUnresolved)
		result, err := onboarding.Reconcile(t.Context(), store)
		if err != nil || result.ReceiptPhase != ReceiptPhaseClosed || backend.releaseCalls != 0 {
			t.Fatal("typed unresolved ownerless exact recovery did not close without Release")
		}
	})
	t.Run("unresolved ownerless next remains unresolved", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		receipt, _ := persistReceiptFixture(t, onboarding, backend, store, planningReceiptUnresolved)
		revision := receipt.Revision()
		_ = receipt.Close()
		backend.lockRevision++
		result, err := onboarding.Reconcile(t.Context(), store)
		if CodeOf(err) != CodeReconcileRequired || result.ReceiptPhase != ReceiptPhaseUnresolved || backend.releaseCalls != 0 {
			t.Fatal("unattributed ownerless next revision was accepted as unresolved cleanup")
		}
		loaded, _, _, _ := store.LoadOperation(t.Context())
		defer loaded.Close() //nolint:errcheck // Test cleanup.
		if loaded.Revision() != revision || loaded.Phase() != ReceiptPhaseUnresolved {
			t.Fatal("unattributed ownerless next revision changed unresolved evidence")
		}
	})
	t.Run("release required ownerless exact stays open", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		receipt, _ := persistReceiptFixture(t, onboarding, backend, store, planningReceiptReleaseRequired)
		revision := receipt.Revision()
		_ = receipt.Close()
		result, err := onboarding.Reconcile(t.Context(), store)
		if CodeOf(err) != CodeReconcileRequired || result.ReceiptPhase != ReceiptPhaseReleaseRequired || backend.releaseCalls != 0 {
			t.Fatal("ownerless unchanged revision falsely closed release_required")
		}
		loaded, _, _, _ := store.LoadOperation(t.Context())
		defer loaded.Close() //nolint:errcheck // Test cleanup.
		if loaded.Revision() != revision || loaded.Phase() != ReceiptPhaseReleaseRequired {
			t.Fatal("ownerless unchanged release_required evidence was rewritten")
		}
	})
	t.Run("foreign remains unresolved", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		_, _ = persistReceiptFixture(t, onboarding, backend, store, planningReceiptClaimPending)
		foreign, _ := datasourceadmin.NewOperationBinding("aebagbafaydqqcikbmga2dqpca")
		backend.lockOwner, backend.lockClaimed = foreign, true
		result, err := onboarding.Reconcile(t.Context(), store)
		if CodeOf(err) != CodeReconcileRequired || result.ReceiptPhase != ReceiptPhaseUnresolved || backend.releaseCalls != 0 {
			t.Fatal("foreign ownership did not remain unresolved and mutation-free")
		}
	})
}

// TestReceiptAbortAndStatusAreBoundedIdempotentAndReadOnly freezes operator recovery reporting.
func TestReceiptAbortAndStatusAreBoundedIdempotentAndReadOnly(t *testing.T) {
	onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
	defer closeOnboardingFixture(store, backend, plan)
	receipt, _ := persistReceiptFixture(t, onboarding, backend, store, planningReceiptClaimPending)
	before, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal("read receipt bytes")
	}
	status, err := onboarding.Status(t.Context(), store)
	after, readErr := os.ReadFile(store.path)
	if err != nil || readErr != nil || !bytes.Equal(before, after) || status.State != "" || status.Revision != 0 ||
		status.Candidate != "" || status.Current != "" || status.PlanComplete || !status.ReceiptPresent ||
		status.ReceiptPhase != ReceiptPhaseClaimPending || status.LockRelation != LockRelationOwnerlessExact ||
		backend.claimCalls != 0 || backend.releaseCalls != 0 {
		t.Fatal("receipt status synthesized public state or changed durable/backend state")
	}
	clear(before)
	clear(after)
	_ = receipt.Close()
	first, err := onboarding.Abort(t.Context(), store)
	if err != nil || first.ReceiptPhase != ReceiptPhaseClosed || backend.releaseCalls != 0 {
		t.Fatal("ownerless receipt abort did not retain closed tombstone")
	}
	closed, _, _, _ := store.LoadOperation(t.Context())
	revision := closed.Revision()
	_ = closed.Close()
	second, err := onboarding.Abort(t.Context(), store)
	if err != nil || second.ReceiptPhase != ReceiptPhaseClosed || backend.releaseCalls != 0 {
		t.Fatal("closed receipt abort was not idempotent")
	}
	closed, _, _, _ = store.LoadOperation(t.Context())
	defer closed.Close() //nolint:errcheck // Test cleanup.
	if closed.Revision() != revision {
		t.Fatal("closed idempotent abort wrote receipt")
	}
	closedStatus, err := onboarding.Status(t.Context(), store)
	if err != nil || closedStatus.State != "" || closedStatus.PlanComplete || !closedStatus.ReceiptPresent ||
		closedStatus.ReceiptPhase != ReceiptPhaseClosed || closedStatus.LockRelation != LockRelationOwnerlessExact {
		t.Fatal("closed receipt status synthesized public plan state")
	}
}

// TestReceiptAbortHeldClaimRequiresExplicitReconcile freezes separation of abort and cleanup.
func TestReceiptAbortHeldClaimRequiresExplicitReconcile(t *testing.T) {
	onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
	defer closeOnboardingFixture(store, backend, plan)
	_, operation := persistReceiptFixture(t, onboarding, backend, store, planningReceiptAllocating)
	backend.lockOwner, backend.lockClaimed = operation, true
	result, err := onboarding.Abort(t.Context(), store)
	if CodeOf(err) != CodeReconcileRequired || result.ReceiptPhase != ReceiptPhaseReleaseRequired ||
		backend.releaseCalls != 0 || !backend.lockClaimed {
		t.Fatal("receipt abort released a held claim instead of requiring explicit reconcile")
	}
	releaseRequired, _, _, _ := store.LoadOperation(t.Context())
	revision := releaseRequired.Revision()
	_ = releaseRequired.Close()
	result, err = onboarding.Abort(t.Context(), store)
	if CodeOf(err) != CodeReconcileRequired || result.ReceiptPhase != ReceiptPhaseReleaseRequired ||
		backend.releaseCalls != 0 {
		t.Fatal("release_required receipt abort was not strict no-write")
	}
	releaseRequired, _, _, _ = store.LoadOperation(t.Context())
	if releaseRequired.Revision() != revision {
		_ = releaseRequired.Close()
		t.Fatal("release_required abort advanced receipt revision")
	}
	_ = releaseRequired.Close()
	result, err = onboarding.Reconcile(t.Context(), store)
	if err != nil || result.ReceiptPhase != ReceiptPhaseClosed || backend.releaseCalls != 1 || backend.lockClaimed {
		t.Fatal("explicit receipt reconcile did not perform exact gated cleanup")
	}
}

// TestClosedReceiptCASReplacementAndMissingOperationResults freeze tombstone reuse and absent reporting.
func TestClosedReceiptCASReplacementAndMissingOperationResults(t *testing.T) {
	t.Run("closed receipt is CAS replaced by a full plan", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		_, _ = persistReceiptFixture(t, onboarding, backend, store, planningReceiptClosed)
		result, err := planOnboarding(t, onboarding, store)
		if err != nil || result.State != StatePlanned || !result.PlanComplete {
			t.Fatal("exact ownerless closed receipt was not CAS-replaced and promoted")
		}
	})
	t.Run("missing operation has bounded non-none empty-state failures", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		if status, err := onboarding.Status(t.Context(), store); CodeOf(err) == CodeNone || status.State != "" {
			t.Fatal("missing status returned CodeNone or synthetic state")
		}
		if result, err := onboarding.Reconcile(t.Context(), store); CodeOf(err) == CodeNone || result.State != "" || result.PlanComplete {
			t.Fatal("missing reconcile returned CodeNone or synthetic plan")
		}
		if result, err := onboarding.Abort(t.Context(), store); CodeOf(err) == CodeNone || result.State != "" || result.PlanComplete {
			t.Fatal("missing abort returned CodeNone or synthetic plan")
		}
	})
}

// TestReceiptPlanRecoveryMatrix freezes claim-pending, allocating, foreign, and unavailable retries.
func TestReceiptPlanRecoveryMatrix(t *testing.T) {
	for _, state := range []planningReceiptState{planningReceiptClaimPending, planningReceiptAllocating} {
		t.Run(string(state)+" exact owner", func(t *testing.T) {
			onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
			defer closeOnboardingFixture(store, backend, plan)
			_, operation := persistReceiptFixture(t, onboarding, backend, store, state)
			backend.lockOwner, backend.lockClaimed = operation, true
			result, err := planOnboarding(t, onboarding, store)
			if err != nil || result.State != StatePlanned || !result.PlanComplete {
				t.Fatal("exact claimed receipt did not resume to planned journal")
			}
		})
	}
	t.Run("claim pending ownerless claims", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		_, _ = persistReceiptFixture(t, onboarding, backend, store, planningReceiptClaimPending)
		if _, err := planOnboarding(t, onboarding, store); err != nil || backend.claimCalls != 1 {
			t.Fatal("ownerless claim_pending receipt did not acquire exact claim")
		}
	})
	t.Run("allocating ownerless becomes unresolved", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		_, _ = persistReceiptFixture(t, onboarding, backend, store, planningReceiptAllocating)
		result, err := planOnboarding(t, onboarding, store)
		if CodeOf(err) != CodeReconcileRequired || result.ReceiptPhase != ReceiptPhaseUnresolved ||
			backend.claimCalls != 0 || backend.releaseCalls != 0 {
			t.Fatal("ownerless allocating retry resumed without exact claimed authority")
		}
	})
	t.Run("foreign and unavailable become unresolved", func(t *testing.T) {
		for _, unavailable := range []bool{false, true} {
			onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
			_, _ = persistReceiptFixture(t, onboarding, backend, store, planningReceiptClaimPending)
			if unavailable {
				backend.observeLockErr = errors.New("backend offline")
			} else {
				foreign, _ := datasourceadmin.NewOperationBinding("aaaaaaaaaaaaaaaaaaaaaaaaaa")
				backend.lockOwner, backend.lockClaimed = foreign, true
			}
			result, err := planOnboarding(t, onboarding, store)
			if CodeOf(err) != CodeReconcileRequired || result.ReceiptPhase != ReceiptPhaseUnresolved || backend.releaseCalls != 0 {
				t.Fatal("foreign or unavailable receipt retry did not stop unresolved")
			}
			closeOnboardingFixture(store, backend, plan)
		}
	})
}

// TestReceiptCancellationAndStoreCASMatrix freezes finite cancellation and concurrent writer behavior.
func TestReceiptCancellationAndStoreCASMatrix(t *testing.T) {
	t.Run("cancelled before receipt", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		result, err := onboarding.Plan(ctx, store, testIntent(t, provider.AlgorithmEd25519SHA256), planDNSPolicy())
		if CodeOf(err) == CodeNone || result.State != "" || backend.claimCalls != 0 {
			t.Fatal("pre-receipt cancellation created public state or reached Claim")
		}
	})
	t.Run("cancelled at claim retains pre-claim receipt", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		ctx, cancel := context.WithCancel(t.Context())
		backend.beforeClaim = cancel
		result, err := onboarding.Plan(ctx, store, testIntent(t, provider.AlgorithmEd25519SHA256), planDNSPolicy())
		if CodeOf(err) != CodeReconcileRequired || result.State != "" || backend.lockClaimed || backend.releaseCalls != 0 {
			t.Fatal("claim cancellation mutated lock authority or synthesized public state")
		}
		receipt, journal, exists, _ := store.LoadOperation(t.Context())
		defer receipt.Close() //nolint:errcheck // Test cleanup.
		if !exists || receipt == nil || journal != nil || receipt.Phase() != ReceiptPhaseClaimPending {
			t.Fatal("claim cancellation lost durable pre-claim recovery authority")
		}
	})
	t.Run("cancelled after claim requires explicit cleanup", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		ctx, cancel := context.WithCancel(t.Context())
		backend.afterCollision = cancel
		result, err := onboarding.Plan(ctx, store, testIntent(t, provider.AlgorithmEd25519SHA256), planDNSPolicy())
		if CodeOf(err) != CodeReconcileRequired || result.State != "" || !backend.lockClaimed || backend.releaseCalls != 0 {
			t.Fatal("post-claim cancellation released implicitly or synthesized public state")
		}
		if _, reconcileErr := onboarding.Reconcile(t.Context(), store); reconcileErr != nil || backend.lockClaimed {
			t.Fatal("explicit reconcile could not clean a post-claim cancellation")
		}
	})
	t.Run("concurrent owner and stale CAS are rejected", func(t *testing.T) {
		onboarding, backend, store, plan, _ := onboardingCoordinatorFixture(t)
		defer closeOnboardingFixture(store, backend, plan)
		if second, err := OpenJournalStore(t.Context(), store.path, DefaultLimits()); CodeOf(err) != CodeConflict || second != nil {
			t.Fatal("concurrent protected journal owner was accepted")
		}
		receipt, _ := persistReceiptFixture(t, onboarding, backend, store, planningReceiptClaimPending)
		receipt.mu.Lock()
		document, _ := encodePlanningReceiptLocked(receipt, receipt.revision)
		receipt.mu.Unlock()
		stale, err := decodePlanningReceipt(document)
		clear(document)
		if err != nil || receipt.RecordAllocating() != nil || store.SaveReceipt(t.Context(), receipt) != nil {
			t.Fatal("advance CAS fixture")
		}
		defer stale.Close() //nolint:errcheck // Test cleanup.
		if err := store.SaveReceipt(t.Context(), stale); CodeOf(err) != CodeConflict {
			t.Fatal("stale receipt CAS overwrote a newer revision")
		}
	})
}

// persistReceiptFixture stores one exact phase and returns its operation binding.
func persistReceiptFixture(
	t *testing.T,
	onboarding *Onboarding,
	backend *onboardingBackendFake,
	store *JournalStore,
	state planningReceiptState,
) (*PlanningReceipt, datasourceadmin.OperationBinding) {
	t.Helper()
	if _, _, exists, err := store.LoadOperation(t.Context()); err != nil || exists {
		t.Fatal("establish absent receipt fixture")
	}
	operation, err := onboarding.allocator.NewOperation(t.Context())
	if err != nil {
		t.Fatal("allocate receipt operation")
	}
	receipt, err := NewPlanningReceipt(
		datasourceadmin.BackendLDAP, planAuthority(), operation, backend.lockRevision,
		testIntent(t, provider.AlgorithmEd25519SHA256), planDNSPolicy(),
	)
	if err != nil {
		t.Fatal("construct receipt fixture")
	}
	if err := store.SaveReceipt(t.Context(), receipt); err != nil {
		t.Fatal("persist claim_pending receipt fixture")
	}
	switch state {
	case planningReceiptClaimPending:
	case planningReceiptAllocating:
		if receipt.RecordAllocating() != nil || store.SaveReceipt(t.Context(), receipt) != nil {
			t.Fatal("persist allocating receipt fixture")
		}
	case planningReceiptReleaseRequired:
		if receipt.RecordReleaseRequired() != nil || store.SaveReceipt(t.Context(), receipt) != nil {
			t.Fatal("persist release_required receipt fixture")
		}
	case planningReceiptUnresolved:
		if receipt.RecordUnresolved() != nil || store.SaveReceipt(t.Context(), receipt) != nil {
			t.Fatal("persist unresolved receipt fixture")
		}
	case planningReceiptClosed:
		if receipt.RecordClosed() != nil || store.SaveReceipt(t.Context(), receipt) != nil {
			t.Fatal("persist closed receipt fixture")
		}
	default:
		t.Fatal("unsupported receipt fixture phase")
	}
	return receipt, operation
}
