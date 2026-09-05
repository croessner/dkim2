package app

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/propagationtest"
)

const (
	propagationTestTenant      = "tenant-a"
	propagationTestOtherTenant = "tenant-b"
	propagationTestLease       = 2 * time.Minute
	propagationTestRetention   = 10 * time.Minute
)

// kitAuthority binds the test-kit authority to the daemon's authority seam.
type kitAuthority struct{ *propagationtest.Authority }

// Acquire records the acquisition and returns the kit as the lease.
func (a kitAuthority) Acquire(ctx context.Context) (SigningLease, error) {
	if err := a.Open(ctx); err != nil {
		return nil, err
	}
	return a.Authority, nil
}

// fixtureClock is one settable deterministic clock shared by every seam.
type fixtureClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now returns the current fixture instant.
func (c *fixtureClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the fixture instant forward.
func (c *fixtureClock) Advance(delta time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(delta)
}

// propagationObservationRecorder records closed stage and result pairs.
type propagationObservationRecorder struct {
	mu      sync.Mutex
	entries []string
}

// ObservePropagation appends one closed observation.
func (r *propagationObservationRecorder) ObservePropagation(stage, result string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, stage+"="+result)
}

// last returns the most recent observation or an empty string.
func (r *propagationObservationRecorder) last() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) == 0 {
		return ""
	}
	return r.entries[len(r.entries)-1]
}

// propagationFixture composes the real coordinator over the frozen corpus,
// a memory replay store, and the tenant-keyed authority double.
type propagationFixture struct {
	corpus      *propagationtest.Corpus
	provider    *propagationtest.Provider
	verifier    *dkim2.Verifier
	authority   *propagationtest.Authority
	key         propagationtest.SigningKey
	store       *dkim2.ReplayMemoryStore
	deriver     *dkim2.ReplayDeriver
	clock       *fixtureClock
	observer    *propagationObservationRecorder
	coordinator *PropagationCoordinator
}

// newPropagationFixture builds one fixture whose tenant holds local
// authority and a delivery-status profile for local.example.
func newPropagationFixture(t *testing.T) *propagationFixture {
	t.Helper()
	corpus := propagationtest.Load(t)
	provider := corpus.Provider(t)
	key := propagationtest.NewSigningKey(t, propagationtest.LocalDomain)
	provider.Publish(key)
	authority := propagationtest.NewAuthority().AddProfile(propagationTestTenant, key)
	clock := &fixtureClock{now: corpus.Clock()}
	store, err := dkim2.NewReplayMemoryStore(dkim2.ReplayMemoryConfig{
		Limits: dkim2.ReplayLimits{MaxEntries: 64, MaxWaiters: 8, PruneBudget: 8, MaxInFlight: 8, MaxAdmissionWaiters: 8},
		Clock:  dkim2.ReplayClockFunc(clock.Now),
	})
	if err != nil {
		t.Fatalf("memory store: %v", err)
	}
	deriver, err := dkim2.NewReplayDeriver(bytes.Repeat([]byte{0x5a}, 32), 7)
	if err != nil {
		t.Fatalf("deriver: %v", err)
	}
	fixture := &propagationFixture{
		corpus: corpus, provider: provider, verifier: corpus.Verifier(t, provider), authority: authority,
		key: key, store: store, deriver: deriver, clock: clock, observer: &propagationObservationRecorder{},
	}
	fixture.coordinator = fixture.newCoordinator(t, fixture.enabledReplay(t))
	return fixture
}

// enabledReplay constructs the propagation replay policy over the memory store.
func (f *propagationFixture) enabledReplay(t *testing.T) PropagationReplayService {
	t.Helper()
	retention, err := dkim2.NewReplayRetention(propagationTestRetention)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := dkim2.NewReplayLease(propagationTestLease)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := NewPropagationReplayCoordinator(f.deriver, f.store, retention, lease)
	if err != nil {
		t.Fatalf("propagation replay: %v", err)
	}
	return replay
}

// newCoordinator constructs the coordinator over the fixture seams.
func (f *propagationFixture) newCoordinator(t *testing.T, replay PropagationReplayService) *PropagationCoordinator {
	t.Helper()
	coordinator, err := NewPropagationCoordinator(PropagationDependencies{
		Verifier: f.verifier, Evaluator: f.verifier, PublicKeys: f.provider,
		Authority: kitAuthority{f.authority}, Policy: config.SigningFlagPolicyConfig{},
		Replay: replay, TokenRetention: propagationTestRetention, Clock: f.clock.Now,
	})
	if err != nil {
		t.Fatalf("coordinator: %v", err)
	}
	coordinator.attachObservability(f.observer)
	return coordinator
}

// request builds the propagation request of one corpus case for the tenant.
func (f *propagationFixture) request(t *testing.T, name, tenant string) PropagationRequest {
	t.Helper()
	testCase := f.corpus.Case(t, name)
	request, err := NewPropagationRequest(
		testCase.RawMessage(t), []byte("<>"), [][]byte{testCase.ForwardPath(t)}, false,
		tenant, propagationtest.ReportingMTA, FidelityLMTPDeliveredCRLF,
	)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return request
}

// propagate runs one propagation and requires a coherent result.
func (f *propagationFixture) propagate(t *testing.T, request PropagationRequest) PropagationResult {
	t.Helper()
	result, err := f.coordinator.Propagate(context.Background(), request)
	if err != nil || !result.Valid() {
		t.Fatalf("Propagate() valid=%t error=%v", result.Valid(), err)
	}
	return result
}

// requireOutcome asserts the closed result, disposition, and failure triple.
func requireOutcome(t *testing.T, result PropagationResult, want PropagationResultClass, disposition PropagationDispositionClass, failure PropagationFailureClass) {
	t.Helper()
	if result.Result() != want || result.Disposition() != disposition || result.Failure() != failure {
		t.Fatalf("outcome = %s/%s/%q, want %s/%s/%q", result.Result(), result.Disposition(), result.Failure(), want, disposition, failure)
	}
}

// TestPropagateEligibleNotificationIsRebuiltSignedAndCommitted proves the
// complete accept path: the derived signing domain, the authenticated next
// hop, the signed bytes that verify with the generic verifier, the
// coordinate-bound commit token, and the idempotent commit.
func TestPropagateEligibleNotificationIsRebuiltSignedAndCommitted(t *testing.T) {
	fixture := newPropagationFixture(t)
	testCase := fixture.corpus.Case(t, propagationtest.CaseRunOfOne)
	result := fixture.propagate(t, fixture.request(t, propagationtest.CaseRunOfOne, propagationTestTenant))
	requireOutcome(t, result, PropagationPass, PropagationDispositionAccept, PropagationFailureNone)
	if result.Replay() != ReplayResultFirstSeen || result.Projection().Propagation() != dkim2.ReceivedDSNPropagationEligible {
		t.Fatalf("replay=%v propagation=%q", result.Replay(), result.Projection().Propagation())
	}
	output, ok := result.Output()
	if !ok || !bytes.Equal(output.NextHopRecipient(), testCase.ExpectedNextHop(t)) || output.SMTPUTF8Required() ||
		!ValidPropagationCommitToken(output.CommitToken()) {
		t.Fatalf("output present=%t next=%q token=%q", ok, output.NextHopRecipient(), output.CommitToken())
	}
	if fixture.authority.Signs.Load() != 1 {
		t.Fatalf("signs = %d, want 1", fixture.authority.Signs.Load())
	}
	assessment, err := fixture.verifier.Assess(context.Background(), dkim2.NewVerifyRequest(
		output.RawMessage(), []byte("<>"), [][]byte{output.NextHopRecipient()},
	))
	if err != nil || !assessment.Applicable() {
		t.Fatalf("propagated assessment applicable=%t error=%v", assessment.Applicable(), err)
	}
	verification, ok := assessment.Verification()
	if !ok || verification.State() != dkim2.ResultStatePASS {
		t.Fatalf("propagated verification state=%q", verification.State())
	}
	if fixture.observer.last() != "completed=accept" {
		t.Fatalf("last observation = %q", fixture.observer.last())
	}
	state, err := fixture.coordinator.CommitPropagation(context.Background(), output.CommitToken())
	if err != nil || state != PropagationCommitCommitted {
		t.Fatalf("commit state=%q error=%v", state, err)
	}
	if state, err := fixture.coordinator.CommitPropagation(context.Background(), output.CommitToken()); err != nil || state != PropagationCommitCommitted {
		t.Fatalf("second commit state=%q error=%v", state, err)
	}
	if fixture.observer.last() != "completed=accept" {
		t.Fatalf("commit observation = %q", fixture.observer.last())
	}
	replayed := fixture.propagate(t, fixture.request(t, propagationtest.CaseRunOfOne, propagationTestTenant))
	requireOutcome(t, replayed, PropagationPass, PropagationDispositionDiscard, PropagationFailureNone)
	if replayed.Replay() != ReplayResultReplayed || fixture.authority.Signs.Load() != 1 {
		t.Fatalf("committed coordinate replay=%v signs=%d", replayed.Replay(), fixture.authority.Signs.Load())
	}
	if fixture.observer.last() != "replay=discard" {
		t.Fatalf("discard observation = %q", fixture.observer.last())
	}
}

// TestPropagateTwoPhaseReplayLeaseAndCommitSemantics proves the pending
// lease: a preceding process record does not block the first propagation, a
// live lease defers, an expired lease is re-served with a fresh rebuild and
// the same coordinate-bound token, and a superseded token still commits.
func TestPropagateTwoPhaseReplayLeaseAndCommitSemantics(t *testing.T) {
	fixture := newPropagationFixture(t)
	request := fixture.request(t, propagationtest.CaseRunOfOne, propagationTestTenant)
	assessment, err := fixture.verifier.Assess(context.Background(), dkim2.NewVerifyRequest(
		request.RawMessage(), request.OuterReversePath(), request.OuterRecipients(),
	))
	if err != nil || !assessment.Applicable() {
		t.Fatalf("outer assessment error=%v", err)
	}
	verification, _ := assessment.Verification()
	identities, err := dkim2.ReplayIdentities(verification)
	if err != nil || identities.Len() != 1 {
		t.Fatalf("identities=%d error=%v", identities.Len(), err)
	}
	identity, _ := identities.Identity(0)
	processKey, err := fixture.deriver.Derive(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	retention, _ := dkim2.NewReplayRetention(propagationTestRetention)
	if check, err := fixture.store.CheckAndRemember(context.Background(), processKey, retention); err != nil || check != dkim2.ReplayCheckFirstSeen {
		t.Fatalf("process record check=%v error=%v", check, err)
	}
	first := fixture.propagate(t, request)
	requireOutcome(t, first, PropagationPass, PropagationDispositionAccept, PropagationFailureNone)
	firstOutput, _ := first.Output()
	live := fixture.propagate(t, request)
	requireOutcome(t, live, PropagationTemperror, PropagationDispositionTempfail, PropagationFailureNone)
	if live.Replay() != ReplayResultIndeterminate || fixture.authority.Signs.Load() != 1 {
		t.Fatalf("live lease replay=%v signs=%d", live.Replay(), fixture.authority.Signs.Load())
	}
	if fixture.observer.last() != "replay=tempfail" {
		t.Fatalf("live lease observation = %q", fixture.observer.last())
	}
	fixture.clock.Advance(propagationTestLease + time.Second)
	reserved := fixture.propagate(t, request)
	requireOutcome(t, reserved, PropagationPass, PropagationDispositionAccept, PropagationFailureNone)
	secondOutput, _ := reserved.Output()
	if fixture.authority.Signs.Load() != 2 || bytes.Equal(firstOutput.RawMessage(), secondOutput.RawMessage()) {
		t.Fatalf("expired lease re-serve signs=%d identical=%t", fixture.authority.Signs.Load(), bytes.Equal(firstOutput.RawMessage(), secondOutput.RawMessage()))
	}
	if firstOutput.CommitToken() == secondOutput.CommitToken() || !ValidPropagationCommitToken(secondOutput.CommitToken()) {
		t.Fatal("re-served attempt did not issue a fresh contract token")
	}
	if check, err := fixture.store.CheckAndRemember(context.Background(), processKey, retention); err != nil || check != dkim2.ReplayCheckReplayed {
		t.Fatalf("process record after propagation check=%v error=%v", check, err)
	}
	if state, err := fixture.coordinator.CommitPropagation(context.Background(), firstOutput.CommitToken()); err != nil || state != PropagationCommitCommitted {
		t.Fatalf("superseded token commit state=%q error=%v", state, err)
	}
	after := fixture.propagate(t, request)
	requireOutcome(t, after, PropagationPass, PropagationDispositionDiscard, PropagationFailureNone)
}

// TestPropagateCommitUnresolvedTokens proves malformed, unknown, expired,
// and restart-orphaned tokens are unresolved without touching the store.
func TestPropagateCommitUnresolvedTokens(t *testing.T) {
	fixture := newPropagationFixture(t)
	for name, token := range map[string]string{
		"malformed": "not base64url!", "short": "AAAA", "unknown": strings.Repeat("A", 43),
	} {
		if state, err := fixture.coordinator.CommitPropagation(context.Background(), token); err != nil || state != PropagationCommitUnresolved {
			t.Fatalf("%s token state=%q error=%v", name, state, err)
		}
	}
	if fixture.observer.last() != "replay=tempfail" {
		t.Fatalf("unresolved observation = %q", fixture.observer.last())
	}
	result := fixture.propagate(t, fixture.request(t, propagationtest.CaseRunOfOne, propagationTestTenant))
	output, _ := result.Output()
	restarted := fixture.newCoordinator(t, fixture.enabledReplay(t))
	if state, err := restarted.CommitPropagation(context.Background(), output.CommitToken()); err != nil || state != PropagationCommitUnresolved {
		t.Fatalf("token after restart state=%q error=%v", state, err)
	}
	fixture.clock.Advance(propagationTestLease + time.Second)
	reserved, err := restarted.Propagate(context.Background(), fixture.request(t, propagationtest.CaseRunOfOne, propagationTestTenant))
	if err != nil {
		t.Fatal(err)
	}
	requireOutcome(t, reserved, PropagationPass, PropagationDispositionAccept, PropagationFailureNone)
	fresh, _ := reserved.Output()
	if fresh.CommitToken() == output.CommitToken() {
		t.Fatal("restarted daemon reused a token it cannot have retained")
	}
	if state, err := restarted.CommitPropagation(context.Background(), fresh.CommitToken()); err != nil || state != PropagationCommitCommitted {
		t.Fatalf("fresh token commit state=%q error=%v", state, err)
	}
	fixture.clock.Advance(propagationTestRetention + time.Second)
	if state, err := restarted.CommitPropagation(context.Background(), fresh.CommitToken()); err != nil || state != PropagationCommitUnresolved {
		t.Fatalf("token past retention state=%q error=%v", state, err)
	}
}

// TestPropagateConcurrentRequestsYieldExactlyOneAccept proves N concurrent
// copies of one notification obtain one accept and N-1 deferrals.
func TestPropagateConcurrentRequestsYieldExactlyOneAccept(t *testing.T) {
	fixture := newPropagationFixture(t)
	request := fixture.request(t, propagationtest.CaseRunOfOne, propagationTestTenant)
	const copies = 8
	results := make([]PropagationResult, copies)
	var wait sync.WaitGroup
	for index := range copies {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := fixture.coordinator.Propagate(context.Background(), request)
			if err == nil {
				results[index] = result
			}
		}()
	}
	wait.Wait()
	accepts, deferrals := 0, 0
	for _, result := range results {
		switch {
		case result.Valid() && result.Disposition() == PropagationDispositionAccept:
			accepts++
		case result.Valid() && result.Disposition() == PropagationDispositionTempfail:
			deferrals++
		default:
			t.Fatalf("unexpected concurrent outcome valid=%t disposition=%q", result.Valid(), result.Disposition())
		}
	}
	if accepts != 1 || deferrals != copies-1 || fixture.authority.Signs.Load() != 1 {
		t.Fatalf("accepts=%d deferrals=%d signs=%d", accepts, deferrals, fixture.authority.Signs.Load())
	}
}

// TestPropagateCoherenceMatrixOverCorpus proves the matrix rows the corpus
// reaches: not_local is rejected on this route, a null previous sender is
// discarded, an unreconstructable previous hop is permerror, an
// unprovisioned local domain is permerror with its own failure class, and a
// second tenant sees the same domain as not local. Invalid input never
// reaches a private key.
func TestPropagateCoherenceMatrixOverCorpus(t *testing.T) {
	fixture := newPropagationFixture(t)
	forwardKey := propagationtest.NewSigningKey(t, propagationtest.ForwardDomain)
	fixture.provider.Publish(forwardKey)
	fixture.authority.AddLocal(propagationTestTenant, propagationtest.ForwardDomain)
	cases := []struct {
		name        string
		testCase    string
		tenant      string
		result      PropagationResultClass
		disposition PropagationDispositionClass
		failure     PropagationFailureClass
		localHop    dkim2.ReceivedDSNLocalHop
		observation string
	}{
		{
			name: "not_local rejects", testCase: propagationtest.CaseRunOfOne, tenant: propagationTestOtherTenant,
			result: PropagationFail, disposition: PropagationDispositionReject, failure: PropagationFailureNone,
			localHop: dkim2.ReceivedDSNLocalHopNotLocal, observation: "evaluation=reject",
		},
		{
			name: "null previous sender discards", testCase: propagationtest.CaseNullPreviousSender, tenant: propagationTestTenant,
			result: PropagationPass, disposition: PropagationDispositionDiscard, failure: PropagationFailureNone,
			localHop: dkim2.ReceivedDSNLocalHopLocal, observation: "evaluation=discard",
		},
		{
			name: "unreconstructable previous hop is permerror", testCase: propagationtest.CasePreviousHopUnverified, tenant: propagationTestTenant,
			result: PropagationPermerror, disposition: PropagationDispositionDiscard, failure: PropagationFailureNotReconstructable,
			localHop: dkim2.ReceivedDSNLocalHopLocal, observation: "rebuild=discard",
		},
		{
			name: "unprovisioned local domain is permerror", testCase: propagationtest.CaseNextDomainRun, tenant: propagationTestTenant,
			result: PropagationPermerror, disposition: PropagationDispositionDiscard, failure: PropagationFailureUnprovisionedDomain,
			localHop: dkim2.ReceivedDSNLocalHopLocal, observation: "signing_domain=discard",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			before := fixture.authority.Signs.Load()
			result := fixture.propagate(t, fixture.request(t, testCase.testCase, testCase.tenant))
			requireOutcome(t, result, testCase.result, testCase.disposition, testCase.failure)
			if result.Projection().LocalHop() != testCase.localHop {
				t.Fatalf("local_hop = %q, want %q", result.Projection().LocalHop(), testCase.localHop)
			}
			if _, present := result.Output(); present {
				t.Fatal("refused propagation carried output")
			}
			if fixture.authority.Signs.Load() != before {
				t.Fatal("refused propagation reached the private key")
			}
			if fixture.observer.last() != testCase.observation {
				t.Fatalf("observation = %q, want %q", fixture.observer.last(), testCase.observation)
			}
		})
	}
	if fixture.authority.Signs.Load() != 0 {
		t.Fatalf("signs = %d, want 0", fixture.authority.Signs.Load())
	}
}

// TestPropagateTemporaryConditionsDefer proves a datasource outage, a
// temporary key failure, and an unusable replay store are deferred without
// signing or burning a reservation.
func TestPropagateTemporaryConditionsDefer(t *testing.T) {
	t.Run("datasource outage", func(t *testing.T) {
		fixture := newPropagationFixture(t)
		fixture.authority.SetOutage(true)
		result := fixture.propagate(t, fixture.request(t, propagationtest.CaseRunOfOne, propagationTestTenant))
		requireOutcome(t, result, PropagationTemperror, PropagationDispositionTempfail, PropagationFailureNone)
		if result.Projection().LocalHop() != dkim2.ReceivedDSNLocalHopTemperror || result.Replay() != ReplayResultNotChecked {
			t.Fatalf("local_hop=%q replay=%v", result.Projection().LocalHop(), result.Replay())
		}
		fixture.authority.SetOutage(false)
		recovered := fixture.propagate(t, fixture.request(t, propagationtest.CaseRunOfOne, propagationTestTenant))
		requireOutcome(t, recovered, PropagationPass, PropagationDispositionAccept, PropagationFailureNone)
	})
	t.Run("temporary key failure", func(t *testing.T) {
		fixture := newPropagationFixture(t)
		fixture.provider.FailTemporarily("remote.example")
		result := fixture.propagate(t, fixture.request(t, propagationtest.CaseRunOfOne, propagationTestTenant))
		requireOutcome(t, result, PropagationTemperror, PropagationDispositionTempfail, PropagationFailureNone)
		if fixture.authority.Signs.Load() != 0 {
			t.Fatal("temporary key failure reached the private key")
		}
	})
	t.Run("replay store unusable", func(t *testing.T) {
		fixture := newPropagationFixture(t)
		if err := fixture.store.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		result := fixture.propagate(t, fixture.request(t, propagationtest.CaseRunOfOne, propagationTestTenant))
		requireOutcome(t, result, PropagationTemperror, PropagationDispositionTempfail, PropagationFailureNone)
		if result.Replay() != ReplayResultIndeterminate || fixture.authority.Signs.Load() != 0 {
			t.Fatalf("replay=%v signs=%d", result.Replay(), fixture.authority.Signs.Load())
		}
	})
}

// TestPropagateWithDisabledReplayStillCommits proves explicitly disabled
// replay storage yields accept with a detached token that commits.
func TestPropagateWithDisabledReplayStillCommits(t *testing.T) {
	fixture := newPropagationFixture(t)
	coordinator := fixture.newCoordinator(t, NewDisabledPropagationReplayCoordinator())
	result, err := coordinator.Propagate(context.Background(), fixture.request(t, propagationtest.CaseRunOfOne, propagationTestTenant))
	if err != nil {
		t.Fatal(err)
	}
	requireOutcome(t, result, PropagationPass, PropagationDispositionAccept, PropagationFailureNone)
	if result.Replay() != ReplayResultDisabled {
		t.Fatalf("replay = %v", result.Replay())
	}
	output, _ := result.Output()
	if state, err := coordinator.CommitPropagation(context.Background(), output.CommitToken()); err != nil || state != PropagationCommitCommitted {
		t.Fatalf("detached commit state=%q error=%v", state, err)
	}
}

// TestPropagateSMTPUTF8RequirementIsReported proves the transport fact of a
// rebuilt notification with a non-ASCII header field.
func TestPropagateSMTPUTF8RequirementIsReported(t *testing.T) {
	fixture := newPropagationFixture(t)
	result := fixture.propagate(t, fixture.request(t, propagationtest.CaseSMTPUTF8Header, propagationTestTenant))
	requireOutcome(t, result, PropagationPass, PropagationDispositionAccept, PropagationFailureNone)
	output, _ := result.Output()
	if !output.SMTPUTF8Required() {
		t.Fatal("smtputf8_required was not reported")
	}
}

// TestPropagationCoordinatorConstructionAndContext proves construction
// refuses missing dependencies and that cancellation is preserved.
func TestPropagationCoordinatorConstructionAndContext(t *testing.T) {
	fixture := newPropagationFixture(t)
	if _, err := NewPropagationCoordinator(PropagationDependencies{}); err == nil {
		t.Fatal("empty dependencies accepted")
	}
	if _, err := NewPropagationCoordinator(PropagationDependencies{
		Verifier: fixture.verifier, Evaluator: fixture.verifier, PublicKeys: fixture.provider,
		Authority: kitAuthority{fixture.authority}, Replay: fixture.enabledReplay(t),
	}); err == nil {
		t.Fatal("zero token retention accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fixture.coordinator.Propagate(cancelled, fixture.request(t, propagationtest.CaseRunOfOne, propagationTestTenant)); err == nil {
		t.Fatal("cancelled propagation succeeded")
	}
	if _, err := fixture.coordinator.CommitPropagation(cancelled, strings.Repeat("A", 43)); err == nil {
		t.Fatal("cancelled commit succeeded")
	}
	if _, err := fixture.coordinator.Propagate(context.Background(), PropagationRequest{}); err == nil {
		t.Fatal("invalid request accepted")
	}
	var nilCoordinator *PropagationCoordinator
	if _, err := nilCoordinator.Propagate(context.Background(), fixture.request(t, propagationtest.CaseRunOfOne, propagationTestTenant)); err == nil {
		t.Fatal("nil coordinator propagated")
	}
	formatted := nilCoordinator.String() + nilCoordinator.GoString()
	if !strings.Contains(formatted, propagationRedacted) {
		t.Fatal("coordinator diagnostics are not content-free")
	}
}

// TestPropagateRejectsNotApplicableAndOmitsTheProjection is the reproducer
// for the first matrix row: a notification that carries no DKIM2 field family
// is nothing this route can propagate. It must be a permanent fail/reject,
// never a temporary defer, and it must omit the projection instead of
// claiming a malformed structure that was never assessed. The same omission
// applies to an outer assessment the route could not read at all, which stays
// temporary.
func TestPropagateRejectsNotApplicableAndOmitsTheProjection(t *testing.T) {
	fixture := newPropagationFixture(t)
	testCase := fixture.corpus.Case(t, propagationtest.CaseRunOfOne)
	raw := testCase.RawMessage(t)
	stripped := stripDKIM2Fields(t, raw)
	request, err := NewPropagationRequest(stripped, []byte("<>"), [][]byte{testCase.ForwardPath(t)},
		false, propagationTestTenant, propagationtest.ReportingMTA, FidelityLMTPDeliveredCRLF)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	result := fixture.propagate(t, request)
	if observed := fixture.observer.last(); observed != propagationStageEvaluation+"="+string(PropagationDispositionReject) {
		t.Fatalf("observation = %q, want the evaluation stage rejecting the notification", observed)
	}
	if result.Result() != PropagationFail || result.Disposition() != PropagationDispositionReject {
		t.Fatalf("result=%q disposition=%q, want fail/reject", result.Result(), result.Disposition())
	}
	if !result.Projection().Absent() {
		t.Fatal("a notification that was never evaluated carried a projection")
	}
	if _, present := result.Output(); present {
		t.Fatal("a rejected notification carried signed output")
	}
	if result.Replay() != ReplayResultNotChecked {
		t.Fatalf("replay = %v, want not_checked", result.Replay())
	}
	if fixture.authority.Signs.Load() != 0 {
		t.Fatal("a not-applicable notification reached the private key")
	}
	unevaluated, err := fixture.coordinator.unevaluatedResult()
	if err != nil || unevaluated.Result() != PropagationTemperror ||
		unevaluated.Disposition() != PropagationDispositionTempfail || !unevaluated.Projection().Absent() {
		t.Fatalf("unevaluated result=%q disposition=%q absent=%t error=%v",
			unevaluated.Result(), unevaluated.Disposition(), unevaluated.Projection().Absent(), err)
	}
	if _, err := NewPropagationResult(PropagationPass, PropagationDispositionDiscard,
		PropagationFailureNone, DeliveryStatusProjection{}, ReplayResultReplayed,
		PropagationOutput{}); err == nil {
		t.Fatal("an evaluated outcome was sealed without its projection")
	}
}

// stripDKIM2Fields removes every DKIM2 protocol field from a notification's
// top-level header block so that the outer assessment is not applicable.
func stripDKIM2Fields(t *testing.T, raw []byte) []byte {
	t.Helper()
	boundary := bytes.Index(raw, []byte("\r\n\r\n"))
	if boundary < 0 {
		t.Fatal("the notification has no top-level header block")
	}
	var kept [][]byte
	skipping := false
	for _, line := range bytes.Split(raw[:boundary], []byte("\r\n")) {
		continuation := len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
		if !continuation {
			lowered := bytes.ToLower(line)
			skipping = bytes.HasPrefix(lowered, []byte("dkim2-signature:")) ||
				bytes.HasPrefix(lowered, []byte("message-instance:"))
		}
		if !skipping {
			kept = append(kept, line)
		}
	}
	header := bytes.Join(kept, []byte("\r\n"))
	if bytes.Contains(bytes.ToLower(header), []byte("dkim2-signature:")) ||
		bytes.Contains(bytes.ToLower(header), []byte("message-instance:")) {
		t.Fatal("the stripped notification still carries a DKIM2 field")
	}
	return append(header, raw[boundary:]...)
}

// TestPropagationSharesTheTenantAuthorityAcrossRequests proves the bounded
// negative cache of a tenant's local-authority resolver spans requests and
// routes. Constructing a fresh resolver per request threw the cache away, so
// every foreign notification cost one datasource read per hop domain no
// matter how many identical notifications arrived.
func TestPropagationSharesTheTenantAuthorityAcrossRequests(t *testing.T) {
	fixture := newPropagationFixture(t)
	authorities, err := NewLocalAuthorityRegistry(kitAuthority{fixture.authority}, fixture.clock.Now)
	if err != nil {
		t.Fatalf("authority registry: %v", err)
	}
	coordinator, err := NewPropagationCoordinator(PropagationDependencies{
		Verifier: fixture.verifier, Evaluator: fixture.verifier, PublicKeys: fixture.provider,
		Authority: kitAuthority{fixture.authority}, Authorities: authorities,
		Policy: config.SigningFlagPolicyConfig{}, Replay: fixture.enabledReplay(t),
		TokenRetention: propagationTestRetention, Clock: fixture.clock.Now,
	})
	if err != nil {
		t.Fatalf("coordinator: %v", err)
	}
	binding, err := NewReceivedDSNBinding(fixture.verifier, authorities, "")
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	request := fixture.request(t, propagationtest.CaseRunOfOne, propagationTestOtherTenant)
	first, err := coordinator.Propagate(context.Background(), request)
	if err != nil || first.Result() != PropagationFail {
		t.Fatalf("first foreign propagation result=%q error=%v", first.Result(), err)
	}
	probes := fixture.authority.AuthorityProbes.Load()
	if probes == 0 {
		t.Fatal("the first foreign notification never reached the datasource")
	}
	second, err := coordinator.Propagate(context.Background(), request)
	if err != nil || second.Result() != PropagationFail {
		t.Fatalf("second foreign propagation result=%q error=%v", second.Result(), err)
	}
	if repeated := fixture.authority.AuthorityProbes.Load(); repeated != probes {
		t.Fatalf("the negative cache did not span requests: probes %d then %d", probes, repeated)
	}
	resolver, err := binding.resolverFor(propagationTestOtherTenant)
	if err != nil {
		t.Fatalf("binding resolver: %v", err)
	}
	shared, ok := resolver.(*LocalAuthorityResolver)
	if !ok || shared.negativeCacheSize() == 0 {
		t.Fatal("the process binding does not share the propagation route's tenant resolver")
	}
}
