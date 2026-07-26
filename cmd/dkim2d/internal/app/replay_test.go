package app

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
)

const replayTestTimestamp = int64(1_700_000_000)

type replayTestProvider struct {
	key *rsa.PublicKey
	err error
}

// LookupPublicKey returns one synthetic public key or bounded provider failure.
func (p replayTestProvider) LookupPublicKey(
	context.Context,
	dkim2.PublicKeyQuery,
) (dkim2.PublicKeyResult, error) {
	if p.err != nil {
		return dkim2.PublicKeyResult{}, p.err
	}
	return dkim2.FoundRSAPublicKey(p.key), nil
}

type recordingReplayDeriver struct {
	inner     *dkim2.ReplayDeriver
	failAt    int
	invalidAt int
	after     func(int)
	calls     atomic.Int64
	mu        sync.Mutex
	storage   []string
}

// Derive records deterministic opaque-key order and injects bounded failures.
func (d *recordingReplayDeriver) Derive(
	ctx context.Context,
	identity dkim2.ReplayIdentity,
) (dkim2.ReplayKey, error) {
	index := int(d.calls.Add(1) - 1)
	if index == d.failAt {
		if d.after != nil {
			d.after(index)
		}
		return dkim2.ReplayKey{}, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	if index == d.invalidAt {
		if d.after != nil {
			d.after(index)
		}
		return dkim2.ReplayKey{}, nil
	}
	key, err := d.inner.Derive(ctx, identity)
	if err == nil {
		var storage string
		if useErr := dkim2.UseReplayStorageKey(key, func(value string) error {
			storage = value
			return nil
		}); useErr != nil {
			return dkim2.ReplayKey{}, useErr
		}
		d.mu.Lock()
		d.storage = append(d.storage, storage)
		d.mu.Unlock()
	}
	if d.after != nil {
		d.after(index)
	}
	return key, err
}

// Calls returns the exact number of derivation attempts.
func (d *recordingReplayDeriver) Calls() int { return int(d.calls.Load()) }

// Storage returns the derived opaque storage sequence without sharing caller mutation.
func (d *recordingReplayDeriver) Storage() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.storage...)
}

type replayStoreResponse struct {
	check dkim2.ReplayCheck
	err   error
}

type recordingReplayStore struct {
	mu        sync.Mutex
	responses []replayStoreResponse
	before    func(int, context.Context)
	calls     int
	storage   []string
}

// CheckAndRemember records sequential key order and returns one scripted pair.
func (s *recordingReplayStore) CheckAndRemember(
	ctx context.Context,
	key dkim2.ReplayKey,
	_ dkim2.ReplayRetention,
) (dkim2.ReplayCheck, error) {
	s.mu.Lock()
	index := s.calls
	s.calls++
	s.mu.Unlock()

	if s.before != nil {
		s.before(index, ctx)
	}
	var storage string
	if err := dkim2.UseReplayStorageKey(key, func(value string) error {
		storage = value
		return nil
	}); err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.storage = append(s.storage, storage)
	var response replayStoreResponse
	if index < len(s.responses) {
		response = s.responses[index]
	} else {
		response.check = dkim2.ReplayCheckFirstSeen
	}
	s.mu.Unlock()
	return response.check, response.err
}

// Calls returns the exact number of store invocations.
func (s *recordingReplayStore) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// Storage returns the observed protected-key order without sharing mutation.
func (s *recordingReplayStore) Storage() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.storage...)
}

type typedNilReplayDeriver struct{}

// Derive satisfies the narrow seam for typed-nil construction tests.
func (*typedNilReplayDeriver) Derive(
	context.Context,
	dkim2.ReplayIdentity,
) (dkim2.ReplayKey, error) {
	return dkim2.ReplayKey{}, nil
}

type typedNilReplayStore struct{}

// CheckAndRemember satisfies the replay store seam for typed-nil tests.
func (*typedNilReplayStore) CheckAndRemember(
	context.Context,
	dkim2.ReplayKey,
	dkim2.ReplayRetention,
) (dkim2.ReplayCheck, error) {
	return 0, nil
}

// TestReplayCoordinatorAcceptsFrozenGoldenPass proves the checked-in protocol vector reaches replay.
func TestReplayCoordinatorAcceptsFrozenGoldenPass(t *testing.T) {
	domain := goldenReplayDomain(t, config.PolicyStrict)
	coordinator, store := scriptedReplayCoordinator(t, []replayStoreResponse{{
		check: dkim2.ReplayCheckFirstSeen,
	}})
	outcome, coordinateErr := coordinator.Coordinate(context.Background(), domain)
	assertReplayOutcome(t, outcome, coordinateErr, ReplayResultFirstSeen, FinalDispositionAccept, true)
	if store.Calls() != 1 {
		t.Fatal("frozen golden PASS did not process its complete replay identity set")
	}
}

// TestReplayCoordinatorPreservesAuthenticThreeRecipientOrder proves sealed ordering and derive-before-store.
func TestReplayCoordinatorPreservesAuthenticThreeRecipientOrder(t *testing.T) {
	recipients := [][]byte{
		[]byte("<third@example.test>"),
		[]byte("<first@example.test>"),
		[]byte("<second@example.test>"),
	}
	domain := authenticReplayDomain(t, recipients, config.PolicyStrict)
	verification, err := domain.Verification()
	if err != nil {
		t.Fatal("authentic domain omitted verification")
	}
	secret := replayTestSecret()
	expected := expectedReplayStorageOrder(t, verification, secret, 7)
	if len(expected) != 3 {
		t.Fatal("authentic replay projection omitted recipients")
	}

	inner, err := dkim2.NewReplayDeriver(secret, 7)
	if err != nil {
		t.Fatal("replay deriver construction failed")
	}
	t.Cleanup(func() { _ = inner.Close(context.Background()) })
	deriver := &recordingReplayDeriver{inner: inner, failAt: -1, invalidAt: -1}
	store := &recordingReplayStore{}
	store.before = func(index int, _ context.Context) {
		if index == 0 && deriver.Calls() != 3 {
			t.Error("store ran before every identity was derived")
		}
	}
	coordinator := mustReplayCoordinator(t, deriver, store)
	outcome, coordinateErr := coordinator.Coordinate(context.Background(), domain)
	assertReplayOutcome(t, outcome, coordinateErr, ReplayResultFirstSeen, FinalDispositionAccept, true)
	if !equalReplayStorage(expected, deriver.Storage()) ||
		!equalReplayStorage(expected, store.Storage()) || store.Calls() != 3 {
		t.Fatal("coordinator changed canonical identity or store order")
	}
}

// TestReplayCoordinatorGateAndDisabledPerformNoWork proves output-neutral gate behavior.
func TestReplayCoordinatorGateAndDisabledPerformNoWork(t *testing.T) {
	recipients := [][]byte{[]byte("<gate@example.test>")}
	passStrict := authenticReplayDomain(t, recipients, config.PolicyStrict)
	passTesting := authenticReplayDomain(t, recipients, config.PolicyTesting)
	malformedStrict := malformedReplayDomain(t, config.PolicyStrict)
	malformedPermissive := malformedReplayDomain(t, config.PolicyPermissive)
	malformedTesting := malformedReplayDomain(t, config.PolicyTesting)
	failedStrict := failedReplayDomain(t, recipients, config.PolicyStrict)
	temporaryStrict := temporaryReplayDomain(t, recipients, config.PolicyStrict)

	inner, err := dkim2.NewReplayDeriver(replayTestSecret(), 1)
	if err != nil {
		t.Fatal("replay deriver construction failed")
	}
	t.Cleanup(func() { _ = inner.Close(context.Background()) })
	deriver := &recordingReplayDeriver{inner: inner, failAt: -1, invalidAt: -1}
	store := &recordingReplayStore{}
	enabled := mustReplayCoordinator(t, deriver, store)

	for _, test := range []struct {
		name        string
		domain      DomainResult
		disposition FinalDisposition
	}{
		{"pass testing", passTesting, FinalDispositionContinue},
		{"permerror strict", malformedStrict, FinalDispositionReject},
		{"permerror permissive", malformedPermissive, FinalDispositionAccept},
		{"permerror testing", malformedTesting, FinalDispositionContinue},
		{"fail strict", failedStrict, FinalDispositionReject},
		{"temperror strict", temporaryStrict, FinalDispositionTempfail},
	} {
		t.Run(test.name, func(t *testing.T) {
			beforeDerives := deriver.Calls()
			beforeStores := store.Calls()
			outcome, coordinateErr := enabled.Coordinate(context.Background(), test.domain)
			assertReplayOutcome(t, outcome, coordinateErr, ReplayResultNotChecked, test.disposition, false)
			if deriver.Calls() != beforeDerives || store.Calls() != beforeStores {
				t.Fatal("replay gate performed derivation or storage work")
			}
		})
	}

	disabled := NewDisabledReplayCoordinator()
	outcome, coordinateErr := disabled.Coordinate(context.Background(), passStrict)
	assertReplayOutcome(t, outcome, coordinateErr, ReplayResultDisabled, FinalDispositionAccept, false)
	if deriver.Calls() != 0 || store.Calls() != 0 {
		t.Fatal("disabled replay performed derivation or storage work")
	}
}

// TestReplayCoordinatorDerivationFailuresAreZeroWrite proves every key precedes mutation.
func TestReplayCoordinatorDerivationFailuresAreZeroWrite(t *testing.T) {
	domain := authenticReplayDomain(t, [][]byte{
		[]byte("<one@example.test>"),
		[]byte("<two@example.test>"),
		[]byte("<three@example.test>"),
	}, config.PolicyStrict)
	for _, test := range []struct {
		name      string
		failAt    int
		invalidAt int
	}{
		{"typed failure", 1, -1},
		{"invalid key", -1, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			inner, err := dkim2.NewReplayDeriver(replayTestSecret(), 1)
			if err != nil {
				t.Fatal("replay deriver construction failed")
			}
			t.Cleanup(func() { _ = inner.Close(context.Background()) })
			deriver := &recordingReplayDeriver{
				inner: inner, failAt: test.failAt, invalidAt: test.invalidAt,
			}
			store := &recordingReplayStore{}
			coordinator := mustReplayCoordinator(t, deriver, store)
			outcome, coordinateErr := coordinator.Coordinate(context.Background(), domain)
			assertReplayOutcome(
				t,
				outcome,
				coordinateErr,
				ReplayResultIndeterminate,
				FinalDispositionTempfail,
				false,
			)
			if store.Calls() != 0 {
				t.Fatal("derivation failure performed a store call")
			}
		})
	}
}

// TestReplayCoordinatorAggregateMatrix proves complete sequential result precedence.
func TestReplayCoordinatorAggregateMatrix(t *testing.T) {
	domain := authenticReplayDomain(t, [][]byte{
		[]byte("<one@example.test>"),
		[]byte("<two@example.test>"),
		[]byte("<three@example.test>"),
	}, config.PolicyStrict)
	tests := []struct {
		name      string
		responses []replayStoreResponse
		class     ReplayResultClass
		final     FinalDisposition
		mutation  bool
	}{
		{
			"all first seen",
			[]replayStoreResponse{{check: dkim2.ReplayCheckFirstSeen}, {check: dkim2.ReplayCheckFirstSeen}, {check: dkim2.ReplayCheckFirstSeen}},
			ReplayResultFirstSeen, FinalDispositionAccept, true,
		},
		{
			"all replayed",
			[]replayStoreResponse{{check: dkim2.ReplayCheckReplayed}, {check: dkim2.ReplayCheckReplayed}, {check: dkim2.ReplayCheckReplayed}},
			ReplayResultReplayed, FinalDispositionReject, false,
		},
		{
			"mixed",
			[]replayStoreResponse{{check: dkim2.ReplayCheckReplayed}, {check: dkim2.ReplayCheckFirstSeen}, {check: dkim2.ReplayCheckReplayed}},
			ReplayResultReplayed, FinalDispositionReject, true,
		},
		{
			"enabled disabled contradiction",
			[]replayStoreResponse{{check: dkim2.ReplayCheckDisabled}, {check: dkim2.ReplayCheckFirstSeen}, {check: dkim2.ReplayCheckReplayed}},
			ReplayResultIndeterminate, FinalDispositionTempfail, true,
		},
		{
			"zero success contradiction",
			[]replayStoreResponse{{}, {check: dkim2.ReplayCheckFirstSeen}, {check: dkim2.ReplayCheckReplayed}},
			ReplayResultIndeterminate, FinalDispositionTempfail, true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator, store := scriptedReplayCoordinator(t, test.responses)
			outcome, coordinateErr := coordinator.Coordinate(context.Background(), domain)
			assertReplayOutcome(t, outcome, coordinateErr, test.class, test.final, test.mutation)
			if store.Calls() != 3 {
				t.Fatal("ordinary aggregate processing stopped before the complete batch")
			}
		})
	}
}

// TestReplayCoordinatorContinuesEveryOrdinaryFailure proves exact error and mutation classification.
func TestReplayCoordinatorContinuesEveryOrdinaryFailure(t *testing.T) {
	domain := authenticReplayDomain(t, [][]byte{
		[]byte("<one@example.test>"),
		[]byte("<two@example.test>"),
		[]byte("<three@example.test>"),
	}, config.PolicyStrict)
	tests := []struct {
		name      string
		response  replayStoreResponse
		mutation  bool
		wantCalls int
	}{
		{"limit", replayStoreResponse{err: dkim2.NewReplayError(dkim2.ReplayErrorLimitExceeded)}, false, 3},
		{"unavailable", replayStoreResponse{err: dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)}, false, 3},
		{"closed", replayStoreResponse{err: dkim2.NewReplayError(dkim2.ReplayErrorClosed)}, false, 3},
		{"invalid", replayStoreResponse{err: dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)}, true, 3},
		{"misconfigured", replayStoreResponse{err: dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)}, true, 3},
		{"indeterminate", replayStoreResponse{err: dkim2.NewReplayError(dkim2.ReplayErrorIndeterminate)}, true, 3},
		{"inconsistent", replayStoreResponse{err: dkim2.NewReplayError(dkim2.ReplayErrorInconsistent)}, true, 3},
		{"invariant", replayStoreResponse{err: dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)}, true, 3},
		{"live typed cancel", replayStoreResponse{err: dkim2.NewReplayError(dkim2.ReplayErrorCancelled)}, true, 1},
		{"live typed deadline", replayStoreResponse{err: dkim2.NewReplayError(dkim2.ReplayErrorDeadlineExceeded)}, true, 1},
		{
			"live typed cancel contradiction",
			replayStoreResponse{
				check: dkim2.ReplayCheckReplayed,
				err:   dkim2.NewReplayError(dkim2.ReplayErrorCancelled),
			},
			true,
			1,
		},
		{
			"live typed deadline contradiction",
			replayStoreResponse{
				check: dkim2.ReplayCheckFirstSeen,
				err:   dkim2.NewReplayError(dkim2.ReplayErrorDeadlineExceeded),
			},
			true,
			1,
		},
		{"unknown", replayStoreResponse{err: errors.New("TOXIC-REPLAY-STORE-ERROR")}, true, 3},
		{
			"contradictory result and error",
			replayStoreResponse{
				check: dkim2.ReplayCheckReplayed,
				err:   dkim2.NewReplayError(dkim2.ReplayErrorUnavailable),
			},
			true,
			3,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			responses := []replayStoreResponse{
				test.response,
				{check: dkim2.ReplayCheckReplayed},
				{check: dkim2.ReplayCheckReplayed},
			}
			coordinator, store := scriptedReplayCoordinator(t, responses)
			outcome, coordinateErr := coordinator.Coordinate(context.Background(), domain)
			assertReplayOutcome(
				t,
				outcome,
				coordinateErr,
				ReplayResultIndeterminate,
				FinalDispositionTempfail,
				test.mutation,
			)
			if store.Calls() != test.wantCalls {
				t.Fatal("store failure used the wrong continuation boundary")
			}
			if strings.Contains(fmt.Sprint(coordinateErr), "TOXIC") {
				t.Fatal("raw store error escaped replay coordination")
			}
		})
	}
}

// TestReplayCoordinatorContextBoundariesProveMutationPrecedence verifies cancellation rules.
func TestReplayCoordinatorContextBoundariesProveMutationPrecedence(t *testing.T) {
	domain := authenticReplayDomain(t, [][]byte{
		[]byte("<one@example.test>"),
		[]byte("<two@example.test>"),
		[]byte("<three@example.test>"),
	}, config.PolicyStrict)

	t.Run("before coordination", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		coordinator, store := scriptedReplayCoordinator(t, nil)
		outcome, coordinateErr := coordinator.Coordinate(ctx, domain)
		if outcome.Valid() || !errors.Is(coordinateErr, context.Canceled) || store.Calls() != 0 {
			t.Fatal("terminal preflight did not use transport cancellation")
		}
	})

	t.Run("after derivation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		inner, err := dkim2.NewReplayDeriver(replayTestSecret(), 1)
		if err != nil {
			t.Fatal("replay deriver construction failed")
		}
		t.Cleanup(func() { _ = inner.Close(context.Background()) })
		deriver := &recordingReplayDeriver{
			inner: inner, failAt: -1, invalidAt: -1,
			after: func(index int) {
				if index == 1 {
					cancel()
				}
			},
		}
		store := &recordingReplayStore{}
		coordinator := mustReplayCoordinator(t, deriver, store)
		outcome, coordinateErr := coordinator.Coordinate(ctx, domain)
		if outcome.Valid() || !errors.Is(coordinateErr, context.Canceled) || store.Calls() != 0 {
			t.Fatal("derivation-boundary cancellation performed mutation or returned an aggregate")
		}
	})

	t.Run("derivation error plus cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		inner, err := dkim2.NewReplayDeriver(replayTestSecret(), 1)
		if err != nil {
			t.Fatal("replay deriver construction failed")
		}
		t.Cleanup(func() { _ = inner.Close(context.Background()) })
		deriver := &recordingReplayDeriver{
			inner: inner, failAt: 0, invalidAt: -1,
			after: func(index int) {
				if index == 0 {
					cancel()
				}
			},
		}
		store := &recordingReplayStore{}
		coordinator := mustReplayCoordinator(t, deriver, store)
		outcome, coordinateErr := coordinator.Coordinate(ctx, domain)
		if outcome.Valid() || !errors.Is(coordinateErr, context.Canceled) ||
			store.Calls() != 0 {
			t.Fatal("terminal context did not dominate simultaneous derivation failure")
		}
	})

	for _, test := range []struct {
		name      string
		first     replayStoreResponse
		mutation  bool
		aggregate bool
	}{
		{"after replayed", replayStoreResponse{check: dkim2.ReplayCheckReplayed}, false, false},
		{"after first seen", replayStoreResponse{check: dkim2.ReplayCheckFirstSeen}, true, true},
		{"after typed indeterminate", replayStoreResponse{err: dkim2.NewReplayError(dkim2.ReplayErrorIndeterminate)}, true, true},
		{"after unknown", replayStoreResponse{err: errors.New("TOXIC-CONTEXT-MARKER")}, true, true},
		{"after invalid result", replayStoreResponse{}, true, true},
		{"after unavailable", replayStoreResponse{err: dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)}, false, false},
		{"matching typed cancel", replayStoreResponse{err: dkim2.NewReplayError(dkim2.ReplayErrorCancelled)}, false, false},
		{
			"matching typed cancel contradiction",
			replayStoreResponse{
				check: dkim2.ReplayCheckFirstSeen,
				err:   dkim2.NewReplayError(dkim2.ReplayErrorCancelled),
			},
			true,
			true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			coordinator, store := scriptedReplayCoordinator(t, []replayStoreResponse{test.first})
			store.before = func(index int, _ context.Context) {
				if index == 0 {
					defer cancel()
				}
			}
			outcome, coordinateErr := coordinator.Coordinate(ctx, domain)
			if test.aggregate {
				assertReplayOutcome(
					t,
					outcome,
					coordinateErr,
					ReplayResultIndeterminate,
					FinalDispositionTempfail,
					test.mutation,
				)
			} else if outcome.Valid() || !errors.Is(coordinateErr, context.Canceled) {
				t.Fatal("pre-dispatch-safe cancellation did not use transport precedence")
			}
			if store.Calls() != 1 {
				t.Fatal("terminal context dispatched additional store work")
			}
		})
	}

	t.Run("deadline contradiction", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
		coordinator, store := scriptedReplayCoordinator(t, []replayStoreResponse{{
			err: dkim2.NewReplayError(dkim2.ReplayErrorDeadlineExceeded),
		}})
		store.before = func(index int, _ context.Context) {
			if index == 0 {
				cancel()
			}
		}
		outcome, coordinateErr := coordinator.Coordinate(ctx, domain)
		assertReplayOutcome(
			t,
			outcome,
			coordinateErr,
			ReplayResultIndeterminate,
			FinalDispositionTempfail,
			true,
		)
		if store.Calls() != 1 {
			t.Fatal("deadline contradiction dispatched additional work")
		}
	})

	t.Run("deadline match", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		coordinator, store := scriptedReplayCoordinator(t, []replayStoreResponse{{
			err: dkim2.NewReplayError(dkim2.ReplayErrorDeadlineExceeded),
		}})
		store.before = func(index int, requestContext context.Context) {
			if index == 0 {
				<-requestContext.Done()
			}
		}
		outcome, coordinateErr := coordinator.Coordinate(ctx, domain)
		if outcome.Valid() || !errors.Is(coordinateErr, context.DeadlineExceeded) {
			t.Fatal("matching typed deadline did not use transport precedence")
		}
		if store.Calls() != 1 {
			t.Fatal("matching deadline dispatched additional work")
		}
	})

	t.Run("deadline match contradiction", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		coordinator, store := scriptedReplayCoordinator(t, []replayStoreResponse{{
			check: dkim2.ReplayCheckReplayed,
			err:   dkim2.NewReplayError(dkim2.ReplayErrorDeadlineExceeded),
		}})
		store.before = func(index int, requestContext context.Context) {
			if index == 0 {
				<-requestContext.Done()
			}
		}
		outcome, coordinateErr := coordinator.Coordinate(ctx, domain)
		assertReplayOutcome(
			t,
			outcome,
			coordinateErr,
			ReplayResultIndeterminate,
			FinalDispositionTempfail,
			true,
		)
		if store.Calls() != 1 {
			t.Fatal("deadline contradiction dispatched additional work")
		}
	})
}

// TestDispositionForPolicyMapsEveryClosedVerdict proves no replay policy rewriting.
func TestDispositionForPolicyMapsEveryClosedVerdict(t *testing.T) {
	for _, test := range []struct {
		verdict     dkim2.PolicyVerdict
		disposition FinalDisposition
		ok          bool
	}{
		{dkim2.PolicyVerdictAccept, FinalDispositionAccept, true},
		{dkim2.PolicyVerdictReject, FinalDispositionReject, true},
		{dkim2.PolicyVerdictTempfail, FinalDispositionTempfail, true},
		{dkim2.PolicyVerdictContinue, FinalDispositionContinue, true},
		{"", 0, false},
		{"future", 0, false},
	} {
		disposition, ok := dispositionForPolicy(test.verdict)
		if disposition != test.disposition || ok != test.ok {
			t.Fatal("policy verdict did not map to its exact final disposition")
		}
	}
}

// TestReplayOutcomeRejectsImpossibleMatrixMembers proves no caller can observe incoherent state.
func TestReplayOutcomeRejectsImpossibleMatrixMembers(t *testing.T) {
	for _, state := range []replayOutcomeState{
		{},
		{class: 255, disposition: FinalDispositionAccept},
		{class: ReplayResultDisabled, disposition: FinalDispositionReject},
		{class: ReplayResultDisabled, disposition: FinalDispositionAccept, possibleMutation: true},
		{class: ReplayResultFirstSeen, disposition: FinalDispositionAccept},
		{class: ReplayResultFirstSeen, disposition: FinalDispositionReject, possibleMutation: true},
		{class: ReplayResultReplayed, disposition: FinalDispositionAccept},
		{class: ReplayResultIndeterminate, disposition: FinalDispositionAccept, possibleMutation: true},
	} {
		outcome := ReplayOutcome{state: &state}
		if outcome.Valid() || outcome.Class() != 0 || outcome.Disposition() != 0 ||
			outcome.possibleStoreMutation() {
			t.Fatal("impossible replay outcome became observable")
		}
	}
}

// TestReplayCoordinatorFailsClosedOnHostileContextsAndConstruction proves bounded contracts.
func TestReplayCoordinatorFailsClosedOnHostileContextsAndConstruction(t *testing.T) {
	var nilDeriver *typedNilReplayDeriver
	var nilStore *typedNilReplayStore
	if coordinator, err := newEnabledReplayCoordinator(nilDeriver, &recordingReplayStore{}, dkim2.DefaultReplayRetention()); coordinator != nil || !IsReplayCoordinatorError(err) {
		t.Fatal("typed-nil deriver construction did not fail closed")
	}
	if coordinator, err := newEnabledReplayCoordinator(&typedNilReplayDeriver{}, nilStore, dkim2.DefaultReplayRetention()); coordinator != nil || !IsReplayCoordinatorError(err) {
		t.Fatal("typed-nil store construction did not fail closed")
	}
	if coordinator, err := newEnabledReplayCoordinator(&typedNilReplayDeriver{}, &recordingReplayStore{}, dkim2.ReplayRetention{}); coordinator != nil || !IsReplayCoordinatorError(err) {
		t.Fatal("invalid retention construction did not fail closed")
	}

	domain := authenticReplayDomain(t, [][]byte{[]byte("<one@example.test>")}, config.PolicyStrict)
	coordinator, store := scriptedReplayCoordinator(t, nil)
	for _, ctx := range []context.Context{
		hostileReplayContext{panicErr: true},
		hostileReplayContext{panicDeadline: true},
		hostileReplayContext{err: errors.New("TOXIC-HOSTILE-CONTEXT")},
	} {
		outcome, coordinateErr := coordinator.Coordinate(ctx, domain)
		if outcome.Valid() || !IsReplayCoordinatorError(coordinateErr) ||
			strings.Contains(fmt.Sprint(coordinateErr), "TOXIC") {
			t.Fatal("hostile context escaped bounded coordination failure")
		}
	}
	var typedNil *hostileReplayContext
	if outcome, err := coordinator.Coordinate(typedNil, domain); outcome.Valid() || !IsReplayCoordinatorError(err) {
		t.Fatal("typed-nil context did not fail closed")
	}
	if store.Calls() != 0 {
		t.Fatal("hostile context reached replay storage")
	}

	expiredCoordinator, expiredStore := scriptedReplayCoordinator(t, nil)
	outcome, coordinateErr := expiredCoordinator.Coordinate(
		expiredNilErrorContext{},
		domain,
	)
	if outcome.Valid() || !errors.Is(coordinateErr, context.DeadlineExceeded) ||
		expiredStore.Calls() != 0 {
		t.Fatal("expired deadline with nil Err reached replay work")
	}
	zeroDeadlineCoordinator, zeroDeadlineStore := scriptedReplayCoordinator(t, nil)
	outcome, coordinateErr = zeroDeadlineCoordinator.Coordinate(
		zeroDeadlineNilErrorContext{},
		domain,
	)
	if outcome.Valid() || !errors.Is(coordinateErr, context.DeadlineExceeded) ||
		zeroDeadlineStore.Calls() != 0 {
		t.Fatal("zero deadline with nil Err reached replay work")
	}
}

// TestReplayCoordinatorPrivacyAndConcurrentReuse proves retained dependencies remain opaque and race-safe.
func TestReplayCoordinatorPrivacyAndConcurrentReuse(t *testing.T) {
	domain := authenticReplayDomain(t, [][]byte{[]byte("<privacy@example.test>")}, config.PolicyStrict)
	coordinator, _ := scriptedReplayCoordinator(t, []replayStoreResponse{{check: dkim2.ReplayCheckReplayed}})
	outcome, err := coordinator.Coordinate(context.Background(), domain)
	assertReplayOutcome(t, outcome, err, ReplayResultReplayed, FinalDispositionReject, false)

	values := []any{
		*coordinator, coordinator, any(*coordinator), []ReplayCoordinator{*coordinator},
		map[string]ReplayCoordinator{"coordinator": *coordinator},
		map[ReplayCoordinator]bool{*coordinator: true},
		outcome, &outcome, any(outcome), []ReplayOutcome{outcome},
		map[string]ReplayOutcome{"outcome": outcome},
		map[ReplayOutcome]bool{outcome: true},
	}
	for _, value := range values {
		formatted := fmt.Sprintf("%s|%q|%v|%+v|%#v|%x|%p", value, value, value, value, value, value, value)
		if strings.Contains(formatted, "TOXIC") || strings.Contains(formatted, "dkim2:replay:v1:") {
			t.Fatal("replay coordinator diagnostics exposed protected state")
		}
		encoded, marshalErr := json.Marshal(value)
		if len(encoded) != 0 || marshalErr == nil ||
			strings.Contains(marshalErr.Error(), "TOXIC") {
			t.Fatal("replay coordinator serialization did not fail closed")
		}
	}
	for _, value := range []interface {
		MarshalText() ([]byte, error)
	}{*coordinator, outcome} {
		text, marshalErr := value.MarshalText()
		if len(text) != 0 || marshalErr == nil ||
			strings.Contains(marshalErr.Error(), "TOXIC") {
			t.Fatal("replay owner text serialization did not fail closed")
		}
	}

	shared, _ := scriptedReplayCoordinator(t, nil)
	var wait sync.WaitGroup
	errs := make(chan error, 32)
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, coordinateErr := shared.Coordinate(context.Background(), domain)
			if coordinateErr != nil || !result.Valid() {
				errs <- &ReplayCoordinatorError{}
			}
		}()
	}
	wait.Wait()
	close(errs)
	if len(errs) != 0 {
		t.Fatal("concurrent coordinator reuse failed")
	}
}

// FuzzReplayCheckClassification proves arbitrary closed pairs stay bounded.
func FuzzReplayCheckClassification(f *testing.F) {
	f.Add(uint8(dkim2.ReplayCheckFirstSeen), uint8(0), uint8(0))
	f.Add(uint8(dkim2.ReplayCheckReplayed), uint8(3), uint8(1))
	f.Add(uint8(255), uint8(255), uint8(2))
	f.Fuzz(func(t *testing.T, checkByte, codeByte, contextByte uint8) {
		check := dkim2.ReplayCheck(checkByte)
		var replayErr error
		if codeByte != 0 {
			codes := []dkim2.ReplayErrorCode{
				dkim2.ReplayErrorInvalidRequest,
				dkim2.ReplayErrorMisconfigured,
				dkim2.ReplayErrorLimitExceeded,
				dkim2.ReplayErrorUnavailable,
				dkim2.ReplayErrorIndeterminate,
				dkim2.ReplayErrorInconsistent,
				dkim2.ReplayErrorCancelled,
				dkim2.ReplayErrorDeadlineExceeded,
				dkim2.ReplayErrorClosed,
				dkim2.ReplayErrorInternalInvariant,
			}
			replayErr = dkim2.NewReplayError(codes[int(codeByte)%len(codes)])
		}
		var contextErr error
		switch contextByte % 3 {
		case 1:
			contextErr = context.Canceled
		case 2:
			contextErr = context.DeadlineExceeded
		}
		classification := classifyReplayCheck(check, replayErr, contextErr)
		if classification.replayed && classification.indeterminate {
			t.Fatal("classification produced contradictory aggregate facts")
		}
	})
}

type hostileReplayContext struct {
	err           error
	panicErr      bool
	panicDeadline bool
}

type expiredNilErrorContext struct{}

type zeroDeadlineNilErrorContext struct{}

// Deadline reports one legitimate already-expired zero deadline.
func (zeroDeadlineNilErrorContext) Deadline() (time.Time, bool) { return time.Time{}, true }

// Done returns no signal to test deadline normalization independently.
func (zeroDeadlineNilErrorContext) Done() <-chan struct{} { return nil }

// Err returns nil so the app boundary must inspect the expired deadline.
func (zeroDeadlineNilErrorContext) Err() error { return nil }

// Value returns no context value.
func (zeroDeadlineNilErrorContext) Value(any) any { return nil }

// Deadline reports an already-expired deadline.
func (expiredNilErrorContext) Deadline() (time.Time, bool) {
	return time.Now().Add(-time.Second), true
}

// Done returns no signal to model one contradictory hostile context.
func (expiredNilErrorContext) Done() <-chan struct{} { return nil }

// Err contradicts the expired deadline and must fail closed.
func (expiredNilErrorContext) Err() error { return nil }

// Value returns no context value.
func (expiredNilErrorContext) Value(any) any { return nil }

// Deadline returns no deadline without exposing hostile state.
func (c hostileReplayContext) Deadline() (time.Time, bool) {
	if c.panicDeadline {
		panic("TOXIC-HOSTILE-CONTEXT-DEADLINE")
	}
	return time.Time{}, false
}

// Done returns no channel because Err drives the hostile contract case.
func (hostileReplayContext) Done() <-chan struct{} { return nil }

// Err returns or panics with one hostile context state.
func (c hostileReplayContext) Err() error {
	if c.panicErr {
		panic("TOXIC-HOSTILE-CONTEXT-PANIC")
	}
	return c.err
}

// Value returns no value without exposing hostile state.
func (hostileReplayContext) Value(any) any { return nil }

// String panics if coordination attempts to format the hostile context.
func (hostileReplayContext) String() string {
	panic("TOXIC-HOSTILE-CONTEXT-FORMAT")
}

// Format panics if coordination attempts to format the hostile context.
func (hostileReplayContext) Format(fmt.State, rune) {
	panic("TOXIC-HOSTILE-CONTEXT-FORMAT")
}

// authenticReplayDomain constructs one cryptographically sealed PASS domain result.
func authenticReplayDomain(
	t *testing.T,
	recipients [][]byte,
	mode config.PolicyMode,
) DomainResult {
	t.Helper()
	raw, key := signedAppReplayMessage(t, recipients)
	return processReplayDomain(t, raw, recipients, replayTestProvider{key: key}, mode)
}

// goldenReplayDomain loads one frozen public PASS vector through the daemon domain seam.
func goldenReplayDomain(t *testing.T, mode config.PolicyMode) DomainResult {
	t.Helper()
	corpusBytes, err := os.ReadFile(
		"../../../../lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-04/public-golden.json",
	)
	if err != nil {
		t.Fatal("golden replay fixture unavailable")
	}
	var corpus appGoldenCorpus
	if json.Unmarshal(corpusBytes, &corpus) != nil || corpus.Draft != dkim2.DraftIdentifier {
		t.Fatal("golden replay fixture invalid")
	}
	vector, ok := corpus.Vectors["rsa_pass"]
	if !ok {
		t.Fatal("golden replay PASS vector unavailable")
	}
	modulus := decodeAppGolden(t, corpus.RSAModulus)
	recipients := make([][]byte, len(vector.Forward))
	for index, encoded := range vector.Forward {
		recipients[index] = decodeAppGolden(t, encoded)
	}
	return processReplayDomain(
		t,
		decodeAppGolden(t, vector.Raw),
		recipients,
		appGoldenProvider{
			key: &rsa.PublicKey{
				N: new(big.Int).SetBytes(modulus),
				E: corpus.RSAExponent,
			},
		},
		mode,
	)
}

// malformedReplayDomain constructs one authentic pre-target PERMERROR domain result.
func malformedReplayDomain(t *testing.T, mode config.PolicyMode) DomainResult {
	t.Helper()
	return processReplayDomain(
		t,
		[]byte("not-rfc5322"),
		[][]byte{[]byte("<malformed@example.test>")},
		noLookupProvider{},
		mode,
	)
}

// temporaryReplayDomain constructs one provider-owned TEMPERROR domain result.
func temporaryReplayDomain(
	t *testing.T,
	recipients [][]byte,
	mode config.PolicyMode,
) DomainResult {
	t.Helper()
	raw, _ := signedAppReplayMessage(t, recipients)
	return processReplayDomain(
		t,
		raw,
		recipients,
		replayTestProvider{err: dkim2.NewTemporaryProviderError()},
		mode,
	)
}

// failedReplayDomain constructs one authenticated selected FAIL without replay work.
func failedReplayDomain(
	t *testing.T,
	recipients [][]byte,
	mode config.PolicyMode,
) DomainResult {
	t.Helper()
	raw, key := signedAppReplayMessage(t, recipients)
	corrupted := []byte(strings.Replace(
		string(raw),
		"body line\r\n",
		"body fail\r\n",
		1,
	))
	return processReplayDomain(t, corrupted, recipients, replayTestProvider{key: key}, mode)
}

// processReplayDomain runs one exact verification and server-owned policy pair.
func processReplayDomain(
	t *testing.T,
	raw []byte,
	recipients [][]byte,
	provider dkim2.PublicKeyProvider,
	mode config.PolicyMode,
) DomainResult {
	t.Helper()
	verifier, err := dkim2.NewVerifier(
		provider,
		dkim2.WithVerificationClock(func() time.Time {
			return time.Unix(replayTestTimestamp, 0)
		}),
	)
	if err != nil {
		t.Fatal("replay verifier construction failed")
	}
	processor, err := NewDomainProcessor(verifier, mode)
	if err != nil {
		t.Fatal("replay domain processor construction failed")
	}
	domain, err := processor.Process(
		context.Background(),
		dkim2.NewVerifyRequest(raw, []byte("<>"), recipients),
	)
	if err != nil || !domain.valid() {
		t.Fatal("replay domain fixture processing failed")
	}
	return domain
}

// signedAppReplayMessage creates one passing synthetic fixture with exact recipients.
func signedAppReplayMessage(
	t *testing.T,
	recipients [][]byte,
) ([]byte, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal("replay RSA fixture construction failed")
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatal("replay canonicalizer construction failed")
	}
	base, err := rawmsg.Parse([]byte(
		"From: sender@example.test\r\nSubject: replay coordinator\r\n\r\nbody line\r\n",
	))
	if err != nil {
		t.Fatal("replay base message construction failed")
	}
	headerHash, _ := canonicalizer.HeaderHashFromMessage(base)
	bodyHash, _ := canonicalizer.BodyHashFromMessage(base)
	headerDigest, _ := headerHash.Digest()
	bodyDigest, _ := bodyHash.Digest()
	encodedRecipients := make([]string, len(recipients))
	for index, recipient := range recipients {
		encodedRecipients[index] = base64.StdEncoding.EncodeToString(recipient)
	}
	build := func(signature string) string {
		return "From: sender@example.test\r\nSubject: replay coordinator\r\n" +
			"Message-Instance: m=1; h=sha256:" + headerDigest.Base64() + ":" + bodyDigest.Base64() + ";\r\n" +
			"DKIM2-Signature: i=1; m=1; t=" + strconv.FormatInt(replayTestTimestamp, 10) +
			"; mf=PD4=; rt=" + strings.Join(encodedRecipients, ",") +
			"; d=example.test; s=selector.test:rsa-sha256:" + signature +
			";\r\n\r\nbody line\r\n"
	}
	placeholder := base64.StdEncoding.EncodeToString(make([]byte, 128))
	unsigned, err := rawmsg.Parse([]byte(build(placeholder)))
	if err != nil {
		t.Fatal("replay unsigned fixture construction failed")
	}
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{
		Headers: unsigned.Headers(), TargetSequence: 1,
	})
	if err != nil {
		t.Fatal("replay signature-input fixture construction failed")
	}
	digest := sha256.Sum256(input.Bytes())
	sealed, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal("replay signature fixture construction failed")
	}
	return []byte(build(base64.StdEncoding.EncodeToString(sealed))), &key.PublicKey
}

// expectedReplayStorageOrder derives the exact sealed set order through the public seam.
func expectedReplayStorageOrder(
	t *testing.T,
	verification dkim2.VerifyResult,
	secret []byte,
	epoch uint32,
) []string {
	t.Helper()
	identities, err := dkim2.ReplayIdentities(verification)
	if err != nil || identities.Len() == 0 {
		t.Fatal("authentic replay identities unavailable")
	}
	deriver, err := dkim2.NewReplayDeriver(secret, epoch)
	if err != nil {
		t.Fatal("expected replay deriver construction failed")
	}
	defer func() { _ = deriver.Close(context.Background()) }()
	storage := make([]string, identities.Len())
	for index := range identities.Len() {
		identity, identityErr := identities.Identity(index)
		key, deriveErr := deriver.Derive(context.Background(), identity)
		if identityErr != nil || deriveErr != nil {
			t.Fatal("expected replay key derivation failed")
		}
		if useErr := dkim2.UseReplayStorageKey(key, func(value string) error {
			storage[index] = value
			return nil
		}); useErr != nil {
			t.Fatal("expected replay key access failed")
		}
	}
	return storage
}

// mustReplayCoordinator constructs one enabled coordinator with default retention.
func mustReplayCoordinator(
	t *testing.T,
	deriver replayKeyDeriver,
	store dkim2.ReplayStore,
) *ReplayCoordinator {
	t.Helper()
	coordinator, err := newEnabledReplayCoordinator(
		deriver,
		store,
		dkim2.DefaultReplayRetention(),
	)
	if err != nil {
		t.Fatal("replay coordinator construction failed")
	}
	return coordinator
}

// scriptedReplayCoordinator constructs one coordinator and scripted provider.
func scriptedReplayCoordinator(
	t *testing.T,
	responses []replayStoreResponse,
) (*ReplayCoordinator, *recordingReplayStore) {
	t.Helper()
	inner, err := dkim2.NewReplayDeriver(replayTestSecret(), 1)
	if err != nil {
		t.Fatal("replay deriver construction failed")
	}
	t.Cleanup(func() { _ = inner.Close(context.Background()) })
	deriver := &recordingReplayDeriver{inner: inner, failAt: -1, invalidAt: -1}
	store := &recordingReplayStore{responses: responses}
	return mustReplayCoordinator(t, deriver, store), store
}

// assertReplayOutcome verifies one exact coherent replay matrix cell.
func assertReplayOutcome(
	t *testing.T,
	outcome ReplayOutcome,
	err error,
	class ReplayResultClass,
	disposition FinalDisposition,
	possibleMutation bool,
) {
	t.Helper()
	if err != nil || !outcome.Valid() || outcome.Class() != class ||
		outcome.Disposition() != disposition ||
		outcome.possibleStoreMutation() != possibleMutation {
		t.Fatal("replay outcome did not match the exact closed matrix")
	}
}

// equalReplayStorage compares exact protected-key order only inside synthetic tests.
func equalReplayStorage(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// replayTestSecret returns one published non-production fixed test secret.
func replayTestSecret() []byte {
	secret := make([]byte, sha256.Size)
	for index := range secret {
		secret[index] = byte(index + 1)
	}
	return secret
}
