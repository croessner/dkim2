package replay

import (
	"context"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
	"time"
)

// propagationTestIdentity returns one sealed message-wide identity.
func propagationTestIdentity(t *testing.T) Identity {
	t.Helper()
	digestBytes, err := hex.DecodeString("63519c8a3d2e4d5f6fb9e689259be264a058a3a9fbc8bb5a9a904bef0e9d9cd5")
	if err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	copy(digest[:], digestBytes)
	set, err := NewIdentitySet(originDigestSource{digest: digest})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := set.Identity(0)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

// storageKeyOf returns the protected storage representation for assertions.
func storageKeyOf(t *testing.T, key Key) string {
	t.Helper()
	var storage string
	if err := UseStorageKey(key, func(value string) error { storage = value; return nil }); err != nil {
		t.Fatal(err)
	}
	return storage
}

// TestPropagationFrameSeparatesIdentities proves the propagation frame yields
// a distinct, deterministic key of the unchanged storage shape for the same
// identity, and that the ordinary derivation is unchanged.
func TestPropagationFrameSeparatesIdentities(t *testing.T) {
	identity := propagationTestIdentity(t)
	deriver, err := NewDeriver(sequenceBytes(0xa0), 0x01020304)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = deriver.Close(context.Background()) })
	process, err := deriver.Derive(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	propagation, err := deriver.DerivePropagation(context.Background(), identity)
	if err != nil || !propagation.Valid() {
		t.Fatalf("DerivePropagation() valid=%t error=%v", propagation.Valid(), err)
	}
	again, err := deriver.DerivePropagation(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	processKey, propagationKey, againKey := storageKeyOf(t, process), storageKeyOf(t, propagation), storageKeyOf(t, again)
	if processKey != "dkim2:replay:v1:01020304:nxK4RF2gtOiO-FVQQuMsarmpn2hjabHQ5lPVvgR169A" {
		t.Fatalf("process key changed: %s", processKey)
	}
	if propagationKey == processKey || propagationKey != againKey {
		t.Fatalf("propagation key=%s process key=%s again=%s", propagationKey, processKey, againKey)
	}
	if len(propagationKey) != storageKeyByteLength || !strings.HasPrefix(propagationKey, "dkim2:replay:v1:01020304:") {
		t.Fatalf("propagation key shape=%q", propagationKey)
	}
	if propagationKey != "dkim2:replay:v1:01020304:"+propagationVectorSuffix {
		t.Fatalf("propagation vector drifted: %s", propagationKey)
	}
	if _, err := deriver.DerivePropagation(context.Background(), Identity{}); ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("invalid identity error=%v", err)
	}
	if _, err := deriver.DerivePropagation(nil, identity); ErrorCodeOf(err) != ErrorCodeInvalidRequest { //nolint:staticcheck // nil context is the misuse under test.
		t.Fatalf("nil context error=%v", err)
	}
	if err := deriver.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := deriver.DerivePropagation(context.Background(), identity); ErrorCodeOf(err) != ErrorCodeClosed {
		t.Fatalf("closed deriver error=%v", err)
	}
	var nilDeriver *Deriver
	if _, err := nilDeriver.DerivePropagation(context.Background(), identity); ErrorCodeOf(err) != ErrorCodeMisconfigured {
		t.Fatalf("nil deriver error=%v", err)
	}
}

// propagationVectorSuffix pins the propagation frame vector for the published identity and secret.
const propagationVectorSuffix = "95FqmpWcrXMdcW2tYuPcjbqBCnyF6Q1ZiqwIb9H2Lng"

// TestPropagationStoredValueVocabulary proves the closed stored values round-trip and reject other strings.
func TestPropagationStoredValueVocabulary(t *testing.T) {
	expiry := time.Unix(1_700_000_000, 250_000_000)
	pending := FormatPropagationPending(expiry)
	if pending != "pending:1700000000250" {
		t.Fatalf("pending value=%q", pending)
	}
	state, lease, ok := ParsePropagationValue(pending)
	if !ok || state != PropagationStatePending || !lease.Equal(expiry) {
		t.Fatalf("parsed pending state=%q lease=%v ok=%t", state, lease, ok)
	}
	state, lease, ok = ParsePropagationValue(PropagationCommittedValue)
	if !ok || state != PropagationStateCommitted || !lease.IsZero() {
		t.Fatalf("parsed committed state=%q lease=%v ok=%t", state, lease, ok)
	}
	for _, invalid := range []string{"", "v1", "pending:", "pending:abc", "pending:-1", "committed:1", "Pending:1", "pending:1700000000250x", "pending:99999999999999999999"} {
		if _, _, ok := ParsePropagationValue(invalid); ok {
			t.Fatalf("invalid value %q accepted", invalid)
		}
	}
	for _, value := range []PropagationState{PropagationStatePending, PropagationStateCommitted} {
		if !value.Known() {
			t.Fatalf("state %q unknown", value)
		}
	}
	if PropagationState("x").Known() || PropagationReservation(0).Known() || PropagationCommit(0).Known() {
		t.Fatal("unknown vocabulary accepted")
	}
	for _, reservation := range []PropagationReservation{PropagationReserved, PropagationPending, PropagationAlreadyCommitted, PropagationReservationDisabled} {
		if !reservation.Known() || reservation.String() == unknownValueText {
			t.Fatalf("reservation %d unknown", reservation)
		}
	}
	for _, commit := range []PropagationCommit{PropagationCommitted, PropagationCommitUnresolved, PropagationCommitDisabled} {
		if !commit.Known() || commit.String() == unknownValueText {
			t.Fatalf("commit %d unknown", commit)
		}
	}
	if PropagationReservation(9).String() != unknownValueText || PropagationCommit(9).String() != unknownValueText {
		t.Fatal("unknown values format as known")
	}
}

// TestPendingCommittedLifecycle proves insert-if-absent reservation, the
// live-lease refusal, the expired-lease refresh, the compare-and-set commit,
// commit idempotence, unknown commits, and retention expiry.
func TestPendingCommittedLifecycle(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	clock := newTestClock(start)
	store := newTestMemoryStore(t, Limits{MaxEntries: 4, MaxWaiters: 1, PruneBudget: 2}, clock)
	key := testReplayKey(7)
	retention := mustRetention(t, 10*time.Minute)
	lease := mustLease(t, 2*time.Minute)
	if outcome, err := store.CommitPropagation(context.Background(), key); err != nil || outcome != PropagationCommitUnresolved {
		t.Fatalf("commit before reservation outcome=%s error=%v", outcome, err)
	}
	if outcome, err := store.ReservePropagation(context.Background(), key, retention, lease); err != nil || outcome != PropagationReserved {
		t.Fatalf("first reservation outcome=%s error=%v", outcome, err)
	}
	clock.Set(start.Add(time.Minute))
	if outcome, err := store.ReservePropagation(context.Background(), key, retention, lease); err != nil || outcome != PropagationPending {
		t.Fatalf("reservation inside lease outcome=%s error=%v", outcome, err)
	}
	clock.Set(start.Add(3 * time.Minute))
	if outcome, err := store.ReservePropagation(context.Background(), key, retention, lease); err != nil || outcome != PropagationReserved {
		t.Fatalf("reservation after lease expiry outcome=%s error=%v", outcome, err)
	}
	clock.Set(start.Add(4 * time.Minute))
	if outcome, err := store.ReservePropagation(context.Background(), key, retention, lease); err != nil || outcome != PropagationPending {
		t.Fatalf("reservation inside refreshed lease outcome=%s error=%v", outcome, err)
	}
	if outcome, err := store.CommitPropagation(context.Background(), key); err != nil || outcome != PropagationCommitted {
		t.Fatalf("commit outcome=%s error=%v", outcome, err)
	}
	if outcome, err := store.CommitPropagation(context.Background(), key); err != nil || outcome != PropagationCommitted {
		t.Fatalf("second commit outcome=%s error=%v", outcome, err)
	}
	if outcome, err := store.ReservePropagation(context.Background(), key, retention, lease); err != nil || outcome != PropagationAlreadyCommitted {
		t.Fatalf("reservation after commit outcome=%s error=%v", outcome, err)
	}
	clock.Set(start.Add(20 * time.Minute))
	if outcome, err := store.ReservePropagation(context.Background(), key, retention, lease); err != nil || outcome != PropagationReserved {
		t.Fatalf("reservation after retention expiry outcome=%s error=%v", outcome, err)
	}
	clock.Set(start.Add(40 * time.Minute))
	if outcome, err := store.CommitPropagation(context.Background(), key); err != nil || outcome != PropagationCommitUnresolved {
		t.Fatalf("commit after retention expiry outcome=%s error=%v", outcome, err)
	}
	if outcome, err := store.ReservePropagation(context.Background(), key, retention, lease); err != nil || outcome != PropagationReserved {
		t.Fatalf("reservation of expired pending outcome=%s error=%v", outcome, err)
	}
	clock.Set(start.Add(41 * time.Minute))
	if outcome, err := store.CommitPropagation(context.Background(), key); err != nil || outcome != PropagationCommitted {
		t.Fatalf("commit of expired-lease pending inside retention outcome=%s error=%v", outcome, err)
	}
}

// TestPendingCommittedKeepsProcessRecordsIndependent proves propagation
// records and first-seen records never share state even under one key.
func TestPendingCommittedKeepsProcessRecordsIndependent(t *testing.T) {
	clock := newTestClock(time.Unix(1_700_000_000, 0))
	store := newTestMemoryStore(t, Limits{MaxEntries: 4, MaxWaiters: 1, PruneBudget: 2}, clock)
	retention := mustRetention(t, time.Minute)
	lease := mustLease(t, 30*time.Second)
	processKey, propagationKey := testReplayKey(1), testReplayKey(2)
	if check, err := store.CheckAndRemember(context.Background(), processKey, retention); err != nil || check != CheckFirstSeen {
		t.Fatalf("process first seen=%s error=%v", check, err)
	}
	if outcome, err := store.ReservePropagation(context.Background(), propagationKey, retention, lease); err != nil || outcome != PropagationReserved {
		t.Fatalf("propagation reserved=%s error=%v", outcome, err)
	}
	if check, err := store.CheckAndRemember(context.Background(), processKey, retention); err != nil || check != CheckReplayed {
		t.Fatalf("process replayed=%s error=%v", check, err)
	}
	if _, err := store.CheckAndRemember(context.Background(), propagationKey, retention); ErrorCodeOf(err) != ErrorCodeInconsistent {
		t.Fatalf("process check on propagation record error=%v", err)
	}
	if _, err := store.ReservePropagation(context.Background(), processKey, retention, lease); ErrorCodeOf(err) != ErrorCodeInconsistent {
		t.Fatalf("propagation reservation on process record error=%v", err)
	}
	if _, err := store.CommitPropagation(context.Background(), processKey); ErrorCodeOf(err) != ErrorCodeInconsistent {
		t.Fatalf("propagation commit on process record error=%v", err)
	}
}

// TestPendingCommittedValidationAndLifecycle proves request validation,
// closed-store refusal, entry limits, and the disabled provider outcomes.
func TestPendingCommittedValidationAndLifecycle(t *testing.T) {
	clock := newTestClock(time.Unix(1_700_000_000, 0))
	store := newTestMemoryStore(t, Limits{MaxEntries: 1, MaxWaiters: 1, PruneBudget: 1}, clock)
	retention := mustRetention(t, time.Minute)
	lease := mustLease(t, 30*time.Second)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.ReservePropagation(cancelled, testReplayKey(1), retention, lease); ErrorCodeOf(err) != ErrorCodeCancelled {
		t.Fatalf("cancelled reservation error=%v", err)
	}
	if _, err := store.CommitPropagation(cancelled, testReplayKey(1)); ErrorCodeOf(err) != ErrorCodeCancelled {
		t.Fatalf("cancelled commit error=%v", err)
	}
	if _, err := store.ReservePropagation(context.Background(), Key{}, retention, lease); ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("zero key error=%v", err)
	}
	if _, err := store.ReservePropagation(context.Background(), testReplayKey(1), Retention{}, lease); ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("zero retention error=%v", err)
	}
	if _, err := store.ReservePropagation(context.Background(), testReplayKey(1), retention, Lease{}); ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("zero lease error=%v", err)
	}
	if _, err := store.CommitPropagation(context.Background(), Key{}); ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("zero commit key error=%v", err)
	}
	if outcome, err := store.ReservePropagation(context.Background(), testReplayKey(1), retention, lease); err != nil || outcome != PropagationReserved {
		t.Fatalf("first reservation=%s error=%v", outcome, err)
	}
	if _, err := store.ReservePropagation(context.Background(), testReplayKey(2), retention, lease); ErrorCodeOf(err) != ErrorCodeLimitExceeded {
		t.Fatalf("entry limit error=%v", err)
	}
	for _, duration := range []time.Duration{0, -time.Second, time.Millisecond / 2, 25 * time.Hour} {
		if _, err := NewLease(duration); ErrorCodeOf(err) != ErrorCodeInvalidRequest {
			t.Fatalf("lease %v accepted", duration)
		}
	}
	if lease.Duration() != 30*time.Second || !lease.Valid() || (Lease{}).Valid() {
		t.Fatal("lease accessors mismatch")
	}
	if err := store.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReservePropagation(context.Background(), testReplayKey(1), retention, lease); ErrorCodeOf(err) != ErrorCodeClosed {
		t.Fatalf("closed reservation error=%v", err)
	}
	if _, err := store.CommitPropagation(context.Background(), testReplayKey(1)); ErrorCodeOf(err) != ErrorCodeClosed {
		t.Fatalf("closed commit error=%v", err)
	}
	var nilStore *MemoryStore
	if _, err := nilStore.ReservePropagation(context.Background(), testReplayKey(1), retention, lease); ErrorCodeOf(err) != ErrorCodeMisconfigured {
		t.Fatalf("nil store reservation error=%v", err)
	}
	disabled := NewDisabledStore()
	if outcome, err := disabled.ReservePropagation(context.Background(), testReplayKey(1), retention, lease); err != nil || outcome != PropagationReservationDisabled {
		t.Fatalf("disabled reservation=%s error=%v", outcome, err)
	}
	if outcome, err := disabled.CommitPropagation(context.Background(), testReplayKey(1)); err != nil || outcome != PropagationCommitDisabled {
		t.Fatalf("disabled commit=%s error=%v", outcome, err)
	}
	if err := disabled.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := disabled.ReservePropagation(context.Background(), testReplayKey(1), retention, lease); ErrorCodeOf(err) != ErrorCodeClosed {
		t.Fatalf("closed disabled reservation error=%v", err)
	}
	stores := []PropagationStore{store, disabled}
	if len(stores) != 2 {
		t.Fatal("stores do not satisfy the propagation contract")
	}
}

// TestPendingCommittedConcurrentReservationsYieldOneReserved proves N
// concurrent reservations of one coordinate produce exactly one reserved outcome.
func TestPendingCommittedConcurrentReservationsYieldOneReserved(t *testing.T) {
	clock := newTestClock(time.Unix(1_700_000_000, 0))
	store := newTestMemoryStore(t, Limits{MaxEntries: 8, MaxWaiters: 64, PruneBudget: 4}, clock)
	retention := mustRetention(t, time.Minute)
	lease := mustLease(t, 30*time.Second)
	key := testReplayKey(3)
	var wait sync.WaitGroup
	var mu sync.Mutex
	counts := map[PropagationReservation]int{}
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			outcome, err := store.ReservePropagation(context.Background(), key, retention, lease)
			if err != nil {
				t.Errorf("reservation error=%v", err)
				return
			}
			mu.Lock()
			counts[outcome]++
			mu.Unlock()
		}()
	}
	wait.Wait()
	if counts[PropagationReserved] != 1 || counts[PropagationPending] != 31 {
		t.Fatalf("counts=%v", counts)
	}
}

// mustLease constructs one lease or fails the test.
func mustLease(t *testing.T, duration time.Duration) Lease {
	t.Helper()
	lease, err := NewLease(duration)
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

// TestPropagationCommitVocabularyAgrees proves the unresolved commit outcome's
// identifier, formatted value, and closed-vocabulary marker agree and stay
// distinct from the out-of-vocabulary marker.
func TestPropagationCommitVocabularyAgrees(t *testing.T) {
	if PropagationCommitUnresolved.String() != "unresolved" || !PropagationCommitUnresolved.Known() {
		t.Fatalf("unresolved commit formats as %q", PropagationCommitUnresolved.String())
	}
	if PropagationCommit(0).String() != unknownValueText || PropagationCommit(0).Known() || PropagationCommitUnresolved.String() == unknownValueText {
		t.Fatalf("out-of-vocabulary commit formats as %q", PropagationCommit(0).String())
	}
}
