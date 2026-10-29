package redisstore

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	dkim2 "github.com/croessner/dkim2"
	"github.com/redis/go-redis/v9"
)

const (
	firstPendingNonce = "1011121314151617"
	foreignNonce      = "aaaaaaaaaaaaaaaa"
)

// legacyPendingValue renders the nonce-free "pending:<unixms>" form that
// earlier providers wrote and that this provider must still read as foreign.
func legacyPendingValue(expiry time.Time) string {
	return dkim2.ReplayPropagationPendingPrefix + strconv.FormatInt(expiry.UnixMilli(), 10)
}

// ownPending is the pending value the first deterministic nonce produces under testLease.
func ownPending() string {
	return pendingValue(time.Second, firstPendingNonce)
}

// TestReservePropagationPinsNonceBearingInsert proves the exact first write.
func TestReservePropagationPinsNonceBearingInsert(t *testing.T) {
	fake := newFakeBackend()
	store := newTestStore(t, fake)
	key, storage := testReplayKey(t, true)
	reservation, err := store.ReservePropagation(context.Background(), key, testRetention(t), testLease(t))
	if err != nil || reservation != dkim2.ReplayPropagationReserved {
		t.Fatalf("reservation=%v err=%v", reservation, err)
	}
	want := []any{commandSet, storage, ownPending(), "nx", commandGet, "px", int64(1500)}
	if got := fake.lastArgs(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("pinned args=%v, want %v", got, want)
	}
	if fake.evalShaCalls != 0 || fake.evalCalls != 0 {
		t.Fatal("absent record ran the takeover script")
	}
}

// TestReservePropagationRecognizesOwnRetriedCommit is the reservation
// reproducer: a lost reply followed by a retry that observes the store's own
// pending value is reserved, never pending.
func TestReservePropagationRecognizesOwnRetriedCommit(t *testing.T) {
	fake := newFakeBackend()
	fake.lostReplies = 1
	store := newTestStore(t, fake)
	key, _ := testReplayKey(t, true)
	reservation, err := store.ReservePropagation(context.Background(), key, testRetention(t), testLease(t))
	if err != nil || reservation != dkim2.ReplayPropagationReserved {
		t.Fatalf("own retried reservation=%v err=%v, want reserved", reservation, err)
	}
}

// TestReservePropagationPreviousValueMatrix proves the first-write mapping.
func TestReservePropagationPreviousValueMatrix(t *testing.T) {
	cases := []struct {
		name        string
		previous    string
		reservation dkim2.ReplayPropagationReservation
		code        dkim2.ReplayErrorCode
		takeover    bool
	}{
		{name: caseCommitted, previous: dkim2.ReplayPropagationCommittedValue, reservation: dkim2.ReplayPropagationAlreadyCommitted},
		{name: "live foreign", previous: pendingValue(time.Minute, foreignNonce), reservation: dkim2.ReplayPropagationPending},
		{name: "live legacy", previous: legacyPendingValue(testNow.Add(time.Minute)), reservation: dkim2.ReplayPropagationPending},
		{name: "expired foreign", previous: pendingValue(-time.Second, foreignNonce), reservation: dkim2.ReplayPropagationReserved, takeover: true},
		{name: "expired legacy", previous: legacyPendingValue(testNow.Add(-time.Second)), reservation: dkim2.ReplayPropagationReserved, takeover: true},
		{name: "lease boundary", previous: pendingValue(0, foreignNonce), reservation: dkim2.ReplayPropagationReserved, takeover: true},
		{name: "first-seen value", previous: firstTestValue, code: dkim2.ReplayErrorInconsistent},
		{name: "garbage", previous: "pending:x", code: dkim2.ReplayErrorInconsistent},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeBackend()
			key, storage := testReplayKey(t, true)
			fake.setStored(storage, test.previous)
			store := newTestStore(t, fake)
			reservation, err := store.ReservePropagation(context.Background(), key, testRetention(t), testLease(t))
			if test.code != "" {
				requireCode(t, err, test.code)
				if store.facts.strongest() != recoveryRestart {
					t.Fatal("grammar violation was not restart-sticky")
				}
				return
			}
			if err != nil || reservation != test.reservation {
				t.Fatalf("reservation=%v err=%v, want %v", reservation, err, test.reservation)
			}
			if test.takeover != (fake.evalShaCalls == 1) {
				t.Fatalf("takeover calls=%d", fake.evalShaCalls)
			}
			if test.takeover {
				if value, _ := fake.stored(storage); value != ownPending() {
					t.Fatal("takeover did not install the own pending value")
				}
			}
		})
	}
}

// TestLeaseTakeoverScriptOutcomes proves the compare-and-set reply mapping.
func TestLeaseTakeoverScriptOutcomes(t *testing.T) {
	expired := pendingValue(-time.Second, foreignNonce)
	cases := []struct {
		name        string
		reply       *redis.Cmd
		reservation dkim2.ReplayPropagationReservation
		code        dkim2.ReplayErrorCode
		recovery    recoveryClass
	}{
		{name: "expected", reply: redis.NewCmdResult(expired, nil), reservation: dkim2.ReplayPropagationReserved},
		{name: "own retried", reply: redis.NewCmdResult(ownPending(), nil), reservation: dkim2.ReplayPropagationReserved},
		{name: "competitor committed", reply: redis.NewCmdResult(dkim2.ReplayPropagationCommittedValue, nil), reservation: dkim2.ReplayPropagationAlreadyCommitted},
		{name: "competitor pending", reply: redis.NewCmdResult(pendingValue(time.Minute, "bbbbbbbbbbbbbbbb"), nil), reservation: dkim2.ReplayPropagationPending},
		{name: "expired between writes", reply: redis.NewCmdResult(nil, redis.Nil), code: dkim2.ReplayErrorIndeterminate, recovery: recoveryTransient},
		{name: "garbage", reply: redis.NewCmdResult("v1", nil), code: dkim2.ReplayErrorInconsistent, recovery: recoveryRestart},
		{name: "integer", reply: redis.NewCmdResult(int64(1), nil), code: dkim2.ReplayErrorInconsistent, recovery: recoveryRestart},
		{name: caseEOF, reply: redis.NewCmdResult(nil, syntheticNetworkError), code: dkim2.ReplayErrorIndeterminate, recovery: recoveryTransient},
		{name: "script error", reply: redis.NewCmdResult(nil, syntheticServerError("ERR Error running script")), code: dkim2.ReplayErrorInconsistent, recovery: recoveryRestart},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeBackend()
			key, storage := testReplayKey(t, true)
			fake.setStored(storage, expired)
			fake.scriptReply = func(keys []string, args []any) *redis.Cmd {
				if keys[0] != storage || args[0] != expired || args[1] != ownPending() || args[2] != int64(1500) {
					t.Errorf("script keys=%v args=%v", keys, args)
				}
				return test.reply
			}
			store := newTestStore(t, fake)
			reservation, err := store.ReservePropagation(context.Background(), key, testRetention(t), testLease(t))
			if test.code != "" {
				requireCode(t, err, test.code)
				if store.facts.strongest() != test.recovery {
					t.Fatalf("recovery=%d, want %d", store.facts.strongest(), test.recovery)
				}
				return
			}
			if err != nil || reservation != test.reservation {
				t.Fatalf("reservation=%v err=%v, want %v", reservation, err, test.reservation)
			}
		})
	}
}

// TestLeaseTakeoverFallsBackToEvalOnlyOnNoScript proves EVALSHA-first dispatch.
func TestLeaseTakeoverFallsBackToEvalOnlyOnNoScript(t *testing.T) {
	fake := newFakeBackend()
	fake.noScript = true
	key, storage := testReplayKey(t, true)
	fake.setStored(storage, pendingValue(-time.Second, foreignNonce))
	store := newTestStore(t, fake)
	reservation, err := store.ReservePropagation(context.Background(), key, testRetention(t), testLease(t))
	if err != nil || reservation != dkim2.ReplayPropagationReserved {
		t.Fatalf("reservation=%v err=%v", reservation, err)
	}
	if fake.evalShaCalls != 1 || fake.evalCalls != 1 {
		t.Fatalf("evalsha=%d eval=%d", fake.evalShaCalls, fake.evalCalls)
	}
}

// TestCommitPropagationRuleIsUnchanged proves every valid previous value
// commits, nil is unresolved, and anything else is inconsistent.
func TestCommitPropagationRuleIsUnchanged(t *testing.T) {
	cases := []struct {
		name   string
		reply  *redis.Cmd
		commit dkim2.ReplayPropagationCommit
		code   dkim2.ReplayErrorCode
	}{
		{name: "own pending", reply: redis.NewCmdResult(ownPending(), nil), commit: dkim2.ReplayPropagationCommitted},
		{name: "foreign pending", reply: redis.NewCmdResult(pendingValue(time.Minute, foreignNonce), nil), commit: dkim2.ReplayPropagationCommitted},
		{name: "legacy pending", reply: redis.NewCmdResult("pending:1", nil), commit: dkim2.ReplayPropagationCommitted},
		{name: "own retried commit", reply: redis.NewCmdResult(dkim2.ReplayPropagationCommittedValue, nil), commit: dkim2.ReplayPropagationCommitted},
		{name: "absent", reply: redis.NewCmdResult(nil, redis.Nil), commit: dkim2.ReplayPropagationCommitUnresolved},
		{name: "first-seen value", reply: redis.NewCmdResult(foreignV2Value, nil), code: dkim2.ReplayErrorInconsistent},
		{name: caseEOF, reply: redis.NewCmdResult(nil, syntheticNetworkError), code: dkim2.ReplayErrorIndeterminate},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeBackend()
			fake.reply = func([]any) *redis.Cmd { return test.reply }
			store := newTestStore(t, fake)
			key, storage := testReplayKey(t, true)
			commit, err := store.CommitPropagation(context.Background(), key)
			want := []any{commandSet, storage, dkim2.ReplayPropagationCommittedValue, "xx", commandGet, "keepttl"}
			if got := fake.lastArgs(); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("pinned args=%v", got)
			}
			if test.code != "" {
				requireCode(t, err, test.code)
				return
			}
			if err != nil || commit != test.commit {
				t.Fatalf("commit=%v err=%v, want %v", commit, err, test.commit)
			}
		})
	}
}

// TestCommitPropagationRecognizesOwnRetriedCommit is the commit reproducer:
// the first attempt commits, its reply is lost, and the retry observes
// committed, which must stay committed.
func TestCommitPropagationRecognizesOwnRetriedCommit(t *testing.T) {
	fake := newFakeBackend()
	key, storage := testReplayKey(t, true)
	fake.setStored(storage, ownPending())
	fake.lostReplies = 1
	store := newTestStore(t, fake)
	commit, err := store.CommitPropagation(context.Background(), key)
	if err != nil || commit != dkim2.ReplayPropagationCommitted {
		t.Fatalf("own retried commit=%v err=%v, want committed", commit, err)
	}
}

// TestPropagationLifecycleRoundTrip proves reserve, pending, commit, and committed in sequence.
func TestPropagationLifecycleRoundTrip(t *testing.T) {
	fake := newFakeBackend()
	store := newTestStore(t, fake)
	deps := fakeDependencies(fake)
	deps.nonceSource = strings.NewReader("\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7")
	other, err := newStoreWithDependencies(context.Background(), testConfig(), Secrets{}, deps)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := testReplayKey(t, true)
	steps := []func() (string, error){
		func() (string, error) {
			value, err := store.ReservePropagation(context.Background(), key, testRetention(t), testLease(t))
			return value.String(), err
		},
		func() (string, error) {
			value, err := other.ReservePropagation(context.Background(), key, testRetention(t), testLease(t))
			return value.String(), err
		},
		func() (string, error) {
			value, err := store.CommitPropagation(context.Background(), key)
			return value.String(), err
		},
		func() (string, error) {
			value, err := other.ReservePropagation(context.Background(), key, testRetention(t), testLease(t))
			return value.String(), err
		},
	}
	for index, want := range []string{"reserved", "pending", "committed", "committed"} {
		got, err := steps[index]()
		if err != nil || got != want {
			t.Fatalf("step %d=%q err=%v, want %q", index, got, err, want)
		}
	}
}

// TestReservePropagationRejectsInvalidLease proves input refusal before I/O.
func TestReservePropagationRejectsInvalidLease(t *testing.T) {
	fake := newFakeBackend()
	store := newTestStore(t, fake)
	key, _ := testReplayKey(t, true)
	_, err := store.ReservePropagation(context.Background(), key, testRetention(t), dkim2.ReplayLease{})
	requireCode(t, err, dkim2.ReplayErrorInvalidRequest)
	if len(fake.doArgs) != 0 {
		t.Fatal("invalid lease dispatched")
	}
}
