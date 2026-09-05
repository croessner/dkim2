package valkey

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	dkim2 "github.com/croessner/dkim2"
	valkeygo "github.com/valkey-io/valkey-go"
)

const (
	propagationTestPendingOld = "pending:1700000060000"
	propagationTestPendingOne = "pending:1"
	propagationTestExpectSet  = "set"
	tokenSET                  = "SET"
	tokenGET                  = "GET"
)

// propagationScriptedClient answers a fixed sequence of conditional-set
// dispatches while recording the exact command shapes the store built.
type propagationScriptedClient struct {
	mu      sync.Mutex
	builds  []conditionalSet
	results []resultReader
	plain   int
}

// BuildSet records an ordinary first-seen build, which propagation never issues.
func (c *propagationScriptedClient) BuildSet(string, string, int64) command {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.plain++
	return fakeCommand{}
}

// BuildConditionalSet records the exact conditional shape and returns a non-retryable command.
func (c *propagationScriptedClient) BuildConditionalSet(request conditionalSet) command {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.builds = append(c.builds, request)
	return fakeCommand{}
}

// Do returns the next scripted result and fails closed when the script is exhausted.
func (c *propagationScriptedClient) Do(context.Context, command) resultReader {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.results) == 0 {
		return impossibleResult{}
	}
	next := c.results[0]
	c.results = c.results[1:]
	return next
}

// nilReply is the authoritative null reply of a GET-form SET.
func nilReply(t *testing.T) resultReader {
	t.Helper()
	return resultFromMessage(t, cachedMessage(t, '_', ""))
}

// bulkReply is the authoritative bulk-string previous value of a GET-form SET.
func bulkReply(t *testing.T, value string) resultReader {
	t.Helper()
	return resultFromMessage(t, cachedMessage(t, '$', value))
}

// newPropagationStore constructs one command-boundary store with a fixed wall clock.
func newPropagationStore(t *testing.T, client commandClient, now time.Time) *Store {
	t.Helper()
	store := mustCommandStore(t, client)
	store.wallClock = func() time.Time { return now }
	return store
}

// TestPropagationPendingCommittedReservation proves the reservation command
// shapes and the closed reply mapping: an absent record is reserved with one
// insert-if-absent command, a live lease is pending, a committed record is
// reported without any write, and an expired lease is re-served by exactly
// one value-conditional compare-and-set on the observed previous value.
func TestPropagationPendingCommittedReservation(t *testing.T) {
	now := time.UnixMilli(1_700_000_100_000)
	retention, err := dkim2.NewReplayRetention(90 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := dkim2.NewReplayLease(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pendingNew := dkim2.FormatReplayPropagationPending(now.Add(2 * time.Second))
	pendingLive := dkim2.FormatReplayPropagationPending(now.Add(time.Second))
	cases := []struct {
		name    string
		replies []resultReader
		want    dkim2.ReplayPropagationReservation
		code    dkim2.ReplayErrorCode
		builds  []conditionalSet
	}{
		{
			name:    "absent is reserved",
			replies: []resultReader{nilReply(t)},
			want:    dkim2.ReplayPropagationReserved,
			builds:  []conditionalSet{{value: pendingNew, milliseconds: 90_000, mode: conditionalSetIfAbsent}},
		},
		{
			name:    "committed is reported",
			replies: []resultReader{bulkReply(t, dkim2.ReplayPropagationCommittedValue)},
			want:    dkim2.ReplayPropagationAlreadyCommitted,
			builds:  []conditionalSet{{value: pendingNew, milliseconds: 90_000, mode: conditionalSetIfAbsent}},
		},
		{
			name:    "live lease is pending",
			replies: []resultReader{bulkReply(t, pendingLive)},
			want:    dkim2.ReplayPropagationPending,
			builds:  []conditionalSet{{value: pendingNew, milliseconds: 90_000, mode: conditionalSetIfAbsent}},
		},
		{
			name:    "expired lease is re-served by compare-and-set",
			replies: []resultReader{bulkReply(t, propagationTestPendingOld), bulkReply(t, propagationTestPendingOld)},
			want:    dkim2.ReplayPropagationReserved,
			builds: []conditionalSet{
				{value: pendingNew, milliseconds: 90_000, mode: conditionalSetIfAbsent},
				{value: pendingNew, expected: propagationTestPendingOld, milliseconds: 90_000, mode: conditionalSetIfEqual},
			},
		},
		{
			name:    "lost refresh race is pending",
			replies: []resultReader{bulkReply(t, propagationTestPendingOld), bulkReply(t, pendingLive)},
			want:    dkim2.ReplayPropagationPending,
			builds: []conditionalSet{
				{value: pendingNew, milliseconds: 90_000, mode: conditionalSetIfAbsent},
				{value: pendingNew, expected: propagationTestPendingOld, milliseconds: 90_000, mode: conditionalSetIfEqual},
			},
		},
		{
			name:    "commit during refresh race is reported",
			replies: []resultReader{bulkReply(t, propagationTestPendingOld), bulkReply(t, dkim2.ReplayPropagationCommittedValue)},
			want:    dkim2.ReplayPropagationAlreadyCommitted,
			builds: []conditionalSet{
				{value: pendingNew, milliseconds: 90_000, mode: conditionalSetIfAbsent},
				{value: pendingNew, expected: propagationTestPendingOld, milliseconds: 90_000, mode: conditionalSetIfEqual},
			},
		},
		{
			name:    "record vanished during refresh is indeterminate",
			replies: []resultReader{bulkReply(t, propagationTestPendingOld), nilReply(t)},
			code:    dkim2.ReplayErrorIndeterminate,
			builds: []conditionalSet{
				{value: pendingNew, milliseconds: 90_000, mode: conditionalSetIfAbsent},
				{value: pendingNew, expected: propagationTestPendingOld, milliseconds: 90_000, mode: conditionalSetIfEqual},
			},
		},
		{
			name:    "foreign stored value is inconsistent",
			replies: []resultReader{bulkReply(t, "v1")},
			code:    dkim2.ReplayErrorInconsistent,
			builds:  []conditionalSet{{value: pendingNew, milliseconds: 90_000, mode: conditionalSetIfAbsent}},
		},
		{
			name:    "simple string reply is inconsistent",
			replies: []resultReader{resultFromMessage(t, cachedMessage(t, '+', "OK"))},
			code:    dkim2.ReplayErrorInconsistent,
			builds:  []conditionalSet{{value: pendingNew, milliseconds: 90_000, mode: conditionalSetIfAbsent}},
		},
		{
			name:    "server error keeps the shared kind mapping",
			replies: []resultReader{resultFromMessage(t, cachedMessage(t, '-', serverKindOOM+" "+syntheticReplyMarker))},
			code:    dkim2.ReplayErrorLimitExceeded,
			builds:  []conditionalSet{{value: pendingNew, milliseconds: 90_000, mode: conditionalSetIfAbsent}},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			client := &propagationScriptedClient{results: testCase.replies}
			store := newPropagationStore(t, client, now)
			key := validReplayKey(t)
			got, err := store.ReservePropagation(context.Background(), key, retention, lease)
			if testCase.code == "" {
				if err != nil || got != testCase.want {
					t.Fatalf("reservation = %s, code %q; want %s", got, dkim2.ReplayErrorCodeOf(err), testCase.want)
				}
			} else if dkim2.ReplayErrorCodeOf(err) != testCase.code || got != 0 {
				t.Fatalf("reservation = %s, code %q; want code %q", got, dkim2.ReplayErrorCodeOf(err), testCase.code)
			}
			if err != nil && strings.Contains(err.Error(), syntheticReplyMarker) {
				t.Fatal("bounded error exposed server reply content")
			}
			assertConditionalBuilds(t, client, testCase.builds)
			if len(client.results) != 0 {
				t.Fatalf("%d scripted replies were not consumed", len(client.results))
			}
		})
	}
}

// TestPropagationPendingCommittedCommit proves the commit is one
// replace-if-present write that keeps the retention TTL, is idempotent for a
// committed record, and reports an absent record as unresolved without any
// second command.
func TestPropagationPendingCommittedCommit(t *testing.T) {
	now := time.UnixMilli(1_700_000_100_000)
	cases := []struct {
		name  string
		reply resultReader
		want  dkim2.ReplayPropagationCommit
		code  dkim2.ReplayErrorCode
	}{
		{name: "pending commits", reply: bulkReply(t, propagationTestPendingOld), want: dkim2.ReplayPropagationCommitted},
		{name: "committed is idempotent", reply: bulkReply(t, dkim2.ReplayPropagationCommittedValue), want: dkim2.ReplayPropagationCommitted},
		{name: "absent is unresolved", reply: nilReply(t), want: dkim2.ReplayPropagationCommitUnresolved},
		{name: "transport failure is indeterminate", reply: &fakeResult{nonValkeyErr: context.DeadlineExceeded}, code: dkim2.ReplayErrorIndeterminate},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			client := &propagationScriptedClient{results: []resultReader{testCase.reply}}
			store := newPropagationStore(t, client, now)
			got, err := store.CommitPropagation(context.Background(), validReplayKey(t))
			if testCase.code == "" {
				if err != nil || got != testCase.want {
					t.Fatalf("commit = %s, code %q; want %s", got, dkim2.ReplayErrorCodeOf(err), testCase.want)
				}
			} else if dkim2.ReplayErrorCodeOf(err) != testCase.code || got != 0 {
				t.Fatalf("commit = %s, code %q; want code %q", got, dkim2.ReplayErrorCodeOf(err), testCase.code)
			}
			assertConditionalBuilds(t, client, []conditionalSet{{
				value: dkim2.ReplayPropagationCommittedValue, mode: conditionalSetIfPresent,
			}})
		})
	}
}

// TestPropagationStoreRejectsBeforeDispatch proves preflight, lifecycle, and
// argument validation refuse the operation before any command is built.
func TestPropagationStoreRejectsBeforeDispatch(t *testing.T) {
	now := time.UnixMilli(1_700_000_100_000)
	retention := dkim2.DefaultReplayRetention()
	lease, err := dkim2.NewReplayLease(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	client := &propagationScriptedClient{}
	store := newPropagationStore(t, client, now)
	key := validReplayKey(t)
	if _, err := store.ReservePropagation(cancelled, key, retention, lease); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorCancelled {
		t.Fatalf("cancelled reservation code = %q", dkim2.ReplayErrorCodeOf(err))
	}
	if _, err := store.CommitPropagation(cancelled, key); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorCancelled {
		t.Fatalf("cancelled commit code = %q", dkim2.ReplayErrorCodeOf(err))
	}
	if _, err := store.ReservePropagation(context.Background(), key, retention, dkim2.ReplayLease{}); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInvalidRequest {
		t.Fatalf("invalid lease code = %q", dkim2.ReplayErrorCodeOf(err))
	}
	if _, err := store.ReservePropagation(context.Background(), key, dkim2.ReplayRetention{}, lease); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInvalidRequest {
		t.Fatalf("invalid retention code = %q", dkim2.ReplayErrorCodeOf(err))
	}
	if _, err := store.ReservePropagation(context.Background(), dkim2.ReplayKey{}, retention, lease); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInvalidRequest {
		t.Fatalf("invalid key code = %q", dkim2.ReplayErrorCodeOf(err))
	}
	var nilStore *Store
	if _, err := nilStore.ReservePropagation(context.Background(), key, retention, lease); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInvalidRequest {
		t.Fatalf("nil store reservation code = %q", dkim2.ReplayErrorCodeOf(err))
	}
	if _, err := nilStore.CommitPropagation(context.Background(), key); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInvalidRequest {
		t.Fatalf("nil store commit code = %q", dkim2.ReplayErrorCodeOf(err))
	}
	if len(client.builds) != 0 || client.plain != 0 {
		t.Fatal("a refused operation built a command")
	}
	closing := newPropagationStore(t, &propagationScriptedClient{}, now)
	if err := closing.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := closing.ReservePropagation(context.Background(), key, retention, lease); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorClosed {
		t.Fatalf("closed reservation code = %q", dkim2.ReplayErrorCodeOf(err))
	}
	if _, err := closing.CommitPropagation(context.Background(), key); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorClosed {
		t.Fatalf("closed commit code = %q", dkim2.ReplayErrorCodeOf(err))
	}
}

// TestNativeAdapterBuildsExactConditionalSets pins the wire tokens of the
// three value-conditional SET forms and proves every form is non-retryable.
func TestNativeAdapterBuildsExactConditionalSets(t *testing.T) {
	key := slotZeroStorageKey()
	adapter := valkeyCommandClient{client: &nativeClientProbe{}}
	cases := []struct {
		name    string
		request conditionalSet
		tokens  []string
	}{
		{
			name:    "insert if absent",
			request: conditionalSet{key: key, value: propagationTestPendingOne, milliseconds: 1234, mode: conditionalSetIfAbsent},
			tokens:  []string{tokenSET, key, propagationTestPendingOne, "NX", tokenGET, "PX", "1234"},
		},
		{
			name:    "compare and set",
			request: conditionalSet{key: key, value: "pending:2", expected: propagationTestPendingOne, milliseconds: 1234, mode: conditionalSetIfEqual},
			tokens:  []string{tokenSET, key, "pending:2", "IFEQ", propagationTestPendingOne, tokenGET, "PX", "1234"},
		},
		{
			name:    "replace if present",
			request: conditionalSet{key: key, value: "committed", mode: conditionalSetIfPresent},
			tokens:  []string{tokenSET, key, "committed", "XX", tokenGET, "KEEPTTL"},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			native, ok := adapter.BuildConditionalSet(testCase.request).(nativeCommand)
			if !ok {
				t.Fatal("production adapter returned an unexpected command wrapper")
			}
			if got := native.completed.Commands(); strings.Join(got, " ") != strings.Join(testCase.tokens, " ") {
				t.Fatalf("tokens = %q, want %q", got, testCase.tokens)
			}
			if native.IsRetryable() {
				t.Fatal("production conditional SET is retryable")
			}
		})
	}
	if _, ok := adapter.BuildConditionalSet(conditionalSet{key: key, value: "x"}).(impossibleCommand); !ok {
		t.Fatal("unknown conditional mode did not yield an impossible command")
	}
	if got := adapter.Do(context.Background(), impossibleCommand{}); got != (impossibleResult{}) {
		t.Fatal("impossible command reached the native client")
	}
}

// TestPropagationValueReplyProof proves the bulk-string proof rejects every
// reply whose cache frame contradicts its scalar projection.
func TestPropagationValueReplyProof(t *testing.T) {
	message := cachedMessage(t, '$', propagationTestPendingOld)
	valid := &fakeResult{raw: propagationTestPendingOld, message: message}
	if outcome := mapValueResult(valid); outcome.err != nil || !outcome.present || outcome.previous != propagationTestPendingOld {
		t.Fatalf("valid bulk reply mapped to %+v", outcome)
	}
	mismatched := &fakeResult{raw: propagationTestPendingOld, message: cachedMessage(t, '$', "pending:1700000060001")}
	if outcome := mapValueResult(mismatched); dkim2.ReplayErrorCodeOf(outcome.err) != dkim2.ReplayErrorInternalInvariant {
		t.Fatalf("frame payload contradiction mapped to %+v", outcome)
	}
	noMessage := &fakeResult{raw: propagationTestPendingOld, messageErr: context.Canceled}
	if outcome := mapValueResult(noMessage); dkim2.ReplayErrorCodeOf(outcome.err) != dkim2.ReplayErrorInternalInvariant {
		t.Fatalf("missing message proof mapped to %+v", outcome)
	}
	oversized := &fakeResult{raw: strings.Repeat("9", maximumReplyBytes+1)}
	if outcome := mapValueResult(oversized); dkim2.ReplayErrorCodeOf(outcome.err) != dkim2.ReplayErrorInconsistent {
		t.Fatalf("oversized reply mapped to %+v", outcome)
	}
	nilWithPayload := &fakeResult{raw: "x", err: valkeygo.Nil}
	if outcome := mapValueResult(nilWithPayload); dkim2.ReplayErrorCodeOf(outcome.err) != dkim2.ReplayErrorInternalInvariant {
		t.Fatalf("nil reply with payload mapped to %+v", outcome)
	}
}

// assertConditionalBuilds compares the recorded builds with the expected shapes
// while ignoring the protected storage key.
func assertConditionalBuilds(t *testing.T, client *propagationScriptedClient, want []conditionalSet) {
	t.Helper()
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.plain != 0 {
		t.Fatal("propagation issued an ordinary first-seen SET")
	}
	if len(client.builds) != len(want) {
		t.Fatalf("built %d conditional commands, want %d", len(client.builds), len(want))
	}
	for index := range want {
		got := client.builds[index]
		if got.key == "" || strings.Contains(got.key, syntheticSecretMarker) {
			t.Fatal("protected command key was absent or derived from a raw secret")
		}
		got.key = ""
		if got != want[index] {
			t.Fatalf("build %d = %+v, want %+v", index, got, want[index])
		}
	}
}
