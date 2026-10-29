package redisstore

import (
	"context"
	"strings"
	"testing"

	dkim2 "github.com/croessner/dkim2"
	"github.com/redis/go-redis/v9"
)

// FuzzRedisResultMapping proves the reply and error mapping never panics,
// stays inside the closed taxonomy, never echoes server text, never reports
// unavailable when the client may have dispatched more than once, and only
// reports first seen for an absent or own previous value.
func FuzzRedisResultMapping(f *testing.F) {
	for _, seed := range []struct {
		kind   uint8
		text   string
		single bool
	}{
		{0, "", true}, {1, firstTestValue, true}, {1, foreignV2Value, false}, {1, "v1", true},
		{1, "pending:1:0123456789abcdef", true}, {2, "READONLY replica", true}, {2, "READONLY replica", false},
		{2, "NOAUTH x", true}, {2, "ERR x", true}, {2, "", true}, {3, caseEOF, true}, {4, "", true}, {5, "", true},
	} {
		f.Add(seed.kind, seed.text, seed.single)
	}
	f.Fuzz(func(t *testing.T, kind uint8, text string, single bool) {
		if len(text) > 2*maximumReplyBytes {
			return
		}
		reply := fuzzReply(kind, text)
		outcome := mapValueReply(reply, single)
		if outcome.err != nil {
			code := dkim2.ReplayErrorCodeOf(outcome.err)
			switch code {
			case dkim2.ReplayErrorIndeterminate, dkim2.ReplayErrorInconsistent, dkim2.ReplayErrorInternalInvariant:
			case dkim2.ReplayErrorUnavailable:
				if !single {
					t.Fatal("unavailable reported although the write may have been retried")
				}
			default:
				t.Fatalf("mapping produced code %q outside the write taxonomy", code)
			}
			if outcome.present || outcome.recovery == recoveryNone ||
				text != "" && len(text) > 3 && strings.Contains(outcome.err.Error(), text) {
				t.Fatal("failure outcome carried a value, no recovery, or server text")
			}
			return
		}
		if outcome.present && len(outcome.previous) > maximumReplyBytes {
			t.Fatal("oversized previous value accepted")
		}

		fake := newFakeBackend()
		fake.reply = func([]any) *redis.Cmd { return fuzzReply(kind, text) }
		store := newTestStore(t, fake)
		key, _ := testReplayKey(t, false)
		check, err := store.CheckAndRemember(context.Background(), key, testRetention(t))
		if err != nil {
			return
		}
		_, _, valid := dkim2.ParseReplayFirstSeenValue(outcome.previous)
		switch check {
		case dkim2.ReplayCheckFirstSeen:
			if outcome.present && outcome.previous != firstTestValue {
				t.Fatal("foreign value reported first seen")
			}
		case dkim2.ReplayCheckReplayed:
			if !outcome.present || !valid || outcome.previous == firstTestValue {
				t.Fatal("replayed reported without a valid foreign value")
			}
		default:
			t.Fatal("unexpected check outcome")
		}
	})
}

// fuzzReply builds one synthetic go-redis reply from a closed kind selector.
func fuzzReply(kind uint8, text string) *redis.Cmd {
	switch kind % 6 {
	case 0:
		return redis.NewCmdResult(nil, redis.Nil)
	case 1:
		return redis.NewCmdResult(text, nil)
	case 2:
		return redis.NewCmdResult(nil, redisServerError(text))
	case 3:
		return redis.NewCmdResult(nil, syntheticNetworkError)
	case 4:
		return redis.NewCmdResult(int64(len(text)), nil)
	default:
		return redis.NewCmdResult(text, redis.Nil)
	}
}
