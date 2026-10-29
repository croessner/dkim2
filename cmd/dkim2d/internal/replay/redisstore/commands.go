package redisstore

import (
	"context"
	"errors"
	"strings"

	dkim2 "github.com/croessner/dkim2"
	"github.com/redis/go-redis/v9"
)

const (
	maximumReplyBytes = 4 * 1024
	maximumKindBytes  = 32
	// maxClientsReplyPrefix is the constant prefix of the connection-limit
	// rejection. It shares the generic ERR kind but proves only that the
	// server refused this attempt for capacity, so it is transient; go-redis
	// retries it as well.
	maxClientsReplyPrefix = "ERR max number of clients reached"
)

// leaseTakeoverScriptSource is the single-key compare-and-set that re-serves
// an expired propagation lease. It replaces the record only when it still
// holds the exact value the caller observed, and always returns the value it
// found, so a retried execution that finds its own new value proves its own
// earlier commit. It touches exactly KEYS[1] and is therefore cluster-safe.
const leaseTakeoverScriptSource = `local current = redis.call('GET', KEYS[1])
if current == ARGV[1] then
  redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3])
end
return current`

// pinnedCommand is one immutable argument vector produced only by the
// builders below. Every attempt go-redis makes for it carries identical
// bytes, including the per-operation nonce inside the value.
type pinnedCommand struct {
	args []any
}

// insertIfAbsentCommand pins SET key value NX GET PX <ms>. PX is spelled out
// because go-redis SetArgs would emit EX for whole-second durations.
func insertIfAbsentCommand(key, value string, milliseconds int64) pinnedCommand {
	return pinnedCommand{args: []any{"set", key, value, "nx", "get", "px", milliseconds}}
}

// commitIfPresentCommand pins SET key committed XX GET KEEPTTL.
func commitIfPresentCommand(key string) pinnedCommand {
	return pinnedCommand{args: []any{"set", key, dkim2.ReplayPropagationCommittedValue, "xx", "get", "keepttl"}}
}

// leaseTakeover is one pinned compare-and-set script invocation.
type leaseTakeover struct {
	key          string
	expected     string
	replacement  string
	milliseconds int64
}

// run executes the pinned SET argument vector against one backend.
func (c pinnedCommand) run(ctx context.Context, client backend) *redis.Cmd {
	return client.Do(ctx, c.args...)
}

// run executes the takeover script with EVALSHA, falling back to EVAL only on
// NOSCRIPT, which proves the EVALSHA attempt did not execute.
func (t leaseTakeover) run(ctx context.Context, script *redis.Script, client backend) *redis.Cmd {
	return script.Run(ctx, client, []string{t.key}, t.expected, t.replacement, t.milliseconds)
}

// valueOutcome is one closed previous-value/error/recovery triple of one write.
type valueOutcome struct {
	previous string
	present  bool
	recovery recoveryClass
	err      error
}

// valueFailure constructs one previous-value-free bounded failure mapping.
func valueFailure(code dkim2.ReplayErrorCode, recovery recoveryClass) valueOutcome {
	return valueOutcome{recovery: recovery, err: dkim2.NewReplayError(code)}
}

// mapValueReply applies the ordered reply mapping shared by every write: a
// nil reply means no previous value, one bounded bulk string is the previous
// value, and every error is classified by mapCommandError. Grammar checks of
// the previous value belong to the operation that knows its value family.
func mapValueReply(command *redis.Cmd, singleAttempt bool) valueOutcome {
	if command == nil {
		return valueFailure(dkim2.ReplayErrorInternalInvariant, recoveryRestart)
	}
	value, err := command.Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			if value != nil {
				return valueFailure(dkim2.ReplayErrorInternalInvariant, recoveryRestart)
			}
			return valueOutcome{}
		}
		return mapCommandError(err, singleAttempt)
	}
	text, ok := value.(string)
	if !ok || len(text) > maximumReplyBytes {
		return valueFailure(dkim2.ReplayErrorInconsistent, recoveryRestart)
	}
	return valueOutcome{previous: text, present: true}
}

// mapCommandError classifies one failed write. A server error reply proves
// only that its own attempt did not execute; when the client may have
// dispatched the write more than once, an earlier attempt may have
// committed, so availability-class server errors are reported as
// indeterminate. Every non-server error (dial, pool, timeout, EOF, context,
// closed client) may follow dispatch and is indeterminate.
func mapCommandError(err error, singleAttempt bool) valueOutcome {
	var serverError redis.Error
	if !errors.As(err, &serverError) || serverError == nil {
		return valueFailure(dkim2.ReplayErrorIndeterminate, recoveryTransient)
	}
	outcome := classifyServerReply(serverError.Error())
	if !singleAttempt && dkim2.ReplayErrorCodeOf(outcome.err) == dkim2.ReplayErrorUnavailable {
		return valueFailure(dkim2.ReplayErrorIndeterminate, outcome.recovery)
	}
	return outcome
}

// classifyServerReply maps one server error reply into its bounded outcome.
// Only the constant max-clients prefix and the leading kind token are
// inspected; the remaining reply text is never rendered or retained.
func classifyServerReply(reply string) valueOutcome {
	if strings.HasPrefix(reply, maxClientsReplyPrefix) {
		return valueFailure(dkim2.ReplayErrorUnavailable, recoveryTransient)
	}
	kind, valid := leadingErrorKind(reply)
	if !valid {
		return valueFailure(dkim2.ReplayErrorInconsistent, recoveryRestart)
	}
	return mapServerKind(kind)
}

// mapServerKind maps one extracted server error kind without inspecting its suffix.
func mapServerKind(kind string) valueOutcome {
	switch kind {
	case "NOAUTH", "WRONGPASS", "NOPERM":
		return valueFailure(dkim2.ReplayErrorUnavailable, recoveryRestart)
	case "OOM", "READONLY", "MASTERDOWN", "CLUSTERDOWN", "LOADING", "NOREPLICAS",
		"MISCONF", "TRYAGAIN", "BUSY", "MOVED", "ASK":
		return valueFailure(dkim2.ReplayErrorUnavailable, recoveryTransient)
	default:
		return valueFailure(dkim2.ReplayErrorInconsistent, recoveryRestart)
	}
}

// leadingErrorKind extracts one exact bounded ASCII server-error token.
func leadingErrorKind(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	end := len(raw)
	for index := range len(raw) {
		if raw[index] == ' ' {
			end = index
			break
		}
	}
	if end < 1 || end > maximumKindBytes {
		return "", false
	}
	for index := range end {
		value := raw[index]
		if value >= 'A' && value <= 'Z' {
			continue
		}
		if index > 0 && (value >= '0' && value <= '9' || value == '_') {
			continue
		}
		return "", false
	}
	return raw[:end], true
}
