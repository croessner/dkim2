package valkey

import (
	"context"
	"encoding/binary"
	"time"

	dkim2 "github.com/croessner/dkim2"
	valkeygo "github.com/valkey-io/valkey-go"
)

// conditionalSetMode is the closed set of value-conditional SET forms the
// propagation record uses. Every form carries GET so that one round trip
// both applies the transition and returns the previous stored value, and
// every form needs only the +set grant of the application principal.
type conditionalSetMode uint8

const (
	// conditionalSetIfAbsent is SET key value NX GET PX <ms>: insert-if-absent
	// reservation of a fresh pending record under the retention TTL.
	conditionalSetIfAbsent conditionalSetMode = iota + 1
	// conditionalSetIfEqual is SET key value IFEQ <expected> GET PX <ms>: the
	// compare-and-set that re-serves an expired lease only against the exact
	// previous value this attempt observed (Valkey 9 value-conditional SET).
	conditionalSetIfEqual
	// conditionalSetIfPresent is SET key value XX GET KEEPTTL: the monotonic
	// pending-to-committed transition that keeps the retention TTL.
	conditionalSetIfPresent
)

// conditionalSet is one exact value-conditional SET request.
type conditionalSet struct {
	key          string
	value        string
	expected     string
	milliseconds int64
	mode         conditionalSetMode
}

// impossibleCommand represents a local builder contradiction that must never dispatch.
type impossibleCommand struct{}

// IsRetryable reports the contradiction as retryable so the store refuses it before dispatch.
func (impossibleCommand) IsRetryable() bool { return true }

// BuildConditionalSet constructs exactly one value-conditional SET with GET.
// Each form is one explicit builder chain rooted at Set, so the source
// boundary audit can prove that GET only ever appears as a SET option.
func (c valkeyCommandClient) BuildConditionalSet(request conditionalSet) command {
	switch request.mode {
	case conditionalSetIfAbsent:
		return nativeCommand{completed: c.client.B().Set().Key(request.key).Value(request.value).
			Nx().Get().PxMilliseconds(request.milliseconds).Build()}
	case conditionalSetIfEqual:
		return nativeCommand{completed: c.client.B().Set().Key(request.key).Value(request.value).
			Ifeq(request.expected).Get().PxMilliseconds(request.milliseconds).Build()}
	case conditionalSetIfPresent:
		return nativeCommand{completed: c.client.B().Set().Key(request.key).Value(request.value).
			Xx().Get().Keepttl().Build()}
	default:
		return impossibleCommand{}
	}
}

// valueOutcome is one closed previous-value/error/recovery triple of a GET-form SET.
type valueOutcome struct {
	previous string
	present  bool
	recovery recoveryClass
	err      error
}

// ReservePropagation reserves one propagation coordinate in two phases at
// most: an insert-if-absent write, and, only when the observed record is a
// pending record whose lease has expired, one compare-and-set against that
// exact observed value. A live lease is pending, a committed record is
// reported without any write, and a record that changed under the
// compare-and-set is reported as the state the competing writer left, never
// as reserved. Ordinary first-seen records are never touched.
func (s *Store) ReservePropagation(
	ctx context.Context,
	key dkim2.ReplayKey,
	retention dkim2.ReplayRetention,
	lease dkim2.ReplayLease,
) (reservation dkim2.ReplayPropagationReservation, resultErr error) {
	if err := s.admitPropagation(ctx); err != nil {
		return 0, err
	}
	if !retention.Valid() || !lease.Valid() {
		return 0, dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
	}
	now := s.wallNow()
	pending := dkim2.FormatReplayPropagationPending(now.Add(lease.Duration()))
	completed, finish, err := s.buildKeyedCommand(ctx, key, func(storageKey string) command {
		return s.client.BuildConditionalSet(conditionalSet{
			key: storageKey, value: pending, milliseconds: retention.Milliseconds(), mode: conditionalSetIfAbsent,
		})
	})
	if err != nil {
		return 0, err
	}
	defer finish()
	if err := preflightContext(ctx); err != nil {
		s.publishPreflightFailure(err)
		return 0, err
	}
	first := s.dispatchValue(ctx, completed)
	if first.err != nil {
		s.publishFailure(first.recovery)
		return 0, first.err
	}
	if !first.present {
		s.publishSuccess()
		return dkim2.ReplayPropagationReserved, nil
	}
	state, leaseExpiry, ok := dkim2.ParseReplayPropagationValue(first.previous)
	if !ok {
		s.publishFailure(recoveryRestart)
		return 0, dkim2.NewReplayError(dkim2.ReplayErrorInconsistent)
	}
	if state == dkim2.ReplayPropagationStateCommitted {
		s.publishSuccess()
		return dkim2.ReplayPropagationAlreadyCommitted, nil
	}
	if leaseExpiry.After(now) {
		s.publishSuccess()
		return dkim2.ReplayPropagationPending, nil
	}
	refresh, err := s.buildFollowUpCommand(key, func(storageKey string) command {
		return s.client.BuildConditionalSet(conditionalSet{
			key: storageKey, value: pending, expected: first.previous,
			milliseconds: retention.Milliseconds(), mode: conditionalSetIfEqual,
		})
	})
	if err != nil {
		return 0, err
	}
	if err := preflightContext(ctx); err != nil {
		s.publishPreflightFailure(err)
		return 0, err
	}
	second := s.dispatchValue(ctx, refresh)
	if second.err != nil {
		s.publishFailure(second.recovery)
		return 0, second.err
	}
	if !second.present {
		// The record expired between the two writes; nothing was reserved
		// and the attempt must not fall through to an unbounded retry.
		s.publishFailure(recoveryTransient)
		return 0, dkim2.NewReplayError(dkim2.ReplayErrorIndeterminate)
	}
	if second.previous == first.previous {
		s.publishSuccess()
		return dkim2.ReplayPropagationReserved, nil
	}
	competing, _, ok := dkim2.ParseReplayPropagationValue(second.previous)
	if !ok {
		s.publishFailure(recoveryRestart)
		return 0, dkim2.NewReplayError(dkim2.ReplayErrorInconsistent)
	}
	s.publishSuccess()
	if competing == dkim2.ReplayPropagationStateCommitted {
		return dkim2.ReplayPropagationAlreadyCommitted, nil
	}
	return dkim2.ReplayPropagationPending, nil
}

// CommitPropagation moves one propagation record from pending to committed
// with a single replace-if-present write that keeps the retention TTL. The
// transition is monotonic, so a committed record is reported committed
// again, and an absent record, whose retention has expired, is unresolved.
func (s *Store) CommitPropagation(
	ctx context.Context,
	key dkim2.ReplayKey,
) (commit dkim2.ReplayPropagationCommit, resultErr error) {
	if err := s.admitPropagation(ctx); err != nil {
		return 0, err
	}
	completed, finish, err := s.buildKeyedCommand(ctx, key, func(storageKey string) command {
		return s.client.BuildConditionalSet(conditionalSet{
			key: storageKey, value: dkim2.ReplayPropagationCommittedValue, mode: conditionalSetIfPresent,
		})
	})
	if err != nil {
		return 0, err
	}
	defer finish()
	if err := preflightContext(ctx); err != nil {
		s.publishPreflightFailure(err)
		return 0, err
	}
	outcome := s.dispatchValue(ctx, completed)
	if outcome.err != nil {
		s.publishFailure(outcome.recovery)
		return 0, outcome.err
	}
	if !outcome.present {
		s.publishSuccess()
		return dkim2.ReplayPropagationCommitUnresolved, nil
	}
	if _, _, ok := dkim2.ParseReplayPropagationValue(outcome.previous); !ok {
		s.publishFailure(recoveryRestart)
		return 0, dkim2.NewReplayError(dkim2.ReplayErrorInconsistent)
	}
	s.publishSuccess()
	return dkim2.ReplayPropagationCommitted, nil
}

// admitPropagation applies the shared preflight and lifecycle refusals.
func (s *Store) admitPropagation(ctx context.Context) error {
	if s == nil || s.storeCore == nil {
		return dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
	}
	if err := preflightContext(ctx); err != nil {
		s.publishPreflightFailure(err)
		return err
	}
	switch s.lifecycleState() {
	case lifecycleClosing, lifecycleClosed:
		return dkim2.NewReplayError(dkim2.ReplayErrorClosed)
	case lifecycleReady:
		return nil
	default:
		s.publishFailure(recoveryRestart)
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
}

// wallNow returns the wall-clock instant that lease expiries are stamped
// with. Lease values are compared across daemon instances, so they are never
// derived from the provider's security-evidence clock.
func (s *Store) wallNow() time.Time {
	if s == nil || s.storeCore == nil || s.wallClock == nil {
		return time.Now().UTC()
	}
	return s.wallClock().UTC()
}

// buildFollowUpCommand builds one further command of an already admitted
// operation under the same protected-key seam and evidence freshness rule.
func (s *Store) buildFollowUpCommand(
	key dkim2.ReplayKey,
	build func(storageKey string) command,
) (completed command, resultErr error) {
	defer func() {
		if recover() != nil {
			completed = nil
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
			s.publishFailure(recoveryRestart)
		}
	}()
	if err := dkim2.UseReplayStorageKey(key, func(storageKey string) error {
		if evidenceErr := s.requireFreshSecurityEvidence(); evidenceErr != nil {
			return evidenceErr
		}
		completed = build(storageKey)
		if nilInterface(completed) || completed.IsRetryable() {
			return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
		return nil
	}); err != nil {
		if dkim2.ReplayErrorCodeOf(err) == dkim2.ReplayErrorInternalInvariant {
			s.publishFailure(recoveryRestart)
		}
		return nil, err
	}
	return completed, nil
}

// dispatchValue owns the post-boundary panic and uncertainty mapping of one GET-form SET.
func (s *Store) dispatchValue(ctx context.Context, completed command) (outcome valueOutcome) {
	defer func() {
		if recover() != nil {
			outcome = valueFailure(dkim2.ReplayErrorIndeterminate, recoveryRestart)
		}
	}()
	result := s.client.Do(ctx, completed)
	if nilInterface(result) {
		return valueFailure(dkim2.ReplayErrorInternalInvariant, recoveryRestart)
	}
	return mapValueResult(result)
}

// mapValueResult applies the exact ordered lossless mapping of a GET-form SET
// reply: a null reply means no previous value, a bulk string is the previous
// value and must be proven by its cache frame and by the closed propagation
// value grammar, and every server error keeps the shared kind mapping.
func mapValueResult(result resultReader) valueOutcome {
	if result.NonValkeyError() != nil {
		return valueFailure(dkim2.ReplayErrorIndeterminate, recoveryTransient)
	}
	raw, err := result.ToString()
	if len(raw) > maximumReplyBytes {
		return valueFailure(dkim2.ReplayErrorInconsistent, recoveryRestart)
	}
	if err == nil {
		return mapBulkValue(result, raw)
	}
	if valkeygo.IsValkeyNil(err) {
		if raw != "" {
			return valueFailure(dkim2.ReplayErrorInternalInvariant, recoveryRestart)
		}
		return valueOutcome{}
	}
	serverError, direct := err.(*valkeygo.ValkeyError)
	if !direct || serverError == nil {
		if valkeygo.IsParseErr(err) {
			return valueFailure(dkim2.ReplayErrorInconsistent, recoveryRestart)
		}
		return valueFailure(dkim2.ReplayErrorInternalInvariant, recoveryRestart)
	}
	kind, valid := leadingErrorKind(raw)
	if !valid {
		return valueFailure(dkim2.ReplayErrorInconsistent, recoveryRestart)
	}
	mapped := mapServerKind(kind)
	return valueFailure(dkim2.ReplayErrorCodeOf(mapped.err), mapped.recovery)
}

// mapBulkValue proves one bulk-string previous value against the pinned
// v1.0.77 cache frame and the closed propagation value grammar.
func mapBulkValue(result resultReader, raw string) valueOutcome {
	if _, _, ok := dkim2.ParseReplayPropagationValue(raw); !ok {
		return valueFailure(dkim2.ReplayErrorInconsistent, recoveryRestart)
	}
	message, err := result.ToMessage()
	if err != nil || !message.IsString() {
		return valueFailure(dkim2.ReplayErrorInternalInvariant, recoveryRestart)
	}
	if message.CacheSize() != 16+len(raw) {
		return valueFailure(dkim2.ReplayErrorInternalInvariant, recoveryRestart)
	}
	frame := message.CacheMarshal(make([]byte, 0, 16+len(raw)))
	if len(frame) != 16+len(raw) || frame[7] != '$' ||
		binary.BigEndian.Uint64(frame[8:16]) != uint64(len(raw)) || string(frame[16:]) != raw {
		return valueFailure(dkim2.ReplayErrorInternalInvariant, recoveryRestart)
	}
	return valueOutcome{previous: raw, present: true}
}

// valueFailure constructs one previous-value-free bounded failure mapping.
func valueFailure(code dkim2.ReplayErrorCode, recovery recoveryClass) valueOutcome {
	return valueOutcome{recovery: recovery, err: dkim2.NewReplayError(code)}
}

var _ dkim2.ReplayPropagationStore = (*Store)(nil)
