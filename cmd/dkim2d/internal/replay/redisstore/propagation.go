package redisstore

import (
	"context"
	"time"

	dkim2 "github.com/croessner/dkim2"
	"github.com/redis/go-redis/v9"
)

// ReservePropagation reserves one propagation coordinate in two writes at
// most: a nonce-bearing insert-if-absent, and, only when the observed record
// is a foreign pending record whose lease has expired, one single-key
// compare-and-set script against that exact observed value. A nil previous
// value or the store's own value is reserved, a committed record is reported
// without a further write, a live foreign lease is pending, and a record that
// changed under the compare-and-set is reported as the state the competing
// writer left, never as reserved.
func (s *Store) ReservePropagation(
	ctx context.Context,
	key dkim2.ReplayKey,
	retention dkim2.ReplayRetention,
	lease dkim2.ReplayLease,
) (dkim2.ReplayPropagationReservation, error) {
	if err := s.admitOperation(ctx); err != nil {
		return 0, err
	}
	if !s.retentionAllowed(retention) || !lease.Valid() {
		return 0, dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
	}
	nonce, err := s.newNonce()
	if err != nil {
		return 0, err
	}
	now := s.wallNow()
	own, err := dkim2.ReplayPropagationPendingValue(now.Add(lease.Duration()), nonce)
	if err != nil {
		s.publishFailure(recoveryRestart)
		return 0, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	command, finish, err := s.buildKeyedCommand(ctx, key, func(storageKey string) pinnedCommand {
		return insertIfAbsentCommand(storageKey, own, retention.Milliseconds())
	})
	if err != nil {
		return 0, err
	}
	defer finish()
	if err := preflightContext(ctx); err != nil {
		s.publishPreflightFailure(err)
		return 0, err
	}
	first := s.dispatch(ctx, func(ctx context.Context) *redis.Cmd { return command.run(ctx, s.client) })
	if first.err != nil {
		s.publishFailure(first.recovery)
		return 0, first.err
	}
	if !first.present || first.previous == own {
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
	takeover, err := s.buildTakeover(key, first.previous, own, retention.Milliseconds())
	if err != nil {
		return 0, err
	}
	if err := preflightContext(ctx); err != nil {
		s.publishPreflightFailure(err)
		return 0, err
	}
	second := s.dispatch(ctx, func(ctx context.Context) *redis.Cmd { return takeover.run(ctx, s.script, s.client) })
	return s.mapTakeover(first.previous, own, second)
}

// buildTakeover builds the compare-and-set of an already admitted operation
// under a second use of the protected-key seam, with the same key prefix.
func (s *Store) buildTakeover(
	key dkim2.ReplayKey,
	expected, replacement string,
	milliseconds int64,
) (takeover leaseTakeover, resultErr error) {
	defer func() {
		if recover() != nil {
			takeover = leaseTakeover{}
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
			s.publishFailure(recoveryRestart)
		}
	}()
	if err := dkim2.UseReplayStorageKey(key, func(storageKey string) error {
		takeover = leaseTakeover{
			key: s.keyPrefix + storageKey, expected: expected, replacement: replacement, milliseconds: milliseconds,
		}
		return nil
	}); err != nil {
		if dkim2.ReplayErrorCodeOf(err) == dkim2.ReplayErrorInternalInvariant {
			s.publishFailure(recoveryRestart)
		}
		return leaseTakeover{}, err
	}
	return takeover, nil
}

// mapTakeover classifies the compare-and-set reply. The expected value means
// this call replaced it; the store's own value means an earlier attempt of
// this call already replaced it; nil means the record expired between the two
// writes and nothing provable was reserved; any other value is the state a
// competing writer left.
func (s *Store) mapTakeover(
	expected, own string,
	outcome valueOutcome,
) (dkim2.ReplayPropagationReservation, error) {
	if outcome.err != nil {
		s.publishFailure(outcome.recovery)
		return 0, outcome.err
	}
	if !outcome.present {
		s.publishFailure(recoveryTransient)
		return 0, dkim2.NewReplayError(dkim2.ReplayErrorIndeterminate)
	}
	if outcome.previous == expected || outcome.previous == own {
		s.publishSuccess()
		return dkim2.ReplayPropagationReserved, nil
	}
	competing, _, ok := dkim2.ParseReplayPropagationValue(outcome.previous)
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

// CommitPropagation moves one propagation record to committed with a single
// replace-if-present write that keeps the retention TTL. Any valid previous
// propagation value, pending in either form, foreign or own, or already
// committed, yields committed, so a retried commit is idempotent. An absent
// record is unresolved, including the residual case where a retried commit
// runs after the record expired.
func (s *Store) CommitPropagation(
	ctx context.Context,
	key dkim2.ReplayKey,
) (dkim2.ReplayPropagationCommit, error) {
	if err := s.admitOperation(ctx); err != nil {
		return 0, err
	}
	command, finish, err := s.buildKeyedCommand(ctx, key, commitIfPresentCommand)
	if err != nil {
		return 0, err
	}
	defer finish()
	if err := preflightContext(ctx); err != nil {
		s.publishPreflightFailure(err)
		return 0, err
	}
	outcome := s.dispatch(ctx, func(ctx context.Context) *redis.Cmd { return command.run(ctx, s.client) })
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

// wallNow returns the wall-clock instant lease expiries are stamped with.
// Lease values are compared across daemon instances, so they always use UTC
// wall time.
func (s *Store) wallNow() time.Time {
	if s.wallClock == nil {
		return time.Now().UTC()
	}
	return s.wallClock().UTC()
}

var _ dkim2.ReplayPropagationStore = (*Store)(nil)
