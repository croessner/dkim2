package dkim2

import (
	"context"
	"time"

	"github.com/croessner/dkim2/internal/replay"
)

const (
	// ReplayKeyAlgorithm identifies the frozen privacy-preserving replay-key algorithm.
	ReplayKeyAlgorithm = replay.KeyAlgorithm
	// ReplayStoredValue is the exact bounded marker stored by enabled replay providers.
	ReplayStoredValue = replay.StoredValue
)

// ReplayKey is an opaque fixed-length replay-storage capability.
type ReplayKey = replay.Key

// ReplayCheck identifies one successful replay-store outcome.
type ReplayCheck = replay.Check

const (
	// ReplayCheckFirstSeen means the identity was atomically retained for the first time.
	ReplayCheckFirstSeen = replay.CheckFirstSeen
	// ReplayCheckReplayed means the identity already existed without retention extension.
	ReplayCheckReplayed = replay.CheckReplayed
	// ReplayCheckDisabled means explicit local policy selected no replay storage.
	ReplayCheckDisabled = replay.CheckDisabled
)

// ReplayStoreState identifies one bounded replay-store lifecycle state.
type ReplayStoreState = replay.StoreState

const (
	// ReplayStoreReady permits enabled storage operations.
	ReplayStoreReady = replay.StoreReady
	// ReplayStoreDegraded reports a fail-closed enabled provider impairment.
	ReplayStoreDegraded = replay.StoreDegraded
	// ReplayStoreDisabled reports an explicitly selected disabled provider.
	ReplayStoreDisabled = replay.StoreDisabled
	// ReplayStoreClosing rejects new operations while admitted work drains.
	ReplayStoreClosing = replay.StoreClosing
	// ReplayStoreClosed rejects all later operations.
	ReplayStoreClosed = replay.StoreClosed
)

// ReplayErrorCode identifies one stable replay failure class.
type ReplayErrorCode = replay.ErrorCode

const (
	// ReplayErrorInvalidRequest classifies invalid input or a missing required value.
	ReplayErrorInvalidRequest = replay.ErrorCodeInvalidRequest
	// ReplayErrorMisconfigured classifies incomplete or unsafe construction.
	ReplayErrorMisconfigured = replay.ErrorCodeMisconfigured
	// ReplayErrorLimitExceeded classifies a hard bounded-resource refusal.
	ReplayErrorLimitExceeded = replay.ErrorCodeLimitExceeded
	// ReplayErrorUnavailable classifies a proved pre-dispatch backend outage.
	ReplayErrorUnavailable = replay.ErrorCodeUnavailable
	// ReplayErrorIndeterminate classifies a write that may have crossed mutation dispatch.
	ReplayErrorIndeterminate = replay.ErrorCodeIndeterminate
	// ReplayErrorInconsistent classifies an authoritative contradictory backend outcome.
	ReplayErrorInconsistent = replay.ErrorCodeInconsistent
	// ReplayErrorCancelled classifies pre-dispatch caller cancellation.
	ReplayErrorCancelled = replay.ErrorCodeCancelled
	// ReplayErrorDeadlineExceeded classifies a pre-dispatch elapsed caller deadline.
	ReplayErrorDeadlineExceeded = replay.ErrorCodeDeadlineExceeded
	// ReplayErrorClosed classifies work rejected after close begins.
	ReplayErrorClosed = replay.ErrorCodeClosed
	// ReplayErrorInternalInvariant classifies impossible in-process state.
	ReplayErrorInternalInvariant = replay.ErrorCodeInternalInvariant
)

// ReplayError is one typed content-free replay failure.
type ReplayError = replay.Error

// NewReplayError constructs one stable replay failure without protected detail.
func NewReplayError(code ReplayErrorCode) error {
	return replay.NewError(code)
}

// ReplayErrorCodeOf returns the stable code for one direct replay failure.
func ReplayErrorCodeOf(err error) ReplayErrorCode {
	return replay.ErrorCodeOf(err)
}

// IsReplayError reports whether err is one direct member of the closed taxonomy.
func IsReplayError(err error) bool {
	return replay.IsTypedError(err)
}

// ReplayRetention is an immutable validated whole-millisecond retention period.
type ReplayRetention = replay.Retention

// NewReplayRetention validates and constructs one replay retention period.
func NewReplayRetention(duration time.Duration) (ReplayRetention, error) {
	return replay.NewRetention(duration)
}

// DefaultReplayRetention returns the frozen fourteen-day default.
func DefaultReplayRetention() ReplayRetention {
	return replay.DefaultRetention()
}

// ReplayStore atomically checks and retains replay identities.
type ReplayStore interface {
	CheckAndRemember(context.Context, ReplayKey, ReplayRetention) (ReplayCheck, error)
}

// ManagedReplayStore adds bounded lifecycle control to a replay store.
type ManagedReplayStore interface {
	ReplayStore
	State() ReplayStoreState
	Close(context.Context) error
}

// ReplayIdentity is one immutable message-wide authenticated replay identity.
type ReplayIdentity = replay.Identity

// ReplayIdentitySet is the compatibility container for one message-wide identity.
type ReplayIdentitySet = replay.IdentitySet //nolint:staticcheck // Public compatibility remains until the documented API window closes.

// ReplayDeriver owns one cloned deployment-local HMAC secret and its lifecycle.
type ReplayDeriver = replay.Deriver

// NewReplayDeriver validates and clones one exact replay-key secret and epoch.
func NewReplayDeriver(secret []byte, epoch uint32) (*ReplayDeriver, error) {
	return replay.NewDeriver(secret, epoch)
}

// ReplayLimits contains reusable hard-bounded replay-provider resources.
type ReplayLimits = replay.Limits

// ReplayClock supplies one deterministic operation time to the memory store.
type ReplayClock = replay.Clock

// ReplayClockFunc adapts one function to the memory-store clock seam.
type ReplayClockFunc = replay.ClockFunc

// ReplayMemoryConfig contains bounded resources and a required injected clock.
type ReplayMemoryConfig struct {
	Limits ReplayLimits
	Clock  ReplayClock
}

// ReplayMemoryStore is a deterministic bounded heap-expiring replay provider.
type ReplayMemoryStore = replay.MemoryStore

// NewReplayMemoryStore validates and constructs one bounded memory replay provider.
func NewReplayMemoryStore(config ReplayMemoryConfig) (*ReplayMemoryStore, error) {
	return replay.NewMemoryStore(replay.MemoryConfig{
		Limits: config.Limits,
		Clock:  config.Clock,
	})
}

// ReplayDisabledStore is an explicit no-storage replay provider.
type ReplayDisabledStore = replay.DisabledStore

// NewReplayDisabledStore constructs one explicit disabled replay provider.
func NewReplayDisabledStore() *ReplayDisabledStore {
	return replay.NewDisabledStore()
}

// UseReplayStorageKey authorizes one synchronous pre-dispatch callback for a protected key.
func UseReplayStorageKey(key ReplayKey, use func(storageKey string) error) error {
	return replay.UseStorageKey(key, use)
}

// ReplayPropagationKeyDomainLabel is the distinct domain-separation frame of propagation coordinates.
const ReplayPropagationKeyDomainLabel = replay.PropagationKeyDomainLabel

// ReplayLease is an immutable validated whole-millisecond propagation pending lease.
type ReplayLease = replay.Lease

// NewReplayLease validates and constructs one propagation pending lease.
func NewReplayLease(duration time.Duration) (ReplayLease, error) {
	return replay.NewLease(duration)
}

// ReplayPropagationState is the closed stored state of one propagation coordinate.
type ReplayPropagationState = replay.PropagationState

const (
	// ReplayPropagationStatePending reports a reserved coordinate whose attempt has not committed.
	ReplayPropagationStatePending = replay.PropagationStatePending
	// ReplayPropagationStateCommitted reports a coordinate whose propagated report was accepted.
	ReplayPropagationStateCommitted = replay.PropagationStateCommitted
	// ReplayPropagationCommittedValue is the exact stored value of a committed coordinate.
	ReplayPropagationCommittedValue = replay.PropagationCommittedValue
	// ReplayPropagationPendingPrefix starts the stored value of a pending coordinate.
	ReplayPropagationPendingPrefix = replay.PropagationPendingPrefix
)

// FormatReplayPropagationPending renders the stored pending value for one lease expiry.
func FormatReplayPropagationPending(leaseExpiry time.Time) string {
	return replay.FormatPropagationPending(leaseExpiry)
}

// ParseReplayPropagationValue decodes one stored propagation value.
func ParseReplayPropagationValue(value string) (ReplayPropagationState, time.Time, bool) {
	return replay.ParsePropagationValue(value)
}

// ReplayPropagationReservation identifies one successful propagation reservation outcome.
type ReplayPropagationReservation = replay.PropagationReservation

const (
	// ReplayPropagationReserved means the coordinate is now pending under a fresh lease.
	ReplayPropagationReserved = replay.PropagationReserved
	// ReplayPropagationPending means another attempt holds a live lease.
	ReplayPropagationPending = replay.PropagationPending
	// ReplayPropagationAlreadyCommitted means the coordinate was committed within retention.
	ReplayPropagationAlreadyCommitted = replay.PropagationAlreadyCommitted
	// ReplayPropagationReservationDisabled means explicit local policy selected no replay storage.
	ReplayPropagationReservationDisabled = replay.PropagationReservationDisabled
)

// ReplayPropagationCommit identifies one successful propagation commit outcome.
type ReplayPropagationCommit = replay.PropagationCommit

const (
	// ReplayPropagationCommitted means the coordinate is committed.
	ReplayPropagationCommitted = replay.PropagationCommitted
	// ReplayPropagationCommitUnresolved means the token resolves to no pending or committed coordinate within retention.
	ReplayPropagationCommitUnresolved = replay.PropagationCommitUnresolved
	// ReplayPropagationCommitDisabled means explicit local policy selected no replay storage.
	ReplayPropagationCommitDisabled = replay.PropagationCommitDisabled
)

// ReplayPropagationStore reserves and commits propagation coordinates in two phases.
type ReplayPropagationStore interface {
	ReservePropagation(context.Context, ReplayKey, ReplayRetention, ReplayLease) (ReplayPropagationReservation, error)
	CommitPropagation(context.Context, ReplayKey) (ReplayPropagationCommit, error)
}

// ReplayIdentities adapts only one coherent verifier-owned aggregate-current-PASS projection.
func ReplayIdentities(result VerifyResult) (ReplayIdentitySet, error) {
	if !result.replayEligible() || result.state == nil || !result.state.hasReplayProjection ||
		!result.state.replayProjection.Valid() {
		return ReplayIdentitySet{}, replay.NewError(replay.ErrorCodeInvalidRequest)
	}
	return replay.NewIdentitySet(result.state.replayProjection)
}
