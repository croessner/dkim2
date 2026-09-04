package replay

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// PropagationKeyDomainLabel is the distinct HMAC domain-separation frame
	// label for delivery-status propagation coordinates.
	PropagationKeyDomainLabel = "dkim2-replay-propagation-v1"
	// PropagationCommittedValue is the exact stored value of a committed coordinate.
	PropagationCommittedValue = "committed"
	// PropagationPendingPrefix starts the stored value of a pending coordinate;
	// the suffix is the lease expiry in Unix milliseconds.
	PropagationPendingPrefix = "pending:"

	minimumLeaseDuration = time.Millisecond
	maximumLeaseDuration = 24 * time.Hour
	maxLeaseExpiryDigits = 16
)

// Lease is an immutable validated whole-millisecond pending lease.
type Lease struct {
	milliseconds int64
}

// NewLease validates and constructs one propagation pending lease.
func NewLease(duration time.Duration) (Lease, error) {
	if duration < minimumLeaseDuration || duration > maximumLeaseDuration || duration%time.Millisecond != 0 {
		return Lease{}, NewError(ErrorCodeInvalidRequest)
	}
	return Lease{milliseconds: int64(duration / time.Millisecond)}, nil
}

// Valid reports whether the lease satisfies the frozen whole-millisecond range.
func (l Lease) Valid() bool {
	_, err := NewLease(l.Duration())
	return err == nil
}

// Duration returns the exact validated duration or zero for an invalid value.
func (l Lease) Duration() time.Duration {
	if l.milliseconds <= 0 || l.milliseconds > int64(maximumLeaseDuration/time.Millisecond) {
		return 0
	}
	return time.Duration(l.milliseconds) * time.Millisecond
}

// PropagationState is the closed stored state of one propagation coordinate.
type PropagationState string

const (
	// PropagationStatePending reports a reserved coordinate whose attempt has not committed.
	PropagationStatePending PropagationState = "pending"
	// PropagationStateCommitted reports a coordinate whose propagated report was accepted.
	PropagationStateCommitted PropagationState = "committed"
)

// Known reports whether the state belongs to the closed vocabulary.
func (s PropagationState) Known() bool {
	return s == PropagationStatePending || s == PropagationStateCommitted
}

// PropagationReservation identifies one successful reservation outcome.
type PropagationReservation uint8

const (
	// PropagationReserved means the coordinate was absent or its lease had expired and is now pending.
	PropagationReserved PropagationReservation = iota + 1
	// PropagationPending means another attempt holds a live lease.
	PropagationPending
	// PropagationAlreadyCommitted means the coordinate was committed within retention.
	PropagationAlreadyCommitted
	// PropagationReservationDisabled means explicit local policy selected no replay storage.
	PropagationReservationDisabled
)

// Known reports whether the reservation belongs to the closed vocabulary.
func (r PropagationReservation) Known() bool {
	return r >= PropagationReserved && r <= PropagationReservationDisabled
}

// String returns the stable reservation value or a constant unknown marker.
func (r PropagationReservation) String() string {
	switch r {
	case PropagationReserved:
		return "reserved"
	case PropagationPending:
		return "pending"
	case PropagationAlreadyCommitted:
		return "committed"
	case PropagationReservationDisabled:
		return disabledValueText
	default:
		return unknownValueText
	}
}

// GoString returns the stable reservation representation.
func (r PropagationReservation) GoString() string { return r.String() }

// Format prevents unknown numeric values from reaching formatting output.
func (r PropagationReservation) Format(state fmt.State, _ rune) { formatClosedValue(state, r.String()) }

// PropagationCommit identifies one successful commit outcome.
type PropagationCommit uint8

const (
	// PropagationCommitted means the coordinate is committed, whether by this call or before.
	PropagationCommitted PropagationCommit = iota + 1
	// PropagationCommitUnresolved means the token resolves to no pending or
	// committed coordinate within retention; it formats as "unresolved" and is
	// the outcome the daemon answers with 409. The plain "unknown" marker is
	// reserved for values outside the closed vocabulary.
	PropagationCommitUnresolved
	// PropagationCommitDisabled means explicit local policy selected no replay storage.
	PropagationCommitDisabled
)

// Known reports whether the commit belongs to the closed vocabulary.
func (c PropagationCommit) Known() bool {
	return c >= PropagationCommitted && c <= PropagationCommitDisabled
}

// String returns the stable commit value or a constant unknown marker.
func (c PropagationCommit) String() string {
	switch c {
	case PropagationCommitted:
		return "committed"
	case PropagationCommitUnresolved:
		return "unresolved"
	case PropagationCommitDisabled:
		return disabledValueText
	default:
		return unknownValueText
	}
}

// GoString returns the stable commit representation.
func (c PropagationCommit) GoString() string { return c.String() }

// Format prevents unknown numeric values from reaching formatting output.
func (c PropagationCommit) Format(state fmt.State, _ rune) { formatClosedValue(state, c.String()) }

// PropagationStore reserves and commits delivery-status propagation
// coordinates in two phases. ReservePropagation inserts a pending record with
// a lease if the coordinate is absent or its pending lease has expired,
// reports a live lease as pending, and reports a committed record as
// committed. CommitPropagation moves a pending record to committed by
// compare-and-set, is idempotent for committed records, and reports an absent
// or expired record as unknown. Ordinary first-seen records are never touched.
type PropagationStore interface {
	ReservePropagation(context.Context, Key, Retention, Lease) (PropagationReservation, error)
	CommitPropagation(context.Context, Key) (PropagationCommit, error)
}

// FormatPropagationPending renders the stored pending value for one lease expiry.
func FormatPropagationPending(leaseExpiry time.Time) string {
	return PropagationPendingPrefix + strconv.FormatInt(leaseExpiry.UnixMilli(), 10)
}

// ParsePropagationValue decodes one stored propagation value. It reports the
// closed state, the lease expiry for pending values, and false for every
// string outside the closed grammar.
func ParsePropagationValue(value string) (PropagationState, time.Time, bool) {
	if value == PropagationCommittedValue {
		return PropagationStateCommitted, time.Time{}, true
	}
	if !strings.HasPrefix(value, PropagationPendingPrefix) {
		return "", time.Time{}, false
	}
	digits := value[len(PropagationPendingPrefix):]
	if len(digits) == 0 || len(digits) > maxLeaseExpiryDigits {
		return "", time.Time{}, false
	}
	for _, character := range digits {
		if character < '0' || character > '9' {
			return "", time.Time{}, false
		}
	}
	milliseconds, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || milliseconds <= 0 {
		return "", time.Time{}, false
	}
	return PropagationStatePending, time.UnixMilli(milliseconds), true
}
