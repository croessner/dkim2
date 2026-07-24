package replay

import (
	"math"
	"time"
)

const (
	minimumRetentionDuration = time.Second
	defaultRetentionDuration = 14 * 24 * time.Hour
	maximumRetentionDuration = 30 * 24 * time.Hour
)

// Retention is an immutable validated whole-millisecond retention period.
type Retention struct {
	milliseconds int64
}

// NewRetention validates and constructs one replay retention period.
func NewRetention(duration time.Duration) (Retention, error) {
	if duration < minimumRetentionDuration ||
		duration > maximumRetentionDuration ||
		duration%time.Millisecond != 0 {
		return Retention{}, NewError(ErrorCodeInvalidRequest)
	}
	milliseconds := int64(duration / time.Millisecond)
	if milliseconds <= 0 || time.Duration(milliseconds)*time.Millisecond != duration {
		return Retention{}, NewError(ErrorCodeInvalidRequest)
	}
	return Retention{milliseconds: milliseconds}, nil
}

// DefaultRetention returns the frozen fourteen-day default.
func DefaultRetention() Retention {
	retention, err := NewRetention(defaultRetentionDuration)
	if err != nil {
		panic("replay: invalid constant default retention")
	}
	return retention
}

// Valid reports whether retention satisfies the frozen whole-millisecond range.
func (r Retention) Valid() bool {
	_, err := NewRetention(r.Duration())
	return err == nil
}

// Duration returns the exact validated duration or zero for an invalid value.
func (r Retention) Duration() time.Duration {
	if r.milliseconds <= 0 || r.milliseconds > math.MaxInt64/int64(time.Millisecond) {
		return 0
	}
	duration := time.Duration(r.milliseconds) * time.Millisecond
	if int64(duration/time.Millisecond) != r.milliseconds {
		return 0
	}
	return duration
}

// Milliseconds returns the signed Valkey PX value or zero for an invalid value.
func (r Retention) Milliseconds() int64 {
	if !r.Valid() {
		return 0
	}
	return r.milliseconds
}

// AddTo computes an exact in-memory expiry without arithmetic wraparound.
func (r Retention) AddTo(now time.Time) (expiry time.Time, resultErr error) {
	defer func() {
		if recover() != nil {
			expiry = time.Time{}
			resultErr = NewError(ErrorCodeInternalInvariant)
		}
	}()
	if !r.Valid() {
		return time.Time{}, NewError(ErrorCodeInvalidRequest)
	}
	if now.IsZero() {
		return time.Time{}, NewError(ErrorCodeInternalInvariant)
	}
	duration := r.Duration()
	addSeconds := int64(duration / time.Second)
	addNanoseconds := int64(duration % time.Second)
	if int64(now.Nanosecond())+addNanoseconds >= int64(time.Second) {
		addSeconds++
	}
	if now.Unix() > math.MaxInt64-addSeconds {
		return time.Time{}, NewError(ErrorCodeInternalInvariant)
	}
	expiry = now.Add(duration)
	if !expiry.After(now) || expiry.Sub(now) != duration {
		return time.Time{}, NewError(ErrorCodeInternalInvariant)
	}
	return expiry, nil
}
