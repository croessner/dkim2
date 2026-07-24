package replay

import (
	"math"
	"testing"
	"time"
)

// TestRetentionAcceptsOnlyFrozenIntegralMillisecondRange verifies exact bounds and units.
func TestRetentionAcceptsOnlyFrozenIntegralMillisecondRange(t *testing.T) {
	for _, duration := range []time.Duration{time.Second, defaultRetentionDuration, maximumRetentionDuration} {
		retention, err := NewRetention(duration)
		if err != nil || !retention.Valid() || retention.Duration() != duration ||
			retention.Milliseconds() != int64(duration/time.Millisecond) {
			t.Fatalf("NewRetention(%s) = %v, %v", duration, retention, err)
		}
	}
	if got := DefaultRetention(); !got.Valid() || got.Duration() != 14*24*time.Hour {
		t.Fatalf("DefaultRetention() = %v", got)
	}
}

// TestRetentionRejectsInvalidAndOverLimitDurations verifies zero, sign, precision, and cap failures.
func TestRetentionRejectsInvalidAndOverLimitDurations(t *testing.T) {
	for _, duration := range []time.Duration{
		0,
		-time.Millisecond,
		time.Nanosecond,
		time.Second - time.Millisecond,
		time.Second + time.Nanosecond,
		maximumRetentionDuration + time.Millisecond,
		time.Duration(math.MaxInt64),
	} {
		retention, err := NewRetention(duration)
		if retention != (Retention{}) || ErrorCodeOf(err) != ErrorCodeInvalidRequest {
			t.Fatalf("NewRetention(%s) = %v, %v", duration, retention, err)
		}
	}
}

// TestRetentionCheckedAdditionPreservesExactExpiry verifies exact boundaries and overflow rejection.
func TestRetentionCheckedAdditionPreservesExactExpiry(t *testing.T) {
	retention, err := NewRetention(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 123_000_000)
	expiry, err := retention.AddTo(now)
	if err != nil || !expiry.Equal(now.Add(time.Second)) || expiry.Sub(now) != time.Second {
		t.Fatalf("AddTo() = %v, %v", expiry, err)
	}

	nearMaximum := time.Unix(math.MaxInt64, 0)
	if got, addErr := retention.AddTo(nearMaximum); !got.IsZero() || ErrorCodeOf(addErr) != ErrorCodeInternalInvariant {
		t.Fatalf("AddTo(overflow) = %v, %v", got, addErr)
	}
	if got, addErr := retention.AddTo(time.Time{}); !got.IsZero() || ErrorCodeOf(addErr) != ErrorCodeInternalInvariant {
		t.Fatalf("AddTo(zero clock) = %v, %v", got, addErr)
	}
	if got, addErr := (Retention{}).AddTo(now); !got.IsZero() || ErrorCodeOf(addErr) != ErrorCodeInvalidRequest {
		t.Fatalf("zero retention AddTo() = %v, %v", got, addErr)
	}
}

// TestRetentionUsesSignedInt64Milliseconds verifies no platform-sized conversion truncates the maximum.
func TestRetentionUsesSignedInt64Milliseconds(t *testing.T) {
	retention, err := NewRetention(maximumRetentionDuration)
	if err != nil {
		t.Fatal(err)
	}
	const want = int64(2_592_000_000)
	if got := retention.Milliseconds(); got != want {
		t.Fatalf("maximum milliseconds = %d, want %d", got, want)
	}
	if int64(int32(retention.Milliseconds())) == retention.Milliseconds() {
		t.Fatal("test prerequisite failed: maximum retention unexpectedly fits signed 32-bit")
	}
}
