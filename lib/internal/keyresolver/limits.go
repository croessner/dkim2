package keyresolver

import "time"

const (
	hardMaxNameBytes         = 253
	hardMaxNameLabels        = 127
	hardMaxTXTRecords        = 1
	hardMaxTXTRecordBytes    = 64 << 10
	hardMaxTags              = 128
	hardMaxTagNameBytes      = 63
	hardMaxTagValueBytes     = 64 << 10
	hardMaxDecodedKeyBytes   = 64 << 10
	hardMaxCacheEntries      = 65_536
	hardMaxConcurrentLookups = 1_024
	hardMaxCoalescedWaiters  = 1_024
)

// Limits bounds DNS owner, record, parser, key, cache, and lookup resources.
type Limits struct {
	MaxSelectorBytes       int
	MaxSelectorLabels      int
	MaxSigningDomainBytes  int
	MaxSigningDomainLabels int
	MaxOwnerBytes          int
	MaxTXTRecords          int
	MaxTXTRecordBytes      int
	MaxTags                int
	MaxTagNameBytes        int
	MaxTagValueBytes       int
	MaxDecodedKeyBytes     int
	MaxCacheEntries        int
	MaxPositiveTTL         time.Duration
	MaxNegativeTTL         time.Duration
	MaxStableErrorTTL      time.Duration
	MaxConcurrentLookups   int
	MaxCoalescedWaiters    int
	LookupTimeout          time.Duration
}

// DefaultLimits returns the restrictive DNS resolver defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxSelectorBytes: 253, MaxSelectorLabels: 127,
		MaxSigningDomainBytes: 253, MaxSigningDomainLabels: 127, MaxOwnerBytes: 253,
		MaxTXTRecords: 1, MaxTXTRecordBytes: 8 << 10, MaxTags: 32,
		MaxTagNameBytes: 63, MaxTagValueBytes: 8 << 10, MaxDecodedKeyBytes: 8 << 10,
		MaxCacheEntries: 1_024, MaxPositiveTTL: time.Hour, MaxNegativeTTL: 5 * time.Minute,
		MaxStableErrorTTL: time.Minute, MaxConcurrentLookups: 64,
		MaxCoalescedWaiters: 64, LookupTimeout: 5 * time.Second,
	}
}

// HardLimits returns every declared hard maximum.
func HardLimits() Limits {
	return Limits{
		MaxSelectorBytes: hardMaxNameBytes, MaxSelectorLabels: hardMaxNameLabels,
		MaxSigningDomainBytes: hardMaxNameBytes, MaxSigningDomainLabels: hardMaxNameLabels,
		MaxOwnerBytes: hardMaxNameBytes, MaxTXTRecords: hardMaxTXTRecords,
		MaxTXTRecordBytes: hardMaxTXTRecordBytes, MaxTags: hardMaxTags,
		MaxTagNameBytes: hardMaxTagNameBytes, MaxTagValueBytes: hardMaxTagValueBytes,
		MaxDecodedKeyBytes: hardMaxDecodedKeyBytes, MaxCacheEntries: hardMaxCacheEntries,
		MaxPositiveTTL: 24 * time.Hour, MaxNegativeTTL: time.Hour,
		MaxStableErrorTTL: 5 * time.Minute, MaxConcurrentLookups: hardMaxConcurrentLookups,
		MaxCoalescedWaiters: hardMaxCoalescedWaiters, LookupTimeout: 30 * time.Second,
	}
}

// Validate rejects zero, negative, or widened limits except declared cache-disable values.
func (l Limits) Validate() error {
	if !positiveWithin(l.MaxSelectorBytes, hardMaxNameBytes) ||
		!positiveWithin(l.MaxSelectorLabels, hardMaxNameLabels) ||
		!positiveWithin(l.MaxSigningDomainBytes, hardMaxNameBytes) ||
		!positiveWithin(l.MaxSigningDomainLabels, hardMaxNameLabels) ||
		!positiveWithin(l.MaxOwnerBytes, hardMaxNameBytes) ||
		!positiveWithin(l.MaxTXTRecords, hardMaxTXTRecords) ||
		!positiveWithin(l.MaxTXTRecordBytes, hardMaxTXTRecordBytes) ||
		!positiveWithin(l.MaxTags, hardMaxTags) ||
		!positiveWithin(l.MaxTagNameBytes, hardMaxTagNameBytes) ||
		!positiveWithin(l.MaxTagValueBytes, hardMaxTagValueBytes) ||
		!positiveWithin(l.MaxDecodedKeyBytes, hardMaxDecodedKeyBytes) ||
		!nonNegativeWithin(l.MaxCacheEntries, hardMaxCacheEntries) ||
		!nonNegativeDurationWithin(l.MaxPositiveTTL, 24*time.Hour) ||
		!nonNegativeDurationWithin(l.MaxNegativeTTL, time.Hour) ||
		!nonNegativeDurationWithin(l.MaxStableErrorTTL, 5*time.Minute) ||
		!positiveWithin(l.MaxConcurrentLookups, hardMaxConcurrentLookups) ||
		!positiveWithin(l.MaxCoalescedWaiters, hardMaxCoalescedWaiters) ||
		l.LookupTimeout <= 0 || l.LookupTimeout > 30*time.Second {
		return newResolverError(ErrorClassContract)
	}
	return nil
}

// positiveWithin reports whether a count is positive and no wider than its hard maximum.
func positiveWithin(value, maximum int) bool {
	return value > 0 && value <= maximum
}

// nonNegativeWithin reports whether a count may disable behavior without exceeding its maximum.
func nonNegativeWithin(value, maximum int) bool {
	return value >= 0 && value <= maximum
}

// nonNegativeDurationWithin reports whether a duration may disable caching without widening its cap.
func nonNegativeDurationWithin(value, maximum time.Duration) bool {
	return value >= 0 && value <= maximum
}
