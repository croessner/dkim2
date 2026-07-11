package keyresolver

import (
	"testing"
	"time"
)

// TestDefaultLimitsMatchClosedDNSBounds verifies every default and hard maximum.
func TestDefaultLimitsMatchClosedDNSBounds(t *testing.T) {
	limits := DefaultLimits()
	if limits.MaxSelectorBytes != 253 || limits.MaxSelectorLabels != 127 ||
		limits.MaxSigningDomainBytes != 253 || limits.MaxSigningDomainLabels != 127 ||
		limits.MaxOwnerBytes != 253 || limits.MaxTXTRecords != 1 ||
		limits.MaxTXTRecordBytes != 8<<10 || limits.MaxTags != 32 ||
		limits.MaxTagNameBytes != 63 || limits.MaxTagValueBytes != 8<<10 ||
		limits.MaxDecodedKeyBytes != 8<<10 || limits.MaxCacheEntries != 1_024 ||
		limits.MaxPositiveTTL != time.Hour || limits.MaxNegativeTTL != 5*time.Minute ||
		limits.MaxStableErrorTTL != time.Minute || limits.MaxConcurrentLookups != 64 ||
		limits.MaxCoalescedWaiters != 64 || limits.LookupTimeout != 5*time.Second {
		t.Fatalf("DefaultLimits() = %#v", limits)
	}
	if err := limits.Validate(); err != nil {
		t.Fatalf("DefaultLimits().Validate() error = %v", err)
	}
}

// TestLimitsAllowOnlyDeclaredNarrowing verifies exact maxima, narrowing, and cache disabling.
func TestLimitsAllowOnlyDeclaredNarrowing(t *testing.T) {
	limits := HardLimits()
	if err := limits.Validate(); err != nil {
		t.Fatalf("HardLimits().Validate() error = %v", err)
	}
	limits.MaxSelectorBytes--
	limits.MaxSelectorLabels--
	limits.MaxSigningDomainBytes--
	limits.MaxSigningDomainLabels--
	limits.MaxOwnerBytes--
	limits.MaxTXTRecordBytes--
	limits.MaxTags--
	limits.MaxTagNameBytes--
	limits.MaxTagValueBytes--
	limits.MaxDecodedKeyBytes--
	limits.MaxCacheEntries = 0
	limits.MaxPositiveTTL = 0
	limits.MaxNegativeTTL = 0
	limits.MaxStableErrorTTL = 0
	limits.MaxConcurrentLookups--
	limits.MaxCoalescedWaiters--
	limits.LookupTimeout--
	if err := limits.Validate(); err != nil {
		t.Fatalf("narrow limits Validate() error = %v", err)
	}
}

// TestLimitsRejectZeroNegativeAndWidenedValues verifies every invalid boundary.
func TestLimitsRejectZeroNegativeAndWidenedValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Limits)
	}{
		{name: "selector bytes zero", mutate: func(l *Limits) { l.MaxSelectorBytes = 0 }},
		{name: "selector bytes wide", mutate: func(l *Limits) { l.MaxSelectorBytes = 254 }},
		{name: "selector labels zero", mutate: func(l *Limits) { l.MaxSelectorLabels = 0 }},
		{name: "selector labels wide", mutate: func(l *Limits) { l.MaxSelectorLabels = 128 }},
		{name: "domain bytes zero", mutate: func(l *Limits) { l.MaxSigningDomainBytes = 0 }},
		{name: "domain bytes wide", mutate: func(l *Limits) { l.MaxSigningDomainBytes = 254 }},
		{name: "domain labels zero", mutate: func(l *Limits) { l.MaxSigningDomainLabels = 0 }},
		{name: "domain labels wide", mutate: func(l *Limits) { l.MaxSigningDomainLabels = 128 }},
		{name: "owner zero", mutate: func(l *Limits) { l.MaxOwnerBytes = 0 }},
		{name: "owner wide", mutate: func(l *Limits) { l.MaxOwnerBytes = 254 }},
		{name: "records zero", mutate: func(l *Limits) { l.MaxTXTRecords = 0 }},
		{name: "records wide", mutate: func(l *Limits) { l.MaxTXTRecords = 2 }},
		{name: "record bytes zero", mutate: func(l *Limits) { l.MaxTXTRecordBytes = 0 }},
		{name: "record bytes wide", mutate: func(l *Limits) { l.MaxTXTRecordBytes = (64 << 10) + 1 }},
		{name: "tags zero", mutate: func(l *Limits) { l.MaxTags = 0 }},
		{name: "tags wide", mutate: func(l *Limits) { l.MaxTags = 129 }},
		{name: "tag name zero", mutate: func(l *Limits) { l.MaxTagNameBytes = 0 }},
		{name: "tag name wide", mutate: func(l *Limits) { l.MaxTagNameBytes = 64 }},
		{name: "tag value zero", mutate: func(l *Limits) { l.MaxTagValueBytes = 0 }},
		{name: "tag value wide", mutate: func(l *Limits) { l.MaxTagValueBytes = (64 << 10) + 1 }},
		{name: "key zero", mutate: func(l *Limits) { l.MaxDecodedKeyBytes = 0 }},
		{name: "key wide", mutate: func(l *Limits) { l.MaxDecodedKeyBytes = (64 << 10) + 1 }},
		{name: "cache negative", mutate: func(l *Limits) { l.MaxCacheEntries = -1 }},
		{name: "cache wide", mutate: func(l *Limits) { l.MaxCacheEntries = 65_537 }},
		{name: "positive ttl negative", mutate: func(l *Limits) { l.MaxPositiveTTL = -1 }},
		{name: "positive ttl wide", mutate: func(l *Limits) { l.MaxPositiveTTL = 24*time.Hour + 1 }},
		{name: "negative ttl negative", mutate: func(l *Limits) { l.MaxNegativeTTL = -1 }},
		{name: "negative ttl wide", mutate: func(l *Limits) { l.MaxNegativeTTL = time.Hour + 1 }},
		{name: "stable ttl negative", mutate: func(l *Limits) { l.MaxStableErrorTTL = -1 }},
		{name: "stable ttl wide", mutate: func(l *Limits) { l.MaxStableErrorTTL = 5*time.Minute + 1 }},
		{name: "lookups zero", mutate: func(l *Limits) { l.MaxConcurrentLookups = 0 }},
		{name: "lookups wide", mutate: func(l *Limits) { l.MaxConcurrentLookups = 1_025 }},
		{name: "waiters zero", mutate: func(l *Limits) { l.MaxCoalescedWaiters = 0 }},
		{name: "waiters wide", mutate: func(l *Limits) { l.MaxCoalescedWaiters = 1_025 }},
		{name: "timeout zero", mutate: func(l *Limits) { l.LookupTimeout = 0 }},
		{name: "timeout wide", mutate: func(l *Limits) { l.LookupTimeout = 30*time.Second + 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limits := DefaultLimits()
			tt.mutate(&limits)
			if err := limits.Validate(); err == nil || !IsErrorClass(err, ErrorClassContract) {
				t.Fatalf("Limits.Validate() error = %v, want contract", err)
			}
		})
	}
}
