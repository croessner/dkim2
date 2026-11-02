package keyresolver

import (
	"bytes"
	"context"
	"testing"
	"time"
)

const policyTestOwner = "_domainkey.example.test."

// TestParseDomainPolicyRecordFlags pins the Section 3.8 flag grammar: the
// strict flag is case-sensitive, flags split on ':' with WSP trimmed, unknown
// flags and a p= tag are ignored, and v=DKIM1 must be the first tag.
func TestParseDomainPolicyRecordFlags(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		strict  bool
		wantErr RecordErrorCode
	}{
		{name: "no f tag", payload: "v=DKIM1"},
		{name: "strict", payload: "v=DKIM1; f=strict", strict: true},
		{name: "uppercase flag is not strict", payload: "v=DKIM1; f=Strict"},
		{name: "unknown then strict", payload: "v=DKIM1; f=foo:strict", strict: true},
		{name: "wsp around flags", payload: "v=DKIM1; f= foo : strict ;", strict: true},
		{name: "unknown only", payload: "v=DKIM1; f=foo:bar"},
		{name: "empty f", payload: "v=DKIM1; f="},
		{name: "p tag irrelevant", payload: "v=DKIM1; p=; f=strict", strict: true},
		{name: "unknown tag ignored", payload: "v=DKIM1; o=-; f=strict", strict: true},
		{name: "duplicate f invalid", payload: "v=DKIM1; f=strict; f=foo", wantErr: RecordErrorInvalidSyntax},
		{name: "broken tag-list invalid", payload: "v=DKIM1; f", wantErr: RecordErrorInvalidSyntax},
		{name: "version not first", payload: "f=strict; v=DKIM1", wantErr: RecordErrorInvalidVersion},
		{name: "foreign version", payload: "v=DKIM2; f=strict", wantErr: RecordErrorInvalidVersion},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record, err := ParseDomainPolicyRecord([]byte(tt.payload), DefaultLimits())
			if tt.wantErr != "" {
				if !IsRecordErrorCode(err, tt.wantErr) || record.Valid() {
					t.Fatalf("ParseDomainPolicyRecord() = %v, %v; want %s", record, err, tt.wantErr)
				}
				return
			}
			if err != nil || !record.Valid() || record.Strict() != tt.strict {
				t.Fatalf("ParseDomainPolicyRecord() strict=%v valid=%v err=%v; want strict=%v", record.Strict(), record.Valid(), err, tt.strict)
			}
		})
	}
}

// TestResolveDomainPolicyClosedOutcomes verifies the Section 3.8 record
// selection: records not beginning with v=DKIM1 are ignored (including a
// record without v=), more than one remaining record is ambiguous, an invalid
// remaining record and a permanent transport failure are invalid, absence is
// authorized, and a temporary transport failure is temporary.
func TestResolveDomainPolicyClosedOutcomes(t *testing.T) {
	tests := []struct {
		name   string
		result LookupResult
		err    error
		want   DomainPolicyStatus
	}{
		{name: "nxdomain authorized", result: mustAbsentLookup(t, AbsenceNXDOMAIN), want: DomainPolicyAuthorized},
		{name: "nodata authorized", result: mustAbsentLookup(t, AbsenceNODATA), want: DomainPolicyAuthorized},
		{name: "no f authorized", result: mustFoundLookup(t, []byte("v=DKIM1")), want: DomainPolicyAuthorized},
		{name: "strict", result: mustFoundLookup(t, []byte("v=DKIM1; f=strict")), want: DomainPolicyStrict},
		{name: "case-sensitive flag", result: mustFoundLookup(t, []byte("v=DKIM1; f=Strict")), want: DomainPolicyAuthorized},
		{name: "unknown flag then strict", result: mustFoundLookup(t, []byte("v=DKIM1; f=foo:strict")), want: DomainPolicyStrict},
		{name: "record without v ignored", result: mustFoundLookup(t, []byte("f=strict")), want: DomainPolicyAuthorized},
		{name: "rfc4870 policy ignored", result: mustFoundLookup(t, []byte("o=-; t=y")), want: DomainPolicyAuthorized},
		{name: "foreign version ignored", result: mustFoundLookup(t, []byte("v=DKIM2; f=strict")), want: DomainPolicyAuthorized},
		{name: "ignored beside strict", result: mustFoundLookups(t, []byte("o=~"), []byte("v=DKIM1; f=strict")), want: DomainPolicyStrict},
		{name: "two policy records ambiguous", result: mustFoundLookups(t, []byte("v=DKIM1"), []byte("v=DKIM1; f=strict")), want: DomainPolicyAmbiguous},
		{name: "count-only ambiguous", result: mustAmbiguousLookup(t, hardMaxTXTRecords+1), want: DomainPolicyAmbiguous},
		{name: "oversized ignored record", result: mustFoundLookups(t, oversizedForeignTXT(), []byte("v=DKIM1; f=strict")), want: DomainPolicyStrict},
		{name: "oversized policy record invalid", result: mustFoundLookup(t, append([]byte("v=DKIM1; f=strict; x="), oversizedForeignTXT()...)), want: DomainPolicyInvalid},
		{name: "invalid tag-list", result: mustFoundLookup(t, []byte("v=DKIM1; f=strict; f=strict")), want: DomainPolicyInvalid},
		{name: "temporary transport", err: NewTransportError(TransportErrorTemporary), want: DomainPolicyTemporary},
		{name: "permanent transport", err: NewTransportError(TransportErrorPermanent), want: DomainPolicyInvalid},
		{name: "unclassified transport", err: context.DeadlineExceeded, want: DomainPolicyInvalid},
		{name: "contradictory result", result: LookupResult{status: LookupStatusFound, dnssec: DNSSECStatusUnavailable}, want: DomainPolicyInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			resolver, err := NewResolver(resolverTransportFunc(func(_ context.Context, owner string) (LookupResult, error) {
				calls++
				if owner != policyTestOwner {
					t.Fatalf("owner = %q", owner)
				}
				return tt.result, tt.err
			}), DefaultLimits())
			if err != nil {
				t.Fatalf("NewResolver() error = %v", err)
			}
			outcome, err := resolver.ResolveDomainPolicy(context.Background(), "Example.Test")
			if err != nil || calls != 1 || !outcome.Valid() || outcome.Status() != tt.want {
				t.Fatalf("ResolveDomainPolicy() = %q valid=%v calls=%d err=%v; want %q", outcome.Status(), outcome.Valid(), calls, err, tt.want)
			}
		})
	}
}

// TestResolveDomainPolicyCachesStableOutcomesInOwnKeySpace verifies that a
// stable policy answer is cached under the policy owner, never shares an
// entry with a key lookup, and that temporary answers are not cached.
func TestResolveDomainPolicyCachesStableOutcomesInOwnKeySpace(t *testing.T) {
	clock := &fakeCacheClock{now: time.Unix(1_000, 0)}
	owners := map[string]int{}
	temporary := true
	resolver, err := NewResolver(resolverTransportFunc(func(_ context.Context, owner string) (LookupResult, error) {
		owners[owner]++
		if owner == policyTestOwner {
			if temporary {
				return LookupResult{}, NewTransportError(TransportErrorTemporary)
			}
			return NewFoundResult([][]byte{[]byte("v=DKIM1; f=strict")}, time.Minute, DNSSECStatusUnavailable)
		}
		return NewAbsentResult(AbsenceNXDOMAIN, time.Minute, DNSSECStatusUnavailable)
	}), DefaultLimits(), WithResolverClock(clock.Now))
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	ctx := context.Background()
	if outcome, err := resolver.ResolveDomainPolicy(ctx, "example.test"); err != nil || outcome.Status() != DomainPolicyTemporary {
		t.Fatalf("temporary policy = %q, %v", outcome.Status(), err)
	}
	temporary = false
	for range 2 {
		if outcome, err := resolver.ResolveDomainPolicy(ctx, "example.test"); err != nil || outcome.Status() != DomainPolicyStrict {
			t.Fatalf("strict policy = %q, %v", outcome.Status(), err)
		}
	}
	if owners[policyTestOwner] != 2 {
		t.Fatalf("policy transport calls = %d, want 2 (temporary uncached, strict cached)", owners[policyTestOwner])
	}
	if outcome, err := resolver.Resolve(ctx, "example.test", "selector", AlgorithmRSASHA256); err != nil || outcome.Status() != KeyOutcomeMissing {
		t.Fatalf("key lookup = %q, %v", outcome.Status(), err)
	}
	if owners[resolverTestOwner] != 1 {
		t.Fatalf("key transport calls = %d", owners[resolverTestOwner])
	}
	clock.now = clock.now.Add(2 * time.Minute)
	if _, err := resolver.ResolveDomainPolicy(ctx, "example.test"); err != nil || owners[policyTestOwner] != 3 {
		t.Fatalf("expired policy calls = %d, %v", owners[policyTestOwner], err)
	}
}

// TestResolveDomainPolicyRejectsUnrepresentableDomain verifies that a domain
// that cannot form a policy owner fails closed as invalid without transport.
func TestResolveDomainPolicyRejectsUnrepresentableDomain(t *testing.T) {
	resolver, err := NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) {
		t.Fatal("transport called for invalid domain")
		return LookupResult{}, nil
	}), DefaultLimits())
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	for _, domain := range []string{"", "bücher.test", "bad..test", "_domainkey.example.test"} {
		if outcome, err := resolver.ResolveDomainPolicy(context.Background(), domain); err != nil || outcome.Status() != DomainPolicyInvalid {
			t.Fatalf("ResolveDomainPolicy(%q) = %q, %v", domain, outcome.Status(), err)
		}
	}
}

// mustFoundLookups constructs one multi-record found answer.
func mustFoundLookups(t *testing.T, payloads ...[]byte) LookupResult {
	t.Helper()
	result, err := NewFoundResult(payloads, time.Minute, DNSSECStatusUnavailable)
	if err != nil {
		t.Fatalf("NewFoundResult() error = %v", err)
	}
	return result
}

// oversizedForeignTXT returns a record that begins with a foreign v= tag and
// exceeds the per-record byte bound, like a long SPF or verification record
// published at the same owner.
func oversizedForeignTXT() []byte {
	return append([]byte("v=spf1 "), bytes.Repeat([]byte("a"), DefaultLimits().MaxTXTRecordBytes)...)
}
