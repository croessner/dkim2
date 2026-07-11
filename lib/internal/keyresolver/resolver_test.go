package keyresolver

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

type resolverTransportFunc func(context.Context, string) (LookupResult, error)

const resolverTestOwner = "selector._domainkey.example.test."

type nilResolverTransport struct{}

// LookupTXT satisfies TXTTransport for typed-nil constructor defense.
func (*nilResolverTransport) LookupTXT(context.Context, string) (LookupResult, error) {
	panic("typed-nil transport must not be called")
}

// LookupTXT implements TXTTransport for resolver orchestration tests.
func (f resolverTransportFunc) LookupTXT(ctx context.Context, owner string) (LookupResult, error) {
	return f(ctx, owner)
}

// TestResolverMapsClosedDNSAndRecordOutcomes verifies exact non-caching orchestration states.
func TestResolverMapsClosedDNSAndRecordOutcomes(t *testing.T) {
	edKey := base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	tests := []struct {
		name       string
		result     LookupResult
		algorithm  Algorithm
		wantStatus KeyOutcomeStatus
		metadata   bool
	}{
		{name: "nxdomain", result: mustAbsentLookup(t, AbsenceNXDOMAIN), algorithm: AlgorithmRSASHA256, wantStatus: KeyOutcomeMissing},
		{name: "nodata", result: mustAbsentLookup(t, AbsenceNODATA), algorithm: AlgorithmRSASHA256, wantStatus: KeyOutcomeMissing},
		{name: "ambiguous", result: mustAmbiguousLookup(t, 2), algorithm: AlgorithmRSASHA256, wantStatus: KeyOutcomeAmbiguous},
		{name: "malformed record", result: mustFoundLookup(t, []byte("v=DKIM1; p=%%%")), algorithm: AlgorithmRSASHA256, wantStatus: KeyOutcomeInvalid},
		{name: "revoked resolver state", result: mustFoundLookup(t, []byte("v=DKIM1; p=; t=y")), algorithm: AlgorithmRSASHA256, wantStatus: KeyOutcomeRevoked, metadata: true},
		{name: "unsupported resolver state", result: mustFoundLookup(t, []byte("v=DKIM1; k=future; p=QQ==; t=y")), algorithm: AlgorithmRSASHA256, wantStatus: KeyOutcomeUnsupportedKeyType, metadata: true},
		{name: "mismatch", result: mustFoundLookup(t, []byte("v=DKIM1; k=ed25519; p="+edKey+"; t=y")), algorithm: AlgorithmRSASHA256, wantStatus: KeyOutcomeAlgorithmMismatch, metadata: true},
		{name: "found ed25519", result: mustFoundLookup(t, []byte("v=DKIM1; k=ed25519; p="+edKey+"; t=y:s")), algorithm: AlgorithmEd25519SHA256, wantStatus: KeyOutcomeFound, metadata: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			resolver, err := NewResolver(resolverTransportFunc(func(_ context.Context, owner string) (LookupResult, error) {
				calls++
				if owner != resolverTestOwner {
					t.Fatalf("owner = %q", owner)
				}
				return tt.result, nil
			}), DefaultLimits())
			if err != nil {
				t.Fatalf("NewResolver() error = %v", err)
			}
			outcome, err := resolver.Resolve(context.Background(), "example.test", testSelector, tt.algorithm)
			if err != nil || calls != 1 || !outcome.Valid() || outcome.Status() != tt.wantStatus || outcome.Metadata().TestingDeclared() != tt.metadata {
				t.Fatalf("Resolve() = status %q valid=%v metadata=%#v calls=%d error=%v", outcome.Status(), outcome.Valid(), outcome.Metadata(), calls, err)
			}
			if tt.name == "found ed25519" && (!outcome.Metadata().StrictIdentityDeclared() || outcome.Metadata().StrictIdentityApplicable()) {
				t.Fatalf("strict metadata = declared %v applicable %v", outcome.Metadata().StrictIdentityDeclared(), outcome.Metadata().StrictIdentityApplicable())
			}
		})
	}
}

// TestResolverRejectsContradictoryLookupResults verifies every mixed transport form fails closed.
func TestResolverRejectsContradictoryLookupResults(t *testing.T) {
	validRecord := newTXTRecord([]byte("v=DKIM1; p=QQ=="))
	tests := []struct {
		name   string
		result LookupResult
	}{
		{name: "zero", result: LookupResult{}},
		{name: "found zero count", result: LookupResult{status: LookupStatusFound, dnssec: DNSSECStatusUnavailable}},
		{name: "found count without unique record", result: LookupResult{status: LookupStatusFound, recordCount: 1, dnssec: DNSSECStatusUnavailable}},
		{name: "found count mismatch", result: LookupResult{status: LookupStatusFound, records: []TXTRecord{validRecord}, recordCount: 2, dnssec: DNSSECStatusUnavailable}},
		{name: "found with absence", result: LookupResult{status: LookupStatusFound, records: []TXTRecord{validRecord}, recordCount: 1, absence: AbsenceNODATA, dnssec: DNSSECStatusUnavailable}},
		{name: "absent with record", result: LookupResult{status: LookupStatusAbsent, records: []TXTRecord{validRecord}, recordCount: 1, absence: AbsenceNODATA, dnssec: DNSSECStatusUnavailable}},
		{name: "absent without class", result: LookupResult{status: LookupStatusAbsent, dnssec: DNSSECStatusUnavailable}},
		{name: "unknown dnssec", result: LookupResult{status: LookupStatusAbsent, absence: AbsenceNODATA, dnssec: "future"}},
		{name: "found with negative ttl", result: LookupResult{status: LookupStatusFound, records: []TXTRecord{validRecord}, recordCount: 1, negativeTTL: time.Second, dnssec: DNSSECStatusUnavailable}},
		{name: "absent with positive ttl", result: LookupResult{status: LookupStatusAbsent, absence: AbsenceNODATA, positiveTTL: time.Second, dnssec: DNSSECStatusUnavailable}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver, err := NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) { return tt.result, nil }), DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			outcome, resolveErr := resolver.Resolve(context.Background(), "example.test", testSelector, AlgorithmRSASHA256)
			if resolveErr != nil || outcome.Status() != KeyOutcomeProviderContract || !outcome.Valid() {
				t.Fatalf("Resolve() = %q valid=%v error=%v, want provider contract", outcome.Status(), outcome.Valid(), resolveErr)
			}
		})
	}

	nonzero := mustAbsentLookup(t, AbsenceNODATA)
	resolver, err := NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) {
		return nonzero, NewTransportError(TransportErrorTemporary)
	}), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	outcome, resolveErr := resolver.Resolve(context.Background(), "example.test", testSelector, AlgorithmRSASHA256)
	if resolveErr != nil || outcome.Status() != KeyOutcomeProviderContract {
		t.Fatalf("nonzero plus error Resolve() = %q/%v", outcome.Status(), resolveErr)
	}
}

// TestResolverRejectsHugeInconsistentAmbiguityWithoutTraversal verifies count-first contract validation.
func TestResolverRejectsHugeInconsistentAmbiguityWithoutTraversal(t *testing.T) {
	result := LookupResult{
		status: LookupStatusFound, recordCount: 1_000_000_000,
		records: []TXTRecord{{payload: []byte("SECRET-MARKER")}}, dnssec: DNSSECStatusUnavailable,
	}
	resolver, err := NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) { return result, nil }), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	outcome, resolveErr := resolver.Resolve(context.Background(), "example.test", testSelector, AlgorithmRSASHA256)
	if resolveErr != nil || outcome.Status() != KeyOutcomeProviderContract {
		t.Fatalf("Resolve() = %q/%v", outcome.Status(), resolveErr)
	}
}

// TestNewResolverRejectsNilAndTypedNilTransport verifies panic-safe dependency validation.
func TestNewResolverRejectsNilAndTypedNilTransport(t *testing.T) {
	var typedNil *nilResolverTransport
	for _, transport := range []TXTTransport{nil, typedNil} {
		if _, err := NewResolver(transport, DefaultLimits()); !IsErrorClass(err, ErrorClassContract) {
			t.Fatalf("NewResolver(%T) error = %v", transport, err)
		}
	}
}

// TestResolverMapsTransportErrorsAndCallerContextDisjointly verifies typed error precedence.
func TestResolverMapsTransportErrorsAndCallerContextDisjointly(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus KeyOutcomeStatus
	}{
		{name: "temporary", err: NewTransportError(TransportErrorTemporary), wantStatus: KeyOutcomeTemporary},
		{name: "permanent", err: NewTransportError(TransportErrorPermanent), wantStatus: KeyOutcomePermanent},
		{name: "raw deadline", err: context.DeadlineExceeded, wantStatus: KeyOutcomeProviderContract},
		{name: "raw canceled", err: context.Canceled, wantStatus: KeyOutcomeProviderContract},
		{name: "raw toxic", err: errors.New("SECRET-MARKER.example"), wantStatus: KeyOutcomeProviderContract},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver, err := NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) { return LookupResult{}, tt.err }), DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			outcome, resolveErr := resolver.Resolve(context.Background(), "example.test", testSelector, AlgorithmRSASHA256)
			if resolveErr != nil || outcome.Status() != tt.wantStatus || strings.Contains(string(outcome.Status()), "SECRET") {
				t.Fatalf("Resolve() = %q/%v", outcome.Status(), resolveErr)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	resolver, err := NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) { calls++; return LookupResult{}, context.Canceled }), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	outcome, resolveErr := resolver.Resolve(ctx, "example.test", testSelector, AlgorithmRSASHA256)
	if !outcome.IsZero() || !errors.Is(resolveErr, context.Canceled) || calls != 0 {
		t.Fatalf("canceled Resolve() = zero=%v error=%v calls=%d", outcome.IsZero(), resolveErr, calls)
	}

	liveCtx, liveCancel := context.WithCancel(context.Background())
	resolver, err = NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) {
		calls++
		liveCancel()
		return LookupResult{}, liveCtx.Err()
	}), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	before := calls
	outcome, resolveErr = resolver.Resolve(liveCtx, "example.test", testSelector, AlgorithmRSASHA256)
	if !outcome.IsZero() || !errors.Is(resolveErr, context.Canceled) || calls != before+1 {
		t.Fatalf("in-flight canceled Resolve() = zero=%v error=%v calls=%d", outcome.IsZero(), resolveErr, calls-before)
	}
}

// TestResolverOwnedLookupDeadlineIsTemporary verifies child timeout is not caller cancellation.
func TestResolverOwnedLookupDeadlineIsTemporary(t *testing.T) {
	limits := DefaultLimits()
	limits.LookupTimeout = time.Millisecond
	resolver, err := NewResolver(resolverTransportFunc(func(ctx context.Context, _ string) (LookupResult, error) {
		<-ctx.Done()
		return LookupResult{}, ctx.Err()
	}), limits)
	if err != nil {
		t.Fatal(err)
	}
	outer := context.Background()
	outcome, resolveErr := resolver.Resolve(outer, "example.test", testSelector, AlgorithmRSASHA256)
	if resolveErr != nil || outcome.Status() != KeyOutcomeTemporary || outer.Err() != nil {
		t.Fatalf("Resolve() = %q/%v outer=%v", outcome.Status(), resolveErr, outer.Err())
	}

	resolver, err = NewResolver(resolverTransportFunc(func(ctx context.Context, _ string) (LookupResult, error) {
		<-ctx.Done()
		return mustFoundLookup(t, []byte("v=DKIM1; p=QQ==")), nil
	}), limits)
	if err != nil {
		t.Fatal(err)
	}
	outcome, resolveErr = resolver.Resolve(outer, "example.test", testSelector, AlgorithmRSASHA256)
	if resolveErr != nil || outcome.Status() != KeyOutcomeTemporary || outcome.Material() != nil {
		t.Fatalf("late successful Resolve() = %q material=%T error=%v", outcome.Status(), outcome.Material(), resolveErr)
	}
}

// TestResolverRejectsInvalidQueriesBeforeTransport verifies unsafe lookup tuples make zero calls.
func TestResolverRejectsInvalidQueriesBeforeTransport(t *testing.T) {
	calls := 0
	resolver, err := NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) {
		calls++
		return LookupResult{}, nil
	}), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct {
		domain, selector string
		algorithm        Algorithm
	}{
		{domain: "bad_domain.test", selector: testSelector, algorithm: AlgorithmRSASHA256},
		{domain: "example.test", selector: "bad_selector", algorithm: AlgorithmRSASHA256},
	} {
		outcome, resolveErr := resolver.Resolve(context.Background(), request.domain, request.selector, request.algorithm)
		if resolveErr != nil || outcome.Status() != KeyOutcomeProviderContract {
			t.Fatalf("invalid query Resolve() = %q/%v", outcome.Status(), resolveErr)
		}
	}
	outcome, resolveErr := resolver.Resolve(context.Background(), "example.test", testSelector, "future")
	if !outcome.IsZero() || !IsErrorClass(resolveErr, ErrorClassContract) || calls != 0 {
		t.Fatalf("unknown algorithm Resolve() = zero=%v error=%v calls=%d", outcome.IsZero(), resolveErr, calls)
	}
}

// TestResolverMapsParserContractToProviderContract verifies injected parser state is never generic invalid.
func TestResolverMapsParserContractToProviderContract(t *testing.T) {
	limits := DefaultLimits()
	resolver, err := NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) {
		return mustFoundLookup(t, []byte("v=DKIM1; p=QQ==")), nil
	}), limits)
	if err != nil {
		t.Fatal(err)
	}
	resolver.limits.MaxTags = 0
	outcome, resolveErr := resolver.Resolve(context.Background(), "example.test", testSelector, AlgorithmRSASHA256)
	if resolveErr != nil || outcome.Status() != KeyOutcomeProviderContract {
		t.Fatalf("Resolve() = %q/%v, want provider contract", outcome.Status(), resolveErr)
	}
}

// TestResolverBoundsPayloadBeforeParsing verifies configured record limit enforcement.
func TestResolverBoundsPayloadBeforeParsing(t *testing.T) {
	limits := DefaultLimits()
	exactPayload := []byte("v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)))
	limits.MaxTXTRecordBytes = len(exactPayload)
	limits.MaxCacheEntries = 0
	resolver, err := NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) {
		return mustFoundLookup(t, exactPayload), nil
	}), limits)
	if err != nil {
		t.Fatal(err)
	}
	outcome, resolveErr := resolver.Resolve(context.Background(), "example.test", testSelector, AlgorithmEd25519SHA256)
	if resolveErr != nil || outcome.Status() != KeyOutcomeFound {
		t.Fatalf("exact Resolve() = %q/%v, want found", outcome.Status(), resolveErr)
	}
	resolver.transport = resolverTransportFunc(func(context.Context, string) (LookupResult, error) {
		return mustFoundLookup(t, append(exactPayload, ' ')), nil
	})
	outcome, resolveErr = resolver.Resolve(context.Background(), "example.test", testSelector, AlgorithmEd25519SHA256)
	if resolveErr != nil || outcome.Status() != KeyOutcomeInvalid {
		t.Fatalf("one-over Resolve() = %q/%v, want invalid", outcome.Status(), resolveErr)
	}

	resolver.transport = resolverTransportFunc(func(context.Context, string) (LookupResult, error) { return mustFoundLookup(t, nil), nil })
	outcome, resolveErr = resolver.Resolve(context.Background(), "example.test", testSelector, AlgorithmEd25519SHA256)
	if resolveErr != nil || outcome.Status() != KeyOutcomeInvalid {
		t.Fatalf("empty Resolve() = %q/%v, want invalid", outcome.Status(), resolveErr)
	}
}

// mustFoundLookup constructs one unique found lookup fixture.
func mustFoundLookup(t *testing.T, payload []byte) LookupResult {
	t.Helper()
	result, err := NewFoundResult([][]byte{payload}, time.Minute, DNSSECStatusUnavailable)
	if err != nil {
		t.Fatalf("NewFoundResult() error = %v", err)
	}
	return result
}

// mustAbsentLookup constructs one authoritative absent fixture.
func mustAbsentLookup(t *testing.T, absence AbsenceClass) LookupResult {
	t.Helper()
	result, err := NewAbsentResult(absence, time.Minute, DNSSECStatusUnavailable)
	if err != nil {
		t.Fatalf("NewAbsentResult() error = %v", err)
	}
	return result
}

// mustAmbiguousLookup constructs count-only ambiguity.
func mustAmbiguousLookup(t *testing.T, count int) LookupResult {
	t.Helper()
	result, err := NewAmbiguousResult(count, time.Minute, DNSSECStatusUnavailable)
	if err != nil {
		t.Fatalf("NewAmbiguousResult() error = %v", err)
	}
	return result
}
