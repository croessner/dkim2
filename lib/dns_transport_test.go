package dkim2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

const testTXTKeyRecord = "p=QQ=="

// TestPublicTXTTransportVocabulariesAreClosed verifies safe public resolver tokens.
func TestPublicTXTTransportVocabulariesAreClosed(t *testing.T) {
	for _, status := range []TXTLookupStatus{TXTLookupStatusFound, TXTLookupStatusAbsent} {
		if !status.Known() {
			t.Fatalf("status %q unknown", status)
		}
	}
	for _, absence := range []TXTAbsenceClass{TXTAbsenceNXDOMAIN, TXTAbsenceNODATA} {
		if !absence.Known() {
			t.Fatalf("absence %q unknown", absence)
		}
	}
	for _, status := range []DNSSECStatus{DNSSECStatusSecure, DNSSECStatusInsecure, DNSSECStatusBogus, DNSSECStatusIndeterminate, DNSSECStatusUnavailable} {
		if !status.Known() {
			t.Fatalf("dnssec %q unknown", status)
		}
	}
	if TXTLookupStatus("").Known() || TXTAbsenceClass("").Known() || DNSSECStatus("").Known() || DNSSECStatus("future").Known() {
		t.Fatal("zero or unknown public transport value accepted")
	}
}

// TestPublicTXTResultsCloneRecordsAndPreserveTTLProvenance verifies immutable public answers.
func TestPublicTXTResultsCloneRecordsAndPreserveTTLProvenance(t *testing.T) {
	payload := []byte(testTXTKeyRecord)
	found, err := NewFoundTXTLookupResult([][]byte{payload}, time.Minute, DNSSECStatusSecure)
	if err != nil {
		t.Fatal(err)
	}
	payload[0] = 'X'
	if found.Status() != TXTLookupStatusFound || found.RecordCount() != 1 || found.PositiveTTL() != time.Minute || found.NegativeTTL() != 0 || string(found.Records()[0].Payload()) != testTXTKeyRecord {
		t.Fatalf("found = %#v", found)
	}
	record := found.Records()[0].Payload()
	record[0] = 'Y'
	if string(found.Records()[0].Payload()) != testTXTKeyRecord {
		t.Fatal("public TXT payload was mutable")
	}
	absent, err := NewAbsentTXTLookupResult(TXTAbsenceNODATA, 30*time.Second, DNSSECStatusInsecure)
	if err != nil || absent.Status() != TXTLookupStatusAbsent || absent.RecordCount() != 0 || absent.Absence() != TXTAbsenceNODATA || absent.NegativeTTL() != 30*time.Second || len(absent.Records()) != 0 {
		t.Fatalf("absent=%#v error=%v", absent, err)
	}
}

// TestPublicTXTResultConstructorsRejectInvalidForms verifies consumers cannot construct mixed state.
func TestPublicTXTResultConstructorsRejectInvalidForms(t *testing.T) {
	if _, err := NewFoundTXTLookupResult(nil, 0, DNSSECStatusUnavailable); err == nil {
		t.Fatal("zero-record found result accepted")
	}
	if _, err := NewAbsentTXTLookupResult("", 0, DNSSECStatusUnavailable); err == nil {
		t.Fatal("zero absence accepted")
	}
	if _, err := NewAbsentTXTLookupResult(TXTAbsenceNODATA, 0, DNSSECStatus("future")); err == nil {
		t.Fatal("unknown absent DNSSEC status accepted")
	}
	if _, err := NewFoundTXTLookupResult([][]byte{[]byte("x")}, 0, DNSSECStatus("future")); err == nil {
		t.Fatal("unknown DNSSEC status accepted")
	}
}

// TestPublicFoundResultPreservesMultipleRecordBoundaries verifies no cross-RR concatenation.
func TestPublicFoundResultPreservesMultipleRecordBoundaries(t *testing.T) {
	first := []byte(testTXTKeyRecord)
	second := []byte("p=Qg==")
	result, err := NewFoundTXTLookupResult([][]byte{first, second}, 0, DNSSECStatusUnavailable)
	if err != nil {
		t.Fatalf("NewFoundTXTLookupResult() error = %v", err)
	}
	first[0], second[0] = 'X', 'Y'
	if result.RecordCount() != 2 || len(result.Records()) != 0 {
		t.Fatalf("ambiguous record count was not preserved: count=%d records=%#v", result.RecordCount(), result.Records())
	}
}

// TestPublicFoundResultPreservesOneEmptyRecord verifies empty RR is distinct from zero RRs.
func TestPublicFoundResultPreservesOneEmptyRecord(t *testing.T) {
	result, err := NewFoundTXTLookupResult([][]byte{nil}, 0, DNSSECStatusUnavailable)
	if err != nil {
		t.Fatalf("NewFoundTXTLookupResult() error = %v", err)
	}
	if records := result.Records(); result.RecordCount() != 1 || len(records) != 1 || len(records[0].Payload()) != 0 {
		t.Fatalf("empty record was not preserved: %#v", records)
	}
}

// TestPublicFoundResultBoundsUniquePayloadBeforeCopy verifies exact and over-hard construction.
func TestPublicFoundResultBoundsUniquePayloadBeforeCopy(t *testing.T) {
	exact := make([]byte, hardMaxTXTRecordPayloadBytes)
	result, err := NewFoundTXTLookupResult([][]byte{exact}, 0, DNSSECStatusUnavailable)
	if err != nil || result.RecordCount() != 1 || len(result.Records()[0].Payload()) != hardMaxTXTRecordPayloadBytes {
		t.Fatalf("exact payload count=%d error=%v", result.RecordCount(), err)
	}
	over := make([]byte, hardMaxTXTRecordPayloadBytes+1)
	if _, err := NewFoundTXTLookupResult([][]byte{over}, 0, DNSSECStatusUnavailable); err == nil {
		t.Fatal("over-hard payload accepted")
	}
}

// TestPublicAmbiguousResultConstructsFromCountOnly verifies third-party transports avoid payload traversal.
func TestPublicAmbiguousResultConstructsFromCountOnly(t *testing.T) {
	result, err := NewAmbiguousTXTLookupResult(100_000, 0, DNSSECStatusUnavailable)
	if err != nil || result.RecordCount() != 100_000 || len(result.Records()) != 0 {
		t.Fatalf("ambiguous result count=%d error=%v", result.RecordCount(), err)
	}
	for _, count := range []int{-1, 0, 1} {
		if _, err := NewAmbiguousTXTLookupResult(count, 0, DNSSECStatusUnavailable); err == nil {
			t.Fatalf("ambiguous count %d accepted", count)
		}
	}
}

type txtTransportFunc func(context.Context, string) (TXTLookupResult, error)

// LookupTXT implements TXTTransport for deterministic public tests.
func (f txtTransportFunc) LookupTXT(ctx context.Context, name string) (TXTLookupResult, error) {
	return f(ctx, name)
}

// TestTXTTransportContractIsContextAware verifies the public seam can preserve caller control flow.
func TestTXTTransportContractIsContextAware(t *testing.T) {
	transport := txtTransportFunc(func(ctx context.Context, _ string) (TXTLookupResult, error) {
		return TXTLookupResult{}, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := transport.LookupTXT(ctx, "s._domainkey.example.test."); !errors.Is(err, context.Canceled) {
		t.Fatalf("LookupTXT() error = %v", err)
	}
}

type fakeNetTXTResolver struct {
	records []string
	err     error
	calls   int
}

// LookupTXT returns configured standard-resolver-shaped results without network access.
func (f *fakeNetTXTResolver) LookupTXT(context.Context, string) ([]string, error) {
	f.calls++
	return f.records, f.err
}

type contextNetTXTResolver struct{}

// LookupTXT returns caller context state to prove adapter cancellation propagation.
func (contextNetTXTResolver) LookupTXT(ctx context.Context, _ string) ([]string, error) {
	return nil, ctx.Err()
}

// TestNetTXTTransportPreservesRecordsAndUsesZeroTTL verifies standard resolver adaptation.
func TestNetTXTTransportPreservesRecordsAndUsesZeroTTL(t *testing.T) {
	transport, err := newNetTXTTransport(&fakeNetTXTResolver{records: []string{"p=QQ==", "p=Qg=="}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := transport.LookupTXT(context.Background(), "s._domainkey.example.test.")
	if err != nil || result.Status() != TXTLookupStatusFound || result.RecordCount() != 2 || len(result.Records()) != 0 {
		t.Fatalf("LookupTXT() result=%#v error=%v", result, err)
	}

	notFound, err := newNetTXTTransport(&fakeNetTXTResolver{err: &net.DNSError{IsNotFound: true}})
	if err != nil {
		t.Fatal(err)
	}
	result, err = notFound.LookupTXT(context.Background(), "s._domainkey.example.test.")
	if err != nil || result.Status() != TXTLookupStatusAbsent || result.Absence() != TXTAbsenceNODATA || result.NegativeTTL() != 0 {
		t.Fatalf("not-found result=%#v error=%v", result, err)
	}

	temporary, err := newNetTXTTransport(&fakeNetTXTResolver{err: fmt.Errorf("wrapped: %w", &net.DNSError{IsTimeout: true})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := temporary.LookupTXT(context.Background(), "s._domainkey.example.test."); ProviderErrorClassOf(err) != ProviderErrorClassTemporary {
		t.Fatalf("temporary LookupTXT() error=%v class=%q", err, ProviderErrorClassOf(err))
	}
}

// TestNetTXTTransportBoundsHugeAmbiguousRRSetWithoutTraversal verifies count-first ambiguity signaling.
func TestNetTXTTransportBoundsHugeAmbiguousRRSetWithoutTraversal(t *testing.T) {
	records := make([]string, 100_000)
	records[99_999] = strings.Repeat("x", (64<<10)+1)
	resolver := &fakeNetTXTResolver{records: records}
	transport, err := newNetTXTTransport(resolver)
	if err != nil {
		t.Fatal(err)
	}
	result, err := transport.LookupTXT(context.Background(), "s._domainkey.example.test.")
	if err != nil || result.RecordCount() != len(records) || len(result.Records()) != 0 {
		t.Fatalf("ambiguous result count=%d records=%d error=%v", result.RecordCount(), len(result.Records()), err)
	}
}

// TestNetTXTTransportPropagatesCallerCancellation verifies adapter context control flow.
func TestNetTXTTransportPropagatesCallerCancellation(t *testing.T) {
	transport, err := newNetTXTTransport(contextNetTXTResolver{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := transport.LookupTXT(ctx, "s._domainkey.example.test."); !errors.Is(err, context.Canceled) {
		t.Fatalf("LookupTXT() error=%v, want caller cancellation", err)
	}
}

// TestNetTXTTransportBoundsUnknownResolverErrors verifies raw causes become unclassified contract state.
func TestNetTXTTransportBoundsUnknownResolverErrors(t *testing.T) {
	const toxic = "TOXIC-RESOLVER-ENDPOINT selector.example"
	transport, err := newNetTXTTransport(&fakeNetTXTResolver{err: errors.New(toxic)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = transport.LookupTXT(context.Background(), "s._domainkey.example.test.")
	if err == nil || ProviderErrorClassOf(err) != "" || err.Error() == toxic {
		t.Fatalf("LookupTXT() error=%v class=%q", err, ProviderErrorClassOf(err))
	}
}

// TestNetTXTTransportRejectsUnsafeRelativeOwnersBeforeLookup verifies search suffixes cannot redirect queries.
func TestNetTXTTransportRejectsUnsafeRelativeOwnersBeforeLookup(t *testing.T) {
	unsafe := []string{"", "relative.example", ".", "Bad._domainkey.example.test.", "s._domainkey.example..test.", "s._domainkey.exämple.test.", "s._domainkey.example.test..", "s.example.test."}
	for _, name := range unsafe {
		resolver := &fakeNetTXTResolver{records: []string{testTXTKeyRecord}}
		transport, err := newNetTXTTransport(resolver)
		if err != nil {
			t.Fatal(err)
		}
		_, err = transport.LookupTXT(context.Background(), name)
		if err == nil || resolver.calls != 0 {
			t.Fatalf("unsafe owner accepted name=%q calls=%d error=%v", name, resolver.calls, err)
		}
		if len(name) > 7 && strings.Contains(err.Error(), name) {
			t.Fatal("unsafe owner error exposed input")
		}
	}
}

// TestNetTXTTransportBoundsRecordPayloadBeforeConstruction verifies exact and over hard payload size.
func TestNetTXTTransportBoundsRecordPayloadBeforeConstruction(t *testing.T) {
	exactResolver := &fakeNetTXTResolver{records: []string{strings.Repeat("x", 64<<10)}}
	exact, err := newNetTXTTransport(exactResolver)
	if err != nil {
		t.Fatal(err)
	}
	result, err := exact.LookupTXT(context.Background(), "s._domainkey.example.test.")
	if err != nil || len(result.Records()) != 1 || len(result.Records()[0].Payload()) != 64<<10 {
		t.Fatalf("exact payload result=%d error=%v", len(result.Records()), err)
	}
	overResolver := &fakeNetTXTResolver{records: []string{strings.Repeat("T", (64<<10)+1)}}
	over, err := newNetTXTTransport(overResolver)
	if err != nil {
		t.Fatal(err)
	}
	_, err = over.LookupTXT(context.Background(), "s._domainkey.example.test.")
	if err == nil || ProviderErrorClassOf(err) != "" || strings.Contains(err.Error(), "TTTTTTTT") || overResolver.calls != 1 {
		t.Fatalf("over payload error=%v class=%q calls=%d", err, ProviderErrorClassOf(err), overResolver.calls)
	}
}

// TestNetTXTTransportRejectsNilResolvers verifies nil and typed-nil dependencies fail safely.
func TestNetTXTTransportRejectsNilResolvers(t *testing.T) {
	if _, err := NewNetTXTTransport(nil); err == nil {
		t.Fatal("nil net resolver accepted")
	}
	var typedNil *fakeNetTXTResolver
	if _, err := newNetTXTTransport(typedNil); err == nil {
		t.Fatal("typed-nil resolver accepted")
	}
}

// TestPublicTXTTransportUsesClosedProviderErrors verifies typed temporary/permanent failures.
func TestPublicTXTTransportUsesClosedProviderErrors(t *testing.T) {
	for _, err := range []error{NewTemporaryProviderError(), NewPermanentProviderError()} {
		transport := txtTransportFunc(func(context.Context, string) (TXTLookupResult, error) {
			return TXTLookupResult{}, err
		})
		_, got := transport.LookupTXT(context.Background(), "s._domainkey.example.test.")
		if ProviderErrorClassOf(got) != ProviderErrorClassOf(err) {
			t.Fatalf("transport class=%q want=%q", ProviderErrorClassOf(got), ProviderErrorClassOf(err))
		}
	}
	if ProviderErrorClassOf(errors.New("temporary resolver.example")) != "" {
		t.Fatal("raw error was classified")
	}
}
