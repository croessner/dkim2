package keyresolver

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// TestTransportVocabulariesAreClosed verifies all declared result metadata classes.
func TestTransportVocabulariesAreClosed(t *testing.T) {
	for _, status := range []LookupStatus{LookupStatusFound, LookupStatusAbsent} {
		if !status.Known() {
			t.Fatalf("status %q unknown", status)
		}
	}
	for _, absence := range []AbsenceClass{AbsenceNXDOMAIN, AbsenceNODATA} {
		if !absence.Known() {
			t.Fatalf("absence %q unknown", absence)
		}
	}
	for _, status := range []DNSSECStatus{DNSSECStatusSecure, DNSSECStatusInsecure, DNSSECStatusBogus, DNSSECStatusIndeterminate, DNSSECStatusUnavailable} {
		if !status.Known() {
			t.Fatalf("dnssec %q unknown", status)
		}
	}
	for _, class := range []TransportErrorClass{TransportErrorTemporary, TransportErrorPermanent} {
		if !class.Known() {
			t.Fatalf("transport class %q unknown", class)
		}
	}
	if LookupStatus("").Known() || AbsenceClass("").Known() || DNSSECStatus("").Known() || DNSSECStatus("future").Known() || TransportErrorClass("").Known() {
		t.Fatal("zero or unknown transport vocabulary accepted")
	}
}

// TestFoundAndAbsentResultsAreMutuallyExclusive verifies constructors and immutable payloads.
func TestFoundAndAbsentResultsAreMutuallyExclusive(t *testing.T) {
	payload := []byte("v=DKIM1; p=QQ==")
	result, err := NewFoundResult([][]byte{payload}, time.Minute, DNSSECStatusSecure)
	if err != nil {
		t.Fatalf("NewFoundResult() error = %v", err)
	}
	payload[0] = 'X'
	records := result.Records()
	if result.Status() != LookupStatusFound || result.RecordCount() != 1 || result.PositiveTTL() != time.Minute || result.NegativeTTL() != 0 || result.Absence() != "" || result.DNSSECStatus() != DNSSECStatusSecure || string(records[0].Payload()) != "v=DKIM1; p=QQ==" {
		t.Fatalf("found result = %#v records=%q", result, records[0].Payload())
	}
	mutated := records[0].Payload()
	mutated[0] = 'Y'
	if string(result.Records()[0].Payload()) != "v=DKIM1; p=QQ==" {
		t.Fatal("found result payload was mutable")
	}

	absent, err := NewAbsentResult(AbsenceNXDOMAIN, 30*time.Second, DNSSECStatusInsecure)
	if err != nil {
		t.Fatalf("NewAbsentResult() error = %v", err)
	}
	if absent.Status() != LookupStatusAbsent || absent.RecordCount() != 0 || absent.Absence() != AbsenceNXDOMAIN || absent.NegativeTTL() != 30*time.Second || absent.PositiveTTL() != 0 || len(absent.Records()) != 0 {
		t.Fatalf("absent result = %#v", absent)
	}
}

// TestResultConstructorsRejectInvalidForms verifies zero and contradictory transport results.
func TestResultConstructorsRejectInvalidForms(t *testing.T) {
	tests := []struct {
		name string
		call func() error
	}{
		{name: "found zero records", call: func() error { _, err := NewFoundResult(nil, 0, DNSSECStatusUnavailable); return err }},
		{name: "found invalid dnssec", call: func() error {
			_, err := NewFoundResult([][]byte{[]byte("x")}, 0, DNSSECStatus("future"))
			return err
		}},
		{name: "absent zero class", call: func() error { _, err := NewAbsentResult("", 0, DNSSECStatusUnavailable); return err }},
		{name: "absent invalid dnssec", call: func() error { _, err := NewAbsentResult(AbsenceNODATA, 0, DNSSECStatus("future")); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); err == nil || !IsErrorClass(err, ErrorClassContract) {
				t.Fatalf("constructor error = %v, want contract", err)
			}
		})
	}
}

// TestFoundResultPreservesMultipleRecordBoundaries verifies ambiguity remains classifiable later.
func TestFoundResultPreservesMultipleRecordBoundaries(t *testing.T) {
	first := []byte("p=QQ==")
	second := []byte("p=Qg==")
	result, err := NewFoundResult([][]byte{first, second}, 0, DNSSECStatusUnavailable)
	if err != nil {
		t.Fatalf("NewFoundResult() error = %v", err)
	}
	first[0], second[0] = 'X', 'Y'
	if result.RecordCount() != 2 || len(result.Records()) != 0 {
		t.Fatalf("ambiguous record count was not preserved: count=%d records=%#v", result.RecordCount(), result.Records())
	}
}

// TestFoundResultPreservesOneEmptyRecord verifies empty RR payload reaches record parsing later.
func TestFoundResultPreservesOneEmptyRecord(t *testing.T) {
	result, err := NewFoundResult([][]byte{nil}, 0, DNSSECStatusUnavailable)
	if err != nil {
		t.Fatalf("NewFoundResult() error = %v", err)
	}
	if records := result.Records(); result.RecordCount() != 1 || len(records) != 1 || len(records[0].Payload()) != 0 {
		t.Fatalf("empty record was not preserved: %#v", records)
	}
}

type fakeTXTTransport struct {
	mu      sync.Mutex
	results map[string]LookupResult
	errors  map[string]error
	queries []string
}

// LookupTXT returns one configured immutable answer while respecting caller context.
func (f *fakeTXTTransport) LookupTXT(ctx context.Context, absoluteName string) (LookupResult, error) {
	if err := ctx.Err(); err != nil {
		return LookupResult{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, absoluteName)
	if err := f.errors[absoluteName]; err != nil {
		return LookupResult{}, err
	}
	return f.results[absoluteName].clone(), nil
}

// Queries returns an immutable copy of captured absolute names.
func (f *fakeTXTTransport) Queries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

// TestFakeTransportIsDeterministicContextAwareAndImmutable proves the test transport contract.
func TestFakeTransportIsDeterministicContextAwareAndImmutable(t *testing.T) {
	answer, err := NewFoundResult([][]byte{[]byte("p=QQ==")}, 0, DNSSECStatusUnavailable)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeTXTTransport{results: map[string]LookupResult{"s._domainkey.example.test.": answer}, errors: map[string]error{}}
	result, err := fake.LookupTXT(context.Background(), "s._domainkey.example.test.")
	if err != nil || string(result.Records()[0].Payload()) != "p=QQ==" {
		t.Fatalf("LookupTXT() result=%#v error=%v", result, err)
	}
	copyResult := result.Records()[0].Payload()
	copyResult[0] = 'X'
	second, err := fake.LookupTXT(context.Background(), "s._domainkey.example.test.")
	if err != nil || string(second.Records()[0].Payload()) != "p=QQ==" || len(fake.Queries()) != 2 {
		t.Fatalf("second LookupTXT() result=%#v error=%v queries=%v", second, err, fake.Queries())
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fake.LookupTXT(canceled, "s._domainkey.example.test."); !errors.Is(err, context.Canceled) || len(fake.Queries()) != 2 {
		t.Fatalf("canceled LookupTXT() error=%v queries=%v", err, fake.Queries())
	}
}

// TestFoundResultBoundsUniquePayloadBeforeCopy verifies exact and over-hard construction.
func TestFoundResultBoundsUniquePayloadBeforeCopy(t *testing.T) {
	exact := make([]byte, hardMaxTXTRecordBytes)
	result, err := NewFoundResult([][]byte{exact}, 0, DNSSECStatusUnavailable)
	if err != nil || result.RecordCount() != 1 || len(result.Records()[0].Payload()) != hardMaxTXTRecordBytes {
		t.Fatalf("exact payload count=%d error=%v", result.RecordCount(), err)
	}
	over := make([]byte, hardMaxTXTRecordBytes+1)
	if _, err := NewFoundResult([][]byte{over}, 0, DNSSECStatusUnavailable); err == nil || !IsErrorClass(err, ErrorClassContract) {
		t.Fatalf("over payload error=%v", err)
	}
}

// TestAmbiguousResultConstructsFromCountOnly verifies external transports need no payload traversal.
func TestAmbiguousResultConstructsFromCountOnly(t *testing.T) {
	result, err := NewAmbiguousResult(100_000, 0, DNSSECStatusUnavailable)
	if err != nil || result.RecordCount() != 100_000 || len(result.Records()) != 0 {
		t.Fatalf("ambiguous result count=%d error=%v", result.RecordCount(), err)
	}
	for _, count := range []int{-1, 0, 1} {
		if _, err := NewAmbiguousResult(count, 0, DNSSECStatusUnavailable); err == nil {
			t.Fatalf("ambiguous count %d accepted", count)
		}
	}
}

// TestTransportErrorsAreClosedAndCauseFree verifies safe typed transport failures.
func TestTransportErrorsAreClosedAndCauseFree(t *testing.T) {
	for _, class := range []TransportErrorClass{TransportErrorTemporary, TransportErrorPermanent} {
		err := NewTransportError(class)
		if TransportErrorClassOf(err) != class || err.Error() != "dns txt transport failure" {
			t.Fatalf("transport error class=%q text=%q", TransportErrorClassOf(err), err.Error())
		}
	}
	if TransportErrorClassOf(errors.New("temporary toxic.example")) != "" || TransportErrorClassOf(NewTransportError("future")) != "" {
		t.Fatal("unclassified transport error accepted")
	}
}
