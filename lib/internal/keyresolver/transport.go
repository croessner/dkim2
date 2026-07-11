package keyresolver

import (
	"bytes"
	"context"
	"errors"
	"time"
)

// LookupStatus identifies a mutually exclusive found or absent TXT answer.
type LookupStatus string

const (
	// LookupStatusFound reports one or more TXT resource records.
	LookupStatusFound LookupStatus = "found"
	// LookupStatusAbsent reports authoritative DNS absence.
	LookupStatusAbsent LookupStatus = "absent"
)

// Known reports whether the status belongs to the closed transport vocabulary.
func (s LookupStatus) Known() bool { return s == LookupStatusFound || s == LookupStatusAbsent }

// AbsenceClass distinguishes authoritative NXDOMAIN from NODATA.
type AbsenceClass string

const (
	// AbsenceNXDOMAIN reports authoritative owner-name absence.
	AbsenceNXDOMAIN AbsenceClass = "nxdomain"
	// AbsenceNODATA reports an existing owner without TXT data.
	AbsenceNODATA AbsenceClass = "nodata"
)

// Known reports whether the absence class belongs to the closed vocabulary.
func (a AbsenceClass) Known() bool { return a == AbsenceNXDOMAIN || a == AbsenceNODATA }

// DNSSECStatus is verdict-neutral resolver diagnostic metadata.
type DNSSECStatus string

const (
	// DNSSECStatusSecure reports a transport-provided secure diagnostic.
	DNSSECStatusSecure DNSSECStatus = "secure"
	// DNSSECStatusInsecure reports a transport-provided insecure diagnostic.
	DNSSECStatusInsecure DNSSECStatus = "insecure"
	// DNSSECStatusBogus reports a transport-provided bogus diagnostic.
	DNSSECStatusBogus DNSSECStatus = "bogus"
	// DNSSECStatusIndeterminate reports a transport-provided indeterminate diagnostic.
	DNSSECStatusIndeterminate DNSSECStatus = "indeterminate"
	// DNSSECStatusUnavailable reports that no DNSSEC diagnostic is available.
	DNSSECStatusUnavailable DNSSECStatus = "unavailable"
)

// Known reports whether the diagnostic belongs to the closed DNSSEC vocabulary.
func (s DNSSECStatus) Known() bool {
	switch s {
	case DNSSECStatusSecure, DNSSECStatusInsecure, DNSSECStatusBogus, DNSSECStatusIndeterminate, DNSSECStatusUnavailable:
		return true
	default:
		return false
	}
}

// TXTRecord owns one already-concatenated TXT resource-record payload.
type TXTRecord struct{ payload []byte }

// newTXTRecord clones one already-bounded transport-concatenated payload.
func newTXTRecord(payload []byte) TXTRecord { return TXTRecord{payload: bytes.Clone(payload)} }

// Payload returns an independent copy of the TXT resource-record payload.
func (r TXTRecord) Payload() []byte { return bytes.Clone(r.payload) }

// LookupResult owns one mutually exclusive found or absent TXT lookup result.
type LookupResult struct {
	status      LookupStatus
	records     []TXTRecord
	recordCount int
	absence     AbsenceClass
	positiveTTL time.Duration
	negativeTTL time.Duration
	dnssec      DNSSECStatus
}

// NewFoundResult constructs found state from raw payloads using count-first validation.
func NewFoundResult(payloads [][]byte, ttl time.Duration, dnssec DNSSECStatus) (LookupResult, error) {
	if len(payloads) == 0 || !dnssec.Known() {
		return LookupResult{}, newResolverError(ErrorClassContract)
	}
	if len(payloads) > 1 {
		return NewAmbiguousResult(len(payloads), ttl, dnssec)
	}
	if len(payloads[0]) > hardMaxTXTRecordBytes {
		return LookupResult{}, newResolverError(ErrorClassContract)
	}
	return LookupResult{status: LookupStatusFound, records: []TXTRecord{newTXTRecord(payloads[0])}, recordCount: 1, positiveTTL: ttl, dnssec: dnssec}, nil
}

// NewAmbiguousResult constructs count-only ambiguity without payload traversal.
func NewAmbiguousResult(recordCount int, ttl time.Duration, dnssec DNSSECStatus) (LookupResult, error) {
	if recordCount <= 1 || !dnssec.Known() {
		return LookupResult{}, newResolverError(ErrorClassContract)
	}
	return LookupResult{status: LookupStatusFound, recordCount: recordCount, positiveTTL: ttl, dnssec: dnssec}, nil
}

// NewAbsentResult constructs one immutable authoritative negative result.
func NewAbsentResult(absence AbsenceClass, ttl time.Duration, dnssec DNSSECStatus) (LookupResult, error) {
	if !absence.Known() || !dnssec.Known() {
		return LookupResult{}, newResolverError(ErrorClassContract)
	}
	return LookupResult{status: LookupStatusAbsent, absence: absence, negativeTTL: ttl, dnssec: dnssec}, nil
}

// Status returns the mutually exclusive lookup status.
func (r LookupResult) Status() LookupStatus { return r.status }

// RecordCount returns the exact RR count without requiring ambiguous payload traversal.
func (r LookupResult) RecordCount() int { return r.recordCount }

// Records returns the unique immutable TXT payload or nil when absent or ambiguous.
func (r LookupResult) Records() []TXTRecord { return cloneTXTRecords(r.records) }

// Absence returns the authoritative negative class when absent.
func (r LookupResult) Absence() AbsenceClass { return r.absence }

// PositiveTTL returns found-answer TTL provenance.
func (r LookupResult) PositiveTTL() time.Duration { return r.positiveTTL }

// NegativeTTL returns authoritative negative TTL provenance.
func (r LookupResult) NegativeTTL() time.Duration { return r.negativeTTL }

// DNSSECStatus returns verdict-neutral bounded diagnostic metadata.
func (r LookupResult) DNSSECStatus() DNSSECStatus { return r.dnssec }

// IsZero reports whether no declared transport result is present.
func (r LookupResult) IsZero() bool {
	return r.status == "" && len(r.records) == 0 && r.recordCount == 0 && r.absence == "" &&
		r.positiveTTL == 0 && r.negativeTTL == 0 && r.dnssec == ""
}

// clone returns a detached copy for transport and cache boundaries.
func (r LookupResult) clone() LookupResult {
	r.records = cloneTXTRecords(r.records)
	return r
}

// cloneTXTRecords clones record containers and payload bytes.
func cloneTXTRecords(records []TXTRecord) []TXTRecord {
	cloned := make([]TXTRecord, len(records))
	for index := range records {
		cloned[index] = newTXTRecord(records[index].payload)
	}
	return cloned
}

// TXTTransport resolves absolute DNS TXT owners through an injected context-aware boundary.
type TXTTransport interface {
	LookupTXT(context.Context, string) (LookupResult, error)
}

// TransportErrorClass identifies an explicitly typed DNS transport failure.
type TransportErrorClass string

const (
	// TransportErrorTemporary identifies retryable DNS transport failure.
	TransportErrorTemporary TransportErrorClass = "temporary"
	// TransportErrorPermanent identifies a stable local transport failure.
	TransportErrorPermanent TransportErrorClass = "permanent"
)

// Known reports whether the class belongs to the closed transport failure vocabulary.
func (c TransportErrorClass) Known() bool {
	return c == TransportErrorTemporary || c == TransportErrorPermanent
}

type transportError struct{ class TransportErrorClass }

// Error returns a cause-free bounded transport diagnostic.
func (e *transportError) Error() string { return "dns txt transport failure" }

// TransportErrorClass returns the typed transport failure class.
func (e *transportError) TransportErrorClass() TransportErrorClass {
	if e == nil {
		return ""
	}
	return e.class
}

// NewTransportError constructs one cause-free typed transport failure.
func NewTransportError(class TransportErrorClass) error { return &transportError{class: class} }

type classifiedTransportError interface {
	error
	TransportErrorClass() TransportErrorClass
}

// TransportErrorClassOf returns a known class without inspecting error text.
func TransportErrorClassOf(err error) TransportErrorClass {
	var classified classifiedTransportError
	if !errors.As(err, &classified) || !classified.TransportErrorClass().Known() {
		return ""
	}
	return classified.TransportErrorClass()
}
