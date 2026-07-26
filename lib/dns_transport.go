package dkim2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/croessner/dkim2/internal/keyresolver"
	"github.com/croessner/dkim2/internal/niliface"
)

const hardMaxTXTRecordPayloadBytes = 64 << 10

const (
	txtRecordRedactedText       = "dkim2.TXTRecord{redacted}"
	txtLookupResultRedactedText = "dkim2.TXTLookupResult{redacted}"
	netTXTTransportRedactedText = "dkim2.NetTXTTransport{redacted}"
)

// TXTLookupStatus identifies a mutually exclusive found or absent DNS answer.
type TXTLookupStatus string

const (
	// TXTLookupStatusFound reports one or more TXT resource records.
	TXTLookupStatusFound TXTLookupStatus = "found"
	// TXTLookupStatusAbsent reports authoritative DNS name or data absence.
	TXTLookupStatusAbsent TXTLookupStatus = "absent"
)

// Known reports whether the status belongs to the closed public vocabulary.
func (s TXTLookupStatus) Known() bool { return s == TXTLookupStatusFound || s == TXTLookupStatusAbsent }

// TXTAbsenceClass distinguishes authoritative NXDOMAIN and NODATA results.
type TXTAbsenceClass string

const (
	// TXTAbsenceNXDOMAIN reports authoritative owner-name absence.
	TXTAbsenceNXDOMAIN TXTAbsenceClass = "nxdomain"
	// TXTAbsenceNODATA reports an existing owner without TXT data.
	TXTAbsenceNODATA TXTAbsenceClass = "nodata"
)

// Known reports whether the absence class belongs to the closed public vocabulary.
func (a TXTAbsenceClass) Known() bool { return a == TXTAbsenceNXDOMAIN || a == TXTAbsenceNODATA }

// DNSSECStatus is optional verdict-neutral resolver diagnostic metadata.
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

// Known reports whether the status belongs to the closed diagnostic vocabulary.
func (s DNSSECStatus) Known() bool {
	switch s {
	case DNSSECStatusSecure, DNSSECStatusInsecure, DNSSECStatusBogus, DNSSECStatusIndeterminate, DNSSECStatusUnavailable:
		return true
	default:
		return false
	}
}

// TXTRecord owns one already-concatenated TXT resource-record payload.
type TXTRecord struct {
	state *txtRecordState
}

type txtRecordState struct {
	payload []byte
}

// newTXTRecord clones one already-bounded TXT resource-record payload.
func newTXTRecord(payload []byte) TXTRecord {
	return TXTRecord{state: &txtRecordState{payload: bytes.Clone(payload)}}
}

// Payload returns an independent payload copy.
func (r TXTRecord) Payload() []byte {
	if r.state == nil {
		return nil
	}
	return bytes.Clone(r.state.payload)
}

// String returns a constant representation without DNS TXT payload bytes.
func (TXTRecord) String() string { return txtRecordRedactedText }

// GoString returns a constant representation without DNS TXT payload bytes.
func (TXTRecord) GoString() string { return txtRecordRedactedText }

// Format prevents formatting from traversing DNS TXT payload bytes.
func (TXTRecord) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, txtRecordRedactedText)
}

// MarshalJSON rejects serialization outside the bounded provider boundary.
func (TXTRecord) MarshalJSON() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// MarshalText rejects diagnostic serialization of DNS TXT payload bytes.
func (TXTRecord) MarshalText() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// TXTLookupResult owns one immutable mutually exclusive found or absent answer.
type TXTLookupResult struct {
	state *txtLookupResultState
}

type txtLookupResultState struct {
	status                   TXTLookupStatus
	records                  []TXTRecord
	recordCount              int
	absence                  TXTAbsenceClass
	positiveTTL, negativeTTL time.Duration
	dnssec                   DNSSECStatus
}

// NewFoundTXTLookupResult constructs found state from raw payloads using count-first validation.
func NewFoundTXTLookupResult(payloads [][]byte, ttl time.Duration, dnssec DNSSECStatus) (TXTLookupResult, error) {
	if len(payloads) == 0 || !dnssec.Known() {
		return TXTLookupResult{}, newAPIError(APIErrorCodeInvalidRequest)
	}
	if len(payloads) > 1 {
		return NewAmbiguousTXTLookupResult(len(payloads), ttl, dnssec)
	}
	if len(payloads[0]) > hardMaxTXTRecordPayloadBytes {
		return TXTLookupResult{}, newAPIError(APIErrorCodeInvalidRequest)
	}
	return TXTLookupResult{state: &txtLookupResultState{
		status: TXTLookupStatusFound, records: []TXTRecord{newTXTRecord(payloads[0])},
		recordCount: 1, positiveTTL: ttl, dnssec: dnssec,
	}}, nil
}

// NewAmbiguousTXTLookupResult constructs count-only ambiguity without payload traversal.
func NewAmbiguousTXTLookupResult(recordCount int, ttl time.Duration, dnssec DNSSECStatus) (TXTLookupResult, error) {
	if recordCount <= 1 || !dnssec.Known() {
		return TXTLookupResult{}, newAPIError(APIErrorCodeInvalidRequest)
	}
	return TXTLookupResult{state: &txtLookupResultState{
		status: TXTLookupStatusFound, recordCount: recordCount,
		positiveTTL: ttl, dnssec: dnssec,
	}}, nil
}

// NewAbsentTXTLookupResult constructs an authoritative negative result.
func NewAbsentTXTLookupResult(absence TXTAbsenceClass, ttl time.Duration, dnssec DNSSECStatus) (TXTLookupResult, error) {
	if !absence.Known() || !dnssec.Known() {
		return TXTLookupResult{}, newAPIError(APIErrorCodeInvalidRequest)
	}
	return TXTLookupResult{state: &txtLookupResultState{
		status: TXTLookupStatusAbsent, absence: absence,
		negativeTTL: ttl, dnssec: dnssec,
	}}, nil
}

// Status returns the mutually exclusive lookup status.
func (r TXTLookupResult) Status() TXTLookupStatus {
	if r.state == nil {
		return ""
	}
	return r.state.status
}

// RecordCount returns the exact RR count without requiring ambiguous payload traversal.
func (r TXTLookupResult) RecordCount() int {
	if r.state == nil {
		return 0
	}
	return r.state.recordCount
}

// Records returns the unique detached TXT payload or nil when absent or ambiguous.
func (r TXTLookupResult) Records() []TXTRecord {
	if r.state == nil {
		return nil
	}
	return clonePublicTXTRecords(r.state.records)
}

// Absence returns the authoritative negative class when absent.
func (r TXTLookupResult) Absence() TXTAbsenceClass {
	if r.state == nil {
		return ""
	}
	return r.state.absence
}

// PositiveTTL returns found-answer TTL provenance.
func (r TXTLookupResult) PositiveTTL() time.Duration {
	if r.state == nil {
		return 0
	}
	return r.state.positiveTTL
}

// NegativeTTL returns authoritative negative TTL provenance.
func (r TXTLookupResult) NegativeTTL() time.Duration {
	if r.state == nil {
		return 0
	}
	return r.state.negativeTTL
}

// DNSSECStatus returns verdict-neutral bounded diagnostic metadata.
func (r TXTLookupResult) DNSSECStatus() DNSSECStatus {
	if r.state == nil {
		return ""
	}
	return r.state.dnssec
}

// IsZero reports whether no declared public transport result is present.
func (r TXTLookupResult) IsZero() bool {
	return r.state == nil || r.state.status == "" && len(r.state.records) == 0 && r.state.recordCount == 0 &&
		r.state.absence == "" && r.state.positiveTTL == 0 && r.state.negativeTTL == 0 && r.state.dnssec == ""
}

// recordStorageCount returns the package-owned record count without cloning payloads.
func (r TXTLookupResult) recordStorageCount() int {
	if r.state == nil {
		return 0
	}
	return len(r.state.records)
}

// String returns a constant representation without DNS TXT payload bytes.
func (TXTLookupResult) String() string { return txtLookupResultRedactedText }

// GoString returns a constant representation without DNS TXT payload bytes.
func (TXTLookupResult) GoString() string { return txtLookupResultRedactedText }

// Format prevents formatting from traversing DNS TXT result storage.
func (TXTLookupResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, txtLookupResultRedactedText)
}

// MarshalJSON rejects serialization outside the bounded provider boundary.
func (TXTLookupResult) MarshalJSON() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// MarshalText rejects diagnostic serialization of DNS TXT result storage.
func (TXTLookupResult) MarshalText() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// clonePublicTXTRecords clones record containers and payload bytes.
func clonePublicTXTRecords(records []TXTRecord) []TXTRecord {
	if records == nil {
		return nil
	}
	cloned := make([]TXTRecord, len(records))
	for index := range records {
		cloned[index] = newTXTRecord(records[index].Payload())
	}
	return cloned
}

// TXTTransport resolves one absolute DNS TXT owner through caller context.
//
// Implementations return a declared result with nil error, a zero result with
// caller context error, or a zero result with an existing typed public provider
// error. Raw and contradictory combinations are contract violations later.
type TXTTransport interface {
	LookupTXT(context.Context, string) (TXTLookupResult, error)
}

type netTXTLookupResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}

// NetTXTTransport adapts standard-library TXT lookup semantics without inventing TTL data.
type NetTXTTransport struct {
	state *netTXTTransportState
}

type netTXTTransportState struct {
	resolver netTXTLookupResolver
}

// NewNetTXTTransport constructs a standard-library TXT transport.
func NewNetTXTTransport(resolver *net.Resolver) (*NetTXTTransport, error) {
	return newNetTXTTransport(resolver)
}

// newNetTXTTransport constructs a transport from a testable standard resolver seam.
func newNetTXTTransport(resolver netTXTLookupResolver) (*NetTXTTransport, error) {
	if nilTXTLookupResolver(resolver) {
		return nil, newAPIError(APIErrorCodeInvalidProvider)
	}
	return &NetTXTTransport{state: &netTXTTransportState{resolver: resolver}}, nil
}

// nilTXTLookupResolver reports nil and typed-nil resolver dependencies.
func nilTXTLookupResolver(resolver netTXTLookupResolver) bool {
	return niliface.IsNil(resolver)
}

// LookupTXT preserves returned RR boundaries and reports zero TTL provenance.
func (t *NetTXTTransport) LookupTXT(ctx context.Context, absoluteName string) (TXTLookupResult, error) {
	if t == nil || t.state == nil || nilTXTLookupResolver(t.state.resolver) || ctx == nil {
		return TXTLookupResult{}, newAPIError(APIErrorCodeInvalidProvider)
	}
	if err := ctx.Err(); err != nil {
		return TXTLookupResult{}, err
	}
	if !keyresolver.ValidAbsoluteOwner(absoluteName) {
		return TXTLookupResult{}, newAPIError(APIErrorCodeInvalidProvider)
	}
	records, err := t.state.resolver.LookupTXT(ctx, absoluteName)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return TXTLookupResult{}, ctxErr
		}
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) {
			if dnsError.IsNotFound {
				// net.Resolver cannot reliably distinguish NXDOMAIN from NODATA.
				return NewAbsentTXTLookupResult(TXTAbsenceNODATA, 0, DNSSECStatusUnavailable)
			}
			return TXTLookupResult{}, NewTemporaryProviderError()
		}
		return TXTLookupResult{}, newAPIError(APIErrorCodeInvalidProvider)
	}
	if len(records) > 1 {
		return NewAmbiguousTXTLookupResult(len(records), 0, DNSSECStatusUnavailable)
	}
	if len(records) == 0 {
		return TXTLookupResult{}, newAPIError(APIErrorCodeInvalidProvider)
	}
	if len(records[0]) > hardMaxTXTRecordPayloadBytes {
		return TXTLookupResult{}, newAPIError(APIErrorCodeInvalidProvider)
	}
	return NewFoundTXTLookupResult([][]byte{[]byte(records[0])}, 0, DNSSECStatusUnavailable)
}

// String returns a constant representation without retained resolver state.
func (NetTXTTransport) String() string { return netTXTTransportRedactedText }

// GoString returns a constant representation without retained resolver state.
func (NetTXTTransport) GoString() string { return netTXTTransportRedactedText }

// Format prevents formatting from traversing the retained resolver.
func (NetTXTTransport) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, netTXTTransportRedactedText)
}

// MarshalJSON rejects serialization of retained resolver dependencies.
func (NetTXTTransport) MarshalJSON() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// MarshalText rejects diagnostic serialization of retained resolver dependencies.
func (NetTXTTransport) MarshalText() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}
