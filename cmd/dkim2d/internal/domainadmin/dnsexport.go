package domainadmin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"sync"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

const (
	dnsExportVersion = "dkim2-dns-export-v1"
	txtChunkBytes    = 200
)

// DNSRecord owns one canonical DNS-04 record derived from staged readback.
type DNSRecord struct {
	domain     []byte
	selector   []byte
	owner      []byte
	payload    []byte
	publicSPKI []byte
	algorithm  provider.Algorithm
}

// StagedDNSSet owns the bounded DNS proof projection of one exact staged candidate.
type StagedDNSSet struct {
	mu      sync.Mutex
	records []DNSRecord
	policy  datasourceadmin.DNSPolicy
	plan    datasourceadmin.PlanDigest
	staged  datasourceadmin.StagedEvidence
	closed  bool
}

// NewStagedDNSSet derives exact DNS records only from plan-selected staged candidate readback.
func NewStagedDNSSet(
	ctx context.Context,
	plan *Plan,
	candidate *datasourceadmin.PublicationEnvelope,
	generation datasourceadmin.GenerationInfo,
	staged datasourceadmin.StagedEvidence,
	limits Limits,
) (*StagedDNSSet, error) {
	if ctx == nil || ctx.Err() != nil || plan == nil || candidate == nil || limits.Validate() != nil ||
		!candidate.PreparedEvidence().Matches(staged) {
		return nil, newError(CodeConflict)
	}
	plan.mu.Lock()
	if plan.closed || plan.candidateGeneration != candidate.Generation() ||
		!candidate.Binding().Equal(plan.operation) || len(plan.credentials) == 0 ||
		len(plan.credentials) > int(limits.MaxDNSRecords) || !plan.digest.Valid() ||
		generation.Generation != plan.candidateGeneration || generation.Current ||
		generation.State != datasourceadmin.StateCommitted ||
		!generation.Operation.Equal(plan.operation) {
		plan.mu.Unlock()
		return nil, newError(CodeConflict)
	}
	intent := plan.intent.clone()
	profileID := plan.profileID
	credentials := append([]AllocatedIdentity(nil), plan.credentials...)
	policy := cloneDNSPolicy(plan.dns)
	planDigest := plan.digest
	plan.mu.Unlock()
	defer clearAllocatedIdentities(credentials)
	if policy.ExportTTLSeconds == 0 || policy.ProofLifetimeSeconds == 0 {
		return nil, newError(CodeConflict)
	}
	records := make([]DNSRecord, 0, len(credentials))
	err := candidate.WithRows(ctx, func(rows datasourceadmin.Rows) error {
		if !exactPlannedRows(rows, intent, profileID, credentials) {
			return newError(CodeConflict)
		}
		for _, allocated := range credentials {
			credential, found := findStagedCredential(rows, profileID, allocated)
			if !found {
				return newError(CodeConflict)
			}
			record, recordErr := newDNSRecord(ctx, intent.Domain(), allocated.selector, allocated.algorithm, credential.PublicSPKI)
			if recordErr != nil {
				return recordErr
			}
			records = append(records, record)
		}
		return nil
	})
	if err != nil || len(records) != len(credentials) {
		clearDNSRecords(records)
		return nil, newError(CodeConflict)
	}
	sort.Slice(records, func(left, right int) bool {
		return bytes.Compare(records[left].owner, records[right].owner) < 0
	})
	return &StagedDNSSet{records: records, policy: policy, plan: planDigest, staged: staged}, nil
}

// exactPlannedRows proves the complete selected profile, policy, credential, handle, and key projection.
func exactPlannedRows(
	rows datasourceadmin.Rows,
	intent Intent,
	profileID string,
	credentials []AllocatedIdentity,
) bool {
	if !intent.valid() || profileID == "" || len(credentials) == 0 {
		return false
	}
	return exactPlannedProfile(rows.Profiles, intent, profileID) &&
		exactPlannedPolicy(rows.Policies, intent, profileID) &&
		exactPlannedCredentials(rows, intent, profileID, credentials)
}

// exactPlannedProfile proves one unscheduled active profile matches the selected domain.
func exactPlannedProfile(rows []datasourceadmin.ProfileRow, intent Intent, profileID string) bool {
	profileCount := 0
	for _, row := range rows {
		if row.ID != profileID {
			continue
		}
		profileCount++
		if row.Domain != intent.Domain() || row.Status != provider.RecordStatusActive.String() ||
			row.NotBeforeUTC != nil || row.NotAfterUTC != nil {
			return false
		}
	}
	return profileCount == 1
}

// exactPlannedPolicy proves one policy tuple exactly matches the selected intent and profile.
func exactPlannedPolicy(rows []datasourceadmin.PolicyRow, intent Intent, profileID string) bool {
	policyCount := 0
	for _, row := range rows {
		tupleMatch := row.TenantID == intent.TenantID() && row.Domain == intent.Domain() &&
			row.Use == intent.ProfileUse().String()
		if row.ProfileID != profileID && !tupleMatch {
			continue
		}
		policyCount++
		if !tupleMatch || row.ProfileID != profileID || row.Status != provider.RecordStatusActive.String() ||
			row.Rollout != intent.Rollout().String() || row.Compatibility != intent.Compatibility().String() ||
			row.FeedbackRouteID != nil {
			return false
		}
	}
	return policyCount == 1
}

// exactPlannedCredentials proves the selected profile has only its planned complete key bindings.
func exactPlannedCredentials(
	rows datasourceadmin.Rows,
	intent Intent,
	profileID string,
	credentials []AllocatedIdentity,
) bool {
	credentialCount := 0
	for _, row := range rows.Credentials {
		if row.ProfileID != profileID {
			continue
		}
		credentialCount++
		if !plannedCredentialAndKeyMatch(rows, intent, credentials, row) {
			return false
		}
	}
	if credentialCount != len(credentials) {
		return false
	}
	for _, allocated := range credentials {
		if exactCredentialCount(rows.Credentials, profileID, allocated) != 1 ||
			exactHandleCount(rows.Handles, allocated.handleID) != 1 {
			return false
		}
	}
	return true
}

// exactCredentialCount counts complete identity matches under one selected profile.
func exactCredentialCount(
	rows []datasourceadmin.CredentialRow,
	profileID string,
	allocated AllocatedIdentity,
) int {
	count := 0
	for _, row := range rows {
		if row.ProfileID == profileID && row.Algorithm == string(allocated.algorithm) &&
			row.Selector == allocated.selector && row.HandleID == allocated.handleID {
			count++
		}
	}
	return count
}

// exactHandleCount counts one allocated handle across the complete candidate snapshot.
func exactHandleCount(rows []datasourceadmin.HandleRow, handleID string) int {
	count := 0
	for _, row := range rows {
		if row.ID == handleID {
			count++
		}
	}
	return count
}

// plannedCredentialAndKeyMatch binds one selected credential to its exact native key row.
func plannedCredentialAndKeyMatch(
	rows datasourceadmin.Rows,
	intent Intent,
	credentials []AllocatedIdentity,
	credential datasourceadmin.CredentialRow,
) bool {
	for _, allocated := range credentials {
		if credential.Algorithm != string(allocated.algorithm) || credential.Selector != allocated.selector ||
			credential.HandleID != allocated.handleID {
			continue
		}
		matches := 0
		for _, row := range rows.KeyMaterial {
			if row.HandleID != allocated.handleID {
				continue
			}
			matches++
			if row.TenantID != intent.TenantID() || row.Domain != intent.Domain() ||
				row.Use != intent.ProfileUse().String() || row.Algorithm != string(allocated.algorithm) ||
				!bytes.Equal(row.PublicSPKI, credential.PublicSPKI) {
				return false
			}
		}
		return matches == 1
	}
	return false
}

// findStagedCredential locates one exact plan allocation in canonical readback rows.
func findStagedCredential(
	rows datasourceadmin.Rows,
	profileID string,
	allocated AllocatedIdentity,
) (datasourceadmin.CredentialRow, bool) {
	for _, row := range rows.Credentials {
		if row.ProfileID == profileID && row.Algorithm == string(allocated.algorithm) &&
			row.Selector == allocated.selector && row.HandleID == allocated.handleID {
			return row, true
		}
	}
	return datasourceadmin.CredentialRow{}, false
}

// newDNSRecord converts canonical SPKI to the exact DNS-04 public-key representation.
func newDNSRecord(
	ctx context.Context,
	domain string,
	selector string,
	algorithm provider.Algorithm,
	publicSPKI []byte,
) (DNSRecord, error) {
	if ctx == nil || ctx.Err() != nil {
		return DNSRecord{}, newError(CodeUnavailable)
	}
	public, err := x509.ParsePKIXPublicKey(publicSPKI)
	if err != nil {
		return DNSRecord{}, newError(CodeDNSInvalid)
	}
	canonicalSPKI, err := x509.MarshalPKIXPublicKey(public)
	if err != nil || !bytes.Equal(canonicalSPKI, publicSPKI) {
		clear(canonicalSPKI)
		return DNSRecord{}, newError(CodeDNSInvalid)
	}
	clear(canonicalSPKI)
	var keyType string
	var dnsKey []byte
	switch algorithm {
	case provider.AlgorithmRSASHA256:
		key, ok := public.(*rsa.PublicKey)
		if !ok || key == nil {
			return DNSRecord{}, newError(CodeDNSAlgorithmMismatch)
		}
		keyType = "rsa"
		dnsKey = x509.MarshalPKCS1PublicKey(key)
	case provider.AlgorithmEd25519SHA256:
		key, ok := public.(ed25519.PublicKey)
		if !ok || len(key) != ed25519.PublicKeySize {
			return DNSRecord{}, newError(CodeDNSAlgorithmMismatch)
		}
		keyType = "ed25519"
		dnsKey = bytes.Clone(key)
	default:
		return DNSRecord{}, newError(CodeDNSUnsupported)
	}
	defer clear(dnsKey)
	payload := []byte("v=DKIM1; k=" + keyType + "; p=" + base64.StdEncoding.EncodeToString(dnsKey))
	query, err := dkim2.NewPublicKeyQuery(domain, selector, dkim2Algorithm(algorithm))
	if err != nil || query.SigningDomain() != domain || query.Selector() != selector {
		clear(payload)
		return DNSRecord{}, newError(CodeDNSInvalid)
	}
	record := DNSRecord{
		domain: []byte(domain), selector: []byte(selector),
		owner: []byte(selector + "._domainkey." + domain + "."), payload: payload,
		publicSPKI: bytes.Clone(publicSPKI), algorithm: algorithm,
	}
	if err := validateDNSRecordRoundTrip(ctx, record); err != nil {
		clearDNSRecord(&record)
		return DNSRecord{}, err
	}
	return record, nil
}

// ValidateCanonicalDNSRecord proves one native credential through the production DNS-04 parser path.
func ValidateCanonicalDNSRecord(
	ctx context.Context,
	domain string,
	selector string,
	algorithm provider.Algorithm,
	publicSPKI []byte,
) error {
	record, err := newDNSRecord(ctx, domain, selector, algorithm, publicSPKI)
	if err != nil {
		return err
	}
	clearDNSRecord(&record)
	return nil
}

// dkim2Algorithm maps only the two supported staged algorithm families.
func dkim2Algorithm(algorithm provider.Algorithm) dkim2.Algorithm {
	if algorithm == provider.AlgorithmEd25519SHA256 {
		return dkim2.AlgorithmEd25519SHA256
	}
	if algorithm == provider.AlgorithmRSASHA256 {
		return dkim2.AlgorithmRSASHA256
	}
	return dkim2.AlgorithmUnknown
}

type exactRecordTransport struct {
	owner   string
	payload []byte
}

// LookupTXT supplies exactly one already-concatenated in-memory RR for parser round-trip.
func (t exactRecordTransport) LookupTXT(ctx context.Context, owner string) (dkim2.TXTLookupResult, error) {
	if ctx == nil || ctx.Err() != nil || owner != t.owner {
		return dkim2.TXTLookupResult{}, dkim2.NewTemporaryProviderError()
	}
	return dkim2.NewFoundTXTLookupResult([][]byte{t.payload}, 0, dkim2.DNSSECStatusUnavailable)
}

// validateDNSRecordRoundTrip reuses the existing DNS parser and public-key validator.
func validateDNSRecordRoundTrip(ctx context.Context, record DNSRecord) error {
	providerValue, err := dkim2.NewDNSPublicKeyProvider(exactRecordTransport{
		owner: string(record.owner), payload: record.payload,
	})
	if err != nil {
		return newError(CodeDNSInvalid)
	}
	query, err := dkim2.NewPublicKeyQuery(string(record.domain), string(record.selector), dkim2Algorithm(record.algorithm))
	if err != nil {
		return newError(CodeDNSInvalid)
	}
	result, err := providerValue.LookupPublicKey(ctx, query)
	if err != nil || result.Status() != dkim2.PublicKeyStatusFound || result.Algorithm() != query.Algorithm() {
		return newError(CodeDNSInvalid)
	}
	actualSPKI, err := resultSPKI(result)
	if err != nil {
		return err
	}
	defer clear(actualSPKI)
	if !bytes.Equal(actualSPKI, record.publicSPKI) {
		return newError(CodeDNSSPKIMismatch)
	}
	return nil
}

// resultSPKI reconstructs canonical SPKI from one found parser result.
func resultSPKI(result dkim2.PublicKeyResult) ([]byte, error) {
	if key, ok := result.RSAPublicKey(); ok {
		value, err := x509.MarshalPKIXPublicKey(key)
		if err == nil {
			return value, nil
		}
	}
	if key, ok := result.Ed25519PublicKey(); ok {
		value, err := x509.MarshalPKIXPublicKey(key)
		if err == nil {
			return value, nil
		}
	}
	return nil, newError(CodeDNSInvalid)
}

// cloneDNSRecords creates one separately owned protected record slice.
func cloneDNSRecords(records []DNSRecord) []DNSRecord {
	result := make([]DNSRecord, len(records))
	for index := range records {
		result[index] = DNSRecord{
			domain: bytes.Clone(records[index].domain), selector: bytes.Clone(records[index].selector),
			owner: bytes.Clone(records[index].owner), payload: bytes.Clone(records[index].payload),
			publicSPKI: bytes.Clone(records[index].publicSPKI), algorithm: records[index].algorithm,
		}
	}
	return result
}

// clearDNSRecord erases every mutable protected record field.
func clearDNSRecord(record *DNSRecord) {
	if record == nil {
		return
	}
	clear(record.domain)
	clear(record.selector)
	clear(record.owner)
	clear(record.payload)
	clear(record.publicSPKI)
	*record = DNSRecord{}
}

// clearDNSRecords erases one complete protected record slice.
func clearDNSRecords(records []DNSRecord) {
	for index := range records {
		clearDNSRecord(&records[index])
	}
	clear(records)
}

// WithRecords supplies detached protected records to one bounded callback.
func (s *StagedDNSSet) WithRecords(ctx context.Context, use func([]DNSRecord) error) error {
	if s == nil || ctx == nil || use == nil || ctx.Err() != nil {
		return newError(CodeConflict)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return newError(CodeConflict)
	}
	records := cloneDNSRecords(s.records)
	s.mu.Unlock()
	defer clearDNSRecords(records)
	if err := use(records); err != nil {
		return newError(CodeUnavailable)
	}
	return nil
}

// Close erases all staged DNS identity and public-key material.
func (s *StagedDNSSet) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	clearDNSRecords(s.records)
	s.records = nil
	s.policy = datasourceadmin.DNSPolicy{}
	s.plan = datasourceadmin.PlanDigest{}
	s.staged = datasourceadmin.StagedEvidence{}
	s.closed = true
	return nil
}

// String returns a constant protected staged-DNS representation.
func (*StagedDNSSet) String() string { return redacted }

// GoString returns a constant protected staged-DNS representation.
func (*StagedDNSSet) GoString() string { return redacted }

// Format prevents DNS identities and record bytes from reaching formatting sinks.
func (*StagedDNSSet) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic staged-DNS serialization.
func (*StagedDNSSet) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }

// String returns a constant protected DNS-record representation.
func (DNSRecord) String() string { return redacted }

// GoString returns a constant protected DNS-record representation.
func (DNSRecord) GoString() string { return redacted }

// Format prevents DNS record bytes from reaching formatting sinks.
func (DNSRecord) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic DNS-record serialization.
func (DNSRecord) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }

// DNSExportResult contains only bounded identity-free artifact counts.
type DNSExportResult struct {
	Records uint32
	Bytes   uint32
}

// ExportCanonicalDNSBatch writes one bounded owner-only DNS artifact from
// already validated campaign proof inputs. It deliberately has no DNS write
// transport and returns counts only.
func ExportCanonicalDNSBatch(ctx context.Context, path string, inputs []DNSProofInput, ttl uint64, limits Limits) (DNSExportResult, error) {
	if ctx == nil || ctx.Err() != nil || limits.Validate() != nil || len(inputs) == 0 || len(inputs) > int(limits.MaxDNSRecords) || ttl == 0 || ttl > 604800 {
		return DNSExportResult{}, newError(CodeProtectedInput)
	}
	records := make([]DNSRecord, 0, len(inputs))
	for _, input := range inputs {
		record, err := newDNSRecord(ctx, input.domain, input.selector, input.algorithm, input.publicSPKI)
		if err != nil {
			clearDNSRecords(records)
			return DNSExportResult{}, err
		}
		records = append(records, record)
	}
	defer clearDNSRecords(records)
	document, err := formatDNSExport(records, ttl, int(limits.MaxDNSExportBytes))
	if err != nil {
		return DNSExportResult{}, err
	}
	defer clear(document)
	result := DNSExportResult{Records: uint32(len(records)), Bytes: uint32(len(document))}
	existing, exists, readErr := config.ReadProtectedDocumentIfExists(path, int(limits.MaxDNSExportBytes))
	if readErr != nil {
		return DNSExportResult{}, mapDNSStoreError(readErr)
	}
	defer clear(existing)
	if exists {
		if !bytes.Equal(existing, document) {
			return DNSExportResult{}, newError(CodeConflict)
		}
		return result, nil
	}
	if err := config.CreateProtectedDocument(ctx, path, document, int(limits.MaxDNSExportBytes)); err != nil {
		return DNSExportResult{}, mapDNSStoreError(err)
	}
	return result, nil
}

// ExportDNS atomically writes one explicit owner-only deterministic zone-file artifact.
func ExportDNS(ctx context.Context, path string, set *StagedDNSSet, limits Limits) (DNSExportResult, error) {
	if ctx == nil || ctx.Err() != nil || set == nil || limits.Validate() != nil {
		return DNSExportResult{}, newError(CodeProtectedInput)
	}
	set.mu.Lock()
	if set.closed || len(set.records) == 0 || len(set.records) > int(limits.MaxDNSRecords) {
		set.mu.Unlock()
		return DNSExportResult{}, newError(CodeConflict)
	}
	records := cloneDNSRecords(set.records)
	ttl := set.policy.ExportTTLSeconds
	set.mu.Unlock()
	defer clearDNSRecords(records)
	document, err := formatDNSExport(records, ttl, int(limits.MaxDNSExportBytes))
	if err != nil {
		return DNSExportResult{}, err
	}
	defer clear(document)
	result := DNSExportResult{Records: uint32(len(records)), Bytes: uint32(len(document))}
	existing, exists, err := config.ReadProtectedDocumentIfExists(path, int(limits.MaxDNSExportBytes))
	if err != nil {
		return DNSExportResult{}, mapDNSStoreError(err)
	}
	if exists {
		exact := bytes.Equal(existing, document)
		clear(existing)
		if exact {
			return result, nil
		}
		return DNSExportResult{}, newError(CodeConflict)
	}
	if err := config.CreateProtectedDocument(ctx, path, document, int(limits.MaxDNSExportBytes)); err != nil {
		if config.CodeOf(err) == config.CodeProtectedConflict {
			concurrent, concurrentExists, readErr := config.ReadProtectedDocumentIfExists(
				path, int(limits.MaxDNSExportBytes),
			)
			if readErr != nil {
				clear(concurrent)
				return DNSExportResult{}, mapDNSStoreError(readErr)
			}
			exact := concurrentExists && bytes.Equal(concurrent, document)
			clear(concurrent)
			if exact {
				return result, nil
			}
			return DNSExportResult{}, newError(CodeConflict)
		}
		return DNSExportResult{}, mapDNSStoreError(err)
	}
	return result, nil
}

// formatDNSExport emits deterministic RFC 1035 TXT presentation with fixed chunks.
func formatDNSExport(records []DNSRecord, ttl uint64, maximum int) ([]byte, error) {
	if len(records) == 0 || ttl == 0 || maximum <= 0 {
		return nil, newError(CodeDNSInvalid)
	}
	var output bytes.Buffer
	output.WriteString("; ")
	output.WriteString(dnsExportVersion)
	output.WriteByte('\n')
	output.WriteString("; ttl-seconds=")
	output.WriteString(strconv.FormatUint(ttl, 10))
	output.WriteByte('\n')
	for _, record := range records {
		if len(record.owner) == 0 || len(record.selector) == 0 || len(record.payload) == 0 ||
			(record.algorithm != provider.AlgorithmRSASHA256 && record.algorithm != provider.AlgorithmEd25519SHA256) {
			return nil, newError(CodeDNSInvalid)
		}
		output.WriteString("; algorithm=")
		output.WriteString(string(record.algorithm))
		output.WriteString(" selector=")
		output.Write(record.selector)
		output.WriteByte('\n')
		output.Write(record.owner)
		output.WriteByte(' ')
		output.WriteString(strconv.FormatUint(ttl, 10))
		output.WriteString(" IN TXT")
		for _, chunk := range txtChunks(record.payload, txtChunkBytes) {
			output.WriteString(" \"")
			output.Write(chunk)
			output.WriteByte('"')
		}
		output.WriteByte('\n')
		if output.Len() > maximum {
			return nil, newError(CodeDNSLimitExceeded)
		}
	}
	return slices.Clone(output.Bytes()), nil
}

// txtChunks returns ordered views whose concatenation is the exact logical RR payload.
func txtChunks(payload []byte, maximum int) [][]byte {
	if len(payload) == 0 || maximum <= 0 {
		return nil
	}
	chunks := make([][]byte, 0, (len(payload)+maximum-1)/maximum)
	for offset := 0; offset < len(payload); offset += maximum {
		end := min(offset+maximum, len(payload))
		chunks = append(chunks, payload[offset:end])
	}
	return chunks
}

// mapDNSStoreError maps protected filesystem classes without paths or record material.
func mapDNSStoreError(err error) error {
	switch config.CodeOf(err) {
	case config.CodeProtectedBusy, config.CodeProtectedConflict:
		return newError(CodeConflict)
	case config.CodeProtectedAmbiguous:
		return newError(CodeReconcileRequired)
	case config.CodeProtectedContent:
		return newError(CodeDNSLimitExceeded)
	default:
		return newError(CodeProtectedInput)
	}
}
