package rotationadmin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

const (
	journalVersion  = "dkim2-rotation-campaign-journal-v1"
	maxJournalBytes = 262_144
)

type batchReceipt struct {
	batch         Batch
	completedUnix int64
	proofPolicy   string
}

// Journal owns one protected resumable campaign state machine.
type Journal struct {
	mu                  sync.Mutex
	revision            uint64
	state               State
	mode                admincontract.Mode
	operation           string
	emergencyReason     string
	sourceSchema        string
	sourceGeneration    uint64
	candidateGeneration uint64
	planDigest          admincontract.Digest
	frozenDigest        admincontract.Digest
	candidateDigest     admincontract.Digest
	workCount           uint32
	recordCount         uint32
	work                []admincontract.WorkItem
	rotationPolicy      string
	dnsPolicy           string
	retentionPolicy     string
	limitProfile        string
	batches             []batchReceipt
	activationUnix      int64
	failureClass        string
	closed              bool
}

// NewJournal constructs one unsaved planned campaign from frozen plan evidence.
func NewJournal(plan *Plan) (*Journal, error) {
	if plan == nil {
		return nil, errInvalid
	}
	plan.mu.Lock()
	defer plan.mu.Unlock()
	if plan.closed || !plan.planDigest.Valid() || !plan.frozenDigest.Valid() || len(plan.work) == 0 {
		return nil, errConflict
	}
	records := 0
	for _, binding := range plan.work {
		records += len(binding.item.Algorithms)
	}
	return &Journal{
		state: StatePlanned, mode: plan.intent.mode, operation: plan.intent.operationValue,
		emergencyReason: plan.intent.emergencyReason, sourceSchema: plan.sourceSchema,
		sourceGeneration: plan.sourceGeneration, candidateGeneration: plan.candidateGeneration,
		planDigest: plan.planDigest, frozenDigest: plan.frozenDigest,
		workCount: uint32(len(plan.work)), recordCount: uint32(records),
		work: cloneJournalWork(plan.work), rotationPolicy: plan.intent.rotationPolicyVersion,
		dnsPolicy: plan.intent.dnsPolicyVersion, retentionPolicy: plan.intent.retentionPolicyVersion,
		limitProfile: plan.intent.limitProfileVersion,
	}, nil
}

// BeginPreparing records the irreversible no-regeneration preparation boundary.
func (j *Journal) BeginPreparing() error { return j.transition(StatePlanned, StatePreparing) }

// RecordPrepared binds the one generated immutable candidate.
func (j *Journal) RecordPrepared(prepared *Prepared) error {
	if j == nil || prepared == nil {
		return errInvalid
	}
	digest, err := prepared.CandidateDigest()
	if err != nil {
		return errConflict
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.state != StatePreparing || prepared.WorkCount() != int(j.workCount) ||
		prepared.DNSRecordCount() != int(j.recordCount) || !digest.Valid() {
		return errConflict
	}
	j.candidateDigest = digest
	j.state = StatePrepared
	return nil
}

// RecordStaged proves exact backend readback before DNS progress.
func (j *Journal) RecordStaged(readback admincontract.Digest) error {
	if j == nil || !readback.Valid() {
		return errInvalid
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.state != StatePrepared || !j.candidateDigest.Equal(readback) {
		return errConflict
	}
	j.state = StateStaged
	return nil
}

// RecordBatchProof appends only the exact next deterministic DNS proof.
func (j *Journal) RecordBatchProof(batch Batch, completed time.Time, proofPolicy string) error {
	if j == nil || !batch.digest.Valid() || completed.IsZero() || completed.Location() != time.UTC || proofPolicy == "" {
		return errInvalid
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || (j.state != StateStaged && j.state != StateDNSInProgress) ||
		batch.Total != j.recordCount || batch.Ordinal != uint32(len(j.batches)+1) {
		return errConflict
	}
	wantStart := uint32(0)
	if len(j.batches) > 0 {
		wantStart = j.batches[len(j.batches)-1].batch.End
	}
	if batch.Start != wantStart || batch.Start >= batch.End || batch.End > batch.Total {
		return errConflict
	}
	wantDigest, err := admincontract.DNSBatchDigest(admincontract.DNSBatch{CandidateDigest: j.candidateDigest, FrozenWorkDigest: j.frozenDigest, Ordinal: batch.Ordinal, Start: batch.Start, End: batch.End, Total: batch.Total})
	if err != nil || !wantDigest.Equal(batch.digest) {
		return errConflict
	}
	j.batches = append(j.batches, batchReceipt{batch: batch, completedUnix: completed.Unix(), proofPolicy: proofPolicy})
	if batch.End == batch.Total {
		j.state = StateDNSComplete
	} else {
		j.state = StateDNSInProgress
	}
	return nil
}

// BeginActivation validates fresh complete proof evidence and records write-ahead state.
func (j *Journal) BeginActivation(now time.Time, maximumProofAge time.Duration) error {
	if j == nil || now.IsZero() || now.Location() != time.UTC || maximumProofAge <= 0 {
		return errInvalid
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.state != StateDNSComplete || len(j.batches) == 0 || j.batches[len(j.batches)-1].batch.End != j.recordCount {
		return errConflict
	}
	for _, receipt := range j.batches {
		completed := time.Unix(receipt.completedUnix, 0).UTC()
		if completed.After(now) || now.Sub(completed) > maximumProofAge {
			return errConflict
		}
	}
	j.state = StateActivating
	j.activationUnix = now.Unix()
	return nil
}

// RecordActivated closes one exact successful pointer transition.
func (j *Journal) RecordActivated() error { return j.transition(StateActivating, StateActivated) }

// RequireReconciliation records an ambiguous outcome without retry authority.
func (j *Journal) RequireReconciliation(failureClass string) error {
	if j == nil || failureClass == "" {
		return errInvalid
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.state == StateActivated || j.state == StateAborted {
		return errConflict
	}
	j.failureClass = failureClass
	j.state = StateReconcileRequired
	return nil
}

// Abort terminates only a nonactivating campaign.
func (j *Journal) Abort() error {
	if j == nil {
		return errInvalid
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.state == StateActivating || j.state == StateActivated {
		return errConflict
	}
	j.state = StateAborted
	return nil
}

// State returns the current closed state.
func (j *Journal) State() State {
	if j == nil {
		return StateFailed
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return StateFailed
	}
	return j.state
}

// MatchesResumeRequest confirms that a command may resume this exact durable
// campaign without exposing its operation identity. Emergency resumes must
// repeat the same one-binding selector and closed reason.
func (j *Journal) MatchesResumeRequest(intent Intent) bool {
	if j == nil {
		return false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.mode != intent.mode {
		return false
	}
	if j.mode == admincontract.ModeNormal {
		return intent.emergencyReason == "" && intent.emergencyBinding == (BindingSelector{})
	}
	if j.mode != admincontract.ModeEmergency || len(j.work) != 1 || j.emergencyReason != intent.emergencyReason {
		return false
	}
	item := j.work[0]
	return item.Tenant == intent.emergencyBinding.Tenant && item.Domain == intent.emergencyBinding.Domain &&
		item.Use == intent.emergencyBinding.Use && item.Profile == intent.emergencyBinding.Profile
}

// Report returns only bounded count and result classes.
func (j *Journal) Report() Report {
	if j == nil {
		return Report{State: StateFailed, ResultClass: "invalid"}
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	result := "in_progress"
	switch j.state {
	case StateActivated:
		result = "success"
	case StateConflict, StateFailed, StateAborted, StateReconcileRequired:
		result = "closed"
	}
	return Report{State: j.state, Mode: j.mode, WorkCount: j.workCount, RecordCount: j.recordCount, BatchCount: uint32(len(j.batches)), ResultClass: result}
}

// Equivalent compares exact protected journal facts for ambiguous-save reconciliation.
func (j *Journal) Equivalent(other *Journal) bool {
	left, leftErr := encodeJournal(j, 1)
	right, rightErr := encodeJournal(other, 1)
	defer clear(left)
	defer clear(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}

// Close erases protected journal identities.
func (j *Journal) Close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.operation, j.emergencyReason, j.sourceSchema, j.failureClass = "", "", "", ""
	j.rotationPolicy, j.dnsPolicy, j.retentionPolicy, j.limitProfile = "", "", "", ""
	clearJournalWork(j.work)
	j.work = nil
	j.planDigest, j.frozenDigest, j.candidateDigest = admincontract.Digest{}, admincontract.Digest{}, admincontract.Digest{}
	j.batches = nil
	j.activationUnix = 0
	j.closed = true
	return nil
}

// transition applies one exact state edge.
func (j *Journal) transition(from, to State) error {
	if j == nil {
		return errInvalid
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.state != from || !admincontract.ValidState(to) {
		return errConflict
	}
	j.state = to
	return nil
}

// String returns a constant protected journal representation.
func (*Journal) String() string { return redacted }

// GoString returns a constant protected journal representation.
func (*Journal) GoString() string { return redacted }

// Format prevents protected journal facts from reaching output.
func (*Journal) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic journal serialization.
func (*Journal) MarshalJSON() ([]byte, error) { return nil, errInvalid }

type journalWire struct {
	Version             string                   `json:"version"`
	Revision            uint64                   `json:"revision"`
	State               State                    `json:"state"`
	Mode                admincontract.Mode       `json:"mode"`
	Operation           string                   `json:"operation"`
	EmergencyReason     string                   `json:"emergency_reason,omitempty"`
	SourceSchema        string                   `json:"source_schema"`
	SourceGeneration    uint64                   `json:"source_generation"`
	CandidateGeneration uint64                   `json:"candidate_generation"`
	PlanDigest          string                   `json:"plan_digest"`
	FrozenDigest        string                   `json:"frozen_digest"`
	CandidateDigest     string                   `json:"candidate_digest,omitempty"`
	WorkCount           uint32                   `json:"work_count"`
	RecordCount         uint32                   `json:"record_count"`
	Batches             []batchWire              `json:"batches"`
	ActivationUnix      int64                    `json:"activation_unix,omitempty"`
	FailureClass        string                   `json:"failure_class,omitempty"`
	Work                []admincontract.WorkItem `json:"work"`
	RotationPolicy      string                   `json:"rotation_policy"`
	DNSPolicy           string                   `json:"dns_policy"`
	RetentionPolicy     string                   `json:"retention_policy"`
	LimitProfile        string                   `json:"limit_profile"`
}

type batchWire struct {
	Ordinal       uint32 `json:"ordinal"`
	Start         uint32 `json:"start"`
	End           uint32 `json:"end"`
	Total         uint32 `json:"total"`
	Digest        string `json:"digest"`
	CompletedUnix int64  `json:"completed_unix"`
	ProofPolicy   string `json:"proof_policy"`
}

// JournalStore owns one stable protected filesystem transaction.
type JournalStore struct {
	mu       sync.Mutex
	store    *config.ProtectedStore
	path     string
	loaded   bool
	revision uint64
	poisoned bool
	closed   bool
}

// OpenJournalStore acquires one protected sibling-lock transaction.
func OpenJournalStore(ctx context.Context, path string) (*JournalStore, error) {
	store, err := config.OpenProtectedStore(ctx, path, maxJournalBytes)
	if err != nil {
		return nil, errBackend
	}
	return &JournalStore{store: store, path: path}, nil
}

// Load reads one exact protected journal revision.
func (s *JournalStore) Load(ctx context.Context) (*Journal, bool, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, false, errInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned || s.store == nil {
		return nil, false, errConflict
	}
	document, exists, err := s.store.Read(ctx)
	if err != nil {
		return nil, false, errBackend
	}
	defer clear(document)
	s.loaded, s.revision = true, 0
	if !exists {
		return nil, false, nil
	}
	journal, err := decodeJournal(document)
	if err != nil {
		return nil, false, err
	}
	s.revision = journal.revision
	return journal, true, nil
}

// Save atomically CAS-advances one loaded protected journal revision.
func (s *JournalStore) Save(ctx context.Context, journal *Journal) error {
	if s == nil || journal == nil || ctx == nil || ctx.Err() != nil {
		return errInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned || s.store == nil || !s.loaded || jRevision(journal) != s.revision || s.revision == math.MaxUint64 {
		return errConflict
	}
	next := s.revision + 1
	document, err := encodeJournal(journal, next)
	if err != nil {
		return err
	}
	defer clear(document)
	if err := s.store.Replace(ctx, document); err != nil {
		s.poisoned = true
		return errBackend
	}
	journal.mu.Lock()
	journal.revision = next
	journal.mu.Unlock()
	s.revision = next
	return nil
}

// Reload closes an ambiguous transaction and reopens authoritative readback.
func (s *JournalStore) Reload(ctx context.Context) (*Journal, bool, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, false, errInvalid
	}
	s.mu.Lock()
	if s.closed || !s.poisoned || s.store == nil {
		s.mu.Unlock()
		return nil, false, errConflict
	}
	if err := s.store.Close(); err != nil {
		s.mu.Unlock()
		return nil, false, errBackend
	}
	store, err := config.OpenProtectedStore(ctx, s.path, maxJournalBytes)
	if err != nil {
		s.closed = true
		s.mu.Unlock()
		return nil, false, errBackend
	}
	s.store, s.loaded, s.revision, s.poisoned = store, false, 0, false
	s.mu.Unlock()
	return s.Load(ctx)
}

// Close releases the stable sibling lock.
func (s *JournalStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.store != nil {
		return s.store.Close()
	}
	return nil
}

// encodeJournal serializes one exact protected revision.
func encodeJournal(journal *Journal, revision uint64) ([]byte, error) {
	if journal == nil || revision == 0 {
		return nil, errInvalid
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.closed || !admincontract.ValidState(journal.state) {
		return nil, errConflict
	}
	wire := journalWire{Version: journalVersion, Revision: revision, State: journal.state, Mode: journal.mode, Operation: journal.operation, EmergencyReason: journal.emergencyReason, SourceSchema: journal.sourceSchema, SourceGeneration: journal.sourceGeneration, CandidateGeneration: journal.candidateGeneration, PlanDigest: journal.planDigest.Hex(), FrozenDigest: journal.frozenDigest.Hex(), CandidateDigest: journal.candidateDigest.Hex(), WorkCount: journal.workCount, RecordCount: journal.recordCount, ActivationUnix: journal.activationUnix, FailureClass: journal.failureClass, Work: cloneJournalItems(journal.work), RotationPolicy: journal.rotationPolicy, DNSPolicy: journal.dnsPolicy, RetentionPolicy: journal.retentionPolicy, LimitProfile: journal.limitProfile, Batches: make([]batchWire, len(journal.batches))}
	for index, receipt := range journal.batches {
		wire.Batches[index] = batchWire{Ordinal: receipt.batch.Ordinal, Start: receipt.batch.Start, End: receipt.batch.End, Total: receipt.batch.Total, Digest: receipt.batch.digest.Hex(), CompletedUnix: receipt.completedUnix, ProofPolicy: receipt.proofPolicy}
	}
	document, err := json.Marshal(wire)
	if err != nil || len(document) > maxJournalBytes {
		clear(document)
		return nil, errLimit
	}
	return document, nil
}

// decodeJournal validates one strict protected journal document.
func decodeJournal(document []byte) (*Journal, error) {
	if len(document) == 0 || len(document) > maxJournalBytes || rejectDuplicateJSONKeys(document) != nil {
		return nil, errInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var wire journalWire
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.Version != journalVersion || wire.Revision == 0 || !admincontract.ValidState(wire.State) {
		return nil, errInvalid
	}
	if _, err := datasourceadmin.NewOperationBinding(wire.Operation); err != nil {
		return nil, errInvalid
	}
	plan, err := admincontract.ParseDigestHex(wire.PlanDigest)
	if err != nil {
		return nil, errInvalid
	}
	frozen, err := admincontract.ParseDigestHex(wire.FrozenDigest)
	if err != nil {
		return nil, errInvalid
	}
	var candidate admincontract.Digest
	if wire.CandidateDigest != "" {
		candidate, err = admincontract.ParseDigestHex(wire.CandidateDigest)
		if err != nil {
			return nil, errInvalid
		}
	}
	journal := &Journal{revision: wire.Revision, state: wire.State, mode: wire.Mode, operation: wire.Operation, emergencyReason: wire.EmergencyReason, sourceSchema: wire.SourceSchema, sourceGeneration: wire.SourceGeneration, candidateGeneration: wire.CandidateGeneration, planDigest: plan, frozenDigest: frozen, candidateDigest: candidate, workCount: wire.WorkCount, recordCount: wire.RecordCount, activationUnix: wire.ActivationUnix, failureClass: wire.FailureClass, work: cloneJournalItems(wire.Work), rotationPolicy: wire.RotationPolicy, dnsPolicy: wire.DNSPolicy, retentionPolicy: wire.RetentionPolicy, limitProfile: wire.LimitProfile}
	for _, receipt := range wire.Batches {
		digest, parseErr := admincontract.ParseDigestHex(receipt.Digest)
		if parseErr != nil {
			_ = journal.Close()
			return nil, errInvalid
		}
		journal.batches = append(journal.batches, batchReceipt{batch: Batch{Ordinal: receipt.Ordinal, Start: receipt.Start, End: receipt.End, Total: receipt.Total, digest: digest}, completedUnix: receipt.CompletedUnix, proofPolicy: receipt.ProofPolicy})
	}
	if validateDecodedJournal(journal) != nil {
		_ = journal.Close()
		return nil, errInvalid
	}
	return journal, nil
}

// validateDecodedJournal replays structural state invariants without mutation.
func validateDecodedJournal(journal *Journal) error { //nolint:gocyclo // Protected wire validation checks the complete state matrix centrally.
	if journal == nil || journal.sourceGeneration == 0 || journal.candidateGeneration <= journal.sourceGeneration || journal.workCount == 0 || journal.recordCount == 0 || journal.recordCount < journal.workCount || len(journal.work) != int(journal.workCount) || journal.rotationPolicy == "" || journal.dnsPolicy == "" || journal.retentionPolicy == "" || journal.limitProfile == "" {
		return errInvalid
	}
	workDigest, digestErr := admincontract.FrozenWorkDigest(journal.work)
	if digestErr != nil || !workDigest.Equal(journal.frozenDigest) {
		return errInvalid
	}
	if journal.mode != admincontract.ModeNormal && journal.mode != admincontract.ModeEmergency {
		return errInvalid
	}
	if journal.mode == admincontract.ModeNormal && journal.emergencyReason != "" || journal.mode == admincontract.ModeEmergency && journal.emergencyReason == "" {
		return errInvalid
	}
	if (journal.state == StateActivating || journal.state == StateActivated) && journal.activationUnix <= 0 ||
		journal.state != StateActivating && journal.state != StateActivated && journal.state != StateReconcileRequired && journal.activationUnix != 0 {
		return errInvalid
	}
	if journal.state == StatePlanned || journal.state == StatePreparing {
		if journal.candidateDigest.Valid() || len(journal.batches) != 0 {
			return errInvalid
		}
	} else if !journal.candidateDigest.Valid() {
		return errInvalid
	}
	previousEnd := uint32(0)
	for index, receipt := range journal.batches {
		if receipt.batch.Ordinal != uint32(index+1) || receipt.batch.Start != previousEnd || receipt.batch.End <= receipt.batch.Start || receipt.batch.End > journal.recordCount || receipt.completedUnix <= 0 || receipt.proofPolicy == "" {
			return errInvalid
		}
		want, err := admincontract.DNSBatchDigest(admincontract.DNSBatch{
			CandidateDigest: journal.candidateDigest, FrozenWorkDigest: journal.frozenDigest,
			Ordinal: receipt.batch.Ordinal, Start: receipt.batch.Start, End: receipt.batch.End,
			Total: receipt.batch.Total,
		})
		if err != nil || receipt.batch.Total != journal.recordCount || !want.Equal(receipt.batch.digest) {
			return errInvalid
		}
		previousEnd = receipt.batch.End
	}
	if (journal.state == StatePrepared || journal.state == StateStaged) && len(journal.batches) != 0 ||
		journal.state == StateDNSInProgress && (len(journal.batches) == 0 || previousEnd == journal.recordCount) ||
		(journal.state == StateDNSComplete || journal.state == StateActivating || journal.state == StateActivated) && len(journal.batches) == 0 {
		return errInvalid
	}
	if (journal.state == StateDNSComplete || journal.state == StateActivating || journal.state == StateActivated) && previousEnd != journal.recordCount {
		return errInvalid
	}
	return nil
}

// rejectDuplicateJSONKeys rejects duplicate object keys at every nesting depth.
func rejectDuplicateJSONKeys(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, isDelimiter := token.(json.Delim)
		if !isDelimiter {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				key, ok := keyToken.(string)
				if keyErr != nil || !ok {
					return errInvalid
				}
				if _, duplicate := seen[key]; duplicate {
					return errInvalid
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errInvalid
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errInvalid
	}
	return nil
}

// jRevision returns one protected revision for store comparison.
func jRevision(journal *Journal) uint64 {
	if journal == nil {
		return 0
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	return journal.revision
}

// cloneJournalWork copies the sealed key-free campaign work from a plan.
func cloneJournalWork(work []frozenBinding) []admincontract.WorkItem {
	items := make([]admincontract.WorkItem, len(work))
	for index := range work {
		items[index] = cloneWorkItem(work[index].item)
	}
	return items
}

// cloneJournalItems copies sealed work across the protected wire boundary.
func cloneJournalItems(items []admincontract.WorkItem) []admincontract.WorkItem {
	result := make([]admincontract.WorkItem, len(items))
	for index := range items {
		result[index] = cloneWorkItem(items[index])
	}
	return result
}

// clearJournalWork erases key-free but identity-bearing sealed work on close.
func clearJournalWork(items []admincontract.WorkItem) {
	for index := range items {
		items[index].Tenant, items[index].Domain, items[index].Use, items[index].Profile = "", "", "", ""
		clear(items[index].Algorithms)
		items[index].Algorithms = nil
	}
	clear(items)
}
