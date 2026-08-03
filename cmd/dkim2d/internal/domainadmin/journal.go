package domainadmin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

const (
	journalVersion       = "dkim2-domain-journal-v1"
	maxJournalJSONDepth  = 32
	maxJournalJSONTokens = 4096
)

// Journal owns one closed protected onboarding operation record.
type Journal struct {
	mu            sync.Mutex
	revision      uint64
	plan          *Plan
	state         OperationState
	prepared      datasourceadmin.PreparedEvidence
	staged        datasourceadmin.StagedEvidence
	activation    *ActivationLineage
	reconcileFrom OperationState
	failure       ErrorCode
	closed        bool
}

// JournalStore holds the stable filesystem lock through read, backend inspection, and sync.
type JournalStore struct {
	mu             sync.Mutex
	protected      journalProtectedStore
	openProtected  journalProtectedStoreOpener
	path           string
	limits         Limits
	loaded         bool
	loadedExists   bool
	loadedRevision uint64
	poisoned       bool
	closed         bool
}

// journalProtectedStore is the smallest protected-document transaction boundary.
type journalProtectedStore interface {
	Read(context.Context) ([]byte, bool, error)
	Replace(context.Context, []byte) error
	Close() error
}

// journalProtectedStoreOpener reacquires one fresh protected transaction after ambiguity.
type journalProtectedStoreOpener func(context.Context, string, int) (journalProtectedStore, error)

type journalWire struct {
	Version                string                 `json:"version"`
	Revision               uint64                 `json:"revision"`
	State                  string                 `json:"state"`
	Backend                string                 `json:"backend"`
	Authority              journalAuthorityWire   `json:"authority"`
	ExpectedCurrent        uint64                 `json:"expected_current"`
	AdministrationRevision uint64                 `json:"administration_revision"`
	CandidateGeneration    uint64                 `json:"candidate_generation"`
	Intent                 journalIntentWire      `json:"intent"`
	ProfileID              string                 `json:"profile_id"`
	Credentials            []journalCredential    `json:"credentials"`
	DNS                    journalDNSWire         `json:"dns"`
	OperationID            string                 `json:"operation_id"`
	PlanDigest             string                 `json:"plan_digest"`
	PreparedDigest         string                 `json:"prepared_digest,omitempty"`
	StagedDigest           string                 `json:"staged_digest,omitempty"`
	FailureClass           string                 `json:"failure_class,omitempty"`
	Activation             *journalActivationWire `json:"activation,omitempty"`
	ReconcileFrom          string                 `json:"reconcile_from,omitempty"`
}

type journalAuthorityWire struct {
	AuthorityID       string                `json:"authority_id"`
	Endpoints         []journalEndpointWire `json:"endpoints"`
	LDAP              *journalLDAPWire      `json:"ldap,omitempty"`
	SQL               *journalSQLWire       `json:"sql,omitempty"`
	TrustFingerprints []string              `json:"trust_fingerprints"`
	ClientFingerprint string                `json:"client_fingerprint,omitempty"`
}

type journalEndpointWire struct {
	Scheme        string `json:"scheme"`
	Host          string `json:"host"`
	Port          uint16 `json:"port"`
	TLSServerName string `json:"tls_server_name"`
}

type journalLDAPWire struct {
	BaseDN              string `json:"base_dn"`
	SnapshotPrincipal   string `json:"snapshot_principal"`
	StagingPrincipal    string `json:"staging_principal"`
	ActivationPrincipal string `json:"activation_principal"`
}

type journalSQLWire struct {
	Database       string `json:"database"`
	Schema         string `json:"schema"`
	SnapshotRole   string `json:"snapshot_role"`
	StagingRole    string `json:"staging_role"`
	ActivationRole string `json:"activation_role"`
}

type journalIntentWire struct {
	Version       string   `json:"version"`
	Domain        string   `json:"domain"`
	TenantID      string   `json:"tenant_id"`
	ProfileUse    string   `json:"profile_use"`
	Algorithms    []string `json:"algorithms"`
	Rollout       string   `json:"rollout"`
	Compatibility string   `json:"compatibility"`
}

type journalCredential struct {
	Algorithm string `json:"algorithm"`
	HandleID  string `json:"handle_id"`
	Selector  string `json:"selector"`
}

type journalDNSWire struct {
	ResolverClass        string   `json:"resolver_class"`
	ResolverEndpoints    []string `json:"resolver_endpoints"`
	ExportTTLSeconds     uint64   `json:"export_ttl_seconds"`
	ProofLifetimeSeconds uint64   `json:"proof_lifetime_seconds"`
}

type journalActivationWire struct {
	ExpectedCurrent        uint64 `json:"expected_current"`
	CandidateGeneration    uint64 `json:"candidate_generation"`
	CandidateDigest        string `json:"candidate_digest"`
	OperationID            string `json:"operation_id"`
	AdministrationRevision uint64 `json:"administration_revision"`
	ProofCompletedUnix     int64  `json:"proof_completed_unix"`
	ProofLifetimeSeconds   uint64 `json:"proof_lifetime_seconds"`
	EmptyBootstrap         bool   `json:"empty_bootstrap"`
	OldCurrentWasActive    bool   `json:"old_current_was_active"`
}

// ActivationLineage owns the exact persisted write-ahead fence for pointer mutation.
type ActivationLineage struct {
	expectedCurrent        uint64
	candidateGeneration    uint64
	candidate              datasourceadmin.CandidateContentDigest
	operation              datasourceadmin.OperationBinding
	administrationRevision uint64
	proofCompletedUnix     int64
	proofLifetimeSeconds   uint64
	emptyBootstrap         bool
	oldCurrentWasActive    bool
}

// MatchesAuthority proves the journal belongs to one exact protected provider descriptor.
func (j *Journal) MatchesAuthority(
	backend datasourceadmin.BackendClass,
	authority datasourceadmin.AuthorityDescriptor,
) bool {
	if j == nil {
		return false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return !j.closed && j.plan != nil && j.plan.backend == backend &&
		authorityEqual(j.plan.authority, authority)
}

// OpenJournalStore acquires one protected transaction owner for a journal path.
func OpenJournalStore(ctx context.Context, path string, limits Limits) (*JournalStore, error) {
	return openJournalStore(ctx, path, limits, func(ctx context.Context, path string, maximum int) (journalProtectedStore, error) {
		return config.OpenProtectedStore(ctx, path, maximum)
	})
}

// OpenStatusJournalStore acquires only an existing journal lock so status cannot create artifacts.
func OpenStatusJournalStore(ctx context.Context, path string, limits Limits) (*JournalStore, error) {
	return openJournalStore(ctx, path, limits, func(ctx context.Context, path string, maximum int) (journalProtectedStore, error) {
		return config.OpenExistingProtectedStore(ctx, path, maximum)
	})
}

// openJournalStore constructs one store through the narrow transaction seam used by recovery tests.
func openJournalStore(
	ctx context.Context,
	path string,
	limits Limits,
	opener journalProtectedStoreOpener,
) (*JournalStore, error) {
	if limits.Validate() != nil || opener == nil {
		return nil, newError(CodeInvalidLimits)
	}
	store, err := opener(ctx, path, int(limits.MaxDocumentBytes))
	if err != nil {
		return nil, mapProtectedStoreError(err)
	}
	return &JournalStore{protected: store, openProtected: opener, path: path, limits: limits}, nil
}

// ReloadOperation closes a poisoned transaction, reacquires authority, and reads the exact union document.
func (s *JournalStore) ReloadOperation(
	ctx context.Context,
) (*PlanningReceipt, *Journal, bool, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, false, newError(CodeProtectedInput)
	}
	s.mu.Lock()
	if s.closed || !s.poisoned || s.protected == nil || s.openProtected == nil || s.path == "" {
		s.mu.Unlock()
		return nil, nil, false, newError(CodeConflict)
	}
	if err := s.protected.Close(); err != nil {
		s.mu.Unlock()
		return nil, nil, false, mapProtectedStoreError(err)
	}
	reopened, err := s.openProtected(ctx, s.path, int(s.limits.MaxDocumentBytes))
	if err != nil {
		s.protected = nil
		s.closed = true
		s.mu.Unlock()
		return nil, nil, false, mapProtectedStoreError(err)
	}
	s.protected = reopened
	s.loaded = false
	s.loadedExists = false
	s.loadedRevision = 0
	s.poisoned = false
	s.mu.Unlock()
	return s.LoadOperation(ctx)
}

// NewJournal constructs one unsaved planned operation from an immutable plan.
func NewJournal(plan *Plan) (*Journal, error) {
	if plan == nil || !plan.Digest().Valid() || plan.validateFacts() != nil {
		return nil, newError(CodeConflict)
	}
	owned := clonePlan(plan)
	if owned == nil {
		return nil, newError(CodeConflict)
	}
	return &Journal{plan: owned, state: StatePlanned, failure: CodeNone}, nil
}

// Load reads and validates one exact journal view under the stable store lock.
func (s *JournalStore) Load(ctx context.Context) (*Journal, bool, error) {
	if s == nil {
		return nil, false, newError(CodeProtectedInput)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned || ctx == nil || ctx.Err() != nil {
		return nil, false, newError(CodeProtectedInput)
	}
	document, exists, err := s.protected.Read(ctx)
	if err != nil {
		return nil, false, mapProtectedStoreError(err)
	}
	defer clear(document)
	s.loaded = true
	s.loadedExists = exists
	s.loadedRevision = 0
	if !exists {
		return nil, false, nil
	}
	journal, err := decodeJournal(document)
	if err != nil {
		return nil, false, err
	}
	s.loadedRevision = journal.revision
	return journal, true, nil
}

// LoadOperation reads one exact tagged planning receipt or promoted journal.
func (s *JournalStore) LoadOperation(
	ctx context.Context,
) (*PlanningReceipt, *Journal, bool, error) {
	if s == nil {
		return nil, nil, false, newError(CodeProtectedInput)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned || ctx == nil || ctx.Err() != nil {
		return nil, nil, false, newError(CodeProtectedInput)
	}
	document, exists, err := s.protected.Read(ctx)
	if err != nil {
		return nil, nil, false, mapProtectedStoreError(err)
	}
	defer clear(document)
	s.loaded = true
	s.loadedExists = exists
	s.loadedRevision = 0
	if !exists {
		return nil, nil, false, nil
	}
	if validateUniqueJSON(document) != nil {
		return nil, nil, false, newError(CodeProtectedInput)
	}
	var header struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(document, &header) != nil {
		return nil, nil, false, newError(CodeProtectedInput)
	}
	if header.Version == planningReceiptVersion {
		receipt, decodeErr := decodePlanningReceipt(document)
		if decodeErr != nil {
			return nil, nil, false, decodeErr
		}
		s.loadedRevision = receipt.revision
		return receipt, nil, true, nil
	}
	if header.Version != journalVersion {
		return nil, nil, false, newError(CodeProtectedInput)
	}
	journal, decodeErr := decodeJournal(document)
	if decodeErr != nil {
		return nil, nil, false, decodeErr
	}
	s.loadedRevision = journal.revision
	return nil, journal, true, nil
}

// SaveReceipt atomically advances one exact loaded planning receipt revision.
func (s *JournalStore) SaveReceipt(ctx context.Context, receipt *PlanningReceipt) error {
	if s == nil || receipt == nil {
		return newError(CodeProtectedInput)
	}
	return s.withLoadedStore(ctx, func() error {
		receipt.mu.Lock()
		defer receipt.mu.Unlock()
		if receipt.closed || receipt.revision != s.loadedRevision ||
			(s.loadedExists != (receipt.revision > 0)) || receipt.revision == math.MaxUint64 {
			return newError(CodeConflict)
		}
		nextRevision := receipt.revision + 1
		document, err := encodePlanningReceiptLocked(receipt, nextRevision)
		if err != nil {
			return err
		}
		defer clear(document)
		return s.replaceLoadedDocument(ctx, document, nextRevision, func() { receipt.revision = nextRevision })
	})
}

// ReplaceClosedReceipt atomically CAS-replaces one retained tombstone with a new claim-pending receipt.
func (s *JournalStore) ReplaceClosedReceipt(
	ctx context.Context,
	closed *PlanningReceipt,
	next *PlanningReceipt,
) error {
	if s == nil || closed == nil || next == nil {
		return newError(CodeProtectedInput)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned || !s.loaded || !s.loadedExists || ctx == nil || ctx.Err() != nil {
		return newError(CodeConflict)
	}
	closed.mu.Lock()
	defer closed.mu.Unlock()
	next.mu.Lock()
	defer next.mu.Unlock()
	if closed.closed || closed.state != planningReceiptClosed || closed.revision == 0 ||
		closed.revision != s.loadedRevision || next.closed || next.state != planningReceiptClaimPending ||
		next.revision != 0 || closed.revision == math.MaxUint64 {
		return newError(CodeConflict)
	}
	nextRevision := closed.revision + 1
	document, err := encodePlanningReceiptLocked(next, nextRevision)
	if err != nil {
		return err
	}
	defer clear(document)
	return s.replaceLoadedDocument(ctx, document, nextRevision, func() { next.revision = nextRevision })
}

// PromoteReceipt atomically replaces one exact loaded receipt with its complete planned journal.
func (s *JournalStore) PromoteReceipt(
	ctx context.Context,
	receipt *PlanningReceipt,
	journal *Journal,
) error {
	if s == nil || receipt == nil || journal == nil {
		return newError(CodeProtectedInput)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned || !s.loaded || !s.loadedExists || ctx == nil || ctx.Err() != nil {
		return newError(CodeConflict)
	}
	receipt.mu.Lock()
	defer receipt.mu.Unlock()
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if receipt.closed || receipt.state != planningReceiptAllocating || receipt.revision == 0 ||
		receipt.revision != s.loadedRevision || journal.closed || journal.revision != 0 ||
		journal.plan == nil || journal.plan.backend != receipt.backend ||
		!authorityEqual(journal.plan.authority, receipt.authority) ||
		!journal.plan.operation.Equal(receipt.operation) ||
		journal.plan.lockRevision != receipt.administrationRevision ||
		!journal.plan.intent.equal(receipt.intent) || !dnsPolicyEqual(journal.plan.dns, receipt.dns) ||
		receipt.revision == math.MaxUint64 {
		return newError(CodeConflict)
	}
	nextRevision := receipt.revision + 1
	document, err := encodeJournalLocked(journal, nextRevision)
	if err != nil {
		return err
	}
	defer clear(document)
	return s.replaceLoadedDocument(ctx, document, nextRevision, func() { journal.revision = nextRevision })
}

// replaceLoadedDocument applies one exact encoded CAS and advances protected owner revisions.
func (s *JournalStore) replaceLoadedDocument(
	ctx context.Context,
	document []byte,
	nextRevision uint64,
	commit func(),
) error {
	if err := s.protected.Replace(ctx, document); err != nil {
		mapped := mapProtectedStoreError(err)
		if CodeOf(mapped) == CodeReconcileRequired {
			s.poisoned = true
		}
		return mapped
	}
	commit()
	s.loadedRevision = nextRevision
	s.loadedExists = true
	return nil
}

// Save atomically advances exactly the loaded monotonic revision.
func (s *JournalStore) Save(ctx context.Context, journal *Journal) error {
	if s == nil || journal == nil {
		return newError(CodeProtectedInput)
	}
	return s.withLoadedStore(ctx, func() error {
		journal.mu.Lock()
		defer journal.mu.Unlock()
		if journal.closed || journal.revision != s.loadedRevision ||
			(s.loadedExists != (journal.revision > 0)) || journal.revision == math.MaxUint64 {
			return newError(CodeConflict)
		}
		nextRevision := journal.revision + 1
		document, err := encodeJournalLocked(journal, nextRevision)
		if err != nil {
			return err
		}
		defer clear(document)
		return s.replaceLoadedDocument(ctx, document, nextRevision, func() { journal.revision = nextRevision })
	})
}

// withLoadedStore serializes one exact loaded-document mutation.
func (s *JournalStore) withLoadedStore(ctx context.Context, mutation func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned || !s.loaded || ctx == nil || ctx.Err() != nil {
		return newError(CodeConflict)
	}
	return mutation()
}

// BeginPreparing records key-generation write-ahead state in memory.
func (j *Journal) BeginPreparing() error {
	return j.transition(StatePlanned, StatePreparing, nil, nil, CodeNone)
}

// KeyGenerationInput derives one single-use preparation input only from a persisted preparing plan.
func (j *Journal) KeyGenerationInput() (*KeyGenerationInput, error) {
	if j == nil {
		return nil, newError(CodeConflict)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.revision == 0 || j.state != StatePreparing || j.plan == nil ||
		j.plan.validateFacts() != nil || !j.plan.digest.Valid() {
		return nil, newError(CodeConflict)
	}
	return &KeyGenerationInput{
		intent: j.plan.intent.clone(), profileID: j.plan.profileID,
		generation:  j.plan.candidateGeneration,
		credentials: append([]AllocatedIdentity(nil), j.plan.credentials...),
	}, nil
}

// RecordPrepared records exact prepared candidate evidence before backend staging.
func (j *Journal) RecordPrepared(evidence datasourceadmin.PreparedEvidence) error {
	if !evidence.Digest().Valid() {
		return newError(CodeConflict)
	}
	return j.transition(StatePreparing, StatePrepared, &evidence, nil, CodeNone)
}

// RecordStaged records exact independently derived backend readback evidence.
func (j *Journal) RecordStaged(evidence datasourceadmin.StagedEvidence) error {
	if !evidence.Digest().Valid() {
		return newError(CodeConflict)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.state != StatePrepared || !j.prepared.Matches(evidence) {
		return newError(CodeConflict)
	}
	j.staged = evidence
	j.state = StateStaged
	return nil
}

// BeginActivating records the exact activation write-ahead lineage before any pointer mutation.
func (j *Journal) BeginActivating(
	proof *DNSProof,
	lock datasourceadmin.AdministrationLock,
	now time.Time,
	emptyBootstrap bool,
	oldCurrentWasActive bool,
) error {
	if j == nil || proof == nil || now.Location() != time.UTC {
		return newError(CodeConflict)
	}
	j.mu.Lock()
	if j.closed || j.state != StateDNSProven || !j.prepared.Matches(j.staged) {
		j.mu.Unlock()
		return newError(CodeConflict)
	}
	planDigest, staged := j.plan.digest, j.staged
	operation, revision := j.plan.operation, j.plan.lockRevision
	wantLifetime := j.plan.dns.ProofLifetimeSeconds
	j.mu.Unlock()
	proofCompleted, proofLifetime, err := proof.activationEvidence(planDigest, staged, now)
	if err != nil || proofLifetime <= 0 || uint64(proofLifetime/time.Second) != wantLifetime ||
		!lock.ValidFor(operation) || lock.Revision() != revision {
		return newError(CodeConflict)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.state != StateDNSProven || !j.prepared.Matches(staged) ||
		!j.plan.digest.Equal(planDigest) || j.plan.lockRevision != revision {
		return newError(CodeConflict)
	}
	lineage := &ActivationLineage{
		expectedCurrent: j.plan.expectedCurrent, candidateGeneration: j.plan.candidateGeneration,
		candidate: j.staged.Digest(), operation: j.plan.operation,
		administrationRevision: j.plan.lockRevision, proofCompletedUnix: proofCompleted.Unix(),
		proofLifetimeSeconds: j.plan.dns.ProofLifetimeSeconds,
		emptyBootstrap:       emptyBootstrap, oldCurrentWasActive: oldCurrentWasActive,
	}
	if !lineage.validFor(j.plan, j.staged) {
		return newError(CodeConflict)
	}
	j.activation = lineage
	j.state = StateActivating
	return nil
}

// RecordDNSExported advances only exact staged evidence to the export-complete phase.
func (j *Journal) RecordDNSExported() error {
	if j == nil {
		return newError(CodeConflict)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || !j.prepared.Matches(j.staged) ||
		(j.state != StateStaged && j.state != StateDNSExported) {
		return newError(CodeConflict)
	}
	j.state = StateDNSExported
	return nil
}

// RecordDNSProven records completion of a fresh proof command without persisting proof authority.
func (j *Journal) RecordDNSProven() error {
	if j == nil {
		return newError(CodeConflict)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || !j.prepared.Matches(j.staged) ||
		(j.state != StateDNSExported && j.state != StateDNSProven) {
		return newError(CodeConflict)
	}
	j.state = StateDNSProven
	return nil
}

// RecordActivated advances only exact activation write-ahead lineage to terminal success.
func (j *Journal) RecordActivated() error {
	if j == nil {
		return newError(CodeConflict)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.state != StateActivating || !j.activation.validFor(j.plan, j.staged) {
		return newError(CodeConflict)
	}
	j.state = StateActivated
	return nil
}

// RecordConflict records one authoritative disagreement without discarding prior activation lineage.
func (j *Journal) RecordConflict() error {
	if j == nil {
		return newError(CodeConflict)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.state.Terminal() {
		return newError(CodeConflict)
	}
	from := j.state
	if from == StateReconcileRequired {
		from = j.reconcileFrom
	}
	j.state = StateConflict
	j.reconcileFrom = from
	j.failure = CodeConflict
	return nil
}

// RecordAborted records a non-destructive terminal stop only for proven pre-commit state.
func (j *Journal) RecordAborted(
	candidate CandidateObservationClass,
	staging datasourceadmin.StagedEvidence,
) error {
	if j == nil {
		return newError(CodeConflict)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.state.Terminal() || j.state == StateActivating || j.state == StateReconcileRequired {
		return newError(CodeConflict)
	}
	from := j.state
	absent := candidate == CandidateAbsent &&
		(from == StatePlanned || from == StatePreparing || from == StatePrepared)
	exactStaging := candidate == CandidateExactStaging && from == StatePrepared &&
		j.prepared.Matches(staging)
	if !absent && !exactStaging {
		return newError(CodeConflict)
	}
	if exactStaging {
		j.staged = staging
	}
	j.state = StateAborted
	j.reconcileFrom = from
	j.failure = CodeNone
	return nil
}

// AdministrationLock reconstructs the exact persisted operation claim fence.
func (j *Journal) AdministrationLock() (datasourceadmin.AdministrationLock, error) {
	if j == nil {
		return datasourceadmin.AdministrationLock{}, newError(CodeConflict)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.plan == nil {
		return datasourceadmin.AdministrationLock{}, newError(CodeConflict)
	}
	lock, err := datasourceadmin.NewAdministrationLock(j.plan.operation, j.plan.lockRevision)
	if err != nil {
		return datasourceadmin.AdministrationLock{}, newError(CodeConflict)
	}
	return lock, nil
}

// RecordAdministrationRelease advances only one exact same-operation successful release revision.
func (j *Journal) RecordAdministrationRelease(
	lock datasourceadmin.AdministrationLock,
	nextRevision uint64,
) error {
	if j == nil || nextRevision == 0 {
		return newError(CodeConflict)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.plan == nil || j.state == StateActivating || j.state == StateActivated ||
		!lock.ValidFor(j.plan.operation) || lock.Revision() != j.plan.lockRevision ||
		lock.Revision() == math.MaxUint64 ||
		nextRevision != lock.Revision()+1 {
		return newError(CodeConflict)
	}
	j.plan.lockRevision = nextRevision
	return nil
}

// ReconcileAdministrationRelease repairs only the exact release-success journal-save-loss window.
func (j *Journal) ReconcileAdministrationRelease(
	observation datasourceadmin.AdministrationLockObservation,
) error {
	if j == nil || !observation.Valid() {
		return newError(CodeConflict)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.plan == nil || j.state == StateActivating || j.state == StateActivated ||
		observation.Claimed() || j.plan.lockRevision == math.MaxUint64 ||
		observation.Revision() != j.plan.lockRevision+1 {
		return newError(CodeConflict)
	}
	j.plan.lockRevision = observation.Revision()
	return nil
}

// validFor proves one activation lineage belongs to the exact plan and staged evidence.
func (l *ActivationLineage) validFor(plan *Plan, staged datasourceadmin.StagedEvidence) bool {
	if l == nil || plan == nil || l.expectedCurrent != plan.expectedCurrent ||
		l.candidateGeneration != plan.candidateGeneration || l.candidateGeneration == 0 ||
		!l.operation.Equal(plan.operation) || l.administrationRevision != plan.lockRevision ||
		l.administrationRevision == 0 || l.proofCompletedUnix <= 0 ||
		l.proofLifetimeSeconds == 0 || l.proofLifetimeSeconds != plan.dns.ProofLifetimeSeconds ||
		!l.candidate.Valid() || !l.candidate.Equal(staged.Digest()) {
		return false
	}
	return l.expectedCurrent == 0 && l.emptyBootstrap && !l.oldCurrentWasActive ||
		l.expectedCurrent != 0 && !l.emptyBootstrap && l.oldCurrentWasActive
}

// String returns a constant protected activation-lineage representation.
func (*ActivationLineage) String() string { return redacted }

// GoString returns a constant protected activation-lineage representation.
func (*ActivationLineage) GoString() string { return redacted }

// Format prevents activation evidence from reaching formatting sinks.
func (*ActivationLineage) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic activation-lineage serialization outside the journal codec.
func (*ActivationLineage) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }

// RequireReconciliation records ambiguity without inventing backend success.
func (j *Journal) RequireReconciliation() error {
	if j == nil {
		return newError(CodeConflict)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.state.Terminal() {
		return newError(CodeConflict)
	}
	if j.state != StateReconcileRequired {
		j.reconcileFrom = j.state
	}
	j.state = StateReconcileRequired
	return nil
}

// recordKeyRecoveryFailureLocked records reconciler-proven loss of prepared-but-unstaged key material.
func (j *Journal) recordKeyRecoveryFailureLocked() error {
	from := j.state
	if from == StateReconcileRequired {
		from = j.reconcileFrom
	}
	if j.closed || from != StatePrepared || !j.prepared.Digest().Valid() || j.activation != nil ||
		j.staged.Digest().Valid() {
		return newError(CodeConflict)
	}
	j.state = StateFailed
	j.failure = CodeKeyRecoveryUnavailable
	j.reconcileFrom = from
	return nil
}

// transition applies one exact evidence-aware in-memory transition.
func (j *Journal) transition(
	from OperationState,
	to OperationState,
	prepared *datasourceadmin.PreparedEvidence,
	staged *datasourceadmin.StagedEvidence,
	failure ErrorCode,
) error {
	if j == nil {
		return newError(CodeConflict)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.state != from || !to.Known() {
		return newError(CodeConflict)
	}
	if prepared != nil {
		j.prepared = *prepared
	}
	if staged != nil {
		j.staged = *staged
	}
	j.failure = failure
	j.state = to
	return nil
}

// State returns the closed current operation state.
func (j *Journal) State() OperationState {
	if j == nil {
		return ""
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ""
	}
	return j.state
}

// Revision returns the monotonic persisted revision or zero before first save.
func (j *Journal) Revision() uint64 {
	if j == nil {
		return 0
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return 0
	}
	return j.revision
}

// Evidence returns the exact typed prepared and staged digest phases without exposing bytes.
func (j *Journal) Evidence() (
	datasourceadmin.PreparedEvidence,
	datasourceadmin.StagedEvidence,
	error,
) {
	if j == nil {
		return datasourceadmin.PreparedEvidence{}, datasourceadmin.StagedEvidence{}, newError(CodeConflict)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return datasourceadmin.PreparedEvidence{}, datasourceadmin.StagedEvidence{}, newError(CodeConflict)
	}
	return j.prepared, j.staged, nil
}

// clonePlan returns one separately owned exact operation plan for coordinator work.
func (j *Journal) clonePlan() (*Plan, error) {
	if j == nil {
		return nil, newError(CodeConflict)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.plan == nil {
		return nil, newError(CodeConflict)
	}
	plan := clonePlan(j.plan)
	if plan == nil {
		return nil, newError(CodeConflict)
	}
	return plan, nil
}

// matchesPromotionRecovery accepts only the exact planned journal attempted by one ambiguous CAS.
func (j *Journal) matchesPromotionRecovery(attempted *Journal) bool {
	loadedPlan, loaded := j.promotionRecoveryPlan()
	attemptedPlan, attemptedValid := attempted.promotionRecoveryPlan()
	if !loaded || !attemptedValid {
		_ = loadedPlan.Close()
		_ = attemptedPlan.Close()
		return false
	}
	defer loadedPlan.Close()    //nolint:errcheck // Detached comparison cleanup has no recovery action.
	defer attemptedPlan.Close() //nolint:errcheck // Detached comparison cleanup has no recovery action.
	return loadedPlan.matchesPromotionRecovery(attemptedPlan)
}

// promotionRecoveryPlan returns a detached plan only from pristine planned journal state.
func (j *Journal) promotionRecoveryPlan() (*Plan, bool) {
	if j == nil {
		return nil, false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.state != StatePlanned || j.plan == nil || j.failure != CodeNone ||
		j.reconcileFrom != "" || j.activation != nil || j.prepared.Digest().Valid() || j.staged.Digest().Valid() {
		return nil, false
	}
	plan := clonePlan(j.plan)
	return plan, plan != nil
}

// WithPlan supplies one detached plan to a bounded callback and then clears it.
func (j *Journal) WithPlan(ctx context.Context, use func(*Plan) error) error {
	if j == nil || ctx == nil || use == nil || ctx.Err() != nil {
		return newError(CodeConflict)
	}
	j.mu.Lock()
	if j.closed {
		j.mu.Unlock()
		return newError(CodeConflict)
	}
	plan := clonePlan(j.plan)
	j.mu.Unlock()
	if plan == nil {
		return newError(CodeConflict)
	}
	defer plan.Close() //nolint:errcheck // The detached plan has no recovery action.
	if err := use(plan); err != nil {
		return newError(CodeUnavailable)
	}
	return nil
}

// Close clears every retained identity-bearing journal value.
func (j *Journal) Close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	clearPlan(j.plan)
	j.plan = nil
	j.prepared = datasourceadmin.PreparedEvidence{}
	j.staged = datasourceadmin.StagedEvidence{}
	j.activation = nil
	j.failure = CodeNone
	j.reconcileFrom = ""
	j.revision = 0
	j.state = ""
	j.closed = true
	return nil
}

// Close releases the stable filesystem transaction owner.
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
	s.path = ""
	if err := s.protected.Close(); err != nil {
		return mapProtectedStoreError(err)
	}
	s.protected = nil
	return nil
}

// encodeJournalLocked emits the sole approved internal protected JSON representation.
func encodeJournalLocked(journal *Journal, revision uint64) ([]byte, error) {
	if journal == nil || journal.plan == nil || !journalRecordValid(journal, revision) {
		return nil, newError(CodeConflict)
	}
	wire, err := journalToWire(journal, revision)
	if err != nil {
		return nil, err
	}
	document, err := json.Marshal(wire)
	if err != nil {
		return nil, newError(CodeUnavailable)
	}
	document = append(document, '\n')
	return document, nil
}

// decodeJournal validates duplicate-free closed JSON and reconstructs protected owners.
func decodeJournal(document []byte) (*Journal, error) {
	if len(document) == 0 || validateUniqueJSON(document) != nil {
		return nil, newError(CodeProtectedInput)
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var wire journalWire
	if decoder.Decode(&wire) != nil {
		return nil, newError(CodeProtectedInput)
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, newError(CodeProtectedInput)
	}
	journal, err := journalFromWire(wire)
	if err != nil || !journalRecordValid(journal, journal.revision) {
		if journal != nil {
			_ = journal.Close()
		}
		return nil, newError(CodeProtectedInput)
	}
	return journal, nil
}

// validateUniqueJSON rejects duplicate keys, multiple values, and malformed nesting.
func validateUniqueJSON(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	tokens := 0
	if err := readUniqueJSONValue(decoder, 0, &tokens); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return newError(CodeProtectedInput)
	}
	return nil
}

// readUniqueJSONValue recursively consumes one bounded decoder value and rejects duplicate keys.
func readUniqueJSONValue(decoder *json.Decoder, depth int, tokens *int) error {
	if decoder == nil || tokens == nil || depth > maxJournalJSONDepth || *tokens >= maxJournalJSONTokens {
		return newError(CodeProtectedInput)
	}
	token, err := decoder.Token()
	if err != nil {
		return newError(CodeProtectedInput)
	}
	*tokens++
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			if *tokens >= maxJournalJSONTokens {
				return newError(CodeProtectedInput)
			}
			keyToken, keyErr := decoder.Token()
			*tokens++
			key, ok := keyToken.(string)
			if keyErr != nil || !ok {
				return newError(CodeProtectedInput)
			}
			if _, duplicate := keys[key]; duplicate {
				return newError(CodeProtectedInput)
			}
			keys[key] = struct{}{}
			if err := readUniqueJSONValue(decoder, depth+1, tokens); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := readUniqueJSONValue(decoder, depth+1, tokens); err != nil {
				return err
			}
		}
	default:
		return newError(CodeProtectedInput)
	}
	if *tokens >= maxJournalJSONTokens {
		return newError(CodeProtectedInput)
	}
	closing, err := decoder.Token()
	*tokens++
	if err != nil || closing != matchingDelimiter(delimiter) {
		return newError(CodeProtectedInput)
	}
	return nil
}

// matchingDelimiter returns the exact close token for one JSON container.
func matchingDelimiter(open json.Delim) json.Delim {
	if open == '{' {
		return '}'
	}
	return ']'
}

// journalRecordValid enforces state-specific evidence without trusting persistence.
func journalRecordValid(journal *Journal, revision uint64) bool {
	if journal == nil || journal.plan == nil || revision == 0 || !journal.state.Known() ||
		!journal.plan.digest.Valid() || journal.plan.validateFacts() != nil {
		return false
	}
	preparedValid := journal.prepared.Digest().Valid()
	stagedValid := journal.staged.Digest().Valid()
	switch journal.state {
	case StatePlanned, StatePreparing:
		return journalUnstartedValid(journal, preparedValid, stagedValid)
	case StatePrepared:
		return journalPreparedValid(journal, preparedValid, stagedValid)
	case StateStaged, StateDNSExported, StateDNSProven:
		return journalStagedValid(journal, preparedValid, stagedValid)
	case StateFailed:
		return journalFailedValid(journal, preparedValid, stagedValid)
	case StateConflict:
		return journalConflictValid(journal)
	case StateAborted:
		return journalAbortedValid(journal, preparedValid, stagedValid)
	case StateReconcileRequired:
		return journalReconcileValid(journal, preparedValid, stagedValid)
	case StateActivating, StateActivated:
		return journalActivationValid(journal, preparedValid, stagedValid)
	default:
		return false
	}
}

// journalUnstartedValid validates planned or preparing evidence shape.
func journalUnstartedValid(journal *Journal, preparedValid, stagedValid bool) bool {
	return !preparedValid && !stagedValid && journal.activation == nil &&
		journal.reconcileFrom == "" && journal.failure == CodeNone
}

// journalPreparedValid validates pre-stage candidate evidence shape.
func journalPreparedValid(journal *Journal, preparedValid, stagedValid bool) bool {
	return preparedValid && !stagedValid && journal.activation == nil &&
		journal.reconcileFrom == "" && journal.failure == CodeNone
}

// journalStagedValid validates exact committed readback evidence shape.
func journalStagedValid(journal *Journal, preparedValid, stagedValid bool) bool {
	return preparedValid && stagedValid && journal.prepared.Matches(journal.staged) &&
		journal.activation == nil && journal.reconcileFrom == "" && journal.failure == CodeNone
}

// journalFailedValid validates reconciler-proven prepared-key loss evidence.
func journalFailedValid(journal *Journal, preparedValid, stagedValid bool) bool {
	return journal.failure == CodeKeyRecoveryUnavailable && preparedValid && !stagedValid &&
		journal.activation == nil && journal.reconcileFrom == StatePrepared
}

// journalConflictValid validates retained ambiguity lineage for terminal conflict.
func journalConflictValid(journal *Journal) bool {
	activationValid := journal.activation == nil || journal.activation.validFor(journal.plan, journal.staged)
	return journal.failure == CodeConflict && activationValid && validReconcileOrigin(journal.reconcileFrom)
}

// journalAbortedValid validates only pre-stage terminal abort evidence.
func journalAbortedValid(journal *Journal, preparedValid, stagedValid bool) bool {
	absentPreStage := !stagedValid &&
		(journal.reconcileFrom == StatePlanned && !preparedValid ||
			journal.reconcileFrom == StatePreparing && !preparedValid ||
			journal.reconcileFrom == StatePrepared && preparedValid)
	exactStaging := journal.reconcileFrom == StatePrepared && preparedValid && stagedValid &&
		journal.prepared.Matches(journal.staged)
	return journal.failure == CodeNone && journal.activation == nil && (absentPreStage || exactStaging)
}

// journalReconcileValid validates ambiguity without erasing its exact prior phase.
func journalReconcileValid(journal *Journal, preparedValid, stagedValid bool) bool {
	activationValid := journal.activation == nil || journal.activation.validFor(journal.plan, journal.staged)
	evidenceValid := !stagedValid || preparedValid && journal.prepared.Matches(journal.staged)
	return journal.failure == CodeNone && activationValid && validReconcileOrigin(journal.reconcileFrom) && evidenceValid
}

// journalActivationValid validates write-ahead lineage and exact staged evidence.
func journalActivationValid(journal *Journal, preparedValid, stagedValid bool) bool {
	return preparedValid && stagedValid && journal.prepared.Matches(journal.staged) &&
		journal.activation.validFor(journal.plan, journal.staged) && journal.reconcileFrom == "" &&
		journal.failure == CodeNone
}

// validReconcileOrigin restricts ambiguity to one exact prior nonterminal workflow phase.
func validReconcileOrigin(state OperationState) bool {
	return state == StatePlanned || state == StatePreparing || state == StatePrepared || state == StateStaged ||
		state == StateDNSExported || state == StateDNSProven || state == StateActivating
}

// mapProtectedStoreError maps only bounded filesystem result classes.
func mapProtectedStoreError(err error) error {
	if CodeOf(err) == CodeReconcileRequired {
		return newError(CodeReconcileRequired)
	}
	switch config.CodeOf(err) {
	case config.CodeProtectedBusy, config.CodeProtectedConflict:
		return newError(CodeConflict)
	case config.CodeProtectedAmbiguous:
		return newError(CodeReconcileRequired)
	default:
		return newError(CodeProtectedInput)
	}
}

// String returns a constant protected journal representation.
func (*Journal) String() string { return redacted }

// GoString returns a constant protected journal representation.
func (*Journal) GoString() string { return redacted }

// Format prevents journal identities and digests from reaching formatting sinks.
func (*Journal) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic journal serialization outside the bounded internal codec.
func (*Journal) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }

// String returns a constant protected journal-store representation.
func (*JournalStore) String() string { return redacted }

// GoString returns a constant protected journal-store representation.
func (*JournalStore) GoString() string { return redacted }

// Format prevents journal paths and transaction state from reaching formatting sinks.
func (*JournalStore) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic journal-store serialization.
func (*JournalStore) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }

// encodeDigest converts one protected digest only for the internal journal codec.
func encodeDigest(value []byte) string {
	defer clear(value)
	return hex.EncodeToString(value)
}

// decodeDigest parses one exact lower-case SHA-256 journal field.
func decodeDigest(value string) ([]byte, error) {
	if len(value) != sha256.Size*2 {
		return nil, newError(CodeProtectedInput)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, newError(CodeProtectedInput)
	}
	return decoded, nil
}

// operationValue reveals an operation only to the bounded internal journal codec.
func operationValue(operation datasourceadmin.OperationBinding) (string, error) {
	value := ""
	if err := operation.WithValue(context.Background(), func(operationID string) error {
		value = operationID
		return nil
	}); err != nil {
		return "", newError(CodeConflict)
	}
	return value, nil
}

// journalToWire creates one bounded internal JSON transfer value.
func journalToWire(journal *Journal, revision uint64) (journalWire, error) {
	operationID, err := operationValue(journal.plan.operation)
	if err != nil {
		return journalWire{}, err
	}
	wire := journalWire{
		Version: journalVersion, Revision: revision, State: string(journal.state),
		Backend: string(journal.plan.backend), Authority: authorityToWire(journal.plan.authority),
		ExpectedCurrent: journal.plan.expectedCurrent, CandidateGeneration: journal.plan.candidateGeneration,
		AdministrationRevision: journal.plan.lockRevision,
		Intent:                 intentToWire(journal.plan.intent), ProfileID: journal.plan.profileID,
		Credentials: credentialsToWire(journal.plan.credentials), DNS: dnsToWire(journal.plan.dns),
		OperationID: operationID, PlanDigest: encodeDigest(journal.plan.digest.Bytes()),
	}
	if journal.prepared.Digest().Valid() {
		wire.PreparedDigest = encodeDigest(journal.prepared.Digest().Bytes())
	}
	if journal.staged.Digest().Valid() {
		wire.StagedDigest = encodeDigest(journal.staged.Digest().Bytes())
	}
	if journal.failure != CodeNone {
		wire.FailureClass = string(journal.failure)
	}
	if journal.reconcileFrom != "" {
		wire.ReconcileFrom = string(journal.reconcileFrom)
	}
	if journal.activation != nil {
		activation, activationErr := activationToWire(journal.activation)
		if activationErr != nil {
			return journalWire{}, activationErr
		}
		wire.Activation = &activation
	}
	return wire, nil
}

// journalFromWire reconstructs typed protected values from one closed wire value.
func journalFromWire(wire journalWire) (*Journal, error) {
	if wire.Version != journalVersion || wire.Revision == 0 {
		return nil, newError(CodeProtectedInput)
	}
	intent, err := newIntent(intentDocument{
		Version: wire.Intent.Version, Domain: wire.Intent.Domain, TenantID: wire.Intent.TenantID,
		ProfileUse: wire.Intent.ProfileUse, Algorithms: wire.Intent.Algorithms,
		Rollout: wire.Intent.Rollout, Compatibility: wire.Intent.Compatibility,
	})
	if err != nil {
		return nil, err
	}
	operation, err := datasourceadmin.NewOperationBinding(wire.OperationID)
	if err != nil {
		return nil, newError(CodeProtectedInput)
	}
	planBytes, err := decodeDigest(wire.PlanDigest)
	if err != nil {
		return nil, err
	}
	planDigest, err := datasourceadmin.ParsePlanDigest(planBytes)
	clear(planBytes)
	if err != nil {
		return nil, newError(CodeProtectedInput)
	}
	authority, err := authorityFromWire(wire.Authority)
	if err != nil {
		return nil, err
	}
	plan := &Plan{
		backend: datasourceadmin.BackendClass(wire.Backend), authority: authority,
		expectedCurrent: wire.ExpectedCurrent, intent: intent, profileID: wire.ProfileID,
		credentials: credentialsFromWire(wire.Credentials), candidateGeneration: wire.CandidateGeneration,
		dns: dnsFromWire(wire.DNS), operation: operation, digest: planDigest, lockRevision: wire.AdministrationRevision,
	}
	accepted := false
	defer func() {
		if !accepted {
			clearPlan(plan)
		}
	}()
	failure := ErrorCode(wire.FailureClass)
	if failure == "" {
		failure = CodeNone
	}
	journal := &Journal{
		revision: wire.Revision, plan: plan, state: OperationState(wire.State),
		failure: failure, reconcileFrom: OperationState(wire.ReconcileFrom),
	}
	if wire.PreparedDigest != "" {
		value, decodeErr := decodeDigest(wire.PreparedDigest)
		if decodeErr != nil {
			return nil, decodeErr
		}
		journal.prepared, err = datasourceadmin.ParsePreparedEvidence(value)
		clear(value)
		if err != nil {
			return nil, newError(CodeProtectedInput)
		}
	}
	if wire.StagedDigest != "" {
		value, decodeErr := decodeDigest(wire.StagedDigest)
		if decodeErr != nil {
			return nil, decodeErr
		}
		journal.staged, err = datasourceadmin.ParseStagedEvidence(value)
		clear(value)
		if err != nil {
			return nil, newError(CodeProtectedInput)
		}
	}
	if wire.Activation != nil {
		journal.activation, err = activationFromWire(*wire.Activation)
		if err != nil {
			return nil, err
		}
	}
	accepted = true
	return journal, nil
}

// validateFacts reuses the exact datasource plan validator with an empty current projection.
func (p *Plan) validateFacts() error {
	if p == nil {
		return newError(CodeConflict)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.lockRevision == 0 || p.candidateGeneration == 0 ||
		p.candidateGeneration <= p.expectedCurrent || !p.operation.Initialized() || !p.digest.Valid() {
		return newError(CodeConflict)
	}
	copyValue := clonePlanLocked(p)
	defer clearPlan(copyValue)
	copyValue.expectedCurrent = 0
	if _, err := copyValue.computeDigest(context.Background(), nil, copyValue.authority); err != nil {
		return newError(CodeConflict)
	}
	return nil
}

// clonePlan detaches every slice-backed protected plan field.
func clonePlan(plan *Plan) *Plan {
	if plan == nil {
		return nil
	}
	plan.mu.Lock()
	defer plan.mu.Unlock()
	if plan.closed {
		return nil
	}
	return clonePlanLocked(plan)
}

// clonePlanLocked detaches one plan while its owner lock is held.
func clonePlanLocked(plan *Plan) *Plan {
	return &Plan{
		backend: plan.backend, authority: cloneAuthority(plan.authority), expectedCurrent: plan.expectedCurrent,
		intent: plan.intent.clone(), profileID: plan.profileID,
		credentials: append([]AllocatedIdentity(nil), plan.credentials...), candidateGeneration: plan.candidateGeneration,
		dns: cloneDNSPolicy(plan.dns), operation: plan.operation, digest: plan.digest, lockRevision: plan.lockRevision,
	}
}

// clearPlan releases every retained protected plan reference.
func clearPlan(plan *Plan) {
	if plan == nil {
		return
	}
	plan.mu.Lock()
	defer plan.mu.Unlock()
	clearPlanLocked(plan)
}

// clearPlanLocked releases plan fields while its owner lock is held.
func clearPlanLocked(plan *Plan) {
	clearAuthority(&plan.authority)
	plan.intent = Intent{}
	plan.profileID = ""
	clearAllocatedIdentities(plan.credentials)
	plan.credentials = nil
	plan.dns = datasourceadmin.DNSPolicy{}
	plan.operation = datasourceadmin.OperationBinding{}
	plan.digest = datasourceadmin.PlanDigest{}
	plan.backend = ""
	plan.expectedCurrent = 0
	plan.candidateGeneration = 0
	plan.lockRevision = 0
}

// activationToWire projects mandatory activation write-ahead evidence.
func activationToWire(value *ActivationLineage) (journalActivationWire, error) {
	if value == nil {
		return journalActivationWire{}, newError(CodeConflict)
	}
	operationID, err := operationValue(value.operation)
	if err != nil {
		return journalActivationWire{}, err
	}
	return journalActivationWire{
		ExpectedCurrent: value.expectedCurrent, CandidateGeneration: value.candidateGeneration,
		CandidateDigest: encodeDigest(value.candidate.Bytes()), OperationID: operationID,
		AdministrationRevision: value.administrationRevision, ProofCompletedUnix: value.proofCompletedUnix,
		ProofLifetimeSeconds: value.proofLifetimeSeconds, EmptyBootstrap: value.emptyBootstrap,
		OldCurrentWasActive: value.oldCurrentWasActive,
	}, nil
}

// activationFromWire reconstructs typed activation write-ahead evidence.
func activationFromWire(value journalActivationWire) (*ActivationLineage, error) {
	operation, err := datasourceadmin.NewOperationBinding(value.OperationID)
	if err != nil {
		return nil, newError(CodeProtectedInput)
	}
	digestBytes, err := decodeDigest(value.CandidateDigest)
	if err != nil {
		return nil, err
	}
	digest, err := datasourceadmin.ParseCandidateContentDigest(digestBytes)
	clear(digestBytes)
	if err != nil {
		return nil, newError(CodeProtectedInput)
	}
	return &ActivationLineage{
		expectedCurrent: value.ExpectedCurrent, candidateGeneration: value.CandidateGeneration,
		candidate: digest, operation: operation, administrationRevision: value.AdministrationRevision,
		proofCompletedUnix: value.ProofCompletedUnix, proofLifetimeSeconds: value.ProofLifetimeSeconds,
		emptyBootstrap: value.EmptyBootstrap, oldCurrentWasActive: value.OldCurrentWasActive,
	}, nil
}

// intentToWire projects one canonical intent into the sole journal codec.
func intentToWire(intent Intent) journalIntentWire {
	document := intent.document()
	return journalIntentWire(document)
}

// credentialsToWire projects protected allocations into the sole journal codec.
func credentialsToWire(values []AllocatedIdentity) []journalCredential {
	result := make([]journalCredential, len(values))
	for index, value := range values {
		result[index] = journalCredential{Algorithm: string(value.algorithm), HandleID: value.handleID, Selector: value.selector}
	}
	return result
}

// credentialsFromWire reconstructs protected allocated identities.
func credentialsFromWire(values []journalCredential) []AllocatedIdentity {
	result := make([]AllocatedIdentity, len(values))
	for index, value := range values {
		result[index] = AllocatedIdentity{algorithm: provider.Algorithm(value.Algorithm), handleID: value.HandleID, selector: value.Selector}
	}
	return result
}

// dnsToWire projects the closed DNS proof policy.
func dnsToWire(value datasourceadmin.DNSPolicy) journalDNSWire {
	return journalDNSWire{
		ResolverClass: value.ResolverClass, ResolverEndpoints: append([]string(nil), value.ResolverEndpoints...),
		ExportTTLSeconds: value.ExportTTLSeconds, ProofLifetimeSeconds: value.ProofLifetimeSeconds,
	}
}

// dnsFromWire reconstructs the closed DNS proof policy.
func dnsFromWire(value journalDNSWire) datasourceadmin.DNSPolicy {
	return datasourceadmin.DNSPolicy{
		ResolverClass: value.ResolverClass, ResolverEndpoints: append([]string(nil), value.ResolverEndpoints...),
		ExportTTLSeconds: value.ExportTTLSeconds, ProofLifetimeSeconds: value.ProofLifetimeSeconds,
	}
}

// authorityToWire projects the protected authority descriptor.
func authorityToWire(value datasourceadmin.AuthorityDescriptor) journalAuthorityWire {
	result := journalAuthorityWire{AuthorityID: value.AuthorityID, TrustFingerprints: make([]string, len(value.TrustFingerprints))}
	for _, endpoint := range value.Endpoints {
		result.Endpoints = append(result.Endpoints, journalEndpointWire{
			Scheme: endpoint.Scheme, Host: endpoint.Host, Port: endpoint.Port, TLSServerName: endpoint.TLSServerName,
		})
	}
	if value.LDAP != nil {
		converted := journalLDAPWire{
			BaseDN: value.LDAP.BaseDN, SnapshotPrincipal: value.LDAP.SnapshotPrincipal,
			StagingPrincipal: value.LDAP.StagingPrincipal, ActivationPrincipal: value.LDAP.ActivationPrincipal,
		}
		result.LDAP = &converted
	}
	if value.SQL != nil {
		converted := journalSQLWire{
			Database: value.SQL.Database, Schema: value.SQL.Schema, SnapshotRole: value.SQL.SnapshotRole,
			StagingRole: value.SQL.StagingRole, ActivationRole: value.SQL.ActivationRole,
		}
		result.SQL = &converted
	}
	for index, fingerprint := range value.TrustFingerprints {
		result.TrustFingerprints[index] = hex.EncodeToString(fingerprint[:])
	}
	if value.ClientCertificateFingerprint != nil {
		result.ClientFingerprint = hex.EncodeToString(value.ClientCertificateFingerprint[:])
	}
	return result
}

// authorityFromWire reconstructs the protected authority descriptor.
func authorityFromWire(value journalAuthorityWire) (datasourceadmin.AuthorityDescriptor, error) {
	result := datasourceadmin.AuthorityDescriptor{AuthorityID: value.AuthorityID}
	for _, endpoint := range value.Endpoints {
		result.Endpoints = append(result.Endpoints, datasourceadmin.AuthorityEndpoint{
			Scheme: endpoint.Scheme, Host: endpoint.Host, Port: endpoint.Port, TLSServerName: endpoint.TLSServerName,
		})
	}
	if value.LDAP != nil {
		converted := datasourceadmin.LDAPAuthority{
			BaseDN: value.LDAP.BaseDN, SnapshotPrincipal: value.LDAP.SnapshotPrincipal,
			StagingPrincipal: value.LDAP.StagingPrincipal, ActivationPrincipal: value.LDAP.ActivationPrincipal,
		}
		result.LDAP = &converted
	}
	if value.SQL != nil {
		converted := datasourceadmin.SQLAuthority{
			Database: value.SQL.Database, Schema: value.SQL.Schema, SnapshotRole: value.SQL.SnapshotRole,
			StagingRole: value.SQL.StagingRole, ActivationRole: value.SQL.ActivationRole,
		}
		result.SQL = &converted
	}
	for _, encoded := range value.TrustFingerprints {
		decoded, err := decodeDigest(encoded)
		if err != nil {
			return datasourceadmin.AuthorityDescriptor{}, err
		}
		var fingerprint [sha256.Size]byte
		copy(fingerprint[:], decoded)
		clear(decoded)
		result.TrustFingerprints = append(result.TrustFingerprints, fingerprint)
	}
	if value.ClientFingerprint != "" {
		decoded, err := decodeDigest(value.ClientFingerprint)
		if err != nil {
			return datasourceadmin.AuthorityDescriptor{}, err
		}
		var fingerprint [sha256.Size]byte
		copy(fingerprint[:], decoded)
		clear(decoded)
		result.ClientCertificateFingerprint = &fingerprint
	}
	return result, nil
}
