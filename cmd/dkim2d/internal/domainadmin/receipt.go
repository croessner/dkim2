package domainadmin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

const planningReceiptVersion = "dkim2-domain-planning-receipt-v1"

const planningReceiptChecksumDomain = "DKIM2-DOMAIN-PLANNING-RECEIPT-CHECKSUM-V1\x00"

type planningReceiptState string

const (
	planningReceiptClaimPending    planningReceiptState = "claim_pending"
	planningReceiptAllocating      planningReceiptState = "allocating"
	planningReceiptReleaseRequired planningReceiptState = "release_required"
	planningReceiptUnresolved      planningReceiptState = "unresolved"
	planningReceiptClosed          planningReceiptState = "closed"
)

// PlanningReceipt durably explains one operation before any global administration claim.
type PlanningReceipt struct {
	mu                     sync.Mutex
	revision               uint64
	backend                datasourceadmin.BackendClass
	authority              datasourceadmin.AuthorityDescriptor
	operation              datasourceadmin.OperationBinding
	administrationRevision uint64
	intent                 Intent
	dns                    datasourceadmin.DNSPolicy
	state                  planningReceiptState
	closed                 bool
}

type planningReceiptWire struct {
	Version                string               `json:"version"`
	Revision               uint64               `json:"revision"`
	State                  string               `json:"state"`
	Backend                string               `json:"backend"`
	Authority              journalAuthorityWire `json:"authority"`
	OperationID            string               `json:"operation_id"`
	AdministrationRevision uint64               `json:"administration_revision"`
	Intent                 journalIntentWire    `json:"intent"`
	DNS                    journalDNSWire       `json:"dns"`
	Digest                 string               `json:"digest"`
}

// MatchesAuthority proves the receipt belongs to the current backend authority.
func (r *PlanningReceipt) MatchesAuthority(
	backend datasourceadmin.BackendClass,
	authority datasourceadmin.AuthorityDescriptor,
) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.closed && r.backend == backend && authorityEqual(r.authority, authority)
}

// NewPlanningReceipt constructs one unsaved exact pre-claim operation record.
func NewPlanningReceipt(
	backend datasourceadmin.BackendClass,
	authority datasourceadmin.AuthorityDescriptor,
	operation datasourceadmin.OperationBinding,
	administrationRevision uint64,
	intent Intent,
	dns datasourceadmin.DNSPolicy,
) (*PlanningReceipt, error) {
	receipt := &PlanningReceipt{
		backend: backend, authority: cloneAuthority(authority), operation: operation,
		administrationRevision: administrationRevision, intent: intent.clone(), dns: cloneDNSPolicy(dns),
		state: planningReceiptClaimPending,
	}
	if !receipt.validLocked() {
		_ = receipt.Close()
		return nil, newError(CodeConflict)
	}
	return receipt, nil
}

// Revision returns the monotonic protected-document revision.
func (r *PlanningReceipt) Revision() uint64 {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0
	}
	return r.revision
}

// Closed reports whether the pre-plan receipt is a retained terminal tombstone.
func (r *PlanningReceipt) Closed() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.closed && r.state == planningReceiptClosed
}

// MatchesCoordinator proves the receipt belongs to the current authority and operator request.
func (r *PlanningReceipt) MatchesCoordinator(
	backend datasourceadmin.BackendClass,
	authority datasourceadmin.AuthorityDescriptor,
	intent Intent,
	dns datasourceadmin.DNSPolicy,
) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.closed && r.backend == backend && authorityEqual(r.authority, authority) &&
		r.intent.equal(intent) && dnsPolicyEqual(r.dns, dns)
}

// sameRecoveryPhase compares exact protected recovery identity without relying on document revision.
func (r *PlanningReceipt) sameRecoveryPhase(other *PlanningReceipt) bool {
	if r == nil || other == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	other.mu.Lock()
	defer other.mu.Unlock()
	return !r.closed && !other.closed && r.backend == other.backend &&
		authorityEqual(r.authority, other.authority) && r.operation.Equal(other.operation) &&
		r.administrationRevision == other.administrationRevision && r.intent.equal(other.intent) &&
		dnsPolicyEqual(r.dns, other.dns) && r.state == other.state
}

// AllocationInput returns detached exact persisted claim and allocation facts.
func (r *PlanningReceipt) AllocationInput() (
	datasourceadmin.OperationBinding,
	uint64,
	Intent,
	datasourceadmin.DNSPolicy,
	error,
) {
	if r == nil {
		return datasourceadmin.OperationBinding{}, 0, Intent{}, datasourceadmin.DNSPolicy{}, newError(CodeConflict)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || (r.state != planningReceiptClaimPending && r.state != planningReceiptAllocating) ||
		!r.validLocked() || r.revision == 0 {
		return datasourceadmin.OperationBinding{}, 0, Intent{}, datasourceadmin.DNSPolicy{}, newError(CodeConflict)
	}
	return r.operation, r.administrationRevision, r.intent.clone(), cloneDNSPolicy(r.dns), nil
}

// reconciliationInput returns exact persisted operation and revision in every receipt state.
func (r *PlanningReceipt) reconciliationInput() (
	datasourceadmin.OperationBinding,
	uint64,
	planningReceiptState,
	error,
) {
	if r == nil {
		return datasourceadmin.OperationBinding{}, 0, "", newError(CodeConflict)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !r.validLocked() || r.revision == 0 {
		return datasourceadmin.OperationBinding{}, 0, "", newError(CodeConflict)
	}
	return r.operation, r.administrationRevision, r.state, nil
}

// ResultState returns only receipt failure without synthesizing a public operation state.
func (r *PlanningReceipt) ResultState() (OperationState, ErrorCode) {
	if r == nil {
		return "", CodeConflict
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return "", CodeConflict
	}
	if r.state == planningReceiptReleaseRequired || r.state == planningReceiptUnresolved {
		return "", CodeReconcileRequired
	}
	return "", CodeNone
}

// Phase returns the bounded internal recovery phase.
func (r *PlanningReceipt) Phase() ReceiptPhase {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ""
	}
	return ReceiptPhase(r.state)
}

// RecordAllocating acknowledges an exact claim before claimed allocation.
func (r *PlanningReceipt) RecordAllocating() error {
	if r == nil {
		return newError(CodeConflict)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || (r.state != planningReceiptClaimPending && r.state != planningReceiptAllocating) {
		return newError(CodeConflict)
	}
	r.state = planningReceiptAllocating
	return nil
}

// RecordReleaseRequired gates all claim cleanup on explicit reconciliation.
func (r *PlanningReceipt) RecordReleaseRequired() error {
	if r == nil {
		return newError(CodeConflict)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || (r.state != planningReceiptClaimPending && r.state != planningReceiptAllocating &&
		r.state != planningReceiptReleaseRequired && r.state != planningReceiptUnresolved) {
		return newError(CodeConflict)
	}
	r.state = planningReceiptReleaseRequired
	return nil
}

// RecordUnresolved retains foreign, skipped-revision, malformed, or unavailable evidence.
func (r *PlanningReceipt) RecordUnresolved() error {
	if r == nil {
		return newError(CodeConflict)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.state == planningReceiptClosed || r.state == planningReceiptReleaseRequired {
		return newError(CodeConflict)
	}
	r.state = planningReceiptUnresolved
	return nil
}

// RecordAdministrationRelease advances only exact ownerless R+1 receipt evidence.
func (r *PlanningReceipt) RecordAdministrationRelease(next uint64) error {
	if r == nil {
		return newError(CodeConflict)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.state != planningReceiptReleaseRequired || r.administrationRevision == ^uint64(0) ||
		next != r.administrationRevision+1 {
		return newError(CodeConflict)
	}
	r.administrationRevision = next
	return nil
}

// RecordClosed retains exact ownerless cleanup without deleting receipt authority.
func (r *PlanningReceipt) RecordClosed() error {
	if r == nil {
		return newError(CodeConflict)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return newError(CodeConflict)
	}
	if r.state == planningReceiptClosed {
		return nil
	}
	if r.state != planningReceiptClaimPending && r.state != planningReceiptReleaseRequired {
		return newError(CodeConflict)
	}
	r.state = planningReceiptClosed
	return nil
}

// recordClosedOwnerlessRecovery closes only unresolved evidence after authoritative ownerless exact-R proof.
func (r *PlanningReceipt) recordClosedOwnerlessRecovery() error {
	if r == nil {
		return newError(CodeConflict)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.state != planningReceiptUnresolved {
		return newError(CodeConflict)
	}
	r.state = planningReceiptClosed
	return nil
}

// Close releases every retained protected receipt field.
func (r *PlanningReceipt) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	clearAuthority(&r.authority)
	r.intent = Intent{}
	r.dns = datasourceadmin.DNSPolicy{}
	r.operation = datasourceadmin.OperationBinding{}
	r.backend = ""
	r.administrationRevision = 0
	r.revision = 0
	r.state = ""
	r.closed = true
	return nil
}

// validLocked validates receipt facts while the receipt owner lock is held.
func (r *PlanningReceipt) validLocked() bool {
	return r != nil && !r.closed && r.operation.Initialized() && r.administrationRevision != 0 &&
		r.intent.valid() && (r.state == planningReceiptClaimPending || r.state == planningReceiptAllocating ||
		r.state == planningReceiptReleaseRequired || r.state == planningReceiptUnresolved ||
		r.state == planningReceiptClosed) &&
		datasourceadmin.ValidateAuthority(r.backend, r.authority) == nil &&
		datasourceadmin.ValidateDNSPolicy(r.dns) == nil
}

// dnsPolicyEqual compares exact canonical resolver and proof policy.
func dnsPolicyEqual(left, right datasourceadmin.DNSPolicy) bool {
	if left.ResolverClass != right.ResolverClass || left.ExportTTLSeconds != right.ExportTTLSeconds ||
		left.ProofLifetimeSeconds != right.ProofLifetimeSeconds || len(left.ResolverEndpoints) != len(right.ResolverEndpoints) {
		return false
	}
	for index := range left.ResolverEndpoints {
		if left.ResolverEndpoints[index] != right.ResolverEndpoints[index] {
			return false
		}
	}
	return true
}

// encodePlanningReceiptLocked serializes one exact receipt with an internal canonical digest.
func encodePlanningReceiptLocked(receipt *PlanningReceipt, revision uint64) ([]byte, error) {
	if receipt == nil || revision == 0 || !receipt.validLocked() {
		return nil, newError(CodeConflict)
	}
	operationID, err := operationValue(receipt.operation)
	if err != nil {
		return nil, err
	}
	wire := planningReceiptWire{
		Version: planningReceiptVersion, Revision: revision, State: string(receipt.state),
		Backend: string(receipt.backend), Authority: authorityToWire(receipt.authority),
		OperationID: operationID, AdministrationRevision: receipt.administrationRevision,
		Intent: intentToWire(receipt.intent), DNS: dnsToWire(receipt.dns),
	}
	digest, err := planningReceiptDigest(wire)
	if err != nil {
		return nil, err
	}
	wire.Digest = hex.EncodeToString(digest[:])
	document, err := json.Marshal(wire)
	if err != nil {
		return nil, newError(CodeUnavailable)
	}
	return append(document, '\n'), nil
}

// decodePlanningReceipt validates one strict protected receipt document.
func decodePlanningReceipt(document []byte) (*PlanningReceipt, error) {
	if len(document) == 0 || validateUniqueJSON(document) != nil {
		return nil, newError(CodeProtectedInput)
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var wire planningReceiptWire
	if decoder.Decode(&wire) != nil {
		return nil, newError(CodeProtectedInput)
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || wire.Version != planningReceiptVersion || wire.Revision == 0 {
		return nil, newError(CodeProtectedInput)
	}
	digestBytes, err := decodeDigest(wire.Digest)
	if err != nil {
		return nil, err
	}
	var stored [sha256.Size]byte
	copy(stored[:], digestBytes)
	clear(digestBytes)
	wire.Digest = ""
	want, err := planningReceiptDigest(wire)
	if err != nil || stored != want {
		return nil, newError(CodeProtectedInput)
	}
	intent, err := newIntent(intentDocument{
		Version: wire.Intent.Version, Domain: wire.Intent.Domain, TenantID: wire.Intent.TenantID,
		ProfileUse: wire.Intent.ProfileUse, Algorithms: wire.Intent.Algorithms,
		Rollout: wire.Intent.Rollout, Compatibility: wire.Intent.Compatibility,
	})
	if err != nil {
		return nil, newError(CodeProtectedInput)
	}
	operation, err := datasourceadmin.NewOperationBinding(wire.OperationID)
	if err != nil {
		return nil, newError(CodeProtectedInput)
	}
	authority, err := authorityFromWire(wire.Authority)
	if err != nil {
		return nil, err
	}
	receipt := &PlanningReceipt{
		revision: wire.Revision, backend: datasourceadmin.BackendClass(wire.Backend), authority: authority,
		operation: operation, administrationRevision: wire.AdministrationRevision,
		intent: intent, dns: dnsFromWire(wire.DNS), state: planningReceiptState(wire.State),
	}
	if !receipt.validLocked() {
		_ = receipt.Close()
		return nil, newError(CodeProtectedInput)
	}
	return receipt, nil
}

// planningReceiptDigest hashes the exact digest-free canonical wire document.
func planningReceiptDigest(wire planningReceiptWire) ([sha256.Size]byte, error) {
	wire.Digest = ""
	encoded, err := json.Marshal(wire)
	if err != nil {
		return [sha256.Size]byte{}, newError(CodeUnavailable)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(planningReceiptChecksumDomain))
	_, _ = hash.Write([]byte{byte(len(encoded) >> 24), byte(len(encoded) >> 16), byte(len(encoded) >> 8), byte(len(encoded))})
	_, _ = hash.Write(encoded)
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	clear(encoded)
	return digest, nil
}

// String returns a constant protected receipt representation.
func (*PlanningReceipt) String() string { return redacted }

// GoString returns a constant protected receipt representation.
func (*PlanningReceipt) GoString() string { return redacted }

// Format prevents receipt authority and operation facts from reaching formatting sinks.
func (*PlanningReceipt) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic planning-receipt serialization.
func (*PlanningReceipt) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }
