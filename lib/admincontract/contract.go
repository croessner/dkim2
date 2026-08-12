// Package admincontract owns the versioned provider-neutral datasource
// administration commitment grammar shared with external lifecycle writers.
//
// The package contains no provider, command, transport, or service dependency.
// Concrete LDAP and SQL mutations remain owned by dkim2d internal packages.
package admincontract

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// ContractVersion is the exact cross-repository compatibility version.
	ContractVersion = "dkim2-admin-contract-v1"
	maxWorkItems    = 131072
	maxTextBytes    = 4096
)

const (
	frozenDomain           = "DKIM2-FROZEN-WORK-V1\x00"
	planDomain             = "DKIM2-ROTATION-CAMPAIGN-PLAN-V1\x00"
	batchDomain            = "DKIM2-ROTATION-DNS-BATCH-V1\x00"
	purgeDomain            = "DKIM2-PURGE-PLAN-V1\x00"
	auditDomain            = "DKIM2-PURGE-AUDIT-V1\x00"
	schemaV2               = "dkim2-datasource-v2"
	schemaV3               = "dkim2-datasource-v3"
	useOriginator          = "originator"
	algorithmEd25519       = "ed25519-sha256"
	algorithmRSA           = "rsa-sha256"
	lifecycleActiveHistory = "active_history"
	lifecycleNeverActive   = "never_active"
	lifecycleAborted       = "aborted"
	lifecycleAbsent        = "absent"
	operationNormal        = "normal"
	receiptPurged          = "purged"
)

// Mode identifies a closed rotation operation class.
type Mode string

// State values describe the closed externally visible campaign progression.
const (
	// ModeNormal rotates the complete frozen active binding inventory once.
	ModeNormal Mode = "normal"
	// ModeEmergency rotates one exact binding for an explicit emergency reason.
	ModeEmergency Mode = "emergency"
)

// State identifies one closed public campaign state.
type State string

// State values describe the closed externally visible campaign progression.
const (
	StatePlanned           State = "planned"
	StatePreparing         State = "preparing"
	StatePrepared          State = "prepared"
	StateStaged            State = "staged"
	StateDNSInProgress     State = "dns_in_progress"
	StateDNSComplete       State = "dns_complete"
	StateActivating        State = "activating"
	StateActivated         State = "activated"
	StateConflict          State = "conflict"
	StateFailed            State = "failed"
	StateAborted           State = "aborted"
	StateReconcileRequired State = "reconcile_required"
)

// Command identifies one closed campaign control action.
type Command string

// Command values identify the closed campaign control vocabulary.
const (
	CommandPlan       Command = "plan"
	CommandPrepare    Command = "prepare"
	CommandStage      Command = "stage"
	CommandDNSExport  Command = "dns_export"
	CommandDNSProve   Command = "dns_prove"
	CommandActivate   Command = "activate"
	CommandStatus     Command = "status"
	CommandReconcile  Command = "reconcile"
	CommandAbort      Command = "abort"
	CommandPurgePlan  Command = "purge_plan"
	CommandPurgeApply Command = "purge_apply"
)

// Digest contains one exact nonzero SHA-256 commitment.
type Digest struct{ value [sha256.Size]byte }

// ParseDigest validates and detaches one exact SHA-256 commitment.
func ParseDigest(value []byte) (Digest, error) {
	if len(value) != sha256.Size {
		return Digest{}, errors.New("admin_contract_invalid")
	}
	var digest Digest
	copy(digest.value[:], value)
	if !digest.Valid() {
		return Digest{}, errors.New("admin_contract_invalid")
	}
	return digest, nil
}

// ParseDigestHex validates one canonical lowercase hexadecimal commitment.
func ParseDigestHex(value string) (Digest, error) {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return Digest{}, errors.New("admin_contract_invalid")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return Digest{}, errors.New("admin_contract_invalid")
	}
	defer clear(decoded)
	return ParseDigest(decoded)
}

// Valid reports whether the digest is initialized.
func (d Digest) Valid() bool {
	var combined byte
	for _, octet := range d.value {
		combined |= octet
	}
	return combined != 0
}

// Equal compares two initialized commitments without early exit.
func (d Digest) Equal(other Digest) bool {
	return d.Valid() && other.Valid() && subtle.ConstantTimeCompare(d.value[:], other.value[:]) == 1
}

// Bytes returns a detached binary commitment for protected persistence.
func (d Digest) Bytes() []byte { return append([]byte(nil), d.value[:]...) }

// Hex returns canonical hexadecimal for public synthetic conformance fixtures.
func (d Digest) Hex() string {
	if !d.Valid() {
		return ""
	}
	return hex.EncodeToString(d.value[:])
}

// WorkItem is one canonical active tenant, domain, use, and profile binding.
type WorkItem struct {
	Tenant     string
	Domain     string
	Use        string
	Profile    string
	Algorithms []string
}

// CampaignPlan is the exact key-free normal or emergency plan projection.
type CampaignPlan struct {
	Version                string
	Mode                   Mode
	SourceSchema           string
	SourceGeneration       uint64
	CandidateGeneration    uint64
	OperationID            string
	Work                   []WorkItem
	EmergencyReason        string
	RotationPolicyVersion  string
	DNSPolicyVersion       string
	RetentionPolicyVersion string
	LimitProfileVersion    string
}

// DNSBatch binds one deterministic contiguous work range to immutable candidate content.
type DNSBatch struct {
	CandidateDigest  Digest
	FrozenWorkDigest Digest
	Ordinal          uint32
	Start            uint32
	End              uint32
	Total            uint32
}

// PurgeTarget is one exact noncurrent generation selected by retention policy.
type PurgeTarget struct {
	Generation    uint64
	Schema        string
	Lifecycle     string
	ContentDigest Digest
}

// PurgePlan is one read-only exact ordered destructive work projection.
type PurgePlan struct {
	Version           string
	CurrentGeneration uint64
	InventoryVersion  string
	PolicyVersion     string
	Targets           []PurgeTarget
}

// AuditReceipt is compact key-free destruction evidence.
type AuditReceipt struct {
	Version         string
	Generation      uint64
	Schema          string
	Lifecycle       string
	OperationClass  string
	ContentDigest   Digest
	DestroyedAt     time.Time
	Result          string
	PolicyVersion   string
	PurgePlanDigest Digest
}

// FrozenWorkDigest validates and commits to an already canonical work inventory.
func FrozenWorkDigest(work []WorkItem) (Digest, error) {
	if !validWork(work) {
		return Digest{}, errors.New("admin_contract_invalid")
	}
	output := sha256.New()
	writeString(output, frozenDomain)
	writeCount(output, len(work))
	for _, item := range work {
		writeWork(output, item)
	}
	return finish(output), nil
}

// CampaignPlanDigest validates and commits to one complete frozen campaign plan.
func CampaignPlanDigest(plan CampaignPlan) (Digest, error) {
	if plan.Version != ContractVersion || !validMode(plan.Mode) || !validSchema(plan.SourceSchema) ||
		plan.SourceGeneration == 0 || plan.CandidateGeneration <= plan.SourceGeneration ||
		!validOperationID(plan.OperationID) || !validVersion(plan.RotationPolicyVersion) ||
		!validVersion(plan.DNSPolicyVersion) || !validVersion(plan.RetentionPolicyVersion) ||
		!validVersion(plan.LimitProfileVersion) {
		return Digest{}, errors.New("admin_contract_invalid")
	}
	if plan.Mode == ModeNormal && plan.EmergencyReason != "" ||
		plan.Mode == ModeEmergency && (len(plan.Work) != 1 || !validEmergencyReason(plan.EmergencyReason)) {
		return Digest{}, errors.New("admin_contract_invalid")
	}
	frozen, err := FrozenWorkDigest(plan.Work)
	if err != nil {
		return Digest{}, err
	}
	output := sha256.New()
	writeString(output, planDomain)
	writeString(output, plan.Version)
	writeString(output, string(plan.Mode))
	writeString(output, plan.SourceSchema)
	writeUint64(output, plan.SourceGeneration)
	writeUint64(output, plan.CandidateGeneration)
	writeString(output, plan.OperationID)
	writeDigest(output, frozen)
	writeString(output, plan.EmergencyReason)
	writeString(output, plan.RotationPolicyVersion)
	writeString(output, plan.DNSPolicyVersion)
	writeString(output, plan.RetentionPolicyVersion)
	writeString(output, plan.LimitProfileVersion)
	return finish(output), nil
}

// DNSBatchDigest validates and commits one deterministic contiguous DNS batch.
func DNSBatchDigest(batch DNSBatch) (Digest, error) {
	if !batch.CandidateDigest.Valid() || !batch.FrozenWorkDigest.Valid() || batch.Ordinal == 0 ||
		batch.Total == 0 || batch.Start >= batch.End || batch.End > batch.Total ||
		batch.Start == 0 && batch.Ordinal != 1 || batch.Ordinal == 1 && batch.Start != 0 {
		return Digest{}, errors.New("admin_contract_invalid")
	}
	output := sha256.New()
	writeString(output, batchDomain)
	writeDigest(output, batch.CandidateDigest)
	writeDigest(output, batch.FrozenWorkDigest)
	writeUint32(output, batch.Ordinal)
	writeUint32(output, batch.Start)
	writeUint32(output, batch.End)
	writeUint32(output, batch.Total)
	return finish(output), nil
}

// PurgePlanDigest validates and commits one exact ordered noncurrent target set.
func PurgePlanDigest(plan PurgePlan) (Digest, error) {
	if plan.Version != ContractVersion || plan.CurrentGeneration == 0 || !validVersion(plan.InventoryVersion) ||
		!validVersion(plan.PolicyVersion) || len(plan.Targets) == 0 || len(plan.Targets) > 4096 {
		return Digest{}, errors.New("admin_contract_invalid")
	}
	previous := uint64(0)
	for _, target := range plan.Targets {
		if target.Generation == 0 || target.Generation == plan.CurrentGeneration || target.Generation <= previous ||
			!validSchema(target.Schema) || !validLifecycle(target.Lifecycle) || !target.ContentDigest.Valid() {
			return Digest{}, errors.New("admin_contract_invalid")
		}
		previous = target.Generation
	}
	output := sha256.New()
	writeString(output, purgeDomain)
	writeString(output, plan.Version)
	writeUint64(output, plan.CurrentGeneration)
	writeString(output, plan.InventoryVersion)
	writeString(output, plan.PolicyVersion)
	writeCount(output, len(plan.Targets))
	for _, target := range plan.Targets {
		writeUint64(output, target.Generation)
		writeString(output, target.Schema)
		writeString(output, target.Lifecycle)
		writeDigest(output, target.ContentDigest)
	}
	return finish(output), nil
}

// AuditCommitment validates and commits one compact key-free purge receipt.
func AuditCommitment(receipt AuditReceipt) (Digest, error) {
	if receipt.Version != ContractVersion || receipt.Generation == 0 || !validSchema(receipt.Schema) ||
		!validLifecycle(receipt.Lifecycle) || !validOperationClass(receipt.OperationClass) ||
		!receipt.ContentDigest.Valid() || receipt.DestroyedAt.IsZero() || receipt.DestroyedAt.Location() != time.UTC ||
		receipt.DestroyedAt.Format(time.RFC3339Nano) == "" || receipt.Result != receiptPurged ||
		!validVersion(receipt.PolicyVersion) || !receipt.PurgePlanDigest.Valid() {
		return Digest{}, errors.New("admin_contract_invalid")
	}
	output := sha256.New()
	writeString(output, auditDomain)
	writeString(output, receipt.Version)
	writeUint64(output, receipt.Generation)
	writeString(output, receipt.Schema)
	writeString(output, receipt.Lifecycle)
	writeString(output, receipt.OperationClass)
	writeDigest(output, receipt.ContentDigest)
	writeString(output, receipt.DestroyedAt.Format(time.RFC3339Nano))
	writeString(output, receipt.Result)
	writeString(output, receipt.PolicyVersion)
	writeDigest(output, receipt.PurgePlanDigest)
	return finish(output), nil
}

// ValidState reports whether a public campaign state belongs to this contract version.
func ValidState(state State) bool {
	return slices.Contains([]State{StatePlanned, StatePreparing, StatePrepared, StateStaged, StateDNSInProgress, StateDNSComplete, StateActivating, StateActivated, StateConflict, StateFailed, StateAborted, StateReconcileRequired}, state)
}

// ValidCommand reports whether a campaign command belongs to this contract version.
func ValidCommand(command Command) bool {
	return slices.Contains([]Command{CommandPlan, CommandPrepare, CommandStage, CommandDNSExport, CommandDNSProve, CommandActivate, CommandStatus, CommandReconcile, CommandAbort, CommandPurgePlan, CommandPurgeApply}, command)
}

// validWork enforces canonical ordering and exact active binding semantics.
func validWork(work []WorkItem) bool {
	if len(work) == 0 || len(work) > maxWorkItems {
		return false
	}
	previous := ""
	for _, item := range work {
		if !validText(item.Tenant, 128) || !validDNSName(item.Domain) || !validUse(item.Use) ||
			!validText(item.Profile, 128) || len(item.Algorithms) == 0 || len(item.Algorithms) > 2 {
			return false
		}
		algorithmPrevious := ""
		for _, algorithm := range item.Algorithms {
			if !validAlgorithm(algorithm) || algorithm <= algorithmPrevious {
				return false
			}
			algorithmPrevious = algorithm
		}
		identity := item.Tenant + "\x00" + item.Domain + "\x00" + item.Use + "\x00" + item.Profile
		if previous != "" && identity <= previous {
			return false
		}
		previous = identity
	}
	return true
}

// writeWork emits the single authoritative frozen binding framing.
func writeWork(output hash.Hash, item WorkItem) {
	writeString(output, item.Tenant)
	writeString(output, item.Domain)
	writeString(output, item.Use)
	writeString(output, item.Profile)
	writeCount(output, len(item.Algorithms))
	for _, algorithm := range item.Algorithms {
		writeString(output, algorithm)
	}
}

// validMode accepts only the explicit normal and emergency classes.
func validMode(mode Mode) bool { return mode == ModeNormal || mode == ModeEmergency }

// validSchema accepts the runtime-compatible native schemas.
func validSchema(value string) bool {
	return value == schemaV2 || value == schemaV3
}

// validVersion accepts one bounded printable opaque policy version.
func validVersion(value string) bool { return validText(value, 128) }

// validUse accepts the closed datasource use vocabulary.
func validUse(value string) bool {
	return slices.Contains([]string{useOriginator, "ordinary_transit", "next_domain_transit", "delivery_status"}, value)
}

// validAlgorithm accepts the closed native signing algorithm vocabulary.
func validAlgorithm(value string) bool { return value == algorithmEd25519 || value == algorithmRSA }

// validEmergencyReason accepts only closed high-priority reason classes.
func validEmergencyReason(value string) bool {
	return slices.Contains([]string{"compromise", "suspected_compromise", "provider_failure", "policy_violation"}, value)
}

// validLifecycle accepts only purge-eligible exact lifecycle classes.
func validLifecycle(value string) bool {
	return slices.Contains([]string{lifecycleActiveHistory, lifecycleNeverActive, lifecycleAborted, lifecycleAbsent}, value)
}

// validOperationClass accepts receipt-safe operation classes.
func validOperationClass(value string) bool {
	return value == operationNormal || value == "emergency" || value == "onboarding" || value == "unknown"
}

// validOperationID accepts canonical nonzero lowercase base32-encoded 128-bit identities.
func validOperationID(value string) bool {
	if len(value) != 26 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(value))
	if err != nil || len(decoded) != 16 {
		clear(decoded)
		return false
	}
	defer clear(decoded)
	var combined byte
	for _, octet := range decoded {
		combined |= octet
	}
	return combined != 0 && strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(decoded)) == value
}

// validText rejects empty, non-UTF8, control-bearing, or oversized contract text.
func validText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || maximum > maxTextBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

// validDNSName accepts one canonical lowercase ASCII domain.
func validDNSName(value string) bool {
	if !validText(value, 253) || value != strings.ToLower(value) || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for label := range strings.SplitSeq(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return true
}

// finish returns one nonzero SHA-256 commitment.
func finish(output hash.Hash) Digest {
	var digest Digest
	copy(digest.value[:], output.Sum(nil))
	return digest
}

// writeDigest writes one fixed-width initialized digest.
func writeDigest(output hash.Hash, digest Digest) { _, _ = output.Write(digest.value[:]) }

// writeString writes one uint32-length-delimited string.
func writeString(output hash.Hash, value string) {
	writeCount(output, len(value))
	_, _ = output.Write([]byte(value))
}

// writeCount writes one bounded collection or byte count.
func writeCount(output hash.Hash, count int) { writeUint32(output, uint32(count)) }

// writeUint32 writes one fixed-width unsigned count.
func writeUint32(output hash.Hash, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	_, _ = output.Write(encoded[:])
}

// writeUint64 writes one fixed-width generation.
func writeUint64(output hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = output.Write(encoded[:])
}
