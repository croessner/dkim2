package datasourceadmin

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"slices"
	"strings"

	"github.com/croessner/dkim2/admincontract"
)

const maxRetentionInventory = 16384

const retentionAuthorityDomain = "DKIM2-RETENTION-AUTHORITY-V1\x00"

const retentionPolicyVersion = "retention-v1"

// RetentionOwnership classifies the authority that supplied one generation's metadata.
type RetentionOwnership string

const (
	// RetentionOwnershipTrusted identifies metadata from the configured generation owner.
	RetentionOwnershipTrusted RetentionOwnership = "trusted"
	// RetentionOwnershipForeign identifies metadata owned by another authority.
	RetentionOwnershipForeign RetentionOwnership = "foreign"
	// RetentionOwnershipUnknown identifies metadata without an exact owner proof.
	RetentionOwnershipUnknown RetentionOwnership = "unknown"
)

// RetentionReason is the closed provider-neutral result of one retention decision.
type RetentionReason string

// RetentionReason values classify every closed retention outcome.
const (
	RetentionReasonCurrent             RetentionReason = "current"
	RetentionReasonOpenCampaign        RetentionReason = "open_campaign"
	RetentionReasonUnknown             RetentionReason = "unknown"
	RetentionReasonMalformed           RetentionReason = "malformed"
	RetentionReasonPartial             RetentionReason = "partial"
	RetentionReasonForeign             RetentionReason = "foreign"
	RetentionReasonLegacy              RetentionReason = "legacy_retained"
	RetentionReasonActiveRollback      RetentionReason = "active_rollback"
	RetentionReasonActiveHistory       RetentionReason = "active_history"
	RetentionReasonClosedNeverActive   RetentionReason = "closed_never_active"
	RetentionReasonEligibleActive      RetentionReason = "eligible_active_history"
	RetentionReasonEligibleNeverActive RetentionReason = "eligible_never_active"
)

// RetentionPolicy bounds selection and audit retention independently of allocation limits.
type RetentionPolicy struct {
	Version                         string
	MaxTotalGenerations             uint32
	MinActiveRollbackGenerations    uint32
	MaxClosedNeverActiveGenerations uint32
	MaxAuditReceipts                uint32
	MaxPurgeBatch                   uint32
	AllowLegacyV2                   bool
}

// DefaultRetentionPolicy returns restrictive finite production defaults.
func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		Version: retentionPolicyVersion, MaxTotalGenerations: 128, MinActiveRollbackGenerations: 8,
		MaxClosedNeverActiveGenerations: 4, MaxAuditReceipts: 1024, MaxPurgeBatch: 64,
	}
}

// Validate rejects unbounded, empty, or contradictory policy settings.
func (p RetentionPolicy) Validate() error {
	if !validRetentionVersion(p.Version) || p.MaxTotalGenerations == 0 || p.MaxTotalGenerations > maxRetentionInventory ||
		p.MinActiveRollbackGenerations > p.MaxTotalGenerations || p.MaxClosedNeverActiveGenerations > p.MaxTotalGenerations ||
		p.MaxAuditReceipts == 0 || p.MaxAuditReceipts > maxRetentionInventory || p.MaxPurgeBatch == 0 || p.MaxPurgeBatch > 4096 {
		return newError(CodeInvalid)
	}
	return nil
}

// RetentionGeneration is key-free lifecycle metadata for one inventory generation.
type RetentionGeneration struct {
	Generation       uint64
	Operation        OperationBinding
	SourceGeneration uint64
	Schema           string
	State            GenerationState
	WasActive        bool
	Complete         bool
	Closed           bool
	Ownership        RetentionOwnership
	ContentDigest    admincontract.Digest
}

// JoinTerminalRecovery applies only exact immutable terminal evidence. A v3
// campaign generation with missing or mismatched terminal evidence is unknown
// and therefore retained; it is never inferred from the current pointer.
func JoinTerminalRecovery(generations []RetentionGeneration, terminals []TerminalRecord) []RetentionGeneration {
	result := append([]RetentionGeneration(nil), generations...)
	for index := range result {
		row := &result[index]
		if row.Schema != SchemaVersionV3 || !row.Operation.Initialized() || row.SourceGeneration == 0 || !row.ContentDigest.Valid() {
			continue
		}
		matched := false
		storedBytes := row.ContentDigest.Bytes()
		storedDigest, parseErr := ParseCandidateContentDigest(storedBytes)
		clear(storedBytes)
		if parseErr != nil {
			row.Ownership = RetentionOwnershipUnknown
			continue
		}
		for _, terminal := range terminals {
			if !terminal.Valid() || !terminal.Operation().Equal(row.Operation) || terminal.SourceGeneration() != row.SourceGeneration || terminal.CandidateGeneration() != row.Generation || !terminal.CandidateDigest().Equal(storedDigest) {
				continue
			}
			if terminal.State() == TerminalClosed && terminal.CurrentGeneration() == row.Generation || terminal.State() == TerminalAborted && terminal.CurrentGeneration() == row.SourceGeneration {
				row.Closed, matched = true, true
				break
			}
		}
		if !matched && !row.WasActive {
			row.Ownership = RetentionOwnershipUnknown
		}
	}
	return result
}

// RetentionInventory is one stable, key-free, provider-neutral inventory projection.
type RetentionInventory struct {
	Version     string
	Current     uint64
	Generations []RetentionGeneration
}

// RetentionInventoryReader owns provider-side stable historical metadata reads.
type RetentionInventoryReader interface {
	Inventory(context.Context, GenerationLimits) (Inventory, error)
}

// RetentionRecoveryLimits bounds an allocation-independent historical recovery read.
type RetentionRecoveryLimits struct {
	MaxGenerations uint32
	PageSize       uint32
	MaxReadBytes   uint32
}

// DefaultRetentionRecoveryLimits returns the fixed finite recovery window.
func DefaultRetentionRecoveryLimits() RetentionRecoveryLimits {
	return RetentionRecoveryLimits{MaxGenerations: 16384, PageSize: 1024, MaxReadBytes: 1 << 30}
}

// Validate rejects widened or unbounded recovery reads.
func (l RetentionRecoveryLimits) Validate() error {
	if l.MaxGenerations == 0 || l.MaxGenerations > 16384 || l.PageSize == 0 || l.PageSize > 1024 || l.PageSize > l.MaxGenerations || l.MaxReadBytes == 0 || l.MaxReadBytes > 1<<30 {
		return newError(CodeInvalid)
	}
	return nil
}

// RetentionRecoveryReader owns one provider's exact paged historical evidence read.
type RetentionRecoveryReader interface {
	RetentionCurrent(context.Context) (uint64, error)
	RetentionPage(context.Context, uint64, uint32) ([]RetentionGeneration, error)
}

// ReadRetentionRecoveryInventory builds a stable full recovery inventory without allocation limits.
func ReadRetentionRecoveryInventory(ctx context.Context, reader RetentionRecoveryReader, limits RetentionRecoveryLimits) (RetentionInventory, error) {
	if ctx == nil || ctx.Err() != nil || reader == nil || limits.Validate() != nil {
		return RetentionInventory{}, newError(CodeInvalid)
	}
	first, err := reader.RetentionCurrent(ctx)
	if err != nil || first == 0 {
		return RetentionInventory{}, newError(CodeUnavailable)
	}
	rows := make([]RetentionGeneration, 0)
	cursor := uint64(0)
	for {
		page, pageErr := reader.RetentionPage(ctx, cursor, limits.PageSize)
		if pageErr != nil {
			return RetentionInventory{}, newError(CodeUnavailable)
		}
		if len(page) == 0 {
			break
		}
		if len(page) > int(limits.PageSize) || len(rows)+len(page) > int(limits.MaxGenerations) {
			return RetentionInventory{}, newError(CodeLimitExceeded)
		}
		for _, row := range page {
			if row.Generation == 0 || row.Generation <= cursor {
				return RetentionInventory{}, newError(CodeConflict)
			}
			cursor = row.Generation
			rows = append(rows, row)
		}
	}
	found := false
	for _, row := range rows {
		if row.Generation == first {
			found = true
			break
		}
	}
	if !found {
		return RetentionInventory{}, newError(CodeConflict)
	}
	final, finalErr := reader.RetentionCurrent(ctx)
	if finalErr != nil || final != first {
		return RetentionInventory{}, newError(CodeConflict)
	}
	return RetentionInventory{Version: "recovery-inventory-v1", Current: first, Generations: rows}, nil
}

// ReadRetentionInventory reads provider-owned metadata without invoking allocation.
func ReadRetentionInventory(ctx context.Context, reader RetentionInventoryReader, limits GenerationLimits) (RetentionInventory, error) {
	if ctx == nil || ctx.Err() != nil || reader == nil || limits.Validate() != nil {
		return RetentionInventory{}, newError(CodeInvalid)
	}
	inventory, err := reader.Inventory(ctx, limits)
	if err != nil {
		return RetentionInventory{}, err
	}
	if inventory.Current == 0 || len(inventory.Generations) == 0 {
		return RetentionInventory{}, newError(CodeConflict)
	}
	result := RetentionInventory{Version: "provider-inventory-v1", Current: inventory.Current, Generations: make([]RetentionGeneration, len(inventory.Generations))}
	for index, generation := range inventory.Generations {
		row := RetentionGeneration{Generation: generation.Generation, Operation: generation.Operation, SourceGeneration: generation.SourceGeneration, Schema: generation.Schema, State: generation.State, WasActive: generation.WasActive, Ownership: RetentionOwnershipTrusted}
		if generation.Schema == SchemaVersionV3 && generation.ContentDigest.Valid() {
			digest, parseErr := admincontract.ParseDigest(generation.ContentDigest.Bytes())
			if parseErr != nil {
				return RetentionInventory{}, newError(CodeConflict)
			}
			row.ContentDigest, row.Complete = digest, generation.State == StateCommitted
		}
		result.Generations[index] = row
	}
	return result, nil
}

// RetentionDecision is one detached classification result.
type RetentionDecision struct {
	Generation uint64
	Reason     RetentionReason
	Eligible   bool
}

// RetentionClassification contains deterministic protected retention results.
type RetentionClassification struct {
	version    string
	current    uint64
	policy     RetentionPolicy
	decisions  []RetentionDecision
	eligible   []RetentionGeneration
	retained   uint32
	unresolved uint32
}

// ClassifyRetentionPages concatenates a stable ordered page stream without applying allocation ceilings.
func ClassifyRetentionPages(version string, current uint64, pages [][]RetentionGeneration, policy RetentionPolicy) (*RetentionClassification, error) {
	if len(pages) == 0 || len(pages) > maxRetentionInventory || !validRetentionVersion(version) {
		return nil, newError(CodeInvalid)
	}
	all := make([]RetentionGeneration, 0)
	var previous uint64
	for _, page := range pages {
		if len(page) == 0 || len(page) > 1024 || len(all)+len(page) > maxRetentionInventory {
			return nil, newError(CodeLimitExceeded)
		}
		for _, generation := range page {
			if generation.Generation == 0 || generation.Generation <= previous {
				return nil, newError(CodeConflict)
			}
			previous = generation.Generation
			all = append(all, generation)
		}
	}
	return ClassifyRetention(RetentionInventory{Version: version, Current: current, Generations: all}, policy)
}

// ClassifyRetention deterministically selects only exact recoverable noncurrent generations.
func ClassifyRetention(inventory RetentionInventory, policy RetentionPolicy) (*RetentionClassification, error) {
	if policy.Validate() != nil || !validRetentionVersion(inventory.Version) || inventory.Current == 0 ||
		len(inventory.Generations) == 0 || len(inventory.Generations) > maxRetentionInventory {
		return nil, newError(CodeInvalid)
	}
	ordered := append([]RetentionGeneration(nil), inventory.Generations...)
	slices.SortFunc(ordered, func(left, right RetentionGeneration) int { return compareUint64(left.Generation, right.Generation) })
	for index, generation := range ordered {
		if generation.Generation == 0 || index > 0 && generation.Generation == ordered[index-1].Generation {
			return nil, newError(CodeConflict)
		}
	}
	commitment, commitmentErr := retentionInventoryCommitment(inventory, policy.Version)
	if commitmentErr != nil {
		return nil, commitmentErr
	}
	classification := &RetentionClassification{version: commitment, current: inventory.Current, policy: policy}
	protected, active, closed := classifyCandidates(ordered, inventory.Current, classification)
	active = markRetainedNewest(active, policy.MinActiveRollbackGenerations, RetentionReasonActiveRollback, classification)
	closed = markRetainedNewest(closed, policy.MaxClosedNeverActiveGenerations, RetentionReasonClosedNeverActive, classification)
	candidates := append(active, closed...)
	slices.SortFunc(candidates, func(left, right RetentionGeneration) int { return compareUint64(left.Generation, right.Generation) })
	remaining := len(ordered)
	for _, generation := range candidates {
		if remaining <= int(policy.MaxTotalGenerations) || len(classification.eligible) >= int(policy.MaxPurgeBatch) {
			classification.add(generation.Generation, retainedReason(generation), false)
			continue
		}
		classification.eligible = append(classification.eligible, generation)
		classification.add(generation.Generation, eligibleReason(generation), true)
		remaining--
	}
	classification.retained = uint32(len(ordered) - len(classification.eligible) - int(classification.unresolved))
	_ = protected
	return classification, nil
}

// classifyCandidates separates never-eligible evidence from exact eligible lifecycle candidates.
func classifyCandidates(generations []RetentionGeneration, current uint64, output *RetentionClassification) (protected, active, closed []RetentionGeneration) {
	for _, generation := range generations {
		switch {
		case generation.Generation == current:
			output.add(generation.Generation, RetentionReasonCurrent, false)
			protected = append(protected, generation)
		case generation.State == StateStaging:
			output.add(generation.Generation, RetentionReasonOpenCampaign, false)
			output.unresolved++
			protected = append(protected, generation)
		case generation.Ownership == RetentionOwnershipForeign:
			output.add(generation.Generation, RetentionReasonForeign, false)
			output.unresolved++
			protected = append(protected, generation)
		case generation.Ownership != RetentionOwnershipTrusted:
			output.add(generation.Generation, RetentionReasonUnknown, false)
			output.unresolved++
			protected = append(protected, generation)
		case generation.Schema != SchemaVersionV2 && generation.Schema != SchemaVersionV3 || generation.State != StateCommitted:
			output.add(generation.Generation, RetentionReasonMalformed, false)
			output.unresolved++
			protected = append(protected, generation)
		case !generation.Complete || !generation.ContentDigest.Valid():
			output.add(generation.Generation, RetentionReasonPartial, false)
			output.unresolved++
			protected = append(protected, generation)
		case generation.Schema == "dkim2-datasource-v2" && !output.policy.AllowLegacyV2:
			output.add(generation.Generation, RetentionReasonLegacy, false)
			protected = append(protected, generation)
		case generation.WasActive:
			active = append(active, generation)
		case generation.Closed:
			closed = append(closed, generation)
		default:
			output.add(generation.Generation, RetentionReasonUnknown, false)
			output.unresolved++
			protected = append(protected, generation)
		}
	}
	return protected, active, closed
}

// markRetainedNewest preserves the newest exact lifecycle records before capacity selection.
func markRetainedNewest(candidates []RetentionGeneration, keep uint32, reason RetentionReason, output *RetentionClassification) []RetentionGeneration {
	slices.SortFunc(candidates, func(left, right RetentionGeneration) int { return compareUint64(right.Generation, left.Generation) })
	for index := 0; index < len(candidates) && index < int(keep); index++ {
		output.add(candidates[index].Generation, reason, false)
	}
	if len(candidates) <= int(keep) {
		return nil
	}
	remaining := append([]RetentionGeneration(nil), candidates[keep:]...)
	clear(candidates)
	return remaining
}

// retainedReason returns the closed unselected lifecycle class.
func retainedReason(generation RetentionGeneration) RetentionReason {
	if generation.WasActive {
		return RetentionReasonActiveHistory
	}
	return RetentionReasonClosedNeverActive
}

// eligibleReason returns the closed selected lifecycle class.
func eligibleReason(generation RetentionGeneration) RetentionReason {
	if generation.WasActive {
		return RetentionReasonEligibleActive
	}
	return RetentionReasonEligibleNeverActive
}

// add records one unique decision.
func (c *RetentionClassification) add(generation uint64, reason RetentionReason, eligible bool) {
	c.decisions = append(c.decisions, RetentionDecision{Generation: generation, Reason: reason, Eligible: eligible})
}

// EligibleCount returns the bounded destructive target count.
func (c *RetentionClassification) EligibleCount() int {
	if c == nil {
		return 0
	}
	return len(c.eligible)
}

// Eligible reports whether one exact generation is selected.
func (c *RetentionClassification) Eligible(generation uint64) bool {
	if c == nil {
		return false
	}
	for _, decision := range c.decisions {
		if decision.Generation == generation {
			return decision.Eligible
		}
	}
	return false
}

// Reason returns the exact closed classification reason or unknown for missing generation evidence.
func (c *RetentionClassification) Reason(generation uint64) RetentionReason {
	if c == nil {
		return RetentionReasonUnknown
	}
	for _, decision := range c.decisions {
		if decision.Generation == generation {
			return decision.Reason
		}
	}
	return RetentionReasonUnknown
}

// EligibleTargets returns a detached canonical destructive target set.
func (c *RetentionClassification) EligibleTargets() []RetentionGeneration {
	if c == nil {
		return nil
	}
	return append([]RetentionGeneration(nil), c.eligible...)
}

// InventoryVersion returns the stable inventory commitment version.
func (c *RetentionClassification) InventoryVersion() string {
	if c == nil {
		return ""
	}
	return c.version
}

// CurrentGeneration returns the exact protected current pointer.
func (c *RetentionClassification) CurrentGeneration() uint64 {
	if c == nil {
		return 0
	}
	return c.current
}

// Policy returns the detached finite policy used for selection.
func (c *RetentionClassification) Policy() RetentionPolicy {
	if c == nil {
		return RetentionPolicy{}
	}
	return c.policy
}

// RetainedCount returns all non-eligible resolved generations.
func (c *RetentionClassification) RetainedCount() uint32 {
	if c == nil {
		return 0
	}
	return c.retained
}

// UnresolvedCount returns all never-eligible ambiguous generations.
func (c *RetentionClassification) UnresolvedCount() uint32 {
	if c == nil {
		return 0
	}
	return c.unresolved
}

// String prevents generation metadata from reaching generic output.
func (*RetentionClassification) String() string { return redacted }

// GoString prevents generation metadata from reaching generic output.
func (*RetentionClassification) GoString() string { return redacted }

// Format prevents generation metadata from reaching generic output.
func (*RetentionClassification) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, redacted)
}

// MarshalJSON rejects generic retention serialization.
func (*RetentionClassification) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// validRetentionVersion accepts one bounded opaque policy or inventory version.
func validRetentionVersion(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
}

// retentionInventoryCommitment binds every observed lifecycle fact and the policy to stale-plan detection.
func retentionInventoryCommitment(inventory RetentionInventory, policyVersion string) (string, error) {
	if !validRetentionVersion(inventory.Version) || !validRetentionVersion(policyVersion) || inventory.Current == 0 {
		return "", newError(CodeInvalid)
	}
	ordered := append([]RetentionGeneration(nil), inventory.Generations...)
	slices.SortFunc(ordered, func(left, right RetentionGeneration) int { return compareUint64(left.Generation, right.Generation) })
	hash := sha256.New()
	_, _ = hash.Write([]byte("DKIM2-RETENTION-INVENTORY-V1\x00"))
	for _, value := range []string{inventory.Version, policyVersion} {
		writeRetentionString(hash, value)
	}
	var current [8]byte
	binary.BigEndian.PutUint64(current[:], inventory.Current)
	_, _ = hash.Write(current[:])
	for index, row := range ordered {
		if row.Generation == 0 || index > 0 && row.Generation == ordered[index-1].Generation {
			return "", newError(CodeConflict)
		}
		var generation [8]byte
		binary.BigEndian.PutUint64(generation[:], row.Generation)
		_, _ = hash.Write(generation[:])
		binary.BigEndian.PutUint64(generation[:], row.SourceGeneration)
		_, _ = hash.Write(generation[:])
		if row.Operation.Initialized() {
			if err := row.Operation.WithValue(context.Background(), func(value string) error {
				writeRetentionString(hash, value)
				return nil
			}); err != nil {
				return "", newError(CodeConflict)
			}
		} else {
			writeRetentionString(hash, "")
		}
		for _, value := range []string{row.Schema, string(row.State), string(row.Ownership)} {
			writeRetentionString(hash, value)
		}
		if row.WasActive {
			_, _ = hash.Write([]byte{1})
		} else {
			_, _ = hash.Write([]byte{0})
		}
		if row.Complete {
			_, _ = hash.Write([]byte{1})
		} else {
			_, _ = hash.Write([]byte{0})
		}
		if row.Closed {
			_, _ = hash.Write([]byte{1})
		} else {
			_, _ = hash.Write([]byte{0})
		}
		_, _ = hash.Write(row.ContentDigest.Bytes())
	}
	return "inventory-" + hex.EncodeToString(hash.Sum(nil)), nil
}

// RetentionInventoryVersion returns the canonical complete observed-inventory commitment.
func RetentionInventoryVersion(inventory RetentionInventory, policyVersion string) (string, error) {
	return retentionInventoryCommitment(inventory, policyVersion)
}

// writeRetentionString writes one unambiguous length-framed commitment field.
func writeRetentionString(output hash.Hash, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = output.Write(length[:])
	_, _ = output.Write([]byte(value))
}

// RetentionAuthorityCommitment binds protected purge planning to one exact configured authority.
func RetentionAuthorityCommitment(backend BackendClass, authority AuthorityDescriptor) (admincontract.Digest, error) {
	if ValidatePurgeAuthority(backend, authority) != nil {
		return admincontract.Digest{}, newError(CodeInvalid)
	}
	output := sha256.New()
	_, _ = output.Write([]byte(retentionAuthorityDomain))
	writeFramedString(output, string(backend))
	writeAuthorityDescriptor(output, authority)
	if authority.LDAP != nil {
		writeFramedString(output, authority.LDAP.PurgePrincipal)
	} else {
		writeFramedString(output, authority.SQL.PurgeRole)
	}
	return admincontract.ParseDigest(output.Sum(nil))
}
