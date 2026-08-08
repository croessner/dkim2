package rotationadmin

import (
	"context"
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// frozenBinding is one exact active policy and current profile binding.
type frozenBinding struct {
	policyIndex int
	item        admincontract.WorkItem
}

// Plan owns one immutable key-free frozen campaign projection.
type Plan struct {
	mu                  sync.Mutex
	intent              Intent
	sourceSchema        string
	sourceGeneration    uint64
	candidateGeneration uint64
	work                []frozenBinding
	frozenDigest        admincontract.Digest
	planDigest          admincontract.Digest
	preparationStarted  bool
	closed              bool
}

// Freeze enumerates every eligible active binding under one stable snapshot.
func Freeze(ctx context.Context, source *datasourceadmin.Snapshot, candidateGeneration uint64, intent Intent, limits Limits) (*Plan, error) { //nolint:gocyclo // One immutable freeze owns the complete campaign work-set validation.
	if ctx == nil || ctx.Err() != nil || source == nil || limits.Validate() != nil ||
		candidateGeneration <= source.Generation() || !intent.operation.Initialized() {
		return nil, errInvalid
	}
	var work []frozenBinding
	err := source.WithRows(ctx, func(rows datasourceadmin.Rows) error {
		profiles := make(map[string]datasourceadmin.ProfileRow, len(rows.Profiles))
		algorithms := make(map[string][]string, len(rows.Profiles))
		for _, profile := range rows.Profiles {
			if _, duplicate := profiles[profile.ID]; duplicate {
				return errConflict
			}
			profiles[profile.ID] = profile
		}
		for _, credential := range rows.Credentials {
			if _, found := profiles[credential.ProfileID]; !found {
				return errConflict
			}
			algorithms[credential.ProfileID] = append(algorithms[credential.ProfileID], credential.Algorithm)
		}
		for index, policy := range rows.Policies {
			if policy.Status != profileStatusActive || policy.Rollout != "enforce" {
				continue
			}
			if intent.mode == admincontract.ModeEmergency && (policy.TenantID != intent.emergencyBinding.Tenant ||
				policy.Domain != intent.emergencyBinding.Domain || policy.Use != intent.emergencyBinding.Use ||
				policy.ProfileID != intent.emergencyBinding.Profile) {
				continue
			}
			profile, found := profiles[policy.ProfileID]
			ordered := append([]string(nil), algorithms[policy.ProfileID]...)
			slices.Sort(ordered)
			if !found || profile.Status != profileStatusActive || profile.Domain != policy.Domain || len(ordered) == 0 {
				return errConflict
			}
			work = append(work, frozenBinding{policyIndex: index, item: admincontract.WorkItem{
				Tenant: policy.TenantID, Domain: policy.Domain, Use: policy.Use,
				Profile: policy.ProfileID, Algorithms: ordered,
			}})
		}
		return nil
	})
	if err != nil {
		return nil, errConflict
	}
	if len(work) == 0 {
		return nil, errConflict
	}
	if len(work) > int(limits.MaxWorkItems) {
		return nil, errLimit
	}
	slices.SortFunc(work, func(left, right frozenBinding) int {
		return compareWork(left.item, right.item)
	})
	if intent.mode == admincontract.ModeEmergency && len(work) != 1 {
		return nil, errConflict
	}
	items := make([]admincontract.WorkItem, len(work))
	for index := range work {
		items[index] = cloneWorkItem(work[index].item)
	}
	frozen, err := admincontract.FrozenWorkDigest(items)
	if err != nil {
		return nil, errConflict
	}
	planDigest, err := admincontract.CampaignPlanDigest(admincontract.CampaignPlan{
		Version: admincontract.ContractVersion, Mode: intent.mode, SourceSchema: source.SchemaVersion(),
		SourceGeneration: source.Generation(), CandidateGeneration: candidateGeneration,
		OperationID: intent.operationValue, Work: items, EmergencyReason: intent.emergencyReason,
		RotationPolicyVersion: intent.rotationPolicyVersion, DNSPolicyVersion: intent.dnsPolicyVersion,
		RetentionPolicyVersion: intent.retentionPolicyVersion, LimitProfileVersion: intent.limitProfileVersion,
	})
	if err != nil {
		return nil, errConflict
	}
	return &Plan{intent: intent, sourceSchema: source.SchemaVersion(), sourceGeneration: source.Generation(), candidateGeneration: candidateGeneration, work: work, frozenDigest: frozen, planDigest: planDigest}, nil
}

// VerifySource proves the frozen plan still binds the exact source content.
func (p *Plan) VerifySource(ctx context.Context, source *datasourceadmin.Snapshot) error {
	if p == nil || ctx == nil || ctx.Err() != nil || source == nil {
		return errInvalid
	}
	p.mu.Lock()
	if p.closed || source.SchemaVersion() != p.sourceSchema || source.Generation() != p.sourceGeneration {
		p.mu.Unlock()
		return errConflict
	}
	want := p.frozenDigest
	intent := p.intent
	candidate := p.candidateGeneration
	p.mu.Unlock()
	rebuilt, err := Freeze(ctx, source, candidate, intent, Limits{MaxWorkItems: 131072, MaxDNSBatchRecords: 4096, MaxDNSBatches: 1024})
	if err != nil {
		return errConflict
	}
	defer rebuilt.Close() //nolint:errcheck // Detached verification cleanup cannot fail.
	if !want.Equal(rebuilt.FrozenDigest()) {
		return errConflict
	}
	return nil
}

// FrozenDigest returns the key-free frozen work commitment.
func (p *Plan) FrozenDigest() admincontract.Digest {
	if p == nil {
		return admincontract.Digest{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return admincontract.Digest{}
	}
	return p.frozenDigest
}

// Digest returns the complete campaign plan commitment.
func (p *Plan) Digest() admincontract.Digest {
	if p == nil {
		return admincontract.Digest{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return admincontract.Digest{}
	}
	return p.planDigest
}

// WorkCount returns the bounded frozen binding count.
func (p *Plan) WorkCount() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0
	}
	return len(p.work)
}

// DNSRecordCount returns the exact candidate credential count.
func (p *Plan) DNSRecordCount() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0
	}
	total := 0
	for _, binding := range p.work {
		total += len(binding.item.Algorithms)
	}
	return total
}

// Close erases protected work identities and invalidates the plan.
func (p *Plan) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for index := range p.work {
		p.work[index] = frozenBinding{}
	}
	p.work = nil
	p.intent = Intent{}
	p.frozenDigest = admincontract.Digest{}
	p.planDigest = admincontract.Digest{}
	p.closed = true
	return nil
}

// String returns a constant protected plan representation.
func (*Plan) String() string { return redacted }

// GoString returns a constant protected plan representation.
func (*Plan) GoString() string { return redacted }

// Format prevents plan identities from reaching formatting sinks.
func (*Plan) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic plan serialization.
func (*Plan) MarshalJSON() ([]byte, error) { return nil, errInvalid }

// compareWork orders one canonical binding without concatenation ambiguity.
func compareWork(left, right admincontract.WorkItem) int {
	for _, pair := range [][2]string{{left.Tenant, right.Tenant}, {left.Domain, right.Domain}, {left.Use, right.Use}, {left.Profile, right.Profile}} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	return 0
}

// cloneWorkItem detaches the only slice-backed work field.
func cloneWorkItem(item admincontract.WorkItem) admincontract.WorkItem {
	item.Algorithms = append([]string(nil), item.Algorithms...)
	return item
}
