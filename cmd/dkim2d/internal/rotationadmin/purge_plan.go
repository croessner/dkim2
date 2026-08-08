package rotationadmin

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"slices"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

const purgeArtifactDomain = "DKIM2-PURGE-PROTECTED-ARTIFACT-V1\x00"

// PurgePlan owns one protected, read-only, authority-bound destructive plan.
type PurgePlan struct {
	backend             datasourceadmin.BackendClass
	authority           datasourceadmin.AuthorityDescriptor
	authorityCommitment admincontract.Digest
	current             uint64
	inventoryVersion    string
	policyVersion       string
	targets             []admincontract.PurgeTarget
	digest              admincontract.Digest
	artifactDigest      admincontract.Digest
	expectedRetained    uint32
	expectedUnresolved  uint32
	closed              bool
}

// PurgeReport contains identity-free planning counts and closed result classes.
type PurgeReport struct {
	TargetCount     uint32
	RetainedCount   uint32
	UnresolvedCount uint32
	ResultClass     string
}

// NewPurgePlan constructs a bounded read-only plan from exact retention classification.
func NewPurgePlan(backend datasourceadmin.BackendClass, authority datasourceadmin.AuthorityDescriptor, classification *datasourceadmin.RetentionClassification) (*PurgePlan, error) {
	if classification == nil || classification.EligibleCount() == 0 {
		return nil, errConflict
	}
	authority = canonicalPurgeAuthority(authority)
	authorityCommitment, err := datasourceadmin.RetentionAuthorityCommitment(backend, authority)
	if err != nil {
		return nil, errInvalid
	}
	targets := make([]admincontract.PurgeTarget, 0, classification.EligibleCount())
	for _, generation := range classification.EligibleTargets() {
		lifecycle := purgeLifecycleNeverActive
		if generation.WasActive {
			lifecycle = purgeLifecycleActiveHistory
		}
		targets = append(targets, admincontract.PurgeTarget{Generation: generation.Generation, Schema: generation.Schema, Lifecycle: lifecycle, ContentDigest: generation.ContentDigest})
	}
	slices.SortFunc(targets, func(left, right admincontract.PurgeTarget) int {
		if left.Generation < right.Generation {
			return -1
		}
		if left.Generation > right.Generation {
			return 1
		}
		return 0
	})
	policy := classification.Policy()
	digest, err := admincontract.PurgePlanDigest(admincontract.PurgePlan{Version: admincontract.ContractVersion, CurrentGeneration: classification.CurrentGeneration(), InventoryVersion: classification.InventoryVersion(), PolicyVersion: policy.Version, Targets: targets})
	if err != nil {
		return nil, errConflict
	}
	artifactDigest, err := newPurgeArtifactDigest(authorityCommitment, digest, uint32(len(targets)), classification.RetainedCount(), classification.UnresolvedCount())
	if err != nil {
		return nil, errConflict
	}
	return &PurgePlan{backend: backend, authority: authority, authorityCommitment: authorityCommitment, current: classification.CurrentGeneration(), inventoryVersion: classification.InventoryVersion(), policyVersion: policy.Version, targets: targets, digest: digest, artifactDigest: artifactDigest, expectedRetained: classification.RetainedCount(), expectedUnresolved: classification.UnresolvedCount()}, nil
}

// Digest returns the exact provider-neutral destructive target commitment.
func (p *PurgePlan) Digest() admincontract.Digest {
	if p == nil || p.closed {
		return admincontract.Digest{}
	}
	return p.digest
}

// AuthorityCommitment returns the exact protected provider authority commitment.
func (p *PurgePlan) AuthorityCommitment() admincontract.Digest {
	if p == nil || p.closed {
		return admincontract.Digest{}
	}
	return p.authorityCommitment
}

// ArtifactDigest returns the protected-plan commitment including authority and expected counts.
func (p *PurgePlan) ArtifactDigest() admincontract.Digest {
	if p == nil || p.closed {
		return admincontract.Digest{}
	}
	return p.artifactDigest
}

// Report returns only bounded planning counts and result classes.
func (p *PurgePlan) Report(classification *datasourceadmin.RetentionClassification) PurgeReport {
	if p == nil || p.closed || classification == nil {
		return PurgeReport{ResultClass: "invalid"}
	}
	return PurgeReport{TargetCount: uint32(len(p.targets)), RetainedCount: p.expectedRetained, UnresolvedCount: p.expectedUnresolved, ResultClass: "planned"}
}

// NewPurgeApplyRequest requires explicit destructive intent and the exact protected plan.
func NewPurgeApplyRequest(plan *PurgePlan, destructive bool) (*PurgeApplyRequest, error) {
	if plan == nil || plan.closed || !destructive || !plan.digest.Valid() || !plan.authorityCommitment.Valid() || !plan.artifactDigest.Valid() {
		return nil, errInvalid
	}
	return &PurgeApplyRequest{plan: plan, digest: plan.digest, authorityCommitment: plan.authorityCommitment, artifactDigest: plan.artifactDigest}, nil
}

// PurgeApplyRequest is an apply fence only; it grants no backend deletion capability.
type PurgeApplyRequest struct {
	plan                *PurgePlan
	digest              admincontract.Digest
	authorityCommitment admincontract.Digest
	artifactDigest      admincontract.Digest
}

// VerifyReadback rejects stale plans and classifies exact all-absent retries as idempotent.
func (r *PurgeApplyRequest) VerifyReadback(backend datasourceadmin.BackendClass, authority datasourceadmin.AuthorityDescriptor, inventory datasourceadmin.RetentionInventory) (PurgeApplyFence, error) {
	if r == nil || r.plan == nil || r.plan.closed || r.plan.backend != backend || inventory.Current != r.plan.current {
		return PurgeApplyFence{}, errConflict
	}
	commitment, err := datasourceadmin.RetentionAuthorityCommitment(backend, canonicalPurgeAuthority(authority))
	if err != nil || !commitment.Equal(r.authorityCommitment) || !r.digest.Equal(r.plan.digest) || !r.artifactDigest.Equal(r.plan.artifactDigest) {
		return PurgeApplyFence{}, errConflict
	}
	byGeneration := make(map[uint64]datasourceadmin.RetentionGeneration, len(inventory.Generations))
	for _, generation := range inventory.Generations {
		if _, duplicate := byGeneration[generation.Generation]; duplicate {
			return PurgeApplyFence{}, errConflict
		}
		byGeneration[generation.Generation] = generation
	}
	current, found := byGeneration[inventory.Current]
	if !found || current.State != datasourceadmin.StateCommitted || !current.Complete || current.Ownership != datasourceadmin.RetentionOwnershipTrusted {
		return PurgeApplyFence{}, errConflict
	}
	fence := PurgeApplyFence{planDigest: r.digest, authorityCommitment: commitment}
	for _, target := range r.plan.targets {
		generation, present := byGeneration[target.Generation]
		if !present {
			fence.absent++
			continue
		}
		if !matchesTarget(generation, target) {
			return PurgeApplyFence{}, errConflict
		}
		fence.present++
	}
	if fence.present != 0 && fence.absent != 0 {
		return PurgeApplyFence{}, errConflict
	}
	versionInventory := inventory
	if fence.absent != 0 {
		versionInventory.Generations = append([]datasourceadmin.RetentionGeneration(nil), inventory.Generations...)
		for _, target := range r.plan.targets {
			versionInventory.Generations = append(versionInventory.Generations, purgeTargetGeneration(target))
		}
	}
	inventoryVersion, inventoryErr := datasourceadmin.RetentionInventoryVersion(versionInventory, r.plan.policyVersion)
	if inventoryErr != nil || inventoryVersion != r.plan.inventoryVersion {
		return PurgeApplyFence{}, errConflict
	}
	return fence, nil
}

// PurgeApplyFence is the validated input to a future separate purge authority.
type PurgeApplyFence struct {
	planDigest          admincontract.Digest
	authorityCommitment admincontract.Digest
	present             uint32
	absent              uint32
}

// Ready reports whether every target still requires a future authorized deletion.
func (f PurgeApplyFence) Ready() bool {
	return f.present != 0 && f.absent == 0 && f.planDigest.Valid() && f.authorityCommitment.Valid()
}

// IdempotentAbsent reports whether this exact plan was already fully removed.
func (f PurgeApplyFence) IdempotentAbsent() bool {
	return f.absent != 0 && f.present == 0 && f.planDigest.Valid() && f.authorityCommitment.Valid()
}

// Close erases the protected authority and target metadata.
func (p *PurgePlan) Close() error {
	if p == nil || p.closed {
		return nil
	}
	p.authority = datasourceadmin.AuthorityDescriptor{}
	clear(p.targets)
	p.targets = nil
	p.digest, p.authorityCommitment, p.artifactDigest = admincontract.Digest{}, admincontract.Digest{}, admincontract.Digest{}
	p.closed = true
	return nil
}

// String prevents plan identities from reaching generic output.
func (*PurgePlan) String() string { return redacted }

// GoString prevents plan identities from reaching generic output.
func (*PurgePlan) GoString() string { return redacted }

// Format prevents plan identities from reaching generic output.
func (*PurgePlan) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic purge-plan serialization.
func (*PurgePlan) MarshalJSON() ([]byte, error) { return nil, errInvalid }

// String returns a bounded identity-free report.
func (r PurgeReport) String() string {
	return fmt.Sprintf("purge targets=%d retained=%d unresolved=%d result=%s", r.TargetCount, r.RetainedCount, r.UnresolvedCount, r.ResultClass)
}

// GoString returns the bounded identity-free report.
func (r PurgeReport) GoString() string { return r.String() }

// Format emits the bounded identity-free report.
func (r PurgeReport) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// matchesTarget proves one exact current noncurrent generation still matches the plan.
func matchesTarget(generation datasourceadmin.RetentionGeneration, target admincontract.PurgeTarget) bool {
	if generation.Generation != target.Generation || generation.Schema != target.Schema || generation.State != datasourceadmin.StateCommitted ||
		generation.Ownership != datasourceadmin.RetentionOwnershipTrusted || !generation.Complete || !generation.ContentDigest.Equal(target.ContentDigest) {
		return false
	}
	if target.Lifecycle == purgeLifecycleActiveHistory {
		return generation.WasActive
	}
	return target.Lifecycle == purgeLifecycleNeverActive && !generation.WasActive && generation.Closed
}

// purgeTargetGeneration reconstructs only exact key-free target facts for all-absent idempotency proof.
func purgeTargetGeneration(target admincontract.PurgeTarget) datasourceadmin.RetentionGeneration {
	return datasourceadmin.RetentionGeneration{Generation: target.Generation, Schema: target.Schema, State: datasourceadmin.StateCommitted, WasActive: target.Lifecycle == purgeLifecycleActiveHistory, Complete: true, Closed: target.Lifecycle == purgeLifecycleNeverActive, Ownership: datasourceadmin.RetentionOwnershipTrusted, ContentDigest: target.ContentDigest}
}

// newPurgeArtifactDigest binds the provider-neutral plan to exact authority and expected counts.
func newPurgeArtifactDigest(authority, plan admincontract.Digest, targets, retained, unresolved uint32) (admincontract.Digest, error) {
	if !authority.Valid() || !plan.Valid() || targets == 0 {
		return admincontract.Digest{}, errInvalid
	}
	output := sha256.New()
	_, _ = output.Write([]byte(purgeArtifactDomain))
	_, _ = output.Write(authority.Bytes())
	_, _ = output.Write(plan.Bytes())
	for _, value := range []uint32{targets, retained, unresolved} {
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], value)
		_, _ = output.Write(encoded[:])
	}
	return admincontract.ParseDigest(output.Sum(nil))
}

// canonicalPurgeAuthority detaches and orders equivalent authority facts before commitment.
func canonicalPurgeAuthority(authority datasourceadmin.AuthorityDescriptor) datasourceadmin.AuthorityDescriptor {
	authority.Endpoints = append([]datasourceadmin.AuthorityEndpoint(nil), authority.Endpoints...)
	authority.TrustFingerprints = append([][32]byte(nil), authority.TrustFingerprints...)
	slices.SortFunc(authority.Endpoints, func(left, right datasourceadmin.AuthorityEndpoint) int {
		for _, pair := range [][2]string{{left.Scheme, right.Scheme}, {left.Host, right.Host}, {left.TLSServerName, right.TLSServerName}} {
			if pair[0] < pair[1] {
				return -1
			}
			if pair[0] > pair[1] {
				return 1
			}
		}
		if left.Port < right.Port {
			return -1
		}
		if left.Port > right.Port {
			return 1
		}
		return 0
	})
	slices.SortFunc(authority.TrustFingerprints, func(left, right [32]byte) int {
		for index := range left {
			if left[index] < right[index] {
				return -1
			}
			if left[index] > right[index] {
				return 1
			}
		}
		return 0
	})
	return authority
}
