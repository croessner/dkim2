package domainadmin

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// Plan owns one immutable key-free operation projection and digest.
type Plan struct {
	mu                  sync.Mutex
	backend             datasourceadmin.BackendClass
	authority           datasourceadmin.AuthorityDescriptor
	expectedCurrent     uint64
	intent              Intent
	profileID           string
	credentials         []AllocatedIdentity
	candidateGeneration uint64
	dns                 datasourceadmin.DNSPolicy
	operation           datasourceadmin.OperationBinding
	lockRevision        uint64
	closed              bool
	digest              datasourceadmin.PlanDigest
}

// NewPlan binds fresh current-state evidence to one exact allocated operation.
func NewPlan(
	ctx context.Context,
	backend datasourceadmin.BackendClass,
	authority datasourceadmin.AuthorityDescriptor,
	allocation *IdentityAllocation,
	dns datasourceadmin.DNSPolicy,
) (*Plan, error) {
	if ctx == nil || ctx.Err() != nil || allocation == nil {
		return nil, newError(CodeInvalidIntent)
	}
	if err := allocation.reservePlanIssuance(); err != nil {
		return nil, err
	}
	allocation.mu.Lock()
	if allocation.closed || allocation.planState != allocationPlanReserved || !allocation.intent.valid() || allocation.candidateGeneration == 0 {
		allocation.mu.Unlock()
		return nil, newError(CodeConflict)
	}
	operation := allocation.operation
	lock := allocation.lock
	candidateGeneration := allocation.candidateGeneration
	intent := allocation.intent.clone()
	profileID := allocation.profileID
	credentials := append([]AllocatedIdentity(nil), allocation.credentials...)
	var source *datasourceadmin.PlanSource
	var sourceErr error
	if allocation.planSource != nil {
		source, sourceErr = allocation.planSource.Clone()
	}
	allocation.mu.Unlock()
	if sourceErr != nil || !lock.ValidFor(operation) {
		_ = source.Close()
		clearAllocatedIdentities(credentials)
		return nil, newError(CodeConflict)
	}
	expectedCurrent := uint64(0)
	if source != nil {
		expectedCurrent = source.Generation()
		if expectedCurrent == 0 {
			_ = source.Close()
			clearAllocatedIdentities(credentials)
			return nil, newError(CodeConflict)
		}
	}
	defer source.Close() //nolint:errcheck // The key-free detached source has no recovery action.
	plan := &Plan{
		backend: backend, authority: cloneAuthority(authority), expectedCurrent: expectedCurrent,
		intent: intent.clone(), profileID: profileID, credentials: credentials,
		candidateGeneration: candidateGeneration, dns: cloneDNSPolicy(dns), operation: operation,
		lockRevision: lock.Revision(),
	}
	digest, err := plan.computeDigest(ctx, source, plan.authority)
	if err != nil {
		clearPlan(plan)
		return nil, newError(CodeConflict)
	}
	plan.digest = digest
	if err := allocation.completePlanIssuance(); err != nil {
		clearPlan(plan)
		return nil, newError(CodeConflict)
	}
	return plan, nil
}

// computeDigest builds the exact datasource-owned key-free digest projection.
func (p *Plan) computeDigest(
	ctx context.Context,
	current *datasourceadmin.PlanSource,
	authority datasourceadmin.AuthorityDescriptor,
) (datasourceadmin.PlanDigest, error) {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return datasourceadmin.PlanDigest{}, newError(CodeConflict)
	}
	operationID := ""
	if err := p.operation.WithValue(ctx, func(value string) error {
		operationID = value
		return nil
	}); err != nil {
		return datasourceadmin.PlanDigest{}, err
	}
	algorithms := p.intent.Algorithms()
	intent := datasourceadmin.PlanIntent{
		Version: p.intent.Version(), Domain: p.intent.Domain(), TenantID: p.intent.TenantID(),
		ProfileUse: p.intent.ProfileUse().String(), Rollout: p.intent.Rollout().String(),
		Compatibility: p.intent.Compatibility().String(), Algorithms: make([]string, len(algorithms)),
	}
	for index, algorithm := range algorithms {
		intent.Algorithms[index] = string(algorithm)
	}
	allocated := make([]datasourceadmin.AllocatedCredential, len(p.credentials))
	for index, credential := range p.credentials {
		allocated[index] = datasourceadmin.AllocatedCredential{
			Algorithm: string(credential.algorithm), HandleID: credential.handleID, Selector: credential.selector,
		}
	}
	return datasourceadmin.NewPlanDigest(datasourceadmin.PlanProjection{
		Backend: p.backend, Authority: cloneAuthority(authority), ExpectedCurrent: p.expectedCurrent,
		Current: current, Intent: intent, ProfileID: p.profileID, Credentials: allocated,
		CandidateGeneration: p.candidateGeneration, DNS: cloneDNSPolicy(p.dns), OperationID: operationID,
	})
}

// VerifyFresh consumes fresh current evidence bound to the original exact claim.
func (p *Plan) VerifyFresh(
	ctx context.Context,
	lock datasourceadmin.AdministrationLock,
	collisions *datasourceadmin.CollisionInventory,
	authority datasourceadmin.AuthorityDescriptor,
) error {
	if p == nil || ctx == nil || ctx.Err() != nil || collisions == nil {
		return newError(CodeConflict)
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return newError(CodeConflict)
	}
	owned := clonePlanLocked(p)
	p.mu.Unlock()
	defer clearPlan(owned)
	if !lock.ValidFor(owned.operation) || lock.Revision() != owned.lockRevision || !collisions.ValidFor(lock) {
		return newError(CodeConflict)
	}
	if collisions.CandidateGeneration() != owned.candidateGeneration || collisions.OperationUsed(owned.operation) ||
		collisions.ProfileIDUsed(owned.profileID) || collisions.PolicyUsed(
		owned.intent.TenantID(), owned.intent.Domain(), owned.intent.ProfileUse().String(),
	) {
		return newError(CodeConflict)
	}
	for _, credential := range owned.credentials {
		if collisions.SelectorUsed(credential.selector) || collisions.HandleIDUsed(credential.handleID) {
			return newError(CodeConflict)
		}
	}
	current, err := collisions.TakePlanSource(lock)
	if err != nil {
		return newError(CodeConflict)
	}
	defer current.Close() //nolint:errcheck // The key-free detached source has no recovery action.
	if (current == nil) != (owned.expectedCurrent == 0) || current != nil && current.Generation() != owned.expectedCurrent {
		return newError(CodeConflict)
	}
	digest, err := owned.computeDigest(ctx, current, authority)
	if err != nil || !owned.digest.Equal(digest) {
		return newError(CodeConflict)
	}
	return nil
}

// VerifyCurrentSnapshot proves that the exact snapshot selected for cloning is the plan source.
func (p *Plan) VerifyCurrentSnapshot(
	ctx context.Context,
	current *datasourceadmin.Snapshot,
	authority datasourceadmin.AuthorityDescriptor,
) error {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return newError(CodeConflict)
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return newError(CodeConflict)
	}
	owned := clonePlanLocked(p)
	p.mu.Unlock()
	defer clearPlan(owned)
	if (current == nil) != (owned.expectedCurrent == 0) ||
		current != nil && current.Generation() != owned.expectedCurrent {
		return newError(CodeConflict)
	}
	var source *datasourceadmin.PlanSource
	var err error
	if current != nil {
		source, err = current.PlanSource(ctx)
		if err != nil {
			return newError(CodeConflict)
		}
		defer source.Close() //nolint:errcheck // The detached source has no recovery action.
	}
	digest, err := owned.computeDigest(ctx, source, authority)
	if err != nil || !owned.digest.Equal(digest) {
		return newError(CodeConflict)
	}
	return nil
}

// MatchesCoordinator reports whether this plan belongs to the configured backend authority.
func (p *Plan) MatchesCoordinator(
	backend datasourceadmin.BackendClass,
	authority datasourceadmin.AuthorityDescriptor,
) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.closed && p.backend == backend && authorityEqual(p.authority, authority)
}

// matchesPromotionRecovery compares exact protected identity without document revision coupling.
func (p *Plan) matchesPromotionRecovery(other *Plan) bool {
	left := clonePlan(p)
	right := clonePlan(other)
	if left == nil || right == nil {
		_ = left.Close()
		_ = right.Close()
		return false
	}
	defer left.Close()  //nolint:errcheck // Detached comparison cleanup has no recovery action.
	defer right.Close() //nolint:errcheck // Detached comparison cleanup has no recovery action.
	if left.validateFacts() != nil || right.validateFacts() != nil {
		return false
	}
	return left.backend == right.backend && authorityEqual(left.authority, right.authority) &&
		left.digest.Equal(right.digest) && left.operation.Equal(right.operation) &&
		left.lockRevision == right.lockRevision
}

// Digest returns the protected exact plan identity.
func (p *Plan) Digest() datasourceadmin.PlanDigest {
	if p == nil {
		return datasourceadmin.PlanDigest{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return datasourceadmin.PlanDigest{}
	}
	return p.digest
}

// Close releases every retained protected plan identity.
func (p *Plan) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	clearPlanLocked(p)
	p.closed = true
	return nil
}

// cloneAuthority detaches every slice and optional authority field.
func cloneAuthority(value datasourceadmin.AuthorityDescriptor) datasourceadmin.AuthorityDescriptor {
	value.Endpoints = slices.Clone(value.Endpoints)
	value.TrustFingerprints = slices.Clone(value.TrustFingerprints)
	if value.LDAP != nil {
		copyValue := *value.LDAP
		value.LDAP = &copyValue
	}
	if value.SQL != nil {
		copyValue := *value.SQL
		value.SQL = &copyValue
	}
	if value.ClientCertificateFingerprint != nil {
		copyValue := *value.ClientCertificateFingerprint
		value.ClientCertificateFingerprint = &copyValue
	}
	return value
}

// cloneDNSPolicy detaches ordered resolver endpoints.
func cloneDNSPolicy(value datasourceadmin.DNSPolicy) datasourceadmin.DNSPolicy {
	value.ResolverEndpoints = slices.Clone(value.ResolverEndpoints)
	return value
}

// clearAuthority releases every retained protected authority reference.
func clearAuthority(value *datasourceadmin.AuthorityDescriptor) {
	if value == nil {
		return
	}
	clear(value.Endpoints)
	clear(value.TrustFingerprints)
	if value.ClientCertificateFingerprint != nil {
		clear(value.ClientCertificateFingerprint[:])
	}
	*value = datasourceadmin.AuthorityDescriptor{}
}

// authorityEqual compares canonical descriptors through their exact stable fields.
func authorityEqual(left, right datasourceadmin.AuthorityDescriptor) bool {
	if left.AuthorityID != right.AuthorityID || !slices.Equal(left.Endpoints, right.Endpoints) ||
		!authorityLDAPEqual(left.LDAP, right.LDAP) || !authoritySQLEqual(left.SQL, right.SQL) ||
		!slices.Equal(left.TrustFingerprints, right.TrustFingerprints) {
		return false
	}
	if left.ClientCertificateFingerprint == nil || right.ClientCertificateFingerprint == nil {
		return left.ClientCertificateFingerprint == nil && right.ClientCertificateFingerprint == nil
	}
	return sha256Equal(*left.ClientCertificateFingerprint, *right.ClientCertificateFingerprint)
}

// authorityLDAPEqual compares optional LDAP descriptor values.
func authorityLDAPEqual(left, right *datasourceadmin.LDAPAuthority) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

// authoritySQLEqual compares optional SQL descriptor values.
func authoritySQLEqual(left, right *datasourceadmin.SQLAuthority) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

// sha256Equal compares public certificate fingerprints without formatting them.
func sha256Equal(left, right [sha256.Size]byte) bool { return left == right }

// String returns a constant protected plan representation.
func (*Plan) String() string { return redacted }

// GoString returns a constant protected plan representation.
func (*Plan) GoString() string { return redacted }

// Format prevents plan identities and digests from reaching formatting sinks.
func (*Plan) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic plan serialization outside the internal journal codec.
func (*Plan) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }
