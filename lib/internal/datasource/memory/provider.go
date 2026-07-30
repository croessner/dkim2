package memory

import (
	"context"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/datasource"
	"github.com/croessner/dkim2/internal/niliface"
)

var _ datasource.Provider = (*Provider)(nil)

// Provider resolves exact records from one immutable in-memory snapshot.
type Provider struct {
	snapshot *snapshot
	complete bool
}

// snapshot contains every complete index published by a Provider.
type snapshot struct {
	generation  uint64
	limits      datasource.Limits
	usage       datasource.Usage
	credentials int
	handles     map[datasource.KeyHandleID]struct{}
	profiles    map[datasource.ProfileID]datasource.ResolvedProfile
	policies    map[policyKey]datasource.Policy
}

// policyKey is one exact canonical administrative lookup tuple.
type policyKey struct {
	tenant datasource.TenantID
	domain string
	use    datasource.ProfileUse
}

// New transactionally validates and owns one immutable static snapshot.
func New(
	generation uint64,
	handles []datasource.KeyHandleID,
	profiles []datasource.Profile,
	policies []datasource.Policy,
	limits datasource.Limits,
) (*Provider, error) {
	if generation == 0 || limits.Validate() != nil {
		return nil, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	if len(handles) > limits.MaxHandles || len(profiles) > limits.MaxProfiles ||
		len(policies) > limits.MaxPolicies {
		return nil, datasource.NewError(datasource.ErrorCodeLimitExceeded)
	}
	usage, err := preflightUsage(handles, profiles, policies, limits)
	if err != nil {
		return nil, err
	}

	handleIndex := make(map[datasource.KeyHandleID]struct{}, len(handles))
	for _, handleID := range handles {
		if !handleID.Valid() {
			return nil, datasource.NewError(datasource.ErrorCodeMalformedData)
		}
		if handleID.ByteLen() > limits.MaxIdentifierBytes {
			return nil, datasource.NewError(datasource.ErrorCodeLimitExceeded)
		}
		if _, duplicate := handleIndex[handleID]; duplicate {
			return nil, datasource.NewError(datasource.ErrorCodeAmbiguous)
		}
		handleIndex[handleID] = struct{}{}
	}

	profileIndex := make(map[datasource.ProfileID]datasource.ResolvedProfile, len(profiles))
	usedHandles := make(map[datasource.KeyHandleID]struct{}, len(handles))
	for _, profile := range profiles {
		if !profile.Valid() {
			return nil, datasource.NewError(datasource.ErrorCodeMalformedData)
		}
		if !profile.ValidForLimits(limits) {
			return nil, datasource.NewError(datasource.ErrorCodeLimitExceeded)
		}
		if _, duplicate := profileIndex[profile.ID()]; duplicate {
			return nil, datasource.NewError(datasource.ErrorCodeAmbiguous)
		}
		credentials := profile.Credentials()
		for _, credential := range credentials {
			if _, declared := handleIndex[credential.KeyHandleID()]; !declared {
				return nil, datasource.NewError(datasource.ErrorCodeMalformedData)
			}
			if _, duplicate := usedHandles[credential.KeyHandleID()]; duplicate {
				return nil, datasource.NewError(datasource.ErrorCodeAmbiguous)
			}
			usedHandles[credential.KeyHandleID()] = struct{}{}
		}
		resolved, err := datasource.NewResolvedProfile(generation, profile)
		if err != nil {
			return nil, datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
		profileIndex[profile.ID()] = resolved
	}

	policyIndex := make(map[policyKey]datasource.Policy, len(policies))
	for _, policy := range policies {
		if !policy.Valid() {
			return nil, datasource.NewError(datasource.ErrorCodeMalformedData)
		}
		if !policy.ValidForLimits(limits) {
			return nil, datasource.NewError(datasource.ErrorCodeLimitExceeded)
		}
		resolvedProfile, found := profileIndex[policy.ProfileID()]
		if !found {
			return nil, datasource.NewError(datasource.ErrorCodeMalformedData)
		}
		profile := resolvedProfile.Profile()
		if policy.SigningDomain() != profile.SigningDomain() {
			return nil, datasource.NewError(datasource.ErrorCodeMalformedData)
		}
		key := policyKey{
			tenant: policy.TenantID(),
			domain: policy.SigningDomain(),
			use:    policy.Use(),
		}
		if _, duplicate := policyIndex[key]; duplicate {
			return nil, datasource.NewError(datasource.ErrorCodeAmbiguous)
		}
		policyIndex[key] = policy
	}

	published := &snapshot{
		generation:  generation,
		limits:      limits,
		usage:       usage,
		credentials: usage.Credentials(),
		handles:     handleIndex,
		profiles:    profileIndex,
		policies:    policyIndex,
	}
	return &Provider{snapshot: published, complete: true}, nil
}

// Valid reports whether the provider owns one complete immutable snapshot.
func (p *Provider) Valid() bool {
	if !p.operational() {
		return false
	}
	snapshot := p.snapshot
	if !snapshot.usage.ValidForLimits(snapshot.limits) ||
		snapshot.usage.Profiles() != len(snapshot.profiles) ||
		snapshot.usage.Handles() != len(snapshot.handles) ||
		snapshot.usage.Policies() != len(snapshot.policies) ||
		snapshot.usage.Bytes() != 0 {
		return false
	}
	for handleID := range snapshot.handles {
		if !handleID.Valid() || handleID.ByteLen() > snapshot.limits.MaxIdentifierBytes {
			return false
		}
	}
	credentials := 0
	usedHandles := make(map[datasource.KeyHandleID]struct{}, len(snapshot.handles))
	for profileID, resolved := range snapshot.profiles {
		if !resolved.ValidForLimits(snapshot.limits) || profileID != resolved.ProfileID() ||
			resolved.Generation() != snapshot.generation {
			return false
		}
		profileCredentials := resolved.Profile().Credentials()
		credentials += len(profileCredentials)
		for _, credential := range profileCredentials {
			if _, declared := snapshot.handles[credential.KeyHandleID()]; !declared {
				return false
			}
			if _, duplicate := usedHandles[credential.KeyHandleID()]; duplicate {
				return false
			}
			usedHandles[credential.KeyHandleID()] = struct{}{}
		}
	}
	if credentials != snapshot.usage.Credentials() ||
		snapshot.usage.Records() != len(snapshot.profiles)+credentials+
			len(snapshot.handles)+len(snapshot.policies) {
		return false
	}
	for key, policy := range snapshot.policies {
		if !policy.ValidForLimits(snapshot.limits) ||
			key != (policyKey{
				tenant: policy.TenantID(),
				domain: policy.SigningDomain(),
				use:    policy.Use(),
			}) {
			return false
		}
		resolved, found := snapshot.profiles[policy.ProfileID()]
		if !found || resolved.Profile().SigningDomain() != policy.SigningDomain() {
			return false
		}
	}
	return true
}

// Equivalent reports whether two valid immutable providers contain the exact
// same generation, limits, accounting, handles, profiles, and policies.
func (p *Provider) Equivalent(other *Provider) bool {
	if !p.Valid() || !other.Valid() {
		return false
	}
	left := p.snapshot
	right := other.snapshot
	if left.generation != right.generation ||
		left.limits != right.limits ||
		left.usage != right.usage ||
		left.credentials != right.credentials ||
		len(left.handles) != len(right.handles) ||
		len(left.profiles) != len(right.profiles) ||
		len(left.policies) != len(right.policies) {
		return false
	}
	for handle := range left.handles {
		if _, found := right.handles[handle]; !found {
			return false
		}
	}
	for id, resolved := range left.profiles {
		otherResolved, found := right.profiles[id]
		if !found ||
			resolved.Generation() != otherResolved.Generation() ||
			!datasource.ProfileFactsEqual(resolved.Profile(), otherResolved.Profile()) {
			return false
		}
	}
	for key, policy := range left.policies {
		if otherPolicy, found := right.policies[key]; !found || policy != otherPolicy {
			return false
		}
	}
	return true
}

// Usage returns immutable bounded snapshot accounting.
func (p *Provider) Usage() (datasource.Usage, error) {
	if !p.Valid() {
		return datasource.Usage{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	return p.snapshot.usage, nil
}

// ResolveProfile resolves one exact active profile from the immutable snapshot.
func (p *Provider) ResolveProfile(
	ctx context.Context,
	request datasource.ProfileRequest,
) (datasource.ResolvedProfile, error) {
	snapshot, err := p.preflight(ctx)
	if err != nil {
		return datasource.ResolvedProfile{}, err
	}
	if !request.Valid() {
		return datasource.ResolvedProfile{}, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	if !request.ValidForLimits(snapshot.limits) {
		return datasource.ResolvedProfile{}, datasource.NewError(datasource.ErrorCodeLimitExceeded)
	}
	resolved, found := snapshot.profiles[request.ProfileID()]
	if !found {
		return datasource.ResolvedProfile{}, datasource.NewError(datasource.ErrorCodeNotFound)
	}
	profile, valid := checkedResolvedProfile(snapshot, resolved, request.ProfileID())
	if !valid {
		return datasource.ResolvedProfile{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	if activeErr := profile.ActiveAt(request.EvaluationTime()); activeErr != nil {
		return datasource.ResolvedProfile{}, activeErr
	}
	output, resultErr := datasource.NewResolvedProfile(snapshot.generation, profile)
	if resultErr != nil {
		return datasource.ResolvedProfile{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	if contextErr := datasource.ErrorFromContext(ctx); contextErr != nil {
		return datasource.ResolvedProfile{}, contextErr
	}
	return output, nil
}

// ResolvePolicy resolves one exact active policy with its same-generation profile.
func (p *Provider) ResolvePolicy(
	ctx context.Context,
	request datasource.PolicyRequest,
) (datasource.ResolvedPolicy, error) {
	snapshot, err := p.preflight(ctx)
	if err != nil {
		return datasource.ResolvedPolicy{}, err
	}
	if !request.Valid() {
		return datasource.ResolvedPolicy{}, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	if !request.ValidForLimits(snapshot.limits) {
		return datasource.ResolvedPolicy{}, datasource.NewError(datasource.ErrorCodeLimitExceeded)
	}
	key := policyKey{
		tenant: request.TenantID(),
		domain: request.SigningDomain(),
		use:    request.Use(),
	}
	policy, found := snapshot.policies[key]
	if !found {
		return datasource.ResolvedPolicy{}, datasource.NewError(datasource.ErrorCodeNotFound)
	}
	if !policy.ValidForLimits(snapshot.limits) ||
		policy.TenantID() != request.TenantID() ||
		policy.SigningDomain() != request.SigningDomain() ||
		policy.Use() != request.Use() {
		return datasource.ResolvedPolicy{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	profile, found := snapshot.profiles[policy.ProfileID()]
	resolvedProfile, valid := checkedResolvedProfile(snapshot, profile, policy.ProfileID())
	if !found || !valid || resolvedProfile.SigningDomain() != policy.SigningDomain() {
		return datasource.ResolvedPolicy{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	if policy.Status() != datasource.RecordStatusActive {
		return datasource.ResolvedPolicy{}, datasource.NewError(datasource.ErrorCodeInactive)
	}
	if activeErr := resolvedProfile.ActiveAt(request.EvaluationTime()); activeErr != nil {
		return datasource.ResolvedPolicy{}, activeErr
	}
	output, resultErr := datasource.NewResolvedPolicy(snapshot.generation, policy, profile)
	if resultErr != nil {
		return datasource.ResolvedPolicy{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	if contextErr := datasource.ErrorFromContext(ctx); contextErr != nil {
		return datasource.ResolvedPolicy{}, contextErr
	}
	return output, nil
}

// String returns a constant protected provider summary.
func (p *Provider) String() string { return "memory.Provider{redacted}" }

// GoString returns a constant protected provider representation.
func (p *Provider) GoString() string { return p.String() }

// Format prevents formatting verbs from exposing snapshot facts.
func (p *Provider) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, p.String()) }

// MarshalJSON emits an empty object so future fields cannot expose snapshot facts.
func (p *Provider) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// operational reports whether lock-free lookup can safely capture the snapshot.
func (p *Provider) operational() bool {
	return p != nil && p.complete && p.snapshot != nil &&
		p.snapshot.generation != 0 && p.snapshot.limits.Validate() == nil &&
		p.snapshot.usage.ValidForLimits(p.snapshot.limits) &&
		p.snapshot.usage.Profiles() == len(p.snapshot.profiles) &&
		p.snapshot.usage.Credentials() == p.snapshot.credentials &&
		p.snapshot.usage.Handles() == len(p.snapshot.handles) &&
		p.snapshot.usage.Policies() == len(p.snapshot.policies) &&
		p.snapshot.usage.Records() == len(p.snapshot.profiles)+p.snapshot.credentials+
			len(p.snapshot.handles)+len(p.snapshot.policies) &&
		p.snapshot.usage.Bytes() == 0 &&
		p.snapshot.handles != nil && p.snapshot.profiles != nil &&
		p.snapshot.policies != nil
}

// preflight captures one valid snapshot after exact context control flow.
func (p *Provider) preflight(ctx context.Context) (*snapshot, error) {
	if niliface.IsNil(ctx) {
		return nil, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	if err := datasource.ErrorFromContext(ctx); err != nil {
		return nil, err
	}
	if !p.operational() {
		return nil, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	return p.snapshot, nil
}

// checkedResolvedProfile returns one bounded stored profile after exact invariant checks.
func checkedResolvedProfile(
	snapshot *snapshot,
	resolved datasource.ResolvedProfile,
	expectedID datasource.ProfileID,
) (datasource.Profile, bool) {
	if snapshot == nil || !resolved.ValidForLimits(snapshot.limits) ||
		resolved.Generation() != snapshot.generation ||
		resolved.ProfileID() != expectedID {
		return datasource.Profile{}, false
	}
	profile := resolved.Profile()
	for _, credential := range profile.Credentials() {
		if _, declared := snapshot.handles[credential.KeyHandleID()]; !declared {
			return datasource.Profile{}, false
		}
	}
	return profile, true
}

// preflightUsage enforces configured count and record-work bounds before index allocation.
func preflightUsage(
	handles []datasource.KeyHandleID,
	profiles []datasource.Profile,
	policies []datasource.Policy,
	limits datasource.Limits,
) (datasource.Usage, error) {
	baseRecords := len(handles)
	if len(profiles) > limits.MaxRecords-baseRecords {
		return datasource.Usage{}, datasource.NewError(datasource.ErrorCodeLimitExceeded)
	}
	baseRecords += len(profiles)
	if len(policies) > limits.MaxRecords-baseRecords {
		return datasource.Usage{}, datasource.NewError(datasource.ErrorCodeLimitExceeded)
	}
	records := baseRecords + len(policies)
	credentials := 0
	for _, profile := range profiles {
		count := profile.CredentialCount()
		if count > limits.MaxRecords-records {
			return datasource.Usage{}, datasource.NewError(datasource.ErrorCodeLimitExceeded)
		}
		records += count
		credentials += count
	}
	usage, err := datasource.NewUsage(
		len(profiles), credentials, len(handles), len(policies), 0, limits,
	)
	if err != nil {
		return datasource.Usage{}, err
	}
	return usage, nil
}
