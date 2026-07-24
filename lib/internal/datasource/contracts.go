package datasource

import (
	"context"
	"fmt"
	"io"
	"time"
)

// ProfileRequest asks for one exact profile under an administrative use.
type ProfileRequest struct {
	profileID ProfileID
	use       ProfileUse
	at        time.Time
}

// NewProfileRequest validates one exact profile request under narrowed limits.
func NewProfileRequest(profileID ProfileID, use ProfileUse, at time.Time, limits Limits) (ProfileRequest, error) {
	if limits.Validate() != nil || !profileID.Valid() || !use.Known() || at.IsZero() {
		return ProfileRequest{}, NewError(ErrorCodeInvalidRequest)
	}
	if profileID.ByteLen() > limits.MaxIdentifierBytes {
		return ProfileRequest{}, NewError(ErrorCodeLimitExceeded)
	}
	return ProfileRequest{profileID: profileID, use: use, at: at.UTC()}, nil
}

// Valid reports whether the profile request is initialized.
func (r ProfileRequest) Valid() bool { return r.validForLimits(HardLimits()) }

// ValidForLimits reports whether the profile request satisfies one narrowed datasource contract.
func (r ProfileRequest) ValidForLimits(limits Limits) bool { return r.validForLimits(limits) }

// ProfileID returns the exact requested identity.
func (r ProfileRequest) ProfileID() ProfileID { return r.profileID }

// Use returns the administrative selection purpose.
func (r ProfileRequest) Use() ProfileUse { return r.use }

// EvaluationTime returns the captured UTC evaluation instant.
func (r ProfileRequest) EvaluationTime() time.Time { return r.at }

// String returns a constant protected request summary.
func (r ProfileRequest) String() string { return "datasource.ProfileRequest{redacted}" }

// GoString returns a constant protected request representation.
func (r ProfileRequest) GoString() string { return r.String() }

// Format prevents formatting verbs from exposing request facts.
func (r ProfileRequest) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// validForLimits verifies the request under one narrowed datasource contract.
func (r ProfileRequest) validForLimits(limits Limits) bool {
	if limits.Validate() != nil {
		return false
	}
	rebuilt, err := NewProfileRequest(r.profileID, r.use, r.at, limits)
	return err == nil && rebuilt == r
}

// PolicyRequest asks for one exact administrative tenant/domain/use binding.
type PolicyRequest struct {
	tenant TenantID
	domain string
	use    ProfileUse
	at     time.Time
}

// NewPolicyRequest validates one exact administrative policy request.
func NewPolicyRequest(tenant TenantID, domain string, use ProfileUse, at time.Time, limits Limits) (PolicyRequest, error) {
	if limits.Validate() != nil || !tenant.Valid() || !use.Known() || at.IsZero() {
		return PolicyRequest{}, NewError(ErrorCodeInvalidRequest)
	}
	if tenant.ByteLen() > limits.MaxIdentifierBytes {
		return PolicyRequest{}, NewError(ErrorCodeLimitExceeded)
	}
	canonical, err := canonicalDatasourceDomain(
		domain, limits.MaxDomainBytes, limits.MaxDomainLabels,
	)
	if err != nil {
		return PolicyRequest{}, err
	}
	return PolicyRequest{tenant: tenant, domain: canonical, use: use, at: at.UTC()}, nil
}

// Valid reports whether the policy request is initialized.
func (r PolicyRequest) Valid() bool { return r.validForLimits(HardLimits()) }

// ValidForLimits reports whether the policy request satisfies one narrowed datasource contract.
func (r PolicyRequest) ValidForLimits(limits Limits) bool { return r.validForLimits(limits) }

// TenantID returns the exact requested tenant.
func (r PolicyRequest) TenantID() TenantID { return r.tenant }

// SigningDomain returns the canonical administrative domain.
func (r PolicyRequest) SigningDomain() string { return r.domain }

// Use returns the administrative selection purpose.
func (r PolicyRequest) Use() ProfileUse { return r.use }

// EvaluationTime returns the captured UTC evaluation instant.
func (r PolicyRequest) EvaluationTime() time.Time { return r.at }

// String returns a constant protected request summary.
func (r PolicyRequest) String() string { return "datasource.PolicyRequest{redacted}" }

// GoString returns a constant protected request representation.
func (r PolicyRequest) GoString() string { return r.String() }

// Format prevents formatting verbs from exposing request facts.
func (r PolicyRequest) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// validForLimits verifies the request under one narrowed datasource contract.
func (r PolicyRequest) validForLimits(limits Limits) bool {
	if limits.Validate() != nil {
		return false
	}
	rebuilt, err := NewPolicyRequest(r.tenant, r.domain, r.use, r.at, limits)
	return err == nil && rebuilt == r
}

// ResolvedProfile is one immutable self-contained profile result.
type ResolvedProfile struct {
	generation uint64
	profile    Profile
	complete   bool
}

// NewResolvedProfile constructs one complete immutable profile result.
func NewResolvedProfile(generation uint64, profile Profile) (ResolvedProfile, error) {
	if generation == 0 || !profile.Valid() {
		return ResolvedProfile{}, NewError(ErrorCodeInvalidRequest)
	}
	return ResolvedProfile{generation: generation, profile: cloneProfile(profile), complete: true}, nil
}

// Valid reports whether the profile result is complete and initialized.
func (r ResolvedProfile) Valid() bool {
	return r.validForLimits(HardLimits())
}

// ValidForLimits reports whether the resolved profile satisfies one narrowed datasource contract.
func (r ResolvedProfile) ValidForLimits(limits Limits) bool { return r.validForLimits(limits) }

// zero reports whether every result field is uninitialized.
func (r ResolvedProfile) zero() bool {
	return !r.complete && r.generation == 0 && r.profile.isZero()
}

// Generation returns the immutable snapshot generation.
func (r ResolvedProfile) Generation() uint64 { return r.generation }

// ProfileID returns the exact resolved profile identity.
func (r ResolvedProfile) ProfileID() ProfileID { return r.profile.ID() }

// Profile returns the immutable complete datasource profile.
func (r ResolvedProfile) Profile() Profile { return cloneProfile(r.profile) }

// String returns a constant protected result summary.
func (r ResolvedProfile) String() string { return "datasource.ResolvedProfile{redacted}" }

// GoString returns a constant protected result representation.
func (r ResolvedProfile) GoString() string { return r.String() }

// Format prevents formatting verbs from exposing result facts.
func (r ResolvedProfile) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// validForLimits verifies the result under one narrowed datasource contract.
func (r ResolvedProfile) validForLimits(limits Limits) bool {
	return limits.Validate() == nil && r.complete && r.generation != 0 &&
		r.profile.ValidForLimits(limits)
}

// cloneResolvedProfile returns a detached immutable resolved-profile result.
func cloneResolvedProfile(input ResolvedProfile) ResolvedProfile {
	input.profile = cloneProfile(input.profile)
	return input
}

// ResolvedPolicy is one immutable self-contained policy and profile result.
type ResolvedPolicy struct {
	generation uint64
	policy     Policy
	profile    ResolvedProfile
	complete   bool
}

// NewResolvedPolicy constructs one complete generation-consistent policy result.
func NewResolvedPolicy(generation uint64, policy Policy, profile ResolvedProfile) (ResolvedPolicy, error) {
	resolvedProfile := profile.Profile()
	if generation == 0 || !policy.Valid() || !profile.Valid() ||
		profile.Generation() != generation ||
		policy.ProfileID() != resolvedProfile.ID() ||
		policy.SigningDomain() != resolvedProfile.SigningDomain() {
		return ResolvedPolicy{}, NewError(ErrorCodeInvalidRequest)
	}
	return ResolvedPolicy{
		generation: generation, policy: policy,
		profile: cloneResolvedProfile(profile), complete: true,
	}, nil
}

// Valid reports whether the policy result is complete and generation-consistent.
func (r ResolvedPolicy) Valid() bool {
	return r.validForLimits(HardLimits())
}

// ValidForLimits reports whether the resolved policy satisfies one narrowed datasource contract.
func (r ResolvedPolicy) ValidForLimits(limits Limits) bool { return r.validForLimits(limits) }

// validForLimits verifies the result under one narrowed datasource contract.
func (r ResolvedPolicy) validForLimits(limits Limits) bool {
	profile := r.profile.Profile()
	return limits.Validate() == nil && r.complete && r.generation != 0 &&
		r.profile.Generation() == r.generation &&
		r.policy.ValidForLimits(limits) && r.profile.ValidForLimits(limits) &&
		r.policy.ProfileID() == profile.ID() &&
		r.policy.SigningDomain() == profile.SigningDomain()
}

// zero reports whether every policy result field is uninitialized.
func (r ResolvedPolicy) zero() bool {
	return !r.complete && r.generation == 0 && r.policy.isZero() && r.profile.zero()
}

// Generation returns the immutable snapshot generation.
func (r ResolvedPolicy) Generation() uint64 { return r.generation }

// Policy returns the immutable administrative binding.
func (r ResolvedPolicy) Policy() Policy { return r.policy }

// Profile returns the immutable same-generation datasource profile.
func (r ResolvedPolicy) Profile() Profile { return r.profile.Profile() }

// String returns a constant protected result summary.
func (r ResolvedPolicy) String() string { return "datasource.ResolvedPolicy{redacted}" }

// GoString returns a constant protected result representation.
func (r ResolvedPolicy) GoString() string { return r.String() }

// Format prevents formatting verbs from exposing result facts.
func (r ResolvedPolicy) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// Provider resolves immutable profile and administrative policy snapshots.
type Provider interface {
	ResolveProfile(context.Context, ProfileRequest) (ResolvedProfile, error)
	ResolvePolicy(context.Context, PolicyRequest) (ResolvedPolicy, error)
}

// ValidateProfileOutcome enforces the closed profile result/error matrix.
func ValidateProfileOutcome(result ResolvedProfile, err error) error {
	if err == nil && result.Valid() || IsTypedError(err) && result.zero() {
		return nil
	}
	return NewError(ErrorCodeInternalInvariant)
}

// ValidatePolicyOutcome enforces the closed policy result/error matrix.
func ValidatePolicyOutcome(result ResolvedPolicy, err error) error {
	if err == nil && result.Valid() || IsTypedError(err) && result.zero() {
		return nil
	}
	return NewError(ErrorCodeInternalInvariant)
}
