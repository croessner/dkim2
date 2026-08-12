package signingprofile

import (
	"crypto/subtle"
	"fmt"
	"io"
	"slices"

	"github.com/croessner/dkim2/internal/datasource"
	"github.com/croessner/dkim2/internal/keyresolver"
	"github.com/croessner/dkim2/internal/signing"
)

// Entry binds one exact datasource credential to one inert private-key handle.
type Entry struct {
	handleID  datasource.KeyHandleID
	handle    signing.PrivateKeyHandle
	profileID datasource.ProfileID
	domain    string
	selector  string
	algorithm datasource.Algorithm
	keyDigest [32]byte
	uses      []datasource.ProfileUse
	complete  bool
}

// NewEntry validates one exact immutable handle-registry binding.
func NewEntry(
	profile datasource.Profile,
	handleID datasource.KeyHandleID,
	handle signing.PrivateKeyHandle,
	allowedUses []datasource.ProfileUse,
	limits datasource.Limits,
) (Entry, error) {
	if limits.Validate() != nil || !profile.Valid() || !handleID.Valid() || !handle.Valid() {
		return Entry{}, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	if !profile.ValidForLimits(limits) || handleID.ByteLen() > limits.MaxIdentifierBytes {
		return Entry{}, datasource.NewError(datasource.ErrorCodeLimitExceeded)
	}
	uses, err := canonicalUses(allowedUses)
	if err != nil {
		return Entry{}, err
	}
	credentials := profile.Credentials()
	var selected datasource.Credential
	matches := 0
	for _, credential := range credentials {
		if credential.KeyHandleID() == handleID {
			selected = credential
			matches++
		}
	}
	if matches != 1 || !selected.ValidForLimits(limits) {
		return Entry{}, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	return Entry{
		handleID: handleID, handle: handle, profileID: profile.ID(),
		domain: profile.SigningDomain(), selector: selected.Selector(),
		algorithm: selected.Algorithm(), keyDigest: selected.PublicKeySPKISHA256(),
		uses: uses, complete: true,
	}, nil
}

// Valid reports whether the entry remains internally complete.
func (e Entry) Valid() bool { return e.validForLimits(datasource.HardLimits()) }

// ValidForLimits reports whether the entry satisfies one narrowed datasource contract.
func (e Entry) ValidForLimits(limits datasource.Limits) bool { return e.validForLimits(limits) }

// validForLimits verifies every exact entry fact under one datasource contract.
func (e Entry) validForLimits(limits datasource.Limits) bool {
	if limits.Validate() != nil || !e.complete || !e.handleID.Valid() || !e.handle.Valid() ||
		!e.profileID.Valid() || !e.algorithm.Known() || len(e.uses) == 0 ||
		e.handleID.ByteLen() > limits.MaxIdentifierBytes ||
		e.profileID.ByteLen() > limits.MaxIdentifierBytes {
		return false
	}
	resolverLimits := keyresolver.DefaultLimits()
	resolverLimits.MaxSigningDomainBytes = limits.MaxDomainBytes
	resolverLimits.MaxSigningDomainLabels = limits.MaxDomainLabels
	resolverLimits.MaxSelectorBytes = limits.MaxSelectorBytes
	resolverLimits.MaxSelectorLabels = limits.MaxSelectorLabels
	query, queryErr := keyresolver.NewQuery(e.domain, e.selector, e.algorithm, resolverLimits)
	if queryErr != nil || query.SigningDomain() != e.domain || query.Selector() != e.selector {
		return false
	}
	uses, err := canonicalUses(e.uses)
	return err == nil && equalUses(uses, e.uses)
}

// KeyHandleID returns the exact provider-neutral registry key.
func (e Entry) KeyHandleID() datasource.KeyHandleID { return e.handleID }

// AllowedUses returns the detached canonical administrative use set.
func (e Entry) AllowedUses() []datasource.ProfileUse {
	return append([]datasource.ProfileUse(nil), e.uses...)
}

// String returns a constant protected registry-entry summary.
func (e Entry) String() string { return "signingprofile.Entry{redacted}" }

// GoString returns a constant protected registry-entry representation.
func (e Entry) GoString() string { return e.String() }

// Format prevents formatting verbs from exposing registry facts.
func (e Entry) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, e.String()) }

// Registry is one immutable exact KeyHandleID-to-signing-handle map.
type Registry struct {
	entries  map[datasource.KeyHandleID]Entry
	groups   map[datasource.ProfileID]bindingGroup
	limits   datasource.Limits
	complete bool
}

// bindingGroup is one canonical ProfileID credential-binding set derived from entries.
type bindingGroup struct {
	domain  string
	handles []datasource.KeyHandleID
}

// NewRegistry validates and detaches one immutable exact registry.
func NewRegistry(entries []Entry, limits datasource.Limits) (Registry, error) {
	if limits.Validate() != nil || len(entries) == 0 {
		return Registry{}, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	if len(entries) > limits.MaxHandles {
		return Registry{}, datasource.NewError(datasource.ErrorCodeLimitExceeded)
	}
	index := make(map[datasource.KeyHandleID]Entry, len(entries))
	for _, entry := range entries {
		if !entry.Valid() {
			return Registry{}, datasource.NewError(datasource.ErrorCodeInvalidRequest)
		}
		if !entry.ValidForLimits(limits) {
			return Registry{}, datasource.NewError(datasource.ErrorCodeLimitExceeded)
		}
		if _, duplicate := index[entry.handleID]; duplicate {
			return Registry{}, datasource.NewError(datasource.ErrorCodeAmbiguous)
		}
		index[entry.handleID] = cloneEntry(entry)
	}
	groups, err := buildBindingGroups(index, limits)
	if err != nil {
		return Registry{}, err
	}
	return Registry{entries: index, groups: groups, limits: limits, complete: true}, nil
}

// Valid reports whether the registry remains complete and exact.
func (r Registry) Valid() bool {
	if !r.complete || r.limits.Validate() != nil || len(r.entries) == 0 ||
		len(r.entries) > r.limits.MaxHandles {
		return false
	}
	for key, entry := range r.entries {
		if !entry.ValidForLimits(r.limits) || key != entry.handleID {
			return false
		}
	}
	rebuilt, err := buildBindingGroups(r.entries, r.limits)
	return err == nil && bindingGroupsEqual(rebuilt, r.groups)
}

// ProjectProfile converts one exact resolved profile without resolving a provider or invoking a signer.
func (r Registry) ProjectProfile(
	result datasource.ResolvedProfile,
	request datasource.ProfileRequest,
	limits signing.Limits,
) (signing.Profile, error) {
	if !r.Valid() || !result.Valid() {
		return signing.Profile{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	if !request.Valid() || limits.Validate() != nil {
		return signing.Profile{}, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	if !result.ValidForLimits(r.limits) {
		return signing.Profile{}, datasource.NewError(datasource.ErrorCodeLimitExceeded)
	}
	if !request.ValidForLimits(r.limits) {
		return signing.Profile{}, datasource.NewError(datasource.ErrorCodeLimitExceeded)
	}
	profile := result.Profile()
	if result.ProfileID() != request.ProfileID() || profile.ID() != request.ProfileID() {
		return signing.Profile{}, datasource.NewError(datasource.ErrorCodeInactive)
	}
	if err := profile.ActiveAt(request.EvaluationTime()); err != nil {
		return signing.Profile{}, err
	}
	return r.project(profile, request.Use(), limits)
}

// ProjectPolicy converts one exact eligible resolved policy without provider or signer calls.
func (r Registry) ProjectPolicy(
	result datasource.ResolvedPolicy,
	request datasource.PolicyRequest,
	limits signing.Limits,
) (signing.Profile, error) {
	if !r.Valid() || !result.Valid() {
		return signing.Profile{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	if !request.Valid() || limits.Validate() != nil {
		return signing.Profile{}, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	if !result.ValidForLimits(r.limits) {
		return signing.Profile{}, datasource.NewError(datasource.ErrorCodeLimitExceeded)
	}
	if !request.ValidForLimits(r.limits) {
		return signing.Profile{}, datasource.NewError(datasource.ErrorCodeLimitExceeded)
	}
	policy := result.Policy()
	profile := result.Profile()
	if policy.TenantID() != request.TenantID() ||
		policy.SigningDomain() != request.SigningDomain() ||
		policy.Use() != request.Use() ||
		policy.ProfileID() != profile.ID() ||
		policy.SigningDomain() != profile.SigningDomain() {
		return signing.Profile{}, datasource.NewError(datasource.ErrorCodeInactive)
	}
	if err := policy.Eligible(); err != nil {
		return signing.Profile{}, err
	}
	if err := profile.ActiveAt(request.EvaluationTime()); err != nil {
		return signing.Profile{}, err
	}
	return r.project(profile, request.Use(), limits)
}

// String returns a constant protected registry summary.
func (r Registry) String() string { return "signingprofile.Registry{redacted}" }

// GoString returns a constant protected registry representation.
func (r Registry) GoString() string { return r.String() }

// Format prevents formatting verbs from exposing registry facts.
func (r Registry) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// project maps one already eligible datasource profile through exact registry entries.
func (r Registry) project(
	profile datasource.Profile,
	use datasource.ProfileUse,
	limits signing.Limits,
) (signing.Profile, error) {
	credentials := profile.Credentials()
	entries, err := r.matchedEntries(profile, use)
	if err != nil {
		return signing.Profile{}, err
	}
	projected := make([]signing.Credential, 0, len(credentials))
	for index, credential := range credentials {
		signingCredential, credentialErr := signing.NewCredential(
			credential.Selector(),
			credential.Algorithm(),
			credential.PublicKey(),
			entries[index].handle,
			limits,
		)
		if credentialErr != nil {
			return signing.Profile{}, datasource.NewError(datasource.ErrorCodeLimitExceeded)
		}
		projected = append(projected, signingCredential)
	}
	output, profileErr := signing.NewProfile(profile.SigningDomain(), projected)
	if profileErr != nil {
		return signing.Profile{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	return output, nil
}

// matchedEntries preflights one complete resolved profile against its exact derived group.
func (r Registry) matchedEntries(profile datasource.Profile, use datasource.ProfileUse) ([]Entry, error) {
	group, found := r.groups[profile.ID()]
	if !found {
		return nil, datasource.NewError(datasource.ErrorCodeNotFound)
	}
	credentials := profile.Credentials()
	if group.domain != profile.SigningDomain() || len(group.handles) > len(credentials) {
		return nil, datasource.NewError(datasource.ErrorCodeInactive)
	}
	matched := make([]Entry, len(credentials))
	for index, credential := range credentials {
		entry, present := r.entries[credential.KeyHandleID()]
		if !present {
			if len(group.handles) < len(credentials) {
				return nil, datasource.NewError(datasource.ErrorCodeNotFound)
			}
			return nil, datasource.NewError(datasource.ErrorCodeInactive)
		}
		if !entry.matches(profile, credential, use) {
			return nil, datasource.NewError(datasource.ErrorCodeInactive)
		}
		matched[index] = entry
	}
	if len(group.handles) != len(credentials) {
		return nil, datasource.NewError(datasource.ErrorCodeInactive)
	}
	return matched, nil
}

// matches verifies every exact registry fact including the public-key digest.
func (e Entry) matches(
	profile datasource.Profile,
	credential datasource.Credential,
	use datasource.ProfileUse,
) bool {
	digest := credential.PublicKeySPKISHA256()
	return e.Valid() && profile.Valid() && credential.Valid() && use.Known() &&
		e.profileID == profile.ID() && e.domain == profile.SigningDomain() &&
		e.handleID == credential.KeyHandleID() &&
		e.selector == credential.Selector() &&
		e.algorithm == credential.Algorithm() &&
		subtle.ConstantTimeCompare(e.keyDigest[:], digest[:]) == 1 &&
		containsUse(e.uses, use)
}

// canonicalUses validates, deduplicates, and orders the complete allowed-use set.
func canonicalUses(input []datasource.ProfileUse) ([]datasource.ProfileUse, error) {
	if len(input) == 0 || len(input) > 4 {
		return nil, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	seen := make(map[datasource.ProfileUse]struct{}, len(input))
	for _, use := range input {
		if !use.Known() {
			return nil, datasource.NewError(datasource.ErrorCodeInvalidRequest)
		}
		if _, duplicate := seen[use]; duplicate {
			return nil, datasource.NewError(datasource.ErrorCodeInvalidRequest)
		}
		seen[use] = struct{}{}
	}
	output := make([]datasource.ProfileUse, 0, len(seen))
	for _, use := range []datasource.ProfileUse{
		datasource.ProfileUseOriginator,
		datasource.ProfileUseOrdinaryTransit,
		datasource.ProfileUseNextDomainTransit,
		datasource.ProfileUseDeliveryStatus,
	} {
		if _, present := seen[use]; present {
			output = append(output, use)
		}
	}
	return output, nil
}

// containsUse reports exact membership in one canonical use set.
func containsUse(uses []datasource.ProfileUse, expected datasource.ProfileUse) bool {
	return slices.Contains(uses, expected)
}

// equalUses compares two canonical use sets.
func equalUses(left, right []datasource.ProfileUse) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// cloneEntry returns a detached immutable registry entry.
func cloneEntry(input Entry) Entry {
	input.uses = append([]datasource.ProfileUse(nil), input.uses...)
	return input
}

// buildBindingGroups validates and canonicalizes per-profile entry sets.
func buildBindingGroups(
	entries map[datasource.KeyHandleID]Entry,
	limits datasource.Limits,
) (map[datasource.ProfileID]bindingGroup, error) {
	byProfile := make(map[datasource.ProfileID][]Entry, len(entries))
	for _, entry := range entries {
		byProfile[entry.profileID] = append(byProfile[entry.profileID], entry)
	}
	if len(byProfile) > limits.MaxProfiles {
		return nil, datasource.NewError(datasource.ErrorCodeLimitExceeded)
	}
	groups := make(map[datasource.ProfileID]bindingGroup, len(byProfile))
	for profileID, candidates := range byProfile {
		if len(candidates) > limits.MaxCredentialsPerProfile {
			return nil, datasource.NewError(datasource.ErrorCodeLimitExceeded)
		}
		domain := candidates[0].domain
		seenAlgorithms := make(map[datasource.Algorithm]struct{}, len(candidates))
		seenSelectors := make(map[string]struct{}, len(candidates))
		byAlgorithm := make(map[datasource.Algorithm]datasource.KeyHandleID, len(candidates))
		for _, entry := range candidates {
			if entry.domain != domain {
				return nil, datasource.NewError(datasource.ErrorCodeAmbiguous)
			}
			if _, duplicate := seenAlgorithms[entry.algorithm]; duplicate {
				return nil, datasource.NewError(datasource.ErrorCodeAmbiguous)
			}
			if _, duplicate := seenSelectors[entry.selector]; duplicate {
				return nil, datasource.NewError(datasource.ErrorCodeAmbiguous)
			}
			seenAlgorithms[entry.algorithm] = struct{}{}
			seenSelectors[entry.selector] = struct{}{}
			byAlgorithm[entry.algorithm] = entry.handleID
		}
		handles := make([]datasource.KeyHandleID, 0, len(candidates))
		for _, algorithm := range []datasource.Algorithm{
			datasource.AlgorithmRSASHA256,
			datasource.AlgorithmEd25519SHA256,
		} {
			if handleID, present := byAlgorithm[algorithm]; present {
				handles = append(handles, handleID)
			}
		}
		groups[profileID] = bindingGroup{domain: domain, handles: handles}
	}
	return groups, nil
}

// bindingGroupsEqual compares immutable derived registry groups.
func bindingGroupsEqual(
	left map[datasource.ProfileID]bindingGroup,
	right map[datasource.ProfileID]bindingGroup,
) bool {
	if len(left) != len(right) {
		return false
	}
	for profileID, leftGroup := range left {
		rightGroup, present := right[profileID]
		if !present || leftGroup.domain != rightGroup.domain ||
			len(leftGroup.handles) != len(rightGroup.handles) {
			return false
		}
		for index := range leftGroup.handles {
			if leftGroup.handles[index] != rightGroup.handles[index] {
				return false
			}
		}
	}
	return true
}
