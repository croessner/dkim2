package memory

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/datasource"
)

const memoryTestGeneration uint64 = 37

var memoryTestTime = time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC)

// TestNewRejectsInvalidAndAmbiguousSnapshots exercises constructor atomicity and closed classification.
func TestNewRejectsInvalidAndAmbiguousSnapshots(t *testing.T) {
	t.Parallel()

	fixture := newMemoryFixture(t)
	second := fixture.profileWith(t, "profile.second", "second.test", "selector-two", "handle.two",
		datasource.RecordStatusActive, time.Time{}, time.Time{})
	secondPolicy := fixture.policyWith(t, "tenant.second", "second.test",
		datasource.ProfileUseOriginator, second.ID(), datasource.RecordStatusActive,
		datasource.RolloutEnforce)
	crossDomainPolicy := fixture.policyWith(t, "tenant.cross", "other.test",
		datasource.ProfileUseOriginator, fixture.profile.ID(), datasource.RecordStatusActive,
		datasource.RolloutEnforce)
	missingProfilePolicy := fixture.policyWith(t, "tenant.missing", fixture.profile.SigningDomain(),
		datasource.ProfileUseOrdinaryTransit, mustMemoryProfileID(t, "profile.missing"),
		datasource.RecordStatusActive, datasource.RolloutEnforce)
	reusedHandleProfile := fixture.profileWithHandle(t, "profile.reused", "reused.test",
		"selector-reused", fixture.handleID)

	invalidLimits := fixture.limits
	invalidLimits.MaxProfiles = 0
	tests := []struct {
		name       string
		generation uint64
		handles    []datasource.KeyHandleID
		profiles   []datasource.Profile
		policies   []datasource.Policy
		limits     datasource.Limits
		code       datasource.ErrorCode
	}{
		{
			name: "zero generation", generation: 0, handles: fixture.handles(),
			profiles: fixture.profiles(), policies: fixture.policies(), limits: fixture.limits,
			code: datasource.ErrorCodeInvalidRequest,
		},
		{
			name: "invalid limits", generation: memoryTestGeneration, handles: fixture.handles(),
			profiles: fixture.profiles(), policies: fixture.policies(), limits: invalidLimits,
			code: datasource.ErrorCodeInvalidRequest,
		},
		{
			name: "zero handle", generation: memoryTestGeneration,
			handles: []datasource.KeyHandleID{{}}, profiles: nil, policies: nil,
			limits: fixture.limits, code: datasource.ErrorCodeMalformedData,
		},
		{
			name: "duplicate handle", generation: memoryTestGeneration,
			handles:  []datasource.KeyHandleID{fixture.handleID, fixture.handleID},
			profiles: nil, policies: nil, limits: fixture.limits,
			code: datasource.ErrorCodeAmbiguous,
		},
		{
			name: "zero profile", generation: memoryTestGeneration,
			handles: fixture.handles(), profiles: []datasource.Profile{{}},
			policies: nil, limits: fixture.limits, code: datasource.ErrorCodeMalformedData,
		},
		{
			name: "duplicate profile id", generation: memoryTestGeneration,
			handles: fixture.handles(), profiles: []datasource.Profile{fixture.profile, fixture.profile},
			policies: nil, limits: fixture.limits, code: datasource.ErrorCodeAmbiguous,
		},
		{
			name: "dangling handle", generation: memoryTestGeneration,
			handles: nil, profiles: fixture.profiles(), policies: nil,
			limits: fixture.limits, code: datasource.ErrorCodeMalformedData,
		},
		{
			name: "global handle reuse", generation: memoryTestGeneration,
			handles: fixture.handles(), profiles: []datasource.Profile{fixture.profile, reusedHandleProfile},
			policies: nil, limits: fixture.limits, code: datasource.ErrorCodeAmbiguous,
		},
		{
			name: "zero policy", generation: memoryTestGeneration,
			handles: fixture.handles(), profiles: fixture.profiles(),
			policies: []datasource.Policy{{}}, limits: fixture.limits,
			code: datasource.ErrorCodeMalformedData,
		},
		{
			name: "duplicate policy tuple", generation: memoryTestGeneration,
			handles: fixture.handles(), profiles: fixture.profiles(),
			policies: []datasource.Policy{fixture.policy, fixture.policy}, limits: fixture.limits,
			code: datasource.ErrorCodeAmbiguous,
		},
		{
			name: "missing profile reference", generation: memoryTestGeneration,
			handles: fixture.handles(), profiles: fixture.profiles(),
			policies: []datasource.Policy{missingProfilePolicy}, limits: fixture.limits,
			code: datasource.ErrorCodeMalformedData,
		},
		{
			name: "cross domain reference", generation: memoryTestGeneration,
			handles: fixture.handles(), profiles: fixture.profiles(),
			policies: []datasource.Policy{crossDomainPolicy}, limits: fixture.limits,
			code: datasource.ErrorCodeMalformedData,
		},
		{
			name: "valid independent records", generation: memoryTestGeneration,
			handles:  []datasource.KeyHandleID{fixture.handleID, second.Credentials()[0].KeyHandleID()},
			profiles: []datasource.Profile{fixture.profile, second},
			policies: []datasource.Policy{fixture.policy, secondPolicy}, limits: fixture.limits,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			provider, err := New(
				test.generation, test.handles, test.profiles, test.policies, test.limits,
			)
			if test.code == "" {
				if err != nil || provider == nil || !provider.Valid() {
					t.Fatalf("New(valid) provider=%v valid=%t error=%v",
						provider, provider != nil && provider.Valid(), err)
				}
				return
			}
			if provider != nil || datasource.ErrorCodeOf(err) != test.code {
				t.Fatalf("New(invalid) provider=%v code=%s, want nil/%s",
					provider, datasource.ErrorCodeOf(err), test.code)
			}
		})
	}
}

// TestNewEnforcesConfiguredCountAndRecordBounds verifies exact-limit acceptance and one-over rejection.
func TestNewEnforcesConfiguredCountAndRecordBounds(t *testing.T) {
	t.Parallel()

	fixture := newMemoryFixture(t)
	second := fixture.profileWith(t, "profile.second", "second.test", "selector-two", "handle.two",
		datasource.RecordStatusActive, time.Time{}, time.Time{})
	secondHandle := second.Credentials()[0].KeyHandleID()
	secondPolicy := fixture.policyWith(t, "tenant.second", "second.test",
		datasource.ProfileUseOriginator, second.ID(), datasource.RecordStatusActive,
		datasource.RolloutEnforce)
	rsaHandle := mustMemoryHandleID(t, "handle.rsa")
	rsaCredential, err := datasource.NewCredential(
		"selector-rsa", datasource.AlgorithmRSASHA256,
		memoryPublicKeySPKI(t, datasource.AlgorithmRSASHA256), rsaHandle, fixture.limits,
	)
	if err != nil {
		t.Fatalf("NewCredential(RSA) error = %v", err)
	}
	edCredential := fixture.profile.Credentials()[0]
	dualProfile, err := datasource.NewProfile(
		mustMemoryProfileID(t, "profile.dual"), "dual.test",
		datasource.RecordStatusActive, []datasource.Credential{edCredential, rsaCredential},
		time.Time{}, time.Time{}, fixture.limits,
	)
	if err != nil {
		t.Fatalf("NewProfile(dual) error = %v", err)
	}

	t.Run("exact configured counts", func(t *testing.T) {
		limits := fixture.limits
		limits.MaxProfiles = 2
		limits.MaxHandles = 2
		limits.MaxPolicies = 2
		limits.MaxRecords = 8
		provider, err := New(
			memoryTestGeneration,
			[]datasource.KeyHandleID{fixture.handleID, secondHandle},
			[]datasource.Profile{fixture.profile, second},
			[]datasource.Policy{fixture.policy, secondPolicy},
			limits,
		)
		if err != nil || provider == nil || !provider.Valid() {
			t.Fatalf("New(exact counts) provider=%v error=%v", provider, err)
		}
		usage, usageErr := provider.Usage()
		if usageErr != nil || usage.Profiles() != 2 || usage.Credentials() != 2 ||
			usage.Handles() != 2 || usage.Policies() != 2 || usage.Records() != 8 ||
			usage.Bytes() != 0 {
			t.Fatalf("Usage() = %#v, %v", usage, usageErr)
		}
	})

	t.Run("exact credentials per profile", func(t *testing.T) {
		limits := fixture.limits
		limits.MaxCredentialsPerProfile = 2
		provider, err := New(
			memoryTestGeneration,
			[]datasource.KeyHandleID{fixture.handleID, rsaHandle},
			[]datasource.Profile{dualProfile}, nil, limits,
		)
		if err != nil || provider == nil || !provider.Valid() {
			t.Fatalf("New(exact credentials) provider=%v error=%v", provider, err)
		}
	})

	tests := []struct {
		name     string
		handles  []datasource.KeyHandleID
		profiles []datasource.Profile
		policies []datasource.Policy
		limits   func(datasource.Limits) datasource.Limits
	}{
		{
			name: "profiles one over", handles: []datasource.KeyHandleID{fixture.handleID, secondHandle},
			profiles: []datasource.Profile{fixture.profile, second},
			limits: func(limits datasource.Limits) datasource.Limits {
				limits.MaxProfiles = 1
				return limits
			},
		},
		{
			name: "handles one over", handles: []datasource.KeyHandleID{fixture.handleID, secondHandle},
			limits: func(limits datasource.Limits) datasource.Limits {
				limits.MaxHandles = 1
				return limits
			},
		},
		{
			name: "policies one over", handles: fixture.handles(), profiles: fixture.profiles(),
			policies: []datasource.Policy{fixture.policy, fixture.policyWith(
				t, "tenant.second", fixture.profile.SigningDomain(),
				datasource.ProfileUseOrdinaryTransit, fixture.profile.ID(),
				datasource.RecordStatusActive, datasource.RolloutEnforce,
			)},
			limits: func(limits datasource.Limits) datasource.Limits {
				limits.MaxPolicies = 1
				return limits
			},
		},
		{
			name: "records one over", handles: fixture.handles(), profiles: fixture.profiles(),
			policies: fixture.policies(),
			limits: func(limits datasource.Limits) datasource.Limits {
				limits.MaxRecords = 3
				return limits
			},
		},
		{
			name:     "credentials per profile one over",
			handles:  []datasource.KeyHandleID{fixture.handleID, rsaHandle},
			profiles: []datasource.Profile{dualProfile},
			limits: func(limits datasource.Limits) datasource.Limits {
				limits.MaxCredentialsPerProfile = 1
				return limits
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := test.limits(fixture.limits)
			provider, err := New(
				memoryTestGeneration, test.handles, test.profiles, test.policies, limits,
			)
			if provider != nil || datasource.ErrorCodeOf(err) != datasource.ErrorCodeLimitExceeded {
				t.Fatalf("New(one over) provider=%v code=%s, want nil/%s",
					provider, datasource.ErrorCodeOf(err), datasource.ErrorCodeLimitExceeded)
			}
		})
	}
}

// TestNewEnforcesNarrowedIdentifierBounds verifies exact and one-over retained identifiers.
func TestNewEnforcesNarrowedIdentifierBounds(t *testing.T) {
	t.Parallel()

	limits := datasource.DefaultLimits()
	limits.MaxIdentifierBytes = 8
	exact := mustMemoryHandleID(t, "handle01")
	oneOver := mustMemoryHandleID(t, "handle002")
	provider, err := New(memoryTestGeneration, []datasource.KeyHandleID{exact}, nil, nil, limits)
	if err != nil || provider == nil || !provider.Valid() {
		t.Fatalf("New(exact identifier) provider=%v error=%v", provider, err)
	}
	provider, err = New(memoryTestGeneration, []datasource.KeyHandleID{oneOver}, nil, nil, limits)
	if provider != nil || datasource.ErrorCodeOf(err) != datasource.ErrorCodeLimitExceeded {
		t.Fatalf("New(one-over identifier) provider=%v code=%s",
			provider, datasource.ErrorCodeOf(err))
	}
}

// TestNewAllowsEmptyAndUnusedDeclarations proves unused opaque handles do not invalidate a static snapshot.
func TestNewAllowsEmptyAndUnusedDeclarations(t *testing.T) {
	t.Parallel()

	limits := datasource.DefaultLimits()
	unused := mustMemoryHandleID(t, "handle.unused")
	tests := []struct {
		name    string
		handles []datasource.KeyHandleID
	}{
		{name: "fully empty"},
		{name: "unused declaration", handles: []datasource.KeyHandleID{unused}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider, err := New(memoryTestGeneration, test.handles, nil, nil, limits)
			if err != nil || provider == nil || !provider.Valid() {
				t.Fatalf("New(empty) provider=%v error=%v", provider, err)
			}
			usage, usageErr := provider.Usage()
			if usageErr != nil || usage.Handles() != len(test.handles) ||
				usage.Profiles() != 0 || usage.Credentials() != 0 ||
				usage.Policies() != 0 || usage.Bytes() != 0 {
				t.Fatalf("Usage() = %#v, %v", usage, usageErr)
			}
		})
	}
}

// TestProviderResolvesExactSelfContainedResults proves exact profile and tuple selection with one generation.
func TestProviderResolvesExactSelfContainedResults(t *testing.T) {
	t.Parallel()

	fixture := newMemoryFixture(t)
	provider := fixture.provider(t)
	profileRequest := mustMemoryProfileRequest(
		t, fixture.profile.ID(), datasource.ProfileUseOriginator, memoryTestTime, fixture.limits,
	)
	resolvedProfile, err := provider.ResolveProfile(context.Background(), profileRequest)
	if err != nil || !resolvedProfile.Valid() ||
		resolvedProfile.Generation() != memoryTestGeneration ||
		resolvedProfile.ProfileID() != fixture.profile.ID() {
		t.Fatalf("ResolveProfile() result=%v error=%v", resolvedProfile, err)
	}

	policyRequest := mustMemoryPolicyRequest(
		t, fixture.policy.TenantID(), fixture.policy.SigningDomain(),
		fixture.policy.Use(), memoryTestTime, fixture.limits,
	)
	resolvedPolicy, err := provider.ResolvePolicy(context.Background(), policyRequest)
	if err != nil || !resolvedPolicy.Valid() ||
		resolvedPolicy.Generation() != memoryTestGeneration ||
		resolvedPolicy.Policy() != fixture.policy ||
		resolvedPolicy.Profile().ID() != fixture.profile.ID() {
		t.Fatalf("ResolvePolicy() result=%v error=%v", resolvedPolicy, err)
	}
	if resolvedPolicy.Generation() != resolvedProfile.Generation() {
		t.Fatalf("nested generation=%d, profile generation=%d",
			resolvedPolicy.Generation(), resolvedProfile.Generation())
	}
}

// TestProviderExactLookupNeverFallsBack verifies tenant, domain, use, and profile identity are exact.
func TestProviderExactLookupNeverFallsBack(t *testing.T) {
	t.Parallel()

	fixture := newMemoryFixture(t)
	provider := fixture.provider(t)
	profileMissing := mustMemoryProfileRequest(
		t, mustMemoryProfileID(t, "profile.absent"), datasource.ProfileUseOriginator,
		memoryTestTime, fixture.limits,
	)
	assertMemoryProfileError(
		context.Background(), t, provider, profileMissing, datasource.ErrorCodeNotFound,
	)

	tests := []datasource.PolicyRequest{
		mustMemoryPolicyRequest(t, mustMemoryTenantID(t, "tenant.absent"),
			fixture.policy.SigningDomain(), fixture.policy.Use(), memoryTestTime, fixture.limits),
		mustMemoryPolicyRequest(t, fixture.policy.TenantID(), "sub."+fixture.policy.SigningDomain(),
			fixture.policy.Use(), memoryTestTime, fixture.limits),
		mustMemoryPolicyRequest(t, fixture.policy.TenantID(), fixture.policy.SigningDomain(),
			datasource.ProfileUseOrdinaryTransit, memoryTestTime, fixture.limits),
	}
	for _, request := range tests {
		assertMemoryPolicyError(
			context.Background(), t, provider, request, datasource.ErrorCodeNotFound,
		)
	}
}

// TestProviderAppliesProfileStateAndPreservesNonEnforcePolicySuccess checks the provider/adaptor role split.
func TestProviderAppliesProfileStateAndPreservesNonEnforcePolicySuccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		profileStatus datasource.RecordStatus
		notBefore     time.Time
		notAfter      time.Time
		at            time.Time
		policyStatus  datasource.RecordStatus
		rollout       datasource.Rollout
		profileCode   datasource.ErrorCode
		policyCode    datasource.ErrorCode
	}{
		{
			name: "window start inclusive", profileStatus: datasource.RecordStatusActive,
			notBefore: memoryTestTime, notAfter: memoryTestTime.Add(time.Hour),
			at: memoryTestTime, policyStatus: datasource.RecordStatusActive,
			rollout: datasource.RolloutEnforce,
		},
		{
			name: "window end exclusive", profileStatus: datasource.RecordStatusActive,
			notBefore: memoryTestTime, notAfter: memoryTestTime.Add(time.Hour),
			at: memoryTestTime.Add(time.Hour), policyStatus: datasource.RecordStatusActive,
			rollout:     datasource.RolloutEnforce,
			profileCode: datasource.ErrorCodeInactive, policyCode: datasource.ErrorCodeInactive,
		},
		{
			name: "before window", profileStatus: datasource.RecordStatusActive,
			notBefore: memoryTestTime, notAfter: memoryTestTime.Add(time.Hour),
			at: memoryTestTime.Add(-time.Nanosecond), policyStatus: datasource.RecordStatusActive,
			rollout:     datasource.RolloutEnforce,
			profileCode: datasource.ErrorCodeInactive, policyCode: datasource.ErrorCodeInactive,
		},
		{
			name: "disabled profile", profileStatus: datasource.RecordStatusDisabled,
			at: memoryTestTime, policyStatus: datasource.RecordStatusActive,
			rollout:     datasource.RolloutEnforce,
			profileCode: datasource.ErrorCodeInactive, policyCode: datasource.ErrorCodeInactive,
		},
		{
			name: "disabled policy", profileStatus: datasource.RecordStatusActive,
			at: memoryTestTime, policyStatus: datasource.RecordStatusDisabled,
			rollout: datasource.RolloutEnforce, policyCode: datasource.ErrorCodeInactive,
		},
		{
			name: "observe is provider success", profileStatus: datasource.RecordStatusActive,
			at: memoryTestTime, policyStatus: datasource.RecordStatusActive,
			rollout: datasource.RolloutObserve,
		},
		{
			name: "off is provider success", profileStatus: datasource.RecordStatusActive,
			at: memoryTestTime, policyStatus: datasource.RecordStatusActive,
			rollout: datasource.RolloutOff,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMemoryFixtureWithState(
				t, test.profileStatus, test.notBefore, test.notAfter,
				test.policyStatus, test.rollout,
			)
			provider := fixture.provider(t)
			profileRequest := mustMemoryProfileRequest(
				t, fixture.profile.ID(), fixture.policy.Use(), test.at, fixture.limits,
			)
			profileResult, profileErr := provider.ResolveProfile(
				context.Background(), profileRequest,
			)
			if test.profileCode == "" {
				if profileErr != nil || !profileResult.Valid() {
					t.Fatalf("ResolveProfile() result=%v error=%v", profileResult, profileErr)
				}
			} else {
				assertMemoryProfileFailure(
					t, profileResult, profileErr, test.profileCode, nil,
				)
			}
			policyRequest := mustMemoryPolicyRequest(
				t, fixture.policy.TenantID(), fixture.policy.SigningDomain(),
				fixture.policy.Use(), test.at, fixture.limits,
			)
			result, err := provider.ResolvePolicy(context.Background(), policyRequest)
			if test.policyCode == "" {
				if err != nil || !result.Valid() || result.Policy().Rollout() != test.rollout {
					t.Fatalf("ResolvePolicy() result=%v error=%v", result, err)
				}
				return
			}
			if result.Valid() || result.Generation() != 0 ||
				datasource.ErrorCodeOf(err) != test.policyCode {
				t.Fatalf("ResolvePolicy() valid=%t generation=%d code=%s, want zero/%s",
					result.Valid(), result.Generation(), datasource.ErrorCodeOf(err), test.policyCode)
			}
		})
	}
}

// TestProviderRejectsInvalidContextsAndRequests checks bounded preflight and context identity.
func TestProviderRejectsInvalidContextsAndRequests(t *testing.T) {
	t.Parallel()

	fixture := newMemoryFixture(t)
	provider := fixture.provider(t)
	validProfile := mustMemoryProfileRequest(
		t, fixture.profile.ID(), fixture.policy.Use(), memoryTestTime, fixture.limits,
	)
	validPolicy := mustMemoryPolicyRequest(
		t, fixture.policy.TenantID(), fixture.policy.SigningDomain(),
		fixture.policy.Use(), memoryTestTime, fixture.limits,
	)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), memoryTestTime.Add(-time.Hour))
	defer stop()
	var typedNil *memoryNilContext

	contexts := []struct {
		name string
		ctx  context.Context
		code datasource.ErrorCode
		is   error
	}{
		{name: "nil", ctx: nil, code: datasource.ErrorCodeInvalidRequest},
		{name: "typed nil", ctx: typedNil, code: datasource.ErrorCodeInvalidRequest},
		{name: "cancelled", ctx: cancelled, code: datasource.ErrorCodeCancelled, is: context.Canceled},
		{name: "deadline", ctx: expired, code: datasource.ErrorCodeDeadlineExceeded, is: context.DeadlineExceeded},
	}
	for _, test := range contexts {
		t.Run(test.name, func(t *testing.T) {
			profileResult, profileErr := provider.ResolveProfile(test.ctx, validProfile)
			assertMemoryProfileFailure(t, profileResult, profileErr, test.code, test.is)
			policyResult, policyErr := provider.ResolvePolicy(test.ctx, validPolicy)
			assertMemoryPolicyFailure(t, policyResult, policyErr, test.code, test.is)
		})
	}

	for _, test := range []struct {
		name     string
		terminal error
		code     datasource.ErrorCode
	}{
		{name: "post lookup cancelled", terminal: context.Canceled, code: datasource.ErrorCodeCancelled},
		{name: "post lookup deadline", terminal: context.DeadlineExceeded, code: datasource.ErrorCodeDeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			profileContext := &memoryStagedContext{terminal: test.terminal}
			profileResult, profileErr := provider.ResolveProfile(profileContext, validProfile)
			assertMemoryProfileFailure(
				t, profileResult, profileErr, test.code, test.terminal,
			)
			policyContext := &memoryStagedContext{terminal: test.terminal}
			policyResult, policyErr := provider.ResolvePolicy(policyContext, validPolicy)
			assertMemoryPolicyFailure(
				t, policyResult, policyErr, test.code, test.terminal,
			)
		})
	}

	t.Run("hostile context panic", func(t *testing.T) {
		profileResult, profileErr := provider.ResolveProfile(memoryPanicContext{}, validProfile)
		assertMemoryProfileFailure(
			t, profileResult, profileErr, datasource.ErrorCodeInternalInvariant, nil,
		)
		policyResult, policyErr := provider.ResolvePolicy(memoryPanicContext{}, validPolicy)
		assertMemoryPolicyFailure(
			t, policyResult, policyErr, datasource.ErrorCodeInternalInvariant, nil,
		)
	})

	t.Run("zero request", func(t *testing.T) {
		assertMemoryProfileError(
			context.Background(), t, provider, datasource.ProfileRequest{},
			datasource.ErrorCodeInvalidRequest,
		)
		assertMemoryPolicyError(
			context.Background(), t, provider, datasource.PolicyRequest{},
			datasource.ErrorCodeInvalidRequest,
		)
	})

	t.Run("over retained request", func(t *testing.T) {
		narrow := fixture.limits
		narrow.MaxIdentifierBytes = 8
		narrowProvider, err := New(
			memoryTestGeneration, nil, nil, nil, narrow,
		)
		if err != nil {
			t.Fatalf("New(narrow) error = %v", err)
		}
		profileRequest := mustMemoryProfileRequest(
			t, mustMemoryProfileID(t, "profile.identifier.too.long"),
			datasource.ProfileUseOriginator, memoryTestTime, datasource.DefaultLimits(),
		)
		policyRequest := mustMemoryPolicyRequest(
			t, mustMemoryTenantID(t, "tenant.identifier.too.long"), "example.test",
			datasource.ProfileUseOriginator, memoryTestTime, datasource.DefaultLimits(),
		)
		assertMemoryProfileError(
			context.Background(), t, narrowProvider, profileRequest,
			datasource.ErrorCodeLimitExceeded,
		)
		assertMemoryPolicyError(
			context.Background(), t, narrowProvider, policyRequest,
			datasource.ErrorCodeLimitExceeded,
		)
	})
}

// TestProviderOwnsInputsAndDetachesResults proves no caller-owned mutable bytes or slices cross the snapshot.
func TestProviderOwnsInputsAndDetachesResults(t *testing.T) {
	t.Parallel()

	fixture := newMemoryFixture(t)
	handles := fixture.handles()
	profiles := fixture.profiles()
	policies := fixture.policies()
	provider, err := New(memoryTestGeneration, handles, profiles, policies, fixture.limits)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	handles[0] = mustMemoryHandleID(t, "handle.mutated")
	profiles[0] = datasource.Profile{}
	policies[0] = datasource.Policy{}

	request := mustMemoryProfileRequest(
		t, fixture.profile.ID(), fixture.policy.Use(), memoryTestTime, fixture.limits,
	)
	first, err := provider.ResolveProfile(context.Background(), request)
	if err != nil {
		t.Fatalf("ResolveProfile(first) error = %v", err)
	}
	firstDER := first.Profile().Credentials()[0].PublicKeySPKIDER()
	expectedDER := bytes.Clone(firstDER)
	firstDER[0] ^= 0xff
	credentials := first.Profile().Credentials()
	credentials[0] = datasource.Credential{}

	second, err := provider.ResolveProfile(context.Background(), request)
	if err != nil {
		t.Fatalf("ResolveProfile(second) error = %v", err)
	}
	if !bytes.Equal(second.Profile().Credentials()[0].PublicKeySPKIDER(), expectedDER) ||
		second.ProfileID() != fixture.profile.ID() ||
		second.Generation() != first.Generation() {
		t.Fatal("caller mutation changed a later immutable result")
	}
}

// TestProviderIsDeterministicAndConcurrent exercises lock-free independent reads and detached mutations.
func TestProviderIsDeterministicAndConcurrent(t *testing.T) {
	t.Parallel()

	fixture := newMemoryFixture(t)
	second := fixture.profileWith(t, "profile.second", "second.test", "selector-two", "handle.two",
		datasource.RecordStatusActive, time.Time{}, time.Time{})
	secondPolicy := fixture.policyWith(t, "tenant.second", second.SigningDomain(),
		datasource.ProfileUseOrdinaryTransit, second.ID(), datasource.RecordStatusActive,
		datasource.RolloutEnforce)
	handles := []datasource.KeyHandleID{fixture.handleID, second.Credentials()[0].KeyHandleID()}
	profiles := []datasource.Profile{fixture.profile, second}
	policies := []datasource.Policy{fixture.policy, secondPolicy}
	provider, err := New(
		memoryTestGeneration,
		handles,
		profiles,
		policies,
		fixture.limits,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	profileRequests := []datasource.ProfileRequest{
		mustMemoryProfileRequest(t, fixture.profile.ID(), fixture.policy.Use(), memoryTestTime, fixture.limits),
		mustMemoryProfileRequest(t, second.ID(), secondPolicy.Use(), memoryTestTime, fixture.limits),
	}
	policyRequests := []datasource.PolicyRequest{
		mustMemoryPolicyRequest(t, fixture.policy.TenantID(), fixture.policy.SigningDomain(),
			fixture.policy.Use(), memoryTestTime, fixture.limits),
		mustMemoryPolicyRequest(t, secondPolicy.TenantID(), secondPolicy.SigningDomain(),
			secondPolicy.Use(), memoryTestTime, fixture.limits),
	}

	const workers = 64
	const iterations = 50
	var wait sync.WaitGroup
	errorsFound := make(chan string, workers)
	start := make(chan struct{})
	for worker := range workers {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			profileRequest := profileRequests[index%len(profileRequests)]
			policyRequest := policyRequests[index%len(policyRequests)]
			for iteration := range iterations {
				profileResult, profileErr := provider.ResolveProfile(
					context.Background(), profileRequest,
				)
				if profileErr != nil || !profileResult.Valid() ||
					profileResult.Generation() != memoryTestGeneration ||
					profileResult.ProfileID() != profileRequest.ProfileID() ||
					profileResult.Profile().SigningDomain() !=
						policyRequests[index%len(policyRequests)].SigningDomain() {
					errorsFound <- "profile"
					return
				}
				der := profileResult.Profile().Credentials()[0].PublicKeySPKIDER()
				der[0] ^= byte(iteration)
				policyResult, policyErr := provider.ResolvePolicy(
					context.Background(), policyRequest,
				)
				if policyErr != nil || !policyResult.Valid() ||
					policyResult.Generation() != memoryTestGeneration ||
					policyResult.Policy().TenantID() != policyRequest.TenantID() ||
					policyResult.Policy().ProfileID() != profileRequest.ProfileID() ||
					policyResult.Profile().ID() != profileRequest.ProfileID() {
					errorsFound <- "policy"
					return
				}
			}
		}(worker)
	}
	wait.Go(func() {
		<-start
		handles[0] = datasource.KeyHandleID{}
		profiles[0] = datasource.Profile{}
		policies[0] = datasource.Policy{}
	})
	close(start)
	wait.Wait()
	close(errorsFound)
	for failure := range errorsFound {
		t.Fatalf("concurrent %s lookup failed", failure)
	}
}

// TestProviderFailsClosedOnImpossibleReceiverState verifies corrupt snapshots cannot produce partial success.
func TestProviderFailsClosedOnImpossibleReceiverState(t *testing.T) {
	t.Parallel()

	fixture := newMemoryFixture(t)
	profileRequest := mustMemoryProfileRequest(
		t, fixture.profile.ID(), fixture.policy.Use(), memoryTestTime, fixture.limits,
	)
	policyRequest := mustMemoryPolicyRequest(
		t, fixture.policy.TenantID(), fixture.policy.SigningDomain(),
		fixture.policy.Use(), memoryTestTime, fixture.limits,
	)
	var nilContext context.Context
	providers := []*Provider{nil, {}, {snapshot: &snapshot{}, complete: true}}
	for _, provider := range providers {
		assertMemoryProfileError(
			context.Background(), t, provider, profileRequest,
			datasource.ErrorCodeInternalInvariant,
		)
		assertMemoryPolicyError(
			context.Background(), t, provider, policyRequest,
			datasource.ErrorCodeInternalInvariant,
		)
		if usage, err := provider.Usage(); usage.Records() != 0 ||
			datasource.ErrorCodeOf(err) != datasource.ErrorCodeInternalInvariant {
			t.Fatalf("Usage(corrupt) records=%d code=%s",
				usage.Records(), datasource.ErrorCodeOf(err))
		}
		assertMemoryProfileError(
			nilContext, t, provider, profileRequest, datasource.ErrorCodeInvalidRequest,
		)
		assertMemoryPolicyError(
			nilContext, t, provider, policyRequest, datasource.ErrorCodeInvalidRequest,
		)
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		profileResult, profileErr := provider.ResolveProfile(cancelled, profileRequest)
		assertMemoryProfileFailure(
			t, profileResult, profileErr, datasource.ErrorCodeCancelled, context.Canceled,
		)
		policyResult, policyErr := provider.ResolvePolicy(cancelled, policyRequest)
		assertMemoryPolicyFailure(
			t, policyResult, policyErr, datasource.ErrorCodeCancelled, context.Canceled,
		)
		expired, stop := context.WithDeadline(
			context.Background(), memoryTestTime.Add(-time.Hour),
		)
		profileResult, profileErr = provider.ResolveProfile(expired, profileRequest)
		assertMemoryProfileFailure(
			t, profileResult, profileErr,
			datasource.ErrorCodeDeadlineExceeded, context.DeadlineExceeded,
		)
		policyResult, policyErr = provider.ResolvePolicy(expired, policyRequest)
		assertMemoryPolicyFailure(
			t, policyResult, policyErr,
			datasource.ErrorCodeDeadlineExceeded, context.DeadlineExceeded,
		)
		stop()
	}
}

// TestProviderFailsClosedOnCorruptTargetFacts verifies O(1) trust-boundary invariant checks.
func TestProviderFailsClosedOnCorruptTargetFacts(t *testing.T) {
	t.Parallel()

	fixture := newMemoryFixture(t)
	profileRequest := mustMemoryProfileRequest(
		t, fixture.profile.ID(), fixture.policy.Use(), memoryTestTime, fixture.limits,
	)
	policyRequest := mustMemoryPolicyRequest(
		t, fixture.policy.TenantID(), fixture.policy.SigningDomain(),
		fixture.policy.Use(), memoryTestTime, fixture.limits,
	)

	t.Run("profile index identity mismatch", func(t *testing.T) {
		provider := fixture.provider(t)
		other := fixture.profileWith(
			t, "profile.other", "other.test", "selector-other", "handle.other",
			datasource.RecordStatusActive, time.Time{}, time.Time{},
		)
		resolved, err := datasource.NewResolvedProfile(memoryTestGeneration, other)
		if err != nil {
			t.Fatal("failed to construct profile corruption fixture")
		}
		provider.snapshot.profiles[fixture.profile.ID()] = resolved
		assertMemoryProfileError(
			context.Background(), t, provider, profileRequest,
			datasource.ErrorCodeInternalInvariant,
		)
	})

	t.Run("profile generation mismatch", func(t *testing.T) {
		provider := fixture.provider(t)
		resolved, err := datasource.NewResolvedProfile(memoryTestGeneration+1, fixture.profile)
		if err != nil {
			t.Fatal("failed to construct generation corruption fixture")
		}
		provider.snapshot.profiles[fixture.profile.ID()] = resolved
		assertMemoryProfileError(
			context.Background(), t, provider, profileRequest,
			datasource.ErrorCodeInternalInvariant,
		)
	})

	t.Run("undeclared target handle", func(t *testing.T) {
		provider := fixture.provider(t)
		delete(provider.snapshot.handles, fixture.handleID)
		assertMemoryProfileError(
			context.Background(), t, provider, profileRequest,
			datasource.ErrorCodeInternalInvariant,
		)
	})

	t.Run("corrupt usage header", func(t *testing.T) {
		provider := fixture.provider(t)
		provider.snapshot.usage = datasource.Usage{}
		assertMemoryProfileError(
			context.Background(), t, provider, profileRequest,
			datasource.ErrorCodeInternalInvariant,
		)
		assertMemoryPolicyError(
			context.Background(), t, provider, policyRequest,
			datasource.ErrorCodeInternalInvariant,
		)
	})

	t.Run("policy tuple mismatch", func(t *testing.T) {
		provider := fixture.provider(t)
		otherPolicy := mustMemoryPolicy(
			t, "tenant.other", fixture.policy.SigningDomain(), fixture.policy.Use(),
			fixture.profile.ID(), datasource.RecordStatusActive,
			datasource.RolloutEnforce, fixture.limits,
		)
		key := policyKey{
			tenant: fixture.policy.TenantID(),
			domain: fixture.policy.SigningDomain(),
			use:    fixture.policy.Use(),
		}
		provider.snapshot.policies[key] = otherPolicy
		assertMemoryPolicyError(
			context.Background(), t, provider, policyRequest,
			datasource.ErrorCodeInternalInvariant,
		)
	})

	t.Run("missing bound profile", func(t *testing.T) {
		provider := fixture.provider(t)
		delete(provider.snapshot.profiles, fixture.profile.ID())
		assertMemoryPolicyError(
			context.Background(), t, provider, policyRequest,
			datasource.ErrorCodeInternalInvariant,
		)
	})

	t.Run("cross domain bound profile", func(t *testing.T) {
		provider := fixture.provider(t)
		otherDomain := mustMemoryProfile(
			t, "profile.example", "other.test", "selector-other", fixture.handleID,
			datasource.RecordStatusActive, time.Time{}, time.Time{}, fixture.limits,
		)
		resolved, err := datasource.NewResolvedProfile(memoryTestGeneration, otherDomain)
		if err != nil {
			t.Fatal("failed to construct domain corruption fixture")
		}
		provider.snapshot.profiles[fixture.profile.ID()] = resolved
		assertMemoryPolicyError(
			context.Background(), t, provider, policyRequest,
			datasource.ErrorCodeInternalInvariant,
		)
	})

	t.Run("disabled policy cannot mask missing profile", func(t *testing.T) {
		disabled := newMemoryFixtureWithState(
			t, datasource.RecordStatusActive, time.Time{}, time.Time{},
			datasource.RecordStatusDisabled, datasource.RolloutEnforce,
		)
		provider := disabled.provider(t)
		request := mustMemoryPolicyRequest(
			t, disabled.policy.TenantID(), disabled.policy.SigningDomain(),
			disabled.policy.Use(), memoryTestTime, disabled.limits,
		)
		delete(provider.snapshot.profiles, disabled.profile.ID())
		assertMemoryPolicyError(
			context.Background(), t, provider, request,
			datasource.ErrorCodeInternalInvariant,
		)
	})
}

// TestProviderFormattingAndJSONDoNotExposeSnapshotFacts proves generic representations stay constant.
func TestProviderFormattingAndJSONDoNotExposeSnapshotFacts(t *testing.T) {
	t.Parallel()

	const marker = "memory-private-marker"
	fixture := newMemoryFixtureWithMarker(t, marker)
	provider := fixture.provider(t)
	for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
		rendered := fmt.Sprintf(format, provider)
		if strings.Contains(rendered, marker) || rendered != "memory.Provider{redacted}" {
			t.Fatalf("provider format %q exposed or changed protected output", format)
		}
	}
	encoded, err := json.Marshal(provider)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.Contains(string(encoded), marker) {
		t.Fatal("JSON exposed a protected snapshot fact")
	}

	request := mustMemoryProfileRequest(
		t, mustMemoryProfileID(t, "profile.absent."+marker),
		datasource.ProfileUseOriginator, memoryTestTime, fixture.limits,
	)
	_, resolveErr := provider.ResolveProfile(context.Background(), request)
	if strings.Contains(fmt.Sprintf("%v", resolveErr), marker) ||
		fmt.Sprint(resolveErr) != string(datasource.ErrorCodeNotFound) {
		t.Fatal("provider error exposed protected facts")
	}
}

// memoryFixture owns one valid deterministic provider input set.
type memoryFixture struct {
	limits   datasource.Limits
	handleID datasource.KeyHandleID
	profile  datasource.Profile
	policy   datasource.Policy
}

// newMemoryFixture constructs the standard active enforce fixture.
func newMemoryFixture(t *testing.T) memoryFixture {
	t.Helper()
	return newMemoryFixtureWithMarker(t, "example")
}

// newMemoryFixtureWithMarker constructs one valid fixture containing a protected marker.
func newMemoryFixtureWithMarker(t *testing.T, marker string) memoryFixture {
	t.Helper()
	limits := datasource.DefaultLimits()
	handleID := mustMemoryHandleID(t, "handle."+marker)
	profile := mustMemoryProfile(
		t, "profile."+marker, marker+".test", "selector-"+marker, handleID,
		datasource.RecordStatusActive, time.Time{}, time.Time{}, limits,
	)
	policy := mustMemoryPolicy(
		t, "tenant."+marker, profile.SigningDomain(), datasource.ProfileUseOriginator,
		profile.ID(), datasource.RecordStatusActive, datasource.RolloutEnforce, limits,
	)
	return memoryFixture{limits: limits, handleID: handleID, profile: profile, policy: policy}
}

// newMemoryFixtureWithState constructs one fixture for status, rollout, and window tests.
func newMemoryFixtureWithState(
	t *testing.T,
	profileStatus datasource.RecordStatus,
	notBefore time.Time,
	notAfter time.Time,
	policyStatus datasource.RecordStatus,
	rollout datasource.Rollout,
) memoryFixture {
	t.Helper()
	fixture := newMemoryFixture(t)
	fixture.profile = mustMemoryProfile(
		t, "profile.example", "example.test", "selector-example", fixture.handleID,
		profileStatus, notBefore, notAfter, fixture.limits,
	)
	fixture.policy = mustMemoryPolicy(
		t, "tenant.example", fixture.profile.SigningDomain(), datasource.ProfileUseOriginator,
		fixture.profile.ID(), policyStatus, rollout, fixture.limits,
	)
	return fixture
}

// handles returns a detached handle declaration slice.
func (f memoryFixture) handles() []datasource.KeyHandleID {
	return []datasource.KeyHandleID{f.handleID}
}

// profiles returns a detached profile declaration slice.
func (f memoryFixture) profiles() []datasource.Profile {
	return []datasource.Profile{f.profile}
}

// policies returns a detached policy declaration slice.
func (f memoryFixture) policies() []datasource.Policy {
	return []datasource.Policy{f.policy}
}

// provider constructs the fixture's validated provider.
func (f memoryFixture) provider(t *testing.T) *Provider {
	t.Helper()
	provider, err := New(
		memoryTestGeneration, f.handles(), f.profiles(), f.policies(), f.limits,
	)
	if err != nil || provider == nil || !provider.Valid() {
		t.Fatalf("New() provider=%v error=%v", provider, err)
	}
	return provider
}

// profileWith constructs one independent profile from fixture limits.
func (f memoryFixture) profileWith(
	t *testing.T,
	id string,
	domain string,
	selector string,
	handle string,
	status datasource.RecordStatus,
	notBefore time.Time,
	notAfter time.Time,
) datasource.Profile {
	t.Helper()
	return mustMemoryProfile(
		t, id, domain, selector, mustMemoryHandleID(t, handle), status,
		notBefore, notAfter, f.limits,
	)
}

// profileWithHandle constructs one independent profile that reuses an opaque handle ID.
func (f memoryFixture) profileWithHandle(
	t *testing.T,
	id string,
	domain string,
	selector string,
	handle datasource.KeyHandleID,
) datasource.Profile {
	t.Helper()
	return mustMemoryProfile(
		t, id, domain, selector, handle, datasource.RecordStatusActive,
		time.Time{}, time.Time{}, f.limits,
	)
}

// policyWith constructs one exact policy from fixture limits.
func (f memoryFixture) policyWith(
	t *testing.T,
	tenant string,
	domain string,
	use datasource.ProfileUse,
	profileID datasource.ProfileID,
	status datasource.RecordStatus,
	rollout datasource.Rollout,
) datasource.Policy {
	t.Helper()
	return mustMemoryPolicy(
		t, tenant, domain, use, profileID, status, rollout, f.limits,
	)
}

// mustMemoryProfile constructs one complete deterministic Ed25519 profile.
func mustMemoryProfile(
	t *testing.T,
	id string,
	domain string,
	selector string,
	handleID datasource.KeyHandleID,
	status datasource.RecordStatus,
	notBefore time.Time,
	notAfter time.Time,
	limits datasource.Limits,
) datasource.Profile {
	t.Helper()
	credential, err := datasource.NewCredential(
		selector, datasource.AlgorithmEd25519SHA256,
		memoryPublicKeySPKI(t, datasource.AlgorithmEd25519SHA256),
		handleID, limits,
	)
	if err != nil {
		t.Fatalf("NewCredential() error = %v", err)
	}
	profile, err := datasource.NewProfile(
		mustMemoryProfileID(t, id), domain, status, []datasource.Credential{credential},
		notBefore, notAfter, limits,
	)
	if err != nil {
		t.Fatalf("NewProfile() error = %v", err)
	}
	return profile
}

// mustMemoryPolicy constructs one strict exact administrative policy.
func mustMemoryPolicy(
	t *testing.T,
	tenant string,
	domain string,
	use datasource.ProfileUse,
	profileID datasource.ProfileID,
	status datasource.RecordStatus,
	rollout datasource.Rollout,
	limits datasource.Limits,
) datasource.Policy {
	t.Helper()
	policy, err := datasource.NewPolicy(
		mustMemoryTenantID(t, tenant), domain, use, profileID, status, rollout,
		datasource.CompatibilityStrict, datasource.FeedbackRouteID{}, limits,
	)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	return policy
}

// mustMemoryProfileID constructs one valid profile identifier.
func mustMemoryProfileID(t *testing.T, value string) datasource.ProfileID {
	t.Helper()
	id, err := datasource.NewProfileID(value)
	if err != nil {
		t.Fatalf("NewProfileID() error = %v", err)
	}
	return id
}

// mustMemoryHandleID constructs one valid handle identifier.
func mustMemoryHandleID(t *testing.T, value string) datasource.KeyHandleID {
	t.Helper()
	id, err := datasource.NewKeyHandleID(value)
	if err != nil {
		t.Fatalf("NewKeyHandleID() error = %v", err)
	}
	return id
}

// mustMemoryTenantID constructs one valid tenant identifier.
func mustMemoryTenantID(t *testing.T, value string) datasource.TenantID {
	t.Helper()
	id, err := datasource.NewTenantID(value)
	if err != nil {
		t.Fatalf("NewTenantID() error = %v", err)
	}
	return id
}

// mustMemoryProfileRequest constructs one valid profile lookup request.
func mustMemoryProfileRequest(
	t *testing.T,
	profileID datasource.ProfileID,
	use datasource.ProfileUse,
	at time.Time,
	limits datasource.Limits,
) datasource.ProfileRequest {
	t.Helper()
	request, err := datasource.NewProfileRequest(profileID, use, at, limits)
	if err != nil {
		t.Fatalf("NewProfileRequest() error = %v", err)
	}
	return request
}

// mustMemoryPolicyRequest constructs one valid exact policy lookup request.
func mustMemoryPolicyRequest(
	t *testing.T,
	tenant datasource.TenantID,
	domain string,
	use datasource.ProfileUse,
	at time.Time,
	limits datasource.Limits,
) datasource.PolicyRequest {
	t.Helper()
	request, err := datasource.NewPolicyRequest(tenant, domain, use, at, limits)
	if err != nil {
		t.Fatalf("NewPolicyRequest() error = %v", err)
	}
	return request
}

// memoryPublicKeySPKI returns deterministic valid public-key DER.
func memoryPublicKeySPKI(t *testing.T, algorithm datasource.Algorithm) []byte {
	t.Helper()
	var publicKey any
	switch algorithm {
	case datasource.AlgorithmRSASHA256:
		modulus := new(big.Int).Lsh(big.NewInt(1), 2047)
		modulus.Add(modulus, big.NewInt(0x31))
		publicKey = &rsa.PublicKey{N: modulus, E: 65537}
	case datasource.AlgorithmEd25519SHA256:
		publicKey = ed25519.PublicKey(bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize))
	default:
		t.Fatal("unsupported test algorithm")
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	return der
}

// assertMemoryProfileError verifies one zero-result typed profile failure.
func assertMemoryProfileError(
	ctx context.Context,
	t *testing.T,
	provider *Provider,
	request datasource.ProfileRequest,
	code datasource.ErrorCode,
) {
	t.Helper()
	result, err := provider.ResolveProfile(ctx, request)
	assertMemoryProfileFailure(t, result, err, code, nil)
}

// assertMemoryPolicyError verifies one zero-result typed policy failure.
func assertMemoryPolicyError(
	ctx context.Context,
	t *testing.T,
	provider *Provider,
	request datasource.PolicyRequest,
	code datasource.ErrorCode,
) {
	t.Helper()
	result, err := provider.ResolvePolicy(ctx, request)
	assertMemoryPolicyFailure(t, result, err, code, nil)
}

// assertMemoryProfileFailure verifies one closed profile result/error pair.
func assertMemoryProfileFailure(
	t *testing.T,
	result datasource.ResolvedProfile,
	err error,
	code datasource.ErrorCode,
	identity error,
) {
	t.Helper()
	if result.Valid() || result.Generation() != 0 ||
		datasource.ErrorCodeOf(err) != code ||
		datasource.ValidateProfileOutcome(result, err) != nil {
		t.Fatalf("profile failure valid=%t generation=%d code=%s, want zero/%s",
			result.Valid(), result.Generation(), datasource.ErrorCodeOf(err), code)
	}
	if identity != nil && !errors.Is(err, identity) {
		t.Fatalf("profile failure errors.Is(%v) = false", identity)
	}
}

// assertMemoryPolicyFailure verifies one closed policy result/error pair.
func assertMemoryPolicyFailure(
	t *testing.T,
	result datasource.ResolvedPolicy,
	err error,
	code datasource.ErrorCode,
	identity error,
) {
	t.Helper()
	if result.Valid() || result.Generation() != 0 ||
		datasource.ErrorCodeOf(err) != code ||
		datasource.ValidatePolicyOutcome(result, err) != nil {
		t.Fatalf("policy failure valid=%t generation=%d code=%s, want zero/%s",
			result.Valid(), result.Generation(), datasource.ErrorCodeOf(err), code)
	}
	if identity != nil && !errors.Is(err, identity) {
		t.Fatalf("policy failure errors.Is(%v) = false", identity)
	}
}

// memoryNilContext is a typed-nil context that must never be invoked.
type memoryNilContext struct{}

// Deadline panics if typed-nil detection fails.
func (*memoryNilContext) Deadline() (time.Time, bool) { panic("typed-nil context invoked") }

// Done panics if typed-nil detection fails.
func (*memoryNilContext) Done() <-chan struct{} { panic("typed-nil context invoked") }

// Err panics if typed-nil detection fails.
func (*memoryNilContext) Err() error { panic("typed-nil context invoked") }

// Value panics if typed-nil detection fails.
func (*memoryNilContext) Value(any) any { panic("typed-nil context invoked") }

// memoryStagedContext changes from active to one terminal state on its second observation.
type memoryStagedContext struct {
	calls    int
	terminal error
}

// Deadline reports no wall-clock deadline for the deterministic staged context.
func (*memoryStagedContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done exposes no channel because tests control state through Err observations.
func (*memoryStagedContext) Done() <-chan struct{} { return nil }

// Err returns active once and the configured terminal state thereafter.
func (c *memoryStagedContext) Err() error {
	c.calls++
	if c.calls == 1 {
		return nil
	}
	return c.terminal
}

// Value returns no context value.
func (*memoryStagedContext) Value(any) any { return nil }

// memoryPanicContext is a hostile nonnil context whose Err method panics.
type memoryPanicContext struct{}

// Deadline reports no deadline without panicking.
func (memoryPanicContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done returns no channel without panicking.
func (memoryPanicContext) Done() <-chan struct{} { return nil }

// Err panics to exercise the datasource context trust boundary.
func (memoryPanicContext) Err() error { panic("hostile context") }

// Value returns no context value.
func (memoryPanicContext) Value(any) any { return nil }
