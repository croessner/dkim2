package signingprofile

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/datasource"
	"github.com/croessner/dkim2/internal/datasource/flatfile"
	"github.com/croessner/dkim2/internal/datasource/memory"
	"github.com/croessner/dkim2/internal/signing"
)

const (
	adapterProfilePath        = "profile"
	adapterPolicyPath         = "policy"
	adapterMemoryProviderName = "memory"
	adapterFlatProviderName   = "flat"
	adapterSigningDomain      = "example.test"
	adapterFixturePath        = "../flatfile/testdata/valid-v1.json"
)

type adapterProvider struct {
	resolveProfile func(context.Context, datasource.ProfileRequest) (datasource.ResolvedProfile, error)
	resolvePolicy  func(context.Context, datasource.PolicyRequest) (datasource.ResolvedPolicy, error)
}

// ResolveProfile delegates one controlled adapter test lookup.
func (p *adapterProvider) ResolveProfile(
	ctx context.Context,
	request datasource.ProfileRequest,
) (datasource.ResolvedProfile, error) {
	if p.resolveProfile == nil {
		return datasource.ResolvedProfile{}, datasource.NewError(datasource.ErrorCodeNotFound)
	}
	return p.resolveProfile(ctx, request)
}

// ResolvePolicy delegates one controlled adapter test lookup.
func (p *adapterProvider) ResolvePolicy(
	ctx context.Context,
	request datasource.PolicyRequest,
) (datasource.ResolvedPolicy, error) {
	if p.resolvePolicy == nil {
		return datasource.ResolvedPolicy{}, datasource.NewError(datasource.ErrorCodeNotFound)
	}
	return p.resolvePolicy(ctx, request)
}

type adapterTypedNilError struct{}

// Error returns a marker that must never cross the adapter boundary.
func (*adapterTypedNilError) Error() string { return "protected typed-nil adapter error" }

type adapterProviderOutcome uint8

const (
	adapterOutcomeZeroNil adapterProviderOutcome = iota
	adapterOutcomeResultTypedError
	adapterOutcomeRawError
	adapterOutcomeTypedNilError
	adapterOutcomePanic
	adapterOutcomeActiveCancelled
	adapterOutcomeActiveDeadline
	adapterOutcomeUnavailable
	adapterOutcomeAmbiguous
)

type adapterProviderOutcomeCase struct {
	name    string
	outcome adapterProviderOutcome
	code    datasource.ErrorCode
}

// adapterProviderOutcomeCases returns the one shared malformed and direct-error
// matrix exercised through both provider methods.
func adapterProviderOutcomeCases() []adapterProviderOutcomeCase {
	return []adapterProviderOutcomeCase{
		{
			name: "zero plus nil", outcome: adapterOutcomeZeroNil,
			code: datasource.ErrorCodeInternalInvariant,
		},
		{
			name: "result plus typed error", outcome: adapterOutcomeResultTypedError,
			code: datasource.ErrorCodeInternalInvariant,
		},
		{
			name: "zero plus raw error", outcome: adapterOutcomeRawError,
			code: datasource.ErrorCodeInternalInvariant,
		},
		{
			name: "zero plus typed nil error", outcome: adapterOutcomeTypedNilError,
			code: datasource.ErrorCodeInternalInvariant,
		},
		{
			name: "panic", outcome: adapterOutcomePanic,
			code: datasource.ErrorCodeInternalInvariant,
		},
		{
			name: "active context plus cancelled code", outcome: adapterOutcomeActiveCancelled,
			code: datasource.ErrorCodeInternalInvariant,
		},
		{
			name: "active context plus deadline code", outcome: adapterOutcomeActiveDeadline,
			code: datasource.ErrorCodeInternalInvariant,
		},
		{
			name: "unavailable", outcome: adapterOutcomeUnavailable,
			code: datasource.ErrorCodeUnavailable,
		},
		{
			name: "ambiguous", outcome: adapterOutcomeAmbiguous,
			code: datasource.ErrorCodeAmbiguous,
		},
	}
}

// adapterOutcomeCall translates one shared outcome into either provider method
// without duplicating the fail-closed result/error matrix.
func adapterOutcomeCall[Request, Result any](
	test adapterProviderOutcomeCase,
	zero Result,
	valid Result,
	raw error,
	typedNil error,
) func(context.Context, Request) (Result, error) {
	return func(context.Context, Request) (Result, error) {
		switch test.outcome {
		case adapterOutcomeZeroNil:
			return zero, nil
		case adapterOutcomeResultTypedError:
			return valid, datasource.NewError(datasource.ErrorCodeUnavailable)
		case adapterOutcomeRawError:
			return zero, raw
		case adapterOutcomeTypedNilError:
			return zero, typedNil
		case adapterOutcomePanic:
			panic("protected provider panic")
		case adapterOutcomeActiveCancelled:
			return zero, datasource.NewError(datasource.ErrorCodeCancelled)
		case adapterOutcomeActiveDeadline:
			return zero, datasource.NewError(datasource.ErrorCodeDeadlineExceeded)
		case adapterOutcomeUnavailable:
			return zero, datasource.NewError(datasource.ErrorCodeUnavailable)
		case adapterOutcomeAmbiguous:
			return zero, datasource.NewError(datasource.ErrorCodeAmbiguous)
		default:
			panic("unhandled adapter provider outcome")
		}
	}
}

// runAdapterProviderOutcomeMatrix applies the one shared outcome matrix through
// a provider-method constructor and signing-profile resolver.
func runAdapterProviderOutcomeMatrix[Request, Result any](
	t *testing.T,
	fixture adapterFixture,
	zero Result,
	valid Result,
	raw error,
	providerFor func(func(context.Context, Request) (Result, error)) datasource.Provider,
	resolve func(Adapter) (signing.Profile, error),
) {
	t.Helper()
	var typedNil *adapterTypedNilError
	for _, test := range adapterProviderOutcomeCases() {
		t.Run(test.name, func(t *testing.T) {
			call := adapterOutcomeCall[Request, Result](
				test, zero, valid, raw, typedNil,
			)
			adapter := mustAdapter(t, providerFor(call), fixture.registry)
			projected, err := resolve(adapter)
			if projected.Valid() || datasource.ErrorCodeOf(err) != test.code {
				t.Fatalf("provider outcome valid=%t code=%s, want %s",
					projected.Valid(), datasource.ErrorCodeOf(err), test.code)
			}
		})
	}
}

// TestAdapterForwardsOneExplicitInstantAndExactProfileFacts proves the higher
// bridge forwards one caller-captured instant in a complete provider request.
func TestAdapterForwardsOneExplicitInstantAndExactProfileFacts(t *testing.T) {
	fixture := newAdapterFixture(t)
	providerCalls := 0
	local := time.Date(2026, time.July, 23, 21, 0, 0, 123, time.FixedZone("local", 2*60*60))
	provider := &adapterProvider{
		resolveProfile: func(_ context.Context, request datasource.ProfileRequest) (datasource.ResolvedProfile, error) {
			providerCalls++
			if request.ProfileID() != fixture.profile.ID() ||
				request.Use() != datasource.ProfileUseOriginator ||
				!request.EvaluationTime().Equal(local) ||
				request.EvaluationTime().Location() != time.UTC {
				t.Fatal("adapter changed exact profile request facts")
			}
			return fixture.resolvedProfile, nil
		},
	}
	adapter := mustAdapter(t, provider, fixture.registry)
	projected, err := adapter.ResolveProfile(
		context.Background(),
		fixture.profile.ID(),
		datasource.ProfileUseOriginator,
		local,
	)
	if err != nil || !projected.Valid() || projected.Domain() != fixture.profile.SigningDomain() {
		t.Fatalf("ResolveProfile() valid=%t code=%s",
			projected.Valid(), datasource.ErrorCodeOf(err))
	}
	if providerCalls != 1 {
		t.Fatalf("provider calls=%d, want 1", providerCalls)
	}
}

// TestAdapterForwardsOneExplicitInstantAndExactPolicyFacts proves policy
// resolution uses the supplied time and self-contained result contract.
func TestAdapterForwardsOneExplicitInstantAndExactPolicyFacts(t *testing.T) {
	fixture := newAdapterFixture(t)
	providerCalls := 0
	provider := &adapterProvider{
		resolvePolicy: func(_ context.Context, request datasource.PolicyRequest) (datasource.ResolvedPolicy, error) {
			providerCalls++
			if request.TenantID() != fixture.tenant ||
				request.SigningDomain() != fixture.profile.SigningDomain() ||
				request.Use() != datasource.ProfileUseOriginator ||
				!request.EvaluationTime().Equal(fixture.at) {
				t.Fatal("adapter changed exact policy request facts")
			}
			return fixture.resolvedPolicy, nil
		},
	}
	adapter := mustAdapter(t, provider, fixture.registry)
	projected, err := adapter.ResolvePolicy(
		context.Background(),
		fixture.tenant,
		fixture.profile.SigningDomain(),
		datasource.ProfileUseOriginator,
		fixture.at,
	)
	if err != nil || !projected.Valid() {
		t.Fatalf("ResolvePolicy() valid=%t code=%s",
			projected.Valid(), datasource.ErrorCodeOf(err))
	}
	if providerCalls != 1 {
		t.Fatalf("provider calls=%d, want 1", providerCalls)
	}
}

// TestAdapterRejectsUnusableConstructionDependencies proves impossible
// injected dependencies cannot publish an adapter.
func TestAdapterRejectsUnusableConstructionDependencies(t *testing.T) {
	fixture := newAdapterFixture(t)
	var typedNil *adapterProvider
	validProvider := &adapterProvider{}
	invalidSigningLimits := signing.DefaultLimits()
	invalidSigningLimits.MaxPrivateSigningCalls = 3

	tests := []struct {
		name          string
		provider      datasource.Provider
		registry      Registry
		signingLimits signing.Limits
		code          datasource.ErrorCode
	}{
		{
			name: "nil provider", registry: fixture.registry,
			signingLimits: signing.DefaultLimits(),
			code:          datasource.ErrorCodeInternalInvariant,
		},
		{
			name: "typed nil provider", provider: typedNil, registry: fixture.registry,
			signingLimits: signing.DefaultLimits(),
			code:          datasource.ErrorCodeInternalInvariant,
		},
		{
			name: "zero registry", provider: validProvider,
			signingLimits: signing.DefaultLimits(),
			code:          datasource.ErrorCodeInternalInvariant,
		},
		{
			name: "invalid signing limits", provider: validProvider, registry: fixture.registry,
			signingLimits: invalidSigningLimits,
			code:          datasource.ErrorCodeInvalidRequest,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter, err := NewAdapter(
				test.provider,
				test.registry,
				test.signingLimits,
			)
			if adapter.Valid() || datasource.ErrorCodeOf(err) != test.code {
				t.Fatalf("NewAdapter() valid=%t code=%s, want %s",
					adapter.Valid(), datasource.ErrorCodeOf(err), test.code)
			}
		})
	}
}

// TestAdapterClosesEveryProfileProviderOutcome proves no malformed result/error
// pair, raw failure, panic, or cancellation mismatch can reach signing projection.
func TestAdapterClosesEveryProfileProviderOutcome(t *testing.T) {
	fixture := newAdapterFixture(t)
	runAdapterProviderOutcomeMatrix(
		t,
		fixture,
		datasource.ResolvedProfile{},
		fixture.resolvedProfile,
		errors.New("protected raw provider failure"),
		func(call func(context.Context, datasource.ProfileRequest) (datasource.ResolvedProfile, error)) datasource.Provider {
			return &adapterProvider{resolveProfile: call}
		},
		func(adapter Adapter) (signing.Profile, error) {
			return adapter.ResolveProfile(
				context.Background(),
				fixture.profile.ID(),
				datasource.ProfileUseOriginator,
				fixture.at,
			)
		},
	)
}

// TestAdapterClosesEveryPolicyProviderOutcome proves the policy path owns the
// same panic, result/error, privacy, and context-code closure as profile lookup.
func TestAdapterClosesEveryPolicyProviderOutcome(t *testing.T) {
	fixture := newAdapterFixture(t)
	runAdapterProviderOutcomeMatrix(
		t,
		fixture,
		datasource.ResolvedPolicy{},
		fixture.resolvedPolicy,
		errors.New("protected raw policy failure"),
		func(call func(context.Context, datasource.PolicyRequest) (datasource.ResolvedPolicy, error)) datasource.Provider {
			return &adapterProvider{resolvePolicy: call}
		},
		func(adapter Adapter) (signing.Profile, error) {
			return adapter.ResolvePolicy(
				context.Background(),
				fixture.tenant,
				fixture.profile.SigningDomain(),
				datasource.ProfileUseOriginator,
				fixture.at,
			)
		},
	)
}

// TestAdapterPassesThroughEveryDirectNonContextFailure proves both lookup
// methods preserve every stable direct provider code without widening it.
func TestAdapterPassesThroughEveryDirectNonContextFailure(t *testing.T) {
	fixture := newAdapterFixture(t)
	codes := []datasource.ErrorCode{
		datasource.ErrorCodeInvalidRequest,
		datasource.ErrorCodeNotFound,
		datasource.ErrorCodeAmbiguous,
		datasource.ErrorCodeInactive,
		datasource.ErrorCodeMalformedData,
		datasource.ErrorCodeLimitExceeded,
		datasource.ErrorCodeUnavailable,
		datasource.ErrorCodeUnsupportedPlatform,
		datasource.ErrorCodeInternalInvariant,
	}
	for _, path := range []string{adapterProfilePath, adapterPolicyPath} {
		for _, code := range codes {
			t.Run(path+"/"+string(code), func(t *testing.T) {
				provider := &adapterProvider{}
				if path == adapterProfilePath {
					provider.resolveProfile = func(context.Context, datasource.ProfileRequest) (datasource.ResolvedProfile, error) {
						return datasource.ResolvedProfile{}, datasource.NewError(code)
					}
				} else {
					provider.resolvePolicy = func(context.Context, datasource.PolicyRequest) (datasource.ResolvedPolicy, error) {
						return datasource.ResolvedPolicy{}, datasource.NewError(code)
					}
				}
				adapter := mustAdapter(t, provider, fixture.registry)
				var result signing.Profile
				var err error
				if path == adapterProfilePath {
					result, err = adapter.ResolveProfile(
						context.Background(),
						fixture.profile.ID(),
						datasource.ProfileUseOriginator,
						fixture.at,
					)
				} else {
					result, err = adapter.ResolvePolicy(
						context.Background(),
						fixture.tenant,
						fixture.profile.SigningDomain(),
						datasource.ProfileUseOriginator,
						fixture.at,
					)
				}
				if result.Valid() || datasource.ErrorCodeOf(err) != code {
					t.Fatalf("result valid=%t code=%s, want %s",
						result.Valid(), datasource.ErrorCodeOf(err), code)
				}
			})
		}
	}
}

// TestAdapterRejectsWrappedTypedProviderFailures proves only direct closed
// datasource errors cross the bridge.
func TestAdapterRejectsWrappedTypedProviderFailures(t *testing.T) {
	fixture := newAdapterFixture(t)
	wrapped := fmt.Errorf(
		"protected wrapped provider marker: %w",
		datasource.NewError(datasource.ErrorCodeUnavailable),
	)
	provider := &adapterProvider{
		resolveProfile: func(context.Context, datasource.ProfileRequest) (datasource.ResolvedProfile, error) {
			return datasource.ResolvedProfile{}, wrapped
		},
		resolvePolicy: func(context.Context, datasource.PolicyRequest) (datasource.ResolvedPolicy, error) {
			return datasource.ResolvedPolicy{}, wrapped
		},
	}
	adapter := mustAdapter(t, provider, fixture.registry)
	profile, profileErr := adapter.ResolveProfile(
		context.Background(),
		fixture.profile.ID(),
		datasource.ProfileUseOriginator,
		fixture.at,
	)
	policy, policyErr := adapter.ResolvePolicy(
		context.Background(),
		fixture.tenant,
		fixture.profile.SigningDomain(),
		datasource.ProfileUseOriginator,
		fixture.at,
	)
	for name, result := range map[string]struct {
		profile signing.Profile
		err     error
	}{
		adapterProfilePath: {profile: profile, err: profileErr},
		adapterPolicyPath:  {profile: policy, err: policyErr},
	} {
		if result.profile.Valid() ||
			datasource.ErrorCodeOf(result.err) != datasource.ErrorCodeInternalInvariant ||
			strings.Contains(fmt.Sprint(result.err), "protected") {
			t.Fatalf("%s wrapped error valid=%t code=%s rendered=%q",
				name,
				result.profile.Valid(),
				datasource.ErrorCodeOf(result.err),
				fmt.Sprint(result.err))
		}
	}
}

// TestAdapterClonesOnlyAValidRegistryAndRedactsFormatting proves a corrupt
// registry is not healed while later caller mutation cannot alter the adapter.
func TestAdapterClonesOnlyAValidRegistryAndRedactsFormatting(t *testing.T) {
	fixture := newAdapterFixture(t)
	provider := &adapterProvider{
		resolveProfile: func(context.Context, datasource.ProfileRequest) (datasource.ResolvedProfile, error) {
			return fixture.resolvedProfile, nil
		},
	}
	corrupt := fixture.registry
	corrupt.complete = false
	if adapter, err := NewAdapter(provider, corrupt, signing.DefaultLimits()); adapter.Valid() ||
		datasource.ErrorCodeOf(err) != datasource.ErrorCodeInternalInvariant {
		t.Fatalf("NewAdapter(corrupt registry) valid=%t code=%s",
			adapter.Valid(), datasource.ErrorCodeOf(err))
	}

	callerRegistry := fixture.registry
	adapter := mustAdapter(t, provider, callerRegistry)
	for key, entry := range callerRegistry.entries {
		entry.uses[0] = datasource.ProfileUseOrdinaryTransit
		callerRegistry.entries[key] = entry
	}
	clear(callerRegistry.groups)
	callerRegistry.complete = false
	projected, err := adapter.ResolveProfile(
		context.Background(),
		fixture.profile.ID(),
		datasource.ProfileUseOriginator,
		fixture.at,
	)
	if err != nil || !projected.Valid() {
		t.Fatalf("adapter retained caller registry aliases: valid=%t code=%s",
			projected.Valid(), datasource.ErrorCodeOf(err))
	}
	formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q", adapter, adapter, adapter, adapter, adapter)
	if !strings.Contains(formatted, "redacted") ||
		strings.Contains(formatted, fixture.profile.SigningDomain()) ||
		strings.Contains(formatted, fixture.profile.ID().String()) {
		t.Fatalf("Adapter formatting exposed protected facts: %q", formatted)
	}
	encoded, err := json.Marshal(adapter)
	if err != nil || string(encoded) != "{}" ||
		strings.Contains(string(encoded), fixture.profile.SigningDomain()) {
		t.Fatalf("json.Marshal(Adapter) = %q, %v", encoded, err)
	}
	var zero Adapter
	if zero.Valid() {
		t.Fatal("zero Adapter reported valid")
	}
}

// TestAdapterClosesCancellationAndEvaluationTimeBoundaries proves caller
// control flow and supplied time are checked without partial success.
func TestAdapterClosesCancellationAndEvaluationTimeBoundaries(t *testing.T) {
	fixture := newAdapterFixture(t)

	t.Run("pre-cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		providerCalls := 0
		adapter := mustAdapter(
			t,
			&adapterProvider{resolveProfile: func(context.Context, datasource.ProfileRequest) (datasource.ResolvedProfile, error) {
				providerCalls++
				return fixture.resolvedProfile, nil
			}},
			fixture.registry,
		)
		profile, err := adapter.ResolveProfile(
			ctx, fixture.profile.ID(), datasource.ProfileUseOriginator, fixture.at,
		)
		if profile.Valid() || datasource.ErrorCodeOf(err) != datasource.ErrorCodeCancelled ||
			!errors.Is(err, context.Canceled) || providerCalls != 0 {
			t.Fatalf("pre-cancel valid=%t code=%s provider-calls=%d",
				profile.Valid(), datasource.ErrorCodeOf(err), providerCalls)
		}
	})

	t.Run("post-provider cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		adapter := mustAdapter(
			t,
			&adapterProvider{resolveProfile: func(context.Context, datasource.ProfileRequest) (datasource.ResolvedProfile, error) {
				cancel()
				return fixture.resolvedProfile, nil
			}},
			fixture.registry,
		)
		profile, err := adapter.ResolveProfile(
			ctx, fixture.profile.ID(), datasource.ProfileUseOriginator, fixture.at,
		)
		if profile.Valid() || datasource.ErrorCodeOf(err) != datasource.ErrorCodeCancelled ||
			!errors.Is(err, context.Canceled) {
			t.Fatalf("post-provider cancellation valid=%t code=%s",
				profile.Valid(), datasource.ErrorCodeOf(err))
		}
	})

	t.Run("malformed pair precedes cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		adapter := mustAdapter(
			t,
			&adapterProvider{resolveProfile: func(context.Context, datasource.ProfileRequest) (datasource.ResolvedProfile, error) {
				cancel()
				return datasource.ResolvedProfile{}, nil
			}},
			fixture.registry,
		)
		profile, err := adapter.ResolveProfile(
			ctx, fixture.profile.ID(), datasource.ProfileUseOriginator, fixture.at,
		)
		if profile.Valid() || datasource.ErrorCodeOf(err) != datasource.ErrorCodeInternalInvariant {
			t.Fatalf("malformed pair hidden by cancellation: valid=%t code=%s",
				profile.Valid(), datasource.ErrorCodeOf(err))
		}
	})

	t.Run("policy post-provider cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		adapter := mustAdapter(
			t,
			&adapterProvider{resolvePolicy: func(context.Context, datasource.PolicyRequest) (datasource.ResolvedPolicy, error) {
				cancel()
				return fixture.resolvedPolicy, nil
			}},
			fixture.registry,
		)
		profile, err := adapter.ResolvePolicy(
			ctx,
			fixture.tenant,
			fixture.profile.SigningDomain(),
			datasource.ProfileUseOriginator,
			fixture.at,
		)
		if profile.Valid() || datasource.ErrorCodeOf(err) != datasource.ErrorCodeCancelled ||
			!errors.Is(err, context.Canceled) {
			t.Fatalf("policy post-provider cancellation valid=%t code=%s",
				profile.Valid(), datasource.ErrorCodeOf(err))
		}
	})

	t.Run("malformed policy pair precedes cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		adapter := mustAdapter(
			t,
			&adapterProvider{resolvePolicy: func(context.Context, datasource.PolicyRequest) (datasource.ResolvedPolicy, error) {
				cancel()
				return datasource.ResolvedPolicy{}, nil
			}},
			fixture.registry,
		)
		profile, err := adapter.ResolvePolicy(
			ctx,
			fixture.tenant,
			fixture.profile.SigningDomain(),
			datasource.ProfileUseOriginator,
			fixture.at,
		)
		if profile.Valid() || datasource.ErrorCodeOf(err) != datasource.ErrorCodeInternalInvariant {
			t.Fatalf("malformed policy pair hidden by cancellation: valid=%t code=%s",
				profile.Valid(), datasource.ErrorCodeOf(err))
		}
	})

	t.Run("zero evaluation time", func(t *testing.T) {
		providerCalls := 0
		adapter := mustAdapter(
			t,
			&adapterProvider{resolveProfile: func(context.Context, datasource.ProfileRequest) (datasource.ResolvedProfile, error) {
				providerCalls++
				return fixture.resolvedProfile, nil
			}},
			fixture.registry,
		)
		profile, err := adapter.ResolveProfile(
			context.Background(),
			fixture.profile.ID(),
			datasource.ProfileUseOriginator,
			time.Time{},
		)
		if profile.Valid() || datasource.ErrorCodeOf(err) != datasource.ErrorCodeInvalidRequest ||
			providerCalls != 0 {
			t.Fatalf("zero time valid=%t code=%s provider-calls=%d",
				profile.Valid(), datasource.ErrorCodeOf(err), providerCalls)
		}
	})
}

// TestAdapterReconcilesExactContextAndProviderOutcomes proves context control
// flow wins ordinary failures, matching context codes retain identity, and
// mismatched codes or provider panics fail as invariants on both lookup paths.
func TestAdapterReconcilesExactContextAndProviderOutcomes(t *testing.T) {
	fixture := newAdapterFixture(t)
	tests := []struct {
		name         string
		contextError error
		providerCode datasource.ErrorCode
		panicCall    bool
		want         datasource.ErrorCode
		contextIs    error
	}{
		{
			name: "matching cancelled", contextError: context.Canceled,
			providerCode: datasource.ErrorCodeCancelled,
			want:         datasource.ErrorCodeCancelled, contextIs: context.Canceled,
		},
		{
			name: "matching deadline", contextError: context.DeadlineExceeded,
			providerCode: datasource.ErrorCodeDeadlineExceeded,
			want:         datasource.ErrorCodeDeadlineExceeded, contextIs: context.DeadlineExceeded,
		},
		{
			name: "cancelled context deadline result", contextError: context.Canceled,
			providerCode: datasource.ErrorCodeDeadlineExceeded,
			want:         datasource.ErrorCodeInternalInvariant,
		},
		{
			name: "deadline context cancelled result", contextError: context.DeadlineExceeded,
			providerCode: datasource.ErrorCodeCancelled,
			want:         datasource.ErrorCodeInternalInvariant,
		},
		{
			name: "ordinary error then cancellation", contextError: context.Canceled,
			providerCode: datasource.ErrorCodeUnavailable,
			want:         datasource.ErrorCodeCancelled, contextIs: context.Canceled,
		},
		{
			name: "internal invariant then cancellation", contextError: context.Canceled,
			providerCode: datasource.ErrorCodeInternalInvariant,
			want:         datasource.ErrorCodeInternalInvariant,
		},
		{
			name: "internal invariant then deadline", contextError: context.DeadlineExceeded,
			providerCode: datasource.ErrorCodeInternalInvariant,
			want:         datasource.ErrorCodeInternalInvariant,
		},
		{
			name: "panic then cancellation", contextError: context.Canceled,
			panicCall: true, want: datasource.ErrorCodeInternalInvariant,
		},
	}
	for _, path := range []string{adapterProfilePath, adapterPolicyPath} {
		for _, test := range tests {
			t.Run(path+"/"+test.name, func(t *testing.T) {
				ctx := newAdapterMutableContext()
				provider := &adapterProvider{}
				if path == adapterProfilePath {
					provider.resolveProfile = func(context.Context, datasource.ProfileRequest) (datasource.ResolvedProfile, error) {
						ctx.finish(test.contextError)
						if test.panicCall {
							panic("protected profile panic after context transition")
						}
						return datasource.ResolvedProfile{}, datasource.NewError(test.providerCode)
					}
				} else {
					provider.resolvePolicy = func(context.Context, datasource.PolicyRequest) (datasource.ResolvedPolicy, error) {
						ctx.finish(test.contextError)
						if test.panicCall {
							panic("protected policy panic after context transition")
						}
						return datasource.ResolvedPolicy{}, datasource.NewError(test.providerCode)
					}
				}
				adapter := mustAdapter(t, provider, fixture.registry)
				var profile signing.Profile
				var err error
				if path == adapterProfilePath {
					profile, err = adapter.ResolveProfile(
						ctx,
						fixture.profile.ID(),
						datasource.ProfileUseOriginator,
						fixture.at,
					)
				} else {
					profile, err = adapter.ResolvePolicy(
						ctx,
						fixture.tenant,
						fixture.profile.SigningDomain(),
						datasource.ProfileUseOriginator,
						fixture.at,
					)
				}
				if profile.Valid() || datasource.ErrorCodeOf(err) != test.want {
					t.Fatalf("result valid=%t code=%s, want %s",
						profile.Valid(), datasource.ErrorCodeOf(err), test.want)
				}
				if test.contextIs != nil && !errors.Is(err, test.contextIs) {
					t.Fatalf("error %v lost context identity %v", err, test.contextIs)
				}
				if test.want == datasource.ErrorCodeInternalInvariant &&
					(!datasource.IsTypedError(err) || errors.Is(err, test.contextError)) {
					t.Fatal("internal invariant did not retain closed precedence")
				}
			})
		}
	}
}

// TestAdapterChecksHostileContextsBeforeAdapterState proves nil, typed-nil,
// panicking, cancelled, and expired contexts do not reach either provider even
// when the adapter itself is zero.
func TestAdapterChecksHostileContextsBeforeAdapterState(t *testing.T) {
	fixture := newAdapterFixture(t)
	var typedNil *adapterMutableContext
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, expire := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer expire()
	tests := []struct {
		name      string
		ctx       context.Context
		want      datasource.ErrorCode
		contextIs error
	}{
		{name: "nil", want: datasource.ErrorCodeInvalidRequest},
		{name: "typed nil", ctx: typedNil, want: datasource.ErrorCodeInvalidRequest},
		{name: "panicking", ctx: adapterPanicContext{}, want: datasource.ErrorCodeInternalInvariant},
		{
			name: "cancelled", ctx: cancelled, want: datasource.ErrorCodeCancelled,
			contextIs: context.Canceled,
		},
		{
			name: "deadline", ctx: expired, want: datasource.ErrorCodeDeadlineExceeded,
			contextIs: context.DeadlineExceeded,
		},
	}
	for _, path := range []string{adapterProfilePath, adapterPolicyPath} {
		for _, test := range tests {
			t.Run(path+"/"+test.name, func(t *testing.T) {
				var zero Adapter
				var result signing.Profile
				var err error
				if path == adapterProfilePath {
					result, err = zero.ResolveProfile(
						test.ctx,
						fixture.profile.ID(),
						datasource.ProfileUseOriginator,
						fixture.at,
					)
				} else {
					result, err = zero.ResolvePolicy(
						test.ctx,
						fixture.tenant,
						fixture.profile.SigningDomain(),
						datasource.ProfileUseOriginator,
						fixture.at,
					)
				}
				if result.Valid() || datasource.ErrorCodeOf(err) != test.want {
					t.Fatalf("zero adapter valid=%t code=%s, want %s",
						result.Valid(), datasource.ErrorCodeOf(err), test.want)
				}
				if test.contextIs != nil && !errors.Is(err, test.contextIs) {
					t.Fatalf("error %v lost context identity %v", err, test.contextIs)
				}
				providerCalls := 0
				provider := &adapterProvider{
					resolveProfile: func(context.Context, datasource.ProfileRequest) (datasource.ResolvedProfile, error) {
						providerCalls++
						return fixture.resolvedProfile, nil
					},
					resolvePolicy: func(context.Context, datasource.PolicyRequest) (datasource.ResolvedPolicy, error) {
						providerCalls++
						return fixture.resolvedPolicy, nil
					},
				}
				valid := mustAdapter(t, provider, fixture.registry)
				if path == adapterProfilePath {
					result, err = valid.ResolveProfile(
						test.ctx,
						fixture.profile.ID(),
						datasource.ProfileUseOriginator,
						fixture.at,
					)
				} else {
					result, err = valid.ResolvePolicy(
						test.ctx,
						fixture.tenant,
						fixture.profile.SigningDomain(),
						datasource.ProfileUseOriginator,
						fixture.at,
					)
				}
				if result.Valid() || datasource.ErrorCodeOf(err) != test.want ||
					providerCalls != 0 {
					t.Fatalf("valid adapter preflight valid=%t code=%s calls=%d",
						result.Valid(), datasource.ErrorCodeOf(err), providerCalls)
				}
			})
		}
	}
}

// TestAdapterChecksTerminationAfterProjection proves the final bounded context
// check suppresses complete projection and denial for cancellation or deadline.
func TestAdapterChecksTerminationAfterProjection(t *testing.T) {
	fixture := newAdapterFixture(t)
	provider := &adapterProvider{
		resolveProfile: func(context.Context, datasource.ProfileRequest) (datasource.ResolvedProfile, error) {
			return fixture.resolvedProfile, nil
		},
		resolvePolicy: func(context.Context, datasource.PolicyRequest) (datasource.ResolvedPolicy, error) {
			return fixture.resolvedPolicy, nil
		},
	}
	adapter := mustAdapter(t, provider, fixture.registry)
	for _, path := range []string{adapterProfilePath, adapterPolicyPath} {
		for _, denied := range []bool{false, true} {
			for _, terminalErr := range []error{context.Canceled, context.DeadlineExceeded} {
				use := datasource.ProfileUseOriginator
				if denied {
					use = datasource.ProfileUseOrdinaryTransit
				}
				ctx := newAdapterPostProjectionContext(terminalErr)
				var result signing.Profile
				var err error
				if path == adapterProfilePath {
					result, err = adapter.ResolveProfile(
						ctx, fixture.profile.ID(), use, fixture.at,
					)
				} else {
					result, err = adapter.ResolvePolicy(
						ctx,
						fixture.tenant,
						fixture.profile.SigningDomain(),
						use,
						fixture.at,
					)
				}
				if result.Valid() || !datasource.IsTypedError(err) ||
					datasource.ErrorCodeOf(err) != datasource.ErrorCodeOf(
						datasource.ErrorFromContext(ctx),
					) ||
					!errors.Is(err, terminalErr) {
					t.Fatalf("post-projection result valid=%t code=%s",
						result.Valid(), datasource.ErrorCodeOf(err))
				}
			}
		}
	}
}

// TestAdapterRejectsWrongResolvedProfileWithoutFallback proves the requested
// identity remains exact even when a provider returns another valid profile.
func TestAdapterRejectsWrongResolvedProfileWithoutFallback(t *testing.T) {
	fixture := newAdapterFixture(t)
	otherID := mustProjectionProfileID(t, "profile.other")
	other := newDatasourceProfile(
		t,
		otherID,
		"selector-other",
		fixture.profile.Credentials()[0].KeyHandleID(),
	)
	result, err := datasource.NewResolvedProfile(fixture.resolvedProfile.Generation(), other)
	if err != nil {
		t.Fatalf("datasource.NewResolvedProfile() error = %v", err)
	}
	adapter := mustAdapter(
		t,
		&adapterProvider{resolveProfile: func(context.Context, datasource.ProfileRequest) (datasource.ResolvedProfile, error) {
			return result, nil
		}},
		fixture.registry,
	)
	profile, err := adapter.ResolveProfile(
		context.Background(),
		fixture.profile.ID(),
		datasource.ProfileUseOriginator,
		fixture.at,
	)
	if profile.Valid() || datasource.ErrorCodeOf(err) != datasource.ErrorCodeInactive {
		t.Fatalf("wrong resolved identity valid=%t code=%s",
			profile.Valid(), datasource.ErrorCodeOf(err))
	}
}

// TestAdapterRejectsNonEnforceAndDisabledPolicyWithoutProjection proves
// administrative observe, off, and disabled states cannot enter signing.
func TestAdapterRejectsNonEnforceAndDisabledPolicyWithoutProjection(t *testing.T) {
	fixture := newAdapterFixture(t)
	tests := []struct {
		name    string
		status  datasource.RecordStatus
		rollout datasource.Rollout
	}{
		{name: "observe", status: datasource.RecordStatusActive, rollout: datasource.RolloutObserve},
		{name: "off", status: datasource.RecordStatusActive, rollout: datasource.RolloutOff},
		{name: "disabled", status: datasource.RecordStatusDisabled, rollout: datasource.RolloutEnforce},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := mustAdapterPolicy(
				t,
				fixture.tenant,
				fixture.profile,
				test.status,
				test.rollout,
			)
			resolved, err := datasource.NewResolvedPolicy(
				fixture.resolvedProfile.Generation(),
				policy,
				fixture.resolvedProfile,
			)
			if err != nil {
				t.Fatalf("datasource.NewResolvedPolicy() error = %v", err)
			}
			adapter := mustAdapter(
				t,
				&adapterProvider{resolvePolicy: func(context.Context, datasource.PolicyRequest) (datasource.ResolvedPolicy, error) {
					return resolved, nil
				}},
				fixture.registry,
			)
			profile, resolveErr := adapter.ResolvePolicy(
				context.Background(),
				fixture.tenant,
				fixture.profile.SigningDomain(),
				datasource.ProfileUseOriginator,
				fixture.at,
			)
			if profile.Valid() || datasource.ErrorCodeOf(resolveErr) != datasource.ErrorCodeInactive {
				t.Fatalf("ResolvePolicy(%s) valid=%t code=%s",
					test.name, profile.Valid(), datasource.ErrorCodeOf(resolveErr))
			}
		})
	}
}

// TestAdapterPreservesMemoryAndFlatFileParityAcrossImmutableGenerations proves
// equivalent self-contained providers drive the same sole signing projection and
// that a later flat-file generation cannot mutate an already returned profile.
func TestAdapterPreservesMemoryAndFlatFileParityAcrossImmutableGenerations(t *testing.T) {
	document, err := os.ReadFile(adapterFixturePath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	limits := datasource.DefaultLimits()
	firstFlat, err := flatfile.Decode(7, document, limits)
	if err != nil {
		t.Fatalf("flatfile.Decode(first) error = %v", err)
	}
	secondFlat, err := flatfile.Decode(8, document, limits)
	if err != nil {
		t.Fatalf("flatfile.Decode(second) error = %v", err)
	}
	profileID := mustProjectionProfileID(t, "profile.example")
	tenant, err := datasource.NewTenantID("tenant.example")
	if err != nil {
		t.Fatalf("datasource.NewTenantID() error = %v", err)
	}
	at := time.Unix(1_700_000_000, 0)
	profileRequest, err := datasource.NewProfileRequest(
		profileID, datasource.ProfileUseOriginator, at, limits,
	)
	if err != nil {
		t.Fatalf("datasource.NewProfileRequest() error = %v", err)
	}
	policyRequest, err := datasource.NewPolicyRequest(
		tenant, adapterSigningDomain, datasource.ProfileUseOriginator, at, limits,
	)
	if err != nil {
		t.Fatalf("datasource.NewPolicyRequest() error = %v", err)
	}
	firstResolved, err := firstFlat.ResolveProfile(context.Background(), profileRequest)
	if err != nil || firstResolved.Generation() != 7 {
		t.Fatalf("first flat generation=%d code=%s",
			firstResolved.Generation(), datasource.ErrorCodeOf(err))
	}
	secondResolved, err := secondFlat.ResolveProfile(context.Background(), profileRequest)
	if err != nil || secondResolved.Generation() != 8 {
		t.Fatalf("second flat generation=%d code=%s",
			secondResolved.Generation(), datasource.ErrorCodeOf(err))
	}
	firstPolicy, err := firstFlat.ResolvePolicy(context.Background(), policyRequest)
	if err != nil {
		t.Fatalf("firstFlat.ResolvePolicy() code=%s", datasource.ErrorCodeOf(err))
	}
	profile := firstResolved.Profile()
	policy := firstPolicy.Policy()
	handleID := profile.Credentials()[0].KeyHandleID()
	memoryProvider, err := memory.New(
		7,
		[]datasource.KeyHandleID{handleID},
		[]datasource.Profile{profile},
		[]datasource.Policy{policy},
		limits,
	)
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	assertAdapterProviderParity(
		t,
		memoryProvider,
		profileRequest,
		policyRequest,
		firstResolved,
		firstPolicy,
	)
	handle, err := signing.NewPrivateKeyHandle([]byte("parity-inert-handle"))
	if err != nil {
		t.Fatalf("signing.NewPrivateKeyHandle() error = %v", err)
	}
	entry, err := NewEntry(
		profile,
		handleID,
		handle,
		[]datasource.ProfileUse{datasource.ProfileUseOriginator},
		limits,
	)
	if err != nil {
		t.Fatalf("NewEntry() error = %v", err)
	}
	registry, err := NewRegistry([]Entry{entry}, limits)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	memoryAdapter := mustAdapter(t, memoryProvider, registry)
	firstAdapter := mustAdapter(t, firstFlat, registry)
	secondAdapter := mustAdapter(t, secondFlat, registry)
	memoryProfile, err := memoryAdapter.ResolveProfile(
		context.Background(), profileID, datasource.ProfileUseOriginator, at,
	)
	if err != nil {
		t.Fatalf("memory ResolveProfile() code=%s", datasource.ErrorCodeOf(err))
	}
	firstProfile, err := firstAdapter.ResolveProfile(
		context.Background(), profileID, datasource.ProfileUseOriginator, at,
	)
	if err != nil {
		t.Fatalf("first flat ResolveProfile() code=%s", datasource.ErrorCodeOf(err))
	}
	if !adapterProfilesEqual(memoryProfile, firstProfile) {
		t.Fatal("memory and flat-file profile projections differ")
	}
	memoryPolicyProfile, err := memoryAdapter.ResolvePolicy(
		context.Background(), tenant, adapterSigningDomain, datasource.ProfileUseOriginator, at,
	)
	if err != nil {
		t.Fatalf("memory ResolvePolicy() code=%s", datasource.ErrorCodeOf(err))
	}
	firstPolicyProfile, err := firstAdapter.ResolvePolicy(
		context.Background(), tenant, adapterSigningDomain, datasource.ProfileUseOriginator, at,
	)
	if err != nil || !adapterProfilesEqual(memoryPolicyProfile, firstPolicyProfile) {
		t.Fatalf("memory/flat policy parity valid=%t/%t code=%s",
			memoryPolicyProfile.Valid(), firstPolicyProfile.Valid(), datasource.ErrorCodeOf(err))
	}

	before := firstProfile.Credentials()
	secondProfile, err := secondAdapter.ResolveProfile(
		context.Background(), profileID, datasource.ProfileUseOriginator, at,
	)
	if err != nil || !adapterProfilesEqual(firstProfile, secondProfile) {
		t.Fatalf("second generation projection differs: code=%s", datasource.ErrorCodeOf(err))
	}
	if !adapterCredentialsEqual(before, firstProfile.Credentials()) {
		t.Fatal("later generation mutated the earlier projected profile")
	}

	baseAdapters := map[string]Adapter{
		adapterMemoryProviderName: memoryAdapter,
		adapterFlatProviderName:   firstAdapter,
	}
	assertAdapterMissingAndControlFlowParity(
		t, baseAdapters, profileID, tenant, at,
	)
	assertAdapterProfileStateParity(
		t, profile, policy, profileID, at, document, limits,
	)
	assertAdapterPolicyStateParity(
		t, profile, tenant, at, document, limits,
	)
	assertAdapterLimitParity(
		t, profile, policy, tenant, at, document, limits,
	)
}

// assertAdapterProviderParity verifies equivalent memory and flat-file
// snapshots expose the same complete profile and policy facts.
func assertAdapterProviderParity(
	t *testing.T,
	memoryProvider *memory.Provider,
	profileRequest datasource.ProfileRequest,
	policyRequest datasource.PolicyRequest,
	wantProfile datasource.ResolvedProfile,
	wantPolicy datasource.ResolvedPolicy,
) {
	t.Helper()
	gotProfile, err := memoryProvider.ResolveProfile(
		context.Background(), profileRequest,
	)
	if err != nil || gotProfile.Generation() != wantProfile.Generation() ||
		gotProfile.ProfileID() != wantProfile.ProfileID() ||
		gotProfile.Profile().SigningDomain() != wantProfile.Profile().SigningDomain() ||
		gotProfile.Profile().CredentialCount() != wantProfile.Profile().CredentialCount() {
		t.Fatalf("provider profile parity generation/code=%d/%s",
			gotProfile.Generation(), datasource.ErrorCodeOf(err))
	}
	gotPolicy, err := memoryProvider.ResolvePolicy(
		context.Background(), policyRequest,
	)
	if err != nil || gotPolicy.Generation() != wantPolicy.Generation() ||
		gotPolicy.Policy().TenantID() != wantPolicy.Policy().TenantID() ||
		gotPolicy.Policy().ProfileID() != wantPolicy.Policy().ProfileID() ||
		gotPolicy.Profile().SigningDomain() != wantPolicy.Profile().SigningDomain() {
		t.Fatalf("provider policy parity generation/code=%d/%s",
			gotPolicy.Generation(), datasource.ErrorCodeOf(err))
	}
}

// assertAdapterMissingAndControlFlowParity verifies shared not-found,
// request-boundary, context, and unauthorized-use failures for both providers.
func assertAdapterMissingAndControlFlowParity(
	t *testing.T,
	adapters map[string]Adapter,
	profileID datasource.ProfileID,
	tenant datasource.TenantID,
	at time.Time,
) {
	t.Helper()
	missingID := mustProjectionProfileID(t, "profile.missing")
	missingTenant, err := datasource.NewTenantID("tenant.missing")
	if err != nil {
		t.Fatalf("datasource.NewTenantID() error = %v", err)
	}
	for providerName, adapter := range adapters {
		t.Run(providerName+"/missing/"+adapterProfilePath, func(t *testing.T) {
			got, resolveErr := adapter.ResolveProfile(
				context.Background(), missingID, datasource.ProfileUseOriginator, at,
			)
			assertAdapterParityFailure(
				t, got, resolveErr, datasource.ErrorCodeNotFound, nil,
			)
		})
		t.Run(providerName+"/missing/"+adapterPolicyPath, func(t *testing.T) {
			got, resolveErr := adapter.ResolvePolicy(
				context.Background(),
				missingTenant,
				adapterSigningDomain,
				datasource.ProfileUseOriginator,
				at,
			)
			assertAdapterParityFailure(
				t, got, resolveErr, datasource.ErrorCodeNotFound, nil,
			)
		})
	}
	assertAdapterRequestBoundaryParity(t, adapters, profileID, tenant, at)
	for providerName, adapter := range adapters {
		t.Run(providerName+"/unauthorized use", func(t *testing.T) {
			got, resolveErr := adapter.ResolveProfile(
				context.Background(),
				profileID,
				datasource.ProfileUseOrdinaryTransit,
				at,
			)
			assertAdapterParityFailure(
				t, got, resolveErr, datasource.ErrorCodeInactive, nil,
			)
		})
	}
}

// assertAdapterRequestBoundaryParity verifies identical invalid-time and
// context-control failures on profile and policy lookups.
func assertAdapterRequestBoundaryParity(
	t *testing.T,
	adapters map[string]Adapter,
	profileID datasource.ProfileID,
	tenant datasource.TenantID,
	at time.Time,
) {
	t.Helper()
	tests := []struct {
		name      string
		ctx       context.Context
		at        time.Time
		code      datasource.ErrorCode
		contextIs error
	}{
		{
			name: "invalid time", ctx: context.Background(), at: time.Time{},
			code: datasource.ErrorCodeInvalidRequest,
		},
		{
			name: "cancelled", ctx: cancelledAdapterContext(),
			at: at, code: datasource.ErrorCodeCancelled, contextIs: context.Canceled,
		},
		{
			name: "deadline", ctx: expiredAdapterContext(),
			at: at, code: datasource.ErrorCodeDeadlineExceeded, contextIs: context.DeadlineExceeded,
		},
	}
	for _, test := range tests {
		for providerName, adapter := range adapters {
			t.Run(providerName+"/"+test.name+"/"+adapterProfilePath, func(t *testing.T) {
				got, resolveErr := adapter.ResolveProfile(
					test.ctx, profileID, datasource.ProfileUseOriginator, test.at,
				)
				assertAdapterParityFailure(t, got, resolveErr, test.code, test.contextIs)
			})
			t.Run(providerName+"/"+test.name+"/"+adapterPolicyPath, func(t *testing.T) {
				got, resolveErr := adapter.ResolvePolicy(
					test.ctx,
					tenant,
					adapterSigningDomain,
					datasource.ProfileUseOriginator,
					test.at,
				)
				assertAdapterParityFailure(t, got, resolveErr, test.code, test.contextIs)
			})
		}
	}
}

// assertAdapterProfileStateParity verifies disabled and validity-window profile
// decisions against equivalent memory and flat-file snapshots.
func assertAdapterProfileStateParity(
	t *testing.T,
	profile datasource.Profile,
	policy datasource.Policy,
	profileID datasource.ProfileID,
	at time.Time,
	document []byte,
	limits datasource.Limits,
) {
	t.Helper()
	documentText := string(document)
	disabledProfile, err := datasource.NewProfile(
		profile.ID(),
		profile.SigningDomain(),
		datasource.RecordStatusDisabled,
		profile.Credentials(),
		time.Time{},
		time.Time{},
		limits,
	)
	if err != nil {
		t.Fatalf("datasource.NewProfile(disabled) error = %v", err)
	}
	disabledDocument := strings.Replace(
		documentText,
		`"status": "active",`+"\n      "+`"credentials"`,
		`"status": "disabled",`+"\n      "+`"credentials"`,
		1,
	)
	for providerName, adapter := range parityAdaptersForSnapshot(
		t, disabledProfile, policy, []byte(disabledDocument), limits,
	) {
		t.Run(providerName+"/disabled profile", func(t *testing.T) {
			got, resolveErr := adapter.ResolveProfile(
				context.Background(), profileID, datasource.ProfileUseOriginator, at,
			)
			assertAdapterParityFailure(
				t, got, resolveErr, datasource.ErrorCodeInactive, nil,
			)
		})
	}
	assertAdapterProfileWindowParity(
		t, profile, policy, profileID, documentText, limits,
	)
}

// assertAdapterProfileWindowParity verifies the exact before-window and
// exclusive not-after decisions for equivalent providers.
func assertAdapterProfileWindowParity(
	t *testing.T,
	profile datasource.Profile,
	policy datasource.Policy,
	profileID datasource.ProfileID,
	documentText string,
	limits datasource.Limits,
) {
	t.Helper()
	notBefore := time.Unix(1_700_000_100, 0).UTC()
	notAfter := time.Unix(1_700_000_200, 0).UTC()
	windowProfile, err := datasource.NewProfile(
		profile.ID(),
		profile.SigningDomain(),
		datasource.RecordStatusActive,
		profile.Credentials(),
		notBefore,
		notAfter,
		limits,
	)
	if err != nil {
		t.Fatalf("datasource.NewProfile(window) error = %v", err)
	}
	windowDocument := strings.Replace(
		documentText,
		`"status": "active",`+"\n      "+`"credentials"`,
		fmt.Sprintf(
			`"status": "active",`+"\n      "+
				`"not_before": %q,`+"\n      "+
				`"not_after": %q,`+"\n      "+
				`"credentials"`,
			notBefore.Format(time.RFC3339Nano),
			notAfter.Format(time.RFC3339Nano),
		),
		1,
	)
	adapters := parityAdaptersForSnapshot(
		t, windowProfile, policy, []byte(windowDocument), limits,
	)
	tests := []struct {
		name string
		at   time.Time
	}{
		{name: "before validity", at: notBefore.Add(-time.Nanosecond)},
		{name: "not-after boundary", at: notAfter},
	}
	for _, test := range tests {
		for providerName, adapter := range adapters {
			t.Run(providerName+"/"+test.name, func(t *testing.T) {
				got, resolveErr := adapter.ResolveProfile(
					context.Background(),
					profileID,
					datasource.ProfileUseOriginator,
					test.at,
				)
				assertAdapterParityFailure(
					t, got, resolveErr, datasource.ErrorCodeInactive, nil,
				)
			})
		}
	}
}

// assertAdapterPolicyStateParity verifies observe, off, and disabled policy
// decisions against equivalent provider snapshots.
func assertAdapterPolicyStateParity(
	t *testing.T,
	profile datasource.Profile,
	tenant datasource.TenantID,
	at time.Time,
	document []byte,
	limits datasource.Limits,
) {
	t.Helper()
	documentText := string(document)
	for _, rollout := range []datasource.Rollout{
		datasource.RolloutObserve,
		datasource.RolloutOff,
	} {
		rolloutPolicy := mustAdapterPolicy(
			t,
			tenant,
			profile,
			datasource.RecordStatusActive,
			rollout,
		)
		rolloutDocument := strings.Replace(
			documentText,
			`"rollout": "enforce"`,
			fmt.Sprintf(`"rollout": %q`, rollout.String()),
			1,
		)
		for providerName, adapter := range parityAdaptersForSnapshot(
			t, profile, rolloutPolicy, []byte(rolloutDocument), limits,
		) {
			t.Run(providerName+"/"+rollout.String(), func(t *testing.T) {
				got, resolveErr := adapter.ResolvePolicy(
					context.Background(),
					tenant,
					adapterSigningDomain,
					datasource.ProfileUseOriginator,
					at,
				)
				assertAdapterParityFailure(
					t, got, resolveErr, datasource.ErrorCodeInactive, nil,
				)
			})
		}
	}
	assertAdapterDisabledPolicyParity(
		t, profile, tenant, at, documentText, limits,
	)
}

// assertAdapterDisabledPolicyParity verifies a disabled administrative record
// denies the same logical policy lookup in both providers.
func assertAdapterDisabledPolicyParity(
	t *testing.T,
	profile datasource.Profile,
	tenant datasource.TenantID,
	at time.Time,
	documentText string,
	limits datasource.Limits,
) {
	t.Helper()
	disabledPolicy := mustAdapterPolicy(
		t,
		tenant,
		profile,
		datasource.RecordStatusDisabled,
		datasource.RolloutEnforce,
	)
	statusIndex := strings.LastIndex(documentText, `"status": "active"`)
	if statusIndex < 0 {
		t.Fatal("valid flat-file fixture lacked policy status")
	}
	disabledDocument := documentText[:statusIndex] +
		`"status": "disabled"` +
		documentText[statusIndex+len(`"status": "active"`):]
	for providerName, adapter := range parityAdaptersForSnapshot(
		t, profile, disabledPolicy, []byte(disabledDocument), limits,
	) {
		t.Run(providerName+"/disabled policy", func(t *testing.T) {
			got, resolveErr := adapter.ResolvePolicy(
				context.Background(),
				tenant,
				adapterSigningDomain,
				datasource.ProfileUseOriginator,
				at,
			)
			assertAdapterParityFailure(
				t, got, resolveErr, datasource.ErrorCodeInactive, nil,
			)
		})
	}
}

// assertAdapterLimitParity verifies identical bounded-identifier failures for
// profile and policy requests against both providers.
func assertAdapterLimitParity(
	t *testing.T,
	profile datasource.Profile,
	policy datasource.Policy,
	tenant datasource.TenantID,
	at time.Time,
	document []byte,
	limits datasource.Limits,
) {
	t.Helper()
	narrowLimits := limits
	narrowLimits.MaxIdentifierBytes = max(
		profile.ID().ByteLen(),
		profile.Credentials()[0].KeyHandleID().ByteLen(),
		tenant.ByteLen(),
	)
	adapters := parityAdaptersForSnapshot(
		t, profile, policy, document, narrowLimits,
	)
	longProfileID := mustProjectionProfileID(
		t, strings.Repeat("p", narrowLimits.MaxIdentifierBytes+1),
	)
	longTenant, err := datasource.NewTenantID(
		strings.Repeat("t", narrowLimits.MaxIdentifierBytes+1),
	)
	if err != nil {
		t.Fatalf("datasource.NewTenantID(long) error = %v", err)
	}
	for providerName, adapter := range adapters {
		t.Run(providerName+"/profile limit exceeded", func(t *testing.T) {
			got, resolveErr := adapter.ResolveProfile(
				context.Background(),
				longProfileID,
				datasource.ProfileUseOriginator,
				at,
			)
			assertAdapterParityFailure(
				t, got, resolveErr, datasource.ErrorCodeLimitExceeded, nil,
			)
		})
		t.Run(providerName+"/policy limit exceeded", func(t *testing.T) {
			got, resolveErr := adapter.ResolvePolicy(
				context.Background(),
				longTenant,
				adapterSigningDomain,
				datasource.ProfileUseOriginator,
				at,
			)
			assertAdapterParityFailure(
				t, got, resolveErr, datasource.ErrorCodeLimitExceeded, nil,
			)
		})
	}
}

type adapterFixture struct {
	at              time.Time
	tenant          datasource.TenantID
	profile         datasource.Profile
	resolvedProfile datasource.ResolvedProfile
	policy          datasource.Policy
	resolvedPolicy  datasource.ResolvedPolicy
	registry        Registry
}

type adapterMutableContext struct {
	mu   sync.RWMutex
	done chan struct{}
	err  error
}

// newAdapterMutableContext constructs one initially active controlled context.
func newAdapterMutableContext() *adapterMutableContext {
	return &adapterMutableContext{done: make(chan struct{})}
}

// Deadline reports no scheduled deadline because tests transition explicitly.
func (*adapterMutableContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done returns the controlled completion channel.
func (c *adapterMutableContext) Done() <-chan struct{} { return c.done }

// Err returns the controlled context state.
func (c *adapterMutableContext) Err() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.err
}

// Value returns no ambient values.
func (*adapterMutableContext) Value(any) any { return nil }

// finish publishes exactly one context control-flow transition.
func (c *adapterMutableContext) finish(err error) {
	c.mu.Lock()
	c.err = err
	close(c.done)
	c.mu.Unlock()
}

type adapterPanicContext struct{}

// Deadline panics to emulate a hostile injected context implementation.
func (adapterPanicContext) Deadline() (time.Time, bool) { panic("protected context deadline panic") }

// Done panics to emulate a hostile injected context implementation.
func (adapterPanicContext) Done() <-chan struct{} { panic("protected context done panic") }

// Err panics to emulate a hostile injected context implementation.
func (adapterPanicContext) Err() error { panic("protected context err panic") }

// Value panics to emulate a hostile injected context implementation.
func (adapterPanicContext) Value(any) any { panic("protected context value panic") }

type adapterPostProjectionContext struct {
	mu          sync.Mutex
	done        chan struct{}
	calls       int
	err         error
	terminalErr error
}

// newAdapterPostProjectionContext constructs a context that terminates on the
// adapter's third bounded Err check.
func newAdapterPostProjectionContext(terminalErr error) *adapterPostProjectionContext {
	return &adapterPostProjectionContext{
		done: make(chan struct{}), terminalErr: terminalErr,
	}
}

// Deadline reports no scheduled deadline.
func (*adapterPostProjectionContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

// Done returns the controlled completion channel.
func (c *adapterPostProjectionContext) Done() <-chan struct{} { return c.done }

// Err transitions to the configured terminal cause on the third adapter boundary.
func (c *adapterPostProjectionContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.calls == 3 {
		c.err = c.terminalErr
		close(c.done)
	}
	return c.err
}

// Value returns no ambient values.
func (*adapterPostProjectionContext) Value(any) any { return nil }

// newAdapterFixture constructs one exact eligible profile/policy/registry graph.
func newAdapterFixture(t *testing.T) adapterFixture {
	t.Helper()
	projection := newProjectionFixture(t, "selector", datasource.ProfileUseOriginator)
	tenant, err := datasource.NewTenantID("tenant.example")
	if err != nil {
		t.Fatalf("datasource.NewTenantID() error = %v", err)
	}
	policy := mustAdapterPolicy(
		t,
		tenant,
		projection.profile,
		datasource.RecordStatusActive,
		datasource.RolloutEnforce,
	)
	resolvedPolicy, err := datasource.NewResolvedPolicy(
		projection.resolvedProfile.Generation(),
		policy,
		projection.resolvedProfile,
	)
	if err != nil {
		t.Fatalf("datasource.NewResolvedPolicy() error = %v", err)
	}
	return adapterFixture{
		at: projection.at, tenant: tenant, profile: projection.profile,
		resolvedProfile: projection.resolvedProfile, policy: policy,
		resolvedPolicy: resolvedPolicy, registry: projection.registry,
	}
}

// mustAdapterPolicy constructs one exact administrative policy fixture.
func mustAdapterPolicy(
	t *testing.T,
	tenant datasource.TenantID,
	profile datasource.Profile,
	status datasource.RecordStatus,
	rollout datasource.Rollout,
) datasource.Policy {
	t.Helper()
	policy, err := datasource.NewPolicy(
		tenant,
		profile.SigningDomain(),
		datasource.ProfileUseOriginator,
		profile.ID(),
		status,
		rollout,
		datasource.CompatibilityStrict,
		datasource.FeedbackRouteID{},
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("datasource.NewPolicy() error = %v", err)
	}
	return policy
}

// mustAdapter constructs one valid adapter fixture.
func mustAdapter(
	t *testing.T,
	provider datasource.Provider,
	registry Registry,
) Adapter {
	t.Helper()
	adapter, err := NewAdapter(
		provider,
		registry,
		signing.DefaultLimits(),
	)
	if err != nil || !adapter.Valid() {
		t.Fatalf("NewAdapter() valid=%t code=%s",
			adapter.Valid(), datasource.ErrorCodeOf(err))
	}
	return adapter
}

// adapterProfilesEqual compares every public signing profile fact without
// depending on formatter output or opaque handle identity.
func adapterProfilesEqual(left, right signing.Profile) bool {
	return left.Valid() && right.Valid() &&
		left.Domain() == right.Domain() &&
		adapterCredentialsEqual(left.Credentials(), right.Credentials())
}

// adapterCredentialsEqual compares canonical selector, algorithm, and public
// material for two signing credential slices.
func adapterCredentialsEqual(left, right []signing.Credential) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Selector() != right[index].Selector() ||
			left[index].Algorithm() != right[index].Algorithm() {
			return false
		}
		leftDER, leftErr := x509.MarshalPKIXPublicKey(left[index].PublicKey())
		rightDER, rightErr := x509.MarshalPKIXPublicKey(right[index].PublicKey())
		if leftErr != nil || rightErr != nil || !bytes.Equal(leftDER, rightDER) {
			return false
		}
	}
	return true
}

// parityAdaptersForSnapshot constructs equivalent memory and decoded flat-file
// adapters from one logical valid snapshot.
func parityAdaptersForSnapshot(
	t *testing.T,
	profile datasource.Profile,
	policy datasource.Policy,
	document []byte,
	limits datasource.Limits,
) map[string]Adapter {
	t.Helper()
	credentials := profile.Credentials()
	handles := make([]datasource.KeyHandleID, len(credentials))
	entries := make([]Entry, len(credentials))
	for index, credential := range credentials {
		handles[index] = credential.KeyHandleID()
		handle, err := signing.NewPrivateKeyHandle(
			fmt.Appendf(nil, "parity-handle-%d", index),
		)
		if err != nil {
			t.Fatalf("signing.NewPrivateKeyHandle() error = %v", err)
		}
		entries[index], err = NewEntry(
			profile,
			credential.KeyHandleID(),
			handle,
			[]datasource.ProfileUse{datasource.ProfileUseOriginator},
			limits,
		)
		if err != nil {
			t.Fatalf("NewEntry() error = %v", err)
		}
	}
	policies := []datasource.Policy(nil)
	if policy.Valid() {
		policies = []datasource.Policy{policy}
	}
	memoryProvider, err := memory.New(
		1,
		handles,
		[]datasource.Profile{profile},
		policies,
		limits,
	)
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	flatProvider, err := flatfile.Decode(1, document, limits)
	if err != nil {
		t.Fatalf("flatfile.Decode() error = %v", err)
	}
	registry, err := NewRegistry(entries, limits)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	memoryAdapter, err := NewAdapter(
		memoryProvider, registry, signing.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("NewAdapter(memory) error = %v", err)
	}
	flatAdapter, err := NewAdapter(
		flatProvider, registry, signing.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("NewAdapter(flatfile) error = %v", err)
	}
	return map[string]Adapter{
		adapterMemoryProviderName: memoryAdapter,
		adapterFlatProviderName:   flatAdapter,
	}
}

// assertAdapterParityFailure verifies one zero-profile failure and optional
// standard context identity.
func assertAdapterParityFailure(
	t *testing.T,
	profile signing.Profile,
	err error,
	code datasource.ErrorCode,
	contextIdentity error,
) {
	t.Helper()
	if profile.Valid() || datasource.ErrorCodeOf(err) != code {
		t.Fatalf("failure valid=%t code=%s, want %s",
			profile.Valid(), datasource.ErrorCodeOf(err), code)
	}
	if contextIdentity != nil && !errors.Is(err, contextIdentity) {
		t.Fatalf("failure %v lost context identity %v", err, contextIdentity)
	}
}

// cancelledAdapterContext constructs one already-cancelled context.
func cancelledAdapterContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// expiredAdapterContext constructs one already-expired deadline context.
func expiredAdapterContext() context.Context {
	ctx := newAdapterMutableContext()
	ctx.finish(context.DeadlineExceeded)
	return ctx
}
