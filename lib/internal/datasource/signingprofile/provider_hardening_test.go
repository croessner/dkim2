package signingprofile

import (
	"context"
	"testing"

	"github.com/croessner/dkim2/internal/datasource"
)

type panicPolicyProvider struct{}

// ResolveProfile panics to model a hostile provider boundary.
func (panicPolicyProvider) ResolveProfile(
	context.Context,
	datasource.ProfileRequest,
) (datasource.ResolvedProfile, error) {
	panic("protected-provider-marker")
}

// ResolvePolicy panics to model a hostile provider boundary.
func (panicPolicyProvider) ResolvePolicy(
	context.Context,
	datasource.PolicyRequest,
) (datasource.ResolvedPolicy, error) {
	panic("protected-provider-marker")
}

// TestResolverConstructionContainsProviderPanic proves candidate construction
// fails closed instead of propagating provider panics into daemon startup.
func TestResolverConstructionContainsProviderPanic(t *testing.T) {
	fixture := newProjectionFixture(
		t, "provider-panic", datasource.ProfileUseOriginator,
	)
	credential := fixture.profile.Credentials()[0]
	binding, err := NewBinding(
		"tenant.provider",
		fixture.profile.SigningDomain(),
		"originator",
		"key.provider",
		fixture.handle,
		string(credential.Algorithm()),
		credential.PublicKeySPKISHA256(),
	)
	if err != nil {
		t.Fatalf("NewBinding() error = %v", err)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("NewResolver() propagated provider panic")
		}
	}()
	resolver, err := NewResolver(
		panicPolicyProvider{}, []Binding{binding}, fixture.at,
	)
	if err == nil || resolver != nil ||
		datasource.ErrorCodeOf(err) != datasource.ErrorCodeInternalInvariant {
		t.Fatalf(
			"NewResolver() resolver=%v code=%s",
			resolver,
			datasource.ErrorCodeOf(err),
		)
	}
}
