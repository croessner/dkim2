package signingprofile

import (
	"context"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/datasource"
)

// inspectionFixtureProvider models a complete immutable inspection owner.
// Active resolution deliberately panics: construction must never request it.
type inspectionFixtureProvider struct {
	panicPolicyProvider
	result datasource.ResolvedPolicy
	err    error
}

// InspectPolicy returns the explicitly configured inert test outcome.
func (p inspectionFixtureProvider) InspectPolicy(context.Context, datasource.PolicyRequest) (datasource.ResolvedPolicy, error) {
	return p.result, p.err
}

// TestInspectionRejectsWrongSelectionAndMalformedOutcomes ensures construction
// checks exact policy scope and the result/error matrix for inert records.
func TestInspectionRejectsWrongSelectionAndMalformedOutcomes(t *testing.T) {
	fixture := newProjectionFixture(t, "inspection", datasource.ProfileUseOriginator)
	credential := fixture.profile.Credentials()[0]
	binding, err := NewBinding("tenant", fixture.profile.SigningDomain(), "originator", "key.example", fixture.handle,
		string(credential.Algorithm()), credential.PublicKeySPKISHA256())
	if err != nil {
		t.Fatal("construct inspection binding")
	}
	for _, test := range []struct {
		name   string
		tenant string
		use    datasource.ProfileUse
		zero   bool
		err    error
	}{
		{name: "wrong tenant", tenant: "other", use: datasource.ProfileUseOriginator},
		{name: "wrong use", tenant: "tenant", use: datasource.ProfileUseOrdinaryTransit},
		{name: "zero nil", zero: true},
		{name: "result plus error", tenant: "tenant", use: datasource.ProfileUseOriginator, err: datasource.NewError(datasource.ErrorCodeUnavailable)},
	} {
		t.Run(test.name, func(t *testing.T) {
			var result datasource.ResolvedPolicy
			if !test.zero {
				tenant, err := datasource.NewTenantID(test.tenant)
				if err != nil {
					t.Fatal("construct inspection tenant")
				}
				policy, err := datasource.NewPolicy(tenant, fixture.profile.SigningDomain(), test.use, fixture.profile.ID(),
					datasource.RecordStatusDisabled, datasource.RolloutOff, datasource.CompatibilityStrict, datasource.FeedbackRouteID{}, datasource.DefaultLimits())
				if err != nil {
					t.Fatal("construct inspection policy")
				}
				result, err = datasource.NewResolvedPolicy(1, policy, fixture.resolvedProfile)
				if err != nil {
					t.Fatal("construct inert inspection result")
				}
			}
			owner := inspectionFixtureProvider{result: result, err: test.err}
			if resolver, err := NewResolver(owner, []Binding{binding}, fixture.at); err == nil || resolver != nil {
				t.Fatal("foreign or malformed inert policy entered the registry")
			}
		})
	}
}

// TestInspectionRequiresCompleteInactiveCredentialGroup preserves exact
// multi-algorithm membership even when no signing authorization is available.
func TestInspectionRequiresCompleteInactiveCredentialGroup(t *testing.T) {
	fixture := newProjectionFixture(t, "inspection", datasource.ProfileUseOriginator)
	rsaID := mustProjectionHandleID(t, "key.rsa")
	credentials := append(fixture.profile.Credentials(), newDatasourceCredential(t, "rsa", datasource.AlgorithmRSASHA256, rsaID, 0))
	profile, err := datasource.NewProfile(fixture.profile.ID(), fixture.profile.SigningDomain(), datasource.RecordStatusDisabled,
		credentials, time.Time{}, time.Time{}, datasource.DefaultLimits())
	if err != nil {
		t.Fatal("construct disabled dual-algorithm profile")
	}
	tenant, _ := datasource.NewTenantID("tenant")
	policy, err := datasource.NewPolicy(tenant, profile.SigningDomain(), datasource.ProfileUseOriginator, profile.ID(),
		datasource.RecordStatusDisabled, datasource.RolloutOff, datasource.CompatibilityStrict, datasource.FeedbackRouteID{}, datasource.DefaultLimits())
	if err != nil {
		t.Fatal("construct disabled dual-algorithm policy")
	}
	resolved, err := datasource.NewResolvedProfile(1, profile)
	if err != nil {
		t.Fatal("construct inactive profile result")
	}
	result, err := datasource.NewResolvedPolicy(1, policy, resolved)
	if err != nil {
		t.Fatal("construct inactive policy result")
	}
	var bindings []Binding
	for _, credential := range credentials {
		var handleID string
		if credential.Algorithm() == datasource.AlgorithmRSASHA256 {
			handleID = "key.rsa"
		} else {
			handleID = "key.example"
		}
		binding, err := NewBinding("tenant", profile.SigningDomain(), "originator", handleID, fixture.handle,
			string(credential.Algorithm()), credential.PublicKeySPKISHA256())
		if err != nil {
			t.Fatal("construct inactive credential binding")
		}
		bindings = append(bindings, binding)
	}
	owner := inspectionFixtureProvider{result: result}
	if resolver, err := NewResolver(owner, bindings[:1], fixture.at); err == nil || resolver != nil {
		t.Fatal("partial inactive credential group entered registry")
	}
	resolver, err := NewResolver(owner, bindings, fixture.at)
	if err != nil || resolver == nil {
		t.Fatal("complete inactive group failed inert construction")
	}
	if err := resolver.Close(context.Background()); err != nil {
		t.Fatal("close inactive fixture resolver")
	}
}
