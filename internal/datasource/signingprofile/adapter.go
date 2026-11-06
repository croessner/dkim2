package signingprofile

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/croessner/dkim2/internal/datasource"
	"github.com/croessner/dkim2/internal/niliface"
	"github.com/croessner/dkim2/internal/signing"
)

// Adapter resolves one datasource selection into a complete signing profile.
type Adapter struct {
	provider      datasource.Provider
	registry      Registry
	signingLimits signing.Limits
	complete      bool
}

// NewAdapter constructs one immutable datasource-to-signing bridge.
func NewAdapter(
	provider datasource.Provider,
	registry Registry,
	signingLimits signing.Limits,
) (Adapter, error) {
	if signingLimits.Validate() != nil {
		return Adapter{}, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	if niliface.IsNil(provider) || !registry.Valid() {
		return Adapter{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	cloned, err := cloneRegistryForAdapter(registry)
	if err != nil {
		return Adapter{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	return Adapter{
		provider: provider, registry: cloned, signingLimits: signingLimits,
		complete: true,
	}, nil
}

// Valid reports whether the adapter retains complete immutable dependencies.
func (a Adapter) Valid() bool {
	return a.complete && !niliface.IsNil(a.provider) &&
		a.registry.Valid() && a.signingLimits.Validate() == nil
}

// ResolveProfile resolves and projects one exact profile selection.
func (a Adapter) ResolveProfile(
	ctx context.Context,
	profileID datasource.ProfileID,
	use datasource.ProfileUse,
	evaluationTime time.Time,
) (profile signing.Profile, resultErr error) {
	defer func() {
		if recover() != nil {
			profile = signing.Profile{}
			resultErr = datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
	}()
	if err := adapterContextError(ctx); err != nil {
		return signing.Profile{}, err
	}
	if !a.Valid() {
		return signing.Profile{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	request, err := datasource.NewProfileRequest(
		profileID, use, evaluationTime, a.registry.limits,
	)
	if err != nil {
		return signing.Profile{}, err
	}
	result, providerPanicked, providerErr := callResolveProfile(ctx, a.provider, request)
	if providerPanicked {
		return signing.Profile{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	if err := datasource.ValidateProfileOutcome(result, providerErr); err != nil {
		return signing.Profile{}, err
	}
	postCallErr := adapterContextError(ctx)
	if err := datasource.ReconcileContextFailure(providerErr, postCallErr); err != nil {
		return signing.Profile{}, err
	}
	projected, projectionErr := a.registry.ProjectProfile(
		result, request, a.signingLimits,
	)
	if err := validateProjectionOutcome(projected, projectionErr); err != nil {
		return signing.Profile{}, err
	}
	postProjectionErr := adapterContextError(ctx)
	if err := datasource.ReconcileContextFailure(projectionErr, postProjectionErr); err != nil {
		return signing.Profile{}, err
	}
	return projected, nil
}

// ResolvePolicy resolves and projects one exact administrative policy selection.
func (a Adapter) ResolvePolicy(
	ctx context.Context,
	tenant datasource.TenantID,
	domain string,
	use datasource.ProfileUse,
	evaluationTime time.Time,
) (profile signing.Profile, resultErr error) {
	defer func() {
		if recover() != nil {
			profile = signing.Profile{}
			resultErr = datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
	}()
	if err := adapterContextError(ctx); err != nil {
		return signing.Profile{}, err
	}
	if !a.Valid() {
		return signing.Profile{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	request, err := datasource.NewPolicyRequest(
		tenant, domain, use, evaluationTime, a.registry.limits,
	)
	if err != nil {
		return signing.Profile{}, err
	}
	result, providerPanicked, providerErr := callResolvePolicy(ctx, a.provider, request)
	if providerPanicked {
		return signing.Profile{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	if err := datasource.ValidatePolicyOutcome(result, providerErr); err != nil {
		return signing.Profile{}, err
	}
	postCallErr := adapterContextError(ctx)
	if err := datasource.ReconcileContextFailure(providerErr, postCallErr); err != nil {
		return signing.Profile{}, err
	}
	projected, projectionErr := a.registry.ProjectPolicy(
		result, request, a.signingLimits,
	)
	if err := validateProjectionOutcome(projected, projectionErr); err != nil {
		return signing.Profile{}, err
	}
	postProjectionErr := adapterContextError(ctx)
	if err := datasource.ReconcileContextFailure(projectionErr, postProjectionErr); err != nil {
		return signing.Profile{}, err
	}
	return projected, nil
}

// String returns a constant protected adapter summary.
func (a Adapter) String() string { return "signingprofile.Adapter{redacted}" }

// GoString returns a constant protected adapter representation.
func (a Adapter) GoString() string { return a.String() }

// Format prevents formatting verbs from exposing adapter dependencies.
func (a Adapter) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, a.String())
}

// MarshalJSON emits an empty object without provider or registry facts.
func (a Adapter) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// cloneRegistryForAdapter deep-copies one already validated registry.
func cloneRegistryForAdapter(registry Registry) (Registry, error) {
	if !registry.Valid() {
		return Registry{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	entries := make([]Entry, 0, len(registry.entries))
	for _, entry := range registry.entries {
		entries = append(entries, cloneEntry(entry))
	}
	cloned, err := NewRegistry(entries, registry.limits)
	if err != nil || !cloned.Valid() {
		return Registry{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	return cloned, nil
}

// adapterContextError validates one caller context at a bounded adapter boundary.
func adapterContextError(ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
	}()
	if niliface.IsNil(ctx) {
		return datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	if err := datasource.ErrorFromContext(ctx); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		if err := datasource.ErrorFromContext(ctx); err != nil {
			return err
		}
		return datasource.NewError(datasource.ErrorCodeInternalInvariant)
	default:
		return nil
	}
}

// callResolveProfile contains panics at the injected profile-provider boundary.
func callResolveProfile(
	ctx context.Context,
	provider datasource.Provider,
	request datasource.ProfileRequest,
) (result datasource.ResolvedProfile, panicked bool, resultErr error) {
	defer func() {
		if recover() != nil {
			result = datasource.ResolvedProfile{}
			panicked = true
			resultErr = datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
	}()
	result, resultErr = provider.ResolveProfile(ctx, request)
	return result, false, resultErr
}

// callResolvePolicy contains panics at the injected policy-provider boundary.
func callResolvePolicy(
	ctx context.Context,
	provider datasource.Provider,
	request datasource.PolicyRequest,
) (result datasource.ResolvedPolicy, panicked bool, resultErr error) {
	defer func() {
		if recover() != nil {
			result = datasource.ResolvedPolicy{}
			panicked = true
			resultErr = datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
	}()
	result, resultErr = provider.ResolvePolicy(ctx, request)
	return result, false, resultErr
}

// validateProjectionOutcome validates one complete signing profile or direct typed failure shape.
func validateProjectionOutcome(profile signing.Profile, err error) error {
	switch {
	case err == nil && profile.Valid():
		return nil
	case err != nil && !profile.Valid() && datasource.IsTypedError(err):
		return nil
	default:
		return datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
}
