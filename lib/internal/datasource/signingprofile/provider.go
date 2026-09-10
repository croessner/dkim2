package signingprofile

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/croessner/dkim2/internal/datasource"
	"github.com/croessner/dkim2/internal/niliface"
	"github.com/croessner/dkim2/internal/signing"
)

// Binding carries one exact administrative key declaration into the sole bridge.
type Binding struct {
	tenant       datasource.TenantID
	domain       string
	use          datasource.ProfileUse
	handleID     datasource.KeyHandleID
	handle       signing.PrivateKeyHandle
	algorithm    datasource.Algorithm
	publicDigest [sha256.Size]byte
	valid        bool
}

const bindingRedacted = "signingprofile.Binding{redacted}"

// String returns a constant protected binding summary.
func (Binding) String() string { return bindingRedacted }

// GoString returns a constant protected binding representation.
func (Binding) GoString() string { return bindingRedacted }

// Format prevents formatting verbs from traversing binding state.
func (Binding) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, bindingRedacted)
}

// MarshalJSON emits an empty object without selection or key facts.
func (Binding) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// Valid reports whether the binding owns one complete protected projection.
func (b Binding) Valid() bool { return b.valid }

// NewBinding validates one exact provider-neutral key declaration.
func NewBinding(
	tenant string,
	domain string,
	useText string,
	handleID string,
	handle signing.PrivateKeyHandle,
	algorithmText string,
	publicDigest [sha256.Size]byte,
) (Binding, error) {
	use, useOK := parseBindingUse(useText)
	algorithm, algorithmOK := parseBindingAlgorithm(algorithmText)
	tenantValue, tenantErr := datasource.NewTenantID(tenant)
	handleValue, handleErr := datasource.NewKeyHandleID(handleID)
	if tenantErr != nil || handleErr != nil || !useOK ||
		!handle.Valid() || !algorithmOK {
		return Binding{}, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	if _, err := datasource.NewPolicyRequest(
		tenantValue, domain, use, time.Unix(1, 0), datasource.DefaultLimits(),
	); err != nil {
		return Binding{}, err
	}
	return Binding{
		tenant: tenantValue, domain: domain, use: use,
		handleID: handleValue, handle: handle, algorithm: algorithm,
		publicDigest: publicDigest, valid: true,
	}, nil
}

// Resolver owns one provider-neutral generation and its exact signing projection
// registry.
type Resolver struct {
	mu       sync.RWMutex
	provider datasource.Provider
	adapter  Adapter
	closed   bool
}

// NewResolver validates every immutable binding, including inactive policies,
// without granting signing authority. Runtime projection still checks status,
// rollout, and validity for each message.
func NewResolver(
	provider datasource.InspectionProvider,
	bindings []Binding,
	at time.Time,
) (*Resolver, error) {
	if niliface.IsNil(provider) || len(bindings) == 0 || at.IsZero() {
		return nil, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	limits := datasource.DefaultLimits()
	if len(bindings) > limits.MaxHandles {
		return nil, datasource.NewError(datasource.ErrorCodeLimitExceeded)
	}
	entries := make([]Entry, 0, len(bindings))
	inspected := make([]datasource.ResolvedPolicy, 0, len(bindings))
	seen := make(map[datasource.KeyHandleID]struct{}, len(bindings))
	for _, binding := range bindings {
		if !binding.valid {
			return nil, datasource.NewError(datasource.ErrorCodeInvalidRequest)
		}
		if _, duplicate := seen[binding.handleID]; duplicate {
			return nil, datasource.NewError(datasource.ErrorCodeAmbiguous)
		}
		resolved, inspectErr := inspectBindingPolicy(provider, binding, at, limits)
		if inspectErr != nil {
			return nil, inspectErr
		}
		if len(inspected) > 0 && resolved.Generation() != inspected[0].Generation() {
			return nil, datasource.NewError(datasource.ErrorCodeMalformedData)
		}
		credential, found := credentialByHandle(resolved.Profile(), binding.handleID)
		if !found || credential.Algorithm() != binding.algorithm ||
			credential.PublicKeySPKISHA256() != binding.publicDigest {
			return nil, datasource.NewError(datasource.ErrorCodeInvalidRequest)
		}
		entry, entryErr := NewEntry(
			resolved.Profile(), binding.handleID, binding.handle,
			[]datasource.ProfileUse{binding.use}, limits,
		)
		if entryErr != nil {
			return nil, entryErr
		}
		entries = append(entries, entry)
		inspected = append(inspected, resolved)
		seen[binding.handleID] = struct{}{}
	}
	registry, err := NewRegistry(entries, limits)
	if err != nil {
		return nil, err
	}
	adapter, err := NewAdapter(provider, registry, signing.DefaultLimits())
	if err != nil {
		return nil, err
	}
	for index, binding := range bindings {
		if _, matchErr := registry.matchedEntries(inspected[index].Profile(), binding.use); matchErr != nil {
			return nil, matchErr
		}
	}
	output := &Resolver{provider: provider, adapter: adapter}
	return output, nil
}

// inspectBindingPolicy contains hostile providers and checks exact immutable
// selection identity before a credential enters the inert registry.
func inspectBindingPolicy(
	provider datasource.InspectionProvider,
	binding Binding,
	at time.Time,
	limits datasource.Limits,
) (result datasource.ResolvedPolicy, resultErr error) {
	defer func() {
		if recover() != nil {
			result = datasource.ResolvedPolicy{}
			resultErr = datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
	}()
	request, err := datasource.NewPolicyRequest(binding.tenant, binding.domain, binding.use, at, limits)
	if err != nil {
		return datasource.ResolvedPolicy{}, err
	}
	resolved, err := provider.InspectPolicy(context.Background(), request)
	if outcomeErr := datasource.ValidatePolicyOutcome(resolved, err); outcomeErr != nil {
		return datasource.ResolvedPolicy{}, outcomeErr
	}
	if err != nil {
		return datasource.ResolvedPolicy{}, err
	}
	policy := resolved.Policy()
	if !resolved.ValidForLimits(limits) || policy.TenantID() != binding.tenant ||
		policy.SigningDomain() != binding.domain || policy.Use() != binding.use {
		return datasource.ResolvedPolicy{}, datasource.NewError(datasource.ErrorCodeMalformedData)
	}
	return resolved, nil
}

// ResolvePolicy returns one internal signing profile from the sole adapter.
func (r *Resolver) ResolvePolicy(
	ctx context.Context,
	tenant string,
	domain string,
	useText string,
	at time.Time,
) (signing.Profile, error) {
	use, useOK := parseBindingUse(useText)
	if r == nil || ctx == nil || !useOK || at.IsZero() {
		return signing.Profile{}, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	tenantID, err := datasource.NewTenantID(tenant)
	if err != nil {
		return signing.Profile{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed || r.provider == nil || !r.adapter.Valid() {
		return signing.Profile{}, datasource.NewError(datasource.ErrorCodeUnavailable)
	}
	return r.adapter.ResolvePolicy(ctx, tenantID, domain, use, at)
}

// parseBindingUse maps the closed public bridge vocabulary.
func parseBindingUse(value string) (datasource.ProfileUse, bool) {
	switch value {
	case "originator":
		return datasource.ProfileUseOriginator, true
	case "ordinary_transit":
		return datasource.ProfileUseOrdinaryTransit, true
	case "delivery_status":
		return datasource.ProfileUseDeliveryStatus, true
	default:
		return 0, false
	}
}

// parseBindingAlgorithm maps the closed public algorithm vocabulary.
func parseBindingAlgorithm(value string) (datasource.Algorithm, bool) {
	switch value {
	case "rsa-sha256":
		return datasource.AlgorithmRSASHA256, true
	case "ed25519-sha256":
		return datasource.AlgorithmEd25519SHA256, true
	default:
		return "", false
	}
}

// Close releases the confined datasource descriptor exactly once.
func (r *Resolver) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	if ctx == nil || ctx.Err() != nil || r.provider == nil {
		return datasource.NewError(datasource.ErrorCodeUnavailable)
	}
	r.closed = true
	r.provider = nil
	r.adapter = Adapter{}
	return nil
}

// credentialByHandle finds exactly one matching profile credential.
func credentialByHandle(
	profile datasource.Profile,
	handle datasource.KeyHandleID,
) (datasource.Credential, bool) {
	var selected datasource.Credential
	count := 0
	for _, credential := range profile.Credentials() {
		if credential.KeyHandleID() == handle {
			selected = credential
			count++
		}
	}
	return selected, count == 1
}
