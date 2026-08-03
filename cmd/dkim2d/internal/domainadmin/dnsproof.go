package domainadmin

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// ResolverPathClass identifies the actual operational recursive lookup boundary.
type ResolverPathClass string

const (
	resolverClassSystem    = "system"
	resolverClassRecursive = "recursive"

	// ResolverPathSystem uses a fresh zero-value resolver over platform resolver configuration.
	ResolverPathSystem ResolverPathClass = "system_recursive"
	// ResolverPathExplicit uses a fresh Go resolver instance over explicit recursive endpoints.
	ResolverPathExplicit ResolverPathClass = "explicit_recursive"
)

// DNSCacheResponsibility states that resolver-path caches remain operator-managed preconditions.
type DNSCacheResponsibility string

const (
	// DNSCacheOperatorManaged requires operators to honor positive TTL and negative-cache policy.
	DNSCacheOperatorManaged DNSCacheResponsibility = "operator_managed_ttl_and_negative_cache"
)

type dnsProviderFactory func(context.Context, datasourceadmin.DNSPolicy) (dkim2.PublicKeyProvider, error)

// DNSProofEngine creates one fresh process-local provider and resolver per proof attempt.
type DNSProofEngine struct {
	limits  Limits
	clock   func() time.Time
	factory dnsProviderFactory
}

// NewDNSProofEngine constructs the production recursive resolver-path proof owner.
func NewDNSProofEngine(limits Limits) (*DNSProofEngine, error) {
	return newDNSProofEngine(limits, time.Now, func(
		ctx context.Context,
		policy datasourceadmin.DNSPolicy,
	) (dkim2.PublicKeyProvider, error) {
		return newRecursiveDNSProvider(ctx, policy, limits.BackendDeadline)
	})
}

// newDNSProofEngine constructs one engine over deterministic clock and provider seams.
func newDNSProofEngine(
	limits Limits,
	clock func() time.Time,
	factory dnsProviderFactory,
) (*DNSProofEngine, error) {
	if limits.Validate() != nil || clock == nil || factory == nil {
		return nil, newError(CodeInvalidLimits)
	}
	return &DNSProofEngine{limits: limits, clock: clock, factory: factory}, nil
}

// Prove performs one fresh recursive-path lookup for every exact staged credential.
func (e *DNSProofEngine) Prove(ctx context.Context, set *StagedDNSSet) (*DNSProof, error) {
	if e == nil || ctx == nil || ctx.Err() != nil || set == nil || e.factory == nil || e.clock == nil ||
		e.limits.Validate() != nil {
		return nil, newError(CodeUnavailable)
	}
	set.mu.Lock()
	if set.closed || len(set.records) == 0 || len(set.records) > int(e.limits.MaxDNSRecords) ||
		set.policy.ProofLifetimeSeconds == 0 {
		set.mu.Unlock()
		return nil, newError(CodeConflict)
	}
	records := cloneDNSRecords(set.records)
	policy := cloneDNSPolicy(set.policy)
	plan := set.plan
	staged := set.staged
	set.mu.Unlock()
	defer clearDNSRecords(records)
	if !plan.Valid() || !staged.Digest().Valid() {
		return nil, newError(CodeConflict)
	}
	lifetime := time.Duration(policy.ProofLifetimeSeconds) * time.Second
	if lifetime <= 0 || lifetime > e.limits.DNSProofLifetime {
		return nil, newError(CodeInvalidLimits)
	}
	bounded, cancel := context.WithTimeout(ctx, e.limits.BackendDeadline)
	defer cancel()
	providerValue, err := e.factory(bounded, policy)
	if err != nil || providerValue == nil {
		return nil, newError(CodeUnavailable)
	}
	for _, record := range records {
		if bounded.Err() != nil {
			return nil, newError(CodeUnavailable)
		}
		query, queryErr := dkim2.NewPublicKeyQuery(
			string(record.domain), string(record.selector), dkim2Algorithm(record.algorithm),
		)
		if queryErr != nil {
			return nil, newError(CodeDNSInvalid)
		}
		result, lookupErr := providerValue.LookupPublicKey(bounded, query)
		if lookupErr != nil {
			return nil, newError(CodeUnavailable)
		}
		if result.Status() != dkim2.PublicKeyStatusFound {
			return nil, dnsStatusError(result.Status())
		}
		if result.Algorithm() != query.Algorithm() {
			return nil, newError(CodeDNSAlgorithmMismatch)
		}
		actualSPKI, spkiErr := resultSPKI(result)
		if spkiErr != nil {
			return nil, spkiErr
		}
		matched := bytes.Equal(actualSPKI, record.publicSPKI)
		clear(actualSPKI)
		if !matched {
			return nil, newError(CodeDNSSPKIMismatch)
		}
	}
	completed := e.clock().UTC().Truncate(time.Second)
	if completed.Unix() <= 0 || bounded.Err() != nil {
		return nil, newError(CodeUnavailable)
	}
	expires := completed.Add(lifetime)
	if !expires.After(completed) {
		return nil, newError(CodeInvalidLimits)
	}
	path := ResolverPathExplicit
	if policy.ResolverClass == resolverClassSystem {
		path = ResolverPathSystem
	}
	return &DNSProof{
		plan: plan, staged: staged, completed: completed, expires: expires, path: path,
		cacheResponsibility: DNSCacheOperatorManaged, recordCount: uint32(len(records)),
	}, nil
}

// dnsStatusError maps the full public resolver result matrix to bounded proof failures.
func dnsStatusError(status dkim2.PublicKeyStatus) error {
	switch status {
	case dkim2.PublicKeyStatusMissing:
		return newError(CodeDNSMissing)
	case dkim2.PublicKeyStatusAmbiguous:
		return newError(CodeDNSAmbiguous)
	case dkim2.PublicKeyStatusUnsupportedKeyType:
		return newError(CodeDNSUnsupported)
	case dkim2.PublicKeyStatusAlgorithmMismatch:
		return newError(CodeDNSAlgorithmMismatch)
	case dkim2.PublicKeyStatusInvalid, dkim2.PublicKeyStatusRevoked:
		return newError(CodeDNSInvalid)
	default:
		return newError(CodeUnavailable)
	}
}

// newRecursiveDNSProvider constructs a new cache-disabled provider over the configured recursive path.
func newRecursiveDNSProvider(
	ctx context.Context,
	policy datasourceadmin.DNSPolicy,
	lookupTimeout time.Duration,
) (dkim2.PublicKeyProvider, error) {
	if ctx == nil || ctx.Err() != nil || lookupTimeout <= 0 || lookupTimeout > 30*time.Second {
		return nil, newError(CodeUnavailable)
	}
	resolver, err := newResolverForDNSPolicy(policy)
	if err != nil {
		return nil, err
	}
	transport, err := dkim2.NewNetTXTTransport(resolver)
	if err != nil {
		return nil, newError(CodeUnavailable)
	}
	configuration := dkim2.DefaultDNSProviderConfig()
	configuration.Parent = ctx
	configuration.Limits.MaxCacheEntries = 0
	configuration.Limits.LookupTimeout = lookupTimeout
	providerValue, err := dkim2.NewDNSPublicKeyProviderWithConfig(transport, configuration)
	if err != nil {
		return nil, newError(CodeUnavailable)
	}
	return providerValue, nil
}

// newResolverForDNSPolicy preserves platform semantics for system paths and confines explicit paths.
func newResolverForDNSPolicy(policy datasourceadmin.DNSPolicy) (*net.Resolver, error) {
	if policy.ResolverClass == resolverClassSystem {
		if len(policy.ResolverEndpoints) != 0 {
			return nil, newError(CodeDNSInvalid)
		}
		return &net.Resolver{}, nil
	}
	if policy.ResolverClass == resolverClassRecursive && len(policy.ResolverEndpoints) != 0 {
		dialer, err := newRecursiveEndpointDialer(policy.ResolverEndpoints)
		if err != nil {
			return nil, err
		}
		resolver := &net.Resolver{PreferGo: true, StrictErrors: true}
		resolver.Dial = dialer.DialContext
		return resolver, nil
	}
	return nil, newError(CodeDNSInvalid)
}

type recursiveEndpointDialer struct {
	endpoints []string
	next      atomic.Uint64
	dialer    net.Dialer
}

// newRecursiveEndpointDialer validates and detaches canonical recursive endpoints.
func newRecursiveEndpointDialer(endpoints []string) (*recursiveEndpointDialer, error) {
	if len(endpoints) == 0 {
		return nil, newError(CodeDNSInvalid)
	}
	owned := make([]string, len(endpoints))
	for index, endpoint := range endpoints {
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil || host == "" || port == "" {
			return nil, newError(CodeDNSInvalid)
		}
		owned[index] = endpoint
	}
	return &recursiveEndpointDialer{endpoints: owned}, nil
}

// DialContext uses only configured recursive endpoints and never the requested default address.
func (d *recursiveEndpointDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || len(d.endpoints) == 0 {
		return nil, newError(CodeUnavailable)
	}
	start := int(d.next.Add(1)-1) % len(d.endpoints)
	for offset := range len(d.endpoints) {
		endpoint := d.endpoints[(start+offset)%len(d.endpoints)]
		connection, err := d.dialer.DialContext(ctx, network, endpoint)
		if err == nil {
			return connection, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, newError(CodeUnavailable)
}

// DNSProof is one unpersisted in-process activation-gating capability.
type DNSProof struct {
	mu                  sync.Mutex
	plan                datasourceadmin.PlanDigest
	staged              datasourceadmin.StagedEvidence
	completed           time.Time
	expires             time.Time
	path                ResolverPathClass
	cacheResponsibility DNSCacheResponsibility
	recordCount         uint32
	closed              bool
}

// ValidFor reports whether this in-process proof is live and bound to one exact plan and staged readback.
func (p *DNSProof) ValidFor(
	plan datasourceadmin.PlanDigest,
	staged datasourceadmin.StagedEvidence,
	now time.Time,
) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.closed && p.plan.Valid() && p.plan.Equal(plan) && p.staged.Digest().Valid() &&
		p.staged.Digest().Equal(staged.Digest()) &&
		!now.Before(p.completed) && now.Before(p.expires)
}

// RequireValidFor returns a bounded expiry or mismatch failure.
func (p *DNSProof) RequireValidFor(
	plan datasourceadmin.PlanDigest,
	staged datasourceadmin.StagedEvidence,
	now time.Time,
) error {
	if p == nil {
		return newError(CodeConflict)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || !p.plan.Valid() || !p.plan.Equal(plan) || !p.staged.Digest().Valid() ||
		!p.staged.Digest().Equal(staged.Digest()) {
		return newError(CodeConflict)
	}
	if now.Before(p.completed) || !now.Before(p.expires) {
		return newError(CodeDNSProofExpired)
	}
	return nil
}

// activationEvidence returns exact live proof timing only for its bound plan and staged readback.
func (p *DNSProof) activationEvidence(
	plan datasourceadmin.PlanDigest,
	staged datasourceadmin.StagedEvidence,
	now time.Time,
) (time.Time, time.Duration, error) {
	if p == nil {
		return time.Time{}, 0, newError(CodeConflict)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || !p.plan.Valid() || !p.plan.Equal(plan) || !p.staged.Digest().Valid() ||
		!p.staged.Digest().Equal(staged.Digest()) {
		return time.Time{}, 0, newError(CodeConflict)
	}
	if now.Before(p.completed) || !now.Before(p.expires) {
		return time.Time{}, 0, newError(CodeDNSProofExpired)
	}
	return p.completed, p.expires.Sub(p.completed), nil
}

// ResolverPath returns the accurate recursive resolver-path class.
func (p *DNSProof) ResolverPath() ResolverPathClass {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ""
	}
	return p.path
}

// CacheResponsibility reports the mandatory operator TTL and negative-cache precondition.
func (p *DNSProof) CacheResponsibility() DNSCacheResponsibility {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ""
	}
	return p.cacheResponsibility
}

// ClaimsAuthoritativeServerContact reports false because the implementation queries recursive resolvers.
func (*DNSProof) ClaimsAuthoritativeServerContact() bool { return false }

// ClaimsUpstreamCacheBypass reports false because recursive positive and negative caches remain upstream.
func (*DNSProof) ClaimsUpstreamCacheBypass() bool { return false }

// Close invalidates and clears the in-process proof capability.
func (p *DNSProof) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.plan = datasourceadmin.PlanDigest{}
	p.staged = datasourceadmin.StagedEvidence{}
	p.completed = time.Time{}
	p.expires = time.Time{}
	p.path = ""
	p.cacheResponsibility = ""
	p.recordCount = 0
	p.closed = true
	return nil
}

// String returns a constant protected DNS-proof representation.
func (*DNSProof) String() string { return redacted }

// GoString returns a constant protected DNS-proof representation.
func (*DNSProof) GoString() string { return redacted }

// Format prevents proof timing and digest state from reaching formatting sinks.
func (*DNSProof) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects persistence of an activation-gating DNS proof.
func (*DNSProof) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }

// String returns a constant DNS-proof engine representation.
func (*DNSProofEngine) String() string { return redacted }

// GoString returns a constant DNS-proof engine representation.
func (*DNSProofEngine) GoString() string { return redacted }

// Format prevents resolver configuration from reaching formatting sinks.
func (*DNSProofEngine) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic DNS-proof engine serialization.
func (*DNSProofEngine) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }
