package app

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/croessner/dkim2"
)

const (
	localAuthorityRedacted = "dkim2d_local_authority"
	// localAuthorityNegativeCacheEntries bounds the daemon's not_local memory.
	// The cache exists so that a stream of foreign delivery-status
	// notifications cannot turn every inbound message into a datasource read.
	localAuthorityNegativeCacheEntries = 1024
	// localAuthorityNegativeTTL bounds how long a not_local answer is reused,
	// so that a newly provisioned domain becomes local without a restart.
	localAuthorityNegativeTTL = 60 * time.Second
	// localAuthorityMaxDomainBytes bounds the canonical domain syntax gate.
	localAuthorityMaxDomainBytes = 253
	// localAuthorityMaxLabelBytes bounds one canonical DNS label.
	localAuthorityMaxLabelBytes = 63
	// localAuthorityRegistryEntries bounds the retained per-tenant resolvers.
	localAuthorityRegistryEntries = 64
)

// LocalAuthorityResolver answers whether a signer-chosen domain is a local
// authority domain for one bound tenant. Locality is datasource authority
// over the domain and nothing else: an address in mf= is never identity. The
// resolver validates canonical domain syntax before every read, because the
// domain arrives from a remote signature, and serves repeated foreign domains
// from a bounded negative cache so that the first datasource dependency on
// the inbound path stays cheap. A datasource outage is reported as an error,
// which the evaluation maps to a temporary local-hop failure, never to
// not_local.
type LocalAuthorityResolver struct {
	authority SigningAuthority
	tenant    string
	clock     func() time.Time

	mu       sync.Mutex
	negative map[string]time.Time
}

// newLocalAuthorityResolver constructs one tenant-bound authority resolver.
func newLocalAuthorityResolver(
	authority SigningAuthority,
	tenant string,
	clock func() time.Time,
) (*LocalAuthorityResolver, error) {
	if nilInterface(authority) || tenant == "" || clock == nil {
		return nil, &DomainError{}
	}
	return &LocalAuthorityResolver{
		authority: authority,
		tenant:    tenant,
		clock:     clock,
		negative:  make(map[string]time.Time, 16),
	}, nil
}

// LookupLocalAuthority reports whether the bound tenant holds an active
// signing profile of any use for the canonical domain. A syntactically
// non-canonical domain is not_local without a datasource read; a temporary
// datasource condition is returned as an error and never degraded.
func (r *LocalAuthorityResolver) LookupLocalAuthority(
	ctx context.Context,
	domain string,
) (dkim2.LocalAuthorityStatus, error) {
	if r == nil || nilInterface(r.authority) || r.clock == nil {
		return "", &DomainError{}
	}
	if err := domainContextError(ctx); err != nil {
		return "", err
	}
	if !canonicalAuthorityDomain(domain) {
		return dkim2.LocalAuthorityNotLocal, nil
	}
	now := r.clock().UTC()
	if r.negativeHit(domain, now) {
		return dkim2.LocalAuthorityNotLocal, nil
	}
	lease, err := r.authority.Acquire(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = lease.Close() }()
	if err := lease.ResolveAnyProfile(ctx, r.tenant, domain, now); err != nil {
		if !permanentPolicyResolutionFailure(err) {
			return "", err
		}
		r.rememberNotLocal(domain, now)
		return dkim2.LocalAuthorityNotLocal, nil
	}
	return dkim2.LocalAuthorityLocal, nil
}

// negativeHit reports a live cached not_local answer for the domain.
func (r *LocalAuthorityResolver) negativeHit(domain string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	expiry, ok := r.negative[domain]
	if !ok {
		return false
	}
	if !now.Before(expiry) {
		delete(r.negative, domain)
		return false
	}
	return true
}

// rememberNotLocal records one bounded negative answer, evicting expired
// entries first and then, if the cache is still full, arbitrary entries, so
// that the memory stays bounded under a hostile stream of foreign domains.
func (r *LocalAuthorityResolver) rememberNotLocal(domain string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for candidate, expiry := range r.negative {
		if !now.Before(expiry) {
			delete(r.negative, candidate)
		}
	}
	for candidate := range r.negative {
		if len(r.negative) < localAuthorityNegativeCacheEntries {
			break
		}
		delete(r.negative, candidate)
	}
	r.negative[domain] = now.Add(localAuthorityNegativeTTL)
}

// negativeCacheSize reports the current bounded negative-cache occupancy.
func (r *LocalAuthorityResolver) negativeCacheSize() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.negative)
}

// LocalAuthorityRegistry owns the daemon's bounded per-tenant authority
// resolvers. One registry is shared by every route that evaluates received
// delivery-status notifications, so that a resolver's negative cache spans
// requests and routes instead of dying with the request that populated it.
type LocalAuthorityRegistry struct {
	authority SigningAuthority
	clock     func() time.Time

	mu        sync.Mutex
	resolvers map[string]*LocalAuthorityResolver
}

// NewLocalAuthorityRegistry constructs one bounded resolver registry. The
// authority may be absent, which leaves every tenant unresolvable and every
// evaluation without a local authority.
func NewLocalAuthorityRegistry(
	authority SigningAuthority,
	clock func() time.Time,
) (*LocalAuthorityRegistry, error) {
	if clock == nil {
		clock = time.Now
	}
	registry := &LocalAuthorityRegistry{
		clock:     clock,
		resolvers: make(map[string]*LocalAuthorityResolver, 4),
	}
	if !nilInterface(authority) {
		registry.authority = authority
	}
	return registry, nil
}

// Available reports whether the registry holds a datasource authority.
func (r *LocalAuthorityRegistry) Available() bool {
	return r != nil && !nilInterface(r.authority)
}

// resolverFor returns the retained tenant-scoped resolver, constructing it on
// first use. An empty tenant has no authority, which the evaluation reports as
// a not-evaluated local hop rather than as a foreign domain.
func (r *LocalAuthorityRegistry) resolverFor(tenant string) (dkim2.LocalAuthority, error) {
	if r == nil {
		return nil, &DomainError{}
	}
	if tenant == "" || !r.Available() {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if resolver, ok := r.resolvers[tenant]; ok {
		return resolver, nil
	}
	resolver, err := newLocalAuthorityResolver(r.authority, tenant, r.clock)
	if err != nil {
		return nil, err
	}
	for candidate := range r.resolvers {
		if len(r.resolvers) < localAuthorityRegistryEntries {
			break
		}
		delete(r.resolvers, candidate)
	}
	r.resolvers[tenant] = resolver
	return resolver, nil
}

// String returns a content-free registry representation.
func (*LocalAuthorityRegistry) String() string { return localAuthorityRedacted }

// GoString returns a content-free registry representation.
func (*LocalAuthorityRegistry) GoString() string { return localAuthorityRedacted }

// Format prevents formatting from traversing the retained tenant resolvers.
func (*LocalAuthorityRegistry) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, localAuthorityRedacted)
}

// canonicalAuthorityDomain accepts only a canonical lower-case ASCII DNS name.
func canonicalAuthorityDomain(domain string) bool {
	if domain == "" || len(domain) > localAuthorityMaxDomainBytes ||
		domain != strings.ToLower(domain) || strings.HasSuffix(domain, ".") {
		return false
	}
	for label := range strings.SplitSeq(domain, ".") {
		if len(label) == 0 || len(label) > localAuthorityMaxLabelBytes ||
			!authorityLabelEdge(label[0]) || !authorityLabelEdge(label[len(label)-1]) {
			return false
		}
		for index := 1; index < len(label)-1; index++ {
			if !authorityLabelEdge(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

// authorityLabelEdge reports whether one byte may start or end a DNS label.
func authorityLabelEdge(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

// String returns a content-free authority-resolver representation.
func (*LocalAuthorityResolver) String() string { return localAuthorityRedacted }

// GoString returns a content-free authority-resolver representation.
func (*LocalAuthorityResolver) GoString() string { return localAuthorityRedacted }

// Format prevents formatting from traversing the tenant and provider state.
func (*LocalAuthorityResolver) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, localAuthorityRedacted)
}

// MarshalJSON rejects serialization of authority-resolver state.
func (*LocalAuthorityResolver) MarshalJSON() ([]byte, error) { return nil, &DomainError{} }

// MarshalText rejects diagnostic serialization of authority-resolver state.
func (*LocalAuthorityResolver) MarshalText() ([]byte, error) { return nil, &DomainError{} }
