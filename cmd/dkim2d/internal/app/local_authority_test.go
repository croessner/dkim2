package app

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"github.com/croessner/dkim2/provider"
)

// testAuthorityLocalDomain is the tenant-and-domain key of the fixture's one
// local authority domain.
const testAuthorityLocalDomain = "tenant|example.test"

// stubAuthorityLease answers authority resolution from a fixed decision table.
type stubAuthorityLease struct {
	owner *stubAuthority
}

// ResolvePolicy is never reached by authority resolution.
func (stubAuthorityLease) ResolvePolicy(
	context.Context,
	string,
	string,
	signingstore.PolicyUse,
	time.Time,
) (dkim2.SigningProfile, error) {
	return dkim2.SigningProfile{}, errors.New("unexpected policy resolution")
}

// ResolveAnyProfile answers one bounded authority probe.
func (l stubAuthorityLease) ResolveAnyProfile(
	_ context.Context,
	tenant string,
	domain string,
	_ time.Time,
) error {
	l.owner.mu.Lock()
	l.owner.probes = append(l.owner.probes, tenant+"|"+domain)
	l.owner.mu.Unlock()
	if l.owner.failure != nil {
		return l.owner.failure
	}
	if _, ok := l.owner.resolved[tenant+"|"+domain]; ok {
		return nil
	}
	return provider.NewError(provider.ErrorCodeNotFound)
}

// SignDigest is never reached by authority resolution.
func (stubAuthorityLease) SignDigest(
	context.Context,
	dkim2.PrivateKeyHandle,
	dkim2.PrivateKeySignRequest,
) (dkim2.PrivateKeySignResult, error) {
	return dkim2.PrivateKeySignResult{}, errors.New("unexpected private signing")
}

// Close records lease release.
func (l stubAuthorityLease) Close() error {
	l.owner.mu.Lock()
	l.owner.closed++
	l.owner.mu.Unlock()
	return nil
}

// stubAuthority hands out one stub lease per acquisition.
type stubAuthority struct {
	mu       sync.Mutex
	probes   []string
	resolved map[string]struct{}
	failure  error
	acquire  error
	closed   int
	acquired int
}

// Acquire pins one stub generation.
func (a *stubAuthority) Acquire(ctx context.Context) (SigningLease, error) {
	if ctx == nil {
		return nil, &DomainError{}
	}
	a.mu.Lock()
	a.acquired++
	a.mu.Unlock()
	if a.acquire != nil {
		return nil, a.acquire
	}
	return stubAuthorityLease{owner: a}, nil
}

// probeCount returns the number of recorded datasource probes.
func (a *stubAuthority) probeCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.probes)
}

// leaseBalance reports whether every acquired lease was closed again.
func (a *stubAuthority) leaseBalance() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.acquired == a.closed
}

func TestLocalAuthorityResolverAnswersLocalForAResolvedProfile(t *testing.T) {
	t.Parallel()

	authority := &stubAuthority{resolved: map[string]struct{}{testAuthorityLocalDomain: {}}}
	resolver, err := newLocalAuthorityResolver(authority, "tenant", time.Now)
	if err != nil {
		t.Fatalf("construct resolver: %v", err)
	}
	status, err := resolver.LookupLocalAuthority(context.Background(), "example.test")
	if err != nil || status != dkim2.LocalAuthorityLocal {
		t.Fatalf("status %q err %v", status, err)
	}
	if !authority.leaseBalance() {
		t.Fatal("resolver leaked a signing generation lease")
	}
}

func TestLocalAuthorityResolverAnswersNotLocalWithoutAnyProfile(t *testing.T) {
	t.Parallel()

	authority := &stubAuthority{resolved: map[string]struct{}{}}
	resolver, err := newLocalAuthorityResolver(authority, "tenant", time.Now)
	if err != nil {
		t.Fatalf("construct resolver: %v", err)
	}
	status, err := resolver.LookupLocalAuthority(context.Background(), "foreign.test")
	if err != nil || status != dkim2.LocalAuthorityNotLocal {
		t.Fatalf("status %q err %v", status, err)
	}
}

func TestLocalAuthorityResolverCachesNegativeAnswers(t *testing.T) {
	t.Parallel()

	authority := &stubAuthority{resolved: map[string]struct{}{}}
	resolver, err := newLocalAuthorityResolver(authority, "tenant", time.Now)
	if err != nil {
		t.Fatalf("construct resolver: %v", err)
	}
	for range 5 {
		if _, err := resolver.LookupLocalAuthority(context.Background(), "foreign.test"); err != nil {
			t.Fatalf("lookup: %v", err)
		}
	}
	if got := authority.probeCount(); got != 1 {
		t.Fatalf("negative cache did not bound probes: %d", got)
	}
}

func TestLocalAuthorityResolverDoesNotCachePositiveAnswers(t *testing.T) {
	t.Parallel()

	authority := &stubAuthority{resolved: map[string]struct{}{testAuthorityLocalDomain: {}}}
	resolver, err := newLocalAuthorityResolver(authority, "tenant", time.Now)
	if err != nil {
		t.Fatalf("construct resolver: %v", err)
	}
	for range 3 {
		if _, err := resolver.LookupLocalAuthority(context.Background(), "example.test"); err != nil {
			t.Fatalf("lookup: %v", err)
		}
	}
	if got := authority.probeCount(); got != 3 {
		t.Fatalf("a local answer was cached: %d probes", got)
	}
}

func TestLocalAuthorityResolverNegativeCacheIsBounded(t *testing.T) {
	t.Parallel()

	authority := &stubAuthority{resolved: map[string]struct{}{}}
	resolver, err := newLocalAuthorityResolver(authority, "tenant", time.Now)
	if err != nil {
		t.Fatalf("construct resolver: %v", err)
	}
	for index := range localAuthorityNegativeCacheEntries + 32 {
		domain := "d" + string(rune('a'+index%26)) + string(rune('a'+(index/26)%26)) +
			string(rune('a'+(index/676)%26)) + ".test"
		if _, err := resolver.LookupLocalAuthority(context.Background(), domain); err != nil {
			t.Fatalf("lookup: %v", err)
		}
	}
	if size := resolver.negativeCacheSize(); size > localAuthorityNegativeCacheEntries {
		t.Fatalf("negative cache holds %d entries", size)
	}
}

func TestLocalAuthorityResolverRejectsNonCanonicalDomains(t *testing.T) {
	t.Parallel()

	authority := &stubAuthority{resolved: map[string]struct{}{testAuthorityLocalDomain: {}}}
	resolver, err := newLocalAuthorityResolver(authority, "tenant", time.Now)
	if err != nil {
		t.Fatalf("construct resolver: %v", err)
	}
	for _, domain := range []string{"", "Example.test", "example..test", "-bad.test", "exa mple.test"} {
		status, err := resolver.LookupLocalAuthority(context.Background(), domain)
		if err != nil || status != dkim2.LocalAuthorityNotLocal {
			t.Fatalf("domain %q: status %q err %v", domain, status, err)
		}
	}
	if got := authority.probeCount(); got != 0 {
		t.Fatalf("non-canonical domain reached the datasource %d times", got)
	}
}

func TestLocalAuthorityResolverReportsTemporaryDatasourceFailure(t *testing.T) {
	t.Parallel()

	authority := &stubAuthority{
		resolved: map[string]struct{}{},
		failure:  provider.NewError(provider.ErrorCodeUnavailable),
	}
	resolver, err := newLocalAuthorityResolver(authority, "tenant", time.Now)
	if err != nil {
		t.Fatalf("construct resolver: %v", err)
	}
	if _, err := resolver.LookupLocalAuthority(context.Background(), "example.test"); err == nil {
		t.Fatal("temporary datasource failure did not surface as an error")
	}
	if _, err := resolver.LookupLocalAuthority(context.Background(), "example.test"); err == nil {
		t.Fatal("temporary failure was cached as not_local")
	}
}

func TestLocalAuthorityResolverReportsUnavailableAuthority(t *testing.T) {
	t.Parallel()

	authority := &stubAuthority{resolved: map[string]struct{}{}, acquire: &DomainError{}}
	resolver, err := newLocalAuthorityResolver(authority, "tenant", time.Now)
	if err != nil {
		t.Fatalf("construct resolver: %v", err)
	}
	if _, err := resolver.LookupLocalAuthority(context.Background(), "example.test"); err == nil {
		t.Fatal("unavailable authority did not surface as an error")
	}
}

func TestLocalAuthorityResolverIsolatesTenants(t *testing.T) {
	t.Parallel()

	authority := &stubAuthority{resolved: map[string]struct{}{"a|example.test": {}}}
	first, err := newLocalAuthorityResolver(authority, "a", time.Now)
	if err != nil {
		t.Fatalf("construct resolver: %v", err)
	}
	second, err := newLocalAuthorityResolver(authority, "b", time.Now)
	if err != nil {
		t.Fatalf("construct resolver: %v", err)
	}
	statusA, errA := first.LookupLocalAuthority(context.Background(), "example.test")
	statusB, errB := second.LookupLocalAuthority(context.Background(), "example.test")
	if errA != nil || statusA != dkim2.LocalAuthorityLocal {
		t.Fatalf("tenant a: %q %v", statusA, errA)
	}
	if errB != nil || statusB != dkim2.LocalAuthorityNotLocal {
		t.Fatalf("tenant b: %q %v", statusB, errB)
	}
}

func TestLocalAuthorityResolverRejectsInvalidConstruction(t *testing.T) {
	t.Parallel()

	if _, err := newLocalAuthorityResolver(&stubAuthority{}, "", time.Now); err == nil {
		t.Fatal("empty tenant was accepted")
	}
	if _, err := newLocalAuthorityResolver(nil, "tenant", time.Now); err == nil {
		t.Fatal("nil authority was accepted")
	}
	if _, err := newLocalAuthorityResolver(&stubAuthority{}, "tenant", nil); err == nil {
		t.Fatal("nil clock was accepted")
	}
}

func TestLocalAuthorityResolverRejectsTerminalContext(t *testing.T) {
	t.Parallel()

	authority := &stubAuthority{resolved: map[string]struct{}{testAuthorityLocalDomain: {}}}
	resolver, err := newLocalAuthorityResolver(authority, "tenant", time.Now)
	if err != nil {
		t.Fatalf("construct resolver: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.LookupLocalAuthority(ctx, "example.test"); err == nil {
		t.Fatal("cancelled context was accepted")
	}
	if got := authority.probeCount(); got != 0 {
		t.Fatalf("cancelled lookup reached the datasource %d times", got)
	}
}

func TestLocalAuthorityResolverDiagnosticsAreContentFree(t *testing.T) {
	t.Parallel()

	resolver, err := newLocalAuthorityResolver(&stubAuthority{}, "secret-tenant", time.Now)
	if err != nil {
		t.Fatalf("construct resolver: %v", err)
	}
	for _, rendered := range []string{resolver.String(), resolver.GoString()} {
		if rendered != localAuthorityRedacted {
			t.Fatalf("diagnostic %q is not content free", rendered)
		}
	}
}
