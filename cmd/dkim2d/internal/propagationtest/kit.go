// Package propagationtest provides test-only fixtures for the daemon's
// received-DSN and propagation paths: the frozen library propagation corpus,
// a static public-key provider over its published keys, deterministic
// Ed25519 delivery-status profiles, and a tenant-keyed signing-authority
// double that reports local authority, resolves profiles, and signs.
package propagationtest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"github.com/croessner/dkim2/provider"
)

const (
	corpusRelativePath = "lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-06/dsn-propagation-golden.json"
	// CaseRunOfOne is a rebuildable single-signature local hop run.
	CaseRunOfOne = "run_of_one"
	// CaseNextDomainRun is a rebuildable nd= run whose signing domain is the forward domain.
	CaseNextDomainRun = "next_domain_run"
	// CaseNullPreviousSender is a valid notification whose previous hop carried a null sender.
	CaseNullPreviousSender = "null_previous_sender"
	// CasePreviousHopUnverified is a notification whose previous hop cannot be reconstructed.
	CasePreviousHopUnverified = "previous_hop_unverified"
	// CaseSMTPUTF8Header is a rebuildable notification whose rebuilt headers need SMTPUTF8.
	CaseSMTPUTF8Header = "smtputf8_header_field"
	// LocalDomain is the corpus' primary local authority domain.
	LocalDomain = "local.example"
	// ForwardDomain is the corpus' second local authority domain.
	ForwardDomain = "forward.local.example"
	// DeliveryStatusSelector is the selector of every delivery-status profile.
	DeliveryStatusSelector = "dsn"
	// ReportingMTA is the canonical reporting name of every corpus case.
	ReportingMTA = "mta.local.example"
)

// Key is one published Ed25519 verification key of the corpus.
type Key struct {
	Domain   string `json:"domain"`
	Selector string `json:"selector"`
	Public   string `json:"ed25519_public_base64"`
}

// Expectation is the frozen library outcome of one case.
type Expectation struct {
	Outcome       string `json:"outcome"`
	Embedded      string `json:"embedded"`
	Propagation   string `json:"propagation"`
	LocalHop      string `json:"local_hop"`
	SigningDomain string `json:"signing_domain,omitempty"`
	NextHop       string `json:"next_hop_base64,omitempty"`
	SMTPUTF8      bool   `json:"smtputf8_required"`
}

// Case is one frozen received notification with its observed envelope.
type Case struct {
	Name         string      `json:"name"`
	Raw          string      `json:"raw_base64"`
	Forward      string      `json:"forward_path_base64"`
	LocalDomains []string    `json:"local_domains"`
	ReportingMTA string      `json:"reporting_mta"`
	Expected     Expectation `json:"expected"`
}

// Corpus is the decoded propagation corpus.
type Corpus struct {
	Draft        string `json:"draft"`
	SigningClock int64  `json:"signing_clock_unix"`
	Keys         []Key  `json:"keys"`
	Cases        []Case `json:"cases"`
}

// Load reads the frozen propagation corpus from the repository.
func Load(t testing.TB) *Corpus {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("derive repository root")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "../../../.."))
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(corpusRelativePath)))
	if err != nil {
		t.Fatalf("read propagation corpus: %v", err)
	}
	var corpus Corpus
	if err := json.Unmarshal(data, &corpus); err != nil || corpus.Draft != dkim2.DraftIdentifier ||
		len(corpus.Keys) == 0 || len(corpus.Cases) == 0 || corpus.SigningClock <= 0 {
		t.Fatal("decode propagation corpus")
	}
	return &corpus
}

// Clock returns the corpus signing instant used for verification and signing.
func (c *Corpus) Clock() time.Time { return time.Unix(c.SigningClock, 0).UTC() }

// Case returns one named case.
func (c *Corpus) Case(t testing.TB, name string) Case {
	t.Helper()
	for _, candidate := range c.Cases {
		if candidate.Name == name {
			return candidate
		}
	}
	t.Fatalf("corpus case %q is absent", name)
	return Case{}
}

// RawMessage returns the decoded received notification bytes.
func (c Case) RawMessage(t testing.TB) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(c.Raw)
	if err != nil || len(raw) == 0 {
		t.Fatalf("decode case %q message", c.Name)
	}
	return raw
}

// ForwardPath returns the observed outer recipient of the notification.
func (c Case) ForwardPath(t testing.TB) []byte {
	t.Helper()
	path, err := base64.StdEncoding.DecodeString(c.Forward)
	if err != nil || len(path) == 0 {
		t.Fatalf("decode case %q forward path", c.Name)
	}
	return path
}

// ExpectedNextHop returns the frozen previous-hop recipient of a rebuildable case.
func (c Case) ExpectedNextHop(t testing.TB) []byte {
	t.Helper()
	path, err := base64.StdEncoding.DecodeString(c.Expected.NextHop)
	if err != nil {
		t.Fatalf("decode case %q next hop", c.Name)
	}
	return path
}

// keyIdentity addresses one published key.
type keyIdentity struct{ domain, selector string }

// Provider serves the corpus keys and test-owned overrides as the bounded
// public-key provider shared by verification, evaluation, and signing.
type Provider struct {
	mu        sync.Mutex
	keys      map[keyIdentity]ed25519.PublicKey
	temporary map[string]bool
	lookups   atomic.Int64
}

// Provider constructs one provider over every published corpus key.
func (c *Corpus) Provider(t testing.TB) *Provider {
	t.Helper()
	provider := &Provider{keys: make(map[keyIdentity]ed25519.PublicKey, len(c.Keys)), temporary: make(map[string]bool)}
	for _, key := range c.Keys {
		public, err := base64.StdEncoding.DecodeString(key.Public)
		if err != nil || len(public) != ed25519.PublicKeySize {
			t.Fatalf("decode corpus key for %q", key.Domain)
		}
		provider.keys[keyIdentity{key.Domain, key.Selector}] = ed25519.PublicKey(public)
	}
	return provider
}

// Publish serves the public half of one test-owned signing key, replacing
// any corpus key under the same domain and selector.
func (p *Provider) Publish(key SigningKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys[keyIdentity{key.Domain, key.Selector}] = key.Public
}

// FailTemporarily makes every lookup for the domain a temporary failure.
func (p *Provider) FailTemporarily(domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.temporary[domain] = true
}

// Lookups reports how many lookups the provider served.
func (p *Provider) Lookups() int64 { return p.lookups.Load() }

// LookupPublicKey implements the library public-key provider.
func (p *Provider) LookupPublicKey(_ context.Context, query dkim2.PublicKeyQuery) (dkim2.PublicKeyResult, error) {
	p.lookups.Add(1)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.temporary[query.SigningDomain()] {
		return dkim2.PublicKeyResult{}, dkim2.NewTemporaryProviderError()
	}
	if query.Algorithm() != dkim2.AlgorithmEd25519SHA256 {
		return dkim2.MissingPublicKey(query.Algorithm()), nil
	}
	key, ok := p.keys[keyIdentity{query.SigningDomain(), query.Selector()}]
	if !ok {
		return dkim2.MissingPublicKey(query.Algorithm()), nil
	}
	return dkim2.FoundEd25519PublicKey(key), nil
}

// Verifier constructs the library verifier over the provider at the corpus clock.
func (c *Corpus) Verifier(t testing.TB, provider dkim2.PublicKeyProvider) *dkim2.Verifier {
	t.Helper()
	clock := c.Clock()
	verifier, err := dkim2.NewVerifier(provider, dkim2.WithVerificationClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatalf("construct verifier: %v", err)
	}
	return verifier
}

// SigningKey is one test-owned Ed25519 delivery-status credential.
type SigningKey struct {
	Domain   string
	Selector string
	Public   ed25519.PublicKey
	Private  ed25519.PrivateKey
	Handle   dkim2.PrivateKeyHandle
	Profile  dkim2.SigningProfile
}

// NewSigningKey generates one delivery-status profile for the domain.
func NewSigningKey(t testing.TB, domain string) SigningKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	handle, err := dkim2.NewPrivateKeyHandle([]byte("handle:" + domain))
	if err != nil {
		t.Fatalf("construct handle: %v", err)
	}
	credential, err := dkim2.NewEd25519SigningCredential(DeliveryStatusSelector, public, handle)
	if err != nil {
		t.Fatalf("construct credential: %v", err)
	}
	profile, err := dkim2.NewEd25519SigningProfile(domain, credential)
	if err != nil {
		t.Fatalf("construct profile: %v", err)
	}
	return SigningKey{Domain: domain, Selector: DeliveryStatusSelector, Public: public, Private: private, Handle: handle, Profile: profile}
}

// Authority is a tenant-keyed signing-authority double. It reports local
// authority for the configured domains, resolves delivery-status profiles
// for the configured keys, signs with them, and can simulate an outage. It
// satisfies both the daemon's authority and lease seams.
type Authority struct {
	mu       sync.Mutex
	local    map[string]map[string]bool
	profiles map[string]map[string]SigningKey
	outage   bool

	Acquires        atomic.Int64
	AuthorityProbes atomic.Int64
	ProfileResolves atomic.Int64
	Signs           atomic.Int64
}

// NewAuthority constructs an authority without any tenant.
func NewAuthority() *Authority {
	return &Authority{local: make(map[string]map[string]bool), profiles: make(map[string]map[string]SigningKey)}
}

// AddLocal marks the domains as local authority domains of the tenant.
func (a *Authority) AddLocal(tenant string, domains ...string) *Authority {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.local[tenant] == nil {
		a.local[tenant] = make(map[string]bool)
	}
	for _, domain := range domains {
		a.local[tenant][domain] = true
	}
	return a
}

// AddProfile installs one delivery-status profile for the tenant and marks
// its domain local.
func (a *Authority) AddProfile(tenant string, key SigningKey) *Authority {
	a.AddLocal(tenant, key.Domain)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.profiles[tenant] == nil {
		a.profiles[tenant] = make(map[string]SigningKey)
	}
	a.profiles[tenant][key.Domain] = key
	return a
}

// SetOutage makes every datasource read a temporary failure.
func (a *Authority) SetOutage(outage bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.outage = outage
}

// Open records one lease acquisition and reports a simulated outage. The
// daemon package binds it to its own authority seam through a thin adapter,
// because this package must not import the daemon application package.
func (a *Authority) Open(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.Acquires.Add(1)
	a.mu.Lock()
	outage := a.outage
	a.mu.Unlock()
	if outage {
		return provider.NewError(provider.ErrorCodeUnavailable)
	}
	return nil
}

// ResolvePolicy returns the tenant's delivery-status profile for the domain
// or an authoritative not-found failure.
func (a *Authority) ResolvePolicy(
	ctx context.Context,
	tenant, domain string,
	use signingstore.PolicyUse,
	_ time.Time,
) (dkim2.SigningProfile, error) {
	if err := ctx.Err(); err != nil {
		return dkim2.SigningProfile{}, err
	}
	a.ProfileResolves.Add(1)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.outage {
		return dkim2.SigningProfile{}, provider.NewError(provider.ErrorCodeUnavailable)
	}
	if use != signingstore.PolicyDeliveryStatus {
		return dkim2.SigningProfile{}, provider.NewError(provider.ErrorCodeNotFound)
	}
	key, ok := a.profiles[tenant][domain]
	if !ok {
		return dkim2.SigningProfile{}, provider.NewError(provider.ErrorCodeNotFound)
	}
	return key.Profile, nil
}

// ResolveAnyProfile reports local authority for the tenant and domain.
func (a *Authority) ResolveAnyProfile(ctx context.Context, tenant, domain string, _ time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.AuthorityProbes.Add(1)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.outage {
		return provider.NewError(provider.ErrorCodeUnavailable)
	}
	if !a.local[tenant][domain] {
		return provider.NewError(provider.ErrorCodeNotFound)
	}
	return nil
}

// SignDigest signs with the key behind the handle of any installed profile.
func (a *Authority) SignDigest(
	ctx context.Context,
	handle dkim2.PrivateKeyHandle,
	request dkim2.PrivateKeySignRequest,
) (dkim2.PrivateKeySignResult, error) {
	if err := ctx.Err(); err != nil {
		return dkim2.PrivateKeySignResult{}, err
	}
	a.Signs.Add(1)
	a.mu.Lock()
	defer a.mu.Unlock()
	if request.Algorithm() != dkim2.AlgorithmEd25519SHA256 {
		return dkim2.PrivateKeySignResult{}, errors.New("unsupported algorithm")
	}
	for _, profiles := range a.profiles {
		for _, key := range profiles {
			if key.Handle == handle {
				digest := request.Digest()
				return dkim2.NewPrivateKeySignResult(ed25519.Sign(key.Private, digest[:])), nil
			}
		}
	}
	return dkim2.PrivateKeySignResult{}, errors.New("unknown handle")
}

// Close releases the stateless lease.
func (*Authority) Close() error { return nil }
