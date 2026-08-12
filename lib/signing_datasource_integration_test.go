//go:build linux || darwin

package dkim2

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/datasource"
	"github.com/croessner/dkim2/internal/datasource/flatfile"
	"github.com/croessner/dkim2/internal/datasource/memory"
	"github.com/croessner/dkim2/internal/datasource/signingprofile"
	"github.com/croessner/dkim2/internal/routeplan"
	internalsigning "github.com/croessner/dkim2/internal/signing"
)

const (
	datasourceBoundaryEvent  = "datasource"
	publicationBoundaryEvent = "publication"
	signerBoundaryEvent      = "signer"
	memoryProviderName       = "memory"
	flatfileProviderName     = "flatfile"
)

type datasourceSigningEvents struct {
	mu     sync.Mutex
	values []string
}

// add appends one integration boundary event.
func (e *datasourceSigningEvents) add(value string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.values = append(e.values, value)
}

// reset clears setup or previous-operation events.
func (e *datasourceSigningEvents) reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.values = nil
}

// snapshot returns a detached ordered event sequence.
func (e *datasourceSigningEvents) snapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.values)
}

type orderedDatasourceProvider struct {
	delegate datasource.Provider
	events   *datasourceSigningEvents
	failure  error
}

// ResolveProfile records completion of the sole datasource profile boundary.
func (p *orderedDatasourceProvider) ResolveProfile(
	ctx context.Context,
	request datasource.ProfileRequest,
) (datasource.ResolvedProfile, error) {
	if p.failure != nil {
		p.events.add(datasourceBoundaryEvent)
		return datasource.ResolvedProfile{}, p.failure
	}
	result, err := p.delegate.ResolveProfile(ctx, request)
	p.events.add(datasourceBoundaryEvent)
	return result, err
}

// ResolvePolicy records completion of the sole datasource policy boundary.
func (p *orderedDatasourceProvider) ResolvePolicy(
	ctx context.Context,
	request datasource.PolicyRequest,
) (datasource.ResolvedPolicy, error) {
	if p.failure != nil {
		p.events.add(datasourceBoundaryEvent)
		return datasource.ResolvedPolicy{}, p.failure
	}
	result, err := p.delegate.ResolvePolicy(ctx, request)
	p.events.add(datasourceBoundaryEvent)
	return result, err
}

type orderedSigningProvider struct {
	key       *rsa.PrivateKey
	published *rsa.PublicKey
	handle    PrivateKeyHandle
	events    *datasourceSigningEvents
}

type orderedRouteAuthority struct {
	delegate *routeplan.MemoryAuthority
	events   *datasourceSigningEvents
}

// Finalize records and delegates one route-fanout plan.
func (a *orderedRouteAuthority) Finalize(
	ctx context.Context,
	query RouteFinalizeQuery,
) (RouteAuthorityResult, error) {
	a.events.add("route")
	result, err := a.delegate.Finalize(ctx, query.value)
	return RouteAuthorityResult{value: result}, err
}

// Reserve records and delegates one signing reservation.
func (a *orderedRouteAuthority) Reserve(
	ctx context.Context,
	query RouteTicketQuery,
) (RouteAuthorityResult, error) {
	a.events.add("route")
	result, err := a.delegate.Reserve(ctx, query.value)
	return RouteAuthorityResult{value: result}, err
}

// ReleaseReservation records and delegates one pre-boundary release.
func (a *orderedRouteAuthority) ReleaseReservation(
	ctx context.Context,
	query RouteTicketQuery,
) (RouteAuthorityResult, error) {
	a.events.add("route")
	result, err := a.delegate.ReleaseReservation(ctx, query.value)
	return RouteAuthorityResult{value: result}, err
}

// Burn records and delegates one irreversible route transition.
func (a *orderedRouteAuthority) Burn(
	ctx context.Context,
	query RouteTicketQuery,
) (RouteAuthorityResult, error) {
	a.events.add("route")
	result, err := a.delegate.Burn(ctx, query.value)
	return RouteAuthorityResult{value: result}, err
}

// Replace records and delegates one same-lineage ticket replacement.
func (a *orderedRouteAuthority) Replace(
	ctx context.Context,
	query RouteTicketQuery,
) (RouteAuthorityResult, error) {
	a.events.add("route")
	result, err := a.delegate.Replace(ctx, query.value)
	return RouteAuthorityResult{value: result}, err
}

// ConsumeRelease records and delegates one restricted release.
func (a *orderedRouteAuthority) ConsumeRelease(
	ctx context.Context,
	query RouteTicketQuery,
) (RouteAuthorityResult, error) {
	a.events.add("route")
	result, err := a.delegate.ConsumeRelease(ctx, query.value)
	return RouteAuthorityResult{value: result}, err
}

// LookupPublicKey proves the fresh publication check precedes private signing.
func (p *orderedSigningProvider) LookupPublicKey(
	_ context.Context,
	query PublicKeyQuery,
) (PublicKeyResult, error) {
	p.events.add(publicationBoundaryEvent)
	if query.SigningDomain() != testSigningDomain ||
		query.Selector() != testRSASelector ||
		query.Algorithm() != AlgorithmRSASHA256 {
		return MissingPublicKey(query.Algorithm()), nil
	}
	return FoundRSAPublicKey(p.published), nil
}

// SignDigest records and performs one opaque-handle RSA signing operation.
func (p *orderedSigningProvider) SignDigest(
	_ context.Context,
	handle PrivateKeyHandle,
	request PrivateKeySignRequest,
) (PrivateKeySignResult, error) {
	p.events.add(signerBoundaryEvent)
	if handle != p.handle || request.Algorithm() != AlgorithmRSASHA256 {
		return PrivateKeySignResult{}, NewPermanentProviderError()
	}
	digest := request.Digest()
	signature, err := rsa.SignPKCS1v15(
		rand.Reader,
		p.key,
		crypto.SHA256,
		digest[:],
	)
	if err != nil {
		return PrivateKeySignResult{}, err
	}
	return NewPrivateKeySignResult(signature), nil
}

// TestDatasourceProfileDrivesFreshPublicationThenOpaqueSigning proves the
// sole bridge completes before DNS publication and private-key callbacks,
// while datasource denial returns no result and invokes neither callback.
func TestDatasourceProfileDrivesFreshPublicationThenOpaqueSigning(t *testing.T) {
	fixture := newDatasourceSigningIntegrationFixture(t)
	requestFor := newDatasourceSigningRequestFactory(t, fixture)
	assertDatasourceProviderDenial(t, fixture, requestFor)
	t.Run("confined reload generation immutability", func(t *testing.T) {
		assertConfinedReloadProfile(t, fixture, requestFor)
	})
	assertAllowedDatasourceSigning(t, fixture, requestFor)
	t.Run("registry authorization denial", func(t *testing.T) {
		assertRegistryAuthorizationDenial(t, fixture, requestFor)
	})
	t.Run("fresh publication drift", func(t *testing.T) {
		assertPublicationDriftDenial(t, fixture, requestFor)
	})
}

type datasourceSigningRequestFactory func([]byte) func(SigningProfile) OriginatorSigningRequest

// newDatasourceSigningRequestFactory delays route planning until datasource
// projection has returned one complete signing profile.
func newDatasourceSigningRequestFactory(
	t *testing.T,
	fixture datasourceSigningIntegrationFixture,
) datasourceSigningRequestFactory {
	t.Helper()
	return func(raw []byte) func(SigningProfile) OriginatorSigningRequest {
		return func(profile SigningProfile) OriginatorSigningRequest {
			ticket := fixture.public.originTicket(t, raw, RouteDisclosureSingle)
			return NewOriginatorSigningRequest(
				raw,
				[]byte("<alice@example.test>"),
				[][]byte{[]byte("<bob@example.net>")},
				ticket,
				profile,
				SigningMetadata{},
				SigningTransportFinalNetworkPreDotStuffing,
			)
		}
	}
}

// assertDatasourceProviderDenial proves a provider failure cannot reach route,
// publication, or private-signing callbacks.
func assertDatasourceProviderDenial(
	t *testing.T,
	fixture datasourceSigningIntegrationFixture,
	requestFor datasourceSigningRequestFactory,
) {
	t.Helper()
	fixture.events.reset()
	deniedResult, deniedRecovery, deniedErr := resolveAndSignDatasourceProfile(
		context.Background(),
		fixture.denied,
		fixture.public.facade,
		fixture.profileID,
		datasource.ProfileUseOriginator,
		fixture.at,
		requestFor([]byte("From: alice@example.test\r\nSubject: denied\r\n\r\nbody\r\n")),
	)
	if deniedResult.Valid() || deniedRecovery.Valid() ||
		datasource.ErrorCodeOf(deniedErr) != datasource.ErrorCodeUnavailable {
		t.Fatalf("denied result/recovery/code=%t/%t/%s",
			deniedResult.Valid(),
			deniedRecovery.Valid(),
			datasource.ErrorCodeOf(deniedErr))
	}
	if got := fixture.events.snapshot(); !slices.Equal(got, []string{datasourceBoundaryEvent}) {
		t.Fatalf("datasource denial callbacks=%v, want datasource only", got)
	}
}

// assertConfinedReloadProfile proves a real confined reload increments the
// provider generation without mutating or invalidating a prior projection.
func assertConfinedReloadProfile(
	t *testing.T,
	fixture datasourceSigningIntegrationFixture,
	requestFor datasourceSigningRequestFactory,
) {
	t.Helper()
	request, err := datasource.NewProfileRequest(
		fixture.profileID,
		datasource.ProfileUseOriginator,
		fixture.at,
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("datasource.NewProfileRequest() error = %v", err)
	}
	beforeResult, err := fixture.flat.ResolveProfile(context.Background(), request)
	if err != nil || beforeResult.Generation() != 1 {
		t.Fatalf("before reload generation/code=%d/%s",
			beforeResult.Generation(), datasource.ErrorCodeOf(err))
	}
	before, err := fixture.allowed[flatfileProviderName].ResolveProfile(
		context.Background(),
		fixture.profileID,
		datasource.ProfileUseOriginator,
		fixture.at,
	)
	if err != nil {
		t.Fatalf("flat adapter before Reload() code=%s", datasource.ErrorCodeOf(err))
	}
	if err := os.WriteFile(fixture.flatPath, fixture.flatDocument, 0o600); err != nil {
		t.Fatalf("os.WriteFile(reload) error = %v", err)
	}
	if err := os.Chmod(fixture.flatPath, 0o600); err != nil {
		t.Fatalf("os.Chmod(reload) error = %v", err)
	}
	if err := fixture.flat.Reload(context.Background()); err != nil {
		t.Fatalf("flatfile.Reload() error = %v", err)
	}
	afterResult, err := fixture.flat.ResolveProfile(context.Background(), request)
	if err != nil || afterResult.Generation() != 2 {
		t.Fatalf("after reload generation/code=%d/%s",
			afterResult.Generation(), datasource.ErrorCodeOf(err))
	}
	after, err := fixture.allowed[flatfileProviderName].ResolveProfile(
		context.Background(),
		fixture.profileID,
		datasource.ProfileUseOriginator,
		fixture.at,
	)
	assertReloadedProfilesEqual(t, before, after, err)
	result, recovery, err := fixture.public.facade.SignOriginator(
		context.Background(),
		requestFor([]byte(
			"From: alice@example.test\r\nSubject: pre-reload profile\r\n\r\nbody\r\n",
		))(SigningProfile{value: before}),
	)
	if err != nil || !result.Valid() || recovery.Valid() {
		t.Fatalf("pre-reload profile after Reload valid/recovery/error=%t/%t/%v",
			result.Valid(), recovery.Valid(), err)
	}
	fixture.events.reset()
}

// assertReloadedProfilesEqual compares two complete one-credential profiles
// only after validating their safe indexing preconditions.
func assertReloadedProfilesEqual(
	t *testing.T,
	before internalsigning.Profile,
	after internalsigning.Profile,
	err error,
) {
	t.Helper()
	if err != nil || !before.Valid() || !after.Valid() ||
		len(before.Credentials()) != 1 || len(after.Credentials()) != 1 {
		t.Fatalf("reload profile preflight valid=%t/%t lengths=%d/%d code=%s",
			before.Valid(), after.Valid(),
			len(before.Credentials()), len(after.Credentials()),
			datasource.ErrorCodeOf(err))
	}
	beforeCredentials := before.Credentials()
	afterCredentials := after.Credentials()
	beforeSPKI, beforeSPKIErr := x509.MarshalPKIXPublicKey(beforeCredentials[0].PublicKey())
	afterSPKI, afterSPKIErr := x509.MarshalPKIXPublicKey(afterCredentials[0].PublicKey())
	if beforeSPKIErr != nil || afterSPKIErr != nil ||
		!bytes.Equal(beforeSPKI, afterSPKI) ||
		before.Domain() != after.Domain() ||
		beforeCredentials[0].Selector() != afterCredentials[0].Selector() ||
		beforeCredentials[0].Algorithm() != afterCredentials[0].Algorithm() {
		t.Fatalf("reload changed projected immutable profile")
	}
}

// assertAllowedDatasourceSigning proves both providers drive the same public
// signing path after datasource completion and fresh publication lookup.
func assertAllowedDatasourceSigning(
	t *testing.T,
	fixture datasourceSigningIntegrationFixture,
	requestFor datasourceSigningRequestFactory,
) {
	t.Helper()
	for name, adapter := range fixture.allowed {
		t.Run(name, func(t *testing.T) {
			fixture.events.reset()
			raw := fmt.Appendf(nil,
				"From: alice@example.test\r\nTo: bob@example.net\r\nSubject: datasource %s\r\n\r\nbody\r\n",
				name,
			)
			result, recovery, err := resolveAndSignDatasourceProfile(
				context.Background(),
				adapter,
				fixture.public.facade,
				fixture.profileID,
				datasource.ProfileUseOriginator,
				fixture.at,
				requestFor(raw),
			)
			if err != nil || !result.Valid() || recovery.Valid() {
				t.Fatalf("success valid/recovery/error=%t/%t/%v",
					result.Valid(), recovery.Valid(), err)
			}
			got := fixture.events.snapshot()
			publicationIndex := slices.Index(got, publicationBoundaryEvent)
			signerIndex := slices.Index(got, signerBoundaryEvent)
			if len(got) == 0 || got[0] != datasourceBoundaryEvent ||
				publicationIndex <= 0 || signerIndex <= publicationIndex {
				t.Fatalf("integration callback order=%v", got)
			}
			if unrestricted, ok := result.Unrestricted(); !ok || !unrestricted.Valid() {
				t.Fatal("signing did not publish one complete unrestricted result")
			}
		})
	}
}

// assertRegistryAuthorizationDenial proves an exact allowed-use mismatch has
// no route, publication, or signer side effect.
func assertRegistryAuthorizationDenial(
	t *testing.T,
	fixture datasourceSigningIntegrationFixture,
	requestFor datasourceSigningRequestFactory,
) {
	t.Helper()
	fixture.events.reset()
	result, recovery, err := resolveAndSignDatasourceProfile(
		context.Background(),
		fixture.allowed[memoryProviderName],
		fixture.public.facade,
		fixture.profileID,
		datasource.ProfileUseOrdinaryTransit,
		fixture.at,
		requestFor([]byte("From: alice@example.test\r\nSubject: unauthorized\r\n\r\nbody\r\n")),
	)
	if result.Valid() || recovery.Valid() ||
		datasource.ErrorCodeOf(err) != datasource.ErrorCodeInactive {
		t.Fatalf("authorization denial result/recovery/code=%t/%t/%s",
			result.Valid(), recovery.Valid(), datasource.ErrorCodeOf(err))
	}
	if got := fixture.events.snapshot(); !slices.Equal(got, []string{datasourceBoundaryEvent}) {
		t.Fatalf("authorization denial callbacks=%v", got)
	}
}

// assertPublicationDriftDenial proves administrative public material cannot
// replace the mandatory fresh DNS/publication authority.
func assertPublicationDriftDenial(
	t *testing.T,
	fixture datasourceSigningIntegrationFixture,
	requestFor datasourceSigningRequestFactory,
) {
	t.Helper()
	driftKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(drift) error = %v", err)
	}
	original := fixture.signing.published
	fixture.signing.published = &driftKey.PublicKey
	t.Cleanup(func() { fixture.signing.published = original })
	fixture.events.reset()
	result, _, signErr := resolveAndSignDatasourceProfile(
		context.Background(),
		fixture.allowed[memoryProviderName],
		fixture.public.facade,
		fixture.profileID,
		datasource.ProfileUseOriginator,
		fixture.at,
		requestFor([]byte("From: alice@example.test\r\nSubject: publication drift\r\n\r\nbody\r\n")),
	)
	if signErr == nil || result.Valid() {
		t.Fatalf("publication drift result/error=%t/%v", result.Valid(), signErr)
	}
	got := fixture.events.snapshot()
	publicationIndex := slices.Index(got, publicationBoundaryEvent)
	if len(got) == 0 || got[0] != datasourceBoundaryEvent ||
		publicationIndex <= 0 || slices.Contains(got, signerBoundaryEvent) {
		t.Fatalf("publication drift callbacks=%v", got)
	}
	fixture.signing.published = original
}

type datasourceSigningIntegrationFixture struct {
	at           time.Time
	profileID    datasource.ProfileID
	allowed      map[string]signingprofile.Adapter
	denied       signingprofile.Adapter
	public       publicSigningFixture
	events       *datasourceSigningEvents
	signing      *orderedSigningProvider
	flat         *flatfile.Provider
	flatPath     string
	flatDocument []byte
}

// newDatasourceSigningIntegrationFixture constructs one exact datasource,
// registry, public signer, publication provider, and private signer graph.
func newDatasourceSigningIntegrationFixture(t *testing.T) datasourceSigningIntegrationFixture {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	publicHandle, err := NewPrivateKeyHandle([]byte("datasource-rsa-handle"))
	if err != nil {
		t.Fatalf("NewPrivateKeyHandle() error = %v", err)
	}
	profileID, err := datasource.NewProfileID("profile.datasource")
	if err != nil {
		t.Fatalf("datasource.NewProfileID() error = %v", err)
	}
	handleID, err := datasource.NewKeyHandleID("key.datasource.rsa")
	if err != nil {
		t.Fatalf("datasource.NewKeyHandleID() error = %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	credential, err := datasource.NewCredential(
		testRSASelector,
		datasource.AlgorithmRSASHA256,
		spki,
		handleID,
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("datasource.NewCredential() error = %v", err)
	}
	profile, err := datasource.NewProfile(
		profileID,
		"example.test",
		datasource.RecordStatusActive,
		[]datasource.Credential{credential},
		time.Time{},
		time.Time{},
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("datasource.NewProfile() error = %v", err)
	}
	provider, err := memory.New(
		1,
		[]datasource.KeyHandleID{handleID},
		[]datasource.Profile{profile},
		nil,
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	document := fmt.Appendf(nil, `{
  "version": "dkim2-datasource-v1",
  "handles": [{"id": "key.datasource.rsa"}],
  "profiles": [{
    "id": "profile.datasource",
    "domain": "example.test",
    "status": "active",
    "credentials": [{
      "algorithm": "rsa-sha256",
      "selector": "rsa",
      "public_key_spki": %q,
      "handle_id": "key.datasource.rsa"
    }]
  }],
  "policies": []
}
`, base64.StdEncoding.EncodeToString(spki))
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0o700); err != nil {
		t.Fatalf("os.Chmod(root) error = %v", err)
	}
	if err := os.WriteFile(rootPath+"/datasource.json", document, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	if err := os.Chmod(rootPath+"/datasource.json", 0o600); err != nil {
		t.Fatalf("os.Chmod(file) error = %v", err)
	}
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatalf("os.Open(root) error = %v", err)
	}
	t.Cleanup(func() {
		if closeErr := root.Close(); closeErr != nil {
			t.Errorf("root.Close() error = %v", closeErr)
		}
	})
	confined, err := flatfile.New(int(root.Fd()), "datasource.json", datasource.DefaultLimits())
	if err != nil {
		t.Fatalf("flatfile.New() error = %v", err)
	}
	t.Cleanup(func() {
		if closeErr := confined.Close(context.Background()); closeErr != nil {
			t.Errorf("flatfile.Close() error = %v", closeErr)
		}
	})
	entry, err := signingprofile.NewEntry(
		profile,
		handleID,
		publicHandle.value,
		[]datasource.ProfileUse{datasource.ProfileUseOriginator},
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("signingprofile.NewEntry() error = %v", err)
	}
	registry, err := signingprofile.NewRegistry(
		[]signingprofile.Entry{entry},
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("signingprofile.NewRegistry() error = %v", err)
	}
	events := &datasourceSigningEvents{}
	memoryProvider := &orderedDatasourceProvider{delegate: provider, events: events}
	flatProvider := &orderedDatasourceProvider{delegate: confined, events: events}
	deniedProvider := &orderedDatasourceProvider{
		delegate: provider,
		events:   events,
		failure:  datasource.NewError(datasource.ErrorCodeUnavailable),
	}
	memoryAdapter, err := signingprofile.NewAdapter(
		memoryProvider,
		registry,
		internalsigning.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("signingprofile.NewAdapter(memory) error = %v", err)
	}
	flatAdapter, err := signingprofile.NewAdapter(
		flatProvider,
		registry,
		internalsigning.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("signingprofile.NewAdapter(flatfile) error = %v", err)
	}
	denied, err := signingprofile.NewAdapter(
		deniedProvider,
		registry,
		internalsigning.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("signingprofile.NewAdapter(denied) error = %v", err)
	}
	signingProvider := &orderedSigningProvider{
		key: rsaKey, published: &rsaKey.PublicKey, handle: publicHandle, events: events,
	}
	authorizer := &authorizeOrdinary{}
	facade, err := NewSigner(
		signingProvider,
		&orderedRouteAuthority{delegate: routeplan.NewMemoryAuthority(), events: events},
		authorizer,
		signingProvider,
		WithSigningClock(func() time.Time { return time.Unix(1_700_000_000, 0) }),
	)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	public := publicSigningFixture{
		facade: facade, authorizer: authorizer,
	}
	return datasourceSigningIntegrationFixture{
		at: time.Unix(1_700_000_000, 0), profileID: profileID,
		allowed: map[string]signingprofile.Adapter{
			memoryProviderName:   memoryAdapter,
			flatfileProviderName: flatAdapter,
		},
		denied: denied, public: public, events: events, signing: signingProvider,
		flat: confined, flatPath: rootPath + "/datasource.json",
		flatDocument: document,
	}
}

// resolveAndSignDatasourceProfile is the test integration seam that refuses to
// enter signing when datasource resolution does not return one complete profile.
func resolveAndSignDatasourceProfile(
	ctx context.Context,
	adapter signingprofile.Adapter,
	signer *Signer,
	profileID datasource.ProfileID,
	use datasource.ProfileUse,
	evaluationTime time.Time,
	request func(SigningProfile) OriginatorSigningRequest,
) (SigningResult, SigningRecovery, error) {
	projected, err := adapter.ResolveProfile(
		ctx,
		profileID,
		use,
		evaluationTime,
	)
	if err != nil {
		return SigningResult{}, SigningRecovery{}, err
	}
	return signer.SignOriginator(ctx, request(SigningProfile{value: projected}))
}
