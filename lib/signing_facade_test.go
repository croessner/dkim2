package dkim2

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/routeplan"
	internalsigning "github.com/croessner/dkim2/internal/signing"
)

type publicRouteMemoryAuthority struct {
	value *routeplan.MemoryAuthority
	calls *atomic.Int64
}

// count records one authority callback when the test requested accounting.
func (a publicRouteMemoryAuthority) count() {
	if a.calls != nil {
		a.calls.Add(1)
	}
}

// Finalize delegates test authority issuance without bypassing the public result bridge.
func (a publicRouteMemoryAuthority) Finalize(ctx context.Context, query RouteFinalizeQuery) (RouteAuthorityResult, error) {
	a.count()
	result, err := a.value.Finalize(ctx, query.value)
	return RouteAuthorityResult{value: result}, err
}

// Reserve delegates one test reservation transition.
func (a publicRouteMemoryAuthority) Reserve(ctx context.Context, query RouteTicketQuery) (RouteAuthorityResult, error) {
	a.count()
	result, err := a.value.Reserve(ctx, query.value)
	return RouteAuthorityResult{value: result}, err
}

// ReleaseReservation delegates one test pre-boundary release transition.
func (a publicRouteMemoryAuthority) ReleaseReservation(ctx context.Context, query RouteTicketQuery) (RouteAuthorityResult, error) {
	a.count()
	result, err := a.value.ReleaseReservation(ctx, query.value)
	return RouteAuthorityResult{value: result}, err
}

// Burn delegates one test external-boundary transition.
func (a publicRouteMemoryAuthority) Burn(ctx context.Context, query RouteTicketQuery) (RouteAuthorityResult, error) {
	a.count()
	result, err := a.value.Burn(ctx, query.value)
	return RouteAuthorityResult{value: result}, err
}

// Replace delegates one test replacement transition.
func (a publicRouteMemoryAuthority) Replace(ctx context.Context, query RouteTicketQuery) (RouteAuthorityResult, error) {
	a.count()
	result, err := a.value.Replace(ctx, query.value)
	return RouteAuthorityResult{value: result}, err
}

// ConsumeRelease delegates one test restricted-release transition.
func (a publicRouteMemoryAuthority) ConsumeRelease(ctx context.Context, query RouteTicketQuery) (RouteAuthorityResult, error) {
	a.count()
	result, err := a.value.ConsumeRelease(ctx, query.value)
	return RouteAuthorityResult{value: result}, err
}

type publicSigningProvider struct {
	rsaKey  *rsa.PrivateKey
	edKey   ed25519.PrivateKey
	lookups atomic.Int64
	signs   atomic.Int64
}

// LookupPublicKey serves immutable public material for generated test credentials.
func (p *publicSigningProvider) LookupPublicKey(_ context.Context, query PublicKeyQuery) (PublicKeyResult, error) {
	p.lookups.Add(1)
	switch query.Algorithm() {
	case AlgorithmRSASHA256:
		return FoundRSAPublicKey(&p.rsaKey.PublicKey), nil
	case AlgorithmEd25519SHA256:
		return FoundEd25519PublicKey(p.edKey.Public().(ed25519.PublicKey)), nil
	default:
		return MissingPublicKey(query.Algorithm()), nil
	}
}

// SignDigest signs exactly the native digest supplied through the public callback.
func (p *publicSigningProvider) SignDigest(_ context.Context, _ PrivateKeyHandle, request PrivateKeySignRequest) (PrivateKeySignResult, error) {
	p.signs.Add(1)
	digest := request.Digest()
	switch request.Algorithm() {
	case AlgorithmRSASHA256:
		signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, p.rsaKey, crypto.SHA256, digest[:])
		if err != nil {
			return PrivateKeySignResult{}, err
		}
		return NewPrivateKeySignResult(signatureBytes), nil
	case AlgorithmEd25519SHA256:
		return NewPrivateKeySignResult(ed25519.Sign(p.edKey, digest[:])), nil
	default:
		return PrivateKeySignResult{}, nil
	}
}

type authorizeOrdinary struct{ calls atomic.Int64 }

// Authorize approves every exact ordinary authorization query.
func (a *authorizeOrdinary) Authorize(_ context.Context, query SigningAuthorizationQuery) (SigningAuthorizationResult, error) {
	a.calls.Add(1)
	return AuthorizeSigning(query), nil
}

type temporaryPrivateSigner struct{ calls atomic.Int64 }

// SignDigest returns one classified temporary callback failure.
func (s *temporaryPrivateSigner) SignDigest(context.Context, PrivateKeyHandle, PrivateKeySignRequest) (PrivateKeySignResult, error) {
	s.calls.Add(1)
	return PrivateKeySignResult{}, NewTemporaryProviderError()
}

type typedNilSigningError struct{}

// Error deliberately panics when invoked on a typed nil to prove bridge preflight.
func (e *typedNilSigningError) Error() string {
	if e == nil {
		panic("typed-nil signing error dereferenced")
	}
	return "private"
}

// ProviderErrorClass deliberately panics when invoked on a typed nil.
func (e *typedNilSigningError) ProviderErrorClass() ProviderErrorClass {
	if e == nil {
		panic("typed-nil signing error classified")
	}
	return ProviderErrorClassTemporary
}

type typedNilErrorPrivateSigner struct{}

// SignDigest returns a typed-nil classified error.
func (typedNilErrorPrivateSigner) SignDigest(context.Context, PrivateKeyHandle, PrivateKeySignRequest) (PrivateKeySignResult, error) {
	var err *typedNilSigningError
	return PrivateKeySignResult{}, err
}

// publicSigningFixture owns one reusable ordinary signing facade and credential.
type publicSigningFixture struct {
	facade          *Signer
	provider        *publicSigningProvider
	profile         SigningProfile
	existingProfile SigningProfile
	authorizer      *authorizeOrdinary
	routeCalls      *atomic.Int64
}

// newPublicSigningFixture constructs one deterministic RSA ordinary signing fixture.
func newPublicSigningFixture(t *testing.T) publicSigningFixture {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	provider := &publicSigningProvider{rsaKey: rsaKey, edKey: edKey}
	authorizer := &authorizeOrdinary{}
	routeCalls := &atomic.Int64{}
	facade, err := NewSigner(
		provider, publicRouteMemoryAuthority{
			value: routeplan.NewMemoryAuthority(),
			calls: routeCalls,
		},
		authorizer, provider, WithSigningClock(func() time.Time { return time.Unix(1_700_000_000, 0) }),
	)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	handle, err := NewPrivateKeyHandle([]byte("fixture-rsa"))
	if err != nil {
		t.Fatalf("NewPrivateKeyHandle() error = %v", err)
	}
	credential, err := NewRSASigningCredential(testRSASelector, &rsaKey.PublicKey, handle)
	if err != nil {
		t.Fatalf("NewRSASigningCredential() error = %v", err)
	}
	profile, err := NewRSASigningProfile("example.test", credential)
	if err != nil {
		t.Fatalf("NewRSASigningProfile() error = %v", err)
	}
	existingProfile, err := NewRSASigningProfile("example.net", credential)
	if err != nil {
		t.Fatalf("NewRSASigningProfile(existing) error = %v", err)
	}
	return publicSigningFixture{
		facade: facade, provider: provider, profile: profile,
		existingProfile: existingProfile, authorizer: authorizer, routeCalls: routeCalls,
	}
}

// originTicket plans one exact originator route ticket.
func (f publicSigningFixture) originTicket(t *testing.T, raw []byte, disclosure RouteDisclosure) RouteCopyTicket {
	t.Helper()
	source, err := NewSigningSource(raw)
	if err != nil {
		t.Fatalf("NewSigningSource() error = %v", err)
	}
	entry, err := NewOriginatorRouteEntry(
		source, []byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")},
		disclosure, []byte("local-route"),
	)
	if err != nil {
		t.Fatalf("NewOriginatorRouteEntry() error = %v", err)
	}
	request, err := NewRouteFanoutRequest([]RouteEntry{entry})
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest() error = %v", err)
	}
	_, tickets, err := f.facade.PlanRouteFanout(context.Background(), request)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout() tickets=%d error=%v", len(tickets), err)
	}
	return tickets[0]
}

// signOrigin signs and returns one unrestricted exact origin output.
func (f publicSigningFixture) signOrigin(t *testing.T, raw []byte, disclosure RouteDisclosure) []byte {
	t.Helper()
	result, recovery, err := f.facade.SignOriginator(
		context.Background(),
		NewOriginatorSigningRequest(
			raw, []byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")},
			f.originTicket(t, raw, disclosure), f.profile, SigningMetadata{},
			SigningTransportFinalNetworkPreDotStuffing,
		),
	)
	if err != nil || recovery.Valid() {
		t.Fatalf("SignOriginator() recovery=%v error=%v", recovery.Valid(), err)
	}
	signed, ok := result.Unrestricted()
	if !ok {
		t.Fatal("SignOriginator() did not return unrestricted output")
	}
	return signed.Bytes()
}

// existingTicket plans one exact capability-bound ordinary ticket.
func (f publicSigningFixture) existingTicket(t *testing.T, capability VerifiedRevisionInput, raw []byte, disclosure RouteDisclosure) RouteCopyTicket {
	t.Helper()
	source, err := NewSigningSource(raw)
	if err != nil {
		t.Fatalf("NewSigningSource() error = %v", err)
	}
	entry, err := NewExistingRouteEntry(
		capability, source, []byte("<relay@example.net>"), [][]byte{[]byte("<carol@next.test>")},
		disclosure, []byte("local-route"),
	)
	if err != nil {
		t.Fatalf("NewExistingRouteEntry() error = %v", err)
	}
	request, err := NewRouteFanoutRequest([]RouteEntry{entry})
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest() error = %v", err)
	}
	_, tickets, err := f.facade.PlanRouteFanout(context.Background(), request)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout() tickets=%d error=%v", len(tickets), err)
	}
	return tickets[0]
}

// existingInControlTicket plans one capability-bound local-only release route.
func (f publicSigningFixture) existingInControlTicket(t *testing.T, capability VerifiedRevisionInput, raw []byte, disclosure RouteDisclosure) RouteCopyTicket {
	t.Helper()
	source, err := NewSigningSource(raw)
	if err != nil {
		t.Fatalf("NewSigningSource() error = %v", err)
	}
	entry, err := NewInControlExistingRouteEntry(
		capability, source, []byte("<relay@example.net>"), [][]byte{[]byte("<carol@next.test>")},
		disclosure, []byte("local-route"), nil,
	)
	if err != nil {
		t.Fatalf("NewInControlExistingRouteEntry() error = %v", err)
	}
	request, err := NewRouteFanoutRequest([]RouteEntry{entry})
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest() error = %v", err)
	}
	_, tickets, err := f.facade.PlanRouteFanout(context.Background(), request)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout() tickets=%d error=%v", len(tickets), err)
	}
	return tickets[0]
}

// TestPublicOriginatorSigningAlgorithmsAndImmutableBytes proves all baseline
// profile shapes through the root facade.
func TestPublicOriginatorSigningAlgorithmsAndImmutableBytes(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	raw := []byte("From: alice@example.test\r\nTo: bob@example.net\r\nSubject: root facade\r\n\r\nbody\r\n")
	for _, testCase := range []struct {
		name       string
		profile    func(PrivateKeyHandle, PrivateKeyHandle) (SigningProfile, error)
		algorithms []Algorithm
	}{
		{name: testRSASelector, algorithms: []Algorithm{AlgorithmRSASHA256}, profile: func(rsaHandle, _ PrivateKeyHandle) (SigningProfile, error) {
			credential, credentialErr := NewRSASigningCredential(testRSASelector, &rsaKey.PublicKey, rsaHandle)
			if credentialErr != nil {
				return SigningProfile{}, credentialErr
			}
			return NewRSASigningProfile("example.test", credential)
		}},
		{name: "ed25519", algorithms: []Algorithm{AlgorithmEd25519SHA256}, profile: func(_, edHandle PrivateKeyHandle) (SigningProfile, error) {
			credential, credentialErr := NewEd25519SigningCredential("ed", edKey.Public().(ed25519.PublicKey), edHandle)
			if credentialErr != nil {
				return SigningProfile{}, credentialErr
			}
			return NewEd25519SigningProfile("example.test", credential)
		}},
		{name: "dual", algorithms: []Algorithm{AlgorithmRSASHA256, AlgorithmEd25519SHA256}, profile: func(rsaHandle, edHandle PrivateKeyHandle) (SigningProfile, error) {
			rsaCredential, credentialErr := NewRSASigningCredential(testRSASelector, &rsaKey.PublicKey, rsaHandle)
			if credentialErr != nil {
				return SigningProfile{}, credentialErr
			}
			edCredential, credentialErr := NewEd25519SigningCredential("ed", edKey.Public().(ed25519.PublicKey), edHandle)
			if credentialErr != nil {
				return SigningProfile{}, credentialErr
			}
			return NewDualSigningProfile("example.test", rsaCredential, edCredential)
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			provider := &publicSigningProvider{rsaKey: rsaKey, edKey: edKey}
			authorizer := &authorizeOrdinary{}
			facade, err := NewSigner(
				provider, publicRouteMemoryAuthority{value: routeplan.NewMemoryAuthority()},
				authorizer, provider, WithSigningClock(func() time.Time { return time.Unix(1_700_000_000, 0) }),
			)
			if err != nil {
				t.Fatalf("NewSigner() error = %v", err)
			}
			rsaHandle, _ := NewPrivateKeyHandle([]byte("rsa-key"))
			edHandle, _ := NewPrivateKeyHandle([]byte("ed-key"))
			profile, err := testCase.profile(rsaHandle, edHandle)
			if err != nil {
				t.Fatalf("profile() error = %v", err)
			}
			source, _ := NewSigningSource(raw)
			entry, err := NewOriginatorRouteEntry(
				source, []byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")},
				RouteDisclosureSingle, []byte("local-route"),
			)
			if err != nil {
				t.Fatalf("NewOriginatorRouteEntry() error = %v", err)
			}
			fanout, _ := NewRouteFanoutRequest([]RouteEntry{entry})
			plan, tickets, err := facade.PlanRouteFanout(context.Background(), fanout)
			if err != nil || !plan.Valid() || len(tickets) != 1 {
				t.Fatalf("PlanRouteFanout() plan=%v tickets=%d error=%v", plan.Valid(), len(tickets), err)
			}
			result, recovery, err := facade.SignOriginator(context.Background(), NewOriginatorSigningRequest(
				raw, []byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")},
				tickets[0], profile, SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
			))
			if err != nil || recovery.Valid() || !result.Valid() {
				t.Fatalf("SignOriginator() valid=%v recovery=%v error=%v", result.Valid(), recovery.Valid(), err)
			}
			signed, ok := result.Unrestricted()
			if !ok || !signed.Valid() {
				t.Fatal("SignOriginator() did not return unrestricted output")
			}
			if facts := signed.Facts(); facts.Role() != SigningRoleOriginator ||
				facts.Sequence() != 1 || facts.NewInstanceNumber() != 1 ||
				!reflect.DeepEqual(facts.Algorithms(), testCase.algorithms) {
				t.Fatalf("Facts() = %#v", facts)
			}
			first := signed.Bytes()
			second := signed.Bytes()
			if len(first) <= len(raw) || !bytes.Contains(first, []byte("Message-Instance:")) ||
				!bytes.Contains(first, []byte("DKIM2-Signature:")) || !bytes.Equal(first, second) {
				t.Fatal("signed output is incomplete or unstable")
			}
			first[0] ^= 0xff
			if bytes.Equal(first, signed.Bytes()) {
				t.Fatal("Bytes() retained caller mutation")
			}
			if got := provider.signs.Load(); got != int64(len(testCase.algorithms)) {
				t.Fatalf("private signing calls = %d", got)
			}
		})
	}
}

// TestPublicInvalidTransportFailsBeforeCallbacksAndRestrictedAPIHasNoBytes
// proves closed transport preflight and the local-only API shape.
func TestPublicInvalidTransportFailsBeforeCallbacksAndRestrictedAPIHasNoBytes(t *testing.T) {
	if _, ok := reflect.TypeOf(LocalOnlySignedMessage{}).MethodByName("Bytes"); ok {
		t.Fatal("LocalOnlySignedMessage exposes Bytes")
	}
	if _, ok := reflect.TypeOf(LocalOnlySignedMessage{}).MethodByName("MarshalText"); ok {
		t.Fatal("LocalOnlySignedMessage exposes MarshalText")
	}
	if _, ok := reflect.TypeOf(SigningResult{}).MethodByName("Bytes"); ok {
		t.Fatal("SigningResult exposes generic Bytes")
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	provider := &publicSigningProvider{rsaKey: rsaKey, edKey: edKey}
	var routeCalls atomic.Int64
	authorizer := &authorizeOrdinary{}
	facade, err := NewSigner(
		provider, publicRouteMemoryAuthority{
			value: routeplan.NewMemoryAuthority(),
			calls: &routeCalls,
		},
		authorizer, provider,
	)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	handle, _ := NewPrivateKeyHandle([]byte(testRSASelector))
	credential, _ := NewRSASigningCredential(testRSASelector, &rsaKey.PublicKey, handle)
	profile, _ := NewRSASigningProfile("example.test", credential)
	raw := []byte("From: a@example.test\r\n\r\nbody\r\n")
	source, _ := NewSigningSource(raw)
	entry, _ := NewOriginatorRouteEntry(
		source, []byte("<a@example.test>"), [][]byte{[]byte("<b@example.net>")},
		RouteDisclosureSingle, []byte("local"),
	)
	fanout, _ := NewRouteFanoutRequest([]RouteEntry{entry})
	_, tickets, err := facade.PlanRouteFanout(context.Background(), fanout)
	if err != nil {
		t.Fatalf("PlanRouteFanout() error = %v", err)
	}
	beforeLookups := provider.lookups.Load()
	beforeSigns := provider.signs.Load()
	beforeAuthorizations := authorizer.calls.Load()
	beforeRouteCalls := routeCalls.Load()
	result, recovery, err := facade.SignOriginator(context.Background(), NewOriginatorSigningRequest(
		raw, []byte("<a@example.test>"), [][]byte{[]byte("<b@example.net>")},
		tickets[0], profile, SigningMetadata{}, SigningTransportForm("wrong"),
	))
	if err == nil || result.Valid() || recovery.Valid() {
		t.Fatalf("invalid transport result=%v recovery=%v error=%v", result.Valid(), recovery.Valid(), err)
	}
	if provider.lookups.Load() != beforeLookups || provider.signs.Load() != beforeSigns ||
		authorizer.calls.Load() != beforeAuthorizations || routeCalls.Load() != beforeRouteCalls {
		t.Fatal("invalid transport crossed an external callback boundary")
	}
}

// TestPublicExistingSigningDerivesForwarderAndReviser proves the combined
// request path derives both ordinary roles exclusively from the hash gate.
//
//nolint:gocyclo // The one integration test intentionally proves both hash-gate branches and final verification.
func TestPublicExistingSigningDerivesForwarderAndReviser(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	origin := fixture.signOrigin(t, []byte(
		"From: alice@example.test\r\nTo: bob@example.net\r\nSubject: before\r\n\r\nbody\r\n",
	), RouteDisclosureSingle)
	verification, capability, err := fixture.facade.VerifyForRevision(
		context.Background(), NewVerifyRequest(
			origin, []byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")},
		),
	)
	if err != nil || verification.Status() != RevisionVerificationVerified || !capability.Valid() {
		t.Fatalf("VerifyForRevision() status=%q capability=%v error=%v", verification.Status(), capability.Valid(), err)
	}

	existingReverse := []byte("<relay@example.net>")
	existingForward := [][]byte{[]byte("<carol@next.test>")}
	unchangedRequest := NewExistingSigningRequest(
		capability, origin, existingReverse, existingForward,
		fixture.existingTicket(t, capability, origin, RouteDisclosureBccSeparated),
		fixture.existingProfile, SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
		RejectUnavailableBody, RecipeCopyOnly,
	)
	existingReverse[1] = 'X'
	existingForward[0][1] = 'Y'
	unchangedResult, recovery, err := fixture.facade.SignExisting(
		context.Background(), unchangedRequest,
	)
	if err != nil || recovery.Valid() || !unchangedResult.Valid() {
		t.Fatalf("unchanged SignExisting() valid=%v recovery=%v error=%v", unchangedResult.Valid(), recovery.Valid(), err)
	}
	unchanged, ok := unchangedResult.Unrestricted()
	if !ok || unchanged.Facts().Role() != SigningRoleHashUnchangedForwarder ||
		unchanged.Facts().NewInstanceNumber() != 0 ||
		unchanged.Facts().RecipeOutcome() != SigningRecipeUnchanged ||
		unchanged.Facts().EnvelopeForm() != SigningEnvelopeOrdinary {
		t.Fatalf("unchanged facts=%#v", unchanged.Facts())
	}
	if bytes.Count(unchanged.Bytes(), []byte("Message-Instance:")) != 1 ||
		bytes.Count(unchanged.Bytes(), []byte("DKIM2-Signature:")) != 2 {
		t.Fatal("hash-unchanged forwarding emitted the wrong protocol field counts")
	}

	revised := bytes.Replace(origin, []byte("Subject: before\r\n"), []byte("Subject: after\r\n"), 1)
	revisedResult, recovery, err := fixture.facade.SignExisting(
		context.Background(),
		NewExistingSigningRequest(
			capability, revised, []byte("<relay@example.net>"), [][]byte{[]byte("<carol@next.test>")},
			fixture.existingTicket(t, capability, revised, RouteDisclosureSingle),
			fixture.existingProfile, SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
			RejectUnavailableBody, RecipeAllowLiterals,
		),
	)
	if err != nil || recovery.Valid() || !revisedResult.Valid() {
		t.Fatalf("revised SignExisting() valid=%v recovery=%v error=%v", revisedResult.Valid(), recovery.Valid(), err)
	}
	reviser, ok := revisedResult.Unrestricted()
	if !ok || reviser.Facts().Role() != SigningRoleReviser ||
		reviser.Facts().NewInstanceNumber() != 2 ||
		reviser.Facts().RecipeOutcome() != SigningRecipeGenerated ||
		len(reviser.Facts().Authorizations()) != 1 ||
		reviser.Facts().Authorizations()[0].Purpose() != SigningAuthorizationPolicy {
		t.Fatalf("reviser facts=%#v", reviser.Facts())
	}
	if bytes.Count(reviser.Bytes(), []byte("Message-Instance:")) != 2 ||
		bytes.Count(reviser.Bytes(), []byte("DKIM2-Signature:")) != 2 {
		t.Fatal("revision emitted the wrong protocol field counts")
	}
	reverified, _, err := fixture.facade.VerifyForRevision(
		context.Background(), NewVerifyRequest(
			reviser.Bytes(), []byte("<relay@example.net>"), [][]byte{[]byte("<carol@next.test>")},
		),
	)
	if err != nil || reverified.Status() != RevisionVerificationVerified {
		t.Fatalf("final VerifyForRevision() status=%q error=%v", reverified.Status(), err)
	}

	bodyRevised := append(append([]byte(nil), origin...), []byte("additional\r\n")...)
	bodyResult, recovery, err := fixture.facade.SignExisting(
		context.Background(),
		NewExistingSigningRequest(
			capability, bodyRevised, []byte("<relay@example.net>"), [][]byte{[]byte("<carol@next.test>")},
			fixture.existingTicket(t, capability, bodyRevised, RouteDisclosureSingle),
			fixture.existingProfile, SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
			RejectUnavailableBody, RecipeCopyOnly,
		),
	)
	if err != nil || recovery.Valid() || !bodyResult.Valid() {
		t.Fatalf("body SignExisting() valid=%v recovery=%v error=%v", bodyResult.Valid(), recovery.Valid(), err)
	}
	bodySigned, ok := bodyResult.Unrestricted()
	if !ok || bodySigned.Facts().Role() != SigningRoleReviser ||
		bodySigned.Facts().BodyUnavailable() {
		t.Fatalf("body revision facts=%#v", bodySigned.Facts())
	}
}

// TestPublicHeaderOnlyRevisionProducesExplicitUnavailableBody proves framing
// preservation and the closed b:null policy through the combined request path.
func TestPublicHeaderOnlyRevisionProducesExplicitUnavailableBody(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	origin := fixture.signOrigin(
		t, []byte("From: alice@example.test\r\nSubject: header only\r\n"),
		RouteDisclosureSingle,
	)
	if bytes.Contains(origin, []byte("\r\n\r\n")) {
		t.Fatal("header-only origin output invented a separator")
	}
	_, capability, err := fixture.facade.VerifyForRevision(
		context.Background(), NewVerifyRequest(
			origin, []byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")},
		),
	)
	if err != nil || !capability.Valid() {
		t.Fatalf("VerifyForRevision() capability=%v error=%v", capability.Valid(), err)
	}
	revised := append(append([]byte(nil), origin...), []byte("\r\nnew body\r\n")...)
	result, recovery, err := fixture.facade.SignExisting(
		context.Background(),
		NewExistingSigningRequest(
			capability, revised, []byte("<relay@example.net>"), [][]byte{[]byte("<carol@next.test>")},
			fixture.existingTicket(t, capability, revised, RouteDisclosureSingle),
			fixture.existingProfile, SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
			AllowUnavailableBody, RecipeCopyOnly,
		),
	)
	if err != nil || recovery.Valid() || !result.Valid() {
		t.Fatalf("SignExisting() valid=%v recovery=%v error=%v", result.Valid(), recovery.Valid(), err)
	}
	signed, ok := result.Unrestricted()
	if !ok || !signed.Facts().BodyUnavailable() ||
		signed.Facts().RecipeOutcome() != SigningRecipeGenerated ||
		!signed.Facts().BodyUnavailableReason().Known() {
		t.Fatalf("b:null unrestricted=%v unavailable=%v recipe=%q reason=%q",
			ok, signed.Facts().BodyUnavailable(), signed.Facts().RecipeOutcome(),
			signed.Facts().BodyUnavailableReason())
	}
}

// TestPublicContextPrecedesParsingAndTypedNilConstruction proves caller
// control flow and typed-nil dependencies fail without protocol outcomes.
func TestPublicContextPrecedesParsingAndTypedNilConstruction(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	outcome, capability, err := fixture.facade.VerifyForRevision(
		canceled, NewVerifyRequest([]byte("bare\nlf"), nil, nil),
	)
	if err != context.Canceled || outcome.Valid() || capability.Valid() {
		t.Fatalf("canceled VerifyForRevision() outcome=%v capability=%v error=%v", outcome.Valid(), capability.Valid(), err)
	}
	var nilContext context.Context
	if outcome, capability, err = fixture.facade.VerifyForRevision(
		nilContext, NewVerifyRequest([]byte("bare\nlf"), nil, nil),
	); err == nil || outcome.Valid() || capability.Valid() {
		t.Fatalf("nil-context VerifyForRevision() outcome=%v capability=%v error=%v", outcome.Valid(), capability.Valid(), err)
	}
	var nilSigner *publicSigningProvider
	if facade, err := NewSigner(
		fixture.provider, publicRouteMemoryAuthority{value: routeplan.NewMemoryAuthority()},
		fixture.authorizer, nilSigner,
	); err == nil || facade != nil {
		t.Fatalf("typed-nil NewSigner() facade=%v error=%v", facade, err)
	}
}

// TestForgedPublicSigningFactsFailClosed locks role, authorization, feedback,
// algorithm, and restriction correlations.
func TestForgedPublicSigningFactsFailClosed(t *testing.T) {
	base := SignedMessageFacts{
		role: SigningRoleOriginator, envelope: SigningEnvelopeOrdinary,
		newInstance: 1, sequence: 1, algorithms: []Algorithm{AlgorithmRSASHA256},
		recipe: SigningRecipeUnchanged, flags: []SignedMessageFlag{},
		multiplicity: 1, restriction: SigningRestrictionUnrestricted, valid: true,
	}
	if !base.Valid() {
		t.Fatal("coherent base facts rejected")
	}
	forgedPolicy := base
	forgedPolicy.authorizations = []SigningAuthorizationFact{{
		purpose: SigningAuthorizationPolicy, status: SigningAuthorizationAuthorized,
		restriction: SigningRestrictionUnrestricted, valid: true,
	}}
	if forgedPolicy.Valid() {
		t.Fatal("originator policy fact was accepted")
	}
	forgedFeedback := base
	forgedFeedback.flags = []SignedMessageFlag{SignedMessageFlagFeedHere}
	if forgedFeedback.Valid() {
		t.Fatal("feedhere without feedback authorization was accepted")
	}
	forgedFeedback.authorizations = []SigningAuthorizationFact{{
		purpose: SigningAuthorizationFeedbackRelay, status: SigningAuthorizationAuthorized,
		restriction: SigningRestrictionUnrestricted, valid: true,
	}}
	if forgedFeedback.Valid() {
		t.Fatal("originator feedback authorization was accepted")
	}
	forgedAlgorithms := base
	forgedAlgorithms.algorithms = []Algorithm{AlgorithmEd25519SHA256, AlgorithmRSASHA256}
	if forgedAlgorithms.Valid() {
		t.Fatal("noncanonical algorithm order was accepted")
	}
}

// TestPublicLocalOnlyResultIsConstructedWithoutByteEscape proves a genuine
// inherited donotmodify violation produces only the restricted variant.
func TestPublicLocalOnlyResultIsConstructedWithoutByteEscape(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	raw := []byte("From: alice@example.test\r\nSubject: protected\r\n\r\nbody\r\n")
	metadata, err := NewSigningMetadata(nil, false, []SigningFlag{SigningFlagDoNotModify})
	if err != nil {
		t.Fatalf("NewSigningMetadata() error = %v", err)
	}
	originResult, recovery, err := fixture.facade.SignOriginator(
		context.Background(), NewOriginatorSigningRequest(
			raw, []byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")},
			fixture.originTicket(t, raw, RouteDisclosureSingle), fixture.profile,
			metadata, SigningTransportFinalNetworkPreDotStuffing,
		),
	)
	if err != nil || recovery.Valid() {
		t.Fatalf("SignOriginator() recovery=%v error=%v", recovery.Valid(), err)
	}
	origin, ok := originResult.Unrestricted()
	if !ok {
		t.Fatal("origin was not unrestricted")
	}
	_, capability, err := fixture.facade.VerifyForRevision(
		context.Background(), NewVerifyRequest(
			origin.Bytes(), []byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")},
		),
	)
	if err != nil || !capability.Valid() {
		t.Fatalf("VerifyForRevision() capability=%v error=%v", capability.Valid(), err)
	}
	revised := bytes.Replace(origin.Bytes(), []byte("Subject: protected\r\n"), []byte("Subject: modified\r\n"), 1)
	result, recovery, err := fixture.facade.SignExisting(
		context.Background(), NewExistingSigningRequest(
			capability, revised, []byte("<relay@example.net>"), [][]byte{[]byte("<carol@next.test>")},
			fixture.existingInControlTicket(t, capability, revised, RouteDisclosureSingle),
			fixture.existingProfile, SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
			RejectUnavailableBody, RecipeAllowLiterals,
		),
	)
	if err != nil || recovery.Valid() || !result.Valid() {
		t.Fatalf("SignExisting() valid=%v recovery=%v error=%v", result.Valid(), recovery.Valid(), err)
	}
	local, ok := result.LocalOnly()
	if !ok || !local.Valid() || local.Facts().Restriction() != SigningRestrictionLocalOnly {
		t.Fatalf("local-only result valid=%v facts=%#v", ok && local.Valid(), local.Facts())
	}
	if _, ok := result.Unrestricted(); ok {
		t.Fatal("local-only result also exposed unrestricted variant")
	}
}

// TestPublicNextDomainCreationReleaseAndCompletion proves the third public path,
// terminal OOB state, exact release, and restored ordinary revision proof.
//
//nolint:gocyclo // The end-to-end test keeps the three protocol transitions visibly ordered.
func TestPublicNextDomainCreationReleaseAndCompletion(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	ctx := context.Background()
	raw := []byte("From: alice@example.test\r\nSubject: next-domain\r\n\r\nbody\r\n")
	origin := fixture.signOrigin(t, raw, RouteDisclosureSingle)
	outcome, capability, err := fixture.facade.VerifyForRevision(
		ctx, NewVerifyRequest(
			origin, []byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")},
		),
	)
	if err != nil || outcome.Status() != RevisionVerificationVerified || !capability.Valid() {
		t.Fatalf("origin revision proof status=%q valid=%t error=%v", outcome.Status(), capability.Valid(), err)
	}
	futureHandle, err := NewPrivateKeyHandle([]byte("future-next-domain"))
	if err != nil {
		t.Fatalf("NewPrivateKeyHandle() error = %v", err)
	}
	futureCredential, err := NewRSASigningCredential(
		"future", &fixture.provider.rsaKey.PublicKey, futureHandle,
	)
	if err != nil {
		t.Fatalf("NewRSASigningCredential() error = %v", err)
	}
	published, err := fixture.facade.IssueNextDomainPublication(
		ctx, NewRSANextDomainPublicationRequest("next.example.test", futureCredential),
	)
	if err != nil || !published.Valid() {
		t.Fatalf("IssueNextDomainPublication() valid=%t error=%v", published.Valid(), err)
	}
	source, err := NewSigningSource(origin)
	if err != nil {
		t.Fatalf("NewSigningSource() error = %v", err)
	}
	entry, err := NewNextDomainRouteEntry(
		capability, source, []byte("<relay@example.net>"),
		[][]byte{[]byte("<receiver@next.example.test>")}, RouteDisclosureSingle,
		[]byte("next-domain-route"), []byte("receiver-transaction-one"),
	)
	if err != nil {
		t.Fatalf("NewNextDomainRouteEntry() error = %v", err)
	}
	fanout, err := NewRouteFanoutRequest([]RouteEntry{entry})
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest() error = %v", err)
	}
	_, tickets, err := fixture.facade.PlanRouteFanout(ctx, fanout)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout() tickets=%d error=%v", len(tickets), err)
	}
	result, recovery, err := fixture.facade.SignNextDomain(
		ctx, NewNextDomainSigningRequest(
			capability, origin, []byte("<relay@example.net>"),
			[][]byte{[]byte("<receiver@next.example.test>")}, tickets[0],
			fixture.existingProfile, SigningMetadata{},
			SigningTransportFinalNetworkPreDotStuffing,
			RejectUnavailableBody, RecipeCopyOnly, "next.example.test", published,
		),
	)
	if err != nil || recovery.Valid() || !result.Valid() {
		t.Fatalf("SignNextDomain() valid=%t recovery=%t error=%v", result.Valid(), recovery.Valid(), err)
	}
	terminal, ok := result.OutOfBandAcceptance()
	if !ok || terminal.Facts().EnvelopeForm() != SigningEnvelopeNextDomain ||
		terminal.Facts().Restriction() != SigningRestrictionOutOfBandAcceptance {
		t.Fatalf("terminal result ok=%t facts=%#v", ok, terminal.Facts())
	}
	if _, ordinary := result.Unrestricted(); ordinary {
		t.Fatal("terminal result exposed unrestricted bytes")
	}
	terminalBytes, err := terminal.ReleaseForOutOfBandAcceptance(
		ctx, tickets[0], []byte("<relay@example.net>"),
		[][]byte{[]byte("<receiver@next.example.test>")},
		[]byte("receiver-transaction-one"), []byte("next-domain-route"),
	)
	if err != nil || len(terminalBytes) == 0 {
		t.Fatalf("OOB release bytes=%d error=%v", len(terminalBytes), err)
	}
	if replay, replayErr := terminal.ReleaseForOutOfBandAcceptance(
		ctx, tickets[0], []byte("<relay@example.net>"),
		[][]byte{[]byte("<receiver@next.example.test>")},
		[]byte("receiver-transaction-one"), []byte("next-domain-route"),
	); replayErr == nil || replay != nil {
		t.Fatalf("OOB replay bytes=%d error=%v", len(replay), replayErr)
	}
	terminalOutcome, terminalCapability, err := fixture.facade.VerifyForRevision(
		ctx, NewVerifyRequest(
			terminalBytes, []byte("<relay@example.net>"),
			[][]byte{[]byte("<receiver@next.example.test>")},
		),
	)
	if err != nil ||
		terminalOutcome.Status() != RevisionVerificationTerminalNextDomainAuthorizationRequired ||
		!terminalCapability.Valid() {
		t.Fatalf("terminal proof status=%q valid=%t error=%v",
			terminalOutcome.Status(), terminalCapability.Valid(), err)
	}
	completionProfile, err := NewRSASigningProfile("next.example.test", futureCredential)
	if err != nil {
		t.Fatalf("NewRSASigningProfile(completion) error = %v", err)
	}
	completionSource, err := NewSigningSource(terminalBytes)
	if err != nil {
		t.Fatalf("NewSigningSource(completion) error = %v", err)
	}
	completionEntry, err := NewReceiverBoundExistingRouteEntry(
		terminalCapability, completionSource, []byte("<relay@next.example.test>"),
		[][]byte{[]byte("<final@example.org>")}, RouteDisclosureSingle,
		[]byte("completion-route"), []byte("receiver-transaction-two"),
	)
	if err != nil {
		t.Fatalf("NewReceiverBoundExistingRouteEntry() error = %v", err)
	}
	completionFanout, err := NewRouteFanoutRequest([]RouteEntry{completionEntry})
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest(completion) error = %v", err)
	}
	_, completionTickets, err := fixture.facade.PlanRouteFanout(ctx, completionFanout)
	if err != nil || len(completionTickets) != 1 {
		t.Fatalf("PlanRouteFanout(completion) tickets=%d error=%v", len(completionTickets), err)
	}
	completedResult, completedRecovery, err := fixture.facade.SignExisting(
		ctx, NewExistingSigningRequest(
			terminalCapability, terminalBytes, []byte("<relay@next.example.test>"),
			[][]byte{[]byte("<final@example.org>")}, completionTickets[0],
			completionProfile, SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
			RejectUnavailableBody, RecipeCopyOnly,
		),
	)
	if err != nil || completedRecovery.Valid() || !completedResult.Valid() {
		t.Fatalf("SignExisting(completion) valid=%t recovery=%t error=%v",
			completedResult.Valid(), completedRecovery.Valid(), err)
	}
	completed, ok := completedResult.Unrestricted()
	if !ok || completed.Facts().EnvelopeForm() != SigningEnvelopeOrdinary {
		t.Fatalf("completion result ok=%t facts=%#v", ok, completed.Facts())
	}
	finalOutcome, _, err := fixture.facade.VerifyForRevision(
		ctx, NewVerifyRequest(
			completed.Bytes(), []byte("<relay@next.example.test>"),
			[][]byte{[]byte("<final@example.org>")},
		),
	)
	if err != nil || finalOutcome.Status() != RevisionVerificationVerified {
		t.Fatalf("completion proof status=%q error=%v", finalOutcome.Status(), err)
	}
}

// TestPublicMismatchFailsBeforeCallbacks proves raw/ticket mismatch is local,
// atomic, and does not invoke publication or private signing.
func TestPublicMismatchFailsBeforeCallbacks(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	raw := []byte("From: alice@example.test\r\n\r\nbody\r\n")
	ticket := fixture.originTicket(t, raw, RouteDisclosureSingle)
	lookups := fixture.provider.lookups.Load()
	signs := fixture.provider.signs.Load()
	authorizations := fixture.authorizer.calls.Load()
	routeCalls := fixture.routeCalls.Load()
	result, recovery, err := fixture.facade.SignOriginator(
		context.Background(), NewOriginatorSigningRequest(
			append(append([]byte(nil), raw...), []byte("changed")...),
			[]byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")}, ticket,
			fixture.profile, SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
		),
	)
	if err == nil || result.Valid() || recovery.Valid() {
		t.Fatalf("mismatch valid=%v recovery=%v error=%v", result.Valid(), recovery.Valid(), err)
	}
	if fixture.provider.lookups.Load() != lookups || fixture.provider.signs.Load() != signs ||
		fixture.authorizer.calls.Load() != authorizations ||
		fixture.routeCalls.Load() != routeCalls {
		t.Fatal("ticket/raw mismatch crossed an external callback")
	}
	for _, envelope := range []struct {
		reverse []byte
		forward [][]byte
	}{
		{reverse: []byte("<wrong@example.test>"), forward: [][]byte{[]byte("<bob@example.net>")}},
		{reverse: []byte("<alice@example.test>"), forward: [][]byte{[]byte("<other@example.net>")}},
		{reverse: []byte("<alice@example.test>"), forward: [][]byte{
			[]byte("<bob@example.net>"), []byte("<extra@example.net>"),
		}},
	} {
		result, recovery, err = fixture.facade.SignOriginator(
			context.Background(), NewOriginatorSigningRequest(
				raw, envelope.reverse, envelope.forward, ticket, fixture.profile,
				SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
			),
		)
		if err == nil || result.Valid() || recovery.Valid() {
			t.Fatalf("envelope mismatch valid=%v recovery=%v error=%v", result.Valid(), recovery.Valid(), err)
		}
	}
	if fixture.provider.lookups.Load() != lookups || fixture.provider.signs.Load() != signs ||
		fixture.authorizer.calls.Load() != authorizations ||
		fixture.routeCalls.Load() != routeCalls {
		t.Fatal("ticket/envelope mismatch crossed an external callback")
	}
}

// TestPublicEnvelopeSnapshotsAndOrderedGroupMatching proves constructors clone
// envelope evidence and ordered recipient drift fails before every callback.
func TestPublicEnvelopeSnapshotsAndOrderedGroupMatching(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	raw := []byte("From: alice@example.test\r\nSubject: group\r\n\r\nbody\r\n")
	testPublicOriginatorEnvelopeSnapshotsAndOrderedGroupMatching(t, fixture, raw)
	testPublicExistingEnvelopeSnapshotsAndOrderedGroupMatching(t, fixture, raw)
}

// testPublicOriginatorEnvelopeSnapshotsAndOrderedGroupMatching proves originator request immutability and ordering.
func testPublicOriginatorEnvelopeSnapshotsAndOrderedGroupMatching(
	t *testing.T,
	fixture publicSigningFixture,
	raw []byte,
) {
	t.Helper()
	reverse := []byte("<alice@example.test>")
	forward := [][]byte{[]byte("<bob@example.net>"), []byte("<bill@example.net>")}
	request := NewOriginatorSigningRequest(
		raw, reverse, forward, planPublicOriginatorGroupTicket(t, fixture, raw, "clone"), fixture.profile,
		SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
	)
	reverse[1] = 'X'
	forward[0][1] = 'Y'
	forward[0], forward[1] = forward[1], forward[0]
	result, recovery, err := fixture.facade.SignOriginator(context.Background(), request)
	if err != nil || recovery.Valid() || !result.Valid() {
		t.Fatalf("mutated caller envelope result=%v recovery=%v error=%v", result.Valid(), recovery.Valid(), err)
	}

	ticket := planPublicOriginatorGroupTicket(t, fixture, raw, "reordered")
	lookups := fixture.provider.lookups.Load()
	signs := fixture.provider.signs.Load()
	authorizations := fixture.authorizer.calls.Load()
	routeCalls := fixture.routeCalls.Load()
	result, recovery, err = fixture.facade.SignOriginator(
		context.Background(), NewOriginatorSigningRequest(
			raw, []byte("<alice@example.test>"),
			[][]byte{[]byte("<bill@example.net>"), []byte("<bob@example.net>")},
			ticket, fixture.profile, SigningMetadata{},
			SigningTransportFinalNetworkPreDotStuffing,
		),
	)
	if err == nil || result.Valid() || recovery.Valid() {
		t.Fatalf("reordered group result=%v recovery=%v error=%v", result.Valid(), recovery.Valid(), err)
	}
	if fixture.provider.lookups.Load() != lookups || fixture.provider.signs.Load() != signs ||
		fixture.authorizer.calls.Load() != authorizations ||
		fixture.routeCalls.Load() != routeCalls {
		t.Fatal("reordered group crossed authorization or provider boundary")
	}
}

// testPublicExistingEnvelopeSnapshotsAndOrderedGroupMatching proves existing request immutability and ordering.
func testPublicExistingEnvelopeSnapshotsAndOrderedGroupMatching(
	t *testing.T,
	fixture publicSigningFixture,
	raw []byte,
) {
	t.Helper()
	origin := fixture.signOrigin(t, raw, RouteDisclosureSingle)
	verification, capability, err := fixture.facade.VerifyForRevision(
		context.Background(), NewVerifyRequest(
			origin, []byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")},
		),
	)
	if err != nil || verification.Status() != RevisionVerificationVerified || !capability.Valid() {
		t.Fatalf("VerifyForRevision() status=%q capability=%v error=%v",
			verification.Status(), capability.Valid(), err)
	}

	existingReverse := []byte("<relay@example.net>")
	existingForward := [][]byte{
		[]byte("<carol@next.test>"),
		[]byte("<carl@next.test>"),
	}
	existingRequest := NewExistingSigningRequest(
		capability, origin, existingReverse, existingForward,
		planPublicExistingGroupTicket(t, fixture, capability, origin, "existing-clone"),
		fixture.existingProfile, SigningMetadata{},
		SigningTransportFinalNetworkPreDotStuffing, RejectUnavailableBody, RecipeCopyOnly,
	)
	existingReverse[1] = 'X'
	existingForward[0][1] = 'Y'
	existingForward[0], existingForward[1] = existingForward[1], existingForward[0]
	result, recovery, err := fixture.facade.SignExisting(context.Background(), existingRequest)
	if err != nil || recovery.Valid() || !result.Valid() {
		t.Fatalf("mutated existing caller envelope result=%v recovery=%v error=%v",
			result.Valid(), recovery.Valid(), err)
	}

	for _, envelope := range []struct {
		name    string
		reverse []byte
		forward [][]byte
	}{
		{
			name:    "one-byte reverse drift",
			reverse: []byte("<Xelay@example.net>"),
			forward: [][]byte{
				[]byte("<carol@next.test>"),
				[]byte("<carl@next.test>"),
			},
		},
		{
			name:    "ordered forward drift",
			reverse: []byte("<relay@example.net>"),
			forward: [][]byte{
				[]byte("<carl@next.test>"),
				[]byte("<carol@next.test>"),
			},
		},
	} {
		t.Run("existing "+envelope.name, func(t *testing.T) {
			existingTicket := planPublicExistingGroupTicket(
				t, fixture, capability, origin, envelope.name,
			)
			lookupsBefore := fixture.provider.lookups.Load()
			signsBefore := fixture.provider.signs.Load()
			authorizationsBefore := fixture.authorizer.calls.Load()
			routeCallsBefore := fixture.routeCalls.Load()
			gotResult, gotRecovery, signErr := fixture.facade.SignExisting(
				context.Background(), NewExistingSigningRequest(
					capability, origin, envelope.reverse, envelope.forward, existingTicket,
					fixture.existingProfile, SigningMetadata{},
					SigningTransportFinalNetworkPreDotStuffing,
					RejectUnavailableBody, RecipeCopyOnly,
				),
			)
			if signErr == nil || gotResult.Valid() || gotRecovery.Valid() {
				t.Fatalf("existing drift result=%v recovery=%v error=%v",
					gotResult.Valid(), gotRecovery.Valid(), signErr)
			}
			if fixture.provider.lookups.Load() != lookupsBefore ||
				fixture.provider.signs.Load() != signsBefore ||
				fixture.authorizer.calls.Load() != authorizationsBefore ||
				fixture.routeCalls.Load() != routeCallsBefore {
				t.Fatal("existing envelope drift crossed an external callback")
			}
		})
	}
}

// planPublicOriginatorGroupTicket creates one exact ordered originator group ticket.
func planPublicOriginatorGroupTicket(
	t *testing.T,
	fixture publicSigningFixture,
	raw []byte,
	scope string,
) RouteCopyTicket {
	t.Helper()
	source, err := NewSigningSource(raw)
	if err != nil {
		t.Fatalf("NewSigningSource() error = %v", err)
	}
	entry, err := NewOriginatorRouteEntry(
		source, []byte("<alice@example.test>"),
		[][]byte{[]byte("<bob@example.net>"), []byte("<bill@example.net>")},
		RouteDisclosureAuthorizedGroup, []byte(scope),
	)
	if err != nil {
		t.Fatalf("NewOriginatorRouteEntry() error = %v", err)
	}
	request, err := NewRouteFanoutRequest([]RouteEntry{entry})
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest() error = %v", err)
	}
	_, tickets, err := fixture.facade.PlanRouteFanout(context.Background(), request)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout() tickets=%d error=%v", len(tickets), err)
	}
	return tickets[0]
}

// planPublicExistingGroupTicket creates one exact ordered existing-message group ticket.
func planPublicExistingGroupTicket(
	t *testing.T,
	fixture publicSigningFixture,
	capability VerifiedRevisionInput,
	raw []byte,
	scope string,
) RouteCopyTicket {
	t.Helper()
	source, err := NewSigningSource(raw)
	if err != nil {
		t.Fatalf("NewSigningSource(existing) error = %v", err)
	}
	entry, err := NewExistingRouteEntry(
		capability, source, []byte("<relay@example.net>"),
		[][]byte{[]byte("<carol@next.test>"), []byte("<carl@next.test>")},
		RouteDisclosureAuthorizedGroup, []byte(scope),
	)
	if err != nil {
		t.Fatalf("NewExistingRouteEntry() error = %v", err)
	}
	fanout, err := NewRouteFanoutRequest([]RouteEntry{entry})
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest(existing) error = %v", err)
	}
	_, tickets, err := fixture.facade.PlanRouteFanout(context.Background(), fanout)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout(existing) tickets=%d error=%v", len(tickets), err)
	}
	return tickets[0]
}

// TestPublicRecoveryCopiesAreConcurrencySafeAndOneShot proves failure after
// burn returns no partial result and exactly one replacement across copies.
func TestPublicRecoveryCopiesAreConcurrencySafeAndOneShot(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	failing := &temporaryPrivateSigner{}
	facade, err := NewSigner(
		fixture.provider, publicRouteMemoryAuthority{value: routeplan.NewMemoryAuthority()},
		fixture.authorizer, failing,
	)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	fixture.facade = facade
	raw := []byte("From: alice@example.test\r\n\r\nbody\r\n")
	result, recovery, err := facade.SignOriginator(
		context.Background(), NewOriginatorSigningRequest(
			raw, []byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")},
			fixture.originTicket(t, raw, RouteDisclosureSingle), fixture.profile,
			SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
		),
	)
	if err == nil || result.Valid() || !recovery.Valid() || !recovery.ReplacementReady() {
		t.Fatalf("failed signing valid=%v recovery=%v ready=%v error=%v",
			result.Valid(), recovery.Valid(), recovery.ReplacementReady(), err)
	}
	copyRecovery := recovery
	type recoveryOutcome struct {
		ticket RouteCopyTicket
		err    error
	}
	start := make(chan struct{})
	outcomes := make(chan recoveryOutcome, 2)
	var group sync.WaitGroup
	for _, candidate := range []SigningRecovery{recovery, copyRecovery} {
		group.Add(1)
		go func(value SigningRecovery) {
			defer group.Done()
			<-start
			ticket, recoverErr := value.Recover(context.Background())
			outcomes <- recoveryOutcome{ticket: ticket, err: recoverErr}
		}(candidate)
	}
	close(start)
	group.Wait()
	close(outcomes)
	successes := 0
	for outcome := range outcomes {
		if outcome.err == nil && outcome.ticket.Valid() {
			successes++
		}
	}
	if successes != 1 || recovery.Valid() || copyRecovery.Valid() {
		t.Fatalf("recovery successes=%d original=%v copy=%v", successes, recovery.Valid(), copyRecovery.Valid())
	}
}

// TestPublicCallbackBridgesRejectInvalidAndTypedNilState proves callback
// contract corruption cannot cross or panic at the public boundary.
func TestPublicCallbackBridgesRejectInvalidAndTypedNilState(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	provider := &publicSigningProvider{rsaKey: rsaKey, edKey: edKey}
	bridge := privateKeySignerBridge{signer: provider}
	if _, err := bridge.SignDigest(
		context.Background(), internalsigning.PrivateKeyHandle{}, internalsigning.PrivateKeySignRequest{},
	); err == nil || provider.signs.Load() != 0 {
		t.Fatalf("invalid internal callback error=%v calls=%d", err, provider.signs.Load())
	}
	var routeCalls atomic.Int64
	routeBridge := routeAuthorityBridge{authority: publicRouteMemoryAuthority{
		value: routeplan.NewMemoryAuthority(), calls: &routeCalls,
	}}
	if _, err := routeBridge.Finalize(context.Background(), routeplan.FinalizeQuery{}); err == nil ||
		routeCalls.Load() != 0 {
		t.Fatalf("invalid finalize query error=%v calls=%d", err, routeCalls.Load())
	}
	if _, err := routeBridge.Reserve(context.Background(), routeplan.TicketQuery{}); err == nil ||
		routeCalls.Load() != 0 {
		t.Fatalf("invalid ticket query error=%v calls=%d", err, routeCalls.Load())
	}

	fixture := newPublicSigningFixture(t)
	facade, err := NewSigner(
		fixture.provider, publicRouteMemoryAuthority{value: routeplan.NewMemoryAuthority()},
		fixture.authorizer, typedNilErrorPrivateSigner{},
	)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	fixture.facade = facade
	raw := []byte("From: alice@example.test\r\n\r\nbody\r\n")
	result, recovery, err := facade.SignOriginator(
		context.Background(), NewOriginatorSigningRequest(
			raw, []byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")},
			fixture.originTicket(t, raw, RouteDisclosureSingle), fixture.profile,
			SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
		),
	)
	if err == nil || result.Valid() || !recovery.Valid() {
		t.Fatalf("typed-nil result=%v recovery=%v error=%v", result.Valid(), recovery.Valid(), err)
	}
}

// TestPublicSigningTypesExcludePrivateAndOpenMaterial locks the public facade shape.
func TestPublicSigningTypesExcludePrivateAndOpenMaterial(t *testing.T) {
	privateKeyType := reflect.TypeOf(rsa.PrivateKey{})
	cryptoSignerType := reflect.TypeOf((*crypto.Signer)(nil)).Elem()
	for _, value := range []any{
		PrivateKeyHandle{}, RSASigningCredential{}, Ed25519SigningCredential{},
		SigningProfile{}, PrivateKeySignRequest{}, PrivateKeySignResult{},
		OriginatorSigningRequest{}, ExistingSigningRequest{}, SigningResult{},
	} {
		typ := reflect.TypeOf(value)
		for index := 0; index < typ.NumField(); index++ {
			field := typ.Field(index).Type
			if field == privateKeyType || field == reflect.PointerTo(privateKeyType) ||
				field.Kind() == reflect.Interface || field.Implements(cryptoSignerType) {
				t.Fatalf("%v field %s exposes private or open material", typ, typ.Field(index).Name)
			}
		}
	}
	digest := sha256.Sum256([]byte("test"))
	if got := (PrivateKeySignRequest{digest: digest, algorithm: AlgorithmRSASHA256, valid: true}).Digest(); got != digest {
		t.Fatal("digest accessor changed immutable request")
	}
}

// TestPublicBccFanoutKeepsCopiesIsolated proves two separately signed privacy
// copies retain parent multiplicity without recipient cross-disclosure.
func TestPublicBccFanoutKeepsCopiesIsolated(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	raw := []byte("From: alice@example.test\r\nSubject: bcc fanout\r\n\r\nbody\r\n")
	source, err := NewSigningSource(raw)
	if err != nil {
		t.Fatalf("NewSigningSource() error = %v", err)
	}
	recipients := [][]byte{[]byte("<bob@example.net>"), []byte("<bill@example.net>")}
	entries := make([]RouteEntry, len(recipients))
	for index, recipient := range recipients {
		entries[index], err = NewOriginatorRouteEntry(
			source, []byte("<alice@example.test>"), [][]byte{recipient},
			RouteDisclosureBccSeparated, []byte(fmt.Sprintf("bcc-%d", index)),
		)
		if err != nil {
			t.Fatalf("NewOriginatorRouteEntry(%d) error = %v", index, err)
		}
	}
	fanout, err := NewRouteFanoutRequest(entries)
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest() error = %v", err)
	}
	plan, tickets, err := fixture.facade.PlanRouteFanout(context.Background(), fanout)
	if err != nil || plan.CopyCount() != 2 || len(tickets) != 2 {
		t.Fatalf("PlanRouteFanout() copies=%d tickets=%d error=%v", plan.CopyCount(), len(tickets), err)
	}
	for index, ticket := range tickets {
		result, recovery, signErr := fixture.facade.SignOriginator(
			context.Background(), NewOriginatorSigningRequest(
				raw, []byte("<alice@example.test>"), [][]byte{recipients[index]},
				ticket, fixture.profile, SigningMetadata{},
				SigningTransportFinalNetworkPreDotStuffing,
			),
		)
		if signErr != nil || recovery.Valid() {
			t.Fatalf("SignOriginator(%d) recovery=%v error=%v", index, recovery.Valid(), signErr)
		}
		signed, ok := result.Unrestricted()
		if !ok || signed.Facts().Multiplicity() != 2 ||
			!slices.Contains(signed.Facts().Flags(), SignedMessageFlagExploded) {
			t.Fatalf("copy %d facts=%#v", index, signed.Facts())
		}
		current := []byte(base64.StdEncoding.EncodeToString(recipients[index]))
		other := []byte(base64.StdEncoding.EncodeToString(recipients[1-index]))
		if !bytes.Contains(signed.Bytes(), current) || bytes.Contains(signed.Bytes(), other) {
			t.Fatalf("copy %d recipient isolation failed", index)
		}
	}
}

// TestPublicSigningFormattingRedactsSeededProtectedValues proves opaque facade
// values never reveal raw, route, nonce, handle, or envelope markers.
func TestPublicSigningFormattingRedactsSeededProtectedValues(t *testing.T) {
	marker := "SECRET-PUBLIC-SIGNING-MARKER"
	handle, err := NewPrivateKeyHandle([]byte(marker + "-handle"))
	if err != nil {
		t.Fatalf("NewPrivateKeyHandle() error = %v", err)
	}
	metadata, err := NewSigningMetadata([]byte(marker+"-nonce"), true, nil)
	if err != nil {
		t.Fatalf("NewSigningMetadata() error = %v", err)
	}
	raw := []byte("From: " + marker + "@example.test\r\n\r\nbody\r\n")
	source, err := NewSigningSource(raw)
	if err != nil {
		t.Fatalf("NewSigningSource() error = %v", err)
	}
	entry, err := NewOriginatorRouteEntry(
		source, []byte("<"+marker+"@example.test>"),
		[][]byte{[]byte("<recipient@example.net>")}, RouteDisclosureSingle,
		[]byte(marker+"-route"),
	)
	if err != nil {
		t.Fatalf("NewOriginatorRouteEntry() error = %v", err)
	}
	request, err := NewRouteFanoutRequest([]RouteEntry{entry})
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest() error = %v", err)
	}
	values := []any{
		handle, metadata, source, entry, request,
		NewOriginatorSigningRequest(
			raw, []byte("<"+marker+"@example.test>"),
			[][]byte{[]byte("<recipient@example.net>")},
			RouteCopyTicket{}, SigningProfile{}, metadata,
			SigningTransportFinalNetworkPreDotStuffing,
		),
		SigningAuthorizationQuery{}, SigningAuthorizationResult{},
		RouteFinalizeQuery{}, RouteTicketQuery{}, RouteAuthorityResult{},
		PrivateKeySignRequest{}, NewPrivateKeySignResult([]byte(marker)),
		VerifiedRevisionInput{}, SigningResult{}, SigningRecovery{},
		newSigningError(SigningErrorInvalidRequest),
	}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if output := fmt.Sprintf(format, value); strings.Contains(output, marker) {
				t.Fatalf("%T format %s leaked marker: %q", value, format, output)
			}
		}
	}
}
