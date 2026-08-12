package signing

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/provider"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/routeplan"
	"github.com/croessner/dkim2/internal/verify"
)

const (
	signerTestKeySource               = "test"
	eventInheritedEd25519             = "inherited:ed25519-sha256"
	eventPublishRSA                   = "publish:rsa-sha256"
	eventPublishEd25519               = "publish:ed25519-sha256"
	eventAuthorizePolicy              = "authorize:policy"
	eventAuthorizeFeedbackRelay       = "authorize:feedback_relay"
	eventAuthorizeRecipientDisclosure = "authorize:recipient_disclosure"
	eventSignRSA                      = "sign:rsa-sha256"
	eventSignEd25519                  = "sign:ed25519-sha256"
	eventRouteReserve                 = "route:reserve"
	eventRouteBurn                    = "route:burn"
	eventRouteReplace                 = "route:replace"
	signerTestPolicyLabel             = "policy"
	signerTestFeedbackFlag            = "feedback"
	signerTestFutureDomain            = "future.example.test"
)

type privateSignerFunc func(context.Context, PrivateKeyHandle, PrivateKeySignRequest) (PrivateKeySignResult, error)

// SignDigest delegates one private-signing test callback.
func (f privateSignerFunc) SignDigest(ctx context.Context, handle PrivateKeyHandle, request PrivateKeySignRequest) (PrivateKeySignResult, error) {
	return f(ctx, handle, request)
}

type nilPrivateSigner struct{}

// SignDigest exists only to construct a typed-nil signer dependency.
func (*nilPrivateSigner) SignDigest(context.Context, PrivateKeyHandle, PrivateKeySignRequest) (PrivateKeySignResult, error) {
	return PrivateKeySignResult{}, nil
}

type typedSignerError struct{}

// Error exists only to construct a typed-nil callback error.
func (*typedSignerError) Error() string { return "SECRET typed signer error" }

type signingEventLog struct {
	mu     sync.Mutex
	events []string
}

// add appends one callback event safely.
func (l *signingEventLog) add(event string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

// reset discards setup events before the operation under test.
func (l *signingEventLog) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = nil
}

// snapshot returns a detached event sequence.
func (l *signingEventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

type recordingRouteAuthority struct {
	delegate routeplan.RouteFanoutAuthority
	events   *signingEventLog
	replace  func(context.Context, routeplan.TicketQuery) (routeplan.AuthorityResult, error)
	reserved func()
	burned   func()
}

type recordingRevisionProvider struct {
	delegate verify.KeyProvider
	events   *signingEventLog
	failure  error
	after    func()
}

// LookupKey records and delegates one inherited revision key lookup.
func (p *recordingRevisionProvider) LookupKey(ctx context.Context, query verify.KeyQuery) (verify.PublicKey, error) {
	p.events.add("inherited:" + string(query.Algorithm))
	if p.failure != nil {
		return verify.PublicKey{}, p.failure
	}
	result, err := p.delegate.LookupKey(ctx, query)
	if p.after != nil {
		p.after()
	}
	return result, err
}

// Finalize records and delegates route-plan issuance.
func (a *recordingRouteAuthority) Finalize(ctx context.Context, query routeplan.FinalizeQuery) (routeplan.AuthorityResult, error) {
	a.events.add("route:finalize")
	return a.delegate.Finalize(ctx, query)
}

// Reserve records and delegates ticket reservation.
func (a *recordingRouteAuthority) Reserve(ctx context.Context, query routeplan.TicketQuery) (routeplan.AuthorityResult, error) {
	a.events.add(eventRouteReserve)
	result, err := a.delegate.Reserve(ctx, query)
	if a.reserved != nil {
		a.reserved()
	}
	return result, err
}

// ReleaseReservation records and delegates pre-boundary release.
func (a *recordingRouteAuthority) ReleaseReservation(ctx context.Context, query routeplan.TicketQuery) (routeplan.AuthorityResult, error) {
	a.events.add("route:release")
	return a.delegate.ReleaseReservation(ctx, query)
}

// Burn records and delegates the external-boundary transition.
func (a *recordingRouteAuthority) Burn(ctx context.Context, query routeplan.TicketQuery) (routeplan.AuthorityResult, error) {
	a.events.add(eventRouteBurn)
	result, err := a.delegate.Burn(ctx, query)
	if a.burned != nil {
		a.burned()
	}
	return result, err
}

// Replace records and delegates same-lineage replacement issuance.
func (a *recordingRouteAuthority) Replace(ctx context.Context, query routeplan.TicketQuery) (routeplan.AuthorityResult, error) {
	a.events.add(eventRouteReplace)
	if a.replace != nil {
		return a.replace(ctx, query)
	}
	return a.delegate.Replace(ctx, query)
}

// ConsumeRelease records and delegates restricted release consumption.
func (a *recordingRouteAuthority) ConsumeRelease(ctx context.Context, query routeplan.TicketQuery) (routeplan.AuthorityResult, error) {
	a.events.add("route:consume")
	return a.delegate.ConsumeRelease(ctx, query)
}

type signerHarness struct {
	revision    RevisionVerifier
	routes      routeplan.Coordinator
	publication *PublicationAuthority
	request     SignFieldRequest
	privateKeys map[PrivateKeyHandle]any
	events      *signingEventLog
	inherited   *recordingRevisionProvider
	authority   *recordingRouteAuthority
}

// newCoordinator constructs the signing coordinator under test.
func (h signerHarness) newCoordinator(t *testing.T, signer PrivateKeySigner, limits Limits) Coordinator {
	t.Helper()
	authorizer := authorizerFunc(func(context.Context, AuthorizationQuery) (AuthorizationResult, error) {
		t.Fatal("originator signing unexpectedly called the authorizer")
		return AuthorizationResult{}, nil
	})
	return h.newCoordinatorWithAuthorizer(t, authorizer, signer, limits)
}

// newCoordinatorWithAuthorizer constructs a coordinator with one controlled authorization service.
func (h signerHarness) newCoordinatorWithAuthorizer(t *testing.T, authorizer Authorizer, signer PrivateKeySigner, limits Limits) Coordinator {
	t.Helper()
	coordinator, err := NewCoordinator(h.revision, h.routes, h.publication, authorizer, signer, limits)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}
	return coordinator
}

// defaultSigner signs the native digest with the harness-owned test key.
func (h signerHarness) defaultSigner(t *testing.T) PrivateKeySigner {
	t.Helper()
	return privateSignerFunc(func(_ context.Context, handle PrivateKeyHandle, request PrivateKeySignRequest) (PrivateKeySignResult, error) {
		h.events.add("sign:" + string(request.Algorithm()))
		key, ok := h.privateKeys[handle]
		if !ok {
			t.Fatal("private signer received an unknown opaque handle")
		}
		digest := request.Digest()
		var signatureBytes []byte
		var err error
		switch request.Algorithm() {
		case AlgorithmRSASHA256:
			signatureBytes, err = rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, digest[:])
		case AlgorithmEd25519SHA256:
			signatureBytes = ed25519.Sign(key.(ed25519.PrivateKey), digest[:])
		default:
			t.Fatalf("private signer received unknown algorithm %q", request.Algorithm())
		}
		return NewPrivateKeySignResult(signatureBytes), err
	})
}

// newSignerHarness builds one exact origin plan, route authority, and publication view.
func newSignerHarness(t *testing.T, algorithms ...Algorithm) signerHarness {
	t.Helper()
	if len(algorithms) == 0 {
		algorithms = []Algorithm{AlgorithmEd25519SHA256}
	}
	fixture := newRevisionTestFixture(t, nil, false)
	revision := newRevisionTestVerifier(t, fixture, bytes.NewReader(bytes.Repeat([]byte{0x9a}, sha256.Size)))
	planner, err := NewHashPlanCoordinator(revision, recipe.GenerationLimits{}, Limits{})
	if err != nil {
		t.Fatalf("NewHashPlanCoordinator() error = %v", err)
	}
	message, err := rawmsg.Parse([]byte("Subject: signer harness\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}
	events := &signingEventLog{}
	authority := &recordingRouteAuthority{delegate: routeplan.NewMemoryAuthority(), events: events}
	routes, err := routeplan.NewCoordinator(authority, routeplan.Limits{})
	if err != nil {
		t.Fatalf("routeplan.NewCoordinator() error = %v", err)
	}
	source, err := routeplan.NewImmutableSource(message.RawBytes())
	if err != nil {
		t.Fatalf("routeplan.NewImmutableSource() error = %v", err)
	}
	entry, err := routeplan.NewEntry(source, routeplan.PurposeOrigin, []byte("<sender@signer.example.test>"),
		[][]byte{[]byte("<recipient@example.test>")}, routeplan.DisclosureSingle, []byte("signer-route"), nil)
	if err != nil {
		t.Fatalf("routeplan.NewEntry() error = %v", err)
	}
	routeRequest, err := routeplan.NewPlanRequest([]routeplan.Entry{entry})
	if err != nil {
		t.Fatalf("routeplan.NewPlanRequest() error = %v", err)
	}
	_, tickets, err := routes.Finalize(context.Background(), routeRequest)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("routeplan.Finalize() tickets=%d error=%v", len(tickets), err)
	}
	plan, err := planner.PlanOriginator(context.Background(), OriginatorPlanRequest{Message: message, Ticket: tickets[0]})
	if err != nil {
		t.Fatalf("PlanOriginator() error = %v", err)
	}

	profile, privateKeys, published := newTestSigningProfile(t, "signer.example.test", algorithms)
	publicationProvider := publicationProviderFunc(func(_ context.Context, query verify.KeyQuery) (verify.PublicKey, error) {
		events.add("publish:" + string(query.Algorithm))
		material, ok := published[string(query.Algorithm)+"\x00"+query.Selector]
		if !ok || query.Domain != profile.Domain() {
			return verify.PublicKey{}, errors.New("unexpected publication query")
		}
		return verify.PublicKey{
			Algorithm: query.Algorithm, Material: material,
			Metadata: verify.KeyMetadata{Status: verify.KeyStatusFound, Source: signerTestKeySource},
		}, nil
	})
	var publicationSeal [sha256.Size]byte
	publicationSeal[0] = 1
	publication, err := newPublicationAuthority(
		publicationProvider, func() time.Time { return time.Unix(1_700_000_000, 0) },
		time.Minute, publicationSeal, maxConsumedPublicationCapabilities,
	)
	if err != nil {
		t.Fatalf("newPublicationAuthority() error = %v", err)
	}
	metadata, err := NewSigningMetadata(nil, false, nil)
	if err != nil {
		t.Fatalf("NewSigningMetadata() error = %v", err)
	}
	events.reset()
	return signerHarness{
		revision: revision, routes: routes, publication: publication, privateKeys: privateKeys, events: events,
		authority: authority,
		request: SignFieldRequest{
			Plan: plan, Message: message, Ticket: tickets[0],
			ReversePath: tickets[0].ReversePath(), ForwardPaths: tickets[0].DisclosureRecipients(),
			Profile: profile, Metadata: metadata,
			Transport: rawmsg.TransportFormFinalNetworkPreDotStuffing,
		},
	}
}

// newExistingSignerHarness builds one feedback-bearing multi-recipient revision operation.
func newExistingSignerHarness(t *testing.T, algorithms ...Algorithm) signerHarness {
	t.Helper()
	return newExistingSignerHarnessWithRecipients(t, [][]byte{
		[]byte("<next-a@example.test>"), []byte("<next-b@example.test>"),
	}, algorithms...)
}

// newExistingSignerHarnessWithRecipients builds one feedback-bearing revision operation with exact output recipients.
func newExistingSignerHarnessWithRecipients(t *testing.T, recipients [][]byte, algorithms ...Algorithm) signerHarness {
	t.Helper()
	fixture := newRevisionTestFixtureWithFlags(t, nil, false, []string{signerTestFeedbackFlag})
	return newExistingSignerHarnessForFixture(t, fixture, recipients, algorithms...)
}

// newExistingSignerHarnessForFixture builds one existing-message operation from exact signed test bytes.
func newExistingSignerHarnessForFixture(t *testing.T, fixture revisionTestFixture, recipients [][]byte, algorithms ...Algorithm) signerHarness {
	t.Helper()
	if len(algorithms) == 0 {
		algorithms = []Algorithm{AlgorithmEd25519SHA256}
	}
	events := &signingEventLog{}
	revisionProvider := &recordingRevisionProvider{delegate: mustRevisionStaticProvider(t, fixture), events: events}
	proofVerifier, err := verify.NewVerifier(revisionProvider, revisionTestClockOption())
	if err != nil {
		t.Fatalf("verify.NewVerifier() error = %v", err)
	}
	revision, err := newRevisionVerifier(
		proofVerifier, Limits{}, bytes.NewReader(bytes.Repeat([]byte{0x9b}, sha256.Size)),
	)
	if err != nil {
		t.Fatalf("newRevisionVerifier() error = %v", err)
	}
	outcome, capability, err := revision.VerifyForRevision(context.Background(), RevisionRequest{
		Message: fixture.message, Envelope: fixture.envelope,
	})
	if err != nil || outcome.Status() != RevisionVerificationVerified || !capability.Valid() {
		t.Fatalf("VerifyForRevision() outcome=%q capability=%t error=%v", outcome.Status(), capability.Valid(), err)
	}
	planner, err := NewHashPlanCoordinator(revision, recipe.GenerationLimits{}, Limits{})
	if err != nil {
		t.Fatalf("NewHashPlanCoordinator() error = %v", err)
	}
	authority := &recordingRouteAuthority{delegate: routeplan.NewMemoryAuthority(), events: events}
	routes, err := routeplan.NewCoordinator(authority, routeplan.Limits{})
	if err != nil {
		t.Fatalf("routeplan.NewCoordinator() error = %v", err)
	}
	source, err := routeplan.NewImmutableSource(fixture.message.RawBytes())
	if err != nil {
		t.Fatalf("routeplan.NewImmutableSource() error = %v", err)
	}
	disclosure := routeplan.DisclosureSingle
	if len(recipients) > 1 {
		disclosure = routeplan.DisclosureAuthorizedGroup
	}
	entry, err := NewBoundRouteEntry(
		capability, source, routeplan.PurposeRevision, []byte("<rcpt@example.test>"),
		recipients, disclosure, []byte("existing-signer-route"),
	)
	if err != nil {
		t.Fatalf("NewBoundRouteEntry() error = %v", err)
	}
	routeRequest, err := routeplan.NewPlanRequest([]routeplan.Entry{entry})
	if err != nil {
		t.Fatalf("routeplan.NewPlanRequest() error = %v", err)
	}
	_, tickets, err := routes.Finalize(context.Background(), routeRequest)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("routeplan.Finalize() tickets=%d error=%v", len(tickets), err)
	}
	plan, err := planner.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: capability, Message: fixture.message, Ticket: tickets[0],
	})
	if err != nil || !plan.Valid() {
		t.Fatalf("PlanExisting() valid=%t error=%v", plan.Valid(), err)
	}
	profile, privateKeys, published := newTestSigningProfile(t, "example.test", algorithms)
	publicationProvider := publicationProviderFunc(func(_ context.Context, query verify.KeyQuery) (verify.PublicKey, error) {
		events.add("publish:" + string(query.Algorithm))
		material, ok := published[string(query.Algorithm)+"\x00"+query.Selector]
		if !ok || query.Domain != profile.Domain() {
			return verify.PublicKey{}, errors.New("unexpected publication query")
		}
		return verify.PublicKey{
			Algorithm: query.Algorithm, Material: material,
			Metadata: verify.KeyMetadata{Status: verify.KeyStatusFound, Source: signerTestKeySource},
		}, nil
	})
	var publicationSeal [sha256.Size]byte
	publicationSeal[0] = 2
	publication, err := newPublicationAuthority(
		publicationProvider, func() time.Time { return time.Unix(1_700_000_000, 0) },
		time.Minute, publicationSeal, maxConsumedPublicationCapabilities,
	)
	if err != nil {
		t.Fatalf("newPublicationAuthority() error = %v", err)
	}
	metadata, err := NewSigningMetadata(nil, false, nil)
	if err != nil {
		t.Fatalf("NewSigningMetadata() error = %v", err)
	}
	events.reset()
	return signerHarness{
		revision: revision, routes: routes, publication: publication, privateKeys: privateKeys, events: events,
		inherited: revisionProvider, authority: authority,
		request: SignFieldRequest{
			Plan: plan, Capability: capability, Message: fixture.message,
			Ticket: tickets[0], ReversePath: tickets[0].ReversePath(),
			ForwardPaths: tickets[0].DisclosureRecipients(), Profile: profile, Metadata: metadata,
			Transport: rawmsg.TransportFormFinalNetworkPreDotStuffing,
		},
	}
}

// rebindOriginHarnessMultiplicity issues an origin ticket from a parent with the requested copy count.
func rebindOriginHarnessMultiplicity(t *testing.T, harness signerHarness, copies int) signerHarness {
	t.Helper()
	source, err := routeplan.NewImmutableSource(harness.request.Message.RawBytes())
	if err != nil {
		t.Fatalf("routeplan.NewImmutableSource() error = %v", err)
	}
	entries := make([]routeplan.Entry, copies)
	for index := range entries {
		entries[index], err = routeplan.NewEntry(
			source, routeplan.PurposeOrigin, []byte("<sender@signer.example.test>"),
			[][]byte{fmt.Appendf(nil, "<recipient-%d@example.test>", index)},
			routeplan.DisclosureSingle, fmt.Appendf(nil, "multiplicity-route-%d", index), nil,
		)
		if err != nil {
			t.Fatalf("routeplan.NewEntry(%d) error = %v", index, err)
		}
	}
	request, err := routeplan.NewPlanRequest(entries)
	if err != nil {
		t.Fatalf("routeplan.NewPlanRequest() error = %v", err)
	}
	_, tickets, err := harness.routes.Finalize(context.Background(), request)
	if err != nil || len(tickets) != copies {
		t.Fatalf("routeplan.Finalize() tickets=%d error=%v", len(tickets), err)
	}
	planner, err := NewHashPlanCoordinator(harness.revision, recipe.GenerationLimits{}, Limits{})
	if err != nil {
		t.Fatalf("NewHashPlanCoordinator() error = %v", err)
	}
	plan, err := planner.PlanOriginator(context.Background(), OriginatorPlanRequest{
		Message: harness.request.Message, Ticket: tickets[0],
	})
	if err != nil {
		t.Fatalf("PlanOriginator() error = %v", err)
	}
	harness.request.Ticket = tickets[0]
	harness.request.ReversePath = tickets[0].ReversePath()
	harness.request.ForwardPaths = tickets[0].DisclosureRecipients()
	harness.request.Plan = plan
	harness.events.reset()
	return harness
}

// newTestSigningProfile constructs deterministic RSA/Ed25519 credentials and provider material.
func newTestSigningProfile(t *testing.T, domain string, algorithms []Algorithm) (Profile, map[PrivateKeyHandle]any, map[string]any) {
	t.Helper()
	credentials := make([]Credential, 0, len(algorithms))
	privateKeys := make(map[PrivateKeyHandle]any, len(algorithms))
	published := make(map[string]any, len(algorithms))
	for _, algorithm := range algorithms {
		selector := "ed-selector"
		handleText := "ed-handle"
		var publicKey any
		var privateKey any
		switch algorithm {
		case AlgorithmRSASHA256:
			selector, handleText = "rsa-selector", "rsa-handle"
			key, keyErr := rsa.GenerateKey(rand.Reader, DefaultLimits().MinRSABits)
			if keyErr != nil {
				t.Fatalf("rsa.GenerateKey() error = %v", keyErr)
			}
			publicKey, privateKey = &key.PublicKey, key
		case AlgorithmEd25519SHA256:
			seed := sha256.Sum256([]byte("signer-harness-ed25519"))
			key := ed25519.NewKeyFromSeed(seed[:])
			publicKey, privateKey = key.Public().(ed25519.PublicKey), key
		default:
			t.Fatalf("unsupported harness algorithm %q", algorithm)
		}
		handle, handleErr := NewPrivateKeyHandle([]byte(handleText))
		if handleErr != nil {
			t.Fatalf("NewPrivateKeyHandle() error = %v", handleErr)
		}
		credential, credentialErr := NewCredential(selector, algorithm, publicKey, handle, Limits{})
		if credentialErr != nil {
			t.Fatalf("NewCredential() error = %v", credentialErr)
		}
		credentials = append(credentials, credential)
		privateKeys[handle] = privateKey
		published[string(algorithm)+"\x00"+selector] = publicKey
	}
	profile, err := NewProfile(domain, credentials)
	if err != nil {
		t.Fatalf("NewProfile() error = %v", err)
	}
	return profile, privateKeys, published
}

// TestPrivateKeySignRequestAndResultAreClosedImmutableAndRedacted proves the opaque callback DTO contract.
func TestPrivateKeySignRequestAndResultAreClosedImmutableAndRedacted(t *testing.T) {
	var zeroDigest [sha256.Size]byte
	request, err := NewPrivateKeySignRequest(AlgorithmEd25519SHA256, zeroDigest)
	if err != nil || !request.Valid() || request.Algorithm() != AlgorithmEd25519SHA256 || request.Digest() != zeroDigest {
		t.Fatalf("zero-digest request valid=%t algorithm=%q error=%v", request.Valid(), request.Algorithm(), err)
	}
	if invalid, requestErr := NewPrivateKeySignRequest(Algorithm("future"), zeroDigest); !IsErrorCode(requestErr, ErrorCodeInvalidRequest) || invalid.Valid() {
		t.Fatalf("unknown-algorithm request valid=%t error=%v", invalid.Valid(), requestErr)
	}

	source := []byte("SECRET detached signature")
	result := NewPrivateKeySignResult(source)
	source[0] = 'X'
	if result.status != PrivateKeySigned || string(result.signature) != "SECRET detached signature" {
		t.Fatal("private result retained caller signature alias")
	}
	for _, value := range []any{request, result, SignFieldRequest{}, CompletedSigningField{}, Recovery{}} {
		formatted := fmt.Sprintf("%v %+v %#v", value, value, value)
		if strings.Contains(formatted, "SECRET") || !strings.Contains(formatted, "redacted") {
			t.Fatalf("unsafe private signing formatting for %T: %q", value, formatted)
		}
	}
}

// TestPrivateSignerResultMatrixRejectsAmbiguityBeforeCancellation locks result/error reconciliation.
func TestPrivateSignerResultMatrixRejectsAmbiguityBeforeCancellation(t *testing.T) {
	credential, _ := testEd25519Credential(t, "signer-matrix")
	coordinator := Coordinator{limits: DefaultLimits()}
	validBytes := make([]byte, ed25519.SignatureSize)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var typedNil *typedSignerError

	tests := []struct {
		name    string
		ctx     context.Context
		result  PrivateKeySignResult
		err     error
		code    ErrorCode
		context bool
	}{
		{name: "zero plus nil", ctx: context.Background(), result: PrivateKeySignResult{}, code: ErrorCodeInternalInvariant},
		{name: "status plus error", ctx: context.Background(), result: NewPrivateKeySignResult(validBytes), err: provider.NewFailure(provider.FailureTemporary), code: ErrorCodeInternalInvariant},
		{name: "illegal status", ctx: context.Background(), result: PrivateKeySignResult{status: PrivateKeySignStatus("future"), signature: validBytes}, code: ErrorCodeInternalInvariant},
		{name: "typed nil error", ctx: context.Background(), err: typedNil, code: ErrorCodeInternalInvariant},
		{name: "raw error", ctx: context.Background(), err: errors.New("SECRET raw signer error"), code: ErrorCodeInternalInvariant},
		{name: "typed temporary", ctx: context.Background(), err: provider.NewFailure(provider.FailureTemporary), code: ErrorCodeCallbackTemporary},
		{name: "typed permanent", ctx: context.Background(), err: provider.NewFailure(provider.FailurePermanent), code: ErrorCodeCallbackPermanent},
		{name: "canceled result contract wins", ctx: ctx, result: PrivateKeySignResult{}, code: ErrorCodeInternalInvariant},
		{name: "matching context error", ctx: ctx, err: context.Canceled, context: true},
		{name: "cancellation after valid result", ctx: ctx, result: NewPrivateKeySignResult(validBytes), context: true},
		{name: "cancellation overrides typed failure", ctx: ctx, err: provider.NewFailure(provider.FailureTemporary), context: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotErr := coordinator.validateSignerResult(test.ctx, credential, test.result, test.err)
			if len(got) != 0 {
				t.Fatalf("failure returned %d partial signature bytes", len(got))
			}
			if test.context {
				if !errors.Is(gotErr, context.Canceled) {
					t.Fatalf("error = %v, want context cancellation", gotErr)
				}
				return
			}
			if !IsErrorCode(gotErr, test.code) {
				t.Fatalf("error = %v, want code %q", gotErr, test.code)
			}
			if strings.Contains(fmt.Sprint(gotErr), "SECRET") {
				t.Fatalf("error exposed callback content: %v", gotErr)
			}
		})
	}
}

// TestPrivateSignerResultLengthBoundsAndAliasing proves exact algorithm lengths and detached output.
func TestPrivateSignerResultLengthBoundsAndAliasing(t *testing.T) {
	edCredential, _ := testEd25519Credential(t, "signer-length-ed")
	rsaKey, err := rsa.GenerateKey(rand.Reader, DefaultLimits().MinRSABits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	handle, err := NewPrivateKeyHandle([]byte("signer-length-rsa"))
	if err != nil {
		t.Fatalf("NewPrivateKeyHandle() error = %v", err)
	}
	rsaCredential, err := NewCredential("rsa-selector", AlgorithmRSASHA256, &rsaKey.PublicKey, handle, Limits{})
	if err != nil {
		t.Fatalf("NewCredential() error = %v", err)
	}
	coordinator := Coordinator{limits: DefaultLimits()}

	for _, test := range []struct {
		name       string
		credential Credential
		length     int
		code       ErrorCode
	}{
		{name: "ed short", credential: edCredential, length: ed25519.SignatureSize - 1, code: ErrorCodeCryptographicSelfCheck},
		{name: "ed long", credential: edCredential, length: ed25519.SignatureSize + 1, code: ErrorCodeCryptographicSelfCheck},
		{name: "rsa short", credential: rsaCredential, length: rsaKey.Size() - 1, code: ErrorCodeCryptographicSelfCheck},
		{name: "rsa long", credential: rsaCredential, length: rsaKey.Size() + 1, code: ErrorCodeCryptographicSelfCheck},
		{name: "hard oversize", credential: edCredential, length: DefaultLimits().MaxPrivateSignatureBytes + 1, code: ErrorCodeInternalInvariant},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, validateErr := coordinator.validateSignerResult(
				context.Background(), test.credential, NewPrivateKeySignResult(make([]byte, test.length)), nil,
			)
			if len(output) != 0 || !IsErrorCode(validateErr, test.code) {
				t.Fatalf("output=%d error=%v, want %q", len(output), validateErr, test.code)
			}
		})
	}

	aliased := bytes.Repeat([]byte{0x5a}, ed25519.SignatureSize)
	result := PrivateKeySignResult{status: PrivateKeySigned, signature: aliased}
	detached, err := coordinator.validateSignerResult(context.Background(), edCredential, result, nil)
	if err != nil {
		t.Fatalf("valid detached result error = %v", err)
	}
	aliased[0] ^= 0xff
	result.signature[1] ^= 0xff
	if detached[0] != 0x5a || detached[1] != 0x5a {
		t.Fatal("validated signer output retained provider alias")
	}
}

// TestCoordinatorRejectsInvalidDependencies proves fail-closed composition.
func TestCoordinatorRejectsInvalidDependencies(t *testing.T) {
	harness := newSignerHarness(t, AlgorithmEd25519SHA256)
	validSigner := harness.defaultSigner(t)
	validAuthorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
		return NewAuthorizationResult(query, AuthorizationDenied), nil
	})
	var nilSigner *nilPrivateSigner
	var nilAuthorizer *nilTestAuthorizer

	tests := []struct {
		name        string
		revision    RevisionVerifier
		routes      routeplan.Coordinator
		publication *PublicationAuthority
		authorizer  Authorizer
		signer      PrivateKeySigner
		limits      Limits
	}{
		{name: "zero revision", routes: harness.routes, publication: harness.publication, authorizer: validAuthorizer, signer: validSigner},
		{name: "zero routes", revision: harness.revision, publication: harness.publication, authorizer: validAuthorizer, signer: validSigner},
		{name: "nil publication", revision: harness.revision, routes: harness.routes, authorizer: validAuthorizer, signer: validSigner},
		{name: "zero publication", revision: harness.revision, routes: harness.routes, publication: &PublicationAuthority{}, authorizer: validAuthorizer, signer: validSigner},
		{name: "typed nil authorizer", revision: harness.revision, routes: harness.routes, publication: harness.publication, authorizer: nilAuthorizer, signer: validSigner},
		{name: "typed nil signer", revision: harness.revision, routes: harness.routes, publication: harness.publication, authorizer: validAuthorizer, signer: nilSigner},
		{name: "widened signer limit", revision: harness.revision, routes: harness.routes, publication: harness.publication, authorizer: validAuthorizer, signer: validSigner, limits: Limits{MaxPrivateSigningCalls: 3}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator, err := NewCoordinator(
				test.revision, test.routes, test.publication, test.authorizer, test.signer, test.limits,
			)
			if coordinator.initialized || !IsErrorCode(err, ErrorCodeInvalidOptions) {
				t.Fatalf("coordinator initialized=%t error=%v", coordinator.initialized, err)
			}
		})
	}
}

// TestOriginSigningSupportsRSAEd25519AndDualInCanonicalOrder proves algorithm semantics and ordering.
func TestOriginSigningSupportsRSAEd25519AndDualInCanonicalOrder(t *testing.T) {
	for _, test := range []struct {
		name       string
		algorithms []Algorithm
		wantEvents []string
	}{
		{
			name: "rsa", algorithms: []Algorithm{AlgorithmRSASHA256},
			wantEvents: []string{eventRouteReserve, eventRouteBurn, eventPublishRSA, eventSignRSA},
		},
		{
			name: "ed25519", algorithms: []Algorithm{AlgorithmEd25519SHA256},
			wantEvents: []string{eventRouteReserve, eventRouteBurn, eventPublishEd25519, eventSignEd25519},
		},
		{
			name: "dual canonicalizes reversed input", algorithms: []Algorithm{AlgorithmEd25519SHA256, AlgorithmRSASHA256},
			wantEvents: []string{
				eventRouteReserve, eventRouteBurn, eventPublishRSA, eventPublishEd25519,
				eventSignRSA, eventSignEd25519,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newSignerHarness(t, test.algorithms...)
			var digests [][sha256.Size]byte
			delegate := harness.defaultSigner(t)
			signer := privateSignerFunc(func(ctx context.Context, handle PrivateKeyHandle, request PrivateKeySignRequest) (PrivateKeySignResult, error) {
				digests = append(digests, request.Digest())
				return delegate.SignDigest(ctx, handle, request)
			})
			coordinator := harness.newCoordinator(t, signer, Limits{})
			completed, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
			if err != nil || !completed.Valid() || recovery.Valid() || recovery.RecoveryPending() ||
				completed.reservation == nil || !completed.reservation.ReplacementRequired() {
				t.Fatalf("completed=%t recovery=%t/%t error=%v", completed.Valid(), recovery.Valid(), recovery.RecoveryPending(), err)
			}
			if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(test.wantEvents) {
				t.Fatalf("callback order = %v, want %v", got, test.wantEvents)
			}
			for index := 1; index < len(digests); index++ {
				if digests[index] != digests[0] {
					t.Fatal("dual signing did not share one canonical SHA-256 digest")
				}
			}
			field := string(completed.field.Bytes())
			if len(test.algorithms) == 2 &&
				strings.Index(field, "rsa-selector:rsa-sha256:") > strings.Index(field, "ed-selector:ed25519-sha256:") {
				t.Fatal("dual complete field did not render RSA before Ed25519")
			}
		})
	}
}

// TestExistingSigningFreezesInheritedPublicationAuthorizationAndSignerOrder proves the complete callback sequence.
func TestExistingSigningFreezesInheritedPublicationAuthorizationAndSignerOrder(t *testing.T) {
	harness := newExistingSignerHarness(t, AlgorithmEd25519SHA256, AlgorithmRSASHA256)
	authorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
		harness.events.add("authorize:" + string(query.Purpose()))
		return NewAuthorizationResult(query, AuthorizationAuthorized), nil
	})
	coordinator := harness.newCoordinatorWithAuthorizer(t, authorizer, harness.defaultSigner(t), Limits{})
	completed, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
	if err != nil || !completed.Valid() || recovery.Valid() {
		t.Fatalf("completed=%t recovery=%t error=%v", completed.Valid(), recovery.Valid(), err)
	}
	want := []string{
		eventRouteReserve, eventRouteBurn, eventInheritedEd25519,
		eventPublishRSA, eventPublishEd25519,
		eventAuthorizePolicy, eventAuthorizeFeedbackRelay, eventAuthorizeRecipientDisclosure,
		eventSignRSA, eventSignEd25519,
	}
	if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("existing callback order = %v, want %v", got, want)
	}
	if !strings.Contains(string(completed.field.Bytes()), "feedhere") {
		t.Fatal("authorized causal feedback did not select the preflighted feedhere branch")
	}
}

// TestExistingFeedbackDenialContinuesOnThePreflightedBaseBranch proves feedback is optional and causal.
func TestExistingFeedbackDenialContinuesOnThePreflightedBaseBranch(t *testing.T) {
	harness := newExistingSignerHarness(t, AlgorithmEd25519SHA256)
	authorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
		harness.events.add("authorize:" + string(query.Purpose()))
		status := AuthorizationAuthorized
		if query.Purpose() == AuthorizationFeedbackRelay {
			status = AuthorizationDenied
		}
		return NewAuthorizationResult(query, status), nil
	})
	coordinator := harness.newCoordinatorWithAuthorizer(t, authorizer, harness.defaultSigner(t), Limits{})
	completed, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
	if err != nil || !completed.Valid() || recovery.Valid() {
		t.Fatalf("completed=%t recovery=%t error=%v", completed.Valid(), recovery.Valid(), err)
	}
	if strings.Contains(string(completed.field.Bytes()), "feedhere") {
		t.Fatal("denied feedback relay emitted feedhere")
	}
	want := []string{
		eventRouteReserve, eventRouteBurn, eventInheritedEd25519, eventPublishEd25519,
		eventAuthorizePolicy, eventAuthorizeFeedbackRelay, eventAuthorizeRecipientDisclosure,
		eventSignEd25519,
	}
	if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("feedback-denial order = %v, want %v", got, want)
	}
}

// TestGeneratedRecipientLimitDoesNotRetroactivelyNarrowVerifiedInheritedEvidence proves limit ownership.
func TestGeneratedRecipientLimitDoesNotRetroactivelyNarrowVerifiedInheritedEvidence(t *testing.T) {
	t.Run("inherited multiplicity is already verified", func(t *testing.T) {
		harness := newExistingSignerHarnessWithRecipients(
			t, [][]byte{[]byte("<next@example.test>")}, AlgorithmEd25519SHA256,
		)
		authorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
			harness.events.add("authorize:" + string(query.Purpose()))
			return NewAuthorizationResult(query, AuthorizationAuthorized), nil
		})
		coordinator := harness.newCoordinatorWithAuthorizer(
			t, authorizer, harness.defaultSigner(t), Limits{MaxGeneratedRecipients: 1},
		)
		completed, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
		if err != nil || !completed.Valid() || recovery.Valid() {
			t.Fatalf("completed=%t recovery=%t error=%v", completed.Valid(), recovery.Valid(), err)
		}
		want := []string{
			eventRouteReserve, eventRouteBurn, eventInheritedEd25519, eventPublishEd25519,
			eventAuthorizePolicy, eventAuthorizeFeedbackRelay, eventSignEd25519,
		}
		if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("single-recipient callback order = %v, want %v", got, want)
		}
	})

	t.Run("generated multiplicity remains narrowed", func(t *testing.T) {
		harness := newExistingSignerHarness(t, AlgorithmEd25519SHA256)
		authorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
			harness.events.add("authorize:" + string(query.Purpose()))
			return NewAuthorizationResult(query, AuthorizationAuthorized), nil
		})
		coordinator := harness.newCoordinatorWithAuthorizer(
			t, authorizer, harness.defaultSigner(t), Limits{MaxGeneratedRecipients: 1},
		)
		completed, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
		assertSigningPreflightLimit(
			t, err, LimitNameMaxGeneratedRecipients, completed, recovery, harness.events,
		)
	})
}

// TestExistingAuthorizationDenialsReturnReplacementWithoutPartialState proves fail-closed policy gates.
func TestExistingAuthorizationDenialsReturnReplacementWithoutPartialState(t *testing.T) {
	for _, test := range []struct {
		name     string
		deny     AuthorizationPurpose
		wantCode ErrorCode
		want     []string
	}{
		{
			name: signerTestPolicyLabel, deny: AuthorizationPolicy, wantCode: ErrorCodeAuthorizationDenied,
			want: []string{
				eventRouteReserve, eventRouteBurn, eventInheritedEd25519, eventPublishEd25519,
				eventAuthorizePolicy, eventRouteReplace,
			},
		},
		{
			name: "disclosure", deny: AuthorizationDisclosure, wantCode: ErrorCodeDisclosureDenied,
			want: []string{
				eventRouteReserve, eventRouteBurn, eventInheritedEd25519, eventPublishEd25519,
				eventAuthorizePolicy, eventAuthorizeFeedbackRelay, eventAuthorizeRecipientDisclosure, eventRouteReplace,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newExistingSignerHarness(t, AlgorithmEd25519SHA256)
			authorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
				harness.events.add("authorize:" + string(query.Purpose()))
				status := AuthorizationAuthorized
				if query.Purpose() == test.deny {
					status = AuthorizationDenied
				}
				return NewAuthorizationResult(query, status), nil
			})
			coordinator := harness.newCoordinatorWithAuthorizer(t, authorizer, harness.defaultSigner(t), Limits{})
			completed, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
			if completed.Valid() || completed.field.Valid() || !recovery.Valid() || !recovery.ReplacementReady() ||
				recovery.RecoveryPending() || !IsErrorCode(err, test.wantCode) {
				t.Fatalf("completed=%t field=%t recovery=%t error=%v",
					completed.Valid(), completed.field.Valid(), recovery.Valid(), err)
			}
			if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(test.want) {
				t.Fatalf("denial order = %v, want %v", got, test.want)
			}
			if replacement, recoverErr := recovery.Recover(context.Background()); recoverErr != nil || !replacement.Valid() {
				t.Fatalf("replacement valid=%t error=%v", replacement.Valid(), recoverErr)
			}
		})
	}
}

// TestExistingAuthorizationBudgetPreflightsTheExactApplicableCallCount proves no late budget discovery.
func TestExistingAuthorizationBudgetPreflightsTheExactApplicableCallCount(t *testing.T) {
	t.Run("exact", func(t *testing.T) {
		harness := newExistingSignerHarness(t, AlgorithmEd25519SHA256)
		authorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
			harness.events.add("authorize:" + string(query.Purpose()))
			return NewAuthorizationResult(query, AuthorizationAuthorized), nil
		})
		coordinator := harness.newCoordinatorWithAuthorizer(
			t, authorizer, harness.defaultSigner(t), Limits{MaxAuthorizationCalls: 3},
		)
		completed, _, err := coordinator.CompleteField(context.Background(), harness.request)
		if err != nil || !completed.Valid() {
			t.Fatalf("exact authorization budget completed=%t error=%v", completed.Valid(), err)
		}
	})

	t.Run("one over", func(t *testing.T) {
		harness := newExistingSignerHarness(t, AlgorithmEd25519SHA256)
		authorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
			harness.events.add("authorize:" + string(query.Purpose()))
			return NewAuthorizationResult(query, AuthorizationAuthorized), nil
		})
		coordinator := harness.newCoordinatorWithAuthorizer(
			t, authorizer, harness.defaultSigner(t), Limits{MaxAuthorizationCalls: 2},
		)
		completed, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
		if !IsErrorCode(err, ErrorCodeLimitExceeded) || completed.Valid() || recovery.initialized ||
			len(harness.events.snapshot()) != 0 {
			t.Fatalf("completed=%t recovery=%t events=%v error=%v",
				completed.Valid(), recovery.initialized, harness.events.snapshot(), err)
		}
	})
}

// TestSigningAggregatesInheritedAndGeneratedLookupAndSetBudgets proves exact combined accounting.
func TestSigningAggregatesInheritedAndGeneratedLookupAndSetBudgets(t *testing.T) {
	baselineHarness := newExistingSignerHarness(t, AlgorithmEd25519SHA256, AlgorithmRSASHA256)
	baselineAuthorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
		return NewAuthorizationResult(query, AuthorizationAuthorized), nil
	})
	baseline := baselineHarness.newCoordinatorWithAuthorizer(
		t, baselineAuthorizer, baselineHarness.defaultSigner(t), Limits{},
	)
	prepared, err := baseline.preflight(context.Background(), baselineHarness.request)
	if err != nil || !prepared.hasRevision {
		t.Fatalf("baseline revision=%t error=%v", prepared.hasRevision, err)
	}
	inherited := prepared.revision.Usage()
	generated := len(baselineHarness.request.Profile.credentials)
	requiredLookups := inherited.KeyLookups() + generated
	requiredSets := inherited.SignatureSets() + generated
	if inherited.KeyLookups() == 0 || inherited.SignatureSets() == 0 || generated != 2 {
		t.Fatalf("unexpected accounting inherited=%d/%d generated=%d",
			inherited.KeyLookups(), inherited.SignatureSets(), generated)
	}

	for _, test := range []struct {
		name      string
		exact     Limits
		over      Limits
		limitName LimitName
	}{
		{
			name:      "public key lookups",
			exact:     Limits{MaxPublicKeyLookups: requiredLookups},
			over:      Limits{MaxPublicKeyLookups: requiredLookups - 1},
			limitName: LimitNameMaxPublicKeyLookups,
		},
		{
			name: "total signature sets",
			exact: Limits{
				MaxTotalSignatureSets: requiredSets, MaxGeneratedSignatureSets: generated,
			},
			over: Limits{
				MaxTotalSignatureSets: requiredSets - 1, MaxGeneratedSignatureSets: generated,
			},
			limitName: LimitNameMaxTotalSignatureSets,
		},
	} {
		t.Run(test.name+" exact", func(t *testing.T) {
			harness := newExistingSignerHarness(t, AlgorithmEd25519SHA256, AlgorithmRSASHA256)
			authorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
				harness.events.add("authorize:" + string(query.Purpose()))
				return NewAuthorizationResult(query, AuthorizationAuthorized), nil
			})
			coordinator := harness.newCoordinatorWithAuthorizer(
				t, authorizer, harness.defaultSigner(t), test.exact,
			)
			completed, recovery, completeErr := coordinator.CompleteField(context.Background(), harness.request)
			if completeErr != nil || !completed.Valid() || recovery.Valid() {
				t.Fatalf("exact completed=%t recovery=%t error=%v",
					completed.Valid(), recovery.Valid(), completeErr)
			}
		})
		t.Run(test.name+" one over", func(t *testing.T) {
			harness := newExistingSignerHarness(t, AlgorithmEd25519SHA256, AlgorithmRSASHA256)
			authorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
				harness.events.add("authorize:" + string(query.Purpose()))
				return NewAuthorizationResult(query, AuthorizationAuthorized), nil
			})
			coordinator := harness.newCoordinatorWithAuthorizer(
				t, authorizer, harness.defaultSigner(t), test.over,
			)
			completed, recovery, completeErr := coordinator.CompleteField(context.Background(), harness.request)
			assertSigningPreflightLimit(
				t, completeErr, test.limitName, completed, recovery, harness.events,
			)
		})
	}
}

// TestInheritedAndPublicationFailuresReplaceTheBurnedTicketBeforeLaterCallbacks proves provider fail-closed ordering.
func TestInheritedAndPublicationFailuresReplaceTheBurnedTicketBeforeLaterCallbacks(t *testing.T) {
	t.Run("inherited", func(t *testing.T) {
		harness := newExistingSignerHarness(t, AlgorithmEd25519SHA256)
		harness.inherited.failure = provider.NewFailure(provider.FailureTemporary)
		authorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
			harness.events.add("authorize:" + string(query.Purpose()))
			return NewAuthorizationResult(query, AuthorizationAuthorized), nil
		})
		coordinator := harness.newCoordinatorWithAuthorizer(t, authorizer, harness.defaultSigner(t), Limits{})
		completed, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
		if err == nil || completed.Valid() || !recovery.Valid() || !recovery.ReplacementReady() {
			t.Fatalf("completed=%t recovery=%t/%t error=%v",
				completed.Valid(), recovery.Valid(), recovery.ReplacementReady(), err)
		}
		want := []string{eventRouteReserve, eventRouteBurn, eventInheritedEd25519, eventRouteReplace}
		if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("inherited failure order = %v, want %v", got, want)
		}
	})

	t.Run("publication", func(t *testing.T) {
		harness := newExistingSignerHarness(t, AlgorithmEd25519SHA256)
		harness.publication.provider = publicationProviderFunc(func(_ context.Context, query verify.KeyQuery) (verify.PublicKey, error) {
			harness.events.add("publish:" + string(query.Algorithm))
			return verify.PublicKey{}, provider.NewFailure(provider.FailureTemporary)
		})
		authorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
			harness.events.add("authorize:" + string(query.Purpose()))
			return NewAuthorizationResult(query, AuthorizationAuthorized), nil
		})
		coordinator := harness.newCoordinatorWithAuthorizer(t, authorizer, harness.defaultSigner(t), Limits{})
		completed, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
		if !IsErrorCode(err, ErrorCodeCallbackTemporary) || completed.Valid() ||
			!recovery.Valid() || !recovery.ReplacementReady() {
			t.Fatalf("completed=%t recovery=%t/%t error=%v",
				completed.Valid(), recovery.Valid(), recovery.ReplacementReady(), err)
		}
		want := []string{
			eventRouteReserve, eventRouteBurn, eventInheritedEd25519,
			eventPublishEd25519, eventRouteReplace,
		}
		if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("publication failure order = %v, want %v", got, want)
		}
	})
}

// TestSigningCanonicalAndInputBudgetsUseExactSpeculativeAndFinalWork proves pure exact/one-over accounting.
func TestSigningCanonicalAndInputBudgetsUseExactSpeculativeAndFinalWork(t *testing.T) {
	for _, test := range []struct {
		name    string
		harness func(*testing.T) signerHarness
	}{
		{name: "origin base branch", harness: func(t *testing.T) signerHarness {
			return newSignerHarness(t, AlgorithmEd25519SHA256)
		}},
		{name: "existing feedback branches", harness: func(t *testing.T) signerHarness {
			return newExistingSignerHarness(t, AlgorithmEd25519SHA256)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			baselineHarness := test.harness(t)
			authorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
				return NewAuthorizationResult(query, AuthorizationAuthorized), nil
			})
			baseline := baselineHarness.newCoordinatorWithAuthorizer(
				t, authorizer, baselineHarness.defaultSigner(t), Limits{},
			)
			prepared, err := baseline.preflight(context.Background(), baselineHarness.request)
			if err != nil {
				t.Fatalf("baseline preflight error = %v", err)
			}
			required := baselineHarness.request.Plan.generation.canonical + prepared.base.input.Len()
			if prepared.hasFeedback {
				required += prepared.feedback.input.Len()
			}
			finalPass := prepared.base.input.Len()
			if prepared.hasFeedback && prepared.feedback.input.Len() > finalPass {
				finalPass = prepared.feedback.input.Len()
			}
			// CompleteField rebuilds the selected branch once. CompleteMessage
			// then hashes the current message and rebuilds the same final
			// Section 9.6 input from the reparsed completed message.
			required += finalPass + baselineHarness.request.Plan.generation.currentCanonical + finalPass

			exactHarness := test.harness(t)
			exact := exactHarness.newCoordinatorWithAuthorizer(
				t, authorizer, exactHarness.defaultSigner(t), Limits{MaxCanonicalWorkBytes: required},
			)
			completed, _, exactErr := exact.CompleteField(context.Background(), exactHarness.request)
			if exactErr != nil || !completed.Valid() {
				t.Fatalf("exact canonical work=%d completed=%t error=%v", required, completed.Valid(), exactErr)
			}

			overHarness := test.harness(t)
			over := overHarness.newCoordinatorWithAuthorizer(
				t, authorizer, overHarness.defaultSigner(t), Limits{MaxCanonicalWorkBytes: required - 1},
			)
			completed, recovery, overErr := over.CompleteField(context.Background(), overHarness.request)
			var typed *Error
			if !errors.As(overErr, &typed) || typed.Details().LimitName != LimitNameMaxCanonicalWorkBytes ||
				completed.Valid() || recovery.Valid() || len(overHarness.events.snapshot()) != 0 {
				t.Fatalf("one-over completed=%t recovery=%t events=%v error=%v",
					completed.Valid(), recovery.Valid(), overHarness.events.snapshot(), overErr)
			}
		})
	}

	t.Run("signature input exact and one over", func(t *testing.T) {
		baselineHarness := newSignerHarness(t, AlgorithmEd25519SHA256)
		baseline := baselineHarness.newCoordinator(t, baselineHarness.defaultSigner(t), Limits{})
		prepared, err := baseline.preflight(context.Background(), baselineHarness.request)
		if err != nil {
			t.Fatalf("baseline preflight error = %v", err)
		}
		required := prepared.base.input.Len()
		exactHarness := newSignerHarness(t, AlgorithmEd25519SHA256)
		exact := exactHarness.newCoordinator(
			t, exactHarness.defaultSigner(t), Limits{MaxSignatureInputBytes: required},
		)
		if completed, _, exactErr := exact.CompleteField(context.Background(), exactHarness.request); exactErr != nil || !completed.Valid() {
			t.Fatalf("exact input=%d completed=%t error=%v", required, completed.Valid(), exactErr)
		}
		overHarness := newSignerHarness(t, AlgorithmEd25519SHA256)
		over := overHarness.newCoordinator(
			t, overHarness.defaultSigner(t), Limits{MaxSignatureInputBytes: required - 1},
		)
		completed, recovery, overErr := over.CompleteField(context.Background(), overHarness.request)
		var typed *Error
		if !errors.As(overErr, &typed) || typed.Details().LimitName != LimitNameMaxSignatureInputBytes ||
			completed.Valid() || recovery.Valid() || len(overHarness.events.snapshot()) != 0 {
			t.Fatalf("one-over completed=%t recovery=%t events=%v error=%v",
				completed.Valid(), recovery.Valid(), overHarness.events.snapshot(), overErr)
		}
	})
}

// TestFinalHeaderAndParentMultiplicityLimitsPreflightExactAndOneOver proves final-only bounds.
func TestFinalHeaderAndParentMultiplicityLimitsPreflightExactAndOneOver(t *testing.T) {
	t.Run("final header fields", func(t *testing.T) {
		baseline := newSignerHarness(t, AlgorithmEd25519SHA256)
		required := baseline.request.Plan.SizeFacts().FinalHeaderFields()
		exactHarness := newSignerHarness(t, AlgorithmEd25519SHA256)
		exact := exactHarness.newCoordinator(
			t, exactHarness.defaultSigner(t), Limits{MaxHeaderFields: required},
		)
		if completed, _, err := exact.CompleteField(context.Background(), exactHarness.request); err != nil || !completed.Valid() {
			t.Fatalf("exact final header fields=%d completed=%t error=%v", required, completed.Valid(), err)
		}

		overHarness := newSignerHarness(t, AlgorithmEd25519SHA256)
		over := overHarness.newCoordinator(
			t, overHarness.defaultSigner(t), Limits{MaxHeaderFields: required - 1},
		)
		completed, recovery, err := over.CompleteField(context.Background(), overHarness.request)
		assertSigningPreflightLimit(t, err, LimitNameMaxHeaderFields, completed, recovery, overHarness.events)
	})

	t.Run("parent multiplicity", func(t *testing.T) {
		const copies = 2
		exactHarness := rebindOriginHarnessMultiplicity(t, newSignerHarness(t, AlgorithmEd25519SHA256), copies)
		exact := exactHarness.newCoordinator(
			t, exactHarness.defaultSigner(t), Limits{MaxParentOutputCopiesAndTickets: copies},
		)
		if completed, _, err := exact.CompleteField(context.Background(), exactHarness.request); err != nil || !completed.Valid() {
			t.Fatalf("exact parent multiplicity=%d completed=%t error=%v", copies, completed.Valid(), err)
		}

		overHarness := rebindOriginHarnessMultiplicity(t, newSignerHarness(t, AlgorithmEd25519SHA256), copies)
		over := overHarness.newCoordinator(
			t, overHarness.defaultSigner(t), Limits{MaxParentOutputCopiesAndTickets: copies - 1},
		)
		completed, recovery, err := over.CompleteField(context.Background(), overHarness.request)
		assertSigningPreflightLimit(
			t, err, LimitNameMaxParentOutputCopiesAndTickets, completed, recovery, overHarness.events,
		)
	})
}

// TestSigningFieldHeaderAndMessageBudgetsPreflightExactAndOneOver proves component taxonomy before callbacks.
func TestSigningFieldHeaderAndMessageBudgetsPreflightExactAndOneOver(t *testing.T) {
	baselineHarness := newSignerHarness(t, AlgorithmEd25519SHA256)
	baseline := baselineHarness.newCoordinator(t, baselineHarness.defaultSigner(t), Limits{})
	prepared, err := baseline.preflight(context.Background(), baselineHarness.request)
	if err != nil {
		t.Fatalf("baseline preflight error = %v", err)
	}
	fieldBytes := prepared.base.size
	baseHeader := baselineHarness.request.Plan.sizes.headerBytes - baselineHarness.request.Plan.sizes.signatureFieldBytes
	baseMessage := baselineHarness.request.Plan.sizes.messageBytes - baselineHarness.request.Plan.sizes.signatureFieldBytes
	headerBytes := baseHeader + fieldBytes
	messageBytes := baseMessage + fieldBytes

	t.Run("broader signer consumes sealed narrow plan dimensions", func(t *testing.T) {
		for _, name := range []LimitName{
			LimitNameMaxFieldBytes, LimitNameMaxHeaderBytes, LimitNameMaxMessageBytes,
		} {
			harness := newSignerHarness(t, AlgorithmEd25519SHA256)
			allowance := fieldBytes - 1
			harness.request.Plan.sizes.signatureFieldBytes = allowance
			harness.request.Plan.sizes.headerBytes = baseHeader + allowance
			harness.request.Plan.sizes.messageBytes = baseMessage + allowance
			harness.request.Plan.sizes.signatureLimit = name
			if !harness.request.Plan.Valid() {
				t.Fatalf("narrow plan invalid for %q", name)
			}
			coordinator := harness.newCoordinator(t, harness.defaultSigner(t), Limits{})
			completed, recovery, completeErr := coordinator.CompleteField(context.Background(), harness.request)
			var typed *Error
			if !errors.As(completeErr, &typed) || typed.Details().LimitName != name ||
				completed.Valid() || recovery.Valid() || len(harness.events.snapshot()) != 0 {
				t.Fatalf("dimension=%q completed=%t recovery=%t events=%v error=%v",
					name, completed.Valid(), recovery.Valid(), harness.events.snapshot(), completeErr)
			}
			wantLimit, wantActual := allowance, fieldBytes
			if name == LimitNameMaxHeaderBytes {
				wantLimit, wantActual = baseHeader+allowance, baseHeader+fieldBytes
			}
			if name == LimitNameMaxMessageBytes {
				wantLimit, wantActual = baseMessage+allowance, baseMessage+fieldBytes
			}
			if typed.Details().Limit != wantLimit || typed.Details().Actual != wantActual {
				t.Fatalf("dimension=%q limit/actual=%d/%d want=%d/%d",
					name, typed.Details().Limit, typed.Details().Actual, wantLimit, wantActual)
			}
		}
	})

	for _, test := range []struct {
		name      string
		exact     Limits
		over      Limits
		limitName LimitName
	}{
		{
			name:      "field",
			exact:     Limits{MaxFieldBytes: fieldBytes, MaxDecodedRecipeBytes: 1},
			over:      Limits{MaxFieldBytes: fieldBytes - 1, MaxDecodedRecipeBytes: 1},
			limitName: LimitNameMaxFieldBytes,
		},
		{
			name:      "header",
			exact:     Limits{MaxHeaderBytes: headerBytes, MaxFieldBytes: fieldBytes, MaxDecodedRecipeBytes: 1},
			over:      Limits{MaxHeaderBytes: headerBytes - 1, MaxFieldBytes: fieldBytes, MaxDecodedRecipeBytes: 1},
			limitName: LimitNameMaxHeaderBytes,
		},
		{
			name: "message",
			exact: Limits{
				MaxMessageBytes: messageBytes, MaxHeaderBytes: headerBytes,
				MaxFieldBytes: fieldBytes, MaxDecodedRecipeBytes: 1,
			},
			over: Limits{
				MaxMessageBytes: messageBytes - 1, MaxHeaderBytes: headerBytes,
				MaxFieldBytes: fieldBytes, MaxDecodedRecipeBytes: 1,
			},
			limitName: LimitNameMaxMessageBytes,
		},
	} {
		t.Run(test.name+" exact", func(t *testing.T) {
			harness := newSignerHarness(t, AlgorithmEd25519SHA256)
			coordinator := harness.newCoordinator(t, harness.defaultSigner(t), test.exact)
			completed, _, completeErr := coordinator.CompleteField(context.Background(), harness.request)
			if completeErr != nil || !completed.Valid() {
				t.Fatalf("exact completed=%t error=%v", completed.Valid(), completeErr)
			}
		})
		t.Run(test.name+" one over", func(t *testing.T) {
			harness := newSignerHarness(t, AlgorithmEd25519SHA256)
			coordinator := harness.newCoordinator(t, harness.defaultSigner(t), test.over)
			completed, recovery, completeErr := coordinator.CompleteField(context.Background(), harness.request)
			assertSigningPreflightLimit(t, completeErr, test.limitName, completed, recovery, harness.events)
		})
	}
}

// assertSigningPreflightLimit verifies typed component rejection before any authority or provider callback.
func assertSigningPreflightLimit(t *testing.T, err error, name LimitName, completed CompletedSigningField, recovery Recovery, events *signingEventLog) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.Details().LimitName != name ||
		completed.Valid() || recovery.Valid() || len(events.snapshot()) != 0 {
		t.Fatalf("completed=%t recovery=%t events=%v error=%v want_limit=%q",
			completed.Valid(), recovery.Valid(), events.snapshot(), err, name)
	}
}

// TestSigningFailureReturnsNoPartialFieldAndSameLineageRecovery proves post-burn atomicity.
func TestSigningFailureReturnsNoPartialFieldAndSameLineageRecovery(t *testing.T) {
	harness := newSignerHarness(t, AlgorithmEd25519SHA256, AlgorithmRSASHA256)
	delegate := harness.defaultSigner(t)
	signer := privateSignerFunc(func(ctx context.Context, handle PrivateKeyHandle, request PrivateKeySignRequest) (PrivateKeySignResult, error) {
		if request.Algorithm() == AlgorithmEd25519SHA256 {
			harness.events.add("sign:" + string(request.Algorithm()))
			return NewPrivateKeySignResult(make([]byte, ed25519.SignatureSize)), nil
		}
		return delegate.SignDigest(ctx, handle, request)
	})
	coordinator := harness.newCoordinator(t, signer, Limits{})
	completed, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
	if completed.Valid() || completed.field.Valid() || completed.reservation != nil ||
		!IsErrorCode(err, ErrorCodeCryptographicSelfCheck) {
		t.Fatalf("partial completed=%t field=%t reservation=%t error=%v",
			completed.Valid(), completed.field.Valid(), completed.reservation != nil, err)
	}
	want := []string{
		eventRouteReserve, eventRouteBurn, eventPublishRSA, eventPublishEd25519,
		eventSignRSA, eventSignEd25519, eventRouteReplace,
	}
	if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("failure callback order = %v, want %v", got, want)
	}
	if !recovery.Valid() || !recovery.ReplacementReady() || recovery.RecoveryPending() {
		t.Fatalf("replacement recovery state valid=%t ready=%t pending=%t",
			recovery.Valid(), recovery.ReplacementReady(), recovery.RecoveryPending())
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if replacement, recoverErr := recovery.Recover(canceled); !errors.Is(recoverErr, context.Canceled) ||
		replacement.Valid() || !recovery.ReplacementReady() {
		t.Fatalf("canceled recovery replacement=%t ready=%t error=%v",
			replacement.Valid(), recovery.ReplacementReady(), recoverErr)
	}
	replacement, recoverErr := recovery.Recover(context.Background())
	if recoverErr != nil || !replacement.Valid() || recovery.initialized {
		t.Fatalf("replacement valid=%t recovery_initialized=%t error=%v", replacement.Valid(), recovery.initialized, recoverErr)
	}
	if repeated, repeatedErr := recovery.Recover(context.Background()); repeated.Valid() ||
		!IsErrorCode(repeatedErr, ErrorCodeInvalidRequest) {
		t.Fatalf("one-shot recovery repeated_valid=%t error=%v", repeated.Valid(), repeatedErr)
	}
}

// TestMalformedReplacementContractDoesNotAdvertiseUnrecoverablePendingState proves recovery truthfulness.
func TestMalformedReplacementContractDoesNotAdvertiseUnrecoverablePendingState(t *testing.T) {
	harness := newSignerHarness(t, AlgorithmEd25519SHA256)
	harness.authority.replace = func(context.Context, routeplan.TicketQuery) (routeplan.AuthorityResult, error) {
		return routeplan.AuthorityResult{}, nil
	}
	signer := privateSignerFunc(func(context.Context, PrivateKeyHandle, PrivateKeySignRequest) (PrivateKeySignResult, error) {
		harness.events.add(eventSignEd25519)
		return NewPrivateKeySignResult(make([]byte, ed25519.SignatureSize)), nil
	})
	coordinator := harness.newCoordinator(t, signer, Limits{})
	completed, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
	if !IsErrorCode(err, ErrorCodeCryptographicSelfCheck) || completed.Valid() ||
		recovery.Valid() || recovery.ReplacementReady() || recovery.RecoveryPending() {
		t.Fatalf("completed=%t recovery=%t/%t/%t error=%v",
			completed.Valid(), recovery.Valid(), recovery.ReplacementReady(), recovery.RecoveryPending(), err)
	}
	if replacement, recoverErr := recovery.Recover(context.Background()); replacement.Valid() ||
		!IsErrorCode(recoverErr, ErrorCodeInvalidRequest) {
		t.Fatalf("unusable recovery replacement=%t error=%v", replacement.Valid(), recoverErr)
	}
}

// TestPendingRecoveryRetainsAReplacementCommittedBeforePostCallCancellation proves retry truthfulness.
func TestPendingRecoveryRetainsAReplacementCommittedBeforePostCallCancellation(t *testing.T) {
	harness := newSignerHarness(t, AlgorithmEd25519SHA256)
	harness.authority.replace = func(context.Context, routeplan.TicketQuery) (routeplan.AuthorityResult, error) {
		return routeplan.AuthorityResult{}, provider.NewFailure(provider.FailureTemporary)
	}
	signer := privateSignerFunc(func(context.Context, PrivateKeyHandle, PrivateKeySignRequest) (PrivateKeySignResult, error) {
		harness.events.add(eventSignEd25519)
		return NewPrivateKeySignResult(make([]byte, ed25519.SignatureSize)), nil
	})
	coordinator := harness.newCoordinator(t, signer, Limits{})
	completed, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
	if !IsErrorCode(err, ErrorCodeCryptographicSelfCheck) || completed.Valid() ||
		!recovery.Valid() || !recovery.RecoveryPending() || recovery.ReplacementReady() {
		t.Fatalf("completed=%t recovery=%t/%t/%t error=%v",
			completed.Valid(), recovery.Valid(), recovery.RecoveryPending(), recovery.ReplacementReady(), err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	harness.authority.replace = func(callCtx context.Context, query routeplan.TicketQuery) (routeplan.AuthorityResult, error) {
		result, replaceErr := harness.authority.delegate.Replace(callCtx, query)
		cancel()
		return result, replaceErr
	}
	replacement, recoverErr := recovery.Recover(ctx)
	if !errors.Is(recoverErr, context.Canceled) || replacement.Valid() ||
		!recovery.Valid() || !recovery.ReplacementReady() || recovery.RecoveryPending() {
		t.Fatalf("post-call replacement=%t recovery=%t/%t/%t error=%v",
			replacement.Valid(), recovery.Valid(), recovery.ReplacementReady(), recovery.RecoveryPending(), recoverErr)
	}
	replacement, recoverErr = recovery.Recover(context.Background())
	if recoverErr != nil || !replacement.Valid() || recovery.Valid() {
		t.Fatalf("fresh replacement=%t recovery=%t error=%v", replacement.Valid(), recovery.Valid(), recoverErr)
	}
}

// TestCoordinatorConcurrentSameTicketReuseHasOneAtomicWinner proves shared-service race safety.
func TestCoordinatorConcurrentSameTicketReuseHasOneAtomicWinner(t *testing.T) {
	harness := newSignerHarness(t, AlgorithmEd25519SHA256)
	coordinator := harness.newCoordinator(t, harness.defaultSigner(t), Limits{})
	type result struct {
		completed CompletedSigningField
		recovery  Recovery
		err       error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Go(func() {
			<-start
			completed, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
			results <- result{completed: completed, recovery: recovery, err: err}
		})
	}
	close(start)
	wait.Wait()
	close(results)
	winners, losers := 0, 0
	for result := range results {
		if result.err == nil && result.completed.Valid() && !result.recovery.Valid() {
			winners++
			continue
		}
		if result.err != nil && !result.completed.Valid() && !result.recovery.Valid() {
			losers++
			continue
		}
		t.Fatalf("ambiguous concurrent result completed=%t recovery=%t error=%v",
			result.completed.Valid(), result.recovery.Valid(), result.err)
	}
	if winners != 1 || losers != 1 {
		t.Fatalf("same-ticket winners=%d losers=%d", winners, losers)
	}
}

// TestCoordinatorConcurrentDistinctPlansReuseTheSameServices proves true shared-service race safety.
func TestCoordinatorConcurrentDistinctPlansReuseTheSameServices(t *testing.T) {
	harness := newSignerHarness(t, AlgorithmEd25519SHA256)
	source, err := routeplan.NewImmutableSource(harness.request.Message.RawBytes())
	if err != nil {
		t.Fatalf("routeplan.NewImmutableSource() error = %v", err)
	}
	entry, err := routeplan.NewEntry(
		source, routeplan.PurposeOrigin, []byte("<sender@signer.example.test>"),
		[][]byte{[]byte("<second@signer.example.test>")}, routeplan.DisclosureSingle,
		[]byte("second-concurrent-route"), nil,
	)
	if err != nil {
		t.Fatalf("routeplan.NewEntry() error = %v", err)
	}
	routeRequest, err := routeplan.NewPlanRequest([]routeplan.Entry{entry})
	if err != nil {
		t.Fatalf("routeplan.NewPlanRequest() error = %v", err)
	}
	_, tickets, err := harness.routes.Finalize(context.Background(), routeRequest)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("routeplan.Finalize() tickets=%d error=%v", len(tickets), err)
	}
	planner, err := NewHashPlanCoordinator(harness.revision, recipe.GenerationLimits{}, Limits{})
	if err != nil {
		t.Fatalf("NewHashPlanCoordinator() error = %v", err)
	}
	secondPlan, err := planner.PlanOriginator(context.Background(), OriginatorPlanRequest{
		Message: harness.request.Message, Ticket: tickets[0],
	})
	if err != nil {
		t.Fatalf("PlanOriginator(second) error = %v", err)
	}
	second := harness.request
	second.Plan = secondPlan
	second.Ticket = tickets[0]
	second.ReversePath = tickets[0].ReversePath()
	second.ForwardPaths = tickets[0].DisclosureRecipients()
	coordinator := harness.newCoordinator(t, harness.defaultSigner(t), Limits{})
	harness.events.reset()

	requests := []SignFieldRequest{harness.request, second}
	start := make(chan struct{})
	results := make(chan error, len(requests))
	var wait sync.WaitGroup
	for _, request := range requests {
		wait.Go(func() {
			<-start
			completed, recovery, completeErr := coordinator.CompleteField(context.Background(), request)
			if completeErr == nil && (!completed.Valid() || recovery.Valid()) {
				completeErr = errors.New("successful concurrent operation returned incoherent state")
			}
			results <- completeErr
		})
	}
	close(start)
	wait.Wait()
	close(results)
	for completeErr := range results {
		if completeErr != nil {
			t.Fatalf("concurrent distinct operation error = %v", completeErr)
		}
	}
}

// TestSigningCancellationAndLimitsDoNotLeakPartialState proves local preflight and post-call context gates.
func TestSigningCancellationAndLimitsDoNotLeakPartialState(t *testing.T) {
	t.Run("preflight cancellation", func(t *testing.T) {
		harness := newSignerHarness(t, AlgorithmEd25519SHA256)
		coordinator := harness.newCoordinator(t, harness.defaultSigner(t), Limits{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		completed, recovery, err := coordinator.CompleteField(ctx, harness.request)
		if !errors.Is(err, context.Canceled) || completed.Valid() || recovery.initialized || len(harness.events.snapshot()) != 0 {
			t.Fatalf("completed=%t recovery=%t events=%v error=%v",
				completed.Valid(), recovery.initialized, harness.events.snapshot(), err)
		}
	})

	t.Run("callback cancellation", func(t *testing.T) {
		harness := newSignerHarness(t, AlgorithmEd25519SHA256)
		delegate := harness.defaultSigner(t)
		ctx, cancel := context.WithCancel(context.Background())
		signer := privateSignerFunc(func(callCtx context.Context, handle PrivateKeyHandle, request PrivateKeySignRequest) (PrivateKeySignResult, error) {
			result, err := delegate.SignDigest(callCtx, handle, request)
			cancel()
			return result, err
		})
		coordinator := harness.newCoordinator(t, signer, Limits{})
		completed, recovery, err := coordinator.CompleteField(ctx, harness.request)
		if !errors.Is(err, context.Canceled) || completed.Valid() || !recovery.initialized {
			t.Fatalf("completed=%t recovery=%t error=%v", completed.Valid(), recovery.initialized, err)
		}
		want := []string{
			eventRouteReserve, eventRouteBurn, eventPublishEd25519,
			eventSignEd25519, eventRouteReplace,
		}
		if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("callback cancellation order = %v, want %v", got, want)
		}
		if replacement, recoverErr := recovery.Recover(context.Background()); recoverErr != nil || !replacement.Valid() {
			t.Fatalf("replacement valid=%t error=%v", replacement.Valid(), recoverErr)
		}
	})

	t.Run("one-over private call budget preflights all callbacks", func(t *testing.T) {
		harness := newSignerHarness(t, AlgorithmEd25519SHA256, AlgorithmRSASHA256)
		limits := Limits{MaxPrivateSigningCalls: 1, MaxGeneratedSignatureSets: 1}
		coordinator := harness.newCoordinator(t, harness.defaultSigner(t), limits)
		completed, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
		if !IsErrorCode(err, ErrorCodeLimitExceeded) || completed.Valid() || recovery.initialized ||
			len(harness.events.snapshot()) != 0 {
			t.Fatalf("completed=%t recovery=%t events=%v error=%v",
				completed.Valid(), recovery.initialized, harness.events.snapshot(), err)
		}
	})
}
