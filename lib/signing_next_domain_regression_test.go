package dkim2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/routeplan"
)

type nextDomainRecordingAuthorizer struct {
	mu                sync.Mutex
	purposes          []SigningAuthorizationPurpose
	oob               []nextDomainOOBObservation
	expectedReceivers map[SigningAuthorizationPurpose][]byte
}

type nextDomainOOBObservation struct {
	purpose      SigningAuthorizationPurpose
	reversePath  []byte
	forwardPaths [][]byte
	receiver     []byte
}

// Authorize records and approves one exact next-domain regression query.
func (a *nextDomainRecordingAuthorizer) Authorize(_ context.Context, query SigningAuthorizationQuery) (SigningAuthorizationResult, error) {
	a.mu.Lock()
	a.purposes = append(a.purposes, query.Purpose())
	if facts, ok := query.OutOfBandFacts(); ok {
		receiver := facts.ReceiverBinding()
		a.oob = append(a.oob, nextDomainOOBObservation{
			purpose: query.Purpose(), reversePath: facts.ReversePath(),
			forwardPaths: facts.ForwardPaths(), receiver: receiver,
		})
		if expected, present := a.expectedReceivers[query.Purpose()]; present &&
			!bytes.Equal(receiver, expected) {
			a.mu.Unlock()
			return DenySigning(query), nil
		}
	}
	a.mu.Unlock()
	return AuthorizeSigning(query), nil
}

// snapshot returns a detached copy of the observed authorization order.
func (a *nextDomainRecordingAuthorizer) snapshot() []SigningAuthorizationPurpose {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]SigningAuthorizationPurpose(nil), a.purposes...)
}

// reset discards the prior operation's authorization events.
func (a *nextDomainRecordingAuthorizer) reset() {
	a.mu.Lock()
	a.purposes = nil
	a.oob = nil
	a.expectedReceivers = nil
	a.mu.Unlock()
}

// expectReceivers configures exact receive and send trust-edge evidence.
func (a *nextDomainRecordingAuthorizer) expectReceivers(receive, send []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.expectedReceivers = make(map[SigningAuthorizationPurpose][]byte, 2)
	if receive != nil {
		a.expectedReceivers[SigningAuthorizationReceiveNextDomain] = bytes.Clone(receive)
	}
	if send != nil {
		a.expectedReceivers[SigningAuthorizationSendNextDomain] = bytes.Clone(send)
	}
}

// oobSnapshot returns detached OOB trust-edge evidence in callback order.
func (a *nextDomainRecordingAuthorizer) oobSnapshot() []nextDomainOOBObservation {
	a.mu.Lock()
	defer a.mu.Unlock()
	result := make([]nextDomainOOBObservation, len(a.oob))
	for index := range a.oob {
		result[index] = nextDomainOOBObservation{
			purpose:      a.oob[index].purpose,
			reversePath:  bytes.Clone(a.oob[index].reversePath),
			forwardPaths: cloneByteSlices(a.oob[index].forwardPaths),
			receiver:     bytes.Clone(a.oob[index].receiver),
		}
	}
	return result
}

type nextDomainSelectiveDriftProvider struct {
	base          *publicSigningProvider
	driftSelector string
	driftKey      *rsa.PrivateKey
	status        PublicKeyStatus
	drift         atomic.Bool
}

// LookupPublicKey returns altered material only for the selected publication after drift is enabled.
func (p *nextDomainSelectiveDriftProvider) LookupPublicKey(ctx context.Context, query PublicKeyQuery) (PublicKeyResult, error) {
	if p.drift.Load() && query.Selector() == p.driftSelector {
		p.base.lookups.Add(1)
		switch p.status {
		case PublicKeyStatusMissing:
			return MissingPublicKey(query.Algorithm()), nil
		case PublicKeyStatusRevoked:
			return RevokedPublicKey(query.Algorithm()), nil
		}
		return FoundRSAPublicKey(&p.driftKey.PublicKey), nil
	}
	return p.base.LookupPublicKey(ctx, query)
}

// SignDigest delegates private signing to the stable fixture key.
func (p *nextDomainSelectiveDriftProvider) SignDigest(ctx context.Context, handle PrivateKeyHandle, request PrivateKeySignRequest) (PrivateKeySignResult, error) {
	return p.base.SignDigest(ctx, handle, request)
}

type nextDomainRegressionFixture struct {
	signer     *Signer
	provider   *publicSigningProvider
	authorizer *nextDomainRecordingAuthorizer
	rsaKey     *rsa.PrivateKey
	clock      *atomic.Int64
}

type adversarialNextDomainClock struct {
	mu     sync.Mutex
	stable time.Time
	first  time.Time
	later  time.Time
	armed  bool
	calls  int
}

// now returns a stable setup time or one first-then-expired signing sequence.
func (c *adversarialNextDomainClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.armed {
		return c.stable
	}
	c.calls++
	if c.calls == 1 {
		return c.first
	}
	return c.later
}

// arm installs one counted first-versus-later sequence.
func (c *adversarialNextDomainClock) arm(first, later time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.first = first
	c.later = later
	c.calls = 0
	c.armed = true
}

// callCount returns the exact number of samples since arm.
func (c *adversarialNextDomainClock) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// newNextDomainRegressionFixture constructs one public RSA fixture with ordered authorization evidence.
func newNextDomainRegressionFixture(t *testing.T) *nextDomainRegressionFixture {
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
	authorizer := &nextDomainRecordingAuthorizer{}
	clock := &atomic.Int64{}
	clock.Store(1_700_000_000)
	signer, err := NewSigner(
		provider,
		publicRouteMemoryAuthority{value: routeplan.NewMemoryAuthority()},
		authorizer,
		provider,
		WithSigningClock(func() time.Time { return time.Unix(clock.Load(), 0) }),
	)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	return &nextDomainRegressionFixture{
		signer: signer, provider: provider, authorizer: authorizer, rsaKey: rsaKey, clock: clock,
	}
}

// newNextDomainRegressionFixtureWithClock constructs one public fixture around a controlled clock.
func newNextDomainRegressionFixtureWithClock(
	t *testing.T,
	clock func() time.Time,
) *nextDomainRegressionFixture {
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
	authorizer := &nextDomainRecordingAuthorizer{}
	signer, err := NewSigner(
		provider,
		publicRouteMemoryAuthority{value: routeplan.NewMemoryAuthority()},
		authorizer,
		provider,
		WithSigningClock(clock),
	)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	return &nextDomainRegressionFixture{
		signer: signer, provider: provider, authorizer: authorizer, rsaKey: rsaKey,
	}
}

// newNextDomainDriftFixture constructs one fixture whose future selector can drift independently.
func newNextDomainDriftFixture(t *testing.T, selector string) (*nextDomainRegressionFixture, *nextDomainSelectiveDriftProvider) {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	driftKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(drift) error = %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	base := &publicSigningProvider{rsaKey: rsaKey, edKey: edKey}
	provider := &nextDomainSelectiveDriftProvider{
		base: base, driftSelector: selector, driftKey: driftKey,
	}
	authorizer := &nextDomainRecordingAuthorizer{}
	clock := &atomic.Int64{}
	clock.Store(1_700_000_000)
	signer, err := NewSigner(
		provider,
		publicRouteMemoryAuthority{value: routeplan.NewMemoryAuthority()},
		authorizer,
		provider,
		WithSigningClock(func() time.Time { return time.Unix(clock.Load(), 0) }),
	)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	return &nextDomainRegressionFixture{
		signer: signer, provider: base, authorizer: authorizer, rsaKey: rsaKey, clock: clock,
	}, provider
}

// profile constructs one fixture-backed profile for an exact canonical domain.
func (f *nextDomainRegressionFixture) profile(t *testing.T, domain, selector string) SigningProfile {
	t.Helper()
	handle, err := NewPrivateKeyHandle([]byte("profile-" + domain + "-" + selector))
	if err != nil {
		t.Fatalf("NewPrivateKeyHandle() error = %v", err)
	}
	credential, err := NewRSASigningCredential(selector, &f.rsaKey.PublicKey, handle)
	if err != nil {
		t.Fatalf("NewRSASigningCredential() error = %v", err)
	}
	profile, err := NewRSASigningProfile(domain, credential)
	if err != nil {
		t.Fatalf("NewRSASigningProfile(%q) error = %v", domain, err)
	}
	return profile
}

// publication issues fresh exact future-key evidence for one proposed nd domain.
func (f *nextDomainRegressionFixture) publication(t *testing.T, domain, selector string) PublishedNextDomainCapability {
	t.Helper()
	handle, err := NewPrivateKeyHandle([]byte("publication-" + domain + "-" + selector))
	if err != nil {
		t.Fatalf("NewPrivateKeyHandle() error = %v", err)
	}
	credential, err := NewRSASigningCredential(selector, &f.rsaKey.PublicKey, handle)
	if err != nil {
		t.Fatalf("NewRSASigningCredential(publication) error = %v", err)
	}
	published, err := f.signer.IssueNextDomainPublication(
		context.Background(), NewRSANextDomainPublicationRequest(domain, credential),
	)
	if err != nil || !published.Valid() {
		t.Fatalf("IssueNextDomainPublication() valid=%t error=%v", published.Valid(), err)
	}
	return published
}

// signOrigin creates one ordinary first hop with caller-selected flags and recipient.
func (f *nextDomainRegressionFixture) signOrigin(t *testing.T, raw []byte, recipient []byte, flags []SigningFlag) []byte {
	t.Helper()
	source, err := NewSigningSource(raw)
	if err != nil {
		t.Fatalf("NewSigningSource() error = %v", err)
	}
	entry, err := NewOriginatorRouteEntry(
		source, []byte("<alice@example.test>"), [][]byte{bytes.Clone(recipient)},
		RouteDisclosureSingle, []byte("origin-route"),
	)
	if err != nil {
		t.Fatalf("NewOriginatorRouteEntry() error = %v", err)
	}
	request, err := NewRouteFanoutRequest([]RouteEntry{entry})
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest() error = %v", err)
	}
	_, tickets, err := f.signer.PlanRouteFanout(context.Background(), request)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout(origin) tickets=%d error=%v", len(tickets), err)
	}
	metadata, err := NewSigningMetadata(nil, false, flags)
	if err != nil {
		t.Fatalf("NewSigningMetadata() error = %v", err)
	}
	result, recovery, err := f.signer.SignOriginator(
		context.Background(),
		NewOriginatorSigningRequest(
			raw, []byte("<alice@example.test>"), [][]byte{bytes.Clone(recipient)},
			tickets[0], f.profile(t, "example.test", "origin"), metadata,
			SigningTransportFinalNetworkPreDotStuffing,
		),
	)
	if err != nil || recovery.Valid() {
		t.Fatalf("SignOriginator() recovery=%t error=%v", recovery.Valid(), err)
	}
	unrestricted, ok := result.Unrestricted()
	if !ok {
		t.Fatal("SignOriginator() did not return unrestricted bytes")
	}
	return unrestricted.Bytes()
}

// verifyRevision requires one exact public revision capability and expected status.
func (f *nextDomainRegressionFixture) verifyRevision(
	t *testing.T,
	raw, reversePath []byte,
	forwardPaths [][]byte,
	status RevisionVerificationStatus,
) VerifiedRevisionInput {
	t.Helper()
	outcome, capability, err := f.signer.VerifyForRevision(
		context.Background(), NewVerifyRequest(raw, reversePath, forwardPaths),
	)
	if err != nil || outcome.Status() != status || !capability.Valid() {
		t.Fatalf("VerifyForRevision() status=%q capability=%t error=%v",
			outcome.Status(), capability.Valid(), err)
	}
	return capability
}

// nextDomainTicket plans one exact OOB terminal route.
func (f *nextDomainRegressionFixture) nextDomainTicket(
	t *testing.T,
	capability VerifiedRevisionInput,
	raw, reversePath []byte,
	forwardPaths [][]byte,
	routeScope, receiverBinding string,
) RouteCopyTicket {
	t.Helper()
	source, err := NewSigningSource(raw)
	if err != nil {
		t.Fatalf("NewSigningSource(next-domain) error = %v", err)
	}
	entry, err := NewNextDomainRouteEntry(
		capability, source, reversePath, forwardPaths, RouteDisclosureSingle,
		[]byte(routeScope), []byte(receiverBinding),
	)
	if err != nil {
		t.Fatalf("NewNextDomainRouteEntry() error = %v", err)
	}
	request, err := NewRouteFanoutRequest([]RouteEntry{entry})
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest(next-domain) error = %v", err)
	}
	_, tickets, err := f.signer.PlanRouteFanout(context.Background(), request)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout(next-domain) tickets=%d error=%v", len(tickets), err)
	}
	return tickets[0]
}

// nextDomainContinuationTicket plans one terminal route with separate inbound and outbound receiver evidence.
func (f *nextDomainRegressionFixture) nextDomainContinuationTicket(
	t *testing.T,
	capability VerifiedRevisionInput,
	raw, reversePath []byte,
	forwardPaths [][]byte,
	routeScope, inboundReceiverBinding, outboundReceiverBinding string,
) RouteCopyTicket {
	t.Helper()
	source, err := NewSigningSource(raw)
	if err != nil {
		t.Fatalf("NewSigningSource(next-domain continuation) error = %v", err)
	}
	entry, err := NewNextDomainContinuationRouteEntry(
		capability, source, reversePath, forwardPaths, RouteDisclosureSingle,
		[]byte(routeScope), []byte(inboundReceiverBinding), []byte(outboundReceiverBinding),
	)
	if err != nil {
		t.Fatalf("NewNextDomainContinuationRouteEntry() error = %v", err)
	}
	request, err := NewRouteFanoutRequest([]RouteEntry{entry})
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest(next-domain continuation) error = %v", err)
	}
	_, tickets, err := f.signer.PlanRouteFanout(context.Background(), request)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout(next-domain continuation) tickets=%d error=%v", len(tickets), err)
	}
	return tickets[0]
}

// existingTicket plans one ordinary route, optionally with receiver evidence for nd completion.
func (f *nextDomainRegressionFixture) existingTicket(
	t *testing.T,
	capability VerifiedRevisionInput,
	raw, reversePath []byte,
	forwardPaths [][]byte,
	routeScope, receiverBinding string,
) RouteCopyTicket {
	t.Helper()
	source, err := NewSigningSource(raw)
	if err != nil {
		t.Fatalf("NewSigningSource(existing) error = %v", err)
	}
	var entry RouteEntry
	if receiverBinding == "" {
		entry, err = NewExistingRouteEntry(
			capability, source, reversePath, forwardPaths, RouteDisclosureSingle, []byte(routeScope),
		)
	} else {
		entry, err = NewReceiverBoundExistingRouteEntry(
			capability, source, reversePath, forwardPaths, RouteDisclosureSingle,
			[]byte(routeScope), []byte(receiverBinding),
		)
	}
	if err != nil {
		t.Fatalf("existing route entry error = %v", err)
	}
	request, err := NewRouteFanoutRequest([]RouteEntry{entry})
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest(existing) error = %v", err)
	}
	_, tickets, err := f.signer.PlanRouteFanout(context.Background(), request)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout(existing) tickets=%d error=%v", len(tickets), err)
	}
	return tickets[0]
}

// signNextDomain executes one terminal operation and returns its restricted result.
func (f *nextDomainRegressionFixture) signNextDomain(
	t *testing.T,
	capability VerifiedRevisionInput,
	raw, reversePath []byte,
	forwardPaths [][]byte,
	ticket RouteCopyTicket,
	profile SigningProfile,
	nextDomain string,
	published PublishedNextDomainCapability,
	literalPolicy RecipeLiteralPolicy,
) (SigningResult, SigningRecovery, error) {
	t.Helper()
	return f.signer.SignNextDomain(
		context.Background(),
		NewNextDomainSigningRequest(
			capability, raw, reversePath, forwardPaths, ticket, profile,
			SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
			RejectUnavailableBody, literalPolicy, nextDomain, published,
		),
	)
}

// releaseNextDomain performs one exact OOB release for a valid terminal result.
func releaseNextDomain(
	t *testing.T,
	result SigningResult,
	ticket RouteCopyTicket,
	reversePath []byte,
	forwardPaths [][]byte,
	routeScope, receiverBinding string,
) []byte {
	t.Helper()
	terminal, ok := result.OutOfBandAcceptance()
	if !ok {
		t.Fatal("next-domain result did not expose the OOB-restricted variant")
	}
	output, err := terminal.ReleaseForOutOfBandAcceptance(
		context.Background(), ticket, reversePath, forwardPaths,
		[]byte(receiverBinding), []byte(routeScope),
	)
	if err != nil || len(output) == 0 {
		t.Fatalf("ReleaseForOutOfBandAcceptance() bytes=%d error=%v", len(output), err)
	}
	return output
}

// prepareContinuationPredecessor creates and releases one valid ordinary-to-nd hop.
func prepareContinuationPredecessor(
	t *testing.T,
	fixture *nextDomainRegressionFixture,
) ([]byte, VerifiedRevisionInput) {
	t.Helper()
	raw := []byte("From: alice@example.test\r\nSubject: split receiver bindings\r\n\r\nbody\r\n")
	origin := fixture.signOrigin(t, raw, []byte("<bob@example.net>"), nil)
	capability := fixture.verifyRevision(
		t, origin, []byte("<alice@example.test>"),
		[][]byte{[]byte("<bob@example.net>")}, RevisionVerificationVerified,
	)
	reversePath := []byte("<relay@example.net>")
	forwardPaths := [][]byte{[]byte("<receiver@next.example.test>")}
	ticket := fixture.nextDomainTicket(
		t, capability, origin, reversePath, forwardPaths, "predecessor-route", "predecessor-outbound",
	)
	result, recovery, err := fixture.signNextDomain(
		t, capability, origin, reversePath, forwardPaths, ticket,
		fixture.profile(t, "example.net", "predecessor"), "next.example.test",
		fixture.publication(t, "next.example.test", "predecessor-next"), RecipeCopyOnly,
	)
	if err != nil || recovery.Valid() || !result.Valid() {
		t.Fatalf("ordinary-to-nd predecessor valid=%t recovery=%t error=%v",
			result.Valid(), recovery.Valid(), err)
	}
	output := releaseNextDomain(
		t, result, ticket, reversePath, forwardPaths,
		"predecessor-route", "predecessor-outbound",
	)
	return output, fixture.verifyRevision(
		t, output, reversePath, forwardPaths,
		RevisionVerificationTerminalNextDomainAuthorizationRequired,
	)
}

// TestPublicNextDomainContinuationOrdersReceiveBeforeSendAndCompletes proves
// ordinary-to-nd, nd-to-nd, and nd-to-ordinary with exact authorization order.
func TestPublicNextDomainContinuationOrdersReceiveBeforeSendAndCompletes(t *testing.T) {
	fixture := newNextDomainRegressionFixture(t)
	ctx := context.Background()
	raw := []byte("From: alice@example.test\r\nSubject: nd continuation\r\n\r\nbody\r\n")
	origin := fixture.signOrigin(
		t, raw, []byte("<bob@example.net>"), []SigningFlag{SigningFlagFeedback},
	)
	capability := fixture.verifyRevision(
		t, origin, []byte("<alice@example.test>"),
		[][]byte{[]byte("<bob@example.net>")}, RevisionVerificationVerified,
	)

	firstReverse := []byte("<relay@example.net>")
	firstForward := [][]byte{[]byte("<receiver@next.example.test>")}
	firstTicket := fixture.nextDomainTicket(
		t, capability, origin, firstReverse, firstForward, "nd-route-one", "receiver-one",
	)
	fixture.authorizer.reset()
	first, recovery, err := fixture.signNextDomain(
		t, capability, origin, firstReverse, firstForward, firstTicket,
		fixture.profile(t, "example.net", "relay-one"), "next.example.test",
		fixture.publication(t, "next.example.test", "next-one"), RecipeCopyOnly,
	)
	if err != nil || recovery.Valid() || !first.Valid() {
		t.Fatalf("ordinary-to-nd valid=%t recovery=%t error=%v", first.Valid(), recovery.Valid(), err)
	}
	firstRestricted, ok := first.OutOfBandAcceptance()
	if !ok || firstRestricted.Facts().Role() != SigningRoleHashUnchangedForwarder ||
		firstRestricted.Facts().RecipeOutcome() != SigningRecipeUnchanged ||
		firstRestricted.Facts().NewInstanceNumber() != 0 {
		t.Fatalf("ordinary-to-nd hash-gate facts ok=%t facts=%#v", ok, firstRestricted.Facts())
	}
	if got, want := fixture.authorizer.snapshot(), []SigningAuthorizationPurpose{
		SigningAuthorizationSendNextDomain,
		SigningAuthorizationPolicy,
		SigningAuthorizationFeedbackRelay,
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ordinary-to-nd authorization order = %v, want %v", got, want)
	}
	firstBytes := releaseNextDomain(
		t, first, firstTicket, firstReverse, firstForward, "nd-route-one", "receiver-one",
	)
	firstTerminal := fixture.verifyRevision(
		t, firstBytes, firstReverse, firstForward,
		RevisionVerificationTerminalNextDomainAuthorizationRequired,
	)

	secondReverse := []byte("<relay@next.example.test>")
	secondForward := [][]byte{[]byte("<receiver@future.example.test>")}
	secondTicket := fixture.nextDomainContinuationTicket(
		t, firstTerminal, firstBytes, secondReverse, secondForward,
		"nd-route-two", "receiver-one-inbound", "receiver-two-outbound",
	)
	fixture.authorizer.reset()
	fixture.authorizer.expectReceivers(
		[]byte("receiver-one-inbound"), []byte("receiver-two-outbound"),
	)
	second, recovery, err := fixture.signNextDomain(
		t, firstTerminal, firstBytes, secondReverse, secondForward, secondTicket,
		fixture.profile(t, "next.example.test", "relay-two"), "future.example.test",
		fixture.publication(t, "future.example.test", "next-two"), RecipeCopyOnly,
	)
	if err != nil || recovery.Valid() || !second.Valid() {
		t.Fatalf("nd-to-nd valid=%t recovery=%t error=%v", second.Valid(), recovery.Valid(), err)
	}
	if got, want := fixture.authorizer.snapshot(), []SigningAuthorizationPurpose{
		SigningAuthorizationReceiveNextDomain,
		SigningAuthorizationSendNextDomain,
		SigningAuthorizationPolicy,
		SigningAuthorizationFeedbackRelay,
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("nd-to-nd authorization order = %v, want %v", got, want)
	}
	if got, want := fixture.authorizer.oobSnapshot(), []nextDomainOOBObservation{
		{
			purpose: SigningAuthorizationReceiveNextDomain, reversePath: firstReverse,
			forwardPaths: firstForward, receiver: []byte("receiver-one-inbound"),
		},
		{
			purpose: SigningAuthorizationSendNextDomain, reversePath: secondReverse,
			forwardPaths: secondForward, receiver: []byte("receiver-two-outbound"),
		},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("nd-to-nd OOB evidence = %#v, want %#v", got, want)
	}
	secondRestricted, ok := second.OutOfBandAcceptance()
	if !ok || secondRestricted.Facts().EnvelopeForm() != SigningEnvelopeNextDomain ||
		secondRestricted.Facts().Restriction() != SigningRestrictionOutOfBandAcceptance ||
		secondRestricted.Facts().Role() != SigningRoleHashUnchangedForwarder ||
		secondRestricted.Facts().RecipeOutcome() != SigningRecipeUnchanged ||
		secondRestricted.Facts().NewInstanceNumber() != 0 {
		t.Fatalf("nd-to-nd result ok=%t facts=%#v", ok, secondRestricted.Facts())
	}
	secondBytes := releaseNextDomain(
		t, second, secondTicket, secondReverse, secondForward,
		"nd-route-two", "receiver-two-outbound",
	)
	secondTerminal := fixture.verifyRevision(
		t, secondBytes, secondReverse, secondForward,
		RevisionVerificationTerminalNextDomainAuthorizationRequired,
	)

	finalReverse := []byte("<relay@future.example.test>")
	finalForward := [][]byte{[]byte("<final@example.org>")}
	completionTicket := fixture.existingTicket(
		t, secondTerminal, secondBytes, finalReverse, finalForward,
		"completion-route", "receiver-three",
	)
	fixture.authorizer.reset()
	fixture.authorizer.expectReceivers([]byte("receiver-three"), nil)
	completedResult, completedRecovery, err := fixture.signer.SignExisting(
		ctx,
		NewExistingSigningRequest(
			secondTerminal, secondBytes, finalReverse, finalForward, completionTicket,
			fixture.profile(t, "future.example.test", "completion"), SigningMetadata{},
			SigningTransportFinalNetworkPreDotStuffing, RejectUnavailableBody, RecipeCopyOnly,
		),
	)
	if err != nil || completedRecovery.Valid() || !completedResult.Valid() {
		t.Fatalf("nd-to-ordinary valid=%t recovery=%t error=%v",
			completedResult.Valid(), completedRecovery.Valid(), err)
	}
	if got, want := fixture.authorizer.snapshot(), []SigningAuthorizationPurpose{
		SigningAuthorizationReceiveNextDomain,
		SigningAuthorizationPolicy,
		SigningAuthorizationFeedbackRelay,
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("nd-to-ordinary authorization order = %v, want %v", got, want)
	}
	if got, want := fixture.authorizer.oobSnapshot(), []nextDomainOOBObservation{
		{
			purpose: SigningAuthorizationReceiveNextDomain, reversePath: secondReverse,
			forwardPaths: secondForward, receiver: []byte("receiver-three"),
		},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("nd completion receive evidence = %#v, want %#v", got, want)
	}
	completed, ok := completedResult.Unrestricted()
	if !ok || completed.Facts().EnvelopeForm() != SigningEnvelopeOrdinary {
		t.Fatalf("nd completion ok=%t facts=%#v", ok, completed.Facts())
	}
	final := fixture.verifyRevision(
		t, completed.Bytes(), finalReverse, finalForward, RevisionVerificationVerified,
	)
	if !final.Valid() {
		t.Fatal("completed next-domain chain did not restore an ordinary revision capability")
	}
}

// TestPublicNextDomainContinuationKeepsInboundAndOutboundTrustEdgesDistinct
// rejects missing or purpose-confused receiver evidence before message release.
func TestPublicNextDomainContinuationKeepsInboundAndOutboundTrustEdgesDistinct(t *testing.T) {
	t.Run("role-specific constructors", func(t *testing.T) {
		fixture := newNextDomainRegressionFixture(t)
		raw := []byte("From: alice@example.test\r\nSubject: constructor matrix\r\n\r\nbody\r\n")
		origin := fixture.signOrigin(t, raw, []byte("<bob@example.net>"), nil)
		ordinaryCapability := fixture.verifyRevision(
			t, origin, []byte("<alice@example.test>"),
			[][]byte{[]byte("<bob@example.net>")}, RevisionVerificationVerified,
		)
		terminal, terminalCapability := prepareContinuationPredecessor(t, fixture)
		ordinarySource, err := NewSigningSource(origin)
		if err != nil {
			t.Fatalf("NewSigningSource(ordinary) error = %v", err)
		}
		terminalSource, err := NewSigningSource(terminal)
		if err != nil {
			t.Fatalf("NewSigningSource(terminal) error = %v", err)
		}
		reversePath := []byte("<relay@example.net>")
		forwardPaths := [][]byte{[]byte("<receiver@example.org>")}
		if _, err = NewNextDomainRouteEntry(
			terminalCapability, terminalSource, reversePath, forwardPaths,
			RouteDisclosureSingle, []byte("route"), []byte("outbound"),
		); err == nil {
			t.Fatal("creation constructor accepted a terminal capability")
		}
		if _, err = NewNextDomainContinuationRouteEntry(
			ordinaryCapability, ordinarySource, reversePath, forwardPaths,
			RouteDisclosureSingle, []byte("route"), []byte("inbound"), []byte("outbound"),
		); err == nil {
			t.Fatal("continuation constructor accepted an ordinary capability")
		}
		if _, err = NewExistingRouteEntry(
			terminalCapability, terminalSource, reversePath, forwardPaths,
			RouteDisclosureSingle, []byte("route"),
		); err == nil {
			t.Fatal("plain existing constructor accepted a terminal capability")
		}
		if _, err = NewReceiverBoundExistingRouteEntry(
			ordinaryCapability, ordinarySource, reversePath, forwardPaths,
			RouteDisclosureSingle, []byte("route"), []byte("inbound"),
		); err == nil {
			t.Fatal("receiver-bound existing constructor accepted an ordinary capability")
		}
	})

	t.Run("missing bindings", func(t *testing.T) {
		fixture := newNextDomainRegressionFixture(t)
		terminal, capability := prepareContinuationPredecessor(t, fixture)
		source, err := NewSigningSource(terminal)
		if err != nil {
			t.Fatalf("NewSigningSource() error = %v", err)
		}
		for _, testCase := range []struct {
			name     string
			inbound  []byte
			outbound []byte
		}{
			{name: "inbound", outbound: []byte("outbound")},
			{name: "outbound", inbound: []byte("inbound")},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				_, entryErr := NewNextDomainContinuationRouteEntry(
					capability, source, []byte("<relay@next.example.test>"),
					[][]byte{[]byte("<receiver@future.example.test>")},
					RouteDisclosureSingle, []byte("continuation-route"),
					testCase.inbound, testCase.outbound,
				)
				if entryErr == nil {
					t.Fatalf("missing %s binding produced a valid entry", testCase.name)
				}
			})
		}
	})

	for _, testCase := range []struct {
		name                string
		inbound             string
		outbound            string
		expectedPurposes    []SigningAuthorizationPurpose
		expectedRecoverable bool
	}{
		{
			name: "swapped", inbound: "expected-outbound", outbound: "expected-inbound",
			expectedPurposes:    []SigningAuthorizationPurpose{SigningAuthorizationReceiveNextDomain},
			expectedRecoverable: true,
		},
		{
			name: "wrong inbound", inbound: "wrong-inbound", outbound: "expected-outbound",
			expectedPurposes:    []SigningAuthorizationPurpose{SigningAuthorizationReceiveNextDomain},
			expectedRecoverable: true,
		},
		{
			name: "wrong outbound", inbound: "expected-inbound", outbound: "wrong-outbound",
			expectedPurposes: []SigningAuthorizationPurpose{
				SigningAuthorizationReceiveNextDomain, SigningAuthorizationSendNextDomain,
			},
			expectedRecoverable: true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newNextDomainRegressionFixture(t)
			terminal, capability := prepareContinuationPredecessor(t, fixture)
			reversePath := []byte("<relay@next.example.test>")
			forwardPaths := [][]byte{[]byte("<receiver@future.example.test>")}
			ticket := fixture.nextDomainContinuationTicket(
				t, capability, terminal, reversePath, forwardPaths,
				"continuation-route", testCase.inbound, testCase.outbound,
			)
			fixture.authorizer.reset()
			fixture.authorizer.expectReceivers(
				[]byte("expected-inbound"), []byte("expected-outbound"),
			)
			beforeSigns := fixture.provider.signs.Load()
			result, recovery, err := fixture.signNextDomain(
				t, capability, terminal, reversePath, forwardPaths, ticket,
				fixture.profile(t, "next.example.test", "continuation"),
				"future.example.test",
				fixture.publication(t, "future.example.test", "continuation-next"),
				RecipeCopyOnly,
			)
			if err == nil || result.Valid() || recovery.Valid() != testCase.expectedRecoverable {
				t.Fatalf("purpose-confused continuation valid=%t recovery=%t error=%v",
					result.Valid(), recovery.Valid(), err)
			}
			if got := fixture.authorizer.snapshot(); !reflect.DeepEqual(got, testCase.expectedPurposes) {
				t.Fatalf("authorization purposes = %v, want %v", got, testCase.expectedPurposes)
			}
			if fixture.provider.signs.Load() != beforeSigns {
				t.Fatal("purpose-confused receiver evidence reached private signing")
			}
		})
	}
}

// TestPublicNextDomainChangedContentUsesTheRevisionGate proves terminal output
// uses the same changed-message hash and inverse-recipe path as ordinary signing.
func TestPublicNextDomainChangedContentUsesTheRevisionGate(t *testing.T) {
	fixture := newNextDomainRegressionFixture(t)
	raw := []byte("From: alice@example.test\r\nSubject: before\r\n\r\nbody\r\n")
	origin := fixture.signOrigin(t, raw, []byte("<bob@example.net>"), nil)
	capability := fixture.verifyRevision(
		t, origin, []byte("<alice@example.test>"),
		[][]byte{[]byte("<bob@example.net>")}, RevisionVerificationVerified,
	)
	changed := bytes.Replace(origin, []byte("Subject: before\r\n"), []byte("Subject: after\r\n"), 1)
	if bytes.Equal(changed, origin) {
		t.Fatal("changed-content fixture did not change")
	}
	reversePath := []byte("<relay@example.net>")
	forwardPaths := [][]byte{[]byte("<receiver@next.example.test>")}
	ticket := fixture.nextDomainTicket(
		t, capability, changed, reversePath, forwardPaths, "changed-route", "changed-receiver",
	)
	result, recovery, err := fixture.signNextDomain(
		t, capability, changed, reversePath, forwardPaths, ticket,
		fixture.profile(t, "example.net", "changed"), "next.example.test",
		fixture.publication(t, "next.example.test", "changed-next"), RecipeAllowLiterals,
	)
	if err != nil || recovery.Valid() || !result.Valid() {
		t.Fatalf("changed next-domain valid=%t recovery=%t error=%v",
			result.Valid(), recovery.Valid(), err)
	}
	terminal, ok := result.OutOfBandAcceptance()
	if !ok || terminal.Facts().Role() != SigningRoleReviser ||
		terminal.Facts().RecipeOutcome() != SigningRecipeGenerated ||
		terminal.Facts().NewInstanceNumber() != 2 {
		t.Fatalf("changed next-domain facts ok=%t facts=%#v", ok, terminal.Facts())
	}
	output := releaseNextDomain(
		t, result, ticket, reversePath, forwardPaths, "changed-route", "changed-receiver",
	)
	fixture.verifyRevision(
		t, output, reversePath, forwardPaths,
		RevisionVerificationTerminalNextDomainAuthorizationRequired,
	)
}

// TestPublicNextDomainRejectsRelaxedAndOlderPredecessorDomains proves only the
// immediate predecessor's exact canonical domain can authorize terminal creation.
func TestPublicNextDomainRejectsRelaxedAndOlderPredecessorDomains(t *testing.T) {
	t.Run("relaxed suffix", func(t *testing.T) {
		assertNextDomainDomainNearMiss(
			t, "<bob@example.net>", "sub.example.net", "relaxed",
		)
	})

	t.Run("relaxed parent", func(t *testing.T) {
		assertNextDomainDomainNearMiss(
			t, "<bob@sub.example.net>", "example.net", "parent",
		)
	})

	t.Run("older hop only", func(t *testing.T) {
		fixture := newNextDomainRegressionFixture(t)
		raw := []byte("From: alice@example.test\r\nSubject: older hop\r\n\r\nbody\r\n")
		origin := fixture.signOrigin(t, raw, []byte("<bob@example.net>"), nil)
		originCapability := fixture.verifyRevision(
			t, origin, []byte("<alice@example.test>"),
			[][]byte{[]byte("<bob@example.net>")}, RevisionVerificationVerified,
		)
		ordinaryReverse := []byte("<relay@example.net>")
		ordinaryForward := [][]byte{[]byte("<next@immediate.test>")}
		ordinaryTicket := fixture.existingTicket(
			t, originCapability, origin, ordinaryReverse, ordinaryForward, "ordinary-route", "",
		)
		ordinaryResult, recovery, err := fixture.signer.SignExisting(
			context.Background(),
			NewExistingSigningRequest(
				originCapability, origin, ordinaryReverse, ordinaryForward, ordinaryTicket,
				fixture.profile(t, "example.net", "ordinary-two"), SigningMetadata{},
				SigningTransportFinalNetworkPreDotStuffing, RejectUnavailableBody, RecipeCopyOnly,
			),
		)
		if err != nil || recovery.Valid() {
			t.Fatalf("ordinary predecessor recovery=%t error=%v", recovery.Valid(), err)
		}
		ordinary, ok := ordinaryResult.Unrestricted()
		if !ok {
			t.Fatal("ordinary predecessor did not expose bytes")
		}
		ordinaryCapability := fixture.verifyRevision(
			t, ordinary.Bytes(), ordinaryReverse, ordinaryForward, RevisionVerificationVerified,
		)
		nextReverse := []byte("<relay@example.net>")
		nextForward := [][]byte{[]byte("<receiver@future.test>")}
		nextTicket := fixture.nextDomainTicket(
			t, ordinaryCapability, ordinary.Bytes(), nextReverse, nextForward,
			"older-route", "older-receiver",
		)
		beforeSigns := fixture.provider.signs.Load()
		fixture.authorizer.reset()
		result, recovery, err := fixture.signNextDomain(
			t, ordinaryCapability, ordinary.Bytes(), nextReverse, nextForward, nextTicket,
			fixture.profile(t, "example.net", "older-match"), "future.test",
			fixture.publication(t, "future.test", "older-next"), RecipeCopyOnly,
		)
		if err == nil || result.Valid() || recovery.Valid() {
			t.Fatalf("older-hop match valid=%t recovery=%t error=%v", result.Valid(), recovery.Valid(), err)
		}
		if fixture.provider.signs.Load() != beforeSigns || len(fixture.authorizer.snapshot()) != 0 {
			t.Fatal("older-hop-only match crossed authorization or private-signing boundary")
		}
	})
}

// assertNextDomainDomainNearMiss proves one exact-equality direction fails before callbacks.
func assertNextDomainDomainNearMiss(
	t *testing.T,
	predecessorRecipient, profileDomain, marker string,
) {
	t.Helper()
	fixture := newNextDomainRegressionFixture(t)
	raw := []byte("From: alice@example.test\r\nSubject: exact domain\r\n\r\nbody\r\n")
	recipient := []byte(predecessorRecipient)
	origin := fixture.signOrigin(t, raw, recipient, nil)
	capability := fixture.verifyRevision(
		t, origin, []byte("<alice@example.test>"),
		[][]byte{recipient}, RevisionVerificationVerified,
	)
	reversePath := []byte("<relay@" + profileDomain + ">")
	forwardPaths := [][]byte{[]byte("<receiver@next.example.test>")}
	ticket := fixture.nextDomainTicket(
		t, capability, origin, reversePath, forwardPaths,
		marker+"-route", marker+"-receiver",
	)
	beforeSigns := fixture.provider.signs.Load()
	fixture.authorizer.reset()
	result, recovery, err := fixture.signNextDomain(
		t, capability, origin, reversePath, forwardPaths, ticket,
		fixture.profile(t, profileDomain, marker), "next.example.test",
		fixture.publication(t, "next.example.test", marker+"-next"), RecipeCopyOnly,
	)
	if err == nil || result.Valid() || recovery.Valid() {
		t.Fatalf("domain near-miss valid=%t recovery=%t error=%v",
			result.Valid(), recovery.Valid(), err)
	}
	if fixture.provider.signs.Load() != beforeSigns ||
		len(fixture.authorizer.snapshot()) != 0 {
		t.Fatal("domain near-miss crossed authorization or private-signing boundary")
	}
}

// TestPublicNextDomainPublicationReuseAndDriftFailBeforeAuthorization proves
// publication evidence is fresh, single-use, and exactly revalidated.
func TestPublicNextDomainPublicationReuseAndDriftFailBeforeAuthorization(t *testing.T) {
	t.Run("reuse", func(t *testing.T) {
		fixture := newNextDomainRegressionFixture(t)
		raw := []byte("From: alice@example.test\r\nSubject: publication reuse\r\n\r\nbody\r\n")
		origin := fixture.signOrigin(t, raw, []byte("<bob@example.net>"), nil)
		capability := fixture.verifyRevision(
			t, origin, []byte("<alice@example.test>"),
			[][]byte{[]byte("<bob@example.net>")}, RevisionVerificationVerified,
		)
		profile := fixture.profile(t, "example.net", "reuse")
		published := fixture.publication(t, "next.example.test", "reuse-next")
		reversePath := []byte("<relay@example.net>")
		forwardPaths := [][]byte{[]byte("<receiver@next.example.test>")}
		firstTicket := fixture.nextDomainTicket(
			t, capability, origin, reversePath, forwardPaths, "reuse-route-one", "reuse-receiver-one",
		)
		first, recovery, err := fixture.signNextDomain(
			t, capability, origin, reversePath, forwardPaths, firstTicket,
			profile, "next.example.test", published, RecipeCopyOnly,
		)
		if err != nil || recovery.Valid() || !first.Valid() {
			t.Fatalf("first publication use valid=%t recovery=%t error=%v", first.Valid(), recovery.Valid(), err)
		}
		secondTicket := fixture.nextDomainTicket(
			t, capability, origin, reversePath, forwardPaths, "reuse-route-two", "reuse-receiver-two",
		)
		beforeSigns := fixture.provider.signs.Load()
		beforeAuthorizations := len(fixture.authorizer.snapshot())
		second, secondRecovery, secondErr := fixture.signNextDomain(
			t, capability, origin, reversePath, forwardPaths, secondTicket,
			profile, "next.example.test", published, RecipeCopyOnly,
		)
		if secondErr == nil || second.Valid() || secondRecovery.Valid() {
			t.Fatalf("publication reuse valid=%t recovery=%t error=%v",
				second.Valid(), secondRecovery.Valid(), secondErr)
		}
		if fixture.provider.signs.Load() != beforeSigns ||
			len(fixture.authorizer.snapshot()) != beforeAuthorizations {
			t.Fatal("consumed publication crossed authorization or private-signing boundary")
		}
	})

	t.Run("drift", func(t *testing.T) {
		const selector = "drift-next"
		fixture, provider := newNextDomainDriftFixture(t, selector)
		raw := []byte("From: alice@example.test\r\nSubject: publication drift\r\n\r\nbody\r\n")
		origin := fixture.signOrigin(t, raw, []byte("<bob@example.net>"), nil)
		capability := fixture.verifyRevision(
			t, origin, []byte("<alice@example.test>"),
			[][]byte{[]byte("<bob@example.net>")}, RevisionVerificationVerified,
		)
		published := fixture.publication(t, "next.example.test", selector)
		reversePath := []byte("<relay@example.net>")
		forwardPaths := [][]byte{[]byte("<receiver@next.example.test>")}
		ticket := fixture.nextDomainTicket(
			t, capability, origin, reversePath, forwardPaths, "drift-route", "drift-receiver",
		)
		provider.drift.Store(true)
		beforeSigns := fixture.provider.signs.Load()
		fixture.authorizer.reset()
		result, recovery, err := fixture.signNextDomain(
			t, capability, origin, reversePath, forwardPaths, ticket,
			fixture.profile(t, "example.net", "stable-profile"), "next.example.test",
			published, RecipeCopyOnly,
		)
		if err == nil || result.Valid() || !recovery.Valid() {
			t.Fatalf("publication drift valid=%t recovery=%t error=%v",
				result.Valid(), recovery.Valid(), err)
		}
		if fixture.provider.signs.Load() != beforeSigns || len(fixture.authorizer.snapshot()) != 0 {
			t.Fatal("publication drift crossed authorization or private-signing boundary")
		}
	})

	for _, status := range []PublicKeyStatus{
		PublicKeyStatusMissing,
		PublicKeyStatusRevoked,
	} {
		t.Run(string(status), func(t *testing.T) {
			const selector = "unavailable-next"
			fixture, provider := newNextDomainDriftFixture(t, selector)
			provider.status = status
			provider.drift.Store(true)
			handle, err := NewPrivateKeyHandle([]byte("unavailable-publication"))
			if err != nil {
				t.Fatalf("NewPrivateKeyHandle() error = %v", err)
			}
			credential, err := NewRSASigningCredential(
				selector, &fixture.rsaKey.PublicKey, handle,
			)
			if err != nil {
				t.Fatalf("NewRSASigningCredential() error = %v", err)
			}
			published, issueErr := fixture.signer.IssueNextDomainPublication(
				context.Background(),
				NewRSANextDomainPublicationRequest("next.example.test", credential),
			)
			if issueErr == nil || published.Valid() {
				t.Fatalf("publication status %q valid=%t error=%v",
					status, published.Valid(), issueErr)
			}
		})
	}

	t.Run("expired", func(t *testing.T) {
		fixture := newNextDomainRegressionFixture(t)
		raw := []byte("From: alice@example.test\r\nSubject: publication expiry\r\n\r\nbody\r\n")
		origin := fixture.signOrigin(t, raw, []byte("<bob@example.net>"), nil)
		capability := fixture.verifyRevision(
			t, origin, []byte("<alice@example.test>"),
			[][]byte{[]byte("<bob@example.net>")}, RevisionVerificationVerified,
		)
		published := fixture.publication(t, "next.example.test", "expired-next")
		reversePath := []byte("<relay@example.net>")
		forwardPaths := [][]byte{[]byte("<receiver@next.example.test>")}
		ticket := fixture.nextDomainTicket(
			t, capability, origin, reversePath, forwardPaths, "expired-route", "expired-receiver",
		)
		fixture.clock.Add(int64((5*time.Minute + time.Second) / time.Second))
		beforeSigns := fixture.provider.signs.Load()
		fixture.authorizer.reset()
		result, recovery, err := fixture.signNextDomain(
			t, capability, origin, reversePath, forwardPaths, ticket,
			fixture.profile(t, "example.net", "expired"), "next.example.test",
			published, RecipeCopyOnly,
		)
		if err == nil || result.Valid() || recovery.Valid() {
			t.Fatalf("expired publication valid=%t recovery=%t error=%v",
				result.Valid(), recovery.Valid(), err)
		}
		if fixture.provider.signs.Load() != beforeSigns || len(fixture.authorizer.snapshot()) != 0 {
			t.Fatal("expired publication crossed authorization or private-signing boundary")
		}
	})
}

// TestPublicNextDomainSigningSamplesOnePlanOwnedInstant proves publication
// freshness cannot observe a second, already-expired signing-time clock sample.
func TestPublicNextDomainSigningSamplesOnePlanOwnedInstant(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	clock := &adversarialNextDomainClock{stable: base}
	fixture := newNextDomainRegressionFixtureWithClock(t, clock.now)
	raw := []byte("From: alice@example.test\r\nSubject: one instant\r\n\r\nbody\r\n")
	origin := fixture.signOrigin(t, raw, []byte("<bob@example.net>"), nil)
	capability := fixture.verifyRevision(
		t, origin, []byte("<alice@example.test>"),
		[][]byte{[]byte("<bob@example.net>")}, RevisionVerificationVerified,
	)

	clock.arm(base, base)
	published := fixture.publication(t, "next.example.test", "one-clock-next")
	if got := clock.callCount(); got != 1 {
		t.Fatalf("publication issue clock calls = %d, want 1", got)
	}
	reversePath := []byte("<relay@example.net>")
	forwardPaths := [][]byte{[]byte("<receiver@next.example.test>")}
	ticket := fixture.nextDomainTicket(
		t, capability, origin, reversePath, forwardPaths, "one-clock-route", "one-clock-receiver",
	)

	clock.arm(base.Add(5*time.Minute-time.Second), base.Add(5*time.Minute+time.Second))
	result, recovery, err := fixture.signNextDomain(
		t, capability, origin, reversePath, forwardPaths, ticket,
		fixture.profile(t, "example.net", "one-clock"), "next.example.test",
		published, RecipeCopyOnly,
	)
	if err != nil || recovery.Valid() || !result.Valid() {
		t.Fatalf("one-clock signing valid=%t recovery=%t error=%v",
			result.Valid(), recovery.Valid(), err)
	}
	if got := clock.callCount(); got != 1 {
		t.Fatalf("signing operation clock calls = %d, want exactly 1", got)
	}
}

// TestPublicNextDomainRejectsOutOfBandAndLocalOnlyConflict proves an OOB
// terminal route cannot be downgraded into a locally releasable result.
func TestPublicNextDomainRejectsOutOfBandAndLocalOnlyConflict(t *testing.T) {
	fixture := newNextDomainRegressionFixture(t)
	raw := []byte("From: alice@example.test\r\nSubject: protected\r\n\r\nbody\r\n")
	origin := fixture.signOrigin(
		t, raw, []byte("<bob@example.net>"), []SigningFlag{SigningFlagDoNotModify},
	)
	capability := fixture.verifyRevision(
		t, origin, []byte("<alice@example.test>"),
		[][]byte{[]byte("<bob@example.net>")}, RevisionVerificationVerified,
	)
	changed := bytes.Replace(origin, []byte("Subject: protected\r\n"), []byte("Subject: changed\r\n"), 1)
	reversePath := []byte("<relay@example.net>")
	forwardPaths := [][]byte{[]byte("<receiver@next.example.test>")}
	ticket := fixture.nextDomainTicket(
		t, capability, changed, reversePath, forwardPaths, "conflict-route", "conflict-receiver",
	)
	beforeSigns := fixture.provider.signs.Load()
	fixture.authorizer.reset()
	result, recovery, err := fixture.signNextDomain(
		t, capability, changed, reversePath, forwardPaths, ticket,
		fixture.profile(t, "example.net", "conflict"), "next.example.test",
		fixture.publication(t, "next.example.test", "conflict-next"), RecipeAllowLiterals,
	)
	if err == nil || result.Valid() || recovery.Valid() {
		t.Fatalf("OOB/local conflict valid=%t recovery=%t error=%v",
			result.Valid(), recovery.Valid(), err)
	}
	if got := fixture.authorizer.snapshot(); len(got) != 0 {
		t.Fatalf("OOB/local conflict crossed authorization boundary: %v", got)
	}
	if fixture.provider.signs.Load() != beforeSigns {
		t.Fatal("OOB/local conflict reached private signing")
	}
}
