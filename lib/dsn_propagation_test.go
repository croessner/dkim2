package dkim2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/dsn"
	"github.com/croessner/dkim2/internal/dsn/dsntest"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/routeplan"
	"github.com/croessner/dkim2/internal/signature"
)

const (
	propagationReportingMTA      = "mta.local.example"
	propagationPreviousSender    = "<sender@remote.example>"
	propagationSigningSelector   = "dsn"
	propagationSigningClock      = int64(dsntest.DefaultTimestamp) + 3600
	propagationOriginHeaders     = "From: sender@remote.example\r\nSubject: origin\r\nMessage-ID: <origin@remote.example>\r\n"
	propagationOriginBody        = "origin body\r\n"
	propagationCurrentHeaders    = "From: sender@remote.example\r\nSubject: forwarded\r\nMessage-ID: <origin@remote.example>\r\n"
	propagationCurrentBody       = "forwarded body\r\n"
	propagationFullRecipe        = `{"h":{"subject":[{"d":[" origin"]}]},"b":[{"d":["origin body"]}]}`
	propagationHeaderRecipe      = `{"h":{"subject":[{"d":[" origin"]}]}}`
	propagationBodyRecipe        = `{"b":[{"d":["origin body"]}]}`
	propagationNullRecipe        = `{"h":{"subject":[{"d":[" origin"]}]},"b":null}`
	propagationEntropySeed       = "dkim2-propagation-test-entropy"
	propagationUpstreamMarker    = "UPSTREAM-DIAGNOSTIC-MARKER"
	propagationTestPrivateMarker = "PROPAGATION-PRIVATE-MARKER"
)

// propagationSigningKey is the delivery_status profile key of local.example.
func propagationSigningKey(domain string) dsntest.Key {
	return dsntest.KeyForLabel(domain+"-delivery-status", propagationSigningSelector)
}

// propagationProvider serves fixture verification keys and signs with the
// delivery_status keys of the local domains through the public callbacks.
type propagationProvider struct {
	temporaryDomain string
	handles         map[string]dsntest.Key
	lookups         int
	signs           int
	mu              sync.Mutex
}

// newPropagationProvider registers the delivery_status handles of the named domains.
func newPropagationProvider(domains ...string) *propagationProvider {
	provider := &propagationProvider{handles: make(map[string]dsntest.Key)}
	for _, domain := range domains {
		provider.handles[domain] = propagationSigningKey(domain)
	}
	return provider
}

// LookupPublicKey implements PublicKeyProvider for fixture and signing keys.
func (p *propagationProvider) LookupPublicKey(_ context.Context, query PublicKeyQuery) (PublicKeyResult, error) {
	p.mu.Lock()
	p.lookups++
	p.mu.Unlock()
	if p.temporaryDomain != "" && query.SigningDomain() == p.temporaryDomain {
		return PublicKeyResult{}, NewTemporaryProviderError()
	}
	if query.Algorithm() != AlgorithmEd25519SHA256 {
		return MissingPublicKey(query.Algorithm()), nil
	}
	if query.Selector() == propagationSigningSelector {
		if key, ok := p.handles[query.SigningDomain()]; ok {
			return FoundEd25519PublicKey(key.Public()), nil
		}
		return MissingPublicKey(query.Algorithm()), nil
	}
	key, ok := receivedDSNKeys()[query.SigningDomain()]
	if !ok || key.Selector != query.Selector() {
		return MissingPublicKey(query.Algorithm()), nil
	}
	return FoundEd25519PublicKey(key.Public()), nil
}

// SignDigest implements PrivateKeySigner by resolving the handle to a fixture domain key.
func (p *propagationProvider) SignDigest(_ context.Context, handle PrivateKeyHandle, request PrivateKeySignRequest) (PrivateKeySignResult, error) {
	p.mu.Lock()
	p.signs++
	p.mu.Unlock()
	for domain, key := range p.handles {
		expected, err := NewPrivateKeyHandle([]byte("handle:" + domain))
		if err != nil || expected != handle || request.Algorithm() != AlgorithmEd25519SHA256 {
			continue
		}
		digest := request.Digest()
		return NewPrivateKeySignResult(ed25519.Sign(key.Private, digest[:])), nil
	}
	return PrivateKeySignResult{}, errors.New("unknown handle")
}

// propagationFixture wires one Signer over the fixture provider.
type propagationFixture struct {
	signer   *Signer
	provider *propagationProvider
	profiles map[string]SigningProfile
}

// newPropagationFixture constructs the signer with a fixed clock and deterministic entropy.
func newPropagationFixture(t *testing.T, provider *propagationProvider) propagationFixture {
	t.Helper()
	signer, err := NewSigner(provider, NewRequestRouteAuthority(), &authorizeOrdinary{}, provider,
		WithSigningClock(func() time.Time { return time.Unix(propagationSigningClock, 0) }))
	if err != nil {
		t.Fatalf("NewSigner() error=%v", err)
	}
	profiles := make(map[string]SigningProfile)
	for domain, key := range provider.handles {
		handle, err := NewPrivateKeyHandle([]byte("handle:" + domain))
		if err != nil {
			t.Fatal(err)
		}
		credential, err := NewEd25519SigningCredential(propagationSigningSelector, key.Public(), handle)
		if err != nil {
			t.Fatal(err)
		}
		profile, err := NewEd25519SigningProfile(domain, credential)
		if err != nil {
			t.Fatal(err)
		}
		profiles[domain] = profile
	}
	return propagationFixture{signer: signer, provider: provider, profiles: profiles}
}

// deterministicEntropy returns a reader that yields a fixed byte sequence derived from seed.
func deterministicEntropy(seed string) *seededReader { return &seededReader{seed: []byte(seed)} }

// seededReader is a deterministic entropy source for fixtures.
type seededReader struct {
	seed    []byte
	counter uint64
	mu      sync.Mutex
}

// Read fills output with bytes derived from the seed and a counter.
func (r *seededReader) Read(output []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index := range output {
		output[index] = r.seed[int(r.counter)%len(r.seed)] ^ byte(r.counter*7)
		r.counter++
	}
	return len(output), nil
}

// propagationOriginal returns the forwarded two-instance chain with the given recipe.
func propagationOriginal(recipeJSON string) dsntest.Original {
	local := receivedDSNHop(receivedDSNLocalDomain, receivedDSNLocalMailFrom, receivedDSNDestination)
	local.Instance = 2
	local.Timestamp = dsntest.DefaultTimestamp + 60
	return dsntest.Original{
		Headers: propagationCurrentHeaders, Body: propagationCurrentBody,
		Revisions: []dsntest.Revision{{Headers: propagationOriginHeaders, Body: propagationOriginBody, Recipe: recipeJSON}},
		Hops: []dsntest.Hop{
			receivedDSNHop(receivedDSNRemoteDomain, propagationPreviousSender, receivedDSNLocalRecipient),
			local,
		},
	}
}

// propagationTwoHopOriginal returns a chain whose previous hop is i=2: the
// origin at other.example signed m=1 towards remote.example, remote.example
// forwarded the unchanged instance as i=2, and the local hop completed with
// m=2 and the given recipe. originRecipient is the origin's rt= path, which
// links or breaks the custody chain below the previous hop.
func propagationTwoHopOriginal(recipeJSON string, originRecipient string) dsntest.Original {
	original := propagationOriginal(recipeJSON)
	origin := receivedDSNHop(receivedDSNOtherDomain, "<origin@other.example>", originRecipient)
	original.Hops = []dsntest.Hop{origin, original.Hops[0], original.Hops[1]}
	return original
}

// propagationCase describes one received DSN at the facade level.
type propagationCase struct {
	original       dsntest.Original
	headersOnly    bool
	deliveryStatus string
	outerRecipient string
	outerSigner    string
	local          []string
	reportingMTA   string
	// mutate optionally rewrites the built original bytes before they are embedded.
	mutate func([]byte) []byte
}

// recipient returns the observed outer recipient of the case.
func (c propagationCase) recipient() string {
	if c.outerRecipient == "" {
		return receivedDSNLocalMailFrom
	}
	return c.outerRecipient
}

// localDomains returns the tenant's local authority domains for the case.
func (c propagationCase) localDomains() []string {
	if c.local == nil {
		return []string{receivedDSNLocalDomain}
	}
	return c.local
}

// mta returns the reporting MTA of the case.
func (c propagationCase) mta() string {
	if c.reportingMTA == "" {
		return propagationReportingMTA
	}
	return c.reportingMTA
}

// build renders the received DSN bytes.
func (c propagationCase) build(t testing.TB) []byte {
	t.Helper()
	original, err := c.original.Build()
	if err != nil {
		t.Fatalf("Original.Build() error=%v", err)
	}
	if c.mutate != nil {
		original = c.mutate(original)
	}
	contentType := "message/rfc822"
	if c.headersOnly {
		contentType = "text/rfc822-headers"
		original = dsntest.HeaderBlock(original)
	}
	deliveryStatus := c.deliveryStatus
	if deliveryStatus == "" {
		deliveryStatus = dsntest.FailedDeliveryStatus(receivedDSNDestinationDomain, receivedDSNDestinationRaw, "5.1.1")
	}
	signerDomain := c.outerSigner
	if signerDomain == "" {
		signerDomain = receivedDSNDestinationDomain
	}
	signer := receivedDSNHop(signerDomain, "<>", c.recipient())
	signer.Timestamp = dsntest.DefaultTimestamp + 120
	raw, err := (dsntest.Report{
		OuterHeaders:        "Received: from destination (" + propagationUpstreamMarker + ")\r\nFrom: MAILER-DAEMON@" + signerDomain + "\r\nSubject: Undelivered Mail\r\n",
		Human:               "human readable " + propagationUpstreamMarker,
		DeliveryStatus:      deliveryStatus,
		OriginalContentType: contentType,
		Original:            original,
		Signer:              &signer,
	}).Build()
	if err != nil {
		t.Fatalf("Report.Build() error=%v", err)
	}
	return raw
}

// request builds the propagation request of the case with the default deterministic identifier entropy.
func (c propagationCase) request(t testing.TB) DSNPropagationRequest {
	t.Helper()
	return c.requestWithEntropy(t, propagationEntropySeed)
}

// requestWithEntropy builds the propagation request with identifier entropy seeded by seed.
func (c propagationCase) requestWithEntropy(t testing.TB, seed string) DSNPropagationRequest {
	t.Helper()
	request := NewDSNPropagationRequest(c.build(t), []byte("<>"), [][]byte{[]byte(c.recipient())}, newReceivedDSNAuthority(c.localDomains()...), c.mta())
	request.state.entropy = deterministicEntropy(seed)
	return request
}

// mustRebuild rebuilds the case and requires the rebuilt outcome.
func (f propagationFixture) mustRebuild(t testing.TB, testCase propagationCase) DSNPropagationEvidence {
	t.Helper()
	evidence, err := f.signer.RebuildDSNForPropagation(context.Background(), testCase.request(t))
	if err != nil || !evidence.Valid() || evidence.Outcome() != DSNPropagationRebuilt {
		t.Fatalf("RebuildDSNForPropagation() outcome=%q valid=%t evaluation=%q error=%v", evidence.Outcome(), evidence.Valid(), evidence.Evaluation().Propagation(), err)
	}
	return evidence
}

// ticket plans one propagation route ticket for the evidence.
func (f propagationFixture) ticket(t testing.TB, evidence DSNPropagationEvidence) RouteCopyTicket {
	t.Helper()
	source, err := NewSigningSource(evidence.state.report.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	entry, err := NewDeliveryStatusPropagationRouteEntry(source, []byte("<>"), [][]byte{evidence.NextHopRecipient()}, []byte("propagation-route"))
	if err != nil {
		t.Fatalf("NewDeliveryStatusPropagationRouteEntry() error=%v", err)
	}
	request, err := NewRouteFanoutRequest([]RouteEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	_, tickets, err := f.signer.PlanRouteFanout(context.Background(), request)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout() tickets=%d error=%v", len(tickets), err)
	}
	return tickets[0]
}

// mustSign signs the evidence with the profile of its signing domain.
func (f propagationFixture) mustSign(t testing.TB, evidence DSNPropagationEvidence) PropagatedDSN {
	t.Helper()
	propagated, recovery, err := f.signer.SignPropagatedDSN(context.Background(), NewDSNPropagationSigningRequest(
		evidence, f.ticket(t, evidence), f.profiles[evidence.SigningDomain()], SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
	))
	if err != nil || recovery.Valid() || !propagated.Valid() {
		t.Fatalf("SignPropagatedDSN() valid=%t recovery=%t error=%v", propagated.Valid(), recovery.Valid(), err)
	}
	return propagated
}

// TestRebuildDSNForPropagationDerivesAuthorityFromCompletionSignature proves
// the evidence carries the removed completion signature's domain, the
// authenticated previous mf=, and the evaluation, and that a caller cannot
// select any of them.
func TestRebuildDSNForPropagationDerivesAuthorityFromCompletionSignature(t *testing.T) {
	fixture := newPropagationFixture(t, newPropagationProvider(receivedDSNLocalDomain))
	evidence := fixture.mustRebuild(t, propagationCase{original: propagationOriginal(propagationFullRecipe)})
	if evidence.SigningDomain() != receivedDSNLocalDomain || !bytes.Equal(evidence.NextHopRecipient(), []byte(propagationPreviousSender)) ||
		evidence.SMTPUTF8Required() || evidence.OriginalForm() != ReceivedDSNOriginalComplete || !evidence.Rebuilt() {
		t.Fatalf("evidence domain=%q next=%q smtputf8=%t form=%q", evidence.SigningDomain(), evidence.NextHopRecipient(), evidence.SMTPUTF8Required(), evidence.OriginalForm())
	}
	evaluation := evidence.Evaluation()
	if !evaluation.Valid() || evaluation.Propagation() != ReceivedDSNPropagationEligible || evaluation.LocalHop() != ReceivedDSNLocalHopLocal {
		t.Fatalf("evaluation propagation=%q local_hop=%q", evaluation.Propagation(), evaluation.LocalHop())
	}
	next := evidence.NextHopRecipient()
	next[1] = 'X'
	if bytes.Equal(evidence.NextHopRecipient(), next) {
		t.Fatal("NextHopRecipient() exposed shared storage")
	}
	headersOnly := fixture.mustRebuild(t, propagationCase{original: propagationOriginal(propagationHeaderRecipe), headersOnly: true})
	if headersOnly.OriginalForm() != ReceivedDSNOriginalHeadersOnly {
		t.Fatalf("headers-only form=%q", headersOnly.OriginalForm())
	}
	nextDomainRun := propagationOriginal(propagationFullRecipe)
	member := receivedDSNNextDomainHop(receivedDSNLocalDomain, receivedDSNForwardDomain)
	member.Instance = 2
	completion := receivedDSNHop(receivedDSNForwardDomain, receivedDSNForwardMailFrom, receivedDSNDestination)
	completion.Instance = 2
	nextDomainRun.Hops = []dsntest.Hop{nextDomainRun.Hops[0], member, completion}
	forwardFixture := newPropagationFixture(t, newPropagationProvider(receivedDSNLocalDomain, receivedDSNForwardDomain))
	runEvidence := forwardFixture.mustRebuild(t, propagationCase{original: nextDomainRun, outerRecipient: receivedDSNForwardMailFrom, local: []string{receivedDSNLocalDomain, receivedDSNForwardDomain}})
	if runEvidence.SigningDomain() != receivedDSNForwardDomain || runEvidence.Evaluation().LocalHopRunLength() != 2 {
		t.Fatalf("run evidence domain=%q run=%d", runEvidence.SigningDomain(), runEvidence.Evaluation().LocalHopRunLength())
	}
}

// TestRebuildDSNForPropagationReportsIneligibleAndFailedOutcomes proves
// ineligible evaluations, non-reconstructable chains, and temporary key
// failures are typed outcomes that carry the evaluation and no output.
func TestRebuildDSNForPropagationReportsIneligibleAndFailedOutcomes(t *testing.T) {
	fixture := newPropagationFixture(t, newPropagationProvider(receivedDSNLocalDomain))
	notLocal, err := fixture.signer.RebuildDSNForPropagation(context.Background(), propagationCase{original: propagationOriginal(propagationFullRecipe), local: []string{receivedDSNOtherDomain}}.request(t))
	if err != nil || !notLocal.Valid() || notLocal.Outcome() != DSNPropagationNotEligible || notLocal.Rebuilt() ||
		notLocal.Evaluation().LocalHop() != ReceivedDSNLocalHopNotLocal || notLocal.SigningDomain() != "" || notLocal.NextHopRecipient() != nil {
		t.Fatalf("not local outcome=%q local_hop=%q error=%v", notLocal.Outcome(), notLocal.Evaluation().LocalHop(), err)
	}
	nullSender := propagationOriginal(propagationFullRecipe)
	nullSender.Hops[0].MailFrom = "<>"
	forbidden, err := fixture.signer.RebuildDSNForPropagation(context.Background(), propagationCase{original: nullSender}.request(t))
	if err != nil || forbidden.Outcome() != DSNPropagationNotEligible || forbidden.Evaluation().Propagation() != ReceivedDSNPropagationForbiddenNullPreviousSender {
		t.Fatalf("null sender outcome=%q propagation=%q error=%v", forbidden.Outcome(), forbidden.Evaluation().Propagation(), err)
	}
	corrupt := propagationOriginal(propagationFullRecipe)
	corrupt.Hops[0].CorruptSignature = true
	unverified, err := fixture.signer.RebuildDSNForPropagation(context.Background(), propagationCase{original: corrupt}.request(t))
	if err != nil || unverified.Outcome() != DSNPropagationNotReconstructable || unverified.Evaluation().Propagation() != ReceivedDSNPropagationEligible || unverified.Rebuilt() {
		t.Fatalf("corrupt previous hop outcome=%q error=%v", unverified.Outcome(), err)
	}
	temporary := newPropagationFixture(t, &propagationProvider{temporaryDomain: receivedDSNRemoteDomain, handles: map[string]dsntest.Key{receivedDSNLocalDomain: propagationSigningKey(receivedDSNLocalDomain)}})
	temperror, err := temporary.signer.RebuildDSNForPropagation(context.Background(), propagationCase{original: propagationOriginal(propagationFullRecipe)}.request(t))
	if err != nil || temperror.Outcome() != DSNPropagationTemporaryError || temperror.Rebuilt() {
		t.Fatalf("temporary outcome=%q error=%v", temperror.Outcome(), err)
	}
	if _, _, err := fixture.signer.SignPropagatedDSN(context.Background(), NewDSNPropagationSigningRequest(
		notLocal, RouteCopyTicket{}, fixture.profiles[receivedDSNLocalDomain], SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
	)); !errors.Is(err, newSigningError(SigningErrorInvalidRequest)) {
		t.Fatalf("signing ineligible evidence error=%v", err)
	}
}

// TestRebuildDSNForPropagationCustodyBelowPreviousHop proves a previous hop
// at i=2 rebuilds when the chain below it links, and that a broken link
// below the previous hop never yields a rebuilt report: the embedded
// verification of the current target rejects the chain first, and the
// historical seam reports custody_rejected for any chain that reached it.
func TestRebuildDSNForPropagationCustodyBelowPreviousHop(t *testing.T) {
	fixture := newPropagationFixture(t, newPropagationProvider(receivedDSNLocalDomain))
	linked := fixture.mustRebuild(t, propagationCase{original: propagationTwoHopOriginal(propagationFullRecipe, "<user@remote.example>")})
	if linked.SigningDomain() != receivedDSNLocalDomain || !bytes.Equal(linked.NextHopRecipient(), []byte(propagationPreviousSender)) || linked.Evaluation().CompletionSequence() != 3 {
		t.Fatalf("linked two-hop evidence domain=%q next=%q", linked.SigningDomain(), linked.NextHopRecipient())
	}
	propagated := fixture.mustSign(t, linked)
	message, err := rawmsg.Parse(propagated.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if signatures, err := signature.Extract(message); err != nil || len(signatures) != 1 || signatures[0].Domain() != receivedDSNLocalDomain {
		t.Fatalf("propagated signatures=%d error=%v", len(signatures), err)
	}
	broken, err := fixture.signer.RebuildDSNForPropagation(context.Background(), propagationCase{original: propagationTwoHopOriginal(propagationFullRecipe, "<user@elsewhere.example>")}.request(t))
	if err != nil || broken.Rebuilt() || broken.Outcome() == DSNPropagationRebuilt || broken.Evaluation().Embedded() != ReceivedDSNEmbeddedUnverified {
		t.Fatalf("broken lower link outcome=%q embedded=%q error=%v", broken.Outcome(), broken.Evaluation().Embedded(), err)
	}
}

// TestRebuildDSNForPropagationRejectsInvalidRequests proves preflight rules:
// null reverse path, one forward path, a tenant authority, a canonical
// reporting MTA, and cancellation, all as typed staged errors.
func TestRebuildDSNForPropagationRejectsInvalidRequests(t *testing.T) {
	fixture := newPropagationFixture(t, newPropagationProvider(receivedDSNLocalDomain))
	base := propagationCase{original: propagationOriginal(propagationFullRecipe)}
	raw := base.build(t)
	authority := newReceivedDSNAuthority(receivedDSNLocalDomain)
	for name, request := range map[string]DSNPropagationRequest{
		"non-null reverse path": NewDSNPropagationRequest(raw, []byte("<x@local.example>"), [][]byte{[]byte(receivedDSNLocalMailFrom)}, authority, propagationReportingMTA),
		"two forward paths":     NewDSNPropagationRequest(raw, []byte("<>"), [][]byte{[]byte(receivedDSNLocalMailFrom), []byte(receivedDSNOtherLocal)}, authority, propagationReportingMTA),
		"no authority":          NewDSNPropagationRequest(raw, []byte("<>"), [][]byte{[]byte(receivedDSNLocalMailFrom)}, nil, propagationReportingMTA),
		"uppercase mta":         NewDSNPropagationRequest(raw, []byte("<>"), [][]byte{[]byte(receivedDSNLocalMailFrom)}, authority, "MTA.local.example"),
		"empty mta":             NewDSNPropagationRequest(raw, []byte("<>"), [][]byte{[]byte(receivedDSNLocalMailFrom)}, authority, ""),
		"empty raw":             NewDSNPropagationRequest(nil, []byte("<>"), [][]byte{[]byte(receivedDSNLocalMailFrom)}, authority, propagationReportingMTA),
		"zero request":          {},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := fixture.signer.RebuildDSNForPropagation(context.Background(), request)
			if DSNPropagationStageOf(err) != DSNPropagationStagePreflight || !errors.Is(err, newSigningError(SigningErrorInvalidRequest)) {
				t.Fatalf("error=%v stage=%q", err, DSNPropagationStageOf(err))
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fixture.signer.RebuildDSNForPropagation(ctx, base.request(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	var nilSigner *Signer
	if _, err := nilSigner.RebuildDSNForPropagation(context.Background(), base.request(t)); err == nil {
		t.Fatal("nil signer accepted")
	}
	malformed := NewDSNPropagationRequest([]byte("not a message"), []byte("<>"), [][]byte{[]byte(receivedDSNLocalMailFrom)}, authority, propagationReportingMTA)
	evidence, err := fixture.signer.RebuildDSNForPropagation(context.Background(), malformed)
	if err != nil || evidence.Outcome() != DSNPropagationNotEligible || evidence.Evaluation().Structure() != ReceivedDSNStructureMalformed {
		t.Fatalf("malformed report outcome=%q structure=%q error=%v", evidence.Outcome(), evidence.Evaluation().Structure(), err)
	}
}

// TestSignPropagatedDSNSingleInstanceSingleSignature proves the signed DSN
// carries exactly one m=1 and one i=1 with mf=<> and rt= equal to the
// previous mf=, that Date equals the signing t=, that the ticket is consumed
// once, and that caller-selected domains and purposes are rejected.
func TestSignPropagatedDSNSingleInstanceSingleSignature(t *testing.T) {
	fixture := newPropagationFixture(t, newPropagationProvider(receivedDSNLocalDomain, receivedDSNRemoteDomain))
	evidence := fixture.mustRebuild(t, propagationCase{original: propagationOriginal(propagationFullRecipe)})
	propagated := fixture.mustSign(t, evidence)
	if propagated.SigningDomain() != receivedDSNLocalDomain || !bytes.Equal(propagated.NextHopRecipient(), []byte(propagationPreviousSender)) || propagated.SMTPUTF8Required() {
		t.Fatalf("propagated domain=%q next=%q", propagated.SigningDomain(), propagated.NextHopRecipient())
	}
	facts := propagated.Facts()
	if !facts.Valid() || facts.NewInstanceNumber() != 1 || facts.Sequence() != 1 || facts.Role() != SigningRoleOriginator {
		t.Fatalf("facts valid=%t instance=%d sequence=%d role=%q", facts.Valid(), facts.NewInstanceNumber(), facts.Sequence(), facts.Role())
	}
	message, err := rawmsg.Parse(propagated.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := signature.Extract(message)
	if err != nil || len(signatures) != 1 || signatures[0].Sequence() != 1 || signatures[0].InstanceNumber() != 1 || signatures[0].Domain() != receivedDSNLocalDomain {
		t.Fatalf("signatures=%d error=%v", len(signatures), err)
	}
	if !bytes.Equal(signatures[0].MailFrom().Value(), []byte("<>")) || len(signatures[0].Recipients()) != 1 || !bytes.Equal(signatures[0].Recipients()[0].Value(), []byte(propagationPreviousSender)) {
		t.Fatal("signature envelope tags mismatch")
	}
	if len(message.Headers().FieldsByName("message-instance")) != 1 {
		t.Fatalf("message instances=%d", len(message.Headers().FieldsByName("message-instance")))
	}
	date, ok := message.Headers().LastFieldByName("date")
	if !ok || strings.TrimSpace(string(date.UnfoldedValue())) != time.Unix(int64(signatures[0].TimestampSeconds()), 0).UTC().Format(time.RFC1123Z) {
		t.Fatalf("date=%q t=%d", date.UnfoldedValue(), signatures[0].TimestampSeconds())
	}
	if signatures[0].TimestampSeconds() != uint64(propagationSigningClock) {
		t.Fatalf("t=%d clock=%d", signatures[0].TimestampSeconds(), propagationSigningClock)
	}
	first := propagated.Bytes()
	first[0] = 'X'
	if bytes.Equal(propagated.Bytes(), first) {
		t.Fatal("Bytes() exposed shared storage")
	}
}

// TestSignPropagatedDSNRejectsCallerDomainsPurposesAndReuse proves the
// ticket is consumed once and that caller-selected domains, ordinary DSN
// tickets, non-null routes, and unknown transports are rejected.
func TestSignPropagatedDSNRejectsCallerDomainsPurposesAndReuse(t *testing.T) {
	fixture := newPropagationFixture(t, newPropagationProvider(receivedDSNLocalDomain, receivedDSNRemoteDomain))
	evidence := fixture.mustRebuild(t, propagationCase{original: propagationOriginal(propagationFullRecipe)})
	ticket := fixture.ticket(t, evidence)
	valid := NewDSNPropagationSigningRequest(evidence, ticket, fixture.profiles[receivedDSNLocalDomain], SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing)
	if _, _, err := fixture.signer.SignPropagatedDSN(context.Background(), valid); err != nil {
		t.Fatalf("second signing with a fresh ticket error=%v", err)
	}
	if _, _, err := fixture.signer.SignPropagatedDSN(context.Background(), valid); err == nil {
		t.Fatal("consumed ticket signed twice")
	}
	foreign := NewDSNPropagationSigningRequest(evidence, fixture.ticket(t, evidence), fixture.profiles[receivedDSNRemoteDomain], SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing)
	if _, _, err := fixture.signer.SignPropagatedDSN(context.Background(), foreign); !errors.Is(err, newSigningError(SigningErrorInvalidRequest)) {
		t.Fatalf("caller domain accepted: %v", err)
	}
	source, err := NewSigningSource(evidence.state.report.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	dsnEntry, err := NewDeliveryStatusRouteEntry(source, []byte("<>"), [][]byte{evidence.NextHopRecipient()}, RouteDisclosureSingle, []byte("dsn-route"))
	if err != nil {
		t.Fatal(err)
	}
	dsnRequest, err := NewRouteFanoutRequest([]RouteEntry{dsnEntry})
	if err != nil {
		t.Fatal(err)
	}
	_, dsnTickets, err := fixture.signer.PlanRouteFanout(context.Background(), dsnRequest)
	if err != nil || len(dsnTickets) != 1 {
		t.Fatal(err)
	}
	if _, _, err := fixture.signer.SignPropagatedDSN(context.Background(), NewDSNPropagationSigningRequest(
		evidence, dsnTickets[0], fixture.profiles[receivedDSNLocalDomain], SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
	)); !errors.Is(err, newSigningError(SigningErrorInvalidRequest)) {
		t.Fatalf("delivery_status ticket accepted for propagation: %v", err)
	}
	if _, err := NewDeliveryStatusPropagationRouteEntry(source, []byte("<x@local.example>"), [][]byte{evidence.NextHopRecipient()}, []byte("route")); err == nil {
		t.Fatal("non-null reverse path accepted for the propagation route")
	}
	if _, err := NewDeliveryStatusPropagationRouteEntry(source, []byte("<>"), [][]byte{evidence.NextHopRecipient(), []byte(receivedDSNOtherLocal)}, []byte("route")); err == nil {
		t.Fatal("two recipients accepted for the propagation route")
	}
	if _, _, err := fixture.signer.SignPropagatedDSN(context.Background(), NewDSNPropagationSigningRequest(
		evidence, fixture.ticket(t, evidence), fixture.profiles[receivedDSNLocalDomain], SigningMetadata{}, SigningTransportForm("other"),
	)); !errors.Is(err, newSigningError(SigningErrorInvalidRequest)) {
		t.Fatalf("unknown transport accepted: %v", err)
	}
}

// TestPropagatedDSNRoundTrip proves the produced DSN verifies with the
// generic verifier and evaluates as local_hop = local, aligned, linked, and
// terminal_origin at the previous hop's simulated view.
func TestPropagatedDSNRoundTrip(t *testing.T) {
	provider := newPropagationProvider(receivedDSNLocalDomain)
	fixture := newPropagationFixture(t, provider)
	for _, testCase := range []struct {
		name string
		spec propagationCase
		form ReceivedDSNEmbedded
	}{
		{"complete", propagationCase{original: propagationOriginal(propagationFullRecipe)}, ReceivedDSNEmbeddedVerified},
		{"headers-only", propagationCase{original: propagationOriginal(propagationHeaderRecipe), headersOnly: true}, ReceivedDSNEmbeddedVerifiedHeadersOnly},
		{"null recipe", propagationCase{original: propagationOriginal(propagationNullRecipe)}, ReceivedDSNEmbeddedVerifiedHeadersOnly},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			propagated := fixture.mustSign(t, fixture.mustRebuild(t, testCase.spec))
			verifier, err := NewVerifier(provider, WithVerificationClock(func() time.Time { return time.Unix(propagationSigningClock+60, 0) }))
			if err != nil {
				t.Fatal(err)
			}
			result, err := verifier.Verify(context.Background(), NewVerifyRequest(propagated.Bytes(), []byte("<>"), [][]byte{propagated.NextHopRecipient()}))
			if err != nil || result.State() != ResultStatePASS || result.Target().Sequence() != 1 || result.Target().Instance() != 1 {
				t.Fatalf("Verify(propagated) state=%q reason=%q error=%v", result.State(), result.PrimaryReason(), err)
			}
			evaluation, err := verifier.EvaluateReceivedDSN(context.Background(), NewReceivedDSNRequest(
				propagated.Bytes(), []byte("<>"), [][]byte{propagated.NextHopRecipient()}, newReceivedDSNAuthority(receivedDSNRemoteDomain),
			))
			if err != nil {
				t.Fatalf("EvaluateReceivedDSN(previous hop view) error=%v", err)
			}
			if evaluation.Structure() != ReceivedDSNStructureValid || evaluation.Embedded() != testCase.form ||
				evaluation.LocalHop() != ReceivedDSNLocalHopLocal || evaluation.OuterAlignment() != ReceivedDSNOuterAlignmentAligned ||
				evaluation.RecipientLinkage() != ReceivedDSNRecipientLinkageLinked || evaluation.Propagation() != ReceivedDSNPropagationTerminalOrigin ||
				evaluation.CompletionSequence() != 1 {
				t.Fatalf("previous hop view structure=%q embedded=%q local_hop=%q alignment=%q linkage=%q propagation=%q",
					evaluation.Structure(), evaluation.Embedded(), evaluation.LocalHop(), evaluation.OuterAlignment(), evaluation.RecipientLinkage(), evaluation.Propagation())
			}
			if strings.Contains(string(propagated.Bytes()), propagationUpstreamMarker) {
				t.Fatal("propagated DSN carries upstream bytes")
			}
		})
	}
}

// TestPropagationEvidenceAndResultsArePrivateAndConcurrent proves redaction
// of every type, the closed error shape, and independent concurrent rebuilds.
func TestPropagationEvidenceAndResultsArePrivateAndConcurrent(t *testing.T) {
	fixture := newPropagationFixture(t, newPropagationProvider(receivedDSNLocalDomain))
	testCase := propagationCase{original: propagationOriginal(propagationFullRecipe), reportingMTA: "mta.local.example"}
	testCase.original.Headers = "X-Private: " + propagationTestPrivateMarker + "\r\n" + testCase.original.Headers
	testCase.original.Revisions[0].Headers = "X-Private: " + propagationTestPrivateMarker + "\r\n" + testCase.original.Revisions[0].Headers
	request := testCase.request(t)
	evidence := fixture.mustRebuild(t, testCase)
	propagated := fixture.mustSign(t, evidence)
	signingRequest := NewDSNPropagationSigningRequest(evidence, RouteCopyTicket{}, fixture.profiles[receivedDSNLocalDomain], SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing)
	for name, value := range map[string]any{
		"request": request, "evidence": evidence, "propagated": propagated, "signing request": signingRequest,
	} {
		for _, rendered := range []string{fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value), fmt.Sprintf("%s", value)} {
			if !strings.Contains(rendered, "redacted") || strings.Contains(rendered, propagationTestPrivateMarker) || strings.Contains(rendered, "remote.example") {
				t.Fatalf("%s formatting leaked: %q", name, rendered)
			}
		}
	}
	for name, marshal := range map[string]func() ([]byte, error){
		"request json": request.MarshalJSON, "request text": request.MarshalText,
		"evidence json": evidence.MarshalJSON, "evidence text": evidence.MarshalText,
		"propagated json": propagated.MarshalJSON, "propagated text": propagated.MarshalText,
	} {
		if encoded, err := marshal(); encoded != nil || err == nil {
			t.Fatalf("%s serialized", name)
		}
	}
	shape := regexp.MustCompile(`^dkim2 dsn propagation error: stage=[a-z_]+$`)
	for _, stage := range []DSNPropagationStage{DSNPropagationStagePreflight, DSNPropagationStageEvaluation, DSNPropagationStageRebuild, DSNPropagationStageSigning} {
		err := newDSNPropagationError(stage, newSigningError(SigningErrorInvalidRequest))
		if !shape.MatchString(err.Error()) || DSNPropagationStageOf(err) != stage || !stage.Known() {
			t.Fatalf("error shape=%q", err.Error())
		}
	}
	if DSNPropagationStage("x").Known() || DSNPropagationOutcome("x").Known() || DSNPropagationStageOf(errors.New("plain")) != "" {
		t.Fatal("unknown vocabulary accepted")
	}
	var wait sync.WaitGroup
	results := make([]DSNPropagationEvidence, 8)
	for index := range results {
		wait.Add(1)
		go func(slot int) {
			defer wait.Done()
			rebuilt, err := fixture.signer.RebuildDSNForPropagation(context.Background(), request)
			if err == nil {
				results[slot] = rebuilt
			}
		}(index)
	}
	wait.Wait()
	for _, rebuilt := range results {
		if !rebuilt.Rebuilt() || rebuilt.SigningDomain() != evidence.SigningDomain() {
			t.Fatal("concurrent rebuild diverged")
		}
	}
	if zero := (DSNPropagationEvidence{}); zero.Valid() || zero.Rebuilt() || zero.Outcome() != "" || zero.Evaluation().Valid() {
		t.Fatal("zero evidence is valid")
	}
	if zero := (PropagatedDSN{}); zero.Valid() || zero.Bytes() != nil || zero.SigningDomain() != "" {
		t.Fatal("zero propagated DSN is valid")
	}
}

// paddedPropagationCase returns the default case with its embedded original
// body padded so that the received DSN is exactly target bytes long.
func paddedPropagationCase(t *testing.T, target int) propagationCase {
	t.Helper()
	base := propagationCase{original: propagationOriginal(propagationFullRecipe)}
	delta := target - len(base.build(t))
	if delta < 0 {
		t.Fatalf("target %d below the unpadded report", target)
	}
	const line = 900
	var padding strings.Builder
	for delta >= line+2 {
		padding.WriteString(strings.Repeat("p", line) + "\r\n")
		delta -= line + 2
	}
	if delta > 0 {
		if delta < 3 {
			rewritten := padding.String()
			padding.Reset()
			padding.WriteString(strings.TrimSuffix(rewritten, "\r\n") + strings.Repeat("p", delta) + "\r\n")
		} else {
			padding.WriteString(strings.Repeat("p", delta-2) + "\r\n")
		}
	}
	base.original.Body = propagationCurrentBody + padding.String()
	if got := len(base.build(t)); got != target {
		t.Fatalf("padded report length=%d target=%d", got, target)
	}
	return base
}

// TestRebuildDSNForPropagationNarrowsParserByFixedPartsAndSignatureAllowance
// proves the received-DSN parser ceiling equals the signer's message limit
// less the fixed report parts and the two generated protocol fields: a DSN at
// that ceiling rebuilds and signs within the limit, one byte more is rejected
// at parsing as limit_exceeded rather than after a rebuild, and limits too
// narrow for any propagation fail at preflight.
func TestRebuildDSNForPropagationNarrowsParserByFixedPartsAndSignatureAllowance(t *testing.T) {
	limits := SigningLimits{MaxMessageBytes: 64 << 10, MaxHeaderBytes: 32 << 10, MaxFieldBytes: 16 << 10, MaxDecodedRecipeBytes: 8 << 10}
	provider := newPropagationProvider(receivedDSNLocalDomain)
	signer, err := NewSigner(provider, NewRequestRouteAuthority(), &authorizeOrdinary{}, provider,
		WithSigningClock(func() time.Time { return time.Unix(propagationSigningClock, 0) }), WithSigningLimits(limits))
	if err != nil {
		t.Fatalf("NewSigner() error=%v", err)
	}
	fixture := propagationFixture{signer: signer, provider: provider, profiles: newPropagationFixture(t, provider).profiles}
	ceiling := limits.MaxMessageBytes - dsn.PropagationFixedPartsBound - 2*limits.MaxFieldBytes
	atCeiling := fixture.mustRebuild(t, paddedPropagationCase(t, ceiling))
	if propagated := fixture.mustSign(t, atCeiling); len(propagated.Bytes()) > limits.MaxMessageBytes {
		t.Fatalf("signed DSN %d bytes exceeds the message limit %d", len(propagated.Bytes()), limits.MaxMessageBytes)
	}
	over, err := signer.RebuildDSNForPropagation(context.Background(), paddedPropagationCase(t, ceiling+1).request(t))
	if err != nil || over.Rebuilt() || over.Outcome() != DSNPropagationNotEligible || over.Evaluation().Structure() != ReceivedDSNStructureLimitExceeded {
		t.Fatalf("over-ceiling outcome=%q structure=%q error=%v", over.Outcome(), over.Evaluation().Structure(), err)
	}
	narrow := SigningLimits{MaxMessageBytes: 36 << 10, MaxHeaderBytes: 32 << 10, MaxFieldBytes: 16 << 10, MaxDecodedRecipeBytes: 8 << 10}
	narrowSigner, err := NewSigner(provider, NewRequestRouteAuthority(), &authorizeOrdinary{}, provider, WithSigningLimits(narrow))
	if err != nil {
		t.Fatalf("NewSigner(narrow) error=%v", err)
	}
	if _, err := narrowSigner.RebuildDSNForPropagation(context.Background(), propagationCase{original: propagationOriginal(propagationFullRecipe)}.request(t)); DSNPropagationStageOf(err) != DSNPropagationStagePreflight {
		t.Fatalf("limits too narrow for propagation accepted: %v", err)
	}
}

// TestPlanPropagationRouteBindsTicketToRebuiltReport proves the signer plans
// exactly one delivery_status_propagation ticket over the rebuilt report's
// own bytes, so that the ticket source matches the message the signer sees,
// that the ticket signs, and that every derived authority stays derived.
func TestPlanPropagationRouteBindsTicketToRebuiltReport(t *testing.T) {
	fixture := newPropagationFixture(t, newPropagationProvider(receivedDSNLocalDomain, receivedDSNRemoteDomain))
	evidence := fixture.mustRebuild(t, propagationCase{original: propagationOriginal(propagationFullRecipe)})
	ticket, err := fixture.signer.PlanPropagationRoute(context.Background(), evidence, []byte("daemon-route"))
	if err != nil || !ticket.Valid() || ticket.TotalMultiplicity() != 1 {
		t.Fatalf("PlanPropagationRoute() valid=%t multiplicity=%d error=%v", ticket.Valid(), ticket.TotalMultiplicity(), err)
	}
	if ticket.value.Purpose() != routeplan.PurposeDeliveryStatusPropagation ||
		!ticket.value.MatchesEnvelope([]byte("<>"), [][]byte{evidence.NextHopRecipient()}) ||
		!ticket.value.MatchesSource(evidence.state.report.Bytes()) {
		t.Fatal("planned ticket is not bound to the null reverse path, the previous mf=, and the rebuilt report bytes")
	}
	propagated, recovery, err := fixture.signer.SignPropagatedDSN(context.Background(), NewDSNPropagationSigningRequest(
		evidence, ticket, fixture.profiles[receivedDSNLocalDomain], SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
	))
	if err != nil || recovery.Valid() || !propagated.Valid() || propagated.SigningDomain() != receivedDSNLocalDomain ||
		!bytes.Equal(propagated.NextHopRecipient(), []byte(propagationPreviousSender)) {
		t.Fatalf("SignPropagatedDSN() with the planned ticket valid=%t recovery=%t error=%v", propagated.Valid(), recovery.Valid(), err)
	}
	if _, _, err := fixture.signer.SignPropagatedDSN(context.Background(), NewDSNPropagationSigningRequest(
		evidence, ticket, fixture.profiles[receivedDSNLocalDomain], SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
	)); err == nil {
		t.Fatal("planned ticket was consumed twice")
	}
	notEligible, err := fixture.signer.RebuildDSNForPropagation(context.Background(), propagationCase{
		original: propagationOriginal(propagationFullRecipe), local: []string{receivedDSNOtherDomain},
	}.request(t))
	if err != nil || notEligible.Rebuilt() {
		t.Fatalf("not-eligible rebuild rebuilt=%t error=%v", notEligible.Rebuilt(), err)
	}
	for name, input := range map[string]DSNPropagationEvidence{"zero": {}, "not_rebuilt": notEligible} {
		if _, err := fixture.signer.PlanPropagationRoute(context.Background(), input, []byte("daemon-route")); !errors.Is(err, newSigningError(SigningErrorInvalidRequest)) {
			t.Fatalf("%s evidence planned a route: %v", name, err)
		}
	}
	var nilSigner *Signer
	if _, err := nilSigner.PlanPropagationRoute(context.Background(), evidence, []byte("daemon-route")); !errors.Is(err, newSigningError(SigningErrorInvalidRequest)) {
		t.Fatalf("nil signer planned a route: %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fixture.signer.PlanPropagationRoute(cancelled, evidence, []byte("daemon-route")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled planning error=%v", err)
	}
}
