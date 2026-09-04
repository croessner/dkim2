package dsn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/dsn/dsntest"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
	"github.com/croessner/dkim2/internal/verify"
)

const (
	receivedOriginDomain      = "origin.example"
	receivedRemoteDomain      = "remote.example"
	receivedLocalDomain       = "local.example"
	receivedForwardDomain     = "forward.local.example"
	receivedDestinationDomain = "destination.example"
	receivedOtherDomain       = "other.example"
	receivedParentDomain      = "example"
	receivedLocalRecipient    = "<user@local.example>"
	receivedLocalMailFrom     = "<forwarded@local.example>"
	receivedDestination       = "<dest@destination.example>"
	receivedDestinationRaw    = "dest@destination.example"
	receivedForwardMailFrom   = "<forwarded@forward.local.example>"
	receivedFailedStatus      = "5.1.1"
	receivedPrivateMarker     = "PRIVATE-MARKER-VALUE"
)

// receivedKeys returns deterministic keys for every domain used by received fixtures.
func receivedKeys() map[string]dsntest.Key {
	return map[string]dsntest.Key{
		receivedOriginDomain:      dsntest.KeyForLabel("origin", "sel"),
		receivedRemoteDomain:      dsntest.KeyForLabel("remote", "sel"),
		receivedLocalDomain:       dsntest.KeyForLabel("local", "sel"),
		receivedForwardDomain:     dsntest.KeyForLabel("forward", "sel"),
		receivedDestinationDomain: dsntest.KeyForLabel("destination", "sel"),
		receivedOtherDomain:       dsntest.KeyForLabel("other", "sel"),
		receivedParentDomain:      dsntest.KeyForLabel("parent", "sel"),
	}
}

// receivedHop renders one ordinary hop for a fixture domain.
func receivedHop(domain, mailFrom string, recipients ...string) dsntest.Hop {
	key, ok := receivedKeys()[domain]
	if !ok {
		key = dsntest.KeyForLabel(domain, "sel")
	}
	return dsntest.Hop{Domain: domain, Key: key, MailFrom: mailFrom, Recipients: recipients}
}

// receivedNextDomainHop renders one nd= hop for a fixture domain.
func receivedNextDomainHop(domain, next string) dsntest.Hop {
	return dsntest.Hop{Domain: domain, Key: receivedKeys()[domain], NextDomain: next}
}

// receivedAuthority answers locality from a fixed set and can simulate outages.
type receivedAuthority struct {
	local     map[string]struct{}
	temporary bool
	lookups   []string
	mu        sync.Mutex
}

// LookupLocalAuthority implements verify.LocalAuthority.
func (a *receivedAuthority) LookupLocalAuthority(ctx context.Context, domain string) (verify.LocalAuthorityStatus, error) {
	a.mu.Lock()
	a.lookups = append(a.lookups, domain)
	a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if a.temporary {
		return "", errors.New("datasource unavailable")
	}
	if _, ok := a.local[domain]; ok {
		return verify.LocalAuthorityLocal, nil
	}
	return verify.LocalAuthorityNotLocal, nil
}

// newReceivedAuthority treats the named domains as local authority domains.
func newReceivedAuthority(domains ...string) *receivedAuthority {
	local := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		local[domain] = struct{}{}
	}
	return &receivedAuthority{local: local}
}

// receivedKeyProvider serves fixture keys and can fail one domain temporarily.
type receivedKeyProvider struct {
	static          verify.StaticKeyProvider
	temporaryDomain string
	lookups         atomic.Int64
}

// LookupKey implements verify.KeyProvider with an optional temporary failure.
func (p *receivedKeyProvider) LookupKey(ctx context.Context, query verify.KeyQuery) (verify.PublicKey, error) {
	p.lookups.Add(1)
	if p.temporaryDomain != "" && query.Domain == p.temporaryDomain {
		return verify.PublicKey{}, verify.NewProviderFailure(verify.ProviderFailureTemporary)
	}
	return p.static.LookupKey(ctx, query)
}

// receivedFixtureClock is the fixed verification instant just after the fixture timestamp.
func receivedFixtureClock() time.Time {
	return time.Unix(int64(dsntest.DefaultTimestamp), 0).Add(time.Minute)
}

// mustReceivedVerifier builds a verifier over every fixture key with a fixed clock.
func mustReceivedVerifier(t *testing.T, temporaryDomain string) (verify.Verifier, *receivedKeyProvider) {
	t.Helper()
	return mustReceivedVerifierAt(t, temporaryDomain, receivedFixtureClock())
}

// mustReceivedVerifierAt builds a verifier over every fixture key whose clock reads now.
func mustReceivedVerifierAt(t *testing.T, temporaryDomain string, now time.Time) (verify.Verifier, *receivedKeyProvider) {
	t.Helper()
	keys := make([]verify.StaticKey, 0, 6)
	for domain, key := range receivedKeys() {
		keys = append(keys, verify.StaticKey{Domain: domain, Selector: key.Selector, Algorithm: verify.AlgorithmEd25519SHA256, Material: key.Public()})
	}
	static, err := verify.NewStaticKeyProvider(keys)
	if err != nil {
		t.Fatalf("NewStaticKeyProvider() error=%v", err)
	}
	provider := &receivedKeyProvider{static: static, temporaryDomain: temporaryDomain}
	verifier, err := verify.NewVerifier(provider, verify.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("NewVerifier() error=%v", err)
	}
	return verifier, provider
}

// receivedSpec describes one received DSN fixture.
type receivedSpec struct {
	hops           []dsntest.Hop
	headersOnly    bool
	unsigned       bool
	deliveryStatus string
	outerSigner    string
	outerRecipient string
	outerUnsigned  bool
	outerTimestamp uint64
}

// defaultReceivedHops returns the ordinary two-hop forwarded chain.
func defaultReceivedHops() []dsntest.Hop {
	return []dsntest.Hop{
		receivedHop(receivedRemoteDomain, "<sender@remote.example>", receivedLocalRecipient),
		receivedHop(receivedLocalDomain, receivedLocalMailFrom, receivedDestination),
	}
}

// build renders the outer DSN bytes for the spec.
func (s receivedSpec) build(t *testing.T) []byte {
	t.Helper()
	hops := s.hops
	if hops == nil {
		hops = defaultReceivedHops()
	}
	var original []byte
	if s.unsigned {
		original = []byte("From: sender@remote.example\r\nSubject: original\r\n\r\nbody\r\n")
	} else {
		built, err := (dsntest.Original{Headers: "From: sender@remote.example\r\nSubject: original\r\n", Body: "body\r\n", Hops: hops}).Build()
		if err != nil {
			t.Fatalf("Original.Build() error=%v", err)
		}
		original = built
	}
	contentType := string(ContentTypeRFC822)
	if s.headersOnly {
		contentType = string(ContentTypeRFC822Headers)
		original = dsntest.HeaderBlock(original)
	}
	deliveryStatus := s.deliveryStatus
	if deliveryStatus == "" {
		deliveryStatus = dsntest.FailedDeliveryStatus(receivedDestinationDomain, receivedDestinationRaw, receivedFailedStatus)
	}
	signerDomain := s.outerSigner
	if signerDomain == "" {
		signerDomain = receivedDestinationDomain
	}
	recipient := s.outerRecipient
	if recipient == "" {
		recipient = receivedLocalMailFrom
	}
	report := dsntest.Report{
		OuterHeaders:        "From: MAILER-DAEMON@" + signerDomain + "\r\nSubject: Undelivered Mail\r\n",
		Human:               "delivery failed",
		DeliveryStatus:      deliveryStatus,
		OriginalContentType: contentType,
		Original:            original,
	}
	if !s.outerUnsigned {
		signer := receivedHop(signerDomain, "<>", recipient)
		signer.Timestamp = s.outerTimestamp
		report.Signer = &signer
	}
	raw, err := report.Build()
	if err != nil {
		t.Fatalf("Report.Build() error=%v", err)
	}
	return raw
}

// evaluateReceived runs one evaluation with a verifier that knows every fixture key.
func evaluateReceived(t *testing.T, spec receivedSpec, authority verify.LocalAuthority) (ReceivedEvaluation, error) {
	t.Helper()
	verifier, _ := mustReceivedVerifier(t, "")
	evaluator, err := NewReceivedEvaluator(verifier, ReceivedEvaluatorConfig{})
	if err != nil {
		t.Fatalf("NewReceivedEvaluator() error=%v", err)
	}
	recipient := spec.outerRecipient
	if recipient == "" {
		recipient = receivedLocalMailFrom
	}
	return evaluator.Evaluate(context.Background(), ReceivedRequest{Raw: spec.build(t), OuterRecipient: []byte(recipient), Authority: authority})
}

// projection is the six-member comparison shape used by the table tests.
type projection struct {
	structure   StructureResult
	embedded    EmbeddedResult
	localHop    LocalHopResult
	alignment   OuterAlignmentResult
	linkage     RecipientLinkageResult
	propagation PropagationResult
}

// projectionOf flattens an evaluation for comparison.
func projectionOf(evaluation ReceivedEvaluation) projection {
	return projection{
		structure: evaluation.Structure(), embedded: evaluation.Embedded(), localHop: evaluation.LocalHop(),
		alignment: evaluation.OuterAlignment(), linkage: evaluation.RecipientLinkage(), propagation: evaluation.Propagation(),
	}
}

// eligibleProjection is the fully linked positive projection for the given form.
func eligibleProjection(embedded EmbeddedResult, propagation PropagationResult) projection {
	return projection{
		structure: StructureValid, embedded: embedded, localHop: LocalHopLocal,
		alignment: OuterAlignmentAligned, linkage: RecipientLinkageLinked, propagation: propagation,
	}
}

// TestReceivedEvaluationEligibleCompleteAndHeadersOnly proves the positive path
// for both RFC 6522 original representations and exposes bounded rebuild facts.
func TestReceivedEvaluationEligibleCompleteAndHeadersOnly(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		headersOnly bool
		embedded    EmbeddedResult
		form        EvidenceForm
	}{
		{name: "complete", embedded: EmbeddedVerified, form: EvidenceFormComplete},
		{name: "headers only", headersOnly: true, embedded: EmbeddedVerifiedHeadersOnly, form: EvidenceFormHeadersOnly},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			evaluation, err := evaluateReceived(t, receivedSpec{headersOnly: testCase.headersOnly}, newReceivedAuthority(receivedLocalDomain))
			if err != nil || !evaluation.Valid() {
				t.Fatalf("Evaluate() valid=%t error=%v", evaluation.Valid(), err)
			}
			if got := projectionOf(evaluation); got != eligibleProjection(testCase.embedded, PropagationEligible) {
				t.Fatalf("projection=%+v", got)
			}
			if evaluation.Form() != testCase.form || evaluation.CompletionSequence() != 2 || evaluation.CompletionInstance() != 1 ||
				evaluation.CompletionDomain() != receivedLocalDomain || evaluation.CompletionTimestamp() != dsntest.DefaultTimestamp {
				t.Fatalf("completion facts: form=%q sequence=%d instance=%d domain=%q", evaluation.Form(), evaluation.CompletionSequence(), evaluation.CompletionInstance(), evaluation.CompletionDomain())
			}
			run, ok := evaluation.Run()
			if !ok || run.LowestSequence() != 2 || run.PreviousHopSequence() != 1 || !bytes.Equal(run.PreviousHopMailFrom(), []byte("<sender@remote.example>")) {
				t.Fatalf("run facts: ok=%t lowest=%d previous=%d", ok, run.LowestSequence(), run.PreviousHopSequence())
			}
			if status := evaluation.PropagationStatus(); string(status) != receivedFailedStatus {
				t.Fatalf("PropagationStatus()=%q", status)
			}
			if _, present := evaluation.OriginalEnvelopeID(); present {
				t.Fatal("OriginalEnvelopeID() present without ENVID")
			}
			if _, present := evaluation.OriginalRecipient(); present {
				t.Fatal("OriginalRecipient() present without ORCPT")
			}
		})
	}
}

// TestReceivedEvaluationStructureFailures proves malformed framing, malformed
// delivery-status bodies, and limit violations stop at the structure stage.
func TestReceivedEvaluationStructureFailures(t *testing.T) {
	notEvaluated := projection{
		structure: StructureMalformed, embedded: "", localHop: LocalHopNotEvaluated,
		alignment: OuterAlignmentNotEvaluated, linkage: RecipientLinkageNotEvaluated, propagation: PropagationNotEvaluated,
	}
	verifier, provider := mustReceivedVerifier(t, "")
	evaluator, err := NewReceivedEvaluator(verifier, ReceivedEvaluatorConfig{})
	if err != nil {
		t.Fatal(err)
	}
	valid := receivedSpec{}.build(t)
	for _, testCase := range []struct {
		name string
		raw  []byte
		want StructureResult
	}{
		{name: "not a report", raw: []byte("From: a@b.example\r\nSubject: " + receivedPrivateMarker + "\r\n\r\nbody\r\n"), want: StructureMalformed},
		{name: "two parts", raw: bytes.Replace(valid, []byte("--dsn-boundary\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\ndelivery failed\r\n"), nil, 1), want: StructureMalformed},
		{name: "missing action", raw: bytes.Replace(valid, []byte("Action: failed\r\n"), nil, 1), want: StructureMalformed},
		{name: "folded final recipient", raw: bytes.Replace(valid, []byte("Final-Recipient: rfc822; "), []byte("Final-Recipient: rfc822;\r\n "), 1), want: StructureMalformed},
		{name: "postfix bounce order is not generic", raw: bytes.Replace(valid, []byte("Final-Recipient: rfc822; dest@destination.example\r\n"), []byte("Final-Recipient: rfc822; dest@destination.example\r\nOriginal-Recipient: rfc822; dest@destination.example\r\n"), 1), want: StructureMalformed},
		{name: "embedded original not a message", raw: bytes.Replace(valid, []byte("From: sender@remote.example\r\nSubject: original\r\n"), []byte("no colon line\r\n"), 1), want: StructureMalformed},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			evaluation, err := evaluator.Evaluate(context.Background(), ReceivedRequest{Raw: testCase.raw, OuterRecipient: []byte(receivedLocalMailFrom), Authority: newReceivedAuthority(receivedLocalDomain)})
			if err != nil || !evaluation.Valid() {
				t.Fatalf("Evaluate() valid=%t error=%v", evaluation.Valid(), err)
			}
			want := notEvaluated
			want.structure = testCase.want
			if got := projectionOf(evaluation); got != want {
				t.Fatalf("projection=%+v", got)
			}
			if strings.Contains(fmt.Sprint(evaluation), receivedPrivateMarker) {
				t.Fatal("evaluation formatting leaked content")
			}
		})
	}
	if lookups := provider.lookups.Load(); lookups != 0 {
		t.Fatalf("structure failures performed %d key lookups", lookups)
	}
	limited, err := NewReceivedEvaluator(verifier, ReceivedEvaluatorConfig{Parser: Options{MaxMessageBytes: 512, MaxPartBytes: 256, MaxBoundaryBytes: 70}})
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := limited.Evaluate(context.Background(), ReceivedRequest{Raw: valid, OuterRecipient: []byte(receivedLocalMailFrom), Authority: newReceivedAuthority(receivedLocalDomain)})
	if err != nil || evaluation.Structure() != StructureLimitExceeded || evaluation.Propagation() != PropagationNotEvaluated {
		t.Fatalf("limited Evaluate() structure=%q propagation=%q error=%v", evaluation.Structure(), evaluation.Propagation(), err)
	}
}

// TestReceivedEvaluationEmbeddedAbsent proves an unsigned embedded original
// stops with propagation not_applicable and every later member not_evaluated.
func TestReceivedEvaluationEmbeddedAbsent(t *testing.T) {
	evaluation, err := evaluateReceived(t, receivedSpec{unsigned: true}, newReceivedAuthority(receivedLocalDomain))
	if err != nil {
		t.Fatal(err)
	}
	want := projection{
		structure: StructureValid, embedded: EmbeddedAbsent, localHop: LocalHopNotEvaluated,
		alignment: OuterAlignmentNotEvaluated, linkage: RecipientLinkageNotEvaluated, propagation: PropagationNotApplicable,
	}
	if got := projectionOf(evaluation); got != want {
		t.Fatalf("projection=%+v", got)
	}
}

// TestReceivedEvaluationEmbeddedUnverifiedAndTemporary proves cryptographic
// failure, an invented headers-only body, and temporary key failure stop at stage two.
func TestReceivedEvaluationEmbeddedUnverifiedAndTemporary(t *testing.T) {
	corrupt := defaultReceivedHops()
	corrupt[1].CorruptSignature = true
	foreignNamingLocal := []dsntest.Hop{
		receivedHop(receivedRemoteDomain, "<sender@remote.example>", receivedLocalRecipient),
		receivedHop(receivedOtherDomain, receivedLocalMailFrom, receivedDestination),
	}
	for _, testCase := range []struct {
		name string
		spec receivedSpec
		want EmbeddedResult
	}{
		{name: "corrupt completion signature", spec: receivedSpec{hops: corrupt}, want: EmbeddedUnverified},
		{name: "headers only with invented body", spec: receivedSpec{headersOnly: false, deliveryStatus: ""}, want: EmbeddedUnverified},
		{name: "foreign signature naming a local address", spec: receivedSpec{hops: foreignNamingLocal}, want: EmbeddedUnverified},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			spec := testCase.spec
			raw := spec.build(t)
			if testCase.name == "headers only with invented body" {
				raw = bytes.Replace(raw, []byte("Content-Type: message/rfc822"), []byte("Content-Type: text/rfc822-headers"), 1)
			}
			verifier, _ := mustReceivedVerifier(t, "")
			evaluator, err := NewReceivedEvaluator(verifier, ReceivedEvaluatorConfig{})
			if err != nil {
				t.Fatal(err)
			}
			evaluation, err := evaluator.Evaluate(context.Background(), ReceivedRequest{Raw: raw, OuterRecipient: []byte(receivedLocalMailFrom), Authority: newReceivedAuthority(receivedLocalDomain)})
			if err != nil || evaluation.Structure() != StructureValid || evaluation.Embedded() != testCase.want ||
				evaluation.LocalHop() != LocalHopNotEvaluated || evaluation.Propagation() != PropagationNotEvaluated {
				t.Fatalf("projection=%+v error=%v", projectionOf(evaluation), err)
			}
		})
	}
	verifier, _ := mustReceivedVerifier(t, receivedLocalDomain)
	evaluator, err := NewReceivedEvaluator(verifier, ReceivedEvaluatorConfig{})
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := evaluator.Evaluate(context.Background(), ReceivedRequest{Raw: receivedSpec{}.build(t), OuterRecipient: []byte(receivedLocalMailFrom), Authority: newReceivedAuthority(receivedLocalDomain)})
	if err != nil || evaluation.Embedded() != EmbeddedTemporaryError || evaluation.LocalHop() != LocalHopNotEvaluated || evaluation.Propagation() != PropagationNotEvaluated {
		t.Fatalf("temporary projection=%+v error=%v", projectionOf(evaluation), err)
	}
}

// TestReceivedEvaluationLocalHopIdentity proves the four-part Section 12.1.2
// item 2 rule and its tenant-less, foreign, mismatched, and outage outcomes.
func TestReceivedEvaluationLocalHopIdentity(t *testing.T) {
	stopped := func(localHop LocalHopResult) projection {
		return projection{
			structure: StructureValid, embedded: EmbeddedVerified, localHop: localHop,
			alignment: OuterAlignmentNotEvaluated, linkage: RecipientLinkageNotEvaluated, propagation: PropagationNotEvaluated,
		}
	}
	for _, testCase := range []struct {
		name      string
		spec      receivedSpec
		authority verify.LocalAuthority
		want      projection
	}{
		{name: "no tenant", spec: receivedSpec{}, authority: nil, want: stopped(LocalHopNotEvaluated)},
		{name: "not local", spec: receivedSpec{}, authority: newReceivedAuthority(receivedOtherDomain), want: stopped(LocalHopNotLocal)},
		{name: "datasource outage", spec: receivedSpec{}, authority: &receivedAuthority{temporary: true}, want: stopped(LocalHopTemporaryError)},
		{name: "wrong outer recipient", spec: receivedSpec{outerRecipient: "<other@local.example>"}, authority: newReceivedAuthority(receivedLocalDomain), want: stopped(LocalHopMismatch)},
		{name: "local part is case sensitive", spec: receivedSpec{outerRecipient: "<Forwarded@local.example>"}, authority: newReceivedAuthority(receivedLocalDomain), want: stopped(LocalHopMismatch)},
		{name: "domain part is case insensitive", spec: receivedSpec{outerRecipient: "<forwarded@LOCAL.Example>"}, authority: newReceivedAuthority(receivedLocalDomain), want: eligibleProjection(EmbeddedVerified, PropagationEligible)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			evaluation, err := evaluateReceived(t, testCase.spec, testCase.authority)
			if err != nil {
				t.Fatal(err)
			}
			if got := projectionOf(evaluation); got != testCase.want {
				t.Fatalf("projection=%+v want=%+v", got, testCase.want)
			}
		})
	}
	authority := newReceivedAuthority(receivedLocalDomain)
	if _, err := evaluateReceived(t, receivedSpec{}, authority); err != nil {
		t.Fatal(err)
	}
	for _, domain := range authority.lookups {
		if domain != receivedLocalDomain && domain != receivedRemoteDomain {
			t.Fatalf("authority received unexpected lookup %q", domain)
		}
	}
}

// TestReceivedEvaluationOuterAlignment proves the outer signer must relaxed-match a completion rt= domain.
func TestReceivedEvaluationOuterAlignment(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		signer string
		want   OuterAlignmentResult
	}{
		{name: "exact", signer: receivedDestinationDomain, want: OuterAlignmentAligned},
		{name: "parent signer relaxed-matches subdomain recipient", signer: "example", want: OuterAlignmentAligned},
		{name: "subdomain signer does not match parent recipient", signer: "mail.destination.example", want: OuterAlignmentMisaligned},
		{name: "unrelated", signer: receivedOtherDomain, want: OuterAlignmentMisaligned},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			evaluation, err := evaluateReceived(t, receivedSpec{outerSigner: testCase.signer}, newReceivedAuthority(receivedLocalDomain))
			if err != nil || evaluation.OuterAlignment() != testCase.want {
				t.Fatalf("OuterAlignment()=%q error=%v", evaluation.OuterAlignment(), err)
			}
			if testCase.want == OuterAlignmentMisaligned && (evaluation.RecipientLinkage() != RecipientLinkageNotEvaluated || evaluation.Propagation() != PropagationNotEvaluated) {
				t.Fatalf("misaligned did not stop: %+v", projectionOf(evaluation))
			}
		})
	}
	hops := []dsntest.Hop{
		receivedHop(receivedRemoteDomain, "<sender@remote.example>", receivedLocalRecipient),
		receivedHop(receivedLocalDomain, receivedLocalMailFrom, "<dest@mail.destination.example>"),
	}
	evaluation, err := evaluateReceived(t, receivedSpec{hops: hops, deliveryStatus: dsntest.FailedDeliveryStatus(receivedDestinationDomain, "dest@mail.destination.example", "5.1.1")}, newReceivedAuthority(receivedLocalDomain))
	if err != nil || evaluation.OuterAlignment() != OuterAlignmentAligned {
		t.Fatalf("relaxed subdomain alignment=%q error=%v", evaluation.OuterAlignment(), err)
	}
}

// TestReceivedEvaluationRecipientLinkageAndFailureClass proves linkage over
// Final-Recipient and decoded Original-Recipient, unlinked groups are ignored,
// and only Action: failed among linked groups propagates.
func TestReceivedEvaluationRecipientLinkageAndFailureClass(t *testing.T) {
	group := func(final, action, status string) string {
		return "\r\nFinal-Recipient: rfc822; " + final + "\r\nAction: " + action + "\r\nStatus: " + status + "\r\n"
	}
	header := "Reporting-MTA: dns; destination.example\r\n"
	for _, testCase := range []struct {
		name        string
		status      string
		linkage     RecipientLinkageResult
		propagation PropagationResult
		code        string
	}{
		{name: "unlinked", status: header + group("other@destination.example", "failed", "5.1.1"), linkage: RecipientLinkageUnlinked, propagation: PropagationNotEvaluated},
		{name: "original recipient links", status: header + "\r\nOriginal-Recipient: rfc822; dest+40destination.example\r\nFinal-Recipient: rfc822; other@destination.example\r\nAction: failed\r\nStatus: 5.1.1\r\n", linkage: RecipientLinkageLinked, propagation: PropagationEligible, code: receivedFailedStatus},
		{name: "unlinked group with different status is ignored", status: header + group("other@destination.example", "failed", "5.2.2") + group(receivedDestinationRaw, "failed", "5.1.1"), linkage: RecipientLinkageLinked, propagation: PropagationEligible, code: receivedFailedStatus},
		{name: "delayed", status: header + group(receivedDestinationRaw, "delayed", "4.4.1"), linkage: RecipientLinkageLinked, propagation: PropagationNotFailure},
		{name: "delivered", status: header + group(receivedDestinationRaw, "delivered", "2.0.0"), linkage: RecipientLinkageLinked, propagation: PropagationNotFailure},
		{name: "linked delayed then linked failed", status: header + group(receivedDestinationRaw, "delayed", "4.4.1") + group(receivedDestinationRaw, "failed", "4.4.7"), linkage: RecipientLinkageLinked, propagation: PropagationEligible, code: "4.4.7"},
		{name: "unlinked failed then linked delayed", status: header + group("other@destination.example", "failed", "5.1.1") + group(receivedDestinationRaw, "delayed", "4.4.1"), linkage: RecipientLinkageLinked, propagation: PropagationNotFailure},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			evaluation, err := evaluateReceived(t, receivedSpec{deliveryStatus: testCase.status}, newReceivedAuthority(receivedLocalDomain))
			if err != nil || evaluation.RecipientLinkage() != testCase.linkage || evaluation.Propagation() != testCase.propagation {
				t.Fatalf("projection=%+v error=%v", projectionOf(evaluation), err)
			}
			if got := string(evaluation.PropagationStatus()); got != testCase.code {
				t.Fatalf("PropagationStatus()=%q want %q", got, testCase.code)
			}
		})
	}
}

// TestReceivedEvaluationReportFacts proves ENVID and matching ORCPT facts are
// exposed from the propagation group only.
func TestReceivedEvaluationReportFacts(t *testing.T) {
	status := "Original-Envelope-Id: envid-123\r\nReporting-MTA: dns; destination.example\r\n\r\n" +
		"Original-Recipient: rfc822; dest+40destination.example\r\nFinal-Recipient: rfc822; dest@destination.example\r\nAction: failed\r\nStatus: 5.1.1\r\n"
	evaluation, err := evaluateReceived(t, receivedSpec{deliveryStatus: status}, newReceivedAuthority(receivedLocalDomain))
	if err != nil || evaluation.Propagation() != PropagationEligible {
		t.Fatalf("projection=%+v error=%v", projectionOf(evaluation), err)
	}
	envelopeID, present := evaluation.OriginalEnvelopeID()
	if !present || string(envelopeID) != "envid-123" {
		t.Fatalf("OriginalEnvelopeID()=%q present=%t", envelopeID, present)
	}
	original, present := evaluation.OriginalRecipient()
	if !present || string(original) != "rfc822; dest+40destination.example" {
		t.Fatalf("OriginalRecipient()=%q present=%t", original, present)
	}
	envelopeID[0] = 'X'
	if again, _ := evaluation.OriginalEnvelopeID(); string(again) != "envid-123" {
		t.Fatal("OriginalEnvelopeID() exposed mutable storage")
	}
	mismatched := strings.Replace(status, "dest+40destination.example", "other+40destination.example", 1)
	evaluation, err = evaluateReceived(t, receivedSpec{deliveryStatus: mismatched}, newReceivedAuthority(receivedLocalDomain))
	if err != nil || evaluation.Propagation() != PropagationEligible {
		t.Fatalf("mismatched ORCPT projection=%+v error=%v", projectionOf(evaluation), err)
	}
	if _, present := evaluation.OriginalRecipient(); present {
		t.Fatal("OriginalRecipient() exposed an ORCPT that does not equal the rt= path")
	}
}

// TestReceivedEvaluationPreviousHopClassification proves terminal origin, nd=
// runs, unsupported chains, null previous senders, and ambiguous previous recipients.
func TestReceivedEvaluationPreviousHopClassification(t *testing.T) {
	corruptMember := receivedNextDomainHop(receivedLocalDomain, receivedForwardDomain)
	corruptMember.CorruptSignature = true
	forwardDestination := "<dest@destination.example>"
	for _, testCase := range []struct {
		name       string
		hops       []dsntest.Hop
		recipient  string
		local      []string
		want       PropagationResult
		wantLowest uint64
	}{
		{name: "terminal origin", hops: []dsntest.Hop{receivedHop(receivedLocalDomain, receivedLocalMailFrom, receivedDestination)},
			local: []string{receivedLocalDomain}, want: PropagationTerminalOrigin, wantLowest: 1},
		{name: "nd run", hops: []dsntest.Hop{
			receivedHop(receivedRemoteDomain, "<sender@remote.example>", receivedLocalRecipient),
			receivedNextDomainHop(receivedLocalDomain, receivedForwardDomain),
			receivedHop(receivedForwardDomain, receivedForwardMailFrom, forwardDestination),
		}, recipient: receivedForwardMailFrom, local: []string{receivedLocalDomain, receivedForwardDomain}, want: PropagationEligible, wantLowest: 2},
		{name: "imaginary hop run", hops: []dsntest.Hop{
			receivedHop(receivedRemoteDomain, "<sender@remote.example>", receivedLocalRecipient),
			receivedHop(receivedLocalDomain, receivedLocalRecipient, "<user@forward.local.example>"),
			receivedHop(receivedForwardDomain, receivedForwardMailFrom, forwardDestination),
		}, recipient: receivedForwardMailFrom, local: []string{receivedLocalDomain, receivedForwardDomain}, want: PropagationEligible, wantLowest: 2},
		{name: "previous hop is nd", hops: []dsntest.Hop{
			receivedHop(receivedOriginDomain, "<sender@origin.example>", "<relay@remote.example>"),
			receivedNextDomainHop(receivedRemoteDomain, receivedLocalDomain),
			receivedHop(receivedLocalDomain, receivedLocalMailFrom, receivedDestination),
		}, local: []string{receivedLocalDomain}, want: PropagationUnsupportedChain, wantLowest: 3},
		{name: "run member does not verify", hops: []dsntest.Hop{
			receivedHop(receivedRemoteDomain, "<sender@remote.example>", receivedLocalRecipient),
			corruptMember,
			receivedHop(receivedForwardDomain, receivedForwardMailFrom, forwardDestination),
		}, recipient: receivedForwardMailFrom, local: []string{receivedLocalDomain, receivedForwardDomain}, want: PropagationUnsupportedChain, wantLowest: 2},
		{name: "null previous sender", hops: []dsntest.Hop{
			receivedHop(receivedRemoteDomain, "<>", receivedLocalRecipient),
			receivedHop(receivedLocalDomain, receivedLocalMailFrom, receivedDestination),
		}, local: []string{receivedLocalDomain}, want: PropagationForbiddenNullPreviousSender, wantLowest: 2},
		{name: "ambiguous previous recipient", hops: []dsntest.Hop{
			receivedHop(receivedRemoteDomain, "<sender@remote.example>", receivedLocalRecipient, "<other@local.example>"),
			receivedHop(receivedLocalDomain, receivedLocalMailFrom, receivedDestination),
		}, local: []string{receivedLocalDomain}, want: PropagationNotReconstructable, wantLowest: 2},
		{name: "nd member under foreign domain ends run", hops: []dsntest.Hop{
			receivedHop(receivedRemoteDomain, "<sender@remote.example>", receivedLocalRecipient),
			receivedNextDomainHop(receivedLocalDomain, receivedForwardDomain),
			receivedHop(receivedForwardDomain, receivedForwardMailFrom, forwardDestination),
		}, recipient: receivedForwardMailFrom, local: []string{receivedForwardDomain}, want: PropagationUnsupportedChain, wantLowest: 3},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			spec := receivedSpec{hops: testCase.hops, outerRecipient: testCase.recipient}
			evaluation, err := evaluateReceived(t, spec, newReceivedAuthority(testCase.local...))
			if err != nil || evaluation.Propagation() != testCase.want || evaluation.LocalHop() != LocalHopLocal ||
				evaluation.RecipientLinkage() != RecipientLinkageLinked {
				t.Fatalf("projection=%+v error=%v", projectionOf(evaluation), err)
			}
			run, ok := evaluation.Run()
			if !ok || run.LowestSequence() != testCase.wantLowest {
				t.Fatalf("run ok=%t lowest=%d", ok, run.LowestSequence())
			}
		})
	}
}

// TestReceivedEvaluationRunMemberTemporaryKeyFailure proves a temporary key
// failure on a run member is reported as an incomplete embedded verification.
func TestReceivedEvaluationRunMemberTemporaryKeyFailure(t *testing.T) {
	hops := []dsntest.Hop{
		receivedHop(receivedRemoteDomain, "<sender@remote.example>", receivedLocalRecipient),
		receivedNextDomainHop(receivedLocalDomain, receivedForwardDomain),
		receivedHop(receivedForwardDomain, receivedForwardMailFrom, receivedDestination),
	}
	verifier, _ := mustReceivedVerifier(t, receivedLocalDomain)
	evaluator, err := NewReceivedEvaluator(verifier, ReceivedEvaluatorConfig{})
	if err != nil {
		t.Fatal(err)
	}
	raw := receivedSpec{hops: hops, outerRecipient: receivedForwardMailFrom}.build(t)
	evaluation, err := evaluator.Evaluate(context.Background(), ReceivedRequest{Raw: raw, OuterRecipient: []byte(receivedForwardMailFrom), Authority: newReceivedAuthority(receivedLocalDomain, receivedForwardDomain)})
	if err != nil || evaluation.Embedded() != EmbeddedTemporaryError || evaluation.LocalHop() != LocalHopNotEvaluated || evaluation.Propagation() != PropagationNotEvaluated {
		t.Fatalf("projection=%+v error=%v", projectionOf(evaluation), err)
	}
}

// TestReceivedEvaluationRequestAndCancellation proves invalid requests and
// cancellation are typed staged errors that never carry content.
func TestReceivedEvaluationRequestAndCancellation(t *testing.T) {
	verifier, _ := mustReceivedVerifier(t, "")
	evaluator, err := NewReceivedEvaluator(verifier, ReceivedEvaluatorConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewReceivedEvaluator(verify.Verifier{}, ReceivedEvaluatorConfig{}); !IsReceivedErrorCode(err, ReceivedErrorInvalidRequest) {
		t.Fatalf("NewReceivedEvaluator(zero verifier) error=%v", err)
	}
	valid := receivedSpec{}.build(t)
	for _, testCase := range []struct {
		name      string
		ctx       context.Context
		request   ReceivedRequest
		wantStage ReceivedStage
	}{
		{name: "nil context", ctx: nil, request: ReceivedRequest{Raw: valid, OuterRecipient: []byte(receivedLocalMailFrom)}, wantStage: ReceivedStagePreflight},
		{name: "empty raw", ctx: context.Background(), request: ReceivedRequest{OuterRecipient: []byte(receivedLocalMailFrom)}, wantStage: ReceivedStagePreflight},
		{name: "invalid outer recipient", ctx: context.Background(), request: ReceivedRequest{Raw: valid, OuterRecipient: []byte("forwarded@local.example")}, wantStage: ReceivedStagePreflight},
		{name: "null outer recipient", ctx: context.Background(), request: ReceivedRequest{Raw: valid, OuterRecipient: []byte("<>")}, wantStage: ReceivedStagePreflight},
		{name: "unsigned outer report", ctx: context.Background(), request: ReceivedRequest{Raw: receivedSpec{outerUnsigned: true}.build(t), OuterRecipient: []byte(receivedLocalMailFrom)}, wantStage: ReceivedStageStructure},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := evaluator.Evaluate(testCase.ctx, testCase.request)
			if !IsReceivedErrorCode(err, ReceivedErrorInvalidRequest) || ReceivedStageOf(err) != testCase.wantStage {
				t.Fatalf("error=%v stage=%q", err, ReceivedStageOf(err))
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = evaluator.Evaluate(ctx, ReceivedRequest{Raw: valid, OuterRecipient: []byte(receivedLocalMailFrom), Authority: newReceivedAuthority(receivedLocalDomain)})
	if !errors.Is(err, context.Canceled) || !IsReceivedErrorCode(err, ReceivedErrorCanceled) || !ReceivedStageOf(err).Known() {
		t.Fatalf("canceled error=%v stage=%q", err, ReceivedStageOf(err))
	}
	cancelling := &cancellingAuthority{}
	cancelCtx, cancelLater := context.WithCancel(context.Background())
	cancelling.cancel = cancelLater
	_, err = evaluator.Evaluate(cancelCtx, ReceivedRequest{Raw: valid, OuterRecipient: []byte(receivedLocalMailFrom), Authority: cancelling})
	if !errors.Is(err, context.Canceled) || ReceivedStageOf(err) != ReceivedStageLocalHop {
		t.Fatalf("in-flight cancellation error=%v stage=%q", err, ReceivedStageOf(err))
	}
	if strings.Contains(err.Error(), "local.example") || strings.Contains(fmt.Sprintf("%+v", err), "local.example") {
		t.Fatalf("error leaked content: %v", err)
	}
}

// cancellingAuthority cancels the caller context during the first lookup.
type cancellingAuthority struct{ cancel context.CancelFunc }

// LookupLocalAuthority cancels and returns the context error.
func (a *cancellingAuthority) LookupLocalAuthority(ctx context.Context, _ string) (verify.LocalAuthorityStatus, error) {
	a.cancel()
	return "", ctx.Err()
}

// TestReceivedEvaluationImmutabilityAndRedaction proves accessors return copies
// and formatting never exposes addresses, domains, or report content.
func TestReceivedEvaluationImmutabilityAndRedaction(t *testing.T) {
	status := "Original-Envelope-Id: " + receivedPrivateMarker + "\r\nReporting-MTA: dns; destination.example\r\n\r\n" +
		"Final-Recipient: rfc822; dest@destination.example\r\nAction: failed\r\nStatus: 5.1.1\r\n"
	evaluation, err := evaluateReceived(t, receivedSpec{deliveryStatus: status}, newReceivedAuthority(receivedLocalDomain))
	if err != nil || !evaluation.Valid() {
		t.Fatal(err)
	}
	status1 := evaluation.PropagationStatus()
	status1[0] = '9'
	if string(evaluation.PropagationStatus()) != receivedFailedStatus {
		t.Fatal("PropagationStatus() exposed mutable storage")
	}
	for _, rendered := range []string{evaluation.String(), evaluation.GoString(), fmt.Sprintf("%v", evaluation), fmt.Sprintf("%+v", evaluation), fmt.Sprintf("%#v", evaluation), fmt.Sprint(&evaluation)} {
		for _, forbidden := range []string{receivedPrivateMarker, "local.example", "destination.example", "forwarded", "5.1.1"} {
			if strings.Contains(rendered, forbidden) {
				t.Fatalf("formatted evaluation leaked %q: %q", forbidden, rendered)
			}
		}
	}
	var zero ReceivedEvaluation
	if zero.Valid() || zero.Structure() != "" || zero.Propagation() != "" {
		t.Fatal("zero evaluation is not inert")
	}
	if _, ok := zero.Run(); ok {
		t.Fatal("zero evaluation exposed a run")
	}
}

// TestReceivedEvaluationConcurrentReuse proves one evaluator is safe for concurrent use.
func TestReceivedEvaluationConcurrentReuse(t *testing.T) {
	verifier, _ := mustReceivedVerifier(t, "")
	evaluator, err := NewReceivedEvaluator(verifier, ReceivedEvaluatorConfig{})
	if err != nil {
		t.Fatal(err)
	}
	raw := receivedSpec{}.build(t)
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			evaluation, err := evaluator.Evaluate(context.Background(), ReceivedRequest{Raw: raw, OuterRecipient: []byte(receivedLocalMailFrom), Authority: newReceivedAuthority(receivedLocalDomain)})
			if err != nil || evaluation.Propagation() != PropagationEligible {
				t.Errorf("Evaluate() propagation=%q error=%v", evaluation.Propagation(), err)
			}
		})
	}
	group.Wait()
}

// TestReceivedEvaluationCompletionWindowUsesOuterTimestamp proves the
// completion signature's Section 8.4 window is evaluated against the outer
// DSN's highest-signature t= rather than the wall clock: a DSN generated one
// day after a forwarding that happened long ago still verifies when it is
// evaluated later, while a DSN generated too long after the forwarding or
// before the forwarding does not.
func TestReceivedEvaluationCompletionWindowUsesOuterTimestamp(t *testing.T) {
	const day = 24 * 60 * 60
	completion := dsntest.DefaultTimestamp
	for _, testCase := range []struct {
		name  string
		outer uint64
		now   time.Time
		want  EmbeddedResult
	}{
		{name: "old forwarding, DSN generated a day later, evaluated a month later", outer: completion + day, now: time.Unix(int64(completion)+30*day, 0), want: EmbeddedVerified},
		{name: "old forwarding, DSN generated after the maximum age", outer: completion + 30*day, now: time.Unix(int64(completion)+30*day+60, 0), want: EmbeddedUnverified},
		{name: "DSN generated before the forwarding beyond skew", outer: completion - 3600, now: time.Unix(int64(completion)+60, 0), want: EmbeddedUnverified},
		{name: "DSN generated within skew before the forwarding", outer: completion - 60, now: time.Unix(int64(completion)+60, 0), want: EmbeddedVerified},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			verifier, _ := mustReceivedVerifierAt(t, "", testCase.now)
			evaluator, err := NewReceivedEvaluator(verifier, ReceivedEvaluatorConfig{})
			if err != nil {
				t.Fatal(err)
			}
			raw := receivedSpec{outerTimestamp: testCase.outer}.build(t)
			evaluation, err := evaluator.Evaluate(context.Background(), ReceivedRequest{Raw: raw, OuterRecipient: []byte(receivedLocalMailFrom), Authority: newReceivedAuthority(receivedLocalDomain)})
			if err != nil || evaluation.Embedded() != testCase.want {
				t.Fatalf("projection=%+v error=%v want embedded=%q", projectionOf(evaluation), err, testCase.want)
			}
			if testCase.want == EmbeddedVerified && evaluation.Propagation() != PropagationEligible {
				t.Fatalf("projection=%+v", projectionOf(evaluation))
			}
		})
	}
}

// TestReceivedEvaluationParentDomainForeignSignerIsNotLocal proves that a
// verified completion signature under a foreign parent domain that names a
// local address in mf= passes the Section 11.4 relaxed match and still stops
// at the locality gate as not_local: the authority is asked about the signer's
// d=, never about the mf= domain.
func TestReceivedEvaluationParentDomainForeignSignerIsNotLocal(t *testing.T) {
	hops := []dsntest.Hop{
		receivedHop(receivedRemoteDomain, "<sender@remote.example>", receivedLocalRecipient),
		receivedHop(receivedParentDomain, receivedLocalMailFrom, receivedDestination),
	}
	authority := newReceivedAuthority(receivedLocalDomain)
	evaluation, err := evaluateReceived(t, receivedSpec{hops: hops}, authority)
	if err != nil {
		t.Fatal(err)
	}
	want := projection{
		structure: StructureValid, embedded: EmbeddedVerified, localHop: LocalHopNotLocal,
		alignment: OuterAlignmentNotEvaluated, linkage: RecipientLinkageNotEvaluated, propagation: PropagationNotEvaluated,
	}
	if got := projectionOf(evaluation); got != want {
		t.Fatalf("projection=%+v want=%+v", got, want)
	}
	if evaluation.CompletionDomain() != "" {
		t.Fatalf("CompletionDomain()=%q for a foreign signer", evaluation.CompletionDomain())
	}
	if len(authority.lookups) != 1 || authority.lookups[0] != receivedParentDomain {
		t.Fatalf("authority lookups=%v want only %q", authority.lookups, receivedParentDomain)
	}
}

// TestVerifierContractErrorClassification proves the embedded stage treats
// only internal-misuse and request-class verifier errors as contract errors,
// so they surface as ReceivedErrorInternal instead of degrading a message
// into unverified, while context and unrelated errors are not contract errors.
func TestVerifierContractErrorClassification(t *testing.T) {
	verifier, _ := mustReceivedVerifier(t, "")
	_, internalErr := verifier.ExtractEmbeddedInput(rawmsg.Message{})
	_, _, requestErr := verify.DetectLocalHopRun(context.Background(), []signature.Signature{{}}, 1, newReceivedAuthority(receivedLocalDomain), verify.LocalHopRunLimits{MaxAuthorityLookups: -1})
	if internalErr == nil || requestErr == nil {
		t.Fatalf("fixture errors internal=%v request=%v", internalErr, requestErr)
	}
	for name, tt := range map[string]struct {
		err  error
		want bool
	}{
		"internal misuse":    {err: internalErr, want: true},
		"request options":    {err: requestErr, want: true},
		"context canceled":   {err: context.Canceled, want: false},
		"unrelated error":    {err: errors.New("unrelated"), want: false},
		"nil error":          {err: nil, want: false},
		"wrapped internal":   {err: fmt.Errorf("wrapped: %w", internalErr), want: true},
		"typed nil verifier": {err: (*verify.Error)(nil), want: false},
	} {
		if got := verifierContractError(tt.err); got != tt.want {
			t.Fatalf("%s: verifierContractError()=%t want %t", name, got, tt.want)
		}
	}
}
