package dkim2

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/dsn/dsntest"
)

const (
	receivedDSNOriginDomain      = "origin.example"
	receivedDSNRemoteDomain      = "remote.example"
	receivedDSNLocalDomain       = "local.example"
	receivedDSNForwardDomain     = "forward.local.example"
	receivedDSNDestinationDomain = "destination.example"
	receivedDSNOtherDomain       = "other.example"
	receivedDSNParentDomain      = "example"
	receivedDSNLocalRecipient    = "<user@local.example>"
	receivedDSNLocalMailFrom     = "<forwarded@local.example>"
	receivedDSNForwardMailFrom   = "<forwarded@forward.local.example>"
	receivedDSNDestination       = "<dest@destination.example>"
	receivedDSNDestinationRaw    = "dest@destination.example"
	receivedDSNClock             = int64(dsntest.DefaultTimestamp) + 60
	receivedDSNOtherLocal        = "<other@local.example>"
	receivedDSNMalformedStatus   = "Reporting-MTA: dns; destination.example\r\n"
	// receivedDSNPostfixOrderStatus is the delivery-status field order Postfix
	// bounce(8) emits: extensions before Arrival-Date, Final-Recipient before
	// Original-Recipient.
	receivedDSNPostfixOrderStatus = "Reporting-MTA: dns; destination.example\r\n" +
		"X-Postfix-Queue-ID: 4hcQ6z1Cg6z1X\r\n" +
		"X-Postfix-Sender: rfc822; forwarded@local.example\r\n" +
		"Arrival-Date: Sat, 05 Sep 2026 07:33:31 +0000 (UTC)\r\n\r\n" +
		"Final-Recipient: rfc822; dest@destination.example\r\n" +
		"Original-Recipient: rfc822;dest@destination.example\r\n" +
		"Action: failed\r\nStatus: 5.1.1\r\n" +
		"Remote-MTA: dns; 127.0.0.1\r\n" +
		"Diagnostic-Code: smtp; 550 5.1.1 forced qualification failure\r\n"
	receivedDSNDay = uint64(24 * 60 * 60)
)

// receivedDSNKeys returns deterministic keys for every fixture domain.
func receivedDSNKeys() map[string]dsntest.Key {
	return map[string]dsntest.Key{
		receivedDSNOriginDomain:      dsntest.KeyForLabel("origin", "sel"),
		receivedDSNRemoteDomain:      dsntest.KeyForLabel("remote", "sel"),
		receivedDSNLocalDomain:       dsntest.KeyForLabel("local", "sel"),
		receivedDSNForwardDomain:     dsntest.KeyForLabel("forward", "sel"),
		receivedDSNDestinationDomain: dsntest.KeyForLabel("destination", "sel"),
		receivedDSNOtherDomain:       dsntest.KeyForLabel("other", "sel"),
		receivedDSNParentDomain:      dsntest.KeyForLabel("parent", "sel"),
	}
}

// receivedDSNHop renders one ordinary hop for a fixture domain.
func receivedDSNHop(domain, mailFrom string, recipients ...string) dsntest.Hop {
	return dsntest.Hop{Domain: domain, Key: receivedDSNKeys()[domain], MailFrom: mailFrom, Recipients: recipients}
}

// receivedDSNNextDomainHop renders one nd= hop for a fixture domain.
func receivedDSNNextDomainHop(domain, next string) dsntest.Hop {
	return dsntest.Hop{Domain: domain, Key: receivedDSNKeys()[domain], NextDomain: next}
}

// receivedDSNDefaultHops returns the ordinary forwarded two-hop chain.
func receivedDSNDefaultHops() []dsntest.Hop {
	return []dsntest.Hop{
		receivedDSNHop(receivedDSNRemoteDomain, "<sender@remote.example>", receivedDSNLocalRecipient),
		receivedDSNHop(receivedDSNLocalDomain, receivedDSNLocalMailFrom, receivedDSNDestination),
	}
}

// receivedDSNParentSignerHops returns a chain whose completion signature is a
// verified foreign parent-domain signer naming a local address in mf=.
func receivedDSNParentSignerHops() []dsntest.Hop {
	return []dsntest.Hop{
		receivedDSNHop(receivedDSNRemoteDomain, "<sender@remote.example>", receivedDSNLocalRecipient),
		receivedDSNHop(receivedDSNParentDomain, receivedDSNLocalMailFrom, receivedDSNDestination),
	}
}

// receivedDSNHopsAt returns the default chain with every t= shifted to the given instant.
func receivedDSNHopsAt(timestamp uint64) []dsntest.Hop {
	hops := receivedDSNDefaultHops()
	for index := range hops {
		hops[index].Timestamp = timestamp
	}
	return hops
}

// receivedDSNSpec describes one received DSN fixture at the public facade level.
type receivedDSNSpec struct {
	hops           []dsntest.Hop
	headersOnly    bool
	unsigned       bool
	deliveryStatus string
	outerSigner    string
	outerRecipient string
	outerTimestamp uint64
}

// recipient returns the observed outer recipient for the spec.
func (s receivedDSNSpec) recipient() string {
	if s.outerRecipient == "" {
		return receivedDSNLocalMailFrom
	}
	return s.outerRecipient
}

// build renders the outer DSN bytes for the spec.
func (s receivedDSNSpec) build(t testing.TB) []byte {
	t.Helper()
	hops := s.hops
	if hops == nil {
		hops = receivedDSNDefaultHops()
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
	contentType := "message/rfc822"
	if s.headersOnly {
		contentType = "text/rfc822-headers"
		original = dsntest.HeaderBlock(original)
	}
	deliveryStatus := s.deliveryStatus
	if deliveryStatus == "" {
		deliveryStatus = dsntest.FailedDeliveryStatus(receivedDSNDestinationDomain, receivedDSNDestinationRaw, "5.1.1")
	}
	signerDomain := s.outerSigner
	if signerDomain == "" {
		signerDomain = receivedDSNDestinationDomain
	}
	signer := receivedDSNHop(signerDomain, "<>", s.recipient())
	signer.Timestamp = s.outerTimestamp
	raw, err := (dsntest.Report{
		OuterHeaders:        "From: MAILER-DAEMON@" + signerDomain + "\r\nSubject: Undelivered Mail\r\n",
		Human:               "delivery failed",
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

// receivedDSNProvider serves fixture keys through the public provider contract.
type receivedDSNProvider struct {
	temporaryDomain string
	missing         bool
	lookups         int
	mu              sync.Mutex
}

// LookupPublicKey implements PublicKeyProvider for fixtures.
func (p *receivedDSNProvider) LookupPublicKey(_ context.Context, query PublicKeyQuery) (PublicKeyResult, error) {
	p.mu.Lock()
	p.lookups++
	p.mu.Unlock()
	if p.missing {
		return MissingPublicKey(query.Algorithm()), nil
	}
	if p.temporaryDomain != "" && query.SigningDomain() == p.temporaryDomain {
		return PublicKeyResult{}, NewTemporaryProviderError()
	}
	key, ok := receivedDSNKeys()[query.SigningDomain()]
	if !ok || key.Selector != query.Selector() || query.Algorithm() != AlgorithmEd25519SHA256 {
		return MissingPublicKey(query.Algorithm()), nil
	}
	return FoundEd25519PublicKey(key.Public()), nil
}

// receivedDSNAuthority answers locality from a fixed domain set or simulates an outage.
type receivedDSNAuthority struct {
	local     map[string]struct{}
	temporary bool
	unknown   bool
}

// LookupLocalAuthority implements LocalAuthority for fixtures.
func (a *receivedDSNAuthority) LookupLocalAuthority(ctx context.Context, domain string) (LocalAuthorityStatus, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if a.temporary {
		return "", errors.New("datasource unavailable")
	}
	if a.unknown {
		return LocalAuthorityStatus("maybe"), nil
	}
	if _, ok := a.local[domain]; ok {
		return LocalAuthorityLocal, nil
	}
	return LocalAuthorityNotLocal, nil
}

// newReceivedDSNAuthority treats the named domains as local authority domains.
func newReceivedDSNAuthority(domains ...string) *receivedDSNAuthority {
	local := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		local[domain] = struct{}{}
	}
	return &receivedDSNAuthority{local: local}
}

// receivedDSNClockOption fixes the verification clock just after the fixture timestamp.
func receivedDSNClockOption() VerifierOption {
	return WithVerificationClock(func() time.Time { return time.Unix(receivedDSNClock, 0) })
}

// mustReceivedDSNVerifier constructs the public verifier over the fixture provider.
func mustReceivedDSNVerifier(t testing.TB, provider PublicKeyProvider) *Verifier {
	t.Helper()
	evaluator, err := NewVerifier(provider, receivedDSNClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error=%v", err)
	}
	return evaluator
}

// evaluateReceivedDSN evaluates one spec with the fixture provider and authority.
func evaluateReceivedDSN(t testing.TB, spec receivedDSNSpec, authority LocalAuthority) (ReceivedDSNEvaluation, error) {
	t.Helper()
	evaluator := mustReceivedDSNVerifier(t, &receivedDSNProvider{})
	return evaluator.EvaluateReceivedDSN(context.Background(), NewReceivedDSNRequest(spec.build(t), []byte("<>"), [][]byte{[]byte(spec.recipient())}, authority))
}
