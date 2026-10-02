package dkim2

import (
	"bytes"
	"errors"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
)

// TestHeaderFromDomainAcceptsOnlyOneASCIIDNSMailbox locks the null-sender
// identity derivation to one From field with one canonical DNS mailbox.
func TestHeaderFromDomainAcceptsOnlyOneASCIIDNSMailbox(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		header string
		domain string
	}{
		{name: "bare", header: "From: alice@Example.TEST\r\n", domain: testSigningDomain},
		{name: "angle", header: "From: Alice <alice@example.test>\r\n", domain: testSigningDomain},
		{name: "quoted display with punctuation", header: "From: \"Doe, Jane: Ops;\" <jane@sub.example.test>\r\n", domain: "sub.example.test"},
		{name: "comment", header: "From: alice@example.test (Vacation, auto: reply)\r\n", domain: testSigningDomain},
		{name: "folded", header: "From: Auto Reply\r\n <noreply@example.test>\r\n", domain: testSigningDomain},
		{name: "encoded word unknown charset", header: "From: =?x-unknown?Q?Abwesenheit?= <a@example.test>\r\n", domain: testSigningDomain},
		{name: "lower case field name", header: "from: alice@example.test\r\n", domain: testSigningDomain},
		{name: "absent", header: "Sender: alice@example.test\r\n"},
		{name: "two fields", header: "From: alice@example.test\r\nFrom: bob@example.test\r\n"},
		{name: "two mailboxes", header: "From: alice@example.test, bob@example.test\r\n"},
		{name: "group", header: "From: Team: alice@example.test;\r\n"},
		{name: "empty group", header: "From: undisclosed-recipients:;\r\n"},
		{name: "address literal", header: "From: alice@[192.0.2.1]\r\n"},
		{name: "utf8 domain", header: "From: alice@b\xc3\xbccher.example\r\n"},
		{name: "utf8 local part", header: "From: j\xc3\xb6rg@example.test\r\n"},
		{name: "no domain", header: "From: alice\r\n"},
		{name: "empty", header: "From: \r\n"},
		{name: "null path", header: "From: <>\r\n"},
		{name: "bad label", header: "From: alice@-example.test\r\n"},
		{name: "underscore", header: "From: alice@ex_ample.test\r\n"},
		{name: "unbalanced angle", header: "From: Alice <alice@example.test\r\n"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			raw := []byte(testCase.header + "To: bob@example.net\r\n\r\nbody\r\n")
			domain, ok := HeaderFromDomain(raw)
			if ok != (testCase.domain != "") || domain != testCase.domain {
				t.Fatalf("HeaderFromDomain() = %q, %t; want %q", domain, ok, testCase.domain)
			}
		})
	}
	if _, ok := HeaderFromDomain([]byte("not a message")); ok {
		t.Fatal("malformed message produced a domain")
	}
}

// nullSenderTicket plans one exact originator ticket for the null reverse path.
func (f publicSigningFixture) nullSenderTicket(t *testing.T, raw []byte, recipient []byte) RouteCopyTicket {
	t.Helper()
	source, err := NewSigningSource(raw)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := NewOriginatorRouteEntry(source, []byte("<>"), [][]byte{recipient}, RouteDisclosureSingle, []byte("null-sender-route"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewRouteFanoutRequest([]RouteEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	_, tickets, err := f.facade.PlanRouteFanout(t.Context(), request)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout() tickets=%d error=%v", len(tickets), err)
	}
	return tickets[0]
}

// TestHeaderFromNullSenderSigningVerifiesWithNullMailFrom proves the explicit
// trusted-route request signs mf=<> with d= equal to the From domain and the
// result verifies through the public verifier.
func TestHeaderFromNullSenderSigningVerifiesWithNullMailFrom(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	raw := []byte("From: Alice <alice@example.test>\r\nTo: bob@example.net\r\nSubject: Out of office\r\nAuto-Submitted: auto-replied\r\n\r\nbody\r\n")
	recipient := []byte("<bob@example.net>")
	result, recovery, err := fixture.facade.SignOriginator(t.Context(), NewHeaderFromNullSenderSigningRequest(
		raw, [][]byte{recipient}, fixture.nullSenderTicket(t, raw, recipient), fixture.profile,
		SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
	))
	if err != nil || recovery.Valid() {
		t.Fatalf("SignOriginator(header_from null) recovery=%t error=%v", recovery.Valid(), err)
	}
	signed, ok := result.Unrestricted()
	if !ok {
		t.Fatal("null-sender signing did not return unrestricted output")
	}
	message, err := rawmsg.Parse(signed.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := signature.Extract(message)
	if err != nil || len(signatures) != 1 || signatures[0].Domain() != "example.test" ||
		!bytes.Equal(signatures[0].MailFrom().Value(), []byte("<>")) ||
		len(signatures[0].Recipients()) != 1 || !bytes.Equal(signatures[0].Recipients()[0].Value(), recipient) {
		t.Fatalf("signature envelope mismatch: signatures=%d error=%v", len(signatures), err)
	}
	fixture.assertPublicChainPass(t, signed.Bytes(), []byte("<>"), [][]byte{recipient}, 1)
}

// TestHeaderFromNullSenderSigningRefusesForeignOrAmbiguousAuthors proves
// the profile domain must equal the single From domain and that the generic
// originator request still refuses a null reverse path.
func TestHeaderFromNullSenderSigningRefusesForeignOrAmbiguousAuthors(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	recipient := []byte("<bob@example.net>")
	for _, raw := range [][]byte{
		[]byte("From: mallory@example.org\r\nTo: bob@example.net\r\n\r\nbody\r\n"),
		[]byte("From: alice@example.test, bob@example.test\r\nTo: bob@example.net\r\n\r\nbody\r\n"),
		[]byte("To: bob@example.net\r\n\r\nbody\r\n"),
	} {
		_, recovery, err := fixture.facade.SignOriginator(t.Context(), NewHeaderFromNullSenderSigningRequest(
			raw, [][]byte{recipient}, fixture.nullSenderTicket(t, raw, recipient), fixture.profile,
			SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
		))
		if !errors.Is(err, newSigningError(SigningErrorAuthorizationDenied)) || recovery.Valid() {
			t.Fatalf("foreign author error=%v recovery=%t", err, recovery.Valid())
		}
	}
	raw := []byte("From: alice@example.test\r\nTo: bob@example.net\r\n\r\nbody\r\n")
	_, _, err := fixture.facade.SignOriginator(t.Context(), NewOriginatorSigningRequest(
		raw, []byte("<>"), [][]byte{recipient}, fixture.nullSenderTicket(t, raw, recipient), fixture.profile,
		SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
	))
	if !errors.Is(err, newSigningError(SigningErrorInvalidRequest)) {
		t.Fatalf("generic null-sender request error=%v", err)
	}
}
