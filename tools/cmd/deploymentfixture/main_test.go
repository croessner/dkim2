//nolint:goconst // Independent deployment assertions intentionally repeat protocol fixture values.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"slices"
	"strings"
	"testing"

	dkim2 "github.com/croessner/dkim2"
)

// TestSMTPReplyRequiresExactQueuedAcceptance freezes real Postfix queue evidence.
func TestSMTPReplyRequiresExactQueuedAcceptance(t *testing.T) {
	reply, err := readSMTPReply(bufio.NewReader(strings.NewReader(
		"250-mx.operator.test\r\n250 2.0.0 Ok: queued as ABC123\r\n",
	)))
	if err != nil || reply.code != 250 {
		t.Fatal("valid bounded SMTP acceptance reply was rejected")
	}
	if identifier, ok := queuedID(reply); !ok || identifier != "ABC123" {
		t.Fatal("exact Postfix queue identifier was not extracted")
	}
	for _, hostile := range []smtpReply{
		{code: 250, terminal: "250 OK"},
		{code: 250, terminal: "250 2.0.0 Ok: queued as ../../queue"},
		{code: 451, terminal: "451 4.7.1 temporary"},
	} {
		if _, ok := queuedID(hostile); ok {
			t.Fatal("non-queue SMTP response produced queue evidence")
		}
	}
}

// TestCapabilitySelectionMinimizesMilterAndDaemonAuthority freezes route separation.
func TestCapabilitySelectionMinimizesMilterAndDaemonAuthority(t *testing.T) {
	if !slices.Equal(daemonCapabilityNames("inbound"), []string{"capability"}) {
		t.Fatal("inbound daemon received signing authority")
	}
	if !slices.Equal(
		daemonCapabilityNames("originator"),
		[]string{"capability", "sign-capability"},
	) {
		t.Fatal("originator daemon received authority outside process and sign")
	}
	if !slices.Equal(
		daemonCapabilityNames("ordinary_transit"),
		[]string{"capability", "revise-capability"},
	) {
		t.Fatal("transit daemon received authority outside process and revise")
	}
	if daemonCapabilityNames("unknown") != nil {
		t.Fatal("unknown route received daemon authority")
	}
	for mode, expected := range map[string]string{
		"inbound": "capability", "originator": "sign-capability",
		"ordinary_transit": "revise-capability",
	} {
		if actual := capabilityForMode(mode); actual != expected {
			t.Fatalf("mode %s selected %s", mode, actual)
		}
	}
	if capabilityForMode("unknown") != "" {
		t.Fatal("unknown route received authority")
	}
}

// TestRouteCapabilityMarkersAreUniqueAndSearchable freezes the deployment
// privacy seeds without weakening the production capability shape.
func TestRouteCapabilityMarkersAreUniqueAndSearchable(t *testing.T) {
	pairs := [][2]string{
		{"inbound", "capability"},
		{"originator", "capability"},
		{"originator", "sign-capability"},
		{"transit", "capability"},
		{"transit", "revise-capability"},
	}
	seen := make(map[string]struct{}, len(pairs))
	for _, pair := range pairs {
		value, err := routeCapabilityMarker(pair[0], pair[1])
		if err != nil || len(value) != 32 ||
			!bytes.HasPrefix(value, []byte("privacy-cap-")) {
			t.Fatal("route capability privacy marker was not exact")
		}
		if _, duplicate := seen[string(value)]; duplicate {
			t.Fatal("route capability privacy marker was reused")
		}
		seen[string(value)] = struct{}{}
		clear(value)
	}
	if value, err := routeCapabilityMarker("unknown", "capability"); err == nil ||
		value != nil {
		t.Fatal("unknown route received a privacy capability")
	}
}

// TestAnswerDNSBoundsQueriesAndReturnsOnlyBoundTXT freezes fixture DNS parsing.
func TestAnswerDNSBoundsQueriesAndReturnsOnlyBoundTXT(t *testing.T) {
	owner := originSelector + "._domainkey." + originDomain + "."
	query := dnsQuery(t, owner, 16)
	response, ok := answerDNS(query, map[string]string{owner: "v=DKIM1; k=rsa; p=AA=="})
	if !ok || len(response) <= len(query) ||
		binary.BigEndian.Uint16(response[6:8]) != 1 {
		t.Fatal("valid TXT query did not receive one answer")
	}
	ednsQuery := append(append([]byte(nil), query...),
		0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0,
	)
	binary.BigEndian.PutUint16(ednsQuery[10:12], 1)
	if ednsResponse, accepted := answerDNS(
		ednsQuery,
		map[string]string{owner: "v=DKIM1; k=rsa; p=AA=="},
	); !accepted || binary.BigEndian.Uint16(ednsResponse[6:8]) != 1 ||
		binary.BigEndian.Uint16(ednsResponse[10:12]) != 0 {
		t.Fatal("valid bounded EDNS query was not answered without extension state")
	}
	longRecord := strings.Repeat("x", 300)
	multiString, ok := answerDNS(query, map[string]string{owner: longRecord})
	if !ok || binary.BigEndian.Uint16(multiString[len(query)+10:len(query)+12]) !=
		uint16(len(longRecord)+2) {
		t.Fatal("long TXT record was not split into bounded character strings")
	}
	for _, hostile := range [][]byte{
		nil,
		make([]byte, 11),
		append([]byte(nil), query[:len(query)-1]...),
		append(append([]byte(nil), query...), make([]byte, 5000)...),
	} {
		if len(hostile) > 4096 {
			hostile = hostile[:11]
		}
		_, _ = answerDNS(hostile, map[string]string{owner: "value"})
	}
	nxdomain, ok := answerDNS(dnsQuery(t, "missing.example.test.", 16), map[string]string{})
	if !ok || binary.BigEndian.Uint16(nxdomain[2:4])&0x000f != 3 {
		t.Fatal("missing owner did not return NXDOMAIN")
	}
	for _, mutate := range []func([]byte) []byte{
		func(value []byte) []byte {
			binary.BigEndian.PutUint16(value[2:4], 0x8000)
			return value
		},
		func(value []byte) []byte {
			binary.BigEndian.PutUint16(value[2:4], 0x0800)
			return value
		},
		func(value []byte) []byte {
			binary.BigEndian.PutUint16(value[len(value)-2:], 3)
			return value
		},
		func(value []byte) []byte {
			return append(value, 0)
		},
		func(value []byte) []byte {
			binary.BigEndian.PutUint16(value[10:12], 2)
			return value
		},
		func(value []byte) []byte {
			value[12] = 0xc0
			return value
		},
	} {
		hostile := mutate(append([]byte(nil), query...))
		if _, accepted := answerDNS(hostile, map[string]string{owner: "value"}); accepted {
			t.Fatal("malformed DNS query was answered")
		}
	}
}

// FuzzDeploymentFixtureDNSNeverPanicsOrChangesClassification exercises the
// test-only UDP boundary while preserving deterministic, bounded responses.
func FuzzDeploymentFixtureDNSNeverPanicsOrChangesClassification(f *testing.F) {
	owner := originSelector + "._domainkey." + originDomain + "."
	valid := dnsQueryForFuzz(owner, 16)
	f.Add(valid)
	f.Add([]byte{})
	f.Add(append(append([]byte(nil), valid...), 0))
	records := map[string]string{owner: "v=DKIM1; k=rsa; p=AA=="}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 4096 {
			input = input[:4096]
		}
		first, firstOK := answerDNS(input, records)
		second, secondOK := answerDNS(input, records)
		if firstOK != secondOK || !bytes.Equal(first, second) {
			t.Fatal("fixture DNS classification changed for identical bytes")
		}
		if len(first) > 4096 {
			t.Fatal("fixture DNS response exceeded its fixed datagram bound")
		}
		if bytes.Equal(input, valid) && (!firstOK || len(first) <= len(valid)) {
			t.Fatal("known-valid fixture DNS query was rejected")
		}
	})
}

// dnsQueryForFuzz constructs one deterministic seed without a testing handle.
func dnsQueryForFuzz(owner string, queryType uint16) []byte {
	query, err := encodeDNSQuery(0x4d32, owner, queryType)
	if err != nil {
		panic("invalid fixed DNS fuzz seed")
	}
	return query
}

// TestStaticProviderRejectsTXTSPKIMismatch freezes DNS/verifier key binding.
func TestStaticProviderRejectsTXTSPKIMismatch(t *testing.T) {
	first := testPublicRecord(t, "s1", originDomain)
	second := testPublicRecord(t, "s1", originDomain)
	first.TXT = second.TXT
	if _, err := newStaticProvider(publicKeySet{
		Version: "dkim2-deployment-public-keys-v1",
		Keys:    []publicKeyRecord{first},
	}); err == nil {
		t.Fatal("mismatched DNS and verifier public keys were accepted")
	}
}

// TestPublicVerifierRejectsUnsignedFixtureMessage freezes failure before live proof.
func TestPublicVerifierRejectsUnsignedFixtureMessage(t *testing.T) {
	record := testPublicRecord(t, originSelector, originDomain)
	provider, err := newStaticProvider(publicKeySet{
		Version: "dkim2-deployment-public-keys-v1",
		Keys:    []publicKeyRecord{record},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := dkim2.NewVerifier(provider)
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.Verify(
		context.Background(),
		dkim2.NewVerifyRequest(
			[]byte("From: sender@example.test\r\n\r\nunsigned\r\n"),
			[]byte("<sender@"+senderDomain+">"),
			[][]byte{[]byte("<" + recipient + ">")},
		),
	)
	if err != nil || result.State() == dkim2.ResultStatePASS {
		t.Fatal("unsigned fixture message passed public verification")
	}
}

// TestDeploymentOrdinaryTransitCustodyContinuity freezes the draft-04
// predecessor rt= to successor mf= domain link while retaining distinct keys.
func TestDeploymentOrdinaryTransitCustodyContinuity(t *testing.T) {
	if transitDomain != originDomain ||
		recipient != "privacy-recipient-7f3c@"+originDomain ||
		originSelector == transitSelector {
		t.Fatal("ordinary-transit fixture breaks custody-domain continuity")
	}
}

// TestFrameSMTPDataNormalizesAndDotStuffs freezes exact test transport framing.
func TestFrameSMTPDataNormalizesAndDotStuffs(t *testing.T) {
	framed, err := frameSMTPData([]byte("Header: value\n\n.line\n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(framed) != "Header: value\r\n\r\n..line\r\n.\r\n" {
		t.Fatalf("unexpected framed data %q", framed)
	}
	if _, err := frameSMTPData([]byte("bare\rreturn")); err == nil {
		t.Fatal("bare carriage return was accepted")
	}
}

// TestNormalizePostcatMessageRestoresCRLFFidelity freezes queue presentation handling.
func TestNormalizePostcatMessageRestoresCRLFFidelity(t *testing.T) {
	normalized, err := normalizePostcatMessage([]byte("Header: value\n\nbody\n"))
	if err != nil || string(normalized) != "Header: value\r\n\r\nbody\r\n" {
		t.Fatalf("normalizePostcatMessage() = %q, %v", normalized, err)
	}
	if _, err := normalizePostcatMessage([]byte("Header: value\r\n")); err == nil {
		t.Fatal("postcat input with carriage returns was accepted")
	}
}

// dnsQuery builds one bounded uncompressed DNS question.
func dnsQuery(t *testing.T, owner string, queryType uint16) []byte {
	t.Helper()
	query, err := encodeDNSQuery(1, owner, queryType)
	if err != nil {
		t.Fatal("invalid test query")
	}
	return query
}

// testPublicRecord creates one exact matching SPKI and DNS RSA record.
func testPublicRecord(t *testing.T, selector, domain string) publicKeyRecord {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return publicKeyRecord{
		Domain: domain, Selector: selector,
		SPKIBase64: base64.StdEncoding.EncodeToString(spki),
		TXT: "v=DKIM1; k=rsa; p=" +
			base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&key.PublicKey)),
	}
}
