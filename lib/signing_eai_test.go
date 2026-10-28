package dkim2

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
)

// TestPublicOriginatorSignsSMTPUTF8Envelope reproduces SMTPUTF8 signing
// (Draft-08 Section 18): an RFC 6531 envelope with UTF-8 local parts and
// U-label domains is signed with mf= and rt= recording the local parts
// unchanged and the domains as A-labels, and the result verifies against the
// original UTF-8 envelope.
func TestPublicOriginatorSignsSMTPUTF8Envelope(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	handle, err := NewPrivateKeyHandle([]byte("fixture-rsa"))
	if err != nil {
		t.Fatalf("NewPrivateKeyHandle() error = %v", err)
	}
	credential, err := NewRSASigningCredential(testRSASelector, &fixture.provider.rsaKey.PublicKey, handle)
	if err != nil {
		t.Fatalf("NewRSASigningCredential() error = %v", err)
	}
	profile, err := NewRSASigningProfile("xn--bcher-kva.example", credential)
	if err != nil {
		t.Fatalf("NewRSASigningProfile() error = %v", err)
	}
	reverse := []byte("<jörg@bücher.example>")
	forward := [][]byte{[]byte("<zoë@münchen.example>")}
	raw := []byte("From: jörg@bücher.example\r\nTo: zoë@münchen.example\r\nSubject: eai\r\n\r\nbody\r\n")
	source, err := NewSigningSource(raw)
	if err != nil {
		t.Fatalf("NewSigningSource() error = %v", err)
	}
	entry, err := NewOriginatorRouteEntry(source, reverse, forward, RouteDisclosureSingle, []byte("local-route"))
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
	result, recovery, err := fixture.facade.SignOriginator(context.Background(), NewOriginatorSigningRequest(
		raw, reverse, forward, tickets[0], profile, SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
	))
	if err != nil || recovery.Valid() {
		t.Fatalf("SignOriginator() recovery=%v error=%v", recovery.Valid(), err)
	}
	signed, ok := result.Unrestricted()
	if !ok {
		t.Fatal("SignOriginator() did not return unrestricted output")
	}
	for _, recorded := range []string{"<jörg@xn--bcher-kva.example>", "<zoë@xn--mnchen-3ya.example>"} {
		if !bytes.Contains(signed.Bytes(), []byte(base64.StdEncoding.EncodeToString([]byte(recorded)))) {
			t.Fatalf("signature does not record %q with an A-label domain", recorded)
		}
	}
	fixture.assertPublicChainPass(t, signed.Bytes(), reverse, forward, 1)
}
