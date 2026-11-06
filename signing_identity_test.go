package dkim2

import (
	"context"
	"testing"
)

// TestSigningIdentityRejectsZeroAndReturnsGeneratedIdentity proves the public accessor owns parser access.
func TestSigningIdentityRejectsZeroAndReturnsGeneratedIdentity(t *testing.T) {
	if domain, timestamp, err := (UnrestrictedSignedMessage{}).SigningIdentity(); err == nil || domain != "" || timestamp != 0 {
		t.Fatal("zero signing result exposed an identity")
	}
	fixture := newPublicSigningFixture(t)
	raw := []byte("From: alice@example.test\r\nSubject: identity\r\n\r\nbody\r\n")
	result, recovery, err := fixture.facade.SignOriginator(context.Background(), NewOriginatorSigningRequest(
		raw, []byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")},
		fixture.originTicket(t, raw, RouteDisclosureSingle), fixture.profile, SigningMetadata{},
		SigningTransportFinalNetworkPreDotStuffing,
	))
	if err != nil || recovery.Valid() {
		t.Fatal("identity fixture signing failed")
	}
	signed, ok := result.Unrestricted()
	if !ok {
		t.Fatal("identity fixture is not unrestricted")
	}
	domain, timestamp, err := signed.SigningIdentity()
	if err != nil || domain != testSigningDomain || timestamp != 1_700_000_000 {
		t.Fatal("generated identity differs from signing inputs")
	}
}
