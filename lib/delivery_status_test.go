package dkim2

import (
	"context"
	"errors"
	"testing"
)

// TestDSNSigningRequiresDedicatedEvidenceAndRoute proves that a structurally
// valid, cryptographically authenticated DSN can use only its dedicated
// evidence and route purpose, while generic null-path signing remains closed.
func TestDSNSigningRequiresDedicatedEvidenceAndRoute(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	original := signDSNOriginal(t, fixture)
	outer := []byte("From: postmaster@example.test\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n" +
		"--dsn\r\nContent-Type: text/plain\r\n\r\nhuman\r\n" +
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; example.test\r\n\r\n" +
		"--dsn\r\nContent-Type: message/rfc822\r\n\r\n" + string(original) + "\r\n--dsn--\r\n")
	identity, err := NewDSNIdentity("example.test")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewDSNSigningEvidenceRequest(
		outer, []byte("<>"), [][]byte{[]byte("<alice@example.test>")},
		[]byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.test>")}, identity,
	))
	if err != nil || !evidence.Valid() {
		t.Fatalf("EvaluateDSNForSigning() evidence=%t error=%v", evidence.Valid(), err)
	}
	source, err := NewSigningSource(outer)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := NewDeliveryStatusRouteEntry(
		source, []byte("<>"), [][]byte{[]byte("<alice@example.test>")},
		RouteDisclosureSingle, []byte("delivery-status-test"),
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewRouteFanoutRequest([]RouteEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	_, tickets, err := fixture.facade.PlanRouteFanout(context.Background(), plan)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout() tickets=%d error=%v", len(tickets), err)
	}
	result, recovery, err := fixture.facade.SignDSN(context.Background(), NewDSNSigningRequest(
		evidence, tickets[0], fixture.profile, SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
	))
	if err != nil || recovery.Valid() || !result.Valid() {
		t.Fatalf("SignDSN() result=%t recovery=%t error=%v", result.Valid(), recovery.Valid(), err)
	}
}

// TestDSNEvidenceRequiresOuterRecipientToMatchHighestMailFrom proves Section
// 12 binds the DSN recipient to the authenticated highest mf= exactly.
func TestDSNEvidenceRequiresOuterRecipientToMatchHighestMailFrom(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	original := signDSNOriginal(t, fixture)
	outer := []byte("From: postmaster@example.test\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n" +
		"--dsn\r\nContent-Type: text/plain\r\n\r\nhuman\r\n" +
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; example.test\r\n\r\n" +
		"--dsn\r\nContent-Type: message/rfc822\r\n\r\n" + string(original) + "\r\n--dsn--\r\n")
	identity, err := NewDSNIdentity("example.test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = fixture.facade.EvaluateDSNForSigning(context.Background(), NewDSNSigningEvidenceRequest(
		outer, []byte("<>"), [][]byte{[]byte("<postmaster@example.test>")},
		[]byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.test>")}, identity,
	))
	if !errors.Is(err, newSigningError(SigningErrorAuthorizationDenied)) {
		t.Fatalf("outer recipient mismatch error = %v", err)
	}
}

// TestDSNEvidenceAllowsAuthenticatedForeignOriginalRecipient proves that a
// local originator may receive a DSN for delivery to a foreign recipient
// domain. Local DSN authority is bound by the authenticated d= and mf= values,
// while rt= remains bound to the independently observed original envelope.
func TestDSNEvidenceAllowsAuthenticatedForeignOriginalRecipient(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	originalRecipient := []byte("<bob@remote.example.test>")
	original := signDSNOriginalForRecipient(t, fixture, originalRecipient)
	outer := []byte("From: postmaster@example.test\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n" +
		"--dsn\r\nContent-Type: text/plain\r\n\r\nhuman\r\n" +
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; example.test\r\n\r\n" +
		"--dsn\r\nContent-Type: message/rfc822\r\n\r\n" + string(original) + "\r\n--dsn--\r\n")
	identity, err := NewDSNIdentity("example.test")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewDSNSigningEvidenceRequest(
		outer, []byte("<>"), [][]byte{[]byte("<alice@example.test>")},
		[]byte("<alice@example.test>"), [][]byte{originalRecipient}, identity,
	))
	if err != nil || !evidence.Valid() {
		t.Fatalf("EvaluateDSNForSigning() evidence=%t error=%v", evidence.Valid(), err)
	}
}

// TestDSNEvidenceAllowsTrustedPostSigningRecipientExpansion proves that a
// local MTA may add an archival recipient after DKIM2 originator signing. The
// authenticated rt= set must remain a subset of the independently observed
// Postfix envelope; an unsigned recipient must never replace signed evidence.
func TestDSNEvidenceAllowsTrustedPostSigningRecipientExpansion(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	originalRecipient := []byte("<bob@remote.example.test>")
	original := signDSNOriginalForRecipient(t, fixture, originalRecipient)
	outer := []byte("From: postmaster@example.test\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n" +
		"--dsn\r\nContent-Type: text/plain\r\n\r\nhuman\r\n" +
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; example.test\r\n\r\n" +
		"--dsn\r\nContent-Type: message/rfc822\r\n\r\n" + string(original) + "\r\n--dsn--\r\n")
	identity, err := NewDSNIdentity("example.test")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewDSNSigningEvidenceRequest(
		outer, []byte("<>"), [][]byte{[]byte("<alice@example.test>")},
		[]byte("<alice@example.test>"), [][]byte{
			originalRecipient,
			[]byte("<archive@archive.example.test>"),
		}, identity,
	))
	if err != nil || !evidence.Valid() {
		t.Fatalf("EvaluateDSNForSigning(expanded envelope) evidence=%t error=%v", evidence.Valid(), err)
	}
	_, err = fixture.facade.EvaluateDSNForSigning(context.Background(), NewDSNSigningEvidenceRequest(
		outer, []byte("<>"), [][]byte{[]byte("<alice@example.test>")},
		[]byte("<alice@example.test>"), [][]byte{[]byte("<archive@archive.example.test>")}, identity,
	))
	if !errors.Is(err, newSigningError(SigningErrorAuthorizationDenied)) {
		t.Fatalf("EvaluateDSNForSigning(replaced signed recipient) error=%v", err)
	}
}

// signDSNOriginal produces one authenticated original whose highest d= and rt=
// domains bind to the local DSN identity used by the test.
func signDSNOriginal(t *testing.T, fixture publicSigningFixture) []byte {
	return signDSNOriginalForRecipient(t, fixture, []byte("<bob@example.test>"))
}

// signDSNOriginalForRecipient produces an authenticated original for one exact
// independently observed recipient path.
func signDSNOriginalForRecipient(
	t *testing.T,
	fixture publicSigningFixture,
	recipient []byte,
) []byte {
	t.Helper()
	raw := []byte("From: alice@example.test\r\n\r\noriginal body\r\n")
	source, err := NewSigningSource(raw)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := NewOriginatorRouteEntry(
		source, []byte("<alice@example.test>"), [][]byte{recipient},
		RouteDisclosureSingle, []byte("original-dsn-evidence"),
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewRouteFanoutRequest([]RouteEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	_, tickets, err := fixture.facade.PlanRouteFanout(context.Background(), plan)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout(original) tickets=%d error=%v", len(tickets), err)
	}
	result, recovery, err := fixture.facade.SignOriginator(context.Background(), NewOriginatorSigningRequest(
		raw, []byte("<alice@example.test>"), [][]byte{recipient},
		tickets[0], fixture.profile, SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
	))
	if err != nil || recovery.Valid() {
		t.Fatalf("SignOriginator(original) recovery=%t error=%v", recovery.Valid(), err)
	}
	signed, ok := result.Unrestricted()
	if !ok {
		t.Fatal("SignOriginator(original) did not return unrestricted output")
	}
	return signed.Bytes()
}
