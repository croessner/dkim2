package dkim2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/dsn"
)

type cancelAfterEvidenceError struct {
	cause  error
	cancel context.CancelFunc
	once   sync.Once
}

// Error returns a bounded test-only error description.
func (*cancelAfterEvidenceError) Error() string { return "independent DSN evidence failure" }

// Unwrap races cancellation only after the mapper has observed an independent failure.
func (e *cancelAfterEvidenceError) Unwrap() error {
	e.once.Do(e.cancel)
	return e.cause
}

// TestDSNSigningRequiresDedicatedEvidenceAndRoute proves that a structurally
// valid, cryptographically authenticated DSN can use only its dedicated
// evidence and route purpose, while generic null-path signing remains closed.
func TestDSNSigningRequiresDedicatedEvidenceAndRoute(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	original := signDSNOriginal(t, fixture)
	outer := []byte("From: postmaster@example.test\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n" +
		"--dsn\r\nContent-Type: text/plain\r\n\r\nhuman\r\n" +
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; example.test\r\n\r\nFinal-Recipient: rfc822; bob@example.test\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n" +
		"--dsn\r\nContent-Type: message/rfc822\r\n\r\n" + string(original) + "\r\n--dsn--\r\n")
	identity, err := NewDSNIdentity("example.test")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewDSNSigningEvidenceRequest(
		outer, []byte("<>"), [][]byte{[]byte("<alice@example.test>")},
		identity,
	))
	if err != nil || !evidence.Valid() {
		t.Fatalf("EvaluateDSNForSigning() evidence=%t error=%v", evidence.Valid(), err)
	}
	derived, err := fixture.facade.EvaluateDSNForSigning(
		context.Background(),
		NewDerivedDSNSigningEvidenceRequest(
			outer, []byte("<>"), [][]byte{[]byte("<alice@example.test>")},
		),
	)
	if err != nil || !derived.Valid() || derived.SigningDomain() != testSigningDomain {
		t.Fatalf(
			"EvaluateDSNForSigning(derived) evidence=%t domain=%q error=%v",
			derived.Valid(), derived.SigningDomain(), err,
		)
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

// TestPostfixDSNCompatibilityRequiresExplicitProvenanceConstructor proves the
// generic evidence constructor remains strict while the clearly named trusted
// adapter constructor admits only the bounded Postfix field form.
func TestPostfixDSNCompatibilityRequiresExplicitProvenanceConstructor(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	original := signDSNOriginal(t, fixture)
	outer := []byte("From: postmaster@example.test\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n" +
		"--dsn\r\nContent-Type: text/plain\r\n\r\nhuman\r\n" +
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\n" +
		"Reporting-MTA: dns; example.test\r\n" +
		"X-Postfix-Queue-ID: synthetic-queue-id\r\n" +
		"Arrival-Date: Tue, 14 Nov 2023 22:13:20 +0000 (UTC)\r\n\r\n" +
		"Final-Recipient: rfc822; bob@example.test\r\n" +
		"Original-Recipient: rfc822; bob@example.test\r\n" +
		"Action: failed\r\nStatus: 5.1.1\r\n" +
		"Diagnostic-Code: smtp; 550 synthetic rejection\r\n\r\n" +
		"--dsn\r\nContent-Type: message/rfc822\r\n\r\n" + string(original) + "\r\n--dsn--\r\n")
	_, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewDerivedDSNSigningEvidenceRequest(
		outer,
		[]byte("<>"),
		[][]byte{[]byte("<alice@example.test>")},
	))
	if !errors.Is(err, newSigningError(SigningErrorAuthorizationDenied)) {
		t.Fatalf("generic Postfix-order evidence error=%v", err)
	}
	evidence, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewPostfixDerivedDSNSigningEvidenceRequest(
		outer,
		[]byte("<>"),
		[][]byte{[]byte("<alice@example.test>")},
	))
	if err != nil || !evidence.Valid() {
		t.Fatalf("trusted Postfix-order evidence valid=%t error=%v", evidence.Valid(), err)
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
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; example.test\r\n\r\nFinal-Recipient: rfc822; bob@example.test\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n" +
		"--dsn\r\nContent-Type: message/rfc822\r\n\r\n" + string(original) + "\r\n--dsn--\r\n")
	identity, err := NewDSNIdentity("example.test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = fixture.facade.EvaluateDSNForSigning(context.Background(), NewDSNSigningEvidenceRequest(
		outer, []byte("<>"), [][]byte{[]byte("<postmaster@example.test>")},
		identity,
	))
	if !errors.Is(err, newSigningError(SigningErrorAuthorizationDenied)) {
		t.Fatalf("outer recipient mismatch error = %v", err)
	}
	linkedMismatch := bytes.Replace(outer, []byte("bob@example.test"), []byte("other@example.test"), 1)
	_, err = fixture.facade.EvaluateDSNForSigning(context.Background(), NewDSNSigningEvidenceRequest(
		linkedMismatch, []byte("<>"), [][]byte{[]byte("<alice@example.test>")}, identity,
	))
	if !errors.Is(err, newSigningError(SigningErrorAuthorizationDenied)) {
		t.Fatalf("delivery-status recipient mismatch error = %v", err)
	}
}

// TestDSNEvidenceErrorsExposeOnlyClosedPipelineStages proves diagnostic
// observability distinguishes pre-policy failures without retaining content.
func TestDSNEvidenceErrorsExposeOnlyClosedPipelineStages(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	original := signDSNOriginal(t, fixture)
	outer := []byte("From: postmaster@example.test\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n" +
		"--dsn\r\nContent-Type: text/plain\r\n\r\nhuman\r\n" +
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; example.test\r\n\r\nFinal-Recipient: rfc822; bob@example.test\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n" +
		"--dsn\r\nContent-Type: message/rfc822\r\n\r\n" + string(original) + "\r\n--dsn--\r\n")
	identity, err := NewDSNIdentity("example.test")
	if err != nil {
		t.Fatal(err)
	}
	otherIdentity, err := NewDSNIdentity("other.example.test")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		raw       []byte
		recipient []byte
		identity  DSNIdentity
		wantStage DSNEvidenceStage
	}{
		{name: "mime", raw: []byte("private-marker"), recipient: []byte("<alice@example.test>"), identity: identity, wantStage: DSNEvidenceStageMIMEParse},
		{name: "embedded-message", raw: bytes.Replace(outer, original, []byte("private-marker\r\n"), 1), recipient: []byte("<alice@example.test>"), identity: identity, wantStage: DSNEvidenceStageEmbeddedMessage},
		{name: "embedded-verification", raw: bytes.Replace(outer, []byte("original body"), []byte("private-marker"), 1), recipient: []byte("<alice@example.test>"), identity: identity, wantStage: DSNEvidenceStageEmbeddedVerification},
		{name: "embedded-unsigned", raw: bytes.Replace(outer, original, []byte("From: alice@example.test\r\nSubject: private-marker\r\n\r\noriginal body\r\n"), 1), recipient: []byte("<alice@example.test>"), identity: identity, wantStage: DSNEvidenceStageEmbeddedUnsigned},
		{name: "delivery-status-linkage", raw: bytes.Replace(outer, []byte("bob@example.test"), []byte("other@example.test"), 1), recipient: []byte("<alice@example.test>"), identity: identity, wantStage: DSNEvidenceStageDeliveryStatusLinkage},
		{name: "outer-recipient-linkage", raw: outer, recipient: []byte("<other@example.test>"), identity: identity, wantStage: DSNEvidenceStageOuterRecipientLinkage},
		{name: "signing-domain", raw: outer, recipient: []byte("<alice@example.test>"), identity: otherIdentity, wantStage: DSNEvidenceStageSigningDomain},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewDSNSigningEvidenceRequest(
				testCase.raw, []byte("<>"), [][]byte{testCase.recipient}, testCase.identity,
			))
			if DSNEvidenceStageOf(err) != testCase.wantStage ||
				!errors.Is(err, newSigningError(SigningErrorAuthorizationDenied)) && testCase.wantStage != DSNEvidenceStageMIMEParse {
				t.Fatalf("stage=%q error=%v", DSNEvidenceStageOf(err), err)
			}
			if bytes.Contains([]byte(err.Error()), []byte("private-marker")) ||
				bytes.Contains([]byte(fmt.Sprintf("%#v", err)), []byte("private-marker")) {
				t.Fatal("evidence diagnostic retained input")
			}
		})
	}
}

// TestDSNEvidenceClassifiesOriginalWithoutDKIM2SignatureAsUnsigned reproduces
// a Postfix bounce for inbound mail that carries only DKIM1 evidence. The
// derived Postfix request must expose the closed unsigned stage while keeping
// the authorization-denied cause, and a failing DKIM2 original must not.
func TestDSNEvidenceClassifiesOriginalWithoutDKIM2SignatureAsUnsigned(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	original := signDSNOriginal(t, fixture)
	outer := []byte("From: postmaster@example.test\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n" +
		"--dsn\r\nContent-Type: text/plain\r\n\r\nhuman\r\n" +
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; example.test\r\n\r\nFinal-Recipient: rfc822; bob@example.test\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n" +
		"--dsn\r\nContent-Type: message/rfc822\r\n\r\n" + string(original) + "\r\n--dsn--\r\n")
	unsigned := bytes.Replace(outer, original, []byte("From: alice@example.test\r\n"+
		"DKIM-Signature: v=1; a=rsa-sha256; d=example.test; s=legacy; h=from; bh=AAAA; b=AAAA\r\n"+
		"Subject: private-marker\r\n\r\noriginal body\r\n"), 1)
	if !DSNEvidenceStageEmbeddedUnsigned.Known() {
		t.Fatal("unsigned stage is not part of the closed pipeline")
	}
	for _, testCase := range []struct {
		name      string
		raw       []byte
		wantStage DSNEvidenceStage
	}{
		{name: "unsigned", raw: unsigned, wantStage: DSNEvidenceStageEmbeddedUnsigned},
		{name: "failing", raw: bytes.Replace(outer, []byte("original body"), []byte("private-marker"), 1), wantStage: DSNEvidenceStageEmbeddedVerification},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			evidence, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewPostfixDerivedDSNSigningEvidenceRequest(
				testCase.raw, []byte("<>"), [][]byte{[]byte("<alice@example.test>")},
			))
			if evidence.Valid() || DSNEvidenceStageOf(err) != testCase.wantStage ||
				!errors.Is(err, newSigningError(SigningErrorAuthorizationDenied)) {
				t.Fatalf("stage=%q error=%v", DSNEvidenceStageOf(err), err)
			}
			if bytes.Contains([]byte(err.Error()), []byte("private-marker")) {
				t.Fatal("evidence diagnostic retained input")
			}
		})
	}
}

// TestDSNEvidencePreservesVerificationStageOnInFlightCancellation proves a
// provider cancellation after message parsing remains distinguishable from
// request preflight while preserving context error classification.
func TestDSNEvidencePreservesVerificationStageOnInFlightCancellation(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	original := signDSNOriginal(t, fixture)
	outer := []byte("From: postmaster@example.test\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n" +
		"--dsn\r\nContent-Type: text/plain\r\n\r\nhuman\r\n" +
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; example.test\r\n\r\nFinal-Recipient: rfc822; bob@example.test\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n" +
		"--dsn\r\nContent-Type: message/rfc822\r\n\r\n" + string(original) + "\r\n--dsn--\r\n")
	ctx, cancel := context.WithCancel(context.Background())
	lookups := 0
	provider := publicProviderFunc(func(providerContext context.Context, _ PublicKeyQuery) (PublicKeyResult, error) {
		lookups++
		cancel()
		return PublicKeyResult{}, providerContext.Err()
	})
	signer, err := NewSigner(
		provider, NewRequestRouteAuthority(), fixture.authorizer, fixture.provider,
		WithSigningClock(func() time.Time { return time.Unix(1_700_000_000, 0) }),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = signer.EvaluateDSNForSigning(ctx, NewPostfixDerivedDSNSigningEvidenceRequest(
		outer, []byte("<>"), [][]byte{[]byte("<alice@example.test>")},
	))
	if !errors.Is(err, context.Canceled) ||
		DSNEvidenceStageOf(err) != DSNEvidenceStageEmbeddedVerification || lookups != 1 {
		t.Fatalf("stage=%q lookups=%d error=%v", DSNEvidenceStageOf(err), lookups, err)
	}
}

// TestDSNEvidencePrefersIndependentFailureOverRacedCancellation proves a
// cancellation observed after a completed linkage failure cannot overwrite
// that failure's actual pipeline stage or response classification.
func TestDSNEvidencePrefersIndependentFailureOverRacedCancellation(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	original := signDSNOriginal(t, fixture)
	outer := []byte("From: postmaster@example.test\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n" +
		"--dsn\r\nContent-Type: text/plain\r\n\r\nhuman\r\n" +
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; example.test\r\n\r\nFinal-Recipient: rfc822; other@example.test\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n" +
		"--dsn\r\nContent-Type: message/rfc822\r\n\r\n" + string(original) + "\r\n--dsn--\r\n")
	report, err := dsn.Parse(outer)
	if err != nil {
		t.Fatal(err)
	}
	_, evidenceErr := fixture.facade.revision.EvaluatePostfixDeliveryStatus(context.Background(), report)
	if !dsn.IsEvidenceErrorCode(evidenceErr, dsn.EvidenceErrorCodeDeliveryStatusLinkage) {
		t.Fatalf("evidence error=%v", evidenceErr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	mapped := mapDSNEvidenceError(ctx, &cancelAfterEvidenceError{cause: evidenceErr, cancel: cancel})
	if !errors.Is(ctx.Err(), context.Canceled) || errors.Is(mapped, context.Canceled) ||
		DSNEvidenceStageOf(mapped) != DSNEvidenceStageDeliveryStatusLinkage {
		t.Fatalf("stage=%q context=%v error=%v", DSNEvidenceStageOf(mapped), ctx.Err(), mapped)
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
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; example.test\r\n\r\nFinal-Recipient: rfc822; bob@remote.example.test\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n" +
		"--dsn\r\nContent-Type: message/rfc822\r\n\r\n" + string(original) + "\r\n--dsn--\r\n")
	identity, err := NewDSNIdentity("example.test")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewDSNSigningEvidenceRequest(
		outer, []byte("<>"), [][]byte{[]byte("<alice@example.test>")},
		identity,
	))
	if err != nil || !evidence.Valid() {
		t.Fatalf("EvaluateDSNForSigning() evidence=%t error=%v", evidence.Valid(), err)
	}
}

// TestDSNEvidenceDoesNotFabricateOriginalEnvelope proves DSN authorization no
// longer accepts a copied signed envelope as independent observation.
func TestDSNEvidenceDoesNotFabricateOriginalEnvelope(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	originalRecipient := []byte("<bob@remote.example.test>")
	original := signDSNOriginalForRecipient(t, fixture, originalRecipient)
	outer := []byte("From: postmaster@example.test\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n" +
		"--dsn\r\nContent-Type: text/plain\r\n\r\nhuman\r\n" +
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; example.test\r\n\r\nFinal-Recipient: rfc822; bob@remote.example.test\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n" +
		"--dsn\r\nContent-Type: message/rfc822\r\n\r\n" + string(original) + "\r\n--dsn--\r\n")
	identity, err := NewDSNIdentity("example.test")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewDSNSigningEvidenceRequest(
		outer, []byte("<>"), [][]byte{[]byte("<alice@example.test>")},
		identity,
	))
	if err != nil || !evidence.Valid() {
		t.Fatalf("EvaluateDSNForSigning(expanded envelope) evidence=%t error=%v", evidence.Valid(), err)
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

// TestDSNSigningRequiresAuthenticReportFrom reproduces Draft-07 Sections
// 11 and 12.4 for MTA-generated DSNs: the report is a new i=1 message, so its
// From must relaxed-match the DSN signing domain or signing fails closed.
func TestDSNSigningRequiresAuthenticReportFrom(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	original := signDSNOriginal(t, fixture)
	outer := []byte("From: postmaster@other.test\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n" +
		"--dsn\r\nContent-Type: text/plain\r\n\r\nhuman\r\n" +
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; example.test\r\n\r\nFinal-Recipient: rfc822; bob@example.test\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n" +
		"--dsn\r\nContent-Type: message/rfc822\r\n\r\n" + string(original) + "\r\n--dsn--\r\n")
	identity, err := NewDSNIdentity("example.test")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewDSNSigningEvidenceRequest(
		outer, []byte("<>"), [][]byte{[]byte("<alice@example.test>")}, identity,
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
		RouteDisclosureSingle, []byte("delivery-status-from-test"),
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
	var signingErr *SigningError
	if result.Valid() || recovery.Valid() || !errors.As(err, &signingErr) || signingErr.Code() != SigningErrorChainFailure {
		t.Fatalf("SignDSN() result=%t recovery=%t error=%v, want chain_failure", result.Valid(), recovery.Valid(), err)
	}
}

// reportingMTADSN wraps one authenticated original in a Postfix-shaped report
// whose From and Reporting-MTA name the reporting MTA, not the original signer.
func reportingMTADSN(original []byte, reportingHost string) []byte {
	return []byte("From: MAILER-DAEMON@" + reportingHost + "\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n" +
		"--dsn\r\nContent-Type: text/plain\r\n\r\nhuman\r\n" +
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\n" +
		"Reporting-MTA: dns; " + reportingHost + "\r\n\r\n" +
		"Final-Recipient: rfc822; bob@example.test\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n" +
		"--dsn\r\nContent-Type: message/rfc822\r\n\r\n" + string(original) + "\r\n--dsn--\r\n")
}

// signEvaluatedDSN plans the delivery-status route for an issued evidence and
// signs it with one profile.
func signEvaluatedDSN(t *testing.T, fixture publicSigningFixture, outer []byte, evidence DSNSigningEvidence, profile SigningProfile) (SigningResult, SigningRecovery, error) {
	t.Helper()
	source, err := NewSigningSource(outer)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := NewDeliveryStatusRouteEntry(
		source, []byte("<>"), [][]byte{[]byte("<alice@example.test>")},
		RouteDisclosureSingle, []byte("delivery-status-reporting-test"),
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
	return fixture.facade.SignDSN(context.Background(), NewDSNSigningRequest(
		evidence, tickets[0], profile, SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
	))
}

// TestPostfixDSNSignsUnderReportingMTAIdentity reproduces an MTA-generated
// bounce whose From names the reporting MTA: Draft-07 Section 12.4 makes the
// derived embedded d= unusable for it, while the configured reporting identity
// signs it after the same embedded verification and recipient linkage.
func TestPostfixDSNSignsUnderReportingMTAIdentity(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	original := signDSNOriginal(t, fixture)
	outer := reportingMTADSN(original, "mx.example.net")
	recipients := [][]byte{[]byte("<alice@example.test>")}

	derived, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewPostfixDerivedDSNSigningEvidenceRequest(
		outer, []byte("<>"), recipients,
	))
	if err != nil || derived.SigningDomain() != testSigningDomain {
		t.Fatalf("derived evidence domain=%q error=%v", derived.SigningDomain(), err)
	}
	result, recovery, err := signEvaluatedDSN(t, fixture, outer, derived, fixture.profile)
	var signingErr *SigningError
	if result.Valid() || recovery.Valid() || !errors.As(err, &signingErr) || signingErr.Code() != SigningErrorChainFailure {
		t.Fatalf("derived SignDSN() result=%t error=%v, want chain_failure", result.Valid(), err)
	}

	reporting, err := NewDSNIdentity("example.net")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewPostfixReportingDSNSigningEvidenceRequest(
		outer, []byte("<>"), recipients, reporting,
	))
	if err != nil || !evidence.Valid() || evidence.SigningDomain() != "example.net" {
		t.Fatalf("reporting evidence valid=%t domain=%q error=%v", evidence.Valid(), evidence.SigningDomain(), err)
	}
	result, _, err = signEvaluatedDSN(t, fixture, outer, evidence, fixture.profile)
	if result.Valid() || !errors.As(err, &signingErr) || signingErr.Code() != SigningErrorInvalidRequest {
		t.Fatalf("embedded-domain profile under reporting identity result=%t error=%v", result.Valid(), err)
	}
	result, recovery, err = signEvaluatedDSN(t, fixture, outer, evidence, fixture.existingProfile)
	if err != nil || recovery.Valid() || !result.Valid() {
		t.Fatalf("reporting SignDSN() result=%t recovery=%t error=%v", result.Valid(), recovery.Valid(), err)
	}
	signed, ok := result.Unrestricted()
	if !ok || !bytes.Contains(signed.Bytes(), []byte("d=example.net;")) {
		t.Fatal("reporting DSN was not signed by the reporting identity")
	}

	foreignFrom := reportingMTADSN(original, "mx.other.test")
	evidence, err = fixture.facade.EvaluateDSNForSigning(context.Background(), NewPostfixReportingDSNSigningEvidenceRequest(
		foreignFrom, []byte("<>"), recipients, reporting,
	))
	if err != nil || !evidence.Valid() {
		t.Fatalf("misconfigured reporting evidence valid=%t error=%v", evidence.Valid(), err)
	}
	result, recovery, err = signEvaluatedDSN(t, fixture, foreignFrom, evidence, fixture.existingProfile)
	if result.Valid() || recovery.Valid() || !errors.As(err, &signingErr) || signingErr.Code() != SigningErrorChainFailure {
		t.Fatalf("reporting identity outside the report From result=%t error=%v, want chain_failure", result.Valid(), err)
	}
}

// TestPostfixReportingDSNKeepsEmbeddedEvidenceGates proves the reporting
// identity relaxes only the signer domain: unlinked recipients, tampered
// originals, and an invalid identity still fail closed.
func TestPostfixReportingDSNKeepsEmbeddedEvidenceGates(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	original := signDSNOriginal(t, fixture)
	reporting, err := NewDSNIdentity("example.net")
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range []struct {
		name       string
		outer      []byte
		recipients [][]byte
		identity   DSNIdentity
		stage      DSNEvidenceStage
	}{
		{name: "invalid identity", outer: reportingMTADSN(original, "mx.example.net"), recipients: [][]byte{[]byte("<alice@example.test>")}, stage: DSNEvidenceStagePreflight},
		{name: "foreign outer recipient", outer: reportingMTADSN(original, "mx.example.net"), recipients: [][]byte{[]byte("<mallory@example.test>")}, identity: reporting, stage: DSNEvidenceStageOuterRecipientLinkage},
		{name: "tampered original", outer: reportingMTADSN(bytes.Replace(original, []byte("original body"), []byte("altered body"), 1), "mx.example.net"), recipients: [][]byte{[]byte("<alice@example.test>")}, identity: reporting, stage: DSNEvidenceStageEmbeddedVerification},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			evidence, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewPostfixReportingDSNSigningEvidenceRequest(
				testCase.outer, []byte("<>"), testCase.recipients, testCase.identity,
			))
			if evidence.Valid() || DSNEvidenceStageOf(err) != testCase.stage {
				t.Fatalf("evidence valid=%t stage=%q error=%v", evidence.Valid(), DSNEvidenceStageOf(err), err)
			}
		})
	}
}
