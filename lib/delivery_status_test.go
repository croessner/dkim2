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
	if err != nil || !derived.Valid() || derived.SigningDomain() != "example.test" {
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
