package dkim2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
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
	evidence, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewDSNSigningEvidenceRequest(
		outer, []byte("<>"), [][]byte{[]byte("<alice@example.test>")},
	))
	if err != nil || !evidence.Valid() {
		t.Fatalf("EvaluateDSNForSigning() evidence=%t error=%v", evidence.Valid(), err)
	}
	if evidence.Resolved() || evidence.SigningDomain() != "" {
		t.Fatal("evaluated DSN evidence carried a signing identity before Section 16.2 resolution")
	}
	evidence, profile, err := fixture.facade.ResolveDSNSigningIdentity(
		context.Background(), evidence, newDSNProfiles(t, testSigningDomain),
	)
	if err != nil || !evidence.Resolved() || evidence.SigningDomain() != testSigningDomain || profile.value.Domain() != testSigningDomain {
		t.Fatalf("ResolveDSNSigningIdentity() domain=%q error=%v", evidence.SigningDomain(), err)
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
		evidence, tickets[0], profile, SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
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
	_, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewDSNSigningEvidenceRequest(
		outer,
		[]byte("<>"),
		[][]byte{[]byte("<alice@example.test>")},
	))
	if !errors.Is(err, newSigningError(SigningErrorAuthorizationDenied)) {
		t.Fatalf("generic Postfix-order evidence error=%v", err)
	}
	evidence, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewPostfixDSNSigningEvidenceRequest(
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
	_, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewDSNSigningEvidenceRequest(
		outer, []byte("<>"), [][]byte{[]byte("<postmaster@example.test>")},
	))
	if !errors.Is(err, newSigningError(SigningErrorAuthorizationDenied)) {
		t.Fatalf("outer recipient mismatch error = %v", err)
	}
	linkedMismatch := bytes.Replace(outer, []byte("bob@example.test"), []byte("other@example.test"), 1)
	_, err = fixture.facade.EvaluateDSNForSigning(context.Background(), NewDSNSigningEvidenceRequest(
		linkedMismatch, []byte("<>"), [][]byte{[]byte("<alice@example.test>")},
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
	cases := []struct {
		name      string
		raw       []byte
		recipient []byte
		wantStage DSNEvidenceStage
	}{
		{name: "mime", raw: []byte("private-marker"), recipient: []byte("<alice@example.test>"), wantStage: DSNEvidenceStageMIMEParse},
		{name: "embedded-message", raw: bytes.Replace(outer, original, []byte("private-marker\r\n"), 1), recipient: []byte("<alice@example.test>"), wantStage: DSNEvidenceStageEmbeddedMessage},
		{name: "embedded-verification", raw: bytes.Replace(outer, []byte("original body"), []byte("private-marker"), 1), recipient: []byte("<alice@example.test>"), wantStage: DSNEvidenceStageEmbeddedVerification},
		{name: "embedded-unsigned", raw: bytes.Replace(outer, original, []byte("From: alice@example.test\r\nSubject: private-marker\r\n\r\noriginal body\r\n"), 1), recipient: []byte("<alice@example.test>"), wantStage: DSNEvidenceStageEmbeddedUnsigned},
		{name: "delivery-status-linkage", raw: bytes.Replace(outer, []byte("bob@example.test"), []byte("other@example.test"), 1), recipient: []byte("<alice@example.test>"), wantStage: DSNEvidenceStageDeliveryStatusLinkage},
		{name: "outer-recipient-linkage", raw: outer, recipient: []byte("<other@example.test>"), wantStage: DSNEvidenceStageOuterRecipientLinkage},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewDSNSigningEvidenceRequest(
				testCase.raw, []byte("<>"), [][]byte{testCase.recipient},
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
			evidence, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewPostfixDSNSigningEvidenceRequest(
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
	_, err = signer.EvaluateDSNForSigning(ctx, NewPostfixDSNSigningEvidenceRequest(
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
	evidence, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewDSNSigningEvidenceRequest(
		outer, []byte("<>"), [][]byte{[]byte("<alice@example.test>")},
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
	evidence, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewDSNSigningEvidenceRequest(
		outer, []byte("<>"), [][]byte{[]byte("<alice@example.test>")},
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
	return signDSNOriginalForRecipients(t, fixture, [][]byte{recipient})
}

// signDSNOriginalForRecipients produces an authenticated original whose
// highest rt= lists every exact recipient path; more than one recipient uses
// the authorized group disclosure.
func signDSNOriginalForRecipients(
	t *testing.T,
	fixture publicSigningFixture,
	recipients [][]byte,
) []byte {
	t.Helper()
	raw := []byte("From: alice@example.test\r\n\r\noriginal body\r\n")
	source, err := NewSigningSource(raw)
	if err != nil {
		t.Fatal(err)
	}
	disclosure := RouteDisclosureSingle
	if len(recipients) > 1 {
		disclosure = RouteDisclosureAuthorizedGroup
	}
	entry, err := NewOriginatorRouteEntry(
		source, []byte("<alice@example.test>"), recipients,
		disclosure, []byte("original-dsn-evidence"),
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
		raw, []byte("<alice@example.test>"), recipients,
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

// dsnSubDomain is a profile domain below the fixture signing domain.
const dsnSubDomain = "sub." + testSigningDomain

// dsnProfiles is a test DSNProfileSource over a fixed set of local
// delivery_status profile domains. It records every lookup in order.
type dsnProfiles struct {
	profiles map[string]SigningProfile
	failures map[string]error
	lookups  []string
}

// DeliveryStatusProfile returns the fixed profile, its absence, or a failure.
func (p *dsnProfiles) DeliveryStatusProfile(_ context.Context, domain string) (SigningProfile, bool, error) {
	p.lookups = append(p.lookups, domain)
	if err, failed := p.failures[domain]; failed {
		return SigningProfile{}, false, err
	}
	profile, found := p.profiles[domain]
	return profile, found, nil
}

// newDSNProfiles builds a profile source whose profiles all reuse the fixture
// RSA credential, so any resolved identity can sign through the fixture.
func newDSNProfiles(t *testing.T, domains ...string) *dsnProfiles {
	t.Helper()
	handle, err := NewPrivateKeyHandle([]byte("fixture-rsa"))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := NewRSASigningCredential(testRSASelector, &loadPublicSigningRSAKey(t).PublicKey, handle)
	if err != nil {
		t.Fatal(err)
	}
	source := &dsnProfiles{profiles: map[string]SigningProfile{}}
	for _, domain := range domains {
		profile, err := NewRSASigningProfile(domain, credential)
		if err != nil {
			t.Fatal(err)
		}
		source.profiles[domain] = profile
	}
	return source
}

// dsnReport wraps one authenticated original in an RFC 6522 report whose own
// From, Reporting-MTA, and RFC 3464 Final-Recipient values are given.
func dsnReport(original []byte, from, reportingHost string, finalRecipients ...string) []byte {
	status := "Reporting-MTA: dns; " + reportingHost + "\r\n\r\n"
	for _, recipient := range finalRecipients {
		status += "Final-Recipient: rfc822; " + recipient + "\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n"
	}
	return []byte("From: " + from + "\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n" +
		"--dsn\r\nContent-Type: text/plain\r\n\r\nhuman\r\n" +
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\n" + status +
		"--dsn\r\nContent-Type: message/rfc822\r\n\r\n" + string(original) + "\r\n--dsn--\r\n")
}

// resolveDSN evaluates one Postfix-route report addressed to the fixture
// sender and resolves its Section 16.2 identity against source.
func resolveDSN(
	t *testing.T,
	fixture publicSigningFixture,
	outer []byte,
	preferred string,
	source DSNProfileSource,
) (DSNSigningEvidence, SigningProfile, error) {
	t.Helper()
	request := NewPostfixDSNSigningEvidenceRequest(outer, []byte("<>"), [][]byte{[]byte("<alice@example.test>")})
	if preferred != "" {
		identity, err := NewDSNIdentity(preferred)
		if err != nil {
			t.Fatal(err)
		}
		request = request.WithPreferredIdentity(identity)
	}
	evidence, err := fixture.facade.EvaluateDSNForSigning(context.Background(), request)
	if err != nil || !evidence.Valid() || evidence.Resolved() {
		t.Fatalf("EvaluateDSNForSigning() valid=%t resolved=%t error=%v", evidence.Valid(), evidence.Resolved(), err)
	}
	return fixture.facade.ResolveDSNSigningIdentity(context.Background(), evidence, source)
}

// assertDSNUnsigned requires the explicit closed "cannot be DKIM2 signed"
// outcome of one stage with the authorization-denied cause.
func assertDSNUnsigned(t *testing.T, evidence DSNSigningEvidence, profile SigningProfile, err error, stage DSNEvidenceStage) {
	t.Helper()
	if evidence.Resolved() || profile.Valid() || DSNEvidenceStageOf(err) != stage ||
		!errors.Is(err, newSigningError(SigningErrorAuthorizationDenied)) {
		t.Fatalf("resolved=%t profile=%t stage=%q error=%v, want %q", evidence.Resolved(), profile.Valid(), DSNEvidenceStageOf(err), err, stage)
	}
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
		RouteDisclosureSingle, []byte("delivery-status-identity-test"),
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

// TestDSNSigningIdentityFollowsRecipientNotReportingDomain reproduces Draft-08
// Section 16.2: the highest embedded rt= is under profile A (example.test),
// the configured reporting domain is B (example.net). The report is signed
// with A; B never signs because it does not relaxed-match an rt= address.
func TestDSNSigningIdentityFollowsRecipientNotReportingDomain(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	outer := dsnReport(signDSNOriginal(t, fixture), "MAILER-DAEMON@mx.example.test", "mx.example.test", "bob@example.test")
	source := newDSNProfiles(t, testSigningDomain, "example.net")
	evidence, profile, err := resolveDSN(t, fixture, outer, "example.net", source)
	if err != nil || evidence.SigningDomain() != testSigningDomain {
		t.Fatalf("resolved domain=%q error=%v", evidence.SigningDomain(), err)
	}
	if slices.Contains(source.lookups, "example.net") {
		t.Fatalf("non-matching reporting domain reached the profile source: %v", source.lookups)
	}
	result, recovery, err := signEvaluatedDSN(t, fixture, outer, evidence, profile)
	if err != nil || recovery.Valid() || !result.Valid() {
		t.Fatalf("SignDSN() result=%t recovery=%t error=%v", result.Valid(), recovery.Valid(), err)
	}
	signed, ok := result.Unrestricted()
	if !ok || !bytes.Contains(signed.Bytes(), []byte("d=example.test;")) {
		t.Fatal("DSN was not signed with the rt=-matching profile domain")
	}
}

// TestDSNSigningIdentityPrefersMatchingReportingDomain proves the reporting
// domain wins within its linkage tier only when it relaxed-matches rt=.
func TestDSNSigningIdentityPrefersMatchingReportingDomain(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	original := signDSNOriginalForRecipient(t, fixture, []byte("<bob@mx.sub.example.test>"))
	outer := dsnReport(original, "MAILER-DAEMON@mx.sub.example.test", "mx.sub.example.test", "bob@mx.sub.example.test")
	evidence, _, err := resolveDSN(t, fixture, outer, testSigningDomain, newDSNProfiles(t, dsnSubDomain, testSigningDomain))
	if err != nil || evidence.SigningDomain() != testSigningDomain {
		t.Fatalf("preferred matching domain=%q error=%v", evidence.SigningDomain(), err)
	}
}

// TestDSNSigningIdentityPrefersLongestProfileDomain proves the most specific
// matching profile domain signs when no preference applies.
func TestDSNSigningIdentityPrefersLongestProfileDomain(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	original := signDSNOriginalForRecipient(t, fixture, []byte("<bob@mx.sub.example.test>"))
	outer := dsnReport(original, "MAILER-DAEMON@mx.sub.example.test", "mx.sub.example.test", "bob@mx.sub.example.test")
	source := newDSNProfiles(t, dsnSubDomain, testSigningDomain)
	evidence, profile, err := resolveDSN(t, fixture, outer, "", source)
	if err != nil || evidence.SigningDomain() != dsnSubDomain || profile.value.Domain() != dsnSubDomain {
		t.Fatalf("longest domain=%q error=%v", evidence.SigningDomain(), err)
	}
	if !slices.Equal(source.lookups, []string{"mx.sub.example.test", dsnSubDomain}) {
		t.Fatalf("lookups=%v", source.lookups)
	}
}

// TestDSNSigningIdentityPrefersRFC3464LinkedRecipient proves a profile that
// matches the recipient named by the RFC 3464 Final-Recipient wins over a
// longer profile that matches only an unlinked rt= recipient, although both
// would make the report From Authentic.
func TestDSNSigningIdentityPrefersRFC3464LinkedRecipient(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	original := signDSNOriginalForRecipients(t, fixture, [][]byte{
		[]byte("<bob@y.example.test>"), []byte("<carol@example.test>"),
	})
	outer := dsnReport(original, "MAILER-DAEMON@x.y.example.test", "x.y.example.test", "carol@example.test")
	evidence, _, err := resolveDSN(t, fixture, outer, "", newDSNProfiles(t, "y.example.test", testSigningDomain))
	if err != nil || evidence.SigningDomain() != testSigningDomain {
		t.Fatalf("linked domain=%q error=%v", evidence.SigningDomain(), err)
	}
	unlinked := dsnReport(original, "MAILER-DAEMON@x.y.example.test", "x.y.example.test", "bob@y.example.test")
	evidence, _, err = resolveDSN(t, fixture, unlinked, "", newDSNProfiles(t, "y.example.test", testSigningDomain))
	if err != nil || evidence.SigningDomain() != "y.example.test" {
		t.Fatalf("linked longest domain=%q error=%v", evidence.SigningDomain(), err)
	}
}

// TestDSNSigningIdentityUnavailableLeavesReportUnsigned reproduces a report
// for which no local delivery_status profile relaxed-matches rt=: the result
// is the explicit identity_unavailable outcome, never another domain.
func TestDSNSigningIdentityUnavailableLeavesReportUnsigned(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	outer := dsnReport(signDSNOriginal(t, fixture), "MAILER-DAEMON@example.net", "mx.example.net", "bob@example.test")
	evidence, profile, err := resolveDSN(t, fixture, outer, "example.net", newDSNProfiles(t, "example.net", "other.example.test"))
	assertDSNUnsigned(t, evidence, profile, err, DSNEvidenceStageIdentityUnavailable)
}

// TestDSNSigningIdentityRequiresAuthenticReportFrom reproduces Draft-08
// Sections 11 and 12.4 for MTA-generated DSNs: the report is a new i=1
// message, so a matching profile whose domain cannot make the report From
// Authentic yields the explicit from_not_authentic outcome.
func TestDSNSigningIdentityRequiresAuthenticReportFrom(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	outer := dsnReport(signDSNOriginal(t, fixture), "MAILER-DAEMON@mx.example.net", "mx.example.net", "bob@example.test")
	evidence, profile, err := resolveDSN(t, fixture, outer, "example.net", newDSNProfiles(t, testSigningDomain, "example.net"))
	assertDSNUnsigned(t, evidence, profile, err, DSNEvidenceStageFromNotAuthentic)

	multiple := bytes.Replace(outer, []byte("From: MAILER-DAEMON@mx.example.net"), []byte("From: a@example.test, b@example.test"), 1)
	evidence, profile, err = resolveDSN(t, fixture, multiple, "", newDSNProfiles(t, testSigningDomain))
	assertDSNUnsigned(t, evidence, profile, err, DSNEvidenceStageFromNotAuthentic)
}

// TestDSNSigningIdentitySenderSideBounceIsUnsigned reproduces the sender-side
// bounce: the highest embedded signature is ours (d=example.test) and its rt=
// is remote. No local profile can relaxed-match the remote rt= address, so
// Section 16.2 can never be satisfied and the report stays unsigned even
// though the embedded original verifies and links.
func TestDSNSigningIdentitySenderSideBounceIsUnsigned(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	original := signDSNOriginalForRecipient(t, fixture, []byte("<bob@remote.example.net>"))
	outer := dsnReport(original, "MAILER-DAEMON@example.test", "mx.example.test", "bob@remote.example.net")
	evidence, profile, err := resolveDSN(t, fixture, outer, testSigningDomain, newDSNProfiles(t, testSigningDomain))
	assertDSNUnsigned(t, evidence, profile, err, DSNEvidenceStageIdentityUnavailable)
}

// TestDSNSigningIdentityFailsClosedOnProfileSourceFailures proves an
// undecided profile answer or a profile for another domain stops resolution
// with the signing_domain stage instead of skipping to another candidate.
func TestDSNSigningIdentityFailsClosedOnProfileSourceFailures(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	outer := dsnReport(signDSNOriginal(t, fixture), "MAILER-DAEMON@example.test", "mx.example.test", "bob@example.test")
	temporary := newDSNProfiles(t, "test")
	temporary.failures = map[string]error{testSigningDomain: NewTemporaryProviderError()}
	evidence, _, err := resolveDSN(t, fixture, outer, "", temporary)
	if evidence.Resolved() || DSNEvidenceStageOf(err) != DSNEvidenceStageSigningDomain ||
		ProviderErrorClassOf(err) != ProviderErrorClassTemporary {
		t.Fatalf("temporary source stage=%q error=%v", DSNEvidenceStageOf(err), err)
	}
	mismatched := newDSNProfiles(t, "example.net")
	mismatched.profiles[testSigningDomain] = mismatched.profiles["example.net"]
	evidence, _, err = resolveDSN(t, fixture, outer, "", mismatched)
	if evidence.Resolved() || DSNEvidenceStageOf(err) != DSNEvidenceStageSigningDomain ||
		!errors.Is(err, newSigningError(SigningErrorInvalidRequest)) {
		t.Fatalf("mismatched profile stage=%q error=%v", DSNEvidenceStageOf(err), err)
	}
	unresolved, err := fixture.facade.EvaluateDSNForSigning(context.Background(),
		NewPostfixDSNSigningEvidenceRequest(outer, []byte("<>"), [][]byte{[]byte("<alice@example.test>")}))
	if err != nil {
		t.Fatal(err)
	}
	result, _, err := signEvaluatedDSN(t, fixture, outer, unresolved, fixture.profile)
	if result.Valid() || !errors.Is(err, newSigningError(SigningErrorInvalidRequest)) {
		t.Fatalf("unresolved evidence signed result=%t error=%v", result.Valid(), err)
	}
}

// TestPostfixDSNPreferenceKeepsEmbeddedEvidenceGates proves a preferred
// identity relaxes nothing: unlinked outer recipients and tampered originals
// still fail closed before any profile lookup.
func TestPostfixDSNPreferenceKeepsEmbeddedEvidenceGates(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	original := signDSNOriginal(t, fixture)
	preferred, err := NewDSNIdentity(testSigningDomain)
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range []struct {
		name       string
		outer      []byte
		recipients [][]byte
		stage      DSNEvidenceStage
	}{
		{name: "foreign outer recipient", outer: dsnReport(original, "MAILER-DAEMON@example.test", "mx.example.test", "bob@example.test"), recipients: [][]byte{[]byte("<mallory@example.test>")}, stage: DSNEvidenceStageOuterRecipientLinkage},
		{name: "tampered original", outer: dsnReport(bytes.Replace(original, []byte("original body"), []byte("altered body"), 1), "MAILER-DAEMON@example.test", "mx.example.test", "bob@example.test"), recipients: [][]byte{[]byte("<alice@example.test>")}, stage: DSNEvidenceStageEmbeddedVerification},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			evidence, err := fixture.facade.EvaluateDSNForSigning(context.Background(), NewPostfixDSNSigningEvidenceRequest(
				testCase.outer, []byte("<>"), testCase.recipients,
			).WithPreferredIdentity(preferred))
			if evidence.Valid() || DSNEvidenceStageOf(err) != testCase.stage {
				t.Fatalf("evidence valid=%t stage=%q error=%v", evidence.Valid(), DSNEvidenceStageOf(err), err)
			}
		})
	}
}
