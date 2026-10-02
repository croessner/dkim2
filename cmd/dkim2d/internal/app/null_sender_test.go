package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
)

// nullSenderAutoReply returns one stable automatic reply authored by the
// originator test domain.
func nullSenderAutoReply(author string) []byte {
	return []byte(
		"From: Vacation <" + author + ">\r\n" +
			"To: recipient@example.net\r\n" +
			"Subject: Auto: out of office\r\n" +
			"Auto-Submitted: auto-replied\r\n" +
			"\r\n" +
			"away\r\n",
	)
}

// TestHeaderFromNullSenderOperationRequestBindsDomainToAuthor proves the
// domain request admits the null reverse path only for the declared policy
// and only when the signing domain is the single From mailbox domain.
func TestHeaderFromNullSenderOperationRequestBindsDomainToAuthor(t *testing.T) {
	recipients := [][]byte{[]byte("<recipient@example.net>")}
	request, err := NewHeaderFromNullSenderOperationRequest(
		nullSenderAutoReply("noreply@origin.example.test"), recipients,
		signingServiceTestTenant, signingServiceOriginDomain, FidelityMilterReconstructedCRLF,
	)
	if err != nil || !request.HeaderFromNullSender() || !bytes.Equal(request.ReversePath(), []byte("<>")) ||
		request.Domain() != signingServiceOriginDomain {
		t.Fatalf("header_from request valid=%t error=%v", request.HeaderFromNullSender(), err)
	}
	for _, raw := range [][]byte{
		nullSenderAutoReply("noreply@other.example.test"),
		[]byte("To: recipient@example.net\r\n\r\nbody\r\n"),
		[]byte("From: a@origin.example.test, b@origin.example.test\r\n\r\nbody\r\n"),
	} {
		if _, err := NewHeaderFromNullSenderOperationRequest(
			raw, recipients, signingServiceTestTenant, signingServiceOriginDomain, FidelityMilterReconstructedCRLF,
		); err == nil {
			t.Fatal("header_from request admitted a foreign or ambiguous author")
		}
	}
	if _, err := NewOperationRequest(
		OperationSign, nullSenderAutoReply("noreply@origin.example.test"), []byte("<>"), recipients,
		signingServiceTestTenant, signingServiceOriginDomain, FidelityMilterReconstructedCRLF,
	); err == nil {
		t.Fatal("generic originator request admitted the null reverse path")
	}
	if _, err := NewRevisionOperationRequest(
		nullSenderAutoReply("noreply@origin.example.test"), []byte("<>"), recipients, []byte("<>"), recipients,
		signingServiceTestTenant, signingServiceOriginDomain, FidelityMilterReconstructedCRLF,
	); err == nil {
		t.Fatal("revision request admitted the null reverse path")
	}
}

// TestSigningServiceRefusesHeaderFromNullSenderByDefault proves the default
// daemon policy refuses the declaration before any datastore access.
func TestSigningServiceRefusesHeaderFromNullSenderByDefault(t *testing.T) {
	request, err := NewHeaderFromNullSenderOperationRequest(
		nullSenderAutoReply("noreply@origin.example.test"), [][]byte{[]byte("<recipient@example.net>")},
		signingServiceTestTenant, signingServiceOriginDomain, FidelityRawRFC5322,
	)
	if err != nil {
		t.Fatal(err)
	}
	authority := &countingSigningAuthority{}
	service, err := NewAuthoritySigningService(signingServicePublicKeys{}, authority, config.SigningPoliciesConfig{})
	if err != nil {
		t.Fatalf("NewAuthoritySigningService() error = %v", err)
	}
	if _, err := service.Sign(context.Background(), request); !IsNullSenderRefused(err) || authority.calls != 0 {
		t.Fatalf("default policy Sign() error=%v acquisitions=%d", err, authority.calls)
	}
}

// countingSigningAuthority records lease acquisitions and never grants one.
type countingSigningAuthority struct {
	calls int
}

// Acquire counts the attempt and reports an unavailable datastore.
func (a *countingSigningAuthority) Acquire(context.Context) (SigningLease, error) {
	a.calls++
	return nil, &DomainError{}
}

// TestSigningServiceSignsHeaderFromNullSenderThatVerifies proves the opt-in
// policy signs mf=<> with d= equal to the From domain, that the result
// verifies, and that an author domain without a policy is not applicable.
func TestSigningServiceSignsHeaderFromNullSenderThatVerifies(t *testing.T) {
	fixture := newSigningServiceFixture(t)
	service, err := NewSigningService(
		fixture.publicKeys, fixture.runtime, false,
		signingPolicies{admitHeaderFromNullSender: true},
	)
	if err != nil {
		t.Fatalf("NewSigningService() error = %v", err)
	}
	service.clock = func() time.Time { return time.Unix(1_700_000_000, 0) }
	raw := nullSenderAutoReply("noreply@origin.example.test")
	recipients := [][]byte{[]byte("<recipient@example.net>")}
	request, err := NewHeaderFromNullSenderOperationRequest(
		raw, recipients, signingServiceTestTenant, signingServiceOriginDomain, FidelityRawRFC5322,
	)
	if err != nil {
		t.Fatal(err)
	}
	assessment, err := service.Sign(context.Background(), request)
	result, ok := assessment.Result()
	if !ok {
		t.Fatalf("null-sender signing was not applicable: error=%v", err)
	}
	assertSigningServicePass(t, result, err, signingServiceOriginSelector)
	signature := result.Fields()[len(result.Fields())-1].Bytes()
	if !bytes.Contains(signature, []byte("mf="+base64.StdEncoding.EncodeToString([]byte("<>")))) ||
		!bytes.Contains(signature, []byte("d="+signingServiceOriginDomain)) {
		t.Fatal("signature lacks mf=<> or the From-bound d=")
	}
	verifier, err := dkim2.NewVerifier(fixture.publicKeys, dkim2.WithVerificationClock(service.clock))
	if err != nil {
		t.Fatal(err)
	}
	signed := insertSigningServiceFields(result.Fields(), raw)
	verified, err := verifier.Verify(context.Background(), dkim2.NewVerifyRequest(signed, []byte("<>"), recipients))
	if err != nil || verified.State() != dkim2.ResultStatePASS {
		t.Fatalf("null-sender verification state=%s reason=%s error=%v", verified.State(), verified.PrimaryReason(), err)
	}

	unknown, err := NewHeaderFromNullSenderOperationRequest(
		nullSenderAutoReply("noreply@unknown.example.test"), recipients,
		signingServiceTestTenant, "unknown.example.test", FidelityRawRFC5322,
	)
	if err != nil {
		t.Fatal(err)
	}
	absent, err := service.Sign(context.Background(), unknown)
	if err != nil || !absent.Valid() || absent.Applicable() {
		t.Fatalf("unknown author domain valid=%t applicable=%t error=%v", absent.Valid(), absent.Applicable(), err)
	}
}
