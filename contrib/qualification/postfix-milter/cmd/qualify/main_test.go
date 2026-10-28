package main

import (
	"errors"
	"strings"
	"testing"
)

// TestQualificationFailureStageIsClosedAndContentFree proves diagnostics expose
// only the fixed stage vocabulary and never arbitrary error content.
func TestQualificationFailureStageIsClosedAndContentFree(t *testing.T) {
	for _, want := range []qualificationStage{
		stageOriginValidation,
		stageDSNQueue,
		stageDSNCardinality,
		stageDSNCrypto,
	} {
		err := qualificationFailure(want)
		stage, ok := qualificationFailureStage(err)
		if !ok || stage != want || err.Error() != "qualification failed" {
			t.Fatalf("closed qualification failure = %q/%t/%q", stage, ok, err)
		}
	}
	if stage, ok := qualificationFailureStage(errors.New("toxic-private-marker")); ok || stage != "" {
		t.Fatalf("arbitrary error exposed as stage %q/%t", stage, ok)
	}
	forged := &qualificationStageError{stage: "future-private-marker"}
	if stage, ok := qualificationFailureStage(forged); ok || stage != "" {
		t.Fatalf("unrecognized stage exposed as %q/%t", stage, ok)
	}
}

// TestQueuedDSNDetectionDoesNotPrejudgeSignature proves queue discovery leaves
// signature cardinality and cryptographic validation to their owning checks.
func TestQueuedDSNDetectionDoesNotPrejudgeSignature(t *testing.T) {
	unsigned := []byte("Content-Type: multipart/report\r\n\r\nmessage/delivery-status\r\n")
	if !isDeliveryStatusReport(unsigned) {
		t.Fatal("unsigned delivery-status report was hidden from validation")
	}
	if isDeliveryStatusReport([]byte("Content-Type: text/plain\r\n\r\nbody\r\n")) {
		t.Fatal("ordinary message was classified as a delivery-status report")
	}
}

// TestTopTraceOrderPinsMilterPlacement proves the qualification pin accepts
// only a header block that starts with the hop's top-placed trace block above
// Postfix's own Received field, and rejects the former bottom placement.
func TestTopTraceOrderPinsMilterPlacement(t *testing.T) {
	top := []byte("Message-Instance: m=1\r\nDKIM2-Signature: i=1\r\nReceived: by mx\r\n\tid 1\r\nFrom: a@example.test\r\n\r\nbody\r\n")
	if err := validateTopTraceOrder(top, milterSignedTraceOrder...); err != nil {
		t.Fatal("top-placed trace block was rejected")
	}
	bottom := []byte("Received: by mx\r\nFrom: a@example.test\r\nMessage-Instance: m=1\r\nDKIM2-Signature: i=1\r\n\r\nbody\r\n")
	if validateTopTraceOrder(bottom, milterSignedTraceOrder...) == nil {
		t.Fatal("bottom-placed trace block was accepted")
	}
	swapped := []byte("DKIM2-Signature: i=1\r\nMessage-Instance: m=1\r\nReceived: by mx\r\nFrom: a@example.test\r\n\r\n")
	if validateTopTraceOrder(swapped, milterSignedTraceOrder...) == nil {
		t.Fatal("signature above its instance was accepted")
	}
	inbound := []byte("Authentication-Results: mx; dkim2=pass\r\nReceived: by in\r\n" + string(top))
	if err := validateTopTraceOrder(inbound, inboundTraceOrder...); err != nil {
		t.Fatal("inbound trace order was rejected")
	}
	if validateTopTraceOrder(top[:10], milterSignedTraceOrder...) == nil {
		t.Fatal("truncated header block was accepted")
	}
}

// TestTopTraceOrderPinsPropagatedPlacement proves the propagated notification
// pin accepts the library-prepended block directly below the re-injection
// Received field and rejects the former bottom placement.
func TestTopTraceOrderPinsPropagatedPlacement(t *testing.T) {
	top := []byte("Received: by reinjection\r\nMessage-Instance: m=1\r\nDKIM2-Signature: i=1\r\nFrom: MAILER-DAEMON@example.test\r\n\r\nbody\r\n")
	if err := validateTopTraceOrder(top, propagatedTraceOrder...); err != nil {
		t.Fatal("top-placed propagated report was rejected")
	}
	bottom := []byte("Received: by reinjection\r\nFrom: MAILER-DAEMON@example.test\r\nMessage-Instance: m=1\r\nDKIM2-Signature: i=1\r\n\r\nbody\r\n")
	if validateTopTraceOrder(bottom, propagatedTraceOrder...) == nil {
		t.Fatal("bottom-placed propagated report was accepted")
	}
}

// TestForeignNotificationRecipientAlignsWithForeignSigner pins the Draft-08
// Section 16.2 topology of the not_local lane: the foreign delivery-status
// signer may sign only a notification whose embedded completion signature
// names a recipient under its own domain, so the foreign original must be
// addressed under the foreign delivery-status profile domain and never under
// the local signing domain.
func TestForeignNotificationRecipientAlignsWithForeignSigner(t *testing.T) {
	address := strings.Trim(foreignRecipient, "<>")
	at := strings.LastIndexByte(address, '@')
	if at < 0 {
		t.Fatalf("foreign recipient %q has no domain", foreignRecipient)
	}
	domain := strings.ToLower(address[at+1:])
	underDomain := func(candidate, signer string) bool {
		return candidate == signer || strings.HasSuffix(candidate, "."+signer)
	}
	if underDomain(domain, signingDomain) {
		t.Fatalf("foreign recipient %q is under the local signing domain", foreignRecipient)
	}
	aligned := false
	for _, identity := range qualificationIdentities {
		if identity.tenant == foreignTenant && identity.use == "delivery_status" &&
			underDomain(domain, identity.domain) {
			aligned = true
		}
	}
	if !aligned {
		t.Fatalf("foreign recipient %q has no aligned foreign delivery_status profile", foreignRecipient)
	}
}
