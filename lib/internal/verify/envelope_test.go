package verify

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/croessner/dkim2/internal/signature"
)

// TestEnvelopeAccessorsAreImmutable verifies current SMTP paths are copied.
func TestEnvelopeAccessorsAreImmutable(t *testing.T) {
	reversePath := []byte("<sender@example.test>")
	forwardPaths := [][]byte{
		[]byte("<one@example.test>"),
		[]byte("<two@example.test>"),
	}

	envelope := NewEnvelope(reversePath, forwardPaths)
	reversePath[1] = 'X'
	forwardPaths[0][1] = 'Y'
	forwardPaths[1] = []byte("<mutated@example.test>")

	if got := envelope.ReversePath(); !bytes.Equal(got, []byte("<sender@example.test>")) {
		t.Fatalf("ReversePath() = %q, want original path", got)
	}
	if got := envelope.ForwardPaths(); len(got) != 2 || !bytes.Equal(got[0], []byte("<one@example.test>")) || !bytes.Equal(got[1], []byte("<two@example.test>")) {
		t.Fatalf("ForwardPaths() = %#v, want original ordered paths", got)
	}

	gotReverse := envelope.ReversePath()
	gotReverse[1] = 'Z'
	gotForward := envelope.ForwardPaths()
	gotForward[0][1] = 'Q'
	gotForward[1] = nil

	if bytes.Equal(envelope.ReversePath(), gotReverse) {
		t.Fatal("ReversePath() reused mutable storage")
	}
	if got := envelope.ForwardPaths(); !bytes.Equal(got[0], []byte("<one@example.test>")) || !bytes.Equal(got[1], []byte("<two@example.test>")) {
		t.Fatalf("ForwardPaths() after mutation = %#v, want original ordered paths", got)
	}
	if envelope.RecipientCount() != 2 {
		t.Fatalf("RecipientCount() = %d, want 2", envelope.RecipientCount())
	}
	if envelope.IsZero() {
		t.Fatal("IsZero() returned true for populated envelope")
	}
}

// TestZeroEnvelopeReportsMissingEvidence verifies zero-value envelope semantics.
func TestZeroEnvelopeReportsMissingEvidence(t *testing.T) {
	var envelope Envelope
	if !envelope.IsZero() {
		t.Fatal("zero Envelope did not report zero state")
	}
	if envelope.RecipientCount() != 0 {
		t.Fatalf("RecipientCount() = %d, want 0", envelope.RecipientCount())
	}
}

// TestVerifierRequiresEnvelopeForCurrentTarget verifies default inbound fail-closed behavior.
func TestVerifierRequiresEnvelopeForCurrentTarget(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	verifier := mustVerifierForFixture(t, fixture)

	result, err := verifier.Verify(context.Background(), Request{Message: fixture.message})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Status() != TargetStatusFail || !hasEnvelopeCheck(result, EnvelopeStatusMissing, CheckStatusFail) {
		t.Fatalf("result = %#v checks=%#v, want missing envelope failure", result, result.Checks())
	}
}

// TestVerifierMatchesEnvelopeAccordingToDraft verifies current-envelope matching from draft-04 Sections 9.2 and 11.4.
func TestVerifierMatchesEnvelopeAccordingToDraft(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	verifier := mustVerifierForFixture(t, fixture)

	tests := []struct {
		name       string
		envelope   Envelope
		wantStatus EnvelopeStatus
	}{
		{
			name:       "matching",
			envelope:   matchingEnvelope(),
			wantStatus: EnvelopeStatusPass,
		},
		{
			name:       "reverse path mismatch",
			envelope:   NewEnvelope([]byte("<sender@example.test>"), [][]byte{[]byte("<rcpt@example.test>")}),
			wantStatus: EnvelopeStatusReversePathMismatch,
		},
		{
			name:       "recipient value mismatch",
			envelope:   NewEnvelope([]byte("<>"), [][]byte{[]byte("<other@example.test>")}),
			wantStatus: EnvelopeStatusRecipientValueMismatch,
		},
		{
			name:       "missing reverse path",
			envelope:   NewEnvelope(nil, [][]byte{[]byte("<rcpt@example.test>")}),
			wantStatus: EnvelopeStatusMissing,
		},
		{
			name:       "missing recipients",
			envelope:   NewEnvelope([]byte("<>"), nil),
			wantStatus: EnvelopeStatusMissing,
		},
		{
			name:       "invalid recipient path",
			envelope:   NewEnvelope([]byte("<>"), [][]byte{[]byte("<>")}),
			wantStatus: EnvelopeStatusInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: tt.envelope})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			wantCheckStatus := CheckStatusFail
			if tt.wantStatus == EnvelopeStatusPass {
				wantCheckStatus = CheckStatusPass
			}
			if !hasEnvelopeCheck(result, tt.wantStatus, wantCheckStatus) {
				t.Fatalf("result = %#v checks=%#v, want envelope %s", result, result.Checks(), tt.wantStatus)
			}
		})
	}
}

// TestVerifierRequiresUsedRecipientsWithoutOrder verifies each current recipient is present in signed rt=.
func TestVerifierRequiresUsedRecipientsWithoutOrder(t *testing.T) {
	signedRecipients := [][]byte{
		[]byte("<one@example.test>"),
		[]byte("<two@EXAMPLE.test>"),
		[]byte("<signed-extra@example.test>"),
	}
	fixture := newRSAVerificationFixtureWithEnvelopeAt(t, testTimestampSeconds, []byte("<>"), signedRecipients)
	verifier := mustVerifierForFixture(t, fixture)

	result, err := verifier.Verify(context.Background(), Request{
		Message: fixture.message,
		Envelope: NewEnvelope([]byte("<>"), [][]byte{
			[]byte("<two@example.TEST>"),
			[]byte("<one@example.test>"),
		}),
	})
	if err != nil {
		t.Fatalf("Verify() reordered subset error = %v", err)
	}
	if !hasEnvelopeCheck(result, EnvelopeStatusPass, CheckStatusPass) {
		t.Fatalf("result = %#v checks=%#v, want reordered subset pass", result, result.Checks())
	}

	result, err = verifier.Verify(context.Background(), Request{
		Message: fixture.message,
		Envelope: NewEnvelope([]byte("<>"), [][]byte{
			[]byte("<one@example.test>"),
			[]byte("<not-signed@example.test>"),
		}),
	})
	if err != nil {
		t.Fatalf("Verify() unsigned recipient error = %v", err)
	}
	if !hasEnvelopeCheck(result, EnvelopeStatusRecipientValueMismatch, CheckStatusFail) {
		t.Fatalf("result = %#v checks=%#v, want unsigned recipient mismatch", result, result.Checks())
	}
}

// TestVerifierLowercasesOnlyEnvelopeDomains verifies ASCII domain folding without local-part normalization.
func TestVerifierLowercasesOnlyEnvelopeDomains(t *testing.T) {
	fixture := newRSAVerificationFixtureWithEnvelopeAt(t, testTimestampSeconds,
		[]byte("<Sender@EXAMPLE.test>"),
		[][]byte{[]byte("<Recipient@EXAMPLE.test>")},
	)
	verifier := mustVerifierForFixture(t, fixture)

	tests := []struct {
		name       string
		envelope   Envelope
		wantStatus EnvelopeStatus
	}{
		{
			name: "ASCII domain case is insignificant",
			envelope: NewEnvelope([]byte("<Sender@example.TEST>"), [][]byte{
				[]byte("<Recipient@example.TEST>"),
			}),
			wantStatus: EnvelopeStatusPass,
		},
		{
			name: "reverse path local part remains case sensitive",
			envelope: NewEnvelope([]byte("<sender@example.test>"), [][]byte{
				[]byte("<Recipient@example.test>"),
			}),
			wantStatus: EnvelopeStatusReversePathMismatch,
		},
		{
			name: "recipient local part remains case sensitive",
			envelope: NewEnvelope([]byte("<Sender@example.test>"), [][]byte{
				[]byte("<recipient@example.test>"),
			}),
			wantStatus: EnvelopeStatusRecipientValueMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: tt.envelope})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}

			wantCheckStatus := CheckStatusFail
			if tt.wantStatus == EnvelopeStatusPass {
				wantCheckStatus = CheckStatusPass
			}
			if !hasEnvelopeCheck(result, tt.wantStatus, wantCheckStatus) {
				t.Fatalf("result = %#v checks=%#v, want envelope %s", result, result.Checks(), tt.wantStatus)
			}
		})
	}
}

// TestVerifierRejectsSMTPUTF8EnvelopePathsAtParserBoundary verifies draft-04 imports ASCII RFC 5321 paths.
func TestVerifierRejectsSMTPUTF8EnvelopePathsAtParserBoundary(t *testing.T) {
	eaiPath := []byte("<\xc3\xbc@example.test>")
	fixture := newRSAVerificationFixture(t)
	raw := bytes.Replace(
		[]byte(fixture.raw),
		[]byte(base64.StdEncoding.EncodeToString([]byte("<rcpt@example.test>"))),
		[]byte(base64.StdEncoding.EncodeToString(eaiPath)),
		1,
	)
	_, err := parseVerificationFixture(string(raw))
	if !signature.IsErrorCode(err, signature.ErrorCodeInvalidEnvelopePath) {
		t.Fatalf("parseVerificationFixture() error = %v, want invalid envelope path", err)
	}
}

// hasEnvelopeCheck reports whether result has one envelope fact.
func hasEnvelopeCheck(result Result, status EnvelopeStatus, checkStatus CheckStatus) bool {
	for _, check := range result.Checks() {
		if check.Kind == CheckKindEnvelope && check.EnvelopeStatus == status && check.Status == checkStatus {
			return true
		}
	}

	return false
}
