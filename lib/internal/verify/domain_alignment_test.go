package verify

import (
	"context"
	"testing"
)

// TestVerifierChecksSigningDomainAgainstMailFrom verifies Sections 8.8, 9.4, and 11.4.
func TestVerifierChecksSigningDomainAgainstMailFrom(t *testing.T) {
	tests := []struct {
		name       string
		reverse    []byte
		wantTarget TargetStatus
		wantDomain DomainAlignmentStatus
		wantCheck  CheckStatus
	}{
		{name: "exact domain", reverse: []byte("<sender@example.test>"), wantTarget: TargetStatusPass, wantDomain: DomainAlignmentStatusPass, wantCheck: CheckStatusPass},
		{name: "subdomain", reverse: []byte("<sender@bounce.example.test>"), wantTarget: TargetStatusPass, wantDomain: DomainAlignmentStatusPass, wantCheck: CheckStatusPass},
		{name: "ascii case insensitive", reverse: []byte("<sender@BOUNCE.EXAMPLE.TEST>"), wantTarget: TargetStatusPass, wantDomain: DomainAlignmentStatusPass, wantCheck: CheckStatusPass},
		{name: "label boundary mismatch", reverse: []byte("<sender@notexample.test>"), wantTarget: TargetStatusFail, wantDomain: DomainAlignmentStatusMismatch, wantCheck: CheckStatusFail},
		{name: "foreign domain", reverse: []byte("<sender@example.invalid>"), wantTarget: TargetStatusFail, wantDomain: DomainAlignmentStatusMismatch, wantCheck: CheckStatusFail},
		{name: "address literal", reverse: []byte("<sender@[192.0.2.1]>"), wantTarget: TargetStatusFail, wantDomain: DomainAlignmentStatusInvalid, wantCheck: CheckStatusFail},
		{name: "null reverse path", reverse: []byte("<>"), wantTarget: TargetStatusPass, wantDomain: DomainAlignmentStatusNotApplicable, wantCheck: CheckStatusNotApplicable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forward := [][]byte{[]byte("<rcpt@example.test>")}
			fixture := newRSAVerificationFixtureWithEnvelopeAt(t, testTimestampSeconds, tt.reverse, forward)
			verifier := mustVerifierForFixture(t, fixture)

			result, err := verifier.Verify(context.Background(), Request{
				Message:  fixture.message,
				Envelope: NewEnvelope(tt.reverse, forward),
			})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if result.Status() != tt.wantTarget || !hasDomainAlignmentCheck(result, tt.wantDomain, tt.wantCheck) {
				t.Fatalf("result = %q checks=%#v, want %s/%s", result.Status(), result.Checks(), tt.wantDomain, tt.wantCheck)
			}
		})
	}
}

// hasDomainAlignmentCheck reports whether result carries one bounded domain-alignment fact.
func hasDomainAlignmentCheck(result Result, status DomainAlignmentStatus, checkStatus CheckStatus) bool {
	for _, check := range result.Checks() {
		if check.Kind == CheckKindDomainAlignment && check.DomainAlignmentStatus == status && check.Status == checkStatus {
			return true
		}
	}

	return false
}
