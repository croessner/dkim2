package daemon

import (
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/daemon/generated"
)

// TestSignatureSelectorPresenceFollowsDraft08Step8 proves the response
// boundary admits a selector exactly for non-passing sets (Draft-08 Section
// 14.6 step 8) and rejects it for pass and for internal-contract facts.
func TestSignatureSelectorPresenceFollowsDraft08Step8(t *testing.T) {
	selector := "selector.test"
	tests := []struct {
		status generated.SignatureSetResultStatus
		reason generated.VerificationReason
		value  *string
		want   bool
	}{
		{generated.SignatureSetResultStatusPass, generated.VerificationReasonNone, nil, true},
		{generated.SignatureSetResultStatusPass, generated.VerificationReasonNone, &selector, false},
		{generated.SignatureSetResultStatusFail, generated.VerificationReasonSignatureMismatch, &selector, true},
		{generated.SignatureSetResultStatusPermerror, generated.VerificationReasonMissingKey, &selector, true},
		{generated.SignatureSetResultStatusPermerror, generated.VerificationReasonMissingKey, nil, false},
		{generated.SignatureSetResultStatusTemperror, generated.VerificationReasonProviderTemporary, &selector, true},
		{generated.SignatureSetResultStatusIgnored, generated.VerificationReasonUnsupportedAlgorithm, &selector, true},
		{generated.SignatureSetResultStatusPermerror, generated.VerificationReasonInternalContract, nil, true},
		{generated.SignatureSetResultStatusPermerror, generated.VerificationReasonInternalContract, &selector, false},
	}
	for _, test := range tests {
		if got := validSignatureSelector(test.status, test.reason, test.value); got != test.want {
			t.Fatalf("validSignatureSelector(%q, %q, present=%t) = %t", test.status, test.reason, test.value != nil, got)
		}
	}
}
