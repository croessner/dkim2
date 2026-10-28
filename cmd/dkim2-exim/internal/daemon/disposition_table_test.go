package daemon

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/croessner/dkim2/authresults"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/daemon/generated"
)

// nonPassVerificationReasons lists every verification reason a FAIL or
// PERMERROR process response can carry.
var nonPassVerificationReasons = []generated.VerificationReason{
	generated.VerificationReasonLimitExceeded, generated.VerificationReasonMalformedMessage,
	generated.VerificationReasonMalformedProtocol, generated.VerificationReasonDuplicateHashAlgorithm,
	generated.VerificationReasonInvalidRecipeJson, generated.VerificationReasonInvalidRecipe,
	generated.VerificationReasonFromNotAuthentic, generated.VerificationReasonDuplicateSelector,
	generated.VerificationReasonMissingProtocol, generated.VerificationReasonSequenceInvalid,
	generated.VerificationReasonUnsupportedAlgorithm, generated.VerificationReasonHashMismatch,
	generated.VerificationReasonSignatureMismatch, generated.VerificationReasonMissingKey,
	generated.VerificationReasonInvalidKey, generated.VerificationReasonAmbiguousKey,
	generated.VerificationReasonRevokedKey, generated.VerificationReasonUnsupportedKeyType,
	generated.VerificationReasonKeyAlgorithmMismatch, generated.VerificationReasonProviderPermanent,
	generated.VerificationReasonProviderContract, generated.VerificationReasonTimestampInvalid,
	generated.VerificationReasonEnvelopeMismatch, generated.VerificationReasonDomainAlignmentMismatch,
	generated.VerificationReasonNextDomainMismatch, generated.VerificationReasonCustodyMismatch,
	generated.VerificationReasonOutOfBandRequired, generated.VerificationReasonBodyHistoryUnavailable,
	generated.VerificationReasonInternalContract,
}

// TestProcessSMTPOutcomeIsIndependentOfFailOrPermerror proves that the Exim
// SMTP outcome of a non-PASS verification depends only on the daemon policy
// disposition: every reason yields the same plan disposition, IPC response
// reason, and actions whether the daemon reports it as FAIL or PERMERROR, so
// moving a reason between the two states cannot change the SMTP reply.
func TestProcessSMTPOutcomeIsIndependentOfFailOrPermerror(t *testing.T) {
	cells := []struct {
		mode        generated.PolicyResultMode
		verdict     generated.PolicyResultVerdict
		disposition generated.Disposition
		want        adapter.Disposition
		report      bool
	}{
		{generated.Strict, generated.PolicyResultVerdictReject, generated.DispositionReject, adapter.DispositionReject, false},
		{generated.Permissive, generated.PolicyResultVerdictAccept, generated.DispositionAccept, adapter.DispositionAccept, true},
		{generated.Testing, generated.PolicyResultVerdictContinue, generated.DispositionContinue, adapter.DispositionContinue, false},
	}
	for _, reason := range nonPassVerificationReasons {
		for _, cell := range cells {
			replies := make(map[generated.VerificationState]string, 2)
			for _, state := range []generated.VerificationState{generated.FAIL, generated.PERMERROR} {
				body := nonPassProcessBody(t, state, reason, cell.mode, cell.verdict, cell.disposition, cell.report)
				plan, err := AdmitProcessJSON(body, "mx.example.test")
				if err != nil || plan.Disposition() != cell.want || plan.TemporaryKey() {
					t.Fatalf("%s %s %s admitted as %#v/%v", reason, state, cell.mode, plan, err)
				}
				response, err := responseFromPlan(plan, nil, 1, nil)
				if err != nil {
					t.Fatalf("%s %s %s response error = %v", reason, state, cell.mode, err)
				}
				replies[state] = string(response.Reason())
			}
			if replies[generated.FAIL] != replies[generated.PERMERROR] {
				t.Fatalf("%s %s replies differ: %v", reason, cell.mode, replies)
			}
		}
	}
}

// nonPassProcessBody encodes one complete current-scope non-PASS process
// response with the daemon-owned report for accepting dispositions.
func nonPassProcessBody(t *testing.T, state generated.VerificationState, reason generated.VerificationReason, mode generated.PolicyResultMode, verdict generated.PolicyResultVerdict, disposition generated.Disposition, report bool) []byte {
	t.Helper()
	value := validProcessFixture()
	value.Actions = generated.ActionPlan{}
	if report {
		header, ok := authresults.New("mx.example.test", strings.ToLower(string(state)), string(reason))
		if !ok {
			t.Fatalf("authresults.New(%s, %s) rejected the reason", state, reason)
		}
		value.Actions = generated.ActionPlan{{Type: generated.AddHeader, Name: generated.AuthenticationResults, Value: header.Value()}}
	}
	value.Disposition = disposition
	value.Verification.State = state
	value.Verification.PrimaryReason = reason
	value.Verification.SignatureSets = []generated.SignatureSetResult{}
	value.Authentication.State = state
	value.Authentication.PrimaryReason = generated.AuthenticationResultPrimaryReason(reason)
	value.Verification.Scope = generated.Current
	value.Verification.HistoricalContent = generated.VerificationResultHistoricalContentNotEvaluated
	value.Verification.HistoricalSignatures = generated.VerificationResultHistoricalSignaturesNotEvaluated
	value.Verification.Checks[0].Reason = reason
	protocolReason := generated.ProtocolPermerror
	if state == generated.FAIL {
		protocolReason = generated.ProtocolFail
	}
	value.Policy.Mode = mode
	value.Policy.Verdict = verdict
	value.Policy.Findings = []generated.PolicyFinding{{Reason: protocolReason, Severity: generated.Permanent}}
	value.Policy.PrimaryReason = protocolReason
	switch mode {
	case generated.Permissive:
		value.Policy.PrimaryReason = generated.PermissiveOverride
		value.Policy.Findings = append(value.Policy.Findings, generated.PolicyFinding{Reason: generated.PermissiveOverride, Severity: generated.Warning})
	case generated.Testing:
		value.Policy.PrimaryReason = generated.TestingModeObserve
		value.Policy.Findings = append(value.Policy.Findings, generated.PolicyFinding{Reason: generated.TestingModeObserve, Severity: generated.Warning})
	}
	value.Replay.Class = generated.NotChecked
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("process response encoding failed")
	}
	return body
}
