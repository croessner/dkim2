package daemon

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/croessner/dkim2/authresults"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/daemon/generated"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/milter"
)

// testHeaderContentType names the response media-type header in fixtures.
const testHeaderContentType = "Content-Type"

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

// TestProcessSMTPOutcomeIsIndependentOfFailOrPermerror proves that the Milter
// SMTP outcome of a non-PASS verification depends only on the daemon policy
// disposition: every reason maps to the same reject, accept, or continue
// outcome whether the daemon reports it as FAIL or PERMERROR, and never as a
// temporary-key tempfail. Moving a reason between FAIL and PERMERROR
// therefore cannot change what the SMTP client sees.
func TestProcessSMTPOutcomeIsIndependentOfFailOrPermerror(t *testing.T) {
	cells := []struct {
		mode        generated.PolicyResultMode
		verdict     generated.PolicyResultVerdict
		disposition generated.Disposition
		want        milter.Disposition
		report      bool
	}{
		{generated.Strict, generated.PolicyResultVerdictReject, generated.DispositionReject, milter.DispositionReject, false},
		{generated.Permissive, generated.PolicyResultVerdictAccept, generated.DispositionAccept, milter.DispositionAccept, true},
		{generated.Testing, generated.PolicyResultVerdictContinue, generated.DispositionContinue, milter.DispositionContinue, true},
	}
	for _, reason := range nonPassVerificationReasons {
		for _, cell := range cells {
			outcomes := make(map[generated.VerificationState]milter.Disposition, 2)
			for _, state := range []generated.VerificationState{generated.FAIL, generated.PERMERROR} {
				value := nonPassProcessResponse(t, state, reason, cell.mode, cell.verdict, cell.disposition, cell.report)
				result, err := (&handlerGuard{authservID: testAuthservID}).mapProcess(processHTTPResponse(t, value))
				if err != nil || result.Result != strings.ToLower(string(state)) || result.TemporaryKey {
					t.Fatalf("%s %s %s mapped to %#v/%v", reason, state, cell.mode, result, err)
				}
				outcomes[state] = result.Outcome
			}
			if outcomes[generated.FAIL] != cell.want || outcomes[generated.PERMERROR] != cell.want {
				t.Fatalf("%s %s outcomes = %v, want %s for both states", reason, cell.mode, outcomes, cell.want)
			}
		}
	}
}

// nonPassProcessResponse builds one complete current-scope non-PASS process
// response with the daemon-owned report for accepting dispositions.
func nonPassProcessResponse(t *testing.T, state generated.VerificationState, reason generated.VerificationReason, mode generated.PolicyResultMode, verdict generated.PolicyResultVerdict, disposition generated.Disposition, report bool) generated.ProcessResponse {
	t.Helper()
	value := validProcessResponse()
	value.Actions = generated.ActionPlan{}
	if report {
		header, ok := authresults.New(testAuthservID, strings.ToLower(string(state)), string(reason))
		if !ok {
			t.Fatalf("authresults.New(%s, %s) rejected the reason", state, reason)
		}
		value.Actions = generated.ActionPlan{{Type: generated.AddHeader, Name: generated.AuthenticationResults, Value: header.Value()}}
	}
	value.Disposition = disposition
	value.Verification.State = state
	value.Verification.PrimaryReason = reason
	value.Authentication.State = state
	value.Authentication.PrimaryReason = generated.AuthenticationResultPrimaryReason(reason)
	value.Verification.Scope = generated.Current
	value.Verification.HistoricalContent = generated.VerificationResultHistoricalContentNotEvaluated
	value.Verification.HistoricalSignatures = generated.VerificationResultHistoricalSignaturesNotEvaluated
	value.Verification.Checks[0].Reason = reason
	protocolReason, severity := generated.ProtocolPermerror, generated.Permanent
	if state == generated.FAIL {
		protocolReason = generated.ProtocolFail
	}
	value.Policy.Mode = mode
	value.Policy.Verdict = verdict
	value.Policy.Findings = []generated.PolicyFinding{{Reason: protocolReason, Severity: severity}}
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
	return value
}

// processHTTPResponse wraps one generated process body in its exact HTTP envelope.
func processHTTPResponse(t *testing.T, value generated.ProcessResponse) *generated.ProcessMessageResponse {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("process response encoding failed")
	}
	return &generated.ProcessMessageResponse{
		Body:    body,
		JSON200: &value,
		HTTPResponse: &http.Response{
			StatusCode:    http.StatusOK,
			ContentLength: int64(len(body)),
			Header:        http.Header{testHeaderContentType: []string{testMediaTypeJSON}},
			Request:       &http.Request{Method: http.MethodPost, URL: &url.URL{Path: routeProcess}},
		},
	}
}
