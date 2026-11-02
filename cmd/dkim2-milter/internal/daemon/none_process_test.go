package daemon

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/daemon/generated"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/milter"
)

// Response header names used by the retired process 204 fixture.
const (
	testHeaderCacheControl = "Cache-Control"
	testHeaderConnection   = "Connection"
)

// noneProcessResponse builds the exact Draft-09 NONE process response the
// daemon returns for a message without any DKIM2 field.
func noneProcessResponse(authority string) generated.ProcessResponse {
	actions := generated.ActionPlan{}
	if authority != "" {
		actions = generated.ActionPlan{{
			Type: generated.AddHeader, Name: generated.AuthenticationResults, Value: authority + "; dkim2=none",
		}}
	}
	return generated.ProcessResponse{
		ApiVersion: generated.V1, Draft: generated.DraftIetfDkimDkim2Spec09,
		Verification: generated.VerificationResult{
			State: generated.NONE, PrimaryReason: generated.VerificationReasonNone, Scope: generated.Current,
			HistoricalContent:    generated.VerificationResultHistoricalContentNotEvaluated,
			HistoricalSignatures: generated.VerificationResultHistoricalSignaturesNotEvaluated,
			CustodyStructure:     generated.VerificationResultCustodyStructureNotEvaluated,
			Checks: []generated.VerificationCheck{{
				Class: generated.VerificationCheckClassProtocol, Reason: generated.VerificationReasonNone,
			}},
			SignatureSets: []generated.SignatureSetResult{},
		},
		Authentication: generated.AuthenticationResult{
			State: generated.NONE, PrimaryReason: generated.AuthenticationResultPrimaryReasonNone,
		},
		Policy: generated.PolicyResult{
			Mode: generated.Strict, Verdict: generated.PolicyResultVerdictContinue, PrimaryReason: generated.PolicyReasonNone,
			Feedback: generated.PolicyFeedback{HistoryCoverage: generated.PolicyFeedbackHistoryCoverageNotEvaluated},
			Findings: []generated.PolicyFinding{{Reason: generated.PolicyReasonNone, Severity: generated.Info}},
		},
		Replay:      generated.ReplayResult{Class: generated.NotChecked},
		Disposition: generated.DispositionContinue,
		Actions:     actions,
	}
}

// TestMapProcessAdmitsExactNone proves the Milter adapter maps the Draft-09
// NONE response to a non-terminal continue that carries only the bound
// dkim2=none report when local reporting is configured.
func TestMapProcessAdmitsExactNone(t *testing.T) {
	result, err := (&handlerGuard{authservID: testAuthservID}).mapProcess(processHTTPResponse(t, noneProcessResponse(testAuthservID)))
	if err != nil || result.Operation != operationProcess || result.Result != verificationNone ||
		result.Outcome != milter.DispositionContinue || result.TemporaryKey || len(result.Actions) != 1 ||
		result.Actions[0].Kind != milter.ActionAddHeader || result.Actions[0].Name != string(generated.AuthenticationResults) ||
		result.Actions[0].Value != testAuthservID+"; dkim2=none" {
		t.Fatalf("NONE with reporting mapped to %#v/%v", result, err)
	}
	for _, mode := range []generated.PolicyResultMode{generated.Permissive, generated.Testing} {
		value := noneProcessResponse("")
		value.Policy.Mode = mode
		result, err = (&handlerGuard{}).mapProcess(processHTTPResponse(t, value))
		if err != nil || result.Result != verificationNone || result.Outcome != milter.DispositionContinue || len(result.Actions) != 0 {
			t.Fatalf("NONE without reporting in %s mapped to %#v/%v", mode, result, err)
		}
	}
}

// TestMapProcessRejectsIncoherentNone proves every deviation from the closed
// NONE shape fails closed, including a terminal verdict or any non-report action.
func TestMapProcessRejectsIncoherentNone(t *testing.T) {
	for name, mutate := range map[string]func(*generated.ProcessResponse){
		"accept verdict": func(v *generated.ProcessResponse) {
			v.Policy.Verdict, v.Disposition = generated.PolicyResultVerdictAccept, generated.DispositionAccept
		},
		"reject verdict": func(v *generated.ProcessResponse) {
			v.Policy.Verdict, v.Disposition, v.Actions = generated.PolicyResultVerdictReject, generated.DispositionReject, generated.ActionPlan{}
		},
		"tempfail verdict": func(v *generated.ProcessResponse) {
			v.Policy.Verdict, v.Disposition, v.Actions = generated.PolicyResultVerdictTempfail, generated.DispositionTempfail, generated.ActionPlan{}
		},
		"policy reason":    func(v *generated.ProcessResponse) { v.Policy.PrimaryReason = generated.ProtocolPass },
		"finding reason":   func(v *generated.ProcessResponse) { v.Policy.Findings[0].Reason = generated.ProtocolPermerror },
		"finding severity": func(v *generated.ProcessResponse) { v.Policy.Findings[0].Severity = generated.Permanent },
		"feedback":         func(v *generated.ProcessResponse) { v.Policy.Feedback.Requested = true },
		"verification reason": func(v *generated.ProcessResponse) {
			v.Verification.PrimaryReason = generated.VerificationReasonMissingProtocol
		},
		"check reason": func(v *generated.ProcessResponse) {
			v.Verification.Checks[0].Reason = generated.VerificationReasonMissingProtocol
		},
		"authentication state": func(v *generated.ProcessResponse) {
			v.Authentication.State = generated.PERMERROR
		},
		"verification state only": func(v *generated.ProcessResponse) { v.Verification.State = generated.PERMERROR },
		"signature set": func(v *generated.ProcessResponse) {
			v.Verification.SignatureSets = []generated.SignatureSetResult{{
				Algorithm: generated.Unknown, Status: generated.SignatureSetResultStatusPass, Reason: generated.VerificationReasonNone,
			}}
		},
		"target": func(v *generated.ProcessResponse) {
			v.Verification.Target = &generated.VerificationTarget{Sequence: "1", Instance: "1"}
		},
		"replay class":    func(v *generated.ProcessResponse) { v.Replay.Class = generated.Disabled },
		"delivery status": func(v *generated.ProcessResponse) { v.DeliveryStatus = &generated.DeliveryStatusProjection{} },
		"report with reason": func(v *generated.ProcessResponse) {
			v.Actions[0].Value = testAuthservID + "; dkim2=none (reason=missing_protocol)"
		},
		"foreign authority": func(v *generated.ProcessResponse) { v.Actions[0].Value = "attacker.example; dkim2=none" },
		"pass report":       func(v *generated.ProcessResponse) { v.Actions[0].Value = testAuthservID + "; dkim2=pass" },
		"missing report":    func(v *generated.ProcessResponse) { v.Actions = generated.ActionPlan{} },
		"signing action": func(v *generated.ProcessResponse) {
			v.Actions = append(v.Actions, generated.AddHeaderAction{Type: generated.AddHeader, Name: generated.DKIM2Signature, Value: "i=1"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := noneProcessResponse(testAuthservID)
			mutate(&value)
			if result, err := (&handlerGuard{authservID: testAuthservID}).mapProcess(processHTTPResponse(t, value)); err == nil {
				t.Fatalf("incoherent NONE accepted as %#v", result)
			}
		})
	}
}

// TestMapProcessRejectsNoContent proves the retired bodyless process
// variant now fails closed instead of continuing without a report.
func TestMapProcessRejectsNoContent(t *testing.T) {
	response := &generated.ProcessMessageResponse{HTTPResponse: &http.Response{
		StatusCode: http.StatusNoContent,
		Request:    &http.Request{Method: http.MethodPost, URL: &url.URL{Path: routeProcess}},
		Close:      true, ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{
			testHeaderCacheControl: []string{cacheControlNoStore}, testHeaderConnection: []string{connectionClose},
		},
	}}
	if result, err := (&handlerGuard{authservID: testAuthservID}).mapProcess(response); err == nil {
		t.Fatalf("process 204 accepted as %#v", result)
	}
}
