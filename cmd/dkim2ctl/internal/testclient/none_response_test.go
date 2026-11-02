package testclient

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2ctl/internal/testclient/generated"
)

// noneProcessDocument builds the exact Draft-09 NONE process response the
// daemon returns for a message without any DKIM2 field.
func noneProcessDocument() generated.ProcessResponse {
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
		Actions: generated.ActionPlan{{
			Type: generated.AddHeader, Name: generated.AuthenticationResults, Value: "mx.example.test; dkim2=none",
		}},
	}
}

// classifyNoneDocument encodes one process document and classifies it.
func classifyNoneDocument(t *testing.T, value generated.ProcessResponse) (ResponseFact, error) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("NONE document encoding failed")
	}
	return classifyResponse(OperationProcess, buildHostileResponse(http.StatusOK, mediaTypeJSON, string(body)))
}

// TestProcessResponseAdmitsExactNone proves the test client admits the
// Draft-09 NONE response with and without the reasonless dkim2=none report.
func TestProcessResponseAdmitsExactNone(t *testing.T) {
	fact, err := classifyNoneDocument(t, noneProcessDocument())
	if err != nil || fact.Process == nil || fact.Process.Verification.State != generated.NONE ||
		fact.Process.Disposition != generated.DispositionContinue || len(fact.Process.Actions) != 1 {
		t.Fatalf("NONE response rejected: %v", err)
	}
	bare := noneProcessDocument()
	bare.Actions = generated.ActionPlan{}
	if _, err = classifyNoneDocument(t, bare); err != nil {
		t.Fatal("NONE response without report rejected")
	}
}

// TestProcessResponseRejectsIncoherentNone proves every deviation from the
// closed NONE shape is a contract failure.
func TestProcessResponseRejectsIncoherentNone(t *testing.T) {
	for name, mutate := range map[string]func(*generated.ProcessResponse){
		"accept verdict": func(v *generated.ProcessResponse) {
			v.Policy.Verdict, v.Disposition = generated.PolicyResultVerdictAccept, generated.DispositionAccept
		},
		"reject verdict": func(v *generated.ProcessResponse) {
			v.Policy.Verdict, v.Disposition, v.Actions = generated.PolicyResultVerdictReject, generated.DispositionReject, generated.ActionPlan{}
		},
		"policy reason":    func(v *generated.ProcessResponse) { v.Policy.PrimaryReason = generated.ProtocolPass },
		"finding severity": func(v *generated.ProcessResponse) { v.Policy.Findings[0].Severity = generated.Permanent },
		"verification reason": func(v *generated.ProcessResponse) {
			v.Verification.PrimaryReason = generated.VerificationReasonMissingProtocol
		},
		"verification state only": func(v *generated.ProcessResponse) { v.Verification.State = generated.PERMERROR },
		"signature set": func(v *generated.ProcessResponse) {
			v.Verification.SignatureSets = []generated.SignatureSetResult{{
				Algorithm: generated.Ed25519Sha256, Status: generated.SignatureSetResultStatusPass, Reason: generated.VerificationReasonNone,
			}}
		},
		"replay class": func(v *generated.ProcessResponse) { v.Replay.Class = generated.Disabled },
		"report with reason": func(v *generated.ProcessResponse) {
			v.Actions[0].Value = "mx.example.test; dkim2=none (reason=missing_protocol)"
		},
		"pass report": func(v *generated.ProcessResponse) { v.Actions[0].Value = "mx.example.test; dkim2=pass" },
		"signing action": func(v *generated.ProcessResponse) {
			v.Actions = append(v.Actions, generated.AddHeaderAction{Type: generated.AddHeader, Name: generated.DKIM2Signature, Value: "i=1"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := noneProcessDocument()
			mutate(&value)
			if _, err := classifyNoneDocument(t, value); ExitClassOf(err) != ExitContract {
				t.Fatal("incoherent NONE response accepted")
			}
		})
	}
}

// TestProcessResponseRejectsNoContent proves the retired bodyless process
// variant is a contract failure.
func TestProcessResponseRejectsNoContent(t *testing.T) {
	response := &http.Response{
		StatusCode: http.StatusNoContent, Close: true, ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{headerCacheControl: {cacheNoStore}},
		Body:   io.NopCloser(strings.NewReader("")),
	}
	if _, err := classifyResponse(OperationProcess, response); ExitClassOf(err) != ExitContract {
		t.Fatal("process 204 accepted")
	}
}
