package daemon

import (
	"encoding/json"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/daemon/generated"
)

// noneProcessFixture builds the exact Draft-09 NONE process response the
// daemon returns for a message without any DKIM2 field.
func noneProcessFixture(authority string) generated.ProcessResponse {
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

// admitNoneFixture encodes one fixture and runs the strict process admission.
func admitNoneFixture(t *testing.T, value generated.ProcessResponse, authservID string) (adapter.Plan, error) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("NONE fixture encoding failed")
	}
	return AdmitProcessJSON(body, authservID)
}

// TestProcessAdmissionAdmitsExactNone proves the Exim adapter admits the
// Draft-09 NONE response as a continue that carries only the bound
// dkim2=none report when local reporting is configured.
func TestProcessAdmissionAdmitsExactNone(t *testing.T) {
	plan, err := admitNoneFixture(t, noneProcessFixture("mx.example.test"), "mx.example.test")
	if err != nil || plan.Result() != adapter.ResultNone || plan.Disposition() != adapter.DispositionContinue ||
		plan.TemporaryKey() || len(plan.Actions()) != 1 ||
		plan.Actions()[0].Name() != "Authentication-Results" ||
		plan.Actions()[0].Value() != "mx.example.test; dkim2=none" {
		t.Fatal("NONE response with reporting was not admitted exactly")
	}
	for _, mode := range []generated.PolicyResultMode{generated.Permissive, generated.Testing} {
		value := noneProcessFixture("")
		value.Policy.Mode = mode
		plan, err = admitNoneFixture(t, value, "")
		if err != nil || plan.Result() != adapter.ResultNone || plan.Disposition() != adapter.DispositionContinue ||
			len(plan.Actions()) != 0 {
			t.Fatalf("NONE response without reporting in %s was not admitted", mode)
		}
	}
}

// TestProcessAdmissionRejectsIncoherentNone proves every deviation from the
// closed NONE shape fails closed, including a terminal verdict or any
// non-report action.
func TestProcessAdmissionRejectsIncoherentNone(t *testing.T) {
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
				Algorithm: generated.Ed25519Sha256, Status: generated.SignatureSetResultStatusPass, Reason: generated.VerificationReasonNone,
			}}
		},
		"target": func(v *generated.ProcessResponse) {
			v.Verification.Target = &generated.VerificationTarget{Sequence: "1", Instance: "1"}
		},
		"replay class":    func(v *generated.ProcessResponse) { v.Replay.Class = generated.Disabled },
		"delivery status": func(v *generated.ProcessResponse) { v.DeliveryStatus = &generated.DeliveryStatusProjection{} },
		"report with reason": func(v *generated.ProcessResponse) {
			v.Actions[0].Value = "mx.example.test; dkim2=none (reason=missing_protocol)"
		},
		"foreign authority": func(v *generated.ProcessResponse) { v.Actions[0].Value = "attacker.example; dkim2=none" },
		"pass report":       func(v *generated.ProcessResponse) { v.Actions[0].Value = "mx.example.test; dkim2=pass" },
		"missing report":    func(v *generated.ProcessResponse) { v.Actions = generated.ActionPlan{} },
		"signing action": func(v *generated.ProcessResponse) {
			v.Actions = append(v.Actions, generated.AddHeaderAction{Type: generated.AddHeader, Name: generated.DKIM2Signature, Value: " i=1"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := noneProcessFixture("mx.example.test")
			mutate(&value)
			if _, err := admitNoneFixture(t, value, "mx.example.test"); err == nil {
				t.Fatal("incoherent NONE response admitted")
			}
		})
	}
	if _, err := admitNoneFixture(t, noneProcessFixture("mx.example.test"), ""); err == nil {
		t.Fatal("NONE report admitted without a configured authority")
	}
}
