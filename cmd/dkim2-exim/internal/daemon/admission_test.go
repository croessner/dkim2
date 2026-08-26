package daemon

import (
	"encoding/json"
	"maps"
	"strings"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/daemon/generated"
)

// validOperationFixture returns one complete generated signing response.
func validOperationFixture() generated.OperationResponse {
	return generated.OperationResponse{
		ApiVersion:  generated.V1,
		Draft:       generated.DraftIetfDkimDkim2Spec05,
		Operation:   generated.Sign,
		Result:      generated.OperationResponseResultPass,
		Disposition: generated.DispositionAccept,
		Actions: generated.ActionPlan{
			{Type: generated.AddHeader, Name: generated.MessageInstance, Value: " m=1; h=x"},
			{Type: generated.AddHeader, Name: generated.DKIM2Signature, Value: " i=1; m=1"},
		},
	}
}

// TestGeneratedFidelityEnumIncludesOnlyApprovedEximValues proves contract generation.
func TestGeneratedFidelityEnumIncludesOnlyApprovedEximValues(t *testing.T) {
	if !generated.EximLocalScanObservedCrlf.Valid() ||
		!generated.EximTransportFilterCrlf.Valid() ||
		generated.MessageInputFidelity("exim_unknown").Valid() {
		t.Fatal("generated Exim fidelity enum drift")
	}
}

// TestOperationAdmissionRejectsAbsentAndZeroValueMembers proves JSON presence.
func TestOperationAdmissionRejectsAbsentAndZeroValueMembers(t *testing.T) {
	value := validOperationFixture()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("fixture encoding failed")
	}
	plan, err := AdmitOperationJSON(body, "sign")
	if err != nil || plan.Disposition() != adapter.DispositionAccept ||
		len(plan.Actions()) != 2 {
		t.Fatal("valid generated operation response failed")
	}
	var document map[string]any
	if json.Unmarshal(body, &document) != nil {
		t.Fatal("fixture decoding failed")
	}
	for _, member := range []string{
		"actions", "api_version", "disposition", "draft", "operation", "result",
	} {
		copyDocument := make(map[string]any, len(document))
		maps.Copy(copyDocument, document)
		delete(copyDocument, member)
		mutated, marshalErr := json.Marshal(copyDocument)
		if marshalErr != nil {
			t.Fatal("mutation encoding failed")
		}
		if _, admitErr := AdmitOperationJSON(mutated, "sign"); admitErr == nil {
			t.Fatalf("missing required member class %s accepted", member)
		}
	}
}

// TestOperationAdmissionRejectsMatrixAndActionDrift proves closed hook policy.
func TestOperationAdmissionRejectsMatrixAndActionDrift(t *testing.T) {
	cases := []generated.OperationResponse{
		func() generated.OperationResponse {
			value := validOperationFixture()
			value.Operation = generated.Revise
			return value
		}(),
		func() generated.OperationResponse {
			value := validOperationFixture()
			value.Disposition = generated.DispositionReject
			return value
		}(),
		func() generated.OperationResponse {
			value := validOperationFixture()
			value.Actions[0].Value = "m=1"
			return value
		}(),
		func() generated.OperationResponse {
			value := validOperationFixture()
			value.Actions[0].Name = generated.AuthenticationResults
			return value
		}(),
	}
	for index, value := range cases {
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal("mutation encoding failed")
		}
		if _, err = AdmitOperationJSON(body, "sign"); err == nil {
			t.Fatalf("invalid operation class %d accepted", index)
		}
	}
}

// TestActionAdmissionAcceptsTheExactOpenAPIMaximum proves the generated
// 65,535-byte value limit is not narrowed by adapter framing overhead.
func TestActionAdmissionAcceptsTheExactOpenAPIMaximum(t *testing.T) {
	exact := strings.Repeat("x", maxActionValueBytes)
	values := generated.ActionPlan{
		{Type: generated.AddHeader, Name: generated.AuthenticationResults, Value: exact},
		{Type: generated.AddHeader, Name: generated.MessageInstance, Value: exact},
		{Type: generated.AddHeader, Name: generated.DKIM2Signature, Value: exact},
	}
	if actions, ok := admitActions(values); !ok || len(actions) != len(values) {
		t.Fatal("exact OpenAPI action-value aggregate was rejected")
	}
	values[0].Value += "x"
	if _, ok := admitActions(values); ok {
		t.Fatal("one-over OpenAPI action value was accepted")
	}

	operation := validOperationFixture()
	operation.Actions[0].Value = " " + strings.Repeat("x", maxActionValueBytes-1)
	operation.Actions[1].Value = " " + strings.Repeat("y", maxActionValueBytes-1)
	body, err := json.Marshal(operation)
	if err != nil {
		t.Fatal("exact-limit operation encoding failed")
	}
	if _, err = AdmitOperationJSON(body, "sign"); err != nil {
		t.Fatal("exact-limit operation response was rejected")
	}
}

// TestRequiredProcessMembersRejectNestedAmbiguity proves absent and explicit
// null non-nullable facts cannot decode into indistinguishable zero values.
func TestRequiredProcessMembersRejectNestedAmbiguity(t *testing.T) {
	body, err := json.Marshal(validProcessFixture())
	if err != nil || !requiredProcessMembers(body) {
		t.Fatal("complete process response was rejected")
	}
	if _, admitErr := AdmitProcessJSON(body, "Invalid.example"); admitErr == nil {
		t.Fatal("invalid Authentication-Results authority was accepted")
	}
	for _, testCase := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "target null", mutate: func(document map[string]any) {
			document["verification"].(map[string]any)["target"] = nil
		}},
		{name: "relay sequence null", mutate: func(document map[string]any) {
			document["policy"].(map[string]any)["feedback"].(map[string]any)["relay_sequence"] = nil
		}},
		{name: "finding sequence null", mutate: func(document map[string]any) {
			document["policy"].(map[string]any)["findings"].([]any)[0].(map[string]any)["sequence"] = nil
		}},
		{name: "key policy member absent", mutate: func(document map[string]any) {
			signature := document["verification"].(map[string]any)["signature_sets"].([]any)[0].(map[string]any)
			delete(signature["key_policy"].(map[string]any), "testing_declared")
		}},
		{name: "key policy null", mutate: func(document map[string]any) {
			document["verification"].(map[string]any)["signature_sets"].([]any)[0].(map[string]any)["key_policy"] = nil
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var document map[string]any
			if decodeErr := json.Unmarshal(body, &document); decodeErr != nil {
				t.Fatal("process fixture decoding failed")
			}
			testCase.mutate(document)
			mutated, marshalErr := json.Marshal(document)
			if marshalErr != nil {
				t.Fatal("process mutation encoding failed")
			}
			if requiredProcessMembers(mutated) {
				t.Fatal("ambiguous nested process response was accepted")
			}
		})
	}
}

// TestProcessAdmissionAdmitsPermerrorPolicyAcceptance proves parity with the Milter inbound boundary.
func TestProcessAdmissionAdmitsPermerrorPolicyAcceptance(t *testing.T) {
	value := validProcessFixture()
	value.Actions[0].Value = "mx.example.test; dkim2=permerror"
	value.Replay.Class = generated.NotChecked
	value.Verification.State = generated.PERMERROR
	value.Verification.PrimaryReason = generated.VerificationReasonMalformedProtocol
	value.Verification.Checks[0].Reason = generated.VerificationReasonMalformedProtocol
	value.Verification.Scope = generated.Current
	value.Verification.HistoricalContent = generated.VerificationResultHistoricalContentNotEvaluated
	value.Verification.HistoricalSignatures = generated.VerificationResultHistoricalSignaturesNotEvaluated
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("permissive process response encoding failed")
	}
	plan, err := AdmitProcessJSON(body, "mx.example.test")
	if err != nil || plan.Result() != adapter.ResultPermerror ||
		plan.Disposition() != adapter.DispositionAccept || len(plan.Actions()) != 1 ||
		plan.Actions()[0].Name() != "Authentication-Results" ||
		plan.Actions()[0].Value() != "mx.example.test; dkim2=permerror" {
		t.Fatal("permissive process response was not admitted exactly")
	}
}

// TestProcessAdmissionAdmitsMultiInstanceTestingContinue proves the shared wire
// expansion does not narrow Exim's unchanged-delivery outcome.
func TestProcessAdmissionAdmitsMultiInstanceTestingContinue(t *testing.T) {
	value := validProcessFixture()
	value.Actions = generated.ActionPlan{}
	value.Disposition = generated.DispositionContinue
	value.Policy.DoNotExplode = generated.PolicyResultDoNotExplodeNotRequested
	value.Policy.DoNotModify = generated.PolicyResultDoNotModifyIndeterminate
	value.Policy.Feedback.HistoryCoverage = generated.PolicyFeedbackHistoryCoverageComplete
	value.Policy.Mode = generated.Testing
	value.Policy.PrimaryReason = generated.TestingModeObserve
	value.Policy.Verdict = generated.PolicyResultVerdictContinue
	sequence := generated.CanonicalUint64("2")
	value.Policy.Findings = []generated.PolicyFinding{
		{Reason: generated.DonotmodifyIndeterminate, Sequence: &sequence, Severity: generated.Warning},
		{Reason: generated.TestingModeObserve, Severity: generated.Warning},
	}
	value.Replay.Class = generated.NotChecked
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("multi-instance process response encoding failed")
	}
	plan, err := AdmitProcessJSON(body, "mx.example.test")
	if err != nil || plan.Result() != adapter.ResultPass ||
		plan.Disposition() != adapter.DispositionContinue || len(plan.Actions()) != 0 {
		t.Fatal("multi-instance testing continue response was not admitted exactly")
	}
}

// TestOperationAdmissionRejectsDuplicateAndToxicJSON proves strict redaction.
func TestOperationAdmissionRejectsDuplicateAndToxicJSON(t *testing.T) {
	body := []byte(`{"actions":[],"actions":[]}`)
	if _, err := AdmitOperationJSON(body, "sign"); err == nil {
		t.Fatal("duplicate JSON member accepted")
	}
	marker := "toxic-mail-marker"
	_, err := AdmitOperationJSON([]byte(marker), "sign")
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Fatal("rejected response escaped diagnostics")
	}
}

// validProcessFixture returns one complete nested process response.
func validProcessFixture() generated.ProcessResponse {
	return generated.ProcessResponse{
		Actions: generated.ActionPlan{{
			Type: generated.AddHeader, Name: generated.AuthenticationResults,
			Value: "mx.example.test; dkim2=pass",
		}},
		ApiVersion: generated.V1, Disposition: generated.DispositionAccept,
		Draft: generated.DraftIetfDkimDkim2Spec05,
		Verification: generated.VerificationResult{
			Checks: []generated.VerificationCheck{{
				Class:  generated.VerificationCheckClassProtocol,
				Reason: generated.VerificationReasonNone,
			}},
			CustodyStructure:     generated.VerificationResultCustodyStructureNotPresent,
			HistoricalContent:    generated.VerificationResultHistoricalContentComplete,
			HistoricalSignatures: generated.VerificationResultHistoricalSignaturesComplete,
			PrimaryReason:        generated.VerificationReasonNone,
			Scope:                generated.Chain,
			SignatureSets: []generated.SignatureSetResult{{
				Algorithm: generated.Ed25519Sha256,
				KeyPolicy: generated.KeyPolicyResult{
					StrictIdentityApplicable: false,
					StrictIdentityDeclared:   false,
					TestingDeclared:          false,
				},
				Reason: generated.VerificationReasonNone,
				Status: generated.SignatureSetResultStatusPass,
			}},
			State: generated.PASS,
		},
		Policy: generated.PolicyResult{
			DoNotExplode: generated.PolicyResultDoNotExplodeNotEvaluated,
			DoNotModify:  generated.PolicyResultDoNotModifyNotEvaluated,
			Feedback: generated.PolicyFeedback{
				HistoryCoverage: generated.PolicyFeedbackHistoryCoverageNotEvaluated,
			},
			Findings: []generated.PolicyFinding{{
				Reason: generated.ProtocolPass, Severity: generated.Info,
			}},
			Mode: generated.Strict, PrimaryReason: generated.ProtocolPass,
			Verdict: generated.PolicyResultVerdictAccept,
		},
		Replay: generated.ReplayResult{Class: generated.Disabled},
	}
}

// TestDraft05PermanentReasonsDoNotDefer proves every new protocol infraction
// becomes an admitted permanent rejection rather than an Exim deferral.
func TestDraft05PermanentReasonsDoNotDefer(t *testing.T) {
	for _, reason := range []generated.VerificationReason{
		generated.VerificationReasonDuplicateHashAlgorithm,
		generated.VerificationReasonInvalidRecipeJson,
		generated.VerificationReasonDuplicateSelector,
		generated.VerificationReasonTooManySignatures,
	} {
		value := validProcessFixture()
		value.Actions = generated.ActionPlan{}
		value.Disposition = generated.DispositionReject
		value.Draft = generated.DraftIetfDkimDkim2Spec05
		value.Verification.State = generated.PERMERROR
		value.Verification.PrimaryReason = reason
		value.Verification.Scope = generated.Current
		value.Verification.HistoricalContent = generated.VerificationResultHistoricalContentNotEvaluated
		value.Verification.HistoricalSignatures = generated.VerificationResultHistoricalSignaturesNotEvaluated
		value.Verification.Checks[0].Reason = reason
		value.Policy.Verdict = generated.PolicyResultVerdictReject
		value.Policy.PrimaryReason = generated.ProtocolPermerror
		value.Policy.Findings[0].Reason = generated.ProtocolPermerror
		value.Policy.Findings[0].Severity = generated.Permanent
		value.Replay.Class = generated.NotChecked
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal("permanent response encoding failed")
		}
		plan, err := AdmitProcessJSON(body, "mx.example.test")
		if err != nil || plan.Result() != adapter.ResultPermerror ||
			plan.Disposition() != adapter.DispositionReject {
			t.Fatalf("permanent reason %q admitted as %#v/%v", reason, plan, err)
		}
	}
}

// FuzzOperationAdmission exercises strict generated boundary decoding.
func FuzzOperationAdmission(f *testing.F) {
	seed, err := json.Marshal(validOperationFixture())
	if err != nil {
		f.Fatal("seed encoding failed")
	}
	f.Add(seed, "sign")
	f.Add([]byte(`{}`), "revise")
	f.Fuzz(func(_ *testing.T, body []byte, operation string) {
		if len(body) > maxResponseBytes+1 {
			return
		}
		_, _ = AdmitOperationJSON(body, operation)
	})
}
