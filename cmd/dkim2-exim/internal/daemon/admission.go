// Package daemon owns the generated OpenAPI boundary for the Exim adapter.
package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/daemon/generated"
)

const (
	maxResponseBytes        = 1 << 20
	maxActionValueBytes     = 65_535
	maxActionAggregateBytes = 3 * maxActionValueBytes
	maxResultFacts          = 128
	maxSignatureSets        = 16
	daemonOperationSign     = "sign"
	daemonOperationRevise   = "revise"
	daemonOperationProcess  = "process"
)

// AdmitOperationJSON strictly decodes and validates one sign or revise response.
func AdmitOperationJSON(body []byte, operation string) (adapter.Plan, error) {
	if len(body) == 0 || len(body) > maxResponseBytes ||
		!requiredOperationMembers(body) {
		return adapter.Plan{}, contractError()
	}
	var value generated.OperationResponse
	if !strictDecode(body, &value) {
		return adapter.Plan{}, contractError()
	}
	return admitOperation(value, operation)
}

// AdmitProcessJSON strictly decodes and validates one process response.
func AdmitProcessJSON(body []byte, authservID string) (adapter.Plan, error) {
	if len(body) == 0 || len(body) > maxResponseBytes ||
		authservID != "" && !validAdministrativeDomain(authservID) ||
		!requiredProcessMembers(body) {
		return adapter.Plan{}, contractError()
	}
	var value generated.ProcessResponse
	if !strictDecode(body, &value) || !validProcess(value, authservID) {
		return adapter.Plan{}, contractError()
	}
	result, ok := verificationResult(value.Verification.State)
	if !ok {
		return adapter.Plan{}, contractError()
	}
	actions, ok := admitActions(value.Actions)
	if !ok {
		return adapter.Plan{}, contractError()
	}
	disposition, ok := mapDisposition(value.Disposition)
	if !ok {
		return adapter.Plan{}, contractError()
	}
	plan, err := adapter.NewPlan(result, disposition, actions)
	if err != nil {
		return adapter.Plan{}, contractError()
	}
	return plan, nil
}

// admitOperation proves the exact operation/result/disposition/action matrix.
func admitOperation(value generated.OperationResponse, operation string) (adapter.Plan, error) {
	if value.ApiVersion != generated.V1 ||
		value.Draft != generated.DraftIetfDkimDkim2Spec05 ||
		string(value.Operation) != operation || !value.Operation.Valid() ||
		!value.Result.Valid() || !value.Disposition.Valid() || value.Actions == nil {
		return adapter.Plan{}, contractError()
	}
	disposition, ok := mapDisposition(value.Disposition)
	if !ok || !validResultDisposition(value.Result, value.Disposition) {
		return adapter.Plan{}, contractError()
	}
	actions, ok := admitActions(value.Actions)
	if !ok || !validOperationActions(operation, value.Result, value.Disposition, actions) {
		return adapter.Plan{}, contractError()
	}
	result, ok := mapOperationResult(value.Result)
	if !ok {
		return adapter.Plan{}, contractError()
	}
	planOperation := adapter.FilterSign
	if operation == daemonOperationRevise {
		planOperation = adapter.FilterRevise
	}
	plan, err := adapter.NewFilterPlan(planOperation, result, disposition, actions)
	if err != nil {
		return adapter.Plan{}, contractError()
	}
	return plan, nil
}

// admitActions validates and copies one complete generated action list.
func admitActions(values generated.ActionPlan) ([]adapter.Action, bool) {
	if values == nil || len(values) > 3 {
		return nil, false
	}
	output := make([]adapter.Action, len(values))
	total := 0
	for index, value := range values {
		total += len(value.Value)
		if value.Type != generated.AddHeader || !value.Type.Valid() ||
			!value.Name.Valid() || value.Value == "" ||
			strings.ContainsAny(value.Value, "\r\n\x00") ||
			len(value.Value) > maxActionValueBytes ||
			total > maxActionAggregateBytes {
			return nil, false
		}
		action, err := adapter.NewAction(
			adapter.ActionAddHeader, string(value.Name), value.Value,
		)
		if err != nil {
			return nil, false
		}
		output[index] = action
	}
	return output, true
}

// validOperationActions enforces exact sign and revise append-only plans.
func validOperationActions(
	operation string,
	result generated.OperationResponseResult,
	disposition generated.Disposition,
	actions []adapter.Action,
) bool {
	if disposition != generated.DispositionAccept {
		return len(actions) == 0
	}
	if result != generated.OperationResponseResultPass {
		return false
	}
	for _, action := range actions {
		if len(action.Value()) == 0 ||
			action.Value()[0] != ' ' && action.Value()[0] != '\t' {
			return false
		}
	}
	switch operation {
	case daemonOperationSign:
		return len(actions) == 2 &&
			actions[0].Name() == string(generated.MessageInstance) &&
			actions[1].Name() == string(generated.DKIM2Signature)
	case daemonOperationRevise:
		return (len(actions) == 1 &&
			actions[0].Name() == string(generated.DKIM2Signature)) ||
			len(actions) == 2 &&
				actions[0].Name() == string(generated.MessageInstance) &&
				actions[1].Name() == string(generated.DKIM2Signature)
	default:
		return false
	}
}

// validResultDisposition enforces the authoritative operation result matrix.
func validResultDisposition(
	result generated.OperationResponseResult,
	disposition generated.Disposition,
) bool {
	switch result {
	case generated.OperationResponseResultPass:
		return disposition == generated.DispositionAccept ||
			disposition == generated.DispositionContinue
	case generated.OperationResponseResultFail, generated.OperationResponseResultPermerror:
		return disposition == generated.DispositionReject
	case generated.OperationResponseResultTemperror:
		return disposition == generated.DispositionTempfail
	default:
		return false
	}
}

// validProcess proves the closed nested process projection and report action.
func validProcess(value generated.ProcessResponse, authservID string) bool {
	if value.ApiVersion != generated.V1 ||
		value.Draft != generated.DraftIetfDkimDkim2Spec05 ||
		!value.Disposition.Valid() || value.Actions == nil ||
		!validVerification(value.Verification) || !validPolicy(value.Policy) ||
		!value.Replay.Class.Valid() || !validProcessMatrix(value) {
		return false
	}
	if value.Disposition != generated.DispositionAccept || authservID == "" {
		return len(value.Actions) == 0
	}
	result, ok := verificationResult(value.Verification.State)
	return ok && len(value.Actions) == 1 &&
		value.Actions[0].Type == generated.AddHeader &&
		value.Actions[0].Name == generated.AuthenticationResults &&
		value.Actions[0].Value == authservID+"; dkim2="+resultText(result)
}

// validProcessMatrix preserves replay and policy coordinator semantics.
func validProcessMatrix(value generated.ProcessResponse) bool {
	switch value.Replay.Class {
	case generated.Disabled, generated.FirstSeen:
		return value.Disposition == generated.DispositionAccept &&
			value.Verification.State == generated.PASS &&
			value.Policy.Verdict == generated.PolicyResultVerdictAccept
	case generated.Replayed:
		return value.Disposition == generated.DispositionReject &&
			value.Verification.State == generated.PASS &&
			value.Policy.Verdict == generated.PolicyResultVerdictAccept
	case generated.Indeterminate:
		return value.Disposition == generated.DispositionTempfail &&
			value.Verification.State == generated.PASS &&
			value.Policy.Verdict == generated.PolicyResultVerdictAccept
	case generated.NotChecked:
		return (value.Verification.State != generated.PASS ||
			value.Policy.Verdict != generated.PolicyResultVerdictAccept) &&
			string(value.Disposition) == string(value.Policy.Verdict)
	default:
		return false
	}
}

// validVerification validates every bounded generated verification fact.
func validVerification(value generated.VerificationResult) bool {
	if !value.State.Valid() || !value.PrimaryReason.Valid() || !value.Scope.Valid() ||
		!value.HistoricalContent.Valid() || !value.HistoricalSignatures.Valid() ||
		!value.CustodyStructure.Valid() || len(value.Checks) < 1 ||
		len(value.Checks) > maxResultFacts || value.SignatureSets == nil ||
		len(value.SignatureSets) > maxSignatureSets ||
		value.Target != nil &&
			(!canonicalUint64(value.Target.Instance) || !canonicalUint64(value.Target.Sequence)) {
		return false
	}
	if !verificationCoverageCoherent(value.State, value.Scope, value.HistoricalContent, value.HistoricalSignatures) {
		return false
	}
	for _, check := range value.Checks {
		if !check.Class.Valid() || !check.Reason.Valid() {
			return false
		}
	}
	for _, signature := range value.SignatureSets {
		if !signature.Algorithm.Valid() || !signature.Status.Valid() ||
			!signature.Reason.Valid() || bool(signature.KeyPolicy.StrictIdentityApplicable) {
			return false
		}
	}
	return true
}

func verificationCoverageCoherent(state generated.VerificationState, scope generated.VerificationResultScope, content generated.VerificationResultHistoricalContent, signatures generated.VerificationResultHistoricalSignatures) bool {
	if state == generated.PASS {
		return scope == generated.Chain &&
			(content == generated.VerificationResultHistoricalContentComplete || content == generated.VerificationResultHistoricalContentPartial) &&
			signatures == generated.VerificationResultHistoricalSignaturesComplete
	}
	return scope == generated.Current && content == generated.VerificationResultHistoricalContentNotEvaluated && signatures == generated.VerificationResultHistoricalSignaturesNotEvaluated
}

// validPolicy validates every bounded generated policy fact.
func validPolicy(value generated.PolicyResult) bool {
	if !value.Mode.Valid() || !value.Verdict.Valid() || !value.PrimaryReason.Valid() ||
		!value.DoNotModify.Valid() || !value.DoNotExplode.Valid() ||
		!value.Feedback.HistoryCoverage.Valid() || len(value.Findings) < 1 ||
		len(value.Findings) > maxResultFacts ||
		value.Feedback.RelaySequence != nil && !canonicalUint64(*value.Feedback.RelaySequence) {
		return false
	}
	for _, finding := range value.Findings {
		if !finding.Reason.Valid() || !finding.Severity.Valid() ||
			finding.Sequence != nil && !canonicalUint64(*finding.Sequence) {
			return false
		}
	}
	return true
}

// requiredOperationMembers proves required-member presence before typed decode.
func requiredOperationMembers(body []byte) bool {
	document, ok := requiredObject(
		body, "actions", "api_version", "disposition", "draft", "operation", "result",
	)
	return ok && requiredActionMembers(document["actions"])
}

// requiredProcessMembers proves every required nested process member exists.
func requiredProcessMembers(body []byte) bool {
	document, ok := requiredObject(
		body, "actions", "api_version", "disposition", "draft", "policy", "replay",
		"verification",
	)
	if !ok || !requiredActionMembers(document["actions"]) {
		return false
	}
	verification, ok := requiredObject(
		document["verification"], "checks", "custody_structure", "historical_content",
		"historical_signatures", "primary_reason", "scope", "signature_sets", "state",
	)
	if !ok || !requiredObjectVector(verification["checks"], "class", "reason") ||
		!requiredSignatureSetMembers(verification["signature_sets"]) ||
		!validOptionalJSONMember(verification, "target") {
		return false
	}
	if target, present := verification["target"]; present {
		if _, targetOK := requiredObject(target, "instance", "sequence"); !targetOK {
			return false
		}
	}
	policy, ok := requiredObject(
		document["policy"], "dns_testing_effective", "do_not_explode", "do_not_modify",
		"feedback", "findings", "mode", "primary_reason", "verdict",
	)
	if !ok {
		return false
	}
	feedback, feedbackOK := requiredObject(
		policy["feedback"], "history_coverage", "relay_required", "requested",
	)
	if !feedbackOK || !validOptionalJSONMember(feedback, "relay_sequence") ||
		!requiredPolicyFindingMembers(policy["findings"]) {
		return false
	}
	_, replayOK := requiredObject(document["replay"], "class")
	return replayOK
}

// requiredSignatureSetMembers proves every signature set and key-policy shape.
func requiredSignatureSetMembers(data []byte) bool {
	var signatures []json.RawMessage
	if json.Unmarshal(data, &signatures) != nil || signatures == nil {
		return false
	}
	for _, signature := range signatures {
		fields, ok := requiredObject(
			signature, "algorithm", "key_policy", "reason", "status",
		)
		if !ok {
			return false
		}
		if _, ok = requiredObject(
			fields["key_policy"],
			"strict_identity_applicable", "strict_identity_declared", "testing_declared",
		); !ok {
			return false
		}
	}
	return true
}

// requiredPolicyFindingMembers proves every finding and optional sequence shape.
func requiredPolicyFindingMembers(data []byte) bool {
	var findings []json.RawMessage
	if json.Unmarshal(data, &findings) != nil || findings == nil {
		return false
	}
	for _, finding := range findings {
		fields, ok := requiredObject(finding, "reason", "severity")
		if !ok || !validOptionalJSONMember(fields, "sequence") {
			return false
		}
	}
	return true
}

// validOptionalJSONMember rejects explicit null for a present non-nullable member.
func validOptionalJSONMember(document map[string]json.RawMessage, name string) bool {
	value, present := document[name]
	return !present ||
		len(value) != 0 && !bytes.Equal(bytes.TrimSpace(value), []byte("null"))
}

// requiredActionMembers proves every action discriminator is present.
func requiredActionMembers(data []byte) bool {
	return requiredObjectVector(data, "name", "type", "value")
}

// requiredObjectVector proves required members for every array object.
func requiredObjectVector(data []byte, required ...string) bool {
	var values []json.RawMessage
	if json.Unmarshal(data, &values) != nil || values == nil {
		return false
	}
	for _, value := range values {
		if _, ok := requiredObject(value, required...); !ok {
			return false
		}
	}
	return true
}

// requiredObject rejects absent or null required members.
func requiredObject(data []byte, required ...string) (map[string]json.RawMessage, bool) {
	var document map[string]json.RawMessage
	if len(data) == 0 || json.Unmarshal(data, &document) != nil || document == nil {
		return nil, false
	}
	for _, name := range required {
		value, present := document[name]
		if !present || len(value) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, false
		}
	}
	return document, true
}

// strictDecode rejects duplicate, unknown, trailing and deeply nested JSON.
func strictDecode(body []byte, destination any) bool {
	if destination == nil || !utf8.Valid(body) || !validateJSON(body) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

// validateJSON rejects duplicate members and excessive nesting.
func validateJSON(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if !consumeJSON(decoder, 1) {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

// consumeJSON recursively validates one bounded JSON value.
func consumeJSON(decoder *json.Decoder, depth int) bool {
	if decoder == nil || depth > 32 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		return true
	}
	switch delimiter {
	case '{':
		members := make(map[string]struct{})
		for decoder.More() {
			nameToken, nameErr := decoder.Token()
			name, ok := nameToken.(string)
			if nameErr != nil || !ok {
				return false
			}
			if _, duplicate := members[name]; duplicate {
				return false
			}
			members[name] = struct{}{}
			if !consumeJSON(decoder, depth+1) {
				return false
			}
		}
		end, endErr := decoder.Token()
		return endErr == nil && end == json.Delim('}')
	case '[':
		for decoder.More() {
			if !consumeJSON(decoder, depth+1) {
				return false
			}
		}
		end, endErr := decoder.Token()
		return endErr == nil && end == json.Delim(']')
	default:
		return false
	}
}

// verificationResult maps the daemon's closed uppercase result vocabulary.
func verificationResult(value generated.VerificationState) (adapter.Result, bool) {
	switch value {
	case generated.PASS:
		return adapter.ResultPass, true
	case generated.FAIL:
		return adapter.ResultFail, true
	case generated.PERMERROR:
		return adapter.ResultPermerror, true
	case generated.TEMPERROR:
		return adapter.ResultTemperror, true
	default:
		return 0, false
	}
}

// mapOperationResult maps one generated result to closed adapter state.
func mapOperationResult(value generated.OperationResponseResult) (adapter.Result, bool) {
	switch value {
	case generated.OperationResponseResultPass:
		return adapter.ResultPass, true
	case generated.OperationResponseResultFail:
		return adapter.ResultFail, true
	case generated.OperationResponseResultPermerror:
		return adapter.ResultPermerror, true
	case generated.OperationResponseResultTemperror:
		return adapter.ResultTemperror, true
	default:
		return 0, false
	}
}

// resultText renders one closed result for the exact RFC 8601 action.
func resultText(value adapter.Result) string {
	switch value {
	case adapter.ResultPass:
		return "pass"
	case adapter.ResultFail:
		return "fail"
	case adapter.ResultPermerror:
		return "permerror"
	case adapter.ResultTemperror:
		return "temperror"
	default:
		return ""
	}
}

// mapDisposition maps one generated enum to adapter domain state.
func mapDisposition(value generated.Disposition) (adapter.Disposition, bool) {
	switch value {
	case generated.DispositionAccept:
		return adapter.DispositionAccept, true
	case generated.DispositionContinue:
		return adapter.DispositionContinue, true
	case generated.DispositionReject:
		return adapter.DispositionReject, true
	case generated.DispositionTempfail:
		return adapter.DispositionTempfail, true
	default:
		return 0, false
	}
}

// canonicalUint64 accepts only the OpenAPI canonical unsigned decimal form.
func canonicalUint64(value generated.CanonicalUint64) bool {
	text := value
	if text == "" || len(text) > 20 || len(text) > 1 && text[0] == '0' {
		return false
	}
	_, err := strconv.ParseUint(text, 10, 64)
	return err == nil
}

// contractError returns one content-free adapter failure.
func contractError() error { return adapter.NewError(adapter.FailureContract) }
