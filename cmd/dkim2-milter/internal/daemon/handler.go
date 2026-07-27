package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/daemon/generated"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/daemon/wire"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/milter"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/resource"
)

const (
	fixedUserAgent      = "dkim2-milter/1"
	modeInbound         = "inbound"
	modeOriginator      = "originator"
	modeOrdinaryTransit = "ordinary_transit"
	daemonScheme        = "http"
	routeProcess        = "/v1/process"
	routeSign           = "/v1/sign"
	routeRevise         = "/v1/revise"
	redactedHandler     = "dkim2_milter_daemon_handler{redacted}"
	verificationPass    = "pass"
)

// Handler calls exactly one generated daemon operation for each EOM snapshot.
type Handler struct {
	state *handlerState
}

// handlerState keeps copied holders opaque through one private guard.
type handlerState struct {
	guard *handlerGuard
}

// handlerGuard owns transport and sensitive request identity.
type handlerGuard struct {
	client     *generated.ClientWithResponses
	transport  *http.Transport
	capability *Capability
	mu         *sync.RWMutex
	closed     bool
	mode       string
	tenant     string
	domain     string
	authservID string
}

// NewHandler constructs a generated-client boundary with a confined transport.
func NewHandler(
	endpoint string,
	capability *Capability,
	mode string,
	tenant string,
	domain string,
	authservID string,
) (*Handler, error) {
	if capability == nil ||
		(mode != modeInbound && mode != modeOriginator && mode != modeOrdinaryTransit) ||
		(mode == modeInbound) != (tenant == "" && domain == "") ||
		(mode != modeInbound && authservID != "") {
		return nil, &Error{}
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != daemonScheme || parsed.Host == "" {
		return nil, &Error{}
	}
	route := capabilityRoute(mode)
	if err := capability.bindRequestTarget(endpoint, route); err != nil {
		return nil, &Error{}
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DisableCompression:     true,
		DisableKeepAlives:      false,
		MaxIdleConns:           4,
		MaxIdleConnsPerHost:    4,
		MaxConnsPerHost:        8,
		IdleConnTimeout:        30 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		ResponseHeaderTimeout:  0,
		DialContext:            exactDialer(parsed.Host),
	}
	httpClient := &http.Client{
		Transport: responseLimitTransport{
			next: transport,
			max:  resource.DaemonResponseBytes,
		},
		CheckRedirect: rejectRedirect,
	}
	client, err := generated.NewClientWithResponses(
		endpoint,
		generated.WithHTTPClient(httpClient),
		generated.WithRequestEditorFn(editFixedRequest),
		generated.WithRequestEditorFn(capability.EditRequest),
	)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, &Error{}
	}
	return &Handler{state: &handlerState{guard: &handlerGuard{
		client: client, transport: transport, capability: capability, mode: mode,
		mu: &sync.RWMutex{}, tenant: tenant, domain: domain, authservID: authservID,
	},
	}}, nil
}

// capabilityRoute maps one validated adapter mode to its sole credentialed route.
func capabilityRoute(mode string) string {
	switch mode {
	case modeInbound:
		return routeProcess
	case modeOriginator:
		return routeSign
	case modeOrdinaryTransit:
		return routeRevise
	default:
		return ""
	}
}

// Handle maps immutable Milter input into one generated request and response.
func (h *Handler) Handle(ctx context.Context, message milter.Message) (milter.Result, error) {
	state := h.privateState()
	if state == nil {
		return milter.Result{}, &milter.Error{Class: milter.FailureContract}
	}
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.closed || state.client == nil || state.transport == nil ||
		state.capability == nil || ctx == nil ||
		message.Fidelity() != milter.FidelityReconstructedCRLF {
		return milter.Result{}, &milter.Error{Class: milter.FailureContract}
	}
	request, err := mapMessage(message)
	if err != nil {
		return milter.Result{}, err
	}
	evidence := &operationEvidence{}
	operationContext := httptrace.WithClientTrace(ctx, evidence.trace())
	switch state.mode {
	case modeInbound:
		var reporting *generated.ReportingContext
		if state.authservID != "" {
			reporting = &generated.ReportingContext{AuthservId: state.authservID}
		}
		response, callErr := state.client.ProcessMessageWithResponse(
			operationContext,
			generated.ProcessMessageJSONRequestBody{
				ApiVersion: generated.V1,
				Draft:      generated.DraftIetfDkimDkim2Spec04,
				Message:    request.message,
				Reporting:  reporting,
				Smtp:       request.smtp,
			},
		)
		if callErr != nil {
			return milter.Result{}, classifyCallError(ctx, callErr, evidence)
		}
		return state.mapProcess(response)
	case modeOriginator:
		response, callErr := state.client.SignMessageWithResponse(
			operationContext,
			generated.SignMessageJSONRequestBody{
				ApiVersion: generated.V1,
				Draft:      generated.DraftIetfDkimDkim2Spec04,
				Message:    request.message,
				Smtp:       request.smtp,
				Context: generated.SigningContext{
					Tenant: state.tenant, Domain: state.domain,
				},
			},
		)
		if callErr != nil {
			return milter.Result{}, classifyCallError(ctx, callErr, evidence)
		}
		return mapOperationResponse(response, "sign")
	case modeOrdinaryTransit:
		response, callErr := state.client.ReviseMessageWithResponse(
			operationContext,
			generated.ReviseMessageJSONRequestBody{
				ApiVersion:   generated.V1,
				Draft:        generated.DraftIetfDkimDkim2Spec04,
				Message:      request.message,
				Smtp:         request.smtp,
				IncomingSmtp: request.smtp,
				Context: generated.SigningContext{
					Tenant: state.tenant, Domain: state.domain,
				},
			},
		)
		if callErr != nil {
			return milter.Result{}, classifyCallError(ctx, callErr, evidence)
		}
		return mapRevisionResponse(response, "revise")
	default:
		return milter.Result{}, &milter.Error{Class: milter.FailureContract}
	}
}

// privateState returns the retained state only within the daemon package.
func (h *Handler) privateState() *handlerGuard {
	if h == nil || h.state == nil {
		return nil
	}
	return h.state.guard
}

// Close prevents new operations and releases pooled daemon connections.
func (h *Handler) Close() error {
	state := h.privateState()
	if state == nil {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed {
		return nil
	}
	state.closed = true
	if state.transport != nil {
		state.transport.CloseIdleConnections()
	}
	state.client = nil
	state.transport = nil
	state.capability = nil
	state.mode = ""
	state.tenant = ""
	state.domain = ""
	state.authservID = ""
	return nil
}

// String returns a content-free handler diagnostic.
func (Handler) String() string { return redactedHandler }

// GoString returns a content-free Go representation.
func (h Handler) GoString() string { return h.String() }

// Format prevents formatting from traversing tenant and reporting identity.
func (h Handler) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, h.String())
}

// MarshalJSON rejects handler serialization.
func (Handler) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// MarshalText rejects handler text serialization.
func (Handler) MarshalText() ([]byte, error) { return nil, &Error{} }

// String returns a content-free private handler-state diagnostic.
func (handlerState) String() string { return redactedHandler }

// GoString returns a content-free private handler-state representation.
func (state handlerState) GoString() string { return state.String() }

// Format prevents nested formatting from traversing retained request identity.
func (state handlerState) Format(output fmt.State, _ rune) {
	_, _ = io.WriteString(output, state.String())
}

// MarshalJSON rejects private handler-state serialization.
func (handlerState) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// MarshalText rejects private handler-state text serialization.
func (handlerState) MarshalText() ([]byte, error) { return nil, &Error{} }

// String returns a content-free private handler-guard diagnostic.
func (handlerGuard) String() string { return redactedHandler }

// GoString returns a content-free private handler-guard representation.
func (guard handlerGuard) GoString() string { return guard.String() }

// Format prevents guard dereferencing from traversing retained request identity.
func (guard handlerGuard) Format(output fmt.State, _ rune) {
	_, _ = io.WriteString(output, guard.String())
}

// MarshalJSON rejects private handler-guard serialization.
func (handlerGuard) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// MarshalText rejects private handler-guard text serialization.
func (handlerGuard) MarshalText() ([]byte, error) { return nil, &Error{} }

type mappedRequest struct {
	message generated.MessageInput
	smtp    generated.SMTPInput
}

// mapMessage creates only generated DTOs and preserves admitted bytes.
func mapMessage(message milter.Message) (mappedRequest, error) {
	raw := message.Raw()
	reverse := message.ReversePath()
	recipients := message.Recipients()
	defer clearMessageCopies(raw, reverse, recipients)
	if len(raw) == 0 || !utf8.Valid(reverse) || len(recipients) == 0 {
		return mappedRequest{}, &milter.Error{Class: milter.FailureFidelity}
	}
	rawValue, err := wire.NewProtectedString(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		return mappedRequest{}, &milter.Error{Class: milter.FailureContract}
	}
	reverseValue, err := wire.NewProtectedString(string(reverse))
	if err != nil {
		return mappedRequest{}, &milter.Error{Class: milter.FailureFidelity}
	}
	recipientValues := make([]wire.ProtectedString, len(recipients))
	for index := range recipients {
		if !utf8.Valid(recipients[index]) {
			return mappedRequest{}, &milter.Error{Class: milter.FailureFidelity}
		}
		recipientValues[index], err = wire.NewProtectedString(string(recipients[index]))
		if err != nil {
			return mappedRequest{}, &milter.Error{Class: milter.FailureFidelity}
		}
	}
	fidelity := generated.MilterReconstructedCrlf
	return mappedRequest{
		message: generated.MessageInput{
			Fidelity: &fidelity, RawRfc5322Base64: rawValue,
		},
		smtp: generated.SMTPInput{MailFrom: reverseValue, RcptTo: recipientValues},
	}, nil
}

// clearMessageCopies erases every temporary byte copy created by DTO mapping.
func clearMessageCopies(raw, reverse []byte, recipients [][]byte) {
	clear(raw)
	clear(reverse)
	for index := range recipients {
		clear(recipients[index])
	}
}

// mapProcess validates the complete inbound response and optional reporting.
func (guard *handlerGuard) mapProcess(response *generated.ProcessMessageResponse) (milter.Result, error) {
	if response != nil {
		defer clear(response.Body)
	}
	if response == nil || !validJSONResponseShape(
		response.HTTPResponse,
		response.Body,
		http.StatusOK,
	) {
		return milter.Result{}, &milter.Error{Class: milter.FailureContract}
	}
	var value generated.ProcessResponse
	if !validProcessRequiredMembers(response.Body) ||
		!strictDecodeResponse(response.Body, &value) ||
		!validProcessContract(&value, guard.authservID) ||
		response.JSON200 == nil {
		return milter.Result{}, &milter.Error{Class: milter.FailureContract}
	}
	result, ok := verificationResult(value.Verification.State)
	if !ok {
		return milter.Result{}, &milter.Error{Class: milter.FailureContract}
	}
	actions := make([]milter.Action, len(value.Actions))
	for index := range value.Actions {
		actions[index] = milter.Action{
			Kind:  milter.ActionKind(value.Actions[index].Type),
			Name:  string(value.Actions[index].Name),
			Value: value.Actions[index].Value,
		}
	}
	return milter.Result{
		Operation: "process", Result: result,
		Outcome: milter.Disposition(value.Disposition), Actions: actions,
	}, nil
}

// mapOperationResponse validates one sign response including its raw JSON envelope.
func mapOperationResponse(
	response *generated.SignMessageResponse,
	operation string,
) (milter.Result, error) {
	if response != nil {
		defer clear(response.Body)
	}
	if response == nil || !validJSONResponseShape(
		response.HTTPResponse,
		response.Body,
		http.StatusOK,
	) {
		return milter.Result{}, &milter.Error{Class: milter.FailureContract}
	}
	var value generated.OperationResponse
	if response.JSON200 == nil || !validOperationRequiredMembers(response.Body) ||
		!strictDecodeResponse(response.Body, &value) {
		return milter.Result{}, &milter.Error{Class: milter.FailureContract}
	}
	return mapOperation(&value, operation)
}

// mapOperationResponse validates one revise response including its raw JSON envelope.
func mapRevisionResponse(
	response *generated.ReviseMessageResponse,
	operation string,
) (milter.Result, error) {
	if response != nil {
		defer clear(response.Body)
	}
	if response == nil || !validJSONResponseShape(
		response.HTTPResponse,
		response.Body,
		http.StatusOK,
	) {
		return milter.Result{}, &milter.Error{Class: milter.FailureContract}
	}
	var value generated.OperationResponse
	if response.JSON200 == nil || !validOperationRequiredMembers(response.Body) ||
		!strictDecodeResponse(response.Body, &value) {
		return milter.Result{}, &milter.Error{Class: milter.FailureContract}
	}
	return mapOperation(&value, operation)
}

// validOperationRequiredMembers proves presence of every required response member.
func validOperationRequiredMembers(body []byte) bool {
	document, ok := requiredJSONObject(
		body,
		"actions", "api_version", "disposition", "draft", "operation", "result",
	)
	if !ok {
		return false
	}
	var actions []json.RawMessage
	if err := json.Unmarshal(document["actions"], &actions); err != nil {
		return false
	}
	for _, action := range actions {
		if _, ok := requiredJSONObject(action, "name", "type", "value"); !ok {
			return false
		}
	}
	return true
}

// validProcessRequiredMembers proves every required nested process member exists.
func validProcessRequiredMembers(body []byte) bool {
	document, ok := requiredJSONObject(
		body,
		"actions", "api_version", "disposition", "draft", "policy", "replay",
		"verification",
	)
	if !ok || !validActionMembers(document["actions"]) ||
		!validVerificationMembers(document["verification"]) ||
		!validPolicyMembers(document["policy"]) {
		return false
	}
	_, replayOK := requiredJSONObject(document["replay"], "class")
	return replayOK
}

// validActionMembers proves every present action has its complete discriminator.
func validActionMembers(data []byte) bool {
	var actions []json.RawMessage
	if err := json.Unmarshal(data, &actions); err != nil {
		return false
	}
	for _, action := range actions {
		if _, ok := requiredJSONObject(action, "name", "type", "value"); !ok {
			return false
		}
	}
	return true
}

// validVerificationMembers proves presence through checks, targets, and key policy.
func validVerificationMembers(data []byte) bool {
	document, ok := requiredJSONObject(
		data,
		"checks", "custody_structure", "historical_content",
		"historical_signatures", "primary_reason", "scope", "signature_sets", "state",
	)
	if !ok {
		return false
	}
	var checks []json.RawMessage
	if err := json.Unmarshal(document["checks"], &checks); err != nil {
		return false
	}
	for _, check := range checks {
		if _, valid := requiredJSONObject(check, "class", "reason"); !valid {
			return false
		}
	}
	var signatures []json.RawMessage
	if err := json.Unmarshal(document["signature_sets"], &signatures); err != nil {
		return false
	}
	for _, signature := range signatures {
		fields, valid := requiredJSONObject(
			signature,
			"algorithm", "key_policy", "reason", "status",
		)
		if !valid {
			return false
		}
		if _, valid = requiredJSONObject(
			fields["key_policy"],
			"strict_identity_applicable", "strict_identity_declared", "testing_declared",
		); !valid {
			return false
		}
	}
	if target, present := document["target"]; present {
		if _, valid := requiredJSONObject(target, "instance", "sequence"); !valid {
			return false
		}
	}
	return true
}

// validPolicyMembers proves presence through feedback, findings, and booleans.
func validPolicyMembers(data []byte) bool {
	document, ok := requiredJSONObject(
		data,
		"dns_testing_effective", "do_not_explode", "do_not_modify", "feedback",
		"findings", "mode", "primary_reason", "verdict",
	)
	if !ok {
		return false
	}
	if _, valid := requiredJSONObject(
		document["feedback"],
		"history_coverage", "relay_required", "requested",
	); !valid {
		return false
	}
	var feedback map[string]json.RawMessage
	if err := json.Unmarshal(document["feedback"], &feedback); err != nil ||
		!validOptionalJSONMember(feedback, "relay_sequence") {
		return false
	}
	var findings []json.RawMessage
	if err := json.Unmarshal(document["findings"], &findings); err != nil {
		return false
	}
	for _, finding := range findings {
		fields, valid := requiredJSONObject(finding, "reason", "severity")
		if !valid || !validOptionalJSONMember(fields, "sequence") {
			return false
		}
	}
	return true
}

// validOptionalJSONMember rejects explicit null for a present non-nullable member.
func validOptionalJSONMember(document map[string]json.RawMessage, name string) bool {
	value, present := document[name]
	return !present || len(value) != 0 && !bytes.Equal(bytes.TrimSpace(value), []byte("null"))
}

// requiredJSONObject rejects absent and explicit-null required members.
func requiredJSONObject(
	data []byte,
	required ...string,
) (map[string]json.RawMessage, bool) {
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

// mapOperation validates a generated sign or revise response.
func mapOperation(
	value *generated.OperationResponse,
	operation string,
) (milter.Result, error) {
	if value == nil ||
		value.ApiVersion != generated.V1 ||
		value.Draft != generated.DraftIetfDkimDkim2Spec04 ||
		string(value.Operation) != operation ||
		!value.Operation.Valid() || !value.Result.Valid() ||
		!value.Disposition.Valid() || value.Actions == nil ||
		len(value.Actions) > 3 {
		return milter.Result{}, &milter.Error{Class: milter.FailureContract}
	}
	actions := make([]milter.Action, len(value.Actions))
	aggregate := 0
	for index := range value.Actions {
		current := value.Actions[index]
		frameBytes := len(current.Name) + len(current.Value) + 3
		aggregate += frameBytes
		if !current.Type.Valid() || !current.Name.Valid() ||
			current.Value == "" || strings.ContainsAny(current.Value, "\r\n\x00") ||
			int64(frameBytes) > resource.MilterActionFrameBytes ||
			int64(aggregate) > resource.MilterActionAggregateBytes {
			return milter.Result{}, &milter.Error{Class: milter.FailureContract}
		}
		actions[index] = milter.Action{
			Kind: milter.ActionKind(current.Type),
			Name: string(current.Name), Value: current.Value,
		}
	}
	return milter.Result{
		Operation: operation, Result: string(value.Result),
		Outcome: milter.Disposition(value.Disposition), Actions: actions,
	}, nil
}

// validJSONResponseShape enforces the exact successful generated-client envelope.
func validJSONResponseShape(response *http.Response, body []byte, status int) bool {
	if response == nil || response.StatusCode != status || response.Request == nil ||
		len(body) == 0 || int64(len(body)) > resource.DaemonResponseBytes ||
		response.ContentLength >= 0 && response.ContentLength != int64(len(body)) {
		return false
	}
	contentTypes := response.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(contentTypes[0])
	return err == nil && mediaType == "application/json" && len(parameters) == 0
}

// strictDecodeResponse rejects duplicate, unknown, trailing, or excessively nested JSON.
func strictDecodeResponse(body []byte, destination any) bool {
	if destination == nil || len(body) == 0 || !utf8.Valid(body) ||
		!validateJSONMembers(body) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

// validateJSONMembers rejects duplicate object members and excessive nesting.
func validateJSONMembers(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if !consumeJSONValue(decoder, 1) {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

// consumeJSONValue validates one JSON value recursively within a fixed depth.
func consumeJSONValue(decoder *json.Decoder, depth int) bool {
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
			if !consumeJSONValue(decoder, depth+1) {
				return false
			}
		}
		end, endErr := decoder.Token()
		return endErr == nil && end == json.Delim('}')
	case '[':
		for decoder.More() {
			if !consumeJSONValue(decoder, depth+1) {
				return false
			}
		}
		end, endErr := decoder.Token()
		return endErr == nil && end == json.Delim(']')
	default:
		return false
	}
}

// validProcessContract validates every closed nested response fact and bound.
func validProcessContract(value *generated.ProcessResponse, authservID string) bool {
	if value == nil || value.ApiVersion != generated.V1 ||
		value.Draft != generated.DraftIetfDkimDkim2Spec04 ||
		!value.Disposition.Valid() || value.Actions == nil ||
		!validProcessReportAction(value, authservID) ||
		!validVerificationContract(value.Verification) ||
		!validPolicyContract(value.Policy) || !value.Replay.Class.Valid() ||
		!validProcessOutcomeMatrix(value) {
		return false
	}
	return true
}

// validProcessReportAction proves the daemon owns the exact configured report.
func validProcessReportAction(
	value *generated.ProcessResponse,
	authservID string,
) bool {
	if value == nil || value.Disposition != generated.DispositionAccept ||
		authservID == "" {
		return value != nil && len(value.Actions) == 0
	}
	result, ok := verificationResult(value.Verification.State)
	return ok && len(value.Actions) == 1 &&
		value.Actions[0].Type == generated.AddHeader &&
		value.Actions[0].Name == generated.AuthenticationResults &&
		value.Actions[0].Value == authservID+"; dkim2="+result
}

// validProcessOutcomeMatrix preserves the daemon replay coordinator contract.
func validProcessOutcomeMatrix(value *generated.ProcessResponse) bool {
	if value == nil {
		return false
	}
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

// validVerificationContract validates the complete generated verification projection.
func validVerificationContract(value generated.VerificationResult) bool {
	if !value.State.Valid() || !value.PrimaryReason.Valid() || !value.Scope.Valid() ||
		!value.HistoricalContent.Valid() || !value.HistoricalSignatures.Valid() ||
		!value.CustodyStructure.Valid() || len(value.Checks) < 1 ||
		len(value.Checks) > 128 || value.SignatureSets == nil ||
		len(value.SignatureSets) > 16 ||
		value.Target != nil &&
			(!canonicalUint64(value.Target.Instance) || !canonicalUint64(value.Target.Sequence)) {
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

// validPolicyContract validates the complete generated policy projection.
func validPolicyContract(value generated.PolicyResult) bool {
	if !value.Mode.Valid() || !value.Verdict.Valid() || !value.PrimaryReason.Valid() ||
		!value.DoNotModify.Valid() || !value.DoNotExplode.Valid() ||
		!value.Feedback.HistoryCoverage.Valid() || len(value.Findings) < 1 ||
		len(value.Findings) > 128 ||
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

// canonicalUint64 accepts only the OpenAPI canonical decimal representation.
func canonicalUint64(value generated.CanonicalUint64) bool {
	text := value
	if text == "" || len(text) > 20 || len(text) > 1 && text[0] == '0' {
		return false
	}
	_, err := strconv.ParseUint(text, 10, 64)
	return err == nil
}

// verificationResult maps the daemon's closed uppercase vocabulary.
func verificationResult(value generated.VerificationState) (string, bool) {
	switch value {
	case generated.PASS:
		return verificationPass, true
	case generated.FAIL:
		return "fail", true
	case generated.PERMERROR:
		return "permerror", true
	case generated.TEMPERROR:
		return "temperror", true
	default:
		return "", false
	}
}

// operationEvidence records whether an HTTP operation may have produced effects.
type operationEvidence struct {
	writeStarted    atomic.Bool
	responseStarted atomic.Bool
}

// trace returns bounded callbacks that retain no request or response content.
func (e *operationEvidence) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		WroteHeaders: func() {
			if e != nil {
				e.writeStarted.Store(true)
			}
		},
		WroteRequest: func(httptrace.WroteRequestInfo) {
			if e != nil {
				e.writeStarted.Store(true)
			}
		},
		GotFirstResponseByte: func() {
			if e != nil {
				e.responseStarted.Store(true)
			}
		},
	}
}

// classifyCallError distinguishes safe pre-write failure from indeterminate effects.
func classifyCallError(
	ctx context.Context,
	err error,
	evidence *operationEvidence,
) error {
	var typed *milter.Error
	if errors.As(err, &typed) {
		return &milter.Error{Class: typed.Class}
	}
	var syntaxError *json.SyntaxError
	var typeError *json.UnmarshalTypeError
	if errors.As(err, &syntaxError) || errors.As(err, &typeError) {
		return &milter.Error{Class: milter.FailureContract}
	}
	if evidence != nil && (evidence.writeStarted.Load() || evidence.responseStarted.Load()) {
		return &milter.Error{Class: milter.FailureIndeterminate}
	}
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &milter.Error{Class: milter.FailureTimeout}
	}
	if ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
		return &milter.Error{Class: milter.FailureInternal}
	}
	var transportError *url.Error
	if errors.As(err, &transportError) {
		return &milter.Error{Class: milter.FailureUnavailable}
	}
	return &milter.Error{Class: milter.FailureContract}
}

// exactDialer rejects any generated-client authority drift.
func exactDialer(authority string) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network string, address string) (net.Conn, error) {
		if network != "tcp" || address != authority {
			return nil, &Error{}
		}
		return dialer.DialContext(ctx, network, address)
	}
}

// editFixedRequest installs only constant transport metadata.
func editFixedRequest(_ context.Context, request *http.Request) error {
	if request == nil || request.URL == nil || request.Header == nil ||
		request.URL.Scheme != "http" || request.URL.User != nil {
		return &Error{}
	}
	request.Header.Set("User-Agent", fixedUserAgent)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Close = false
	return nil
}

// rejectRedirect forbids all redirect following.
func rejectRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

type responseLimitTransport struct {
	next http.RoundTripper
	max  int64
}

// RoundTrip caps each response body before generated decoding.
func (t responseLimitTransport) RoundTrip(
	request *http.Request,
) (response *http.Response, resultErr error) {
	defer func() {
		if recover() != nil {
			if response != nil && response.Body != nil {
				_ = response.Body.Close()
			}
			response = nil
			resultErr = &Error{}
		}
	}()
	if t.next == nil || t.max < 1 {
		return nil, &Error{}
	}
	response, err := t.next.RoundTrip(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, err
	}
	if response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, &Error{}
	}
	response.Body = &limitedResponseBody{
		reader: io.LimitReader(response.Body, t.max+1),
		body:   response.Body,
		remain: t.max,
	}
	return response, nil
}

type limitedResponseBody struct {
	reader io.Reader
	body   io.ReadCloser
	remain int64
}

// Read rejects the first byte beyond the operation response cap.
func (b *limitedResponseBody) Read(output []byte) (count int, resultErr error) {
	defer func() {
		if recover() != nil {
			count = 0
			resultErr = &Error{}
		}
	}()
	if b == nil || b.reader == nil || b.remain < 0 {
		return 0, &Error{}
	}
	if b.remain == 0 {
		var probe [1]byte
		count, err := b.reader.Read(probe[:])
		if count != 0 || err == nil {
			return 0, &Error{}
		}
		return 0, err
	}
	if int64(len(output)) > b.remain {
		output = output[:b.remain]
	}
	count, err := b.reader.Read(output)
	b.remain -= int64(count)
	return count, err
}

// Close releases the underlying response stream.
func (b *limitedResponseBody) Close() (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &Error{}
		}
	}()
	if b == nil || b.body == nil {
		return nil
	}
	return b.body.Close()
}

var _ milter.Handler = (*Handler)(nil)
var _ http.RoundTripper = responseLimitTransport{}
