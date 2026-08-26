package testclient

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/croessner/dkim2/cmd/dkim2ctl/internal/testclient/generated"
	"github.com/croessner/dkim2/cmd/dkim2ctl/internal/testclient/wire"
)

const (
	fixtureSchema                 = "dkim2ctl.fixture.v1"
	caseHealth                    = "health"
	caseReadiness                 = "readiness"
	caseProcess                   = "process"
	caseSign                      = "sign"
	caseRevise                    = "revise"
	caseDSNSign                   = "sign_dsn"
	caseNegative                  = "negative"
	mutationMissingCapability     = "missing_capability"
	mutationDuplicateCapability   = "duplicate_capability"
	mutationEmptyCapability       = "empty_capability"
	mutationMismatchingCapability = "mismatching_capability"
	mutationUnsupportedMedia      = "unsupported_media_type"
	mutationMalformedJSON         = "malformed_json"
	mutationUnknownMember         = "unknown_json_member"
	mutationTruncatedBody         = "truncated_request_body"
	mutationBodyOverLimit         = "body_over_limit"
	mutationUnsupportedMethod     = "unsupported_method"
	mutationContaminatedTarget    = "contaminated_request_target"
	mutationWrongRouteCapability  = "wrong_route_capability"
	maxFixtureBytes               = 1024 * 1024
	maxAggregateBytes             = 32 * 1024 * 1024
	maxFixtureDepth               = 16
	maxCasesPerFixture            = 256
	maxCasesPerInvocation         = 4096
	maxCaseIdentifier             = 64
	maxRecipients                 = 2000
	maxEnvelopeText               = 256
	expectedForbiddenCode         = "forbidden"
	expectedInvalidJSONCode       = "invalid_json"
)

// fixtureDocument is the strict test-harness model, not an HTTP response model.
type fixtureDocument struct {
	Schema  string        `json:"schema"`
	Draft   string        `json:"draft"`
	Fixture string        `json:"fixture"`
	Cases   []fixtureCase `json:"cases"`
}

// fixtureCase owns one closed operation input and allowlisted expectation.
type fixtureCase struct {
	Case     string               `json:"case"`
	Kind     string               `json:"kind"`
	Process  *fixtureProcessInput `json:"process,omitempty"`
	Sign     *fixtureSignInput    `json:"sign,omitempty"`
	Revise   *fixtureReviseInput  `json:"revise,omitempty"`
	DSNSign  *fixtureDSNSignInput `json:"sign_dsn,omitempty"`
	Negative *negativeInput       `json:"negative,omitempty"`
	Expect   fixtureExpectation   `json:"expect"`
}

// fixtureProcessInput holds generated-request-compatible scalar inputs.
type fixtureProcessInput struct {
	MessageBase64 string   `json:"raw_rfc5322_base64"`
	Fidelity      *string  `json:"fidelity,omitempty"`
	MailFrom      string   `json:"mail_from"`
	Recipients    []string `json:"rcpt_to"`
	AuthservID    *string  `json:"authserv_id,omitempty"`
}

// fixtureSignInput holds protected originator inputs before generated mapping.
type fixtureSignInput struct {
	MessageBase64 string   `json:"raw_rfc5322_base64"`
	Fidelity      *string  `json:"fidelity,omitempty"`
	MailFrom      string   `json:"mail_from"`
	Recipients    []string `json:"rcpt_to"`
	Tenant        string   `json:"tenant"`
	Domain        string   `json:"domain"`
}

// fixtureReviseInput holds protected inherited and outgoing revision inputs.
type fixtureReviseInput struct {
	MessageBase64      string   `json:"raw_rfc5322_base64"`
	Fidelity           *string  `json:"fidelity,omitempty"`
	MailFrom           string   `json:"mail_from"`
	Recipients         []string `json:"rcpt_to"`
	IncomingMailFrom   string   `json:"incoming_mail_from"`
	IncomingRecipients []string `json:"incoming_rcpt_to"`
	Tenant             string   `json:"tenant"`
	Domain             string   `json:"domain"`
}

// fixtureDSNSignInput holds delivery-status inputs before generated mapping.
type fixtureDSNSignInput struct {
	OuterMessageBase64 string   `json:"outer_raw_rfc5322_base64"`
	OuterMailFrom      string   `json:"outer_mail_from"`
	OuterRecipients    []string `json:"outer_rcpt_to"`
	Tenant             string   `json:"tenant"`
}

// negativeInput selects one closed raw-contract mutation.
type negativeInput struct {
	Mutation  string  `json:"mutation"`
	Operation *string `json:"operation,omitempty"`
}

// fixtureExpectation contains only allowlisted typed response assertions.
type fixtureExpectation struct {
	HTTPStatus        int                      `json:"http_status"`
	HealthStatus      *string                  `json:"health_status,omitempty"`
	ReadinessStatus   *string                  `json:"readiness_status,omitempty"`
	ErrorCode         *string                  `json:"error_code,omitempty"`
	Disposition       *string                  `json:"disposition,omitempty"`
	VerificationState *string                  `json:"verification_state,omitempty"`
	PolicyVerdict     *string                  `json:"policy_verdict,omitempty"`
	ReplayClass       *string                  `json:"replay_class,omitempty"`
	Operation         *string                  `json:"operation,omitempty"`
	Result            *string                  `json:"result,omitempty"`
	Actions           *[]fixtureExpectedAction `json:"actions,omitempty"`
}

// fixtureExpectedAction freezes one exact ordered generated action.
type fixtureExpectedAction struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// plannedCase binds one validated fixture identity to one case.
type plannedCase struct {
	fixture string
	value   fixtureCase
}

// ExecutionPlan is one immutable deterministic set of validated cases.
type ExecutionPlan struct {
	fixtures                  []string
	cases                     []plannedCase
	requiresCapability        bool
	requiresSignCapability    bool
	requiresReviseCapability  bool
	requiresDSNSignCapability bool
}

// FixtureIdentifiers returns a defensive copy of deterministic fixture IDs.
func (p ExecutionPlan) FixtureIdentifiers() []string {
	return append([]string(nil), p.fixtures...)
}

// LoadExecutionPlan validates every path and document before returning a plan.
func LoadExecutionPlan(paths []string) (ExecutionPlan, error) {
	if len(paths) == 0 || len(paths) > 256 {
		return ExecutionPlan{}, NewExitError(ExitFixture)
	}
	canonical := make([]string, len(paths))
	seenPaths := make(map[string]struct{}, len(paths))
	for index, path := range paths {
		if path == "" || strings.ContainsRune(path, '\x00') {
			return ExecutionPlan{}, NewExitError(ExitFixture)
		}
		canonical[index] = filepath.Clean(path)
		if _, exists := seenPaths[canonical[index]]; exists {
			return ExecutionPlan{}, NewExitError(ExitFixture)
		}
		seenPaths[canonical[index]] = struct{}{}
	}
	sort.Strings(canonical)

	var plan ExecutionPlan
	fixtureIDs := make(map[string]struct{}, len(canonical))
	caseIDs := make(map[string]struct{})
	aggregateBytes := 0
	decodedMessageBytes := 0
	for _, path := range canonical {
		data, err := readFixtureFile(path)
		if err != nil {
			return ExecutionPlan{}, err
		}
		aggregateBytes += len(data)
		if aggregateBytes > maxAggregateBytes {
			return ExecutionPlan{}, NewExitError(ExitFixture)
		}
		document, decodedBytes, err := decodeFixture(data)
		if err != nil {
			return ExecutionPlan{}, err
		}
		decodedMessageBytes += decodedBytes
		if decodedMessageBytes > maxAggregateBytes {
			return ExecutionPlan{}, NewExitError(ExitFixture)
		}
		if _, exists := fixtureIDs[document.Fixture]; exists {
			return ExecutionPlan{}, NewExitError(ExitFixture)
		}
		fixtureIDs[document.Fixture] = struct{}{}
		plan.fixtures = append(plan.fixtures, document.Fixture)
		sort.Slice(document.Cases, func(left, right int) bool {
			return document.Cases[left].Case < document.Cases[right].Case
		})
		for _, testCase := range document.Cases {
			if _, exists := caseIDs[testCase.Case]; exists {
				return ExecutionPlan{}, NewExitError(ExitFixture)
			}
			caseIDs[testCase.Case] = struct{}{}
			if testCase.Kind == caseProcess {
				plan.requiresCapability = true
			}
			if testCase.Kind == caseSign {
				plan.requiresSignCapability = true
			}
			if testCase.Kind == caseRevise {
				plan.requiresReviseCapability = true
			}
			if testCase.Kind == caseDSNSign {
				plan.requiresDSNSignCapability = true
			}
			if testCase.Kind == caseNegative {
				operation := negativeOperation(*testCase.Negative)
				if testCase.Negative.Mutation == mutationWrongRouteCapability ||
					operation == OperationProcess {
					plan.requiresCapability = true
				} else if operation == OperationSign {
					plan.requiresSignCapability = true
				} else if operation == OperationRevise {
					plan.requiresReviseCapability = true
				}
			}
			plan.cases = append(plan.cases, plannedCase{fixture: document.Fixture, value: testCase})
		}
		if len(plan.cases) > maxCasesPerInvocation {
			return ExecutionPlan{}, NewExitError(ExitFixture)
		}
	}
	return plan, nil
}

// readFixtureFile reads one regular non-symlink file through a bounded snapshot.
func readFixtureFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, NewExitError(ExitFixture)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, NewExitError(ExitFixture)
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, NewExitError(ExitFixture)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxFixtureBytes+1))
	if err != nil || len(data) > maxFixtureBytes {
		return nil, NewExitError(ExitFixture)
	}
	return data, nil
}

// decodeFixture performs strict syntax, structure, and semantic validation.
func decodeFixture(data []byte) (fixtureDocument, int, error) {
	if len(data) == 0 || !utf8.Valid(data) || bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		return fixtureDocument{}, 0, NewExitError(ExitFixture)
	}
	if err := validateJSONMembers(data); err != nil {
		return fixtureDocument{}, 0, err
	}
	var document fixtureDocument
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return fixtureDocument{}, 0, NewExitError(ExitFixture)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fixtureDocument{}, 0, NewExitError(ExitFixture)
	}
	return validateFixture(document)
}

// validateJSONMembers rejects duplicates and excessive nesting before typed decode.
func validateJSONMembers(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder, 1); err != nil {
		return NewExitError(ExitFixture)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return NewExitError(ExitFixture)
	}
	return nil
}

// consumeJSONValue recursively validates duplicate members and depth.
func consumeJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxFixtureDepth {
		return NewExitError(ExitFixture)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		return nil
	}
	switch delimiter {
	case '{':
		members := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return NewExitError(ExitFixture)
			}
			if _, duplicate := members[name]; duplicate {
				return NewExitError(ExitFixture)
			}
			members[name] = struct{}{}
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return NewExitError(ExitFixture)
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return NewExitError(ExitFixture)
		}
	default:
		return NewExitError(ExitFixture)
	}
	return nil
}

// validateFixture enforces the complete closed fixture contract.
func validateFixture(document fixtureDocument) (fixtureDocument, int, error) {
	if document.Schema != fixtureSchema || document.Draft != draftVersion ||
		!validIdentifier(document.Fixture) ||
		len(document.Cases) == 0 || len(document.Cases) > maxCasesPerFixture {
		return fixtureDocument{}, 0, NewExitError(ExitFixture)
	}
	seen := make(map[string]struct{}, len(document.Cases))
	decodedBytes := 0
	for _, testCase := range document.Cases {
		if !validIdentifier(testCase.Case) {
			return fixtureDocument{}, 0, NewExitError(ExitFixture)
		}
		if _, duplicate := seen[testCase.Case]; duplicate {
			return fixtureDocument{}, 0, NewExitError(ExitFixture)
		}
		seen[testCase.Case] = struct{}{}
		size, err := validateFixtureCase(testCase)
		if err != nil {
			return fixtureDocument{}, 0, err
		}
		decodedBytes += size
	}
	return document, decodedBytes, nil
}

// validateFixtureCase enforces kind-specific inputs and allowlisted expectations.
func validateFixtureCase(testCase fixtureCase) (int, error) {
	if testCase.Expect.HTTPStatus < 100 || testCase.Expect.HTTPStatus > 599 {
		return 0, NewExitError(ExitFixture)
	}
	switch testCase.Kind {
	case caseHealth:
		if !validStatusFixture(testCase, caseHealth) {
			return 0, NewExitError(ExitFixture)
		}
	case caseReadiness:
		if !validStatusFixture(testCase, caseReadiness) {
			return 0, NewExitError(ExitFixture)
		}
	case caseProcess:
		if testCase.Process == nil || testCase.operationInputCount() != 1 {
			return 0, NewExitError(ExitFixture)
		}
		return validateProcessInput(*testCase.Process, testCase.Expect)
	case caseSign:
		if testCase.Sign == nil || testCase.operationInputCount() != 1 {
			return 0, NewExitError(ExitFixture)
		}
		return validateSignInput(*testCase.Sign, testCase.Expect)
	case caseRevise:
		if testCase.Revise == nil || testCase.operationInputCount() != 1 {
			return 0, NewExitError(ExitFixture)
		}
		return validateReviseInput(*testCase.Revise, testCase.Expect)
	case caseDSNSign:
		if testCase.DSNSign == nil || testCase.operationInputCount() != 1 {
			return 0, NewExitError(ExitFixture)
		}
		return validateDSNSignInput(*testCase.DSNSign, testCase.Expect)
	case caseNegative:
		if testCase.Negative == nil || testCase.operationInputCount() != 1 ||
			!validNegativeMutation(testCase.Negative.Mutation) ||
			!validNegativeOperation(*testCase.Negative) ||
			testCase.Expect.ErrorCode == nil || expectationFieldCount(testCase.Expect) != 1 ||
			!validNegativeExpectation(
				testCase.Negative.Mutation,
				testCase.Expect.HTTPStatus,
				*testCase.Expect.ErrorCode,
			) {
			return 0, NewExitError(ExitFixture)
		}
	default:
		return 0, NewExitError(ExitFixture)
	}
	return 0, nil
}

// validStatusFixture checks one unauthenticated generated status expectation.
func validStatusFixture(testCase fixtureCase, kind string) bool {
	if testCase.operationInputCount() != 0 ||
		testCase.Expect.HTTPStatus != http.StatusOK ||
		expectationFieldCount(testCase.Expect) != 1 {
		return false
	}
	switch kind {
	case caseHealth:
		return testCase.Expect.HealthStatus != nil &&
			*testCase.Expect.HealthStatus == "alive"
	case caseReadiness:
		return testCase.Expect.ReadinessStatus != nil &&
			*testCase.Expect.ReadinessStatus == "ready"
	default:
		return false
	}
}

// operationInputCount returns the number of mutually exclusive case payloads.
func (c fixtureCase) operationInputCount() int {
	count := 0
	for _, present := range []bool{
		c.Process != nil, c.Sign != nil, c.Revise != nil, c.DSNSign != nil, c.Negative != nil,
	} {
		if present {
			count++
		}
	}
	return count
}

// validNegativeExpectation binds each closed request mutation to the daemon's
// authoritative OpenAPI error projection.
func validNegativeExpectation(mutation string, status int, code string) bool {
	switch mutation {
	case mutationMissingCapability, mutationDuplicateCapability,
		mutationEmptyCapability, mutationMismatchingCapability,
		mutationWrongRouteCapability:
		return status == 403 && code == expectedForbiddenCode
	case mutationUnsupportedMedia:
		return status == 415 && code == "unsupported_media_type"
	case mutationMalformedJSON, mutationTruncatedBody:
		return status == 400 && code == expectedInvalidJSONCode
	case mutationUnknownMember, mutationContaminatedTarget:
		return status == 400 && code == "invalid_contract"
	case mutationBodyOverLimit:
		return status == 413 && code == "request_too_large"
	case mutationUnsupportedMethod:
		return status == 405 && code == "method_not_allowed"
	default:
		return false
	}
}

// negativeOperation returns the explicit closed route or the compatible default.
func negativeOperation(input negativeInput) Operation {
	if input.Operation == nil {
		return OperationProcess
	}
	return Operation(*input.Operation)
}

// validNegativeOperation checks route/mutation coherence without protected access.
func validNegativeOperation(input negativeInput) bool {
	operation := negativeOperation(input)
	if operation != OperationProcess && operation != OperationSign &&
		operation != OperationRevise {
		return false
	}
	return input.Mutation != mutationWrongRouteCapability ||
		input.Operation != nil &&
			(operation == OperationSign || operation == OperationRevise)
}

// expectationFieldCount counts explicitly selected allowlisted assertions.
func expectationFieldCount(expectation fixtureExpectation) int {
	count := 0
	for _, value := range []*string{
		expectation.HealthStatus, expectation.ReadinessStatus, expectation.ErrorCode,
		expectation.Disposition, expectation.VerificationState,
		expectation.PolicyVerdict, expectation.ReplayClass,
		expectation.Operation, expectation.Result,
	} {
		if value != nil {
			count++
		}
	}
	if expectation.Actions != nil {
		count++
	}
	return count
}

// validateProcessInput bounds protected request values and expected projections.
func validateProcessInput(input fixtureProcessInput, expectation fixtureExpectation) (int, error) {
	decoded, err := validateMessageAndEnvelope(
		input.MessageBase64, input.Fidelity, input.MailFrom, input.Recipients,
	)
	if err != nil {
		return 0, NewExitError(ExitFixture)
	}
	if input.AuthservID != nil && !validDomain(*input.AuthservID) {
		return 0, NewExitError(ExitFixture)
	}
	if !utf8.ValidString(input.MailFrom) ||
		expectation.Disposition == nil || expectation.VerificationState == nil ||
		expectation.PolicyVerdict == nil || expectation.ReplayClass == nil ||
		expectation.Actions == nil ||
		expectationFieldCount(expectation) != 5 ||
		!validOptionalEnum(expectation.Disposition, "accept", "reject", "tempfail", "continue") ||
		!validOptionalEnum(expectation.VerificationState, "PASS", "FAIL", "PERMERROR", "TEMPERROR") ||
		!validOptionalEnum(expectation.PolicyVerdict, "accept", "reject", "tempfail", "continue") ||
		!validOptionalEnum(expectation.ReplayClass,
			"not_checked", "disabled", "first_seen", "replayed", "indeterminate") ||
		!validExpectedActions(expectation.Actions) {
		return 0, NewExitError(ExitFixture)
	}
	return decoded, nil
}

// validateSignInput checks one originator request and complete response expectation.
func validateSignInput(input fixtureSignInput, expectation fixtureExpectation) (int, error) {
	decoded, err := validateMessageAndEnvelope(
		input.MessageBase64, input.Fidelity, input.MailFrom, input.Recipients,
	)
	if err != nil || input.Fidelity == nil ||
		!validTenant(input.Tenant) || !validDomain(input.Domain) ||
		!validOperationExpectation(caseSign, expectation) {
		return 0, NewExitError(ExitFixture)
	}
	return decoded, nil
}

// validateReviseInput checks inherited/outgoing envelopes and revision expectation.
func validateReviseInput(input fixtureReviseInput, expectation fixtureExpectation) (int, error) {
	decoded, err := validateMessageAndEnvelope(
		input.MessageBase64, input.Fidelity, input.MailFrom, input.Recipients,
	)
	if err != nil {
		return 0, err
	}
	if _, err := validateMessageAndEnvelope(
		input.MessageBase64, input.Fidelity,
		input.IncomingMailFrom, input.IncomingRecipients,
	); err != nil || input.Fidelity == nil ||
		!validTenant(input.Tenant) || !validDomain(input.Domain) ||
		!validOperationExpectation(caseRevise, expectation) {
		return 0, NewExitError(ExitFixture)
	}
	return decoded, nil
}

// validateDSNSignInput checks the exact outer DSN envelope.
func validateDSNSignInput(input fixtureDSNSignInput, expectation fixtureExpectation) (int, error) {
	decoded, err := validateDSNMessageAndEnvelope(
		input.OuterMessageBase64, input.OuterMailFrom, input.OuterRecipients,
	)
	if err != nil || input.OuterMailFrom != "<>" ||
		len(input.OuterRecipients) != 1 ||
		!validTenant(input.Tenant) ||
		!validOperationExpectation(string(OperationDSNSign), expectation) {
		return 0, NewExitError(ExitFixture)
	}
	return decoded, nil
}

// validateDSNMessageAndEnvelope checks canonical Base64 and the Postfix DSN
// outer envelope without accepting a caller-selected representation.
func validateDSNMessageAndEnvelope(
	messageBase64 string,
	mailFrom string,
	recipients []string,
) (int, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(messageBase64)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != messageBase64 ||
		!validSMTPEnvelope(mailFrom, recipients) {
		return 0, NewExitError(ExitFixture)
	}
	return len(decoded), nil
}

// validSMTPEnvelope checks bounded scalar SMTP envelope facts.
func validSMTPEnvelope(mailFrom string, recipients []string) bool {
	if len(mailFrom) > maxEnvelopeText || len(recipients) == 0 ||
		len(recipients) > maxRecipients || !utf8.ValidString(mailFrom) {
		return false
	}
	for _, recipient := range recipients {
		if len(recipient) > maxEnvelopeText || !utf8.ValidString(recipient) {
			return false
		}
	}
	return true
}

// validateMessageAndEnvelope checks canonical Base64, fidelity, and SMTP bounds.
func validateMessageAndEnvelope(
	messageBase64 string,
	fidelity *string,
	mailFrom string,
	recipients []string,
) (int, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(messageBase64)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != messageBase64 ||
		!validSMTPEnvelope(mailFrom, recipients) {
		return 0, NewExitError(ExitFixture)
	}
	if fidelity != nil && !generated.MessageInputFidelity(*fidelity).Valid() {
		return 0, NewExitError(ExitFixture)
	}
	return len(decoded), nil
}

// validOperationExpectation checks exact generated operation result and actions.
func validOperationExpectation(kind string, expectation fixtureExpectation) bool {
	expectedOperation := kind
	if kind == string(OperationDSNSign) {
		expectedOperation = string(generated.DeliveryStatus)
	}
	if expectation.HTTPStatus != http.StatusOK ||
		expectation.Operation == nil || *expectation.Operation != expectedOperation ||
		expectation.Result == nil ||
		expectation.Disposition == nil ||
		expectation.Actions == nil ||
		expectationFieldCount(expectation) != 4 ||
		!validOptionalEnum(expectation.Result, "pass", "fail", "permerror", "temperror") ||
		!validOptionalEnum(expectation.Disposition, "accept", "reject", "tempfail", "continue") ||
		!validExpectedActions(expectation.Actions) {
		return false
	}
	result := generated.OperationResponseResult(*expectation.Result)
	disposition := generated.Disposition(*expectation.Disposition)
	operation := generated.OperationResponseOperation(*expectation.Operation)
	actions := make(generated.ActionPlan, len(*expectation.Actions))
	for index, action := range *expectation.Actions {
		actions[index] = generated.AddHeaderAction{
			Type:  generated.AddHeaderActionType(action.Type),
			Name:  generated.AddHeaderActionName(action.Name),
			Value: action.Value,
		}
	}
	return validOperationOutcome(result, disposition) &&
		validOperationActions(operation, disposition, actions)
}

// validExpectedActions checks bounded exact action fields without interpreting values.
func validExpectedActions(actions *[]fixtureExpectedAction) bool {
	if actions == nil {
		return true
	}
	if len(*actions) > 3 {
		return false
	}
	for _, action := range *actions {
		if action.Type != string(generated.AddHeader) ||
			!generated.AddHeaderActionName(action.Name).Valid() ||
			action.Value == "" || len(action.Value) > 65535 ||
			strings.ContainsAny(action.Value, "\r\n\x00") {
			return false
		}
	}
	return true
}

// validTenant accepts one bounded canonical administrative identifier.
func validTenant(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, current := range []byte(value) {
		if (current < 'a' || current > 'z') && (current < '0' || current > '9') &&
			(index == 0 || current != '.' && current != '_' && current != '-') {
			return false
		}
	}
	return true
}

// validDomain accepts one canonical lower-case ASCII domain.
func validDomain(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) {
		return false
	}
	for label := range strings.SplitSeq(value, ".") {
		if len(label) == 0 || len(label) > 63 ||
			!asciiAlphanumeric(label[0]) ||
			!asciiAlphanumeric(label[len(label)-1]) {
			return false
		}
		for index, current := range []byte(label) {
			if index > 0 && index < len(label)-1 &&
				!asciiAlphanumeric(current) && current != '-' {
				return false
			}
		}
	}
	return true
}

// asciiAlphanumeric reports whether one byte is lower-case DNS alphanumeric.
func asciiAlphanumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

// generatedMessageInput maps one fixture message into the generated DTO.
func generatedMessageInput(messageBase64 string, fidelity *string) (generated.MessageInput, error) {
	message, err := wire.NewProtectedString(messageBase64)
	if err != nil {
		return generated.MessageInput{}, NewExitError(ExitFixture)
	}
	result := generated.MessageInput{RawRfc5322Base64: message}
	if fidelity != nil {
		value := generated.MessageInputFidelity(*fidelity)
		result.Fidelity = &value
	}
	return result, nil
}

// validIdentifier checks one bounded lowercase ASCII fixture or case identifier.
func validIdentifier(value string) bool {
	if len(value) < 1 || len(value) > maxCaseIdentifier {
		return false
	}
	for _, current := range []byte(value) {
		if (current < 'a' || current > 'z') && (current < '0' || current > '9') &&
			current != '.' && current != '_' && current != '-' {
			return false
		}
	}
	return true
}

// validNegativeMutation checks the exact test-only mutation vocabulary.
func validNegativeMutation(value string) bool {
	switch value {
	case mutationMissingCapability, mutationDuplicateCapability, mutationEmptyCapability,
		mutationMismatchingCapability, mutationUnsupportedMedia, mutationMalformedJSON,
		mutationUnknownMember, mutationTruncatedBody, mutationBodyOverLimit,
		mutationUnsupportedMethod, mutationContaminatedTarget,
		mutationWrongRouteCapability:
		return true
	default:
		return false
	}
}

// generatedProcessRequest maps protected fixture input only at the client boundary.
func generatedProcessRequest(input fixtureProcessInput) (generated.ProcessRequest, error) {
	message, err := generatedMessageInput(input.MessageBase64, input.Fidelity)
	if err != nil {
		return generated.ProcessRequest{}, NewExitError(ExitFixture)
	}
	smtp, err := generatedSMTPInput(input.MailFrom, input.Recipients)
	if err != nil {
		return generated.ProcessRequest{}, err
	}
	request := generated.ProcessRequest{
		ApiVersion: generated.V1,
		Draft:      generated.DraftIetfDkimDkim2Spec05,
		Message:    message,
		Smtp:       smtp,
	}
	if input.AuthservID != nil {
		request.Reporting = &generated.ReportingContext{AuthservId: *input.AuthservID}
	}
	return request, nil
}

// generatedSignRequest maps one protected sign fixture at the generated boundary.
func generatedSignRequest(input fixtureSignInput) (generated.SignRequest, error) {
	message, err := generatedMessageInput(input.MessageBase64, input.Fidelity)
	if err != nil {
		return generated.SignRequest{}, err
	}
	smtp, err := generatedSMTPInput(input.MailFrom, input.Recipients)
	if err != nil {
		return generated.SignRequest{}, err
	}
	return generated.SignRequest{
		ApiVersion: generated.V1,
		Draft:      generated.DraftIetfDkimDkim2Spec05,
		Message:    message,
		Smtp:       smtp,
		Context: generated.SigningContext{
			Tenant: input.Tenant,
			Domain: input.Domain,
		},
	}, nil
}

// generatedReviseRequest maps inherited and outgoing facts at one boundary.
func generatedReviseRequest(input fixtureReviseInput) (generated.ReviseRequest, error) {
	message, err := generatedMessageInput(input.MessageBase64, input.Fidelity)
	if err != nil {
		return generated.ReviseRequest{}, err
	}
	smtp, err := generatedSMTPInput(input.MailFrom, input.Recipients)
	if err != nil {
		return generated.ReviseRequest{}, err
	}
	incoming, err := generatedSMTPInput(
		input.IncomingMailFrom, input.IncomingRecipients,
	)
	if err != nil {
		return generated.ReviseRequest{}, err
	}
	return generated.ReviseRequest{
		ApiVersion:   generated.V1,
		Draft:        generated.DraftIetfDkimDkim2Spec05,
		Message:      message,
		Smtp:         smtp,
		IncomingSmtp: incoming,
		Context: generated.SigningContext{
			Tenant: input.Tenant,
			Domain: input.Domain,
		},
	}, nil
}

// generatedDSNSignRequest maps the isolated delivery-status fixture boundary.
func generatedDSNSignRequest(input fixtureDSNSignInput) (generated.DSNSignRequest, error) {
	messageValue, err := wire.NewProtectedString(input.OuterMessageBase64)
	if err != nil {
		return generated.DSNSignRequest{}, err
	}
	message := generated.DSNMessageInput{RawRfc5322Base64: messageValue}
	outer, err := generatedSMTPInput(input.OuterMailFrom, input.OuterRecipients)
	if err != nil {
		return generated.DSNSignRequest{}, err
	}
	return generated.DSNSignRequest{
		ApiVersion: generated.V1,
		Draft:      generated.DraftIetfDkimDkim2Spec05,
		Message:    message,
		OuterSmtp:  outer,
		Context: generated.DeliveryStatusContext{
			Tenant: input.Tenant,
		},
	}, nil
}

// generatedSMTPInput converts one validated envelope without copying DTO types.
func generatedSMTPInput(
	mailFromValue string,
	recipientValues []string,
) (generated.SMTPInput, error) {
	mailFrom, err := wire.NewProtectedString(mailFromValue)
	if err != nil {
		return generated.SMTPInput{}, NewExitError(ExitFixture)
	}
	recipients := make([]wire.ProtectedString, len(recipientValues))
	for index, recipient := range recipientValues {
		recipients[index], err = wire.NewProtectedString(recipient)
		if err != nil {
			return generated.SMTPInput{}, NewExitError(ExitFixture)
		}
	}
	return generated.SMTPInput{MailFrom: mailFrom, RcptTo: recipients}, nil
}
