package testclient

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
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
	maxFixtureBytes               = 1024 * 1024
	maxAggregateBytes             = 32 * 1024 * 1024
	maxFixtureDepth               = 16
	maxCasesPerFixture            = 256
	maxCasesPerInvocation         = 4096
	maxCaseIdentifier             = 64
	maxRecipients                 = 2000
	maxEnvelopeText               = 256
	expectedForbiddenCode         = "forbidden"
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
	Negative *negativeInput       `json:"negative,omitempty"`
	Expect   fixtureExpectation   `json:"expect"`
}

// fixtureProcessInput holds generated-request-compatible scalar inputs.
type fixtureProcessInput struct {
	MessageBase64 string   `json:"raw_rfc5322_base64"`
	MailFrom      string   `json:"mail_from"`
	Recipients    []string `json:"rcpt_to"`
}

// negativeInput selects one closed raw-contract mutation.
type negativeInput struct {
	Mutation string `json:"mutation"`
}

// fixtureExpectation contains only allowlisted typed response assertions.
type fixtureExpectation struct {
	HTTPStatus        int     `json:"http_status"`
	HealthStatus      *string `json:"health_status,omitempty"`
	ReadinessStatus   *string `json:"readiness_status,omitempty"`
	ErrorCode         *string `json:"error_code,omitempty"`
	Disposition       *string `json:"disposition,omitempty"`
	VerificationState *string `json:"verification_state,omitempty"`
	PolicyVerdict     *string `json:"policy_verdict,omitempty"`
	ReplayClass       *string `json:"replay_class,omitempty"`
}

// plannedCase binds one validated fixture identity to one case.
type plannedCase struct {
	fixture string
	value   fixtureCase
}

// ExecutionPlan is one immutable deterministic set of validated cases.
type ExecutionPlan struct {
	fixtures           []string
	cases              []plannedCase
	requiresCapability bool
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
			if testCase.Kind == caseProcess || testCase.Kind == caseNegative {
				plan.requiresCapability = true
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
		if testCase.Process != nil || testCase.Negative != nil ||
			testCase.Expect.HTTPStatus != 200 ||
			testCase.Expect.HealthStatus == nil || *testCase.Expect.HealthStatus != "alive" ||
			expectationPointerCount(testCase.Expect) != 1 {
			return 0, NewExitError(ExitFixture)
		}
	case caseReadiness:
		if testCase.Process != nil || testCase.Negative != nil ||
			testCase.Expect.HTTPStatus != 200 ||
			testCase.Expect.ReadinessStatus == nil || *testCase.Expect.ReadinessStatus != "ready" ||
			expectationPointerCount(testCase.Expect) != 1 {
			return 0, NewExitError(ExitFixture)
		}
	case caseProcess:
		if testCase.Process == nil || testCase.Negative != nil {
			return 0, NewExitError(ExitFixture)
		}
		return validateProcessInput(*testCase.Process, testCase.Expect)
	case caseNegative:
		if testCase.Process != nil || testCase.Negative == nil ||
			!validNegativeMutation(testCase.Negative.Mutation) ||
			testCase.Expect.ErrorCode == nil || expectationPointerCount(testCase.Expect) != 1 ||
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

// validNegativeExpectation binds each closed request mutation to the daemon's
// authoritative OpenAPI error projection.
func validNegativeExpectation(mutation string, status int, code string) bool {
	switch mutation {
	case mutationMissingCapability, mutationDuplicateCapability,
		mutationEmptyCapability, mutationMismatchingCapability:
		return status == 403 && code == expectedForbiddenCode
	case mutationUnsupportedMedia:
		return status == 415 && code == "unsupported_media_type"
	case mutationMalformedJSON, mutationTruncatedBody:
		return status == 400 && code == "invalid_json"
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

// expectationPointerCount counts explicitly selected allowlisted assertions.
func expectationPointerCount(expectation fixtureExpectation) int {
	count := 0
	for _, value := range []*string{
		expectation.HealthStatus, expectation.ReadinessStatus, expectation.ErrorCode,
		expectation.Disposition, expectation.VerificationState,
		expectation.PolicyVerdict, expectation.ReplayClass,
	} {
		if value != nil {
			count++
		}
	}
	return count
}

// validateProcessInput bounds protected request values and expected projections.
func validateProcessInput(input fixtureProcessInput, expectation fixtureExpectation) (int, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(input.MessageBase64)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != input.MessageBase64 ||
		len(input.MailFrom) > maxEnvelopeText ||
		len(input.Recipients) == 0 || len(input.Recipients) > maxRecipients {
		return 0, NewExitError(ExitFixture)
	}
	for _, recipient := range input.Recipients {
		if len(recipient) > maxEnvelopeText || !utf8.ValidString(recipient) {
			return 0, NewExitError(ExitFixture)
		}
	}
	if !utf8.ValidString(input.MailFrom) ||
		expectation.Disposition == nil || expectation.VerificationState == nil ||
		expectation.PolicyVerdict == nil || expectation.ReplayClass == nil ||
		expectationPointerCount(expectation) != 4 ||
		!validOptionalEnum(expectation.Disposition, "accept", "reject", "tempfail", "continue") ||
		!validOptionalEnum(expectation.VerificationState, "PASS", "FAIL", "PERMERROR", "TEMPERROR") ||
		!validOptionalEnum(expectation.PolicyVerdict, "accept", "reject", "tempfail", "continue") ||
		!validOptionalEnum(expectation.ReplayClass,
			"not_checked", "disabled", "first_seen", "replayed", "indeterminate") {
		return 0, NewExitError(ExitFixture)
	}
	return len(decoded), nil
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
		mutationUnsupportedMethod, mutationContaminatedTarget:
		return true
	default:
		return false
	}
}

// generatedProcessRequest maps protected fixture input only at the client boundary.
func generatedProcessRequest(input fixtureProcessInput) (generated.ProcessRequest, error) {
	message, err := wire.NewProtectedString(input.MessageBase64)
	if err != nil {
		return generated.ProcessRequest{}, NewExitError(ExitFixture)
	}
	mailFrom, err := wire.NewProtectedString(input.MailFrom)
	if err != nil {
		return generated.ProcessRequest{}, NewExitError(ExitFixture)
	}
	recipients := make([]wire.ProtectedString, len(input.Recipients))
	for index, recipient := range input.Recipients {
		recipients[index], err = wire.NewProtectedString(recipient)
		if err != nil {
			return generated.ProcessRequest{}, NewExitError(ExitFixture)
		}
	}
	return generated.ProcessRequest{
		ApiVersion: generated.V1,
		Draft:      generated.DraftIetfDkimDkim2Spec04,
		Message:    generated.MessageInput{RawRfc5322Base64: message},
		Smtp:       generated.SMTPInput{MailFrom: mailFrom, RcptTo: recipients},
	}, nil
}
