package tools_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/dkim2/tools/internal/strictjson"
	"github.com/getkin/kin-openapi/openapi3"
)

const (
	contractDraft            = "draft-ietf-dkim-dkim2-spec-06"
	fixtureSchemaName        = "dkim2.dsn-propagate-fixture.v1"
	fixtureMaxDepth          = 32
	fixtureMaxTokens         = 1 << 16
	fixtureMaxBytes          = 1 << 20
	propagatePath            = "/v1/dsn/propagate"
	propagateCommitPath      = "/v1/dsn/propagate/commit"
	propagateCapabilityName  = "dsnPropagateCapability"
	propagateCapabilityField = "X-DKIM2-DSN-Propagate-Capability"

	// Repeated contract member names and vocabulary values.
	contractAPIVersionMember  = "api_version"
	contractMailFromMember    = "mail_from"
	contractTemperrorValue    = "temperror"
	contractNotEvaluatedValue = "not_evaluated"
	contractDispositionMember = "disposition"
	contractForwardPathMember = "rcpt_to"
	contractDraftMember       = "draft"
	contractOperationMember   = "operation"
	contractResultMember      = "result"
)

// propagationFixtureFile is one reference file of documents checked against the
// authoritative contract under a single expectation.
type propagationFixtureFile struct {
	Schema      string                   `json:"schema"`
	Draft       string                   `json:"draft"`
	Expectation string                   `json:"expectation"`
	Cases       []propagationFixtureCase `json:"cases"`
}

// propagationFixtureCase names the component schema one document is validated
// against and, for a rejected document, why the contract must refuse it.
type propagationFixtureCase struct {
	Case     string          `json:"case"`
	Schema   string          `json:"schema"`
	Document json.RawMessage `json:"document"`
	Violates string          `json:"violates"`
}

// TestPinnedValidatorLoadsContract proves the directly pinned validator accepts
// the authoritative local OpenAPI 3.0.3 document without external references.
func TestPinnedValidatorLoadsContract(t *testing.T) {
	t.Parallel()

	document := loadContract(t)
	if document.OpenAPI != "3.0.3" {
		t.Fatalf("unexpected OpenAPI version %q", document.OpenAPI)
	}
	if err := document.Validate(context.Background()); err != nil {
		t.Fatalf("validate OpenAPI contract: %v", err)
	}
}

// TestOpenAPIContractFreezesSharedOperationShapes proves that the propagation
// contract did not change the shared disposition, operation response, or
// envelope schemas that existing generated clients depend on.
func TestOpenAPIContractFreezesSharedOperationShapes(t *testing.T) {
	t.Parallel()

	document := loadContract(t)
	assertEnum(t, "Disposition", schemaOf(t, document, "Disposition"),
		[]string{"accept", "reject", "tempfail", "continue"})

	operationResponse := schemaOf(t, document, "OperationResponse")
	assertRequired(t, "OperationResponse", operationResponse,
		[]string{
			contractAPIVersionMember, contractDraftMember, contractOperationMember,
			contractResultMember, contractDispositionMember, "actions",
		})
	assertProperties(t, "OperationResponse", operationResponse,
		[]string{
			contractAPIVersionMember, contractDraftMember, contractOperationMember,
			contractResultMember, contractDispositionMember, "actions",
		})
	assertEnum(t, "OperationResponse.operation", propertyOf(t, operationResponse, contractOperationMember),
		[]string{"sign", "revise", "delivery_status"})
	sharedDisposition := operationResponse.Properties[contractDispositionMember].Ref
	if sharedDisposition != "#/components/schemas/Disposition" {
		t.Fatalf("OperationResponse.disposition no longer references the shared disposition: %q",
			sharedDisposition)
	}

	smtpInput := schemaOf(t, document, "SMTPInput")
	assertRequired(t, "SMTPInput", smtpInput, []string{contractMailFromMember, contractForwardPathMember})
	assertProperties(t, "SMTPInput", smtpInput, []string{contractMailFromMember, contractForwardPathMember})
	if maximum := propertyOf(t, smtpInput, contractForwardPathMember).MaxItems; maximum == nil || *maximum != 2000 {
		t.Fatal("the shared envelope forward-path bound changed")
	}
}

// TestOpenAPIContractDeclaresPropagationOperations proves both propagation
// routes exist under their own capability with the exact closed status maps.
func TestOpenAPIContractDeclaresPropagationOperations(t *testing.T) {
	t.Parallel()

	document := loadContract(t)
	scheme := document.Components.SecuritySchemes[propagateCapabilityName]
	if scheme == nil || scheme.Value == nil {
		t.Fatal("the propagation capability scheme is absent")
	}
	if scheme.Value.Type != "apiKey" || scheme.Value.In != "header" ||
		scheme.Value.Name != propagateCapabilityField {
		t.Fatalf("unexpected propagation capability binding %q/%q/%q",
			scheme.Value.Type, scheme.Value.In, scheme.Value.Name)
	}

	for _, expected := range []struct {
		path      string
		operation string
		request   string
		success   string
		responses []string
	}{
		{
			path:      propagatePath,
			operation: "propagateDeliveryStatus",
			request:   "DSNPropagateRequest",
			success:   "DSNPropagateResponse",
			responses: []string{"200", "400", "403", "408", "413", "415", "417", "500", "503"},
		},
		{
			path:      propagateCommitPath,
			operation: "commitDeliveryStatusPropagation",
			request:   "DSNPropagateCommitRequest",
			success:   "DSNPropagateCommitResponse",
			responses: []string{"200", "400", "403", "408", "409", "413", "415", "417", "500", "503"},
		},
	} {
		item := document.Paths.Value(expected.path)
		if item == nil {
			t.Fatalf("missing path %s", expected.path)
		}
		operations := item.Operations()
		if len(operations) != 1 || operations["POST"] == nil {
			t.Fatalf("path %s does not expose exactly one POST operation", expected.path)
		}
		operation := operations["POST"]
		if operation.OperationID != expected.operation {
			t.Fatalf("unexpected operation ID %q for %s", operation.OperationID, expected.path)
		}
		assertOnlyCapability(t, operation)
		assertReferences(t, expected.path+" request", requestSchemaRef(t, operation), expected.request)
		assertReferences(t, expected.path+" success", successSchemaRef(t, operation), expected.success)

		statuses := make([]string, 0, len(operation.Responses.Map()))
		for status := range operation.Responses.Map() {
			statuses = append(statuses, status)
		}
		slices.Sort(statuses)
		if !slices.Equal(statuses, expected.responses) {
			t.Fatalf("unexpected status map for %s: %v", expected.path, statuses)
		}
	}
}

// TestOpenAPIContractClosesPropagationVocabularies proves every propagation and
// received delivery-status vocabulary mirrors the library projection exactly.
func TestOpenAPIContractClosesPropagationVocabularies(t *testing.T) {
	t.Parallel()

	document := loadContract(t)

	disposition := schemaOf(t, document, "PropagationDisposition")
	assertEnum(t, "PropagationDisposition", disposition, []string{"accept", "reject", "discard", "tempfail"})
	for _, rule := range []string{
		"pass permits accept or discard",
		"permerror requires discard",
		"fail requires reject",
		"temperror requires tempfail",
	} {
		if !strings.Contains(strings.Join(strings.Fields(disposition.Description), " "), rule) {
			t.Fatalf("the propagation coherence rule does not state %q", rule)
		}
	}

	projection := schemaOf(t, document, "DeliveryStatusProjection")
	members := []string{"structure", "embedded", "local_hop", "outer_alignment", "recipient_linkage", "propagation"}
	assertRequired(t, "DeliveryStatusProjection", projection, members)
	assertProperties(t, "DeliveryStatusProjection", projection, members)
	for member, values := range map[string][]string{
		"structure":         {"valid", "malformed", "limit_exceeded"},
		"embedded":          {"verified", "verified_headers_only", "unverified", contractTemperrorValue, "absent", contractNotEvaluatedValue},
		"local_hop":         {"local", "not_local", "mismatch", contractTemperrorValue, contractNotEvaluatedValue},
		"outer_alignment":   {"aligned", "misaligned", contractNotEvaluatedValue},
		"recipient_linkage": {"linked", "unlinked", contractNotEvaluatedValue},
		"propagation": {
			"not_applicable", "eligible", "terminal_origin", "not_failure",
			"forbidden_null_previous_sender", "unsupported_chain", "not_reconstructable", contractNotEvaluatedValue,
		},
	} {
		assertEnum(t, "DeliveryStatusProjection."+member, propertyOf(t, projection, member), values)
	}

	response := schemaOf(t, document, "DSNPropagateResponse")
	assertRequired(t, "DSNPropagateResponse", response,
		[]string{
			contractAPIVersionMember, contractDraftMember, contractOperationMember,
			contractResultMember, contractDispositionMember, "replay",
		})
	if slices.Contains(response.Required, "delivery_status") {
		t.Fatal("the propagation response requires a projection that the evaluation may never produce")
	}
	if propertyOf(t, response, "delivery_status") == nil {
		t.Fatal("the propagation response omits the optional projection member")
	}
	assertEnum(t, "DSNPropagateResponse.operation", propertyOf(t, response, contractOperationMember),
		[]string{"delivery_status_propagation"})
	assertEnum(t, "DSNPropagateResponse.result", propertyOf(t, response, contractResultMember),
		[]string{"pass", "fail", "permerror", contractTemperrorValue})
	assertEnum(t, "DSNPropagateResponse.propagation_failure", propertyOf(t, response, "propagation_failure"),
		[]string{"not_reconstructable", "unprovisioned_domain"})

	output := schemaOf(t, document, "PropagationOutput")
	outputMembers := []string{
		"next_hop_recipient", "smtputf8_required", "eight_bit_mime_required",
		"commit_token", "raw_rfc5322_base64",
	}
	assertRequired(t, "PropagationOutput", output, outputMembers)
	assertProperties(t, "PropagationOutput", output, outputMembers)

	envelope := schemaOf(t, document, "PropagationSMTPInput")
	assertRequired(t, "PropagationSMTPInput", envelope,
		[]string{contractMailFromMember, contractForwardPathMember, "smtputf8"})
	forwardPaths := propertyOf(t, envelope, contractForwardPathMember)
	if forwardPaths.MaxItems == nil || *forwardPaths.MaxItems != 1 || forwardPaths.MinItems != 1 {
		t.Fatal("the propagation envelope does not admit exactly one forward path")
	}

	assertEnum(t, "PropagationMessageInput.fidelity",
		propertyOf(t, schemaOf(t, document, "PropagationMessageInput"), "fidelity"),
		[]string{"raw_rfc5322", "lmtp_delivered_crlf"})
	assertEnum(t, "MessageInput.fidelity", propertyOf(t, schemaOf(t, document, "MessageInput"), "fidelity"),
		[]string{
			"raw_rfc5322", "milter_reconstructed_crlf", "exim_local_scan_observed_crlf",
			"exim_transport_filter_crlf", "lmtp_delivered_crlf",
		})

	commitResponse := schemaOf(t, document, "DSNPropagateCommitResponse")
	assertRequired(t, "DSNPropagateCommitResponse", commitResponse,
		[]string{contractAPIVersionMember, contractDraftMember, "state"})
	assertEnum(t, "DSNPropagateCommitResponse.state", propertyOf(t, commitResponse, "state"), []string{"committed"})
}

// TestOpenAPIContractAdmitsAndRefusesReferenceFixtures proves the published
// reference documents validate exactly as recorded against the contract.
func TestOpenAPIContractAdmitsAndRefusesReferenceFixtures(t *testing.T) {
	t.Parallel()

	document := loadContract(t)
	for _, name := range []string{"dsn-propagate.json", "dsn-propagate-negative.json"} {
		fixture := loadFixture(t, name)
		for _, testCase := range fixture.Cases {
			schema := schemaOf(t, document, testCase.Schema)
			var value any
			if err := json.Unmarshal(testCase.Document, &value); err != nil {
				t.Fatalf("%s/%s: decode document: %v", name, testCase.Case, err)
			}
			err := schema.VisitJSON(value, openapi3.EnableFormatValidation())
			switch fixture.Expectation {
			case "valid":
				if err != nil {
					t.Fatalf("%s/%s: contract rejected an admitted document: %v", name, testCase.Case, err)
				}
				if testCase.Violates != "" {
					t.Fatalf("%s/%s: an admitted document records a violation", name, testCase.Case)
				}
			case "invalid":
				if err == nil {
					t.Fatalf("%s/%s: contract admitted a document that %s", name, testCase.Case, testCase.Violates)
				}
				if testCase.Violates == "" {
					t.Fatalf("%s/%s: a refused document records no reason", name, testCase.Case)
				}
			default:
				t.Fatalf("%s: unknown expectation %q", name, fixture.Expectation)
			}
		}
	}
}

// loadContract loads the authoritative contract without external references.
func loadContract(t *testing.T) *openapi3.T {
	t.Helper()

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = false
	document, err := loader.LoadFromFile(filepath.Join("..", "docs", "specs", "openapi", "dkim2d.yaml"))
	if err != nil {
		t.Fatalf("load OpenAPI contract: %v", err)
	}

	return document
}

// loadFixture decodes one bounded duplicate-free reference fixture file.
func loadFixture(t *testing.T, name string) propagationFixtureFile {
	t.Helper()

	content, err := os.ReadFile(filepath.Join("..", "testdata", "reference", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	if len(content) > fixtureMaxBytes {
		t.Fatalf("fixture %s exceeds the bounded size", name)
	}
	var fixture propagationFixtureFile
	if err := strictjson.Decode(content, &fixture, fixtureMaxDepth, fixtureMaxTokens); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
	if fixture.Schema != fixtureSchemaName || fixture.Draft != contractDraft || len(fixture.Cases) == 0 {
		t.Fatalf("fixture %s does not declare the pinned fixture contract", name)
	}

	return fixture
}

// schemaOf resolves one required component schema.
func schemaOf(t *testing.T, document *openapi3.T, name string) *openapi3.Schema {
	t.Helper()

	reference, ok := document.Components.Schemas[name]
	if !ok || reference == nil || reference.Value == nil {
		t.Fatalf("missing component schema %s", name)
	}

	return reference.Value
}

// propertyOf resolves one required property of a component schema.
func propertyOf(t *testing.T, schema *openapi3.Schema, name string) *openapi3.Schema {
	t.Helper()

	property, ok := schema.Properties[name]
	if !ok || property == nil || property.Value == nil {
		t.Fatalf("missing property %s", name)
	}

	return property.Value
}

// assertEnum proves one closed vocabulary matches the expected values in order.
func assertEnum(t *testing.T, name string, schema *openapi3.Schema, expected []string) {
	t.Helper()

	values := make([]string, 0, len(schema.Enum))
	for _, value := range schema.Enum {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("%s carries a non-string enum value", name)
		}
		values = append(values, text)
	}
	if !slices.Equal(values, expected) {
		t.Fatalf("%s vocabulary is %v, want %v", name, values, expected)
	}
}

// assertRequired proves an object schema requires exactly the expected members.
func assertRequired(t *testing.T, name string, schema *openapi3.Schema, expected []string) {
	t.Helper()

	required := slices.Clone(schema.Required)
	wanted := slices.Clone(expected)
	slices.Sort(required)
	slices.Sort(wanted)
	if !slices.Equal(required, wanted) {
		t.Fatalf("%s requires %v, want %v", name, required, wanted)
	}
}

// assertProperties proves an object schema is closed over exactly the expected
// members.
func assertProperties(t *testing.T, name string, schema *openapi3.Schema, expected []string) {
	t.Helper()

	if schema.AdditionalProperties.Has == nil || *schema.AdditionalProperties.Has {
		t.Fatalf("%s is not a closed object", name)
	}
	properties := make([]string, 0, len(schema.Properties))
	for property := range schema.Properties {
		properties = append(properties, property)
	}
	wanted := slices.Clone(expected)
	slices.Sort(properties)
	slices.Sort(wanted)
	if !slices.Equal(properties, wanted) {
		t.Fatalf("%s exposes %v, want %v", name, properties, wanted)
	}
}

// assertOnlyCapability proves an operation admits the propagation capability
// alone.
func assertOnlyCapability(t *testing.T, operation *openapi3.Operation) {
	t.Helper()

	if operation.Security == nil || len(*operation.Security) != 1 {
		t.Fatalf("operation %s has no single security requirement", operation.OperationID)
	}
	requirement := (*operation.Security)[0]
	scopes, ok := requirement[propagateCapabilityName]
	if !ok || len(requirement) != 1 || len(scopes) != 0 {
		t.Fatalf("operation %s does not require only the propagation capability", operation.OperationID)
	}
}

// requestSchemaRef returns the JSON request body reference of one operation.
func requestSchemaRef(t *testing.T, operation *openapi3.Operation) string {
	t.Helper()

	if operation.RequestBody == nil || operation.RequestBody.Value == nil ||
		!operation.RequestBody.Value.Required {
		t.Fatalf("operation %s has no required request body", operation.OperationID)
	}
	media := operation.RequestBody.Value.Content.Get("application/json")
	if media == nil || media.Schema == nil {
		t.Fatalf("operation %s has no JSON request schema", operation.OperationID)
	}

	return media.Schema.Ref
}

// successSchemaRef returns the JSON schema reference of the 200 response.
func successSchemaRef(t *testing.T, operation *openapi3.Operation) string {
	t.Helper()

	response := operation.Responses.Value("200")
	if response == nil || response.Value == nil {
		t.Fatalf("operation %s has no success response", operation.OperationID)
	}
	media := response.Value.Content.Get("application/json")
	if media == nil || media.Schema == nil {
		t.Fatalf("operation %s has no JSON success schema", operation.OperationID)
	}

	return media.Schema.Ref
}

// assertReferences proves one schema reference names the expected component.
func assertReferences(t *testing.T, name string, reference string, expected string) {
	t.Helper()

	if reference != "#/components/schemas/"+expected {
		t.Fatalf("%s references %q, want %s", name, reference, expected)
	}
}
