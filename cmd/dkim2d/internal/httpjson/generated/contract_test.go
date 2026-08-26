package generated

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/wire"
	"github.com/getkin/kin-openapi/openapi3"
)

const (
	testHeaderCacheControl       = "Cache-Control"
	testHeaderConnection         = "Connection"
	testHeaderContentTypeOptions = "X-Content-Type-Options"
	testMethodGet                = "GET"
	testMethodPost               = "POST"
	testMetricsPath              = "/metrics"
	testDSNSignPath              = "/v1/dsn/sign"
	testProcessPath              = "/v1/process"
	testRevisePath               = "/v1/revise"
	testSignPath                 = "/v1/sign"
	testPropertyAPIVersion       = "api_version"
	testPropertyClass            = "class"
	testPropertyDNSTesting       = "dns_testing_effective"
	testPropertyDraft            = "draft"
	testPropertyDisposition      = "disposition"
	testPropertyMessage          = "message"
	testPropertyIncomingSMTP     = "incoming_smtp"
	testPropertyReporting        = "reporting"
	testPropertySMTP             = "smtp"
	testPropertyContext          = "context"
	testPropertyActions          = "actions"
	testPropertyPrimaryReason    = "primary_reason"
	testPropertyReason           = "reason"
	testPropertySequence         = "sequence"
	testPropertyStatus           = "status"
	testPropertyTenant           = "tenant"
	testValueComplete            = "complete"
	testValueIndeterminate       = "indeterminate"
	testValueNotEvaluated        = "not_evaluated"
	testSchemaOperationResponse  = "OperationResponse"
)

type expectedOperation struct {
	id        string
	responses []string
	success   string
	head      bool
}

// TestEmbeddedOpenAPIContract locks the generated server to the approved daemon
// OpenAPI source.
func TestEmbeddedOpenAPIContract(t *testing.T) {
	t.Parallel()

	document, err := GetSwagger()
	if err != nil {
		t.Fatalf("load embedded OpenAPI: %v", err)
	}
	if document.OpenAPI != "3.0.3" {
		t.Fatalf("unexpected OpenAPI version %q", document.OpenAPI)
	}
	if len(document.Servers) != 0 {
		t.Fatal("embedded OpenAPI unexpectedly declares a server")
	}
	if err := document.Validate(context.Background()); err != nil {
		t.Fatalf("validate embedded OpenAPI: %v", err)
	}

	expected := map[string]map[string]expectedOperation{
		testMetricsPath: {
			testMethodGet: {
				id:        "getMetrics",
				responses: []string{"200", "400", "417", "500"},
			},
		},
		"/healthz": {
			testMethodGet: {
				id:        "getHealth",
				responses: []string{"200", "304", "400", "412", "417", "500"},
				success:   "HealthResponse",
			},
			"HEAD": {
				id:        "headHealth",
				responses: []string{"200", "304", "400", "412", "417", "500"},
				head:      true,
			},
		},
		"/readyz": {
			testMethodGet: {
				id:        "getReadiness",
				responses: []string{"200", "304", "400", "412", "417", "500", "503"},
				success:   "ReadinessResponse",
			},
			"HEAD": {
				id:        "headReadiness",
				responses: []string{"200", "304", "400", "412", "417", "500", "503"},
				head:      true,
			},
		},
		testProcessPath: {
			testMethodPost: {
				id:        "processMessage",
				responses: []string{"200", "204", "400", "403", "408", "413", "415", "417", "500", "503"},
				success:   "ProcessResponse",
			},
		},
		testSignPath: {
			testMethodPost: {
				id:        "signMessage",
				responses: []string{"200", "204", "400", "403", "408", "413", "415", "417", "500", "503"},
				success:   testSchemaOperationResponse,
			},
		},
		testRevisePath: {
			testMethodPost: {
				id:        "reviseMessage",
				responses: []string{"200", "400", "403", "408", "413", "415", "417", "500", "503"},
				success:   testSchemaOperationResponse,
			},
		},
		testDSNSignPath: {
			testMethodPost: {
				id:        "signDeliveryStatus",
				responses: []string{"200", "400", "403", "408", "413", "415", "417", "500", "503"},
				success:   testSchemaOperationResponse,
			},
		},
	}
	if document.Paths.Len() != len(expected) {
		t.Fatalf("unexpected path count %d", document.Paths.Len())
	}

	for path, expectedMethods := range expected {
		item := document.Paths.Value(path)
		if item == nil {
			t.Fatalf("missing path %s", path)
		}
		operations := item.Operations()
		if len(operations) != len(expectedMethods) {
			t.Fatalf("unexpected operation count for %s: %d", path, len(operations))
		}
		for method, want := range expectedMethods {
			operation := operations[method]
			if operation == nil {
				t.Fatalf("missing operation %s %s", method, path)
			}
			if operation.OperationID != want.id {
				t.Fatalf("unexpected operation ID for %s %s: %q", method, path, operation.OperationID)
			}
			assertOperationSecurity(t, path, operation)
			assertOperationResponses(t, method, path, operation, want)
		}
	}

	assertLocalCapability(t, document)
	assertProcessRequestBody(t, document)
	assertDeliveryStatusRequestBody(t, document)
	assertClosedObjectSchemas(t, document)
	assertFrozenSchemaShapes(t, document)
	assertFrozenEnums(t, document)
	assertProtectedBindings(t)
}

// assertOperationSecurity verifies the exact public and protected operation
// security declarations.
func assertOperationSecurity(t *testing.T, path string, operation *openapi3.Operation) {
	t.Helper()

	if operation.Security == nil {
		t.Fatalf("operation %s has no explicit security declaration", operation.OperationID)
	}
	if path != testProcessPath && path != testSignPath && path != testRevisePath && path != testDSNSignPath {
		if len(*operation.Security) != 0 {
			t.Fatalf("status operation %s is unexpectedly protected", operation.OperationID)
		}
		return
	}
	if len(*operation.Security) != 1 {
		t.Fatalf("process operation has %d security alternatives", len(*operation.Security))
	}
	requirement := (*operation.Security)[0]
	schemeName := "localCapability"
	if path == testDSNSignPath {
		schemeName = "dsnSignCapability"
	}
	scopes, ok := requirement[schemeName]
	if !ok || len(requirement) != 1 || len(scopes) != 0 {
		t.Fatalf("operation %s does not require only %s", operation.OperationID, schemeName)
	}
}

// assertOperationResponses verifies exact status maps, schema ownership, and
// mandatory response metadata.
func assertOperationResponses(
	t *testing.T,
	method string,
	path string,
	operation *openapi3.Operation,
	want expectedOperation,
) {
	t.Helper()

	if operation.Responses == nil || operation.Responses.Default() != nil {
		t.Fatalf("operation %s has missing responses or a default", operation.OperationID)
	}
	gotKeys := make([]string, 0, operation.Responses.Len())
	for key := range operation.Responses.Map() {
		gotKeys = append(gotKeys, key)
	}
	slices.Sort(gotKeys)
	if !slices.Equal(gotKeys, want.responses) {
		t.Fatalf("unexpected responses for %s %s: %v", method, path, gotKeys)
	}
	if want.head &&
		(!strings.Contains(operation.Description, "304") ||
			!strings.Contains(operation.Description, "neither Content-Type nor Content-Length")) {
		t.Fatalf("HEAD operation %s does not describe the 304 metadata exception", operation.OperationID)
	}

	for status, responseRef := range operation.Responses.Map() {
		if responseRef == nil || responseRef.Value == nil {
			t.Fatalf("response %s for %s is unresolved", status, operation.OperationID)
		}
		assertOperationResponse(t, path, operation.OperationID, status, responseRef.Value, want)
	}
}

// assertOperationResponse verifies one response's headers and content schema.
func assertOperationResponse(
	t *testing.T,
	path string,
	operationID string,
	status string,
	response *openapi3.Response,
	want expectedOperation,
) {
	t.Helper()

	expectedHeaders := expectedResponseHeaders(path, status)
	actualHeaders := make([]string, 0, len(response.Headers))
	for name := range response.Headers {
		actualHeaders = append(actualHeaders, name)
	}
	slices.Sort(actualHeaders)
	if !slices.Equal(actualHeaders, expectedHeaders) {
		t.Fatalf("response %s for %s has headers %v", status, operationID, actualHeaders)
	}
	for _, name := range requiredResponseHeaders(path, status) {
		header := response.Headers[name]
		if header == nil || header.Value == nil || !header.Value.Required {
			t.Fatalf("response %s for %s lacks required %s", status, operationID, name)
		}
	}
	date := response.Headers["Date"]
	if date == nil || date.Value == nil || date.Value.Required {
		t.Fatalf("response %s for %s has invalid Date metadata", status, operationID)
	}
	if status == "503" {
		retry := response.Headers["Retry-After"]
		if retry == nil || retry.Value == nil || !retry.Value.Required {
			t.Fatalf("response 503 for %s lacks required Retry-After", operationID)
		}
	}
	assertResponseHeaderSchemas(t, operationID, status, response.Headers)
	assertResponseContent(t, operationID, status, response, want)
}

// expectedResponseHeaders returns the sorted exact header inventory.
func expectedResponseHeaders(path string, status string) []string {
	headers := requiredResponseHeaders(path, status)
	headers = append(headers, "Date")
	if status == "503" {
		headers = append(headers, "Retry-After")
	}
	slices.Sort(headers)

	return headers
}

// requiredResponseHeaders returns the required headers for one response.
func requiredResponseHeaders(path string, status string) []string {
	headers := []string{testHeaderCacheControl, testHeaderConnection}
	if status == "304" {
		return append(headers, "ETag")
	}
	if status == "204" && (path == testProcessPath || path == testSignPath) {
		return headers
	}
	headers = append(headers, "Content-Length", testHeaderContentTypeOptions)
	if status == "200" && (path == "/healthz" || path == "/readyz") {
		headers = append(headers, "ETag")
	}

	return headers
}

// assertResponseContent verifies bodyless responses and JSON schema ownership.
func assertResponseContent(
	t *testing.T,
	operationID string,
	status string,
	response *openapi3.Response,
	want expectedOperation,
) {
	t.Helper()

	if want.head || status == "304" || status == "204" {
		if len(response.Content) != 0 {
			t.Fatalf("bodyless response %s for %s declares content", status, operationID)
		}
		return
	}
	if operationID == "getMetrics" && status == "200" {
		media := response.Content["text/plain"]
		if len(response.Content) != 1 || media == nil || media.Schema == nil ||
			media.Schema.Value == nil || !media.Schema.Value.Type.Is("string") ||
			media.Schema.Value.MaxLength == nil || *media.Schema.Value.MaxLength != 262144 {
			t.Fatal("metrics success response lacks its bounded text schema")
		}
		return
	}
	media := response.Content["application/json"]
	if len(response.Content) != 1 || media == nil || media.Schema == nil {
		t.Fatalf("response %s for %s lacks JSON schema", status, operationID)
	}
	expectedSchema := "ErrorResponse"
	if status == "200" {
		expectedSchema = want.success
	}
	if media.Schema.Ref != "#/components/schemas/"+expectedSchema {
		t.Fatalf("response %s for %s uses %q", status, operationID, media.Schema.Ref)
	}
}

// assertResponseHeaderSchemas locks mandatory singleton header values and
// lexical patterns.
func assertResponseHeaderSchemas(
	t *testing.T,
	operationID string,
	status string,
	headers openapi3.Headers,
) {
	t.Helper()

	expectedEnums := map[string]string{
		testHeaderCacheControl: "no-store",
		testHeaderConnection:   "close",
	}
	if headers[testHeaderContentTypeOptions] != nil {
		expectedEnums[testHeaderContentTypeOptions] = "nosniff"
	}
	if status == "503" {
		expectedEnums["Retry-After"] = "1"
	}
	for name, expected := range expectedEnums {
		schema := headers[name].Value.Schema
		if schema == nil || schema.Value == nil || !schema.Value.Type.Is("string") ||
			len(schema.Value.Enum) != 1 ||
			fmt.Sprint(schema.Value.Enum[0]) != expected {
			t.Fatalf("response %s for %s has invalid %s singleton", status, operationID, name)
		}
	}

	if headers["Content-Length"] != nil {
		contentLength := headers["Content-Length"].Value.Schema
		if contentLength == nil || contentLength.Value == nil ||
			!contentLength.Value.Type.Is("string") ||
			contentLength.Value.Pattern != "^(0|[1-9][0-9]*)$" {
			t.Fatalf("response %s for %s has invalid Content-Length pattern", status, operationID)
		}
	}
	if headers["ETag"] != nil {
		entityTag := headers["ETag"].Value.Schema
		if entityTag == nil || entityTag.Value == nil ||
			!entityTag.Value.Type.Is("string") ||
			entityTag.Value.Pattern != `^"[0-9a-f]{64}"$` {
			t.Fatalf("response %s for %s has invalid ETag pattern", status, operationID)
		}
	}
	date := headers["Date"].Value.Schema
	const datePattern = "^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), [0-9]{2} " +
		"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{4} " +
		"[0-9]{2}:[0-9]{2}:[0-9]{2} GMT$"
	if date == nil || date.Value == nil || !date.Value.Type.Is("string") ||
		date.Value.Pattern != datePattern {
		t.Fatalf("response %s for %s has invalid Date pattern", status, operationID)
	}
}

// assertProcessRequestBody locks the authenticated operation to one required
// JSON ProcessRequest body.
func assertProcessRequestBody(t *testing.T, document *openapi3.T) {
	t.Helper()

	operation := document.Paths.Value(testProcessPath).Post
	if operation == nil || operation.RequestBody == nil || operation.RequestBody.Value == nil ||
		!operation.RequestBody.Value.Required || len(operation.RequestBody.Value.Content) != 1 {
		t.Fatal("process operation lacks one required request body")
	}
	media := operation.RequestBody.Value.Content["application/json"]
	if media == nil || media.Schema == nil ||
		media.Schema.Ref != "#/components/schemas/ProcessRequest" {
		t.Fatal("process operation request body is not ProcessRequest JSON")
	}
}

// assertDeliveryStatusRequestBody locks the dedicated DSN request to protected
// shared raw-message and SMTP DTOs without caller-supplied evidence claims.
func assertDeliveryStatusRequestBody(t *testing.T, document *openapi3.T) {
	t.Helper()
	operation := document.Paths.Value(testDSNSignPath).Post
	if operation == nil || operation.RequestBody == nil || operation.RequestBody.Value == nil ||
		!operation.RequestBody.Value.Required || len(operation.RequestBody.Value.Content) != 1 {
		t.Fatal("DSN operation lacks one required request body")
	}
	media := operation.RequestBody.Value.Content["application/json"]
	if media == nil || media.Schema == nil || media.Schema.Ref != "#/components/schemas/DSNSignRequest" {
		t.Fatal("DSN operation request body is not DSNSignRequest JSON")
	}
}

// assertLocalCapability locks the repository-local API-key scheme and rejects
// an accidental Bearer interpretation.
func assertLocalCapability(t *testing.T, document *openapi3.T) {
	t.Helper()

	if document.Components == nil || len(document.Components.SecuritySchemes) != 2 {
		t.Fatal("unexpected security-scheme inventory")
	}
	reference := document.Components.SecuritySchemes["localCapability"]
	if reference == nil || reference.Value == nil {
		t.Fatal("missing localCapability scheme")
	}
	scheme := reference.Value
	if scheme.Type != "apiKey" || scheme.In != "header" ||
		scheme.Name != "X-DKIM2-Capability" || scheme.Scheme != "" {
		t.Fatal("localCapability is not the approved local API-key scheme")
	}
	dsnReference := document.Components.SecuritySchemes["dsnSignCapability"]
	if dsnReference == nil || dsnReference.Value == nil || dsnReference.Value.Type != "apiKey" ||
		dsnReference.Value.In != "header" || dsnReference.Value.Name != "X-DKIM2-DSN-Sign-Capability" ||
		dsnReference.Value.Scheme != "" {
		t.Fatal("dsnSignCapability is not the approved dedicated API-key scheme")
	}
}

// assertClosedObjectSchemas requires every component object to reject unknown
// properties.
func assertClosedObjectSchemas(t *testing.T, document *openapi3.T) {
	t.Helper()

	for name, reference := range document.Components.Schemas {
		if reference == nil || reference.Value == nil || reference.Value.Type == nil ||
			!reference.Value.Type.Is("object") {
			continue
		}
		additional := reference.Value.AdditionalProperties.Has
		if additional == nil || *additional {
			t.Fatalf("object schema %s permits unspecified properties", name)
		}
	}
}

// assertFrozenSchemaShapes locks every object property/required inventory and
// all request scalar and collection bounds.
func assertFrozenSchemaShapes(t *testing.T, document *openapi3.T) {
	t.Helper()

	assertObjectInventories(t, document)
	assertRequestBounds(t, document)
	assertResultArrayBounds(t, document)
}

// assertObjectInventories locks every component object's property and required
// field inventory.
func assertObjectInventories(t *testing.T, document *openapi3.T) {
	t.Helper()

	type shape struct {
		properties []string
		required   []string
	}
	expected := map[string]shape{
		"ProcessRequest": {
			properties: []string{testPropertyAPIVersion, testPropertyDraft, testPropertyMessage, testPropertyReporting, testPropertySMTP},
			required:   []string{testPropertyAPIVersion, testPropertyDraft, testPropertyMessage, testPropertySMTP},
		},
		"SignRequest": {
			properties: []string{testPropertyAPIVersion, testPropertyContext, testPropertyDraft, testPropertyMessage, testPropertySMTP},
			required:   []string{testPropertyAPIVersion, testPropertyContext, testPropertyDraft, testPropertyMessage, testPropertySMTP},
		},
		"ReviseRequest": {
			properties: []string{testPropertyAPIVersion, testPropertyContext, testPropertyDraft, testPropertyIncomingSMTP, testPropertyMessage, testPropertySMTP},
			required:   []string{testPropertyAPIVersion, testPropertyContext, testPropertyDraft, testPropertyIncomingSMTP, testPropertyMessage, testPropertySMTP},
		},
		"DSNSignRequest": {
			properties: []string{testPropertyAPIVersion, testPropertyContext, testPropertyDraft, testPropertyMessage, "outer_smtp"},
			required:   []string{testPropertyAPIVersion, testPropertyContext, testPropertyDraft, testPropertyMessage, "outer_smtp"},
		},
		"MessageInput": {
			properties: []string{"fidelity", "raw_rfc5322_base64"},
			required:   []string{"raw_rfc5322_base64"},
		},
		"SMTPInput": {
			properties: []string{"mail_from", "rcpt_to"},
			required:   []string{"mail_from", "rcpt_to"},
		},
		"ProcessResponse": {
			properties: []string{testPropertyActions, testPropertyAPIVersion, testPropertyDisposition, testPropertyDraft, "policy", "replay", "verification"},
			required:   []string{testPropertyActions, testPropertyAPIVersion, testPropertyDisposition, testPropertyDraft, "policy", "replay", "verification"},
		},
		"SigningContext": {
			properties: []string{"domain", testPropertyTenant},
			required:   []string{"domain", testPropertyTenant},
		},
		"DeliveryStatusContext": {
			properties: []string{testPropertyTenant},
			required:   []string{testPropertyTenant},
		},
		"ReportingContext": {
			properties: []string{"authserv_id"},
			required:   []string{"authserv_id"},
		},
		testSchemaOperationResponse: {
			properties: []string{testPropertyActions, testPropertyAPIVersion, testPropertyDisposition, testPropertyDraft, "operation", "result"},
			required:   []string{testPropertyActions, testPropertyAPIVersion, testPropertyDisposition, testPropertyDraft, "operation", "result"},
		},
		"AddHeaderAction": {
			properties: []string{"name", "type", "value"},
			required:   []string{"name", "type", "value"},
		},
		"VerificationResult": {
			properties: []string{
				"checks", "custody_structure", "historical_content", "historical_signatures",
				testPropertyPrimaryReason, "scope", "signature_sets", "state", "target",
			},
			required: []string{
				"checks", "custody_structure", "historical_content", "historical_signatures",
				testPropertyPrimaryReason, "scope", "signature_sets", "state",
			},
		},
		"VerificationTarget": {
			properties: []string{"instance", testPropertySequence},
			required:   []string{"instance", testPropertySequence},
		},
		"VerificationCheck": {
			properties: []string{testPropertyClass, testPropertyReason},
			required:   []string{testPropertyClass, testPropertyReason},
		},
		"SignatureSetResult": {
			properties: []string{"algorithm", "key_policy", testPropertyReason, testPropertyStatus},
			required:   []string{"algorithm", "key_policy", testPropertyReason, testPropertyStatus},
		},
		"KeyPolicyResult": {
			properties: []string{"strict_identity_applicable", "strict_identity_declared", "testing_declared"},
			required:   []string{"strict_identity_applicable", "strict_identity_declared", "testing_declared"},
		},
		"PolicyResult": {
			properties: []string{
				testPropertyDNSTesting, "do_not_explode", "do_not_modify", "feedback",
				"findings", "mode", testPropertyPrimaryReason, "verdict",
			},
			required: []string{
				testPropertyDNSTesting, "do_not_explode", "do_not_modify", "feedback",
				"findings", "mode", testPropertyPrimaryReason, "verdict",
			},
		},
		"PolicyFeedback": {
			properties: []string{"history_coverage", "relay_required", "relay_sequence", "requested"},
			required:   []string{"history_coverage", "relay_required", "requested"},
		},
		"PolicyFinding": {
			properties: []string{testPropertyReason, testPropertySequence, "severity"},
			required:   []string{testPropertyReason, "severity"},
		},
		"ReplayResult": {
			properties: []string{testPropertyClass},
			required:   []string{testPropertyClass},
		},
		"HealthResponse": {
			properties: []string{testPropertyAPIVersion, testPropertyDraft, testPropertyStatus},
			required:   []string{testPropertyAPIVersion, testPropertyDraft, testPropertyStatus},
		},
		"ReadinessResponse": {
			properties: []string{testPropertyAPIVersion, testPropertyDraft, testPropertyStatus},
			required:   []string{testPropertyAPIVersion, testPropertyDraft, testPropertyStatus},
		},
		"ErrorResponse": {
			properties: []string{testPropertyAPIVersion, "category", "code", testPropertyDraft},
			required:   []string{testPropertyAPIVersion, "category", "code", testPropertyDraft},
		},
	}
	for name, want := range expected {
		schema := requiredSchema(t, document, name)
		properties := make([]string, 0, len(schema.Properties))
		for property := range schema.Properties {
			properties = append(properties, property)
		}
		slices.Sort(properties)
		slices.Sort(want.properties)
		required := append([]string(nil), schema.Required...)
		slices.Sort(required)
		slices.Sort(want.required)
		if !slices.Equal(properties, want.properties) || !slices.Equal(required, want.required) {
			t.Fatalf("schema %s has properties %v and required %v", name, properties, required)
		}
	}
}

// assertRequestBounds locks protected request scalar and collection bounds.
func assertRequestBounds(t *testing.T, document *openapi3.T) {
	t.Helper()

	message := requiredSchema(t, document, "MessageInput").Properties["raw_rfc5322_base64"].Value
	if message == nil || !message.Type.Is("string") || message.Format != "byte" ||
		message.MinLength != 0 || message.MaxLength == nil || *message.MaxLength != 44_739_244 {
		t.Fatal("raw message schema bounds are not frozen")
	}
	smtp := requiredSchema(t, document, "SMTPInput")
	mailFrom := smtp.Properties["mail_from"].Value
	if mailFrom == nil || !mailFrom.Type.Is("string") || mailFrom.MinLength != 0 ||
		mailFrom.MaxLength == nil || *mailFrom.MaxLength != 256 {
		t.Fatal("MAIL FROM schema bounds are not frozen")
	}
	recipients := smtp.Properties["rcpt_to"].Value
	if recipients == nil || !recipients.Type.Is("array") || recipients.MinItems != 1 ||
		recipients.MaxItems == nil || *recipients.MaxItems != 2000 || recipients.UniqueItems ||
		recipients.Items == nil || recipients.Items.Value == nil ||
		!recipients.Items.Value.Type.Is("string") || recipients.Items.Value.MinLength != 0 ||
		recipients.Items.Value.MaxLength == nil || *recipients.Items.Value.MaxLength != 256 {
		t.Fatal("RCPT TO schema bounds are not frozen")
	}
	if requiredSchema(t, document, "CanonicalUint64").Pattern != "^[1-9][0-9]{0,19}$" {
		t.Fatal("canonical uint64 schema pattern is not frozen")
	}
}

// assertResultArrayBounds locks bounded result collections.
func assertResultArrayBounds(t *testing.T, document *openapi3.T) {
	t.Helper()

	verification := requiredSchema(t, document, "VerificationResult")
	checks := verification.Properties["checks"].Value
	if checks == nil || !checks.Type.Is("array") || checks.MinItems != 1 ||
		checks.MaxItems == nil || *checks.MaxItems != 128 {
		t.Fatal("verification checks bounds are not frozen")
	}
	signatureSets := verification.Properties["signature_sets"].Value
	if signatureSets == nil || !signatureSets.Type.Is("array") ||
		signatureSets.MaxItems == nil || *signatureSets.MaxItems != 16 {
		t.Fatal("signature set bounds are not frozen")
	}
	findings := requiredSchema(t, document, "PolicyResult").Properties["findings"].Value
	if findings == nil || !findings.Type.Is("array") || findings.MinItems != 1 ||
		findings.MaxItems == nil || *findings.MaxItems != 128 {
		t.Fatal("policy findings bounds are not frozen")
	}
}

// assertFrozenEnums locks singleton protocol values and closed public result
// inventories.
func assertFrozenEnums(t *testing.T, document *openapi3.T) {
	t.Helper()

	expected := map[string][]string{
		"APIVersion":        {"v1"},
		"DraftVersion":      {"draft-ietf-dkim-dkim2-spec-05"},
		"VerificationState": {"PASS", "FAIL", "PERMERROR", "TEMPERROR"},
		"VerificationReason": {
			"none", "limit_exceeded", "malformed_message", "malformed_protocol",
			"duplicate_hash_algorithm", "invalid_recipe_json", "duplicate_selector",
			"too_many_signatures",
			"missing_protocol", "sequence_invalid", "unsupported_algorithm",
			"hash_mismatch", "signature_mismatch", "missing_key", "invalid_key",
			"ambiguous_key", "revoked_key", "unsupported_key_type",
			"key_algorithm_mismatch", "provider_temporary", "provider_permanent",
			"provider_contract", "timestamp_invalid", "envelope_mismatch",
			"domain_alignment_mismatch", "next_domain_mismatch",
			"out_of_band_required", "internal_contract",
		},
		"PolicyReason": {
			"protocol_pass", "protocol_fail", "protocol_permerror",
			"protocol_temperror", "permissive_override", "testing_mode_observe",
			"dns_testing_effective", "dns_testing_mixed", "dns_testing_ineligible",
			"donotmodify_indeterminate", "donotmodify_not_evaluated",
			"donotexplode_violated",
			"donotexplode_indeterminate", "donotexplode_not_evaluated",
			"feedback_requested", "feedback_relay_selected", "feedhere_inert",
			"exploded_reported",
		},
	}
	for name, want := range expected {
		schema := requiredSchema(t, document, name)
		got := make([]string, 0, len(schema.Enum))
		for _, value := range schema.Enum {
			got = append(got, fmt.Sprint(value))
		}
		if !slices.Equal(got, want) {
			t.Fatalf("schema %s has enum %v", name, got)
		}
	}

	assertPropertyEnum(t, document, "ProcessResponse", "disposition",
		[]string{"accept", "reject", "tempfail", "continue"})
	assertPropertyEnum(t, document, "VerificationResult", "scope", []string{"current", "chain"})
	assertPropertyEnum(t, document, "VerificationResult", "historical_content",
		[]string{testValueNotEvaluated, testValueComplete, "partial"})
	assertPropertyEnum(t, document, "VerificationResult", "historical_signatures",
		[]string{testValueNotEvaluated, testValueComplete})
	assertPropertyEnum(t, document, "VerificationResult", "custody_structure",
		[]string{testValueNotEvaluated, "not_present", "nd_links_evaluated", "terminal_nd_requires_oob"})
	assertPropertyEnum(t, document, "VerificationCheck", "class", []string{
		"message", "protocol", "body_hash", "header_hash", "signature", "key",
		"timestamp", "envelope", "domain_alignment", "next_domain", "provider",
		"internal_contract",
	})
	assertPropertyEnum(t, document, "SignatureSetResult", "algorithm",
		[]string{"rsa-sha256", "ed25519-sha256", "unknown"})
	assertPropertyEnum(t, document, "SignatureSetResult", "status",
		[]string{"pass", "fail", "permerror", "temperror", "ignored"})
	strictIdentity := requiredSchema(t, document, "KeyPolicyResult").
		Properties["strict_identity_applicable"].Value
	if strictIdentity == nil || !strictIdentity.Type.Is("boolean") ||
		len(strictIdentity.Enum) != 1 {
		t.Fatal("strict_identity_applicable is not a boolean singleton")
	}
	strictIdentityValue, ok := strictIdentity.Enum[0].(bool)
	if !ok || strictIdentityValue {
		t.Fatal("strict_identity_applicable is not singleton false")
	}
	assertPropertyEnum(t, document, "PolicyResult", "mode",
		[]string{"strict", "permissive", "testing"})
	assertPropertyEnum(t, document, "PolicyResult", "verdict",
		[]string{"accept", "reject", "tempfail", "continue"})
	assertPropertyEnum(t, document, "PolicyResult", "do_not_modify",
		[]string{"not_requested", testValueIndeterminate, testValueNotEvaluated})
	assertPropertyEnum(t, document, "PolicyResult", "do_not_explode",
		[]string{"not_requested", "violated", testValueIndeterminate, testValueNotEvaluated})
	assertPropertyEnum(t, document, "PolicyFeedback", "history_coverage",
		[]string{testValueComplete, testValueIndeterminate, testValueNotEvaluated})
	assertPropertyEnum(t, document, "PolicyFinding", "severity",
		[]string{"info", "warning", "permanent", "temporary"})
	assertPropertyEnum(t, document, "ReplayResult", "class",
		[]string{"not_checked", "disabled", "first_seen", "replayed", testValueIndeterminate})
	assertPropertyEnum(t, document, "HealthResponse", "status", []string{"alive"})
	assertPropertyEnum(t, document, "ReadinessResponse", "status", []string{"ready"})
	assertPropertyEnum(t, document, "ErrorResponse", "category",
		[]string{"request", "availability", "internal"})
	assertPropertyEnum(t, document, "ErrorResponse", "code", []string{
		"invalid_json", "invalid_contract", "unsupported_version", "unsupported_draft",
		"request_too_large", "unsupported_media_type", "not_found",
		"method_not_allowed", "forbidden", "service_not_ready", "service_overloaded",
		"request_timeout", "request_deadline", "expectation_failed", "precondition_failed",
		"internal_error",
	})
	assertPropertyEnum(t, document, testSchemaOperationResponse, "operation",
		[]string{"sign", "revise", "delivery_status"})
}

// assertPropertyEnum compares one inline property enum without sorting because
// source order is part of the generated contract.
func assertPropertyEnum(
	t *testing.T,
	document *openapi3.T,
	schemaName string,
	propertyName string,
	expected []string,
) {
	t.Helper()

	property := requiredSchema(t, document, schemaName).Properties[propertyName]
	if property == nil || property.Value == nil {
		t.Fatalf("missing property %s.%s", schemaName, propertyName)
	}
	actual := make([]string, 0, len(property.Value.Enum))
	for _, value := range property.Value.Enum {
		actual = append(actual, fmt.Sprint(value))
	}
	if !slices.Equal(actual, expected) {
		t.Fatalf("property %s.%s has enum %v", schemaName, propertyName, actual)
	}
}

// requiredSchema resolves one required component schema for focused
// assertions.
func requiredSchema(t *testing.T, document *openapi3.T, name string) *openapi3.Schema {
	t.Helper()

	reference := document.Components.Schemas[name]
	if reference == nil || reference.Value == nil {
		t.Fatalf("missing component schema %s", name)
	}
	return reference.Value
}

// assertProtectedBindings proves generated request DTOs expose only the
// target-local opaque wrapper for protected scalar values.
func assertProtectedBindings(t *testing.T) {
	t.Helper()

	protectedType := reflect.TypeFor[wire.ProtectedString]()
	messageField, ok := reflect.TypeFor[MessageInput]().FieldByName("RawRfc5322Base64")
	if !ok || messageField.Type != protectedType {
		t.Fatal("raw message field is not wire.ProtectedString")
	}
	mailField, ok := reflect.TypeFor[SMTPInput]().FieldByName("MailFrom")
	if !ok || mailField.Type != protectedType {
		t.Fatal("MAIL FROM field is not wire.ProtectedString")
	}
	recipientsField, ok := reflect.TypeFor[SMTPInput]().FieldByName("RcptTo")
	if !ok || recipientsField.Type.Kind() != reflect.Slice ||
		recipientsField.Type.Elem() != protectedType {
		t.Fatal("RCPT TO field is not []wire.ProtectedString")
	}
}

// TestGeneratedRequestFormattingIsContentFree proves nested DTO formatting
// cannot disclose protected request bytes in plain or hexadecimal form.
func TestGeneratedRequestFormattingIsContentFree(t *testing.T) {
	t.Parallel()

	const marker = "DO-NOT-PRINT-RFC5322-OR-ENVELOPE"
	protected, err := wire.NewProtectedString(marker)
	if err != nil {
		t.Fatalf("construct protected value: %v", err)
	}
	request := ProcessRequest{
		ApiVersion: V1,
		Draft:      DraftIetfDkimDkim2Spec05,
		Message:    MessageInput{RawRfc5322Base64: protected},
		Smtp: SMTPInput{
			MailFrom: protected,
			RcptTo:   []wire.ProtectedString{protected},
		},
	}
	values := []any{
		request,
		&request,
		any(request),
		[]any{request, &request},
		map[string]any{"request": request},
		struct{ Request ProcessRequest }{Request: request},
	}
	encodedMarker := fmt.Sprintf("%x", []byte(marker))
	for _, format := range []string{"%s", "%q", "%v", "%+v", "%#v", "%x", "%p"} {
		for _, value := range values {
			output := fmt.Sprintf(format, value)
			if strings.Contains(output, marker) || strings.Contains(output, encodedMarker) {
				t.Fatalf("format %s disclosed protected request bytes", format)
			}
		}
	}
}
