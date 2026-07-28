package testclient

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

const forbiddenResponseBody = `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","code":"forbidden","category":"request"}`
const testForbiddenCode = "forbidden"

const validProcessResponseBody = `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","verification":{"state":"PERMERROR","primary_reason":"malformed_message","scope":"current","historical_content":"not_evaluated","historical_signatures":"not_evaluated","custody_structure":"not_present","checks":[{"class":"message","reason":"malformed_message"}],"signature_sets":[]},"policy":{"mode":"strict","verdict":"reject","primary_reason":"protocol_permerror","do_not_modify":"not_evaluated","do_not_explode":"not_evaluated","dns_testing_effective":false,"feedback":{"requested":false,"relay_required":false,"history_coverage":"not_evaluated"},"findings":[{"reason":"protocol_permerror","severity":"permanent"}]},"replay":{"class":"not_checked"},"disposition":"reject","actions":[]}`

// captureDoer records one request and returns a deterministic response.
type captureDoer struct {
	mu       sync.Mutex
	requests []*http.Request
	response func(*http.Request) *http.Response
}

// Do records the request without retaining its protected body bytes.
func (d *captureDoer) Do(request *http.Request) (*http.Response, error) {
	d.mu.Lock()
	d.requests = append(d.requests, request)
	d.mu.Unlock()
	if d.response == nil {
		return nil, errors.New("private-fake-transport")
	}
	return d.response(request), nil
}

// lastRequest returns the last synchronized request.
func (d *captureDoer) lastRequest() *http.Request {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.requests) == 0 {
		return nil
	}
	return d.requests[len(d.requests)-1]
}

// TestNegativeBuilderFreezesClosedMutationShapes proves no generic sender exists.
func TestNegativeBuilderFreezesClosedMutationShapes(t *testing.T) {
	t.Parallel()
	var secret [32]byte
	for index := range secret {
		secret[index] = byte(index + 1)
	}
	for _, mutation := range []string{
		mutationMissingCapability, mutationDuplicateCapability, mutationEmptyCapability,
		mutationMismatchingCapability, mutationUnsupportedMedia, mutationMalformedJSON,
		mutationUnknownMember, mutationTruncatedBody, mutationBodyOverLimit,
		mutationUnsupportedMethod, mutationContaminatedTarget,
	} {
		mutation := mutation
		t.Run(mutation, func(t *testing.T) {
			t.Parallel()
			capability, _ := newCapability(secret)
			defer func() { _ = capability.Close() }()
			request, err := buildNegativeRequest(
				t.Context(), "http://127.0.0.1:8080", mutation, capability,
			)
			if err != nil || request.URL.Host != "127.0.0.1:8080" ||
				request.URL.Path != processPath {
				t.Fatal("closed negative mutation rejected or escaped authority")
			}
			values := request.Header.Values(capabilityHeader)
			switch mutation {
			case mutationMissingCapability:
				if len(values) != 0 {
					t.Fatal("missing mutation attached capability")
				}
			case mutationDuplicateCapability:
				if len(values) != 2 {
					t.Fatal("duplicate mutation did not create two fields")
				}
			default:
				if len(values) != 1 {
					t.Fatal("negative mutation did not attach one capability field")
				}
			}
			if mutation == mutationBodyOverLimit &&
				request.ContentLength != 47_878_317 {
				t.Fatal("body-over-limit mutation changed")
			}
		})
	}
	capability, _ := newCapability(secret)
	defer func() { _ = capability.Close() }()
	if _, err := buildNegativeRequest(
		t.Context(), "http://127.0.0.1:8080", "arbitrary", capability,
	); ExitClassOf(err) != ExitInternal {
		t.Fatal("generic negative mutation accepted")
	}
}

// TestNegativeExpectationIsBoundToMutation proves fixtures cannot redefine the
// daemon response expected for a closed request mutation.
func TestNegativeExpectationIsBoundToMutation(t *testing.T) {
	t.Parallel()
	if !validNegativeExpectation(mutationMissingCapability, http.StatusForbidden, testForbiddenCode) {
		t.Fatal("declared missing-capability expectation rejected")
	}
	for _, hostile := range []struct {
		mutation string
		status   int
		code     string
	}{
		{mutationMissingCapability, http.StatusInternalServerError, "internal_error"},
		{mutationUnsupportedMedia, http.StatusForbidden, testForbiddenCode},
		{"malformed_response", http.StatusBadRequest, expectedInvalidJSONCode},
	} {
		if validNegativeExpectation(hostile.mutation, hostile.status, hostile.code) {
			t.Fatal("mutation-independent expectation accepted")
		}
	}
}

// TestCallNegativeClassifiesTypedErrorAndKeepsMarkersPrivate proves raw flow.
func TestCallNegativeClassifiesTypedErrorAndKeepsMarkersPrivate(t *testing.T) {
	t.Parallel()
	doer := &captureDoer{
		response: func(_ *http.Request) *http.Response {
			return buildHostileResponse(http.StatusForbidden, mediaTypeJSON, forbiddenResponseBody)
		},
	}
	runtime, _ := NewRuntimeWithDoer("http://127.0.0.1:8080", doer)
	var secret [32]byte
	copy(secret[:], strings.Repeat("Q", 32))
	capability, _ := newCapability(secret)
	defer func() { _ = capability.Close() }()
	fact, err := runtime.CallNegative(t.Context(), mutationMissingCapability, capability)
	if err != nil || fact.Status != 403 || fact.Error == nil ||
		string(fact.Error.Code) != testForbiddenCode {
		t.Fatal("typed negative error rejected")
	}
	if request := doer.lastRequest(); request == nil || len(request.Header.Values(capabilityHeader)) != 0 {
		t.Fatal("missing-capability request shape changed")
	}
}

// TestNegativeResponseRejectsMalformedAndContradictoryContracts freezes fail-closed behavior.
func TestNegativeResponseRejectsMalformedAndContradictoryContracts(t *testing.T) {
	t.Parallel()
	for _, response := range []*http.Response{
		buildHostileResponse(http.StatusForbidden, "text/plain", forbiddenResponseBody),
		buildHostileResponse(http.StatusForbidden, mediaTypeJSON, `{`),
		buildHostileResponse(http.StatusForbidden, mediaTypeJSON,
			strings.Replace(forbiddenResponseBody, `"forbidden"`, `"internal_error"`, 1)),
	} {
		if _, err := classifyNegativeResponse(
			OperationProcess, response,
		); ExitClassOf(err) != ExitContract {
			t.Fatal("malformed negative response accepted")
		}
	}
}

// TestNegativeResponseRequiresStatusSpecificHeaders proves RFC 9110 method and
// retry metadata remain part of the closed response contract.
func TestNegativeResponseRequiresStatusSpecificHeaders(t *testing.T) {
	t.Parallel()
	methodBody := `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04",` +
		`"code":"method_not_allowed","category":"request"}`
	method := buildHostileResponse(http.StatusMethodNotAllowed, mediaTypeJSON, methodBody)
	method.Header.Del("Allow")
	if _, err := classifyNegativeResponse(
		OperationProcess, method,
	); ExitClassOf(err) != ExitContract {
		t.Fatal("405 without Allow accepted")
	}
	retryBody := `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04",` +
		`"code":"service_not_ready","category":"availability"}`
	retry := buildHostileResponse(http.StatusServiceUnavailable, mediaTypeJSON, retryBody)
	retry.Header.Del("Retry-After")
	if _, err := classifyNegativeResponse(
		OperationProcess, retry,
	); ExitClassOf(err) != ExitContract {
		t.Fatal("503 without Retry-After accepted")
	}
}

// TestPositiveProcessUsesGeneratedDTOAndStableProjection proves the ordinary authenticated flow.
func TestPositiveProcessUsesGeneratedDTOAndStableProjection(t *testing.T) {
	t.Parallel()
	doer := &captureDoer{
		response: func(_ *http.Request) *http.Response {
			return buildHostileResponse(http.StatusOK, mediaTypeJSON, validProcessResponseBody)
		},
	}
	runtime, _ := NewRuntimeWithDoer("http://127.0.0.1:8080", doer)
	var secret [32]byte
	copy(secret[:], strings.Repeat("K", 32))
	capability, _ := newCapability(secret)
	defer func() { _ = capability.Close() }()
	var output bytes.Buffer
	application := NewApplication(&output)
	state := "PERMERROR"
	disposition := "reject"
	policy := "reject"
	replay := "not_checked"
	planned := plannedCase{
		fixture: "fixture-process",
		value: fixtureCase{
			Case: "case-process", Kind: caseProcess,
			Process: &fixtureProcessInput{
				MessageBase64: "U3ViamVjdDogcHJpdmF0ZS1tYXJrZXINCg0KcHJpdmF0ZS1tYXJrZXI=",
				MailFrom:      "private-marker@example.test",
				Recipients:    []string{"private-recipient@example.test"},
			},
			Expect: fixtureExpectation{
				HTTPStatus: 200, Disposition: &disposition,
				VerificationState: &state, PolicyVerdict: &policy, ReplayClass: &replay,
			},
		},
	}
	if class := application.executePlannedCase(
		t.Context(), runtime, operationCapabilities{process: capability}, planned,
	); class != ExitOK {
		t.Fatal("positive generated process flow failed")
	}
	request := doer.lastRequest()
	if request == nil || request.Method != http.MethodPost ||
		request.URL.Path != processPath || len(request.Header.Values(capabilityHeader)) != 1 {
		t.Fatal("generated process request shape changed")
	}
	if strings.Contains(output.String(), "private") ||
		!strings.Contains(output.String(), `"disposition":"reject"`) {
		t.Fatal("stable process projection leaked protected input or lost typed output")
	}
}

// sequenceDoer returns one response per generated call.
type sequenceDoer struct {
	mu        sync.Mutex
	responses []*http.Response
}

// Do returns the next configured response.
func (d *sequenceDoer) Do(_ *http.Request) (*http.Response, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.responses) == 0 {
		return nil, errors.New("private-sequence-exhausted")
	}
	response := d.responses[0]
	d.responses = d.responses[1:]
	return response, nil
}

// TestSmokeUsesGeneratedHealthAndReadiness proves true and false readiness flows.
func TestSmokeUsesGeneratedHealthAndReadiness(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		expectReady bool
		readiness   *http.Response
	}{
		{
			name: "ready", expectReady: true,
			readiness: exactJSONResponse(http.StatusOK,
				`{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","status":"ready"}`),
		},
		{
			name: "not ready", expectReady: false,
			readiness: exactJSONResponse(http.StatusServiceUnavailable,
				`{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","code":"service_not_ready","category":"availability"}`),
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			doer := &sequenceDoer{responses: []*http.Response{
				exactJSONResponse(http.StatusOK, healthResponseBody),
				test.readiness,
			}}
			var output bytes.Buffer
			application := NewApplication(&output)
			application.newRuntime = func(_ Options) (*Runtime, error) {
				return NewRuntimeWithDoer("http://127.0.0.1:8080", doer)
			}
			if err := application.Smoke(DefaultOptions(), test.expectReady); err != nil {
				t.Fatal("valid smoke flow failed")
			}
			if !strings.Contains(output.String(), `"operation":"smoke","outcome":"match"`) {
				t.Fatal("smoke output changed")
			}
		})
	}
}

// exactJSONResponse constructs an exact metadata-bearing fake response.
func exactJSONResponse(status int, body string) *http.Response {
	return buildHostileResponse(status, mediaTypeJSON, body)
}

var _ io.Reader = repeatingByteReader{}
