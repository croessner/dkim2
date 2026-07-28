package testclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const signAcceptResponse = `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","operation":"sign","result":"pass","disposition":"accept","actions":[{"type":"add_header","name":"Message-Instance","value":"v=1; i=1; h=sha256:synthetic"},{"type":"add_header","name":"DKIM2-Signature","value":"v=1; a=ed25519-sha256; d=example.test; s=test; b=synthetic"}]}`
const reviseContinueResponse = `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","operation":"revise","result":"pass","disposition":"continue","actions":[]}`
const operationFixtureMessageBase64 = "U3ViamVjdDogdGVzdA0KDQpib2R5DQo="
const operationFixtureRecipient = "<recipient@example.test>"
const operationFixtureDomain = "example.test"

// TestGeneratedSignAndReviseRequestsPreserveDistinctFacts proves generated DTO use.
func TestGeneratedSignAndReviseRequestsPreserveDistinctFacts(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name      string
		operation Operation
		response  string
		path      string
		call      func(*Runtime, *Capability) (ResponseFact, error)
	}{
		{
			name: "sign", operation: OperationSign,
			response: signAcceptResponse, path: signPath,
			call: func(runtime *Runtime, capability *Capability) (ResponseFact, error) {
				request, err := generatedSignRequest(fixtureSignInput{
					MessageBase64: operationFixtureMessageBase64,
					MailFrom:      "<sender@example.test>", Recipients: []string{operationFixtureRecipient},
					Tenant: "tenant-a", Domain: operationFixtureDomain,
				})
				if err != nil {
					return ResponseFact{}, err
				}
				return runtime.CallSign(t.Context(), request, capability.EditRequest)
			},
		},
		{
			name: "revise", operation: OperationRevise,
			response: reviseContinueResponse, path: revisePath,
			call: func(runtime *Runtime, capability *Capability) (ResponseFact, error) {
				request, err := generatedReviseRequest(fixtureReviseInput{
					MessageBase64: operationFixtureMessageBase64,
					MailFrom:      "<out@example.test>", Recipients: []string{operationFixtureRecipient},
					IncomingMailFrom:   "<in@example.test>",
					IncomingRecipients: []string{operationFixtureRecipient},
					Tenant:             "tenant-a", Domain: operationFixtureDomain,
				})
				if err != nil {
					return ResponseFact{}, err
				}
				return runtime.CallRevise(t.Context(), request, capability.EditRequest)
			},
		},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			doer := &captureDoer{response: func(_ *http.Request) *http.Response {
				return buildHostileResponse(http.StatusOK, mediaTypeJSON, testCase.response)
			}}
			client, err := NewRuntimeWithDoer("http://127.0.0.1:8080", doer)
			if err != nil {
				t.Fatal("runtime construction failed")
			}
			var value [32]byte
			value[0] = byte(len(testCase.name))
			capability, _ := newCapability(value)
			capability.operation = testCase.operation
			defer func() { _ = capability.Close() }()
			fact, err := testCase.call(client, capability)
			if err != nil || fact.Operation != testCase.operation ||
				(fact.Sign != nil) != (testCase.operation == OperationSign) ||
				(fact.Revise != nil) != (testCase.operation == OperationRevise) {
				t.Fatal("generated operation fact lost route correlation")
			}
			request := doer.lastRequest()
			if request == nil || request.URL.Path != testCase.path ||
				len(request.Header.Values(capabilityHeader)) != 1 {
				t.Fatal("generated request escaped its declared route")
			}
			var document map[string]json.RawMessage
			if json.NewDecoder(request.Body).Decode(&document) != nil ||
				document["api_version"] == nil || document["draft"] == nil ||
				document["message"] == nil || document["smtp"] == nil ||
				document["context"] == nil {
				t.Fatal("generated request body lost required DTO members")
			}
		})
	}
}

// TestOperationResponseMatrixRejectsContradictions freezes complete response rules.
func TestOperationResponseMatrixRejectsContradictions(t *testing.T) {
	t.Parallel()
	for _, response := range []string{
		strings.Replace(signAcceptResponse, `"operation":"sign"`, `"operation":"revise"`, 1),
		strings.Replace(signAcceptResponse, `"disposition":"accept"`, `"disposition":"reject"`, 1),
		strings.Replace(signAcceptResponse,
			`[{"type":"add_header","name":"Message-Instance","value":"v=1; i=1; h=sha256:synthetic"},{"type":"add_header","name":"DKIM2-Signature","value":"v=1; a=ed25519-sha256; d=example.test; s=test; b=synthetic"}]`,
			`[{"type":"add_header","name":"DKIM2-Signature","value":"v=1; a=ed25519-sha256; d=example.test; s=test; b=synthetic"}]`, 1),
		strings.Replace(signAcceptResponse, `"actions":`, `"unknown":true,"actions":`, 1),
		strings.Replace(signAcceptResponse, `"actions":`, `"actions":[],"actions":`, 1),
		strings.Replace(signAcceptResponse, `,"actions":[`, `,"missing":[`, 1),
		strings.Replace(signAcceptResponse, "v=1; i=1; h=sha256:synthetic", "bad\r\nvalue", 1),
	} {
		response := buildHostileResponse(http.StatusOK, mediaTypeJSON, response)
		if _, err := classifyResponse(OperationSign, response); ExitClassOf(err) != ExitContract {
			t.Fatal("contradictory operation response accepted")
		}
	}
}

// TestOperationFixturesRejectVersionFidelityAndBase64Contradictions proves
// offline validation closes every operation input before protected access.
func TestOperationFixturesRejectVersionFidelityAndBase64Contradictions(t *testing.T) {
	t.Parallel()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("operation fixture source unavailable")
	}
	path := filepath.Join(
		filepath.Dir(filepath.Dir(filepath.Dir(source))),
		"testdata", "fixtures", draftVersion, "sign.json",
	)
	input, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("operation fixture unavailable")
	}
	for _, mutation := range []func(string) string{
		func(value string) string {
			return strings.Replace(
				value,
				`"draft": "draft-ietf-dkim-dkim2-spec-04"`,
				`"draft": "draft-ietf-dkim-dkim2-spec-05"`,
				1,
			)
		},
		func(value string) string {
			return strings.Replace(
				value,
				`"raw_rfc5322_base64": "`+operationFixtureMessageBase64+`"`,
				`"raw_rfc5322_base64": "***"`,
				1,
			)
		},
		func(value string) string {
			return strings.Replace(
				value,
				`"fidelity": "raw_rfc5322"`,
				`"fidelity": "unknown"`,
				1,
			)
		},
		func(value string) string {
			return strings.Replace(
				value,
				"        \"fidelity\": \"raw_rfc5322\",\n",
				"",
				1,
			)
		},
		func(value string) string {
			return strings.Replace(
				value,
				`"tenant": "tenant-a"`,
				`"unknown": true, "tenant": "tenant-a"`,
				1,
			)
		},
		func(value string) string {
			return strings.Replace(
				value,
				`"tenant": "tenant-a"`,
				`"tenant": "tenant-a", "tenant": "tenant-a"`,
				1,
			)
		},
	} {
		if _, _, decodeErr := decodeFixture(
			[]byte(mutation(string(input))),
		); ExitClassOf(decodeErr) != ExitFixture {
			t.Fatal("contradictory operation fixture accepted")
		}
	}
}

// TestOperationResponseLimitFailsClosed proves a generated success cannot
// exceed the same bounded response owner used by process.
func TestOperationResponseLimitFailsClosed(t *testing.T) {
	t.Parallel()
	response := buildHostileResponse(
		http.StatusOK,
		mediaTypeJSON,
		strings.Repeat("x", int(processBodyLimit)+1),
	)
	if _, err := classifyResponse(
		OperationSign,
		response,
	); ExitClassOf(err) != ExitContract {
		t.Fatal("oversized operation response accepted")
	}
}

// TestOperationResponseAcceptsDocumentedNoMutationAndRevisePlans freezes daemon parity.
func TestOperationResponseAcceptsDocumentedNoMutationAndRevisePlans(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		operation Operation
		response  string
	}{
		{OperationSign, `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","operation":"sign","result":"pass","disposition":"continue","actions":[]}`},
		{OperationRevise, `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","operation":"revise","result":"pass","disposition":"accept","actions":[{"type":"add_header","name":"DKIM2-Signature","value":"v=1; b=unchanged"}]}`},
		{OperationRevise, `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","operation":"revise","result":"pass","disposition":"accept","actions":[{"type":"add_header","name":"Message-Instance","value":"v=1; i=2"},{"type":"add_header","name":"DKIM2-Signature","value":"v=1; b=changed"}]}`},
	} {
		response := buildHostileResponse(http.StatusOK, mediaTypeJSON, testCase.response)
		if _, err := classifyResponse(testCase.operation, response); err != nil {
			t.Fatal("documented operation outcome rejected")
		}
	}
}

// TestOfflineOperationValidationDoesNotAcquireCapabilitiesOrRuntime proves
// every fixture finishes offline admission before protected or network work.
func TestOfflineOperationValidationDoesNotAcquireCapabilitiesOrRuntime(t *testing.T) {
	t.Parallel()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("operation fixture source unavailable")
	}
	fixtures := filepath.Join(
		filepath.Dir(filepath.Dir(filepath.Dir(source))),
		"testdata", "fixtures", draftVersion,
	)
	var output strings.Builder
	application := NewApplication(&output)
	application.newRuntime = func(Options) (*Runtime, error) {
		panic("offline validation acquired runtime")
	}
	options := DefaultOptions()
	options.ServerURL = "http://127.0.0.1:1"
	options.CapabilityFile = filepath.Join(t.TempDir(), "missing-process")
	options.SignCapabilityFile = filepath.Join(t.TempDir(), "missing-sign")
	options.ReviseCapabilityFile = filepath.Join(t.TempDir(), "missing-revise")
	if err := application.Validate(options, []string{
		filepath.Join(fixtures, "process-report.json"),
		filepath.Join(fixtures, "sign.json"),
		filepath.Join(fixtures, "revise.json"),
	}); err != nil {
		t.Fatal("offline operation validation accessed a protected or network dependency")
	}
}

// TestFixtureRejectsExtraneousOrMissingActionExpectations proves closed cases.
func TestFixtureRejectsExtraneousOrMissingActionExpectations(t *testing.T) {
	t.Parallel()
	hostileHealth := strings.Replace(
		validHealthFixture,
		`"health_status":"alive"`,
		`"health_status":"alive","actions":[]`,
		1,
	)
	if _, _, err := decodeFixture([]byte(hostileHealth)); ExitClassOf(err) != ExitFixture {
		t.Fatal("health fixture accepted action expectation")
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source unavailable")
	}
	processPath := filepath.Join(
		filepath.Dir(filepath.Dir(filepath.Dir(source))),
		"testdata", "fixtures", draftVersion, "process.json",
	)
	process, err := os.ReadFile(processPath)
	if err != nil {
		t.Fatal("process fixture unavailable")
	}
	missing := strings.Replace(string(process), ",\n        \"actions\": []", "", 1)
	if _, _, err := decodeFixture([]byte(missing)); ExitClassOf(err) != ExitFixture {
		t.Fatal("process fixture accepted missing action expectation")
	}
}

// TestDuplicateCapabilityBytesFailBeforeRuntime proves operation separation.
func TestDuplicateCapabilityBytesFailBeforeRuntime(t *testing.T) {
	directory := t.TempDir()
	processCapability := filepath.Join(directory, "process-capability")
	signCapability := filepath.Join(directory, "sign-capability")
	for _, path := range []string{processCapability, signCapability} {
		if err := os.WriteFile(path, []byte(strings.Repeat("D", 32)), 0o600); err != nil {
			t.Fatal("write capability")
		}
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source unavailable")
	}
	fixtures := filepath.Join(
		filepath.Dir(filepath.Dir(filepath.Dir(source))),
		"testdata", "fixtures", draftVersion,
	)
	var runtimeCalls int
	application := NewApplication(io.Discard)
	application.newRuntime = func(Options) (*Runtime, error) {
		runtimeCalls++
		return nil, NewExitError(ExitInternal)
	}
	options := DefaultOptions()
	options.CapabilityFile = processCapability
	options.SignCapabilityFile = signCapability
	err := application.Run(options, []string{
		filepath.Join(fixtures, "process.json"),
		filepath.Join(fixtures, "sign.json"),
	})
	if ExitClassOf(err) != ExitCapability || runtimeCalls != 0 {
		t.Fatal("duplicate operation capabilities reached runtime")
	}
}

// TestCapabilitiesAreDistinctUsesConstantTimeValueComparison checks the local seam.
func TestCapabilitiesAreDistinctUsesConstantTimeValueComparison(t *testing.T) {
	t.Parallel()
	var first, second [32]byte
	first[0] = 1
	second[0] = 2
	left, _ := newCapability(first)
	right, _ := newCapability(second)
	duplicate, _ := newCapability(first)
	defer func() {
		_ = left.Close()
		_ = right.Close()
		_ = duplicate.Close()
	}()
	if !capabilitiesAreDistinct(left, right) ||
		capabilitiesAreDistinct(left, duplicate) {
		t.Fatal("capability separation comparison changed")
	}
}

// TestOperationResponseTimeoutRemainsContentFree freezes timeout classification.
func TestOperationResponseTimeoutRemainsContentFree(t *testing.T) {
	t.Parallel()
	runtime, _ := NewRuntimeWithDoer("http://127.0.0.1:8080", &captureDoer{})
	ctx, cancel := context.WithTimeout(t.Context(), time.Nanosecond)
	defer cancel()
	var value [32]byte
	value[0] = 1
	capability, _ := newCapability(value)
	capability.operation = OperationSign
	defer func() { _ = capability.Close() }()
	request, _ := generatedSignRequest(fixtureSignInput{
		MessageBase64: "", MailFrom: "", Recipients: []string{""},
		Tenant: "test", Domain: operationFixtureDomain,
	})
	if _, err := runtime.CallSign(
		ctx, request, capability.EditRequest,
	); ExitClassOf(err) != ExitTransport {
		t.Fatal("operation timeout classification changed")
	}
}
