package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/daemon/generated"
)

// filterClientStub captures generated sign/revise request ownership.
type filterClientStub struct {
	response               []byte
	signCalls, reviseCalls int
	signRequest            generated.SignMessageJSONRequestBody
	reviseRequest          generated.ReviseMessageJSONRequestBody
	status                 int
	contentType            string
	err                    error
	rawResponse            *http.Response
}

// TestFilterProcessorAcceptsRealSignNoContent proves the generated HTTP client
// projects authoritative signing non-applicability into an immutable no-op plan.
func TestFilterProcessorAcceptsRealSignNoContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer func() { _ = request.Body.Close() }()
		if request.Method != http.MethodPost || request.URL.Path != "/v1/sign" {
			t.Error("generated sign client escaped its route")
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Connection", "close")
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	client, err := generated.NewClient(server.URL, generated.WithHTTPClient(&http.Client{Timeout: time.Second}))
	if err != nil {
		t.Fatal("generated filter client construction failed")
	}
	processor, err := NewFilterProcessor(client, "tenant", "example.test")
	if err != nil {
		t.Fatal("filter no-content processor construction failed")
	}
	request := testSignFilterRequest(t)
	plan, err := processor.Process(t.Context(), request)
	if err != nil || plan.Operation() != adapter.OperationSign ||
		plan.Result() != adapter.ResultNone || plan.Disposition() != adapter.DispositionContinue ||
		len(plan.Actions()) != 0 {
		t.Fatalf("real sign 204 failed: plan=%v err=%v", plan, err)
	}
}

// TestFilterProcessorRejectsReviseAndMalformedNoContent proves 204 remains
// bound to sign and cannot carry representation state.
func TestFilterProcessorRejectsReviseAndMalformedNoContent(t *testing.T) {
	tests := append(noContentResponseMutations(), noContentResponseMutation{
		name: "revise",
		response: func(string) *http.Response {
			return exactNoContentHTTPResponse("/v1/revise")
		},
	})
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			response := testCase.response("/v1/sign")
			if testCase.name == "wrong route" {
				response.Request.URL = mustParseRequestPath("/v1/process")
			}
			client := &filterClientStub{rawResponse: response}
			processor, err := NewFilterProcessor(client, "tenant", "example.test")
			if err != nil {
				t.Fatal("malformed filter fixture construction failed")
			}
			request := testSignFilterRequest(t)
			if testCase.name == "revise" {
				request = testReviseFilterRequest(t)
			}
			wantClass := testCase.class
			if wantClass == 0 {
				wantClass = adapter.FailureContract
			}
			if _, processErr := processor.Process(t.Context(), request); !testAdapterFailureClass(processErr, wantClass) {
				t.Fatal("unsupported or malformed filter 204 was admitted")
			}
		})
	}
}

// mustParseRequestPath returns one relative request URL for raw-response tests.
func mustParseRequestPath(path string) *url.URL {
	value, err := url.Parse(path)
	if err != nil {
		panic("invalid test URL")
	}
	return value
}

// testSignFilterRequest returns one valid immutable originator fixture.
func testSignFilterRequest(t *testing.T) adapter.FilterRequest {
	t.Helper()
	outgoing, err := adapter.NewOutgoingEnvelope(
		[]byte("<sender@example.test>"), []byte("<recipient@example.test>"),
	)
	if err != nil {
		t.Fatal("test outgoing envelope construction failed")
	}
	request, err := adapter.NewSignRequest([]byte("Subject: filter\n\nbody\n"), outgoing)
	if err != nil {
		t.Fatal("test sign request construction failed")
	}
	return request
}

// testReviseFilterRequest returns one valid immutable ordinary-transit fixture.
func testReviseFilterRequest(t *testing.T) adapter.FilterRequest {
	t.Helper()
	outgoing, err := adapter.NewOutgoingEnvelope(
		[]byte("<sender@example.test>"), []byte("<recipient@example.test>"),
	)
	if err != nil {
		t.Fatal("test outgoing envelope construction failed")
	}
	incoming, err := adapter.NewIncomingEvidence(
		[]byte("<incoming@example.test>"),
		[][]byte{[]byte("<received@example.test>")},
		adapter.SessionSMTP,
	)
	if err != nil {
		t.Fatal("test incoming evidence construction failed")
	}
	request, err := adapter.NewReviseRequest(
		[]byte("Subject: filter\n\nbody\n"), outgoing, incoming,
	)
	if err != nil {
		t.Fatal("test revise request construction failed")
	}
	return request
}

// SignMessage returns the configured generated signing response.
func (s *filterClientStub) SignMessage(_ context.Context, request generated.SignMessageJSONRequestBody, _ ...generated.RequestEditorFn) (*http.Response, error) {
	s.signCalls++
	s.signRequest = request
	if s.err != nil {
		return nil, s.err
	}
	if s.rawResponse != nil {
		return s.rawResponse, nil
	}
	return configuredJSONResponse(s.response, s.status, s.contentType), nil
}

// ReviseMessage returns the configured generated revision response.
func (s *filterClientStub) ReviseMessage(_ context.Context, request generated.ReviseMessageJSONRequestBody, _ ...generated.RequestEditorFn) (*http.Response, error) {
	s.reviseCalls++
	s.reviseRequest = request
	if s.err != nil {
		return nil, s.err
	}
	if s.rawResponse != nil {
		return s.rawResponse, nil
	}
	return configuredJSONResponse(s.response, s.status, s.contentType), nil
}

// configuredJSONResponse creates one raw response with test-controlled status
// and media type while retaining valid defaults.
func configuredJSONResponse(body []byte, status int, contentType string) *http.Response {
	if status == 0 {
		status = http.StatusOK
	}
	if contentType == "" {
		contentType = jsonMediaType
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{contentTypeHeader: []string{contentType}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

// TestFilterProcessorUsesOnlyTheSelectedGeneratedOperation proves no sign/revise fallback.
func TestFilterProcessorUsesOnlyTheSelectedGeneratedOperation(t *testing.T) {
	response, err := json.Marshal(validOperationFixture())
	if err != nil {
		t.Fatal("operation fixture encoding failed")
	}
	client := &filterClientStub{response: response}
	processor, err := NewFilterProcessor(client, "tenant", "example.test")
	if err != nil {
		t.Fatal("filter processor construction failed")
	}
	outgoing, err := adapter.NewOutgoingEnvelope([]byte("<sender@example.test>"), []byte("<recipient@example.test>"))
	if err != nil {
		t.Fatal("outgoing authority construction failed")
	}
	request, err := adapter.NewSignRequest([]byte("Subject: filter\n\nbody\n"), outgoing)
	if err != nil {
		t.Fatal("filter request construction failed")
	}
	plan, err := processor.Process(context.Background(), request)
	if err != nil || plan.Operation() != adapter.OperationSign || client.signCalls != 1 || client.reviseCalls != 0 {
		t.Fatal("filter processor selected an incorrect daemon operation")
	}
}

// TestFilterProcessorKeepsRevisionAuthoritiesDistinct proves generated request
// mapping cannot alias incoming evidence with the outgoing transport envelope.
func TestFilterProcessorKeepsRevisionAuthoritiesDistinct(t *testing.T) {
	responseValue := validOperationFixture()
	responseValue.Operation = generated.Revise
	responseValue.Actions = generated.ActionPlan{
		{Type: generated.AddHeader, Name: generated.DKIM2Signature, Value: " i=2; s=a"},
	}
	response, _ := json.Marshal(responseValue)
	client := &filterClientStub{response: response}
	processor, _ := NewFilterProcessor(client, "tenant", "example.test")
	outgoing, _ := adapter.NewOutgoingEnvelope(
		[]byte("<outgoing@example.test>"),
		[]byte("<batch@example.test>"),
	)
	incoming, _ := adapter.NewIncomingEvidence(
		[]byte("<incoming@example.test>"),
		[][]byte{[]byte("<received@example.test>")},
		adapter.SessionSMTP,
	)
	request, _ := adapter.NewReviseRequest(
		[]byte("Subject: filter\n\nbody\n"),
		outgoing,
		incoming,
	)
	if _, err := processor.Process(context.Background(), request); err != nil {
		t.Fatal("revision processing failed")
	}
	outgoingSender, _ := client.reviseRequest.Smtp.MailFrom.Bytes()
	outgoingRecipient, _ := client.reviseRequest.Smtp.RcptTo[0].Bytes()
	incomingSender, _ := client.reviseRequest.IncomingSmtp.MailFrom.Bytes()
	incomingRecipient, _ := client.reviseRequest.IncomingSmtp.RcptTo[0].Bytes()
	defer clear(outgoingSender)
	defer clear(outgoingRecipient)
	defer clear(incomingSender)
	defer clear(incomingRecipient)
	if string(outgoingSender) != "<outgoing@example.test>" ||
		string(outgoingRecipient) != "<batch@example.test>" ||
		string(incomingSender) != "<incoming@example.test>" ||
		string(incomingRecipient) != "<received@example.test>" {
		t.Fatal("generated revision request conflated envelope authorities")
	}
}

// TestFilterProcessorRejectsRawResponseFailures proves status, media type,
// malformed JSON, absent required fields, and overflow all fail closed.
func TestFilterProcessorRejectsRawResponseFailures(t *testing.T) {
	valid, _ := json.Marshal(validOperationFixture())
	tests := []filterClientStub{
		{response: valid, status: http.StatusServiceUnavailable},
		{response: valid, contentType: "text/plain"},
		{response: []byte("{")},
		{response: []byte(`{"api_version":"v1"}`)},
		{response: bytes.Repeat([]byte{'x'}, maxResponseBytes+1)},
	}
	for index := range tests {
		client := &tests[index]
		processor, _ := NewFilterProcessor(client, "tenant", "example.test")
		outgoing, _ := adapter.NewOutgoingEnvelope(
			[]byte("<sender@example.test>"),
			[]byte("<recipient@example.test>"),
		)
		request, _ := adapter.NewSignRequest(
			[]byte("Subject: filter\n\nbody\n"),
			outgoing,
		)
		if _, err := processor.Process(context.Background(), request); err == nil {
			t.Fatal("invalid raw daemon response was admitted")
		}
	}
}

// TestFilterProcessorClassifiesDeadline proves a timed-out generated call is
// never mistaken for an unchanged-delivery result.
func TestFilterProcessorClassifiesDeadline(t *testing.T) {
	client := &filterClientStub{err: context.DeadlineExceeded}
	processor, _ := NewFilterProcessor(client, "tenant", "example.test")
	outgoing, _ := adapter.NewOutgoingEnvelope(
		[]byte("<sender@example.test>"),
		[]byte("<recipient@example.test>"),
	)
	request, _ := adapter.NewSignRequest(
		[]byte("Subject: filter\n\nbody\n"),
		outgoing,
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := processor.Process(ctx, request)
	var classified *adapter.Error
	if !errors.As(err, &classified) || classified.Class() != adapter.FailureTimeout {
		t.Fatal("deadline was not classified as a closed timeout")
	}
}
