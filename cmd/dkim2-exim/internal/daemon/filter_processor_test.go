package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

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
}

// SignMessage returns the configured generated signing response.
func (s *filterClientStub) SignMessage(_ context.Context, request generated.SignMessageJSONRequestBody, _ ...generated.RequestEditorFn) (*http.Response, error) {
	s.signCalls++
	s.signRequest = request
	if s.err != nil {
		return nil, s.err
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
