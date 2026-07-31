package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/daemon/generated"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/ipc"
)

const testEvidenceLocator = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// processClientFunc supplies one independently controlled generated client call.
type processClientFunc func(context.Context, generated.ProcessMessageJSONRequestBody, ...generated.RequestEditorFn) (*http.Response, error)

// ProcessMessage calls the independently controlled generated process fixture.
func (f processClientFunc) ProcessMessage(ctx context.Context, body generated.ProcessMessageJSONRequestBody, editors ...generated.RequestEditorFn) (*http.Response, error) {
	return f(ctx, body, editors...)
}

// evidencePublisherStub captures exact accepted receive-time authority.
type evidencePublisherStub struct {
	calls    int
	incoming adapter.IncomingEvidence
	locator  string
	err      error
}

// failOpenWarningStub records one mandatory bounded warning attempt.
type failOpenWarningStub struct {
	calls int
	err   error
	panic bool
}

// RecordFailOpen returns one test-controlled warning result.
func (s *failOpenWarningStub) RecordFailOpenContext(context.Context) error {
	s.calls++
	if s.panic {
		panic("sensitive warning detail")
	}
	return s.err
}

// PublishIncoming returns one test-controlled opaque locator.
func (s *evidencePublisherStub) PublishIncoming(_ context.Context, incoming adapter.IncomingEvidence) (string, error) {
	s.calls++
	s.incoming = incoming
	return s.locator, s.err
}

// TestProcessorUsesGeneratedProcessAndAdmitsCompleteInboundPlan proves the
// generated client request, strict raw response admission, and DXI1 mapping.
func TestProcessorUsesGeneratedProcessAndAdmitsCompleteInboundPlan(t *testing.T) {
	encoded, err := json.Marshal(validProcessFixture())
	if err != nil {
		t.Fatal("process fixture encoding failed")
	}
	called := false
	processor, err := NewProcessor(processClientFunc(func(
		ctx context.Context,
		request generated.ProcessMessageJSONRequestBody,
		_ ...generated.RequestEditorFn,
	) (*http.Response, error) {
		called = true
		if ctx == nil || request.Reporting == nil || request.Reporting.AuthservId != "mx.example.test" ||
			request.Message.Fidelity == nil || *request.Message.Fidelity != generated.EximLocalScanObservedCrlf {
			t.Fatal("generated process request lost inbound authority")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{contentTypeHeader: []string{jsonMediaType}},
			Body:       io.NopCloser(bytes.NewReader(encoded)),
		}, nil
	}), "mx.example.test")
	if err != nil {
		t.Fatal("processor construction failed")
	}
	input, err := adapter.NewLocalScanRequest(
		bytes.Repeat([]byte{'a'}, ipc.BuildIDBytes), adapter.SessionSMTP, nil, 0, nil, nil,
		[]byte("<sender@example.test>"), [][]byte{[]byte("<recipient@example.test>")},
		[][]byte{
			[]byte("Authentication-Results: mx.example.test; dkim=fail\n"),
			[]byte("Subject: test\n"),
		}, []byte("body\n"),
	)
	if err != nil {
		t.Fatal("input construction failed")
	}
	response, err := processor.Process(context.Background(), input)
	if err != nil || !called || response.Decision() != ipc.DecisionAccept ||
		!bytes.Equal(response.AddValue(), []byte("mx.example.test; dkim2=pass")) {
		t.Fatal("strict generated process mapping failed")
	}
	if got := response.Removals(); len(got) != 1 || got[0] != 1 {
		t.Fatal("local RFC 8601 claim was not selected for descending removal")
	}
}

// TestProcessorPublishesAcceptedRevisionEvidence proves local-scan acceptance
// returns a locator only after exact receive-time authority is persisted.
func TestProcessorPublishesAcceptedRevisionEvidence(t *testing.T) {
	encoded, err := json.Marshal(validProcessFixture())
	if err != nil {
		t.Fatal("process fixture encoding failed")
	}
	publisher := &evidencePublisherStub{
		locator: testEvidenceLocator,
	}
	processor, err := NewProcessorWithEvidence(
		processClientFunc(func(
			context.Context,
			generated.ProcessMessageJSONRequestBody,
			...generated.RequestEditorFn,
		) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{contentTypeHeader: []string{jsonMediaType}},
				Body:       io.NopCloser(bytes.NewReader(encoded)),
			}, nil
		}),
		"mx.example.test",
		publisher,
	)
	if err != nil {
		t.Fatal("evidence processor construction failed")
	}
	input, err := adapter.NewLocalScanRequest(
		bytes.Repeat([]byte{'a'}, ipc.BuildIDBytes),
		adapter.SessionSMTP,
		nil,
		0,
		nil,
		nil,
		[]byte("<incoming@example.test>"),
		[][]byte{[]byte("<received@example.test>")},
		[][]byte{[]byte("Subject: evidence\n")},
		[]byte("body\n"),
	)
	if err != nil {
		t.Fatal("input construction failed")
	}
	response, err := processor.Process(context.Background(), input)
	if err != nil || publisher.calls != 1 ||
		string(response.Locator()) != publisher.locator ||
		string(publisher.incoming.MailFrom()) != "<incoming@example.test>" {
		t.Fatal("accepted processing did not publish exact revision evidence")
	}
}

// TestProcessorFailOpenPublishesEvidenceBeforeAcceptance proves the sole
// reached-service dial-failure path remains unchanged, visible, and evidence-safe.
func TestProcessorFailOpenPublishesEvidenceBeforeAcceptance(t *testing.T) {
	publisher := &evidencePublisherStub{
		locator: testEvidenceLocator,
	}
	warning := &failOpenWarningStub{}
	processor, err := NewProcessorWithPolicy(
		processClientFunc(func(
			context.Context,
			generated.ProcessMessageJSONRequestBody,
			...generated.RequestEditorFn,
		) (*http.Response, error) {
			return nil, &net.OpError{
				Op: transportDialOperation, Net: "tcp", Err: errors.New("unavailable"),
			}
		}),
		"mx.example.test",
		publisher,
		InboundFailOpen,
		warning,
	)
	if err != nil {
		t.Fatal("fail-open processor construction failed")
	}
	input := testLocalScanRequest(t, [][]byte{[]byte("Subject: evidence\n")})
	response, err := processor.Process(context.Background(), input)
	if err != nil || response.Decision() != ipc.DecisionAccept ||
		len(response.Removals()) != 0 || len(response.AddValue()) != 0 ||
		string(response.Locator()) != publisher.locator ||
		publisher.calls != 1 || warning.calls != 1 {
		t.Fatal("reached-service availability failure did not fail open safely")
	}
}

// TestProcessorFailOpenExclusionsRemainClosed proves contract failures, forged
// local claims, response receipt, evidence failure, and warning failure cannot open.
func TestProcessorFailOpenExclusionsRemainClosed(t *testing.T) {
	dialFailure := &net.OpError{
		Op: transportDialOperation, Net: "tcp", Err: errors.New("unavailable"),
	}
	tests := []struct {
		name         string
		headers      [][]byte
		response     *http.Response
		processErr   error
		publishErr   error
		warningErr   error
		warningPanic bool
	}{
		{
			name:       "contract error",
			headers:    [][]byte{[]byte("Subject: contract\n")},
			processErr: errors.New("contract"),
		},
		{
			name: "forged local authentication results",
			headers: [][]byte{
				[]byte("Authentication-Results: mx.example.test; dkim=pass\n"),
			},
			processErr: dialFailure,
		},
		{
			name:       "response received",
			headers:    [][]byte{[]byte("Subject: response\n")},
			response:   &http.Response{Body: io.NopCloser(bytes.NewReader(nil))},
			processErr: dialFailure,
		},
		{
			name:       "evidence publication failure",
			headers:    [][]byte{[]byte("Subject: evidence\n")},
			processErr: dialFailure,
			publishErr: errors.New("store"),
		},
		{
			name:       "warning failure",
			headers:    [][]byte{[]byte("Subject: warning\n")},
			processErr: dialFailure,
			warningErr: errors.New("sink"),
		},
		{
			name:         "warning panic",
			headers:      [][]byte{[]byte("Subject: panic\n")},
			processErr:   dialFailure,
			warningPanic: true,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			publisher := &evidencePublisherStub{
				locator: testEvidenceLocator,
				err:     testCase.publishErr,
			}
			warning := &failOpenWarningStub{
				err:   testCase.warningErr,
				panic: testCase.warningPanic,
			}
			processor, err := NewProcessorWithPolicy(
				processClientFunc(func(
					context.Context,
					generated.ProcessMessageJSONRequestBody,
					...generated.RequestEditorFn,
				) (*http.Response, error) {
					return testCase.response, testCase.processErr
				}),
				"mx.example.test",
				publisher,
				InboundFailOpen,
				warning,
			)
			if err != nil {
				t.Fatal("fail-open exclusion processor construction failed")
			}
			response, processErr := processor.Process(
				context.Background(),
				testLocalScanRequest(t, testCase.headers),
			)
			if processErr == nil || response.Decision() == ipc.DecisionAccept {
				t.Fatal("excluded daemon failure was accepted")
			}
		})
	}
}

// testLocalScanRequest creates one exact valid receive-time fixture.
func testLocalScanRequest(t *testing.T, headers [][]byte) adapter.LocalScanRequest {
	t.Helper()
	input, err := adapter.NewLocalScanRequest(
		bytes.Repeat([]byte{'a'}, ipc.BuildIDBytes),
		adapter.SessionSMTP,
		nil,
		0,
		nil,
		nil,
		[]byte("<incoming@example.test>"),
		[][]byte{[]byte("<received@example.test>")},
		headers,
		[]byte("body\n"),
	)
	if err != nil {
		t.Fatal("local-scan fixture construction failed")
	}
	return input
}
