package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

// TestProcessorAcceptsRealNoContentAndScrubsLocalClaims proves the generated
// client preserves the bodyless applicability result while RFC 8601 cleanup
// remains mandatory on the inbound Exim trajectory.
func TestProcessorAcceptsRealNoContentAndScrubsLocalClaims(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer func() { _ = request.Body.Close() }()
		if request.Method != http.MethodPost || request.URL.Path != "/v1/process" {
			t.Error("generated process client escaped its route")
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Connection", "close")
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	client, err := generated.NewClient(server.URL, generated.WithHTTPClient(&http.Client{Timeout: time.Second}))
	if err != nil {
		t.Fatal("generated process client construction failed")
	}
	publisher := &evidencePublisherStub{locator: testEvidenceLocator}
	processor, err := NewProcessorWithEvidence(client, "mx.example.test", publisher)
	if err != nil {
		t.Fatal("process no-content processor construction failed")
	}
	input := testLocalScanRequest(t, [][]byte{
		[]byte("Authentication-Results: mx.example.test; forged=pass\n"),
		[]byte("Subject: unsigned\n"),
	})
	processContext, outcome := adapter.WithOutcome(t.Context())
	response, err := processor.Process(processContext, input)
	if err != nil || response.Decision() != ipc.DecisionAccept ||
		len(response.AddValue()) != 0 || string(response.Locator()) != testEvidenceLocator ||
		publisher.calls != 1 || outcome.FailOpen() {
		t.Fatalf("real process 204 failed: response=%v err=%v", response, err)
	}
	if removals := response.Removals(); len(removals) != 1 || removals[0] != 1 {
		t.Fatal("not-applicable process did not scrub the forged local claim")
	}
}

// TestProcessorRejectsMalformedNoContent proves process applicability cannot
// smuggle representation state or weaken the close-delimited wire contract.
func TestProcessorRejectsMalformedNoContent(t *testing.T) {
	tests := noContentResponseMutations()
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			processor, err := NewProcessor(processClientFunc(func(
				context.Context,
				generated.ProcessMessageJSONRequestBody,
				...generated.RequestEditorFn,
			) (*http.Response, error) {
				return testCase.response("/v1/process"), nil
			}), "mx.example.test")
			if err != nil {
				t.Fatal("malformed process fixture construction failed")
			}
			wantClass := testCase.class
			if wantClass == 0 {
				wantClass = adapter.FailureContract
			}
			if _, processErr := processor.Process(
				t.Context(), testLocalScanRequest(t, [][]byte{[]byte("Subject: unsigned\n")}),
			); !testAdapterFailureClass(processErr, wantClass) {
				t.Fatal("malformed process 204 was admitted")
			}
		})
	}
}

// TestResponseFromContinuePlanAlwaysScrubsLocalClaims proves RFC 8601 cleanup
// is independent of whether the daemon result was applicable or bodyless.
func TestResponseFromContinuePlanAlwaysScrubsLocalClaims(t *testing.T) {
	plan, err := adapter.NewPlan(adapter.ResultPass, adapter.DispositionContinue, nil)
	if err != nil {
		t.Fatal("applicable continue fixture construction failed")
	}
	response, err := responseFromPlan(plan, []uint16{3, 1}, 3, nil)
	if err != nil || response.Decision() != ipc.DecisionAccept {
		t.Fatal("applicable continue plan mapping failed")
	}
	removals := response.Removals()
	if len(removals) != 2 || removals[0] != 3 || removals[1] != 1 {
		t.Fatal("applicable continue plan discarded local RFC 8601 removals")
	}
}

type noContentResponseMutation struct {
	name     string
	class    adapter.FailureClass
	response func(string) *http.Response
}

type failingResponseBody struct {
	readErr  error
	closeErr error
}

// Read returns one injected response-body failure without content.
func (b *failingResponseBody) Read([]byte) (int, error) { return 0, b.readErr }

// Close returns one injected response-body close failure.
func (b *failingResponseBody) Close() error { return b.closeErr }

// testAdapterFailureClass checks one closed adapter failure without string matching.
func testAdapterFailureClass(err error, class adapter.FailureClass) bool {
	var failure *adapter.Error
	return errors.As(err, &failure) && failure.Class() == class
}

// noContentResponseMutations returns adjacent invalid 204 transport shapes.
func noContentResponseMutations() []noContentResponseMutation {
	return []noContentResponseMutation{
		{name: "nil body", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Body = nil
			return value
		}},
		{name: "body", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Body = io.NopCloser(bytes.NewReader([]byte("{}")))
			return value
		}},
		{name: "content type", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Header.Set("Content-Type", jsonMediaType)
			return value
		}},
		{name: "content length", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Header.Set("Content-Length", "0")
			return value
		}},
		{name: "unknown projected content length", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.ContentLength = -1
			return value
		}},
		{name: "nonzero projected content length", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.ContentLength = 2
			return value
		}},
		{name: "xcto", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Header.Set("X-Content-Type-Options", "nosniff")
			return value
		}},
		{name: "cache control", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Header.Set("Cache-Control", "public")
			return value
		}},
		{name: "missing cache control", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Header.Del("Cache-Control")
			return value
		}},
		{name: "duplicate cache control", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Header.Add("Cache-Control", "no-store")
			return value
		}},
		{name: "wrong connection", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Header.Set("Connection", "keep-alive")
			return value
		}},
		{name: "duplicate connection", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Header.Add("Connection", "close")
			return value
		}},
		{name: "open connection", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Close = false
			return value
		}},
		{name: "missing connection without HTTP 1.1 projection", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Header.Del("Connection")
			value.ProtoMajor = 0
			value.ProtoMinor = 0
			return value
		}},
		{name: "missing connection over HTTP 2", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Header.Del("Connection")
			value.ProtoMajor = 2
			return value
		}},
		{name: "explicit connection close over HTTP 2", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.ProtoMajor = 2
			return value
		}},
		{name: "invalid date", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Header.Set("Date", "not-a-date")
			return value
		}},
		{name: "duplicate date", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Header["Date"] = []string{"Mon, 02 Jan 2006 15:04:05 GMT", "Mon, 02 Jan 2006 15:04:05 GMT"}
			return value
		}},
		{name: "transfer encoding", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.TransferEncoding = []string{"chunked"}
			return value
		}},
		{name: "transfer encoding header", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Header.Set("Transfer-Encoding", "chunked")
			return value
		}},
		{name: "trailer", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Trailer = http.Header{"Digest": {"invalid"}}
			return value
		}},
		{name: "read failure", class: adapter.FailureUnavailable, response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Body = &failingResponseBody{readErr: errors.New("read")}
			return value
		}},
		{name: "close failure", class: adapter.FailureUnavailable, response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Body = &failingResponseBody{readErr: io.EOF, closeErr: errors.New("close")}
			return value
		}},
		{name: "wrong route", response: func(string) *http.Response {
			return exactNoContentHTTPResponse("/v1/sign")
		}},
		{name: "wrong method", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Request.Method = http.MethodGet
			return value
		}},
		{name: "query", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Request.URL.RawQuery = "unexpected=true"
			return value
		}},
		{name: "fragment", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Request.URL.Fragment = "unexpected"
			return value
		}},
		{name: "missing request", response: func(path string) *http.Response {
			value := exactNoContentHTTPResponse(path)
			value.Request = nil
			return value
		}},
	}
}

// exactNoContentHTTPResponse returns one exact injected raw OpenAPI 204 response.
func exactNoContentHTTPResponse(path string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Header: http.Header{
			"Cache-Control": {"no-store"},
			"Connection":    {"close"},
		},
		Body:          io.NopCloser(bytes.NewReader(nil)),
		ContentLength: 0,
		Close:         true,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       &http.Request{Method: http.MethodPost, URL: mustParseRequestPath(path)},
	}
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
