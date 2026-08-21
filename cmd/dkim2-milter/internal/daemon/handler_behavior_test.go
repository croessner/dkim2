package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/daemon/generated"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/milter"
)

const (
	handlerPrivacyMarker = "toxic-handler-private-marker"
	testAuthservID       = "mx.example.test"
	testDomain           = "example.test"
	testDSNDomain        = "dsn.example.test"
	testTenant           = "tenant"
	testCaseWrongMethod  = "wrong method"
	testCaseWrongRoute   = "wrong route"
	testCaseQuery        = "query"
	validResponseDate    = "Mon, 02 Jan 2006 15:04:05 GMT"
)

// TestHandlerUsesOneExactGeneratedOperation proves route, headers, DTOs, and no retry.
func TestHandlerUsesOneExactGeneratedOperation(t *testing.T) {
	for _, testCase := range []struct {
		mode      string
		route     string
		operation generated.OperationResponseOperation
	}{
		{mode: modeOriginator, route: routeSign, operation: generated.Sign},
		{mode: modeOrdinaryTransit, route: routeRevise, operation: generated.Revise},
	} {
		t.Run(testCase.mode, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls++
				if request.Method != http.MethodPost || request.URL.String() != testCase.route ||
					request.Header.Get("User-Agent") != fixedUserAgent ||
					request.Header.Get("Accept") != "application/json" ||
					request.Header.Get("Cache-Control") != cacheControlNoStore ||
					request.Header.Get(capabilityHeader) == "" ||
					request.Header.Get("Cookie") != "" ||
					request.Header.Get("Authorization") != "" {
					t.Error("generated request escaped the fixed transport contract")
				}
				var document map[string]any
				decoder := json.NewDecoder(request.Body)
				if err := decoder.Decode(&document); err != nil {
					t.Error("generated request body was not JSON")
				}
				contextValue, _ := document["context"].(map[string]any)
				if contextValue["tenant"] != testTenant || contextValue["domain"] != testDomain {
					t.Error("generated signing context was not mapped exactly")
				}
				writer.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(writer).Encode(validOperationResponse(testCase.operation))
			}))
			defer server.Close()
			capability := testCapability(t)
			handler, err := NewHandler(
				server.URL, capability, testCase.mode, testTenant, testDomain,
				milter.DomainSourceStatic,
				map[string]string{modeOriginator: testDSNDomain}[testCase.mode], "",
			)
			if err != nil {
				t.Fatal("handler construction failed")
			}
			t.Cleanup(func() { _ = handler.Close() })
			message := testMessage(t)
			result, err := handler.Handle(t.Context(), message)
			if err != nil || calls != 1 || result.Operation != string(testCase.operation) ||
				result.Outcome != milter.DispositionReject {
				t.Fatalf("Handle()=(%v,%v), calls=%d", result, err, calls)
			}
		})
	}
}

// TestHandlerUsesExactInboundGeneratedOperation proves process DTO and report mapping.
func TestHandlerUsesExactInboundGeneratedOperation(t *testing.T) {
	calls := 0
	message := testMessage(t)
	expectedRaw := base64.StdEncoding.EncodeToString(message.Raw())
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if request.Method != http.MethodPost || request.URL.String() != routeProcess ||
			request.Header.Get("User-Agent") != fixedUserAgent ||
			request.Header.Get(capabilityHeader) == "" {
			t.Error("generated process request escaped the fixed transport contract")
		}
		var document map[string]any
		if err := json.NewDecoder(request.Body).Decode(&document); err != nil {
			t.Error("generated process request body was not JSON")
		}
		messageInput, _ := document["message"].(map[string]any)
		smtpInput, _ := document["smtp"].(map[string]any)
		reporting, _ := document["reporting"].(map[string]any)
		recipients, _ := smtpInput["rcpt_to"].([]any)
		if document["api_version"] != "v1" ||
			document["draft"] != "draft-ietf-dkim-dkim2-spec-04" ||
			messageInput["fidelity"] != "milter_reconstructed_crlf" ||
			messageInput["raw_rfc5322_base64"] != expectedRaw ||
			smtpInput["mail_from"] != "<a@example.test>" ||
			len(recipients) != 1 || recipients[0] != "<b@example.test>" ||
			reporting["authserv_id"] != testAuthservID ||
			document["context"] != nil {
			t.Error("generated process request DTO was not mapped exactly")
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(validProcessResponse())
	}))
	defer server.Close()
	handler, err := NewHandler(
		server.URL, testCapability(t), modeInbound, "", "", milter.DomainSourceStatic,
		"", "mx.example.test",
	)
	if err != nil {
		t.Fatal("inbound handler construction failed")
	}
	t.Cleanup(func() { _ = handler.Close() })
	result, err := handler.Handle(t.Context(), message)
	if err != nil || calls != 1 || result.Operation != operationProcess ||
		result.Result != verificationPass || result.Outcome != milter.DispositionAccept ||
		len(result.Actions) != 1 ||
		result.Actions[0].Kind != milter.ActionAddHeader ||
		result.Actions[0].Name != "Authentication-Results" ||
		result.Actions[0].Value != "mx.example.test; dkim2=pass" {
		t.Fatalf("Handle()=(%v,%v), calls=%d", result, err, calls)
	}
}

// TestHandlerAcceptsUnsignedNoContent proves the generated client preserves the
// exact applicability response through the real HTTP transport.
func TestHandlerAcceptsUnsignedNoContent(t *testing.T) {
	testHandlerAcceptsNoContent(
		t, modeInbound, "", "", routeProcess, operationProcess,
	)
}

// testHandlerAcceptsNoContent proves one generated client preserves an exact
// applicability response through real HTTP transport.
func testHandlerAcceptsNoContent(
	t *testing.T,
	mode string,
	tenant string,
	domain string,
	route string,
	operation string,
) {
	t.Helper()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if request.Method != http.MethodPost || request.URL.String() != route {
			t.Error("no-content request escaped the fixed route contract")
		}
		writer.Header().Set("Cache-Control", cacheControlNoStore)
		writer.Header().Set("Connection", "close")
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	handler, err := NewHandler(
		server.URL, testCapability(t), mode, tenant, domain, milter.DomainSourceStatic,
		map[string]string{modeOriginator: testDSNDomain}[mode], "",
	)
	if err != nil {
		t.Fatal("no-content handler construction failed")
	}
	t.Cleanup(func() { _ = handler.Close() })
	result, err := handler.Handle(t.Context(), testMessage(t))
	if err != nil || calls != 1 || result.Operation != operation || result.Result != verificationNone ||
		result.Outcome != milter.DispositionContinue || len(result.Actions) != 0 {
		t.Fatalf("Handle()=(%v,%v), calls=%d", result, err, calls)
	}
}

// TestMapProcessAcceptsOnlyExactUnsignedNoContent proves the applicability wire variant.
func TestMapProcessAcceptsOnlyExactUnsignedNoContent(t *testing.T) {
	request := &http.Request{Method: http.MethodPost, URL: &url.URL{Path: routeProcess}}
	response := &generated.ProcessMessageResponse{
		HTTPResponse: &http.Response{
			StatusCode: http.StatusNoContent,
			Request:    request,
			Close:      true,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Cache-Control": []string{cacheControlNoStore},
				"Connection":    []string{connectionClose},
				"Date":          []string{validResponseDate},
			},
			ContentLength: 0,
		},
	}
	guard := &handlerGuard{authservID: testAuthservID}
	result, err := guard.mapProcess(response)
	if err != nil || result.Operation != operationProcess || result.Result != verificationNone ||
		result.Outcome != milter.DispositionContinue || len(result.Actions) != 0 {
		t.Fatalf("mapProcess() = %#v, %v", result, err)
	}
	withoutDate := *response
	withoutDateHTTP := *response.HTTPResponse
	withoutDateHTTP.Header = response.HTTPResponse.Header.Clone()
	withoutDateHTTP.Header.Del("Date")
	withoutDate.HTTPResponse = &withoutDateHTTP
	if _, withoutDateErr := guard.mapProcess(&withoutDate); withoutDateErr != nil {
		t.Fatal("optional Date header was required")
	}
	for _, testCase := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: testCaseWrongMethod, mutate: func(value *http.Request) { value.Method = http.MethodGet }},
		{name: testCaseWrongRoute, mutate: func(value *http.Request) { value.URL.Path = routeSign }},
		{name: testCaseQuery, mutate: func(value *http.Request) { value.URL.RawQuery = "unexpected=true" }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := *response
			candidateHTTP := *response.HTTPResponse
			candidateRequest := *response.HTTPResponse.Request
			candidateURL := *response.HTTPResponse.Request.URL
			candidateRequest.URL = &candidateURL
			testCase.mutate(&candidateRequest)
			candidateHTTP.Request = &candidateRequest
			candidate.HTTPResponse = &candidateHTTP
			if _, err := guard.mapProcess(&candidate); err == nil {
				t.Fatal("misbound process response was accepted")
			}
		})
	}
	assertRejectsMalformedNoContent(t, response.HTTPResponse)
}

// TestMapSignAcceptsOnlyExactNotApplicableNoContent proves the originator
// applicability wire variant is bodyless, mutation-free, and operation-bound.
func TestMapSignAcceptsOnlyExactNotApplicableNoContent(t *testing.T) {
	request := &http.Request{Method: http.MethodPost, URL: &url.URL{Path: routeSign}}
	response := &generated.SignMessageResponse{
		HTTPResponse: &http.Response{
			StatusCode: http.StatusNoContent,
			Request:    request,
			Close:      true,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Cache-Control": []string{cacheControlNoStore},
				"Connection":    []string{connectionClose},
				"Date":          []string{validResponseDate},
			},
			ContentLength: 0,
		},
	}
	result, err := mapOperationResponse(response, operationSign)
	if err != nil || result.Operation != operationSign || result.Result != verificationNone ||
		result.Outcome != milter.DispositionContinue || len(result.Actions) != 0 {
		t.Fatalf("mapOperationResponse() = %#v, %v", result, err)
	}
	withoutDate := *response
	withoutDateHTTP := *response.HTTPResponse
	withoutDateHTTP.Header = response.HTTPResponse.Header.Clone()
	withoutDateHTTP.Header.Del("Date")
	withoutDate.HTTPResponse = &withoutDateHTTP
	if _, withoutDateErr := mapOperationResponse(&withoutDate, operationSign); withoutDateErr != nil {
		t.Fatal("optional Date header was required")
	}
	for _, testCase := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: testCaseWrongMethod, mutate: func(value *http.Request) { value.Method = http.MethodGet }},
		{name: testCaseWrongRoute, mutate: func(value *http.Request) { value.URL.Path = routeProcess }},
		{name: testCaseQuery, mutate: func(value *http.Request) { value.URL.RawQuery = "unexpected=true" }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := *response
			candidateHTTP := *response.HTTPResponse
			candidateRequest := *response.HTTPResponse.Request
			candidateURL := *response.HTTPResponse.Request.URL
			candidateRequest.URL = &candidateURL
			testCase.mutate(&candidateRequest)
			candidateHTTP.Request = &candidateRequest
			candidate.HTTPResponse = &candidateHTTP
			if _, err := mapOperationResponse(&candidate, operationSign); err == nil {
				t.Fatal("misbound sign response was accepted")
			}
		})
	}
	assertRejectsMalformedNoContent(t, response.HTTPResponse)
}

// assertRejectsMalformedNoContent exercises the shared strict 204 envelope
// against representation, framing, and date mutations.
func assertRejectsMalformedNoContent(t *testing.T, response *http.Response) {
	t.Helper()
	for _, testCase := range []struct {
		name   string
		mutate func(*http.Response, *[]byte, *bool)
	}{
		{name: "body", mutate: func(_ *http.Response, body *[]byte, _ *bool) { *body = []byte("{}") }},
		{name: "JSON document", mutate: func(_ *http.Response, _ *[]byte, document *bool) { *document = true }},
		{name: "content type", mutate: func(value *http.Response, _ *[]byte, _ *bool) {
			value.Header.Set("Content-Type", "application/json")
		}},
		{name: "content length zero", mutate: func(value *http.Response, _ *[]byte, _ *bool) {
			value.Header.Set("Content-Length", "0")
		}},
		{name: "transfer encoding", mutate: func(value *http.Response, _ *[]byte, _ *bool) {
			value.TransferEncoding = []string{"chunked"}
		}},
		{name: "transfer encoding declaration", mutate: func(value *http.Response, _ *[]byte, _ *bool) {
			value.Header.Set("transfer-encoding", "chunked")
		}},
		{name: "raw transfer encoding declaration", mutate: func(value *http.Response, _ *[]byte, _ *bool) {
			value.Header["tRaNsFeR-EnCoDiNg"] = []string{"chunked"}
		}},
		{name: "trailer projection", mutate: func(value *http.Response, _ *[]byte, _ *bool) {
			value.Trailer = http.Header{"Digest": {"sha-256=synthetic"}}
		}},
		{name: "trailer declaration", mutate: func(value *http.Response, _ *[]byte, _ *bool) {
			value.Header.Set("trailer", "Digest")
		}},
		{name: "missing cache control", mutate: func(value *http.Response, _ *[]byte, _ *bool) {
			value.Header.Del("Cache-Control")
		}},
		{name: "missing connection", mutate: func(value *http.Response, _ *[]byte, _ *bool) {
			value.Header.Del("Connection")
		}},
		{name: "duplicate connection", mutate: func(value *http.Response, _ *[]byte, _ *bool) {
			value.Header.Add("Connection", connectionClose)
		}},
		{name: "invalid date", mutate: func(value *http.Response, _ *[]byte, _ *bool) {
			value.Header.Set("Date", "Monday, 02-Jan-06 15:04:05 GMT")
		}},
		{name: "mismatched date weekday", mutate: func(value *http.Response, _ *[]byte, _ *bool) {
			value.Header.Set("Date", "Tue, 02 Jan 2006 15:04:05 GMT")
		}},
		{name: "duplicate date", mutate: func(value *http.Response, _ *[]byte, _ *bool) {
			value.Header.Add("Date", validResponseDate)
		}},
		{name: "open projected connection", mutate: func(value *http.Response, _ *[]byte, _ *bool) {
			value.Close = false
		}},
		{name: "HTTP/2 explicit connection close", mutate: func(value *http.Response, _ *[]byte, _ *bool) {
			value.ProtoMajor = 2
			value.ProtoMinor = 0
		}},
		{name: "wrong status", mutate: func(value *http.Response, _ *[]byte, _ *bool) {
			value.StatusCode = http.StatusOK
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := *response
			candidate.Header = response.Header.Clone()
			var body []byte
			hasJSONDocument := false
			testCase.mutate(&candidate, &body, &hasJSONDocument)
			if validNoContentResponseShape(&candidate, body, hasJSONDocument) {
				t.Fatal("malformed no-content response was accepted")
			}
		})
	}
}

// TestHandlerNonOKResponseIsContractFailure proves HTTP status cannot enable fail-open.
func TestHandlerNonOKResponseIsContractFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(writer, `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","code":"service_unavailable","category":"availability"}`)
	}))
	defer server.Close()
	handler, err := NewHandler(
		server.URL, testCapability(t), modeOriginator, testTenant, testDomain,
		milter.DomainSourceStatic, testDSNDomain, "",
	)
	if err != nil {
		t.Fatal("handler construction failed")
	}
	t.Cleanup(func() { _ = handler.Close() })
	_, err = handler.Handle(t.Context(), testMessage(t))
	assertFailureClass(t, err, milter.FailureContract)
}

// TestHandlerDerivesOriginatorDomainFromEnvelopeSender proves per-message exact selection.
func TestHandlerDerivesOriginatorDomainFromEnvelopeSender(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls++
		var document map[string]any
		if err := json.NewDecoder(request.Body).Decode(&document); err != nil {
			t.Error("generated request body was not JSON")
		}
		contextValue, _ := document["context"].(map[string]any)
		if contextValue["tenant"] != testTenant || contextValue["domain"] != testDomain {
			t.Error("envelope sender domain was not mapped exactly")
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(validOperationResponse(generated.Sign))
	}))
	defer server.Close()
	handler, err := NewHandler(
		server.URL, testCapability(t), modeOriginator, testTenant, "",
		milter.DomainSourceEnvelopeSender, testDSNDomain, "",
	)
	if err != nil {
		t.Fatal("handler construction failed")
	}
	t.Cleanup(func() { _ = handler.Close() })
	message, err := milter.NewMessage(
		[]byte("From: sender@example.test\r\n\r\nbody"),
		[]byte("<sender@Example.TEST>"),
		[][]byte{[]byte("<recipient@example.test>")},
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := handler.Handle(t.Context(), message)
	if err != nil || calls != 1 || result.Domains.Role() != "signing" ||
		result.Domains.Domains() != testDomain {
		t.Fatalf("Handle() result=%v error=%v, calls=%d", result, err, calls)
	}
	for _, reverse := range []string{"<sender@[192.0.2.1]>", "<séndér@example.test>", "<sender@täst.example>"} {
		message, err := milter.NewMessage(
			[]byte("From: sender@example.test\r\n\r\nbody"),
			[]byte(reverse),
			[][]byte{[]byte("<recipient@example.test>")},
		)
		if err != nil {
			t.Fatal(err)
		}
		result, handleErr := handler.Handle(t.Context(), message)
		if handleErr != nil || result.Operation != operationSign ||
			result.Result != verificationNone || result.Outcome != milter.DispositionContinue ||
			len(result.Actions) != 0 {
			t.Fatalf("Handle(%q)=(%v,%v)", reverse, result, handleErr)
		}
	}
	message, err = milter.NewMessage(
		[]byte("From: sender@example.test\r\n\r\nbody"),
		[]byte("<sender@example.test>"),
		[][]byte{[]byte("<réçipient@example.test>")},
	)
	if err != nil {
		t.Fatal(err)
	}
	result, handleErr := handler.Handle(t.Context(), message)
	if handleErr != nil || result.Operation != operationSign ||
		result.Result != verificationNone || result.Outcome != milter.DispositionContinue ||
		len(result.Actions) != 0 {
		t.Fatalf("Handle(EAI recipient)=(%v,%v)", result, handleErr)
	}
	if calls != 1 {
		t.Fatalf("invalid envelope domains reached daemon: calls=%d", calls)
	}
}

// TestObservedDomainsMatchesAuthoritativeRouteSelection proves that operator
// logging follows inbound envelope targets and the selected originator domain.
func TestObservedDomainsMatchesAuthoritativeRouteSelection(t *testing.T) {
	message, err := milter.NewMessage(
		[]byte("Subject: test\r\n\r\nbody\r\n"),
		[]byte("<sender@Origin.Example>"),
		[][]byte{
			[]byte("<first@Target.Example>"),
			[]byte("<second@target.example>"),
		},
	)
	if err != nil {
		t.Fatal("message construction failed")
	}
	inbound := observedDomains(&handlerGuard{mode: modeInbound}, message)
	if inbound.Role() != "recipient" || inbound.Domains() != "target.example" ||
		inbound.Count() != 1 || inbound.Truncated() {
		t.Fatalf("inbound domains=%#v", inbound)
	}
	originator := observedDomains(&handlerGuard{
		mode: modeOriginator, domainSource: milter.DomainSourceEnvelopeSender,
	}, message)
	if originator.Role() != "signing" || originator.Domains() != "origin.example" ||
		originator.Count() != 1 || originator.Truncated() {
		t.Fatalf("originator domains=%#v", originator)
	}
}

// TestHandlerTempfailsNullReversePathUntilPrevalidatedDSNGateExists reproduces
// the missing Draft-04 Section 12.1 trusted-evidence gate.
func TestHandlerTempfailsNullReversePathUntilPrevalidatedDSNGateExists(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls++
	}))
	defer server.Close()
	handler, err := NewHandler(
		server.URL, testCapability(t), modeOriginator, testTenant, "",
		milter.DomainSourceEnvelopeSender, testDSNDomain, "",
	)
	if err != nil {
		t.Fatal("handler construction failed")
	}
	t.Cleanup(func() { _ = handler.Close() })
	message, err := milter.NewMessage(
		[]byte("From: mailer-daemon@example.test\r\n\r\nbody"),
		[]byte("<>"),
		[][]byte{[]byte("<sender@example.test>")},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = handler.Handle(t.Context(), message)
	assertFailureClass(t, err, milter.FailureContract)
	if calls != 0 {
		t.Fatalf("null-sender message reached daemon without trusted DSN gate: calls=%d", calls)
	}
}

// TestHandlerRejectsIncompleteDSNSigningAuthority proves null-sender signing
// cannot fall back to other message or route evidence.
func TestHandlerRejectsIncompleteDSNSigningAuthority(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("invalid DSN signing state reached the daemon")
	}))
	defer server.Close()
	for _, authority := range []string{"", "DSN.example.test", "recipient@example.test"} {
		if handler, err := NewHandler(
			server.URL, testCapability(t), modeOriginator, testTenant, testDomain,
			milter.DomainSourceStatic, authority, "",
		); err == nil || handler != nil {
			t.Fatalf("NewHandler() accepted DSN authority %q", authority)
		}
	}
}

// TestHandlerAcceptsOriginatorNoContent proves absent policy remains a no-op
// through the generated client and exact HTTP response validator.
func TestHandlerAcceptsOriginatorNoContent(t *testing.T) {
	testHandlerAcceptsNoContent(
		t, modeOriginator, testTenant, testDomain, routeSign, operationSign,
	)
}

// TestOperationEvidenceClassifiesIndeterminateBoundaries proves no retry after effects.
func TestOperationEvidenceClassifiesIndeterminateBoundaries(t *testing.T) {
	expired, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
	cancel()
	canceled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	for _, testCase := range []struct {
		name            string
		requestStarted  bool
		responseStarted bool
		ctx             context.Context
		input           error
		want            milter.FailureClass
	}{
		{
			name: "typed class wins over context",
			ctx:  expired, input: &milter.Error{Class: milter.FailureContract},
			want: milter.FailureContract,
		},
		{
			name: "deadline before write",
			ctx:  expired, input: context.DeadlineExceeded,
			want: milter.FailureTimeout,
		},
		{
			name: "request write attempted", requestStarted: true,
			ctx: expired, input: context.DeadlineExceeded, want: milter.FailureIndeterminate,
		},
		{
			name: "response byte observed", responseStarted: true,
			ctx: context.Background(), input: io.ErrUnexpectedEOF, want: milter.FailureIndeterminate,
		},
		{
			name: "dial failure",
			ctx:  context.Background(), input: &url.Error{Op: "Post", URL: "redacted", Err: io.EOF},
			want: milter.FailureUnavailable,
		},
		{
			name: "shutdown cancellation before write",
			ctx:  canceled, input: context.Canceled,
			want: milter.FailureInternal,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			evidence := &operationEvidence{}
			if testCase.requestStarted {
				evidence.writeStarted.Store(true)
			}
			if testCase.responseStarted {
				evidence.responseStarted.Store(true)
			}
			err := classifyCallError(testCase.ctx, testCase.input, evidence)
			assertFailureClass(t, err, testCase.want)
		})
	}
}

// TestOperationTraceRecordsRequestAndResponseProgress freezes the owned evidence seam.
func TestOperationTraceRecordsRequestAndResponseProgress(t *testing.T) {
	evidence := &operationEvidence{}
	trace := evidence.trace()
	trace.WroteHeaders()
	if !evidence.writeStarted.Load() {
		t.Fatal("header write was not recorded")
	}
	trace.WroteRequest(httptrace.WroteRequestInfo{Err: io.ErrClosedPipe})
	if !evidence.writeStarted.Load() {
		t.Fatal("partial request write evidence was lost")
	}
	trace.GotFirstResponseByte()
	if !evidence.responseStarted.Load() {
		t.Fatal("response-byte evidence was not recorded")
	}
}

// TestResponseLimitTransportRejectsUnsafeResponses proves nil, panic, and overflow closure.
func TestResponseLimitTransportRejectsUnsafeResponses(t *testing.T) {
	for _, testCase := range []struct {
		name string
		next http.RoundTripper
	}{
		{name: "nil response", next: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, nil
		})},
		{name: "nil body", next: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK}, nil
		})},
		{name: "panic", next: roundTripFunc(func(*http.Request) (*http.Response, error) {
			panic(handlerPrivacyMarker)
		})},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			transport := responseLimitTransport{next: testCase.next, max: 4}
			response, err := transport.RoundTrip(httptest.NewRequest(http.MethodPost, "http://127.0.0.1/", strings.NewReader("x")))
			if err == nil || response != nil || strings.Contains(err.Error(), handlerPrivacyMarker) {
				t.Fatal("unsafe response escaped the bounded transport")
			}
		})
	}
	closed := false
	transport := responseLimitTransport{
		next: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       closeTracker{Reader: strings.NewReader("12345"), closed: &closed},
			}, nil
		}),
		max: 4,
	}
	response, err := transport.RoundTrip(httptest.NewRequest(http.MethodPost, "http://127.0.0.1/", strings.NewReader("x")))
	if err != nil {
		t.Fatal("bounded response construction failed")
	}
	_, err = io.ReadAll(response.Body)
	if err == nil {
		t.Fatal("overflow response was accepted")
	}
	if closeErr := response.Body.Close(); closeErr != nil || !closed {
		t.Fatal("overflow response did not close its owner")
	}
}

// TestMapMessageClearsEveryTemporaryCopy proves mapper exits erase byte copies.
func TestMapMessageClearsEveryTemporaryCopy(t *testing.T) {
	message := testMessage(t)
	request, err := mapMessage(message)
	if err != nil || request.message.Fidelity == nil ||
		*request.message.Fidelity != generated.MilterReconstructedCrlf ||
		len(request.smtp.RcptTo) != 1 {
		t.Fatal("valid message mapping failed")
	}
	invalid, err := milter.NewMessage(
		[]byte("From: a@example.test\r\n\r\n"),
		[]byte("<a@example.test>"),
		[][]byte{{0xff}},
	)
	if err != nil {
		t.Fatal("invalid UTF-8 test message construction failed")
	}
	if _, err := mapMessage(invalid); err == nil {
		t.Fatal("invalid recipient mapping succeeded")
	}
}

// TestProcessResponseValidationRejectsNestedContractDrift proves complete validation.
func TestProcessResponseValidationRejectsNestedContractDrift(t *testing.T) {
	value := validProcessResponse()
	if !validProcessContract(&value, testAuthservID) {
		t.Fatal("valid process response was rejected")
	}
	value.Policy.Feedback.HistoryCoverage = generated.PolicyFeedbackHistoryCoverage("future")
	if validProcessContract(&value, testAuthservID) {
		t.Fatal("nested policy drift was accepted")
	}
	value = validProcessResponse()
	value.Verification.Checks = make([]generated.VerificationCheck, 129)
	if validProcessContract(&value, testAuthservID) {
		t.Fatal("oversized verification checks were accepted")
	}
	value = validProcessResponse()
	value.Replay.Class = generated.NotChecked
	if validProcessContract(&value, testAuthservID) {
		t.Fatal("PASS plus accept with skipped replay was accepted")
	}
}

// TestProcessContractAdmitsPermerrorPolicyAcceptance proves parity with the Exim inbound boundary.
func TestProcessContractAdmitsPermerrorPolicyAcceptance(t *testing.T) {
	value := validProcessResponse()
	value.Actions[0].Value = testAuthservID + "; dkim2=permerror"
	value.Replay.Class = generated.NotChecked
	value.Verification.State = generated.PERMERROR
	value.Verification.PrimaryReason = generated.VerificationReasonMalformedProtocol
	value.Verification.Checks[0].Reason = generated.VerificationReasonMalformedProtocol
	value.Verification.Scope = generated.Current
	value.Verification.HistoricalContent = generated.VerificationResultHistoricalContentNotEvaluated
	value.Verification.HistoricalSignatures = generated.VerificationResultHistoricalSignaturesNotEvaluated
	if !validProcessContract(&value, testAuthservID) {
		t.Fatal("permissive process response was rejected")
	}
}

// TestProcessContractAdmitsMultiInstanceTestingContinue proves the adapter
// accepts authenticated chain policy evidence with the daemon-owned report.
func TestProcessContractAdmitsMultiInstanceTestingContinue(t *testing.T) {
	value := validProcessResponse()
	value.Actions = generated.ActionPlan{{
		Type: generated.AddHeader, Name: generated.AuthenticationResults,
		Value: testAuthservID + "; dkim2=pass",
	}}
	value.Disposition = generated.DispositionContinue
	value.Policy.DoNotExplode = generated.PolicyResultDoNotExplodeNotRequested
	value.Policy.DoNotModify = generated.PolicyResultDoNotModifyIndeterminate
	value.Policy.Feedback.HistoryCoverage = generated.PolicyFeedbackHistoryCoverageComplete
	value.Policy.Mode = generated.Testing
	value.Policy.PrimaryReason = generated.TestingModeObserve
	value.Policy.Verdict = generated.PolicyResultVerdictContinue
	sequence := generated.CanonicalUint64("2")
	value.Policy.Findings = []generated.PolicyFinding{
		{Reason: generated.DonotmodifyIndeterminate, Sequence: &sequence, Severity: generated.Warning},
		{Reason: generated.TestingModeObserve, Severity: generated.Warning},
	}
	value.Replay.Class = generated.NotChecked
	if !validProcessContract(&value, testAuthservID) {
		t.Fatal("multi-instance testing continue response was rejected")
	}
	value.Actions = generated.ActionPlan{}
	if validProcessContract(&value, testAuthservID) {
		t.Fatal("multi-instance testing continue response omitted its report")
	}
}

// TestRequiredResponseMembersRejectZeroValueAmbiguity proves absent required facts fail closed.
func TestRequiredResponseMembersRejectZeroValueAmbiguity(t *testing.T) {
	processBody, err := json.Marshal(validProcessResponse())
	if err != nil || !validProcessRequiredMembers(processBody) {
		t.Fatal("complete process response was rejected")
	}
	for _, testCase := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "signature sets absent", mutate: func(document map[string]any) {
			delete(document["verification"].(map[string]any), "signature_sets")
		}},
		{name: "DNS testing absent", mutate: func(document map[string]any) {
			delete(document["policy"].(map[string]any), "dns_testing_effective")
		}},
		{name: "feedback requested absent", mutate: func(document map[string]any) {
			delete(document["policy"].(map[string]any)["feedback"].(map[string]any), "requested")
		}},
		{name: "feedback relay required null", mutate: func(document map[string]any) {
			document["policy"].(map[string]any)["feedback"].(map[string]any)["relay_required"] = nil
		}},
		{name: "optional feedback sequence null", mutate: func(document map[string]any) {
			document["policy"].(map[string]any)["feedback"].(map[string]any)["relay_sequence"] = nil
		}},
		{name: "optional finding sequence null", mutate: func(document map[string]any) {
			document["policy"].(map[string]any)["findings"].([]any)[0].(map[string]any)["sequence"] = nil
		}},
		{name: "key-policy testing absent", mutate: func(document map[string]any) {
			verification := document["verification"].(map[string]any)
			verification["signature_sets"] = []any{map[string]any{
				"algorithm": "ed25519-sha256",
				"key_policy": map[string]any{
					"strict_identity_applicable": false,
					"strict_identity_declared":   false,
				},
				"reason": "none",
				"status": verificationPass,
			}}
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(processBody, &document); err != nil {
				t.Fatal("process fixture was not JSON")
			}
			testCase.mutate(document)
			body, err := json.Marshal(document)
			if err != nil {
				t.Fatal("mutated process fixture was not JSON")
			}
			if validProcessRequiredMembers(body) {
				t.Fatal("process response with an absent required fact was accepted")
			}
		})
	}

	operationBody, err := json.Marshal(validOperationResponse(generated.Sign))
	if err != nil || !validOperationRequiredMembers(operationBody) {
		t.Fatal("complete operation response was rejected")
	}
	var operation map[string]any
	if err := json.Unmarshal(operationBody, &operation); err != nil {
		t.Fatal("operation fixture was not JSON")
	}
	operation["actions"] = []any{map[string]any{
		"name":  "DKIM2-Signature",
		"type":  "add_header",
		"value": nil,
	}}
	operationBody, err = json.Marshal(operation)
	if err != nil || validOperationRequiredMembers(operationBody) {
		t.Fatal("operation response with a null action value was accepted")
	}
}

// FuzzRawDaemonResponseAndActionAdmissionNeverPanics exercises the complete JSON boundary.
func FuzzRawDaemonResponseAndActionAdmissionNeverPanics(f *testing.F) {
	operationBody, err := json.Marshal(validOperationResponse(generated.Sign))
	if err != nil {
		f.Fatal(err)
	}
	processBody, err := json.Marshal(validProcessResponse())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(operationBody)
	f.Add(processBody)
	f.Add([]byte(`{"actions":[],"actions":[]}`))
	f.Add([]byte(`{"unknown":true}`))
	f.Add([]byte(`{"actions":null}`))
	f.Add([]byte(strings.Repeat(`{"nested":`, 40) + `null` + strings.Repeat(`}`, 40)))
	f.Fuzz(func(_ *testing.T, body []byte) {
		if len(body) > 1<<20 {
			return
		}
		var operation generated.OperationResponse
		operationRequired := validOperationRequiredMembers(body)
		operationDecoded := strictDecodeResponse(body, &operation)
		if operationRequired && operationDecoded {
			_, _ = mapOperation(&operation, "sign")
			_, _ = mapOperation(&operation, "revise")
		}

		var process generated.ProcessResponse
		processRequired := validProcessRequiredMembers(body)
		processDecoded := strictDecodeResponse(body, &process)
		if processRequired && processDecoded {
			_ = validProcessContract(&process, testAuthservID)
		}
	})
}

// validOperationResponse returns one closed refusal without mutations.
func validOperationResponse(operation generated.OperationResponseOperation) generated.OperationResponse {
	return generated.OperationResponse{
		Actions: generated.ActionPlan{}, ApiVersion: generated.V1,
		Disposition: generated.DispositionReject,
		Draft:       generated.DraftIetfDkimDkim2Spec04,
		Operation:   operation, Result: generated.OperationResponseResultFail,
	}
}

// validProcessResponse returns one complete generated process response.
func validProcessResponse() generated.ProcessResponse {
	return generated.ProcessResponse{
		Actions: generated.ActionPlan{{
			Type: generated.AddHeader, Name: generated.AuthenticationResults,
			Value: testAuthservID + "; dkim2=pass",
		}},
		ApiVersion:  generated.V1,
		Disposition: generated.DispositionAccept,
		Draft:       generated.DraftIetfDkimDkim2Spec04,
		Verification: generated.VerificationResult{
			Checks: []generated.VerificationCheck{{
				Class:  generated.VerificationCheckClassProtocol,
				Reason: generated.VerificationReasonNone,
			}},
			CustodyStructure:     generated.VerificationResultCustodyStructureNotPresent,
			HistoricalContent:    generated.VerificationResultHistoricalContentComplete,
			HistoricalSignatures: generated.VerificationResultHistoricalSignaturesComplete,
			PrimaryReason:        generated.VerificationReasonNone,
			Scope:                generated.Chain,
			SignatureSets:        []generated.SignatureSetResult{},
			State:                generated.PASS,
		},
		Policy: generated.PolicyResult{
			DoNotExplode: generated.PolicyResultDoNotExplodeNotEvaluated,
			DoNotModify:  generated.PolicyResultDoNotModifyNotEvaluated,
			Feedback: generated.PolicyFeedback{
				HistoryCoverage: generated.PolicyFeedbackHistoryCoverageNotEvaluated,
			},
			Findings: []generated.PolicyFinding{{
				Reason: generated.ProtocolPass, Severity: generated.Info,
			}},
			Mode:          generated.Strict,
			PrimaryReason: generated.ProtocolPass,
			Verdict:       generated.PolicyResultVerdictAccept,
		},
		Replay: generated.ReplayResult{Class: generated.Disabled},
	}
}

// testCapability constructs one isolated protected value.
func testCapability(t *testing.T) *Capability {
	t.Helper()
	var value [32]byte
	value[0] = 1
	capability, err := newCapability(value)
	if err != nil {
		t.Fatal("capability construction failed")
	}
	t.Cleanup(func() { _ = capability.Close() })
	return capability
}

// testMessage returns one immutable valid mapper input.
func testMessage(t *testing.T) milter.Message {
	t.Helper()
	message, err := milter.NewMessage(
		[]byte("From: a@example.test\r\n\r\n"),
		[]byte("<a@example.test>"),
		[][]byte{[]byte("<b@example.test>")},
	)
	if err != nil {
		t.Fatal("message construction failed")
	}
	return message
}

// assertFailureClass verifies one content-free typed error.
func assertFailureClass(t *testing.T, err error, class milter.FailureClass) {
	t.Helper()
	var failure *milter.Error
	if !errors.As(err, &failure) || failure.Class != class ||
		strings.Contains(err.Error(), handlerPrivacyMarker) {
		t.Fatalf("error=%v, want class %q", err, class)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip implements the test transport seam.
func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type closeTracker struct {
	io.Reader
	closed *bool
}

// Close records release of the test response owner.
func (c closeTracker) Close() error {
	*c.closed = true
	return nil
}
