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
					request.Header.Get("Cache-Control") != "no-store" ||
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
				if contextValue["tenant"] != "tenant" || contextValue["domain"] != "example.test" {
					t.Error("generated signing context was not mapped exactly")
				}
				writer.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(writer).Encode(validOperationResponse(testCase.operation))
			}))
			defer server.Close()
			capability := testCapability(t)
			handler, err := NewHandler(
				server.URL, capability, testCase.mode, "tenant", "example.test", "",
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
		server.URL, testCapability(t), modeInbound, "", "", "mx.example.test",
	)
	if err != nil {
		t.Fatal("inbound handler construction failed")
	}
	t.Cleanup(func() { _ = handler.Close() })
	result, err := handler.Handle(t.Context(), message)
	if err != nil || calls != 1 || result.Operation != "process" ||
		result.Result != verificationPass || result.Outcome != milter.DispositionAccept ||
		len(result.Actions) != 1 ||
		result.Actions[0].Kind != milter.ActionAddHeader ||
		result.Actions[0].Name != "Authentication-Results" ||
		result.Actions[0].Value != "mx.example.test; dkim2=pass" {
		t.Fatalf("Handle()=(%v,%v), calls=%d", result, err, calls)
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
		server.URL, testCapability(t), modeOriginator, "tenant", "example.test", "",
	)
	if err != nil {
		t.Fatal("handler construction failed")
	}
	t.Cleanup(func() { _ = handler.Close() })
	_, err = handler.Handle(t.Context(), testMessage(t))
	assertFailureClass(t, err, milter.FailureContract)
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
	if !validProcessContract(&value, testAuthservID) {
		t.Fatal("permissive process response was rejected")
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
			CustodyStructure:     generated.VerificationResultCustodyStructureNotEvaluated,
			HistoricalContent:    generated.VerificationResultHistoricalContentNotEvaluated,
			HistoricalSignatures: generated.VerificationResultHistoricalSignaturesNotEvaluated,
			PrimaryReason:        generated.VerificationReasonNone,
			Scope:                generated.Current,
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
