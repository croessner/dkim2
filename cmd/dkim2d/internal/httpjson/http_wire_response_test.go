package httpjson

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
)

// TestPreMarshaledStatusResponseFreezesExactTagHeadAnd304Shapes covers representation metadata.
func TestPreMarshaledStatusResponseFreezesExactTagHeadAnd304Shapes(t *testing.T) {
	t.Parallel()
	value := generated.HealthResponse{
		ApiVersion: generated.V1,
		Draft:      generated.DraftIetfDkimDkim2Spec05,
		Status:     generated.Alive,
	}
	get, err := newStatusResponse(value, false, "Sat, 25 Jul 2026 08:00:00 GMT", true)
	if err != nil {
		t.Fatalf("newStatusResponse() error = %v", err)
	}
	sum := sha256.Sum256(get.body)
	wantTag := `"` + hex.EncodeToString(sum[:]) + `"`
	if get.etag != wantTag {
		t.Fatalf("ETag = %q, want %q", get.etag, wantTag)
	}

	getRecorder := httptest.NewRecorder()
	if err := get.write(getRecorder); err != nil {
		t.Fatalf("GET write() error = %v", err)
	}
	if getRecorder.Code != http.StatusOK || getRecorder.Body.String() != string(get.body) ||
		getRecorder.Header().Get("Content-Length") == "" || getRecorder.Header().Get("ETag") != wantTag {
		t.Fatal("GET response bytes or metadata differ")
	}

	head := get
	head.head = true
	headRecorder := httptest.NewRecorder()
	if err := head.write(headRecorder); err != nil {
		t.Fatalf("HEAD write() error = %v", err)
	}
	if headRecorder.Code != getRecorder.Code || headRecorder.Body.Len() != 0 ||
		headRecorder.Header().Get("Content-Length") != getRecorder.Header().Get("Content-Length") ||
		headRecorder.Header().Get("ETag") != wantTag {
		t.Fatal("HEAD response is not representation-identical")
	}

	notModifiedRecorder := httptest.NewRecorder()
	notModified, err := get.asNotModified()
	if err != nil {
		t.Fatalf("asNotModified() error = %v", err)
	}
	if err := notModified.write(notModifiedRecorder); err != nil {
		t.Fatalf("304 write() error = %v", err)
	}
	header := notModifiedRecorder.Header()
	if notModifiedRecorder.Code != http.StatusNotModified || notModifiedRecorder.Body.Len() != 0 ||
		header.Get("ETag") != wantTag || header.Get("Cache-Control") != testNoStoreValue ||
		header.Get("Connection") != testCloseValue || header.Get("Date") == "" {
		t.Fatal("304 required metadata differs")
	}
	for _, forbidden := range []string{
		"Content-Length", headerContentType, "X-Content-Type-Options", "Last-Modified",
		"Vary", "Allow", "Retry-After", "Accept-Ranges", "Content-Range",
	} {
		if _, present := header[forbidden]; present {
			t.Fatalf("304 emitted forbidden header %s", forbidden)
		}
	}
}

// TestPreMarshaledErrorResponseFreezesClosedBodyAndHeaders covers exact application errors.
func TestPreMarshaledErrorResponseFreezesClosedBodyAndHeaders(t *testing.T) {
	t.Parallel()
	response, err := newErrorResponse(
		http.StatusServiceUnavailable,
		generated.ErrorResponseCodeServiceOverloaded,
		generated.Availability,
		false,
		"",
		false,
	)
	if err != nil {
		t.Fatalf("newErrorResponse() error = %v", err)
	}
	recorder := httptest.NewRecorder()
	if err := response.write(recorder); err != nil {
		t.Fatalf("write() error = %v", err)
	}
	if recorder.Code != http.StatusServiceUnavailable ||
		recorder.Header().Get("Retry-After") != "1" ||
		recorder.Header().Get("Connection") != testCloseValue ||
		recorder.Header().Get("Cache-Control") != testNoStoreValue ||
		recorder.Header().Get("X-Content-Type-Options") != testNoSniffValue ||
		recorder.Header().Get("Content-Length") == "" ||
		recorder.Header().Get("Date") != "" {
		t.Fatal("503 response headers differ")
	}
	const want = `{"api_version":"v1","category":"availability","code":"service_overloaded","draft":"draft-ietf-dkim-dkim2-spec-05"}`
	if recorder.Body.String() != want {
		t.Fatalf("503 body = %q, want %q", recorder.Body.String(), want)
	}
}

// TestApplyResponseDateFreezesValidatedStatusPolicy proves Date cannot fall back to Go's wall clock.
func TestApplyResponseDateFreezesValidatedStatusPolicy(t *testing.T) {
	t.Parallel()
	const date = "Thu, 01 Jan 1970 00:00:00 GMT"
	for _, testCase := range []struct {
		name    string
		status  int
		present bool
		want    string
	}{
		{name: "204 provider", status: http.StatusNoContent, present: true, want: date},
		{name: "304 provider", status: http.StatusNotModified, present: true, want: date},
		{name: "414 provider", status: http.StatusRequestURITooLong, present: true, want: date},
		{name: "501 provider", status: http.StatusNotImplemented, present: true},
		{name: "505 provider", status: http.StatusHTTPVersionNotSupported, present: true},
		{name: "204 unavailable", status: http.StatusNoContent},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			header := make(http.Header)
			header.Set("Date", "Go-wall-clock-placeholder")
			applyResponseDate(header, testCase.status, date, testCase.present)
			if got := header.Get("Date"); got != testCase.want {
				t.Fatalf("Date = %q, want %q", got, testCase.want)
			}
			if testCase.want == "" {
				if value, present := header["Date"]; !present || value != nil {
					t.Fatal("Date omission did not suppress Go's automatic field")
				}
			}
		})
	}
}

// TestPreMarshaledResponseRejectsForgedStatusCodeCategoryCrossProducts freezes the matrix.
func TestPreMarshaledResponseRejectsForgedStatusCodeCategoryCrossProducts(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		status   int
		code     generated.ErrorResponseCode
		category generated.ErrorResponseCategory
	}{
		{status: http.StatusBadRequest, code: generated.ErrorResponseCodeInternalError, category: generated.Internal},
		{status: http.StatusInternalServerError, code: generated.ErrorResponseCodeInvalidJson, category: generated.Request},
		{status: http.StatusServiceUnavailable, code: generated.ErrorResponseCodeServiceNotReady, category: generated.Request},
		{status: http.StatusForbidden, code: generated.ErrorResponseCodeForbidden, category: generated.Availability},
		{status: http.StatusOK, code: generated.ErrorResponseCodeForbidden, category: generated.Request},
	} {
		if _, err := newErrorResponse(testCase.status, testCase.code, testCase.category, false, "", false); err == nil {
			t.Fatalf("forged matrix row %#v was accepted", testCase)
		}
	}
	if _, err := newJSONResponse(http.StatusCreated, generated.ProcessResponse{}, false, "", false); err == nil {
		t.Fatal("arbitrary JSON success status was accepted")
	}
	if _, err := newJSONResponse(http.StatusOK, generated.ProcessResponse{}, false, "", false); err == nil {
		t.Fatal("forged empty process DTO was accepted")
	}
	if _, err := newStatusResponse(generated.HealthResponse{
		ApiVersion: generated.V1,
		Draft:      generated.DraftIetfDkimDkim2Spec05,
		Status:     "forged",
	}, false, "", false); err == nil {
		t.Fatal("forged status DTO was accepted")
	}
	if _, err := newStatusResponse(struct{}{}, false, "", false); err == nil {
		t.Fatal("parallel status DTO was accepted")
	}
}

// TestProcessWireValidationRejectsSkippedReplayAfterPass proves the final
// response boundary preserves the exact replay coordinator matrix.
func TestProcessWireValidationRejectsSkippedReplayAfterPass(t *testing.T) {
	response := validWireProcessResponse()
	if !validProcessResponse(response) {
		t.Fatal("valid disabled-replay response was rejected")
	}
	response.Replay.Class = generated.NotChecked
	if validProcessResponse(response) {
		t.Fatal("PASS plus accept with skipped replay was accepted")
	}
	response = validWireProcessResponse()
	response.Actions = generated.ActionPlan{{
		Type: generated.AddHeader, Name: generated.AuthenticationResults,
		Value: testInboundPassReport,
	}}
	if !validProcessResponse(response) {
		t.Fatal("daemon-owned process report was rejected")
	}
	response.Actions[0].Value = "mx.example.test; dkim2=fail"
	if validProcessResponse(response) {
		t.Fatal("process report inconsistent with verification was accepted")
	}
	response = validWireProcessResponse()
	response.Actions = generated.ActionPlan{{
		Type: generated.AddHeader, Name: generated.AuthenticationResults,
		Value: testInboundPassReport,
	}}
	response.Disposition = generated.DispositionContinue
	response.Policy.Mode = generated.Testing
	response.Policy.PrimaryReason = generated.TestingModeObserve
	response.Policy.Verdict = generated.PolicyResultVerdictContinue
	response.Replay.Class = generated.NotChecked
	if !validProcessResponse(response) {
		t.Fatal("testing continue report was rejected")
	}
	response.Disposition = generated.DispositionReject
	response.Policy.Verdict = generated.PolicyResultVerdictReject
	if validProcessResponse(response) {
		t.Fatal("rejecting process response carried a report action")
	}
}

// validWireProcessResponse returns one complete PASS-plus-accept response.
func validWireProcessResponse() generated.ProcessResponse {
	return generated.ProcessResponse{
		Actions:     generated.ActionPlan{},
		ApiVersion:  generated.V1,
		Disposition: generated.DispositionAccept,
		Draft:       generated.DraftIetfDkimDkim2Spec05,
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

// TestPreMarshaledResponseBuildersRejectForgedMetadata proves private-type invariants.
func TestPreMarshaledResponseBuildersRejectForgedMetadata(t *testing.T) {
	t.Parallel()
	health := generated.HealthResponse{
		ApiVersion: generated.V1,
		Draft:      generated.DraftIetfDkimDkim2Spec05,
		Status:     generated.Alive,
	}
	if _, err := newStatusResponse(health, false, "forged\r\nX-Leak: value", true); err == nil {
		t.Fatal("forged Date was accepted")
	}
	if _, err := newStatusResponse(health, false, "Fri, 25 Jul 2026 08:00:00 GMT", true); err == nil {
		t.Fatal("wrong-weekday Date was accepted")
	}
	if _, err := newStatusResponse(health, false, "Sat, 25 Jul 2026 08:00:00 UTC", true); err == nil {
		t.Fatal("noncanonical Date was accepted")
	}
	selected, err := newStatusResponse(health, false, "", false)
	if err != nil {
		t.Fatalf("newStatusResponse() error = %v", err)
	}
	if _, err := (preMarshaledResponse{}).asNotModified(); err == nil {
		t.Fatal("forged 304 source was accepted")
	}
	selectedHead := selected
	selectedHead.head = true
	if _, err := selectedHead.asNotModified(); err != nil {
		t.Fatalf("HEAD selected representation could not derive 304: %v", err)
	}
	if _, err := selected.withAllow("GET\r\nX-Leak: value"); err == nil {
		t.Fatal("header-unsafe Allow was accepted")
	}
	methodNotAllowed, err := newErrorResponse(
		http.StatusMethodNotAllowed,
		generated.ErrorResponseCodeMethodNotAllowed,
		generated.Request,
		false,
		"",
		false,
	)
	if err != nil {
		t.Fatalf("newErrorResponse() error = %v", err)
	}
	for _, value := range []string{"GET, HEAD", http.MethodPost} {
		if _, err := methodNotAllowed.withAllow(value); err != nil {
			t.Fatalf("withAllow(%q) error = %v", value, err)
		}
	}
	if _, err := selected.withAllow("GET, HEAD"); err == nil {
		t.Fatal("Allow was attached to a non-405 response")
	}
}
