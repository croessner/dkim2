package httpjson

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	dkim2 "github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
)

const (
	maxErrorResponseBytes   = 4_096
	maxSuccessResponseBytes = 262_144
	jsonContentType         = "application/json"
	cacheControlNoStore     = "no-store"
	connectionCloseValue    = "close"
)

var errWireResponse = errors.New("http response write failure")

// preMarshaledResponse owns one validated exact response representation.
type preMarshaledResponse struct {
	status      int
	body        []byte
	head        bool
	notModified bool
	etag        string
	allow       string
	retryAfter  bool
	date        string
	datePresent bool
}

// newErrorResponse constructs one bounded content-free application error.
func newErrorResponse(
	status int,
	code generated.ErrorResponseCode,
	category generated.ErrorResponseCategory,
	head bool,
	date string,
	datePresent bool,
) (preMarshaledResponse, error) {
	if !validApplicationError(status, code, category) ||
		datePresent && !validHTTPDate(date) {
		return preMarshaledResponse{}, errWireResponse
	}
	if !datePresent {
		date = ""
	}
	body, err := marshalBounded(generated.ErrorResponse{
		ApiVersion: generated.V1,
		Category:   category,
		Code:       code,
		Draft:      generated.DraftIetfDkimDkim2Spec04,
	}, maxErrorResponseBytes)
	if err != nil {
		return preMarshaledResponse{}, err
	}
	return preMarshaledResponse{
		status: status, body: body, head: head,
		retryAfter: status == http.StatusServiceUnavailable,
		date:       date, datePresent: datePresent && status < 500,
	}, nil
}

// newJSONResponse constructs one bounded exact success representation.
func newJSONResponse(
	status int,
	value any,
	head bool,
	date string,
	datePresent bool,
) (preMarshaledResponse, error) {
	if status != http.StatusOK || !validSuccessResponse(value) ||
		datePresent && !validHTTPDate(date) {
		return preMarshaledResponse{}, errWireResponse
	}
	if !datePresent {
		date = ""
	}
	body, err := marshalBounded(value, maxSuccessResponseBytes)
	if err != nil {
		return preMarshaledResponse{}, err
	}
	return preMarshaledResponse{
		status: status, body: body, head: head,
		date: date, datePresent: datePresent && status < 500,
	}, nil
}

// validSuccessResponse validates the exact generated success union.
func validSuccessResponse(value any) bool {
	switch typed := value.(type) {
	case generated.ProcessResponse:
		return validProcessResponse(typed)
	case generated.OperationResponse:
		return validOperationResponse(typed)
	default:
		return false
	}
}

// validApplicationError enforces the one closed status, code, and category matrix.
func validApplicationError(
	status int,
	code generated.ErrorResponseCode,
	category generated.ErrorResponseCategory,
) bool {
	if !code.Valid() || !category.Valid() {
		return false
	}
	switch code {
	case generated.ErrorResponseCodeInvalidJson,
		generated.ErrorResponseCodeInvalidContract,
		generated.ErrorResponseCodeUnsupportedVersion,
		generated.ErrorResponseCodeUnsupportedDraft:
		return status == http.StatusBadRequest && category == generated.Request
	case generated.ErrorResponseCodeForbidden:
		return status == http.StatusForbidden && category == generated.Request
	case generated.ErrorResponseCodeNotFound:
		return status == http.StatusNotFound && category == generated.Request
	case generated.ErrorResponseCodeMethodNotAllowed:
		return status == http.StatusMethodNotAllowed && category == generated.Request
	case generated.ErrorResponseCodeRequestTimeout:
		return status == http.StatusRequestTimeout && category == generated.Request
	case generated.ErrorResponseCodePreconditionFailed:
		return status == http.StatusPreconditionFailed && category == generated.Request
	case generated.ErrorResponseCodeRequestTooLarge:
		return status == http.StatusRequestEntityTooLarge && category == generated.Request
	case generated.ErrorResponseCodeUnsupportedMediaType:
		return status == http.StatusUnsupportedMediaType && category == generated.Request
	case generated.ErrorResponseCodeExpectationFailed:
		return status == http.StatusExpectationFailed && category == generated.Request
	case generated.ErrorResponseCodeInternalError:
		return status == http.StatusInternalServerError && category == generated.Internal
	case generated.ErrorResponseCodeServiceNotReady,
		generated.ErrorResponseCodeServiceOverloaded,
		generated.ErrorResponseCodeRequestDeadline:
		return status == http.StatusServiceUnavailable && category == generated.Availability
	default:
		return false
	}
}

// newStatusResponse constructs a status-route 200 representation and strong entity tag.
func newStatusResponse(
	value any,
	head bool,
	date string,
	datePresent bool,
) (preMarshaledResponse, error) {
	if !validStatusResponse(value) || datePresent && !validHTTPDate(date) {
		return preMarshaledResponse{}, errWireResponse
	}
	if !datePresent {
		date = ""
	}
	body, err := marshalBounded(value, maxSuccessResponseBytes)
	if err != nil {
		return preMarshaledResponse{}, err
	}
	response := preMarshaledResponse{
		status: http.StatusOK, body: body, head: head,
		date: date, datePresent: datePresent,
	}
	sum := sha256.Sum256(response.body)
	response.etag = `"` + hex.EncodeToString(sum[:]) + `"`
	return response, nil
}

// validStatusResponse accepts only exact health or readiness singleton DTOs.
func validStatusResponse(value any) bool {
	switch response := value.(type) {
	case generated.HealthResponse:
		return response.ApiVersion == generated.V1 &&
			response.Draft == generated.DraftIetfDkimDkim2Spec04 &&
			response.Status == generated.Alive
	case generated.ReadinessResponse:
		return response.ApiVersion == generated.V1 &&
			response.Draft == generated.DraftIetfDkimDkim2Spec04 &&
			response.Status == generated.Ready
	default:
		return false
	}
}

// validProcessResponse validates every closed generated enum and coherence rule before commit.
func validProcessResponse(response generated.ProcessResponse) bool {
	if response.ApiVersion != generated.V1 ||
		response.Draft != generated.DraftIetfDkimDkim2Spec04 ||
		!response.Disposition.Valid() ||
		!validProcessActions(response) ||
		!response.Replay.Class.Valid() ||
		!validVerificationResponse(response.Verification) ||
		!validPolicyResponse(response.Policy) {
		return false
	}
	switch response.Replay.Class {
	case generated.Disabled, generated.FirstSeen:
		return response.Disposition == generated.DispositionAccept &&
			response.Verification.State == generated.PASS &&
			response.Policy.Verdict == generated.PolicyResultVerdictAccept
	case generated.Replayed:
		return response.Disposition == generated.DispositionReject &&
			response.Verification.State == generated.PASS &&
			response.Policy.Verdict == generated.PolicyResultVerdictAccept
	case generated.Indeterminate:
		return response.Disposition == generated.DispositionTempfail &&
			response.Verification.State == generated.PASS &&
			response.Policy.Verdict == generated.PolicyResultVerdictAccept
	case generated.NotChecked:
		return (response.Verification.State != generated.PASS ||
			response.Policy.Verdict != generated.PolicyResultVerdictAccept) &&
			string(response.Disposition) == string(response.Policy.Verdict)
	default:
		return false
	}
}

// validProcessActions validates the sole daemon-owned RFC 8601 projection.
func validProcessActions(response generated.ProcessResponse) bool {
	if response.Disposition != generated.DispositionAccept {
		return len(response.Actions) == 0
	}
	if len(response.Actions) == 0 {
		return true
	}
	if len(response.Actions) != 1 {
		return false
	}
	action := response.Actions[0]
	result, ok := authenticationResult(response.Verification.State)
	suffix := "; dkim2=" + result
	if !ok || action.Type != generated.AddHeader ||
		action.Name != generated.AuthenticationResults ||
		!strings.HasSuffix(action.Value, suffix) {
		return false
	}
	return validSigningDomain(strings.TrimSuffix(action.Value, suffix))
}

// validOperationResponse validates one complete sign or revision response.
func validOperationResponse(response generated.OperationResponse) bool {
	if response.ApiVersion != generated.V1 ||
		response.Draft != generated.DraftIetfDkimDkim2Spec04 ||
		!response.Operation.Valid() || !response.Result.Valid() ||
		!response.Disposition.Valid() ||
		!validWireOperationOutcome(response.Result, response.Disposition) ||
		!validOperationActionMatrix(response.Operation, response.Disposition, response.Actions) {
		return false
	}
	for _, action := range response.Actions {
		if action.Type != generated.AddHeader || !action.Name.Valid() ||
			action.Value == "" || len(action.Value) > 65535 ||
			strings.ContainsAny(action.Value, "\r\n\x00") {
			return false
		}
	}
	return true
}

// validWireOperationOutcome enforces the generated result/disposition matrix.
func validWireOperationOutcome(
	result generated.OperationResponseResult,
	disposition generated.Disposition,
) bool {
	switch result {
	case generated.OperationResponseResultPass:
		return disposition == generated.DispositionAccept ||
			disposition == generated.DispositionContinue
	case generated.OperationResponseResultFail,
		generated.OperationResponseResultPermerror:
		return disposition == generated.DispositionReject
	case generated.OperationResponseResultTemperror:
		return disposition == generated.DispositionTempfail
	default:
		return false
	}
}

// validVerificationResponse validates one complete generated verification projection.
func validVerificationResponse(response generated.VerificationResult) bool {
	if !response.State.Valid() || !response.PrimaryReason.Valid() ||
		!response.Scope.Valid() || !response.HistoricalContent.Valid() ||
		!response.HistoricalSignatures.Valid() || !response.CustodyStructure.Valid() ||
		len(response.Checks) == 0 || len(response.Checks) > dkim2.HardMaxCheckFacts ||
		len(response.SignatureSets) > dkim2.HardMaxSignatureFacts {
		return false
	}
	if response.Target != nil &&
		(!validCanonicalUint64(response.Target.Sequence) || !validCanonicalUint64(response.Target.Instance)) {
		return false
	}
	for _, check := range response.Checks {
		if !check.Class.Valid() || !check.Reason.Valid() {
			return false
		}
	}
	for _, signature := range response.SignatureSets {
		if !signature.Algorithm.Valid() || !signature.Status.Valid() ||
			!signature.Reason.Valid() || !signature.KeyPolicy.StrictIdentityApplicable.Valid() {
			return false
		}
	}
	return true
}

// validPolicyResponse validates one complete generated local-policy projection.
func validPolicyResponse(response generated.PolicyResult) bool {
	if !response.Mode.Valid() || !response.Verdict.Valid() ||
		!response.PrimaryReason.Valid() || !response.DoNotModify.Valid() ||
		!response.DoNotExplode.Valid() || !response.Feedback.HistoryCoverage.Valid() ||
		len(response.Findings) == 0 || len(response.Findings) > dkim2.HardMaxPolicyFindings ||
		(response.Feedback.RelaySequence != nil) != response.Feedback.RelayRequired {
		return false
	}
	if response.Feedback.RelaySequence != nil &&
		!validCanonicalUint64(*response.Feedback.RelaySequence) {
		return false
	}
	for _, finding := range response.Findings {
		if !finding.Reason.Valid() || !finding.Severity.Valid() ||
			finding.Sequence != nil && !validCanonicalUint64(*finding.Sequence) {
			return false
		}
	}
	return true
}

// validCanonicalUint64 validates one positive canonical decimal response identifier.
func validCanonicalUint64(value string) bool {
	if value == "" || value[0] == '0' {
		return false
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil && parsed > 0 && strconv.FormatUint(parsed, 10) == value
}

// asNotModified derives the exact minimal 304 shape from a selected status response.
func (r preMarshaledResponse) asNotModified() (preMarshaledResponse, error) {
	if r.status != http.StatusOK || r.etag == "" || len(r.body) == 0 ||
		r.notModified || r.allow != "" || r.retryAfter {
		return preMarshaledResponse{}, errWireResponse
	}
	return preMarshaledResponse{
		status: http.StatusNotModified, head: true, notModified: true, etag: r.etag,
		date: r.date, datePresent: r.datePresent,
	}, nil
}

// withAllow adds one frozen method inventory to a 405 response.
func (r preMarshaledResponse) withAllow(value string) (preMarshaledResponse, error) {
	if r.status != http.StatusMethodNotAllowed ||
		value != "GET, HEAD" && value != http.MethodPost && value != http.MethodGet {
		return preMarshaledResponse{}, errWireResponse
	}
	r.allow = value
	return r, nil
}

// VisitGetHealthResponse writes a generated-interface compatible exact response.
func (r preMarshaledResponse) VisitGetHealthResponse(writer http.ResponseWriter) error {
	return r.write(writer)
}

// VisitHeadHealthResponse writes a generated-interface compatible exact response.
func (r preMarshaledResponse) VisitHeadHealthResponse(writer http.ResponseWriter) error {
	return r.write(writer)
}

// VisitGetReadinessResponse writes a generated-interface compatible exact response.
func (r preMarshaledResponse) VisitGetReadinessResponse(writer http.ResponseWriter) error {
	return r.write(writer)
}

// VisitHeadReadinessResponse writes a generated-interface compatible exact response.
func (r preMarshaledResponse) VisitHeadReadinessResponse(writer http.ResponseWriter) error {
	return r.write(writer)
}

// VisitProcessMessageResponse writes a generated-interface compatible exact response.
func (r preMarshaledResponse) VisitProcessMessageResponse(writer http.ResponseWriter) error {
	return r.write(writer)
}

type operationSignResponse struct{ preMarshaledResponse }

// VisitSignMessageResponse writes one exact generated-interface response.
func (r operationSignResponse) VisitSignMessageResponse(writer http.ResponseWriter) error {
	return r.write(writer)
}

type operationReviseResponse struct{ preMarshaledResponse }

// VisitReviseMessageResponse writes one exact generated-interface response.
func (r operationReviseResponse) VisitReviseMessageResponse(writer http.ResponseWriter) error {
	return r.write(writer)
}

// write commits the frozen headers and writes all selected body bytes.
func (r preMarshaledResponse) write(writer http.ResponseWriter) error {
	if writer == nil || r.status < 100 || r.status > 599 {
		return errWireResponse
	}
	header := writer.Header()
	clear(header)
	header.Set("Cache-Control", cacheControlNoStore)
	header.Set("Connection", connectionCloseValue)
	applyResponseDate(header, r.status, r.date, r.datePresent)
	if r.etag != "" {
		header.Set("ETag", r.etag)
	}
	if r.allow != "" {
		header.Set("Allow", r.allow)
	}
	if r.retryAfter {
		header.Set("Retry-After", "1")
	}
	if !r.notModified {
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set(headerContentType, jsonContentType)
		header.Set("Content-Length", strconv.Itoa(len(r.body)))
	}
	writer.WriteHeader(r.status)
	if r.head || r.notModified || len(r.body) == 0 {
		return nil
	}
	for body := r.body; len(body) > 0; {
		written, err := writer.Write(body)
		if written > 0 {
			body = body[written:]
		}
		if err != nil || written == 0 {
			return errWireResponse
		}
	}
	return nil
}

// applyResponseDate seeds or suppresses Go's automatic Date using the validated provider policy.
func applyResponseDate(
	header http.Header,
	status int,
	date string,
	present bool,
) {
	if present && status >= 200 && status <= 499 {
		header.Set("Date", date)
		return
	}
	header["Date"] = nil
}

// marshalBounded serializes one closed generated DTO without a trailing newline.
func marshalBounded(value any, limit int) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil || len(body) > limit {
		return nil, errWireResponse
	}
	return body, nil
}

// String returns a content-free response representation.
func (preMarshaledResponse) String() string { return "dkim2d_http_response" }

// GoString returns a content-free response representation.
func (preMarshaledResponse) GoString() string { return "dkim2d_http_response" }

// Format prevents formatting from traversing response identifiers.
func (preMarshaledResponse) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "dkim2d_http_response")
}
