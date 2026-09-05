package httpjson

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	dkim2 "github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
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
		Draft:      generated.DraftIetfDkimDkim2Spec06,
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
	case generated.DSNPropagateResponse:
		return validPropagationResponse(typed)
	case generated.DSNPropagateCommitResponse:
		return validPropagationCommitResponse(typed)
	default:
		return false
	}
}

// validPropagationResponse validates the closed propagation contract before
// commit: every enum, the projection, this operation's own result and
// disposition coherence rule, and the presence rules of the two optional
// members, so that an incoherent internal result never reaches the wire.
func validPropagationResponse(response generated.DSNPropagateResponse) bool {
	if response.ApiVersion != generated.V1 ||
		response.Draft != generated.DraftIetfDkimDkim2Spec06 ||
		response.Operation != generated.PropagationOperationDeliveryStatusPropagation ||
		!response.Result.Valid() || !response.Disposition.Valid() ||
		!response.Replay.Class.Valid() ||
		!validWirePropagationOutcome(response.Result, response.Disposition) ||
		!validWirePropagationProjection(response) {
		return false
	}
	if (response.PropagationFailure != nil) != (response.Result == generated.PropagationResultPermerror) ||
		response.PropagationFailure != nil && !response.PropagationFailure.Valid() {
		return false
	}
	if (response.Propagation != nil) != (response.Disposition == generated.PropagationDispositionAccept) {
		return false
	}
	return response.Propagation == nil || validPropagationOutput(*response.Propagation)
}

// validWirePropagationOutcome enforces the propagation result/disposition
// matrix: pass permits accept or discard, fail requires reject, permerror
// requires discard, and temperror requires tempfail.
func validWirePropagationOutcome(
	result generated.DSNPropagateResponseResult,
	disposition generated.PropagationDisposition,
) bool {
	switch result {
	case generated.PropagationResultPass:
		return disposition == generated.PropagationDispositionAccept ||
			disposition == generated.PropagationDispositionDiscard
	case generated.PropagationResultFail:
		return disposition == generated.PropagationDispositionReject
	case generated.PropagationResultPermerror:
		return disposition == generated.PropagationDispositionDiscard
	case generated.PropagationResultTemperror:
		return disposition == generated.PropagationDispositionTempfail
	default:
		return false
	}
}

// validWirePropagationProjection enforces where the optional delivery-status
// member may be absent. Only the two outcomes decided before the evaluation
// may omit it: a notification with no DKIM2 field family, which is a
// permanent refusal, and an unusable outer assessment, which is temporary.
// Every present projection must be complete.
func validWirePropagationProjection(response generated.DSNPropagateResponse) bool {
	if response.DeliveryStatus == nil {
		return response.Result == generated.PropagationResultFail ||
			response.Result == generated.PropagationResultTemperror
	}
	return validDeliveryStatusProjection(*response.DeliveryStatus)
}

// validDeliveryStatusProjection validates every closed projection member.
func validDeliveryStatusProjection(projection generated.DeliveryStatusProjection) bool {
	return projection.Structure.Valid() && projection.Embedded.Valid() &&
		projection.LocalHop.Valid() && projection.OuterAlignment.Valid() &&
		projection.RecipientLinkage.Valid() && projection.Propagation.Valid()
}

// validPropagationOutput validates the bounded signed-notification member.
func validPropagationOutput(output generated.PropagationOutput) bool {
	raw, rawErr := output.RawRfc5322Base64.Bytes()
	nextHop, nextHopErr := output.NextHopRecipient.Bytes()
	token, tokenErr := output.CommitToken.Bytes()
	return rawErr == nil && len(raw) > 0 && nextHopErr == nil && len(nextHop) > 0 &&
		len(nextHop) <= maxSMTPPathBytes && tokenErr == nil &&
		app.ValidPropagationCommitToken(string(token))
}

// validPropagationCommitResponse validates the closed committed singleton.
func validPropagationCommitResponse(response generated.DSNPropagateCommitResponse) bool {
	return response.ApiVersion == generated.V1 &&
		response.Draft == generated.DraftIetfDkimDkim2Spec06 &&
		response.State == generated.PropagationStateCommitted
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
	case generated.ErrorResponseCodePropagationCommitUnresolved:
		return status == http.StatusConflict && category == generated.Request
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
			response.Draft == generated.DraftIetfDkimDkim2Spec06 &&
			response.Status == generated.Alive
	case generated.ReadinessResponse:
		return response.ApiVersion == generated.V1 &&
			response.Draft == generated.DraftIetfDkimDkim2Spec06 &&
			response.Status == generated.Ready
	default:
		return false
	}
}

// validProcessResponse validates every closed generated enum and coherence rule before commit.
func validProcessResponse(response generated.ProcessResponse) bool {
	if response.ApiVersion != generated.V1 ||
		response.Draft != generated.DraftIetfDkimDkim2Spec06 ||
		!response.Disposition.Valid() ||
		!validProcessActions(response) ||
		!response.Replay.Class.Valid() ||
		!validAuthenticationResponse(response.Authentication, response.Verification.State, response.Replay.Class) ||
		!validVerificationResponse(response.Verification) ||
		!validVerifierProjection(response.VerifierProjection, response.Verification) ||
		!validPolicyResponse(response.Policy) {
		return false
	}
	switch response.Replay.Class {
	case generated.Disabled, generated.FirstSeen, generated.Exploded:
		return response.Verification.State == generated.PASS &&
			string(response.Disposition) == string(response.Policy.Verdict)
	case generated.Replayed:
		return response.Disposition == generated.DispositionReject &&
			response.Verification.State == generated.PASS &&
			response.Policy.Verdict == generated.PolicyResultVerdictReject
	case generated.Indeterminate:
		return response.Disposition == generated.DispositionTempfail &&
			response.Verification.State == generated.PASS &&
			response.Policy.Verdict == generated.PolicyResultVerdictTempfail
	case generated.NotChecked:
		return (response.Verification.State != generated.PASS ||
			response.Policy.Verdict != generated.PolicyResultVerdictAccept) &&
			string(response.Disposition) == string(response.Policy.Verdict)
	default:
		return false
	}
}

// validVerifierProjection enforces presence and closed wire coherence for complete PASS evidence.
func validVerifierProjection(projection *generated.VerifierProjection, verification generated.VerificationResult) bool {
	required := verification.State == generated.PASS && verification.Scope == generated.Chain &&
		verification.CustodyStructure != generated.VerificationResultCustodyStructureTerminalNdRequiresOob
	if (projection != nil) != required {
		return false
	}
	if projection == nil {
		return true
	}
	if projection.Schema != generated.Dkim2VerifierProjectionV1 || projection.Draft != generated.DraftIetfDkimDkim2Spec06 ||
		projection.BindingAlgorithm != generated.Sha256 || len(projection.Binding) != 32 ||
		len(projection.Hops) == 0 || len(projection.Hops) > 128 || verification.Target == nil ||
		strconv.Itoa(len(projection.Hops)) != verification.Target.Sequence {
		return false
	}
	for index, hop := range projection.Hops {
		if !validVerifierHop(hop, index) {
			return false
		}
	}
	last := projection.Hops[len(projection.Hops)-1]
	return last.Sequence == verification.Target.Sequence && last.MessageInstance == verification.Target.Instance
}

// validVerifierHop validates bounded closed record shape without recreating verifier-owned bindings.
func validVerifierHop(hop generated.VerifierHop, index int) bool {
	if !validVerifierHopShape(hop, index) || !validVerifierCustody(hop, index) {
		return false
	}

	return validVerifierRecipe(hop)
}

// validVerifierHopShape validates bounded scalar and collection shape.
func validVerifierHopShape(hop generated.VerifierHop, index int) bool {
	return hop.Sequence == strconv.Itoa(index+1) && validCanonicalUint64(hop.MessageInstance) &&
		len(hop.HopBinding) == 32 && validSigningDomain(hop.SignerDomain) &&
		len(hop.SignatureAlgorithms) > 0 && len(hop.SignatureAlgorithms) <= 4 &&
		sortedUniqueVerifierAlgorithms(hop.SignatureAlgorithms) && hop.SignatureState == generated.VerifierHopSignatureStatePass &&
		hop.CustodyTransition.Valid() && hop.RecipeMode.Valid() && hop.RecipeBodyMode.Valid() &&
		hop.HistoryHeaderState.Valid() && hop.HistoryBodyState.Valid() && hop.BodyAvailability.Valid() &&
		len(hop.RecipeDigest) == 32 && len(hop.AffectedHeaders) <= 128 && len(hop.ChangeClasses) <= 2 &&
		hop.ChangeCount == len(hop.ChangeClasses) && hop.AffectedHeaderCount == len(hop.AffectedHeaders) &&
		sort.StringsAreSorted(hop.AffectedHeaders) && sortedUniqueStrings(hop.AffectedHeaders) &&
		sortedUniqueVerifierChanges(hop.ChangeClasses)
}

// validVerifierCustody validates the ordered custody role without admitting terminal OOB authority.
func validVerifierCustody(hop generated.VerifierHop, index int) bool {
	return (index != 0 || hop.CustodyTransition == generated.VerifierHopCustodyTransitionOrigin) &&
		(index <= 0 || hop.CustodyTransition != generated.VerifierHopCustodyTransitionOrigin) &&
		hop.CustodyTransition != generated.VerifierHopCustodyTransitionTerminalNextDomain
}

// validVerifierRecipe validates coherence between the normalized Recipe facts.
func validVerifierRecipe(hop generated.VerifierHop) bool {
	if hop.RecipeHasHeaderChanges != (len(hop.AffectedHeaders) > 0) ||
		hop.BodyAvailability == generated.VerifierHopBodyAvailabilityUnavailable != (hop.HistoryBodyState == generated.VerifierHistoryStateUnavailable) {
		return false
	}
	if hop.RecipeMode == generated.Unchanged {
		return !hop.RecipeHasHeaderChanges && hop.RecipeBodyMode == generated.VerifierHopRecipeBodyModeAbsent && len(hop.ChangeClasses) == 0
	}
	return hop.RecipeMode == generated.Applied &&
		(hop.RecipeHasHeaderChanges || hop.RecipeBodyMode != generated.VerifierHopRecipeBodyModeAbsent)
}

// sortedUniqueVerifierAlgorithms validates lexical ordering and the closed generated enum.
func sortedUniqueVerifierAlgorithms(values []generated.VerifierHopSignatureAlgorithms) bool {
	stringsView := make([]string, len(values))
	for index, value := range values {
		if !value.Valid() {
			return false
		}
		stringsView[index] = string(value)
	}
	return sortedUniqueStrings(stringsView)
}

// sortedUniqueVerifierChanges validates lexical ordering and the closed generated enum.
func sortedUniqueVerifierChanges(values []generated.VerifierHopChangeClasses) bool {
	stringsView := make([]string, len(values))
	for index, value := range values {
		if !value.Valid() {
			return false
		}
		stringsView[index] = string(value)
	}
	return sortedUniqueStrings(stringsView)
}

// sortedUniqueStrings validates strict ascending lexical byte order.
func sortedUniqueStrings(values []string) bool {
	for index, value := range values {
		if value == "" || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

// validAuthenticationResponse enforces the Draft-06 final authentication projection.
func validAuthenticationResponse(
	authentication generated.AuthenticationResult,
	verification generated.VerificationState,
	replay generated.ReplayResultClass,
) bool {
	if !authentication.State.Valid() || !authentication.PrimaryReason.Valid() {
		return false
	}
	switch replay {
	case generated.Replayed:
		return authentication.State == generated.FAIL &&
			authentication.PrimaryReason == generated.AuthenticationResultPrimaryReasonDuplicateMessageWithoutExploded
	case generated.Indeterminate:
		return authentication.State == generated.TEMPERROR &&
			(authentication.PrimaryReason == generated.AuthenticationResultPrimaryReasonReplayIndeterminate ||
				authentication.PrimaryReason == generated.AuthenticationResultPrimaryReasonReplayEvidenceUnavailable)
	case generated.Disabled, generated.FirstSeen, generated.Exploded, generated.NotChecked:
		return authentication.State == verification
	default:
		return false
	}
}

// validProcessActions validates the sole daemon-owned RFC 8601 projection.
func validProcessActions(response generated.ProcessResponse) bool {
	if response.Disposition != generated.DispositionAccept &&
		response.Disposition != generated.DispositionContinue {
		return len(response.Actions) == 0
	}
	if len(response.Actions) == 0 {
		return true
	}
	if len(response.Actions) != 1 {
		return false
	}
	action := response.Actions[0]
	result, ok := authenticationResult(response.Authentication.State)
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
		response.Draft != generated.DraftIetfDkimDkim2Spec06 ||
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
	if !verificationCoverageCoherent(response.State, response.Scope, response.HistoricalContent, response.HistoricalSignatures) {
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

func verificationCoverageCoherent(state generated.VerificationState, scope generated.VerificationResultScope, content generated.VerificationResultHistoricalContent, signatures generated.VerificationResultHistoricalSignatures) bool {
	if state == generated.PASS {
		return scope == generated.Chain &&
			(content == generated.VerificationResultHistoricalContentComplete || content == generated.VerificationResultHistoricalContentPartial) &&
			signatures == generated.VerificationResultHistoricalSignaturesComplete
	}
	return scope == generated.Current && content == generated.VerificationResultHistoricalContentNotEvaluated && signatures == generated.VerificationResultHistoricalSignaturesNotEvaluated
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

type operationDeliveryStatusResponse struct{ preMarshaledResponse }

// VisitSignDeliveryStatusResponse writes one exact generated-interface response.
func (r operationDeliveryStatusResponse) VisitSignDeliveryStatusResponse(writer http.ResponseWriter) error {
	return r.write(writer)
}

type propagationResponse struct{ preMarshaledResponse }

// VisitPropagateDeliveryStatusResponse writes one exact generated-interface response.
func (r propagationResponse) VisitPropagateDeliveryStatusResponse(writer http.ResponseWriter) error {
	return r.write(writer)
}

type propagationCommitResponse struct{ preMarshaledResponse }

// VisitCommitDeliveryStatusPropagationResponse writes one exact generated-interface response.
func (r propagationCommitResponse) VisitCommitDeliveryStatusPropagationResponse(
	writer http.ResponseWriter,
) error {
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
