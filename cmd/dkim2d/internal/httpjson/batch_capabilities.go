package httpjson

import (
	"context"
	"net/http"
	"strings"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
)

// batchCapabilities advertises actual implementation bounds without resolving keys or signing.
func batchCapabilities() generated.BatchRevisionCapabilities {
	return generated.BatchRevisionCapabilities{
		ApiVersion: generated.V1, Draft: generated.DraftIetfDkimDkim2Spec06,
		Protocol: generated.BatchRevisionV1, OriginalCurrent: true, FullFanout: true, ControlledVia: true,
		MaxCopies: app.MaxBatchRevisionCopies, MaxControlledHops: 1,
		MaxAggregateMessageBytes: app.MaxBatchRevisionMessageBytes,
		MaxRequestBytes:          maxProcessBodyBytes, MaxResponseBytes: maxSuccessResponseBytes,
		MaxHeaderFields: 3, ExternalNullSender: false,
	}
}

// serveBatchCapabilities admits only one bodyless and separately authenticated capability query.
func (h *HTTPBoundary) serveBatchCapabilities(writer *boundaryWriter, request *http.Request, facts transportFacts) {
	if request.Method != http.MethodGet {
		date, present := responseDate(request.Context())
		response, err := newErrorResponse(http.StatusMethodNotAllowed,
			generated.ErrorResponseCodeMethodNotAllowed, generated.Request,
			request.Method == http.MethodHead, date, present)
		if err == nil {
			response, err = response.withAllow(metricsAllowMethod)
		}
		h.writePrepared(writer, request, response, err)
		return
	}
	if facts.expect != expectNone {
		h.writeError(writer, request, http.StatusExpectationFailed,
			generated.ErrorResponseCodeExpectationFailed, generated.Request)
		return
	}
	if invalidBatchCapabilitiesRequest(request, facts) {
		h.writeError(writer, request, http.StatusBadRequest,
			generated.ErrorResponseCodeInvalidContract, generated.Request)
		return
	}
	request, authenticated := authenticateOperationCapability(request, h.batchReviseMatcher)
	if !authenticated {
		h.writeError(writer, request, http.StatusForbidden,
			generated.ErrorResponseCodeForbidden, generated.Request)
		return
	}
	if request.Context().Err() != nil {
		h.writeContextFailure(writer, request)
		return
	}
	if !h.readiness.Ready() {
		h.writeError(writer, request, http.StatusServiceUnavailable,
			generated.ErrorResponseCodeServiceNotReady, generated.Availability)
		return
	}
	h.generated.GetBatchRevisionCapabilities(writer, request)
}

// invalidBatchCapabilitiesRequest rejects ambiguous request metadata without inspecting message data.
func invalidBatchCapabilitiesRequest(request *http.Request, facts transportFacts) bool {
	if strings.Contains(request.RequestURI, "?") || request.ContentLength != 0 || facts.framing != framingAbsent {
		return true
	}
	for _, name := range []string{headerContentType, "Content-Encoding", "If-Match", "If-None-Match",
		"If-Modified-Since", "If-Unmodified-Since", "If-Range"} {
		if hasHeader(request.Header, name) {
			return true
		}
	}
	return false
}

// GetBatchRevisionCapabilities projects the fixed contract only for an admitted batch service.
func (a *strictAdapter) GetBatchRevisionCapabilities(ctx context.Context,
	_ generated.GetBatchRevisionCapabilitiesRequestObject) (generated.GetBatchRevisionCapabilitiesResponseObject, error) {
	if a == nil || !localCapabilityAuthenticated(ctx) {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	if service, ok := a.operations.(app.BatchRevisionService); !ok || nilInterfaceValue(service) {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	date, present := responseDate(ctx)
	response, err := newJSONResponse(http.StatusOK, batchCapabilities(), false, date, present)
	if err != nil {
		return nil, err
	}
	return batchCapabilitiesResponse{response}, nil
}

type batchCapabilitiesResponse struct{ preMarshaledResponse }

// VisitGetBatchRevisionCapabilitiesResponse emits the bounded protected-route result.
func (r batchCapabilitiesResponse) VisitGetBatchRevisionCapabilitiesResponse(writer http.ResponseWriter) error {
	return r.write(writer)
}
