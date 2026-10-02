package httpjson

import (
	"context"
	"net/http"
	"strings"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
)

// batchLimits carries the deployment's enforced batch bounds from the HTTP
// boundary to the generated adapter, so the capability route advertises
// exactly what the transport and mapper accept.
type batchLimits struct {
	aggregate int
	request   int64
}

// configured reports whether the boundary supplied explicit limits.
func (l batchLimits) configured() bool { return l.aggregate != 0 || l.request != 0 }

// valid reports whether both limits lie inside the closed contract.
func (l batchLimits) valid() bool {
	return l.aggregate >= 1 && l.aggregate <= app.HardMaxBatchRevisionMessageBytes &&
		l.request >= 1 && l.request <= maxBatchProcessBodyBytes
}

// aggregateBytes returns the enforced aggregate, or the default when the
// adapter runs without a boundary-supplied value.
func (l batchLimits) aggregateBytes() int {
	if !l.configured() {
		return app.MaxBatchRevisionMessageBytes
	}
	return l.aggregate
}

// requestBytes returns the enforced batch request body ceiling, or the
// closed default-sizing ceiling when no boundary value is present.
func (l batchLimits) requestBytes() int64 {
	if !l.configured() {
		return maxProcessBodyBytes
	}
	return l.request
}

// batchCapabilities advertises the enforced deployment bounds without resolving keys or signing.
func batchCapabilities(limits batchLimits) generated.BatchRevisionCapabilities {
	return generated.BatchRevisionCapabilities{
		ApiVersion: generated.V1, Draft: generated.DraftIetfDkimDkim2Spec06,
		Protocol: generated.BatchRevisionV1, OriginalCurrent: true, FullFanout: true, ControlledVia: true,
		MaxCopies: app.MaxBatchRevisionCopies, MaxControlledHops: 1,
		MaxAggregateMessageBytes: int64(limits.aggregateBytes()),
		MaxRequestBytes:          limits.requestBytes(), MaxResponseBytes: maxSuccessResponseBytes,
		MaxHeaderFields: 3, ExternalNullSender: false,
	}
}

// validBatchCapabilities accepts exactly the fixed protocol facts with
// deployment bounds inside the closed contract.
func validBatchCapabilities(value generated.BatchRevisionCapabilities) bool {
	limits := batchLimits{aggregate: int(value.MaxAggregateMessageBytes), request: value.MaxRequestBytes}
	return value.MaxAggregateMessageBytes <= int64(app.HardMaxBatchRevisionMessageBytes) &&
		limits.valid() && value == batchCapabilities(limits)
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
	response, err := newJSONResponse(http.StatusOK, batchCapabilities(a.batch), false, date, present)
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
