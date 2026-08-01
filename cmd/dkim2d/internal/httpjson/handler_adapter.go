package httpjson

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/observability"
)

type strictFailureClass uint8

const (
	strictFailureInternal strictFailureClass = iota + 1
	strictFailureCanceled
	strictFailureDeadline
	strictFailureInvalidContract
	strictFailureRequestTooLarge
)

// strictAdapterError reports one closed generated-handler failure.
type strictAdapterError struct {
	class strictFailureClass
}

// Error returns a constant content-free strict-adapter diagnostic.
func (*strictAdapterError) Error() string { return "http strict adapter failure" }

// Is recognizes one strict-adapter failure class.
func (e *strictAdapterError) Is(target error) bool {
	other, ok := target.(*strictAdapterError)
	return ok && e != nil && e.class == other.class
}

// readinessSource is the no-I/O readiness snapshot seam.
type readinessSource interface {
	Ready() bool
}

// inboundProcessService is the immutable app processing seam.
type inboundProcessService interface {
	Process(context.Context, dkim2.VerifyRequest) (app.InboundResult, error)
}

// strictAdapter maps generated operation objects to immutable app services.
type strictAdapter struct {
	readiness  readinessSource
	processor  inboundProcessService
	operations app.OperationService
	metrics    *observability.Metrics
}

// newStrictAdapter constructs one generated strict-server implementation.
func newStrictAdapter(
	readiness readinessSource,
	processor inboundProcessService,
	dependencies ...any,
) (*strictAdapter, error) {
	if nilInterfaceValue(readiness) || nilInterfaceValue(processor) {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	var metrics *observability.Metrics
	var operations app.OperationService
	for _, dependency := range dependencies {
		switch typed := dependency.(type) {
		case *observability.Metrics:
			if metrics != nil || typed == nil {
				return nil, &strictAdapterError{class: strictFailureInternal}
			}
			metrics = typed
		case app.OperationService:
			if operations != nil || nilInterfaceValue(typed) {
				return nil, &strictAdapterError{class: strictFailureInternal}
			}
			operations = typed
		default:
			return nil, &strictAdapterError{class: strictFailureInternal}
		}
	}
	if metrics == nil {
		var err error
		metrics, err = observability.NewMetrics()
		if err != nil {
			return nil, &strictAdapterError{class: strictFailureInternal}
		}
	}
	if metrics == nil {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	return &strictAdapter{
		readiness: readiness, processor: processor, operations: operations, metrics: metrics,
	}, nil
}

// GetMetrics returns the generated representation for contract-level callers.
//
// The outer boundary owns the stricter wire content type and request policy.
func (a *strictAdapter) GetMetrics(
	ctx context.Context,
	_ generated.GetMetricsRequestObject,
) (generated.GetMetricsResponseObject, error) {
	if a == nil || a.metrics == nil {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	body, err := a.metrics.Gather()
	if err != nil {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	date, present := responseDate(ctx)
	var datePointer *string
	if present {
		datePointer = &date
	}
	return generated.GetMetrics200TextResponse{
		Body: string(body),
		Headers: generated.GetMetrics200ResponseHeaders{
			CacheControl:        cacheControlNoStore,
			Connection:          connectionCloseValue,
			ContentLength:       strconv.Itoa(len(body)),
			Date:                datePointer,
			XContentTypeOptions: "nosniff",
		},
	}, nil
}

// GetHealth reports content-free process liveness.
func (a *strictAdapter) GetHealth(
	ctx context.Context,
	_ generated.GetHealthRequestObject,
) (generated.GetHealthResponseObject, error) {
	date, datePresent := responseDate(ctx)
	response, err := newStatusResponse(generated.HealthResponse{
		ApiVersion: generated.V1,
		Draft:      generated.DraftIetfDkimDkim2Spec04,
		Status:     generated.Alive,
	}, false, date, datePresent)
	return response, err
}

// HeadHealth reports GET-identical liveness metadata without content.
func (a *strictAdapter) HeadHealth(
	ctx context.Context,
	_ generated.HeadHealthRequestObject,
) (generated.HeadHealthResponseObject, error) {
	date, datePresent := responseDate(ctx)
	response, err := newStatusResponse(generated.HealthResponse{
		ApiVersion: generated.V1,
		Draft:      generated.DraftIetfDkimDkim2Spec04,
		Status:     generated.Alive,
	}, true, date, datePresent)
	return response, err
}

// GetReadiness reports one no-I/O readiness sample.
func (a *strictAdapter) GetReadiness(
	ctx context.Context,
	_ generated.GetReadinessRequestObject,
) (generated.GetReadinessResponseObject, error) {
	return a.readinessResponse(ctx, false)
}

// HeadReadiness reports GET-identical readiness metadata without content.
func (a *strictAdapter) HeadReadiness(
	ctx context.Context,
	_ generated.HeadReadinessRequestObject,
) (generated.HeadReadinessResponseObject, error) {
	return a.readinessResponse(ctx, true)
}

// ProcessMessage maps one validated generated request into the inbound use case.
func (a *strictAdapter) ProcessMessage(
	ctx context.Context,
	request generated.ProcessMessageRequestObject,
) (generated.ProcessMessageResponseObject, error) {
	if a == nil || a.processor == nil || request.Body == nil {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	if ctx != nil && ctx.Err() != nil {
		return nil, classifyStrictContextFailure(ctx)
	}
	ledger, ok := workingSetLedgerFromContext(ctx)
	if !ok || ledger == nil {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	if err := ledger.FinishGeneratedDecode(); err != nil {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	if err := ledger.BeginRequestMapping(); err != nil {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	domainRequest, err := MapProcessRequest(*request.Body)
	if err != nil {
		switch {
		case IsMappingError(err, MappingInvalidContract):
			return nil, &strictAdapterError{class: strictFailureInvalidContract}
		case IsMappingError(err, MappingRequestTooLarge):
			return nil, &strictAdapterError{class: strictFailureRequestTooLarge}
		}
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	if err := ledger.BeginVerifyRequest(); err != nil {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	verifyRequest, err := domainRequest.VerifyRequest()
	if err != nil {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	if err := ledger.FinishRequestMapping(); err != nil {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	if err := ledger.BeginDomainProcessing(); err != nil {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	if ctx != nil && ctx.Err() != nil {
		return nil, classifyStrictContextFailure(ctx)
	}
	result, err := a.processor.Process(ctx, verifyRequest)
	if err != nil {
		return nil, classifyStrictContextFailure(ctx)
	}
	if !result.Valid() {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	if !result.Applicable() {
		date, datePresent := responseDate(ctx)
		var dateHeader *string
		if datePresent {
			dateHeader = &date
		}
		return generated.ProcessMessage204Response{Headers: generated.ProcessMessage204ResponseHeaders{
			CacheControl: cacheControlNoStore,
			Connection:   connectionCloseValue,
			Date:         dateHeader,
		}}, nil
	}
	response, err := MapInboundResult(result, domainRequest.AuthservID())
	if err != nil {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	date, datePresent := responseDate(ctx)
	return newJSONResponse(http.StatusOK, response, false, date, datePresent)
}

// SignMessage maps and executes one generated originator operation.
func (a *strictAdapter) SignMessage(
	ctx context.Context,
	request generated.SignMessageRequestObject,
) (generated.SignMessageResponseObject, error) {
	if a == nil || a.operations == nil || request.Body == nil {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	domainRequest, err := MapSignRequest(*request.Body)
	if err != nil {
		return nil, classifyMappingFailure(err)
	}
	assessment, err := executeSignOperation(ctx, a.operations, domainRequest)
	if err != nil {
		return nil, classifyStrictContextFailure(ctx)
	}
	if !assessment.Valid() {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	if !assessment.Applicable() {
		date, datePresent := responseDate(ctx)
		var dateHeader *string
		if datePresent {
			dateHeader = &date
		}
		return generated.SignMessage204Response{Headers: generated.SignMessage204ResponseHeaders{
			CacheControl: cacheControlNoStore,
			Connection:   connectionCloseValue,
			Date:         dateHeader,
		}}, nil
	}
	result, ok := assessment.Result()
	if !ok {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	response, err := MapOperationResult(result)
	if err != nil {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	date, datePresent := responseDate(ctx)
	wire, err := newJSONResponse(http.StatusOK, response, false, date, datePresent)
	if err != nil {
		return nil, err
	}
	return operationSignResponse{wire}, nil
}

// ReviseMessage maps and executes one generated sealed revision operation.
func (a *strictAdapter) ReviseMessage(
	ctx context.Context,
	request generated.ReviseMessageRequestObject,
) (generated.ReviseMessageResponseObject, error) {
	if a == nil || a.operations == nil || request.Body == nil {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	domainRequest, err := MapReviseRequest(*request.Body)
	if err != nil {
		return nil, classifyMappingFailure(err)
	}
	result, err := executeRevisionOperation(ctx, a.operations, domainRequest)
	if err != nil {
		return nil, classifyStrictContextFailure(ctx)
	}
	response, err := MapOperationResult(result)
	if err != nil {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	date, datePresent := responseDate(ctx)
	wire, err := newJSONResponse(http.StatusOK, response, false, date, datePresent)
	if err != nil {
		return nil, err
	}
	return operationReviseResponse{wire}, nil
}

// classifyMappingFailure maps one bounded DTO admission failure.
func classifyMappingFailure(err error) error {
	if IsMappingError(err, MappingRequestTooLarge) {
		return &strictAdapterError{class: strictFailureRequestTooLarge}
	}
	if IsMappingError(err, MappingInvalidContract) {
		return &strictAdapterError{class: strictFailureInvalidContract}
	}
	return &strictAdapterError{class: strictFailureInternal}
}

// readinessResponse selects exactly ready 200 or closed 503.
func (a *strictAdapter) readinessResponse(
	ctx context.Context,
	head bool,
) (preMarshaledResponse, error) {
	date, datePresent := responseDate(ctx)
	if a == nil || a.readiness == nil || !a.readiness.Ready() {
		return newErrorResponse(
			http.StatusServiceUnavailable,
			generated.ErrorResponseCodeServiceNotReady,
			generated.Availability,
			head,
			date,
			datePresent,
		)
	}
	return newStatusResponse(generated.ReadinessResponse{
		ApiVersion: generated.V1,
		Draft:      generated.DraftIetfDkimDkim2Spec04,
		Status:     generated.Ready,
	}, head, date, datePresent)
}

// responseDate samples only the private connection's validated Date provider.
func responseDate(ctx context.Context) (string, bool) {
	state, ok := transportStateFromContext(ctx)
	if !ok {
		return "", false
	}
	return state.ValidDate()
}

// classifyStrictContextFailure maps exact terminal context without retaining an app error.
func classifyStrictContextFailure(ctx context.Context) (result error) {
	defer func() {
		if recover() != nil {
			result = &strictAdapterError{class: strictFailureInternal}
		}
	}()
	if ctx != nil {
		switch ctx.Err() {
		case context.Canceled:
			return &strictAdapterError{class: strictFailureCanceled}
		case context.DeadlineExceeded:
			return &strictAdapterError{class: strictFailureDeadline}
		}
	}
	return &strictAdapterError{class: strictFailureInternal}
}

// IsStrictAdapterError reports whether err belongs to one closed adapter class.
func IsStrictAdapterError(err error, class strictFailureClass) bool {
	return errors.Is(err, &strictAdapterError{class: class})
}

// String returns a content-free strict-adapter representation.
func (strictAdapter) String() string { return "dkim2d_strict_adapter" }

// GoString returns a content-free strict-adapter representation.
func (strictAdapter) GoString() string { return "dkim2d_strict_adapter" }

// Format prevents formatting from traversing strict-adapter dependencies.
func (strictAdapter) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "dkim2d_strict_adapter")
}

var _ generated.StrictServerInterface = (*strictAdapter)(nil)
