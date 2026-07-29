package httpjson

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/observability"
	"go.opentelemetry.io/otel/trace"
)

const (
	statusAllowMethods   = "GET, HEAD"
	processAllowMethod   = "POST"
	serverAllowMethods   = "GET, HEAD, POST, OPTIONS"
	healthPath           = "/healthz"
	readinessPath        = "/readyz"
	metricsPath          = "/metrics"
	processPath          = "/v1/process"
	signPath             = "/v1/sign"
	revisePath           = "/v1/revise"
	metricsAllowMethod   = "GET"
	observationUnmatched = "unmatched"
	observationProcess   = "process"
	observationSuccess   = "success"
)

var errHTTPBoundaryConfig = errors.New("http boundary configuration failure")

type boundaryAbortSignal struct {
	tag byte
}

var boundaryAbort = &boundaryAbortSignal{tag: 1}

// FatalNotifier marks readiness false and requests orderly process shutdown.
type FatalNotifier interface {
	NotifyFatal()
}

// BoundaryConfig contains the immutable HTTP containment policy.
type BoundaryConfig struct {
	Authority       string
	RequestDeadline time.Duration
	MaxInFlight     int
	MaxWaiters      int
	AdmissionWait   time.Duration
}

// HTTPBoundary owns route, admission, validation, and generated-adapter ordering.
type HTTPBoundary struct {
	authority     string
	deadline      time.Duration
	matcher       capabilityMatcher
	signMatcher   capabilityMatcher
	reviseMatcher capabilityMatcher
	readiness     readinessSource
	validator     *RequestValidator
	admission     *processAdmission
	strict        *strictAdapter
	generated     generated.ServerInterface
	fatal         FatalNotifier
	metrics       *observability.Metrics
	telemetry     *observability.Runtime
}

// NewHTTPBoundary constructs one immutable process-local HTTP handler.
func NewHTTPBoundary(
	config BoundaryConfig,
	matcher capabilityMatcher,
	readiness readinessSource,
	processor inboundProcessService,
	notifier FatalNotifier,
	validator *RequestValidator,
	dependencies ...any,
) (*HTTPBoundary, error) {
	if config.Authority == "" || strings.ContainsAny(config.Authority, "\r\n/?#@") ||
		config.RequestDeadline <= 0 || nilInterfaceValue(matcher) ||
		nilInterfaceValue(readiness) || nilInterfaceValue(processor) ||
		nilInterfaceValue(notifier) || validator == nil {
		return nil, errHTTPBoundaryConfig
	}
	admission, err := newProcessAdmission(
		config.MaxInFlight,
		config.MaxWaiters,
		config.AdmissionWait,
	)
	if err != nil {
		return nil, errHTTPBoundaryConfig
	}
	telemetry, operation, signMatcher, reviseMatcher, dependenciesOK :=
		parseBoundaryDependencies(dependencies)
	if !dependenciesOK {
		return nil, errHTTPBoundaryConfig
	}
	var metrics *observability.Metrics
	if telemetry != nil {
		metrics = telemetry.Metrics()
	}
	if metrics == nil {
		metrics, err = observability.NewMetrics()
		if err != nil {
			return nil, errHTTPBoundaryConfig
		}
	}
	strictDependencies := []any{metrics}
	if !nilInterfaceValue(operation) {
		strictDependencies = append(strictDependencies, operation)
	}
	strict, err := newStrictAdapter(readiness, processor, strictDependencies...)
	if err != nil {
		return nil, errHTTPBoundaryConfig
	}
	boundary := &HTTPBoundary{
		authority:     config.Authority,
		deadline:      config.RequestDeadline,
		matcher:       matcher,
		signMatcher:   signMatcher,
		reviseMatcher: reviseMatcher,
		readiness:     readiness,
		validator:     validator,
		admission:     admission,
		strict:        strict,
		fatal:         notifier,
		metrics:       metrics,
		telemetry:     telemetry,
	}
	boundary.generated = generated.NewStrictHandlerWithOptions(
		strict,
		nil,
		generated.StrictHTTPServerOptions{
			RequestErrorHandlerFunc: func(
				writer http.ResponseWriter,
				request *http.Request,
				_ error,
			) {
				if bounded, ok := writer.(*boundaryWriter); ok {
					boundary.writeInternal(bounded, request)
				}
			},
			ResponseErrorHandlerFunc: func(
				writer http.ResponseWriter,
				request *http.Request,
				err error,
			) {
				if bounded, ok := writer.(*boundaryWriter); ok {
					boundary.writeStrictFailure(bounded, request, err)
				}
			},
		},
	)
	return boundary, nil
}

type signMatcherDependency struct{ capabilityMatcher }
type reviseMatcherDependency struct{ capabilityMatcher }

// parseBoundaryDependencies accepts at most one optional runtime, operation
// service, and each named signing capability.
func parseBoundaryDependencies(
	values []any,
) (*observability.Runtime, app.OperationService, capabilityMatcher, capabilityMatcher, bool) {
	var runtime *observability.Runtime
	var operation app.OperationService
	var signMatcher capabilityMatcher
	var reviseMatcher capabilityMatcher
	for _, value := range values {
		switch typed := value.(type) {
		case *observability.Runtime:
			if runtime != nil || typed == nil {
				return nil, nil, nil, nil, false
			}
			runtime = typed
		case app.OperationService:
			if !nilInterfaceValue(operation) || nilInterfaceValue(typed) {
				return nil, nil, nil, nil, false
			}
			operation = typed
		case signMatcherDependency:
			if !nilInterfaceValue(signMatcher) || nilInterfaceValue(typed.capabilityMatcher) {
				return nil, nil, nil, nil, false
			}
			signMatcher = typed.capabilityMatcher
		case reviseMatcherDependency:
			if !nilInterfaceValue(reviseMatcher) || nilInterfaceValue(typed.capabilityMatcher) {
				return nil, nil, nil, nil, false
			}
			reviseMatcher = typed.capabilityMatcher
		default:
			return nil, nil, nil, nil, false
		}
	}
	enabled := !nilInterfaceValue(operation)
	hasMatcher := !nilInterfaceValue(signMatcher) || !nilInterfaceValue(reviseMatcher)
	if enabled != hasMatcher {
		return nil, nil, nil, nil, false
	}
	return runtime, operation, signMatcher, reviseMatcher, true
}

// Close rejects new process admission and interrupts ordinary waiters.
func (h *HTTPBoundary) Close() {
	if h != nil && h.admission != nil {
		h.admission.Close()
	}
}

// ServeHTTP applies the frozen outer precedence and one-operation policy.
func (h *HTTPBoundary) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if h == nil || writer == nil || request == nil {
		return
	}
	var ownedReservation *processReservation
	var workingContext *workingSetContext
	defer func() {
		if ownedReservation != nil {
			ownedReservation.HandlerDone()
		}
	}()
	originalRequest := request
	defer func() {
		originalRequest.Trailer = nil
		originalRequest.Host = ""
		originalRequest.RemoteAddr = ""
		originalRequest.TransferEncoding = nil
		request.Trailer = nil
		request.Host = ""
		request.RemoteAddr = ""
		request.TransferEncoding = nil
		request.Body = http.NoBody
		request.ContentLength = 0
		originalRequest.Body = http.NoBody
		originalRequest.ContentLength = 0
		workingContext.Clear()
	}()
	committed := &boundaryWriter{ResponseWriter: writer}
	observeHTTP := request.URL != nil && request.URL.Path != metricsPath
	operation, route := httpObservationRoute(request)
	started := time.Now()
	var rootSpan trace.Span
	if observeHTTP {
		h.metrics.HTTPStarted(operation)
		rootContext, span := h.startHTTPSpan(request, route)
		request = request.WithContext(rootContext)
		rootSpan = span
		defer h.completeHTTPObservation(
			committed, operation, httpObservationMethod(request.Method), started, rootSpan,
		)
	}
	clientContext := request.Context()
	defer func() {
		recovered := recover()
		if recovered == boundaryAbort {
			panic(http.ErrAbortHandler)
		}
		if recovered != nil {
			h.notifyFatal()
			if committed.committed {
				if state, ok := transportStateFromContext(request.Context()); ok {
					_ = state.Close()
				}
				panic(http.ErrAbortHandler)
			}
			if clientContext.Err() == context.Canceled {
				if state, ok := transportStateFromContext(request.Context()); ok {
					_ = state.Close()
				}
				panic(http.ErrAbortHandler)
			}
			h.writeError(committed, request, http.StatusInternalServerError,
				generated.ErrorResponseCodeInternalError, generated.Internal)
		}
	}()
	h.serveBoundaryRequest(
		committed,
		&request,
		originalRequest,
		&ownedReservation,
		&workingContext,
	)
}

// startHTTPSpan starts one fresh server root without accepting inbound trace identity.
func (h *HTTPBoundary) startHTTPSpan(
	request *http.Request,
	route string,
) (context.Context, trace.Span) {
	if h == nil || h.telemetry == nil || h.telemetry.Tracing() == nil || request == nil {
		return requestContext(request), trace.SpanFromContext(context.Background())
	}
	methodFact, _ := observability.TextSpanFact("http.request.method", httpObservationMethod(request.Method))
	routeFact, _ := observability.TextSpanFact("http.route", route)
	return h.telemetry.Tracing().StartRoot(
		request.Context(), "dkim2d.http.request", methodFact, routeFact,
	)
}

// requestContext returns a nonnil context for telemetry fallbacks.
func requestContext(request *http.Request) context.Context {
	if request == nil || request.Context() == nil {
		return context.Background()
	}
	return request.Context()
}

// completeHTTPObservation closes bounded metrics, logs, and the root span.
func (h *HTTPBoundary) completeHTTPObservation(
	writer *boundaryWriter,
	operation string,
	method string,
	started time.Time,
	span trace.Span,
) {
	status := http.StatusInternalServerError
	if writer != nil && writer.status >= 200 && writer.status <= 599 {
		status = writer.status
	}
	statusClass := strconv.Itoa(status/100) + "xx"
	h.metrics.HTTPCompleted(operation, statusClass, time.Since(started))
	outcome := observability.SpanCompleted
	if status >= 500 {
		outcome = observability.SpanInternalError
	}
	observability.EndHTTPSpan(span, status, outcome)
	if h.telemetry != nil {
		h.telemetry.Logger().Info(
			"http.request.completed",
			slog.String("operation", operation),
			slog.String("method", method),
			slog.String("route", httpObservationPath(operation)),
			slog.String("status_class", statusClass),
			slog.String("result", httpObservationResult(status)),
		)
	}
}

// httpObservationRoute maps one request target into a closed route and operation.
func httpObservationRoute(request *http.Request) (string, string) {
	if request == nil || request.URL == nil {
		return observationUnmatched, observationUnmatched
	}
	switch request.URL.Path {
	case healthPath:
		return "health", healthPath
	case readinessPath:
		return "readiness", readinessPath
	case processPath:
		return observationProcess, processPath
	case signPath:
		return "sign", signPath
	case revisePath:
		return "revise", revisePath
	default:
		return observationUnmatched, observationUnmatched
	}
}

// httpObservationMethod maps arbitrary methods into a closed vocabulary.
func httpObservationMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodOptions:
		return method
	default:
		return "other"
	}
}

// httpObservationPath maps a closed operation back to its route label.
func httpObservationPath(operation string) string {
	switch operation {
	case "health":
		return healthPath
	case "readiness":
		return readinessPath
	case observationProcess:
		return processPath
	case "sign":
		return signPath
	case "revise":
		return revisePath
	default:
		return observationUnmatched
	}
}

// httpObservationResult maps one status into a closed operational class.
func httpObservationResult(status int) string {
	switch {
	case status < 400:
		return observationSuccess
	case status < 500:
		return "failure"
	default:
		return "internal"
	}
}

// notifyFatal contains notifier failure so the original panic owns wire disposition.
func (h *HTTPBoundary) notifyFatal() {
	defer func() {
		_ = recover()
	}()
	h.fatal.NotifyFatal()
}

// serveBoundaryRequest validates transport facts and dispatches one supported route.
func (h *HTTPBoundary) serveBoundaryRequest(
	committed *boundaryWriter,
	requestPointer **http.Request,
	originalRequest *http.Request,
	ownedReservation **processReservation,
	workingContext **workingSetContext,
) {
	if requestPointer == nil || *requestPointer == nil {
		panic(boundaryAbort)
	}
	request := *requestPointer
	state, statePresent := transportStateFromContext(request.Context())
	if !statePresent {
		panic(boundaryAbort)
	}
	state.MarkHandlerEntered()
	ctx, cancel := context.WithTimeout(request.Context(), h.deadline)
	defer cancel()
	request = request.WithContext(ctx)
	*requestPointer = request
	originalRequest.RemoteAddr = ""
	request.RemoteAddr = ""
	request.Header.Del("X-Dk2E")
	request.Header.Del("X-DKIM2-Framing-X")
	traceContextPresent := consumeTraceContext(request.Header)
	facts := state.Facts()
	hostValue, hostCount, hostOK := state.ConsumeHost()
	facts.hostValue = ""
	request = withBoundaryRequestState(
		request,
		request.ContentLength != 0 || facts.framing != framingAbsent,
	)
	*requestPointer = request
	if !hostOK || hostCount != facts.hostCount {
		abortBoundaryRequest(request)
	}

	if request.Method == "PRI" && request.RequestURI == "*" &&
		facts.protoMajor == 2 && facts.protoMinor == 0 {
		h.writeHeaderOnly(committed, request, http.StatusHTTPVersionNotSupported, true, "")
		return
	}
	if facts.protoMajor != 1 {
		abortBoundaryRequest(request)
	}
	if facts.hostCount != 1 {
		h.writeError(committed, request, http.StatusBadRequest,
			generated.ErrorResponseCodeInvalidContract, generated.Request)
		return
	}
	if facts.requestTargetOverLimit || len(request.RequestURI) > transportRequestTargetLimit {
		h.writeHeaderOnly(committed, request, http.StatusRequestURITooLong, true, "")
		return
	}
	if invalidBoundaryFraming(facts) {
		h.writeError(committed, request, http.StatusBadRequest,
			generated.ErrorResponseCodeInvalidContract, generated.Request)
		return
	}
	if facts.protoMinor == 0 && facts.expect == expectContinue {
		facts.expect = expectNone
	}
	if facts.framing == framingUnsupportedFinalChunked {
		h.writeHeaderOnly(committed, request, http.StatusNotImplemented, true, "")
		return
	}
	if len(request.Method) > transportMethodInspectLimit {
		h.writeHeaderOnly(committed, request, http.StatusNotImplemented, true, "")
		return
	}
	form, valid := h.validateTarget(request, facts, hostValue)
	if !valid {
		h.writeError(committed, request, http.StatusBadRequest,
			generated.ErrorResponseCodeInvalidContract, generated.Request)
		return
	}
	request.Host = ""
	request.TransferEncoding = nil
	originalRequest.Host = ""
	originalRequest.TransferEncoding = nil
	if form == targetAuthority {
		h.writeHeaderOnly(committed, request, http.StatusNotImplemented, true, "")
		return
	}
	if form == targetAsterisk {
		h.serveOptions(committed, request, facts)
		return
	}
	if !supportedBoundaryMethod(request.Method) {
		h.writeHeaderOnly(committed, request, http.StatusNotImplemented, true, "")
		return
	}

	switch request.URL.Path {
	case healthPath, readinessPath:
		h.serveStatus(committed, request, facts)
	case metricsPath:
		h.serveMetrics(committed, request, facts, traceContextPresent)
	case processPath, signPath, revisePath:
		h.serveProcess(
			committed,
			request,
			originalRequest,
			facts,
			ownedReservation,
			workingContext,
		)
	default:
		h.writeError(committed, request, http.StatusNotFound,
			generated.ErrorResponseCodeNotFound, generated.Request)
	}
}

// invalidBoundaryFraming rejects ambiguous or unsupported HTTP/1 framing.
func invalidBoundaryFraming(facts transportFacts) bool {
	return facts.protoMinor == 0 && facts.framing != framingAbsent ||
		facts.expectObsFold || facts.contentLengthConflict || facts.framing == framingBad
}

// consumeTraceContext reports and clears every inbound trace-context channel.
func consumeTraceContext(header http.Header) bool {
	present := hasHeader(header, "Traceparent") ||
		hasHeader(header, "Tracestate") ||
		hasHeader(header, "Baggage")
	header.Del("Traceparent")
	header.Del("Tracestate")
	header.Del("Baggage")
	return present
}

// supportedBoundaryMethod reports whether routing handles one exact method.
func supportedBoundaryMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodOptions:
		return true
	default:
		return false
	}
}

// serveMetrics applies the exact specialized scrape contract without tracing or recursion.
func (h *HTTPBoundary) serveMetrics(
	writer *boundaryWriter,
	request *http.Request,
	facts transportFacts,
	traceContextPresent bool,
) {
	if request.Method != http.MethodGet {
		date, present := responseDate(request.Context())
		response, err := newErrorResponse(
			http.StatusMethodNotAllowed,
			generated.ErrorResponseCodeMethodNotAllowed,
			generated.Request,
			request.Method == http.MethodHead,
			date,
			present,
		)
		if err == nil {
			response, err = response.withAllow(metricsAllowMethod)
		}
		h.writePrepared(writer, request, response, err)
		return
	}
	if strings.Contains(request.RequestURI, "?") || request.ContentLength > 0 ||
		facts.framing != framingAbsent || facts.expect != expectNone ||
		traceContextPresent || hasHeader(request.Header, headerContentType) ||
		hasHeader(request.Header, "Content-Encoding") ||
		hasHeader(request.Header, "X-DKIM2-Capability") ||
		hasHeader(request.Header, "If-Match") ||
		hasHeader(request.Header, "If-None-Match") ||
		hasHeader(request.Header, "If-Modified-Since") ||
		hasHeader(request.Header, "If-Unmodified-Since") ||
		hasHeader(request.Header, "If-Range") {
		h.writeError(writer, request, http.StatusBadRequest,
			generated.ErrorResponseCodeInvalidContract, generated.Request)
		return
	}
	body, err := h.metrics.Gather()
	if err != nil || len(body) > 256<<10 {
		h.writeInternal(writer, request)
		return
	}
	header := writer.Header()
	clear(header)
	header.Set("Cache-Control", cacheControlNoStore)
	header.Set(headerContentType, observability.MetricsContentType)
	header.Set("Content-Length", strconv.Itoa(len(body)))
	header.Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	if _, err := writer.Write(body); err != nil {
		panic(boundaryAbort)
	}
}

type targetForm uint8

const (
	targetInvalid targetForm = iota
	targetOrigin
	targetAbsolute
	targetAuthority
	targetAsterisk
)

// validateTarget checks request-target form and exact local authority.
func (h *HTTPBoundary) validateTarget(
	request *http.Request,
	facts transportFacts,
	hostValue string,
) (targetForm, bool) {
	if request == nil || request.URL == nil || facts.hostCount != 1 ||
		request.URL.RawPath != "" {
		return targetInvalid, false
	}
	if request.RequestURI == "*" {
		return targetAsterisk, request.Method == http.MethodOptions && request.Host == h.authority
	}
	if request.Method == http.MethodConnect {
		if strings.HasPrefix(request.RequestURI, "/") {
			return targetInvalid, false
		}
		return targetAuthority, request.RequestURI == h.authority &&
			request.Host == h.authority && hostValue == h.authority
	}
	if request.URL.IsAbs() {
		return targetAbsolute,
			strings.EqualFold(request.URL.Scheme, "http") &&
				request.URL.User == nil && request.URL.Host == h.authority &&
				request.URL.Fragment == "" && request.URL.Opaque == ""
	}
	if strings.HasPrefix(request.RequestURI, "/") {
		return targetOrigin, request.Host == h.authority && hostValue == h.authority
	}
	return targetInvalid, false
}

// serveOptions writes the exact bodyless server-wide OPTIONS response.
func (h *HTTPBoundary) serveOptions(
	writer *boundaryWriter,
	request *http.Request,
	facts transportFacts,
) {
	if request.URL == nil || request.URL.RawQuery != "" ||
		strings.Contains(request.RequestURI, "?") || facts.contentLengthPresent ||
		facts.framing != framingAbsent {
		h.writeError(writer, request, http.StatusBadRequest,
			generated.ErrorResponseCodeInvalidContract, generated.Request)
		return
	}
	if facts.expect != expectNone {
		h.writeError(writer, request, http.StatusExpectationFailed,
			generated.ErrorResponseCodeExpectationFailed, generated.Request)
		return
	}
	if hasHeader(request.Header, headerContentType) ||
		hasHeader(request.Header, "Content-Encoding") {
		h.writeError(writer, request, http.StatusBadRequest,
			generated.ErrorResponseCodeInvalidContract, generated.Request)
		return
	}
	h.writeHeaderOnly(writer, request, http.StatusNoContent, false, serverAllowMethods)
}

// serveStatus applies bodyless route policy and selected-representation preconditions.
func (h *HTTPBoundary) serveStatus(
	writer *boundaryWriter,
	request *http.Request,
	facts transportFacts,
) {
	head := request.Method == http.MethodHead
	if request.Method != http.MethodGet && !head {
		date, present := responseDate(request.Context())
		response, err := newErrorResponse(http.StatusMethodNotAllowed,
			generated.ErrorResponseCodeMethodNotAllowed, generated.Request,
			head, date, present)
		if err != nil {
			h.writeInternal(writer, request)
			return
		}
		response, err = response.withAllow(statusAllowMethods)
		h.writePrepared(writer, request, response, err)
		return
	}
	if strings.Contains(request.RequestURI, "?") || request.ContentLength > 0 ||
		facts.framing != framingAbsent {
		h.writeError(writer, request, http.StatusBadRequest,
			generated.ErrorResponseCodeInvalidContract, generated.Request)
		return
	}
	if facts.expect != expectNone {
		h.writeError(writer, request, http.StatusExpectationFailed,
			generated.ErrorResponseCodeExpectationFailed, generated.Request)
		return
	}
	if hasHeader(request.Header, headerContentType) ||
		hasHeader(request.Header, "Content-Encoding") {
		h.writeError(writer, request, http.StatusBadRequest,
			generated.ErrorResponseCodeInvalidContract, generated.Request)
		return
	}
	var response preMarshaledResponse
	var err error
	switch request.URL.Path {
	case healthPath:
		response, err = h.healthResponse(request.Context(), head)
	case readinessPath:
		response, err = h.readinessResponse(request.Context(), head)
	}
	if err != nil {
		h.writeInternal(writer, request)
		return
	}
	if response.status != http.StatusOK {
		h.writePrepared(writer, request, response, nil)
		return
	}
	switch evaluateStatusPreconditions(request.Header, response.etag) {
	case preconditionProceed:
	case preconditionNotModified:
		response, err = response.asNotModified()
	case preconditionFailed:
		date, present := responseDate(request.Context())
		response, err = newErrorResponse(http.StatusPreconditionFailed,
			generated.ErrorResponseCodePreconditionFailed, generated.Request,
			head, date, present)
	case preconditionInvalid:
		date, present := responseDate(request.Context())
		response, err = newErrorResponse(http.StatusBadRequest,
			generated.ErrorResponseCodeInvalidContract, generated.Request,
			head, date, present)
	}
	h.writePrepared(writer, request, response, err)
}

// serveProcess applies authenticated admission, body, JSON, OAS, and domain stages.
func (h *HTTPBoundary) serveProcess(
	writer *boundaryWriter,
	request *http.Request,
	originalRequest *http.Request,
	facts transportFacts,
	ownedReservation **processReservation,
	ownedWorkingContext **workingSetContext,
) {
	preparedRequest, continueEligible, ok := h.prepareProcessRequest(writer, request, facts)
	if !ok {
		return
	}
	request = preparedRequest
	var lease *processLease
	var failure admissionFailure
	if continueEligible {
		lease, failure = h.admission.TryAcquire(request.Context())
	} else {
		lease, failure = h.admission.Acquire(request.Context())
	}
	if lease == nil {
		h.writeAdmissionFailure(writer, request, failure)
		return
	}
	ledger, err := newWorkingSetLedger(processWorkingSetUnitBytes)
	if err != nil {
		lease.Release()
		h.writeInternal(writer, request)
		return
	}
	if err := ledger.Claim(workingSetFixedStorage, maximumFixedRequestStorageBytes); err != nil {
		ledger.ReleaseAll()
		lease.Release()
		h.writeInternal(writer, request)
		return
	}
	reservation, err := newProcessReservation(lease, ledger)
	if err != nil {
		ledger.ReleaseAll()
		lease.Release()
		h.writeInternal(writer, request)
		return
	}
	state, statePresent := transportStateFromContext(request.Context())
	if ownedReservation == nil || *ownedReservation != nil || !statePresent ||
		!state.OwnProcessReservation(reservation) {
		ledger.ReleaseAll()
		lease.Release()
		h.writeInternal(writer, request)
		return
	}
	*ownedReservation = reservation
	workingCtx, holder, err := withWorkingSetContext(request.Context(), ledger)
	if err != nil {
		h.writeInternal(writer, request)
		return
	}
	if ownedWorkingContext == nil || *ownedWorkingContext != nil {
		h.writeInternal(writer, request)
		return
	}
	*ownedWorkingContext = holder
	request = request.WithContext(workingCtx)
	h.processReservedRequest(
		writer,
		request,
		originalRequest,
		continueEligible,
		ledger,
	)
}

// prepareProcessRequest applies route policy before consuming admission capacity.
func (h *HTTPBoundary) prepareProcessRequest(
	writer *boundaryWriter,
	request *http.Request,
	facts transportFacts,
) (*http.Request, bool, bool) {
	if request.Method != http.MethodPost {
		date, present := responseDate(request.Context())
		response, err := newErrorResponse(http.StatusMethodNotAllowed,
			generated.ErrorResponseCodeMethodNotAllowed, generated.Request,
			request.Method == http.MethodHead, date, present)
		if err == nil {
			response, err = response.withAllow(processAllowMethod)
		}
		h.writePrepared(writer, request, response, err)
		return request, false, false
	}
	if strings.Contains(request.RequestURI, "?") {
		h.writeError(writer, request, http.StatusBadRequest,
			generated.ErrorResponseCodeInvalidContract, generated.Request)
		return request, false, false
	}
	if facts.expect == expectUnsupported || facts.expect == expectMalformed {
		h.writeError(writer, request, http.StatusExpectationFailed,
			generated.ErrorResponseCodeExpectationFailed, generated.Request)
		return request, false, false
	}
	if !validJSONContentType(request.Header.Values(headerContentType)) ||
		hasHeader(request.Header, "Content-Encoding") {
		h.writeError(writer, request, http.StatusUnsupportedMediaType,
			generated.ErrorResponseCodeUnsupportedMediaType, generated.Request)
		return request, false, false
	}
	var authenticated bool
	request, authenticated = authenticateLocalCapability(request, h.matcherForPath(request.URL.Path))
	if !authenticated {
		h.writeError(writer, request, http.StatusForbidden,
			generated.ErrorResponseCodeForbidden, generated.Request)
		return request, false, false
	}
	if request.Context().Err() != nil {
		h.writeContextFailure(writer, request)
		return request, false, false
	}
	if !h.readiness.Ready() {
		h.writeError(writer, request, http.StatusServiceUnavailable,
			generated.ErrorResponseCodeServiceNotReady, generated.Availability)
		return request, false, false
	}
	announced := request.ContentLength > 0 || facts.framing == framingSingleChunked
	continueEligible := facts.expect == expectContinue &&
		facts.protoMinor >= 1 && announced
	if continueEligible && request.ContentLength > maxProcessBodyBytes {
		h.writeError(writer, request, http.StatusRequestEntityTooLarge,
			generated.ErrorResponseCodeRequestTooLarge, generated.Request)
		return request, false, false
	}
	return request, continueEligible, true
}

// matcherForPath returns only the capability assigned to the exact operation.
func (h *HTTPBoundary) matcherForPath(path string) capabilityMatcher {
	switch path {
	case processPath:
		return h.matcher
	case signPath:
		return h.signMatcher
	case revisePath:
		return h.reviseMatcher
	default:
		return nil
	}
}

// processReservedRequest consumes and validates one admitted request body.
func (h *HTTPBoundary) processReservedRequest(
	writer *boundaryWriter,
	request *http.Request,
	originalRequest *http.Request,
	continueEligible bool,
	ledger *workingSetLedger,
) {
	if request.Context().Err() != nil {
		h.writeContextFailure(writer, request)
		return
	}
	if !h.readiness.Ready() {
		h.writeError(writer, request, http.StatusServiceUnavailable,
			generated.ErrorResponseCodeServiceNotReady, generated.Availability)
		return
	}
	if request.ContentLength > maxProcessBodyBytes {
		h.writeError(writer, request, http.StatusRequestEntityTooLarge,
			generated.ErrorResponseCodeRequestTooLarge, generated.Request)
		return
	}
	if continueEligible {
		clear(writer.Header())
		writer.WriteHeader(http.StatusContinue)
		if state, ok := transportStateFromContext(request.Context()); ok && state.ResponseTerminal() {
			abortBoundaryRequest(request)
		}
	}
	if err := ledger.BeginBodyRead(); err != nil {
		h.writeInternal(writer, request)
		return
	}
	body, bodyFailure := readProcessBody(writer, request, originalRequest)
	switch bodyFailure {
	case 0:
	case bodyFailureTooLarge:
		h.writeError(writer, request, http.StatusRequestEntityTooLarge,
			generated.ErrorResponseCodeRequestTooLarge, generated.Request)
		return
	case bodyFailureTimeout:
		h.writeError(writer, request, http.StatusRequestTimeout,
			generated.ErrorResponseCodeRequestTimeout, generated.Request)
		return
	case bodyFailureDisconnect:
		abortBoundaryRequest(request)
	default:
		h.writeError(writer, request, http.StatusBadRequest,
			generated.ErrorResponseCodeInvalidContract, generated.Request)
		return
	}
	defer clear(body)
	if !h.validateProcessBody(writer, request, body, ledger) {
		return
	}
	request.Body = http.NoBody
	request.ContentLength = 0
	request.Body = io.NopCloser(bytes.NewReader(body))
	if err := ledger.BeginGeneratedProcessing(); err != nil {
		request.Body = http.NoBody
		h.writeInternal(writer, request)
		return
	}
	switch request.URL.Path {
	case processPath:
		h.generated.ProcessMessage(writer, request)
	case signPath:
		h.generated.SignMessage(writer, request)
	case revisePath:
		h.generated.ReviseMessage(writer, request)
	default:
		h.writeInternal(writer, request)
	}
	request.Body = http.NoBody
	request.ContentLength = 0
}

// validateProcessBody applies lexical, known-field, OpenAPI, and spelling checks.
func (h *HTTPBoundary) validateProcessBody(
	writer *boundaryWriter,
	request *http.Request,
	body []byte,
	ledger *workingSetLedger,
) bool {
	if err := ledger.FinishBodyRead(); err != nil {
		h.writeInternal(writer, request)
		return false
	}
	if request.Context().Err() != nil {
		h.writeContextFailure(writer, request)
		return false
	}
	constants, err := preflightJSON(body)
	if err != nil {
		h.writeJSONPreflightFailure(writer, request, err)
		return false
	}
	if request.Context().Err() != nil {
		h.writeContextFailure(writer, request)
		return false
	}
	if err := preflightKnownFields(body, constants); err != nil {
		if isKnownFieldFailure(err, knownFieldRequestTooLarge) {
			h.writeError(writer, request, http.StatusRequestEntityTooLarge,
				generated.ErrorResponseCodeRequestTooLarge, generated.Request)
		} else {
			h.writeError(writer, request, http.StatusBadRequest,
				generated.ErrorResponseCodeInvalidContract, generated.Request)
		}
		return false
	}
	if request.Context().Err() != nil {
		h.writeContextFailure(writer, request)
		return false
	}
	if err := ledger.BeginValidation(); err != nil {
		h.writeInternal(writer, request)
		return false
	}
	validationErr := h.validator.ValidateOperation(request, body)
	if err := ledger.FinishValidation(); err != nil {
		h.writeInternal(writer, request)
		return false
	}
	if validationErr != nil {
		h.writeError(writer, request, http.StatusBadRequest,
			generated.ErrorResponseCodeInvalidContract, generated.Request)
		return false
	}
	if request.Context().Err() != nil {
		h.writeContextFailure(writer, request)
		return false
	}
	if err := validateRawMessageSpelling(constants); err != nil {
		h.writeError(writer, request, http.StatusBadRequest,
			generated.ErrorResponseCodeInvalidContract, generated.Request)
		return false
	}
	if request.Context().Err() != nil {
		h.writeContextFailure(writer, request)
		return false
	}
	return true
}

// writeStrictFailure maps one closed generated-adapter failure.
func (h *HTTPBoundary) writeStrictFailure(
	writer *boundaryWriter,
	request *http.Request,
	err error,
) {
	switch {
	case IsStrictAdapterError(err, strictFailureCanceled):
		abortBoundaryRequest(request)
	case IsStrictAdapterError(err, strictFailureDeadline):
		h.writeError(writer, request, http.StatusServiceUnavailable,
			generated.ErrorResponseCodeRequestDeadline, generated.Availability)
	case IsStrictAdapterError(err, strictFailureInvalidContract):
		h.writeError(writer, request, http.StatusBadRequest,
			generated.ErrorResponseCodeInvalidContract, generated.Request)
	case IsStrictAdapterError(err, strictFailureRequestTooLarge):
		h.writeError(writer, request, http.StatusRequestEntityTooLarge,
			generated.ErrorResponseCodeRequestTooLarge, generated.Request)
	default:
		h.writeInternal(writer, request)
	}
}

// healthResponse returns one exact health representation.
func (h *HTTPBoundary) healthResponse(ctx context.Context, head bool) (preMarshaledResponse, error) {
	date, present := responseDate(ctx)
	return newStatusResponse(generated.HealthResponse{
		ApiVersion: generated.V1,
		Draft:      generated.DraftIetfDkimDkim2Spec04,
		Status:     generated.Alive,
	}, head, date, present)
}

// readinessResponse samples readiness once and returns the exact selected response.
func (h *HTTPBoundary) readinessResponse(ctx context.Context, head bool) (preMarshaledResponse, error) {
	return h.strict.readinessResponse(ctx, head)
}

// writeJSONPreflightFailure maps one closed lexical/resource outcome.
func (h *HTTPBoundary) writeJSONPreflightFailure(
	writer *boundaryWriter,
	request *http.Request,
	err error,
) {
	var failure *jsonPreflightError
	if !errors.As(err, &failure) {
		h.writeInternal(writer, request)
		return
	}
	switch failure.Code() {
	case jsonPreflightRequestTooLarge:
		h.writeError(writer, request, http.StatusRequestEntityTooLarge,
			generated.ErrorResponseCodeRequestTooLarge, generated.Request)
	case jsonPreflightUnsupportedVersion:
		h.writeError(writer, request, http.StatusBadRequest,
			generated.ErrorResponseCodeUnsupportedVersion, generated.Request)
	case jsonPreflightUnsupportedDraft:
		h.writeError(writer, request, http.StatusBadRequest,
			generated.ErrorResponseCodeUnsupportedDraft, generated.Request)
	case jsonPreflightInvalidContract:
		h.writeError(writer, request, http.StatusBadRequest,
			generated.ErrorResponseCodeInvalidContract, generated.Request)
	default:
		h.writeError(writer, request, http.StatusBadRequest,
			generated.ErrorResponseCodeInvalidJson, generated.Request)
	}
}

// writeAdmissionFailure maps one closed acquisition outcome.
func (h *HTTPBoundary) writeAdmissionFailure(
	writer *boundaryWriter,
	request *http.Request,
	failure admissionFailure,
) {
	switch failure {
	case admissionCanceled:
		abortBoundaryRequest(request)
	case admissionDeadline:
		h.writeError(writer, request, http.StatusServiceUnavailable,
			generated.ErrorResponseCodeRequestDeadline, generated.Availability)
	case admissionNotReady:
		h.writeError(writer, request, http.StatusServiceUnavailable,
			generated.ErrorResponseCodeServiceNotReady, generated.Availability)
	default:
		h.writeError(writer, request, http.StatusServiceUnavailable,
			generated.ErrorResponseCodeServiceOverloaded, generated.Availability)
	}
}

// writeContextFailure maps observed request cancellation without exposing a cause.
func (h *HTTPBoundary) writeContextFailure(writer *boundaryWriter, request *http.Request) {
	if request.Context().Err() == context.Canceled {
		abortBoundaryRequest(request)
	}
	h.writeError(writer, request, http.StatusServiceUnavailable,
		generated.ErrorResponseCodeRequestDeadline, generated.Availability)
}

// abortBoundaryRequest closes tracked ownership and suppresses net/http's implicit 200.
func abortBoundaryRequest(request *http.Request) {
	if request != nil {
		if state, ok := transportStateFromContext(request.Context()); ok {
			_ = state.Close()
		}
	}
	panic(boundaryAbort)
}

// writeError constructs one exact bounded application error.
func (h *HTTPBoundary) writeError(
	writer *boundaryWriter,
	request *http.Request,
	status int,
	code generated.ErrorResponseCode,
	category generated.ErrorResponseCategory,
) {
	date, present := responseDate(request.Context())
	response, err := newErrorResponse(status, code, category,
		request.Method == http.MethodHead, date, present)
	h.writePrepared(writer, request, response, err)
}

// writeInternal writes one closed internal failure before any prior commit.
func (h *HTTPBoundary) writeInternal(writer *boundaryWriter, request *http.Request) {
	h.writeError(writer, request, http.StatusInternalServerError,
		generated.ErrorResponseCodeInternalError, generated.Internal)
}

// writePrepared commits one prevalidated response after narrowing unread-body waits.
func (h *HTTPBoundary) writePrepared(
	writer *boundaryWriter,
	request *http.Request,
	response preMarshaledResponse,
	err error,
) {
	if err != nil || writer.committed {
		if !writer.committed {
			h.writeInternal(writer, request)
		}
		return
	}
	if !h.prepareEarlyFinal(request) {
		return
	}
	_ = response.write(writer)
}

// prepareEarlyFinal prevents Go's body-close path from waiting on future bytes.
func (*HTTPBoundary) prepareEarlyFinal(request *http.Request) bool {
	if request == nil || request.Body == nil || !boundaryBodyUnread(request) {
		return true
	}
	state, ok := transportStateFromContext(request.Context())
	if !ok {
		return true
	}
	if err := state.AdvanceReadDeadline(time.Now()); err != nil {
		_ = state.Close()
		panic(boundaryAbort)
	}
	return true
}

// writeHeaderOnly commits one exact bodyless outer transport response.
func (h *HTTPBoundary) writeHeaderOnly(
	writer *boundaryWriter,
	request *http.Request,
	status int,
	contentLength bool,
	allow string,
) {
	if !h.prepareEarlyFinal(request) {
		return
	}
	header := writer.Header()
	clear(header)
	header.Set("Cache-Control", cacheControlNoStore)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Connection", "close")
	date, present := responseDate(request.Context())
	applyResponseDate(header, status, date, present)
	if contentLength {
		header.Set("Content-Length", "0")
	}
	if allow != "" {
		header.Set("Allow", allow)
	}
	writer.WriteHeader(status)
}

// hasHeader reports field occurrence even when its combined value is empty.
func hasHeader(header http.Header, name string) bool {
	_, present := header[http.CanonicalHeaderKey(name)]
	return present
}

// boundaryWriter records final response commitment while preserving informational writes.
type boundaryWriter struct {
	http.ResponseWriter
	committed bool
	status    int
}

// WriteHeader forwards one status and records only final commitment.
func (w *boundaryWriter) WriteHeader(status int) {
	if status >= 200 {
		w.committed = true
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

// Write marks implicit final response commitment.
func (w *boundaryWriter) Write(value []byte) (int, error) {
	w.committed = true
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(value)
}

var _ http.Handler = (*HTTPBoundary)(nil)
