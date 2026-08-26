package observability

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

const (
	traceInstrumentationName = "github.com/croessner/dkim2/cmd/dkim2d"
	traceDraftValue          = "draft-ietf-dkim-dkim2-spec-05"
	traceShutdownBudget      = 5 * time.Second
)

var allowedSpanNames = []string{
	"dkim2d.http.request", "dkim2d.process", "dkim2.verify",
	"dkim2.dns.lookup", "dkim2.policy.evaluate",
	"dkim2.replay.coordinate", "dkim2.replay.store",
}

var allowedSpanValues = map[string][]string{
	"dkim2.result":        {valueSuccess, valueFailure, valueTemporary, valueInternal},
	"dkim2.policy_mode":   {valueStrict, valuePermissive, valueTesting},
	"dkim2.verdict":       {valuePass, valueFail, valueNeutral, valueTemperror, valuePermerror},
	"dkim2.replay_state":  {valueNotChecked, valueDisabled, valueFirstSeen, valueReplayed, valueIndeterminate},
	"dkim2.reason_class":  {valueNone, valueProtocol, valuePolicy, valueAvailability, valueInternal},
	"dkim2.error_class":   {valueNone, "canceled", "deadline", valueTemporary, valueInternal},
	"http.request.method": {"GET", "HEAD", "POST", "OPTIONS", "other"},
	"http.route":          {"/healthz", "/readyz", "/metrics", "/v1/process", "/v1/sign", "/v1/revise", valueUnmatched},
}

// SpanOutcome identifies whether one completed span represents an invariant failure.
type SpanOutcome uint8

const (
	// SpanCompleted leaves status unset for completed protocol and policy outcomes.
	SpanCompleted SpanOutcome = iota + 1
	// SpanInternalError marks an internal or required-availability failure without description.
	SpanInternalError
)

// SpanFact is one immutable admitted trace attribute.
type SpanFact struct {
	key      string
	text     string
	number   int
	isNumber bool
}

// TextSpanFact constructs one closed text attribute.
func TextSpanFact(key, value string) (SpanFact, bool) {
	if !slices.Contains(allowedSpanValues[key], value) {
		return SpanFact{}, false
	}
	return SpanFact{key: key, text: value}, true
}

// HTTPStatusSpanFact constructs the sole bounded integer attribute.
func HTTPStatusSpanFact(status int) (SpanFact, bool) {
	if status < 100 || status > 599 {
		return SpanFact{}, false
	}
	return SpanFact{key: "http.response.status_code", number: status, isNumber: true}, true
}

// TraceRuntime owns one tracer provider without mutating global OTel state.
type TraceRuntime struct {
	provider     trace.TracerProvider
	sdkProvider  *sdktrace.TracerProvider
	shutdownOnce sync.Once
	shutdownErr  error
}

// NewTraceRuntime constructs disabled or bounded direct HTTPS OTLP tracing.
func NewTraceRuntime(ctx context.Context, settings config.TracingConfig, rootsDER [][]byte) (*TraceRuntime, error) {
	return newTraceRuntime(ctx, settings, rootsDER, nil)
}

// newTraceRuntime constructs tracing with one optional bounded failure reporter.
func newTraceRuntime(
	ctx context.Context,
	settings config.TracingConfig,
	rootsDER [][]byte,
	report traceDropReporter,
) (*TraceRuntime, error) {
	if ctx == nil {
		return nil, errRejectedRecord
	}
	switch settings.Exporter() {
	case config.TracingNone:
		return &TraceRuntime{provider: noop.NewTracerProvider()}, nil
	case config.TracingOTLPHTTP:
		exporter, err := newOTLPExporter(ctx, settings, rootsDER)
		if err != nil {
			return nil, errRejectedRecord
		}
		processor, err := newBoundedBatchProcessor(
			exporter,
			traceQueueSize,
			traceBatchSize,
			traceBatchDelay,
			settings.ExportTimeout(),
			report,
		)
		if err != nil {
			_ = containedExporterShutdown(ctx, exporter)
			return nil, errRejectedRecord
		}
		return newSDKTraceRuntime(settings, processor)
	default:
		return nil, errRejectedRecord
	}
}

// newSDKTraceRuntime constructs the exact instance-owned SDK provider.
func newSDKTraceRuntime(settings config.TracingConfig, processor sdktrace.SpanProcessor) (*TraceRuntime, error) {
	if processor == nil || settings.SamplePerMillion() == 0 ||
		settings.SamplePerMillion() > 1_000_000 {
		return nil, errRejectedRecord
	}
	resources, err := resource.New(
		context.Background(),
		resource.WithAttributes(
			attribute.String("service.name", "dkim2d"),
			attribute.String("service.namespace", "dkim2"),
			attribute.String("dkim2.draft", traceDraftValue),
		),
	)
	if err != nil {
		return nil, errRejectedRecord
	}
	ratio := float64(settings.SamplePerMillion()) / 1_000_000
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithResource(resources),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
		sdktrace.WithSpanProcessor(processor),
		sdktrace.WithRawSpanLimits(sdktrace.SpanLimits{
			AttributeValueLengthLimit:   64,
			AttributeCountLimit:         8,
			EventCountLimit:             0,
			LinkCountLimit:              0,
			AttributePerEventCountLimit: 0,
			AttributePerLinkCountLimit:  0,
		}),
	)
	return &TraceRuntime{provider: provider, sdkProvider: provider}, nil
}

// newOTLPExporter creates a proxy-free, redirect-free HTTPS exporter.
func newOTLPExporter(ctx context.Context, settings config.TracingConfig, rootsDER [][]byte) (sdktrace.SpanExporter, error) {
	if !exporterEnvironmentClean() {
		return nil, errRejectedRecord
	}
	client, err := endpointHTTPClient(settings, rootsDER)
	if err != nil {
		return nil, errRejectedRecord
	}
	exporter, err := otlptracehttp.New(
		ctx,
		otlptracehttp.WithHTTPClient(client),
		otlptracehttp.WithEndpointURL(settings.Endpoint()),
		otlptracehttp.WithURLPath("/v1/traces"),
		otlptracehttp.WithHeaders(map[string]string{}),
		otlptracehttp.WithCompression(otlptracehttp.NoCompression),
		otlptracehttp.WithTimeout(settings.ExportTimeout()),
		otlptracehttp.WithRetry(otlptracehttp.RetryConfig{Enabled: false}),
		otlptracehttp.WithMaxRequestSize(1<<20),
	)
	if err != nil {
		return nil, errRejectedRecord
	}
	return exporter, nil
}

// exporterEnvironmentClean rejects every environment-controlled OTLP override.
func exporterEnvironmentClean() bool {
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "OTEL_EXPORTER_OTLP_") ||
			name == "OTEL_GO_X_OBSERVABILITY" {
			return false
		}
	}
	return true
}

// StartRoot starts one fresh server root while preserving caller cancellation.
func (r *TraceRuntime) StartRoot(ctx context.Context, name string, facts ...SpanFact) (context.Context, trace.Span) {
	if r == nil || r.provider == nil || ctx == nil || !slices.Contains(allowedSpanNames, name) {
		return ctx, trace.SpanFromContext(context.Background())
	}
	attributes, ok := spanAttributes(facts)
	if !ok {
		return ctx, trace.SpanFromContext(context.Background())
	}
	cleared := trace.ContextWithSpanContext(ctx, trace.SpanContext{})
	return r.start(cleared, name, trace.WithNewRoot(), trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(attributes...))
}

// StartChild starts one exact child span through the existing context.
func (r *TraceRuntime) StartChild(ctx context.Context, name string, facts ...SpanFact) (context.Context, trace.Span) {
	if r == nil || r.provider == nil || ctx == nil || !slices.Contains(allowedSpanNames, name) {
		return ctx, trace.SpanFromContext(context.Background())
	}
	attributes, ok := spanAttributes(facts)
	if !ok {
		return ctx, trace.SpanFromContext(context.Background())
	}
	return r.start(ctx, name, trace.WithAttributes(attributes...))
}

// start contains tracer panics and returns a no-op span on invalid facts.
func (r *TraceRuntime) start(ctx context.Context, name string, options ...trace.SpanStartOption) (result context.Context, span trace.Span) {
	result = ctx
	span = trace.SpanFromContext(context.Background())
	defer func() {
		if recover() != nil {
			result = ctx
			span = trace.SpanFromContext(context.Background())
		}
	}()
	return r.provider.Tracer(traceInstrumentationName).Start(ctx, name, options...)
}

// EndSpan records only closed status and always contains telemetry panics.
func EndSpan(span trace.Span, outcome SpanOutcome) {
	EndSpanWithFacts(span, outcome)
}

// EndSpanWithFacts records closed completion facts and status before ending.
func EndSpanWithFacts(span trace.Span, outcome SpanOutcome, facts ...SpanFact) {
	if span == nil {
		return
	}
	defer func() { _ = recover() }()
	attributes, ok := spanAttributes(facts)
	if !ok {
		outcome = SpanInternalError
	} else if len(attributes) > 0 {
		span.SetAttributes(attributes...)
	}
	if outcome == SpanInternalError {
		span.SetStatus(codes.Error, "")
	}
	span.End()
}

// EndHTTPSpan records one bounded response code before closing an HTTP span.
func EndHTTPSpan(span trace.Span, status int, outcome SpanOutcome) {
	if span == nil {
		return
	}
	defer func() { _ = recover() }()
	if fact, ok := HTTPStatusSpanFact(status); ok {
		span.SetAttributes(attribute.Int(fact.key, fact.number))
	}
	if outcome == SpanInternalError {
		span.SetStatus(codes.Error, "")
	}
	span.End()
}

// Shutdown stops the provider exactly once through a fixed child budget.
func (r *TraceRuntime) Shutdown(parent context.Context) error {
	if r == nil || parent == nil || r.sdkProvider == nil {
		return nil
	}
	r.shutdownOnce.Do(func() {
		ctx, cancel := context.WithTimeout(parent, traceShutdownBudget)
		defer cancel()
		defer func() {
			if recover() != nil {
				r.shutdownErr = errRejectedRecord
			}
		}()
		if err := r.sdkProvider.Shutdown(ctx); err != nil {
			r.shutdownErr = errRejectedRecord
		}
	})
	return r.shutdownErr
}

// spanAttributes validates and converts one bounded fact list.
func spanAttributes(facts []SpanFact) ([]attribute.KeyValue, bool) {
	if len(facts) > 8 {
		return nil, false
	}
	attributes := make([]attribute.KeyValue, 0, len(facts))
	seen := make(map[string]struct{}, len(facts))
	for _, fact := range facts {
		if fact.key == "" {
			return nil, false
		}
		if _, duplicate := seen[fact.key]; duplicate {
			return nil, false
		}
		seen[fact.key] = struct{}{}
		if fact.isNumber {
			if fact.key != "http.response.status_code" || fact.number < 100 || fact.number > 599 {
				return nil, false
			}
			attributes = append(attributes, attribute.Int(fact.key, fact.number))
			continue
		}
		if !slices.Contains(allowedSpanValues[fact.key], fact.text) {
			return nil, false
		}
		attributes = append(attributes, attribute.String(fact.key, fact.text))
	}
	return attributes, true
}

// endpointHTTPClient creates an endpoint-bound transport with no proxy or redirects.
func endpointHTTPClient(settings config.TracingConfig, rootsDER [][]byte) (*http.Client, error) {
	endpoint, err := url.Parse(settings.Endpoint())
	if err != nil {
		return nil, errRejectedRecord
	}
	pool := x509.NewCertPool()
	for _, der := range rootsDER {
		certificate, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			return nil, errRejectedRecord
		}
		pool.AddCert(certificate)
	}
	if len(rootsDER) == 0 {
		return nil, errRejectedRecord
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    pool,
		ServerName: endpoint.Hostname(),
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: settings.ExportTimeout()}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSClientConfig:       tlsConfig,
		DisableCompression:    true,
		ResponseHeaderTimeout: settings.ExportTimeout(),
	}
	return &http.Client{
		Transport: transport,
		Timeout:   settings.ExportTimeout(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect rejected")
		},
	}, nil
}
