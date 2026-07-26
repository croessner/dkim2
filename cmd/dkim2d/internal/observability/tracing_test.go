package observability

import (
	"context"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// TestTraceRuntimeProducesExactParentageAndStatus proves fresh roots and explicit child context.
func TestTraceRuntimeProducesExactParentageAndStatus(t *testing.T) {
	settings := testTracingSettings(t)
	exporter := tracetest.NewInMemoryExporter()
	runtime, err := newSDKTraceRuntime(settings, sdktrace.NewSimpleSpanProcessor(exporter))
	if err != nil {
		t.Fatal("trace runtime construction failed")
	}
	remote := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1},
		SpanID:     trace.SpanID{2},
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	inbound := trace.ContextWithRemoteSpanContext(context.Background(), remote)
	resultFact, _ := TextSpanFact("dkim2.result", "success")
	rootContext, root := runtime.StartRoot(inbound, "dkim2d.http.request", resultFact)
	childContext, child := runtime.StartChild(rootContext, "dkim2d.process", resultFact)
	_, verify := runtime.StartChild(childContext, "dkim2.verify", resultFact)
	EndSpan(verify, SpanCompleted)
	EndSpan(child, SpanCompleted)
	EndSpan(root, SpanInternalError)
	spans := exporter.GetSpans()
	if len(spans) != 3 {
		t.Fatal("exact span set changed")
	}
	verifySpan, childSpan, rootSpan := spans[0], spans[1], spans[2]
	if rootSpan.Parent.IsValid() || rootSpan.SpanContext.TraceID() == remote.TraceID() ||
		childSpan.Parent.SpanID() != rootSpan.SpanContext.SpanID() ||
		verifySpan.Parent.SpanID() != childSpan.SpanContext.SpanID() {
		t.Fatal("fresh-root or child parentage changed")
	}
	if rootSpan.Status.Code != codes.Error || rootSpan.Status.Description != "" ||
		childSpan.Status.Code != codes.Unset {
		t.Fatal("closed span status mapping changed")
	}
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatal("trace runtime shutdown failed")
	}
}

// TestTraceRuntimeDoesNotMutateGlobals proves provider and propagator ownership.
func TestTraceRuntimeDoesNotMutateGlobals(t *testing.T) {
	provider := otel.GetTracerProvider()
	propagator := otel.GetTextMapPropagator()
	settings := testTracingSettings(t)
	exporter := tracetest.NewInMemoryExporter()
	runtime, err := newSDKTraceRuntime(settings, sdktrace.NewSimpleSpanProcessor(exporter))
	if err != nil || runtime == nil {
		t.Fatal("trace runtime construction failed")
	}
	if otel.GetTracerProvider() != provider || otel.GetTextMapPropagator() != propagator {
		t.Fatal("trace construction mutated global OTel state")
	}
}

// TestNoopTraceRuntimeHasNoSDKOrNetwork proves disabled mode constructs only no-op tracing.
func TestNoopTraceRuntimeHasNoSDKOrNetwork(t *testing.T) {
	snapshot, err := config.Load([]byte(testObservabilityConfig), config.FlagValues{})
	if err != nil {
		t.Fatal("test config rejected")
	}
	runtime, err := NewTraceRuntime(context.Background(), snapshot.Observability().Tracing(), nil)
	if err != nil || runtime == nil || runtime.sdkProvider != nil {
		t.Fatal("disabled tracing constructed an SDK provider")
	}
	_, span := runtime.StartRoot(context.Background(), "dkim2d.http.request")
	if span.IsRecording() {
		t.Fatal("disabled tracing recorded a span")
	}
	EndSpan(span, SpanInternalError)
}

// TestOTLPExporterRejectsEnvironmentOverrides proves only typed config is authoritative.
func TestOTLPExporterRejectsEnvironmentOverrides(t *testing.T) {
	for _, name := range []string{
		"OTEL_EXPORTER_OTLP_HEADERS",
		"OTEL_EXPORTER_OTLP_TRACES_INSECURE",
		"OTEL_GO_X_OBSERVABILITY",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "private-marker")
			if exporterEnvironmentClean() {
				t.Fatal("environment-driven exporter override was accepted")
			}
		})
	}
}

// testTracingSettings returns a fully sampled validated trace configuration.
func testTracingSettings(t *testing.T) config.TracingConfig {
	t.Helper()
	document := testObservabilityConfig + `
observability:
  tracing:
    exporter: otlp_http
    endpoint: https://127.0.0.1:4318/v1/traces
    ca_file: /secure/0123456789abcdef0123456789abcdef/otlp-ca
    sample_per_million: 1000000
    export_timeout: 5s
`
	snapshot, err := config.Load([]byte(document), config.FlagValues{})
	if err != nil {
		t.Fatal("trace test config rejected")
	}
	return snapshot.Observability().Tracing()
}
