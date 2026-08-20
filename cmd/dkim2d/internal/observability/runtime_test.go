package observability

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestRuntimeVerificationObservationEmitsExactSpan proves only an authentic
// applicable-verification event becomes the daemon's verification span.
func TestRuntimeVerificationObservationEmitsExactSpan(t *testing.T) {
	t.Parallel()
	exporter := tracetest.NewInMemoryExporter()
	tracing, err := newSDKTraceRuntime(
		testTracingSettings(t),
		sdktrace.NewSimpleSpanProcessor(exporter),
	)
	if err != nil {
		t.Fatal("trace runtime construction failed")
	}
	t.Cleanup(func() { _ = tracing.Shutdown(context.Background()) })
	runtime := &Runtime{tracing: tracing}
	event, ok := dkim2.NewObservationEvent(
		dkim2.ObservationVerifyCompleted,
		dkim2.ObservationOperationVerify,
		dkim2.ObservationResultSuccess,
		dkim2.ObservationReasonNone,
		dkim2.ObservationErrorNone,
		dkim2.ObservationAlgorithmNone,
		dkim2.ObservationCacheNotUsed,
		dkim2.ObservationBucketSmall,
		dkim2.ObservationBucketSmall,
		dkim2.ObservationBucketSmall,
		dkim2.ObservationBucketNone,
		dkim2.ObservationBucketNone,
	)
	if !ok {
		t.Fatal("verification observation fixture rejected")
	}
	runtime.Observe(context.Background(), event)
	spans := exporter.GetSpans()
	if len(spans) != 1 || spans[0].Name != "dkim2.verify" {
		t.Fatalf("verification spans = %#v", spans)
	}
	want := attribute.String("dkim2.result", valueSuccess)
	if len(spans[0].Attributes) != 1 || spans[0].Attributes[0] != want {
		t.Fatalf("verification span attributes = %#v", spans[0].Attributes)
	}
}

// TestRuntimeOwnsClosedDisabledTelemetry proves combined construction and exact shutdown.
func TestRuntimeOwnsClosedDisabledTelemetry(t *testing.T) {
	snapshot, err := config.Load([]byte(testObservabilityConfig), config.FlagValues{})
	if err != nil {
		t.Fatal("test config rejected")
	}
	var logs bytes.Buffer
	runtime, err := NewRuntime(
		context.Background(),
		snapshot.Observability(),
		&logs,
		config.TracingStartupMaterial{},
	)
	if err != nil || runtime == nil || runtime.Metrics() == nil ||
		runtime.Tracing() == nil || runtime.Tracing().sdkProvider != nil {
		t.Fatal("combined disabled runtime construction failed")
	}
	runtime.SetReady(true)
	runtime.Logger().Info("unsupported.event")
	event, ok := dkim2.NewObservationEvent(
		dkim2.ObservationDNSLookupCompleted,
		dkim2.ObservationOperationDNSLookup,
		dkim2.ObservationResultSuccess,
		dkim2.ObservationReasonNone,
		dkim2.ObservationErrorNone,
		dkim2.ObservationAlgorithmRSA,
		dkim2.ObservationCacheNotUsed,
		dkim2.ObservationBucketSmall,
		dkim2.ObservationBucketNone,
		dkim2.ObservationBucketNone,
		dkim2.ObservationBucketNone,
		dkim2.ObservationBucketNone,
	)
	if !ok {
		t.Fatal("test observation invalid")
	}
	runtime.Observe(context.Background(), event)
	runtime.ObserveDSNEvidence("embedded_verification", valueFailure)
	output, gatherErr := runtime.Metrics().Gather()
	if gatherErr != nil ||
		!strings.Contains(string(output), `dkim2d_dns_lookups_total{cache_result="not_used",dns_result="`+valueFound+`"} 1`) ||
		!strings.Contains(string(output), `dkim2d_observation_dropped_total{reason_class="invalid",signal="log"} 1`) ||
		!strings.Contains(string(output), `dkim2d_dsn_evidence_total{evidence_stage="embedded_verification",result="failure"} 1`) ||
		!strings.Contains(string(output), "dkim2d_readiness 1") {
		t.Fatal("combined runtime did not project closed metrics")
	}
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatal("first shutdown failed")
	}
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatal("repeated shutdown changed its result")
	}
	if bytes.Contains(logs.Bytes(), []byte("recipient@example.test")) {
		t.Fatal("runtime telemetry exposed identity input")
	}
	if !bytes.Contains(logs.Bytes(), []byte(`"msg":"dsn.evidence.completed"`)) ||
		bytes.Contains(logs.Bytes(), []byte("private-marker")) {
		t.Fatal("runtime omitted or widened DSN evidence diagnostics")
	}
}

// TestRuntimeReadinessCannotRepublishAfterTerminalWithdrawal proves logs and metrics agree.
func TestRuntimeReadinessCannotRepublishAfterTerminalWithdrawal(t *testing.T) {
	snapshot, err := config.Load([]byte(testObservabilityConfig), config.FlagValues{})
	if err != nil {
		t.Fatal("test config rejected")
	}
	var logs bytes.Buffer
	runtime, err := NewRuntime(
		context.Background(),
		snapshot.Observability(),
		&logs,
		config.TracingStartupMaterial{},
	)
	if err != nil {
		t.Fatal("runtime construction failed")
	}
	runtime.SetReady(true)
	runtime.SetReady(false)
	terminalOffset := logs.Len()
	runtime.SetReady(true)
	if bytes.Contains(logs.Bytes()[terminalOffset:], []byte(`"ready":true`)) ||
		bytes.Contains(logs.Bytes()[terminalOffset:], []byte(`"lifecycle_state":"active"`)) {
		t.Fatal("terminal readiness withdrawal was contradicted by later logs")
	}
	output, gatherErr := runtime.Metrics().Gather()
	if gatherErr != nil || !strings.Contains(string(output), "dkim2d_readiness 0") {
		t.Fatal("terminal readiness metric changed")
	}
}
