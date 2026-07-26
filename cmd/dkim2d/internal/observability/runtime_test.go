package observability

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
)

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
	output, gatherErr := runtime.Metrics().Gather()
	if gatherErr != nil ||
		!strings.Contains(string(output), `dkim2d_dns_lookups_total{cache_result="not_used",dns_result="`+valueFound+`"} 1`) ||
		!strings.Contains(string(output), `dkim2d_observation_dropped_total{reason_class="invalid",signal="log"} 1`) ||
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
