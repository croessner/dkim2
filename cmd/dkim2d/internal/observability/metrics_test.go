package observability

import (
	"bytes"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMetricsExposeExactInventoryWithoutRuntimeCollectors proves fresh-registry ownership.
func TestMetricsExposeExactInventoryWithoutRuntimeCollectors(t *testing.T) {
	metrics, err := NewMetrics()
	if err != nil {
		t.Fatal("metrics construction failed")
	}
	metrics.SetReady(true)
	metrics.HTTPStarted("health")
	metrics.HTTPCompleted("health", valueStatus2XX, 5*time.Millisecond)
	first, err := metrics.Gather()
	if err != nil {
		t.Fatal("metrics gather failed")
	}
	second, err := metrics.Gather()
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("metrics exposition is not deterministic")
	}
	text := string(first)
	for _, name := range []string{
		metricReadiness, "dkim2d_http_requests_total",
		"dkim2d_http_request_duration_seconds", "dkim2d_http_in_flight",
	} {
		if !strings.Contains(text, name) {
			t.Fatal("declared metric missing")
		}
	}
	if strings.Contains(text, "go_gc_") || strings.Contains(text, "process_cpu_") {
		t.Fatal("standard global collector leaked into the fresh registry")
	}
}

// TestMetricsDescriptorsAndBucketsMatchDurableContract proves the literal inventory.
func TestMetricsDescriptorsAndBucketsMatchDurableContract(t *testing.T) {
	metrics, err := NewMetrics()
	if err != nil {
		t.Fatal("metrics construction failed")
	}
	families, err := metrics.registry.Gather()
	if err != nil {
		t.Fatal("metrics gathering failed")
	}
	names := make([]string, 0, len(families))
	for _, family := range families {
		names = append(names, family.GetName())
	}
	sort.Strings(names)
	wantNames := []string{
		metricReadiness,
	}
	// Uninstantiated vector collectors are absent from Gather until used.
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("initial metric families = %v, want %v", names, wantNames)
	}
	if !reflect.DeepEqual(httpProcessBuckets, []float64{
		.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60,
	}) || !reflect.DeepEqual(dnsReplayBuckets, []float64{
		.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2, 5,
	}) {
		t.Fatal("histogram bucket contract changed")
	}
	if !slices.Contains(httpOperations(), valueDSNSign) {
		t.Fatal("delivery-status HTTP operation is absent from metrics")
	}
}

// TestMetricsMaximumClosedCardinalityFitsExpositionCap proves no legal series can overflow.
func TestMetricsMaximumClosedCardinalityFitsExpositionCap(t *testing.T) {
	metrics, err := NewMetrics()
	if err != nil {
		t.Fatal("metrics construction failed")
	}
	for _, operation := range httpOperations() {
		for _, status := range []string{valueStatus2XX, valueStatus3XX, valueStatus4XX, valueStatus5XX} {
			metrics.HTTPStarted(operation)
			metrics.HTTPCompleted(operation, status, time.Millisecond)
		}
	}
	for _, result := range []string{valueSuccess, valueFailure, valueTemporary, valueInternal} {
		for _, verdict := range []string{valuePass, valueFail, valueNeutral, valueTemperror, valuePermerror} {
			for _, replay := range []string{valueNotChecked, valueDisabled, valueFirstSeen, valueReplayed, valueIndeterminate} {
				for _, disposition := range []string{"accept", "continue", "reject", "tempfail"} {
					metrics.ProcessCompleted(
						result,
						verdict,
						replay,
						disposition,
						time.Millisecond,
					)
				}
			}
		}
	}
	for _, verdict := range []string{valuePass, valueFail, valueNeutral, valueTemperror, valuePermerror} {
		for _, reason := range []string{valueNone, valueProtocol, valuePolicy, valueAvailability, valueInternal} {
			for _, mode := range []string{valueStrict, valuePermissive, valueTesting} {
				metrics.PolicyCompleted(verdict, reason, mode)
			}
		}
	}
	for _, result := range []string{valueFound, "missing", valueInvalid, "ambiguous", valueTemporary, valueInternal} {
		for _, cache := range []string{valueHit, valueMiss, valueNotUsed} {
			metrics.DNSCompleted(result, cache, time.Millisecond)
		}
	}
	for _, replay := range []string{valueNotChecked, valueDisabled, valueFirstSeen, valueReplayed, valueIndeterminate} {
		for _, result := range []string{valueSuccess, valueFailure, valueTemporary, valueInternal} {
			metrics.ReplayCompleted(replay, result, time.Millisecond)
		}
	}
	for _, signal := range []string{"log", "trace", "metric"} {
		for _, reason := range []string{"invalid", valueOverflow, valuePanic, valueExport} {
			metrics.ObservationDropped(signal, reason)
		}
	}
	output, gatherErr := metrics.Gather()
	if gatherErr != nil || len(output) > maxMetricsBytes {
		t.Fatalf(
			"maximum legal metric vocabulary exceeds cap: bytes=%d err=%v",
			len(output),
			gatherErr,
		)
	}
}

// TestMetricsRejectArbitraryLabels proves invalid values do not create series.
func TestMetricsRejectArbitraryLabels(t *testing.T) {
	metrics, err := NewMetrics()
	if err != nil {
		t.Fatal("metrics construction failed")
	}
	metrics.HTTPStarted("private-marker.example")
	metrics.HTTPCompleted("health", "private-marker", time.Second)
	metrics.ProcessCompleted("private-marker", "pass", "first_seen", "accept", time.Second)
	output, err := metrics.Gather()
	if err != nil {
		t.Fatal("metrics gather failed")
	}
	if bytes.Contains(output, []byte("private-marker")) {
		t.Fatal("arbitrary label value escaped")
	}
}

// TestMetricsRecordEverySupportedOperation proves all implemented HTTP routes are observable.
func TestMetricsRecordEverySupportedOperation(t *testing.T) {
	metrics, err := NewMetrics()
	if err != nil {
		t.Fatal("metrics construction failed")
	}
	for _, operation := range []string{valueProcess, valueSign, valueRevise} {
		metrics.HTTPStarted(operation)
		metrics.HTTPCompleted(operation, valueStatus2XX, time.Millisecond)
	}
	output, err := metrics.Gather()
	if err != nil {
		t.Fatal("metrics gather failed")
	}
	for _, operation := range []string{valueProcess, valueSign, valueRevise} {
		want := []byte(`dkim2d_http_requests_total{operation="` + operation + `",status_class="2xx"} 1`)
		if !bytes.Contains(output, want) {
			t.Fatalf("missing completed HTTP series for %q", operation)
		}
	}
}

// TestMetricsConcurrentUpdatesAreRaceSafe proves collector ownership under load.
func TestMetricsConcurrentUpdatesAreRaceSafe(t *testing.T) {
	metrics, err := NewMetrics()
	if err != nil {
		t.Fatal("metrics construction failed")
	}
	var workers sync.WaitGroup
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 50 {
				metrics.HTTPStarted("process")
				metrics.HTTPCompleted("process", valueStatus2XX, time.Millisecond)
				metrics.ProcessCompleted("success", "pass", "first_seen", "accept", time.Millisecond)
				metrics.PolicyCompleted("pass", "none", "strict")
				metrics.DNSCompleted(valueFound, valueHit, time.Millisecond)
				metrics.ReplayCompleted("first_seen", "success", time.Millisecond)
			}
		}()
	}
	workers.Wait()
	if _, err := metrics.Gather(); err != nil {
		t.Fatal("concurrent collector gather failed")
	}
}

// TestReadinessGaugeCannotRiseAfterTerminalZero proves shutdown monotonicity.
func TestReadinessGaugeCannotRiseAfterTerminalZero(t *testing.T) {
	metrics, err := NewMetrics()
	if err != nil {
		t.Fatal("metrics construction failed")
	}
	metrics.SetReady(true)
	metrics.SetReady(false)
	metrics.SetReady(true)
	output, err := metrics.Gather()
	if err != nil || !strings.Contains(string(output), "dkim2d_readiness 0") {
		t.Fatal("terminal readiness gauge rose again")
	}
}
