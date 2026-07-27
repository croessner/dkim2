package observability

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// TestRegistryExposesExactInventoryAndNoGlobalCollectors proves local ownership.
func TestRegistryExposesExactInventoryAndNoGlobalCollectors(t *testing.T) {
	registry := NewRegistry()
	registry.setReady(true)
	registry.RecordConnectionAdmission("accepted")
	registry.RecordMessage(
		"inbound", "process", "accept", valueSuccess, "none",
		2*time.Millisecond, 2_000, 2, false,
	)
	registry.RecordMessage(
		"inbound", "process", "tempfail", "failure", "contract",
		2*time.Millisecond, 2_000, 2, false,
	)
	registry.RecordCallback("eom", "terminal", valueSuccess)
	registry.RecordAction("add_header", valueSuccess)
	first, err := registry.Gather()
	if err != nil {
		t.Fatal("gather failed")
	}
	second, err := registry.Gather()
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("gather was not deterministic")
	}
	for _, name := range []string{
		"dkim2_milter_readiness",
		metricConnectionAdmissions,
		metricMessages,
		metricMessageFailures,
		metricFailOpen,
		metricMessageDuration,
		metricMessageSize,
		metricRecipientCount,
		metricCallbacks,
		metricActions,
	} {
		if !bytes.Contains(first, []byte(name)) {
			t.Fatalf("declared metric %q missing", name)
		}
	}
	for _, forbidden := range [][]byte{
		[]byte("go_gc_"), []byte("process_cpu_"), []byte(privacyMarker),
	} {
		if bytes.Contains(first, forbidden) {
			t.Fatal("forbidden series or marker escaped")
		}
	}
}

// TestRegistryRejectsArbitraryLabelsWithoutCreatingSeries proves closed cardinality.
func TestRegistryRejectsArbitraryLabelsWithoutCreatingSeries(t *testing.T) {
	registry := NewRegistry()
	registry.RecordConnectionAdmission(privacyMarker)
	registry.RecordMessage(
		privacyMarker, "process", "accept", valueSuccess, "none",
		time.Second, 1, 1, false,
	)
	registry.RecordCallback("eom", privacyMarker, valueSuccess)
	registry.RecordAction(privacyMarker, valueSuccess)
	output, err := registry.Gather()
	if err != nil {
		t.Fatal("gather failed")
	}
	if bytes.Contains(output, []byte(privacyMarker)) ||
		bytes.Contains(output, []byte("messages_total{")) ||
		bytes.Contains(output, []byte("message_failures_total{")) ||
		bytes.Contains(output, []byte(metricFailOpen+" 1")) ||
		bytes.Contains(output, []byte(metricMessageDuration+"_count 1")) ||
		bytes.Contains(output, []byte(metricMessageSize+"_count 1")) ||
		bytes.Contains(output, []byte(metricRecipientCount+"_count 1")) ||
		bytes.Contains(output, []byte("callbacks_total{")) ||
		bytes.Contains(output, []byte("actions_total{")) ||
		bytes.Contains(output, []byte("admissions_total{")) {
		t.Fatal("invalid label created a metric series")
	}
}

// TestRegistryMaximumVocabularyRemainsUnderCap proves bounded cardinality.
func TestRegistryMaximumVocabularyRemainsUnderCap(t *testing.T) {
	registry := NewRegistry()
	for _, admission := range closedVocabulary(keyAdmission) {
		registry.RecordConnectionAdmission(admission)
	}
	for _, mode := range closedVocabulary(keyMode) {
		for _, disposition := range closedVocabulary(keyDisposition) {
			for _, result := range closedVocabulary(keyResultClass) {
				for _, failure := range closedVocabulary(keyFailureClass) {
					operation, _ := daemonOperationForMode(mode)
					registry.RecordMessage(
						mode, operation, disposition, result, failure,
						time.Millisecond, 1, 1, false,
					)
					registry.RecordMessage(
						mode, operation, disposition, result, failure,
						time.Millisecond, 1, 1, true,
					)
				}
			}
		}
	}
	for _, callback := range closedVocabulary(keyCallbackClass) {
		for _, state := range closedVocabulary(keyStateClass) {
			for _, result := range closedVocabulary(keyResultClass) {
				registry.RecordCallback(callback, state, result)
			}
		}
	}
	for _, action := range closedVocabulary(keyActionKind) {
		for _, result := range closedVocabulary(keyResultClass) {
			registry.RecordAction(action, result)
		}
	}
	for _, duration := range []time.Duration{
		0, time.Millisecond, 5 * time.Millisecond, 10 * time.Millisecond,
		25 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond,
		250 * time.Millisecond, 500 * time.Millisecond, time.Second,
		2500 * time.Millisecond, 5 * time.Second, 10 * time.Second,
		30 * time.Second,
	} {
		registry.RecordMessage(
			"inbound", "process", "accept", valueSuccess, "none",
			duration, 1, 1, false,
		)
	}
	for _, size := range []uint64{0, 1, 1_000, 10_000, 100_000, 1_000_000, 10_000_000} {
		registry.RecordMessage(
			"inbound", "process", "accept", valueSuccess, "none",
			time.Millisecond, size, 1, false,
		)
	}
	for _, recipients := range []uint64{0, 1, 2, 11, 101, 1_001} {
		registry.RecordMessage(
			"inbound", "process", "accept", valueSuccess, "none",
			time.Millisecond, 1, recipients, false,
		)
	}
	output, err := registry.Gather()
	if err != nil || len(output) > maxMetricsBytes {
		t.Fatalf("maximum closed vocabulary exceeded cap: bytes=%d", len(output))
	}
}

// TestRegistryConcurrentUpdatesAndGatherAreRaceSafe proves shared runtime safety.
func TestRegistryConcurrentUpdatesAndGatherAreRaceSafe(t *testing.T) {
	registry := NewRegistry()
	var workers sync.WaitGroup
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				registry.RecordConnectionAdmission("accepted")
				registry.RecordMessage(
					"inbound", "process", "accept", valueSuccess, "none",
					time.Millisecond, 10, 1, false,
				)
				registry.RecordCallback("eom", "terminal", valueSuccess)
				registry.RecordAction("accept", valueSuccess)
				_, _ = registry.Gather()
			}
		}()
	}
	workers.Wait()
	if _, err := registry.Gather(); err != nil {
		t.Fatal("concurrent gather failed")
	}
}

// TestMetricBucketsFreezeExactBoundaries proves classification is stable.
func TestMetricBucketsFreezeExactBoundaries(t *testing.T) {
	durationBuckets := metricDurationBuckets()
	messageBuckets := metricMessageBuckets()
	recipientBuckets := metricRecipientBuckets()
	if len(durationBuckets) != 13 || durationBuckets[0] != .001 ||
		durationBuckets[len(durationBuckets)-1] != 30 ||
		len(messageBuckets) != 6 || messageBuckets[0] != 1_000 ||
		messageBuckets[len(messageBuckets)-1] != 32_000_000 ||
		len(recipientBuckets) != 5 || recipientBuckets[0] != 1 ||
		recipientBuckets[len(recipientBuckets)-1] != 2_000 {
		t.Fatal("closed bucket boundary changed")
	}
}

// TestClosedVocabularyAndBucketsReturnIsolatedValues proves no mutable globals leak.
func TestClosedVocabularyAndBucketsReturnIsolatedValues(t *testing.T) {
	firstVocabulary := closedVocabulary(keyMode)
	firstVocabulary[0] = privacyMarker
	if closedVocabulary(keyMode)[0] == privacyMarker {
		t.Fatal("closed vocabulary shared mutable process state")
	}
	firstBuckets := metricDurationBuckets()
	firstBuckets[0] = 99
	if metricDurationBuckets()[0] != .001 {
		t.Fatal("metric buckets shared mutable process state")
	}
}

// TestZeroRegistryContainsCallsWithoutPanicking proves hostile seam containment.
func TestZeroRegistryContainsCallsWithoutPanicking(t *testing.T) {
	var registry Registry
	registry.setReady(true)
	registry.recordLifecycle("active")
	registry.RecordConnectionAdmission("accepted")
	registry.RecordMessage(
		"inbound", "process", "accept", valueSuccess, "none",
		time.Millisecond, 1, 1, false,
	)
	registry.RecordCallback("eom", "terminal", valueSuccess)
	registry.RecordAction("accept", valueSuccess)
	if _, err := registry.Gather(); err == nil {
		t.Fatal("zero registry gathered successfully")
	}
}
