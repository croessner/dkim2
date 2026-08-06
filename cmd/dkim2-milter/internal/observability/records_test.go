package observability

import (
	"bytes"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/milter"
)

// TestRuntimeRecordsAllClosedAdapterFacts proves log and metric projection.
func TestRuntimeRecordsAllClosedAdapterFacts(t *testing.T) {
	var output bytes.Buffer
	runtime, err := New(observabilitySnapshot(t, "info"), &output)
	if err != nil {
		t.Fatal("runtime construction failed")
	}
	runtime.RecordConnectionAdmission("accepted")
	runtime.RecordCallback("eom", "terminal", valueSuccess, 2*time.Millisecond)
	runtime.RecordCallback("macro", "helo", valueSuccess, 2*time.Millisecond)
	runtime.RecordMessage(
		valueModeInbound, valueAccept, valueSuccess, valueNone,
		2*time.Millisecond, 2_000, 2, false,
		mustDomainObservation(t, "recipient", "example.test,example.org", 2, false),
	)
	runtime.RecordAction("add_header", valueSuccess)
	runtime.RecordAction("change_header", valueSuccess)
	runtime.RecordAction("insert_header", valueSuccess)
	for _, eventID := range []string{
		eventConnectionAdmission,
		eventCallbackCompleted,
		eventMessageCompleted,
		eventActionCompleted,
	} {
		if !bytes.Contains(output.Bytes(), []byte(`"event_id":"`+eventID+`"`)) {
			t.Fatalf("closed event %q missing", eventID)
		}
	}
	if !bytes.Contains(output.Bytes(), []byte(`"daemon_operation":"process"`)) ||
		!bytes.Contains(output.Bytes(), []byte(`"processed_domains":"example.test,example.org"`)) ||
		!bytes.Contains(output.Bytes(), []byte(`"callback_class":"macro"`)) ||
		!bytes.Contains(output.Bytes(), []byte(`"action_kind":"change_header"`)) ||
		!bytes.Contains(output.Bytes(), []byte(`"action_kind":"insert_header"`)) {
		t.Fatal("derived operation or macro callback was not observable")
	}
	exposition, err := runtime.Gather()
	if err != nil {
		t.Fatal("metric gathering failed")
	}
	for _, metric := range []string{
		metricConnectionAdmissions,
		metricCallbacks,
		metricMessages,
		metricActions,
		metricMessageDuration,
		metricMessageSize,
		metricRecipientCount,
	} {
		if !bytes.Contains(exposition, []byte(metric)) {
			t.Fatalf("closed metric %q missing", metric)
		}
	}
}

// mustDomainObservation constructs one test-only validated domain observation.
func mustDomainObservation(
	t *testing.T,
	role, domains string,
	count uint64,
	truncated bool,
) milter.DomainObservation {
	t.Helper()
	observation, ok := milter.NewDomainObservation(role, domains, count, truncated)
	if !ok {
		t.Fatal("domain observation construction failed")
	}
	return observation
}

// TestRuntimeRejectsIncoherentMessageOutcomesWithoutPartialTelemetry proves cohesion.
func TestRuntimeRejectsIncoherentMessageOutcomesWithoutPartialTelemetry(t *testing.T) {
	var output bytes.Buffer
	runtime, err := New(observabilitySnapshot(t, "info"), &output)
	if err != nil {
		t.Fatal("runtime construction failed")
	}
	before, err := runtime.Gather()
	if err != nil {
		t.Fatal("initial gather failed")
	}
	for _, outcome := range []struct {
		disposition, result, failure string
		failOpen                     bool
	}{
		{disposition: valueReject, result: valueSuccess, failure: valueNone, failOpen: true},
		{disposition: valueAccept, result: valueSuccess, failure: "indeterminate"},
		{disposition: valueClose, result: "failure", failure: valueNone},
	} {
		runtime.RecordMessage(
			valueModeInbound, outcome.disposition, outcome.result, outcome.failure,
			time.Millisecond, 1, 1, outcome.failOpen, milter.DomainObservation{},
		)
	}
	after, err := runtime.Gather()
	if err != nil || !bytes.Equal(before, after) || output.Len() != 0 {
		t.Fatal("incoherent message outcome produced partial telemetry")
	}
}

// TestSuccessfulMessageDoesNotIncrementFailureMetric freezes semantic naming.
func TestSuccessfulMessageDoesNotIncrementFailureMetric(t *testing.T) {
	var output bytes.Buffer
	runtime, err := New(observabilitySnapshot(t, "info"), &output)
	if err != nil {
		t.Fatal("runtime construction failed")
	}
	runtime.RecordMessage(
		"originator", valueAccept, valueSuccess, valueNone,
		time.Millisecond, 1, 1, false,
		mustDomainObservation(t, "signing", "example.test", 1, false),
	)
	exposition, err := runtime.Gather()
	if err != nil {
		t.Fatal("gather failed")
	}
	if bytes.Contains(exposition, []byte(metricMessageFailures)) ||
		!bytes.Contains(exposition, []byte(`daemon_operation="sign"`)) {
		t.Fatal("successful outcome created a failure series or lost operation")
	}
}

// TestPostfixDSNMessageUsesDedicatedOperation proves low-cardinality routing.
func TestPostfixDSNMessageUsesDedicatedOperation(t *testing.T) {
	var output bytes.Buffer
	runtime, err := New(observabilitySnapshot(t, "info"), &output)
	if err != nil {
		t.Fatal("runtime construction failed")
	}
	runtime.RecordMessage(
		valueModePostfixDSN, valueAccept, valueSuccess, valueNone,
		time.Millisecond, 1, 1, false,
		mustDomainObservation(t, "signing", "example.test", 1, false),
	)
	exposition, err := runtime.Gather()
	if err != nil {
		t.Fatal("gather failed")
	}
	if !bytes.Contains(output.Bytes(), []byte(`"daemon_operation":"`+valueOperationDSN+`"`)) ||
		!bytes.Contains(exposition, []byte(`daemon_operation="`+valueOperationDSN+`"`)) {
		t.Fatal("Postfix DSN outcome lost its dedicated operation")
	}
}

// TestRuntimeRejectsInvalidObservationsAtomically proves no partial projection.
func TestRuntimeRejectsInvalidObservationsAtomically(t *testing.T) {
	var output bytes.Buffer
	runtime, err := New(observabilitySnapshot(t, "info"), &output)
	if err != nil {
		t.Fatal("runtime construction failed")
	}
	before, err := runtime.Gather()
	if err != nil {
		t.Fatal("initial gather failed")
	}
	runtime.RecordConnectionAdmission(privacyMarker)
	runtime.RecordCallback(privacyMarker, "terminal", valueSuccess, time.Second)
	runtime.RecordMessage(
		privacyMarker, valueAccept, valueSuccess, valueNone,
		time.Second, 1, 1, false, milter.DomainObservation{},
	)
	runtime.RecordMessage(
		valueModeInbound, valueAccept, valueSuccess, valueNone,
		time.Second, maxObservedMessageBytes+1, 1, false, milter.DomainObservation{},
	)
	runtime.RecordAction(privacyMarker, valueSuccess)
	after, err := runtime.Gather()
	if err != nil || !bytes.Equal(before, after) || output.Len() != 0 {
		t.Fatal("invalid observation produced a partial log or metric")
	}
}

// TestLoggingBucketsFreezeExactBoundaries proves stable bounded classifications.
func TestLoggingBucketsFreezeExactBoundaries(t *testing.T) {
	if durationBucket(999*time.Microsecond) != valueDurationLT1ms ||
		durationBucket(time.Millisecond) != valueDurationLT5ms ||
		durationBucket(30*time.Second) != valueDurationGTE30s ||
		messageSizeBucket(0) != "0" ||
		messageSizeBucket(1_000) != valueSizeLT10k ||
		recipientCountBucket(10) != "2_10" ||
		recipientCountBucket(1_001) != valueRecipientsGTE {
		t.Fatal("closed logging bucket boundary changed")
	}
}
