package observability

import (
	"bytes"
	"slices"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

const (
	// MetricsContentType is the exact successful Prometheus exposition type.
	MetricsContentType = "text/plain; version=0.0.4; charset=utf-8"
	maxMetricsBytes    = 256 << 10

	metricActions              = "dkim2_milter_actions_total"
	metricCallbacks            = "dkim2_milter_callbacks_total"
	metricConnectionAdmissions = "dkim2_milter_connection_admissions_total"
	metricFailOpen             = "dkim2_milter_fail_open_total"
	metricLifecycle            = "dkim2_milter_lifecycle_total"
	metricMessageDuration      = "dkim2_milter_message_duration_seconds"
	metricMessageFailures      = "dkim2_milter_message_failures_total"
	metricMessageSize          = "dkim2_milter_message_size_bytes"
	metricMessages             = "dkim2_milter_messages_total"
	metricReadiness            = "dkim2_milter_readiness"
	metricRecipientCount       = "dkim2_milter_recipient_count"
	maxObservedMessageBytes    = 32 << 20
	maxObservedRecipients      = 2_000
)

// Registry owns one fresh Prometheus registry and the exact adapter inventory.
type Registry struct {
	registry *prometheus.Registry

	readiness  prometheus.Gauge
	lifecycle  *prometheus.CounterVec
	admissions *prometheus.CounterVec
	messages   *prometheus.CounterVec
	failures   *prometheus.CounterVec
	failOpen   prometheus.Counter
	duration   prometheus.Histogram
	size       prometheus.Histogram
	recipients prometheus.Histogram
	callbacks  *prometheus.CounterVec
	actions    *prometheus.CounterVec

	invalid atomic.Bool
}

// NewRegistry constructs one exact inventory without global collectors.
func NewRegistry() *Registry {
	registry := prometheus.NewRegistry()
	durationBucketValues := metricDurationBuckets()
	messageBucketValues := metricMessageBuckets()
	recipientBucketValues := metricRecipientBuckets()
	result := &Registry{
		registry: registry,
		readiness: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: metricReadiness,
			Help: "Whether the adapter admits readiness-dependent work.",
		}),
		lifecycle: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricLifecycle,
			Help: "Adapter lifecycle transitions.",
		}, []string{keyLifecycleState}),
		admissions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricConnectionAdmissions,
			Help: "Connection admission outcomes.",
		}, []string{keyAdmission}),
		messages: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricMessages,
			Help: "Completed bounded message outcomes.",
		}, []string{keyMode, keyDaemonOperation, keyDisposition, keyResultClass}),
		failures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricMessageFailures,
			Help: "Completed messages by failure class.",
		}, []string{keyFailureClass}),
		failOpen: prometheus.NewCounter(prometheus.CounterOpts{
			Name: metricFailOpen,
			Help: "Messages accepted through the explicit fail-open policy.",
		}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    metricMessageDuration,
			Help:    "Completed message duration.",
			Buckets: append([]float64(nil), durationBucketValues[:]...),
		}),
		size: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    metricMessageSize,
			Help:    "Reconstructed message size.",
			Buckets: append([]float64(nil), messageBucketValues[:]...),
		}),
		recipients: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    metricRecipientCount,
			Help:    "Envelope recipient count.",
			Buckets: append([]float64(nil), recipientBucketValues[:]...),
		}),
		callbacks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricCallbacks,
			Help: "Completed bounded Milter callbacks.",
		}, []string{keyCallbackClass, keyStateClass, keyResultClass}),
		actions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricActions,
			Help: "Completed bounded adapter actions.",
		}, []string{keyActionKind, keyResultClass}),
	}
	collectors := []prometheus.Collector{
		result.readiness,
		result.lifecycle,
		result.admissions,
		result.messages,
		result.failures,
		result.failOpen,
		result.duration,
		result.size,
		result.recipients,
		result.callbacks,
		result.actions,
	}
	for _, collector := range collectors {
		if err := registry.Register(collector); err != nil {
			result.invalid.Store(true)
			break
		}
	}
	result.readiness.Set(0)
	return result
}

// setReady records the exact readiness gauge.
func (r *Registry) setReady(ready bool) {
	defer containMetricPanic()
	if !r.usable() {
		return
	}
	if ready {
		r.readiness.Set(1)
		return
	}
	r.readiness.Set(0)
}

// recordLifecycle records one closed lifecycle state.
func (r *Registry) recordLifecycle(state string) {
	defer containMetricPanic()
	if r.usable() && closedMetricValue(keyLifecycleState, state) {
		r.lifecycle.WithLabelValues(state).Inc()
	}
}

// RecordConnectionAdmission records one closed admission outcome.
func (r *Registry) RecordConnectionAdmission(admission string) {
	defer containMetricPanic()
	if r.usable() && closedMetricValue(keyAdmission, admission) {
		r.admissions.WithLabelValues(admission).Inc()
	}
}

// RecordMessage records one bounded outcome plus histogram measurements.
func (r *Registry) RecordMessage(
	mode string,
	operation string,
	disposition string,
	resultClass string,
	failureClass string,
	duration time.Duration,
	messageBytes uint64,
	recipients uint64,
	failOpen bool,
) {
	defer containMetricPanic()
	if !r.usable() || duration < 0 ||
		messageBytes > maxObservedMessageBytes ||
		recipients > maxObservedRecipients ||
		!closedMetricValue(keyMode, mode) ||
		!closedMetricValue(keyDaemonOperation, operation) ||
		!closedMetricValue(keyDisposition, disposition) ||
		!closedMetricValue(keyResultClass, resultClass) ||
		!closedMetricValue(keyFailureClass, failureClass) ||
		!validMessageOutcome(disposition, resultClass, failureClass, failOpen) {
		return
	}
	r.messages.WithLabelValues(mode, operation, disposition, resultClass).Inc()
	if failureClass != valueNone {
		r.failures.WithLabelValues(failureClass).Inc()
	}
	if failOpen {
		r.failOpen.Inc()
	}
	r.duration.Observe(duration.Seconds())
	r.size.Observe(float64(messageBytes))
	r.recipients.Observe(float64(recipients))
}

// RecordCallback records one closed callback and state outcome.
func (r *Registry) RecordCallback(
	callbackClass string,
	stateClass string,
	resultClass string,
) {
	defer containMetricPanic()
	if !r.usable() ||
		!closedMetricValue(keyCallbackClass, callbackClass) ||
		!closedMetricValue(keyStateClass, stateClass) ||
		!closedMetricValue(keyResultClass, resultClass) {
		return
	}
	r.callbacks.WithLabelValues(callbackClass, stateClass, resultClass).Inc()
}

// RecordAction records one validated adapter action result.
func (r *Registry) RecordAction(actionKind string, resultClass string) {
	defer containMetricPanic()
	if !r.usable() ||
		!closedMetricValue(keyActionKind, actionKind) ||
		!closedMetricValue(keyResultClass, resultClass) {
		return
	}
	r.actions.WithLabelValues(actionKind, resultClass).Inc()
}

// Gather returns deterministic capped Prometheus text.
func (r *Registry) Gather() (outputBytes []byte, resultErr error) {
	defer func() {
		if recover() != nil {
			outputBytes = nil
			resultErr = errConfiguration
		}
	}()
	if !r.usable() {
		return nil, errConfiguration
	}
	families, err := r.registry.Gather()
	if err != nil {
		return nil, errConfiguration
	}
	var output bytes.Buffer
	for _, family := range families {
		if _, err := expfmt.MetricFamilyToText(&output, family); err != nil {
			return nil, errConfiguration
		}
		if output.Len() > maxMetricsBytes {
			return nil, errConfiguration
		}
	}
	return append([]byte(nil), output.Bytes()...), nil
}

// usable reports whether the complete exact collector inventory exists.
func (r *Registry) usable() bool {
	return r != nil && !r.invalid.Load() && r.registry != nil &&
		r.readiness != nil && r.lifecycle != nil && r.admissions != nil &&
		r.messages != nil && r.failures != nil && r.failOpen != nil &&
		r.duration != nil && r.size != nil && r.recipients != nil &&
		r.callbacks != nil && r.actions != nil
}

// closedMetricValue applies the exact low-cardinality vocabulary.
func closedMetricValue(key string, value string) bool {
	values := closedVocabulary(key)
	return values != nil && slices.Contains(values, value)
}

// containMetricPanic prevents collector defects from crossing telemetry boundaries.
func containMetricPanic() {
	_ = recover()
}

// metricDurationBuckets returns the immutable duration boundary value.
func metricDurationBuckets() [13]float64 {
	return [13]float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30}
}

// metricMessageBuckets returns the immutable message-size boundary value.
func metricMessageBuckets() [6]float64 {
	return [6]float64{1_000, 10_000, 100_000, 1_000_000, 10_000_000, 32_000_000}
}

// metricRecipientBuckets returns the immutable recipient-count boundary value.
func metricRecipientBuckets() [5]float64 {
	return [5]float64{1, 10, 100, 1_000, 2_000}
}
