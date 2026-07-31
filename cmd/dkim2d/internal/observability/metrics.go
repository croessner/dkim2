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
)

var (
	httpProcessBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60}
	dnsReplayBuckets   = []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2, 5}
)

// Metrics owns one fresh process-local registry and exact collector set.
type Metrics struct {
	registry *prometheus.Registry

	readiness       prometheus.Gauge
	httpRequests    *prometheus.CounterVec
	httpDuration    *prometheus.HistogramVec
	httpInFlight    *prometheus.GaugeVec
	process         *prometheus.CounterVec
	processDuration *prometheus.HistogramVec
	policy          *prometheus.CounterVec
	dns             *prometheus.CounterVec
	dnsDuration     *prometheus.HistogramVec
	replay          *prometheus.CounterVec
	replayDuration  *prometheus.HistogramVec
	datasource      *prometheus.CounterVec
	datasourceTime  *prometheus.HistogramVec
	dropped         *prometheus.CounterVec

	readyTerminal atomic.Bool
}

// NewMetrics constructs one exact collector inventory on a fresh registry.
func NewMetrics() (*Metrics, error) {
	metrics := &Metrics{
		registry: prometheus.NewRegistry(),
		readiness: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: metricReadiness,
			Help: "Whether the daemon currently admits readiness-dependent work.",
		}),
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dkim2d_http_requests_total",
			Help: "Completed bounded HTTP requests.",
		}, []string{keyOperation, keyStatusClass}),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "dkim2d_http_request_duration_seconds",
			Help:    "Bounded HTTP request duration.",
			Buckets: append([]float64(nil), httpProcessBuckets...),
		}, []string{keyOperation}),
		httpInFlight: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "dkim2d_http_in_flight",
			Help: "Current bounded HTTP request count.",
		}, []string{keyOperation}),
		process: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dkim2d_process_total",
			Help: "Completed inbound processing outcomes.",
		}, []string{keyResult, keyVerdict, keyReplayState, keyDisposition}),
		processDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "dkim2d_process_duration_seconds",
			Help:    "Inbound processing duration.",
			Buckets: append([]float64(nil), httpProcessBuckets...),
		}, []string{keyResult}),
		policy: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dkim2d_policy_decisions_total",
			Help: "Completed local policy decisions.",
		}, []string{keyVerdict, keyReasonClass, keyPolicyMode}),
		dns: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dkim2d_dns_lookups_total",
			Help: "Completed DNS public-key lookups.",
		}, []string{keyDNSResult, keyCacheResult}),
		dnsDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "dkim2d_dns_lookup_duration_seconds",
			Help:    "DNS public-key lookup duration.",
			Buckets: append([]float64(nil), dnsReplayBuckets...),
		}, []string{keyDNSResult}),
		replay: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dkim2d_replay_coordinates_total",
			Help: "Completed replay coordination outcomes.",
		}, []string{keyReplayState, keyResult}),
		replayDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "dkim2d_replay_coordinate_duration_seconds",
			Help:    "Replay coordination duration.",
			Buckets: append([]float64(nil), dnsReplayBuckets...),
		}, []string{keyReplayState}),
		datasource: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dkim2d_datasource_operations_total",
			Help: "Completed bounded datasource operations.",
		}, []string{keyProvider, keyOperation, keyProviderState, keyResult}),
		datasourceTime: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "dkim2d_datasource_operation_duration_seconds",
			Help:    "Bounded datasource operation duration.",
			Buckets: append([]float64(nil), dnsReplayBuckets...),
		}, []string{keyProvider, keyOperation, keyResult}),
		dropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dkim2d_observation_dropped_total",
			Help: "Contained observation drops.",
		}, []string{"signal", keyReasonClass}),
	}
	collectors := []prometheus.Collector{
		metrics.readiness, metrics.httpRequests, metrics.httpDuration,
		metrics.httpInFlight, metrics.process, metrics.processDuration,
		metrics.policy, metrics.dns, metrics.dnsDuration, metrics.replay,
		metrics.replayDuration, metrics.datasource, metrics.datasourceTime,
		metrics.dropped,
	}
	for _, collector := range collectors {
		if err := metrics.registry.Register(collector); err != nil {
			return nil, errRejectedRecord
		}
	}
	metrics.readiness.Set(0)
	return metrics, nil
}

// DatasourceCompleted records one closed provider lifecycle operation.
func (m *Metrics) DatasourceCompleted(
	providerClass string,
	operation string,
	state string,
	result string,
	duration time.Duration,
) {
	defer containMetricPanic()
	if m == nil || !closedMetricValue(keyProvider, providerClass) ||
		!closedMetricValue(keyOperation, operation) ||
		!closedMetricValue(keyProviderState, state) ||
		!closedMetricValue(keyResult, result) || duration < 0 {
		return
	}
	m.datasource.WithLabelValues(providerClass, operation, state, result).Inc()
	m.datasourceTime.WithLabelValues(providerClass, operation, result).Observe(duration.Seconds())
}

// SetReady publishes readiness monotonically until terminal shutdown.
func (m *Metrics) SetReady(ready bool) {
	defer containMetricPanic()
	if m == nil || m.readiness == nil {
		return
	}
	if !ready {
		m.readyTerminal.Store(true)
		m.readiness.Set(0)
		return
	}
	if !m.readyTerminal.Load() {
		m.readiness.Set(1)
	}
}

// HTTPStarted increments one admitted route in-flight gauge.
func (m *Metrics) HTTPStarted(operation string) {
	defer containMetricPanic()
	if m != nil && slices.Contains(httpOperations(), operation) {
		m.httpInFlight.WithLabelValues(operation).Inc()
	}
}

// HTTPCompleted records one bounded route outcome.
func (m *Metrics) HTTPCompleted(operation, statusClass string, duration time.Duration) {
	defer containMetricPanic()
	if m == nil || !slices.Contains(httpOperations(), operation) ||
		!slices.Contains([]string{valueStatus2XX, valueStatus3XX, valueStatus4XX, valueStatus5XX}, statusClass) ||
		duration < 0 {
		return
	}
	m.httpInFlight.WithLabelValues(operation).Dec()
	m.httpRequests.WithLabelValues(operation, statusClass).Inc()
	m.httpDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// ProcessCompleted records one closed inbound outcome.
func (m *Metrics) ProcessCompleted(result, verdict, replayState, disposition string, duration time.Duration) {
	defer containMetricPanic()
	if m == nil || !closedMetricValue(keyResult, result) ||
		!closedMetricValue(keyVerdict, verdict) ||
		!closedMetricValue(keyReplayState, replayState) ||
		!closedMetricValue(keyDisposition, disposition) || duration < 0 {
		return
	}
	m.process.WithLabelValues(result, verdict, replayState, disposition).Inc()
	m.processDuration.WithLabelValues(result).Observe(duration.Seconds())
}

// PolicyCompleted records one closed local policy outcome.
func (m *Metrics) PolicyCompleted(verdict, reason, mode string) {
	defer containMetricPanic()
	if m == nil || !closedMetricValue(keyVerdict, verdict) ||
		!closedMetricValue(keyReasonClass, reason) ||
		!closedMetricValue(keyPolicyMode, mode) {
		return
	}
	m.policy.WithLabelValues(verdict, reason, mode).Inc()
}

// DNSCompleted records one closed DNS lookup outcome.
func (m *Metrics) DNSCompleted(result, cache string, duration time.Duration) {
	defer containMetricPanic()
	if m == nil || !closedMetricValue(keyDNSResult, result) ||
		!closedMetricValue(keyCacheResult, cache) || duration < 0 {
		return
	}
	m.dns.WithLabelValues(result, cache).Inc()
	m.dnsDuration.WithLabelValues(result).Observe(duration.Seconds())
}

// ReplayCompleted records one closed replay coordination outcome.
func (m *Metrics) ReplayCompleted(state, result string, duration time.Duration) {
	defer containMetricPanic()
	if m == nil || !closedMetricValue(keyReplayState, state) ||
		!closedMetricValue(keyResult, result) || duration < 0 {
		return
	}
	m.replay.WithLabelValues(state, result).Inc()
	m.replayDuration.WithLabelValues(state).Observe(duration.Seconds())
}

// ObservationDropped records one bounded signal and drop reason.
func (m *Metrics) ObservationDropped(signal, reason string) {
	defer containMetricPanic()
	if m == nil || !slices.Contains([]string{"log", "trace", "metric"}, signal) ||
		!slices.Contains([]string{valueInvalid, valueOverflow, valuePanic, valueExport}, reason) {
		return
	}
	m.dropped.WithLabelValues(signal, reason).Inc()
}

// Gather returns one deterministic capped Prometheus text representation.
func (m *Metrics) Gather() (outputBytes []byte, resultErr error) {
	defer func() {
		if recover() != nil {
			outputBytes = nil
			resultErr = errRejectedRecord
		}
	}()
	if m == nil || m.registry == nil {
		return nil, errRejectedRecord
	}
	families, err := m.registry.Gather()
	if err != nil {
		return nil, errRejectedRecord
	}
	var output bytes.Buffer
	for _, family := range families {
		if _, err := expfmt.MetricFamilyToText(&output, family); err != nil {
			return nil, errRejectedRecord
		}
		if output.Len() > maxMetricsBytes {
			return nil, errRejectedRecord
		}
	}
	return output.Bytes(), nil
}

// Registry returns the process-local gatherer for descriptor-focused tests.
func (m *Metrics) Registry() prometheus.Gatherer {
	if m == nil {
		return nil
	}
	return m.registry
}

// closedMetricValue applies the exact low-cardinality label vocabulary.
func closedMetricValue(key, value string) bool {
	values := allowedLogValues[key]
	return len(values) > 0 && slices.Contains(values, value)
}

// httpOperations returns one fresh route-operation allowlist.
func httpOperations() []string {
	return []string{
		"health", "readiness", "metrics", valueProcess, valueSign, valueRevise, valueUnmatched,
	}
}

// containMetricPanic prevents collector defects from crossing telemetry boundaries.
func containMetricPanic() {
	_ = recover()
}
