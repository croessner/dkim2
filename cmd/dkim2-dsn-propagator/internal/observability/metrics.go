package observability

import (
	"bytes"
	"slices"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

const (
	// MetricsContentType is the exact successful Prometheus exposition type.
	MetricsContentType = "text/plain; version=0.0.4; charset=utf-8"
	maxMetricsBytes    = 256 << 10

	metricTransactions = "dsn_propagator_transactions_total"
	metricReinjections = "dsn_propagator_reinjection_total"
	metricCommits      = "dsn_propagator_commit_total"
	metricLifecycle    = "dsn_propagator_lifecycle_total"
	metricReadiness    = "dsn_propagator_readiness"
)

// Registry owns one fresh Prometheus registry and the exact adapter inventory.
//
// The inventory is limited to the closed outcome sets of the propagation
// contract plus process lifecycle, so no label can ever carry a domain,
// address, tenant, host, queue identifier, or raw error.
type Registry struct {
	registry *prometheus.Registry

	readiness    prometheus.Gauge
	lifecycle    *prometheus.CounterVec
	transactions *prometheus.CounterVec
	reinjections *prometheus.CounterVec
	commits      *prometheus.CounterVec

	invalid atomic.Bool
}

// NewRegistry constructs one exact inventory without global collectors.
func NewRegistry() *Registry {
	registry := prometheus.NewRegistry()
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
		transactions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricTransactions,
			Help: "Completed propagation transactions by closed outcome.",
		}, []string{keyTransactionOutcome}),
		reinjections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricReinjections,
			Help: "Re-injection attempts by closed outcome.",
		}, []string{keyTransactionOutcome}),
		commits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricCommits,
			Help: "Propagation commit attempts by closed outcome.",
		}, []string{keyTransactionOutcome}),
	}
	collectors := []prometheus.Collector{
		result.readiness, result.lifecycle, result.transactions,
		result.reinjections, result.commits,
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

// RecordTransaction records one closed propagation transaction outcome.
func (r *Registry) RecordTransaction(outcome string) {
	defer containMetricPanic()
	if r.usable() && closedMetricValue(keyTransactionOutcome, outcome) {
		r.transactions.WithLabelValues(outcome).Inc()
	}
}

// RecordReinjection records one closed re-injection outcome.
func (r *Registry) RecordReinjection(outcome string) {
	defer containMetricPanic()
	if r.usable() && closedMetricValue(keyReinjectionOutcome, outcome) {
		r.reinjections.WithLabelValues(outcome).Inc()
	}
}

// RecordCommit records one closed commit outcome.
func (r *Registry) RecordCommit(outcome string) {
	defer containMetricPanic()
	if r.usable() && closedMetricValue(keyCommitOutcome, outcome) {
		r.commits.WithLabelValues(outcome).Inc()
	}
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
		r.readiness != nil && r.lifecycle != nil && r.transactions != nil &&
		r.reinjections != nil && r.commits != nil
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
