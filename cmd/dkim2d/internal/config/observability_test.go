package config

import (
	"strings"
	"testing"
	"time"
)

// TestObservabilityDefaultsAreClosed proves disabled tracing performs no conditional materialization.
func TestObservabilityDefaultsAreClosed(t *testing.T) {
	clearStableEnvironment(t)
	snapshot, err := Load([]byte(disabledYAML()), FlagValues{})
	if err != nil {
		t.Fatalf("Load() failed with code %s", CodeOf(err))
	}
	observation := snapshot.Observability()
	if observation.LogLevel() != LogLevelInfo || observation.DebugDNS() ||
		observation.DebugReplay() || observation.DebugMessageShape() ||
		observation.Tracing().Exporter() != TracingNone ||
		observation.Tracing().Endpoint() != "" ||
		observation.Tracing().CAFile() != "" {
		t.Fatal("disabled observability defaults widened")
	}
}

// TestObservabilityTracingMatrix proves exact loopback TLS and conditional defaults.
func TestObservabilityTracingMatrix(t *testing.T) {
	clearStableEnvironment(t)
	caPath := "/secure/" + testGeneration + "/otlp-ca"
	document := disabledYAML() + `
observability:
  logging:
    level: debug
  debug:
    message_shape: true
    dns: true
    replay: true
  tracing:
    exporter: otlp_http
    endpoint: https://127.0.0.1:4318/v1/traces
    ca_file: ` + caPath + "\n"
	snapshot, err := Load([]byte(document), FlagValues{})
	if err != nil {
		t.Fatalf("Load() failed with code %s", CodeOf(err))
	}
	observation := snapshot.Observability()
	tracing := observation.Tracing()
	if observation.LogLevel() != LogLevelDebug || !observation.DebugMessageShape() ||
		!observation.DebugDNS() || !observation.DebugReplay() ||
		tracing.Exporter() != TracingOTLPHTTP ||
		tracing.Endpoint() != "https://127.0.0.1:4318/v1/traces" ||
		tracing.CAFile() != caPath || tracing.SamplePerMillion() != 10_000 ||
		tracing.ExportTimeout() != 5*time.Second {
		t.Fatal("enabled tracing contract changed")
	}
}

// TestObservabilityTracingRejectsForbiddenAuthoritiesAndDisabledLeaves freezes fail-closed grammar.
func TestObservabilityTracingRejectsForbiddenAuthoritiesAndDisabledLeaves(t *testing.T) {
	clearStableEnvironment(t)
	base := disabledYAML()
	for _, endpoint := range []string{
		"http://127.0.0.1:4318/v1/traces",
		"https://localhost:4318/v1/traces",
		"https://127.0.0.1:4318/",
		"https://127.0.0.1:04318/v1/traces",
		"https://127.0.0.1:4318/v1/traces?token=x",
		"https://user@127.0.0.1:4318/v1/traces",
		"https://[::ffff:127.0.0.1]:4318/v1/traces",
	} {
		document := base + `
observability:
  tracing:
    exporter: otlp_http
    endpoint: ` + endpoint + `
    ca_file: /secure/` + testGeneration + "/otlp-ca\n"
		if _, err := Load([]byte(document), FlagValues{}); CodeOf(err) != CodeInvalidField {
			t.Fatal("invalid OTLP authority was accepted")
		}
	}
	if _, err := Load([]byte(base+`
observability:
  tracing:
    exporter: none
    endpoint: https://127.0.0.1:4318/v1/traces
`), FlagValues{}); CodeOf(err) != CodeInvalidField {
		t.Fatal("disabled tracing accepted an explicit conditional leaf")
	}
}

// TestObservabilityTracingBoundsRejectAdjacentValues proves exact sampling and timeout ranges.
func TestObservabilityTracingBoundsRejectAdjacentValues(t *testing.T) {
	clearStableEnvironment(t)
	template := disabledYAML() + `
observability:
  tracing:
    exporter: otlp_http
    endpoint: https://[::1]:4318/v1/traces
    ca_file: /secure/` + testGeneration + `/otlp-ca
    sample_per_million: SAMPLE
    export_timeout: TIMEOUT
`
	for _, replacement := range []struct {
		sample  string
		timeout string
	}{
		{"0", "5s"}, {"1000001", "5s"}, {"10000", duration99ms}, {"10000", "10001ms"},
	} {
		document := strings.ReplaceAll(template, "SAMPLE", replacement.sample)
		document = strings.ReplaceAll(document, "TIMEOUT", replacement.timeout)
		if _, err := Load([]byte(document), FlagValues{}); CodeOf(err) != CodeInvalidField {
			t.Fatal("adjacent tracing bound was accepted")
		}
	}
}
