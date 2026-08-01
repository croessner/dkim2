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

// TestObservabilityTracingAcceptsCanonicalRemoteHTTPS proves remote collectors use the stable endpoint field.
func TestObservabilityTracingAcceptsCanonicalRemoteHTTPS(t *testing.T) {
	clearStableEnvironment(t)
	caPath := "/secure/" + testGeneration + "/otlp-ca"
	for _, endpoint := range []string{
		"https://metrics.roessner-net.de:4318/v1/traces",
		"https://192.0.2.10:4318/v1/traces",
		"https://[2001:db8::10]:4318/v1/traces",
		"https://127.0.0.1:4318/v1/traces",
		"https://[::1]:4318/v1/traces",
	} {
		document := disabledYAML() + `
observability:
  tracing:
    exporter: otlp_http
    endpoint: ` + endpoint + `
    ca_file: ` + caPath + "\n"
		snapshot, err := Load([]byte(document), FlagValues{})
		if err != nil {
			t.Fatalf("Load() rejected canonical HTTPS endpoint with code %s", CodeOf(err))
		}
		if snapshot.Observability().Tracing().Endpoint() != endpoint {
			t.Fatal("validated remote endpoint changed")
		}
	}
}

// TestObservabilityTracingRejectsForbiddenAuthoritiesAndDisabledLeaves freezes fail-closed grammar.
func TestObservabilityTracingRejectsForbiddenAuthoritiesAndDisabledLeaves(t *testing.T) {
	clearStableEnvironment(t)
	base := disabledYAML()
	for _, endpoint := range []string{
		"http://127.0.0.1:4318/v1/traces",
		"https://Metrics.example:4318/v1/traces",
		"https://metrics.example.:4318/v1/traces",
		"https://-metrics.example:4318/v1/traces",
		"https://metrics..example:4318/v1/traces",
		"https://métrics.example:4318/v1/traces",
		"https://metrics.example/v1/traces",
		"https://127.0.0.1:4318/",
		"https://127.0.0.1:04318/v1/traces",
		"https://127.0.0.1:4318/v1/traces?token=x",
		"https://127.0.0.1:4318/v1/traces?",
		"https://127.0.0.1:4318/v1/traces#",
		"https://user@127.0.0.1:4318/v1/traces",
		"https://[::ffff:127.0.0.1]:4318/v1/traces",
		"https://[fe80::1%25eth0]:4318/v1/traces",
		"https://[::]:4318/v1/traces",
		"https://224.0.0.1:4318/v1/traces",
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
	if _, err := Load([]byte(base+`
observability:
  tracing:
    exporter: otlp_http
    endpoint: https://metrics.example:4318/v1/traces
    server_name: other.example
    ca_file: /secure/`+testGeneration+`/otlp-ca
`), FlagValues{}); CodeOf(err) != CodeInvalidYAML {
		t.Fatalf("tracing server_name returned code %s", CodeOf(err))
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
