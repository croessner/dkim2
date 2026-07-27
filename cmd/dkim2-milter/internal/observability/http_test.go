package observability

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

const testMetricsAuthority = "127.0.0.1:9817"

// TestMetricsHandlerServesOnlyExactLocalScrape proves the success contract.
func TestMetricsHandlerServesOnlyExactLocalScrape(t *testing.T) {
	registry := NewRegistry()
	handler, err := MetricsHandler(testMetricsAuthority, registry)
	if err != nil {
		t.Fatal("valid metrics handler construction failed")
	}
	request := httptest.NewRequest(http.MethodGet, metricsTarget, nil)
	request.Host = testMetricsAuthority
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		response.Header().Get("Content-Type") != MetricsContentType ||
		response.Header().Get("Cache-Control") != "no-store" ||
		!bytes.Contains(response.Body.Bytes(), []byte("dkim2_milter_readiness")) {
		t.Fatal("exact scrape did not produce bounded exposition")
	}
}

// TestMetricsHandlerRejectsHostTargetMethodAndInputMatrix proves strict HTTP admission.
func TestMetricsHandlerRejectsHostTargetMethodAndInputMatrix(t *testing.T) {
	handler, err := MetricsHandler(testMetricsAuthority, NewRegistry())
	if err != nil {
		t.Fatal("valid metrics handler construction failed")
	}
	tests := []struct {
		name       string
		method     string
		target     string
		host       string
		headerName string
		status     int
	}{
		{name: "wrong host", method: http.MethodGet, target: metricsTarget, host: "127.0.0.1:9818", status: http.StatusBadRequest},
		{name: "query", method: http.MethodGet, target: metricsTarget + "?q=x", host: testMetricsAuthority, status: http.StatusBadRequest},
		{name: "head", method: http.MethodHead, target: metricsTarget, host: testMetricsAuthority, status: http.StatusMethodNotAllowed},
		{name: "post", method: http.MethodPost, target: metricsTarget, host: testMetricsAuthority, status: http.StatusMethodNotAllowed},
		{name: "trace", method: http.MethodGet, target: metricsTarget, host: testMetricsAuthority, headerName: "Traceparent", status: http.StatusBadRequest},
		{name: "authorization", method: http.MethodGet, target: metricsTarget, host: testMetricsAuthority, headerName: "Authorization", status: http.StatusBadRequest},
		{name: "conditional", method: http.MethodGet, target: metricsTarget, host: testMetricsAuthority, headerName: "If-None-Match", status: http.StatusBadRequest},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(
				testCase.method,
				testCase.target,
				nil,
			)
			request.Host = testCase.host
			if testCase.headerName != "" {
				request.Header.Set(testCase.headerName, privacyMarker)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != testCase.status ||
				bytes.Contains(response.Body.Bytes(), []byte(privacyMarker)) {
				t.Fatal("invalid scrape was not rejected content-free")
			}
			if testCase.status == http.StatusMethodNotAllowed &&
				response.Header().Get("Allow") != http.MethodGet {
				t.Fatal("method rejection omitted the fixed Allow header")
			}
		})
	}
}

// TestMetricsHandlerRejectsNoncanonicalAuthorities proves loopback-only construction.
func TestMetricsHandlerRejectsNoncanonicalAuthorities(t *testing.T) {
	for _, authority := range []string{
		"", "localhost:9817", "0.0.0.0:9817", "127.0.0.1:09817",
		"127.0.0.1", "[::ffff:127.0.0.1]:9817", "[::1%lo0]:9817",
	} {
		if _, err := MetricsHandler(authority, NewRegistry()); err == nil {
			t.Fatalf("invalid authority %q accepted", authority)
		}
	}
	if _, err := MetricsHandler("[::1]:9817", NewRegistry()); err != nil {
		t.Fatal("canonical IPv6 loopback authority rejected")
	}
}
