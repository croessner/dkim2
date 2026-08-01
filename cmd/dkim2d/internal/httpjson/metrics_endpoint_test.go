package httpjson

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/observability"
)

// TestMetricsEndpointReturnsExactBoundedRepresentation proves specialized success headers.
func TestMetricsEndpointReturnsExactBoundedRepresentation(t *testing.T) {
	handler, _, _, _ := newBoundaryFixture(t)
	request := httptest.NewRequest(http.MethodGet, "http://"+boundaryTestAuthority+metricsPath, nil)
	recorder := httptest.NewRecorder()
	handler.serveMetrics(
		&boundaryWriter{ResponseWriter: recorder},
		request,
		transportFacts{framing: framingAbsent, expect: expectNone},
		false,
	)
	response := recorder.Result()
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK ||
		response.Header.Get(headerContentType) != observability.MetricsContentType ||
		response.Header.Get("Cache-Control") != cacheControlNoStore ||
		response.Header.Get("X-Content-Type-Options") != "nosniff" ||
		!strings.Contains(recorder.Body.String(), "dkim2d_readiness") {
		t.Fatal("metrics success representation changed")
	}
}

// TestMetricsEndpointRejectsEveryInputChannelAndHEAD proves the strict scrape surface.
func TestMetricsEndpointRejectsEveryInputChannelAndHEAD(t *testing.T) {
	handler, _, _, _ := newBoundaryFixture(t)
	tests := []struct {
		method       string
		target       string
		header       string
		tracePresent bool
		want         int
	}{
		{method: http.MethodHead, target: metricsPath, want: http.StatusMethodNotAllowed},
		{method: http.MethodGet, target: metricsPath + "?x=1", want: http.StatusBadRequest},
		{method: http.MethodGet, target: metricsPath, header: headerContentType, want: http.StatusBadRequest},
		{method: http.MethodGet, target: metricsPath, header: "If-None-Match", want: http.StatusBadRequest},
		{method: http.MethodGet, target: metricsPath, header: "X-DKIM2-Capability", want: http.StatusBadRequest},
		{method: http.MethodGet, target: metricsPath, tracePresent: true, want: http.StatusBadRequest},
	}
	for index, test := range tests {
		request := httptest.NewRequest(test.method, "http://"+boundaryTestAuthority+test.target, nil)
		if test.header != "" {
			request.Header.Set(test.header, "private-marker")
		}
		recorder := httptest.NewRecorder()
		handler.serveMetrics(
			&boundaryWriter{ResponseWriter: recorder},
			request,
			transportFacts{framing: framingAbsent, expect: expectNone},
			test.tracePresent,
		)
		if recorder.Code != test.want || strings.Contains(recorder.Body.String(), "private-marker") {
			t.Fatalf("metrics input channel %d was not rejected safely: got %d want %d", index, recorder.Code, test.want)
		}
		if test.method == http.MethodHead && recorder.Header().Get("Allow") != metricsAllowMethod {
			t.Fatal("metrics HEAD response lost exact Allow contract")
		}
	}
}

// TestMetricsEndpointPublicSocketContract proves real transport routing and response shapes.
func TestMetricsEndpointPublicSocketContract(t *testing.T) {
	address, _ := startRawBoundaryServer(t)
	success := rawBoundaryExchange(
		t,
		address,
		"GET /metrics HTTP/1.1\r\nHost: "+address+"\r\n\r\n",
	)
	if !strings.HasPrefix(success, "HTTP/1.1 200 OK\r\n") ||
		rawResponseHeader(success, headerContentType) != observability.MetricsContentType ||
		rawResponseHeader(success, "Cache-Control") != cacheControlNoStore ||
		rawResponseHeader(success, "Connection") != connectionCloseValue ||
		!strings.Contains(rawResponseBody(success), "dkim2d_readiness") {
		t.Fatal("public metrics success shape changed")
	}
	head := rawBoundaryExchange(
		t,
		address,
		"HEAD /metrics HTTP/1.1\r\nHost: "+address+"\r\n\r\n",
	)
	if !strings.HasPrefix(head, "HTTP/1.1 405 Method Not Allowed\r\n") ||
		rawResponseHeader(head, "Allow") != metricsAllowMethod ||
		rawResponseBody(head) != "" {
		t.Fatal("public metrics HEAD shape changed")
	}
	rejected := rawBoundaryExchange(
		t,
		address,
		"GET /metrics HTTP/1.1\r\nHost: "+address+
			"\r\nTraceparent: private-marker\r\n\r\n",
	)
	if !strings.HasPrefix(rejected, "HTTP/1.1 400 Bad Request\r\n") ||
		strings.Contains(rejected, "private-marker") {
		t.Fatal("public metrics trace input was not rejected safely")
	}
}
