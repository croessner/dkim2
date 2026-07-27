package observability

import (
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// MetricsHandler returns a strict loopback-authority metrics handler.
func MetricsHandler(authority string, registry *Registry) (http.Handler, error) {
	if !validLoopbackAuthority(authority) || registry == nil {
		return nil, errConfiguration
	}
	return &metricsHandler{authority: authority, registry: registry}, nil
}

// metricsHandler serves only the exact local scrape contract.
type metricsHandler struct {
	authority string
	registry  *Registry
}

// ServeHTTP enforces exact method, target, authority, and body rules.
func (h *metricsHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	defer func() {
		if recover() != nil {
			func() {
				defer func() { _ = recover() }()
				writeBoundedHTTPError(writer, http.StatusInternalServerError)
			}()
		}
	}()
	if h == nil || h.registry == nil || request == nil ||
		request.Proto != "HTTP/1.1" || request.Host != h.authority ||
		request.RequestURI != metricsTarget || request.URL == nil ||
		request.URL.Path != metricsTarget || request.URL.RawQuery != "" ||
		request.URL.Fragment != "" || request.ContentLength > 0 ||
		(request.Body != nil && request.Body != http.NoBody) ||
		len(request.TransferEncoding) != 0 || forbiddenScrapeHeaders(request.Header) {
		writeBoundedHTTPError(writer, http.StatusBadRequest)
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writeBoundedHTTPError(writer, http.StatusMethodNotAllowed)
		return
	}
	output, err := h.registry.Gather()
	if err != nil {
		writeBoundedHTTPError(writer, http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", MetricsContentType)
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(output)
}

// forbiddenScrapeHeaders rejects stateful, conditional, privileged, and trace input.
func forbiddenScrapeHeaders(header http.Header) bool {
	for _, name := range []string{
		"Authorization", "Baggage", "Content-Type", "Cookie", "If-Match",
		"If-Modified-Since", "If-None-Match", "If-Range", "If-Unmodified-Since",
		"Host", "Proxy-Authorization", "Range", "Traceparent", "Tracestate",
	} {
		if len(header.Values(name)) != 0 {
			return true
		}
	}
	return false
}

// writeBoundedHTTPError emits one content-free fixed response.
func writeBoundedHTTPError(writer http.ResponseWriter, status int) {
	if writer == nil {
		return
	}
	body := "request rejected\n"
	if status == http.StatusInternalServerError {
		body = "metrics unavailable\n"
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, body)
}

// validLoopbackAuthority accepts only canonical unmapped loopback literals.
func validLoopbackAuthority(value string) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil || net.JoinHostPort(host, port) != value {
		return false
	}
	address, addrErr := netip.ParseAddr(host)
	number, portErr := strconv.Atoi(port)
	return addrErr == nil && portErr == nil && address.IsLoopback() &&
		address.Zone() == "" && !address.Is4In6() && number > 0 &&
		number <= 65535 && strconv.Itoa(number) == port &&
		!strings.ContainsAny(value, "\r\n\t ")
}
