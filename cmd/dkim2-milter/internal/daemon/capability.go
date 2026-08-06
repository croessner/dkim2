// Package daemon owns the generated-client transport boundary.
package daemon

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/endpoint"
)

const (
	capabilityHeader    = "X-DKIM2-Capability"
	dsnCapabilityHeader = "X-DKIM2-DSN-Sign-Capability"
)

const redactedCapability = "dkim2_milter_capability{redacted}"

// Capability owns one exact process capability until close.
type Capability struct {
	state *capabilityState
}

// capabilityState keeps the public holder copy-safe while owning one guard.
type capabilityState struct {
	guard *capabilityGuard
}

// capabilityGuard synchronizes and erases the credential and its route binding.
type capabilityGuard struct {
	mu     *sync.Mutex
	value  [32]byte
	closed bool
	target string
	header string
}

// newCapability takes ownership of one nonzero protected value.
func newCapability(value [32]byte) (*Capability, error) {
	var nonzero byte
	for _, current := range value {
		nonzero |= current
	}
	if nonzero == 0 {
		return nil, &Error{}
	}
	return &Capability{state: &capabilityState{
		guard: &capabilityGuard{mu: &sync.Mutex{}, value: value},
	}}, nil
}

// bindRequestTarget confines this capability to one generated operation target.
func (c *Capability) bindRequestTarget(endpoint, route string) error {
	guard := c.guard()
	if guard == nil || !supportedCapabilityRoute(route) {
		return &Error{}
	}
	if !validCapabilityEndpoint(endpoint) {
		return &Error{}
	}
	target := endpoint + route
	header := capabilityHeaderForRoute(route)
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.closed || guard.target != "" &&
		(guard.target != target || guard.header != header) {
		return &Error{}
	}
	guard.target = target
	guard.header = header
	return nil
}

// validCapabilityEndpoint accepts one canonical literal loopback HTTP authority.
func validCapabilityEndpoint(value string) bool {
	return endpoint.IsCanonicalLoopbackHTTPURL(value)
}

// supportedCapabilityRoute recognizes only mode-specific generated operations.
func supportedCapabilityRoute(route string) bool {
	return route == routeProcess || route == routeSign || route == routeRevise ||
		route == routeDeliveryStatus
}

// capabilityHeaderForRoute selects the OpenAPI-declared credential field for
// one already validated operation route.
func capabilityHeaderForRoute(route string) string {
	if route == routeDeliveryStatus {
		return dsnCapabilityHeader
	}
	return capabilityHeader
}

// EditRequest adds the credential only to the exact bound generated request.
func (c *Capability) EditRequest(ctx context.Context, request *http.Request) error {
	guard := c.guard()
	if guard == nil || ctx == nil || ctx.Err() != nil || !validCapabilityRequest(request) {
		return &Error{}
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.closed || guard.target == "" || guard.header == "" ||
		request.URL.String() != guard.target {
		return &Error{}
	}
	request.Header.Set(guard.header, base64.RawURLEncoding.EncodeToString(guard.value[:]))
	return nil
}

// guard returns the private mutable owner without exposing it across packages.
func (c *Capability) guard() *capabilityGuard {
	if c == nil || c.state == nil {
		return nil
	}
	return c.state.guard
}

// validCapabilityRequest proves the generated request shape before credentialing it.
func validCapabilityRequest(request *http.Request) bool {
	if request == nil || request.URL == nil || request.Header == nil ||
		request.Method != http.MethodPost ||
		request.Host != "" && request.Host != request.URL.Host ||
		request.URL.Scheme != daemonScheme || request.URL.Host == "" ||
		request.URL.User != nil || request.URL.RawPath != "" ||
		request.URL.RawQuery != "" || request.URL.ForceQuery ||
		request.URL.Fragment != "" || request.URL.Opaque != "" ||
		request.Body == nil || request.ContentLength <= 0 ||
		len(request.TransferEncoding) != 0 || request.Trailer != nil {
		return false
	}
	for name := range request.Header {
		if strings.EqualFold(name, capabilityHeader) ||
			strings.EqualFold(name, dsnCapabilityHeader) {
			return false
		}
	}
	if len(request.Header) != 4 {
		return false
	}
	return exactHeader(request.Header, "Content-Type", "application/json") &&
		exactHeader(request.Header, "User-Agent", fixedUserAgent) &&
		exactHeader(request.Header, "Accept", "application/json") &&
		exactHeader(request.Header, "Cache-Control", cacheControlNoStore)
}

// exactHeader recognizes one canonical single-valued generated header.
func exactHeader(header http.Header, name, value string) bool {
	values, present := header[http.CanonicalHeaderKey(name)]
	return present && len(values) == 1 && values[0] == value
}

// Close clears the retained capability.
func (c *Capability) Close() error {
	guard := c.guard()
	if guard == nil {
		return nil
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if !guard.closed {
		clear(guard.value[:])
		guard.target = ""
		guard.header = ""
		guard.closed = true
	}
	return nil
}

// String returns a content-free diagnostic.
func (Capability) String() string { return redactedCapability }

// GoString returns a content-free Go diagnostic.
func (Capability) GoString() string { return redactedCapability }

// Format prevents formatting from traversing protected bytes.
func (Capability) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, redactedCapability)
}

// MarshalJSON rejects capability serialization.
func (Capability) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// MarshalText rejects capability text serialization.
func (Capability) MarshalText() ([]byte, error) { return nil, &Error{} }

// String returns a content-free private-state diagnostic.
func (capabilityState) String() string { return redactedCapability }

// GoString returns a content-free private-state Go diagnostic.
func (state capabilityState) GoString() string { return state.String() }

// Format prevents copied private state from traversing into the guard.
func (state capabilityState) Format(output fmt.State, _ rune) {
	_, _ = io.WriteString(output, state.String())
}

// MarshalJSON rejects private-state serialization.
func (capabilityState) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// MarshalText rejects private-state text serialization.
func (capabilityState) MarshalText() ([]byte, error) { return nil, &Error{} }

// String returns a content-free guard diagnostic.
func (capabilityGuard) String() string { return redactedCapability }

// GoString returns a content-free guard Go diagnostic.
func (guard capabilityGuard) GoString() string { return guard.String() }

// Format prevents nested formatting from traversing the mutable credential.
func (guard capabilityGuard) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, guard.String())
}

// MarshalJSON rejects guard serialization.
func (capabilityGuard) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// MarshalText rejects guard text serialization.
func (capabilityGuard) MarshalText() ([]byte, error) { return nil, &Error{} }

// Error is one content-free daemon-boundary failure.
type Error struct{}

// Error returns a stable secret-safe diagnostic.
func (*Error) Error() string { return "dkim2-milter daemon boundary failure" }

// Is recognizes the bounded daemon error.
func (*Error) Is(target error) bool {
	_, ok := target.(*Error)
	return ok
}
