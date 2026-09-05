// Package daemon owns the generated-client transport boundary of the adapter.
//
// The package holds exactly one protected propagation capability, confines it
// to the two propagation operations of one literal loopback origin, and
// validates every response before the adapter may act on it.
package daemon

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/endpoint"
)

const (
	propagateCapabilityHeader = "X-DKIM2-DSN-Propagate-Capability"
	capabilityHeader          = "X-DKIM2-Capability"
	dsnSignCapabilityHeader   = "X-DKIM2-DSN-Sign-Capability"
	routePropagate            = "/v1/dsn/propagate"
	routeCommit               = "/v1/dsn/propagate/commit"
	redactedCapability        = "dkim2_dsn_propagator_capability{redacted}"
)

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
	mu      *sync.Mutex
	value   [32]byte
	closed  bool
	targets map[string]struct{}
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

// bindRequestTargets confines this capability to the two propagation operations
// of exactly one literal loopback origin.
func (c *Capability) bindRequestTargets(origin string) error {
	guard := c.guard()
	if guard == nil || !endpoint.IsCanonicalLoopbackHTTPURL(origin) {
		return &Error{}
	}
	targets := map[string]struct{}{
		origin + routePropagate: {},
		origin + routeCommit:    {},
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.closed || guard.targets != nil && !sameTargets(guard.targets, targets) {
		return &Error{}
	}
	guard.targets = targets
	return nil
}

// sameTargets compares two already bounded target sets for exact equality.
func sameTargets(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for target := range left {
		if _, present := right[target]; !present {
			return false
		}
	}
	return true
}

// EditRequest adds the credential only to an exact bound generated request.
func (c *Capability) EditRequest(ctx context.Context, request *http.Request) error {
	guard := c.guard()
	if guard == nil || ctx == nil || ctx.Err() != nil || !validCapabilityRequest(request) {
		return &Error{}
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.closed || len(guard.targets) == 0 {
		return &Error{}
	}
	if _, bound := guard.targets[request.URL.String()]; !bound {
		return &Error{}
	}
	request.Header.Set(
		propagateCapabilityHeader,
		base64.RawURLEncoding.EncodeToString(guard.value[:]),
	)
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
		if strings.EqualFold(name, propagateCapabilityHeader) ||
			strings.EqualFold(name, capabilityHeader) ||
			strings.EqualFold(name, dsnSignCapabilityHeader) {
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
		guard.targets = nil
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
func (*Error) Error() string { return "dkim2-dsn-propagator daemon boundary failure" }

// Is recognizes the bounded daemon error.
func (*Error) Is(target error) bool {
	_, ok := target.(*Error)
	return ok
}
