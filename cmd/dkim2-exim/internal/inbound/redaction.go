package inbound

import (
	"fmt"
	"io"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
)

const serviceRedacted = "dkim2_exim_inbound{redacted}"

// String keeps service configuration diagnostics content-free.
func (ServiceConfig) String() string { return serviceRedacted }

// GoString keeps service configuration Go diagnostics content-free.
func (c ServiceConfig) GoString() string { return c.String() }

// Format prevents formatting from traversing protected service configuration.
func (c ServiceConfig) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, c.String()) }

// MarshalJSON rejects serialization of protected service configuration.
func (ServiceConfig) MarshalJSON() ([]byte, error) {
	return nil, adapter.NewError(adapter.FailureContract)
}

// MarshalText rejects textual serialization of protected service configuration.
func (ServiceConfig) MarshalText() ([]byte, error) {
	return nil, adapter.NewError(adapter.FailureContract)
}

// String keeps service diagnostics content-free.
func (Service) String() string { return serviceRedacted }

// GoString keeps service Go diagnostics content-free.
func (s Service) GoString() string { return s.String() }

// Format prevents formatting from traversing protected service state.
func (s Service) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, s.String()) }

// MarshalJSON rejects serialization of protected service state.
func (Service) MarshalJSON() ([]byte, error) {
	return nil, adapter.NewError(adapter.FailureContract)
}

// MarshalText rejects textual serialization of protected service state.
func (Service) MarshalText() ([]byte, error) {
	return nil, adapter.NewError(adapter.FailureContract)
}
