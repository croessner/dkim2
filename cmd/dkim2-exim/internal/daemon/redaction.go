package daemon

import (
	"fmt"
	"io"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
)

const processorRedacted = "dkim2_exim_processor{redacted}"

// String keeps inbound processor diagnostics content-free.
func (Processor) String() string { return processorRedacted }

// GoString keeps inbound processor Go diagnostics content-free.
func (p Processor) GoString() string { return p.String() }

// Format prevents formatting from traversing inbound processor authority.
func (p Processor) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, p.String()) }

// MarshalJSON rejects serialization of inbound processor authority.
func (Processor) MarshalJSON() ([]byte, error) {
	return nil, adapter.NewError(adapter.FailureContract)
}

// MarshalText rejects textual serialization of inbound processor authority.
func (Processor) MarshalText() ([]byte, error) {
	return nil, adapter.NewError(adapter.FailureContract)
}

// String keeps filter processor diagnostics content-free.
func (FilterProcessor) String() string { return processorRedacted }

// GoString keeps filter processor Go diagnostics content-free.
func (p FilterProcessor) GoString() string { return p.String() }

// Format prevents formatting from traversing filter processor authority.
func (p FilterProcessor) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, p.String()) }

// MarshalJSON rejects serialization of filter processor authority.
func (FilterProcessor) MarshalJSON() ([]byte, error) {
	return nil, adapter.NewError(adapter.FailureContract)
}

// MarshalText rejects textual serialization of filter processor authority.
func (FilterProcessor) MarshalText() ([]byte, error) {
	return nil, adapter.NewError(adapter.FailureContract)
}
