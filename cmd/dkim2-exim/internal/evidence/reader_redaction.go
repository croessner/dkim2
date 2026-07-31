package evidence

import (
	"fmt"
	"io"
)

const readerRedacted = "exim_evidence_reader{redacted}"

// String keeps Reader diagnostics content-free.
func (Reader) String() string { return readerRedacted }

// GoString keeps Reader Go diagnostics content-free.
func (r Reader) GoString() string { return r.String() }

// Format prevents formatting from traversing protected reader state.
func (r Reader) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// MarshalJSON rejects serialization of protected reader state.
func (Reader) MarshalJSON() ([]byte, error) { return nil, ErrEvidence }

// MarshalText rejects textual serialization of protected reader state.
func (Reader) MarshalText() ([]byte, error) { return nil, ErrEvidence }
