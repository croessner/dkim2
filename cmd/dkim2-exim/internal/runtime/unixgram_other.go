//go:build !linux

package runtime

import (
	"fmt"
	"io"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/securefile"
)

// unixgramSink is an unavailable protected sink outside Linux.
type unixgramSink struct{}

// String prevents destination disclosure on unsupported platforms.
func (unixgramSink) String() string { return "runtime.unixgramSink{redacted}" }

// GoString prevents destination disclosure on unsupported platforms.
func (s unixgramSink) GoString() string { return s.String() }

// Format prevents formatter traversal on unsupported platforms.
func (s unixgramSink) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, s.String())
}

// MarshalJSON rejects serialization on unsupported platforms.
func (unixgramSink) MarshalJSON() ([]byte, error) { return nil, errRuntime }

// openUnixgramSink fails closed outside Linux.
func openUnixgramSink(string) (*unixgramSink, securefile.Identity, error) {
	return nil, securefile.Identity{}, errRuntime
}

// Write fails closed outside Linux.
func (*unixgramSink) Write([]byte) error { return errRuntime }

// Close has no unsupported-platform resource to release.
func (*unixgramSink) Close() error { return nil }
