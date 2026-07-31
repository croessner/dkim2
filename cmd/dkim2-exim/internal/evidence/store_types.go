package evidence

import (
	"context"
	"encoding"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
)

const (
	// DefaultMaxRecords is the default live evidence-record count cap.
	DefaultMaxRecords = 100_000
	// DefaultMaxBytes is the default actual live evidence-byte cap.
	DefaultMaxBytes int64 = 536_870_912
	// MinimumMaxRecords is the narrowest supported production count cap.
	MinimumMaxRecords = 1
	// MaximumMaxRecords is the widest supported production count cap.
	MaximumMaxRecords = 1_000_000
	// MinimumMaxBytes is the narrowest supported production byte cap.
	MinimumMaxBytes int64 = 1 << 20
	// MaximumMaxBytes is the widest supported production byte cap.
	MaximumMaxBytes int64 = 1 << 30
)

// Limits declares exact live-record and actual-byte evidence admission caps.
type Limits struct {
	MaxRecords int
	MaxBytes   int64
}

// DefaultLimits returns the durable evidence-store defaults.
func DefaultLimits() Limits {
	return Limits{MaxRecords: DefaultMaxRecords, MaxBytes: DefaultMaxBytes}
}

// Valid reports whether limits are inside the production configuration range.
func (l Limits) Valid() bool {
	return l.MaxRecords >= MinimumMaxRecords &&
		l.MaxRecords <= MaximumMaxRecords &&
		l.MaxBytes >= MinimumMaxBytes &&
		l.MaxBytes <= MaximumMaxBytes
}

// Stats is one content-free exact live evidence-accounting snapshot.
type Stats struct {
	Records int
	Bytes   int64
}

// Valid reports whether a snapshot is structurally possible.
func (s Stats) Valid() bool { return s.Records >= 0 && s.Bytes >= 0 }

// Ready verifies that the store can authorize evidence-dependent work.
func (s *Store) Ready() error { return s.readyError() }

// PublishContext creates one immutable record with caller cancellation.
func (s *Store) PublishContext(ctx context.Context, retention time.Duration, incoming adapter.IncomingEvidence) (Record, error) {
	return s.publishContext(ctx, retention, incoming)
}

// LoadContext reads one immutable record with caller cancellation.
func (s *Store) LoadContext(ctx context.Context, locator string) (Record, error) {
	return s.loadContext(ctx, locator)
}

// CollectContext performs one bounded authenticated expiry sweep.
func (s *Store) CollectContext(ctx context.Context) error {
	return s.collectContext(ctx)
}

// Stats returns exact live count and actual-record-byte accounting.
func (s *Store) Stats() (Stats, error) { return s.storeStats() }

// Publish creates one immutable record using a non-cancelled caller context.
func (s *Store) Publish(retention time.Duration, incoming adapter.IncomingEvidence) (Record, error) {
	return s.PublishContext(context.Background(), retention, incoming)
}

// Load reads one immutable record using a non-cancelled caller context.
func (s *Store) Load(locator string) (Record, error) {
	return s.LoadContext(context.Background(), locator)
}

// Collect performs one bounded authenticated expiry sweep.
func (s *Store) Collect() error { return s.CollectContext(context.Background()) }

// String keeps Store diagnostics content-free.
func (Store) String() string { return "exim_evidence_store{redacted}" }

// GoString keeps Store Go diagnostics content-free.
func (s Store) GoString() string { return s.String() }

// Format prevents formatting from traversing protected store state.
func (s Store) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, s.String())
}

// MarshalJSON rejects serialization of protected store state.
func (Store) MarshalJSON() ([]byte, error) { return nil, ErrEvidence }

// MarshalText rejects textual serialization of protected store state.
func (Store) MarshalText() ([]byte, error) { return nil, ErrEvidence }

var (
	_ fmt.Formatter          = (*Store)(nil)
	_ json.Marshaler         = (*Store)(nil)
	_ encoding.TextMarshaler = (*Store)(nil)
)
