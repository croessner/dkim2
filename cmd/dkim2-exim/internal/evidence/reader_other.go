//go:build !linux && !darwin

package evidence

import (
	"context"
	"time"
)

// Reader is unavailable without an audited descriptor policy.
type Reader struct{}

// NewReader fails closed on unsupported evidence-reader platforms.
func NewReader(string, string, string, func() time.Time) (*Reader, error) {
	return nil, ErrNotReady
}

// LoadContext fails closed on unsupported evidence-reader platforms.
func (*Reader) LoadContext(context.Context, string) (Record, error) {
	return Record{}, ErrNotReady
}

// Close is a no-op for an unavailable evidence reader.
func (*Reader) Close() error { return nil }
