package evidence

import (
	"context"
	"crypto/subtle"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
)

// RecordLoader is the narrow context-aware record read boundary used by filters.
type RecordLoader interface {
	LoadContext(context.Context, string) (Record, error)
}

// RecordStore is the context-aware read/write boundary used by the service.
type RecordStore interface {
	RecordLoader
	PublishContext(context.Context, time.Duration, adapter.IncomingEvidence) (Record, error)
}

// IncomingLoader adapts authenticated records to the filter evidence seam.
type IncomingLoader struct {
	store RecordLoader
}

// NewIncomingLoader binds one context-aware record store.
func NewIncomingLoader(store RecordLoader) (*IncomingLoader, error) {
	if store == nil {
		return nil, ErrEvidence
	}
	return &IncomingLoader{store: store}, nil
}

// Load returns only the immutable incoming authority from one authenticated record.
func (l *IncomingLoader) Load(ctx context.Context, locator string) (adapter.IncomingEvidence, error) {
	if l == nil || l.store == nil || ctx == nil {
		return adapter.IncomingEvidence{}, ErrEvidence
	}
	record, err := l.store.LoadContext(ctx, locator)
	if err != nil || !validLocator(locator) || !validLocator(record.Locator()) ||
		subtle.ConstantTimeCompare(
			[]byte(record.Locator()),
			[]byte(locator),
		) != 1 {
		return adapter.IncomingEvidence{}, ErrEvidence
	}
	incoming := record.Incoming()
	if !validIncoming(incoming) {
		return adapter.IncomingEvidence{}, ErrEvidence
	}
	return incoming, nil
}

// IncomingPublisher adapts accepted receive-time authority to record publication.
type IncomingPublisher struct {
	store     RecordStore
	retention time.Duration
}

// NewIncomingPublisher binds one store and exact authenticated retention.
func NewIncomingPublisher(store RecordStore, retention time.Duration) (*IncomingPublisher, error) {
	if store == nil || retention < MinimumRetention || retention > MaximumRetention ||
		retention%time.Second != 0 {
		return nil, ErrEvidence
	}
	return &IncomingPublisher{store: store, retention: retention}, nil
}

// PublishIncoming persists one immutable record and returns only its opaque locator.
func (p *IncomingPublisher) PublishIncoming(
	ctx context.Context,
	incoming adapter.IncomingEvidence,
) (string, error) {
	if p == nil || p.store == nil || ctx == nil || !validIncoming(incoming) {
		return "", ErrEvidence
	}
	record, err := p.store.PublishContext(ctx, p.retention, incoming)
	if err != nil || !validLocator(record.Locator()) {
		return "", ErrEvidence
	}
	return record.Locator(), nil
}
