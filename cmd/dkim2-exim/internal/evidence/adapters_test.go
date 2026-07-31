package evidence

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
)

// contextMarkerKey prevents evidence-adapter test context collisions.
type contextMarkerKey struct{}

// recordStoreStub supplies context-aware evidence records without filesystem access.
type recordStoreStub struct {
	record      Record
	loadContext context.Context
	loadLocator string
	published   adapter.IncomingEvidence
}

// LoadContext returns the immutable test record.
func (s *recordStoreStub) LoadContext(ctx context.Context, locator string) (Record, error) {
	s.loadContext = ctx
	s.loadLocator = locator
	return s.record, nil
}

// PublishContext captures incoming authority and returns the immutable test record.
func (s *recordStoreStub) PublishContext(_ context.Context, _ time.Duration, incoming adapter.IncomingEvidence) (Record, error) {
	s.published = incoming
	return s.record, nil
}

// TestIncomingAdaptersProjectOnlyRecordAuthority proves filter and inbound
// seams exchange the immutable incoming envelope and opaque locator only.
func TestIncomingAdaptersProjectOnlyRecordAuthority(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	incoming, err := adapter.NewIncomingEvidence(
		[]byte(testIncomingSender),
		[][]byte{[]byte("<received@example.test>")},
		adapter.SessionSMTP,
	)
	if err != nil {
		t.Fatal("incoming fixture construction failed")
	}
	record, err := NewRecord(
		now,
		MinimumRetention,
		incoming,
		bytes.NewReader(bytes.Repeat([]byte{0x42}, LocatorBytes)),
	)
	if err != nil {
		t.Fatal("record fixture construction failed")
	}
	store := &recordStoreStub{record: record}
	loader, err := NewIncomingLoader(store)
	if err != nil {
		t.Fatal("incoming loader construction failed")
	}
	ctx := context.WithValue(
		context.Background(),
		contextMarkerKey{},
		"context-marker",
	)
	loaded, err := loader.Load(ctx, record.Locator())
	if err != nil || store.loadContext != ctx || store.loadLocator != record.Locator() ||
		string(loaded.MailFrom()) != testIncomingSender {
		t.Fatal("incoming loader changed context, locator, or record authority")
	}
	publisher, err := NewIncomingPublisher(store, MinimumRetention)
	if err != nil {
		t.Fatal("incoming publisher construction failed")
	}
	locator, err := publisher.PublishIncoming(ctx, incoming)
	if err != nil || locator != record.Locator() ||
		string(store.published.MailFrom()) != testIncomingSender {
		t.Fatal("incoming publisher changed record authority or locator")
	}
	if _, err = loader.Load(ctx, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); err == nil {
		t.Fatal("incoming loader accepted a record for a different locator")
	}
}
