package ldap

import (
	"context"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	datasourceruntime "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/runtime"
	"github.com/croessner/dkim2/provider"
)

type staticRegistry uint64

// Load returns one synthetic exact protected generation.
func (g staticRegistry) Load(
	context.Context,
	uint64,
) (datasourceruntime.Registry, error) {
	return g, nil
}

// Generation returns the injected protected registry generation.
func (g staticRegistry) Generation(context.Context) (uint64, error) {
	return uint64(g), nil
}

// Bindings returns no signing bindings for mapper-only loader tests.
func (staticRegistry) Bindings() []provider.Binding { return nil }

// Close completes the synthetic registry lifecycle.
func (staticRegistry) Close(context.Context) error { return nil }

// SignDigest is unreachable in mapper-only loader tests.
func (staticRegistry) SignDigest(
	context.Context,
	dkim2.PrivateKeyHandle,
	dkim2.PrivateKeySignRequest,
) (dkim2.PrivateKeySignResult, error) {
	return dkim2.PrivateKeySignResult{}, dkim2.NewTemporaryProviderError()
}

type fakeConnector struct {
	client *fakeClient
}

// Connect returns one synthetic authenticated client.
func (c fakeConnector) Connect(context.Context) (Client, error) { return c.client, nil }

type fakeClient struct {
	records   DatasetRecords
	pages     map[RecordClass][]Page
	positions map[RecordClass]int
	abandoned int
	discarded bool
}

// ReadCurrent returns detached current metadata.
func (c *fakeClient) ReadCurrent(context.Context) (Entry, error) {
	return cloneEntry(c.records.Current), nil
}

// ReadGenerationRoot returns detached generation-root metadata.
func (c *fakeClient) ReadGenerationRoot(context.Context, uint64) (Entry, error) {
	return cloneEntry(c.records.Root), nil
}

// SearchPage returns the next injected page without interpreting the cookie.
func (c *fakeClient) SearchPage(
	_ context.Context,
	class RecordClass,
	_ uint64,
	_ []byte,
	_ int,
	_ int,
) (Page, error) {
	position := c.positions[class]
	c.positions[class] = position + 1
	return c.pages[class][position], nil
}

// Abandon records one bounded paging abandonment.
func (c *fakeClient) Abandon(context.Context, RecordClass, uint64, []byte) error {
	c.abandoned++
	return nil
}

// Discard records that the connection may not return to a pool.
func (c *fakeClient) Discard() { c.discarded = true }

// Close completes the synthetic connection lifecycle.
func (c *fakeClient) Close() error { return nil }

// TestLoaderAcceptsRepeatedAndEmptyOpaquePages proves cookies are opaque and
// only an empty response cookie completes paging.
func TestLoaderAcceptsRepeatedAndEmptyOpaquePages(t *testing.T) {
	t.Parallel()
	records := minimalRecords(t)
	pages := map[RecordClass][]Page{
		RecordClassHandle: {
			{Cookie: []byte("opaque"), Bytes: 1},
			{Cookie: []byte("opaque"), Bytes: 1},
			{Entries: records.Handles, Bytes: 64},
		},
		RecordClassProfile:    {{Entries: records.Profiles, Bytes: 64}},
		RecordClassCredential: {{Entries: records.Credentials, Bytes: 256}},
		RecordClassPolicy:     {{Entries: records.Policies, Bytes: 128}},
	}
	client := &fakeClient{records: records, pages: pages, positions: make(map[RecordClass]int)}
	loader, err := NewLoader(
		fakeConnector{client: client}, staticRegistry(1), provider.DefaultLimits(),
		1, 1<<20, 2*time.Second,
	)
	if err != nil {
		t.Fatal("construct loader")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	candidate, err := loader.Load(ctx)
	if err != nil || !candidate.Valid() {
		t.Fatal("load complete opaque paging sequence")
	}
}

// TestLoaderRejectsOversizedCookieWithoutEcho proves unaccepted control data
// is discarded rather than sent in abandonment.
func TestLoaderRejectsOversizedCookieWithoutEcho(t *testing.T) {
	t.Parallel()
	records := minimalRecords(t)
	client := &fakeClient{
		records: records,
		pages: map[RecordClass][]Page{
			RecordClassHandle: {{Cookie: make([]byte, 4097), Bytes: 1}},
		},
		positions: make(map[RecordClass]int),
	}
	loader, err := NewLoader(
		fakeConnector{client: client}, staticRegistry(1), provider.DefaultLimits(),
		1, 1<<20, 2*time.Second,
	)
	if err != nil {
		t.Fatal("construct loader")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := loader.Load(ctx); provider.ErrorCodeOf(err) != provider.ErrorCodeLimitExceeded {
		t.Fatal("oversized cookie must hit a local limit")
	}
	if client.abandoned != 0 || !client.discarded {
		t.Fatal("unaccepted cookie must never be echoed")
	}
}
