package ldap

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/croessner/dkim2/provider"
)

type fakeConnector struct {
	client *fakeClient
}

// Connect returns one synthetic authenticated client.
func (c fakeConnector) Connect(context.Context) (Client, error) { return c.client, nil }

type fakeClient struct {
	records     DatasetRecords
	pages       map[RecordClass][]Page
	positions   map[RecordClass]int
	abandoned   int
	discarded   bool
	generations []uint64
}

// ReadCurrent returns detached current metadata.
func (c *fakeClient) ReadCurrent(context.Context) (Entry, error) {
	return cloneEntry(c.records.Current), nil
}

// ReadGenerationRoot returns detached generation-root metadata.
func (c *fakeClient) ReadGenerationRoot(context.Context, uint64) (Entry, error) {
	return cloneEntry(c.records.Root), nil
}

// SearchPage records the requested generation and returns the next injected
// page without interpreting the cookie.
func (c *fakeClient) SearchPage(
	_ context.Context,
	class RecordClass,
	generation uint64,
	_ []byte,
	_ int,
	_ int,
) (Page, error) {
	c.generations = append(c.generations, generation)
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
		RecordClassProfile:     {{Entries: records.Profiles, Bytes: 64}},
		RecordClassCredential:  {{Entries: records.Credentials, Bytes: 256}},
		RecordClassPolicy:      {{Entries: records.Policies, Bytes: 128}},
		RecordClassKeyMaterial: {{Entries: records.KeyMaterial, Bytes: 256}},
	}
	client := &fakeClient{records: records, pages: pages, positions: make(map[RecordClass]int)}
	loader, err := NewLoader(
		fakeConnector{client: client}, provider.DefaultLimits(),
		1, 1<<20, 2*time.Second,
	)
	if err != nil {
		t.Fatal("construct loader")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	privateValue := records.KeyMaterial[0].Attributes[attrPrivatePKCS8][0]
	privateCopy := bytes.Clone(privateValue)
	candidate, err := loader.Load(ctx)
	if err != nil || !candidate.Valid() {
		t.Fatal("load complete opaque paging sequence")
	}
	if bytes.Equal(privateValue, privateCopy) {
		t.Fatal("LDAP loader retained a private page buffer")
	}
	for _, value := range privateValue {
		if value != 0 {
			t.Fatal("LDAP loader did not clear a private page buffer")
		}
	}
	if err := candidate.Registry.Close(context.Background()); err != nil {
		t.Fatalf("Registry.Close() error = %v", err)
	}
	clear(privateCopy)
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
		fakeConnector{client: client}, provider.DefaultLimits(),
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

// TestLoaderRejectsMissingNativeKeyMaterial proves a public-only generation
// never becomes a valid network signing candidate.
func TestLoaderRejectsMissingNativeKeyMaterial(t *testing.T) {
	records := minimalRecords(t)
	pages := map[RecordClass][]Page{
		RecordClassHandle:      {{Entries: records.Handles, Bytes: 64}},
		RecordClassProfile:     {{Entries: records.Profiles, Bytes: 64}},
		RecordClassCredential:  {{Entries: records.Credentials, Bytes: 256}},
		RecordClassPolicy:      {{Entries: records.Policies, Bytes: 128}},
		RecordClassKeyMaterial: {{}},
	}
	client := &fakeClient{records: records, pages: pages, positions: make(map[RecordClass]int)}
	loader, err := NewLoader(
		fakeConnector{client: client}, provider.DefaultLimits(),
		2, 1<<20, 2*time.Second,
	)
	if err != nil {
		t.Fatal("construct loader")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := loader.Load(ctx); provider.ErrorCodeOf(err) != provider.ErrorCodeMalformedData {
		t.Fatal("LDAP loader accepted missing native key material")
	}
}

// TestRuntimeMetadataProjectionIncludesCampaignSource freezes the immutable
// source-generation input required to recompute a v3 campaign digest.
func TestRuntimeMetadataProjectionIncludesCampaignSource(t *testing.T) {
	t.Parallel()
	projection := metadataProjection()
	seen := 0
	for _, attribute := range projection {
		if attribute == attrSourceGeneration {
			seen++
		}
	}
	if seen != 1 {
		t.Fatal("runtime metadata projection lost the campaign source fence")
	}
}

// compositeLoaderPages serves minimal records as single pages.
func compositeLoaderPages(records DatasetRecords) map[RecordClass][]Page {
	return map[RecordClass][]Page{
		RecordClassHandle:      {{Entries: records.Handles, Bytes: 64}},
		RecordClassProfile:     {{Entries: records.Profiles, Bytes: 64}},
		RecordClassCredential:  {{Entries: records.Credentials, Bytes: 256}},
		RecordClassPolicy:      {{Entries: records.Policies, Bytes: 128}},
		RecordClassKeyMaterial: {{Entries: records.KeyMaterial, Bytes: 256}},
	}
}

// TestLoaderReadsOnlyTheCurrentGeneration proves the runtime signing loader
// searches every record class strictly within the current generation, so
// retired generations (which may still hold credentials of the removed
// mldsa44-ed25519-sha512 algorithm) are never parsed for signing.
func TestLoaderReadsOnlyTheCurrentGeneration(t *testing.T) {
	t.Parallel()
	records := minimalRecords(t)
	client := &fakeClient{records: records, pages: compositeLoaderPages(records), positions: make(map[RecordClass]int)}
	loader, err := NewLoader(fakeConnector{client: client}, provider.DefaultLimits(), 1, 1<<20, 2*time.Second)
	if err != nil {
		t.Fatal("construct loader")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	candidate, err := loader.Load(ctx)
	if err != nil || !candidate.Valid() {
		t.Fatal("load current generation")
	}
	defer candidate.Registry.Close(context.Background()) //nolint:errcheck // Test cleanup has no recovery.
	if len(client.generations) != 5 {
		t.Fatalf("searched %d record classes, want 5", len(client.generations))
	}
	for _, generation := range client.generations {
		if generation != 1 {
			t.Fatalf("loader searched generation %d, want only current generation 1", generation)
		}
	}
}

// TestLoaderRejectsCompositeCredentialInCurrentGeneration proves a current
// generation that still declares the removed mldsa44-ed25519-sha512
// algorithm fails closed as malformed data instead of loading partially.
func TestLoaderRejectsCompositeCredentialInCurrentGeneration(t *testing.T) {
	t.Parallel()
	records := minimalRecords(t)
	records.Credentials[0].Attributes[attrAlgorithm] = [][]byte{[]byte("mldsa44-ed25519-sha512")}
	client := &fakeClient{records: records, pages: compositeLoaderPages(records), positions: make(map[RecordClass]int)}
	loader, err := NewLoader(fakeConnector{client: client}, provider.DefaultLimits(), 1, 1<<20, 2*time.Second)
	if err != nil {
		t.Fatal("construct loader")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := loader.Load(ctx); provider.ErrorCodeOf(err) != provider.ErrorCodeMalformedData {
		t.Fatalf("Load() error = %v, want malformed data", err)
	}
}
