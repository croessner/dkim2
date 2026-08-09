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
