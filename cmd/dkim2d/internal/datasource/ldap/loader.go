package ldap

import (
	"context"
	"fmt"
	"io"
	"time"

	datasourceruntime "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/runtime"
	"github.com/croessner/dkim2/provider"
)

const loaderRedacted = "ldap_loader{redacted}"

// Page is one bounded LDAP simple-paged-results response.
type Page struct {
	Entries []Entry
	Cookie  []byte
	Bytes   int
}

// Client is the owned authenticated connection seam for one exact endpoint.
type Client interface {
	ReadCurrent(context.Context) (Entry, error)
	ReadGenerationRoot(context.Context, uint64) (Entry, error)
	SearchPage(context.Context, RecordClass, uint64, []byte, int, int) (Page, error)
	Abandon(context.Context, RecordClass, uint64, []byte) error
	Discard()
	Close() error
}

// Connector establishes one authenticated verified-TLS LDAP connection.
type Connector interface {
	Connect(context.Context) (Client, error)
}

// Loader reads one fenced LDAP generation into an immutable local snapshot.
type Loader struct {
	connector   Connector
	registry    datasourceruntime.RegistrySource
	limits      provider.Limits
	pageSize    int
	maxBytes    int
	maxDeadline time.Duration
}

// NewLoader validates one bounded LDAP loader configuration.
func NewLoader(
	connector Connector,
	registry datasourceruntime.RegistrySource,
	limits provider.Limits,
	pageSize int,
	maxBytes int,
	maxDeadline time.Duration,
) (*Loader, error) {
	if connector == nil || registry == nil || limits.Validate() != nil ||
		pageSize <= 0 || pageSize > 256 ||
		maxBytes <= 0 || maxBytes > 32<<20 ||
		maxDeadline <= 0 || maxDeadline > 30*time.Second {
		return nil, provider.NewError(provider.ErrorCodeInvalidRequest)
	}
	return &Loader{
		connector: connector, registry: registry, limits: limits,
		pageSize: pageSize, maxBytes: maxBytes, maxDeadline: maxDeadline,
	}, nil
}

// Load reads, fences, validates, and joins one complete LDAP generation.
func (l *Loader) Load(ctx context.Context) (candidate datasourceruntime.Candidate, resultErr error) {
	defer func() {
		if recover() != nil {
			candidate = datasourceruntime.Candidate{}
			resultErr = provider.NewError(provider.ErrorCodeInternalInvariant)
		}
	}()
	if l == nil {
		return datasourceruntime.Candidate{}, provider.NewError(provider.ErrorCodeInvalidRequest)
	}
	if err := validateLoadContext(ctx, l.maxDeadline); err != nil {
		return datasourceruntime.Candidate{}, err
	}
	client, err := l.connector.Connect(ctx)
	if err != nil || client == nil {
		return datasourceruntime.Candidate{}, classifyBoundary(ctx)
	}
	defer func() {
		if closeErr := client.Close(); resultErr == nil && closeErr != nil {
			candidate = datasourceruntime.Candidate{}
			resultErr = provider.NewError(provider.ErrorCodeUnavailable)
		}
	}()
	current, err := client.ReadCurrent(ctx)
	if err != nil {
		return datasourceruntime.Candidate{}, classifyBoundary(ctx)
	}
	generation, err := mapMetadata(current)
	if err != nil {
		return datasourceruntime.Candidate{}, err
	}
	root, err := client.ReadGenerationRoot(ctx, generation)
	if err != nil {
		return datasourceruntime.Candidate{}, classifyBoundary(ctx)
	}
	records := DatasetRecords{Current: current, Root: root}
	aggregateBytes := entryBytes(current) + entryBytes(root)
	classes := []struct {
		class       RecordClass
		maximum     int
		destination *[]Entry
	}{
		{RecordClassHandle, l.limits.MaxHandles, &records.Handles},
		{RecordClassProfile, l.limits.MaxProfiles, &records.Profiles},
		{RecordClassCredential, l.limits.MaxProfiles * l.limits.MaxCredentialsPerProfile, &records.Credentials},
		{RecordClassPolicy, l.limits.MaxPolicies, &records.Policies},
	}
	for _, item := range classes {
		entries, bytesRead, loadErr := l.loadClass(
			ctx, client, item.class, generation, item.maximum,
		)
		if loadErr != nil {
			return datasourceruntime.Candidate{}, loadErr
		}
		if aggregateBytes > l.maxBytes-bytesRead {
			return datasourceruntime.Candidate{}, provider.NewError(provider.ErrorCodeLimitExceeded)
		}
		aggregateBytes += bytesRead
		*item.destination = entries
	}
	finalCurrent, err := client.ReadCurrent(ctx)
	if err != nil {
		return datasourceruntime.Candidate{}, classifyBoundary(ctx)
	}
	finalGeneration, err := mapMetadata(finalCurrent)
	if err != nil || finalGeneration != generation {
		return datasourceruntime.Candidate{}, provider.NewError(provider.ErrorCodeUnavailable)
	}
	dataset, err := MapDataset(records, l.limits)
	if err != nil {
		return datasourceruntime.Candidate{}, err
	}
	registry, err := l.registry.Load(ctx, generation)
	if err != nil {
		return datasourceruntime.Candidate{}, classifyBoundary(ctx)
	}
	closeRegistry := true
	defer func() {
		if closeRegistry {
			_ = registry.Close(context.Background())
		}
	}()
	registryGeneration, err := registry.Generation(ctx)
	if err != nil {
		return datasourceruntime.Candidate{}, classifyBoundary(ctx)
	}
	if registryGeneration != generation {
		return datasourceruntime.Candidate{}, provider.NewError(provider.ErrorCodeMalformedData)
	}
	closeRegistry = false
	return datasourceruntime.Candidate{
		Dataset: dataset, RegistryGeneration: registryGeneration,
		Bindings: registry.Bindings(), Registry: registry,
	}, nil
}

// loadClass follows the bounded opaque RFC 2696 cookie contract.
func (l *Loader) loadClass(
	ctx context.Context,
	client Client,
	class RecordClass,
	generation uint64,
	maximum int,
) ([]Entry, int, error) {
	cookie := []byte(nil)
	acceptedCookie := false
	entries := make([]Entry, 0, min(l.pageSize, maximum))
	bytesRead := 0
	pageSize := min(l.pageSize, maximum)
	for responses := 0; responses <= maximum; responses++ {
		page, err := client.SearchPage(
			ctx, class, generation, cookie, pageSize, maximum+1,
		)
		if err != nil {
			l.cleanupPaging(ctx, client, class, generation, cookie, acceptedCookie)
			return nil, 0, classifyBoundary(ctx)
		}
		if page.Bytes < 0 || page.Bytes > 4<<20 ||
			len(page.Cookie) > 4096 || len(page.Entries) > maximum+1 ||
			bytesRead > l.maxBytes-page.Bytes {
			l.cleanupPaging(ctx, client, class, generation, cookie, acceptedCookie)
			return nil, 0, provider.NewError(provider.ErrorCodeLimitExceeded)
		}
		bytesRead += page.Bytes
		for _, entry := range page.Entries {
			if len(entries) >= maximum {
				l.cleanupPaging(ctx, client, class, generation, cookie, acceptedCookie)
				return nil, 0, provider.NewError(provider.ErrorCodeLimitExceeded)
			}
			entries = append(entries, cloneEntry(entry))
		}
		if len(page.Cookie) == 0 {
			return entries, bytesRead, nil
		}
		cookie = append(cookie[:0], page.Cookie...)
		acceptedCookie = true
	}
	l.cleanupPaging(ctx, client, class, generation, cookie, acceptedCookie)
	return nil, 0, provider.NewError(provider.ErrorCodeLimitExceeded)
}

// cleanupPaging performs at most one bounded abandonment or discards the connection.
func (l *Loader) cleanupPaging(
	ctx context.Context,
	client Client,
	class RecordClass,
	generation uint64,
	cookie []byte,
	accepted bool,
) {
	if ctx.Err() != nil || !accepted {
		client.Discard()
		return
	}
	if err := client.Abandon(ctx, class, generation, cookie); err != nil || ctx.Err() != nil {
		client.Discard()
	}
}

// String returns a constant protected loader summary.
func (*Loader) String() string { return loaderRedacted }

// GoString returns a constant protected loader representation.
func (*Loader) GoString() string { return loaderRedacted }

// Format prevents formatting verbs from traversing loader state.
func (*Loader) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, loaderRedacted) }

// MarshalJSON emits an empty object without endpoint or credential facts.
func (*Loader) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// validateLoadContext requires one caller deadline within the immutable bound.
func validateLoadContext(ctx context.Context, maximum time.Duration) error {
	if ctx == nil {
		return provider.NewError(provider.ErrorCodeInvalidRequest)
	}
	switch ctx.Err() {
	case context.Canceled:
		return provider.NewError(provider.ErrorCodeCancelled)
	case context.DeadlineExceeded:
		return provider.NewError(provider.ErrorCodeDeadlineExceeded)
	case nil:
	default:
		return provider.NewError(provider.ErrorCodeInternalInvariant)
	}
	deadline, found := ctx.Deadline()
	if !found || time.Until(deadline) > maximum {
		return provider.NewError(provider.ErrorCodeInvalidRequest)
	}
	return nil
}

// classifyBoundary converts backend detail into one secret-safe class.
func classifyBoundary(ctx context.Context) error {
	if ctx != nil {
		switch ctx.Err() {
		case context.Canceled:
			return provider.NewError(provider.ErrorCodeCancelled)
		case context.DeadlineExceeded:
			return provider.NewError(provider.ErrorCodeDeadlineExceeded)
		}
	}
	return provider.NewError(provider.ErrorCodeUnavailable)
}

// cloneEntry detaches one bounded LDAP record.
func cloneEntry(input Entry) Entry {
	output := Entry{Class: input.Class, Attributes: make(map[string][][]byte, len(input.Attributes))}
	for name, values := range input.Attributes {
		detached := make([][]byte, len(values))
		for index := range values {
			detached[index] = append([]byte(nil), values[index]...)
		}
		output.Attributes[name] = detached
	}
	return output
}

// entryBytes returns checked decoded bytes for one record.
func entryBytes(entry Entry) int {
	total := 0
	for name, values := range entry.Attributes {
		total += len(name)
		for _, value := range values {
			total += len(value)
		}
	}
	return total
}
