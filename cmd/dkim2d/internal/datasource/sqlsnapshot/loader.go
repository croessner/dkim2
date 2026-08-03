package sqlsnapshot

import (
	"context"
	"fmt"
	"io"
	"time"

	datasourceruntime "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/runtime"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"github.com/croessner/dkim2/provider"
)

const (
	loaderRedacted          = "sql_snapshot_loader{redacted}"
	repeatableReadIsolation = "repeatable read"
	serializableIsolation   = "serializable"
	datasetStateStaging     = "staging"
	datasetStateCommitted   = "committed"
)

// Transaction is one fixed-query read-only stable-snapshot boundary.
type Transaction interface {
	Isolation(context.Context) (string, bool, error)
	ReadCurrent(context.Context) (MetadataRow, error)
	HandlePage(context.Context, string, int) ([]HandleRow, error)
	ProfilePage(context.Context, string, int) ([]ProfileRow, error)
	CredentialPage(context.Context, string, string, int) ([]CredentialRow, error)
	PolicyPage(context.Context, string, string, string, int) ([]PolicyRow, error)
	KeyMaterialPage(context.Context, string, int) ([]KeyMaterialRow, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// Pool begins bounded read-only transactions and owns backend resources.
type Pool interface {
	Begin(context.Context) (Transaction, error)
	Close()
}

// Loader reads one repeatable-read SQL generation into an immutable snapshot.
type Loader struct {
	pool        Pool
	limits      provider.Limits
	pageSize    int
	maxBytes    int
	maxDeadline time.Duration
}

// NewLoader validates one bounded SQL loader configuration.
func NewLoader(
	pool Pool,
	limits provider.Limits,
	pageSize int,
	maxBytes int,
	maxDeadline time.Duration,
) (*Loader, error) {
	if pool == nil || limits.Validate() != nil ||
		pageSize <= 0 || pageSize > 256 ||
		maxBytes <= 0 || maxBytes > 32<<20 ||
		maxDeadline <= 0 || maxDeadline > 30*time.Second {
		return nil, provider.NewError(provider.ErrorCodeInvalidRequest)
	}
	return &Loader{
		pool: pool, limits: limits, pageSize: pageSize,
		maxBytes: maxBytes, maxDeadline: maxDeadline,
	}, nil
}

// Load reads, fences, validates, commits, and joins one complete SQL generation.
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
	transaction, err := l.pool.Begin(ctx)
	if err != nil || transaction == nil {
		return datasourceruntime.Candidate{}, classifyBoundary(ctx)
	}
	committed := false
	defer func() {
		if !committed {
			_ = transaction.Rollback(ctx)
		}
	}()
	isolation, readOnly, err := transaction.Isolation(ctx)
	if err != nil || !readOnly ||
		isolation != repeatableReadIsolation && isolation != serializableIsolation {
		return datasourceruntime.Candidate{}, provider.NewError(provider.ErrorCodeUnavailable)
	}
	current, err := transaction.ReadCurrent(ctx)
	if err != nil {
		return datasourceruntime.Candidate{}, classifyBoundary(ctx)
	}
	generation, err := mapMetadata(current)
	if err != nil {
		return datasourceruntime.Candidate{}, err
	}
	rows := DatasetRows{Current: current}
	bytesRead := metadataBytes(current)
	rows.Handles, err = l.loadHandles(ctx, transaction)
	if err == nil {
		bytesRead += handleBytes(rows.Handles)
		rows.Profiles, err = l.loadProfiles(ctx, transaction)
	}
	if err == nil {
		bytesRead += profileBytes(rows.Profiles)
		rows.Credentials, err = l.loadCredentials(ctx, transaction)
	}
	if err == nil {
		bytesRead += credentialBytes(rows.Credentials)
		rows.Policies, err = l.loadPolicies(ctx, transaction)
	}
	if err == nil {
		bytesRead += policyBytes(rows.Policies)
		rows.KeyMaterial, err = l.loadKeyMaterial(ctx, transaction)
	}
	if err != nil {
		return datasourceruntime.Candidate{}, err
	}
	defer clearKeyMaterialRows(rows.KeyMaterial)
	bytesRead += keyMaterialBytes(rows.KeyMaterial)
	if bytesRead < 0 || bytesRead > l.maxBytes {
		return datasourceruntime.Candidate{}, provider.NewError(provider.ErrorCodeLimitExceeded)
	}
	rows.Final, err = transaction.ReadCurrent(ctx)
	if err != nil {
		return datasourceruntime.Candidate{}, classifyBoundary(ctx)
	}
	dataset, err := MapDataset(rows, l.limits)
	if err != nil {
		return datasourceruntime.Candidate{}, err
	}
	materials, err := MapNativeKeyMaterial(rows.KeyMaterial, generation)
	if err != nil {
		return datasourceruntime.Candidate{}, err
	}
	defer closeNativeMaterials(materials)
	registry, err := signingstore.OpenNativeRegistry(generation, materials)
	if err != nil {
		return datasourceruntime.Candidate{}, provider.NewError(provider.ErrorCodeMalformedData)
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
	if err := transaction.Commit(ctx); err != nil {
		return datasourceruntime.Candidate{}, classifyBoundary(ctx)
	}
	committed = true
	if err := contextFailure(ctx); err != nil {
		return datasourceruntime.Candidate{}, err
	}
	closeRegistry = false
	return datasourceruntime.Candidate{
		Dataset: dataset, RegistryGeneration: registryGeneration,
		Bindings: registry.Bindings(), Registry: registry,
	}, nil
}

// loadKeyMaterial reads deterministic native-key handle pages.
func (l *Loader) loadKeyMaterial(
	ctx context.Context,
	tx Transaction,
) ([]KeyMaterialRow, error) {
	output := make([]KeyMaterialRow, 0)
	cursor := ""
	bytesRead := 0
	for responses := 0; responses <= l.limits.MaxHandles; responses++ {
		page, err := tx.KeyMaterialPage(ctx, cursor, l.pageSize)
		if err != nil {
			clearKeyMaterialRows(output)
			return nil, classifyBoundary(ctx)
		}
		if len(page) == 0 {
			return output, nil
		}
		if len(page) > l.pageSize || len(output) > l.limits.MaxHandles-len(page) {
			clearKeyMaterialRows(page)
			clearKeyMaterialRows(output)
			return nil, provider.NewError(provider.ErrorCodeLimitExceeded)
		}
		pageBytes := keyMaterialBytes(page)
		if pageBytes < 0 || bytesRead > l.maxBytes-pageBytes {
			clearKeyMaterialRows(page)
			clearKeyMaterialRows(output)
			return nil, provider.NewError(provider.ErrorCodeLimitExceeded)
		}
		next := page[len(page)-1].HandleID
		if next <= cursor {
			clearKeyMaterialRows(page)
			clearKeyMaterialRows(output)
			return nil, provider.NewError(provider.ErrorCodeLimitExceeded)
		}
		output = append(output, page...)
		bytesRead += pageBytes
		cursor = next
	}
	clearKeyMaterialRows(output)
	return nil, provider.NewError(provider.ErrorCodeLimitExceeded)
}

// loadHandles reads deterministic handle keyset pages.
//
//nolint:dupl // Separate typed cursors prevent cross-record pagination mistakes.
func (l *Loader) loadHandles(ctx context.Context, tx Transaction) ([]HandleRow, error) {
	output := make([]HandleRow, 0)
	cursor := ""
	for responses := 0; responses <= l.limits.MaxHandles; responses++ {
		page, err := tx.HandlePage(ctx, cursor, l.pageSize)
		if err != nil {
			return nil, classifyBoundary(ctx)
		}
		if len(page) == 0 {
			return output, nil
		}
		if len(page) > l.pageSize || len(output) > l.limits.MaxHandles-len(page) {
			return nil, provider.NewError(provider.ErrorCodeLimitExceeded)
		}
		next := page[len(page)-1].HandleID
		if next <= cursor {
			return nil, provider.NewError(provider.ErrorCodeLimitExceeded)
		}
		output = append(output, page...)
		cursor = next
	}
	return nil, provider.NewError(provider.ErrorCodeLimitExceeded)
}

// loadProfiles reads deterministic profile keyset pages.
//
//nolint:dupl // Separate typed cursors prevent cross-record pagination mistakes.
func (l *Loader) loadProfiles(ctx context.Context, tx Transaction) ([]ProfileRow, error) {
	output := make([]ProfileRow, 0)
	cursor := ""
	for responses := 0; responses <= l.limits.MaxProfiles; responses++ {
		page, err := tx.ProfilePage(ctx, cursor, l.pageSize)
		if err != nil {
			return nil, classifyBoundary(ctx)
		}
		if len(page) == 0 {
			return output, nil
		}
		if len(page) > l.pageSize || len(output) > l.limits.MaxProfiles-len(page) {
			return nil, provider.NewError(provider.ErrorCodeLimitExceeded)
		}
		next := page[len(page)-1].ProfileID
		if next <= cursor {
			return nil, provider.NewError(provider.ErrorCodeLimitExceeded)
		}
		output = append(output, page...)
		cursor = next
	}
	return nil, provider.NewError(provider.ErrorCodeLimitExceeded)
}

// loadCredentials reads deterministic composite credential keyset pages.
func (l *Loader) loadCredentials(ctx context.Context, tx Transaction) ([]CredentialRow, error) {
	maximum := l.limits.MaxProfiles * l.limits.MaxCredentialsPerProfile
	output := make([]CredentialRow, 0)
	profileCursor, algorithmCursor := "", ""
	for responses := 0; responses <= maximum; responses++ {
		page, err := tx.CredentialPage(ctx, profileCursor, algorithmCursor, l.pageSize)
		if err != nil {
			return nil, classifyBoundary(ctx)
		}
		if len(page) == 0 {
			return output, nil
		}
		if len(page) > l.pageSize || len(output) > maximum-len(page) {
			return nil, provider.NewError(provider.ErrorCodeLimitExceeded)
		}
		last := page[len(page)-1]
		if last.ProfileID < profileCursor ||
			last.ProfileID == profileCursor && last.Algorithm <= algorithmCursor {
			return nil, provider.NewError(provider.ErrorCodeLimitExceeded)
		}
		output = append(output, page...)
		profileCursor, algorithmCursor = last.ProfileID, last.Algorithm
	}
	return nil, provider.NewError(provider.ErrorCodeLimitExceeded)
}

// loadPolicies reads deterministic composite policy keyset pages.
func (l *Loader) loadPolicies(ctx context.Context, tx Transaction) ([]PolicyRow, error) {
	output := make([]PolicyRow, 0)
	tenantCursor, domainCursor, useCursor := "", "", ""
	for responses := 0; responses <= l.limits.MaxPolicies; responses++ {
		page, err := tx.PolicyPage(
			ctx, tenantCursor, domainCursor, useCursor, l.pageSize,
		)
		if err != nil {
			return nil, classifyBoundary(ctx)
		}
		if len(page) == 0 {
			return output, nil
		}
		if len(page) > l.pageSize || len(output) > l.limits.MaxPolicies-len(page) {
			return nil, provider.NewError(provider.ErrorCodeLimitExceeded)
		}
		last := page[len(page)-1]
		if !tupleGreater(
			last.TenantID, last.Domain, last.Use,
			tenantCursor, domainCursor, useCursor,
		) {
			return nil, provider.NewError(provider.ErrorCodeLimitExceeded)
		}
		output = append(output, page...)
		tenantCursor, domainCursor, useCursor = last.TenantID, last.Domain, last.Use
	}
	return nil, provider.NewError(provider.ErrorCodeLimitExceeded)
}

// Close releases the owned pool resources.
func (l *Loader) Close() {
	if l != nil && l.pool != nil {
		l.pool.Close()
	}
}

// String returns a constant protected loader summary.
func (*Loader) String() string { return loaderRedacted }

// GoString returns a constant protected loader representation.
func (*Loader) GoString() string { return loaderRedacted }

// Format prevents formatting verbs from traversing loader state.
func (*Loader) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, loaderRedacted) }

// MarshalJSON emits an empty object without backend facts.
func (*Loader) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// validateLoadContext requires one caller deadline within the immutable bound.
func validateLoadContext(ctx context.Context, maximum time.Duration) error {
	if err := contextFailure(ctx); err != nil {
		return err
	}
	deadline, found := ctx.Deadline()
	if !found || time.Until(deadline) > maximum {
		return provider.NewError(provider.ErrorCodeInvalidRequest)
	}
	return nil
}

// contextFailure maps terminal caller state into the closed taxonomy.
func contextFailure(ctx context.Context) error {
	if ctx == nil {
		return provider.NewError(provider.ErrorCodeInvalidRequest)
	}
	switch ctx.Err() {
	case nil:
		return nil
	case context.Canceled:
		return provider.NewError(provider.ErrorCodeCancelled)
	case context.DeadlineExceeded:
		return provider.NewError(provider.ErrorCodeDeadlineExceeded)
	default:
		return provider.NewError(provider.ErrorCodeInternalInvariant)
	}
}

// classifyBoundary converts raw driver failures into content-free classes.
func classifyBoundary(ctx context.Context) error {
	if err := contextFailure(ctx); err != nil {
		return err
	}
	return provider.NewError(provider.ErrorCodeUnavailable)
}

// tupleGreater compares one three-column C-collated keyset cursor.
func tupleGreater(a, b, c, x, y, z string) bool {
	return a > x || a == x && (b > y || b == y && c > z)
}

// metadataBytes returns bounded row-accounting bytes.
func metadataBytes(row MetadataRow) int {
	total := len(row.Generation) + len(row.SchemaVersion) + len(row.DatasetState) +
		len(row.CandidateDigest) + len(row.PointerDigest)
	if row.OperationID != nil {
		total += len(*row.OperationID)
	}
	return total
}

// handleBytes returns aggregate encoded handle-row bytes.
func handleBytes(rows []HandleRow) int {
	total := 0
	for _, row := range rows {
		total += len(row.Generation) + len(row.HandleID)
	}
	return total
}

// profileBytes returns aggregate encoded profile-row bytes.
func profileBytes(rows []ProfileRow) int {
	total := 0
	for _, row := range rows {
		total += len(row.Generation) + len(row.ProfileID) + len(row.Domain) + len(row.Status)
		if row.NotBeforeUTC != nil {
			total += len(*row.NotBeforeUTC)
		}
		if row.NotAfterUTC != nil {
			total += len(*row.NotAfterUTC)
		}
	}
	return total
}

// credentialBytes returns aggregate encoded credential-row bytes.
func credentialBytes(rows []CredentialRow) int {
	total := 0
	for _, row := range rows {
		total += len(row.Generation) + len(row.ProfileID) + len(row.Algorithm) +
			len(row.Selector) + len(row.PublicKeySPKI) + len(row.HandleID)
	}
	return total
}

// policyBytes returns aggregate encoded policy-row bytes.
func policyBytes(rows []PolicyRow) int {
	total := 0
	for _, row := range rows {
		total += len(row.Generation) + len(row.TenantID) + len(row.Domain) +
			len(row.Use) + len(row.ProfileID) + len(row.Status) +
			len(row.Rollout) + len(row.Compatibility)
		if row.FeedbackRouteID != nil {
			total += len(*row.FeedbackRouteID)
		}
	}
	return total
}

// keyMaterialBytes returns aggregate native-key row bytes.
func keyMaterialBytes(rows []KeyMaterialRow) int {
	total := 0
	for _, row := range rows {
		total += len(row.Generation) + len(row.TenantID) + len(row.Domain) +
			len(row.Use) + len(row.HandleID) + len(row.Algorithm) +
			len(row.PublicSPKI) + len(row.PrivatePKCS8)
	}
	return total
}
