package postgresql

import (
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/sqlsnapshot"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"github.com/croessner/dkim2/provider"
)

const (
	loaderRedacted          = "postgresql_loader{redacted}"
	schemaVersion           = "dkim2-datasource-v2"
	repeatableReadIsolation = "repeatable read"
)

// Transaction is one fixed-query read-only stable-snapshot boundary.
type Transaction = sqlsnapshot.Transaction

// Pool begins bounded read-only transactions and owns backend resources.
type Pool = sqlsnapshot.Pool

// Loader reads one repeatable-read PostgreSQL generation into an immutable snapshot.
type Loader = sqlsnapshot.Loader

// MetadataRow is one explicit dataset metadata projection.
type MetadataRow = sqlsnapshot.MetadataRow

// HandleRow is one explicit opaque handle projection.
type HandleRow = sqlsnapshot.HandleRow

// ProfileRow is one explicit profile projection.
type ProfileRow = sqlsnapshot.ProfileRow

// CredentialRow is one explicit public credential projection.
type CredentialRow = sqlsnapshot.CredentialRow

// PolicyRow is one explicit administrative policy projection.
type PolicyRow = sqlsnapshot.PolicyRow

// KeyMaterialRow is one explicit native private-key projection.
type KeyMaterialRow = sqlsnapshot.KeyMaterialRow

// DatasetRows contains one transactionally fenced exact generation.
type DatasetRows = sqlsnapshot.DatasetRows

// NewLoader validates one bounded PostgreSQL loader configuration.
func NewLoader(
	pool Pool,
	limits provider.Limits,
	pageSize int,
	maxBytes int,
	maxDeadline time.Duration,
) (*Loader, error) {
	return sqlsnapshot.NewLoader(pool, limits, pageSize, maxBytes, maxDeadline)
}

// MapDataset validates one stable PostgreSQL row snapshot through provider-neutral owners.
func MapDataset(rows DatasetRows, limits provider.Limits) (*provider.Dataset, error) {
	return sqlsnapshot.MapDataset(rows, limits)
}

// MapNativeKeyMaterial validates and detaches one exact native PostgreSQL key set.
func MapNativeKeyMaterial(
	rows []KeyMaterialRow,
	generation uint64,
) ([]*signingstore.NativeKeyMaterial, error) {
	return sqlsnapshot.MapNativeKeyMaterial(rows, generation)
}

// clearKeyMaterialRows clears detached PostgreSQL key buffers on scan failure.
func clearKeyMaterialRows(rows []KeyMaterialRow) {
	sqlsnapshot.ClearKeyMaterialRows(rows)
}
