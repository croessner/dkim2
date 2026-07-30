package postgresql

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var postgresqlEnvironment = []string{
	"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE",
	"PGSERVICE", "PGSERVICEFILE", "PGAPPNAME", "PGCONNECT_TIMEOUT", "PGSSLMODE",
	"PGSSLKEY", "PGSSLCERT", "PGSSNI", "PGSSLROOTCERT", "PGSSLPASSWORD",
	"PGSSLNEGOTIATION", "PGTARGETSESSIONATTRS", "PGTZ", "PGOPTIONS",
	"PGMINPROTOCOLVERSION", "PGMAXPROTOCOLVERSION", "PGCHANNELBINDING",
	"PGREQUIREAUTH",
}

// ConnectionConfig owns one verified single-authority PostgreSQL endpoint.
type ConnectionConfig struct {
	Address         string
	ServerName      string
	Database        string
	User            string
	Password        []byte
	RootCAs         *x509.CertPool
	ConnectTimeout  time.Duration
	MaxConnections  int32
	IdleConnections int32
}

// Validate rejects environment-derived, insecure, multi-authority, or widened settings.
func (c ConnectionConfig) Validate() error {
	host, port, err := net.SplitHostPort(c.Address)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || portErr != nil || portNumber == 0 || host == "" ||
		c.ServerName == "" || c.Database == "" || c.User == "" ||
		len(c.Password) == 0 || c.RootCAs == nil ||
		c.ConnectTimeout <= 0 || c.ConnectTimeout > 30*time.Second ||
		c.MaxConnections <= 0 || c.MaxConnections > 4 ||
		c.IdleConnections < 0 || c.IdleConnections > 2 ||
		c.IdleConnections > c.MaxConnections ||
		len(c.Address) > 512 || len(c.ServerName) > 253 ||
		len(c.Database) > 128 || len(c.User) > 128 || len(c.Password) > 16<<10 {
		return errors.New("invalid postgresql connection configuration")
	}
	return nil
}

// String returns a constant protected connection summary.
func (ConnectionConfig) String() string { return loaderRedacted }

// GoString returns a constant protected connection representation.
func (ConnectionConfig) GoString() string { return loaderRedacted }

// Format prevents formatting verbs from exposing connection facts.
func (ConnectionConfig) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, loaderRedacted)
}

// MarshalJSON emits an empty object without connection facts.
func (ConnectionConfig) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// OpenPool constructs a pgx pool exclusively from validated typed fields.
func OpenPool(ctx context.Context, config ConnectionConfig) (Pool, error) {
	if ctx == nil || config.Validate() != nil {
		return nil, errors.New("postgresql pool unavailable")
	}
	poolConfig, err := newPoolConfig(config)
	if err != nil {
		return nil, errors.New("postgresql pool unavailable")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, errors.New("postgresql pool unavailable")
	}
	return &pgxPool{pool: pool}, nil
}

// newPoolConfig constructs an environment-independent single-authority pool.
func newPoolConfig(config ConnectionConfig) (*pgxpool.Config, error) {
	if config.Validate() != nil || RejectEnvironment() != nil {
		return nil, errors.New("postgresql pool unavailable")
	}
	host, port, _ := net.SplitHostPort(config.Address)
	portNumber, _ := strconv.ParseUint(port, 10, 16)
	poolConfig, err := pgxpool.ParseConfig(
		"postgres://placeholder:placeholder@127.0.0.1:5432/placeholder?sslmode=require",
	)
	if err != nil || RejectEnvironment() != nil {
		return nil, errors.New("postgresql pool unavailable")
	}
	poolConfig.ConnConfig.Host = host
	poolConfig.ConnConfig.Port = uint16(portNumber)
	poolConfig.ConnConfig.Database = config.Database
	poolConfig.ConnConfig.User = config.User
	poolConfig.ConnConfig.Password = string(config.Password)
	poolConfig.ConnConfig.ConnectTimeout = config.ConnectTimeout
	poolConfig.ConnConfig.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: config.ServerName,
		RootCAs: config.RootCAs,
	}
	poolConfig.ConnConfig.Fallbacks = nil
	poolConfig.ConnConfig.RuntimeParams = map[string]string{
		"application_name": "dkim2d",
	}
	poolConfig.MaxConns = config.MaxConnections
	poolConfig.MinConns = 0
	poolConfig.MinIdleConns = config.IdleConnections
	poolConfig.MaxConnLifetime = time.Hour
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.HealthCheckPeriod = time.Minute
	return poolConfig, nil
}

// RejectEnvironment fails closed when libpq-compatible process variables
// could influence pgx parsing or cause implicit filesystem access.
func RejectEnvironment() error {
	for _, name := range postgresqlEnvironment {
		if value, present := os.LookupEnv(name); present && value != "" {
			return errors.New("postgresql environment unavailable")
		}
	}
	return nil
}

type pgxPool struct {
	pool *pgxpool.Pool
}

// Begin starts one read-only repeatable-read transaction.
func (p *pgxPool) Begin(ctx context.Context) (Transaction, error) {
	if p == nil || p.pool == nil {
		return nil, errors.New("postgresql transaction unavailable")
	}
	transaction, err := p.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, errors.New("postgresql transaction unavailable")
	}
	return &pgxTransaction{transaction: transaction}, nil
}

// Close releases all pooled PostgreSQL connections.
func (p *pgxPool) Close() {
	if p != nil && p.pool != nil {
		p.pool.Close()
	}
}

type pgxTransaction struct {
	transaction pgx.Tx
	generation  string
}

// Isolation proves the effective transaction isolation and read-only state.
func (t *pgxTransaction) Isolation(ctx context.Context) (string, bool, error) {
	var isolation, readOnlyText string
	if t == nil || t.transaction == nil {
		return "", false, errors.New("postgresql isolation unavailable")
	}
	if err := t.transaction.QueryRow(ctx, queryIsolation).Scan(&isolation, &readOnlyText); err != nil {
		return "", false, errors.New("postgresql isolation unavailable")
	}
	return isolation, readOnlyText == "on", nil
}

// ReadCurrent reads exactly one current committed metadata row.
func (t *pgxTransaction) ReadCurrent(ctx context.Context) (MetadataRow, error) {
	var row MetadataRow
	if t == nil || t.transaction == nil {
		return row, errors.New("postgresql metadata unavailable")
	}
	err := t.transaction.QueryRow(ctx, queryCurrent).Scan(
		&row.Generation, &row.SchemaVersion, &row.DatasetState,
	)
	if err != nil {
		return MetadataRow{}, errors.New("postgresql metadata unavailable")
	}
	if t.generation == "" {
		t.generation = row.Generation
	}
	return row, nil
}

// HandlePage reads one deterministic handle keyset page.
func (t *pgxTransaction) HandlePage(
	ctx context.Context,
	after string,
	limit int,
) ([]HandleRow, error) {
	rows, err := t.transaction.Query(ctx, queryHandles, t.generation, after, limit)
	if err != nil {
		return nil, errors.New("postgresql page unavailable")
	}
	defer rows.Close()
	output := make([]HandleRow, 0, limit)
	for rows.Next() {
		var row HandleRow
		if err := rows.Scan(&row.Generation, &row.HandleID); err != nil {
			return nil, errors.New("postgresql page unavailable")
		}
		output = append(output, row)
	}
	if rows.Err() != nil {
		return nil, errors.New("postgresql page unavailable")
	}
	return output, nil
}

// ProfilePage reads one deterministic profile keyset page.
func (t *pgxTransaction) ProfilePage(
	ctx context.Context,
	after string,
	limit int,
) ([]ProfileRow, error) {
	rows, err := t.transaction.Query(ctx, queryProfiles, t.generation, after, limit)
	if err != nil {
		return nil, errors.New("postgresql page unavailable")
	}
	defer rows.Close()
	output := make([]ProfileRow, 0, limit)
	for rows.Next() {
		var row ProfileRow
		if err := rows.Scan(
			&row.Generation, &row.ProfileID, &row.Domain, &row.Status,
			&row.NotBeforeUTC, &row.NotAfterUTC,
		); err != nil {
			return nil, errors.New("postgresql page unavailable")
		}
		output = append(output, row)
	}
	if rows.Err() != nil {
		return nil, errors.New("postgresql page unavailable")
	}
	return output, nil
}

// CredentialPage reads one deterministic credential keyset page.
func (t *pgxTransaction) CredentialPage(
	ctx context.Context,
	afterProfile string,
	afterAlgorithm string,
	limit int,
) ([]CredentialRow, error) {
	rows, err := t.transaction.Query(
		ctx, queryCredentials, t.generation, afterProfile, afterAlgorithm, limit,
	)
	if err != nil {
		return nil, errors.New("postgresql page unavailable")
	}
	defer rows.Close()
	output := make([]CredentialRow, 0, limit)
	for rows.Next() {
		var row CredentialRow
		if err := rows.Scan(
			&row.Generation, &row.ProfileID, &row.Algorithm, &row.Selector,
			&row.PublicKeySPKI, &row.HandleID,
		); err != nil {
			return nil, errors.New("postgresql page unavailable")
		}
		output = append(output, row)
	}
	if rows.Err() != nil {
		return nil, errors.New("postgresql page unavailable")
	}
	return output, nil
}

// PolicyPage reads one deterministic policy keyset page.
func (t *pgxTransaction) PolicyPage(
	ctx context.Context,
	afterTenant string,
	afterDomain string,
	afterUse string,
	limit int,
) ([]PolicyRow, error) {
	rows, err := t.transaction.Query(
		ctx, queryPolicies, t.generation, afterTenant, afterDomain, afterUse, limit,
	)
	if err != nil {
		return nil, errors.New("postgresql page unavailable")
	}
	defer rows.Close()
	output := make([]PolicyRow, 0, limit)
	for rows.Next() {
		var row PolicyRow
		if err := rows.Scan(
			&row.Generation, &row.TenantID, &row.Domain, &row.Use,
			&row.ProfileID, &row.Status, &row.Rollout, &row.Compatibility,
			&row.FeedbackRouteID,
		); err != nil {
			return nil, errors.New("postgresql page unavailable")
		}
		output = append(output, row)
	}
	if rows.Err() != nil {
		return nil, errors.New("postgresql page unavailable")
	}
	return output, nil
}

// Commit completes the read-only snapshot before local publication.
func (t *pgxTransaction) Commit(ctx context.Context) error {
	if t == nil || t.transaction == nil {
		return errors.New("postgresql completion unavailable")
	}
	if err := t.transaction.Commit(ctx); err != nil {
		return errors.New("postgresql completion unavailable")
	}
	t.transaction = nil
	return nil
}

// Rollback closes an incomplete read-only transaction.
func (t *pgxTransaction) Rollback(ctx context.Context) error {
	if t == nil || t.transaction == nil {
		return nil
	}
	err := t.transaction.Rollback(ctx)
	t.transaction = nil
	if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return errors.New("postgresql rollback unavailable")
	}
	return nil
}
