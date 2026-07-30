package migration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"time"

	datasourcepostgresql "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/postgresql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	queryPublicationCurrent = `SELECT current.generation::text
FROM dkim2_datasource.current_generation AS current
JOIN dkim2_datasource.dataset_generations AS dataset
  ON dataset.generation = current.generation
WHERE current.singleton = TRUE
  AND dataset.schema_version = 'dkim2-datasource-v1'
  AND dataset.dataset_state = 'committed'`
	queryPublicationCurrentLocked = queryPublicationCurrent + `
FOR UPDATE OF current`
	queryPublicationEmpty = `SELECT
  NOT EXISTS (SELECT 1 FROM dkim2_datasource.current_generation)
  AND NOT EXISTS (SELECT 1 FROM dkim2_datasource.dataset_generations)
  AND NOT EXISTS (SELECT 1 FROM dkim2_datasource.handles)
  AND NOT EXISTS (SELECT 1 FROM dkim2_datasource.profiles)
  AND NOT EXISTS (SELECT 1 FROM dkim2_datasource.credentials)
  AND NOT EXISTS (SELECT 1 FROM dkim2_datasource.policies)`
	queryInsertGeneration = `INSERT INTO dkim2_datasource.dataset_generations
(generation, schema_version, dataset_state)
VALUES ($1::numeric, 'dkim2-datasource-v1', 'staging')`
	queryInsertHandle = `INSERT INTO dkim2_datasource.handles
(generation, handle_id) VALUES ($1::numeric, $2)`
	queryInsertProfile = `INSERT INTO dkim2_datasource.profiles
(generation, profile_id, signing_domain, record_status, not_before_utc, not_after_utc)
VALUES ($1::numeric, $2, $3, $4, $5, $6)`
	queryInsertCredential = `INSERT INTO dkim2_datasource.credentials
(generation, profile_id, algorithm, selector, public_key_spki, handle_id)
VALUES ($1::numeric, $2, $3, $4, $5, $6)`
	queryInsertPolicy = `INSERT INTO dkim2_datasource.policies
(generation, tenant_id, signing_domain, profile_use, profile_id, record_status,
 rollout, compatibility, feedback_route_id)
VALUES ($1::numeric, $2, $3, $4, $5, $6, $7, $8, $9)`
	queryValidatePublication = `SELECT
  (SELECT count(*) FROM dkim2_datasource.handles WHERE generation = $1::numeric),
  (SELECT count(*) FROM dkim2_datasource.profiles WHERE generation = $1::numeric),
  (SELECT count(*) FROM dkim2_datasource.credentials WHERE generation = $1::numeric),
  (SELECT count(*) FROM dkim2_datasource.policies WHERE generation = $1::numeric)`
	queryCommitPublication = `UPDATE dkim2_datasource.dataset_generations
SET dataset_state = 'committed'
WHERE generation = $1::numeric AND dataset_state = 'staging'`
	queryFencePublication = `UPDATE dkim2_datasource.current_generation
SET generation = $2::numeric
WHERE singleton = TRUE AND generation = $1::numeric`
	queryFenceBootstrap = `INSERT INTO dkim2_datasource.current_generation
(singleton, generation) VALUES (TRUE, $1::numeric)`
)

// PostgreSQLPublisher owns one transactionally fenced PostgreSQL writer.
type PostgreSQLPublisher struct {
	pool *pgxpool.Pool
}

// NewPostgreSQLPublisherClient opens one verified single-authority SQL publisher.
func NewPostgreSQLPublisherClient(
	ctx context.Context,
	config PostgreSQLPublicationConfig,
	password []byte,
	rootsDER [][]byte,
) (*PostgreSQLPublisher, func() error, error) {
	if ctx == nil || !validPostgreSQLPublication(config) ||
		len(password) == 0 || len(password) > 16<<10 || len(rootsDER) == 0 {
		return nil, nil, errors.New("postgresql publication unavailable")
	}
	host, port, err := net.SplitHostPort(config.Address)
	if err != nil {
		return nil, nil, errors.New("postgresql publication unavailable")
	}
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if portErr != nil || portNumber == 0 {
		return nil, nil, errors.New("postgresql publication unavailable")
	}
	if datasourcepostgresql.RejectEnvironment() != nil {
		return nil, nil, errors.New("postgresql publication unavailable")
	}
	poolConfig, err := pgxpool.ParseConfig(
		"postgres://placeholder@127.0.0.1:5432/placeholder?sslmode=require",
	)
	if err != nil || datasourcepostgresql.RejectEnvironment() != nil {
		return nil, nil, errors.New("postgresql publication unavailable")
	}
	roots := x509.NewCertPool()
	for _, encoded := range rootsDER {
		certificate, parseErr := x509.ParseCertificate(encoded)
		if parseErr != nil {
			return nil, nil, errors.New("postgresql publication unavailable")
		}
		roots.AddCert(certificate)
	}
	poolConfig.ConnConfig.Host = host
	poolConfig.ConnConfig.Port = uint16(portNumber)
	poolConfig.ConnConfig.Database = config.Database
	poolConfig.ConnConfig.User = config.User
	poolConfig.ConnConfig.Password = string(password)
	poolConfig.ConnConfig.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: config.ServerName, RootCAs: roots,
	}
	poolConfig.ConnConfig.Fallbacks = nil
	poolConfig.ConnConfig.RuntimeParams = map[string]string{
		"application_name": "dkim2d-datasource-publisher",
	}
	poolConfig.MaxConns = 2
	poolConfig.MinConns = 0
	poolConfig.MaxConnIdleTime = time.Minute
	poolConfig.MaxConnLifetime = 5 * time.Minute
	poolConfig.HealthCheckPeriod = 30 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil || pool.Ping(ctx) != nil {
		if pool != nil {
			pool.Close()
		}
		return nil, nil, errors.New("postgresql publication unavailable")
	}
	publisher, err := NewPostgreSQLPublisher(pool)
	if err != nil {
		pool.Close()
		return nil, nil, errors.New("postgresql publication unavailable")
	}
	return publisher, func() error {
		pool.Close()
		return nil
	}, nil
}

// NewPostgreSQLPublisher constructs one explicit already-authenticated publisher.
func NewPostgreSQLPublisher(pool *pgxpool.Pool) (*PostgreSQLPublisher, error) {
	if pool == nil {
		return nil, errors.New("postgresql publication unavailable")
	}
	return &PostgreSQLPublisher{pool: pool}, nil
}

// Current reads one exact PostgreSQL fence or proves an entirely empty backend.
func (p *PostgreSQLPublisher) Current(ctx context.Context) (uint64, error) {
	if p == nil || p.pool == nil || ctx == nil {
		return 0, errors.New("postgresql publication unavailable")
	}
	var current string
	if err := p.pool.QueryRow(ctx, queryPublicationCurrent).Scan(&current); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return 0, errors.New("postgresql publication unavailable")
		}
		var empty bool
		if emptyErr := p.pool.QueryRow(ctx, queryPublicationEmpty).Scan(&empty); emptyErr != nil ||
			!empty {
			return 0, errors.New("postgresql publication unavailable")
		}
		return 0, nil
	}
	generation, err := parseGeneration(current)
	if err != nil {
		return 0, errors.New("postgresql publication unavailable")
	}
	return generation, nil
}

// Publish inserts, validates, commits, and fences one generation in one transaction.
//
//nolint:gocyclo // Every transactional durable step has an explicit fail-closed check.
func (p *PostgreSQLPublisher) Publish(
	ctx context.Context,
	expected uint64,
	candidate PublicationCandidate,
) (resultErr error) {
	if p == nil || p.pool == nil || ctx == nil || candidate.generation == 0 ||
		candidate.generation <= expected {
		return errors.New("postgresql publication unavailable")
	}
	transaction, err := p.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite,
	})
	if err != nil {
		return errors.New("postgresql publication unavailable")
	}
	defer func() {
		if transaction != nil {
			_ = transaction.Rollback(ctx)
		}
	}()
	var currentText string
	if expected == 0 {
		var empty bool
		if err := transaction.QueryRow(ctx, queryPublicationEmpty).Scan(&empty); err != nil ||
			!empty {
			return errors.New("postgresql publication unavailable")
		}
	} else {
		if err := transaction.QueryRow(
			ctx, queryPublicationCurrentLocked,
		).Scan(&currentText); err != nil {
			return errors.New("postgresql publication unavailable")
		}
		current, err := parseGeneration(currentText)
		if err != nil || current != expected {
			return errors.New("postgresql publication unavailable")
		}
	}
	rows := candidate.rows
	if rows.Current.Generation != rows.Final.Generation ||
		rows.Current.Generation != candidateGenerationText(candidate) {
		return errors.New("postgresql publication unavailable")
	}
	if _, err := transaction.Exec(
		ctx, queryInsertGeneration, rows.Current.Generation,
	); err != nil {
		return errors.New("postgresql publication unavailable")
	}
	for _, row := range rows.Handles {
		if _, err := transaction.Exec(
			ctx, queryInsertHandle, row.Generation, row.HandleID,
		); err != nil {
			return errors.New("postgresql publication unavailable")
		}
	}
	for _, row := range rows.Profiles {
		if _, err := transaction.Exec(
			ctx, queryInsertProfile,
			row.Generation, row.ProfileID, row.Domain, row.Status,
			row.NotBeforeUTC, row.NotAfterUTC,
		); err != nil {
			return errors.New("postgresql publication unavailable")
		}
	}
	for _, row := range rows.Credentials {
		if _, err := transaction.Exec(
			ctx, queryInsertCredential,
			row.Generation, row.ProfileID, row.Algorithm, row.Selector,
			row.PublicKeySPKI, row.HandleID,
		); err != nil {
			return errors.New("postgresql publication unavailable")
		}
	}
	for _, row := range rows.Policies {
		if _, err := transaction.Exec(
			ctx, queryInsertPolicy,
			row.Generation, row.TenantID, row.Domain, row.Use, row.ProfileID,
			row.Status, row.Rollout, row.Compatibility, row.FeedbackRouteID,
		); err != nil {
			return errors.New("postgresql publication unavailable")
		}
	}
	var handles, profiles, credentials, policies int
	if err := transaction.QueryRow(
		ctx, queryValidatePublication, rows.Current.Generation,
	).Scan(&handles, &profiles, &credentials, &policies); err != nil ||
		handles != len(rows.Handles) || profiles != len(rows.Profiles) ||
		credentials != len(rows.Credentials) || policies != len(rows.Policies) {
		return errors.New("postgresql publication unavailable")
	}
	tag, err := transaction.Exec(ctx, queryCommitPublication, rows.Current.Generation)
	if err != nil || tag.RowsAffected() != 1 {
		return errors.New("postgresql publication unavailable")
	}
	if expected == 0 {
		tag, err = transaction.Exec(
			ctx, queryFenceBootstrap, rows.Current.Generation,
		)
	} else {
		tag, err = transaction.Exec(
			ctx, queryFencePublication, currentText, rows.Current.Generation,
		)
	}
	if err != nil || tag.RowsAffected() != 1 {
		return errors.New("postgresql publication unavailable")
	}
	if err := transaction.Commit(ctx); err != nil {
		return errors.New("postgresql publication unavailable")
	}
	transaction = nil
	return nil
}

// candidateGenerationText returns one canonical candidate generation.
func candidateGenerationText(candidate PublicationCandidate) string {
	if candidate.generation == 0 {
		return ""
	}
	return strconv.FormatUint(candidate.generation, 10)
}
