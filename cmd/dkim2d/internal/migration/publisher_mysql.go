package migration

import (
	"context"
	"database/sql"
	"errors"
	"time"

	datasourcemysql "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/mysql"
)

const (
	queryMySQLPublicationCurrent = `SELECT CAST(current_generation.generation AS CHAR)
FROM dkim2_current_generation AS current_generation
JOIN dkim2_dataset_generations AS dataset USING (generation)
WHERE current_generation.singleton = 1
  AND dataset.schema_version = 'dkim2-datasource-v2'
  AND dataset.dataset_state = 'committed'`
	queryMySQLPublicationCurrentLocked = queryMySQLPublicationCurrent + ` FOR UPDATE`
	queryMySQLPublicationLock          = `SELECT singleton
FROM dkim2_publication_lock
WHERE singleton = 1
FOR UPDATE`
	queryMySQLPublicationEmpty = `SELECT
  NOT EXISTS (SELECT 1 FROM dkim2_current_generation)
  AND NOT EXISTS (SELECT 1 FROM dkim2_dataset_generations)
  AND NOT EXISTS (SELECT 1 FROM dkim2_handles)
  AND NOT EXISTS (SELECT 1 FROM dkim2_profiles)
  AND NOT EXISTS (SELECT 1 FROM dkim2_credentials)
  AND NOT EXISTS (SELECT 1 FROM dkim2_policies)
  AND NOT EXISTS (SELECT 1 FROM dkim2_key_material)`
	queryMySQLInsertGeneration    = `CALL dkim2_v2_insert_generation(?)`
	queryMySQLInsertHandle        = `CALL dkim2_v2_insert_handle(?, ?)`
	queryMySQLInsertProfile       = `CALL dkim2_v2_insert_profile(?, ?, ?, ?, ?, ?)`
	queryMySQLInsertCredential    = `CALL dkim2_v2_insert_credential(?, ?, ?, ?, ?, ?)`
	queryMySQLInsertPolicy        = `CALL dkim2_v2_insert_policy(?, ?, ?, ?, ?, ?, ?, ?, ?)`
	queryMySQLInsertKeyMaterial   = `CALL dkim2_v2_insert_key_material(?, ?, ?, ?, ?, ?, ?, ?)`
	queryMySQLValidatePublication = `SELECT
  (SELECT count(*) FROM dkim2_handles WHERE generation = ?),
  (SELECT count(*) FROM dkim2_profiles WHERE generation = ?),
  (SELECT count(*) FROM dkim2_credentials WHERE generation = ?),
  (SELECT count(*) FROM dkim2_policies WHERE generation = ?),
  (SELECT count(*) FROM dkim2_key_material WHERE generation = ?)`
	queryMySQLCommitPublication = `CALL dkim2_v2_seal_generation(?)`
	queryMySQLFencePublication  = `CALL dkim2_v2_update_current(?, ?)`
	queryMySQLFenceBootstrap    = `CALL dkim2_v2_insert_current(?)`
)

// MySQLPublisher owns one transactionally fenced MySQL or MariaDB writer.
type MySQLPublisher struct {
	database *sql.DB
}

// NewMySQLPublisherClient opens one verified single-authority SQL publisher.
func NewMySQLPublisherClient(
	ctx context.Context,
	config MySQLPublicationConfig,
	password []byte,
	rootsDER [][]byte,
) (*MySQLPublisher, func() error, error) {
	if ctx == nil || !validSQLPublication(config) || len(password) == 0 ||
		len(password) > 16<<10 || len(rootsDER) == 0 {
		return nil, nil, errors.New("mysql publication unavailable")
	}
	roots, err := migrationRootPool(rootsDER)
	if err != nil {
		return nil, nil, errors.New("mysql publication unavailable")
	}
	database, err := datasourcemysql.OpenDatabase(ctx, datasourcemysql.ConnectionConfig{
		Address: config.Address, ServerName: config.ServerName,
		Database: config.Database, User: config.User, Password: password,
		RootCAs: roots, ConnectTimeout: publicationConnectTimeout(ctx),
		MaxConnections: 2, IdleConnections: 0,
	})
	if err != nil {
		return nil, nil, errors.New("mysql publication unavailable")
	}
	publisher, err := NewMySQLPublisher(database)
	if err != nil {
		_ = database.Close()
		return nil, nil, errors.New("mysql publication unavailable")
	}
	return publisher, database.Close, nil
}

// publicationConnectTimeout derives one bounded positive connection budget.
func publicationConnectTimeout(ctx context.Context) time.Duration {
	maximum := 5 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 && remaining < maximum {
			return remaining
		}
	}
	return maximum
}

// NewMySQLPublisher constructs one explicit already-authenticated publisher.
func NewMySQLPublisher(database *sql.DB) (*MySQLPublisher, error) {
	if database == nil {
		return nil, errors.New("mysql publication unavailable")
	}
	return &MySQLPublisher{database: database}, nil
}

// Current reads one exact SQL fence or proves an otherwise empty backend.
func (p *MySQLPublisher) Current(ctx context.Context) (uint64, error) {
	if p == nil || p.database == nil || ctx == nil {
		return 0, errors.New("mysql publication unavailable")
	}
	var current string
	if err := p.database.QueryRowContext(ctx, queryMySQLPublicationCurrent).Scan(&current); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return 0, errors.New("mysql publication unavailable")
		}
		var empty bool
		if emptyErr := p.database.QueryRowContext(ctx, queryMySQLPublicationEmpty).Scan(&empty); emptyErr != nil || !empty {
			return 0, errors.New("mysql publication unavailable")
		}
		return 0, nil
	}
	generation, err := parseGeneration(current)
	if err != nil {
		return 0, errors.New("mysql publication unavailable")
	}
	return generation, nil
}

// Publish inserts, validates, commits, and fences one generation in one transaction.
//
//nolint:gocyclo // Every transactional durable step has an explicit fail-closed check.
func (p *MySQLPublisher) Publish(
	ctx context.Context,
	expected uint64,
	candidate PublicationCandidate,
) (resultErr error) {
	if p == nil || p.database == nil || ctx == nil || candidate.Generation() == 0 ||
		candidate.Generation() <= expected {
		return errors.New("mysql publication unavailable")
	}
	rows, rowsErr := candidate.detachedRows(ctx)
	if rowsErr != nil {
		return errors.New("mysql publication unavailable")
	}
	defer clearCandidateRows(&rows)
	transaction, err := p.database.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
		ReadOnly:  false,
	})
	if err != nil {
		return errors.New("mysql publication unavailable")
	}
	defer func() {
		if transaction != nil {
			_ = transaction.Rollback()
		}
	}()
	var lockValue int
	if err := transaction.QueryRowContext(ctx, queryMySQLPublicationLock).Scan(&lockValue); err != nil || lockValue != 1 {
		return errors.New("mysql publication unavailable")
	}
	var currentText string
	if expected == 0 {
		var empty bool
		if err := transaction.QueryRowContext(ctx, queryMySQLPublicationEmpty).Scan(&empty); err != nil || !empty {
			return errors.New("mysql publication unavailable")
		}
	} else {
		if err := transaction.QueryRowContext(ctx, queryMySQLPublicationCurrentLocked).Scan(&currentText); err != nil {
			return errors.New("mysql publication unavailable")
		}
		current, parseErr := parseGeneration(currentText)
		if parseErr != nil || current != expected {
			return errors.New("mysql publication unavailable")
		}
	}
	if rows.Current.Generation != rows.Final.Generation ||
		rows.Current.Generation != candidateGenerationText(candidate) {
		return errors.New("mysql publication unavailable")
	}
	if _, err := transaction.ExecContext(ctx, queryMySQLInsertGeneration, rows.Current.Generation); err != nil {
		return errors.New("mysql publication unavailable")
	}
	for _, row := range rows.Handles {
		if _, err := transaction.ExecContext(ctx, queryMySQLInsertHandle, row.Generation, row.HandleID); err != nil {
			return errors.New("mysql publication unavailable")
		}
	}
	for _, row := range rows.Profiles {
		if _, err := transaction.ExecContext(
			ctx, queryMySQLInsertProfile, row.Generation, row.ProfileID, row.Domain,
			row.Status, row.NotBeforeUTC, row.NotAfterUTC,
		); err != nil {
			return errors.New("mysql publication unavailable")
		}
	}
	for _, row := range rows.Credentials {
		if _, err := transaction.ExecContext(
			ctx, queryMySQLInsertCredential, row.Generation, row.ProfileID,
			row.Algorithm, row.Selector, row.PublicKeySPKI, row.HandleID,
		); err != nil {
			return errors.New("mysql publication unavailable")
		}
	}
	for _, row := range rows.Policies {
		if _, err := transaction.ExecContext(
			ctx, queryMySQLInsertPolicy, row.Generation, row.TenantID, row.Domain,
			row.Use, row.ProfileID, row.Status, row.Rollout, row.Compatibility,
			row.FeedbackRouteID,
		); err != nil {
			return errors.New("mysql publication unavailable")
		}
	}
	for _, row := range rows.KeyMaterial {
		if _, err := transaction.ExecContext(
			ctx, queryMySQLInsertKeyMaterial, row.Generation, row.TenantID,
			row.Domain, row.Use, row.HandleID, row.Algorithm, row.PublicSPKI,
			row.PrivatePKCS8,
		); err != nil {
			return errors.New("mysql publication unavailable")
		}
	}
	var handles, profiles, credentials, policies, keyMaterial int
	generation := rows.Current.Generation
	if err := transaction.QueryRowContext(
		ctx, queryMySQLValidatePublication,
		generation, generation, generation, generation, generation,
	).Scan(&handles, &profiles, &credentials, &policies, &keyMaterial); err != nil ||
		handles != len(rows.Handles) || profiles != len(rows.Profiles) ||
		credentials != len(rows.Credentials) || policies != len(rows.Policies) ||
		keyMaterial != len(rows.KeyMaterial) {
		return errors.New("mysql publication unavailable")
	}
	_, err = transaction.ExecContext(ctx, queryMySQLCommitPublication, generation)
	if err != nil {
		return errors.New("mysql publication unavailable")
	}
	if expected == 0 {
		_, err = transaction.ExecContext(ctx, queryMySQLFenceBootstrap, generation)
	} else {
		_, err = transaction.ExecContext(ctx, queryMySQLFencePublication, generation, currentText)
	}
	if err != nil {
		return errors.New("mysql publication unavailable")
	}
	if err := transaction.Commit(); err != nil {
		return errors.New("mysql publication unavailable")
	}
	transaction = nil
	return nil
}
