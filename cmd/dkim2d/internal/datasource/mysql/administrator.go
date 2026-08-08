package mysql

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/sqlsnapshot"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
	driver "github.com/go-sql-driver/mysql"
)

const (
	mysqlInactiveRole        = "NONE"
	mysqlLockOperationColumn = "lock_operation_id"
	queryAdminLock           = `CALL dkim2_v3_lock_observe()`
	queryAdminLockForUpdate  = `CALL dkim2_v3_lock_for_update()`
	queryAdminCurrent        = `SELECT CAST(current_generation.generation AS CHAR), dataset.schema_version,
       dataset.dataset_state, dataset.operation_id, dataset.candidate_digest, CAST(dataset.source_generation AS CHAR),
       current_generation.candidate_digest, dataset.was_active
FROM dkim2_current_generation AS current_generation
JOIN dkim2_dataset_generations AS dataset USING (generation)
WHERE current_generation.singleton = 1`
	queryAdminCurrentForUpdate       = `CALL dkim2_v3_current_for_update()`
	queryAdminCandidateRootForUpdate = `CALL dkim2_v3_lock_candidate_root(?, ?, ?, ?)`
	queryAdminGenerations            = `SELECT CAST(generation AS CHAR), schema_version, dataset_state,
       operation_id, candidate_digest, CAST(source_generation AS CHAR), was_active
FROM dkim2_dataset_generations WHERE generation > ? ORDER BY generation LIMIT ?`
	queryAdminGenerationsForUpdate = queryAdminGenerations + ` FOR UPDATE`
	queryAdminClaim                = `CALL dkim2_v3_claim_lock(?, ?)`
	queryAdminRelease              = `CALL dkim2_v3_release_lock(?, ?)`
	queryAdminInsertGeneration     = `CALL dkim2_v3_insert_generation(?, ?, ?, ?)`
	queryAdminInsertHandle         = `CALL dkim2_v3_insert_handle(?, ?, ?, ?, ?)`
	queryAdminInsertProfile        = `CALL dkim2_v3_insert_profile(?, ?, ?, ?, ?, ?, ?, ?, ?)`
	queryAdminInsertCredential     = `CALL dkim2_v3_insert_credential(?, ?, ?, ?, ?, ?, ?, ?, ?)`
	queryAdminInsertPolicy         = `CALL dkim2_v3_insert_policy(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	queryAdminInsertKeyMaterial    = `CALL dkim2_v3_insert_key_material(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	queryAdminSeal                 = `CALL dkim2_v3_seal_generation(?, ?, ?, ?)`
	queryAdminActivate             = `CALL dkim2_v3_activate(?, ?, ?, ?, ?)`
	candidateRootDeniedMessage     = "dkim2 v3 candidate lock denied"
)

type sqlAdministrationConnector struct {
	database  *sql.DB
	mode      sqlsnapshot.AdministrationMode
	authority sqlsnapshot.AdministrationAuthority
}

// OpenAdministrator opens three distinct verified MySQL-family role pools.
func OpenAdministrator(
	ctx context.Context,
	snapshotConfig ConnectionConfig,
	stagingConfig ConnectionConfig,
	activationConfig ConnectionConfig,
	limits provider.Limits,
	generations datasourceadmin.GenerationLimits,
	pageSize int,
) (*sqlsnapshot.Administrator, error) {
	snapshot, err := openAdministrationConnector(ctx, snapshotConfig, sqlsnapshot.AdministrationSnapshot)
	if err != nil {
		return nil, err
	}
	stager, err := openAdministrationConnector(ctx, stagingConfig, sqlsnapshot.AdministrationStaging)
	if err != nil {
		snapshot.Close()
		return nil, err
	}
	activator, err := openAdministrationConnector(ctx, activationConfig, sqlsnapshot.AdministrationActivation)
	if err != nil {
		snapshot.Close()
		stager.Close()
		return nil, err
	}
	administrator, err := sqlsnapshot.NewAdministrator(
		snapshot, stager, activator, limits, generations, pageSize,
	)
	if err != nil {
		snapshot.Close()
		stager.Close()
		activator.Close()
		return nil, err
	}
	return administrator, nil
}

// openAdministrationConnector opens one exact role-scoped database pool.
func openAdministrationConnector(
	ctx context.Context,
	config ConnectionConfig,
	mode sqlsnapshot.AdministrationMode,
) (*sqlAdministrationConnector, error) {
	database, err := OpenDatabase(ctx, config)
	if err != nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	var effectiveUser string
	var effectiveRole sql.NullString
	if err := database.QueryRowContext(ctx, `SELECT CURRENT_USER(), CURRENT_ROLE()`).Scan(
		&effectiveUser, &effectiveRole,
	); err != nil {
		_ = database.Close()
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	user, _, present := strings.Cut(effectiveUser, "@")
	roleInactive := !effectiveRole.Valid || strings.ToUpper(effectiveRole.String) == mysqlInactiveRole
	if !present || user != config.User || !roleInactive {
		_ = database.Close()
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	authority, err := sqlsnapshot.NewAdministrationAuthority(effectiveUser)
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	return &sqlAdministrationConnector{database: database, mode: mode, authority: authority}, nil
}

// Authority returns the connector's opaque role identity.
func (c *sqlAdministrationConnector) Authority() sqlsnapshot.AdministrationAuthority {
	if c == nil {
		return sqlsnapshot.AdministrationAuthority{}
	}
	return c.authority
}

// Begin opens one role-compatible database session and transaction.
func (c *sqlAdministrationConnector) Begin(
	ctx context.Context,
	mode sqlsnapshot.AdministrationMode,
) (sqlsnapshot.AdministrationTransaction, error) {
	if c == nil || c.database == nil || mode != c.mode {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	connection, err := c.database.Conn(ctx)
	if err != nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	isolation := querySessionIsolation
	if mode != sqlsnapshot.AdministrationSnapshot {
		isolation = `SET SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE`
	}
	if _, err := connection.ExecContext(ctx, isolation); err != nil {
		_ = connection.Close()
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	options := &sql.TxOptions{Isolation: sql.LevelSerializable}
	if mode == sqlsnapshot.AdministrationSnapshot {
		options.Isolation = sql.LevelRepeatableRead
		options.ReadOnly = true
		if _, err := connection.ExecContext(ctx, querySessionReadOnly); err != nil {
			_ = connection.Close()
			return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
	}
	transaction, err := connection.BeginTx(ctx, options)
	if err != nil {
		_ = connection.Close()
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return &sqlAdministrationTransaction{
		transaction: transaction, connection: connection, mode: mode,
	}, nil
}

// Close releases one role-scoped database pool.
func (c *sqlAdministrationConnector) Close() {
	if c != nil && c.database != nil {
		_ = c.database.Close()
	}
}

type sqlAdministrationTransaction struct {
	transaction     *sql.Tx
	connection      *sql.Conn
	mode            sqlsnapshot.AdministrationMode
	lockRevision    uint64
	lockOperation   string
	candidateDigest []byte
}

// Isolation proves or returns the closed effective transaction properties.
func (t *sqlAdministrationTransaction) Isolation(ctx context.Context) (string, bool, error) {
	if t == nil || t.connection == nil {
		return "", false, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	isolation, readOnly, err := readAdministrationIsolation(ctx, t)
	if err != nil {
		return "", false, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return normalizeAdministrationIsolation(isolation), readOnly != 0, nil
}

// normalizeAdministrationIsolation accepts only the two configured strengths.
func normalizeAdministrationIsolation(value string) string {
	value = strings.ToLower(strings.ReplaceAll(value, "-", " "))
	if value == repeatableReadIsolation || value == serializableIsolation {
		return value
	}
	return ""
}

// readAdministrationIsolation supports both modern and legacy server variables.
func readAdministrationIsolation(ctx context.Context, t *sqlAdministrationTransaction) (string, int, error) {
	var isolation string
	var readOnly int
	err := t.queryRow(ctx, queryIsolation).Scan(&isolation, &readOnly)
	if err == nil {
		return isolation, readOnly, nil
	}
	err = t.queryRow(ctx, queryLegacyIsolation).Scan(&isolation, &readOnly)
	return isolation, readOnly, err
}

// ReadLock reads and optionally locks the singleton administration fence.
func (t *sqlAdministrationTransaction) ReadLock(ctx context.Context, locked bool) (uint64, *string, error) {
	query := queryAdminLock
	if locked && t.transaction != nil {
		query = queryAdminLockForUpdate
	}
	var revisionText string
	var owner *string
	if err := t.queryRow(ctx, query).Scan(&revisionText, &owner); err != nil {
		return 0, nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	revision, err := strconv.ParseUint(revisionText, 10, 64)
	if err != nil || revision == 0 {
		return 0, nil, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	if locked {
		t.lockRevision = revision
		if owner != nil {
			t.lockOperation = *owner
		}
	}
	return revision, owner, nil
}

// ReadCurrentOptional reads and optionally locks the singleton current fence.
func (t *sqlAdministrationTransaction) ReadCurrentOptional(ctx context.Context, locked bool) (sqlsnapshot.MetadataRow, bool, error) {
	query := queryAdminCurrent
	if locked && t.transaction != nil {
		query = queryAdminCurrentForUpdate
	}
	var row sqlsnapshot.MetadataRow
	err := t.queryRow(ctx, query).Scan(
		&row.Generation, &row.SchemaVersion, &row.DatasetState, &row.OperationID,
		&row.CandidateDigest, &row.SourceGeneration, &row.PointerDigest, &row.WasActive,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return sqlsnapshot.MetadataRow{}, false, nil
	}
	if err != nil {
		return sqlsnapshot.MetadataRow{}, false, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return row, true, nil
}

// LockCandidateRoot invokes the exact definer-owned committed-root lock.
func (t *sqlAdministrationTransaction) LockCandidateRoot(
	ctx context.Context,
	fence sqlsnapshot.CandidateRootFence,
) (sqlsnapshot.MetadataRow, error) {
	var row sqlsnapshot.MetadataRow
	var queryErr error
	if err := fence.WithProtectedValues(ctx, func(operation string, digest []byte) error {
		queryErr = candidateRootMySQLError(t.queryRow(
			ctx, queryAdminCandidateRootForUpdate, fence.Generation(),
			operation, digest, strconv.FormatUint(fence.Revision(), 10),
		).Scan(
			&row.Generation, &row.SchemaVersion, &row.DatasetState,
			&row.OperationID, &row.CandidateDigest, &row.SourceGeneration, &row.WasActive,
		))
		return nil
	}); err != nil {
		return sqlsnapshot.MetadataRow{}, err
	}
	return row, queryErr
}

// candidateRootMySQLError distinguishes exact denial from backend failure.
func candidateRootMySQLError(err error) error {
	if errors.Is(err, sql.ErrNoRows) || exactCandidateRootDenial(err) {
		return datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	return adminMySQLError(err)
}

// exactCandidateRootDenial accepts only the fixed definer-procedure signal.
func exactCandidateRootDenial(err error) bool {
	var mysqlError *driver.MySQLError
	return errors.As(err, &mysqlError) && mysqlError.Number == 1644 &&
		mysqlError.SQLState == [5]byte{'4', '5', '0', '0', '0'} &&
		mysqlError.Message == candidateRootDeniedMessage
}

// GenerationPage reads one deterministic metadata page.
func (t *sqlAdministrationTransaction) GenerationPage(ctx context.Context, after string, limit int, locked bool) ([]sqlsnapshot.MetadataRow, error) {
	query := queryAdminGenerations
	if locked && t.transaction != nil {
		query = queryAdminGenerationsForUpdate
	}
	rows, err := t.query(ctx, query, after, limit)
	if err != nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	defer func() { _ = rows.Close() }()
	output := make([]sqlsnapshot.MetadataRow, 0, limit)
	for rows.Next() {
		var row sqlsnapshot.MetadataRow
		if err := rows.Scan(&row.Generation, &row.SchemaVersion, &row.DatasetState, &row.OperationID, &row.CandidateDigest, &row.SourceGeneration, &row.WasActive); err != nil {
			return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
		output = append(output, row)
	}
	if rows.Err() != nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return output, nil
}

// HandlePageFor reads one explicit generation handle page.
func (t *sqlAdministrationTransaction) HandlePageFor(ctx context.Context, generation, after string, limit int) ([]sqlsnapshot.HandleRow, error) {
	rows, err := t.query(ctx, queryHandles, generation, after, limit)
	if err != nil {
		return nil, adminMySQLError(err)
	}
	defer func() { _ = rows.Close() }()
	output := make([]sqlsnapshot.HandleRow, 0, limit)
	for rows.Next() {
		var row sqlsnapshot.HandleRow
		if rows.Scan(&row.Generation, &row.HandleID) != nil {
			return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
		output = append(output, row)
	}
	return output, adminMySQLError(rows.Err())
}

// ProfilePageFor reads one explicit generation profile page.
func (t *sqlAdministrationTransaction) ProfilePageFor(ctx context.Context, generation, after string, limit int) ([]sqlsnapshot.ProfileRow, error) {
	rows, err := t.query(ctx, queryProfiles, generation, after, limit)
	if err != nil {
		return nil, adminMySQLError(err)
	}
	defer func() { _ = rows.Close() }()
	output := make([]sqlsnapshot.ProfileRow, 0, limit)
	for rows.Next() {
		var row sqlsnapshot.ProfileRow
		if rows.Scan(&row.Generation, &row.ProfileID, &row.Domain, &row.Status, &row.NotBeforeUTC, &row.NotAfterUTC) != nil {
			return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
		output = append(output, row)
	}
	return output, adminMySQLError(rows.Err())
}

// CredentialPageFor reads one explicit generation credential page.
func (t *sqlAdministrationTransaction) CredentialPageFor(ctx context.Context, generation, profile, algorithm string, limit int) ([]sqlsnapshot.CredentialRow, error) {
	rows, err := t.query(ctx, queryCredentials, generation, profile, algorithm, limit)
	if err != nil {
		return nil, adminMySQLError(err)
	}
	defer func() { _ = rows.Close() }()
	output := make([]sqlsnapshot.CredentialRow, 0, limit)
	for rows.Next() {
		var row sqlsnapshot.CredentialRow
		if rows.Scan(&row.Generation, &row.ProfileID, &row.Algorithm, &row.Selector, &row.PublicKeySPKI, &row.HandleID) != nil {
			return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
		output = append(output, row)
	}
	return output, adminMySQLError(rows.Err())
}

// PolicyPageFor reads one explicit generation policy page.
func (t *sqlAdministrationTransaction) PolicyPageFor(ctx context.Context, generation, tenant, domain, use string, limit int) ([]sqlsnapshot.PolicyRow, error) {
	rows, err := t.query(ctx, queryPolicies, generation, tenant, domain, use, limit)
	if err != nil {
		return nil, adminMySQLError(err)
	}
	defer func() { _ = rows.Close() }()
	output := make([]sqlsnapshot.PolicyRow, 0, limit)
	for rows.Next() {
		var row sqlsnapshot.PolicyRow
		if rows.Scan(&row.Generation, &row.TenantID, &row.Domain, &row.Use, &row.ProfileID, &row.Status, &row.Rollout, &row.Compatibility, &row.FeedbackRouteID) != nil {
			return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
		output = append(output, row)
	}
	return output, adminMySQLError(rows.Err())
}

// KeyMaterialPageFor reads one explicit generation private-key page.
func (t *sqlAdministrationTransaction) KeyMaterialPageFor(ctx context.Context, generation, after string, limit int) ([]sqlsnapshot.KeyMaterialRow, error) {
	rows, err := t.query(ctx, queryKeyMaterial, generation, after, limit)
	if err != nil {
		return nil, adminMySQLError(err)
	}
	defer func() { _ = rows.Close() }()
	output := make([]sqlsnapshot.KeyMaterialRow, 0, limit)
	for rows.Next() {
		var row sqlsnapshot.KeyMaterialRow
		if rows.Scan(&row.Generation, &row.TenantID, &row.Domain, &row.Use, &row.HandleID, &row.Algorithm, &row.PublicSPKI, &row.PrivatePKCS8) != nil {
			sqlsnapshot.ClearKeyMaterialRows(output)
			return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
		output = append(output, row)
	}
	if rows.Err() != nil {
		sqlsnapshot.ClearKeyMaterialRows(output)
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return output, nil
}

// ClaimLock invokes the fixed definer claim routine.
func (t *sqlAdministrationTransaction) ClaimLock(ctx context.Context, revision uint64, owner string) (int64, error) {
	_, err := t.exec(ctx, queryAdminClaim, strconv.FormatUint(revision, 10), owner)
	return successfulRoutine(err)
}

// ReleaseLock invokes the fixed definer release routine.
func (t *sqlAdministrationTransaction) ReleaseLock(ctx context.Context, revision uint64, owner string) (int64, error) {
	_, err := t.exec(ctx, queryAdminRelease, strconv.FormatUint(revision, 10), owner)
	return successfulRoutine(err)
}

// InsertGeneration invokes the fixed v3 root routine.
func (t *sqlAdministrationTransaction) InsertGeneration(ctx context.Context, row sqlsnapshot.MetadataRow) error {
	if row.OperationID == nil || t.lockRevision == 0 {
		return datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	t.lockOperation, t.candidateDigest = *row.OperationID, append([]byte(nil), row.CandidateDigest...)
	_, err := t.exec(ctx, queryAdminInsertGeneration, row.Generation, t.lockOperation, t.candidateDigest, row.SourceGeneration, strconv.FormatUint(t.lockRevision, 10))
	return adminMySQLError(err)
}

// InsertRows invokes only fixed operation-bound v3 child routines.
func (t *sqlAdministrationTransaction) InsertRows(ctx context.Context, rows sqlsnapshot.DatasetRows) error {
	if t.lockRevision == 0 || t.lockOperation == "" || len(t.candidateDigest) != 32 {
		return datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	extra := []any{t.lockOperation, t.candidateDigest, strconv.FormatUint(t.lockRevision, 10)}
	for _, row := range rows.Handles {
		if _, err := t.exec(ctx, queryAdminInsertHandle, append([]any{row.Generation, row.HandleID}, extra...)...); err != nil {
			return adminMySQLError(err)
		}
	}
	for _, row := range rows.Profiles {
		if _, err := t.exec(ctx, queryAdminInsertProfile, append([]any{row.Generation, row.ProfileID, row.Domain, row.Status, row.NotBeforeUTC, row.NotAfterUTC}, extra...)...); err != nil {
			return adminMySQLError(err)
		}
	}
	for _, row := range rows.Credentials {
		if _, err := t.exec(ctx, queryAdminInsertCredential, append([]any{row.Generation, row.ProfileID, row.Algorithm, row.Selector, row.PublicKeySPKI, row.HandleID}, extra...)...); err != nil {
			return adminMySQLError(err)
		}
	}
	for _, row := range rows.Policies {
		if _, err := t.exec(ctx, queryAdminInsertPolicy, append([]any{row.Generation, row.TenantID, row.Domain, row.Use, row.ProfileID, row.Status, row.Rollout, row.Compatibility, row.FeedbackRouteID}, extra...)...); err != nil {
			return adminMySQLError(err)
		}
	}
	for _, row := range rows.KeyMaterial {
		if _, err := t.exec(ctx, queryAdminInsertKeyMaterial, append([]any{row.Generation, row.TenantID, row.Domain, row.Use, row.HandleID, row.Algorithm, row.PublicSPKI, row.PrivatePKCS8}, extra...)...); err != nil {
			return adminMySQLError(err)
		}
	}
	return nil
}

// SealGeneration invokes the exact operation-bound seal routine.
func (t *sqlAdministrationTransaction) SealGeneration(ctx context.Context, generation, operation string, digest []byte) (int64, error) {
	_, err := t.exec(ctx, queryAdminSeal, generation, operation, digest, strconv.FormatUint(t.lockRevision, 10))
	return successfulRoutine(err)
}

// ActivateCurrent delegates the complete atomic pointer transition to one definer routine.
func (t *sqlAdministrationTransaction) ActivateCurrent(
	ctx context.Context,
	current sqlsnapshot.CurrentPointerFence,
	candidate sqlsnapshot.CandidateRootFence,
) (int64, error) {
	if t.mode != sqlsnapshot.AdministrationActivation || t.transaction == nil {
		return 0, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	var mutationErr error
	if err := candidate.WithProtectedValues(ctx, func(operation string, digest []byte) error {
		_, mutationErr = t.transaction.ExecContext(
			ctx, queryAdminActivate, current.Generation(), candidate.Generation(),
			operation, digest, strconv.FormatUint(candidate.Revision(), 10),
		)
		return nil
	}); err != nil {
		return 0, err
	}
	return successfulRoutine(mutationErr)
}

// Commit completes a normal transaction or releases an activation session.
func (t *sqlAdministrationTransaction) Commit(_ context.Context) error {
	if t == nil {
		return datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	if t.transaction != nil {
		err := t.transaction.Commit()
		t.transaction = nil
		t.closeConnection()
		return adminMySQLError(err)
	}
	t.closeConnection()
	return nil
}

// Rollback aborts a normal transaction or releases an activation session.
func (t *sqlAdministrationTransaction) Rollback(_ context.Context) error {
	if t == nil {
		return nil
	}
	if t.transaction != nil {
		err := t.transaction.Rollback()
		t.transaction = nil
		t.closeConnection()
		if !errors.Is(err, sql.ErrTxDone) {
			return adminMySQLError(err)
		}
		return nil
	}
	t.closeConnection()
	return nil
}

// queryRow selects the transaction or activation connection executor.
func (t *sqlAdministrationTransaction) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	if t.transaction != nil {
		return t.transaction.QueryRowContext(ctx, query, args...)
	}
	return t.connection.QueryRowContext(ctx, query, args...)
}

// query selects the transaction or activation connection executor.
func (t *sqlAdministrationTransaction) query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if t.transaction != nil {
		return t.transaction.QueryContext(ctx, query, args...)
	}
	return t.connection.QueryContext(ctx, query, args...)
}

// exec selects the transaction or activation connection executor.
func (t *sqlAdministrationTransaction) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if t.transaction != nil {
		return t.transaction.ExecContext(ctx, query, args...)
	}
	return t.connection.ExecContext(ctx, query, args...)
}

// closeConnection clears protected state and returns the session to its pool.
func (t *sqlAdministrationTransaction) closeConnection() {
	clear(t.candidateDigest)
	t.candidateDigest = nil
	t.lockOperation = ""
	t.lockRevision = 0
	if t.connection != nil {
		_ = t.connection.Close()
		t.connection = nil
	}
}

// successfulRoutine maps one signaled routine outcome into an exact row result.
func successfulRoutine(err error) (int64, error) {
	if err != nil {
		return 0, adminMySQLError(err)
	}
	return 1, nil
}

// adminMySQLError maps every driver detail into a content-free class.
func adminMySQLError(err error) error {
	if err == nil {
		return nil
	}
	return datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
}
