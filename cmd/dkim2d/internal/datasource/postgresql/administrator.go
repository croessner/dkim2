package postgresql

import (
	"context"
	"errors"
	"strconv"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/sqlsnapshot"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	queryAdminIsolation = `SELECT current_setting('transaction_isolation'), current_setting('transaction_read_only')`
	queryAdminLock      = `SELECT lock_revision, lock_operation_id
FROM dkim2_datasource.administration_lock_observe()`
	queryAdminLockForUpdate = `SELECT lock_revision, lock_operation_id
FROM dkim2_datasource.administration_lock_for_update()`
	queryAdminCurrent = `SELECT current.generation::text, dataset.schema_version, dataset.dataset_state,
       dataset.operation_id, dataset.candidate_digest, current.candidate_digest,
       dataset.was_active
FROM dkim2_datasource.current_generation AS current
JOIN dkim2_datasource.dataset_generations AS dataset USING (generation)
WHERE current.singleton = TRUE`
	queryAdminCurrentForUpdate = queryAdminCurrent + ` FOR UPDATE OF current, dataset`
	queryAdminGenerations      = `SELECT generation::text, schema_version, dataset_state,
       operation_id, candidate_digest, was_active
FROM dkim2_datasource.dataset_generations
WHERE generation > $1 ORDER BY generation LIMIT $2`
	queryAdminGenerationsForUpdate   = queryAdminGenerations + ` FOR UPDATE`
	queryAdminCandidateRootForUpdate = `SELECT generation, schema_version, dataset_state,
       operation_id, candidate_digest, was_active
FROM dkim2_datasource.candidate_root_for_update($1, $2, $3)`
	queryAdminClaim            = `CALL dkim2_datasource.administration_lock_claim($1, $2)`
	queryAdminRelease          = `CALL dkim2_datasource.administration_lock_release($1, $2)`
	queryAdminInsertGeneration = `INSERT INTO dkim2_datasource.dataset_generations
(generation, schema_version, dataset_state, operation_id, candidate_digest, was_active)
VALUES ($1, 'dkim2-datasource-v3', 'staging', $2, $3, FALSE)`
	queryAdminInsertHandle  = `INSERT INTO dkim2_datasource.handles (generation, handle_id) VALUES ($1, $2)`
	queryAdminInsertProfile = `INSERT INTO dkim2_datasource.profiles
(generation, profile_id, signing_domain, record_status, not_before_utc, not_after_utc)
VALUES ($1, $2, $3, $4, $5, $6)`
	queryAdminInsertCredential = `INSERT INTO dkim2_datasource.credentials
(generation, profile_id, algorithm, selector, public_key_spki, handle_id)
VALUES ($1, $2, $3, $4, $5, $6)`
	queryAdminInsertPolicy = `INSERT INTO dkim2_datasource.policies
(generation, tenant_id, signing_domain, profile_use, profile_id, record_status, rollout, compatibility, feedback_route_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	queryAdminInsertKeyMaterial = `INSERT INTO dkim2_datasource.key_material
(generation, tenant_id, signing_domain, profile_use, handle_id, algorithm, public_key_spki, private_key_pkcs8)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	queryAdminSeal = `UPDATE dkim2_datasource.dataset_generations SET dataset_state = 'committed'
WHERE generation = $1 AND schema_version = 'dkim2-datasource-v3'
AND dataset_state = 'staging' AND operation_id = $2 AND candidate_digest = $3`
	queryAdminMarkActive = `UPDATE dkim2_datasource.dataset_generations SET was_active = TRUE
WHERE generation = $1 AND dataset_state = 'committed'`
	queryAdminInsertCurrent = `INSERT INTO dkim2_datasource.current_generation
(singleton, generation, candidate_digest) VALUES (TRUE, $1, $2)`
	queryAdminUpdateCurrent = `UPDATE dkim2_datasource.current_generation
SET generation = $1, candidate_digest = $2
WHERE singleton = TRUE AND generation = $3
  AND candidate_digest IS NOT DISTINCT FROM $4`
)

type pgxAdministrationConnector struct {
	pool      *pgxpool.Pool
	mode      sqlsnapshot.AdministrationMode
	authority sqlsnapshot.AdministrationAuthority
}

// OpenAdministrator opens three distinct verified PostgreSQL role pools.
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
	connectors := []*pgxAdministrationConnector{snapshot, stager, activator}
	roles := []string{snapshotConfig.User, stagingConfig.User, activationConfig.User}
	for index, connector := range connectors {
		if err := connector.rejectCrossRoleMembership(ctx, roles, index); err != nil {
			snapshot.Close()
			stager.Close()
			activator.Close()
			return nil, err
		}
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

// openAdministrationConnector opens one exact role-scoped pgx pool.
func openAdministrationConnector(
	ctx context.Context,
	config ConnectionConfig,
	mode sqlsnapshot.AdministrationMode,
) (*pgxAdministrationConnector, error) {
	poolConfig, err := newPoolConfig(config)
	if err != nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	var currentUser, sessionUser string
	if err := pool.QueryRow(ctx, `SELECT current_user, session_user`).Scan(&currentUser, &sessionUser); err != nil ||
		currentUser != config.User || sessionUser != config.User {
		pool.Close()
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	capabilities := map[sqlsnapshot.AdministrationMode]string{
		sqlsnapshot.AdministrationSnapshot:   "dkim2_snapshot",
		sqlsnapshot.AdministrationStaging:    "dkim2_stager",
		sqlsnapshot.AdministrationActivation: "dkim2_activator",
	}
	for candidateMode, role := range capabilities {
		var member bool
		if err := pool.QueryRow(ctx, `SELECT pg_has_role(current_user, $1, 'MEMBER')`, role).Scan(&member); err != nil ||
			member != (candidateMode == mode) {
			pool.Close()
			return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
	}
	var legacyPublisher bool
	if err := pool.QueryRow(ctx, `SELECT pg_has_role(current_user, 'dkim2_publisher', 'MEMBER')`).Scan(&legacyPublisher); err != nil || legacyPublisher {
		pool.Close()
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	authority, err := sqlsnapshot.NewAdministrationAuthority(currentUser)
	if err != nil {
		pool.Close()
		return nil, err
	}
	return &pgxAdministrationConnector{pool: pool, mode: mode, authority: authority}, nil
}

// rejectCrossRoleMembership prevents one authenticated principal from
// inheriting either of the other administration authorities.
func (c *pgxAdministrationConnector) rejectCrossRoleMembership(
	ctx context.Context,
	roles []string,
	self int,
) error {
	for index, role := range roles {
		if index == self {
			continue
		}
		var member bool
		if err := c.pool.QueryRow(
			ctx, `SELECT pg_has_role(current_user, $1, 'MEMBER')`, role,
		).Scan(&member); err != nil || member {
			return datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
	}
	return nil
}

// Authority returns the connector's opaque role identity.
func (c *pgxAdministrationConnector) Authority() sqlsnapshot.AdministrationAuthority {
	if c == nil {
		return sqlsnapshot.AdministrationAuthority{}
	}
	return c.authority
}

// Begin opens one exact role-compatible pgx transaction.
func (c *pgxAdministrationConnector) Begin(
	ctx context.Context,
	mode sqlsnapshot.AdministrationMode,
) (sqlsnapshot.AdministrationTransaction, error) {
	if c == nil || c.pool == nil || mode != c.mode {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	options := pgx.TxOptions{IsoLevel: pgx.Serializable}
	if mode == sqlsnapshot.AdministrationSnapshot {
		options.IsoLevel = pgx.RepeatableRead
		options.AccessMode = pgx.ReadOnly
	}
	tx, err := c.pool.BeginTx(ctx, options)
	if err != nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return &pgxAdministrationTransaction{tx: tx, mode: mode}, nil
}

// Close releases one role-scoped pgx pool.
func (c *pgxAdministrationConnector) Close() {
	if c != nil && c.pool != nil {
		c.pool.Close()
	}
}

type pgxAdministrationTransaction struct {
	tx   pgx.Tx
	mode sqlsnapshot.AdministrationMode
}

// Isolation proves the effective pgx transaction properties.
func (t *pgxAdministrationTransaction) Isolation(ctx context.Context) (string, bool, error) {
	var isolation, readOnly string
	if t == nil || t.tx == nil || t.tx.QueryRow(ctx, queryAdminIsolation).Scan(&isolation, &readOnly) != nil {
		return "", false, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return isolation, readOnly == "on", nil
}

// ReadLock reads and optionally row-locks the singleton administration fence.
func (t *pgxAdministrationTransaction) ReadLock(ctx context.Context, locked bool) (uint64, *string, error) {
	query := queryAdminLock
	if locked {
		query = queryAdminLockForUpdate
	}
	var revisionText string
	var owner *string
	if err := t.tx.QueryRow(ctx, query).Scan(&revisionText, &owner); err != nil {
		return 0, nil, administrationLockReadPGError(ctx, t.mode, locked, err)
	}
	revision, err := strconv.ParseUint(revisionText, 10, 64)
	if err != nil || revision == 0 {
		return 0, nil, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	return revision, owner, nil
}

// ReadCurrentOptional reads and optionally locks the singleton current fence.
func (t *pgxAdministrationTransaction) ReadCurrentOptional(ctx context.Context, locked bool) (MetadataRow, bool, error) {
	query := queryAdminCurrent
	if locked {
		query = queryAdminCurrentForUpdate
	}
	var row MetadataRow
	err := t.tx.QueryRow(ctx, query).Scan(
		&row.Generation, &row.SchemaVersion, &row.DatasetState, &row.OperationID,
		&row.CandidateDigest, &row.PointerDigest, &row.WasActive,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return MetadataRow{}, false, nil
	}
	if err != nil {
		return MetadataRow{}, false, currentFenceReadPGError(ctx, t.mode, locked, err)
	}
	return row, true, nil
}

// LockCandidateRoot locks and returns one exact committed candidate root.
func (t *pgxAdministrationTransaction) LockCandidateRoot(
	ctx context.Context,
	fence sqlsnapshot.CandidateRootFence,
) (MetadataRow, error) {
	var row MetadataRow
	var queryErr error
	if err := fence.WithProtectedValues(ctx, func(operation string, digest []byte) error {
		queryErr = candidateRootPGError(t.tx.QueryRow(
			ctx, queryAdminCandidateRootForUpdate, fence.Generation(), operation, digest,
		).Scan(
			&row.Generation, &row.SchemaVersion, &row.DatasetState,
			&row.OperationID, &row.CandidateDigest, &row.WasActive,
		))
		return nil
	}); err != nil {
		return MetadataRow{}, err
	}
	return row, queryErr
}

// candidateRootPGError distinguishes authoritative absence from backend failure.
func candidateRootPGError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	return adminPGError(err)
}

// administrationLockReadPGError classifies one physical singleton-lock read.
func administrationLockReadPGError(
	ctx context.Context,
	mode sqlsnapshot.AdministrationMode,
	locked bool,
	err error,
) error {
	return administrationFenceReadPGError(ctx, mode, locked, err)
}

// currentFenceReadPGError classifies one locked or unlocked current read.
func currentFenceReadPGError(
	ctx context.Context,
	mode sqlsnapshot.AdministrationMode,
	locked bool,
	err error,
) error {
	return administrationFenceReadPGError(ctx, mode, locked, err)
}

// administrationFenceReadPGError maps only a live activation serialization to conflict.
func administrationFenceReadPGError(
	ctx context.Context,
	mode sqlsnapshot.AdministrationMode,
	locked bool,
	err error,
) error {
	var postgresError *pgconn.PgError
	if ctx != nil && ctx.Err() == nil && mode == sqlsnapshot.AdministrationActivation && locked &&
		errors.As(err, &postgresError) && postgresError.Code == "40001" {
		return datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	return adminPGError(err)
}

// GenerationPage reads one deterministic metadata page.
func (t *pgxAdministrationTransaction) GenerationPage(ctx context.Context, after string, limit int, locked bool) ([]MetadataRow, error) {
	query := queryAdminGenerations
	if locked {
		query = queryAdminGenerationsForUpdate
	}
	rows, err := t.tx.Query(ctx, query, after, limit)
	if err != nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	defer rows.Close()
	output := make([]MetadataRow, 0, limit)
	for rows.Next() {
		var row MetadataRow
		if err := rows.Scan(
			&row.Generation, &row.SchemaVersion, &row.DatasetState,
			&row.OperationID, &row.CandidateDigest, &row.WasActive,
		); err != nil {
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
func (t *pgxAdministrationTransaction) HandlePageFor(ctx context.Context, generation, after string, limit int) ([]HandleRow, error) {
	return (&pgxTransaction{transaction: t.tx, generation: generation}).HandlePage(ctx, after, limit)
}

// ProfilePageFor reads one explicit generation profile page.
func (t *pgxAdministrationTransaction) ProfilePageFor(ctx context.Context, generation, after string, limit int) ([]ProfileRow, error) {
	return (&pgxTransaction{transaction: t.tx, generation: generation}).ProfilePage(ctx, after, limit)
}

// CredentialPageFor reads one explicit generation credential page.
func (t *pgxAdministrationTransaction) CredentialPageFor(ctx context.Context, generation, profile, algorithm string, limit int) ([]CredentialRow, error) {
	return (&pgxTransaction{transaction: t.tx, generation: generation}).CredentialPage(ctx, profile, algorithm, limit)
}

// PolicyPageFor reads one explicit generation policy page.
func (t *pgxAdministrationTransaction) PolicyPageFor(ctx context.Context, generation, tenant, domain, use string, limit int) ([]PolicyRow, error) {
	return (&pgxTransaction{transaction: t.tx, generation: generation}).PolicyPage(ctx, tenant, domain, use, limit)
}

// KeyMaterialPageFor reads one explicit generation private-key page.
func (t *pgxAdministrationTransaction) KeyMaterialPageFor(ctx context.Context, generation, after string, limit int) ([]KeyMaterialRow, error) {
	return (&pgxTransaction{transaction: t.tx, generation: generation}).KeyMaterialPage(ctx, after, limit)
}

// ClaimLock claims one exact ownerless revision.
func (t *pgxAdministrationTransaction) ClaimLock(ctx context.Context, revision uint64, owner string) (int64, error) {
	return t.execProcedure(ctx, queryAdminClaim, strconv.FormatUint(revision, 10), owner)
}

// ReleaseLock clears one exact owner and advances its revision.
func (t *pgxAdministrationTransaction) ReleaseLock(ctx context.Context, revision uint64, owner string) (int64, error) {
	return t.execProcedure(ctx, queryAdminRelease, strconv.FormatUint(revision, 10), owner)
}

// InsertGeneration inserts one exact v3 staging root.
func (t *pgxAdministrationTransaction) InsertGeneration(ctx context.Context, row MetadataRow) error {
	_, err := t.tx.Exec(ctx, queryAdminInsertGeneration, row.Generation, row.OperationID, row.CandidateDigest)
	return adminPGError(err)
}

// InsertRows inserts every complete candidate row through fixed statements.
func (t *pgxAdministrationTransaction) InsertRows(ctx context.Context, rows DatasetRows) error {
	for _, row := range rows.Handles {
		if _, err := t.tx.Exec(ctx, queryAdminInsertHandle, row.Generation, row.HandleID); err != nil {
			return adminPGError(err)
		}
	}
	for _, row := range rows.Profiles {
		if _, err := t.tx.Exec(ctx, queryAdminInsertProfile, row.Generation, row.ProfileID, row.Domain, row.Status, row.NotBeforeUTC, row.NotAfterUTC); err != nil {
			return adminPGError(err)
		}
	}
	for _, row := range rows.Credentials {
		if _, err := t.tx.Exec(ctx, queryAdminInsertCredential, row.Generation, row.ProfileID, row.Algorithm, row.Selector, row.PublicKeySPKI, row.HandleID); err != nil {
			return adminPGError(err)
		}
	}
	for _, row := range rows.Policies {
		if _, err := t.tx.Exec(ctx, queryAdminInsertPolicy, row.Generation, row.TenantID, row.Domain, row.Use, row.ProfileID, row.Status, row.Rollout, row.Compatibility, row.FeedbackRouteID); err != nil {
			return adminPGError(err)
		}
	}
	for _, row := range rows.KeyMaterial {
		if _, err := t.tx.Exec(ctx, queryAdminInsertKeyMaterial, row.Generation, row.TenantID, row.Domain, row.Use, row.HandleID, row.Algorithm, row.PublicSPKI, row.PrivatePKCS8); err != nil {
			return adminPGError(err)
		}
	}
	return nil
}

// SealGeneration seals only exact operation and digest metadata.
func (t *pgxAdministrationTransaction) SealGeneration(ctx context.Context, generation, operation string, digest []byte) (int64, error) {
	return t.execAffected(ctx, queryAdminSeal, generation, operation, digest)
}

// ActivateCurrent marks old history and advances generation plus active digest.
func (t *pgxAdministrationTransaction) ActivateCurrent(
	ctx context.Context,
	current sqlsnapshot.CurrentPointerFence,
	candidate sqlsnapshot.CandidateRootFence,
) (int64, error) {
	var affected int64
	var mutationErr error
	accessErr := candidate.WithProtectedValues(ctx, func(_ string, candidateDigest []byte) error {
		if current.Generation() == "0" {
			affected, mutationErr = t.execAffected(
				ctx, queryAdminInsertCurrent, candidate.Generation(), candidateDigest,
			)
			return nil
		}
		marked, err := t.execAffected(ctx, queryAdminMarkActive, current.Generation())
		if err != nil || marked != 1 {
			mutationErr = adminPGError(err)
			return nil
		}
		return current.WithPointerDigest(ctx, func(pointerDigest []byte) error {
			affected, mutationErr = t.execAffected(
				ctx, queryAdminUpdateCurrent, candidate.Generation(), candidateDigest,
				current.Generation(), pointerDigest,
			)
			return nil
		})
	})
	if accessErr != nil {
		return 0, accessErr
	}
	return affected, mutationErr
}

// execAffected executes one fixed mutation and returns its exact row count.
func (t *pgxAdministrationTransaction) execAffected(ctx context.Context, query string, arguments ...any) (int64, error) {
	result, err := t.tx.Exec(ctx, query, arguments...)
	if err != nil {
		return 0, adminPGError(err)
	}
	return result.RowsAffected(), nil
}

// execProcedure invokes one fixed definer procedure and reports one semantic mutation.
func (t *pgxAdministrationTransaction) execProcedure(ctx context.Context, query string, arguments ...any) (int64, error) {
	if _, err := t.tx.Exec(ctx, query, arguments...); err != nil {
		return 0, adminPGError(err)
	}
	return 1, nil
}

// Commit commits one explicit pgx administration transaction.
func (t *pgxAdministrationTransaction) Commit(ctx context.Context) error {
	if t == nil || t.tx == nil {
		return datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	err := t.tx.Commit(ctx)
	t.tx = nil
	return adminPGError(err)
}

// Rollback aborts one incomplete pgx administration transaction.
func (t *pgxAdministrationTransaction) Rollback(ctx context.Context) error {
	if t == nil || t.tx == nil {
		return nil
	}
	err := t.tx.Rollback(ctx)
	t.tx = nil
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return adminPGError(err)
}

// adminPGError maps every driver detail into a content-free class.
func adminPGError(err error) error {
	if err == nil {
		return nil
	}
	return datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
}
