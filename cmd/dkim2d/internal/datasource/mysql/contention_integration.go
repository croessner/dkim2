//go:build datasourceintegration

package mysql

import (
	"context"
	"database/sql"
	"math"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

const (
	queryAdministrationConnectionID        = `SELECT CONNECTION_ID()`
	queryMySQLActivationContentionWaitEdge = `SELECT EXISTS (
    SELECT 1
      FROM performance_schema.data_lock_waits AS waits
      JOIN performance_schema.data_locks AS requested_lock
        ON requested_lock.ENGINE = waits.ENGINE
       AND requested_lock.ENGINE_LOCK_ID = waits.REQUESTING_ENGINE_LOCK_ID
      JOIN performance_schema.data_locks AS blocking_lock
        ON blocking_lock.ENGINE = waits.ENGINE
       AND blocking_lock.ENGINE_LOCK_ID = waits.BLOCKING_ENGINE_LOCK_ID
      JOIN performance_schema.threads AS requesting_thread
        ON requesting_thread.THREAD_ID = requested_lock.THREAD_ID
      JOIN performance_schema.threads AS blocking_thread
        ON blocking_thread.THREAD_ID = blocking_lock.THREAD_ID
     WHERE requesting_thread.PROCESSLIST_ID = ?
       AND blocking_thread.PROCESSLIST_ID = ?
       AND requested_lock.OBJECT_SCHEMA = DATABASE()
       AND requested_lock.OBJECT_NAME = 'dkim2_publication_lock'
       AND requested_lock.LOCK_STATUS = 'WAITING'
       AND blocking_lock.OBJECT_SCHEMA = requested_lock.OBJECT_SCHEMA
       AND blocking_lock.OBJECT_NAME = requested_lock.OBJECT_NAME
)`
	queryMariaDBActivationContentionWaitEdge = "SELECT EXISTS (\n" +
		"    SELECT 1\n" +
		"      FROM information_schema.INNODB_LOCK_WAITS AS waits\n" +
		"      JOIN information_schema.INNODB_TRX AS requesting_trx\n" +
		"        ON requesting_trx.trx_id = waits.requesting_trx_id\n" +
		"      JOIN information_schema.INNODB_TRX AS blocking_trx\n" +
		"        ON blocking_trx.trx_id = waits.blocking_trx_id\n" +
		"      JOIN information_schema.INNODB_LOCKS AS requested_lock\n" +
		"        ON requested_lock.lock_id = waits.requested_lock_id\n" +
		"      JOIN information_schema.INNODB_LOCKS AS blocking_lock\n" +
		"        ON blocking_lock.lock_id = waits.blocking_lock_id\n" +
		"     WHERE requesting_trx.trx_mysql_thread_id = ?\n" +
		"       AND blocking_trx.trx_mysql_thread_id = ?\n" +
		"       AND requested_lock.lock_table = CONCAT('`', DATABASE(), '`.`dkim2_publication_lock`')\n" +
		"       AND blocking_lock.lock_table = requested_lock.lock_table\n" +
		")"
)

// ActivationContentionObserver owns one integration-only MySQL-family observer pool.
type ActivationContentionObserver struct {
	database *sql.DB
	query    string
}

// OpenMySQLActivationContentionObserver opens a verified MySQL observer authority.
func OpenMySQLActivationContentionObserver(
	ctx context.Context,
	config ConnectionConfig,
) (*ActivationContentionObserver, error) {
	return openActivationContentionObserver(ctx, config, queryMySQLActivationContentionWaitEdge)
}

// OpenMariaDBActivationContentionObserver opens a verified MariaDB observer authority.
func OpenMariaDBActivationContentionObserver(
	ctx context.Context,
	config ConnectionConfig,
) (*ActivationContentionObserver, error) {
	return openActivationContentionObserver(ctx, config, queryMariaDBActivationContentionWaitEdge)
}

// openActivationContentionObserver opens one separate integration observer.
func openActivationContentionObserver(
	ctx context.Context,
	config ConnectionConfig,
	query string,
) (*ActivationContentionObserver, error) {
	if ctx == nil || query == "" {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	database, err := OpenDatabase(ctx, config)
	if err != nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return &ActivationContentionObserver{database: database, query: query}, nil
}

// ObserveWaitEdge proves one exact waiter-to-holder MySQL-family lock edge.
func (o *ActivationContentionObserver) ObserveWaitEdge(
	ctx context.Context,
	holderID uint64,
	waiterID uint64,
) (bool, error) {
	if ctx == nil || holderID == 0 || waiterID == 0 || holderID == waiterID ||
		holderID > math.MaxInt64 || waiterID > math.MaxInt64 {
		return false, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	if ctx.Err() != nil {
		return false, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	if o == nil || o.database == nil || o.query == "" {
		return false, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	var observed bool
	if err := o.database.QueryRowContext(
		ctx, o.query, int64(waiterID), int64(holderID),
	).Scan(&observed); err != nil {
		return false, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return observed, nil
}

// Close releases the integration-only observer pool.
func (o *ActivationContentionObserver) Close() {
	if o != nil && o.database != nil {
		_ = o.database.Close()
	}
}

// IntegrationConnectionID returns this transaction's exact server connection ID.
func (t *sqlAdministrationTransaction) IntegrationConnectionID(ctx context.Context) (uint64, error) {
	if ctx == nil || t == nil || t.transaction == nil {
		return 0, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	var id uint64
	if err := t.transaction.QueryRowContext(ctx, queryAdministrationConnectionID).Scan(&id); err != nil || id == 0 {
		return 0, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return id, nil
}
