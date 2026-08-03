//go:build datasourceintegration

package postgresql

import (
	"context"
	"math"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	queryAdministrationConnectionID   = `SELECT pg_backend_pid()`
	queryActivationContentionWaitEdge = `SELECT EXISTS (
    SELECT 1
      FROM pg_stat_activity AS waiter
     WHERE waiter.pid = $2
       AND waiter.wait_event_type = 'Lock'
       AND $1 = ANY(pg_blocking_pids($2))
)`
)

// ActivationContentionObserver owns one integration-only PostgreSQL observer pool.
type ActivationContentionObserver struct {
	pool *pgxpool.Pool
}

// OpenActivationContentionObserver opens a separate verified observer authority.
func OpenActivationContentionObserver(
	ctx context.Context,
	config ConnectionConfig,
) (*ActivationContentionObserver, error) {
	if ctx == nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	poolConfig, err := newPoolConfig(config)
	if err != nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return &ActivationContentionObserver{pool: pool}, nil
}

// ObserveWaitEdge proves one exact waiter-to-holder PostgreSQL lock edge.
func (o *ActivationContentionObserver) ObserveWaitEdge(
	ctx context.Context,
	holderID uint64,
	waiterID uint64,
) (bool, error) {
	if ctx == nil || holderID == 0 || waiterID == 0 ||
		holderID == waiterID || holderID > math.MaxInt32 || waiterID > math.MaxInt32 {
		return false, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	if ctx.Err() != nil {
		return false, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	if o == nil || o.pool == nil {
		return false, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	var observed bool
	if err := o.pool.QueryRow(
		ctx, queryActivationContentionWaitEdge, int32(holderID), int32(waiterID),
	).Scan(&observed); err != nil {
		return false, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return observed, nil
}

// Close releases the integration-only observer pool.
func (o *ActivationContentionObserver) Close() {
	if o != nil && o.pool != nil {
		o.pool.Close()
	}
}

// IntegrationConnectionID returns this transaction's exact PostgreSQL backend PID.
func (t *pgxAdministrationTransaction) IntegrationConnectionID(ctx context.Context) (uint64, error) {
	if ctx == nil || t == nil || t.tx == nil {
		return 0, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	var id int32
	if err := t.tx.QueryRow(ctx, queryAdministrationConnectionID).Scan(&id); err != nil || id <= 0 {
		return 0, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return uint64(id), nil
}
