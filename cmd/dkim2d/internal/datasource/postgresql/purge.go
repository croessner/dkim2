package postgresql

import (
	"context"
	"errors"
	"strconv"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/rotationadmin"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	queryPurgeGeneration = `CALL dkim2_datasource.purge_generation($1, $2, $3, $4, $5, $6, $7)`
	queryPurgeCurrent    = `SELECT generation::text FROM dkim2_datasource.current_generation WHERE singleton = TRUE`
	queryPurgePresent    = `SELECT EXISTS(SELECT 1 FROM dkim2_datasource.dataset_generations WHERE generation = $1)`
	queryPurgeTarget     = `SELECT schema_version, dataset_state, candidate_digest, was_active
FROM dkim2_datasource.dataset_generations WHERE generation = $1`
	queryPurgeReceipt = `SELECT schema_version, lifecycle, content_digest, policy_version, purge_plan_digest
FROM dkim2_datasource.purge_audit_receipts WHERE generation = $1`
)

// PurgeExecutor owns the PostgreSQL fourth-role destruction session. It has no
// direct table mutation API; the schema-owned routine is the only write path.
type PurgeExecutor struct{ pool *pgxpool.Pool }

// OpenPurgeExecutor opens and verifies a dedicated PostgreSQL purge principal.
func OpenPurgeExecutor(ctx context.Context, config ConnectionConfig) (*PurgeExecutor, error) {
	if ctx == nil || config.Validate() != nil {
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
	valid := false
	defer func() {
		if !valid {
			pool.Close()
		}
	}()
	var currentUser, sessionUser string
	if err := pool.QueryRow(ctx, `SELECT current_user, session_user`).Scan(&currentUser, &sessionUser); err != nil || currentUser != config.User || sessionUser != config.User {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	for role, expected := range map[string]bool{"dkim2_purger": true, "dkim2_snapshot": false, "dkim2_stager": false, "dkim2_activator": false, "dkim2_publisher": false} {
		var member bool
		if err := pool.QueryRow(ctx, `SELECT pg_has_role(current_user, $1, 'MEMBER')`, role).Scan(&member); err != nil || member != expected {
			return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
	}
	valid = true
	return &PurgeExecutor{pool: pool}, nil
}

// Close releases the dedicated purge pool.
func (e *PurgeExecutor) Close() {
	if e != nil && e.pool != nil {
		e.pool.Close()
		e.pool = nil
	}
}

// Purge invokes the fixed schema-owned procedure exactly once per protected
// target. A transport or commit error remains unknown and is never retried.
func (e *PurgeExecutor) Purge(ctx context.Context, command rotationadmin.PurgeCommand) (rotationadmin.PurgeExecutionResult, error) {
	if e == nil || e.pool == nil || ctx == nil || ctx.Err() != nil {
		return rotationadmin.PurgeExecutionResult{Unknown: true}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	err := command.WithTargets(ctx, func(targets []admincontract.PurgeTarget) error {
		plan := command.PlanDigest().Bytes()
		defer clear(plan)
		for _, target := range targets {
			digest := target.ContentDigest.Bytes()
			_, callErr := e.pool.Exec(ctx, queryPurgeGeneration, strconv.FormatUint(target.Generation, 10), target.Schema, digest,
				strconv.FormatUint(command.CurrentGeneration(), 10), target.Lifecycle, command.PolicyVersion(), plan)
			clear(digest)
			if callErr != nil {
				return errors.New("postgresql purge outcome unknown")
			}
		}
		return nil
	})
	if err != nil {
		return rotationadmin.PurgeExecutionResult{Unknown: true}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return rotationadmin.PurgeExecutionResult{Committed: true}, nil
}

// Reconcile reads exact target and receipt state after an uncertain procedure
// outcome. It repeats a call only after proving that target never committed.
func (e *PurgeExecutor) Reconcile(ctx context.Context, command rotationadmin.PurgeCommand) (rotationadmin.PurgeExecutionResult, error) {
	if e == nil || e.pool == nil || ctx == nil || ctx.Err() != nil {
		return rotationadmin.PurgeExecutionResult{Unknown: true}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	err := command.WithTargets(ctx, func(targets []admincontract.PurgeTarget) error {
		var current string
		if err := e.pool.QueryRow(ctx, queryPurgeCurrent).Scan(&current); err != nil || current != strconv.FormatUint(command.CurrentGeneration(), 10) {
			return errors.New("postgresql purge fence unavailable")
		}
		plan := command.PlanDigest().Bytes()
		defer clear(plan)
		for _, target := range targets {
			var present bool
			if err := e.pool.QueryRow(ctx, queryPurgePresent, strconv.FormatUint(target.Generation, 10)).Scan(&present); err != nil {
				return errors.New("postgresql purge reconciliation unavailable")
			}
			if present {
				if err := e.reconcilePresentTarget(ctx, command, target, plan); err != nil {
					return err
				}
				continue
			}
			var schema, lifecycle, policy string
			var digest, receiptPlan []byte
			if err := e.pool.QueryRow(ctx, queryPurgeReceipt, strconv.FormatUint(target.Generation, 10)).Scan(&schema, &lifecycle, &digest, &policy, &receiptPlan); err != nil {
				return errors.New("postgresql purge reconciliation unavailable")
			}
			targetDigest := target.ContentDigest.Bytes()
			valid := schema == target.Schema && lifecycle == target.Lifecycle && policy == command.PolicyVersion() &&
				bytesEqual(digest, targetDigest) && bytesEqual(receiptPlan, plan)
			clear(targetDigest)
			clear(digest)
			clear(receiptPlan)
			if !valid {
				return errors.New("postgresql purge reconciliation unavailable")
			}
		}
		return nil
	})
	if err != nil {
		return rotationadmin.PurgeExecutionResult{Unknown: true}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return rotationadmin.PurgeExecutionResult{Committed: true}, nil
}

// reconcilePresentTarget proves that one target never committed before the
// fixed routine is called again with unchanged protected command facts.
func (e *PurgeExecutor) reconcilePresentTarget(ctx context.Context, command rotationadmin.PurgeCommand, target admincontract.PurgeTarget, plan []byte) error {
	var schema, state string
	var digest []byte
	var wasActive bool
	if err := e.pool.QueryRow(ctx, queryPurgeTarget, strconv.FormatUint(target.Generation, 10)).Scan(&schema, &state, &digest, &wasActive); err != nil {
		return errors.New("postgresql purge reconciliation unavailable")
	}
	targetDigest := target.ContentDigest.Bytes()
	valid := schema == target.Schema && state == "committed" && wasActive == (target.Lifecycle == "active_history") && bytesEqual(digest, targetDigest)
	clear(digest)
	clear(targetDigest)
	if !valid {
		return errors.New("postgresql purge reconciliation unavailable")
	}
	digest = target.ContentDigest.Bytes()
	defer clear(digest)
	if _, err := e.pool.Exec(ctx, queryPurgeGeneration, strconv.FormatUint(target.Generation, 10), target.Schema, digest,
		strconv.FormatUint(command.CurrentGeneration(), 10), target.Lifecycle, command.PolicyVersion(), plan); err != nil {
		return errors.New("postgresql purge outcome unknown")
	}
	return nil
}

// bytesEqual compares bounded digest commitments without early exit.
func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
