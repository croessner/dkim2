package mysql

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/rotationadmin"
)

const (
	queryPurgeGeneration = `CALL dkim2_v3_purge_generation(?, ?, ?, ?, ?, ?, ?)`
	queryPurgeCurrent    = `SELECT CAST(generation AS CHAR) FROM dkim2_current_generation WHERE singleton = 1`
	queryPurgePresent    = `SELECT EXISTS(SELECT 1 FROM dkim2_dataset_generations WHERE generation = ?)`
	queryPurgeTarget     = `SELECT schema_version, dataset_state, candidate_digest, was_active
FROM dkim2_dataset_generations WHERE generation = ?`
	queryPurgeReceipt = `SELECT schema_version, lifecycle, content_digest, policy_version, purge_plan_digest
FROM dkim2_purge_audit_receipts WHERE generation = ?`
)

// PurgeExecutor owns a direct least-privilege MySQL-family purge login. Its
// only mutation is the fixed schema-owned destructive procedure.
type PurgeExecutor struct{ database *sql.DB }

// OpenPurgeExecutor opens and verifies a distinct direct MySQL/MariaDB login.
func OpenPurgeExecutor(ctx context.Context, config ConnectionConfig) (*PurgeExecutor, error) {
	database, err := OpenDatabase(ctx, config)
	if err != nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	valid := false
	defer func() {
		if !valid {
			_ = database.Close()
		}
	}()
	var effectiveUser string
	var effectiveRole sql.NullString
	if err := database.QueryRowContext(ctx, `SELECT CURRENT_USER(), CURRENT_ROLE()`).Scan(&effectiveUser, &effectiveRole); err != nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	user, _, present := strings.Cut(effectiveUser, "@")
	if !present || user != config.User || (effectiveRole.Valid && strings.ToUpper(effectiveRole.String) != "NONE") {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	valid = true
	return &PurgeExecutor{database: database}, nil
}

// Purge invokes the one fixed destructive routine once per exact target. It
// deliberately leaves an error result unknown rather than retrying a commit.
func (e *PurgeExecutor) Purge(ctx context.Context, command rotationadmin.PurgeCommand) (rotationadmin.PurgeExecutionResult, error) {
	if e == nil || e.database == nil || ctx == nil || ctx.Err() != nil {
		return rotationadmin.PurgeExecutionResult{Unknown: true}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	err := command.WithTargets(ctx, func(targets []admincontract.PurgeTarget) error {
		plan := command.PlanDigest().Bytes()
		defer clear(plan)
		for _, target := range targets {
			digest := target.ContentDigest.Bytes()
			_, err := e.database.ExecContext(ctx, queryPurgeGeneration, strconv.FormatUint(target.Generation, 10), target.Schema, digest,
				strconv.FormatUint(command.CurrentGeneration(), 10), target.Lifecycle, command.PolicyVersion(), plan)
			clear(digest)
			if err != nil {
				return errors.New("mysql purge outcome unknown")
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
// result. It repeats a call only after proving an exact target never committed.
func (e *PurgeExecutor) Reconcile(ctx context.Context, command rotationadmin.PurgeCommand) (rotationadmin.PurgeExecutionResult, error) {
	if e == nil || e.database == nil || ctx == nil || ctx.Err() != nil {
		return rotationadmin.PurgeExecutionResult{Unknown: true}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	err := command.WithTargets(ctx, func(targets []admincontract.PurgeTarget) error {
		var current string
		if err := e.database.QueryRowContext(ctx, queryPurgeCurrent).Scan(&current); err != nil || current != strconv.FormatUint(command.CurrentGeneration(), 10) {
			return errors.New("mysql purge fence unavailable")
		}
		plan := command.PlanDigest().Bytes()
		defer clear(plan)
		for _, target := range targets {
			var present bool
			if err := e.database.QueryRowContext(ctx, queryPurgePresent, strconv.FormatUint(target.Generation, 10)).Scan(&present); err != nil {
				return errors.New("mysql purge reconciliation unavailable")
			}
			if present {
				if err := e.reconcilePresentTarget(ctx, command, target, plan); err != nil {
					return err
				}
				continue
			}
			var schema, lifecycle, policy string
			var digest, receiptPlan []byte
			if err := e.database.QueryRowContext(ctx, queryPurgeReceipt, strconv.FormatUint(target.Generation, 10)).Scan(&schema, &lifecycle, &digest, &policy, &receiptPlan); err != nil {
				return errors.New("mysql purge reconciliation unavailable")
			}
			targetDigest := target.ContentDigest.Bytes()
			valid := schema == target.Schema && lifecycle == target.Lifecycle && policy == command.PolicyVersion() &&
				constantTimeEqual(digest, targetDigest) && constantTimeEqual(receiptPlan, plan)
			clear(targetDigest)
			clear(digest)
			clear(receiptPlan)
			if !valid {
				return errors.New("mysql purge reconciliation unavailable")
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
// fixed procedure is called again with unchanged protected command facts.
func (e *PurgeExecutor) reconcilePresentTarget(ctx context.Context, command rotationadmin.PurgeCommand, target admincontract.PurgeTarget, plan []byte) error {
	var schema, state string
	var digest []byte
	var wasActive bool
	if err := e.database.QueryRowContext(ctx, queryPurgeTarget, strconv.FormatUint(target.Generation, 10)).Scan(&schema, &state, &digest, &wasActive); err != nil {
		return errors.New("mysql purge reconciliation unavailable")
	}
	targetDigest := target.ContentDigest.Bytes()
	valid := schema == target.Schema && state == "committed" && wasActive == (target.Lifecycle == "active_history") && constantTimeEqual(digest, targetDigest)
	clear(digest)
	clear(targetDigest)
	if !valid {
		return errors.New("mysql purge reconciliation unavailable")
	}
	digest = target.ContentDigest.Bytes()
	defer clear(digest)
	if _, err := e.database.ExecContext(ctx, queryPurgeGeneration, strconv.FormatUint(target.Generation, 10), target.Schema, digest,
		strconv.FormatUint(command.CurrentGeneration(), 10), target.Lifecycle, command.PolicyVersion(), plan); err != nil {
		return errors.New("mysql purge outcome unknown")
	}
	return nil
}

// Close releases the independent destructive login.
func (e *PurgeExecutor) Close() {
	if e != nil && e.database != nil {
		_ = e.database.Close()
		e.database = nil
	}
}

// constantTimeEqual compares bounded commitments without exposing early exits.
func constantTimeEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
