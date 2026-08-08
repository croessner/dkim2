package postgresql

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const terminalCall = `CALL dkim2_datasource.record_campaign_terminal($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`

// TerminalExecutor invokes only the fixed PostgreSQL 005 terminal procedure.
type TerminalExecutor struct{ pool *pgxpool.Pool }

// Close releases the dedicated terminal-closure pool.
func (e *TerminalExecutor) Close() {
	if e != nil && e.pool != nil {
		e.pool.Close()
		e.pool = nil
	}
}

// OpenTerminalExecutor verifies a closer-only PostgreSQL principal.
func OpenTerminalExecutor(ctx context.Context, config ConnectionConfig) (*TerminalExecutor, error) {
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
	var user, session string
	if err := pool.QueryRow(ctx, `SELECT current_user, session_user`).Scan(&user, &session); err != nil || user != config.User || session != config.User {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	for role, want := range map[string]bool{"dkim2_closer": true, "dkim2_purger": false, roleSnapshot: false, roleStager: false, roleActivator: false} {
		var member bool
		if err := pool.QueryRow(ctx, `SELECT pg_has_role(current_user,$1,'MEMBER')`, role).Scan(&member); err != nil || member != want {
			return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
	}
	valid = true
	return &TerminalExecutor{pool: pool}, nil
}

// RecordTerminal invokes once and reconciles an uncertain outcome by exact immutable row readback.
func (e *TerminalExecutor) RecordTerminal(ctx context.Context, record datasourceadmin.TerminalRecord) error {
	if e == nil || e.pool == nil || ctx == nil || !record.Valid() {
		return datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	operation := ""
	if err := record.Operation().WithValue(ctx, func(v string) error { operation = v; return nil }); err != nil {
		return datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	digest := record.CandidateDigest().Bytes()
	defer clear(digest)
	_, err := e.pool.Exec(ctx, terminalCall, operation, record.CandidateSchema(), record.SourceSchema(), strconv.FormatUint(record.SourceGeneration(), 10), strconv.FormatUint(record.CandidateGeneration(), 10), strconv.FormatUint(record.CurrentGeneration(), 10), digest, string(record.State()), record.Reason(), record.RecordedAt())
	if err == nil {
		return e.reconcile(ctx, record)
	}
	if reconcileErr := e.reconcile(ctx, record); reconcileErr == nil {
		return nil
	}
	return datasourceadmin.NewError(datasourceadmin.CodeReconcileRequired)
}

// ReadTerminal returns only an exact immutable terminal projection.
func (e *TerminalExecutor) ReadTerminal(ctx context.Context, operation datasourceadmin.OperationBinding) (datasourceadmin.TerminalRecord, bool, error) {
	if e == nil || e.pool == nil || ctx == nil || !operation.Initialized() {
		return datasourceadmin.TerminalRecord{}, false, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	value := ""
	_ = operation.WithValue(ctx, func(v string) error { value = v; return nil })
	var candidateSchema, sourceSchema, state, reason string
	var source, candidate, current string
	var digest []byte
	var when time.Time
	err := e.pool.QueryRow(ctx, `SELECT schema_version,source_schema,source_generation::text,candidate_generation::text,current_generation::text,candidate_digest,terminal_state,terminal_reason,terminal_time FROM dkim2_datasource.campaign_terminals WHERE operation_id=$1`, value).Scan(&candidateSchema, &sourceSchema, &source, &candidate, &current, &digest, &state, &reason, &when)
	if errors.Is(err, pgx.ErrNoRows) {
		return datasourceadmin.TerminalRecord{}, false, nil
	}
	if err != nil {
		return datasourceadmin.TerminalRecord{}, false, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	defer clear(digest)
	s, se := strconv.ParseUint(source, 10, 64)
	c, ce := strconv.ParseUint(candidate, 10, 64)
	cur, ue := strconv.ParseUint(current, 10, 64)
	d, de := datasourceadmin.ParseCandidateContentDigest(digest)
	if se != nil || ce != nil || ue != nil || de != nil {
		return datasourceadmin.TerminalRecord{}, false, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	r, re := datasourceadmin.NewTerminalRecord(operation, candidateSchema, sourceSchema, s, c, cur, d, datasourceadmin.TerminalState(state), reason, when.UTC())
	if re != nil {
		return datasourceadmin.TerminalRecord{}, false, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	return r, true, nil
}

func (e *TerminalExecutor) reconcile(ctx context.Context, expected datasourceadmin.TerminalRecord) error {
	actual, present, err := e.ReadTerminal(ctx, expected.Operation())
	if err != nil || !present || !terminalRecordEqual(actual, expected) {
		return errors.New("terminal unknown")
	}
	return nil
}
func terminalRecordEqual(a, b datasourceadmin.TerminalRecord) bool {
	return a.Operation().Equal(b.Operation()) && a.CandidateSchema() == b.CandidateSchema() && a.SourceSchema() == b.SourceSchema() && a.SourceGeneration() == b.SourceGeneration() && a.CandidateGeneration() == b.CandidateGeneration() && a.CurrentGeneration() == b.CurrentGeneration() && a.CandidateDigest().Equal(b.CandidateDigest()) && a.State() == b.State() && a.Reason() == b.Reason() && a.RecordedAt().Equal(b.RecordedAt())
}
