package mysql

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// TerminalExecutor invokes only the fixed MySQL/MariaDB 005 terminal procedure.
type TerminalExecutor struct{ database *sql.DB }

// OpenTerminalExecutor verifies a distinct closer login.
func OpenTerminalExecutor(ctx context.Context, config ConnectionConfig) (*TerminalExecutor, error) { //nolint:dupl // Closer and purger retain distinct authority constructors.
	db, err := OpenDatabase(ctx, config)
	if err != nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	good := false
	defer func() {
		if !good {
			_ = db.Close()
		}
	}()
	var user string
	var role sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT CURRENT_USER(), CURRENT_ROLE()`).Scan(&user, &role); err != nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	name, _, ok := strings.Cut(user, "@")
	if !ok || name != config.User || (role.Valid && strings.ToUpper(role.String) != mysqlInactiveRole) {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	good = true
	return &TerminalExecutor{database: db}, nil
}

// RecordTerminal invokes once and accepts only exact immutable-row reconciliation.
func (e *TerminalExecutor) RecordTerminal(ctx context.Context, r datasourceadmin.TerminalRecord) error {
	if e == nil || e.database == nil || ctx == nil || !r.Valid() {
		return datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	op := ""
	if err := r.Operation().WithValue(ctx, func(v string) error { op = v; return nil }); err != nil {
		return datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	d := r.CandidateDigest().Bytes()
	defer clear(d)
	_, err := e.database.ExecContext(ctx, `CALL dkim2_v3_record_campaign_terminal(?,?,?,?,?,?,?,?,?,?)`, op, r.CandidateSchema(), r.SourceSchema(), strconv.FormatUint(r.SourceGeneration(), 10), strconv.FormatUint(r.CandidateGeneration(), 10), strconv.FormatUint(r.CurrentGeneration(), 10), d, string(r.State()), r.Reason(), r.RecordedAt())
	if err == nil {
		actual, present, readErr := e.ReadTerminal(ctx, r.Operation())
		if present && readErr == nil && terminalEqual(actual, r) {
			return nil
		}
	}
	return datasourceadmin.NewError(datasourceadmin.CodeReconcileRequired)
}

// ReadTerminal projects one exact immutable terminal row or proven absence.
func (e *TerminalExecutor) ReadTerminal(ctx context.Context, op datasourceadmin.OperationBinding) (datasourceadmin.TerminalRecord, bool, error) {
	if e == nil || e.database == nil || ctx == nil || !op.Initialized() {
		return datasourceadmin.TerminalRecord{}, false, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	v := ""
	_ = op.WithValue(ctx, func(s string) error { v = s; return nil })
	var candidateSchema, sourceSchema, state, reason, source, candidate, current string
	var digest []byte
	var when time.Time
	err := e.database.QueryRowContext(ctx, `SELECT schema_version,source_schema,CAST(source_generation AS CHAR),CAST(candidate_generation AS CHAR),CAST(current_generation AS CHAR),candidate_digest,terminal_state,terminal_reason,terminal_time FROM dkim2_campaign_terminals WHERE operation_id=?`, v).Scan(&candidateSchema, &sourceSchema, &source, &candidate, &current, &digest, &state, &reason, &when)
	if err == sql.ErrNoRows {
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
	r, re := datasourceadmin.NewTerminalRecord(op, candidateSchema, sourceSchema, s, c, cur, d, datasourceadmin.TerminalState(state), reason, when.UTC())
	if re != nil {
		return datasourceadmin.TerminalRecord{}, false, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	return r, true, nil
}

// Close releases the dedicated closer login.
func (e *TerminalExecutor) Close() {
	if e != nil && e.database != nil {
		_ = e.database.Close()
		e.database = nil
	}
}

func terminalEqual(left, right datasourceadmin.TerminalRecord) bool {
	return left.Operation().Equal(right.Operation()) && left.SourceSchema() == right.SourceSchema() && left.SourceGeneration() == right.SourceGeneration() && left.CandidateGeneration() == right.CandidateGeneration() && left.CurrentGeneration() == right.CurrentGeneration() && left.CandidateDigest().Equal(right.CandidateDigest()) && left.State() == right.State() && left.Reason() == right.Reason() && left.RecordedAt().Equal(right.RecordedAt())
}
