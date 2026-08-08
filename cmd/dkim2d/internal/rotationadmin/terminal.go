package rotationadmin

import (
	"context"
	"time"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// AbortWithTerminal persists immutable abort evidence before changing the local
// journal. It permits only an exact staged nonactivating candidate to retire.
func AbortWithTerminal(ctx context.Context, journal *Journal, recorder datasourceadmin.TerminalRecorder, reason string, when time.Time) error {
	if ctx == nil || ctx.Err() != nil || journal == nil || recorder == nil || when.IsZero() || when.Location() != time.UTC || (reason != "operator_abort" && reason != "reconcile_abort") {
		return errInvalid
	}
	journal.mu.Lock()
	if journal.closed || (journal.state != StateStaged && journal.state != StateDNSInProgress && journal.state != StateDNSComplete && journal.state != StateReconcileRequired) || !journal.candidateDigest.Valid() {
		journal.mu.Unlock()
		return errConflict
	}
	operationText, schema, source, candidate, digest := journal.operation, journal.sourceSchema, journal.sourceGeneration, journal.candidateGeneration, journal.candidateDigest
	journal.mu.Unlock()
	operation, err := datasourceadmin.NewOperationBinding(operationText)
	if err != nil {
		return errConflict
	}
	terminal, err := datasourceadmin.NewTerminalRecord(operation, datasourceadmin.SchemaVersionV3, schema, source, candidate, source, candidateDigestFromContract(digest), datasourceadmin.TerminalAborted, reason, when)
	if err != nil {
		return errConflict
	}
	if err := recorder.RecordTerminal(ctx, terminal); err != nil {
		_ = journal.RequireReconciliation("terminal_abort")
		return errBackend
	}
	if err := journal.Abort(); err != nil {
		return errConflict
	}
	return nil
}

// candidateDigestFromContract converts the shared exact SHA-256 commitment to
// the datasource-owned opaque digest without exposing it to generic output.
func candidateDigestFromContract(digest admincontract.Digest) datasourceadmin.CandidateContentDigest {
	bytes := digest.Bytes()
	defer clear(bytes)
	result, _ := datasourceadmin.ParseCandidateContentDigest(bytes)
	return result
}
