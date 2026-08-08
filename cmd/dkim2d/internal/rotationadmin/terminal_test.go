package rotationadmin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

type abortTerminalFake struct {
	record datasourceadmin.TerminalRecord
	err    error
	calls  int
}

func (f *abortTerminalFake) RecordTerminal(_ context.Context, record datasourceadmin.TerminalRecord) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	if f.record.Valid() {
		if !terminalRecordsEqual(f.record, record) {
			return errors.New("foreign terminal")
		}
		return nil
	}
	f.record = record
	return nil
}

func (f *abortTerminalFake) ReadTerminal(context.Context, datasourceadmin.OperationBinding) (datasourceadmin.TerminalRecord, bool, error) {
	return f.record, f.record.Valid(), nil
}

func terminalRecordsEqual(left, right datasourceadmin.TerminalRecord) bool {
	return left.Valid() && right.Valid() && left.Operation().Equal(right.Operation()) && left.CandidateSchema() == right.CandidateSchema() && left.SourceSchema() == right.SourceSchema() && left.SourceGeneration() == right.SourceGeneration() && left.CandidateGeneration() == right.CandidateGeneration() && left.CurrentGeneration() == right.CurrentGeneration() && left.CandidateDigest().Equal(right.CandidateDigest()) && left.State() == right.State() && left.Reason() == right.Reason()
}

// TestAbortWithTerminalIsEvidenceFirstAndIdempotent proves a retry can reuse
// durable abort evidence while an uncertain write never aborts the journal.
func TestAbortWithTerminalIsEvidenceFirstAndIdempotent(t *testing.T) {
	plan, prepared := preparedCampaign(t, 1)
	defer plan.Close()     //nolint:errcheck // Test-owned protected values are closed best-effort.
	defer prepared.Close() //nolint:errcheck // Test-owned protected values are closed best-effort.
	journal, err := NewJournal(plan)
	if err != nil || journal.BeginPreparing() != nil || journal.RecordPrepared(prepared) != nil || journal.RecordStaged(mustCandidateDigest(t, prepared)) != nil {
		t.Fatal("prepare staged journal")
	}
	fake := &abortTerminalFake{}
	if err := AbortWithTerminal(t.Context(), journal, fake, "operator_abort", time.Unix(2_000_000_000, 0).UTC()); err != nil || journal.State() != StateAborted || !fake.record.Valid() {
		t.Fatal("terminal evidence was not persisted before abort")
	}
	if err := AbortWithTerminal(t.Context(), journal, fake, "operator_abort", time.Unix(2_000_000_000, 0).UTC()); err == nil || fake.calls != 1 {
		t.Fatal("aborted journal retried terminal mutation")
	}
}

func TestAbortWithTerminalUnknownOutcomeRequiresReconciliation(t *testing.T) {
	plan, prepared := preparedCampaign(t, 1)
	defer plan.Close()     //nolint:errcheck // Test-owned protected values are closed best-effort.
	defer prepared.Close() //nolint:errcheck // Test-owned protected values are closed best-effort.
	journal, _ := NewJournal(plan)
	_ = journal.BeginPreparing()
	_ = journal.RecordPrepared(prepared)
	_ = journal.RecordStaged(mustCandidateDigest(t, prepared))
	fake := &abortTerminalFake{err: errors.New("unknown")}
	if err := AbortWithTerminal(t.Context(), journal, fake, "operator_abort", time.Unix(2_000_000_000, 0).UTC()); err == nil || journal.State() != StateReconcileRequired {
		t.Fatal("unknown terminal outcome aborted local journal")
	}
}
