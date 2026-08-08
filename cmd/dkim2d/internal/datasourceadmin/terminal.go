package datasourceadmin

import (
	"context"
	"time"
)

// TerminalState identifies the one-way durable outcome of a campaign.
type TerminalState string

const (
	// TerminalClosed proves a campaign candidate became the exact current generation.
	TerminalClosed TerminalState = "closed"
	// TerminalAborted proves a nonactivating candidate was explicitly retired.
	TerminalAborted TerminalState = "aborted"
)

// TerminalRecord is key-free immutable evidence for one terminal campaign outcome.
type TerminalRecord struct {
	operation           OperationBinding
	candidateSchema     string
	sourceSchema        string
	sourceGeneration    uint64
	candidateGeneration uint64
	currentGeneration   uint64
	candidateDigest     CandidateContentDigest
	state               TerminalState
	reason              string
	recordedAt          time.Time
}

// NewTerminalRecord validates exact one-way terminal evidence before it reaches a provider.
func NewTerminalRecord(operation OperationBinding, candidateSchema, sourceSchema string, source, candidate, current uint64, digest CandidateContentDigest, state TerminalState, reason string, recordedAt time.Time) (TerminalRecord, error) {
	record := TerminalRecord{operation: operation, candidateSchema: candidateSchema, sourceSchema: sourceSchema, sourceGeneration: source, candidateGeneration: candidate, currentGeneration: current, candidateDigest: digest, state: state, reason: reason, recordedAt: recordedAt}
	if !record.Valid() {
		return TerminalRecord{}, newError(CodeInvalid)
	}
	return record, nil
}

// Valid accepts only exact campaign terminal evidence and closed reason classes.
func (r TerminalRecord) Valid() bool {
	if !r.operation.Initialized() || r.candidateSchema != SchemaVersionV3 || (r.sourceSchema != SchemaVersionV2 && r.sourceSchema != SchemaVersionV3) || r.sourceGeneration == 0 || r.candidateGeneration <= r.sourceGeneration || r.currentGeneration == 0 || !r.candidateDigest.Valid() || r.recordedAt.IsZero() || r.recordedAt.Location() != time.UTC || len(r.reason) == 0 || len(r.reason) > 64 {
		return false
	}
	for _, character := range r.reason {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return (r.state == TerminalClosed && r.currentGeneration == r.candidateGeneration && r.reason == "activated") ||
		(r.state == TerminalAborted && r.currentGeneration == r.sourceGeneration && (r.reason == "operator_abort" || r.reason == "reconcile_abort"))
}

// Operation returns the protected terminal operation identity.
func (r TerminalRecord) Operation() OperationBinding { return r.operation }

// SourceGeneration returns the frozen source generation.
func (r TerminalRecord) SourceGeneration() uint64 { return r.sourceGeneration }

// CandidateSchema returns the immutable v3 candidate schema class.
func (r TerminalRecord) CandidateSchema() string { return r.candidateSchema }

// SourceSchema returns the exact frozen source datasource schema class.
func (r TerminalRecord) SourceSchema() string { return r.sourceSchema }

// CandidateGeneration returns the immutable campaign candidate generation.
func (r TerminalRecord) CandidateGeneration() uint64 { return r.candidateGeneration }

// CurrentGeneration returns the exact terminal current-pointer fence.
func (r TerminalRecord) CurrentGeneration() uint64 { return r.currentGeneration }

// CandidateDigest returns the exact immutable candidate commitment.
func (r TerminalRecord) CandidateDigest() CandidateContentDigest { return r.candidateDigest }

// State returns the closed terminal outcome class.
func (r TerminalRecord) State() TerminalState { return r.state }

// Reason returns the closed terminal reason class.
func (r TerminalRecord) Reason() string { return r.reason }

// RecordedAt returns the exact UTC terminal timestamp.
func (r TerminalRecord) RecordedAt() time.Time { return r.recordedAt }

// TerminalRecorder persists and reads exact one-way campaign terminal evidence.
type TerminalRecorder interface {
	RecordTerminal(context.Context, TerminalRecord) error
	ReadTerminal(context.Context, OperationBinding) (TerminalRecord, bool, error)
}
