package service

import (
	"strings"
	"testing"
)

// TestNewResultRejectsUnknownAndImpossibleFacts verifies fail-closed result ownership.
func TestNewResultRejectsUnknownAndImpossibleFacts(t *testing.T) {
	tests := []struct {
		name       string
		state      State
		custody    Custody
		reason     Reason
		checks     []CheckFact
		signatures []SignatureSetFact
	}{
		{name: "unknown state", state: State("future"), custody: CustodyNotPresent, reason: ReasonNone},
		{name: "unknown custody", state: StatePERMERROR, custody: Custody("future"), reason: ReasonInternalContract},
		{name: "pass without custody evaluation", state: StatePASS, custody: CustodyNotEvaluated, reason: ReasonNone},
		{name: "pass with terminal custody", state: StatePASS, custody: CustodyTerminalNDRequiresOOB, reason: ReasonNone},
		{name: "unknown reason", state: StatePERMERROR, custody: CustodyNotEvaluated, reason: Reason("raw-secret")},
		{name: "unknown check", state: StatePERMERROR, custody: CustodyNotEvaluated, reason: ReasonInternalContract, checks: []CheckFact{{Class: CheckClass("raw-secret"), Reason: ReasonInternalContract}}},
		{name: "unknown signature", state: StatePERMERROR, custody: CustodyNotPresent, reason: ReasonInternalContract, signatures: []SignatureSetFact{{Algorithm: Algorithm("raw-secret"), Status: SignaturePASS, Reason: ReasonNone}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := newResult(tt.state, tt.custody, Target{}, tt.reason, tt.checks, tt.signatures)
			if result.State() != StatePERMERROR || result.Custody() != CustodyNotEvaluated || result.PrimaryReason() != ReasonInternalContract {
				t.Fatalf("result = %q/%q/%q", result.State(), result.Custody(), result.PrimaryReason())
			}
		})
	}
}

// TestServiceErrorRejectsUnknownDiagnosticTokens verifies errors never echo arbitrary codes.
func TestServiceErrorRejectsUnknownDiagnosticTokens(t *testing.T) {
	err := newError(ErrorCode("RAW-SECRET-CODE"))
	if strings.Contains(err.Error(), "RAW-SECRET-CODE") || err.Code() != "" {
		t.Fatalf("unknown error code escaped: %q/%q", err.Error(), err.Code())
	}
}
