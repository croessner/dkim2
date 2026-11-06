package datasource

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestReconcileContextFailureEnforcesClosedPrecedence exhaustively covers
// ordinary, terminal, contradictory, untyped, and internal boundary outcomes.
func TestReconcileContextFailureEnforcesClosedPrecedence(t *testing.T) {
	t.Parallel()

	cancelled := ErrorFromContext(cancelledReconciliationContext())
	deadline := ErrorFromContext(deadlineReconciliationContext())
	ordinary := NewError(ErrorCodeUnavailable)
	internal := NewError(ErrorCodeInternalInvariant)
	var typedNil *Error
	tests := []struct {
		name         string
		boundaryErr  error
		contextErr   error
		expectedCode ErrorCode
		expected     error
	}{
		{name: "success active", expectedCode: ""},
		{
			name: "success cancelled", contextErr: cancelled,
			expectedCode: ErrorCodeCancelled, expected: cancelled,
		},
		{
			name: "success deadline", contextErr: deadline,
			expectedCode: ErrorCodeDeadlineExceeded, expected: deadline,
		},
		{
			name: "ordinary active", boundaryErr: ordinary,
			expectedCode: ErrorCodeUnavailable, expected: ordinary,
		},
		{
			name: "ordinary cancelled", boundaryErr: ordinary, contextErr: cancelled,
			expectedCode: ErrorCodeCancelled, expected: cancelled,
		},
		{
			name: "ordinary deadline", boundaryErr: ordinary, contextErr: deadline,
			expectedCode: ErrorCodeDeadlineExceeded, expected: deadline,
		},
		{
			name: "matching cancellation", boundaryErr: NewError(ErrorCodeCancelled),
			contextErr: cancelled, expectedCode: ErrorCodeCancelled, expected: cancelled,
		},
		{
			name: "matching deadline", boundaryErr: NewError(ErrorCodeDeadlineExceeded),
			contextErr: deadline, expectedCode: ErrorCodeDeadlineExceeded, expected: deadline,
		},
		{
			name: "cancelled without context", boundaryErr: NewError(ErrorCodeCancelled),
			expectedCode: ErrorCodeInternalInvariant,
		},
		{
			name: "deadline without context", boundaryErr: NewError(ErrorCodeDeadlineExceeded),
			expectedCode: ErrorCodeInternalInvariant,
		},
		{
			name: "mismatched context", boundaryErr: NewError(ErrorCodeCancelled),
			contextErr: deadline, expectedCode: ErrorCodeInternalInvariant,
		},
		{
			name:        "mismatched deadline context",
			boundaryErr: NewError(ErrorCodeDeadlineExceeded),
			contextErr:  cancelled, expectedCode: ErrorCodeInternalInvariant,
		},
		{
			name: "internal beats cancellation", boundaryErr: internal,
			contextErr: cancelled, expectedCode: ErrorCodeInternalInvariant,
		},
		{
			name: "internal beats deadline", boundaryErr: internal,
			contextErr: deadline, expectedCode: ErrorCodeInternalInvariant,
		},
		{
			name: "hostile context classification", boundaryErr: ordinary,
			contextErr: internal, expectedCode: ErrorCodeInternalInvariant,
		},
		{
			name: "untyped boundary", boundaryErr: errors.New("protected"),
			contextErr: cancelled, expectedCode: ErrorCodeInternalInvariant,
		},
		{
			name: "typed nil boundary", boundaryErr: typedNil,
			contextErr: cancelled, expectedCode: ErrorCodeInternalInvariant,
		},
		{
			name: "typed nil context", boundaryErr: ordinary,
			contextErr: typedNil, expectedCode: ErrorCodeInternalInvariant,
		},
		{
			name: "untyped context", boundaryErr: ordinary,
			contextErr: errors.New("protected"), expectedCode: ErrorCodeInternalInvariant,
		},
		{
			name: "ordinary typed context", boundaryErr: ordinary,
			contextErr:   NewError(ErrorCodeUnavailable),
			expectedCode: ErrorCodeInternalInvariant,
		},
	}
	for _, test := range tests {
		result := ReconcileContextFailure(test.boundaryErr, test.contextErr)
		if test.expectedCode == "" {
			if result != nil {
				t.Fatalf("%s returned a failure", test.name)
			}
			continue
		}
		if ErrorCodeOf(result) != test.expectedCode {
			t.Fatalf("%s returned code=%s", test.name, ErrorCodeOf(result))
		}
		if test.expected != nil && result != test.expected {
			t.Fatalf("%s did not preserve the selected exact error", test.name)
		}
	}
}

// cancelledReconciliationContext constructs one exact cancelled context.
func cancelledReconciliationContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// deadlineReconciliationContext constructs one exact elapsed-deadline context.
func deadlineReconciliationContext() context.Context {
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
	cancel()
	return ctx
}
