// Package datasourceadmin owns provider-neutral offline datasource administration.
package datasourceadmin

import (
	"errors"
	"fmt"
	"io"
)

const redacted = "dkim2d_datasource_admin{redacted}"

// ErrorCode identifies one bounded administration failure.
type ErrorCode string

const (
	// CodeNone reports no classified error.
	CodeNone ErrorCode = "none"
	// CodeInvalid reports malformed administrative content.
	CodeInvalid ErrorCode = "invalid"
	// CodeConflict reports disagreement with authoritative state.
	CodeConflict ErrorCode = "conflict"
	// CodeLimitExceeded reports a finite administrative resource fence.
	CodeLimitExceeded ErrorCode = "limit_exceeded"
	// CodeUnavailable reports an unavailable backend operation.
	CodeUnavailable ErrorCode = "unavailable"
	// CodeReconcileRequired reports an ambiguous mutation outcome.
	CodeReconcileRequired ErrorCode = "reconcile_required"
)

// Error is one content-free datasource-administration failure.
type Error struct{ code ErrorCode }

// Error returns a constant diagnostic.
func (*Error) Error() string { return "datasource administration failed" }

// Code returns the closed failure class.
func (e *Error) Code() ErrorCode {
	if e == nil {
		return CodeNone
	}
	return e.code
}

// String returns a constant protected representation.
func (*Error) String() string { return redacted }

// GoString returns a constant protected Go representation.
func (*Error) GoString() string { return redacted }

// Format prevents formatting verbs from exposing administrative context.
func (*Error) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// newError creates one content-free error.
func newError(code ErrorCode) error { return &Error{code: code} }

// NewError creates one bounded provider-adapter failure classification.
func NewError(code ErrorCode) error {
	switch code {
	case CodeInvalid, CodeConflict, CodeLimitExceeded, CodeUnavailable, CodeReconcileRequired:
		return newError(code)
	default:
		return newError(CodeInvalid)
	}
}

// CodeOf extracts the stable administration failure class.
func CodeOf(err error) ErrorCode {
	var target *Error
	if errors.As(err, &target) {
		return target.Code()
	}
	if err == nil {
		return CodeNone
	}
	return CodeUnavailable
}
