package replay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// ErrorCode identifies one stable replay failure class.
type ErrorCode string

const (
	// ErrorCodeInvalidRequest classifies invalid input or a missing required value.
	ErrorCodeInvalidRequest ErrorCode = "invalid_request"
	// ErrorCodeMisconfigured classifies incomplete or unsafe construction.
	ErrorCodeMisconfigured ErrorCode = "misconfigured"
	// ErrorCodeLimitExceeded classifies a hard bounded-resource refusal.
	ErrorCodeLimitExceeded ErrorCode = "limit_exceeded"
	// ErrorCodeUnavailable classifies a proved pre-dispatch backend outage.
	ErrorCodeUnavailable ErrorCode = "unavailable"
	// ErrorCodeIndeterminate classifies a write that may have crossed mutation dispatch.
	ErrorCodeIndeterminate ErrorCode = "indeterminate"
	// ErrorCodeInconsistent classifies an authoritative contradictory backend outcome.
	ErrorCodeInconsistent ErrorCode = "inconsistent"
	// ErrorCodeCancelled classifies pre-dispatch caller cancellation.
	ErrorCodeCancelled ErrorCode = "cancelled"
	// ErrorCodeDeadlineExceeded classifies a pre-dispatch elapsed caller deadline.
	ErrorCodeDeadlineExceeded ErrorCode = "deadline_exceeded"
	// ErrorCodeClosed classifies work rejected after close begins.
	ErrorCodeClosed ErrorCode = "closed"
	// ErrorCodeInternalInvariant classifies impossible in-process state.
	ErrorCodeInternalInvariant ErrorCode = "internal_invariant"
)

// Known reports whether the code belongs to the closed replay taxonomy.
func (c ErrorCode) Known() bool {
	switch c {
	case ErrorCodeInvalidRequest, ErrorCodeMisconfigured, ErrorCodeLimitExceeded,
		ErrorCodeUnavailable, ErrorCodeIndeterminate, ErrorCodeInconsistent,
		ErrorCodeCancelled, ErrorCodeDeadlineExceeded, ErrorCodeClosed,
		ErrorCodeInternalInvariant:
		return true
	default:
		return false
	}
}

// String returns the stable error code or a constant unknown marker.
func (c ErrorCode) String() string {
	if !c.Known() {
		return unknownValueText
	}
	return string(c)
}

// GoString returns the stable error-code representation.
func (c ErrorCode) GoString() string { return c.String() }

// Format prevents unknown input from reaching formatting output.
func (c ErrorCode) Format(state fmt.State, _ rune) {
	formatClosedValue(state, c.String())
}

// MarshalText emits only a known replay error code.
func (c ErrorCode) MarshalText() ([]byte, error) {
	return marshalClosedText(c.Known(), c.String())
}

// MarshalJSON emits only a known replay error code.
func (c ErrorCode) MarshalJSON() ([]byte, error) {
	return marshalClosedJSON(c.Known(), c.String())
}

// Error is one typed content-free replay failure.
type Error struct {
	code  ErrorCode
	cause error
}

// NewError constructs one stable replay failure without protected detail.
func NewError(code ErrorCode) error {
	if !code.Known() {
		code = ErrorCodeInternalInvariant
	}
	switch code {
	case ErrorCodeCancelled:
		return &Error{code: code, cause: context.Canceled}
	case ErrorCodeDeadlineExceeded:
		return &Error{code: code, cause: context.DeadlineExceeded}
	default:
		return &Error{code: code}
	}
}

// PreflightContext maps a context state before any mutation boundary.
func PreflightContext(ctx context.Context) (result error) {
	defer func() {
		if recover() != nil {
			result = NewError(ErrorCodeInternalInvariant)
		}
	}()
	if nilContext(ctx) {
		return NewError(ErrorCodeInvalidRequest)
	}
	switch ctx.Err() {
	case nil:
		return nil
	case context.Canceled:
		return NewError(ErrorCodeCancelled)
	case context.DeadlineExceeded:
		return NewError(ErrorCodeDeadlineExceeded)
	default:
		return NewError(ErrorCodeInternalInvariant)
	}
}

// Error returns only the stable replay failure class.
func (e *Error) Error() string {
	if e == nil || !e.valid() {
		return string(ErrorCodeInternalInvariant)
	}
	return string(e.code)
}

// GoString returns only the stable replay failure class.
func (e *Error) GoString() string { return e.Error() }

// Format prevents formatting verbs from exposing cause representation.
func (e *Error) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, e.Error())
}

// MarshalText emits only the stable replay failure class.
func (e *Error) MarshalText() ([]byte, error) {
	return []byte(e.Error()), nil
}

// MarshalJSON emits only the stable replay failure class.
func (e *Error) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.Error())
}

// Unwrap preserves only exact pre-dispatch context identity.
func (e *Error) Unwrap() error {
	if e == nil || !e.valid() {
		return nil
	}
	return e.cause
}

// Code returns the stable failure code.
func (e *Error) Code() ErrorCode {
	if e == nil || !e.valid() {
		return ErrorCodeInternalInvariant
	}
	return e.code
}

// ErrorCodeOf returns the stable code for one direct replay failure.
func ErrorCodeOf(err error) ErrorCode {
	target, ok := err.(*Error)
	if !ok || target == nil || !target.valid() {
		return ErrorCodeInternalInvariant
	}
	return target.code
}

// IsTypedError reports whether err is one direct member of the closed taxonomy.
func IsTypedError(err error) bool {
	target, ok := err.(*Error)
	return ok && target != nil && target.valid()
}

// valid reports whether the failure code and optional context cause agree.
func (e *Error) valid() bool {
	if e == nil || !e.code.Known() {
		return false
	}
	switch e.code {
	case ErrorCodeCancelled:
		return e.cause == context.Canceled
	case ErrorCodeDeadlineExceeded:
		return e.cause == context.DeadlineExceeded
	default:
		return e.cause == nil
	}
}

// nilContext reports both nil-interface and typed-nil context values.
func nilContext(ctx context.Context) bool {
	return nilInterface(ctx)
}
