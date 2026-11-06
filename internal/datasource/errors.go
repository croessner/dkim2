package datasource

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// ErrorCode is one stable datasource failure class.
type ErrorCode string

const (
	// ErrorCodeInvalidRequest classifies an invalid request or zero value.
	ErrorCodeInvalidRequest ErrorCode = "invalid_request"
	// ErrorCodeNotFound classifies an absent exact record or binding.
	ErrorCodeNotFound ErrorCode = "not_found"
	// ErrorCodeAmbiguous classifies duplicate exact records.
	ErrorCodeAmbiguous ErrorCode = "ambiguous"
	// ErrorCodeInactive classifies a closed administrative record.
	ErrorCodeInactive ErrorCode = "inactive"
	// ErrorCodeMalformedData classifies invalid provider input.
	ErrorCodeMalformedData ErrorCode = "malformed_data"
	// ErrorCodeLimitExceeded classifies an exceeded resource bound.
	ErrorCodeLimitExceeded ErrorCode = "limit_exceeded"
	// ErrorCodeUnavailable classifies a provider that cannot safely serve.
	ErrorCodeUnavailable ErrorCode = "unavailable"
	// ErrorCodeUnsupportedPlatform classifies missing confinement primitives.
	ErrorCodeUnsupportedPlatform ErrorCode = "unsupported_platform"
	// ErrorCodeCancelled classifies context cancellation.
	ErrorCodeCancelled ErrorCode = "cancelled"
	// ErrorCodeDeadlineExceeded classifies an elapsed context deadline.
	ErrorCodeDeadlineExceeded ErrorCode = "deadline_exceeded"
	// ErrorCodeInternalInvariant classifies an impossible internal state.
	ErrorCodeInternalInvariant ErrorCode = "internal_invariant"
)

// Known reports whether the code belongs to the closed taxonomy.
func (c ErrorCode) Known() bool {
	switch c {
	case ErrorCodeInvalidRequest, ErrorCodeNotFound, ErrorCodeAmbiguous, ErrorCodeInactive,
		ErrorCodeMalformedData, ErrorCodeLimitExceeded, ErrorCodeUnavailable,
		ErrorCodeUnsupportedPlatform, ErrorCodeCancelled, ErrorCodeDeadlineExceeded,
		ErrorCodeInternalInvariant:
		return true
	default:
		return false
	}
}

// Error is one typed secret-safe datasource failure.
type Error struct {
	code  ErrorCode
	cause error
}

// NewError constructs one stable datasource failure without protected detail.
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

// ErrorFromContext maps a context state into the closed error taxonomy.
func ErrorFromContext(ctx context.Context) (result error) {
	defer func() {
		if recover() != nil {
			result = NewError(ErrorCodeInternalInvariant)
		}
	}()
	if ctx == nil {
		return NewError(ErrorCodeInvalidRequest)
	}
	switch err := ctx.Err(); {
	case errors.Is(err, context.Canceled):
		return &Error{code: ErrorCodeCancelled, cause: context.Canceled}
	case errors.Is(err, context.DeadlineExceeded):
		return &Error{code: ErrorCodeDeadlineExceeded, cause: context.DeadlineExceeded}
	case err == nil:
		return nil
	default:
		return NewError(ErrorCodeInternalInvariant)
	}
}

// ReconcileContextFailure combines one validated boundary failure with the
// context state observed after that boundary. Internal or contradictory
// outcomes fail closed; coherent terminal context controls ordinary outcomes.
func ReconcileContextFailure(boundaryErr, contextErr error) error {
	boundaryCode := ErrorCode("")
	if boundaryErr != nil {
		if !IsTypedError(boundaryErr) {
			return NewError(ErrorCodeInternalInvariant)
		}
		boundaryCode = ErrorCodeOf(boundaryErr)
		if boundaryCode == ErrorCodeInternalInvariant {
			return NewError(ErrorCodeInternalInvariant)
		}
	}

	contextCode := ErrorCode("")
	if contextErr != nil {
		if !IsTypedError(contextErr) {
			return NewError(ErrorCodeInternalInvariant)
		}
		contextCode = ErrorCodeOf(contextErr)
		switch contextCode {
		case ErrorCodeCancelled, ErrorCodeDeadlineExceeded:
		case ErrorCodeInternalInvariant:
			return NewError(ErrorCodeInternalInvariant)
		default:
			return NewError(ErrorCodeInternalInvariant)
		}
	}

	if boundaryErr == nil {
		return contextErr
	}
	switch boundaryCode {
	case ErrorCodeCancelled, ErrorCodeDeadlineExceeded:
		if contextErr == nil || contextCode != boundaryCode {
			return NewError(ErrorCodeInternalInvariant)
		}
		return contextErr
	default:
		if contextErr != nil {
			return contextErr
		}
		return boundaryErr
	}
}

// Error returns only the stable failure class.
func (e *Error) Error() string {
	if e == nil || !e.code.Known() {
		return string(ErrorCodeInternalInvariant)
	}
	return string(e.code)
}

// GoString returns only the stable failure class.
func (e *Error) GoString() string { return e.Error() }

// Format prevents formatting verbs from exposing internal cause representation.
func (e *Error) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, e.Error()) }

// Unwrap preserves only standard context cancellation identity.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Code returns the stable failure code.
func (e *Error) Code() ErrorCode {
	if e == nil || !e.code.Known() {
		return ErrorCodeInternalInvariant
	}
	return e.code
}

// ErrorCodeOf returns the stable code for one datasource failure.
func ErrorCodeOf(err error) ErrorCode {
	target, ok := err.(*Error)
	if ok && target != nil && target.valid() {
		return target.code
	}
	return ErrorCodeInternalInvariant
}

// IsTypedError reports whether an error belongs to the closed datasource taxonomy.
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
		return errors.Is(e.cause, context.Canceled)
	case ErrorCodeDeadlineExceeded:
		return errors.Is(e.cause, context.DeadlineExceeded)
	default:
		return e.cause == nil
	}
}
