package routeplan

import (
	"errors"
	"fmt"
)

// ErrorCode identifies one bounded route planning failure.
type ErrorCode string

const (
	// ErrorInvalidOptions reports invalid or widened limits.
	ErrorInvalidOptions ErrorCode = "invalid_options"
	// ErrorInvalidRequest reports malformed route input.
	ErrorInvalidRequest ErrorCode = "invalid_request"
	// ErrorLimitExceeded reports a coupled planning or call budget failure.
	ErrorLimitExceeded ErrorCode = "limit_exceeded"
	// ErrorDenied reports an authority denial.
	ErrorDenied ErrorCode = "denied"
	// ErrorTemporary reports typed retryable authority unavailability.
	ErrorTemporary ErrorCode = "temporary"
	// ErrorPermanent reports typed permanent authority unavailability.
	ErrorPermanent ErrorCode = "permanent"
	// ErrorContract reports an illegal authority result/error matrix.
	ErrorContract ErrorCode = "contract"
	// ErrorState reports an illegal ticket transition.
	ErrorState ErrorCode = "state"
)

// Known reports whether code belongs to the closed route error vocabulary.
func (c ErrorCode) Known() bool {
	switch c {
	case ErrorInvalidOptions, ErrorInvalidRequest, ErrorLimitExceeded, ErrorDenied,
		ErrorTemporary, ErrorPermanent, ErrorContract, ErrorState:
		return true
	default:
		return false
	}
}

// Error is a content-free route planning failure.
type Error struct{ code ErrorCode }

// newError constructs one bounded route error.
func newError(code ErrorCode) *Error {
	if !code.Known() {
		code = ErrorContract
	}
	return &Error{code: code}
}

// newLimitError constructs one bounded limit failure without attacker counts.
func newLimitError(_ int) *Error { return newError(ErrorLimitExceeded) }

// Error returns a deterministic secret-safe diagnostic.
func (e *Error) Error() string {
	if e == nil {
		return "route planning error"
	}
	return fmt.Sprintf("route planning error: code=%s", e.code)
}

// Code returns the closed route error code.
func (e *Error) Code() ErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}

// Is matches route errors by stable code.
func (e *Error) Is(target error) bool {
	var typed *Error
	return e != nil && errors.As(target, &typed) && typed != nil && e.code == typed.code
}

// IsErrorCode reports whether err contains a route error with code.
func IsErrorCode(err error, code ErrorCode) bool {
	var typed *Error
	return errors.As(err, &typed) && typed != nil && typed.code == code
}
