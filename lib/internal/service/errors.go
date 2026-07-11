package service

import "errors"

// ErrorCode identifies bounded service API misuse.
type ErrorCode string

const (
	// ErrorInvalidConfig reports an unsafe coordinator configuration.
	ErrorInvalidConfig ErrorCode = "invalid_config"
	// ErrorInvalidRequest reports internal caller misuse.
	ErrorInvalidRequest ErrorCode = "invalid_request"
)

// Known reports whether the code belongs to the closed service vocabulary.
func (c ErrorCode) Known() bool { return c == ErrorInvalidConfig || c == ErrorInvalidRequest }

// Error is a cause-free bounded service API error.
type Error struct{ code ErrorCode }

// newError constructs a service error without retaining inputs or causes.
func newError(code ErrorCode) *Error {
	if !code.Known() {
		code = ""
	}
	return &Error{code: code}
}

// Error returns a bounded non-sensitive diagnostic.
func (e *Error) Error() string {
	if e == nil || !e.code.Known() {
		return "verification service error"
	}
	return "verification service error: " + string(e.code)
}

// Is matches service errors by stable code.
func (e *Error) Is(target error) bool {
	var other *Error
	return errors.As(target, &other) && e != nil && other != nil && e.code == other.code
}

// Code returns the stable service error code.
func (e *Error) Code() ErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}
