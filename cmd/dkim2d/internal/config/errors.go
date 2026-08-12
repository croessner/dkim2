package config

import "errors"

// Code identifies one content-free configuration failure class.
type Code string

const (
	// CodeInvalidYAML identifies a malformed or structurally forbidden YAML document.
	CodeInvalidYAML Code = "config_invalid_yaml"
	// CodeInvalidSource identifies an invalid source, provenance, or merge result.
	CodeInvalidSource Code = "config_invalid_source"
	// CodeInvalidPlaceholder identifies invalid or unresolved placeholder syntax.
	CodeInvalidPlaceholder Code = "config_invalid_placeholder"
	// CodeInvalidField identifies an invalid declared scalar.
	CodeInvalidField Code = "config_invalid_field"
	// CodeInvalidMatrix identifies a backend presence-matrix violation.
	CodeInvalidMatrix Code = "config_invalid_backend_matrix"
	// CodeInternal identifies a failed internal configuration invariant.
	CodeInternal Code = "config_internal"
	// CodeSerialization identifies a forbidden effective-configuration serialization.
	CodeSerialization Code = "config_serialization_forbidden"
	// CodeProtectedPath identifies an invalid or untrusted protected path.
	CodeProtectedPath Code = "config_protected_path"
	// CodeProtectedAccess identifies invalid protected ownership, mode, link, shape, or descriptor state.
	CodeProtectedAccess Code = "config_protected_access"
	// CodeProtectedIO identifies a content-free protected descriptor operation failure.
	CodeProtectedIO Code = "config_protected_io"
	// CodeProtectedContent identifies malformed or inconsistent protected material.
	CodeProtectedContent Code = "config_protected_content"
	// CodeProtectedUnsupported identifies a platform without the required descriptor primitives.
	CodeProtectedUnsupported Code = "config_protected_unsupported"
	// CodeProtectedClosed identifies use after protected ownership was released.
	CodeProtectedClosed Code = "config_protected_closed"
	// CodeProtectedAmbiguous identifies a replacement whose durability or serialization fence became uncertain.
	CodeProtectedAmbiguous Code = "config_protected_ambiguous"
	// CodeProtectedBusy identifies an already-held stable protected transaction lock.
	CodeProtectedBusy Code = "config_protected_busy"
	// CodeProtectedConflict identifies a protected entry that changed since its exact read view.
	CodeProtectedConflict Code = "config_protected_conflict"
	// CodeProtectedTransferred identifies an invalid ownership transfer or owner use after transfer.
	CodeProtectedTransferred Code = "config_protected_transferred"
)

// Error is one stable content-free configuration failure.
type Error struct {
	code Code
}

// Error returns only the stable failure code.
func (e *Error) Error() string {
	if e == nil {
		return string(CodeInternal)
	}
	return string(e.code)
}

// Code returns the stable content-free failure class.
func (e *Error) Code() Code {
	if e == nil {
		return CodeInternal
	}
	return e.code
}

// newError constructs one content-free configuration error.
func newError(code Code) error {
	return &Error{code: code}
}

// CodeOf extracts a stable code without exposing an underlying value.
func CodeOf(err error) Code {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code()
	}
	return CodeInternal
}
