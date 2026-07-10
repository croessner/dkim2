package canonical

import (
	"errors"
	"fmt"
)

// ErrorCode identifies a bounded canonicalization failure.
type ErrorCode string

const (
	// ErrorCodeUnsupportedAlgorithm reports a hash or signature algorithm outside the allowlist.
	ErrorCodeUnsupportedAlgorithm ErrorCode = "unsupported_algorithm"
	// ErrorCodeInvalidOptions reports unsafe canonicalization options.
	ErrorCodeInvalidOptions ErrorCode = "invalid_options"
	// ErrorCodeLimitExceeded reports a canonicalization resource-limit violation.
	ErrorCodeLimitExceeded ErrorCode = "limit_exceeded"
	// ErrorCodeMalformedState reports invalid parser-owned state consumed by canonicalization.
	ErrorCodeMalformedState ErrorCode = "malformed_state"
	// ErrorCodeAmbiguousSelection reports ambiguous canonical input selection.
	ErrorCodeAmbiguousSelection ErrorCode = "ambiguous_selection"
	// ErrorCodeMissingTarget reports a missing target field or digest.
	ErrorCodeMissingTarget ErrorCode = "missing_target"
	// ErrorCodeDuplicateTarget reports repeated target identifiers.
	ErrorCodeDuplicateTarget ErrorCode = "duplicate_target"
	// ErrorCodeInternalMisuse reports invalid internal canonicalization API use.
	ErrorCodeInternalMisuse ErrorCode = "internal_misuse"
)

// ErrorClass groups canonicalization failures for stable callers.
type ErrorClass string

const (
	// ErrorClassAlgorithm classifies unsupported algorithm selection.
	ErrorClassAlgorithm ErrorClass = "algorithm"
	// ErrorClassInvariant classifies invalid options or internal invariants.
	ErrorClassInvariant ErrorClass = "invariant"
	// ErrorClassLimit classifies configured resource-limit failures.
	ErrorClassLimit ErrorClass = "limit"
	// ErrorClassMalformed classifies malformed parser-owned state.
	ErrorClassMalformed ErrorClass = "malformed"
	// ErrorClassAmbiguous classifies ambiguous target or input selection.
	ErrorClassAmbiguous ErrorClass = "ambiguous"
	// ErrorClassMissing classifies omitted required targets.
	ErrorClassMissing ErrorClass = "missing"
	// ErrorClassDuplicate classifies duplicate target identifiers.
	ErrorClassDuplicate ErrorClass = "duplicate"
	// ErrorClassInternal classifies package misuse that should not depend on message input.
	ErrorClassInternal ErrorClass = "internal"
)

// ErrorLocation identifies bounded canonicalization context.
type ErrorLocation struct {
	// Kind records the canonicalization byte stream when known.
	Kind Kind
	// FieldIndex records a raw header occurrence index when relevant.
	FieldIndex int
	// TargetNumber records an m= or i= target number when relevant.
	TargetNumber uint64
}

// ErrorDetails carries bounded metadata for Error.
type ErrorDetails struct {
	// Class records the stable operational class for the error.
	Class ErrorClass
	// Algorithm records a safe hash or signature algorithm name.
	Algorithm HashAlgorithm
	// LimitName records the resource limit identifier for structured callers.
	LimitName string
	// Limit records the configured limit when relevant.
	Limit int
	// Count records the observed count or size when relevant.
	Count int
	// TargetName records an allowlisted target class such as message_instance.
	TargetName string
}

// Error is a typed, secret-safe canonicalization error.
type Error struct {
	code     ErrorCode
	location ErrorLocation
	details  ErrorDetails
	cause    error
}

// newError constructs a bounded canonicalization error without raw message data.
func newError(code ErrorCode, location ErrorLocation, details ErrorDetails, cause error) *Error {
	if details.Class == "" {
		details.Class = classForCode(code)
	}

	details.Algorithm = HashAlgorithm(safeDiagnosticToken(string(details.Algorithm)))
	details.LimitName = safeDiagnosticToken(details.LimitName)
	details.TargetName = safeDiagnosticToken(details.TargetName)

	return &Error{
		code:     code,
		location: sanitizeLocation(location),
		details:  sanitizeDetails(details),
		cause:    cause,
	}
}

// Error returns a bounded diagnostic without canonical bytes or raw fields.
func (e *Error) Error() string {
	if e == nil {
		return "canonicalization error: <nil>"
	}

	msg := fmt.Sprintf("canonicalization error: code=%s class=%s kind=%s field_index=%d target_number=%d",
		safeDiagnosticToken(string(e.code)),
		safeDiagnosticToken(string(e.details.Class)),
		safeDiagnosticToken(string(e.location.Kind)),
		e.location.FieldIndex,
		e.location.TargetNumber,
	)
	if e.details.Algorithm != "" {
		msg += fmt.Sprintf(" algorithm=%s", e.details.Algorithm)
	}
	if e.details.TargetName != "" {
		msg += fmt.Sprintf(" target=%s", e.details.TargetName)
	}
	if e.details.Limit > 0 {
		msg += fmt.Sprintf(" limit=%d", e.details.Limit)
	}
	if e.details.Count > 0 {
		msg += fmt.Sprintf(" count=%d", e.details.Count)
	}

	return msg
}

// Is matches canonicalization errors by code for errors.Is.
func (e *Error) Is(target error) bool {
	var targetErr *Error
	if !errors.As(target, &targetErr) {
		return false
	}

	return e != nil && targetErr != nil && e.code == targetErr.code
}

// Unwrap returns the structured lower-level cause when one exists.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.cause
}

// Code returns the stable canonicalization error code.
func (e *Error) Code() ErrorCode {
	if e == nil {
		return ""
	}

	return e.code
}

// Location returns bounded canonicalization location metadata.
func (e *Error) Location() ErrorLocation {
	if e == nil {
		return ErrorLocation{}
	}

	return e.location
}

// Class returns the stable operational error class.
func (e *Error) Class() ErrorClass {
	if e == nil {
		return ""
	}

	return e.details.Class
}

// Algorithm returns the safe algorithm name associated with the error.
func (e *Error) Algorithm() HashAlgorithm {
	if e == nil {
		return ""
	}

	return e.details.Algorithm
}

// LimitName returns the resource limit name for structured callers only.
func (e *Error) LimitName() string {
	if e == nil {
		return ""
	}

	return e.details.LimitName
}

// Limit returns the configured resource limit associated with the error.
func (e *Error) Limit() int {
	if e == nil {
		return 0
	}

	return e.details.Limit
}

// Count returns the observed resource count or size associated with the error.
func (e *Error) Count() int {
	if e == nil {
		return 0
	}

	return e.details.Count
}

// TargetName returns the allowlisted target class associated with the error.
func (e *Error) TargetName() string {
	if e == nil {
		return ""
	}

	return e.details.TargetName
}

// IsErrorCode reports whether err contains a canonicalization Error with code.
func IsErrorCode(err error, code ErrorCode) bool {
	var canonicalErr *Error
	if !errors.As(err, &canonicalErr) {
		return false
	}

	return canonicalErr.Code() == code
}

// classForCode maps canonicalization codes to default operational classes.
func classForCode(code ErrorCode) ErrorClass {
	switch code {
	case ErrorCodeUnsupportedAlgorithm:
		return ErrorClassAlgorithm
	case ErrorCodeInvalidOptions:
		return ErrorClassInvariant
	case ErrorCodeLimitExceeded:
		return ErrorClassLimit
	case ErrorCodeAmbiguousSelection:
		return ErrorClassAmbiguous
	case ErrorCodeMissingTarget:
		return ErrorClassMissing
	case ErrorCodeDuplicateTarget:
		return ErrorClassDuplicate
	case ErrorCodeInternalMisuse:
		return ErrorClassInternal
	default:
		return ErrorClassMalformed
	}
}

// sanitizeLocation prevents negative indexes from leaking invalid context.
func sanitizeLocation(location ErrorLocation) ErrorLocation {
	if !validKind(location.Kind) {
		location.Kind = ""
	}
	if location.FieldIndex < 0 {
		location.FieldIndex = 0
	}

	return location
}

// sanitizeDetails clamps counters and leaves only safe diagnostic tokens.
func sanitizeDetails(details ErrorDetails) ErrorDetails {
	if details.Limit < 0 {
		details.Limit = 0
	}
	if details.Count < 0 {
		details.Count = 0
	}

	return details
}

// safeDiagnosticToken bounds structured tokens before including them in errors.
func safeDiagnosticToken(value string) string {
	const maxDiagnosticTokenBytes = 64

	if value == "" {
		return ""
	}
	if len(value) > maxDiagnosticTokenBytes {
		return "redacted"
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '-' || b == '.' {
			continue
		}

		return "redacted"
	}

	return value
}
