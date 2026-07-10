package instance

import (
	"errors"
	"fmt"
)

// ErrorCode identifies a bounded Message-Instance parser failure.
type ErrorCode string

const (
	// ErrorCodeWrongHeaderField reports a non Message-Instance header field.
	ErrorCodeWrongHeaderField ErrorCode = "wrong_header_field"
	// ErrorCodeMissingRequiredTag reports an omitted required Message-Instance tag.
	ErrorCodeMissingRequiredTag ErrorCode = "missing_required_tag"
	// ErrorCodeInvalidNumber reports malformed, zero, or overflowing m= syntax.
	ErrorCodeInvalidNumber ErrorCode = "invalid_number"
	// ErrorCodeMalformedHashSet reports an h= entry without exactly three parts.
	ErrorCodeMalformedHashSet ErrorCode = "malformed_hash_set"
	// ErrorCodeDuplicateHashName reports a duplicate algorithm name inside h=.
	ErrorCodeDuplicateHashName ErrorCode = "duplicate_hash_name"
	// ErrorCodeInvalidHashBase64 reports malformed baseline sha256 hash base64.
	ErrorCodeInvalidHashBase64 ErrorCode = "invalid_hash_base64"
	// ErrorCodeInvalidHashLength reports a baseline sha256 hash with the wrong size.
	ErrorCodeInvalidHashLength ErrorCode = "invalid_hash_length"
	// ErrorCodeInvalidRecipeBase64 reports malformed r= base64string syntax.
	ErrorCodeInvalidRecipeBase64 ErrorCode = "invalid_recipe_base64"
	// ErrorCodeLimitExceeded reports a Message-Instance resource-limit violation.
	ErrorCodeLimitExceeded ErrorCode = "limit_exceeded"
	// ErrorCodeInvalidOptions reports unsafe Message-Instance parser options.
	ErrorCodeInvalidOptions ErrorCode = "invalid_options"
	// ErrorCodeMissingOrigin reports a collection without m=1.
	ErrorCodeMissingOrigin ErrorCode = "missing_origin"
	// ErrorCodeDuplicateNumber reports repeated Message-Instance m= numbers.
	ErrorCodeDuplicateNumber ErrorCode = "duplicate_number"
	// ErrorCodeSequenceGap reports a missing Message-Instance m= number.
	ErrorCodeSequenceGap ErrorCode = "sequence_gap"
)

// ErrorClass groups Message-Instance parser failures for stable callers.
type ErrorClass string

const (
	// ErrorClassMalformed classifies malformed Message-Instance syntax.
	ErrorClassMalformed ErrorClass = "malformed"
	// ErrorClassMissing classifies omitted required tags.
	ErrorClassMissing ErrorClass = "missing"
	// ErrorClassDuplicate classifies duplicate semantic names.
	ErrorClassDuplicate ErrorClass = "duplicate"
	// ErrorClassLimit classifies configured resource-limit failures.
	ErrorClassLimit ErrorClass = "limit"
	// ErrorClassInvariant classifies invalid parser configuration.
	ErrorClassInvariant ErrorClass = "invariant"
)

// ErrorLocation identifies bounded Message-Instance parser context.
type ErrorLocation struct {
	// FieldIndex records the rawmsg header occurrence index when known.
	FieldIndex int
	// HashIndex records the zero-based h= hash-set index when relevant.
	HashIndex int
}

// ErrorDetails carries bounded parser metadata for Error.
type ErrorDetails struct {
	// Class records the stable operational class for the error.
	Class ErrorClass
	// TagName records an allowlisted Message-Instance tag when relevant.
	TagName string
	// LimitName records the resource limit identifier for structured callers.
	LimitName string
	// Limit records the configured limit when relevant.
	Limit int
	// Count records the observed count or size when relevant.
	Count int
	// ExpectedNumber records the sequence number required by validation.
	ExpectedNumber uint64
	// ObservedNumber records the sequence number found by validation.
	ObservedNumber uint64
}

// Error is a typed, secret-safe Message-Instance parser error.
type Error struct {
	code     ErrorCode
	location ErrorLocation
	details  ErrorDetails
	cause    error
}

// newError constructs a bounded parser error without raw field data.
func newError(code ErrorCode, location ErrorLocation, details ErrorDetails, cause error) *Error {
	if details.Class == "" {
		details.Class = classForCode(code)
	}

	details.TagName = safeDiagnosticToken(details.TagName)
	details.LimitName = safeDiagnosticToken(details.LimitName)

	return &Error{
		code:     code,
		location: sanitizeLocation(location),
		details:  sanitizeDetails(details),
		cause:    cause,
	}
}

// Error returns a bounded diagnostic without raw hashes or recipe bytes.
func (e *Error) Error() string {
	if e == nil {
		return "instance parser error: <nil>"
	}

	msg := fmt.Sprintf("instance parser error: code=%s class=%s field_index=%d hash_index=%d",
		safeDiagnosticToken(string(e.code)), safeDiagnosticToken(string(e.details.Class)),
		e.location.FieldIndex, e.location.HashIndex)
	if e.details.TagName != "" {
		msg += fmt.Sprintf(" tag=%s", e.details.TagName)
	}
	if e.details.Limit > 0 {
		msg += fmt.Sprintf(" limit=%d", e.details.Limit)
	}
	if e.details.Count > 0 {
		msg += fmt.Sprintf(" count=%d", e.details.Count)
	}
	if e.details.ExpectedNumber > 0 {
		msg += fmt.Sprintf(" expected=%d", e.details.ExpectedNumber)
	}
	if e.details.ObservedNumber > 0 {
		msg += fmt.Sprintf(" observed=%d", e.details.ObservedNumber)
	}

	return msg
}

// Is matches parser errors by code for errors.Is.
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

// Code returns the stable parser error code.
func (e *Error) Code() ErrorCode {
	if e == nil {
		return ""
	}

	return e.code
}

// Location returns bounded parser location metadata.
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

// TagName returns the allowlisted tag name associated with the error.
func (e *Error) TagName() string {
	if e == nil {
		return ""
	}

	return e.details.TagName
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

// ExpectedNumber returns the required sequence number for validation errors.
func (e *Error) ExpectedNumber() uint64 {
	if e == nil {
		return 0
	}

	return e.details.ExpectedNumber
}

// ObservedNumber returns the observed sequence number for validation errors.
func (e *Error) ObservedNumber() uint64 {
	if e == nil {
		return 0
	}

	return e.details.ObservedNumber
}

// IsErrorCode reports whether err contains an instance Error with code.
func IsErrorCode(err error, code ErrorCode) bool {
	var parserErr *Error
	if !errors.As(err, &parserErr) {
		return false
	}

	return parserErr.Code() == code
}

// classForCode maps parser codes to default operational classes.
func classForCode(code ErrorCode) ErrorClass {
	switch code {
	case ErrorCodeMissingRequiredTag:
		return ErrorClassMissing
	case ErrorCodeDuplicateHashName, ErrorCodeDuplicateNumber:
		return ErrorClassDuplicate
	case ErrorCodeLimitExceeded:
		return ErrorClassLimit
	case ErrorCodeInvalidOptions:
		return ErrorClassInvariant
	default:
		return ErrorClassMalformed
	}
}

// sanitizeLocation prevents negative indexes from leaking invalid context.
func sanitizeLocation(location ErrorLocation) ErrorLocation {
	if location.FieldIndex < 0 {
		location.FieldIndex = 0
	}
	if location.HashIndex < 0 {
		location.HashIndex = 0
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
