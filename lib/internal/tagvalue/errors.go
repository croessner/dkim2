package tagvalue

import (
	"errors"
	"fmt"
	"io"
)

// ErrorCode identifies a bounded DKIM2 tag-value scanner failure.
type ErrorCode string

const (
	// ErrorCodeEmptyTagSpec reports an empty tag spec except for a final semicolon.
	ErrorCodeEmptyTagSpec ErrorCode = "empty_tag_spec"
	// ErrorCodeMissingTagTerminator reports a tag list whose final tag lacks its semicolon.
	ErrorCodeMissingTagTerminator ErrorCode = "missing_tag_terminator"
	// ErrorCodeMissingEquals reports a tag spec without a name/value separator.
	ErrorCodeMissingEquals ErrorCode = "missing_equals"
	// ErrorCodeInvalidTagName reports a tag name outside DKIM2 tag syntax.
	ErrorCodeInvalidTagName ErrorCode = "invalid_tag_name"
	// ErrorCodeInvalidTagValue reports an extension value outside printable tag-value syntax.
	ErrorCodeInvalidTagValue ErrorCode = "invalid_tag_value"
	// ErrorCodeDuplicateTag reports a duplicate known or extension tag.
	ErrorCodeDuplicateTag ErrorCode = "duplicate_tag"
	// ErrorCodeLimitExceeded reports a configured scanner resource limit violation.
	ErrorCodeLimitExceeded ErrorCode = "limit_exceeded"
	// ErrorCodeInvalidOptions reports unsafe scanner options or known-tag input.
	ErrorCodeInvalidOptions ErrorCode = "invalid_options"
	// ErrorCodeInvalidBase64Alphabet reports bytes outside the standard alphabet.
	ErrorCodeInvalidBase64Alphabet ErrorCode = "invalid_base64_alphabet"
	// ErrorCodeInvalidBase64Padding reports misplaced or excessive padding.
	ErrorCodeInvalidBase64Padding ErrorCode = "invalid_base64_padding"
	// ErrorCodeInvalidBase64Length reports an empty or structurally invalid encoded length.
	ErrorCodeInvalidBase64Length ErrorCode = "invalid_base64_length"
	// ErrorCodeInvalidBase64PadBits reports non-zero RFC 4648 pad bits.
	ErrorCodeInvalidBase64PadBits ErrorCode = "invalid_base64_pad_bits"
)

// Known reports whether code belongs to the closed tag-value vocabulary.
func (c ErrorCode) Known() bool {
	switch c {
	case ErrorCodeEmptyTagSpec, ErrorCodeMissingTagTerminator, ErrorCodeMissingEquals,
		ErrorCodeInvalidTagName, ErrorCodeInvalidTagValue, ErrorCodeDuplicateTag,
		ErrorCodeLimitExceeded, ErrorCodeInvalidOptions, ErrorCodeInvalidBase64Alphabet,
		ErrorCodeInvalidBase64Padding, ErrorCodeInvalidBase64Length, ErrorCodeInvalidBase64PadBits:
		return true
	default:
		return false
	}
}

// ErrorClass groups tag-value scanner failures into stable operational classes.
type ErrorClass string

const (
	// ErrorClassMalformed classifies malformed DKIM2 tag-list syntax.
	ErrorClassMalformed ErrorClass = "malformed"
	// ErrorClassDuplicate classifies duplicate tag names.
	ErrorClassDuplicate ErrorClass = "duplicate"
	// ErrorClassLimit classifies resource-limit failures.
	ErrorClassLimit ErrorClass = "limit"
	// ErrorClassInvariant classifies invalid scanner configuration.
	ErrorClassInvariant ErrorClass = "invariant"
)

// Known reports whether class belongs to the closed tag-value vocabulary.
func (c ErrorClass) Known() bool {
	return c == ErrorClassMalformed || c == ErrorClassDuplicate || c == ErrorClassLimit || c == ErrorClassInvariant
}

// LimitName identifies one closed tag-value scanner limit.
type LimitName string

// Tag-value limit names form the closed scanner resource vocabulary.
const (
	LimitNameMaxFieldValueBytes    LimitName = "max_field_value_bytes"
	LimitNameMaxTags               LimitName = "max_tags"
	LimitNameMaxTagNameBytes       LimitName = "max_tag_name_bytes"
	LimitNameMaxTagValueBytes      LimitName = "max_tag_value_bytes"
	LimitNameMaxBase64DecodedBytes LimitName = "max_base64_decoded_bytes"
)

// Known reports whether name belongs to the closed scanner limit vocabulary.
func (n LimitName) Known() bool {
	return n == LimitNameMaxFieldValueBytes || n == LimitNameMaxTags || n == LimitNameMaxTagNameBytes ||
		n == LimitNameMaxTagValueBytes || n == LimitNameMaxBase64DecodedBytes
}

// ErrorLocation identifies bounded tag-list context for a scanner error.
type ErrorLocation struct {
	// Offset records a zero-based byte offset when known.
	Offset int
	// TagIndex records a zero-based tag-spec index when known.
	TagIndex int
}

// ErrorDetails carries bounded metadata for Error.
type ErrorDetails struct {
	// Class records the stable operational class for the error.
	Class ErrorClass
	// LimitName records the resource limit identifier for structured callers.
	LimitName LimitName
	// Limit records the configured limit when relevant.
	Limit int
	// Count records the observed count or size when relevant.
	Count int
	// tagName records only a scanner-proven KnownTags member.
	tagName string
}

// Error is a typed, secret-safe DKIM2 tag-value scanner error.
type Error struct {
	code     ErrorCode
	location ErrorLocation
	details  ErrorDetails
}

// NewError constructs a bounded scanner error for classification.
func NewError(code ErrorCode, location ErrorLocation, details ErrorDetails) *Error {
	if !code.Known() {
		code = ErrorCodeInvalidOptions
	}
	details.Class = classForCode(code)
	if !details.LimitName.Known() {
		details.LimitName = ""
	}

	return &Error{
		code:     code,
		location: sanitizeLocation(location),
		details:  sanitizeDetails(details),
	}
}

// Error returns a bounded diagnostic without raw tag values.
func (e *Error) Error() string {
	if e == nil {
		return "tagvalue scanner error: <nil>"
	}

	msg := fmt.Sprintf("tagvalue scanner error: code=%s class=%s offset=%d tag_index=%d",
		safeDiagnosticToken(string(e.code)), safeDiagnosticToken(string(e.details.Class)),
		e.location.Offset, e.location.TagIndex)
	if e.details.tagName != "" {
		msg += fmt.Sprintf(" tag=%s", e.details.tagName)
	}
	if e.details.Limit > 0 {
		msg += fmt.Sprintf(" limit=%d", e.details.Limit)
	}
	if e.details.Count > 0 {
		msg += fmt.Sprintf(" count=%d", e.details.Count)
	}

	return msg
}

// GoString returns the same secret-safe diagnostic for Go-syntax formatting.
func (e *Error) GoString() string { return e.Error() }

// Format routes every fmt form through the secret-safe diagnostic.
func (e *Error) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, e.Error()) }

// Is matches scanner errors by code for errors.Is.
func (e *Error) Is(target error) bool {
	var targetErr *Error
	if !errors.As(target, &targetErr) {
		return false
	}

	return e != nil && targetErr != nil && e.code == targetErr.code
}

// Code returns the stable scanner error code.
func (e *Error) Code() ErrorCode {
	if e == nil {
		return ""
	}

	return e.code
}

// Location returns bounded scanner location metadata.
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

// TagName returns the allowlisted canonical tag name associated with the error.
func (e *Error) TagName() string {
	if e == nil {
		return ""
	}

	return e.details.tagName
}

// LimitName returns the resource limit name for structured callers only.
func (e *Error) LimitName() string {
	if e == nil {
		return ""
	}

	return string(e.details.LimitName)
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

// IsErrorCode reports whether err contains a scanner Error with code.
func IsErrorCode(err error, code ErrorCode) bool {
	var scannerErr *Error
	if !errors.As(err, &scannerErr) {
		return false
	}

	return scannerErr.Code() == code
}

// classForCode maps stable error codes to default classes.
func classForCode(code ErrorCode) ErrorClass {
	switch code {
	case ErrorCodeDuplicateTag:
		return ErrorClassDuplicate
	case ErrorCodeLimitExceeded:
		return ErrorClassLimit
	case ErrorCodeInvalidOptions:
		return ErrorClassInvariant
	default:
		return ErrorClassMalformed
	}
}

// sanitizeLocation prevents negative positions from leaking invalid context.
func sanitizeLocation(location ErrorLocation) ErrorLocation {
	if location.Offset < 0 {
		location.Offset = 0
	}
	if location.TagIndex < 0 {
		location.TagIndex = 0
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
