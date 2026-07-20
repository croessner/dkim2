package rawmsg

import (
	"errors"
	"fmt"
)

// ErrorCode identifies a bounded raw-message parser or invariant failure.
type ErrorCode string

const (
	// ErrorCodeBareLF reports a bare LF rejected by strict CRLF policy.
	ErrorCodeBareLF ErrorCode = "bare_lf"
	// ErrorCodeBareCR reports a bare CR rejected by strict CRLF policy.
	ErrorCodeBareCR ErrorCode = "bare_cr"
	// ErrorCodeMixedLineEndings reports incompatible line endings in one input.
	ErrorCodeMixedLineEndings ErrorCode = "mixed_line_endings"
	// ErrorCodeMissingDelimiter reports a missing header/body delimiter.
	ErrorCodeMissingDelimiter ErrorCode = "missing_header_body_delimiter"
	// ErrorCodeMalformedHeader reports malformed header syntax.
	ErrorCodeMalformedHeader ErrorCode = "malformed_header"
	// ErrorCodeLimitExceeded reports a configured resource limit violation.
	ErrorCodeLimitExceeded ErrorCode = "limit_exceeded"
	// ErrorCodeUnsupportedPolicy reports an unknown parser policy value.
	ErrorCodeUnsupportedPolicy ErrorCode = "unsupported_policy"
	// ErrorCodeInvalidTransportForm reports missing or unsupported signing transport metadata.
	ErrorCodeInvalidTransportForm ErrorCode = "invalid_transport_form"
	// ErrorCodeInvalidInvariant reports an invalid type-construction invariant.
	ErrorCodeInvalidInvariant ErrorCode = "invalid_invariant"
)

// ErrorReasonClass groups parser failures into stable operational classes.
type ErrorReasonClass string

const (
	// ErrorReasonMalformed classifies syntactically malformed message input.
	ErrorReasonMalformed ErrorReasonClass = "malformed"
	// ErrorReasonPolicy classifies input rejected by an explicit parser policy.
	ErrorReasonPolicy ErrorReasonClass = "policy"
	// ErrorReasonLimit classifies input rejected by resource limits.
	ErrorReasonLimit ErrorReasonClass = "limit"
	// ErrorReasonInvariant classifies invalid internal domain construction.
	ErrorReasonInvariant ErrorReasonClass = "invariant"
)

// ErrorLocation identifies bounded byte and line context for a parser error.
type ErrorLocation struct {
	// Offset records a zero-based byte offset when known.
	Offset int
	// Line records a one-based input line number when known.
	Line int
	// Column records a one-based input column number when known.
	Column int
}

// ParserErrorDetails carries bounded classification metadata for ParserError.
type ParserErrorDetails struct {
	// Reason records the stable operational class for the error.
	Reason ErrorReasonClass
	// PolicyName records a bounded parser policy name when relevant.
	PolicyName string
	// LimitName records the resource limit identifier for structured callers.
	LimitName string
	// Limit records the numeric resource limit when relevant.
	Limit int
}

// ParserError is a typed, secret-safe raw-message parser error.
type ParserError struct {
	code     ErrorCode
	location ErrorLocation
	details  ParserErrorDetails
}

// NewParserError constructs a bounded parser error for classification.
func NewParserError(code ErrorCode, location ErrorLocation, details ParserErrorDetails) *ParserError {
	if details.Reason == "" {
		details.Reason = reasonForCode(code)
	}

	return &ParserError{
		code:     code,
		location: sanitizeLocation(location),
		details:  details,
	}
}

// Error returns a bounded diagnostic without raw message-derived values.
func (e *ParserError) Error() string {
	if e == nil {
		return "rawmsg parser error: <nil>"
	}

	msg := fmt.Sprintf("rawmsg parser error: code=%s reason=%s offset=%d line=%d column=%d",
		safeDiagnosticToken(string(e.code)), safeDiagnosticToken(string(e.details.Reason)),
		e.location.Offset, e.location.Line, e.location.Column)
	if e.details.PolicyName != "" {
		msg += fmt.Sprintf(" policy=%s", safeDiagnosticToken(e.details.PolicyName))
	}
	if e.details.Limit > 0 {
		msg += fmt.Sprintf(" limit=%d", e.details.Limit)
	}

	return msg
}

// Is matches parser errors by code for errors.Is.
func (e *ParserError) Is(target error) bool {
	var targetErr *ParserError
	if !errors.As(target, &targetErr) {
		return false
	}

	return e != nil && targetErr != nil && e.code == targetErr.code
}

// Code returns the stable parser error code.
func (e *ParserError) Code() ErrorCode {
	if e == nil {
		return ""
	}

	return e.code
}

// Location returns bounded byte and line context for the error.
func (e *ParserError) Location() ErrorLocation {
	if e == nil {
		return ErrorLocation{}
	}

	return e.location
}

// ReasonClass returns the stable operational error class.
func (e *ParserError) ReasonClass() ErrorReasonClass {
	if e == nil {
		return ""
	}

	return e.details.Reason
}

// PolicyName returns the bounded parser policy name associated with the error.
func (e *ParserError) PolicyName() string {
	if e == nil {
		return ""
	}

	return e.details.PolicyName
}

// LimitName returns the resource limit name for structured callers only.
func (e *ParserError) LimitName() string {
	if e == nil {
		return ""
	}

	return e.details.LimitName
}

// Limit returns the numeric resource limit associated with the error.
func (e *ParserError) Limit() int {
	if e == nil {
		return 0
	}

	return e.details.Limit
}

// IsParserErrorCode reports whether err contains a ParserError with code.
func IsParserErrorCode(err error, code ErrorCode) bool {
	var parserErr *ParserError
	if !errors.As(err, &parserErr) {
		return false
	}

	return parserErr.Code() == code
}

// reasonForCode maps stable error codes to default reason classes.
func reasonForCode(code ErrorCode) ErrorReasonClass {
	switch code {
	case ErrorCodeBareLF, ErrorCodeBareCR, ErrorCodeMixedLineEndings, ErrorCodeMissingDelimiter, ErrorCodeInvalidTransportForm:
		return ErrorReasonPolicy
	case ErrorCodeMalformedHeader:
		return ErrorReasonMalformed
	case ErrorCodeLimitExceeded:
		return ErrorReasonLimit
	case ErrorCodeInvalidInvariant:
		return ErrorReasonInvariant
	default:
		return ErrorReasonMalformed
	}
}

// sanitizeLocation prevents negative offsets from leaking invalid context.
func sanitizeLocation(location ErrorLocation) ErrorLocation {
	if location.Offset < 0 {
		location.Offset = 0
	}
	if location.Line < 0 {
		location.Line = 0
	}
	if location.Column < 0 {
		location.Column = 0
	}

	return location
}

// safeDiagnosticToken bounds structured tokens before including them in errors.
func safeDiagnosticToken(value string) string {
	const maxDiagnosticTokenBytes = 64

	if value == "" {
		return "unknown"
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
