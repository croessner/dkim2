package dsn

import (
	"errors"
	"fmt"
)

// ErrorCode identifies one closed DSN structural parser failure.
type ErrorCode string

const (
	// ErrorCodeInvalidOptions reports incoherent resource limits.
	ErrorCodeInvalidOptions ErrorCode = "invalid_options"
	// ErrorCodeInvalidMessage reports raw RFC 5322 input rejected before DSN parsing.
	ErrorCodeInvalidMessage ErrorCode = "invalid_message"
	// ErrorCodeMissingContentType reports an absent required Content-Type field.
	ErrorCodeMissingContentType ErrorCode = "missing_content_type"
	// ErrorCodeInvalidContentType reports malformed or duplicate MIME content-type metadata.
	ErrorCodeInvalidContentType ErrorCode = "invalid_content_type"
	// ErrorCodeInvalidReportType reports a multipart report without report-type=delivery-status.
	ErrorCodeInvalidReportType ErrorCode = "invalid_report_type"
	// ErrorCodeInvalidBoundary reports a missing, invalid, or unsafe MIME boundary.
	ErrorCodeInvalidBoundary ErrorCode = "invalid_boundary"
	// ErrorCodeMalformedMultipart reports structurally malformed multipart framing.
	ErrorCodeMalformedMultipart ErrorCode = "malformed_multipart"
	// ErrorCodeInvalidPartCount reports a report that does not contain exactly three parts.
	ErrorCodeInvalidPartCount ErrorCode = "invalid_part_count"
	// ErrorCodeInvalidPart reports a MIME part that is not a bounded raw RFC 5322 entity.
	ErrorCodeInvalidPart ErrorCode = "invalid_part"
	// ErrorCodeInvalidPartContentType reports an unexpected required DSN part media type.
	ErrorCodeInvalidPartContentType ErrorCode = "invalid_part_content_type"
	// ErrorCodeLimitExceeded reports a configured parser resource limit violation.
	ErrorCodeLimitExceeded ErrorCode = "limit_exceeded"
)

const (
	// LimitNameMaxMessageBytes identifies the full report byte ceiling.
	LimitNameMaxMessageBytes = "max_message_bytes"
	// LimitNameMaxPartBytes identifies the individual MIME-part byte ceiling.
	LimitNameMaxPartBytes = "max_part_bytes"
	// LimitNameMaxBoundaryBytes identifies the MIME-boundary byte ceiling.
	LimitNameMaxBoundaryBytes = "max_boundary_bytes"
)

// Error is a typed, content-free DSN structural parser error.
type Error struct {
	code      ErrorCode
	partIndex int
	limitName string
	limit     int
	actual    int
}

// Error returns a deterministic diagnostic without raw message-derived content.
func (e *Error) Error() string {
	if e == nil {
		return "dsn error: <nil>"
	}
	message := fmt.Sprintf("dsn error: code=%s part=%d", e.code, e.partIndex)
	if e.limitName != "" {
		message += fmt.Sprintf(" limit_name=%s limit=%d actual=%d", e.limitName, e.limit, e.actual)
	}
	return message
}

// Is matches DSN errors by their stable code.
func (e *Error) Is(target error) bool {
	var targetError *Error
	return errors.As(target, &targetError) && e != nil && targetError != nil && e.code == targetError.code
}

// Code returns the stable error code.
func (e *Error) Code() ErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}

// PartIndex returns the one-based MIME part index when the error is part-specific.
func (e *Error) PartIndex() int {
	if e == nil {
		return 0
	}
	return e.partIndex
}

// LimitName returns the bounded resource-limit name when relevant.
func (e *Error) LimitName() string {
	if e == nil {
		return ""
	}
	return e.limitName
}

// Limit returns the configured resource ceiling when relevant.
func (e *Error) Limit() int {
	if e == nil {
		return 0
	}
	return e.limit
}

// Actual returns the observed bounded size when relevant.
func (e *Error) Actual() int {
	if e == nil {
		return 0
	}
	return e.actual
}

// IsErrorCode reports whether err contains the requested DSN error code.
func IsErrorCode(err error, code ErrorCode) bool {
	var dsnError *Error
	return errors.As(err, &dsnError) && dsnError.Code() == code
}

// newError constructs one bounded content-free DSN error.
func newError(code ErrorCode, partIndex int, limitName string, limit int, actual int) *Error {
	if partIndex < 0 || partIndex > 3 {
		partIndex = 0
	}
	if limit < 0 {
		limit = 0
	}
	if actual < 0 {
		actual = 0
	}
	if limitName != LimitNameMaxMessageBytes && limitName != LimitNameMaxPartBytes && limitName != LimitNameMaxBoundaryBytes {
		limitName = ""
	}
	return &Error{code: code, partIndex: partIndex, limitName: limitName, limit: limit, actual: actual}
}
