package recipe

import (
	"errors"
	"fmt"
)

// ErrorCode identifies one closed recipe failure.
type ErrorCode string

const (
	// ErrorCodeInvalidOptions reports unsafe or incoherent recipe limits.
	ErrorCodeInvalidOptions ErrorCode = "invalid_options"
	// ErrorCodeInvalidState reports a zero or incoherent recipe domain value.
	ErrorCodeInvalidState ErrorCode = "invalid_state"
	// ErrorCodeLimitExceeded reports a bounded resource limit failure.
	ErrorCodeLimitExceeded ErrorCode = "limit_exceeded"
	// ErrorCodeInvalidJSON reports malformed RFC 8259 syntax.
	ErrorCodeInvalidJSON ErrorCode = "invalid_json"
	// ErrorCodeDuplicateMember reports repeated JSON object names.
	ErrorCodeDuplicateMember ErrorCode = "duplicate_member"
	// ErrorCodeInvalidTopLevel reports a non-object recipe root.
	ErrorCodeInvalidTopLevel ErrorCode = "invalid_top_level"
	// ErrorCodeMissingRecipeDimension reports a root without h or b.
	ErrorCodeMissingRecipeDimension ErrorCode = "missing_recipe_dimension"
	// ErrorCodeInvalidHeaderName reports a non-RFC 5322 recipe key.
	ErrorCodeInvalidHeaderName ErrorCode = "invalid_header_name"
	// ErrorCodeHeaderNameCollision reports ASCII case-folded key duplication.
	ErrorCodeHeaderNameCollision ErrorCode = "header_name_collision"
	// ErrorCodeInvalidHeaderRecipe reports an invalid h member shape.
	ErrorCodeInvalidHeaderRecipe ErrorCode = "invalid_header_recipe"
	// ErrorCodeInvalidBodyRecipe reports an invalid b member shape.
	ErrorCodeInvalidBodyRecipe ErrorCode = "invalid_body_recipe"
	// ErrorCodeInvalidStep reports an unknown or mixed recipe step.
	ErrorCodeInvalidStep ErrorCode = "invalid_step"
	// ErrorCodeInvalidCopyRange reports invalid inclusive copy coordinates.
	ErrorCodeInvalidCopyRange ErrorCode = "invalid_copy_range"
	// ErrorCodeCopyRangeOrder reports overlapping or descending copy ranges.
	ErrorCodeCopyRangeOrder ErrorCode = "copy_range_order"
	// ErrorCodeCopyRangeOutOfBounds reports a range outside its source.
	ErrorCodeCopyRangeOutOfBounds ErrorCode = "copy_range_out_of_bounds"
	// ErrorCodeInvalidLiteral reports invalid UTF-8 or line-breaking data.
	ErrorCodeInvalidLiteral ErrorCode = "invalid_literal"
	// ErrorCodeSourceUnavailable reports a copy operation without source bytes.
	ErrorCodeSourceUnavailable ErrorCode = "source_unavailable"
)

// Known reports whether code belongs to the closed recipe vocabulary.
func (c ErrorCode) Known() bool {
	switch c {
	case ErrorCodeInvalidOptions, ErrorCodeInvalidState, ErrorCodeLimitExceeded, ErrorCodeInvalidJSON,
		ErrorCodeDuplicateMember, ErrorCodeInvalidTopLevel, ErrorCodeMissingRecipeDimension,
		ErrorCodeInvalidHeaderName, ErrorCodeHeaderNameCollision, ErrorCodeInvalidHeaderRecipe,
		ErrorCodeInvalidBodyRecipe, ErrorCodeInvalidStep, ErrorCodeInvalidCopyRange,
		ErrorCodeCopyRangeOrder, ErrorCodeCopyRangeOutOfBounds, ErrorCodeInvalidLiteral,
		ErrorCodeSourceUnavailable:
		return true
	default:
		return false
	}
}

// ErrorClass groups recipe failures without retaining input.
type ErrorClass string

const (
	// ErrorClassOptions identifies constructor configuration failures.
	ErrorClassOptions ErrorClass = "options"
	// ErrorClassState identifies invalid domain states.
	ErrorClassState ErrorClass = "state"
	// ErrorClassLimit identifies resource-limit failures.
	ErrorClassLimit ErrorClass = "limit"
	// ErrorClassSyntax identifies malformed JSON text.
	ErrorClassSyntax ErrorClass = "syntax"
	// ErrorClassSchema identifies recipe-v1 shape failures.
	ErrorClassSchema ErrorClass = "schema"
	// ErrorClassRange identifies invalid copy coordinates.
	ErrorClassRange ErrorClass = "range"
	// ErrorClassSource identifies unavailable reconstruction input.
	ErrorClassSource ErrorClass = "source"
)

// Known reports whether class belongs to the closed recipe vocabulary.
func (c ErrorClass) Known() bool {
	return c == ErrorClassOptions || c == ErrorClassState || c == ErrorClassLimit ||
		c == ErrorClassSyntax || c == ErrorClassSchema || c == ErrorClassRange || c == ErrorClassSource
}

// Dimension identifies one bounded recipe dimension.
type Dimension string

const (
	// DimensionRecipe identifies whole-plan processing.
	DimensionRecipe Dimension = "recipe"
	// DimensionHeader identifies header reconstruction.
	DimensionHeader Dimension = "header"
	// DimensionBody identifies body reconstruction.
	DimensionBody Dimension = "body"
)

// Known reports whether dimension belongs to the closed recipe vocabulary.
func (d Dimension) Known() bool {
	return d == DimensionRecipe || d == DimensionHeader || d == DimensionBody
}

// ErrorLocation carries bounded structural coordinates only.
type ErrorLocation struct {
	Offset        int
	StepIndex     int
	MemberIndex   int
	HeaderOrdinal int
	BodyLine      int
}

// ErrorDetails carries bounded closed recipe diagnostics.
type ErrorDetails struct {
	Class     ErrorClass
	LimitName string
	Expected  int
	Actual    int
	Dimension Dimension
	StepKind  StepKind
}

// Error is a typed recipe failure that never retains input-derived causes.
type Error struct {
	code     ErrorCode
	location ErrorLocation
	details  ErrorDetails
}

// newError constructs a bounded error and deliberately drops arbitrary causes.
func newError(code ErrorCode, location ErrorLocation, details ErrorDetails, _ error) *Error {
	if !details.Class.Known() {
		details.Class = classForCode(code)
	}
	location = sanitizeErrorLocation(location)
	if !details.Dimension.Known() {
		details.Dimension = ""
	}
	if !details.StepKind.Known() {
		details.StepKind = ""
	}
	if !knownLimitName(details.LimitName) {
		details.LimitName = ""
	}
	if details.Expected < 0 {
		details.Expected = 0
	}
	if details.Actual < 0 {
		details.Actual = 0
	}

	return &Error{code: code, location: location, details: details}
}

// Error returns a deterministic secret-safe recipe diagnostic.
func (e *Error) Error() string {
	if e == nil {
		return "recipe error: <nil>"
	}
	message := fmt.Sprintf("recipe error: code=%s class=%s offset=%d step=%d member=%d header=%d body_line=%d",
		e.code, e.details.Class, e.location.Offset, e.location.StepIndex,
		e.location.MemberIndex, e.location.HeaderOrdinal, e.location.BodyLine)
	if e.details.LimitName != "" {
		message += fmt.Sprintf(" limit_name=%s", e.details.LimitName)
	}
	if e.details.Expected > 0 {
		message += fmt.Sprintf(" expected=%d", e.details.Expected)
	}
	if e.details.Actual > 0 {
		message += fmt.Sprintf(" actual=%d", e.details.Actual)
	}
	if e.details.Dimension.Known() {
		message += fmt.Sprintf(" dimension=%s", e.details.Dimension)
	}
	if e.details.StepKind.Known() {
		message += fmt.Sprintf(" step_kind=%s", e.details.StepKind)
	}
	return message
}

// Is matches recipe errors by stable code.
func (e *Error) Is(target error) bool {
	var typed *Error
	return e != nil && errors.As(target, &typed) && typed != nil && e.code == typed.code
}

// Code returns the closed recipe error code.
func (e *Error) Code() ErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}

// Class returns the closed recipe error class.
func (e *Error) Class() ErrorClass {
	if e == nil {
		return ""
	}
	return e.details.Class
}

// Location returns bounded structural coordinates.
func (e *Error) Location() ErrorLocation {
	if e == nil {
		return ErrorLocation{}
	}
	return e.location
}

// LimitName returns a stable configured limit identifier.
func (e *Error) LimitName() string {
	if e == nil {
		return ""
	}
	return e.details.LimitName
}

// Dimension returns the closed recipe dimension associated with the failure.
func (e *Error) Dimension() Dimension {
	if e == nil {
		return ""
	}
	return e.details.Dimension
}

// IsErrorCode reports whether err contains a recipe Error with code.
func IsErrorCode(err error, code ErrorCode) bool {
	var typed *Error
	return errors.As(err, &typed) && typed.Code() == code
}

// classForCode maps closed codes to stable classes.
func classForCode(code ErrorCode) ErrorClass {
	switch code {
	case ErrorCodeInvalidOptions:
		return ErrorClassOptions
	case ErrorCodeInvalidState:
		return ErrorClassState
	case ErrorCodeLimitExceeded:
		return ErrorClassLimit
	case ErrorCodeInvalidJSON, ErrorCodeDuplicateMember, ErrorCodeInvalidTopLevel:
		return ErrorClassSyntax
	case ErrorCodeMissingRecipeDimension, ErrorCodeInvalidHeaderName,
		ErrorCodeHeaderNameCollision, ErrorCodeInvalidHeaderRecipe,
		ErrorCodeInvalidBodyRecipe, ErrorCodeInvalidStep, ErrorCodeInvalidLiteral:
		return ErrorClassSchema
	case ErrorCodeInvalidCopyRange, ErrorCodeCopyRangeOrder, ErrorCodeCopyRangeOutOfBounds:
		return ErrorClassRange
	case ErrorCodeSourceUnavailable:
		return ErrorClassSource
	default:
		return ErrorClassState
	}
}

// sanitizeErrorLocation clamps impossible negative coordinates.
func sanitizeErrorLocation(location ErrorLocation) ErrorLocation {
	if location.Offset < 0 {
		location.Offset = 0
	}
	if location.StepIndex < 0 {
		location.StepIndex = 0
	}
	if location.MemberIndex < 0 {
		location.MemberIndex = 0
	}
	if location.HeaderOrdinal < 0 {
		location.HeaderOrdinal = 0
	}
	if location.BodyLine < 0 {
		location.BodyLine = 0
	}
	return location
}

// knownLimitName permits only closed repository-owned recipe limit identifiers.
func knownLimitName(value string) bool {
	switch value {
	case limitNameMaxDecodedRecipeBytes, limitNameMaxJSONDepth, limitNameMaxJSONMembers, limitNameMaxJSONTokens,
		limitNameMaxHeaderNames, limitNameMaxHeaderNameBytes, limitNameMaxTotalHeaderNameBytes,
		limitNameMaxStepsPerHeader, limitNameMaxBodySteps, limitNameMaxTotalSteps, limitNameMaxCopyRanges,
		limitNameMaxCopiedItemsPerRange, limitNameMaxTotalCopiedItems, limitNameMaxDataStrings,
		limitNameMaxDataStringBytes, limitNameMaxTotalLiteralBytes, limitNameMaxHeaderFields,
		limitNameMaxHeaderFieldBytes, limitNameMaxHeaderLineBytes, limitNameMaxHeaderBytes,
		limitNameMaxBodyLines, limitNameMaxBodyLineBytes, limitNameMaxStateBytes, limitNameMaxOperationWorkUnits,
		"literal_limit_coherence", "step_limit_coherence", "copy_limit_coherence":
		return true
	default:
		return false
	}
}
