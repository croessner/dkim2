package signature

import (
	"errors"
	"fmt"
	"io"
)

// ErrorCode identifies a bounded DKIM2-Signature parser failure.
type ErrorCode string

const (
	// ErrorCodeWrongHeaderField reports a non DKIM2-Signature header field.
	ErrorCodeWrongHeaderField ErrorCode = "wrong_header_field"
	// ErrorCodeMissingRequiredTag reports an omitted required signature tag.
	ErrorCodeMissingRequiredTag ErrorCode = "missing_required_tag"
	// ErrorCodeInvalidNumber reports malformed, zero, or overflowing i= or m= syntax.
	ErrorCodeInvalidNumber ErrorCode = "invalid_number"
	// ErrorCodeInvalidTimestamp reports malformed or overflowing t= syntax.
	ErrorCodeInvalidTimestamp ErrorCode = "invalid_timestamp"
	// ErrorCodeInvalidEnvelopeBase64 reports malformed mf= or rt= base64 syntax.
	ErrorCodeInvalidEnvelopeBase64 ErrorCode = "invalid_envelope_base64"
	// ErrorCodeInvalidEnvelopePath reports decoded mf= or rt= path shape failure.
	ErrorCodeInvalidEnvelopePath ErrorCode = "invalid_envelope_path"
	// ErrorCodeInvalidDomain reports d= or nd= outside parser-level DNS-label syntax.
	ErrorCodeInvalidDomain ErrorCode = "invalid_domain"
	// ErrorCodeInvalidEnvelopeForm reports a missing or conflicting nd=/mf=/rt= combination.
	ErrorCodeInvalidEnvelopeForm ErrorCode = "invalid_envelope_form"
	// ErrorCodeMalformedSignatureSet reports malformed selector:algorithm:signature syntax.
	ErrorCodeMalformedSignatureSet ErrorCode = "malformed_signature_set"
	// ErrorCodeDuplicateSelector reports duplicate selectors inside s=.
	ErrorCodeDuplicateSelector ErrorCode = "duplicate_selector"
	// ErrorCodeTooManySignatures reports a third occurrence of one signing algorithm.
	ErrorCodeTooManySignatures ErrorCode = "too_many_signatures"
	// ErrorCodeInvalidSignatureBase64 reports malformed s= signature base64 syntax.
	ErrorCodeInvalidSignatureBase64 ErrorCode = "invalid_signature_base64"
	// ErrorCodeInvalidSignatureLength reports a known signature with the wrong size.
	ErrorCodeInvalidSignatureLength ErrorCode = "invalid_signature_length"
	// ErrorCodeInvalidNonce reports malformed or oversized n= syntax.
	ErrorCodeInvalidNonce ErrorCode = "invalid_nonce"
	// ErrorCodeMalformedFlag reports malformed f= flag syntax.
	ErrorCodeMalformedFlag ErrorCode = "malformed_flag"
	// ErrorCodeDuplicateKnownFlag reports duplicate known flags inside f=.
	ErrorCodeDuplicateKnownFlag ErrorCode = "duplicate_known_flag"
	// ErrorCodeLimitExceeded reports a DKIM2-Signature resource-limit violation.
	ErrorCodeLimitExceeded ErrorCode = "limit_exceeded"
	// ErrorCodeInvalidOptions reports unsafe DKIM2-Signature parser options.
	ErrorCodeInvalidOptions ErrorCode = "invalid_options"
	// ErrorCodeMissingOrigin reports a collection without i=1.
	ErrorCodeMissingOrigin ErrorCode = "missing_origin"
	// ErrorCodeDuplicateSequence reports repeated DKIM2-Signature i= numbers.
	ErrorCodeDuplicateSequence ErrorCode = "duplicate_sequence"
	// ErrorCodeSequenceGap reports a missing DKIM2-Signature i= number.
	ErrorCodeSequenceGap ErrorCode = "sequence_gap"
	// ErrorCodeUnreferencedInstance reports a Message-Instance above every signature m= reference.
	ErrorCodeUnreferencedInstance ErrorCode = "unreferenced_instance"
	// ErrorCodeInvalidInstanceReference reports missing or decreasing signature m= references.
	ErrorCodeInvalidInstanceReference ErrorCode = "invalid_instance_reference"
	// ErrorCodeInvalidConstruction reports invalid generated-field input.
	ErrorCodeInvalidConstruction ErrorCode = "invalid_construction"
	// ErrorCodeRenderInvariant reports an internal generated-field rendering failure.
	ErrorCodeRenderInvariant ErrorCode = "render_invariant"
	// ErrorCodeCustodyMismatch reports a fail-closed custody transition or alignment failure.
	ErrorCodeCustodyMismatch ErrorCode = "custody_mismatch"
)

// Known reports whether code belongs to the closed DKIM2-Signature vocabulary.
func (c ErrorCode) Known() bool {
	switch c {
	case ErrorCodeWrongHeaderField, ErrorCodeMissingRequiredTag, ErrorCodeInvalidNumber,
		ErrorCodeInvalidTimestamp, ErrorCodeInvalidEnvelopeBase64, ErrorCodeInvalidEnvelopePath,
		ErrorCodeInvalidDomain, ErrorCodeInvalidEnvelopeForm, ErrorCodeMalformedSignatureSet,
		ErrorCodeDuplicateSelector, ErrorCodeTooManySignatures,
		ErrorCodeInvalidSignatureBase64, ErrorCodeInvalidSignatureLength, ErrorCodeInvalidNonce,
		ErrorCodeMalformedFlag, ErrorCodeDuplicateKnownFlag, ErrorCodeLimitExceeded,
		ErrorCodeInvalidOptions, ErrorCodeMissingOrigin, ErrorCodeDuplicateSequence,
		ErrorCodeSequenceGap, ErrorCodeUnreferencedInstance, ErrorCodeInvalidInstanceReference, ErrorCodeInvalidConstruction,
		ErrorCodeRenderInvariant, ErrorCodeCustodyMismatch:
		return true
	default:
		return false
	}
}

// ErrorClass groups DKIM2-Signature parser failures for stable callers.
type ErrorClass string

const (
	// ErrorClassMalformed classifies malformed DKIM2-Signature syntax.
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

// Known reports whether class belongs to the closed DKIM2-Signature vocabulary.
func (c ErrorClass) Known() bool {
	return c == ErrorClassMalformed || c == ErrorClassMissing || c == ErrorClassDuplicate ||
		c == ErrorClassLimit || c == ErrorClassInvariant
}

// TagName identifies one closed DKIM2-Signature tag name.
type TagName string

// DKIM2-Signature tag names form the closed diagnostic vocabulary.
const (
	TagNameSequence   TagName = "i"
	TagNameInstance   TagName = "m"
	TagNameTimestamp  TagName = "t"
	TagNameMailFrom   TagName = "mf"
	TagNameRecipients TagName = "rt"
	TagNameNextDomain TagName = "nd"
	TagNameDomain     TagName = "d"
	TagNameSignatures TagName = "s"
	TagNameNonce      TagName = "n"
	TagNameFlags      TagName = "f"
)

// Known reports whether name belongs to the closed signature tag vocabulary.
func (n TagName) Known() bool {
	switch n {
	case TagNameSequence, TagNameInstance, TagNameTimestamp, TagNameMailFrom,
		TagNameRecipients, TagNameNextDomain, TagNameDomain, TagNameSignatures,
		TagNameNonce, TagNameFlags:
		return true
	default:
		return false
	}
}

// LimitName identifies one closed DKIM2-Signature limit name.
type LimitName string

// DKIM2-Signature limit names form the closed resource vocabulary.
const (
	LimitNameMaxRecipients        LimitName = "max_recipients"
	LimitNameMaxSignatureSets     LimitName = "max_signature_sets"
	LimitNameMaxFlags             LimitName = "max_flags"
	LimitNameMaxNonceBytes        LimitName = "max_nonce_bytes"
	LimitNameMaxSignatures        LimitName = "max_signatures"
	LimitNameMaxFieldBytes        LimitName = "max_field_bytes"
	LimitNameMaxLineBytes         LimitName = "max_line_bytes"
	LimitNameMaxEnvelopePathBytes LimitName = "max_envelope_path_bytes"
	LimitNameMaxSignatureBytes    LimitName = "max_signature_bytes"
	LimitNameRenderCoherence      LimitName = "render_limit_coherence"
)

// Known reports whether name belongs to the closed signature limit vocabulary.
func (n LimitName) Known() bool {
	switch n {
	case LimitNameMaxRecipients, LimitNameMaxSignatureSets, LimitNameMaxFlags,
		LimitNameMaxNonceBytes, LimitNameMaxSignatures, LimitNameMaxFieldBytes,
		LimitNameMaxLineBytes, LimitNameMaxEnvelopePathBytes,
		LimitNameMaxSignatureBytes, LimitNameRenderCoherence:
		return true
	default:
		return false
	}
}

// ErrorLocation identifies bounded DKIM2-Signature parser context.
type ErrorLocation struct {
	// FieldIndex records the rawmsg header occurrence index when known.
	FieldIndex int
	// RecipientIndex records the zero-based rt= path index when relevant.
	RecipientIndex int
	// SignatureIndex records the zero-based s= set index when relevant.
	SignatureIndex int
	// FlagIndex records the zero-based f= flag index when relevant.
	FlagIndex int
}

// ErrorDetails carries bounded parser metadata for Error.
type ErrorDetails struct {
	// Class records the stable operational class for the error.
	Class ErrorClass
	// TagName records an allowlisted DKIM2-Signature tag when relevant.
	TagName TagName
	// LimitName records the resource limit identifier for structured callers.
	LimitName LimitName
	// Limit records the configured limit when relevant.
	Limit int
	// Count records the observed count or size when relevant.
	Count int
	// ExpectedNumber records the sequence or reference number required by validation.
	ExpectedNumber uint64
	// ObservedNumber records the sequence or reference number found by validation.
	ObservedNumber uint64
}

// Error is a typed, secret-safe DKIM2-Signature parser error.
type Error struct {
	code     ErrorCode
	location ErrorLocation
	details  ErrorDetails
	cause    error
}

// newError constructs a bounded parser error without raw field data.
func newError(code ErrorCode, location ErrorLocation, details ErrorDetails, cause error) *Error {
	if !code.Known() {
		code = ErrorCodeRenderInvariant
	}
	details.Class = classForCode(code)

	if !details.TagName.Known() {
		details.TagName = ""
	}
	if !details.LimitName.Known() {
		details.LimitName = ""
	}

	return &Error{
		code:     code,
		location: sanitizeLocation(location),
		details:  sanitizeDetails(details),
		cause:    cause,
	}
}

// Error returns a bounded diagnostic without raw envelope, nonce, or signature data.
func (e *Error) Error() string {
	if e == nil {
		return "signature parser error: <nil>"
	}

	msg := fmt.Sprintf(
		"signature parser error: code=%s class=%s field_index=%d recipient_index=%d signature_index=%d flag_index=%d",
		safeDiagnosticToken(string(e.code)),
		safeDiagnosticToken(string(e.details.Class)),
		e.location.FieldIndex,
		e.location.RecipientIndex,
		e.location.SignatureIndex,
		e.location.FlagIndex,
	)
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

// GoString returns the same secret-safe diagnostic for Go-syntax formatting.
func (e *Error) GoString() string { return e.Error() }

// Format routes every fmt form through the secret-safe diagnostic.
func (e *Error) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, e.Error()) }

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

	return string(e.details.TagName)
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

// ExpectedNumber returns the required sequence or reference number for validation errors.
func (e *Error) ExpectedNumber() uint64 {
	if e == nil {
		return 0
	}

	return e.details.ExpectedNumber
}

// ObservedNumber returns the observed sequence or reference number for validation errors.
func (e *Error) ObservedNumber() uint64 {
	if e == nil {
		return 0
	}

	return e.details.ObservedNumber
}

// IsErrorCode reports whether err contains a signature Error with code.
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
	case ErrorCodeDuplicateSelector, ErrorCodeDuplicateKnownFlag, ErrorCodeDuplicateSequence:
		return ErrorClassDuplicate
	case ErrorCodeLimitExceeded, ErrorCodeTooManySignatures:
		return ErrorClassLimit
	case ErrorCodeInvalidOptions, ErrorCodeRenderInvariant:
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
	if location.RecipientIndex < 0 {
		location.RecipientIndex = 0
	}
	if location.SignatureIndex < 0 {
		location.SignatureIndex = 0
	}
	if location.FlagIndex < 0 {
		location.FlagIndex = 0
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
