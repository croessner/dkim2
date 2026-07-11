package verify

import (
	"errors"
	"fmt"
)

const redactedDiagnosticToken = "redacted"

// ErrorCode identifies a bounded verification failure.
type ErrorCode string

const (
	// ErrorCodeInvalidOptions reports unsafe verifier construction settings.
	ErrorCodeInvalidOptions ErrorCode = "invalid_options"
	// ErrorCodeInvalidRequest reports unsafe verifier request shape.
	ErrorCodeInvalidRequest ErrorCode = "invalid_request"
	// ErrorCodeLimitExceeded reports a verification resource-limit violation.
	ErrorCodeLimitExceeded ErrorCode = "limit_exceeded"
	// ErrorCodeUnsupportedAlgorithm reports an algorithm outside the active contract.
	ErrorCodeUnsupportedAlgorithm ErrorCode = "unsupported_algorithm"
	// ErrorCodeUnsupportedTarget reports a target requiring unavailable historical message bytes.
	ErrorCodeUnsupportedTarget ErrorCode = "unsupported_target"
	// ErrorCodeDisabledAlgorithm reports an algorithm disabled by local policy.
	ErrorCodeDisabledAlgorithm ErrorCode = "disabled_algorithm"
	// ErrorCodeMissingKey reports absent public key material.
	ErrorCodeMissingKey ErrorCode = "missing_key"
	// ErrorCodeAmbiguousKey reports multiple matching public keys.
	ErrorCodeAmbiguousKey ErrorCode = "ambiguous_key"
	// ErrorCodeInvalidKey reports malformed or mismatched public key material.
	ErrorCodeInvalidKey ErrorCode = "invalid_key"
	// ErrorCodeWrongKeyType reports key material with the wrong Go public-key type.
	ErrorCodeWrongKeyType ErrorCode = "wrong_key_type"
	// ErrorCodeKeyPolicyRejected reports a key rejected by local policy.
	ErrorCodeKeyPolicyRejected ErrorCode = "key_policy_rejected"
	// ErrorCodeProviderError reports a bounded key-provider failure.
	ErrorCodeProviderError ErrorCode = "provider_error"
	// ErrorCodeMalformedState reports malformed parser-owned verification state.
	ErrorCodeMalformedState ErrorCode = "malformed_state"
	// ErrorCodeSequenceInvalid reports non-contiguous or duplicate extracted numbering.
	ErrorCodeSequenceInvalid ErrorCode = "sequence_invalid"
	// ErrorCodeMissingTarget reports a missing signature or instance target.
	ErrorCodeMissingTarget ErrorCode = "missing_target"
	// ErrorCodeDuplicateTarget reports duplicate signature or instance targets.
	ErrorCodeDuplicateTarget ErrorCode = "duplicate_target"
	// ErrorCodeHashMismatch reports body or header hash mismatch.
	ErrorCodeHashMismatch ErrorCode = "hash_mismatch"
	// ErrorCodeSignatureMismatch reports cryptographic signature mismatch.
	ErrorCodeSignatureMismatch ErrorCode = "signature_mismatch"
	// ErrorCodeTimestampInvalid reports timestamp policy failure.
	ErrorCodeTimestampInvalid ErrorCode = "timestamp_invalid"
	// ErrorCodeEnvelopeMismatch reports current-envelope mismatch.
	ErrorCodeEnvelopeMismatch ErrorCode = "envelope_mismatch"
	// ErrorCodeDomainAlignmentMismatch reports d= and mf= domain misalignment.
	ErrorCodeDomainAlignmentMismatch ErrorCode = "domain_alignment_mismatch"
	// ErrorCodeNextDomainMismatch reports nd= not matching the next signature d=.
	ErrorCodeNextDomainMismatch ErrorCode = "next_domain_mismatch"
	// ErrorCodeMissingNextSignature reports nd= without its immediate successor signature.
	ErrorCodeMissingNextSignature ErrorCode = "missing_next_signature"
	// ErrorCodeOutOfBandRequired reports terminal nd= requiring unavailable OOB acceptance.
	ErrorCodeOutOfBandRequired ErrorCode = "out_of_band_required"
	// ErrorCodeInternalMisuse reports invalid internal verifier API use.
	ErrorCodeInternalMisuse ErrorCode = "internal_misuse"
)

// ErrorClass groups verification failures for stable callers.
type ErrorClass string

const (
	// ErrorClassInvariant classifies invalid options or internal invariants.
	ErrorClassInvariant ErrorClass = "invariant"
	// ErrorClassRequest classifies invalid request shapes.
	ErrorClassRequest ErrorClass = "request"
	// ErrorClassLimit classifies resource-limit failures.
	ErrorClassLimit ErrorClass = "limit"
	// ErrorClassAlgorithm classifies unsupported or disabled algorithm state.
	ErrorClassAlgorithm ErrorClass = "algorithm"
	// ErrorClassUnsupported classifies behavior the current verifier cannot reconstruct safely.
	ErrorClassUnsupported ErrorClass = "unsupported"
	// ErrorClassKey classifies key lookup or key validation failures.
	ErrorClassKey ErrorClass = "key"
	// ErrorClassMalformed classifies malformed parser-owned state.
	ErrorClassMalformed ErrorClass = "malformed"
	// ErrorClassMissing classifies missing required verification targets.
	ErrorClassMissing ErrorClass = "missing"
	// ErrorClassDuplicate classifies duplicate verification targets.
	ErrorClassDuplicate ErrorClass = "duplicate"
	// ErrorClassHash classifies body or header hash mismatch.
	ErrorClassHash ErrorClass = "hash"
	// ErrorClassSignature classifies cryptographic signature failure.
	ErrorClassSignature ErrorClass = "signature"
	// ErrorClassTimestamp classifies timestamp policy failure.
	ErrorClassTimestamp ErrorClass = "timestamp"
	// ErrorClassEnvelope classifies current-envelope mismatch.
	ErrorClassEnvelope ErrorClass = "envelope"
	// ErrorClassNextDomain classifies nd= chain validation failures.
	ErrorClassNextDomain ErrorClass = "next_domain"
	// ErrorClassInternal classifies package misuse not derived from message input.
	ErrorClassInternal ErrorClass = "internal"
)

// ErrorLocation identifies bounded verification context.
type ErrorLocation struct {
	// Check records the verification check dimension.
	Check CheckKind
	// SignatureIndex records a zero-based s= set position when relevant.
	SignatureIndex int
	// TargetSequence records a DKIM2-Signature i= value when relevant.
	TargetSequence uint64
	// InstanceNumber records a Message-Instance m= value when relevant.
	InstanceNumber uint64
}

// ErrorDetails carries bounded metadata for Error.
type ErrorDetails struct {
	// Class records the stable operational class for the error.
	Class ErrorClass
	// Algorithm records a safe signature algorithm name.
	Algorithm Algorithm
	// Status records a safe per-check status token.
	Status CheckStatus
	// LimitName records the resource limit identifier for structured callers.
	LimitName string
	// Limit records the configured limit when relevant.
	Limit int
	// Count records the observed count or size when relevant.
	Count int
	// TargetName records an allowlisted target class such as dkim2_signature.
	TargetName string
}

// Error is a typed, secret-safe verification error.
type Error struct {
	code     ErrorCode
	location ErrorLocation
	details  ErrorDetails
	cause    error
	custody  CustodyStatus
}

// CustodyStatus returns established whole-sequence coverage for chain errors.
func (e *Error) CustodyStatus() CustodyStatus {
	if e == nil {
		return ""
	}
	return e.custody
}

// newError constructs a bounded verification error without raw message data.
func newError(code ErrorCode, location ErrorLocation, details ErrorDetails, cause error) *Error {
	if details.Class == "" {
		details.Class = classForCode(code)
	}

	details.Algorithm = Algorithm(safeDiagnosticToken(string(details.Algorithm)))
	details.LimitName = safeDiagnosticToken(details.LimitName)
	details.TargetName = safeDiagnosticToken(details.TargetName)
	if !details.Status.Known() {
		details.Status = ""
	}

	return &Error{
		code:     code,
		location: sanitizeLocation(location),
		details:  sanitizeDetails(details),
		cause:    cause,
	}
}

// Error returns a bounded diagnostic without message, envelope, signature, or key bytes.
func (e *Error) Error() string {
	if e == nil {
		return "verification error: <nil>"
	}

	msg := fmt.Sprintf("verification error: code=%s class=%s check=%s signature_index=%d target_sequence=%d instance_number=%d",
		safeDiagnosticToken(string(e.code)),
		safeDiagnosticToken(string(e.details.Class)),
		safeDiagnosticToken(string(e.location.Check)),
		e.location.SignatureIndex,
		e.location.TargetSequence,
		e.location.InstanceNumber,
	)
	if e.details.Algorithm != "" {
		msg += fmt.Sprintf(" algorithm=%s", e.details.Algorithm)
	}
	if e.details.Status != "" {
		msg += fmt.Sprintf(" status=%s", e.details.Status)
	}
	if e.details.TargetName != "" {
		msg += fmt.Sprintf(" target=%s", e.details.TargetName)
	}
	if e.details.LimitName != "" {
		msg += fmt.Sprintf(" limit_name=%s", e.details.LimitName)
	}
	if e.details.Limit > 0 {
		msg += fmt.Sprintf(" limit=%d", e.details.Limit)
	}
	if e.details.Count > 0 {
		msg += fmt.Sprintf(" count=%d", e.details.Count)
	}

	return msg
}

// Is matches verification errors by code for errors.Is.
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

// Code returns the stable verification error code.
func (e *Error) Code() ErrorCode {
	if e == nil {
		return ""
	}

	return e.code
}

// Location returns bounded verification location metadata.
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
func (e *Error) Algorithm() Algorithm {
	if e == nil {
		return ""
	}

	return e.details.Algorithm
}

// Status returns the safe check status associated with the error.
func (e *Error) Status() CheckStatus {
	if e == nil {
		return ""
	}

	return e.details.Status
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

// IsErrorCode reports whether err contains a verification Error with code.
func IsErrorCode(err error, code ErrorCode) bool {
	var verifyErr *Error
	if !errors.As(err, &verifyErr) {
		return false
	}

	return verifyErr.Code() == code
}

// invalidOptionError reports unsafe construction options without raw input.
func invalidOptionError(limitName string, value int) *Error {
	return newError(ErrorCodeInvalidOptions, ErrorLocation{}, ErrorDetails{
		Class:     ErrorClassInvariant,
		LimitName: limitName,
		Limit:     value,
	}, nil)
}

// unsupportedAlgorithmError reports an algorithm outside the verification contract.
func unsupportedAlgorithmError(algorithm Algorithm) *Error {
	return newError(ErrorCodeUnsupportedAlgorithm, ErrorLocation{Check: CheckKindSignature}, ErrorDetails{
		Class:     ErrorClassAlgorithm,
		Algorithm: algorithm,
		Status:    CheckStatusUnsupported,
	}, nil)
}

// disabledAlgorithmError reports a known algorithm disabled by local policy.
func disabledAlgorithmError(algorithm Algorithm) *Error {
	return newError(ErrorCodeDisabledAlgorithm, ErrorLocation{Check: CheckKindKey}, ErrorDetails{
		Class:     ErrorClassAlgorithm,
		Algorithm: algorithm,
		Status:    CheckStatusFail,
	}, nil)
}

// missingKeyError reports absent public key material for one algorithm.
func missingKeyError(algorithm Algorithm) *Error {
	return newError(ErrorCodeMissingKey, ErrorLocation{Check: CheckKindKey}, ErrorDetails{
		Class:     ErrorClassKey,
		Algorithm: algorithm,
		Status:    CheckStatusFail,
	}, nil)
}

// ambiguousKeyError reports duplicate or ambiguous public key material.
func ambiguousKeyError(algorithm Algorithm) *Error {
	return newError(ErrorCodeAmbiguousKey, ErrorLocation{Check: CheckKindKey}, ErrorDetails{
		Class:     ErrorClassKey,
		Algorithm: algorithm,
		Status:    CheckStatusFail,
	}, nil)
}

// invalidKeyError reports malformed public key material.
func invalidKeyError(algorithm Algorithm) *Error {
	return newError(ErrorCodeInvalidKey, ErrorLocation{Check: CheckKindKey}, ErrorDetails{
		Class:     ErrorClassKey,
		Algorithm: algorithm,
		Status:    CheckStatusFail,
	}, nil)
}

// wrongKeyTypeError reports mismatched Go public key material.
func wrongKeyTypeError(algorithm Algorithm) *Error {
	return newError(ErrorCodeWrongKeyType, ErrorLocation{Check: CheckKindKey}, ErrorDetails{
		Class:     ErrorClassKey,
		Algorithm: algorithm,
		Status:    CheckStatusFail,
	}, nil)
}

// keyPolicyRejectedError reports local key or algorithm policy rejection.
func keyPolicyRejectedError(algorithm Algorithm) *Error {
	return newError(ErrorCodeKeyPolicyRejected, ErrorLocation{Check: CheckKindKey}, ErrorDetails{
		Class:     ErrorClassKey,
		Algorithm: algorithm,
		Status:    CheckStatusFail,
	}, nil)
}

// providerError reports a bounded provider failure without raw provider details.
func providerError(algorithm Algorithm, cause error) *Error {
	return newError(ErrorCodeProviderError, ErrorLocation{Check: CheckKindKey}, ErrorDetails{
		Class:     ErrorClassKey,
		Algorithm: algorithm,
		Status:    CheckStatusFail,
	}, cause)
}

// classForCode maps verification codes to default operational classes.
func classForCode(code ErrorCode) ErrorClass {
	switch code {
	case ErrorCodeInvalidOptions:
		return ErrorClassInvariant
	case ErrorCodeInvalidRequest:
		return ErrorClassRequest
	case ErrorCodeLimitExceeded:
		return ErrorClassLimit
	case ErrorCodeUnsupportedAlgorithm, ErrorCodeDisabledAlgorithm:
		return ErrorClassAlgorithm
	case ErrorCodeUnsupportedTarget:
		return ErrorClassUnsupported
	case ErrorCodeOutOfBandRequired:
		return ErrorClassUnsupported
	case ErrorCodeMissingKey, ErrorCodeAmbiguousKey, ErrorCodeInvalidKey, ErrorCodeWrongKeyType, ErrorCodeKeyPolicyRejected, ErrorCodeProviderError:
		return ErrorClassKey
	case ErrorCodeMissingTarget:
		return ErrorClassMissing
	case ErrorCodeDuplicateTarget:
		return ErrorClassDuplicate
	case ErrorCodeHashMismatch:
		return ErrorClassHash
	case ErrorCodeSignatureMismatch:
		return ErrorClassSignature
	case ErrorCodeTimestampInvalid:
		return ErrorClassTimestamp
	case ErrorCodeEnvelopeMismatch, ErrorCodeDomainAlignmentMismatch:
		return ErrorClassEnvelope
	case ErrorCodeNextDomainMismatch, ErrorCodeMissingNextSignature:
		return ErrorClassNextDomain
	case ErrorCodeInternalMisuse:
		return ErrorClassInternal
	default:
		return ErrorClassMalformed
	}
}

// sanitizeLocation prevents negative indexes from leaking invalid context.
func sanitizeLocation(location ErrorLocation) ErrorLocation {
	if !validCheckKind(location.Check) {
		location.Check = ""
	}
	if location.SignatureIndex < 0 {
		location.SignatureIndex = 0
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

// validCheckKind reports whether kind is part of the verification vocabulary.
func validCheckKind(kind CheckKind) bool {
	switch kind {
	case CheckKindBodyHash, CheckKindHeaderHash, CheckKindSignature, CheckKindKey, CheckKindTimestamp, CheckKindEnvelope, CheckKindDomainAlignment, CheckKindNextDomain:
		return true
	default:
		return false
	}
}

// safeDiagnosticToken bounds structured tokens before including them in errors.
func safeDiagnosticToken(value string) string {
	const maxDiagnosticTokenBytes = 64

	if value == "" {
		return ""
	}
	if len(value) > maxDiagnosticTokenBytes {
		return redactedDiagnosticToken
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '-' || b == '.' {
			continue
		}

		return redactedDiagnosticToken
	}

	return value
}
