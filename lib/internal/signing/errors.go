package signing

import (
	"errors"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/signature"
)

// ErrorCode identifies one closed signing contract failure.
type ErrorCode string

// Signing error codes form the closed failure vocabulary.
const (
	ErrorCodeInvalidOptions           ErrorCode = "invalid_options"
	ErrorCodeInvalidRequest           ErrorCode = "invalid_request"
	ErrorCodeCapabilityMismatch       ErrorCode = "capability_mismatch"
	ErrorCodeMalformedInput           ErrorCode = "malformed_input"
	ErrorCodeProtocolTampering        ErrorCode = "protocol_tampering"
	ErrorCodeSequenceFailure          ErrorCode = "sequence_failure"
	ErrorCodeReferenceFailure         ErrorCode = "reference_failure"
	ErrorCodeHashStateAmbiguity       ErrorCode = "hash_state_ambiguity"
	ErrorCodeChainFailure             ErrorCode = "chain_failure"
	ErrorCodeAuthorizationDenied      ErrorCode = "authorization_denied"
	ErrorCodeAuthorizationUnavailable ErrorCode = "authorization_unavailable"
	ErrorCodePolicyRestriction        ErrorCode = "policy_restriction"
	ErrorCodeDisclosureDenied         ErrorCode = "disclosure_denied"
	ErrorCodeUnsupportedAlgorithm     ErrorCode = "unsupported_algorithm"
	ErrorCodeKeyMismatch              ErrorCode = "key_mismatch"
	ErrorCodeCallbackTemporary        ErrorCode = "callback_temporary"
	ErrorCodeCallbackPermanent        ErrorCode = "callback_permanent"
	ErrorCodeCryptographicSelfCheck   ErrorCode = "cryptographic_self_check_failure"
	ErrorCodeLimitExceeded            ErrorCode = "limit_exceeded"
	ErrorCodeInternalInvariant        ErrorCode = "internal_invariant_failure"
)

// Known reports whether code belongs to the closed signing vocabulary.
func (c ErrorCode) Known() bool {
	switch c {
	case ErrorCodeInvalidOptions, ErrorCodeInvalidRequest, ErrorCodeCapabilityMismatch,
		ErrorCodeMalformedInput, ErrorCodeProtocolTampering, ErrorCodeSequenceFailure,
		ErrorCodeReferenceFailure, ErrorCodeHashStateAmbiguity, ErrorCodeChainFailure,
		ErrorCodeAuthorizationDenied, ErrorCodeAuthorizationUnavailable,
		ErrorCodePolicyRestriction, ErrorCodeDisclosureDenied, ErrorCodeUnsupportedAlgorithm,
		ErrorCodeKeyMismatch, ErrorCodeCallbackTemporary, ErrorCodeCallbackPermanent,
		ErrorCodeCryptographicSelfCheck, ErrorCodeLimitExceeded, ErrorCodeInternalInvariant:
		return true
	default:
		return false
	}
}

// ErrorClass groups signing failures without exposing content.
type ErrorClass string

// Signing error classes form the closed operational vocabulary.
const (
	ErrorClassOptions       ErrorClass = "options"
	ErrorClassRequest       ErrorClass = "request"
	ErrorClassProtocol      ErrorClass = "protocol"
	ErrorClassAuthorization ErrorClass = "authorization"
	ErrorClassProvider      ErrorClass = "provider"
	ErrorClassCryptographic ErrorClass = "cryptographic"
	ErrorClassLimit         ErrorClass = "limit"
	ErrorClassInvariant     ErrorClass = "invariant"
)

// Known reports whether class belongs to the closed signing vocabulary.
func (c ErrorClass) Known() bool {
	return c == ErrorClassOptions || c == ErrorClassRequest || c == ErrorClassProtocol ||
		c == ErrorClassAuthorization || c == ErrorClassProvider || c == ErrorClassCryptographic ||
		c == ErrorClassLimit || c == ErrorClassInvariant
}

// Phase identifies one bounded signing operation phase.
type Phase string

// Signing phases form the closed operation-stage vocabulary.
const (
	PhaseOptions   Phase = "options"
	PhasePreflight Phase = "preflight"
	PhaseSequence  Phase = "sequence"
	PhaseRender    Phase = "render"
	PhaseCallback  Phase = "callback"
	PhaseComplete  Phase = "complete"
)

// Known reports whether phase belongs to the closed signing vocabulary.
func (p Phase) Known() bool {
	return p == PhaseOptions || p == PhasePreflight || p == PhaseSequence ||
		p == PhaseRender || p == PhaseCallback || p == PhaseComplete
}

// Algorithm aliases the signature owner's closed signing algorithm vocabulary.
type Algorithm = signature.Algorithm

// Signing algorithms reuse the signature package's protocol vocabulary.
const (
	AlgorithmRSASHA256     = signature.AlgorithmRSASHA256
	AlgorithmEd25519SHA256 = signature.AlgorithmEd25519SHA256
)

// LimitName identifies one closed signing limit or coherence rule.
type LimitName string

// Signing limit names form the closed resource vocabulary.
const (
	LimitNameMaxMessageBytes                 LimitName = "max_message_bytes"
	LimitNameMaxHeaderBytes                  LimitName = "max_header_bytes"
	LimitNameMaxHeaderFields                 LimitName = "max_header_fields"
	LimitNameMaxFieldBytes                   LimitName = "max_field_bytes"
	LimitNameMaxLineBytes                    LimitName = "max_line_bytes"
	LimitNameMaxInstances                    LimitName = "max_instances"
	LimitNameMaxSignatures                   LimitName = "max_signatures"
	LimitNameMaxProtocolFields               LimitName = "max_protocol_fields"
	LimitNameMaxHashSetsPerInstance          LimitName = "max_hash_sets_per_instance"
	LimitNameMaxSignatureSetsPerField        LimitName = "max_signature_sets_per_field"
	LimitNameMaxTotalSignatureSets           LimitName = "max_total_signature_sets"
	LimitNameMaxPublicKeyLookups             LimitName = "max_public_key_lookups"
	LimitNameMaxSignatureInputBytes          LimitName = "max_signature_input_bytes"
	LimitNameMaxCanonicalWorkBytes           LimitName = "max_canonical_work_bytes"
	LimitNameMaxGeneratedRecipients          LimitName = "max_generated_recipients"
	LimitNameMaxParentOutputCopiesAndTickets LimitName = "max_parent_output_copies_and_tickets"
	LimitNameMaxEnvelopePathBytes            LimitName = "max_envelope_path_bytes"
	LimitNameMaxDecodedRecipeBytes           LimitName = "max_decoded_recipe_bytes"
	LimitNameMaxGeneratedSignatureSets       LimitName = "max_generated_signature_sets"
	LimitNameMaxAuthorizationCalls           LimitName = "max_authorization_calls"
	LimitNameMaxPrivateSigningCalls          LimitName = "max_private_signing_calls"
	LimitNameMaxNonceBytes                   LimitName = "max_nonce_bytes"
	LimitNameMinRSABits                      LimitName = "min_rsa_bits"
	LimitNameMaxRSABits                      LimitName = "max_rsa_bits"
	LimitNameMaxPrivateSignatureBytes        LimitName = "max_private_signature_bytes"
	LimitNameMaxNewInstances                 LimitName = "max_new_instances"
	LimitNameRequiredNewSignatures           LimitName = "required_new_signatures"
	LimitNameExactCryptographicContract      LimitName = "exact_cryptographic_contract"
	LimitNameLimitCoherence                  LimitName = "limit_coherence"
	LimitNameRecipeFieldCoherence            LimitName = "recipe_field_coherence"
)

// Known reports whether name belongs to the closed signing limit vocabulary.
func (n LimitName) Known() bool {
	switch n {
	case LimitNameMaxMessageBytes, LimitNameMaxHeaderBytes, LimitNameMaxHeaderFields, LimitNameMaxFieldBytes,
		LimitNameMaxLineBytes, LimitNameMaxInstances, LimitNameMaxSignatures,
		LimitNameMaxProtocolFields, LimitNameMaxHashSetsPerInstance,
		LimitNameMaxSignatureSetsPerField, LimitNameMaxTotalSignatureSets,
		LimitNameMaxPublicKeyLookups, LimitNameMaxSignatureInputBytes,
		LimitNameMaxCanonicalWorkBytes, LimitNameMaxGeneratedRecipients,
		LimitNameMaxParentOutputCopiesAndTickets, LimitNameMaxEnvelopePathBytes,
		LimitNameMaxDecodedRecipeBytes, LimitNameMaxGeneratedSignatureSets,
		LimitNameMaxAuthorizationCalls, LimitNameMaxPrivateSigningCalls,
		LimitNameMaxNonceBytes, LimitNameMinRSABits, LimitNameMaxRSABits,
		LimitNameMaxPrivateSignatureBytes, LimitNameMaxNewInstances,
		LimitNameRequiredNewSignatures, LimitNameExactCryptographicContract,
		LimitNameLimitCoherence, LimitNameRecipeFieldCoherence:
		return true
	default:
		return false
	}
}

// ErrorLocation carries bounded signing coordinates only.
type ErrorLocation struct {
	Phase     Phase
	Resource  Resource
	Algorithm Algorithm
	Sequence  uint64
	Instance  uint64
}

// ErrorDetails carries bounded signing metadata only.
type ErrorDetails struct {
	Class     ErrorClass
	LimitName LimitName
	Limit     int
	Actual    int
}

// Error is a typed signing failure that never retains arbitrary causes or input.
type Error struct {
	code     ErrorCode
	location ErrorLocation
	details  ErrorDetails
}

// newError constructs one normalized bounded signing error.
func newError(code ErrorCode, location ErrorLocation, details ErrorDetails) *Error {
	if !code.Known() {
		code = ErrorCodeInternalInvariant
	}
	if !location.Phase.Known() {
		location.Phase = ""
	}
	if !location.Resource.Known() {
		location.Resource = ""
	}
	if !location.Algorithm.Known() {
		location.Algorithm = ""
	}
	details.Class = classForCode(code)
	if !details.LimitName.Known() {
		details.LimitName = ""
	}
	if details.Limit < 0 {
		details.Limit = 0
	}
	if details.Actual < 0 {
		details.Actual = 0
	}
	return &Error{code: code, location: location, details: details}
}

// Error returns a deterministic secret-safe diagnostic.
func (e *Error) Error() string {
	if e == nil {
		return "signing error: <nil>"
	}
	message := fmt.Sprintf("signing error: code=%s class=%s phase=%s resource=%s algorithm=%s sequence=%d instance=%d",
		e.code, e.details.Class, e.location.Phase, e.location.Resource, e.location.Algorithm,
		e.location.Sequence, e.location.Instance)
	if e.details.LimitName != "" {
		message += fmt.Sprintf(" limit_name=%s", e.details.LimitName)
	}
	if e.details.Limit > 0 {
		message += fmt.Sprintf(" limit=%d", e.details.Limit)
	}
	if e.details.Actual > 0 {
		message += fmt.Sprintf(" actual=%d", e.details.Actual)
	}
	return message
}

// Is matches signing errors by stable code.
func (e *Error) Is(target error) bool {
	var typed *Error
	return e != nil && errors.As(target, &typed) && typed != nil && e.code == typed.code
}

// Code returns the closed error code.
func (e *Error) Code() ErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}

// Class returns the closed error class.
func (e *Error) Class() ErrorClass {
	if e == nil {
		return ""
	}
	return e.details.Class
}

// Location returns normalized bounded coordinates.
func (e *Error) Location() ErrorLocation {
	if e == nil {
		return ErrorLocation{}
	}
	return e.location
}

// Details returns normalized bounded error metadata.
func (e *Error) Details() ErrorDetails {
	if e == nil {
		return ErrorDetails{}
	}
	return e.details
}

// Format renders every fmt form through the secret-safe diagnostic.
func (e *Error) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, e.Error())
}

// IsErrorCode reports whether err contains a signing Error with code.
func IsErrorCode(err error, code ErrorCode) bool {
	var typed *Error
	return errors.As(err, &typed) && typed != nil && typed.code == code
}

// classForCode maps error codes to their fixed operational class.
func classForCode(code ErrorCode) ErrorClass {
	switch code {
	case ErrorCodeInvalidOptions:
		return ErrorClassOptions
	case ErrorCodeInvalidRequest, ErrorCodeCapabilityMismatch:
		return ErrorClassRequest
	case ErrorCodeAuthorizationDenied, ErrorCodeAuthorizationUnavailable,
		ErrorCodePolicyRestriction, ErrorCodeDisclosureDenied:
		return ErrorClassAuthorization
	case ErrorCodeCallbackTemporary, ErrorCodeCallbackPermanent:
		return ErrorClassProvider
	case ErrorCodeUnsupportedAlgorithm, ErrorCodeKeyMismatch, ErrorCodeCryptographicSelfCheck:
		return ErrorClassCryptographic
	case ErrorCodeLimitExceeded:
		return ErrorClassLimit
	case ErrorCodeInternalInvariant:
		return ErrorClassInvariant
	default:
		return ErrorClassProtocol
	}
}
