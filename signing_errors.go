package dkim2

import (
	"context"
	"errors"
	"fmt"

	"github.com/croessner/dkim2/internal/signing"
)

// SigningErrorCode identifies one bounded signing failure.
type SigningErrorCode string

// Public signing failures use the protocol core's closed vocabulary.
const (
	SigningErrorInvalidOptions           SigningErrorCode = "invalid_options"
	SigningErrorInvalidRequest           SigningErrorCode = "invalid_request"
	SigningErrorCapabilityMismatch       SigningErrorCode = "capability_mismatch"
	SigningErrorMalformedInput           SigningErrorCode = "malformed_input"
	SigningErrorProtocolTampering        SigningErrorCode = "protocol_tampering"
	SigningErrorSequenceFailure          SigningErrorCode = "sequence_failure"
	SigningErrorReferenceFailure         SigningErrorCode = "reference_failure"
	SigningErrorHashStateAmbiguity       SigningErrorCode = "hash_state_ambiguity"
	SigningErrorChainFailure             SigningErrorCode = "chain_failure"
	SigningErrorAuthorizationDenied      SigningErrorCode = "authorization_denied"
	SigningErrorAuthorizationUnavailable SigningErrorCode = "authorization_unavailable"
	SigningErrorPolicyRestriction        SigningErrorCode = "policy_restriction"
	SigningErrorDisclosureDenied         SigningErrorCode = "disclosure_denied"
	SigningErrorUnsupportedAlgorithm     SigningErrorCode = "unsupported_algorithm"
	SigningErrorKeyMismatch              SigningErrorCode = "key_mismatch"
	SigningErrorCallbackTemporary        SigningErrorCode = "callback_temporary"
	SigningErrorCallbackPermanent        SigningErrorCode = "callback_permanent"
	SigningErrorCryptographicSelfCheck   SigningErrorCode = "cryptographic_self_check_failure"
	SigningErrorLimitExceeded            SigningErrorCode = "limit_exceeded"
	SigningErrorInternalInvariant        SigningErrorCode = "internal_invariant_failure"
)

// Known reports whether the code belongs to the public signing vocabulary.
func (c SigningErrorCode) Known() bool {
	switch c {
	case SigningErrorInvalidOptions, SigningErrorInvalidRequest, SigningErrorCapabilityMismatch,
		SigningErrorMalformedInput, SigningErrorProtocolTampering, SigningErrorSequenceFailure,
		SigningErrorReferenceFailure, SigningErrorHashStateAmbiguity, SigningErrorChainFailure,
		SigningErrorAuthorizationDenied, SigningErrorAuthorizationUnavailable,
		SigningErrorPolicyRestriction, SigningErrorDisclosureDenied, SigningErrorUnsupportedAlgorithm,
		SigningErrorKeyMismatch, SigningErrorCallbackTemporary, SigningErrorCallbackPermanent,
		SigningErrorCryptographicSelfCheck, SigningErrorLimitExceeded, SigningErrorInternalInvariant:
		return true
	default:
		return false
	}
}

// SigningError is a bounded cause-free public signing failure.
type SigningError struct{ code SigningErrorCode }

// Error returns a secret-safe stable diagnostic.
func (e *SigningError) Error() string {
	if e == nil || !e.code.Known() {
		return "dkim2 signing error"
	}
	return "dkim2 signing error: " + string(e.code)
}

// Code returns the stable public signing error code.
func (e *SigningError) Code() SigningErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}

// Is matches public signing errors by stable code.
func (e *SigningError) Is(target error) bool {
	var candidate *SigningError
	return e != nil && errors.As(target, &candidate) && candidate != nil && e.code == candidate.code
}

// Format renders every fmt form through the bounded diagnostic.
func (e *SigningError) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(e.Error()))
}

// newSigningError constructs one normalized public signing error.
func newSigningError(code SigningErrorCode) *SigningError {
	if !code.Known() {
		code = SigningErrorInternalInvariant
	}
	return &SigningError{code: code}
}

// mapSigningError translates internal signing failures without retaining causes.
func mapSigningError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var typed *signing.Error
	if !errors.As(err, &typed) || typed == nil {
		return newSigningError(SigningErrorInternalInvariant)
	}
	code := SigningErrorCode(typed.Code())
	if !code.Known() {
		code = SigningErrorInternalInvariant
	}
	return newSigningError(code)
}
