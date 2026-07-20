package cryptodkim2

import (
	"errors"
	"fmt"
	"io"
)

// ErrorCode identifies one closed cryptographic contract failure.
type ErrorCode string

const (
	// ErrorCodeInvalidOptions reports widened or incoherent crypto limits.
	ErrorCodeInvalidOptions ErrorCode = "invalid_options"
	// ErrorCodeUnsupportedAlgorithm reports an algorithm outside the closed contract.
	ErrorCodeUnsupportedAlgorithm ErrorCode = "unsupported_algorithm"
	// ErrorCodeWrongKeyType reports material with a mismatched Go key type.
	ErrorCodeWrongKeyType ErrorCode = "wrong_key_type"
	// ErrorCodeInvalidKey reports malformed public-key material.
	ErrorCodeInvalidKey ErrorCode = "invalid_key"
	// ErrorCodeKeyPolicyRejected reports structurally valid material outside fixed policy.
	ErrorCodeKeyPolicyRejected ErrorCode = "key_policy_rejected"
	// ErrorCodeInvalidDigestLength reports a non-SHA-256 digest length.
	ErrorCodeInvalidDigestLength ErrorCode = "invalid_digest_length"
	// ErrorCodeInvalidSignatureLength reports an algorithm-incoherent signature length.
	ErrorCodeInvalidSignatureLength ErrorCode = "invalid_signature_length"
	// ErrorCodeSignatureMismatch reports cryptographic verification failure.
	ErrorCodeSignatureMismatch ErrorCode = "signature_mismatch"
)

// Known reports whether code belongs to the closed crypto vocabulary.
func (c ErrorCode) Known() bool {
	switch c {
	case ErrorCodeInvalidOptions, ErrorCodeUnsupportedAlgorithm, ErrorCodeWrongKeyType,
		ErrorCodeInvalidKey, ErrorCodeKeyPolicyRejected, ErrorCodeInvalidDigestLength,
		ErrorCodeInvalidSignatureLength, ErrorCodeSignatureMismatch:
		return true
	default:
		return false
	}
}

// Error is a cause-free secret-safe crypto failure.
type Error struct{ code ErrorCode }

// newError constructs one normalized crypto error.
func newError(code ErrorCode) *Error {
	if !code.Known() {
		code = ErrorCodeInvalidOptions
	}
	return &Error{code: code}
}

// Error returns one bounded content-free diagnostic.
func (e *Error) Error() string {
	if e == nil {
		return "dkim2 crypto failure: <nil>"
	}
	return "dkim2 crypto failure: code=" + string(e.code)
}

// Code returns the closed failure code.
func (e *Error) Code() ErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}

// Is matches crypto errors by closed code.
func (e *Error) Is(target error) bool {
	var typed *Error
	return e != nil && errors.As(target, &typed) && typed != nil && e.code == typed.code
}

// GoString returns the same secret-safe diagnostic for Go-syntax formatting.
func (e *Error) GoString() string { return e.Error() }

// Format routes every fmt form through the secret-safe diagnostic.
func (e *Error) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, e.Error()) }

// ErrorCodeOf returns a closed crypto code without inspecting error text.
func ErrorCodeOf(err error) ErrorCode {
	var typed *Error
	if !errors.As(err, &typed) || typed == nil {
		return ""
	}
	return typed.Code()
}
