package dkim2

import "errors"

// APIErrorCode identifies bounded verifier construction or request misuse.
type APIErrorCode string

const (
	// APIErrorCodeInvalidProvider reports a missing or unusable provider dependency.
	APIErrorCodeInvalidProvider APIErrorCode = "invalid_provider"
	// APIErrorCodeInvalidOption reports an unsafe verifier option.
	APIErrorCodeInvalidOption APIErrorCode = "invalid_option"
	// APIErrorCodeInvalidRequest reports programmer misuse of the request contract.
	APIErrorCodeInvalidRequest APIErrorCode = "invalid_request"
)

// Known reports whether the code is in the closed public API-error vocabulary.
func (c APIErrorCode) Known() bool {
	switch c {
	case APIErrorCodeInvalidProvider, APIErrorCodeInvalidOption, APIErrorCodeInvalidRequest:
		return true
	default:
		return false
	}
}

// APIError is a bounded typed error for verifier construction or request misuse.
type APIError struct {
	code APIErrorCode
}

// newAPIError constructs an API error without retaining input values or causes.
func newAPIError(code APIErrorCode) *APIError {
	if !code.Known() {
		code = ""
	}

	return &APIError{code: code}
}

// Error returns a bounded diagnostic without message, envelope, key, or provider data.
func (e *APIError) Error() string {
	if e == nil || !e.code.Known() {
		return "dkim2 API error"
	}

	return "dkim2 API error: " + string(e.code)
}

// Is matches API errors by their stable code.
func (e *APIError) Is(target error) bool {
	var targetError *APIError
	if !errors.As(target, &targetError) {
		return false
	}

	return e != nil && targetError != nil && e.code.Known() && e.code == targetError.code
}

// Code returns the stable API-error code.
func (e *APIError) Code() APIErrorCode {
	if e == nil {
		return ""
	}

	return e.code
}

// ProviderErrorClass identifies an explicitly classified provider failure.
type ProviderErrorClass string

const (
	// ProviderErrorClassTemporary identifies a provider failure that may succeed later.
	ProviderErrorClassTemporary ProviderErrorClass = "temporary"
	// ProviderErrorClassPermanent identifies an unrecoverable provider failure.
	ProviderErrorClassPermanent ProviderErrorClass = "permanent"
)

// Known reports whether the class is in the closed provider-error vocabulary.
func (c ProviderErrorClass) Known() bool {
	switch c {
	case ProviderErrorClassTemporary, ProviderErrorClassPermanent:
		return true
	default:
		return false
	}
}

// ClassifiedProviderError exposes machine-readable provider failure class without a raw cause.
type ClassifiedProviderError interface {
	error
	ProviderErrorClass() ProviderErrorClass
}

// providerError is the cause-free implementation of ClassifiedProviderError.
type providerError struct {
	class ProviderErrorClass
}

// NewTemporaryProviderError constructs a cause-free temporary provider error.
func NewTemporaryProviderError() error {
	return &providerError{class: ProviderErrorClassTemporary}
}

// NewPermanentProviderError constructs a cause-free permanent provider error.
func NewPermanentProviderError() error {
	return &providerError{class: ProviderErrorClassPermanent}
}

// Error returns a bounded provider diagnostic without provider-specific data.
func (e *providerError) Error() string {
	if e == nil || !e.class.Known() {
		return "public key provider error"
	}

	return "public key provider error: " + string(e.class)
}

// ProviderErrorClass returns the machine-readable provider failure class.
func (e *providerError) ProviderErrorClass() ProviderErrorClass {
	if e == nil {
		return ""
	}

	return e.class
}

// ProviderErrorClassOf returns a known typed provider class or the zero value.
func ProviderErrorClassOf(err error) ProviderErrorClass {
	var classified ClassifiedProviderError
	if !errors.As(err, &classified) {
		return ""
	}
	class := classified.ProviderErrorClass()
	if !class.Known() {
		return ""
	}

	return class
}
