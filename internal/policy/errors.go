package policy

import "errors"

const (
	limitNameAuthenticatedHops = "max_authenticated_hops"
	limitNameFindings          = "max_findings"
	limitNameActions           = "max_actions"
)

// ErrorCode identifies one bounded policy API failure.
type ErrorCode string

const (
	// ErrorInvalidConfig reports unknown or unsafe evaluator configuration.
	ErrorInvalidConfig ErrorCode = "invalid_config"
	// ErrorInvalidInput reports unknown or incoherent policy input.
	ErrorInvalidInput ErrorCode = "invalid_input"
	// ErrorLimitExceeded reports a configured policy resource limit.
	ErrorLimitExceeded ErrorCode = "limit_exceeded"
	// ErrorInternalContract reports impossible internal policy state.
	ErrorInternalContract ErrorCode = "internal_contract"
)

// Known reports whether the code belongs to the closed error vocabulary.
func (c ErrorCode) Known() bool {
	return c == ErrorInvalidConfig || c == ErrorInvalidInput || c == ErrorLimitExceeded || c == ErrorInternalContract
}

// Error stores bounded cause-free policy failure metadata.
type Error struct {
	code       ErrorCode
	limitName  string
	configured int
	observed   int
}

// Error returns a stable diagnostic without policy or message input.
func (e *Error) Error() string {
	if e == nil || !e.code.Known() {
		return "policy failure"
	}
	if e.code == ErrorLimitExceeded && validLimitName(e.limitName) {
		return "policy failure: limit_exceeded " + e.limitName
	}
	return "policy failure: " + string(e.code)
}

// Is supports errors.Is matching by closed error code.
func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && e != nil && other != nil && e.code.Known() && e.code == other.code
}

// Code returns the closed policy error code.
func (e *Error) Code() ErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}

// LimitName returns the allowlisted configured limit name.
func (e *Error) LimitName() string {
	if e == nil {
		return ""
	}
	return e.limitName
}

// ConfiguredLimit returns the configured limit without input content.
func (e *Error) ConfiguredLimit() int {
	if e == nil {
		return 0
	}
	return e.configured
}

// ObservedCount returns the bounded observed count.
func (e *Error) ObservedCount() int {
	if e == nil {
		return 0
	}
	return e.observed
}

// newError constructs one cause-free policy error.
func newError(code ErrorCode) error {
	if !code.Known() {
		code = ErrorInternalContract
	}
	return &Error{code: code}
}

// newLimitError constructs one allowlisted policy limit error.
func newLimitError(name string, configured, observed int) error {
	if !validLimitName(name) || configured <= 0 || observed <= configured {
		return newError(ErrorInternalContract)
	}
	return &Error{code: ErrorLimitExceeded, limitName: name, configured: configured, observed: observed}
}

// validLimitName reports whether name belongs to the diagnostic allowlist.
func validLimitName(name string) bool {
	return name == limitNameAuthenticatedHops || name == limitNameFindings || name == limitNameActions
}

// IsErrorCode reports whether err carries the requested closed code.
func IsErrorCode(err error, code ErrorCode) bool {
	return code.Known() && errors.Is(err, &Error{code: code})
}
