package dkim2

import (
	"errors"

	"github.com/croessner/dkim2/internal/policy"
)

// PolicyErrorCode identifies one bounded public policy-evaluation failure.
type PolicyErrorCode string

const (
	// PolicyErrorInvalidOption reports an unknown, duplicate, zero, or widening option.
	PolicyErrorInvalidOption PolicyErrorCode = "invalid_option"
	// PolicyErrorInvalidInput reports absent or incoherent sealed verification provenance.
	PolicyErrorInvalidInput PolicyErrorCode = "invalid_input"
	// PolicyErrorLimitExceeded reports a configured public policy resource limit.
	PolicyErrorLimitExceeded PolicyErrorCode = "limit_exceeded"
	// PolicyErrorInternalContract reports an impossible internal policy result.
	PolicyErrorInternalContract PolicyErrorCode = "internal_contract"
)

// Known reports whether the code belongs to the closed public vocabulary.
func (c PolicyErrorCode) Known() bool {
	return c == PolicyErrorInvalidOption || c == PolicyErrorInvalidInput || c == PolicyErrorLimitExceeded || c == PolicyErrorInternalContract
}

// PolicyError stores cause-free and message-free policy failure metadata.
type PolicyError struct {
	code       PolicyErrorCode
	limitName  string
	configured int
	observed   int
}

// Error returns one stable diagnostic without verification or message content.
func (e *PolicyError) Error() string {
	if e == nil || !e.code.Known() {
		return "policy evaluation failure"
	}
	if e.code == PolicyErrorLimitExceeded && policyLimitNameKnown(e.limitName) {
		return "policy evaluation failure: limit_exceeded " + e.limitName
	}
	return "policy evaluation failure: " + string(e.code)
}

// Is supports errors.Is matching by closed public error code.
func (e *PolicyError) Is(target error) bool {
	other, ok := target.(*PolicyError)
	return ok && e != nil && other != nil && e.code.Known() && e.code == other.code
}

// Code returns the closed public policy error code.
func (e *PolicyError) Code() PolicyErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}

// LimitName returns an allowlisted public policy limit name.
func (e *PolicyError) LimitName() string {
	if e == nil {
		return ""
	}
	return e.limitName
}

// ConfiguredLimit returns the configured limit without input content.
func (e *PolicyError) ConfiguredLimit() int {
	if e == nil {
		return 0
	}
	return e.configured
}

// ObservedCount returns the bounded observed count.
func (e *PolicyError) ObservedCount() int {
	if e == nil {
		return 0
	}
	return e.observed
}

// newPolicyError constructs one cause-free public policy error.
func newPolicyError(code PolicyErrorCode) *PolicyError {
	if !code.Known() {
		code = PolicyErrorInternalContract
	}
	return &PolicyError{code: code}
}

// adaptPolicyError maps internal cause-free metadata into the public error vocabulary.
func adaptPolicyError(err error) *PolicyError {
	var internal *policy.Error
	if !errors.As(err, &internal) {
		return newPolicyError(PolicyErrorInternalContract)
	}
	switch internal.Code() {
	case policy.ErrorInvalidConfig:
		return newPolicyError(PolicyErrorInvalidOption)
	case policy.ErrorInvalidInput:
		return newPolicyError(PolicyErrorInvalidInput)
	case policy.ErrorLimitExceeded:
		if !policyLimitNameKnown(internal.LimitName()) {
			return newPolicyError(PolicyErrorInternalContract)
		}
		return &PolicyError{code: PolicyErrorLimitExceeded, limitName: internal.LimitName(), configured: internal.ConfiguredLimit(), observed: internal.ObservedCount()}
	case policy.ErrorInternalContract:
		return newPolicyError(PolicyErrorInternalContract)
	default:
		return newPolicyError(PolicyErrorInternalContract)
	}
}

// policyLimitNameKnown restricts public diagnostics to policy-owned limit names.
func policyLimitNameKnown(name string) bool {
	return name == "max_authenticated_hops" || name == "max_findings" || name == "max_actions"
}
