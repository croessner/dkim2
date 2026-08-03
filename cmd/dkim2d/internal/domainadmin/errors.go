// Package domainadmin owns the offline native-domain onboarding state machine.
package domainadmin

import (
	"errors"
	"fmt"
	"io"
)

const redacted = "dkim2d_domain_admin{redacted}"

// ErrorCode identifies one bounded administrative failure class.
type ErrorCode string

const (
	// CodeNone reports the absence of a classified error.
	CodeNone ErrorCode = "none"
	// CodeProtectedInput reports an untrusted protected input descriptor.
	CodeProtectedInput ErrorCode = "protected_input"
	// CodeInvalidIntent reports a malformed or noncanonical domain intent.
	CodeInvalidIntent ErrorCode = "invalid_intent"
	// CodeInvalidLimits reports unsafe administrative resource limits.
	CodeInvalidLimits ErrorCode = "invalid_limits"
	// CodeConflict reports authoritative state that disagrees with the operation.
	CodeConflict ErrorCode = "conflict"
	// CodeUnavailable reports a bounded external authority failure.
	CodeUnavailable ErrorCode = "unavailable"
	// CodeReconcileRequired reports an ambiguous outcome requiring explicit reconciliation.
	CodeReconcileRequired ErrorCode = "reconcile_required"
	// CodeKeyRecoveryUnavailable reports lost prepared key material before staging.
	CodeKeyRecoveryUnavailable ErrorCode = "key_recovery_unavailable"
	// CodeDNSMissing reports NXDOMAIN or NODATA on the configured resolver path.
	CodeDNSMissing ErrorCode = "dns_missing"
	// CodeDNSAmbiguous reports more than one TXT resource record.
	CodeDNSAmbiguous ErrorCode = "dns_ambiguous"
	// CodeDNSInvalid reports malformed, revoked, or incoherent DNS key material.
	CodeDNSInvalid ErrorCode = "dns_invalid"
	// CodeDNSUnsupported reports a DNS key type outside the supported algorithm set.
	CodeDNSUnsupported ErrorCode = "dns_unsupported"
	// CodeDNSAlgorithmMismatch reports disagreement between staged and DNS algorithms.
	CodeDNSAlgorithmMismatch ErrorCode = "dns_algorithm_mismatch"
	// CodeDNSSPKIMismatch reports a valid DNS key different from staged readback.
	CodeDNSSPKIMismatch ErrorCode = "dns_spki_mismatch"
	// CodeDNSLimitExceeded reports a bounded DNS record or export limit.
	CodeDNSLimitExceeded ErrorCode = "dns_limit_exceeded"
	// CodeDNSProofExpired reports a proof capability outside its in-process lifetime.
	CodeDNSProofExpired ErrorCode = "dns_proof_expired"
)

// Error is one secret-safe administrative failure.
type Error struct{ code ErrorCode }

// Error returns a constant string without identity-bearing detail.
func (e *Error) Error() string { return "domain administration failed" }

// Code returns the bounded failure class.
func (e *Error) Code() ErrorCode {
	if e == nil {
		return CodeNone
	}
	return e.code
}

// String returns a constant protected representation.
func (*Error) String() string { return redacted }

// GoString returns a constant protected Go representation.
func (*Error) GoString() string { return redacted }

// Format prevents formatting verbs from exposing protected error context.
func (*Error) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// newError constructs one closed administrative failure.
func newError(code ErrorCode) error { return &Error{code: code} }

// CodeOf returns the bounded class for an administrative error.
func CodeOf(err error) ErrorCode {
	var target *Error
	if errors.As(err, &target) {
		return target.Code()
	}
	if err == nil {
		return CodeNone
	}
	return CodeUnavailable
}
