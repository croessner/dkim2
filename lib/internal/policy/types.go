package policy

// Mode identifies one explicit local policy posture.
type Mode string

const (
	// ModeStrict enforces DKIM2 failure and proven policy violations.
	ModeStrict Mode = "strict"
	// ModePermissive accepts permanent DKIM2 failure while retaining findings.
	ModePermissive Mode = "permissive"
	// ModeTesting observes DKIM2 outcomes without a terminal DKIM2 decision.
	ModeTesting Mode = "testing"
)

// Known reports whether the mode belongs to the closed policy vocabulary.
func (m Mode) Known() bool { return m == ModeStrict || m == ModePermissive || m == ModeTesting }

// ProtocolClass mirrors one authoritative four-state verification outcome.
type ProtocolClass string

const (
	// ProtocolPASS reports successful verification.
	ProtocolPASS ProtocolClass = "PASS"
	// ProtocolFAIL reports a supported integrity mismatch.
	ProtocolFAIL ProtocolClass = "FAIL"
	// ProtocolPERMERROR reports a permanent verification error.
	ProtocolPERMERROR ProtocolClass = "PERMERROR"
	// ProtocolTEMPERROR reports a temporary verification error.
	ProtocolTEMPERROR ProtocolClass = "TEMPERROR"
)

// Known reports whether the class belongs to the closed verification vocabulary.
func (p ProtocolClass) Known() bool {
	return p == ProtocolPASS || p == ProtocolFAIL || p == ProtocolPERMERROR || p == ProtocolTEMPERROR
}

// Verdict identifies one local policy disposition.
type Verdict string

const (
	// VerdictAccept authorizes normal continuation under DKIM2 policy.
	VerdictAccept Verdict = "accept"
	// VerdictReject reports permanent local-policy rejection.
	VerdictReject Verdict = "reject"
	// VerdictTempfail reports temporary SMTP deferral.
	VerdictTempfail Verdict = "tempfail"
	// VerdictContinue withholds a terminal DKIM2 decision.
	VerdictContinue Verdict = "continue"
)

// Known reports whether the verdict belongs to the closed policy vocabulary.
func (v Verdict) Known() bool {
	return v == VerdictAccept || v == VerdictReject || v == VerdictTempfail || v == VerdictContinue
}

// ActionKind identifies the single disposition action matching a verdict.
type ActionKind string

const (
	// ActionAccept matches an accept verdict.
	ActionAccept ActionKind = "accept"
	// ActionReject matches a reject verdict.
	ActionReject ActionKind = "reject"
	// ActionTempfail matches a temporary-failure verdict.
	ActionTempfail ActionKind = "tempfail"
	// ActionContinue matches a non-terminal continue verdict.
	ActionContinue ActionKind = "continue"
)

// Known reports whether the action belongs to the closed policy vocabulary.
func (a ActionKind) Known() bool {
	return a == ActionAccept || a == ActionReject || a == ActionTempfail || a == ActionContinue
}

// ComplianceState identifies one bounded request-compliance assessment.
type ComplianceState string

const (
	// ComplianceNotRequested reports that no authenticated request exists.
	ComplianceNotRequested ComplianceState = "not_requested"
	// ComplianceHonored reports positively established compliance.
	ComplianceHonored ComplianceState = "honored"
	// ComplianceViolated reports a proven later-hop violation.
	ComplianceViolated ComplianceState = "violated"
	// ComplianceIndeterminate reports incomplete positive evidence.
	ComplianceIndeterminate ComplianceState = "indeterminate"
	// ComplianceNotEvaluated reports that historical evaluation did not run.
	ComplianceNotEvaluated ComplianceState = "not_evaluated"
)

// Known reports whether the state belongs to the closed compliance vocabulary.
func (c ComplianceState) Known() bool {
	return c == ComplianceNotRequested || c == ComplianceHonored || c == ComplianceViolated ||
		c == ComplianceIndeterminate || c == ComplianceNotEvaluated
}

// TransitionState identifies one authenticated message-state transition.
type TransitionState string

const (
	// TransitionOrigin identifies the first authenticated message state.
	TransitionOrigin TransitionState = "origin"
	// TransitionUnchanged reports no covered content change.
	TransitionUnchanged TransitionState = "unchanged"
	// TransitionBodyChanged reports a body-hash-changing transition.
	TransitionBodyChanged TransitionState = "body_changed"
	// TransitionHeadersChanged reports removed or changed header fields.
	TransitionHeadersChanged TransitionState = "headers_removed_or_changed"
	// TransitionBodyAndHeadersChanged reports both prohibited change classes.
	TransitionBodyAndHeadersChanged TransitionState = "body_and_headers_changed"
	// TransitionHeaderAdditionOnly reports only permitted header additions.
	TransitionHeaderAdditionOnly TransitionState = "header_addition_only"
	// TransitionIndeterminate reports incomplete transition evidence.
	TransitionIndeterminate TransitionState = "indeterminate"
	// TransitionNotEvaluated reports that transition evaluation did not run.
	TransitionNotEvaluated TransitionState = "not_evaluated"
)

// Known reports whether the transition belongs to the closed vocabulary.
func (s TransitionState) Known() bool {
	switch s {
	case TransitionOrigin, TransitionUnchanged, TransitionBodyChanged, TransitionHeadersChanged,
		TransitionBodyAndHeadersChanged, TransitionHeaderAdditionOnly, TransitionIndeterminate, TransitionNotEvaluated:
		return true
	default:
		return false
	}
}

// TargetForm identifies whether verification selected an authoritative target.
type TargetForm string

const (
	// TargetSelected reports a positive authoritative target sequence.
	TargetSelected TargetForm = "target_selected"
	// TargetUnavailable reports a bounded pre-target permanent result.
	TargetUnavailable TargetForm = "target_unavailable"
)

// Known reports whether the target form belongs to the closed vocabulary.
func (t TargetForm) Known() bool { return t == TargetSelected || t == TargetUnavailable }

// FindingSeverity identifies one bounded policy finding severity.
type FindingSeverity string

const (
	// SeverityInfo reports informational authenticated state.
	SeverityInfo FindingSeverity = "info"
	// SeverityWarning reports non-terminal policy concern or override.
	SeverityWarning FindingSeverity = "warning"
	// SeverityPermanent reports a permanent failure or violation.
	SeverityPermanent FindingSeverity = "permanent"
	// SeverityTemporary reports a retryable verification failure.
	SeverityTemporary FindingSeverity = "temporary"
)

// Known reports whether the severity belongs to the closed vocabulary.
func (s FindingSeverity) Known() bool {
	return s == SeverityInfo || s == SeverityWarning || s == SeverityPermanent || s == SeverityTemporary
}

// PolicyReason identifies one closed decision, finding, or error reason.
//
//nolint:revive // PolicyReason matches the durable cross-boundary domain vocabulary.
type PolicyReason string

// Frozen policy reason constants shared by decisions, findings, and errors.
const (
	ReasonInvalidInput              PolicyReason = "invalid_input"
	ReasonLimitExceeded             PolicyReason = "limit_exceeded"
	ReasonInternalContract          PolicyReason = "internal_contract"
	ReasonProtocolPass              PolicyReason = "protocol_pass"
	ReasonProtocolFail              PolicyReason = "protocol_fail"
	ReasonProtocolPermerror         PolicyReason = "protocol_permerror"
	ReasonProtocolTemperror         PolicyReason = "protocol_temperror"
	ReasonPermissiveOverride        PolicyReason = "permissive_override"
	ReasonTestingModeObserve        PolicyReason = "testing_mode_observe"
	ReasonDNSTestingEffective       PolicyReason = "dns_testing_effective"
	ReasonDNSTestingMixed           PolicyReason = "dns_testing_mixed"
	ReasonDNSTestingIneligible      PolicyReason = "dns_testing_ineligible"
	ReasonDoNotModifyHonored        PolicyReason = "donotmodify_honored"
	ReasonDoNotModifyViolated       PolicyReason = "donotmodify_violated"
	ReasonDoNotModifyIndeterminate  PolicyReason = "donotmodify_indeterminate"
	ReasonDoNotModifyNotEvaluated   PolicyReason = "donotmodify_not_evaluated"
	ReasonDoNotExplodeViolated      PolicyReason = "donotexplode_violated"
	ReasonDoNotExplodeIndeterminate PolicyReason = "donotexplode_indeterminate"
	ReasonDoNotExplodeNotEvaluated  PolicyReason = "donotexplode_not_evaluated"
	ReasonFeedbackRequested         PolicyReason = "feedback_requested"
	ReasonFeedbackRelaySelected     PolicyReason = "feedback_relay_selected"
	ReasonFeedHereInert             PolicyReason = "feedhere_inert"
	ReasonExplodedReported          PolicyReason = "exploded_reported"
)

// Known reports whether the reason belongs to the frozen policy vocabulary.
func (r PolicyReason) Known() bool {
	switch r {
	case ReasonInvalidInput, ReasonLimitExceeded, ReasonInternalContract,
		ReasonProtocolPass, ReasonProtocolFail, ReasonProtocolPermerror, ReasonProtocolTemperror,
		ReasonPermissiveOverride, ReasonTestingModeObserve,
		ReasonDNSTestingEffective, ReasonDNSTestingMixed, ReasonDNSTestingIneligible,
		ReasonDoNotModifyHonored, ReasonDoNotModifyViolated, ReasonDoNotModifyIndeterminate,
		ReasonDoNotModifyNotEvaluated, ReasonDoNotExplodeViolated, ReasonDoNotExplodeIndeterminate,
		ReasonDoNotExplodeNotEvaluated, ReasonFeedbackRequested, ReasonFeedbackRelaySelected,
		ReasonFeedHereInert, ReasonExplodedReported:
		return true
	default:
		return false
	}
}

// severityForReason returns the frozen severity paired with one known reason.
func severityForReason(reason PolicyReason) FindingSeverity {
	switch reason {
	case ReasonProtocolPass, ReasonDoNotModifyHonored,
		ReasonFeedbackRequested, ReasonFeedbackRelaySelected, ReasonFeedHereInert, ReasonExplodedReported:
		return SeverityInfo
	case ReasonPermissiveOverride, ReasonTestingModeObserve, ReasonDNSTestingEffective,
		ReasonDNSTestingMixed, ReasonDNSTestingIneligible, ReasonDoNotModifyIndeterminate,
		ReasonDoNotModifyNotEvaluated, ReasonDoNotExplodeIndeterminate, ReasonDoNotExplodeNotEvaluated:
		return SeverityWarning
	case ReasonProtocolTemperror:
		return SeverityTemporary
	case ReasonInvalidInput, ReasonLimitExceeded, ReasonInternalContract, ReasonProtocolFail,
		ReasonProtocolPermerror, ReasonDoNotModifyViolated, ReasonDoNotExplodeViolated:
		return SeverityPermanent
	default:
		return ""
	}
}
