package dkim2

import (
	"slices"

	"github.com/croessner/dkim2/internal/policy"
)

// PolicyMode identifies one explicit local policy posture.
type PolicyMode string

const (
	// PolicyModeStrict enforces verification failure and proven violations.
	PolicyModeStrict PolicyMode = "strict"
	// PolicyModePermissive accepts permanent verification failures with findings.
	PolicyModePermissive PolicyMode = "permissive"
	// PolicyModeTesting observes outcomes without a terminal DKIM2 disposition.
	PolicyModeTesting PolicyMode = "testing"
)

// Known reports whether the mode belongs to the closed vocabulary.
func (m PolicyMode) Known() bool {
	return m == PolicyModeStrict || m == PolicyModePermissive || m == PolicyModeTesting
}

// PolicyVerdict identifies one local policy disposition separate from verification.
type PolicyVerdict string

const (
	// PolicyVerdictAccept authorizes normal continuation.
	PolicyVerdictAccept PolicyVerdict = "accept"
	// PolicyVerdictReject reports permanent local-policy rejection.
	PolicyVerdictReject PolicyVerdict = "reject"
	// PolicyVerdictTempfail reports retryable local deferral.
	PolicyVerdictTempfail PolicyVerdict = "tempfail"
	// PolicyVerdictContinue withholds a terminal DKIM2 decision.
	PolicyVerdictContinue PolicyVerdict = "continue"
)

// Known reports whether the verdict belongs to the closed vocabulary.
func (v PolicyVerdict) Known() bool {
	return v == PolicyVerdictAccept || v == PolicyVerdictReject || v == PolicyVerdictTempfail || v == PolicyVerdictContinue
}

// PolicyReason identifies one closed policy decision or finding reason.
type PolicyReason string

const (
	// PolicyReasonInvalidInput reports invalid policy input.
	PolicyReasonInvalidInput PolicyReason = "invalid_input"
	// PolicyReasonLimitExceeded reports a policy resource limit.
	PolicyReasonLimitExceeded PolicyReason = "limit_exceeded"
	// PolicyReasonInternalContract reports impossible internal state.
	PolicyReasonInternalContract PolicyReason = "internal_contract"
	// PolicyReasonProtocolPass reports authoritative verification success.
	PolicyReasonProtocolPass PolicyReason = "protocol_pass"
	// PolicyReasonProtocolFail reports authoritative integrity failure.
	PolicyReasonProtocolFail PolicyReason = "protocol_fail"
	// PolicyReasonProtocolPermerror reports authoritative permanent error.
	PolicyReasonProtocolPermerror PolicyReason = "protocol_permerror"
	// PolicyReasonProtocolTemperror reports authoritative temporary error.
	PolicyReasonProtocolTemperror PolicyReason = "protocol_temperror"
	// PolicyReasonPermissiveOverride reports an explicit permissive override.
	PolicyReasonPermissiveOverride PolicyReason = "permissive_override"
	// PolicyReasonTestingModeObserve reports explicit local observation mode.
	PolicyReasonTestingModeObserve PolicyReason = "testing_mode_observe"
	// PolicyReasonDNSTestingEffective reports DNS testing made policy non-terminal.
	PolicyReasonDNSTestingEffective PolicyReason = "dns_testing_effective"
	// PolicyReasonDNSTestingMixed reports incomplete testing declarations across relevant sets.
	PolicyReasonDNSTestingMixed PolicyReason = "dns_testing_mixed"
	// PolicyReasonDNSTestingIneligible reports declarations on an ineligible failure.
	PolicyReasonDNSTestingIneligible PolicyReason = "dns_testing_ineligible"
	// PolicyReasonDoNotModifyHonored reports proven compliance with a modification request.
	PolicyReasonDoNotModifyHonored PolicyReason = "donotmodify_honored"
	// PolicyReasonDoNotModifyViolated reports a proven prohibited later modification.
	PolicyReasonDoNotModifyViolated PolicyReason = "donotmodify_violated"
	// PolicyReasonDoNotModifyIndeterminate reports incomplete modification evidence.
	PolicyReasonDoNotModifyIndeterminate PolicyReason = "donotmodify_indeterminate"
	// PolicyReasonDoNotModifyNotEvaluated reports unavailable modification history.
	PolicyReasonDoNotModifyNotEvaluated PolicyReason = "donotmodify_not_evaluated"
	// PolicyReasonDoNotExplodeViolated reports a proven later explosion.
	PolicyReasonDoNotExplodeViolated PolicyReason = "donotexplode_violated"
	// PolicyReasonDoNotExplodeIndeterminate reports incomplete explosion evidence.
	PolicyReasonDoNotExplodeIndeterminate PolicyReason = "donotexplode_indeterminate"
	// PolicyReasonDoNotExplodeNotEvaluated reports unavailable explosion history.
	PolicyReasonDoNotExplodeNotEvaluated PolicyReason = "donotexplode_not_evaluated"
	// PolicyReasonFeedbackRequested reports an authenticated feedback request.
	PolicyReasonFeedbackRequested PolicyReason = "feedback_requested"
	// PolicyReasonFeedbackRelaySelected reports the selected authenticated relay.
	PolicyReasonFeedbackRelaySelected PolicyReason = "feedback_relay_selected"
	// PolicyReasonFeedHereInert reports a relay flag without causal consent.
	PolicyReasonFeedHereInert PolicyReason = "feedhere_inert"
	// PolicyReasonExplodedReported reports an authenticated explosion flag.
	PolicyReasonExplodedReported PolicyReason = "exploded_reported"
)

// Known reports whether the reason belongs to the frozen public vocabulary.
func (r PolicyReason) Known() bool { return policy.PolicyReason(r).Known() }

// PolicyFindingSeverity identifies one bounded finding severity.
type PolicyFindingSeverity string

const (
	// PolicySeverityInfo reports informational authenticated state.
	PolicySeverityInfo PolicyFindingSeverity = "info"
	// PolicySeverityWarning reports a non-terminal concern or override.
	PolicySeverityWarning PolicyFindingSeverity = "warning"
	// PolicySeverityPermanent reports a permanent failure or violation.
	PolicySeverityPermanent PolicyFindingSeverity = "permanent"
	// PolicySeverityTemporary reports a retryable verification failure.
	PolicySeverityTemporary PolicyFindingSeverity = "temporary"
)

// Known reports whether the severity belongs to the closed vocabulary.
func (s PolicyFindingSeverity) Known() bool { return policy.FindingSeverity(s).Known() }

// PolicyCompliance identifies one authenticated request-compliance state.
type PolicyCompliance string

const (
	// PolicyComplianceNotRequested reports that no authenticated request exists.
	PolicyComplianceNotRequested PolicyCompliance = "not_requested"
	// PolicyComplianceHonored reports positively established compliance.
	PolicyComplianceHonored PolicyCompliance = "honored"
	// PolicyComplianceViolated reports a proven later-hop violation.
	PolicyComplianceViolated PolicyCompliance = "violated"
	// PolicyComplianceIndeterminate reports incomplete positive evidence.
	PolicyComplianceIndeterminate PolicyCompliance = "indeterminate"
	// PolicyComplianceNotEvaluated reports that historical evaluation did not run.
	PolicyComplianceNotEvaluated PolicyCompliance = "not_evaluated"
)

// Known reports whether the state belongs to the closed vocabulary.
func (c PolicyCompliance) Known() bool { return policy.ComplianceState(c).Known() }

// PolicyHistoryCoverage identifies authenticated policy-history coverage.
type PolicyHistoryCoverage string

const (
	// PolicyHistoryNotEvaluated reports deliberately unevaluated history.
	PolicyHistoryNotEvaluated PolicyHistoryCoverage = "not_evaluated"
	// PolicyHistoryComplete reports exact contiguous authenticated history.
	PolicyHistoryComplete PolicyHistoryCoverage = "complete"
	// PolicyHistoryIndeterminate reports explicitly partial authenticated history.
	PolicyHistoryIndeterminate PolicyHistoryCoverage = "indeterminate"
)

// Known reports whether coverage belongs to the closed vocabulary.
func (h PolicyHistoryCoverage) Known() bool { return policy.HistoryCoverage(h).Known() }

// PolicyFinding records one immutable bounded policy fact.
type PolicyFinding struct {
	reason      PolicyReason
	severity    PolicyFindingSeverity
	sequence    uint64
	hasSequence bool
	initialized bool
}

// Reason returns the closed finding reason.
func (f PolicyFinding) Reason() PolicyReason { return f.reason }

// Severity returns the frozen severity for the reason.
func (f PolicyFinding) Severity() PolicyFindingSeverity { return f.severity }

// Sequence returns an optional authenticated sequence and presence flag.
func (f PolicyFinding) Sequence() (uint64, bool) { return f.sequence, f.hasSequence }

// Valid reports whether the finding came from a coherent internal decision.
func (f PolicyFinding) Valid() bool {
	requiresSequence := publicFindingRequiresSequence(f.reason)
	return f.initialized && publicFindingReasonAllowed(f.reason) && f.severity == publicSeverityForReason(f.reason) &&
		(requiresSequence && f.hasSequence && f.sequence > 0 || !requiresSequence && !f.hasSequence && f.sequence == 0)
}

// publicFindingReasonAllowed excludes error-only reasons from immutable findings.
func publicFindingReasonAllowed(reason PolicyReason) bool {
	return reason.Known() && reason != PolicyReasonInvalidInput && reason != PolicyReasonLimitExceeded && reason != PolicyReasonInternalContract
}

// publicSeverityForReason returns the frozen public severity for one known reason.
func publicSeverityForReason(reason PolicyReason) PolicyFindingSeverity {
	switch reason {
	case PolicyReasonProtocolPass, PolicyReasonDoNotModifyHonored,
		PolicyReasonFeedbackRequested, PolicyReasonFeedbackRelaySelected, PolicyReasonFeedHereInert, PolicyReasonExplodedReported:
		return PolicySeverityInfo
	case PolicyReasonPermissiveOverride, PolicyReasonTestingModeObserve, PolicyReasonDNSTestingEffective,
		PolicyReasonDNSTestingMixed, PolicyReasonDNSTestingIneligible, PolicyReasonDoNotModifyIndeterminate,
		PolicyReasonDoNotModifyNotEvaluated, PolicyReasonDoNotExplodeIndeterminate, PolicyReasonDoNotExplodeNotEvaluated:
		return PolicySeverityWarning
	case PolicyReasonProtocolTemperror:
		return PolicySeverityTemporary
	case PolicyReasonProtocolFail, PolicyReasonProtocolPermerror, PolicyReasonDoNotModifyViolated, PolicyReasonDoNotExplodeViolated:
		return PolicySeverityPermanent
	default:
		return ""
	}
}

// publicFindingRequiresSequence reports whether a finding must identify an authenticated hop.
func publicFindingRequiresSequence(reason PolicyReason) bool {
	switch reason {
	case PolicyReasonDoNotModifyHonored, PolicyReasonDoNotModifyViolated, PolicyReasonDoNotModifyIndeterminate,
		PolicyReasonDoNotModifyNotEvaluated, PolicyReasonDoNotExplodeViolated, PolicyReasonDoNotExplodeIndeterminate,
		PolicyReasonDoNotExplodeNotEvaluated, PolicyReasonFeedbackRequested, PolicyReasonFeedbackRelaySelected,
		PolicyReasonFeedHereInert, PolicyReasonExplodedReported:
		return true
	default:
		return false
	}
}

// PolicyFeedbackIntent stores bounded authenticated feedback routing intent.
type PolicyFeedbackIntent struct {
	requested     bool
	relayRequired bool
	relaySequence uint64
	history       PolicyHistoryCoverage
	initialized   bool
}

// Requested reports whether authenticated feedback was requested.
func (i PolicyFeedbackIntent) Requested() bool { return i.requested }

// RelayRequired reports whether an authenticated eligible relay exists.
func (i PolicyFeedbackIntent) RelayRequired() bool { return i.relayRequired }

// RelaySequence returns the highest eligible relay sequence or zero.
func (i PolicyFeedbackIntent) RelaySequence() uint64 { return i.relaySequence }

// HistoryCoverage returns explicit feedback-history coverage.
func (i PolicyFeedbackIntent) HistoryCoverage() PolicyHistoryCoverage { return i.history }

// Valid reports whether feedback intent is coherent and initialized.
func (i PolicyFeedbackIntent) Valid() bool {
	return i.initialized && i.history.Known() && (i.relayRequired && i.requested && i.relaySequence > 0 || !i.relayRequired && i.relaySequence == 0)
}

// PolicyActionKind identifies one closed disposition action.
type PolicyActionKind string

const (
	// PolicyActionAccept matches an accept verdict.
	PolicyActionAccept PolicyActionKind = "accept"
	// PolicyActionReject matches a reject verdict.
	PolicyActionReject PolicyActionKind = "reject"
	// PolicyActionTempfail matches a temporary-failure verdict.
	PolicyActionTempfail PolicyActionKind = "tempfail"
	// PolicyActionContinue matches explicit non-terminal continuation.
	PolicyActionContinue PolicyActionKind = "continue"
)

// Known reports whether the action kind belongs to the closed vocabulary.
func (k PolicyActionKind) Known() bool { return policy.ActionKind(k).Known() }

// PolicyAction stores one immutable local disposition.
type PolicyAction struct {
	kind        PolicyActionKind
	initialized bool
}

// Kind returns the closed action kind.
func (a PolicyAction) Kind() PolicyActionKind { return a.kind }

// Terminal reports whether the action is terminal for DKIM2 policy.
func (a PolicyAction) Terminal() bool { return a.initialized && a.kind != PolicyActionContinue }

// Valid reports whether the action is initialized and known.
func (a PolicyAction) Valid() bool { return a.initialized && a.kind.Known() }

// PolicyActionPlan stores exactly one immutable local disposition.
type PolicyActionPlan struct {
	actions     []PolicyAction
	initialized bool
}

// Actions returns an independent copy containing exactly one action.
func (p PolicyActionPlan) Actions() []PolicyAction { return slices.Clone(p.actions) }

// Valid reports whether the plan contains exactly one coherent disposition.
func (p PolicyActionPlan) Valid() bool {
	return p.initialized && len(p.actions) == 1 && p.actions[0].Valid()
}

// PolicyDecision stores one immutable public local-policy outcome.
type PolicyDecision struct {
	verificationState ResultState
	mode              PolicyMode
	verdict           PolicyVerdict
	primaryReason     PolicyReason
	modify            PolicyCompliance
	explode           PolicyCompliance
	feedback          PolicyFeedbackIntent
	dnsEffective      bool
	findings          []PolicyFinding
	actionPlan        PolicyActionPlan
	source            policy.Decision
	initialized       bool
}

// VerificationState returns the unchanged authoritative verification state.
func (d PolicyDecision) VerificationState() ResultState { return d.verificationState }

// Mode returns the explicit local policy mode.
func (d PolicyDecision) Mode() PolicyMode { return d.mode }

// Verdict returns the local disposition separate from verification.
func (d PolicyDecision) Verdict() PolicyVerdict { return d.verdict }

// PrimaryReason returns the exact deterministic policy reason.
func (d PolicyDecision) PrimaryReason() PolicyReason { return d.primaryReason }

// DoNotModifyCompliance returns aggregate authenticated modification compliance.
func (d PolicyDecision) DoNotModifyCompliance() PolicyCompliance { return d.modify }

// DoNotExplodeCompliance returns aggregate authenticated explosion compliance.
func (d PolicyDecision) DoNotExplodeCompliance() PolicyCompliance { return d.explode }

// FeedbackIntent returns bounded authenticated feedback intent by value.
func (d PolicyDecision) FeedbackIntent() PolicyFeedbackIntent { return d.feedback }

// DNSTestingEffective reports whether eligible DNS testing changed policy treatment.
func (d PolicyDecision) DNSTestingEffective() bool { return d.dnsEffective }

// Findings returns an independent ordered copy of policy findings.
func (d PolicyDecision) Findings() []PolicyFinding { return slices.Clone(d.findings) }

// ActionPlan returns an immutable action plan whose collection accessor clones.
func (d PolicyDecision) ActionPlan() PolicyActionPlan {
	return PolicyActionPlan{actions: d.actionPlan.Actions(), initialized: d.actionPlan.initialized}
}

// IsZero reports whether the decision carries no initialized policy state.
func (d PolicyDecision) IsZero() bool {
	return !d.initialized && d.verificationState == "" && d.mode == "" && d.verdict == "" && d.primaryReason == "" &&
		d.modify == "" && d.explode == "" && !d.feedback.initialized && !d.dnsEffective && len(d.findings) == 0 && !d.actionPlan.initialized && len(d.actionPlan.actions) == 0 && d.source.IsZero()
}

// Valid reports whether the public decision is initialized and internally coherent.
func (d PolicyDecision) Valid() bool {
	if !d.initialized || !d.verificationState.Known() || !d.mode.Known() || !d.verdict.Known() || !d.primaryReason.Known() || !d.modify.Known() || !d.explode.Known() || !d.feedback.Valid() || !d.actionPlan.Valid() || len(d.findings) == 0 {
		return false
	}
	for _, finding := range d.findings {
		if !finding.Valid() {
			return false
		}
	}
	return d.actionPlan.actions[0].kind == PolicyActionKind(d.verdict) && publicDecisionMatchesSource(d)
}

// publicDecisionMatchesSource binds every public field to the validated immutable internal decision.
func publicDecisionMatchesSource(d PolicyDecision) bool {
	if !d.source.Valid() || PolicyMode(d.source.Mode()) != d.mode || PolicyVerdict(d.source.Verdict()) != d.verdict ||
		PolicyReason(d.source.PrimaryReason()) != d.primaryReason || PolicyCompliance(d.source.DoNotModifyCompliance()) != d.modify ||
		PolicyCompliance(d.source.DoNotExplodeCompliance()) != d.explode || d.source.DNSTestingEffective() != d.dnsEffective {
		return false
	}
	protocol, ok := publicPolicyProtocol(d.verificationState)
	if !ok || d.source.Protocol() != protocol {
		return false
	}
	feedback := d.source.FeedbackIntent()
	if d.feedback.requested != feedback.Requested() || d.feedback.relayRequired != feedback.RelayRequired() ||
		d.feedback.relaySequence != feedback.RelaySequence() || d.feedback.history != PolicyHistoryCoverage(feedback.HistoryCoverage()) {
		return false
	}
	sourceFindings := d.source.Findings()
	if len(sourceFindings) != len(d.findings) {
		return false
	}
	for index, source := range sourceFindings {
		sequence, present := source.Sequence()
		finding := d.findings[index]
		if finding.reason != PolicyReason(source.Reason()) || finding.severity != PolicyFindingSeverity(source.Severity()) || finding.sequence != sequence || finding.hasSequence != present {
			return false
		}
	}
	sourceActions := d.source.Actions()
	return len(sourceActions) == 1 && d.actionPlan.actions[0].kind == PolicyActionKind(sourceActions[0].Kind())
}

// EvaluatePolicy evaluates only the sealed projection embedded by library verification.
func EvaluatePolicy(result VerifyResult, options ...PolicyOption) (PolicyDecision, error) {
	config, err := applyPolicyOptions(options...)
	if err != nil {
		return PolicyDecision{}, err
	}
	if !verifyResultPolicyProvenanceValid(result) {
		return PolicyDecision{}, newPolicyError(PolicyErrorInvalidInput)
	}
	evaluator, err := policy.NewEvaluator(config.internalConfig())
	if err != nil {
		return PolicyDecision{}, adaptPolicyError(err)
	}
	decision, err := evaluator.EvaluateProjection(result.policyProjection.Clone())
	if err != nil {
		return PolicyDecision{}, adaptPolicyError(err)
	}
	public, ok := adaptPolicyDecision(result.state, decision)
	if !ok {
		return PolicyDecision{}, newPolicyError(PolicyErrorInternalContract)
	}
	return public, nil
}

// verifyResultPolicyProvenanceValid binds public state to the sealed projection without reparsing public facts.
func verifyResultPolicyProvenanceValid(result VerifyResult) bool {
	data := verifyResultData{state: result.state, scope: result.scope, historicalContent: result.historicalContent, historicalSignatures: result.historicalSignatures, custodyStructure: result.custodyStructure, target: result.target, primaryReason: result.primaryReason, checks: result.checks, signatures: result.signatures, policyProjection: result.policyProjection}
	if result.draft != DraftIdentifier || !verifyResultDataValid(data) || !result.policyProjection.Valid() {
		return false
	}
	protocol, ok := publicPolicyProtocol(result.state)
	if !ok || result.policyProjection.Protocol() != protocol {
		return false
	}
	if result.policyProjection.Form() == policy.TargetUnavailable {
		return result.state == ResultStatePERMERROR && result.target == (VerificationTarget{}) && unavailableReasonMatches(result.policyProjection.PreTargetReason(), result.primaryReason) && len(result.policyProjection.Hops()) == 0 && len(result.policyProjection.SignatureFacts()) == 0
	}
	return result.policyProjection.Form() == policy.TargetSelected && result.target.Sequence() > 0 && result.target.Instance() > 0 && result.policyProjection.TargetSequence() == result.target.Sequence() && policy.VerificationReason(result.primaryReason) == result.policyProjection.VerificationReason()
}

// publicPolicyProtocol maps the authoritative four-state result to policy protocol class.
func publicPolicyProtocol(state ResultState) (policy.ProtocolClass, bool) {
	switch state {
	case ResultStatePASS:
		return policy.ProtocolPASS, true
	case ResultStateFAIL:
		return policy.ProtocolFAIL, true
	case ResultStatePERMERROR:
		return policy.ProtocolPERMERROR, true
	case ResultStateTEMPERROR:
		return policy.ProtocolTEMPERROR, true
	default:
		return "", false
	}
}

// unavailableReasonMatches binds every allowed pre-target reason exactly.
func unavailableReasonMatches(pre policy.PreTargetReason, reason ReasonCode) bool {
	return string(pre) == string(reason) && pre.Known() && (reason == ReasonLimitExceeded || reason == ReasonMalformedMessage || reason == ReasonMalformedProtocol || reason == ReasonMissingProtocol || reason == ReasonSequenceInvalid || reason == ReasonInternalContract)
}

// adaptPolicyDecision deep-copies one validated internal decision into public values.
func adaptPolicyDecision(state ResultState, input policy.Decision) (PolicyDecision, bool) {
	if !input.Valid() {
		return PolicyDecision{}, false
	}
	findings := make([]PolicyFinding, 0, len(input.Findings()))
	for _, finding := range input.Findings() {
		sequence, present := finding.Sequence()
		findings = append(findings, PolicyFinding{reason: PolicyReason(finding.Reason()), severity: PolicyFindingSeverity(finding.Severity()), sequence: sequence, hasSequence: present, initialized: true})
	}
	actions := input.Actions()
	if len(actions) != 1 {
		return PolicyDecision{}, false
	}
	feedback := input.FeedbackIntent()
	decision := PolicyDecision{verificationState: state, mode: PolicyMode(input.Mode()), verdict: PolicyVerdict(input.Verdict()), primaryReason: PolicyReason(input.PrimaryReason()), modify: PolicyCompliance(input.DoNotModifyCompliance()), explode: PolicyCompliance(input.DoNotExplodeCompliance()), feedback: PolicyFeedbackIntent{requested: feedback.Requested(), relayRequired: feedback.RelayRequired(), relaySequence: feedback.RelaySequence(), history: PolicyHistoryCoverage(feedback.HistoryCoverage()), initialized: true}, dnsEffective: input.DNSTestingEffective(), findings: findings, actionPlan: PolicyActionPlan{actions: []PolicyAction{{kind: PolicyActionKind(actions[0].Kind()), initialized: true}}, initialized: true}, source: input, initialized: true}
	return decision, decision.Valid()
}
