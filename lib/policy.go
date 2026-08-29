package dkim2

import (
	"fmt"
	"io"
	"slices"

	"github.com/croessner/dkim2/internal/policy"
)

const (
	policyDecisionRedactedText = "dkim2.PolicyDecision{redacted}"
	policyFeedbackRedactedText = "dkim2.PolicyFeedbackIntent{redacted}"
	policyFindingRedactedText  = "dkim2.PolicyFinding{redacted}"
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
	state *policyFindingState
}

// policyFindingState stores the private scalar state of one public finding.
type policyFindingState struct {
	reason      PolicyReason
	severity    PolicyFindingSeverity
	sequence    uint64
	hasSequence bool
	initialized bool
}

// Reason returns the closed finding reason.
func (f PolicyFinding) Reason() PolicyReason {
	if f.state == nil {
		return ""
	}
	return f.state.reason
}

// Severity returns the frozen severity for the reason.
func (f PolicyFinding) Severity() PolicyFindingSeverity {
	if f.state == nil {
		return ""
	}
	return f.state.severity
}

// Sequence returns an optional authenticated sequence and presence flag.
func (f PolicyFinding) Sequence() (uint64, bool) {
	if f.state == nil {
		return 0, false
	}
	return f.state.sequence, f.state.hasSequence
}

// Valid reports whether the finding came from a coherent internal decision.
func (f PolicyFinding) Valid() bool {
	if f.state == nil {
		return false
	}
	requiresSequence := publicFindingRequiresSequence(f.state.reason)
	return f.state.initialized && publicFindingReasonAllowed(f.state.reason) &&
		f.state.severity == publicSeverityForReason(f.state.reason) &&
		(requiresSequence && f.state.hasSequence && f.state.sequence > 0 ||
			!requiresSequence && !f.state.hasSequence && f.state.sequence == 0)
}

// String returns a constant representation without sequence identifiers.
func (PolicyFinding) String() string { return policyFindingRedactedText }

// GoString returns a constant representation without sequence identifiers.
func (PolicyFinding) GoString() string { return policyFindingRedactedText }

// Format prevents formatting from traversing sequence identifiers.
func (PolicyFinding) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, policyFindingRedactedText)
}

// MarshalJSON rejects direct serialization outside generated response DTOs.
func (PolicyFinding) MarshalJSON() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// MarshalText rejects diagnostic serialization of authenticated sequence state.
func (PolicyFinding) MarshalText() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
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
	state *policyFeedbackIntentState
}

// policyFeedbackIntentState stores the private scalar state of public feedback intent.
type policyFeedbackIntentState struct {
	requested     bool
	relayRequired bool
	relaySequence uint64
	history       PolicyHistoryCoverage
	initialized   bool
}

// Requested reports whether authenticated feedback was requested.
func (i PolicyFeedbackIntent) Requested() bool {
	return i.state != nil && i.state.requested
}

// RelayRequired reports whether an authenticated eligible relay exists.
func (i PolicyFeedbackIntent) RelayRequired() bool {
	return i.state != nil && i.state.relayRequired
}

// RelaySequence returns the highest eligible relay sequence or zero.
func (i PolicyFeedbackIntent) RelaySequence() uint64 {
	if i.state == nil {
		return 0
	}
	return i.state.relaySequence
}

// HistoryCoverage returns explicit feedback-history coverage.
func (i PolicyFeedbackIntent) HistoryCoverage() PolicyHistoryCoverage {
	if i.state == nil {
		return ""
	}
	return i.state.history
}

// Valid reports whether feedback intent is coherent and initialized.
func (i PolicyFeedbackIntent) Valid() bool {
	return i.state != nil && i.state.initialized && i.state.history.Known() &&
		(i.state.relayRequired && i.state.requested && i.state.relaySequence > 0 ||
			!i.state.relayRequired && i.state.relaySequence == 0)
}

// String returns a constant representation without relay identifiers.
func (PolicyFeedbackIntent) String() string { return policyFeedbackRedactedText }

// GoString returns a constant representation without relay identifiers.
func (PolicyFeedbackIntent) GoString() string { return policyFeedbackRedactedText }

// Format prevents formatting from traversing relay identifiers.
func (PolicyFeedbackIntent) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, policyFeedbackRedactedText)
}

// MarshalJSON rejects direct serialization outside generated response DTOs.
func (PolicyFeedbackIntent) MarshalJSON() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// MarshalText rejects diagnostic serialization of authenticated relay state.
func (PolicyFeedbackIntent) MarshalText() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
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
	state *policyDecisionState
}

// policyDecisionState stores the immutable private projection of one public decision.
type policyDecisionState struct {
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
func (d PolicyDecision) VerificationState() ResultState {
	if d.state == nil {
		return ""
	}
	return d.state.verificationState
}

// Mode returns the explicit local policy mode.
func (d PolicyDecision) Mode() PolicyMode {
	if d.state == nil {
		return ""
	}
	return d.state.mode
}

// Verdict returns the local disposition separate from verification.
func (d PolicyDecision) Verdict() PolicyVerdict {
	if d.state == nil {
		return ""
	}
	return d.state.verdict
}

// PrimaryReason returns the exact deterministic policy reason.
func (d PolicyDecision) PrimaryReason() PolicyReason {
	if d.state == nil {
		return ""
	}
	return d.state.primaryReason
}

// DoNotModifyCompliance returns aggregate authenticated modification compliance.
func (d PolicyDecision) DoNotModifyCompliance() PolicyCompliance {
	if d.state == nil {
		return ""
	}
	return d.state.modify
}

// DoNotExplodeCompliance returns aggregate authenticated explosion compliance.
func (d PolicyDecision) DoNotExplodeCompliance() PolicyCompliance {
	if d.state == nil {
		return ""
	}
	return d.state.explode
}

// FeedbackIntent returns bounded authenticated feedback intent by value.
func (d PolicyDecision) FeedbackIntent() PolicyFeedbackIntent {
	if d.state == nil {
		return PolicyFeedbackIntent{}
	}
	return d.state.feedback
}

// DNSTestingEffective reports whether eligible DNS testing changed policy treatment.
func (d PolicyDecision) DNSTestingEffective() bool {
	return d.state != nil && d.state.dnsEffective
}

// Findings returns an independent ordered copy of policy findings.
func (d PolicyDecision) Findings() []PolicyFinding {
	if d.state == nil {
		return nil
	}
	return slices.Clone(d.state.findings)
}

// ActionPlan returns an immutable action plan whose collection accessor clones.
func (d PolicyDecision) ActionPlan() PolicyActionPlan {
	if d.state == nil {
		return PolicyActionPlan{}
	}
	return PolicyActionPlan{actions: d.state.actionPlan.Actions(), initialized: d.state.actionPlan.initialized}
}

// IsZero reports whether the decision carries no initialized policy state.
func (d PolicyDecision) IsZero() bool {
	return d.state == nil
}

// Valid reports whether the public decision is initialized and internally coherent.
func (d PolicyDecision) Valid() bool {
	if d.state == nil || !d.state.initialized || !d.state.verificationState.Known() ||
		!d.state.mode.Known() || !d.state.verdict.Known() || !d.state.primaryReason.Known() ||
		!d.state.modify.Known() || !d.state.explode.Known() || !d.state.feedback.Valid() ||
		!d.state.actionPlan.Valid() || len(d.state.findings) == 0 {
		return false
	}
	for _, finding := range d.state.findings {
		if !finding.Valid() {
			return false
		}
	}
	return d.state.actionPlan.actions[0].kind == PolicyActionKind(d.state.verdict) &&
		publicDecisionMatchesSource(d)
}

// String returns a constant representation without sealed policy facts.
func (PolicyDecision) String() string { return policyDecisionRedactedText }

// GoString returns a constant representation without sealed policy facts.
func (PolicyDecision) GoString() string { return policyDecisionRedactedText }

// Format prevents formatting from traversing sealed policy facts.
func (PolicyDecision) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, policyDecisionRedactedText)
}

// MarshalJSON rejects direct serialization outside generated response DTOs.
func (PolicyDecision) MarshalJSON() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// MarshalText rejects diagnostic serialization of sealed policy state.
func (PolicyDecision) MarshalText() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// publicDecisionMatchesSource binds every public field to the validated immutable internal decision.
func publicDecisionMatchesSource(d PolicyDecision) bool {
	if d.state == nil {
		return false
	}
	state := d.state
	if !state.source.Valid() || PolicyMode(state.source.Mode()) != state.mode ||
		PolicyVerdict(state.source.Verdict()) != state.verdict ||
		PolicyReason(state.source.PrimaryReason()) != state.primaryReason ||
		PolicyCompliance(state.source.DoNotModifyCompliance()) != state.modify ||
		PolicyCompliance(state.source.DoNotExplodeCompliance()) != state.explode ||
		state.source.DNSTestingEffective() != state.dnsEffective {
		return false
	}
	protocol, ok := publicPolicyProtocol(state.verificationState)
	if !ok || state.source.Protocol() != protocol {
		return false
	}
	feedback := state.source.FeedbackIntent()
	if state.feedback.Requested() != feedback.Requested() ||
		state.feedback.RelayRequired() != feedback.RelayRequired() ||
		state.feedback.RelaySequence() != feedback.RelaySequence() ||
		state.feedback.HistoryCoverage() != PolicyHistoryCoverage(feedback.HistoryCoverage()) {
		return false
	}
	sourceFindings := state.source.Findings()
	if len(sourceFindings) != len(state.findings) {
		return false
	}
	for index, source := range sourceFindings {
		sequence, present := source.Sequence()
		finding := state.findings[index]
		findingSequence, findingPresent := finding.Sequence()
		if finding.Reason() != PolicyReason(source.Reason()) ||
			finding.Severity() != PolicyFindingSeverity(source.Severity()) ||
			findingSequence != sequence || findingPresent != present {
			return false
		}
	}
	sourceActions := state.source.Actions()
	return len(sourceActions) == 1 &&
		state.actionPlan.actions[0].kind == PolicyActionKind(sourceActions[0].Kind())
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
	decision, err := evaluator.EvaluateProjection(result.state.policyProjection.Clone())
	if err != nil {
		return PolicyDecision{}, adaptPolicyError(err)
	}
	public, ok := adaptPolicyDecision(result.state.resultState, decision)
	if !ok {
		return PolicyDecision{}, newPolicyError(PolicyErrorInternalContract)
	}
	return public, nil
}

// EvaluateAuthenticationPolicy evaluates local policy from the authoritative final Draft-06 result.
func EvaluateAuthenticationPolicy(result AuthenticationResult, options ...PolicyOption) (PolicyDecision, error) {
	config, err := applyPolicyOptions(options...)
	if err != nil {
		return PolicyDecision{}, err
	}
	if !result.Valid() || !verifyResultPolicyProvenanceValid(result.Verification()) {
		return PolicyDecision{}, newPolicyError(PolicyErrorInvalidInput)
	}
	evaluator, err := policy.NewEvaluator(config.internalConfig())
	if err != nil {
		return PolicyDecision{}, adaptPolicyError(err)
	}
	decision, err := evaluator.EvaluateAuthenticationProjection(
		result.Verification().state.policyProjection.Clone(),
		policy.ProtocolClass(result.State()),
	)
	if err != nil {
		return PolicyDecision{}, adaptPolicyError(err)
	}
	public, ok := adaptPolicyDecision(result.State(), decision)
	if !ok {
		return PolicyDecision{}, newPolicyError(PolicyErrorInternalContract)
	}
	return public, nil
}

// verifyResultPolicyProvenanceValid binds public state to the sealed projection without reparsing public facts.
func verifyResultPolicyProvenanceValid(result VerifyResult) bool {
	if result.state == nil {
		return false
	}
	state := result.state
	data := verifyResultData{state: state.resultState, scope: state.scope, historicalContent: state.historicalContent, historicalSignatures: state.historicalSignatures, custodyStructure: state.custodyStructure, target: state.target, primaryReason: state.primaryReason, checks: state.checks, signatures: state.signatures, policyProjection: state.policyProjection}
	if state.draft != DraftIdentifier || !verifyResultDataValid(data) || !state.policyProjection.Valid() {
		return false
	}
	protocol, ok := publicPolicyProtocol(state.resultState)
	if !ok || state.policyProjection.Protocol() != protocol {
		return false
	}
	if state.policyProjection.Form() == policy.TargetUnavailable {
		return state.resultState == ResultStatePERMERROR && state.target.isZero() && unavailableReasonMatches(state.policyProjection.PreTargetReason(), state.primaryReason) && len(state.policyProjection.Hops()) == 0 && len(state.policyProjection.SignatureFacts()) == 0
	}
	return state.policyProjection.Form() == policy.TargetSelected && state.target.Sequence() > 0 && state.target.Instance() > 0 && state.policyProjection.TargetSequence() == state.target.Sequence() && policy.VerificationReason(state.primaryReason) == state.policyProjection.VerificationReason()
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
	return string(pre) == string(reason) && pre.Known() && (reason == ReasonLimitExceeded || reason == ReasonMalformedMessage || reason == ReasonMalformedProtocol || reason == ReasonDuplicateHashAlgorithm || reason == ReasonDuplicateSelector || reason == ReasonTooManySignatures || reason == ReasonMissingProtocol || reason == ReasonSequenceInvalid || reason == ReasonInternalContract)
}

// adaptPolicyDecision deep-copies one validated internal decision into public values.
func adaptPolicyDecision(state ResultState, input policy.Decision) (PolicyDecision, bool) {
	if !input.Valid() {
		return PolicyDecision{}, false
	}
	findings := make([]PolicyFinding, 0, len(input.Findings()))
	for _, finding := range input.Findings() {
		sequence, present := finding.Sequence()
		findings = append(findings, PolicyFinding{state: &policyFindingState{
			reason: PolicyReason(finding.Reason()), severity: PolicyFindingSeverity(finding.Severity()),
			sequence: sequence, hasSequence: present, initialized: true,
		}})
	}
	actions := input.Actions()
	if len(actions) != 1 {
		return PolicyDecision{}, false
	}
	feedback := input.FeedbackIntent()
	decision := PolicyDecision{state: &policyDecisionState{
		verificationState: state, mode: PolicyMode(input.Mode()), verdict: PolicyVerdict(input.Verdict()),
		primaryReason: PolicyReason(input.PrimaryReason()), modify: PolicyCompliance(input.DoNotModifyCompliance()),
		explode: PolicyCompliance(input.DoNotExplodeCompliance()), feedback: PolicyFeedbackIntent{
			state: &policyFeedbackIntentState{
				requested: feedback.Requested(), relayRequired: feedback.RelayRequired(),
				relaySequence: feedback.RelaySequence(), history: PolicyHistoryCoverage(feedback.HistoryCoverage()),
				initialized: true,
			},
		}, dnsEffective: input.DNSTestingEffective(), findings: findings,
		actionPlan: PolicyActionPlan{
			actions:     []PolicyAction{{kind: PolicyActionKind(actions[0].Kind()), initialized: true}},
			initialized: true,
		},
		source: input, initialized: true,
	}}
	return decision, decision.Valid()
}
