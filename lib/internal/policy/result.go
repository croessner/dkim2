package policy

import "slices"

// Finding records one bounded deterministic policy fact.
type Finding struct {
	reason      PolicyReason
	severity    FindingSeverity
	sequence    uint64
	hasSequence bool
}

// Reason returns the closed finding reason.
func (f Finding) Reason() PolicyReason { return f.reason }

// Severity returns the frozen severity for the reason.
func (f Finding) Severity() FindingSeverity { return f.severity }

// Sequence returns the optional authenticated sequence and presence flag.
func (f Finding) Sequence() (uint64, bool) { return f.sequence, f.hasSequence }

// Valid reports whether finding fields satisfy frozen coherence rules.
func (f Finding) Valid() bool {
	return findingReasonAllowed(f.reason) && f.severity == severityForReason(f.reason) &&
		(findingRequiresSequence(f.reason) && f.hasSequence && f.sequence > 0 ||
			!findingRequiresSequence(f.reason) && !f.hasSequence && f.sequence == 0)
}

// newFinding constructs one validated policy finding.
func newFinding(reason PolicyReason, sequence uint64, hasSequence bool) (Finding, error) {
	finding := Finding{reason: reason, severity: severityForReason(reason), sequence: sequence, hasSequence: hasSequence}
	if !finding.Valid() {
		return Finding{}, newError(ErrorInternalContract)
	}
	return finding, nil
}

// findingReasonAllowed reports whether a reason may appear as a finding.
func findingReasonAllowed(reason PolicyReason) bool {
	return reason.Known() && reason != ReasonInvalidInput && reason != ReasonLimitExceeded && reason != ReasonInternalContract
}

// findingRequiresSequence reports whether the frozen emission row requires a hop sequence.
func findingRequiresSequence(reason PolicyReason) bool {
	switch reason {
	case ReasonDoNotModifyHonored, ReasonDoNotModifyViolated, ReasonDoNotModifyIndeterminate,
		ReasonDoNotModifyNotEvaluated, ReasonDoNotExplodeViolated, ReasonDoNotExplodeIndeterminate,
		ReasonDoNotExplodeNotEvaluated, ReasonFeedbackRequested, ReasonFeedbackRelaySelected,
		ReasonFeedHereInert, ReasonExplodedReported:
		return true
	default:
		return false
	}
}

// Action stores one immutable local disposition.
type Action struct{ kind ActionKind }

// Kind returns the closed disposition action kind.
func (a Action) Kind() ActionKind { return a.kind }

// Valid reports whether the action belongs to the closed vocabulary.
func (a Action) Valid() bool { return a.kind.Known() }

// Decision stores one immutable local policy outcome separate from verification.
type Decision struct {
	protocol            ProtocolClass
	mode                Mode
	verdict             Verdict
	primaryReason       PolicyReason
	modifyState         ComplianceState
	explodeState        ComplianceState
	feedbackIntent      FeedbackIntent
	dnsTestingEffective bool
	findings            []Finding
	actions             []Action
	initialized         bool
	authenticationFinal bool
}

// Protocol returns the unchanged authoritative verification class.
func (d Decision) Protocol() ProtocolClass { return d.protocol }

// Mode returns the explicit local policy mode.
func (d Decision) Mode() Mode { return d.mode }

// Verdict returns the separate local policy verdict.
func (d Decision) Verdict() Verdict { return d.verdict }

// PrimaryReason returns the deterministic decision reason.
func (d Decision) PrimaryReason() PolicyReason { return d.primaryReason }

// DoNotModifyCompliance returns aggregate authenticated modification compliance.
func (d Decision) DoNotModifyCompliance() ComplianceState { return d.modifyState }

// DoNotExplodeCompliance returns aggregate authenticated explosion compliance.
func (d Decision) DoNotExplodeCompliance() ComplianceState { return d.explodeState }

// FeedbackIntent returns bounded authenticated feedback intent by value.
func (d Decision) FeedbackIntent() FeedbackIntent { return d.feedbackIntent }

// DNSTestingEffective reports whether DNS testing changed policy treatment.
func (d Decision) DNSTestingEffective() bool { return d.dnsTestingEffective }

// Findings returns an independent ordered copy of policy findings.
func (d Decision) Findings() []Finding { return slices.Clone(d.findings) }

// Actions returns an independent copy containing one disposition action.
func (d Decision) Actions() []Action { return slices.Clone(d.actions) }

// IsZero reports whether the decision carries no initialized policy state.
func (d Decision) IsZero() bool {
	return !d.initialized && !d.authenticationFinal && d.protocol == "" && d.mode == "" && d.verdict == "" && d.primaryReason == "" && d.modifyState == "" && d.explodeState == "" && !d.feedbackIntent.Valid() && !d.dnsTestingEffective && len(d.findings) == 0 && len(d.actions) == 0
}

// Valid reports whether decision state satisfies closed base invariants.
func (d Decision) Valid() bool {
	if !d.basicValid() {
		return false
	}
	expectedVerdict, expectedPrimary, expectedReasons := d.expectedBaseOutcome()
	if len(d.findings) < len(expectedReasons) {
		return false
	}
	for index, reason := range expectedReasons {
		if d.findings[index].reason != reason {
			return false
		}
	}
	remainder := d.findings[len(expectedReasons):]
	if !validFindingOrder(remainder) || dnsFindingCount(remainder) > 1 {
		return false
	}
	if !d.dnsTestingEffective && d.mode == ModeStrict && d.protocol == ProtocolPASS {
		modifyViolation, explodeViolation := complianceViolations(remainder)
		if modifyViolation {
			expectedVerdict, expectedPrimary = VerdictReject, ReasonDoNotModifyViolated
		} else if explodeViolation {
			expectedVerdict, expectedPrimary = VerdictReject, ReasonDoNotExplodeViolated
		}
	}
	if d.verdict != expectedVerdict || d.primaryReason != expectedPrimary || !dnsDecisionCoherent(d.protocol, d.dnsTestingEffective, remainder) ||
		!feedbackFindingCoherent(d.feedbackIntent, d.findings) || !complianceFindingCoherent(d.modifyState, d.findings, true) || !complianceFindingCoherent(d.explodeState, d.findings, false) {
		return false
	}
	return true
}

// dnsDecisionCoherent binds the single DNS classification to protocol treatment.
func dnsDecisionCoherent(protocol ProtocolClass, effective bool, findings []Finding) bool {
	count := dnsFindingCount(findings)
	if count > 1 || effective != hasFinding(findings, ReasonDNSTestingEffective) {
		return false
	}
	if effective {
		return protocol == ProtocolPASS || protocol == ProtocolFAIL || protocol == ProtocolPERMERROR
	}
	return true
}

// basicValid checks closed fields, actions, and individual finding shape.
func (d Decision) basicValid() bool {
	if !d.initialized || !d.protocol.Known() || !d.mode.Known() || !d.verdict.Known() ||
		!findingReasonAllowed(d.primaryReason) || !d.modifyState.Known() || !d.explodeState.Known() ||
		!d.feedbackIntent.Valid() || len(d.findings) == 0 || len(d.actions) != 1 || d.actions[0].kind != actionForVerdict(d.verdict) {
		return false
	}
	for _, finding := range d.findings {
		if !finding.Valid() {
			return false
		}
	}
	return true
}

// expectedBaseOutcome derives mode findings and DNS-effective precedence.
func (d Decision) expectedBaseOutcome() (Verdict, PolicyReason, []PolicyReason) {
	if d.authenticationFinal {
		verdict := strictVerdict(d.protocol)
		reason := reasonForProtocol(d.protocol)
		return verdict, reason, []PolicyReason{reason}
	}
	verdict, primary, reasons := baseOutcome(d.protocol, d.mode)
	if !d.dnsTestingEffective {
		return verdict, primary, reasons
	}
	if d.mode == ModePermissive && len(reasons) == 2 && reasons[1] == ReasonPermissiveOverride {
		reasons = reasons[:1]
	}
	return VerdictContinue, ReasonDNSTestingEffective, reasons
}

// newAuthenticationDecision seals a non-overridable final replay outcome while retaining authenticated compliance facts.
func newAuthenticationDecision(protocol ProtocolClass, mode Mode, source Decision) (Decision, error) {
	if !source.Valid() || source.protocol != ProtocolPASS ||
		(protocol != ProtocolFAIL && protocol != ProtocolTEMPERROR) {
		return Decision{}, newError(ErrorInternalContract)
	}
	reason := reasonForProtocol(protocol)
	finding, err := newFinding(reason, 0, false)
	if err != nil {
		return Decision{}, err
	}
	derived := make([]Finding, 0, len(source.findings))
	for _, current := range source.findings {
		switch current.reason {
		case ReasonProtocolPass, ReasonTestingModeObserve, ReasonPermissiveOverride,
			ReasonDNSTestingEffective, ReasonDNSTestingMixed, ReasonDNSTestingIneligible:
			continue
		default:
			derived = append(derived, current)
		}
	}
	findings := append([]Finding{finding}, derived...)
	verdict := strictVerdict(protocol)
	decision := Decision{
		protocol: protocol, mode: mode, verdict: verdict, primaryReason: reason,
		modifyState: source.modifyState, explodeState: source.explodeState,
		feedbackIntent: source.feedbackIntent, findings: findings,
		actions: []Action{{kind: actionForVerdict(verdict)}}, initialized: true,
		authenticationFinal: true,
	}
	if !decision.Valid() {
		return Decision{}, newError(ErrorInternalContract)
	}
	return decision, nil
}

// complianceViolations reports proven modification and explosion findings.
func complianceViolations(findings []Finding) (bool, bool) {
	modify, explode := false, false
	for _, finding := range findings {
		modify = modify || finding.reason == ReasonDoNotModifyViolated
		explode = explode || finding.reason == ReasonDoNotExplodeViolated
	}
	return modify, explode
}

// dnsFindingCount counts the closed DNS classification findings.
func dnsFindingCount(findings []Finding) int {
	count := 0
	for _, finding := range findings {
		if complianceFindingClass(finding.reason) == 1 {
			count++
		}
	}
	return count
}

// newDecision constructs one immutable validated policy decision.
func newDecision(protocol ProtocolClass, mode Mode, verdict Verdict, primary PolicyReason, modifyState, explodeState ComplianceState, feedback FeedbackIntent, dnsEffective bool, findings []Finding) (Decision, error) {
	decision := Decision{
		protocol: protocol, mode: mode, verdict: verdict, primaryReason: primary,
		modifyState: modifyState, explodeState: explodeState,
		feedbackIntent: feedback, dnsTestingEffective: dnsEffective,
		findings: slices.Clone(findings), actions: []Action{{kind: actionForVerdict(verdict)}}, initialized: true,
	}
	if !decision.Valid() {
		return Decision{}, newError(ErrorInternalContract)
	}
	return decision, nil
}

// validFindingOrder enforces compliance class and ascending sequence order.
func validFindingOrder(findings []Finding) bool {
	previousClass := 0
	previousSequence := uint64(0)
	for _, finding := range findings {
		class := complianceFindingClass(finding.reason)
		sequence, hasSequence := finding.Sequence()
		if class == 0 || class < previousClass || class == 1 && hasSequence || class > 1 && !hasSequence || class == previousClass && class > 1 && sequence <= previousSequence {
			return false
		}
		previousClass, previousSequence = class, sequence
	}
	return true
}

// complianceFindingClass returns the frozen P03 finding class order.
func complianceFindingClass(reason PolicyReason) int {
	switch reason {
	case ReasonDNSTestingEffective, ReasonDNSTestingMixed, ReasonDNSTestingIneligible:
		return 1
	case ReasonDoNotModifyHonored, ReasonDoNotModifyViolated, ReasonDoNotModifyIndeterminate, ReasonDoNotModifyNotEvaluated:
		return 2
	case ReasonDoNotExplodeViolated, ReasonDoNotExplodeIndeterminate, ReasonDoNotExplodeNotEvaluated:
		return 3
	case ReasonFeedbackRequested:
		return 4
	case ReasonFeedbackRelaySelected, ReasonFeedHereInert:
		return 5
	case ReasonExplodedReported:
		return 6
	default:
		return 0
	}
}

// complianceFindingCoherent binds aggregate states to their per-request findings.
func complianceFindingCoherent(state ComplianceState, findings []Finding, modify bool) bool {
	hasClass, hasViolated, hasHonored, hasIndeterminate, hasNotEvaluated := false, false, false, false, false
	for _, finding := range findings {
		if modify && complianceFindingClass(finding.reason) != 2 || !modify && complianceFindingClass(finding.reason) != 3 {
			continue
		}
		hasClass = true
		switch finding.reason {
		case ReasonDoNotModifyViolated, ReasonDoNotExplodeViolated:
			hasViolated = true
		case ReasonDoNotModifyHonored:
			hasHonored = true
		case ReasonDoNotModifyIndeterminate, ReasonDoNotExplodeIndeterminate:
			hasIndeterminate = true
		case ReasonDoNotModifyNotEvaluated, ReasonDoNotExplodeNotEvaluated:
			hasNotEvaluated = true
		}
	}
	switch state {
	case ComplianceViolated:
		return hasViolated
	case ComplianceHonored:
		return modify && hasHonored && !hasViolated && !hasIndeterminate && !hasNotEvaluated
	case ComplianceIndeterminate:
		return !hasViolated && (hasIndeterminate || !hasClass)
	case ComplianceNotEvaluated:
		return !hasViolated && !hasIndeterminate && (hasNotEvaluated || !hasClass)
	case ComplianceNotRequested:
		return !hasClass
	default:
		return false
	}
}

// hasFinding reports whether one exact reason is present.
func hasFinding(findings []Finding, reason PolicyReason) bool {
	for _, finding := range findings {
		if finding.reason == reason {
			return true
		}
	}
	return false
}

// feedbackFindingCoherent binds intent booleans and selected sequence to findings.
func feedbackFindingCoherent(intent FeedbackIntent, findings []Finding) bool {
	requested := false
	relayRequired := false
	relaySequence := uint64(0)
	for _, finding := range findings {
		switch finding.reason {
		case ReasonFeedbackRequested:
			requested = true
		case ReasonFeedbackRelaySelected:
			if relayRequired {
				return false
			}
			relayRequired = true
			relaySequence = finding.sequence
		}
	}
	return intent.requested == requested && intent.relayRequired == relayRequired && intent.relaySequence == relaySequence
}

// actionForVerdict returns the unique action matching a known verdict.
func actionForVerdict(verdict Verdict) ActionKind {
	switch verdict {
	case VerdictAccept:
		return ActionAccept
	case VerdictReject:
		return ActionReject
	case VerdictTempfail:
		return ActionTempfail
	case VerdictContinue:
		return ActionContinue
	default:
		return ""
	}
}
