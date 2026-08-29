package policy

// Evaluator applies deterministic local policy over sealed verification facts.
type Evaluator struct{ config Config }

// NewEvaluator validates and constructs one immutable policy evaluator.
func NewEvaluator(config Config) (Evaluator, error) {
	if err := config.Validate(); err != nil {
		return Evaluator{}, err
	}
	return Evaluator{config: config}, nil
}

// evaluateBase applies the closed mode matrix without historical or DNS facts.
func (e Evaluator) evaluateBase(protocol ProtocolClass) (Decision, error) {
	if err := e.config.Validate(); err != nil {
		return Decision{}, err
	}
	if !protocol.Known() {
		return Decision{}, newError(ErrorInvalidInput)
	}
	verdict, primary, reasons := baseOutcome(protocol, e.config.Mode)
	if len(reasons) > e.config.Limits.MaxFindings {
		return Decision{}, newLimitError(limitNameFindings, e.config.Limits.MaxFindings, len(reasons))
	}
	findings := make([]Finding, 0, len(reasons))
	for _, reason := range reasons {
		finding, err := newFinding(reason, 0, false)
		if err != nil {
			return Decision{}, err
		}
		findings = append(findings, finding)
	}
	return newDecision(protocol, e.config.Mode, verdict, primary, ComplianceNotEvaluated, ComplianceNotEvaluated, FeedbackIntent{history: HistoryNotEvaluated}, false, findings)
}

// EvaluateProjection applies policy to one service-sealed internal projection.
func (e Evaluator) EvaluateProjection(projection Projection) (Decision, error) {
	if err := e.config.Validate(); err != nil {
		return Decision{}, err
	}
	if projection.IsZero() {
		return Decision{}, newError(ErrorInvalidInput)
	}
	if !projection.Valid() {
		return Decision{}, newError(ErrorInternalContract)
	}
	dns, err := evaluateDNSTesting(projection)
	if err != nil {
		return Decision{}, err
	}
	verdict, primary, baseReasons := baseOutcome(projection.Protocol(), e.config.Mode)
	if dns.effective {
		verdict, primary = VerdictContinue, ReasonDNSTestingEffective
		if e.config.Mode == ModePermissive && len(baseReasons) == 2 && baseReasons[1] == ReasonPermissiveOverride {
			baseReasons = baseReasons[:1]
		}
	}
	hops := projection.Hops()
	if len(hops) > e.config.Limits.MaxAuthenticatedHops {
		return Decision{}, newLimitError(limitNameAuthenticatedHops, e.config.Limits.MaxAuthenticatedHops, len(hops))
	}
	suppressAuthenticatedFlags := dns.effective && projection.Protocol() == ProtocolPASS
	if suppressAuthenticatedFlags {
		hops = nil
	}
	feedback := summarizeFeedback(hops, projection.HistoryCoverage())
	derivedCount := countComplianceFindings(hops) + feedback.feedbackFindingCount()
	if dns.reason != "" {
		derivedCount++
	}
	if derivedCount > e.config.Limits.MaxFindings || len(baseReasons) > e.config.Limits.MaxFindings-derivedCount {
		return Decision{}, newLimitError(limitNameFindings, e.config.Limits.MaxFindings, len(baseReasons)+derivedCount)
	}
	compliance := complianceEvaluation{modifyState: initialComplianceState(projection), explodeState: initialComplianceState(projection)}
	if !suppressAuthenticatedFlags {
		compliance, err = evaluateCompliance(projection)
		if err != nil {
			return Decision{}, err
		}
	}
	findings := make([]Finding, 0, len(baseReasons)+derivedCount)
	for _, reason := range baseReasons {
		finding, findingErr := newFinding(reason, 0, false)
		if findingErr != nil {
			return Decision{}, findingErr
		}
		findings = append(findings, finding)
	}
	if dns.reason != "" {
		finding, findingErr := newFinding(dns.reason, 0, false)
		if findingErr != nil {
			return Decision{}, findingErr
		}
		findings = append(findings, finding)
	}
	findings = append(findings, compliance.modify...)
	findings = append(findings, compliance.explode...)
	feedbackRequests, feedbackRelays, err := feedbackFindings(hops, feedback)
	if err != nil {
		return Decision{}, err
	}
	findings = append(findings, feedbackRequests...)
	findings = append(findings, feedbackRelays...)
	findings = append(findings, compliance.reports...)
	if !dns.effective && e.config.Mode == ModeStrict && projection.Protocol() == ProtocolPASS {
		if compliance.modifyState == ComplianceViolated {
			verdict, primary = VerdictReject, ReasonDoNotModifyViolated
		} else if compliance.explodeState == ComplianceViolated {
			verdict, primary = VerdictReject, ReasonDoNotExplodeViolated
		}
	}
	return newDecision(projection.Protocol(), e.config.Mode, verdict, primary, compliance.modifyState, compliance.explodeState, feedback.intent, dns.effective, findings)
}

// EvaluateAuthenticationProjection applies non-overridable replay failure after deriving authenticated compliance facts.
func (e Evaluator) EvaluateAuthenticationProjection(projection Projection, protocol ProtocolClass) (Decision, error) {
	decision, err := e.EvaluateProjection(projection)
	if err != nil {
		return Decision{}, err
	}
	if protocol == projection.Protocol() {
		return decision, nil
	}
	return newAuthenticationDecision(protocol, e.config.Mode, decision)
}

// baseOutcome returns the exact base verdict, primary reason, and finding order.
func baseOutcome(protocol ProtocolClass, mode Mode) (Verdict, PolicyReason, []PolicyReason) {
	protocolReason := reasonForProtocol(protocol)
	reasons := []PolicyReason{protocolReason}
	switch mode {
	case ModeStrict:
		return strictVerdict(protocol), protocolReason, reasons
	case ModePermissive:
		if protocol == ProtocolFAIL || protocol == ProtocolPERMERROR {
			return VerdictAccept, ReasonPermissiveOverride, append(reasons, ReasonPermissiveOverride)
		}
		return strictVerdict(protocol), protocolReason, reasons
	case ModeTesting:
		return VerdictContinue, ReasonTestingModeObserve, append(reasons, ReasonTestingModeObserve)
	default:
		return "", "", nil
	}
}

// strictVerdict maps one known protocol class to strict local disposition.
func strictVerdict(protocol ProtocolClass) Verdict {
	switch protocol {
	case ProtocolPASS:
		return VerdictAccept
	case ProtocolFAIL, ProtocolPERMERROR:
		return VerdictReject
	case ProtocolTEMPERROR:
		return VerdictTempfail
	default:
		return ""
	}
}

// reasonForProtocol maps one known protocol class to its finding reason.
func reasonForProtocol(protocol ProtocolClass) PolicyReason {
	switch protocol {
	case ProtocolPASS:
		return ReasonProtocolPass
	case ProtocolFAIL:
		return ReasonProtocolFail
	case ProtocolPERMERROR:
		return ReasonProtocolPermerror
	case ProtocolTEMPERROR:
		return ReasonProtocolTemperror
	default:
		return ""
	}
}
