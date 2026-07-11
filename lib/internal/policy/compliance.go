package policy

// complianceEvaluation stores bounded per-projection compliance output.
type complianceEvaluation struct {
	modifyState  ComplianceState
	explodeState ComplianceState
	modify       []Finding
	explode      []Finding
	reports      []Finding
}

// countComplianceFindings pre-counts exact derived findings without allocation.
func countComplianceFindings(hops []HopFact) int {
	count := 0
	for _, hop := range hops {
		if hop.DoNotModify() {
			count++
		}
		if hop.DoNotExplode() {
			count++
		}
		if hop.Exploded() {
			count++
		}
	}
	return count
}

// evaluateCompliance derives per-request findings from authenticated facts only.
func evaluateCompliance(projection Projection) (complianceEvaluation, error) {
	hops := projection.Hops()
	evaluation := complianceEvaluation{
		modifyState:  initialComplianceState(projection),
		explodeState: initialComplianceState(projection),
		modify:       make([]Finding, 0, len(hops)),
		explode:      make([]Finding, 0, len(hops)),
		reports:      make([]Finding, 0, len(hops)),
	}
	for index, hop := range hops {
		if hop.DoNotModify() {
			state, reason := evaluateModifyRequest(projection.HistoryCoverage(), hops, index)
			finding, err := newFinding(reason, hop.Sequence(), true)
			if err != nil {
				return complianceEvaluation{}, err
			}
			evaluation.modify = append(evaluation.modify, finding)
			evaluation.modifyState = mergeComplianceState(evaluation.modifyState, state)
		}
		if hop.DoNotExplode() {
			state, reason := evaluateExplodeRequest(projection.HistoryCoverage(), hops, index)
			finding, err := newFinding(reason, hop.Sequence(), true)
			if err != nil {
				return complianceEvaluation{}, err
			}
			evaluation.explode = append(evaluation.explode, finding)
			evaluation.explodeState = mergeComplianceState(evaluation.explodeState, state)
		}
		if hop.Exploded() {
			finding, err := newFinding(ReasonExplodedReported, hop.Sequence(), true)
			if err != nil {
				return complianceEvaluation{}, err
			}
			evaluation.reports = append(evaluation.reports, finding)
		}
	}
	return evaluation, nil
}

// initialComplianceState reflects what the authenticated coverage can establish globally.
func initialComplianceState(projection Projection) ComplianceState {
	switch projection.HistoryCoverage() {
	case HistoryComplete:
		return ComplianceNotRequested
	case HistoryIndeterminate:
		return ComplianceIndeterminate
	case HistoryNotEvaluated:
		return ComplianceNotEvaluated
	default:
		return ComplianceNotEvaluated
	}
}

// evaluateModifyRequest derives one request state using strictly later transitions.
func evaluateModifyRequest(coverage HistoryCoverage, hops []HopFact, requestIndex int) (ComplianceState, PolicyReason) {
	if coverage == HistoryNotEvaluated {
		return ComplianceNotEvaluated, ReasonDoNotModifyNotEvaluated
	}
	if coverage == HistoryIndeterminate {
		return ComplianceIndeterminate, ReasonDoNotModifyIndeterminate
	}
	violated := false
	indeterminate := false
	positive := false
	requestSequence := hops[requestIndex].Sequence()
	for _, later := range hops[requestIndex+1:] {
		if later.Sequence() <= requestSequence {
			continue
		}
		switch later.Transition() {
		case TransitionBodyChanged, TransitionHeadersChanged, TransitionBodyAndHeadersChanged:
			violated = true
		case TransitionUnchanged, TransitionHeaderAdditionOnly:
			positive = true
		case TransitionIndeterminate, TransitionNotEvaluated:
			indeterminate = true
		}
	}
	if violated {
		return ComplianceViolated, ReasonDoNotModifyViolated
	}
	if indeterminate || !positive {
		return ComplianceIndeterminate, ReasonDoNotModifyIndeterminate
	}
	return ComplianceHonored, ReasonDoNotModifyHonored
}

// evaluateExplodeRequest derives one request state without absence-as-proof.
func evaluateExplodeRequest(coverage HistoryCoverage, hops []HopFact, requestIndex int) (ComplianceState, PolicyReason) {
	if coverage == HistoryNotEvaluated {
		return ComplianceNotEvaluated, ReasonDoNotExplodeNotEvaluated
	}
	if coverage == HistoryIndeterminate {
		return ComplianceIndeterminate, ReasonDoNotExplodeIndeterminate
	}
	requestSequence := hops[requestIndex].Sequence()
	for _, later := range hops[requestIndex+1:] {
		if later.Sequence() > requestSequence && later.Exploded() {
			return ComplianceViolated, ReasonDoNotExplodeViolated
		}
	}
	return ComplianceIndeterminate, ReasonDoNotExplodeIndeterminate
}

// mergeComplianceState applies deterministic aggregate violation precedence.
func mergeComplianceState(current, next ComplianceState) ComplianceState {
	if complianceRank(next) > complianceRank(current) {
		return next
	}
	return current
}

// complianceRank orders aggregate states from least to most conservative.
func complianceRank(state ComplianceState) int {
	switch state {
	case ComplianceNotRequested:
		return 0
	case ComplianceHonored:
		return 1
	case ComplianceNotEvaluated:
		return 2
	case ComplianceIndeterminate:
		return 3
	case ComplianceViolated:
		return 4
	default:
		return -1
	}
}
