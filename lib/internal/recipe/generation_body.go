package recipe

import (
	"bytes"
	"unicode/utf8"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// bodyPlanningResult stores one immutable package-internal body planning outcome.
type bodyPlanningResult struct {
	outcome     BodyGenerationOutcome
	unavailable BodyUnavailableReason
	steps       []step
	initialized bool
}

// Valid reports whether the result is one coherent closed body outcome.
func (r bodyPlanningResult) Valid() bool {
	if !r.initialized || !r.outcome.Known() {
		return false
	}
	switch r.outcome {
	case BodyGenerationUnchanged:
		return len(r.steps) == 0 && !r.unavailable.Known()
	case BodyGenerationUnavailable:
		return len(r.steps) == 0 && r.unavailable.Known()
	case BodyGenerationGenerated:
		if r.unavailable.Known() {
			return false
		}
		previousCopyEnd := 0
		for _, instruction := range r.steps {
			if !instruction.valid() {
				return false
			}
			if start, end, copyStep := instruction.copyRange(); copyStep {
				if previousCopyEnd != 0 && start <= previousCopyEnd {
					return false
				}
				previousCopyEnd = end
			}
		}
		return true
	default:
		return false
	}
}

// Outcome returns the closed body planning outcome.
func (r bodyPlanningResult) Outcome() BodyGenerationOutcome {
	if !r.Valid() {
		return ""
	}
	return r.outcome
}

// UnavailableReason returns a reason only for an authorized unavailable result.
func (r bodyPlanningResult) UnavailableReason() BodyUnavailableReason {
	if !r.Valid() || r.outcome != BodyGenerationUnavailable {
		return ""
	}
	return r.unavailable
}

// stepsCopy returns detached generated body operations.
func (r bodyPlanningResult) stepsCopy() []step {
	if !r.Valid() || r.outcome != BodyGenerationGenerated {
		return nil
	}
	return cloneSteps(r.steps)
}

// newUnchangedBodyPlanningResult constructs the closed omitted-body outcome.
func newUnchangedBodyPlanningResult() bodyPlanningResult {
	return bodyPlanningResult{outcome: BodyGenerationUnchanged, initialized: true}
}

// newGeneratedBodyPlanningResult validates and takes ownership of generated steps.
func newGeneratedBodyPlanningResult(steps []step, counter *generationCounter) (bodyPlanningResult, error) {
	if err := chargeBodyPlanPass(steps, counter); err != nil {
		return bodyPlanningResult{}, err
	}
	result := bodyPlanningResult{outcome: BodyGenerationGenerated, steps: steps, initialized: true}
	if !result.Valid() {
		return bodyPlanningResult{}, generationInvariantErrorForDimension(DimensionBody)
	}
	return result, nil
}

// newUnavailableBodyPlanningResult constructs one authorized closed unavailable outcome.
func newUnavailableBodyPlanningResult(reason BodyUnavailableReason) (bodyPlanningResult, error) {
	result := bodyPlanningResult{outcome: BodyGenerationUnavailable, unavailable: reason, initialized: true}
	if !result.Valid() {
		return bodyPlanningResult{}, generationInvariantErrorForDimension(DimensionBody)
	}
	return result, nil
}

// planBody deterministically plans only inverse body reconstruction and framing.
func (g Generator) planBody(request GenerationRequest, budget *generationPlanBudget) (bodyPlanningResult, error) {
	if err := g.validateRequest(request); err != nil {
		return bodyPlanningResult{}, err
	}
	if budget == nil || budget.counter == nil || budget.limits != g.limits.RecipeLimits || budget.counter.limits != g.limits {
		return bodyPlanningResult{}, generationInvariantErrorForDimension(DimensionBody)
	}
	counter := budget.counter
	previous, current := request.Previous(), request.Current()
	previousBytes, ok := bodyGenerationInputBytes(previous)
	if !ok {
		return bodyPlanningResult{}, generationLimitError(limitNameMaxInputBytes, g.limits.MaxInputBytes, previousBytes, DimensionBody)
	}
	currentBytes, ok := bodyGenerationInputBytes(current)
	if !ok {
		return bodyPlanningResult{}, generationLimitError(limitNameMaxInputBytes, g.limits.MaxInputBytes, currentBytes, DimensionBody)
	}
	inputBytes, ok := checkedAdd(previousBytes, currentBytes)
	if !ok {
		return bodyPlanningResult{}, generationLimitError(limitNameMaxInputBytes, g.limits.MaxInputBytes, inputBytes, DimensionBody)
	}
	inputItems, ok := checkedAdd(previous.body.LineCount(), current.body.LineCount())
	if !ok {
		return bodyPlanningResult{}, generationLimitError(limitNameMaxInputItems, g.limits.MaxInputItems, inputItems, DimensionBody)
	}
	if err := counter.chargeInput(inputBytes, inputItems, DimensionBody); err != nil {
		return bodyPlanningResult{}, err
	}
	if err := validateBodyGenerationState(previous, g.limits.RecipeLimits, counter); err != nil {
		return bodyPlanningResult{}, err
	}
	if err := validateBodyGenerationState(current, g.limits.RecipeLimits, counter); err != nil {
		return bodyPlanningResult{}, err
	}
	equalityWork, ok := checkedAdd(max(previous.body.Len(), current.body.Len()), 1)
	if !ok {
		return bodyPlanningResult{}, generationLimitError(limitNameMaxGenerationWorkUnits, counter.limits.MaxGenerationWorkUnits, equalityWork, DimensionBody)
	}
	if err := counter.chargeWork(equalityWork, DimensionBody); err != nil {
		return bodyPlanningResult{}, err
	}
	if previous.framing == current.framing && previous.body.Equal(current.body) {
		return newUnchangedBodyPlanningResult(), nil
	}
	if previous.framing == rawmsg.MessageFramingHeaderOnly {
		return resolveUnavailableBody(request.BodyUnavailablePolicy(), BodyUnavailableReasonUnrepresentable)
	}
	if previous.body.LineCount() == 0 {
		return newGeneratedBodyPlanningResult(nil, counter)
	}
	target, err := collectBodyGenerationLines(previous.body, counter)
	if err != nil {
		return bodyPlanningResult{}, err
	}
	source, err := collectBodyGenerationLines(current.body, counter)
	if err != nil {
		return bodyPlanningResult{}, err
	}
	steps, reason, err := budget.planBodyLines(target, source, request.LiteralPolicy())
	if err != nil {
		return bodyPlanningResult{}, err
	}
	if reason.Known() {
		return resolveUnavailableBody(request.BodyUnavailablePolicy(), reason)
	}
	return newGeneratedBodyPlanningResult(steps, counter)
}

// bodyGenerationInputBytes includes the framing delimiter examined for one state.
func bodyGenerationInputBytes(state State) (int, bool) {
	separator := 0
	if state.framing == rawmsg.MessageFramingDelimited {
		separator = 2
	}
	return checkedAdd(state.body.Len(), separator)
}

// validateBodyGenerationState enforces inherited state and body-line limits without cloning.
func validateBodyGenerationState(state State, limits Limits, counter *generationCounter) error {
	if !knownGenerationState(state) {
		return newError(ErrorCodeInvalidState, ErrorLocation{}, ErrorDetails{Class: ErrorClassState, Dimension: DimensionBody}, nil)
	}
	separator := 0
	if state.framing == rawmsg.MessageFramingDelimited {
		separator = 2
	}
	stateBytes, ok := checkedSum(state.headers.OriginalByteLen(), separator, state.body.Len())
	if !ok || stateBytes > limits.MaxStateBytes {
		return generationLimitError(limitNameMaxStateBytes, limits.MaxStateBytes, stateBytes, DimensionBody)
	}
	if state.body.LineCount() > limits.MaxBodyLines {
		return generationLimitError(limitNameMaxBodyLines, limits.MaxBodyLines, state.body.LineCount(), DimensionBody)
	}
	return state.body.VisitLines(func(line rawmsg.BodyLineView) error {
		lineWork, ok := checkedAdd(line.EncodedLen(), 1)
		if !ok {
			return generationLimitError(limitNameMaxGenerationWorkUnits, counter.limits.MaxGenerationWorkUnits, lineWork, DimensionBody)
		}
		if err := counter.chargeWork(lineWork, DimensionBody); err != nil {
			return err
		}
		if line.ContentLen() > limits.MaxBodyLineBytes {
			return generationLimitError(limitNameMaxBodyLineBytes, limits.MaxBodyLineBytes, line.ContentLen(), DimensionBody)
		}
		return nil
	})
}

// collectBodyGenerationLines takes one charged owned copy per top-down source item.
func collectBodyGenerationLines(body rawmsg.Body, counter *generationCounter) ([][]byte, error) {
	storageWork, ok := checkedAdd(body.LineCount(), 1)
	if !ok {
		return nil, generationLimitError(limitNameMaxGenerationWorkUnits, counter.limits.MaxGenerationWorkUnits, storageWork, DimensionBody)
	}
	if err := counter.chargeWork(storageWork, DimensionBody); err != nil {
		return nil, err
	}
	lines := make([][]byte, 0, body.LineCount())
	err := body.VisitLines(func(line rawmsg.BodyLineView) error {
		lineWork, ok := checkedAdd(line.EncodedLen(), 1)
		if !ok {
			return generationLimitError(limitNameMaxGenerationWorkUnits, counter.limits.MaxGenerationWorkUnits, lineWork, DimensionBody)
		}
		if err := counter.chargeWork(lineWork, DimensionBody); err != nil {
			return err
		}
		lines = append(lines, line.EncodedCopy())
		return nil
	})
	if err != nil {
		return nil, err
	}
	return lines, nil
}

// planBodyLines applies exact earliest-monotone matching in top-down order.
func (b *generationPlanBudget) planBodyLines(target, source [][]byte, policy LiteralDisclosurePolicy) ([]step, BodyUnavailableReason, error) {
	projectedCandidates, ok := checkedAdd(b.counter.candidates, len(source))
	if !ok || projectedCandidates > b.counter.limits.MaxCandidateEntries {
		return nil, "", generationLimitError(limitNameMaxCandidateEntries, b.counter.limits.MaxCandidateEntries, projectedCandidates, DimensionBody)
	}
	if err := b.counter.chargeWork(1, DimensionBody); err != nil {
		return nil, "", err
	}
	candidates := newExactCandidateIndex()
	for index, value := range source {
		if err := candidates.add(value, index+1, b.counter, DimensionBody); err != nil {
			return nil, "", err
		}
	}
	var steps []step
	lastCopyEnd := 0
	for _, encoded := range target {
		candidate, err := candidates.lookup(encoded, b.counter, DimensionBody)
		if err != nil {
			return nil, "", err
		}
		selected := 0
		for candidate != nil && candidate.cursor < len(candidate.positions) {
			if err := b.counter.chargeComparison(DimensionBody); err != nil {
				return nil, "", err
			}
			occurrence := candidate.positions[candidate.cursor]
			candidate.cursor++
			if occurrence > lastCopyEnd {
				selected = occurrence
				break
			}
		}
		if selected != 0 {
			if err := b.appendCopy(&steps, selected, DimensionBody, b.limits.MaxBodySteps, limitNameMaxBodySteps); err != nil {
				return nil, "", err
			}
			lastCopyEnd = selected
			continue
		}
		content, representable, err := bodyLiteralContent(encoded, b.counter)
		if err != nil {
			return nil, "", err
		}
		if !representable {
			return nil, BodyUnavailableReasonUnrepresentable, nil
		}
		if policy == CopyOnly {
			return nil, BodyUnavailableReasonLiteralRequired, nil
		}
		if len(content) > b.limits.MaxBodyLineBytes {
			return nil, "", generationLimitError(limitNameMaxBodyLineBytes, b.limits.MaxBodyLineBytes, len(content), DimensionBody)
		}
		if err := b.appendDataLiteral(&steps, content, DimensionBody, b.limits.MaxBodySteps, limitNameMaxBodySteps); err != nil {
			return nil, "", err
		}
	}
	return steps, "", nil
}

// bodyLiteralContent charges representability scans before validating one terminated line.
func bodyLiteralContent(encoded []byte, counter *generationCounter) ([]byte, bool, error) {
	if err := counter.chargeWork(1, DimensionBody); err != nil {
		return nil, false, err
	}
	if len(encoded) < 2 || encoded[len(encoded)-2] != '\r' || encoded[len(encoded)-1] != '\n' {
		return nil, false, nil
	}
	content := encoded[:len(encoded)-2]
	validationWork, ok := checkedMultiply(len(content), 2)
	if ok {
		validationWork, ok = checkedAdd(validationWork, 1)
	}
	if !ok {
		return nil, false, generationLimitError(limitNameMaxGenerationWorkUnits, counter.limits.MaxGenerationWorkUnits, validationWork, DimensionBody)
	}
	if err := counter.chargeWork(validationWork, DimensionBody); err != nil {
		return nil, false, err
	}
	return content, utf8.Valid(content) && !bytes.ContainsAny(content, "\r\n"), nil
}

// chargeBodyPlanPass accounts for final step and literal validation scans.
func chargeBodyPlanPass(steps []step, counter *generationCounter) error {
	for _, instruction := range steps {
		work := 1
		for _, literal := range instruction.data {
			literalWork, ok := checkedMultiply(len(literal), 2)
			if ok {
				literalWork, ok = checkedAdd(literalWork, 1)
			}
			if ok {
				work, ok = checkedAdd(work, literalWork)
			}
			if !ok {
				return generationLimitError(limitNameMaxGenerationWorkUnits, counter.limits.MaxGenerationWorkUnits, work, DimensionBody)
			}
		}
		if err := counter.chargeWork(work, DimensionBody); err != nil {
			return err
		}
	}
	return nil
}

// resolveUnavailableBody applies only the explicit body-unavailable policy.
func resolveUnavailableBody(policy BodyUnavailablePolicy, reason BodyUnavailableReason) (bodyPlanningResult, error) {
	if !policy.Known() || !reason.Known() {
		return bodyPlanningResult{}, generationInvariantErrorForDimension(DimensionBody)
	}
	if policy == AllowUnavailableBody {
		return newUnavailableBodyPlanningResult(reason)
	}
	return bodyPlanningResult{}, newError(ErrorCodeBodyUnrepresentable, ErrorLocation{}, ErrorDetails{Class: ErrorClassRepresentation, Dimension: DimensionBody}, nil)
}
