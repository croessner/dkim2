package recipe

import "github.com/croessner/dkim2/internal/rawmsg"

// bodyOutput incrementally owns one bounded reconstructed body.
type bodyOutput struct {
	applier Applier
	state   State
	usage   *usageCounter
	bytes   []byte
	lines   int
	framing rawmsg.MessageFraming
}

// applyBody applies only the body dimension under a fresh operation counter.
func (a Applier) applyBody(current State, recipe Recipe) (State, Usage, error) {
	usage, err := newUsageCounter(a.limits)
	if err != nil {
		return State{}, Usage{}, err
	}
	state, applyErr := a.applyBodyUsing(current, recipe, usage, false)
	return state, usage.usage(), applyErr
}

// applyBodyUsing applies the body dimension under a caller-owned counter.
func (a Applier) applyBodyUsing(current State, recipe Recipe, usage *usageCounter, sourcePrepared bool) (State, error) {
	if !a.valid() || !current.Valid() || !recipe.Valid() || usage == nil {
		return State{}, invalidStateError()
	}
	if err := a.validateBodyPlanBudgets(recipe); err != nil {
		return State{}, err
	}
	if recipe.bodyMode == BodyModeUnavailable {
		if current.headers.OriginalByteLen() > a.limits.MaxStateBytes {
			return State{}, bodyLimitError(limitNameMaxStateBytes, a.limits.MaxStateBytes, current.headers.OriginalByteLen())
		}
		return newUnavailableState(current.headers)
	}
	if recipe.bodyMode == BodyModeAbsent && current.availability == BodyAvailabilityUnavailable {
		if current.headers.OriginalByteLen() > a.limits.MaxStateBytes {
			return State{}, bodyLimitError(limitNameMaxStateBytes, a.limits.MaxStateBytes, current.headers.OriginalByteLen())
		}
		return current, nil
	}
	if current.availability == BodyAvailabilityUnavailable {
		if recipeHasBodyCopy(recipe) {
			return State{}, newError(ErrorCodeSourceUnavailable, ErrorLocation{}, ErrorDetails{Dimension: DimensionBody, StepKind: StepKindCopy}, nil)
		}
		return a.emitBodyData(current, recipe, usage)
	}

	if !sourcePrepared {
		_, err := a.preflightKnownBodySource(current, recipe, usage)
		if err != nil {
			return State{}, err
		}
	}
	framing := current.framing
	if recipe.bodyMode == BodyModeSteps {
		framing = rawmsg.MessageFramingDelimited
	}
	output := bodyOutput{applier: a, state: current, usage: usage, framing: framing}
	if recipe.bodyMode == BodyModeAbsent {
		for lineIndex := 0; lineIndex < current.body.LineCount(); lineIndex++ {
			if err := output.appendSourceLine(current.body, lineIndex); err != nil {
				return State{}, err
			}
		}
		return output.finish()
	}

	for _, instruction := range recipe.bodySteps {
		if start, end, copyStep := instruction.copyRange(); copyStep {
			for lineNumber := start; lineNumber <= end; lineNumber++ {
				if err := output.appendSourceLine(current.body, lineNumber-1); err != nil {
					return State{}, err
				}
			}
			continue
		}
		for _, literal := range instruction.data {
			if err := output.appendData(literal); err != nil {
				return State{}, err
			}
		}
	}
	return output.finish()
}

// validateBodyPlanBudgets revalidates combined structural budgets under the applier.
func (a Applier) validateBodyPlanBudgets(recipe Recipe) error {
	if len(recipe.bodySteps) > a.limits.MaxBodySteps {
		return bodyLimitError(limitNameMaxBodySteps, a.limits.MaxBodySteps, len(recipe.bodySteps))
	}
	return validateAllPlanStepBudgets(recipe, a.limits, DimensionBody)
}

// preflightKnownBodySource validates source metadata and copy feasibility without cloning bytes.
func (a Applier) preflightKnownBodySource(current State, recipe Recipe, usage *usageCounter) (rawmsg.BodyLineIndex, error) {
	if current.availability != BodyAvailabilityKnown {
		return rawmsg.BodyLineIndex{}, invalidStateError()
	}
	if usage == nil {
		return rawmsg.BodyLineIndex{}, invalidStateError()
	}
	if current.body.LineCount() > a.limits.MaxBodyLines {
		return rawmsg.BodyLineIndex{}, bodyLimitError(limitNameMaxBodyLines, a.limits.MaxBodyLines, current.body.LineCount())
	}
	lines := current.body.Lines()
	for lineIndex := 0; lineIndex < lines.Len(); lineIndex++ {
		line, ok := lines.Line(lineIndex)
		if !ok {
			return rawmsg.BodyLineIndex{}, invalidStateError()
		}
		if err := usage.chargeItems(1); err != nil {
			return rawmsg.BodyLineIndex{}, err
		}
		length := line.EndOffset() - line.StartOffset()
		if length > a.limits.MaxBodyLineBytes {
			return rawmsg.BodyLineIndex{}, bodyLimitError(limitNameMaxBodyLineBytes, a.limits.MaxBodyLineBytes, length)
		}
	}
	if recipe.bodyMode == BodyModeSteps {
		if err := validateBodyCopySources(recipe, lines, a.limits.MaxBodyLines, usage); err != nil {
			return rawmsg.BodyLineIndex{}, err
		}
	}
	return lines, nil
}

// recipeHasBodyCopy reports whether the body plan depends on source bytes.
func recipeHasBodyCopy(recipe Recipe) bool {
	for _, instruction := range recipe.bodySteps {
		if _, _, copyStep := instruction.copyRange(); copyStep {
			return true
		}
	}
	return false
}

// validateBodyCopySources checks bounds and final-only unterminated copies before emission.
func validateBodyCopySources(recipe Recipe, lines rawmsg.BodyLineIndex, maxBodyLines int, usage *usageCounter) error {
	emissions := 0
	for _, instruction := range recipe.bodySteps {
		if start, end, copyStep := instruction.copyRange(); copyStep {
			if end > lines.Len() {
				return newError(ErrorCodeCopyRangeOutOfBounds, ErrorLocation{}, ErrorDetails{Dimension: DimensionBody, StepKind: StepKindCopy, Expected: lines.Len(), Actual: end}, nil)
			}
			if err := usage.chargeItems(end - start + 1); err != nil {
				return err
			}
			var ok bool
			emissions, ok = checkedAdd(emissions, end-start+1)
			if !ok || emissions > maxBodyLines {
				return bodyLimitError(limitNameMaxBodyLines, maxBodyLines, emissions)
			}
			continue
		}
		var ok bool
		emissions, ok = checkedAdd(emissions, len(instruction.data))
		if !ok || emissions > maxBodyLines {
			return bodyLimitError(limitNameMaxBodyLines, maxBodyLines, emissions)
		}
	}
	ordinal := 0
	for stepIndex, instruction := range recipe.bodySteps {
		if start, end, copyStep := instruction.copyRange(); copyStep {
			for number := start; number <= end; number++ {
				line, _ := lines.Line(number - 1)
				if line.LineEndingWidth() == 0 && ordinal != emissions-1 {
					return newError(ErrorCodeInvalidState, ErrorLocation{StepIndex: stepIndex, BodyLine: number}, ErrorDetails{Dimension: DimensionBody, StepKind: StepKindCopy}, nil)
				}
				var ok bool
				ordinal, ok = checkedAdd(ordinal, 1)
				if !ok {
					return invalidStateError()
				}
			}
			continue
		}
		var ok bool
		ordinal, ok = checkedAdd(ordinal, len(instruction.data))
		if !ok {
			return invalidStateError()
		}
	}
	return nil
}

// emitBodyData reconstructs a known body without unavailable source bytes.
func (a Applier) emitBodyData(current State, recipe Recipe, usage *usageCounter) (State, error) {
	output := bodyOutput{applier: a, state: current, usage: usage, framing: rawmsg.MessageFramingDelimited}
	for _, instruction := range recipe.bodySteps {
		for _, literal := range instruction.data {
			if err := output.appendData(literal); err != nil {
				return State{}, err
			}
		}
	}
	return output.finish()
}

// appendData appends one literal and mandatory CRLF under all budgets.
func (o *bodyOutput) appendData(literal []byte) error {
	length, ok := checkedAdd(len(literal), 2)
	if !ok || len(literal) > o.applier.limits.MaxBodyLineBytes {
		return bodyLimitError(limitNameMaxBodyLineBytes, o.applier.limits.MaxBodyLineBytes, len(literal))
	}
	if err := o.reserveLine(length); err != nil {
		return err
	}
	o.bytes = append(o.bytes, literal...)
	o.bytes = append(o.bytes, '\r', '\n')
	return nil
}

// appendSourceLine reserves budgets before cloning one exact source line.
func (o *bodyOutput) appendSourceLine(body rawmsg.Body, lineIndex int) error {
	length, ok := body.LineEncodedLen(lineIndex)
	if !ok {
		return invalidStateError()
	}
	if err := o.reserveLine(length); err != nil {
		return err
	}
	encoded, ok := body.LineBytes(lineIndex)
	if !ok || len(encoded) != length {
		return invalidStateError()
	}
	o.bytes = append(o.bytes, encoded...)
	return nil
}

// reserveLine charges count, state, item, and emitted work before allocation.
func (o *bodyOutput) reserveLine(length int) error {
	nextLines, ok := checkedAdd(o.lines, 1)
	if !ok || nextLines > o.applier.limits.MaxBodyLines {
		return bodyLimitError(limitNameMaxBodyLines, o.applier.limits.MaxBodyLines, nextLines)
	}
	nextBytes, ok := checkedAdd(len(o.bytes), length)
	if !ok {
		return bodyLimitError(limitNameMaxStateBytes, o.applier.limits.MaxStateBytes, nextBytes)
	}
	stateBytes, ok := checkedAdd(o.state.headers.OriginalByteLen(), 2)
	if !ok {
		return bodyLimitError(limitNameMaxStateBytes, o.applier.limits.MaxStateBytes, stateBytes)
	}
	stateBytes, ok = checkedAdd(stateBytes, nextBytes)
	if !ok || stateBytes > o.applier.limits.MaxStateBytes {
		return bodyLimitError(limitNameMaxStateBytes, o.applier.limits.MaxStateBytes, stateBytes)
	}
	if err := o.usage.chargeItems(1); err != nil {
		return err
	}
	if err := o.usage.chargeEmitted(length); err != nil {
		return err
	}
	o.lines = nextLines
	return nil
}

// finish validates framing and constructs one immutable known state.
func (o *bodyOutput) finish() (State, error) {
	separator := 0
	if o.framing == rawmsg.MessageFramingDelimited {
		separator = 2
	}
	stateBytes, ok := checkedAdd(o.state.headers.OriginalByteLen(), separator)
	if !ok {
		return State{}, bodyLimitError(limitNameMaxStateBytes, o.applier.limits.MaxStateBytes, stateBytes)
	}
	stateBytes, ok = checkedAdd(stateBytes, len(o.bytes))
	if !ok || stateBytes > o.applier.limits.MaxStateBytes {
		return State{}, bodyLimitError(limitNameMaxStateBytes, o.applier.limits.MaxStateBytes, stateBytes)
	}
	body, err := rawmsg.NewReconstructedBody(o.bytes, o.applier.rawOptions)
	if err != nil {
		return State{}, mapRawApplicationError(err, DimensionBody)
	}
	return newKnownState(o.state.headers, body, o.framing)
}

// bodyLimitError constructs one body-dimension application limit failure.
func bodyLimitError(name string, limit, actual int) *Error {
	return applicationLimitError(DimensionBody, name, limit, actual)
}
