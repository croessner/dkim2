package recipe

import (
	"bytes"
	"errors"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// headerGroup stores source occurrences in physical top-down order.
type headerGroup struct {
	fields [][]byte
}

// headerOutput incrementally owns bounded reconstructed output.
type headerOutput struct {
	applier      Applier
	current      State
	usage        *usageCounter
	encoded      [][]byte
	headerBytes  int
	enforceState bool
}

// applyHeaders transactionally applies only the recipe header dimension.
func (a Applier) applyHeaders(current State, recipe Recipe) (State, Usage, error) {
	usage, counterErr := newUsageCounter(a.limits)
	if counterErr != nil {
		return State{}, Usage{}, counterErr
	}
	state, err := a.applyHeadersUsing(current, recipe, usage, true)
	return state, usage.usage(), err
}

// applyHeadersUsing applies headers under a caller-owned operation counter.
func (a Applier) applyHeadersUsing(current State, recipe Recipe, usage *usageCounter, enforceState bool) (State, error) {
	if !a.valid() || !current.Valid() || !recipe.Valid() {
		return State{}, invalidStateError()
	}
	if err := a.validateHeaderPlanBudgets(recipe); err != nil {
		return State{}, err
	}

	groups, names, sourceOrder, nameBytes, err := a.collectHeaderGroups(current.headers, usage)
	if err != nil {
		return State{}, err
	}
	output := headerOutput{applier: a, current: current, usage: usage, enforceState: enforceState}
	if !recipe.hasHeaderRecipe {
		for _, field := range sourceOrder {
			if err := output.appendField(field); err != nil {
				return State{}, err
			}
		}
		return output.finish()
	}

	plans := make(map[string]headerPlan, len(recipe.headers))
	for _, plan := range recipe.headers {
		plans[plan.canonicalName] = plan
		if _, exists := groups[plan.canonicalName]; exists {
			continue
		}
		if len(names) >= a.limits.MaxHeaderNames {
			return State{}, applyLimitError(limitNameMaxHeaderNames, a.limits.MaxHeaderNames, len(names)+1)
		}
		nextNameBytes, ok := checkedAdd(nameBytes, len(plan.name))
		if !ok || nextNameBytes > a.limits.MaxTotalHeaderNameBytes {
			return State{}, applyLimitError(limitNameMaxTotalHeaderNameBytes, a.limits.MaxTotalHeaderNameBytes, nextNameBytes)
		}
		nameBytes = nextNameBytes
		groups[plan.canonicalName] = headerGroup{}
		names = append(names, plan.canonicalName)
	}
	if err := sortHeaderNames(names, usage); err != nil {
		return State{}, err
	}

	totalCopied := 0
	for _, canonicalName := range names {
		group := groups[canonicalName]
		plan, mentioned := plans[canonicalName]
		if !mentioned {
			for _, field := range group.fields {
				if err := output.appendField(field); err != nil {
					return State{}, err
				}
			}
			continue
		}
		if err := a.appendHeaderPlan(&output, group, plan, &totalCopied); err != nil {
			return State{}, err
		}
	}
	return output.finish()
}

// validateHeaderPlanBudgets revalidates broadly parsed plans under this applier.
func (a Applier) validateHeaderPlanBudgets(recipe Recipe) error {
	if !recipe.hasHeaderRecipe {
		return nil
	}
	if len(recipe.headers) > a.limits.MaxHeaderNames {
		return applyLimitError(limitNameMaxHeaderNames, a.limits.MaxHeaderNames, len(recipe.headers))
	}
	totalNames := 0
	budget := planBudgetAccumulator{}
	for _, plan := range recipe.headers {
		if len(plan.name) > a.limits.MaxHeaderNameBytes {
			return applyLimitError(limitNameMaxHeaderNameBytes, a.limits.MaxHeaderNameBytes, len(plan.name))
		}
		var ok bool
		totalNames, ok = checkedAdd(totalNames, len(plan.name))
		if !ok || totalNames > a.limits.MaxTotalHeaderNameBytes {
			return applyLimitError(limitNameMaxTotalHeaderNameBytes, a.limits.MaxTotalHeaderNameBytes, totalNames)
		}
		if len(plan.steps) > a.limits.MaxStepsPerHeader {
			return applyLimitError(limitNameMaxStepsPerHeader, a.limits.MaxStepsPerHeader, len(plan.steps))
		}
		if err := budget.addSteps(plan.steps, a.limits, DimensionHeader); err != nil {
			return err
		}
	}
	return nil
}

// collectHeaderGroups preflights then indexes exact source fields.
func (a Applier) collectHeaderGroups(headers rawmsg.HeaderBlock, usage *usageCounter) (map[string]headerGroup, []string, [][]byte, int, error) {
	if headers.Len() > a.limits.MaxHeaderFields {
		return nil, nil, nil, 0, applyLimitError(limitNameMaxHeaderFields, a.limits.MaxHeaderFields, headers.Len())
	}
	if headers.OriginalByteLen() > a.limits.MaxHeaderBytes {
		return nil, nil, nil, 0, applyLimitError(limitNameMaxHeaderBytes, a.limits.MaxHeaderBytes, headers.OriginalByteLen())
	}
	groups := make(map[string]headerGroup)
	names := make([]string, 0)
	sourceOrder := make([][]byte, 0, headers.Len())
	totalNameBytes := 0
	for _, field := range headers.Fields() {
		if err := usage.chargeItems(1); err != nil {
			return nil, nil, nil, 0, err
		}
		original := field.OriginalBytes()
		if len(original) > a.limits.MaxHeaderFieldBytes {
			return nil, nil, nil, 0, applyLimitError(limitNameMaxHeaderFieldBytes, a.limits.MaxHeaderFieldBytes, len(original))
		}
		if actual, tooLong := physicalHeaderLineLengthOver(original, a.limits.MaxHeaderLineBytes); tooLong {
			return nil, nil, nil, 0, applyLimitError(limitNameMaxHeaderLineBytes, a.limits.MaxHeaderLineBytes, actual)
		}
		name := field.NameLower()
		group, exists := groups[name]
		if !exists {
			if len(name) > a.limits.MaxHeaderNameBytes {
				return nil, nil, nil, 0, applyLimitError(limitNameMaxHeaderNameBytes, a.limits.MaxHeaderNameBytes, len(name))
			}
			if len(names) >= a.limits.MaxHeaderNames {
				return nil, nil, nil, 0, applyLimitError(limitNameMaxHeaderNames, a.limits.MaxHeaderNames, len(names)+1)
			}
			nextNameBytes, ok := checkedAdd(totalNameBytes, len(name))
			if !ok || nextNameBytes > a.limits.MaxTotalHeaderNameBytes {
				return nil, nil, nil, 0, applyLimitError(limitNameMaxTotalHeaderNameBytes, a.limits.MaxTotalHeaderNameBytes, nextNameBytes)
			}
			totalNameBytes = nextNameBytes
			names = append(names, name)
		}
		group.fields = append(group.fields, original)
		groups[name] = group
		sourceOrder = append(sourceOrder, original)
	}
	return groups, names, sourceOrder, totalNameBytes, nil
}

// appendHeaderPlan walks conceptual emissions in reverse physical order.
func (a Applier) appendHeaderPlan(output *headerOutput, group headerGroup, plan headerPlan, totalCopied *int) error {
	for stepIndex := len(plan.steps) - 1; stepIndex >= 0; stepIndex-- {
		instruction := plan.steps[stepIndex]
		if start, end, copyStep := instruction.copyRange(); copyStep {
			count := end - start + 1
			if end > len(group.fields) {
				return newError(ErrorCodeCopyRangeOutOfBounds, ErrorLocation{StepIndex: stepIndex}, ErrorDetails{Dimension: DimensionHeader, StepKind: StepKindCopy, Expected: len(group.fields), Actual: end}, nil)
			}
			if count > a.limits.MaxCopiedItemsPerRange {
				return applyLimitError(limitNameMaxCopiedItemsPerRange, a.limits.MaxCopiedItemsPerRange, count)
			}
			nextCopied, ok := checkedAdd(*totalCopied, count)
			if !ok || nextCopied > a.limits.MaxTotalCopiedItems {
				return applyLimitError(limitNameMaxTotalCopiedItems, a.limits.MaxTotalCopiedItems, nextCopied)
			}
			if err := output.usage.chargeItems(count); err != nil {
				return err
			}
			*totalCopied = nextCopied
			for occurrence := end; occurrence >= start; occurrence-- {
				if err := output.appendField(group.fields[len(group.fields)-occurrence]); err != nil {
					return err
				}
			}
			continue
		}
		for literalIndex := len(instruction.data) - 1; literalIndex >= 0; literalIndex-- {
			if err := output.appendData(plan.name, instruction.data[literalIndex]); err != nil {
				return err
			}
		}
	}
	return nil
}

// appendField validates and charges one existing field before cloning it.
func (o *headerOutput) appendField(field []byte) error {
	if err := o.reserveField(len(field), field); err != nil {
		return err
	}
	o.encoded = append(o.encoded, bytes.Clone(field))
	return nil
}

// appendData validates and charges one literal field before allocating it.
func (o *headerOutput) appendData(name string, literal []byte) error {
	nameAndColon, ok := checkedAdd(len(name), 1)
	if !ok {
		return applyLimitError(limitNameMaxHeaderLineBytes, o.applier.limits.MaxHeaderLineBytes, nameAndColon)
	}
	lineLength, ok := checkedAdd(nameAndColon, len(literal))
	if !ok || lineLength > o.applier.limits.MaxHeaderLineBytes {
		return applyLimitError(limitNameMaxHeaderLineBytes, o.applier.limits.MaxHeaderLineBytes, lineLength)
	}
	fieldLength, ok := checkedAdd(lineLength, 2)
	if !ok {
		return applyLimitError(limitNameMaxHeaderFieldBytes, o.applier.limits.MaxHeaderFieldBytes, fieldLength)
	}
	if err := o.reserveField(fieldLength, nil); err != nil {
		return err
	}
	field := make([]byte, 0, fieldLength)
	field = append(field, name...)
	field = append(field, ':')
	field = append(field, literal...)
	field = append(field, '\r', '\n')
	o.encoded = append(o.encoded, field)
	return nil
}

// reserveField validates and charges all output ceilings before allocation.
func (o *headerOutput) reserveField(length int, field []byte) error {
	nextFields, ok := checkedAdd(len(o.encoded), 1)
	if !ok || nextFields > o.applier.limits.MaxHeaderFields {
		return applyLimitError(limitNameMaxHeaderFields, o.applier.limits.MaxHeaderFields, nextFields)
	}
	if length > o.applier.limits.MaxHeaderFieldBytes {
		return applyLimitError(limitNameMaxHeaderFieldBytes, o.applier.limits.MaxHeaderFieldBytes, length)
	}
	if field != nil {
		if actual, tooLong := physicalHeaderLineLengthOver(field, o.applier.limits.MaxHeaderLineBytes); tooLong {
			return applyLimitError(limitNameMaxHeaderLineBytes, o.applier.limits.MaxHeaderLineBytes, actual)
		}
	}
	nextHeaderBytes, ok := checkedAdd(o.headerBytes, length)
	if !ok || nextHeaderBytes > o.applier.limits.MaxHeaderBytes {
		return applyLimitError(limitNameMaxHeaderBytes, o.applier.limits.MaxHeaderBytes, nextHeaderBytes)
	}
	if o.enforceState {
		stateBytes, err := o.stateBytes(nextHeaderBytes, nextFields)
		if err != nil || stateBytes > o.applier.limits.MaxStateBytes {
			return applyLimitError(limitNameMaxStateBytes, o.applier.limits.MaxStateBytes, stateBytes)
		}
	}
	if err := o.usage.chargeItems(1); err != nil {
		return err
	}
	if err := o.usage.chargeEmitted(length); err != nil {
		return err
	}
	o.headerBytes = nextHeaderBytes
	return nil
}

// stateBytes returns the effective materialized state size for an output prefix.
func (o *headerOutput) stateBytes(headerBytes, headerFields int) (int, error) {
	if o.current.availability != BodyAvailabilityKnown {
		return headerBytes, nil
	}
	base := o.current.body.Len()
	if o.current.framing == rawmsg.MessageFramingDelimited || o.current.framing == rawmsg.MessageFramingHeaderOnly && headerFields == 0 {
		var ok bool
		base, ok = checkedAdd(base, 2)
		if !ok {
			return base, invalidStateError()
		}
	}
	total, ok := checkedAdd(headerBytes, base)
	if !ok {
		return total, invalidStateError()
	}
	return total, nil
}

// finish validates empty-output framing and constructs one detached state.
func (o *headerOutput) finish() (State, error) {
	if o.enforceState {
		stateBytes, err := o.stateBytes(o.headerBytes, len(o.encoded))
		if err != nil || stateBytes > o.applier.limits.MaxStateBytes {
			return State{}, applyLimitError(limitNameMaxStateBytes, o.applier.limits.MaxStateBytes, stateBytes)
		}
	}
	headers, err := rawmsg.NewReconstructedHeaderBlock(o.encoded, o.applier.rawOptions)
	if err != nil {
		return State{}, mapRawApplicationError(err, DimensionHeader)
	}
	if o.current.availability == BodyAvailabilityUnavailable {
		state, stateErr := newUnavailableState(headers)
		return state, stateErr
	}
	framing := o.current.framing
	if framing == rawmsg.MessageFramingHeaderOnly && headers.Len() == 0 {
		framing = rawmsg.MessageFramingDelimited
	}
	state, stateErr := newKnownState(headers, o.current.body, framing)
	return state, stateErr
}

// sortHeaderNames insertion-sorts canonical names while charging each comparison.
func sortHeaderNames(names []string, usage *usageCounter) error {
	for index := 1; index < len(names); index++ {
		candidate := names[index]
		position := index
		for position > 0 {
			if err := usage.chargeWork(1); err != nil {
				return err
			}
			if names[position-1] <= candidate {
				break
			}
			names[position] = names[position-1]
			position--
		}
		names[position] = candidate
	}
	return nil
}

// physicalHeaderLineLengthOver returns the first over-limit physical line length.
func physicalHeaderLineLengthOver(field []byte, limit int) (int, bool) {
	for len(field) > 0 {
		end := bytes.Index(field, []byte("\r\n"))
		if end < 0 {
			return len(field), true
		}
		if end > limit {
			return end, true
		}
		field = field[end+2:]
	}
	return 0, false
}

// applyLimitError constructs one bounded header-application limit failure.
func applyLimitError(name string, limit, actual int) *Error {
	return applicationLimitError(DimensionHeader, name, limit, actual)
}

// applicationLimitError constructs one dimension-aware application limit failure.
func applicationLimitError(dimension Dimension, name string, limit, actual int) *Error {
	return newError(ErrorCodeLimitExceeded, ErrorLocation{}, ErrorDetails{Class: ErrorClassLimit, LimitName: name, Expected: limit, Actual: actual, Dimension: dimension}, nil)
}

// mapRawApplicationError converts raw failures without retaining their causes.
func mapRawApplicationError(err error, dimension Dimension) *Error {
	var parserErr *rawmsg.ParserError
	if errors.As(err, &parserErr) && parserErr.Code() == rawmsg.ErrorCodeLimitExceeded {
		actual, ok := checkedAdd(parserErr.Limit(), 1)
		if !ok {
			actual = parserErr.Limit()
		}
		return applicationLimitError(dimension, parserErr.LimitName(), parserErr.Limit(), actual)
	}
	return invalidStateError()
}
