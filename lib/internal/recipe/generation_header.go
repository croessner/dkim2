package recipe

import (
	"bytes"
	"math/bits"
	"strings"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// headerPlanningResult stores an immutable package-internal header planning outcome.
type headerPlanningResult struct {
	plans           []headerPlan
	classifications []headerClassification
	classified      bool
	initialized     bool
}

// Valid reports whether the result contains sorted unique lowercase plans.
func (r headerPlanningResult) Valid() bool {
	if !r.initialized {
		return false
	}
	previous := ""
	for _, plan := range r.plans {
		if !plan.valid() || plan.name != plan.canonicalName || previous != "" && plan.canonicalName <= previous {
			return false
		}
		previous = plan.canonicalName
	}
	return true
}

// Changed reports whether relevant header reconstruction needs at least one plan.
func (r headerPlanningResult) Changed() bool { return r.Valid() && len(r.plans) > 0 }

// headerPlans returns detached sorted plans for later package-internal proof stages.
func (r headerPlanningResult) headerPlans() []headerPlan {
	if !r.Valid() {
		return nil
	}
	plans := make([]headerPlan, len(r.plans))
	for index, plan := range r.plans {
		plans[index] = plan.clone()
	}
	return plans
}

// newHeaderPlanningResult constructs one immutable validated result.
func newHeaderPlanningResult(plans []headerPlan) (headerPlanningResult, error) {
	result := headerPlanningResult{plans: plans, initialized: true}
	if !result.Valid() {
		return headerPlanningResult{}, generationInvariantError()
	}
	return result, nil
}

// newClassifiedHeaderPlanningResult retains the exact sorted planning relevance decisions for self-proof.
func newClassifiedHeaderPlanningResult(plans []headerPlan, classifications []headerClassification) (headerPlanningResult, error) {
	result, err := newHeaderPlanningResult(plans)
	if err != nil {
		return headerPlanningResult{}, err
	}
	result.classifications = classifications
	result.classified = true
	return result, nil
}

// generationHeaderGroup stores exact unfolded values in bottom-up occurrence order.
type generationHeaderGroup struct {
	values [][]byte
}

// headerClassification stores the planning-phase relevance decision for final proof.
type headerClassification struct {
	name     string
	relevant bool
}

// planHeaders deterministically plans only inverse header reconstruction.
func (g Generator) planHeaders(request GenerationRequest, budget *generationPlanBudget) (headerPlanningResult, error) {
	fail := func(err error) (headerPlanningResult, error) { return headerPlanningResult{}, err }
	if err := g.validateRequest(request); err != nil {
		return fail(err)
	}
	if budget == nil || budget.counter == nil || budget.limits != g.limits.RecipeLimits || budget.counter.limits != g.limits {
		return fail(generationInvariantError())
	}
	counter := budget.counter
	previous, current := request.Previous(), request.Current()
	inputBytes, ok := checkedAdd(previous.headers.OriginalByteLen(), current.headers.OriginalByteLen())
	if !ok {
		return fail(generationLimitError(limitNameMaxInputBytes, g.limits.MaxInputBytes, inputBytes, DimensionHeader))
	}
	inputItems, ok := checkedAdd(previous.headers.Len(), current.headers.Len())
	if !ok {
		return fail(generationLimitError(limitNameMaxInputItems, g.limits.MaxInputItems, inputItems, DimensionHeader))
	}
	if err := counter.chargeInput(inputBytes, inputItems, DimensionHeader); err != nil {
		return fail(err)
	}
	if err := validateHeaderGenerationState(previous, g.limits.RecipeLimits, counter); err != nil {
		return fail(err)
	}
	if err := validateHeaderGenerationState(current, g.limits.RecipeLimits, counter); err != nil {
		return fail(err)
	}

	var nameSet map[string]struct{}
	nameBytes := 0
	previousGroups, err := collectHeaderGroups(previous.headers, &nameSet, &nameBytes, g.limits.RecipeLimits, counter)
	if err != nil {
		return fail(err)
	}
	currentGroups, err := collectHeaderGroups(current.headers, &nameSet, &nameBytes, g.limits.RecipeLimits, counter)
	if err != nil {
		return fail(err)
	}
	names, err := sortedHeaderNames(nameSet, counter)
	if err != nil {
		return fail(err)
	}

	planningStorage, ok := checkedSum(len(names), len(names), 2)
	if !ok {
		return fail(headerGenerationLimitError(limitNameMaxGenerationWorkUnits, counter.limits.MaxGenerationWorkUnits, planningStorage))
	}
	if err := counter.chargeWork(planningStorage, DimensionHeader); err != nil {
		return fail(err)
	}
	plans, classifications, err := g.planNamedHeaderGroups(names, previousGroups, currentGroups, request.LiteralPolicy(), budget)
	if err != nil {
		return fail(err)
	}
	if err := g.recheckHeaderClassifications(classifications, counter); err != nil {
		return fail(err)
	}
	if err := chargeHeaderPlanPass(plans, counter); err != nil {
		return fail(err)
	}
	result, err := newClassifiedHeaderPlanningResult(plans, classifications)
	if err != nil {
		return fail(err)
	}
	return result, nil
}

// planNamedHeaderGroups classifies sorted names and plans each relevant changed group.
func (g Generator) planNamedHeaderGroups(names []string, previousGroups, currentGroups map[string]generationHeaderGroup, policy LiteralDisclosurePolicy, budget *generationPlanBudget) ([]headerPlan, []headerClassification, error) {
	counter := budget.counter
	classifications := make([]headerClassification, 0, len(names))
	plans := make([]headerPlan, 0, len(names))
	for _, name := range names {
		planningNameWork, ok := checkedNameScanWork(len(name), 6, 2)
		if !ok {
			return nil, nil, headerGenerationLimitError(limitNameMaxGenerationWorkUnits, counter.limits.MaxGenerationWorkUnits, planningNameWork)
		}
		if err := counter.chargeWork(planningNameWork, DimensionHeader); err != nil {
			return nil, nil, err
		}
		relevant, classifyErr := g.classifyHeaderOnce(name)
		if classifyErr != nil {
			return nil, nil, classifyErr
		}
		classifications = append(classifications, headerClassification{name: name, relevant: relevant})
		equal, compareErr := equalHeaderValues(previousGroups[name].values, currentGroups[name].values, counter)
		if compareErr != nil {
			return nil, nil, compareErr
		}
		if !relevant || equal {
			continue
		}
		plan, planErr := budget.planHeaderGroup(name, previousGroups[name].values, currentGroups[name].values, policy)
		if planErr != nil {
			return nil, nil, planErr
		}
		if err := counter.chargeWork(1, DimensionHeader); err != nil {
			return nil, nil, err
		}
		plans = append(plans, plan)
	}
	return plans, classifications, nil
}

// recheckHeaderClassifications proves every sorted name retained its planning decision.
func (g Generator) recheckHeaderClassifications(classifications []headerClassification, counter *generationCounter) error {
	for _, classification := range classifications {
		finalNameWork, ok := checkedNameScanWork(len(classification.name), 2, 1)
		if !ok {
			return headerGenerationLimitError(limitNameMaxGenerationWorkUnits, counter.limits.MaxGenerationWorkUnits, finalNameWork)
		}
		if err := counter.chargeWork(finalNameWork, DimensionHeader); err != nil {
			return err
		}
		relevant, classifyErr := g.classifyHeaderOnce(classification.name)
		if classifyErr != nil || relevant != classification.relevant {
			return headerRelevanceInvariantError()
		}
	}
	return nil
}

// classifyHeaderOnce invokes the validated relevance dependency once for one operation phase.
func (g Generator) classifyHeaderOnce(nameLower string) (bool, error) {
	canonicalName, ok := rawmsg.CanonicalHeaderName(nameLower)
	if !g.Valid() || !ok || canonicalName != nameLower {
		return false, headerRelevanceInvariantError()
	}
	relevant, err := g.relevance.IsRelevantHeader(nameLower)
	if err != nil {
		return false, headerRelevanceInvariantError()
	}
	return relevant, nil
}

// validateHeaderGenerationState enforces inherited state and raw-header limits before indexing.
func validateHeaderGenerationState(state State, limits Limits, counter *generationCounter) error {
	if !knownGenerationState(state) {
		return newError(ErrorCodeInvalidState, ErrorLocation{}, ErrorDetails{Class: ErrorClassState}, nil)
	}
	stateBytes, ok := checkedAdd(state.headers.OriginalByteLen(), state.body.Len())
	if state.framing == rawmsg.MessageFramingDelimited {
		stateBytes, ok = checkedAdd(stateBytes, 2)
	}
	if !ok || stateBytes > limits.MaxStateBytes {
		return generationLimitError(limitNameMaxStateBytes, limits.MaxStateBytes, stateBytes, DimensionHeader)
	}
	if state.headers.Len() > limits.MaxHeaderFields {
		return generationLimitError(limitNameMaxHeaderFields, limits.MaxHeaderFields, state.headers.Len(), DimensionHeader)
	}
	if state.headers.OriginalByteLen() > limits.MaxHeaderBytes {
		return generationLimitError(limitNameMaxHeaderBytes, limits.MaxHeaderBytes, state.headers.OriginalByteLen(), DimensionHeader)
	}
	return state.headers.VisitFieldsReverse(func(field rawmsg.HeaderFieldView) error {
		originalBytes := field.OriginalByteLen()
		if err := counter.chargeWork(originalBytes+1, DimensionHeader); err != nil {
			return err
		}
		if originalBytes > limits.MaxHeaderFieldBytes {
			return generationLimitError(limitNameMaxHeaderFieldBytes, limits.MaxHeaderFieldBytes, originalBytes, DimensionHeader)
		}
		if actual := field.MaximumPhysicalLineBytes(); actual > limits.MaxHeaderLineBytes {
			return generationLimitError(limitNameMaxHeaderLineBytes, limits.MaxHeaderLineBytes, actual, DimensionHeader)
		}
		return nil
	})
}

// collectHeaderGroups builds bounded exact bottom-up sequences and one shared distinct-name set.
func collectHeaderGroups(headers rawmsg.HeaderBlock, names *map[string]struct{}, totalNameBytes *int, limits Limits, counter *generationCounter) (map[string]generationHeaderGroup, error) {
	var groups map[string]generationHeaderGroup
	err := headers.VisitFieldsReverse(func(field rawmsg.HeaderFieldView) error {
		name := field.NameLower()
		valueBytes := field.UnfoldedValueLen()
		nameWork, ok := checkedNameScanWork(len(name), 4, 0)
		if !ok {
			return headerGenerationLimitError(limitNameMaxGenerationWorkUnits, counter.limits.MaxGenerationWorkUnits, nameWork)
		}
		collectionWork, ok := checkedSum(nameWork, valueBytes, 6)
		if !ok {
			return headerGenerationLimitError(limitNameMaxGenerationWorkUnits, counter.limits.MaxGenerationWorkUnits, collectionWork)
		}
		if err := counter.chargeWork(collectionWork, DimensionHeader); err != nil {
			return err
		}
		if _, exists := (*names)[name]; !exists {
			if len(*names)+1 > limits.MaxHeaderNames {
				return headerGenerationLimitError(limitNameMaxHeaderNames, limits.MaxHeaderNames, len(*names)+1)
			}
			if len(name) > limits.MaxHeaderNameBytes {
				return headerGenerationLimitError(limitNameMaxHeaderNameBytes, limits.MaxHeaderNameBytes, len(name))
			}
			nextNameBytes, added := checkedAdd(*totalNameBytes, len(name))
			if !added || nextNameBytes > limits.MaxTotalHeaderNameBytes {
				return headerGenerationLimitError(limitNameMaxTotalHeaderNameBytes, limits.MaxTotalHeaderNameBytes, nextNameBytes)
			}
			*totalNameBytes = nextNameBytes
			if *names == nil {
				*names = make(map[string]struct{})
			}
			(*names)[name] = struct{}{}
		}
		if groups == nil {
			groups = make(map[string]generationHeaderGroup)
		}
		value := field.UnfoldedValueCopy()
		group := groups[name]
		group.values = append(group.values, value)
		groups[name] = group
		return nil
	})
	if err != nil {
		return nil, err
	}
	return groups, nil
}

// checkedNameScanWork bounds repeated complete string hashing and validation scans.
func checkedNameScanWork(nameBytes, scans, overhead int) (int, bool) {
	work, ok := checkedMultiply(nameBytes, scans)
	if !ok {
		return work, false
	}
	return checkedAdd(work, overhead)
}

// sortedHeaderNames precharges a deterministic comparison bound before sorting retained names.
func sortedHeaderNames(union map[string]struct{}, counter *generationCounter) ([]string, error) {
	if err := counter.chargeWork(len(union)+1, DimensionHeader); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(union))
	maxNameBytes := 0
	for name := range union {
		names = append(names, name)
		if len(name) > maxNameBytes {
			maxNameBytes = len(name)
		}
	}
	if err := sortGeneratedHeaderNames(names, maxNameBytes, counter); err != nil {
		return nil, err
	}
	return names, nil
}

// sortGeneratedHeaderNames precharges a merge-sort upper bound including byte comparisons and moves.
func sortGeneratedHeaderNames(names []string, maxNameBytes int, counter *generationCounter) error {
	if len(names) < 2 {
		return nil
	}
	passes := bits.Len(uint(len(names) - 1))
	byteAwareFactor, ok := checkedAdd(maxNameBytes, 3)
	if !ok {
		return headerGenerationLimitError(limitNameMaxGenerationWorkUnits, counter.limits.MaxGenerationWorkUnits, byteAwareFactor)
	}
	sortWork, ok := checkedMultiply(len(names), passes)
	if ok {
		sortWork, ok = checkedMultiply(sortWork, byteAwareFactor)
	}
	if ok {
		sortWork, ok = checkedAdd(sortWork, len(names))
	}
	if !ok {
		return headerGenerationLimitError(limitNameMaxGenerationWorkUnits, counter.limits.MaxGenerationWorkUnits, sortWork)
	}
	if err := counter.chargeWork(sortWork, DimensionHeader); err != nil {
		return err
	}
	scratch := make([]string, len(names))
	source, target := names, scratch
	for width := 1; width < len(names); width *= 2 {
		for start := 0; start < len(names); start += 2 * width {
			middle := min(start+width, len(names))
			end := min(start+2*width, len(names))
			left, right := start, middle
			for output := start; output < end; output++ {
				if left < middle && (right >= end || strings.Compare(source[left], source[right]) <= 0) {
					target[output] = source[left]
					left++
				} else {
					target[output] = source[right]
					right++
				}
			}
		}
		source, target = target, source
	}
	if &source[0] != &names[0] {
		copy(names, source)
	}
	return nil
}

// equalHeaderValues compares exact unfolded sequences in bottom-up order.
func equalHeaderValues(left, right [][]byte, counter *generationCounter) (bool, error) {
	if err := counter.chargeWork(1, DimensionHeader); err != nil {
		return false, err
	}
	if len(left) != len(right) {
		return false, nil
	}
	for index := range left {
		if err := counter.chargeWork(len(left[index])+1, DimensionHeader); err != nil {
			return false, err
		}
		if !bytes.Equal(left[index], right[index]) {
			return false, nil
		}
	}
	return true, nil
}

// chargeHeaderPlanPass accounts for final validation before ownership transfer.
func chargeHeaderPlanPass(plans []headerPlan, counter *generationCounter) error {
	for _, plan := range plans {
		if err := counter.chargeWork(len(plan.name)+1, DimensionHeader); err != nil {
			return err
		}
		for _, instruction := range plan.steps {
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
					return headerGenerationLimitError(limitNameMaxGenerationWorkUnits, counter.limits.MaxGenerationWorkUnits, work)
				}
			}
			if err := counter.chargeWork(work, DimensionHeader); err != nil {
				return err
			}
		}
	}
	return nil
}

// planHeaderGroup applies earliest monotone exact matching for one relevant changed name.
func (b *generationPlanBudget) planHeaderGroup(name string, target, source [][]byte, policy LiteralDisclosurePolicy) (headerPlan, error) {
	if len(target) == 0 {
		return b.newOwnedHeaderPlan(name, nil)
	}
	projectedCandidates, ok := checkedAdd(b.counter.candidates, len(source))
	if !ok || projectedCandidates > b.counter.limits.MaxCandidateEntries {
		return headerPlan{}, headerGenerationLimitError(limitNameMaxCandidateEntries, b.counter.limits.MaxCandidateEntries, projectedCandidates)
	}
	if err := b.counter.chargeWork(1, DimensionHeader); err != nil {
		return headerPlan{}, err
	}
	candidates := newExactCandidateIndex()
	for index, value := range source {
		if err := candidates.add(value, index+1, b.counter, DimensionHeader); err != nil {
			return headerPlan{}, err
		}
	}

	var steps []step
	lastCopyEnd := 0
	for _, value := range target {
		candidate, err := candidates.lookup(value, b.counter, DimensionHeader)
		if err != nil {
			return headerPlan{}, err
		}
		selected := 0
		for candidate != nil && candidate.cursor < len(candidate.positions) {
			if err := b.counter.chargeComparison(DimensionHeader); err != nil {
				return headerPlan{}, err
			}
			occurrence := candidate.positions[candidate.cursor]
			candidate.cursor++
			if occurrence > lastCopyEnd {
				selected = occurrence
				break
			}
		}
		if selected != 0 {
			if err := b.appendHeaderCopy(&steps, selected); err != nil {
				return headerPlan{}, err
			}
			lastCopyEnd = selected
			continue
		}
		if policy == CopyOnly {
			return headerPlan{}, headerUnrepresentableError()
		}
		if err := b.appendHeaderLiteral(&steps, name, value); err != nil {
			return headerPlan{}, err
		}
	}
	return b.newOwnedHeaderPlan(name, steps)
}

// newOwnedHeaderPlan validates operation-local storage before transferring its ownership.
func (b *generationPlanBudget) newOwnedHeaderPlan(name string, steps []step) (headerPlan, error) {
	candidate := headerPlan{name: name, canonicalName: name, steps: steps, initialized: true}
	if err := chargeHeaderPlanPass([]headerPlan{candidate}, b.counter); err != nil {
		return headerPlan{}, err
	}
	if !candidate.valid() {
		return headerPlan{}, generationInvariantError()
	}
	return candidate, nil
}

// appendHeaderCopy adds one header occurrence through the shared copy planner.
func (b *generationPlanBudget) appendHeaderCopy(steps *[]step, occurrence int) error {
	return b.appendCopy(steps, occurrence, DimensionHeader, b.limits.MaxStepsPerHeader, limitNameMaxStepsPerHeader)
}

// appendHeaderLiteral validates one reconstructed field before shared literal planning.
func (b *generationPlanBudget) appendHeaderLiteral(steps *[]step, name string, value []byte) error {
	if len(name)+1+len(value) > b.limits.MaxHeaderLineBytes || len(name)+1+len(value)+2 > b.limits.MaxHeaderFieldBytes {
		return headerUnrepresentableError()
	}
	return b.appendDataLiteral(steps, value, DimensionHeader, b.limits.MaxStepsPerHeader, limitNameMaxStepsPerHeader)
}

// headerUnrepresentableError returns a secret-safe closed representation failure.
func headerUnrepresentableError() *Error {
	return newError(ErrorCodeHeaderUnrepresentable, ErrorLocation{}, ErrorDetails{
		Class: ErrorClassRepresentation, Dimension: DimensionHeader,
	}, nil)
}

// headerRelevanceInvariantError returns a secret-safe dependency invariant failure.
func headerRelevanceInvariantError() *Error {
	return newError(ErrorCodeHeaderRelevance, ErrorLocation{}, ErrorDetails{
		Class: ErrorClassInvariant, Dimension: DimensionHeader,
	}, nil)
}

// generationInvariantError returns a secret-safe internal planning invariant failure.
func generationInvariantError() *Error {
	return generationInvariantErrorForDimension(DimensionHeader)
}

// headerGenerationLimitError constructs one header-dimension bounded failure.
func headerGenerationLimitError(name string, limit, actual int) *Error {
	return generationLimitError(name, limit, actual, DimensionHeader)
}
