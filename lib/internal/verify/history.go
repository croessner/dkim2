package verify

import (
	"context"
	"crypto/subtle"
	"math"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/recipe"
)

const (
	historyLimitDecoded = "max_cumulative_decoded_bytes"
	historyLimitEmitted = "max_cumulative_emitted_bytes"
	historyLimitItems   = "max_cumulative_items"
	historyLimitWork    = "max_cumulative_work_units"
)

// HistoryCoverage identifies authenticated historical content coverage.
type HistoryCoverage string

const (
	// HistoryCoverageComplete reports matched content through m=1.
	HistoryCoverageComplete HistoryCoverage = "complete"
	// HistoryCoveragePartial reports bounded proof without every historical dimension.
	HistoryCoveragePartial HistoryCoverage = "partial"
	// HistoryCoverageUnreconstructable reports failure before one authenticated hop.
	HistoryCoverageUnreconstructable HistoryCoverage = "unreconstructable"
	// HistoryCoverageFailed reports a supported historical hash mismatch.
	HistoryCoverageFailed HistoryCoverage = "failed"
	// HistoryCoverageUnsupported reports an unsupported first historical hash tuple.
	HistoryCoverageUnsupported HistoryCoverage = "unsupported"
)

// Known reports whether coverage belongs to the closed history vocabulary.
func (c HistoryCoverage) Known() bool {
	return c == HistoryCoverageComplete || c == HistoryCoveragePartial || c == HistoryCoverageUnreconstructable || c == HistoryCoverageFailed || c == HistoryCoverageUnsupported
}

// HistoryStopReason identifies why authenticated descent stopped.
type HistoryStopReason string

const (
	// HistoryStopOriginReached reports descent through m=1.
	HistoryStopOriginReached HistoryStopReason = "origin_reached"
	// HistoryStopRecipeMissing reports absent required r=.
	HistoryStopRecipeMissing HistoryStopReason = "recipe_missing"
	// HistoryStopRecipeInvalid reports malformed authenticated recipe JSON.
	HistoryStopRecipeInvalid HistoryStopReason = "recipe_invalid"
	// HistoryStopApplicationInvalid reports invalid recipe application.
	HistoryStopApplicationInvalid HistoryStopReason = "application_invalid"
	// HistoryStopSourceUnavailable reports a copy from unavailable body state.
	HistoryStopSourceUnavailable HistoryStopReason = "source_unavailable"
	// HistoryStopLimitExceeded reports a cumulative or per-operation ceiling.
	HistoryStopLimitExceeded HistoryStopReason = "limit_exceeded"
	// HistoryStopHashMismatch reports a supported historical digest mismatch.
	HistoryStopHashMismatch HistoryStopReason = "hash_mismatch"
	// HistoryStopHashUnsupported reports an unknown-only historical hash tuple.
	HistoryStopHashUnsupported HistoryStopReason = "unsupported_hash"
	// HistoryStopHashMissing reports absence of a SHA-256 tuple.
	HistoryStopHashMissing HistoryStopReason = "hash_missing"
	// HistoryStopInternalContract reports an impossible internal state.
	HistoryStopInternalContract HistoryStopReason = "internal_contract"
)

// Known reports whether reason belongs to the closed stop vocabulary.
func (r HistoryStopReason) Known() bool {
	switch r {
	case HistoryStopOriginReached, HistoryStopRecipeMissing, HistoryStopRecipeInvalid,
		HistoryStopApplicationInvalid, HistoryStopSourceUnavailable, HistoryStopLimitExceeded,
		HistoryStopHashMismatch, HistoryStopHashUnsupported, HistoryStopHashMissing, HistoryStopInternalContract:
		return true
	default:
		return false
	}
}

// HistoryDimensionState identifies one historical content comparison.
type HistoryDimensionState string

const (
	// HistoryDimensionMatched reports equal supported digests.
	HistoryDimensionMatched HistoryDimensionState = "matched"
	// HistoryDimensionMismatch reports unequal supported digests.
	HistoryDimensionMismatch HistoryDimensionState = "mismatch"
	// HistoryDimensionUnavailable reports truthfully absent reconstructed body bytes.
	HistoryDimensionUnavailable HistoryDimensionState = "unavailable"
	// HistoryDimensionUnsupported reports an unknown-only expected hash algorithm.
	HistoryDimensionUnsupported HistoryDimensionState = "unsupported"
)

// Known reports whether state belongs to the closed dimension vocabulary.
func (s HistoryDimensionState) Known() bool {
	return s == HistoryDimensionMatched || s == HistoryDimensionMismatch || s == HistoryDimensionUnavailable || s == HistoryDimensionUnsupported
}

// HistoryRecipeMode identifies the fixed recipe transition mode.
type HistoryRecipeMode string

const (
	// HistoryRecipeModeApplied reports one parsed and applied r= transition.
	HistoryRecipeModeApplied HistoryRecipeMode = "applied"
)

// Known reports whether mode belongs to the closed recipe-mode vocabulary.
func (m HistoryRecipeMode) Known() bool { return m == HistoryRecipeModeApplied }

// HistoryLimits bounds one authenticated historical walk.
type HistoryLimits struct {
	// MaxTransitions bounds evaluated adjacent hops.
	MaxTransitions int
	// MaxCumulativeDecodedBytes bounds parsed recipe bytes.
	MaxCumulativeDecodedBytes int
	// MaxCumulativeEmittedBytes bounds reconstructed bytes.
	MaxCumulativeEmittedBytes int
	// MaxCumulativeItems bounds structural and output items.
	MaxCumulativeItems int
	// MaxCumulativeWorkUnits bounds aggregate recipe work.
	MaxCumulativeWorkUnits int
	// MaxRetainedTransitions bounds retained immutable transition details.
	MaxRetainedTransitions int
}

// DefaultHistoryLimits returns hard cumulative ceilings.
func DefaultHistoryLimits() HistoryLimits {
	return HistoryLimits{128, 6 << 20, 64 << 20, 524288, 16777216, 128}
}

// normalized fills zero defaults and rejects unsafe limits.
func (l HistoryLimits) normalized() (HistoryLimits, error) {
	defaults := DefaultHistoryLimits()
	values := []*int{&l.MaxTransitions, &l.MaxCumulativeDecodedBytes, &l.MaxCumulativeEmittedBytes, &l.MaxCumulativeItems, &l.MaxCumulativeWorkUnits, &l.MaxRetainedTransitions}
	hard := []int{defaults.MaxTransitions, defaults.MaxCumulativeDecodedBytes, defaults.MaxCumulativeEmittedBytes, defaults.MaxCumulativeItems, defaults.MaxCumulativeWorkUnits, defaults.MaxRetainedTransitions}
	for index, value := range values {
		if *value < 0 || *value > hard[index] {
			return HistoryLimits{}, historyError(ErrorCodeHistoryInvalidOptions)
		}
		if *value == 0 {
			*value = hard[index]
		}
	}
	if l.MaxRetainedTransitions > l.MaxTransitions {
		return HistoryLimits{}, historyError(ErrorCodeHistoryInvalidOptions)
	}
	return l, nil
}

// HistoryUsage stores cumulative recipe-owned operation usage.
type HistoryUsage struct {
	decoded, emitted, items, work int
	initialized                   bool
}

// Valid reports whether usage is initialized and nonnegative.
func (u HistoryUsage) Valid() bool {
	return u.initialized && u.decoded >= 0 && u.emitted >= 0 && u.items >= 0 && u.work >= 0
}

// DecodedBytes returns cumulative decoded recipe bytes.
func (u HistoryUsage) DecodedBytes() int { return u.decoded }

// EmittedBytes returns cumulative reconstructed bytes.
func (u HistoryUsage) EmittedBytes() int { return u.emitted }

// Items returns cumulative structural and output items.
func (u HistoryUsage) Items() int { return u.items }

// WorkUnits returns cumulative recipe operation work.
func (u HistoryUsage) WorkUnits() int { return u.work }

// addRecipe transactionally adds one parser or applier Usage.
func (u HistoryUsage) addRecipe(value recipe.Usage, limits HistoryLimits) (HistoryUsage, error) {
	if !u.Valid() || !value.Valid() {
		if u.Valid() {
			return u, historyError(ErrorCodeHistoryInternalContract)
		}
		return HistoryUsage{initialized: true}, historyError(ErrorCodeHistoryInternalContract)
	}
	decoded, ok := historyAdd(u.decoded, value.DecodedBytes())
	if !ok {
		decoded = math.MaxInt
	}
	emitted, emittedOK := historyAdd(u.emitted, value.EmittedBytes())
	if !emittedOK {
		emitted = math.MaxInt
	}
	items, itemsOK := historyAdd(u.items, value.Items())
	if !itemsOK {
		items = math.MaxInt
	}
	work, workOK := historyAdd(u.work, value.WorkUnits())
	if !workOK {
		work = math.MaxInt
	}
	next := HistoryUsage{decoded, emitted, items, work, true}
	if !ok || decoded > limits.MaxCumulativeDecodedBytes {
		return next, historyLimitError(historyLimitDecoded, limits.MaxCumulativeDecodedBytes, decoded)
	}
	if !emittedOK || emitted > limits.MaxCumulativeEmittedBytes {
		return next, historyLimitError(historyLimitEmitted, limits.MaxCumulativeEmittedBytes, emitted)
	}
	if !itemsOK || items > limits.MaxCumulativeItems {
		return next, historyLimitError(historyLimitItems, limits.MaxCumulativeItems, items)
	}
	if !workOK || work > limits.MaxCumulativeWorkUnits {
		return next, historyLimitError(historyLimitWork, limits.MaxCumulativeWorkUnits, work)
	}
	return next, nil
}

// HistoryTransition stores one immutable adjacent authenticated reconstruction.
type HistoryTransition struct {
	from, to     uint64
	mode         HistoryRecipeMode
	header, body HistoryDimensionState
	state        recipe.State
	initialized  bool
}

// Valid reports whether transition is adjacent and dimensionally coherent.
func (t HistoryTransition) Valid() bool {
	if !t.initialized || t.from <= 1 || t.to+1 != t.from || !t.mode.Known() || !t.header.Known() || !t.body.Known() || !t.state.Valid() {
		return false
	}
	if t.header == HistoryDimensionUnavailable || (t.body == HistoryDimensionUnavailable) != (t.state.BodyState() == recipe.BodyAvailabilityUnavailable) {
		return false
	}
	return t.body == HistoryDimensionUnavailable || (t.header == HistoryDimensionUnsupported) == (t.body == HistoryDimensionUnsupported)
}

// FromInstance returns the m= number owning the applied recipe.
func (t HistoryTransition) FromInstance() uint64 { return t.from }

// ToInstance returns the reconstructed adjacent m= number.
func (t HistoryTransition) ToInstance() uint64 { return t.to }

// RecipeMode returns the fixed applied transition mode.
func (t HistoryTransition) RecipeMode() HistoryRecipeMode { return t.mode }

// HeaderState returns historical header comparison state.
func (t HistoryTransition) HeaderState() HistoryDimensionState { return t.header }

// BodyState returns historical body comparison or availability state.
func (t HistoryTransition) BodyState() HistoryDimensionState { return t.body }

// ReconstructedState returns immutable reconstructed content when valid.
func (t HistoryTransition) ReconstructedState() (recipe.State, bool) { return t.state, t.Valid() }

// HistoryWalk stores one bounded authenticated content descent.
type HistoryWalk struct {
	coverage        HistoryCoverage
	stop            HistoryStopReason
	target, reached uint64
	transitions     []HistoryTransition
	usage           HistoryUsage
	terminalHeader  HistoryDimensionState
	terminalBody    HistoryDimensionState
	hadUnavailable  bool
	initialized     bool
}

// Valid reports whether retained facts and authoritative fold metadata agree.
func (w HistoryWalk) Valid() bool {
	if !w.initialized || !w.coverage.Known() || !w.stop.Known() || w.target == 0 || w.reached == 0 || w.reached > w.target || !w.usage.Valid() {
		return false
	}
	if !w.validTransitions() {
		return false
	}
	return w.validCoverage(w.target - w.reached)
}

// validTransitions verifies retained prefix and fold metadata coherence.
func (w HistoryWalk) validTransitions() bool {
	for index, transition := range w.transitions {
		if !transition.Valid() || index > 0 && w.transitions[index-1].to != transition.from {
			return false
		}
		if transition.header == HistoryDimensionUnavailable {
			return false
		}
		if transition.body == HistoryDimensionUnavailable && !w.hadUnavailable {
			return false
		}
		if index < len(w.transitions)-1 && (transition.header == HistoryDimensionMismatch || transition.body == HistoryDimensionMismatch || transition.header == HistoryDimensionUnsupported || transition.body == HistoryDimensionUnsupported) {
			return false
		}
		if (transition.header == HistoryDimensionMismatch || transition.body == HistoryDimensionMismatch) && w.coverage != HistoryCoverageFailed {
			return false
		}
		if transition.header == HistoryDimensionUnsupported || transition.body == HistoryDimensionUnsupported {
			if w.coverage != HistoryCoverageUnsupported && (w.coverage != HistoryCoveragePartial || w.stop != HistoryStopHashUnsupported) {
				return false
			}
		}
	}
	if len(w.transitions) > 0 {
		if w.transitions[0].from != w.target || w.transitions[len(w.transitions)-1].to < w.reached {
			return false
		}
	} else if w.reached != w.target && w.target != 1 {
		return false
	}
	return true
}

// validCoverage verifies the authoritative coverage and stop fold.
func (w HistoryWalk) validCoverage(evaluated uint64) bool {
	switch w.coverage {
	case HistoryCoverageComplete:
		if w.stop != HistoryStopOriginReached || w.reached != 1 || w.hadUnavailable || evaluated > 0 && (w.terminalHeader != HistoryDimensionMatched || w.terminalBody != HistoryDimensionMatched) {
			return false
		}
		for _, transition := range w.transitions {
			if transition.header != HistoryDimensionMatched || transition.body != HistoryDimensionMatched {
				return false
			}
		}
		return true
	case HistoryCoveragePartial:
		if evaluated == 0 {
			return false
		}
		if w.stop == HistoryStopOriginReached {
			return w.reached == 1 && w.hadUnavailable
		}
		if w.stop == HistoryStopHashUnsupported {
			return w.terminalHeader == HistoryDimensionUnsupported || w.terminalBody == HistoryDimensionUnsupported
		}
		return w.reached > 1 && sealedHistoryStop(w.stop)
	case HistoryCoverageUnreconstructable:
		return evaluated == 0 && sealedHistoryStop(w.stop)
	case HistoryCoverageFailed:
		return evaluated > 0 && w.stop == HistoryStopHashMismatch && (w.terminalHeader == HistoryDimensionMismatch || w.terminalBody == HistoryDimensionMismatch)
	case HistoryCoverageUnsupported:
		return evaluated == 1 && w.stop == HistoryStopHashUnsupported && (w.terminalHeader == HistoryDimensionUnsupported || w.terminalBody == HistoryDimensionUnsupported)
	default:
		return false
	}
}

// Coverage returns authoritative authenticated historical coverage.
func (w HistoryWalk) Coverage() HistoryCoverage { return w.coverage }

// StopReason returns the closed reason descent stopped.
func (w HistoryWalk) StopReason() HistoryStopReason { return w.stop }

// TargetInstance returns the current target m= number.
func (w HistoryWalk) TargetInstance() uint64 { return w.target }

// ReachedInstance returns the earliest evaluated m= number.
func (w HistoryWalk) ReachedInstance() uint64 { return w.reached }

// Transitions returns cloned retained transition facts.
func (w HistoryWalk) Transitions() []HistoryTransition {
	return append([]HistoryTransition(nil), w.transitions...)
}

// Usage returns cumulative recipe-owned accounting.
func (w HistoryWalk) Usage() HistoryUsage { return w.usage }

// clone returns a detached immutable walk.
func (w HistoryWalk) clone() HistoryWalk { w.transitions = w.Transitions(); return w }

// HistoryCoordinator owns parsing, application, canonicalization, and cumulative policy.
type HistoryCoordinator struct {
	parser        recipe.Parser
	applier       recipe.Applier
	canonicalizer canonical.Canonicalizer
	limits        HistoryLimits
	initialized   bool
}

// NewHistoryCoordinator constructs one bounded internal history coordinator.
func NewHistoryCoordinator(parser recipe.Parser, applier recipe.Applier, canonicalizer canonical.Canonicalizer, limits HistoryLimits) (HistoryCoordinator, error) {
	resolved, err := limits.normalized()
	if err != nil {
		return HistoryCoordinator{}, err
	}
	if !parser.Valid() || !applier.Valid() {
		return HistoryCoordinator{}, historyError(ErrorCodeHistoryInvalidOptions)
	}
	if canonicalizer.Options().Validate() != nil {
		return HistoryCoordinator{}, historyError(ErrorCodeHistoryInvalidOptions)
	}
	return HistoryCoordinator{parser, applier, canonicalizer, resolved, true}, nil
}

// ValidatePrevious compares reconstructed content against one adjacent previous instance.
func (c HistoryCoordinator) ValidatePrevious(state recipe.State, current, previous instance.MessageInstance) (HistoryTransition, error) {
	if !c.initialized || !state.Valid() {
		return HistoryTransition{}, historyError(ErrorCodeHistoryInvalidState)
	}
	if current.Number() <= 1 || previous.Number()+1 != current.Number() {
		return HistoryTransition{}, historyError(ErrorCodeHistoryInstanceNotAdjacent)
	}
	hashSet, selection := previous.SHA256HashSet()
	return c.validatePreviousSelection(state, current, previous, hashSet, selection)
}

// validatePreviousSelection owns future-compatible hash-selection result mapping.
func (c HistoryCoordinator) validatePreviousSelection(state recipe.State, current, previous instance.MessageInstance, hashSet instance.HashSet, selection instance.HashSelectionStatus) (HistoryTransition, error) {
	if selection == instance.HashSelectionStatusMissing {
		return HistoryTransition{}, historyError(ErrorCodeHistoryMissingSHA256)
	}
	bodyState := HistoryDimensionUnsupported
	if state.BodyState() == recipe.BodyAvailabilityUnavailable {
		bodyState = HistoryDimensionUnavailable
	}
	if selection == instance.HashSelectionStatusUnsupported {
		return HistoryTransition{current.Number(), previous.Number(), HistoryRecipeModeApplied, HistoryDimensionUnsupported, bodyState, state, true}, nil
	}
	headerResult, err := c.canonicalizer.HeaderHash(state.Headers())
	if err != nil {
		return HistoryTransition{}, historyError(ErrorCodeHistoryInternalContract)
	}
	headerDigest, ok := headerResult.Digest()
	if !ok {
		return HistoryTransition{}, historyError(ErrorCodeHistoryInternalContract)
	}
	expectedHeader, headerOK := hashSet.HeaderHash()
	expectedBody, bodyOK := hashSet.BodyHash()
	if !headerOK || !bodyOK {
		return HistoryTransition{}, historyError(ErrorCodeHistoryInternalContract)
	}
	headerState := historyDigestState(headerDigest.Bytes(), expectedHeader.Decoded())
	if body, known := state.Body(); known {
		bodyResult, hashErr := c.canonicalizer.BodyHash(body)
		if hashErr != nil {
			return HistoryTransition{}, historyError(ErrorCodeHistoryInternalContract)
		}
		bodyDigest, digestOK := bodyResult.Digest()
		if !digestOK {
			return HistoryTransition{}, historyError(ErrorCodeHistoryInternalContract)
		}
		bodyState = historyDigestState(bodyDigest.Bytes(), expectedBody.Decoded())
	}
	return HistoryTransition{current.Number(), previous.Number(), HistoryRecipeModeApplied, headerState, bodyState, state, true}, nil
}

// Walk reconstructs authenticated historical content after coherent current PASS.
func (c HistoryCoordinator) Walk(ctx context.Context, current Result, collection instance.Collection, initial recipe.State) (HistoryWalk, error) {
	if ctx == nil {
		return HistoryWalk{}, historyError(ErrorCodeHistoryInvalidState)
	}
	if err := ctx.Err(); err != nil {
		return HistoryWalk{}, err
	}
	if !c.initialized || !aggregateCurrentPass(current) || !collection.Valid() || !initial.Valid() || current.target.InstanceNumber != collection.HighestNumber() {
		return HistoryWalk{}, historyError(ErrorCodeHistoryInvalidState)
	}
	target := current.target.InstanceNumber
	usage := HistoryUsage{initialized: true}
	currentInstance, ok := collection.ByNumber(target)
	if !ok || !c.currentStateMatches(initial, currentInstance) {
		return HistoryWalk{}, historyError(ErrorCodeHistoryInvalidState)
	}
	if target == 1 {
		return newHistoryWalk(HistoryCoverageComplete, HistoryStopOriginReached, 1, 1, nil, usage), nil
	}
	state := initial
	transitions := make([]HistoryTransition, 0)
	var lastTransition HistoryTransition
	reached := target
	sawUnavailable := false
	for number := target; number > 1; number-- {
		if err := ctx.Err(); err != nil {
			return HistoryWalk{}, err
		}
		if target-number+1 > uint64(c.limits.MaxTransitions) {
			return sealedHistory(target, reached, transitions, usage, HistoryStopLimitExceeded, sawUnavailable), nil
		}
		currentInstance, currentOK := collection.ByNumber(number)
		previous, previousOK := collection.ByNumber(number - 1)
		if !currentOK || !previousOK {
			return sealedHistory(target, reached, transitions, usage, HistoryStopInternalContract, sawUnavailable), nil
		}
		encoded, hasRecipe := currentInstance.Recipe()
		if !hasRecipe {
			return sealedHistory(target, reached, transitions, usage, HistoryStopRecipeMissing, sawUnavailable), nil
		}
		plan, parseUsage, parseErr := c.parser.Parse(encoded.Decoded())
		var usageErr error
		usage, usageErr = usage.addRecipe(parseUsage, c.limits)
		if stop, stopped := historyParseStop(parseErr, usageErr); stopped {
			return sealedHistory(target, reached, transitions, usage, stop, sawUnavailable), nil
		}
		next, applyUsage, applyErr := c.applier.Apply(state, plan)
		usage, usageErr = usage.addRecipe(applyUsage, c.limits)
		if stop, stopped := historyApplyStop(applyErr, usageErr); stopped {
			return sealedHistory(target, reached, transitions, usage, stop, sawUnavailable), nil
		}
		transition, transitionErr := c.ValidatePrevious(next, currentInstance, previous)
		if transitionErr != nil {
			stop := historyTransitionStop(transitionErr)
			return sealedHistory(target, reached, transitions, usage, stop, sawUnavailable), nil
		}
		if len(transitions) < c.limits.MaxRetainedTransitions {
			transitions = append(transitions, transition)
		}
		lastTransition = transition
		reached = number - 1
		if transition.body == HistoryDimensionUnavailable {
			sawUnavailable = true
		}
		if transition.header == HistoryDimensionMismatch || transition.body == HistoryDimensionMismatch {
			return newHistoryWalk(HistoryCoverageFailed, HistoryStopHashMismatch, target, reached, transitions, usage).withTerminal(transition).withUnavailable(sawUnavailable), nil
		}
		if transition.header == HistoryDimensionUnsupported || transition.body == HistoryDimensionUnsupported {
			coverage := HistoryCoverageUnsupported
			if target-reached > 1 {
				coverage = HistoryCoveragePartial
			}
			return newHistoryWalk(coverage, HistoryStopHashUnsupported, target, reached, transitions, usage).withTerminal(transition).withUnavailable(sawUnavailable), nil
		}
		state = next
	}
	coverage := HistoryCoverageComplete
	if sawUnavailable {
		coverage = HistoryCoveragePartial
	}
	return newHistoryWalk(coverage, HistoryStopOriginReached, target, reached, transitions, usage).withTerminal(lastTransition).withUnavailable(sawUnavailable), nil
}

// currentStateMatches binds direct Walk input to the already passing current tuple.
func (c HistoryCoordinator) currentStateMatches(state recipe.State, current instance.MessageInstance) bool {
	if state.BodyState() != recipe.BodyAvailabilityKnown {
		return false
	}
	hashSet, selection := current.SHA256HashSet()
	if selection != instance.HashSelectionStatusSelected {
		return false
	}
	headerExpected, headerOK := hashSet.HeaderHash()
	bodyExpected, bodyOK := hashSet.BodyHash()
	body, known := state.Body()
	if !headerOK || !bodyOK || !known {
		return false
	}
	headerResult, headerErr := c.canonicalizer.HeaderHash(state.Headers())
	bodyResult, bodyErr := c.canonicalizer.BodyHash(body)
	if headerErr != nil || bodyErr != nil {
		return false
	}
	headerDigest, headerDigestOK := headerResult.Digest()
	bodyDigest, bodyDigestOK := bodyResult.Digest()
	return headerDigestOK && bodyDigestOK &&
		historyDigestState(headerDigest.Bytes(), headerExpected.Decoded()) == HistoryDimensionMatched &&
		historyDigestState(bodyDigest.Bytes(), bodyExpected.Decoded()) == HistoryDimensionMatched
}

// historyParseStop maps parser and cumulative failures to one closed stop.
func historyParseStop(parseErr, usageErr error) (HistoryStopReason, bool) {
	if usageErr != nil {
		if IsErrorCode(usageErr, ErrorCodeHistoryLimitExceeded) {
			return HistoryStopLimitExceeded, true
		}
		return HistoryStopInternalContract, true
	}
	if recipe.IsErrorCode(parseErr, recipe.ErrorCodeLimitExceeded) {
		return HistoryStopLimitExceeded, true
	}
	return HistoryStopRecipeInvalid, parseErr != nil
}

// historyApplyStop maps application and cumulative failures to one closed stop.
func historyApplyStop(applyErr, usageErr error) (HistoryStopReason, bool) {
	if usageErr != nil {
		if IsErrorCode(usageErr, ErrorCodeHistoryLimitExceeded) {
			return HistoryStopLimitExceeded, true
		}
		return HistoryStopInternalContract, true
	}
	if recipe.IsErrorCode(applyErr, recipe.ErrorCodeLimitExceeded) {
		return HistoryStopLimitExceeded, true
	}
	if recipe.IsErrorCode(applyErr, recipe.ErrorCodeSourceUnavailable) {
		return HistoryStopSourceUnavailable, true
	}
	return HistoryStopApplicationInvalid, applyErr != nil
}

// historyTransitionStop maps usage-free comparison errors to one closed stop.
func historyTransitionStop(err error) HistoryStopReason {
	if IsErrorCode(err, ErrorCodeHistoryMissingSHA256) {
		return HistoryStopHashMissing
	}
	return HistoryStopInternalContract
}

// aggregateCurrentPass validates coherent target-bound current PASS evidence.
func aggregateCurrentPass(result Result) bool {
	if result.status != TargetStatusPass || result.target.Sequence == 0 || result.target.InstanceNumber == 0 {
		return false
	}
	headerCount, bodyCount := 0, 0
	signatureChecks := make(map[Algorithm]int)
	signatureSets := make(map[Algorithm]int)
	for _, check := range result.checks {
		if check.Target != result.target {
			return false
		}
		switch check.Kind {
		case CheckKindHeaderHash:
			headerCount++
			if check.Status != CheckStatusPass || check.HashStatus != HashStatusPass {
				return false
			}
		case CheckKindBodyHash:
			bodyCount++
			if check.Status != CheckStatusPass || check.HashStatus != HashStatusPass {
				return false
			}
		case CheckKindSignature:
			if check.Status == CheckStatusPass {
				if !knownAlgorithm(check.Algorithm) {
					return false
				}
				signatureChecks[check.Algorithm]++
			} else {
				return false
			}
		default:
			if !validCheckKind(check.Kind) || check.Status != CheckStatusPass && check.Status != CheckStatusNotApplicable {
				return false
			}
		}
	}
	for _, set := range result.signatureSets {
		switch set.Status {
		case SignatureSetStatusPass:
			if !knownAlgorithm(set.Algorithm) || set.KeyStatus != KeyStatusFound {
				return false
			}
			signatureSets[set.Algorithm]++
		default:
			return false
		}
	}
	if headerCount != 1 || bodyCount != 1 || len(signatureChecks) == 0 || len(signatureChecks) != len(signatureSets) {
		return false
	}
	for algorithm, count := range signatureChecks {
		if count <= 0 || signatureSets[algorithm] != count {
			return false
		}
	}
	return true
}

// sealedHistoryStop reports whether stop belongs to a non-result failure lane.
func sealedHistoryStop(stop HistoryStopReason) bool {
	switch stop {
	case HistoryStopRecipeMissing, HistoryStopRecipeInvalid, HistoryStopApplicationInvalid,
		HistoryStopSourceUnavailable, HistoryStopLimitExceeded, HistoryStopHashMissing, HistoryStopInternalContract:
		return true
	default:
		return false
	}
}

// sealedHistory folds one authenticated non-result failure into an initialized walk.
func sealedHistory(target, reached uint64, transitions []HistoryTransition, usage HistoryUsage, stop HistoryStopReason, sawUnavailable bool) HistoryWalk {
	coverage := HistoryCoverageUnreconstructable
	if len(transitions) > 0 {
		coverage = HistoryCoveragePartial
	}
	return newHistoryWalk(coverage, stop, target, reached, transitions, usage).withUnavailable(sawUnavailable)
}

// newHistoryWalk constructs one immutable internal walk candidate.
func newHistoryWalk(coverage HistoryCoverage, stop HistoryStopReason, target, reached uint64, transitions []HistoryTransition, usage HistoryUsage) HistoryWalk {
	return HistoryWalk{coverage: coverage, stop: stop, target: target, reached: reached, transitions: append([]HistoryTransition(nil), transitions...), usage: usage, initialized: true}
}

// withTerminal records the last evaluated transition even when retention is narrowed.
func (w HistoryWalk) withTerminal(transition HistoryTransition) HistoryWalk {
	if transition.Valid() {
		w.terminalHeader = transition.header
		w.terminalBody = transition.body
	}
	return w
}

// withUnavailable records whether any evaluated hop lost body availability.
func (w HistoryWalk) withUnavailable(value bool) HistoryWalk {
	w.hadUnavailable = value
	return w
}

// newInternalContractHistoryWalk seals an impossible post-PASS integration failure.
func newInternalContractHistoryWalk(target uint64) HistoryWalk {
	return newHistoryWalk(HistoryCoverageUnreconstructable, HistoryStopInternalContract, target, target, nil, HistoryUsage{initialized: true})
}

// historyDigestState compares fixed-size SHA-256 values in constant time.
func historyDigestState(actual, expected []byte) HistoryDimensionState {
	if len(actual) == 32 && len(expected) == 32 && subtle.ConstantTimeCompare(actual, expected) == 1 {
		return HistoryDimensionMatched
	}
	return HistoryDimensionMismatch
}

// historyAdd adds nonnegative cumulative counters without overflow.
func historyAdd(left, right int) (int, bool) {
	if left < 0 || right < 0 || left > math.MaxInt-right {
		return math.MaxInt, false
	}
	return left + right, true
}

// historyError constructs one bounded direct history contract error.
func historyError(code ErrorCode) *Error {
	return newError(code, ErrorLocation{}, ErrorDetails{}, nil)
}

// historyLimitError constructs one stable cumulative ceiling diagnostic.
func historyLimitError(name string, limit, actual int) *Error {
	return newError(ErrorCodeHistoryLimitExceeded, ErrorLocation{}, ErrorDetails{LimitName: name, Limit: limit, Count: actual}, nil)
}
