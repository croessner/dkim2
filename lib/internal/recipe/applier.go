package recipe

import "github.com/croessner/dkim2/internal/rawmsg"

// Applier owns immutable recipe application limits and reconstruction policy.
type Applier struct {
	limits      Limits
	rawOptions  rawmsg.ParserOptions
	initialized bool
}

// NewApplier constructs one fail-closed recipe applier.
func NewApplier(limits Limits) (Applier, error) {
	resolved, err := limits.normalized()
	if err != nil {
		return Applier{}, err
	}
	options := rawmsg.DefaultParserOptions()
	options.MaxMessageBytes = resolved.MaxStateBytes
	options.MaxHeaderBytes = resolved.MaxHeaderBytes
	options.MaxHeaderFields = resolved.MaxHeaderFields
	options.MaxHeaderFieldBytes = resolved.MaxHeaderFieldBytes
	options.MaxHeaderLineBytes = resolved.MaxHeaderLineBytes
	options.MaxBodyLineBytes = resolved.MaxBodyLineBytes
	if err := options.Validate(); err != nil {
		return Applier{}, invalidOptionsError("")
	}
	return Applier{limits: resolved, rawOptions: options, initialized: true}, nil
}

// valid reports whether the applier owns coherent resolved limits.
func (a Applier) valid() bool {
	return a.initialized && a.limits.Validate() == nil && a.rawOptions.Validate() == nil
}

// Valid reports whether the applier owns coherent resolved limits.
func (a Applier) Valid() bool { return a.valid() }

// Apply transactionally reconstructs both recipe dimensions under one operation budget.
func (a Applier) Apply(current State, recipe Recipe) (State, Usage, error) {
	usage, err := newUsageCounter(a.limits)
	if err != nil {
		return State{}, Usage{}, err
	}
	if !a.valid() || !current.Valid() || !recipe.Valid() {
		return State{}, usage.usage(), invalidStateError()
	}
	if err := a.validateHeaderPlanBudgets(recipe); err != nil {
		return State{}, usage.usage(), err
	}
	if err := a.validateBodyPlanBudgets(recipe); err != nil {
		return State{}, usage.usage(), err
	}
	if current.availability == BodyAvailabilityUnavailable && recipeHasBodyCopy(recipe) {
		return State{}, usage.usage(), newError(ErrorCodeSourceUnavailable, ErrorLocation{}, ErrorDetails{Dimension: DimensionBody, StepKind: StepKindCopy}, nil)
	}
	sourcePrepared := false
	if current.availability == BodyAvailabilityKnown && recipe.bodyMode != BodyModeUnavailable {
		_, err := a.preflightKnownBodySource(current, recipe, usage)
		if err != nil {
			return State{}, usage.usage(), err
		}
		sourcePrepared = true
	}
	enforceHeaderState := recipe.bodyMode == BodyModeAbsent
	headerState, err := a.applyHeadersUsing(current, recipe, usage, enforceHeaderState)
	if err != nil {
		return State{}, usage.usage(), err
	}
	state, err := a.applyBodyUsing(headerState, recipe, usage, sourcePrepared)
	if err != nil {
		return State{}, usage.usage(), err
	}
	return state, usage.usage(), nil
}
