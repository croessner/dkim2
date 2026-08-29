package recipe

import (
	"bytes"
	"slices"
	"unicode/utf8"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// StepKind identifies one closed recipe operation.
type StepKind string

const (
	// StepKindCopy identifies an inclusive source-range copy.
	StepKindCopy StepKind = "copy"
	// StepKindData identifies literal data emission.
	StepKindData StepKind = "data"
)

// Known reports whether kind belongs to the Draft-06 recipe vocabulary.
func (k StepKind) Known() bool { return k == StepKindCopy || k == StepKindData }

// BodyMode identifies the body member form in one parsed recipe.
type BodyMode string

const (
	// BodyModeAbsent preserves the source body state.
	BodyModeAbsent BodyMode = "absent"
	// BodyModeSteps applies an ordered body recipe.
	BodyModeSteps BodyMode = "steps"
	// BodyModeUnavailable declares that prior body bytes cannot be reconstructed.
	BodyModeUnavailable BodyMode = "unavailable"
)

// Known reports whether mode belongs to the closed recipe vocabulary.
func (m BodyMode) Known() bool {
	return m == BodyModeAbsent || m == BodyModeSteps || m == BodyModeUnavailable
}

// BodyAvailability identifies whether reconstructed body bytes exist.
type BodyAvailability string

const (
	// BodyAvailabilityKnown reports validated body bytes and indexing.
	BodyAvailabilityKnown BodyAvailability = "known"
	// BodyAvailabilityUnavailable reports that no body bytes exist.
	BodyAvailabilityUnavailable BodyAvailability = "unavailable"
)

// Known reports whether availability belongs to the closed recipe vocabulary.
func (a BodyAvailability) Known() bool {
	return a == BodyAvailabilityKnown || a == BodyAvailabilityUnavailable
}

// step stores one immutable copy range or data-string sequence.
type step struct {
	kind        StepKind
	copyStart   int
	copyEnd     int
	data        [][]byte
	initialized bool
}

// copyRange returns the inclusive copy range when this is a copy step.
func (s step) copyRange() (int, int, bool) {
	return s.copyStart, s.copyEnd, s.initialized && s.kind == StepKindCopy
}

// dataValues returns deep-cloned literals when this is a data step.
func (s step) dataValues() [][]byte {
	if !s.initialized || s.kind != StepKindData {
		return nil
	}
	return cloneBytesList(s.data)
}

// valid reports whether a step's closed representation is coherent.
func (s step) valid() bool {
	if !s.initialized || !s.kind.Known() {
		return false
	}
	if s.kind == StepKindCopy {
		return s.copyStart > 0 && s.copyEnd >= s.copyStart && len(s.data) == 0
	}
	if s.copyStart != 0 || s.copyEnd != 0 || len(s.data) == 0 {
		return false
	}
	for _, literal := range s.data {
		if !validDataLiteral(literal) {
			return false
		}
	}
	return true
}

// newCopyStep constructs one positive inclusive copy step.
func newCopyStep(start, end int) (step, error) {
	candidate := step{kind: StepKindCopy, copyStart: start, copyEnd: end, initialized: true}
	if !candidate.valid() {
		return step{}, newError(ErrorCodeInvalidCopyRange, ErrorLocation{}, ErrorDetails{StepKind: StepKindCopy}, nil)
	}
	return candidate, nil
}

// newDataStep constructs one immutable nonempty data step.
func newDataStep(data [][]byte) (step, error) {
	if len(data) == 0 {
		return step{}, newError(ErrorCodeInvalidLiteral, ErrorLocation{}, ErrorDetails{StepKind: StepKindData}, nil)
	}
	for _, literal := range data {
		if !validDataLiteral(literal) {
			return step{}, newError(ErrorCodeInvalidLiteral, ErrorLocation{}, ErrorDetails{StepKind: StepKindData}, nil)
		}
	}
	candidate := step{kind: StepKindData, data: cloneBytesList(data), initialized: true}
	if !candidate.valid() {
		return step{}, newError(ErrorCodeInvalidLiteral, ErrorLocation{}, ErrorDetails{StepKind: StepKindData}, nil)
	}
	return candidate, nil
}

// validDataLiteral enforces the shared decoded UTF-8 and line-break invariant.
func validDataLiteral(literal []byte) bool {
	return utf8.Valid(literal) && !bytes.ContainsAny(literal, "\r\n")
}

// clone returns a detached step value.
func (s step) clone() step { s.data = cloneBytesList(s.data); return s }

// headerPlan stores one immutable case-folded header recipe.
type headerPlan struct {
	name          string
	canonicalName string
	steps         []step
	initialized   bool
}

// valid reports whether the plan owns a coherent field name and ordered closed steps.
func (p headerPlan) valid() bool {
	canonicalName, ok := rawmsg.CanonicalHeaderName(p.name)
	if !p.initialized || !ok || canonicalName != p.canonicalName || p.name != canonicalName {
		return false
	}
	previousCopyEnd := 0
	for _, step := range p.steps {
		if !step.valid() {
			return false
		}
		if start, end, copyStep := step.copyRange(); copyStep {
			if previousCopyEnd != 0 && start <= previousCopyEnd {
				return false
			}
			previousCopyEnd = end
		}
	}
	return true
}

// stepsCopy returns detached ordered recipe steps.
func (p headerPlan) stepsCopy() []step { return cloneSteps(p.steps) }

// newHeaderPlan constructs one immutable header plan.
func newHeaderPlan(name, canonicalName string, steps []step) (headerPlan, error) {
	resolvedName, ok := rawmsg.CanonicalHeaderName(name)
	if !ok || canonicalName != resolvedName || name != canonicalName {
		return headerPlan{}, newError(ErrorCodeInvalidHeaderName, ErrorLocation{}, ErrorDetails{}, nil)
	}
	previousCopyEnd := 0
	for _, step := range steps {
		if !step.valid() {
			return headerPlan{}, newError(ErrorCodeInvalidStep, ErrorLocation{}, ErrorDetails{}, nil)
		}
		if start, end, copyStep := step.copyRange(); copyStep {
			if previousCopyEnd != 0 && start <= previousCopyEnd {
				return headerPlan{}, newError(ErrorCodeCopyRangeOrder, ErrorLocation{}, ErrorDetails{StepKind: StepKindCopy}, nil)
			}
			previousCopyEnd = end
		}
	}
	return headerPlan{name: name, canonicalName: canonicalName, steps: cloneSteps(steps), initialized: true}, nil
}

// clone returns a detached header plan.
func (p headerPlan) clone() headerPlan { p.steps = cloneSteps(p.steps); return p }

// Recipe stores one immutable parsed Draft-06 reconstruction plan.
type Recipe struct {
	headers         []headerPlan
	hasHeaderRecipe bool
	bodyMode        BodyMode
	bodySteps       []step
	initialized     bool
}

// Valid reports whether the recipe is an initialized coherent closed model.
func (r Recipe) Valid() bool {
	if !r.initialized || !r.bodyMode.Known() || !r.hasHeaderRecipe && r.bodyMode == BodyModeAbsent {
		return false
	}
	if !r.hasHeaderRecipe && len(r.headers) != 0 {
		return false
	}
	if r.hasHeaderRecipe && len(r.headers) == 0 {
		return false
	}
	if r.bodyMode != BodyModeSteps && len(r.bodySteps) != 0 {
		return false
	}
	previousName := ""
	for _, plan := range r.headers {
		if !plan.valid() || previousName != "" && plan.canonicalName <= previousName {
			return false
		}
		previousName = plan.canonicalName
	}
	previousCopyEnd := 0
	for _, step := range r.bodySteps {
		if !step.valid() {
			return false
		}
		if start, end, copyStep := step.copyRange(); copyStep {
			if previousCopyEnd != 0 && start <= previousCopyEnd {
				return false
			}
			previousCopyEnd = end
		}
	}
	return true
}

// HasHeaderRecipe reports whether h was present.
func (r Recipe) HasHeaderRecipe() bool { return r.Valid() && r.hasHeaderRecipe }

// HeaderNames returns deterministic retained key spellings only.
func (r Recipe) HeaderNames() []string {
	if !r.Valid() {
		return nil
	}
	names := make([]string, len(r.headers))
	for i, plan := range r.headers {
		names[i] = plan.name
	}
	return names
}

// BodyMode returns the closed body-member form.
func (r Recipe) BodyMode() BodyMode {
	if !r.Valid() {
		return ""
	}
	return r.bodyMode
}

// headerPlans returns detached plans for package-owned application.
func (r Recipe) headerPlans() []headerPlan {
	plans := make([]headerPlan, len(r.headers))
	for i, plan := range r.headers {
		plans[i] = plan.clone()
	}
	return plans
}

// newRecipe constructs an immutable recipe from already sorted unique plans.
func newRecipe(headers []headerPlan, hasHeaders bool, bodyMode BodyMode, bodySteps []step) (Recipe, error) {
	plans := make([]headerPlan, len(headers))
	for i, plan := range headers {
		plans[i] = plan.clone()
	}
	for index, plan := range plans {
		if !plan.valid() {
			return Recipe{}, newError(ErrorCodeInvalidState, ErrorLocation{}, ErrorDetails{Class: ErrorClassState}, nil)
		}
		if index > 0 && plans[index-1].canonicalName == plan.canonicalName {
			return Recipe{}, newError(ErrorCodeHeaderNameCollision, ErrorLocation{}, ErrorDetails{}, nil)
		}
	}
	previousCopyEnd := 0
	for _, step := range bodySteps {
		if !step.valid() {
			return Recipe{}, newError(ErrorCodeInvalidStep, ErrorLocation{}, ErrorDetails{}, nil)
		}
		if start, end, copyStep := step.copyRange(); copyStep {
			if previousCopyEnd != 0 && start <= previousCopyEnd {
				return Recipe{}, newError(ErrorCodeCopyRangeOrder, ErrorLocation{}, ErrorDetails{Dimension: DimensionBody, StepKind: StepKindCopy}, nil)
			}
			previousCopyEnd = end
		}
	}
	recipe := Recipe{headers: plans, hasHeaderRecipe: hasHeaders, bodyMode: bodyMode, bodySteps: cloneSteps(bodySteps), initialized: true}
	if !recipe.Valid() {
		return Recipe{}, newError(ErrorCodeInvalidState, ErrorLocation{}, ErrorDetails{Class: ErrorClassState}, nil)
	}
	return recipe, nil
}

// cloneSteps returns detached ordered steps.
func cloneSteps(steps []step) []step {
	if len(steps) == 0 {
		return nil
	}
	cloned := slices.Clone(steps)
	for i := range cloned {
		cloned[i] = cloned[i].clone()
	}
	return cloned
}

// cloneBytesList returns detached byte strings.
func cloneBytesList(values [][]byte) [][]byte {
	if len(values) == 0 {
		return nil
	}
	cloned := make([][]byte, len(values))
	for i, value := range values {
		cloned[i] = bytes.Clone(value)
	}
	return cloned
}
