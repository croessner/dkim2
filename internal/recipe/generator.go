package recipe

import (
	"github.com/croessner/dkim2/internal/niliface"
	"github.com/croessner/dkim2/internal/rawmsg"
)

// HeaderRelevance classifies validated canonical lowercase header names.
// Implementations must be immutable, deterministic, concurrent-safe, and must
// return errors that do not retain or expose header names or message content.
type HeaderRelevance interface {
	Validate() error
	IsRelevantHeader(nameLower string) (bool, error)
}

// Generator stores immutable validated generation dependencies and limits.
type Generator struct {
	limits      GenerationLimits
	relevance   HeaderRelevance
	initialized bool
}

// NewGenerator constructs an immutable fail-closed recipe generator.
func NewGenerator(limits GenerationLimits, relevance HeaderRelevance) (Generator, error) {
	resolved, err := limits.normalized()
	if err != nil {
		return Generator{}, err
	}
	if !stableHeaderRelevance(relevance) {
		return Generator{}, newError(ErrorCodeInvalidGenerator, ErrorLocation{}, ErrorDetails{Class: ErrorClassState}, nil)
	}
	return Generator{limits: resolved, relevance: relevance, initialized: true}, nil
}

// Valid reports whether the generator was constructed with validated dependencies.
func (g Generator) Valid() bool {
	return g.initialized && stableHeaderRelevance(g.relevance)
}

// Limits returns the immutable normalized generation limits.
func (g Generator) Limits() GenerationLimits {
	if !g.Valid() {
		return GenerationLimits{}
	}
	return g.limits
}

// Generate deterministically plans and returns a recipe only after strict parse, apply, and semantic proof.
func (g Generator) Generate(request GenerationRequest) (Generation, GenerationUsage, error) {
	limits := g.limits
	if !g.Valid() {
		limits = DefaultGenerationLimits()
	}
	counter := newGenerationCounter(limits)
	fail := func(err error) (Generation, GenerationUsage, error) {
		return Generation{}, counter.failedUsage(), err
	}
	if err := g.validateRequest(request); err != nil {
		return fail(err)
	}
	budget, err := newGenerationPlanBudget(&counter)
	if err != nil {
		return fail(err)
	}
	headerPlan, err := g.planHeaders(request, budget)
	if err != nil {
		return fail(err)
	}
	bodyPlan, err := g.planBody(request, budget)
	if err != nil {
		return fail(err)
	}
	if !headerPlan.Changed() && bodyPlan.Outcome() == BodyGenerationUnchanged {
		return newUnchangedGeneration(), counter.usage(), nil
	}
	plan, err := newGenerationSerializationPlan(headerPlan, bodyPlan)
	if err != nil {
		return fail(err)
	}
	serialized, err := budget.serializeGenerationPlan(plan)
	if err != nil {
		return fail(err)
	}
	proof, err := g.proveSerializedGeneration(request, serialized, &counter)
	if err != nil {
		return fail(err)
	}
	generation, err := newProvenGeneration(proof)
	if err != nil {
		return fail(err)
	}
	return generation, counter.usage(), nil
}

// validateRequest rejects zero generators and invalid or body-unknown requests before planning.
func (g Generator) validateRequest(request GenerationRequest) error {
	if !g.Valid() {
		return newError(ErrorCodeInvalidGenerator, ErrorLocation{}, ErrorDetails{Class: ErrorClassState}, nil)
	}
	if !request.Valid() {
		return newError(ErrorCodeInvalidRequest, ErrorLocation{}, ErrorDetails{Class: ErrorClassRequest}, nil)
	}
	return nil
}

// classifyStableHeader validates the interface domain and rejects callback failure or disagreement.
func (g Generator) classifyStableHeader(nameLower string) (bool, error) {
	if !g.Valid() {
		return false, newError(ErrorCodeInvalidGenerator, ErrorLocation{}, ErrorDetails{Class: ErrorClassState}, nil)
	}
	canonicalName, ok := rawmsg.CanonicalHeaderName(nameLower)
	if !ok || canonicalName != nameLower {
		return false, newError(ErrorCodeHeaderRelevance, ErrorLocation{}, ErrorDetails{Class: ErrorClassInvariant}, nil)
	}
	first, err := g.relevance.IsRelevantHeader(nameLower)
	if err != nil {
		return false, newError(ErrorCodeHeaderRelevance, ErrorLocation{}, ErrorDetails{Class: ErrorClassInvariant}, nil)
	}
	second, err := g.relevance.IsRelevantHeader(nameLower)
	if err != nil || first != second {
		return false, newError(ErrorCodeHeaderRelevance, ErrorLocation{}, ErrorDetails{Class: ErrorClassInvariant}, nil)
	}
	return first, nil
}

// nilInterface reports nil and typed-nil interface dependencies without invoking methods.
func nilInterface(value any) bool {
	return niliface.IsNil(value)
}

// stableHeaderRelevance validates a dependency twice and drops callback errors opaquely.
func stableHeaderRelevance(relevance HeaderRelevance) bool {
	if nilInterface(relevance) || relevance.Validate() != nil {
		return false
	}
	return relevance.Validate() == nil
}
