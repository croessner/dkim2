package recipe

import "bytes"

// LiteralDisclosurePolicy controls whether generated recipes may embed previous content.
type LiteralDisclosurePolicy uint8

const (
	// CopyOnly forbids embedding previous header or body content.
	CopyOnly LiteralDisclosurePolicy = iota
	// AllowLiterals permits bounded literal disclosure in generated recipes.
	AllowLiterals
)

// Known reports whether policy belongs to the closed disclosure vocabulary.
func (p LiteralDisclosurePolicy) Known() bool { return p == CopyOnly || p == AllowLiterals }

// BodyUnavailablePolicy controls whether an unrepresentable previous body may become b:null.
type BodyUnavailablePolicy uint8

const (
	// RejectUnavailableBody fails closed when the previous body cannot be reconstructed.
	RejectUnavailableBody BodyUnavailablePolicy = iota
	// AllowUnavailableBody permits an explicit unavailable-body success outcome.
	AllowUnavailableBody
)

// Known reports whether policy belongs to the closed unavailable-body vocabulary.
func (p BodyUnavailablePolicy) Known() bool {
	return p == RejectUnavailableBody || p == AllowUnavailableBody
}

// GenerationOutcome identifies one closed top-level generation success.
type GenerationOutcome string

const (
	// GenerationOutcomeUnchanged reports that no recipe-semantic relevant change exists.
	GenerationOutcomeUnchanged GenerationOutcome = "unchanged"
	// GenerationOutcomeRecipe reports one initialized recipe result.
	GenerationOutcomeRecipe GenerationOutcome = "recipe"
)

// Known reports whether outcome belongs to the closed generation vocabulary.
func (o GenerationOutcome) Known() bool {
	return o == GenerationOutcomeUnchanged || o == GenerationOutcomeRecipe
}

// BodyGenerationOutcome identifies the generated recipe's body dimension.
type BodyGenerationOutcome string

const (
	// BodyGenerationUnchanged reports that the body member is omitted.
	BodyGenerationUnchanged BodyGenerationOutcome = "unchanged"
	// BodyGenerationGenerated reports that body steps reconstruct the previous body.
	BodyGenerationGenerated BodyGenerationOutcome = "generated"
	// BodyGenerationUnavailable reports an explicitly authorized b:null result.
	BodyGenerationUnavailable BodyGenerationOutcome = "unavailable"
)

// Known reports whether outcome belongs to the closed body-generation vocabulary.
func (o BodyGenerationOutcome) Known() bool {
	return o == BodyGenerationUnchanged || o == BodyGenerationGenerated || o == BodyGenerationUnavailable
}

// BodyUnavailableReason identifies a non-sensitive reason for an authorized b:null result.
type BodyUnavailableReason string

const (
	// BodyUnavailableReasonUnrepresentable reports draft framing or literal unrepresentability.
	BodyUnavailableReasonUnrepresentable BodyUnavailableReason = "unrepresentable"
	// BodyUnavailableReasonLiteralRequired reports a literal forbidden by copy-only policy.
	BodyUnavailableReasonLiteralRequired BodyUnavailableReason = "literal_required"
)

// Known reports whether reason belongs to the closed unavailable-body vocabulary.
func (r BodyUnavailableReason) Known() bool {
	return r == BodyUnavailableReasonUnrepresentable || r == BodyUnavailableReasonLiteralRequired
}

// GenerationRequest stores one immutable inverse-generation request.
type GenerationRequest struct {
	previous              State
	current               State
	bodyUnavailablePolicy BodyUnavailablePolicy
	literalPolicy         LiteralDisclosurePolicy
	initialized           bool
}

// NewGenerationRequest constructs a request from known initialized states and closed policies.
func NewGenerationRequest(previous, current State, bodyPolicy BodyUnavailablePolicy, literalPolicy LiteralDisclosurePolicy) (GenerationRequest, error) {
	if !bodyPolicy.Known() || !literalPolicy.Known() {
		return GenerationRequest{}, newError(ErrorCodeInvalidPolicy, ErrorLocation{}, ErrorDetails{Class: ErrorClassPolicy}, nil)
	}
	if !knownGenerationState(previous) || !knownGenerationState(current) {
		return GenerationRequest{}, newError(ErrorCodeInvalidRequest, ErrorLocation{}, ErrorDetails{Class: ErrorClassRequest}, nil)
	}
	return GenerationRequest{
		previous: previous, current: current, bodyUnavailablePolicy: bodyPolicy,
		literalPolicy: literalPolicy, initialized: true,
	}, nil
}

// Valid reports whether the request contains two known states and closed policies.
func (r GenerationRequest) Valid() bool {
	return r.initialized && knownGenerationState(r.previous) && knownGenerationState(r.current) &&
		r.bodyUnavailablePolicy.Known() && r.literalPolicy.Known()
}

// Previous returns the immutable previous target state.
func (r GenerationRequest) Previous() State {
	if !r.Valid() {
		return State{}
	}
	return r.previous
}

// Current returns the immutable current source state.
func (r GenerationRequest) Current() State {
	if !r.Valid() {
		return State{}
	}
	return r.current
}

// BodyUnavailablePolicy returns the closed body-unavailable policy.
func (r GenerationRequest) BodyUnavailablePolicy() BodyUnavailablePolicy {
	if !r.Valid() {
		return BodyUnavailablePolicy(255)
	}
	return r.bodyUnavailablePolicy
}

// LiteralPolicy returns the closed literal-disclosure policy.
func (r GenerationRequest) LiteralPolicy() LiteralDisclosurePolicy {
	if !r.Valid() {
		return LiteralDisclosurePolicy(255)
	}
	return r.literalPolicy
}

// knownGenerationState reports whether state has an initialized known body.
func knownGenerationState(state State) bool {
	return state.Valid() && state.BodyState() == BodyAvailabilityKnown
}

// Generation stores one immutable closed generation success.
type Generation struct {
	outcome     GenerationOutcome
	bodyOutcome BodyGenerationOutcome
	unavailable BodyUnavailableReason
	recipe      Recipe
	decodedJSON []byte
	initialized bool
}

// Valid reports whether generation is a coherent unchanged or recipe success.
func (g Generation) Valid() bool {
	if !g.initialized || !g.outcome.Known() || !g.bodyOutcome.Known() {
		return false
	}
	if g.outcome == GenerationOutcomeUnchanged {
		return g.bodyOutcome == BodyGenerationUnchanged && !g.unavailable.Known() && !g.recipe.Valid() && len(g.decodedJSON) == 0
	}
	if !g.recipe.Valid() || len(g.decodedJSON) == 0 {
		return false
	}
	switch g.bodyOutcome {
	case BodyGenerationUnchanged:
		return !g.unavailable.Known() && g.recipe.BodyMode() == BodyModeAbsent
	case BodyGenerationGenerated:
		return !g.unavailable.Known() && g.recipe.BodyMode() == BodyModeSteps
	case BodyGenerationUnavailable:
		return g.unavailable.Known() && g.recipe.BodyMode() == BodyModeUnavailable
	default:
		return false
	}
}

// Outcome returns the closed top-level generation outcome.
func (g Generation) Outcome() GenerationOutcome {
	if !g.Valid() {
		return ""
	}
	return g.outcome
}

// BodyOutcome returns the closed body generation outcome.
func (g Generation) BodyOutcome() BodyGenerationOutcome {
	if !g.Valid() {
		return ""
	}
	return g.bodyOutcome
}

// BodyUnavailableReason returns the reason only for an unavailable-body result.
func (g Generation) BodyUnavailableReason() BodyUnavailableReason {
	if !g.Valid() || g.bodyOutcome != BodyGenerationUnavailable {
		return ""
	}
	return g.unavailable
}

// Recipe returns a detached immutable recipe for recipe success.
func (g Generation) Recipe() (Recipe, bool) {
	if !g.Valid() || g.outcome != GenerationOutcomeRecipe {
		return Recipe{}, false
	}
	return cloneRecipe(g.recipe), true
}

// DecodedJSON returns a detached copy of protected decoded recipe JSON.
func (g Generation) DecodedJSON() []byte {
	if !g.Valid() || g.outcome != GenerationOutcomeRecipe {
		return nil
	}
	return bytes.Clone(g.decodedJSON)
}

// newUnchangedGeneration constructs the closed no-recipe success.
func newUnchangedGeneration() Generation {
	return Generation{outcome: GenerationOutcomeUnchanged, bodyOutcome: BodyGenerationUnchanged, initialized: true}
}

// newProvenGeneration atomically transfers one completed self-proof into an immutable public result.
func newProvenGeneration(proof generationProof) (Generation, error) {
	if !proof.Valid() {
		return Generation{}, generationInvariantErrorForDimension(DimensionRecipe)
	}
	candidate := Generation{
		outcome: GenerationOutcomeRecipe, bodyOutcome: proof.bodyOutcome, unavailable: proof.unavailable,
		recipe: proof.recipe, decodedJSON: proof.decodedJSON, initialized: true,
	}
	return candidate, nil
}

// cloneRecipe returns a deep copy of one initialized recipe.
func cloneRecipe(recipe Recipe) Recipe {
	if !recipe.Valid() {
		return Recipe{}
	}
	return Recipe{
		headers: recipe.headerPlans(), hasHeaderRecipe: recipe.hasHeaderRecipe,
		bodyMode: recipe.bodyMode, bodySteps: cloneSteps(recipe.bodySteps), initialized: true,
	}
}

// GenerationUsage stores bounded numeric accounting for one generation attempt.
type GenerationUsage struct {
	inputBytes, inputItems        int
	candidates, candidateKeyBytes int
	comparisons, generatedSteps   int
	generatedLiterals             int
	literalBytes, jsonBytes       int
	proofWorkUnits, workUnits     int
	initialized                   bool
}

// Valid reports whether usage contains only initialized nonnegative counters.
func (u GenerationUsage) Valid() bool {
	return u.initialized && u.inputBytes >= 0 && u.inputItems >= 0 && u.candidates >= 0 &&
		u.candidateKeyBytes >= 0 && u.comparisons >= 0 && u.generatedSteps >= 0 &&
		u.generatedLiterals >= 0 && u.literalBytes >= 0 && u.jsonBytes >= 0 && u.proofWorkUnits >= 0 && u.workUnits >= 0
}

// InputBytes returns source and target bytes examined.
func (u GenerationUsage) InputBytes() int { return u.inputBytes }

// InputItems returns source and target items examined.
func (u GenerationUsage) InputItems() int { return u.inputItems }

// Candidates returns retained source occurrence entries.
func (u GenerationUsage) Candidates() int { return u.candidates }

// CandidateKeyBytes returns protected key bytes retained during matching.
func (u GenerationUsage) CandidateKeyBytes() int { return u.candidateKeyBytes }

// Comparisons returns exact target lookup and candidate advance operations.
func (u GenerationUsage) Comparisons() int { return u.comparisons }

// GeneratedSteps returns planned recipe steps.
func (u GenerationUsage) GeneratedSteps() int { return u.generatedSteps }

// GeneratedLiterals returns planned data-string count.
func (u GenerationUsage) GeneratedLiterals() int { return u.generatedLiterals }

// LiteralBytes returns previous content bytes authorized for disclosure.
func (u GenerationUsage) LiteralBytes() int { return u.literalBytes }

// JSONBytes returns generated decoded recipe bytes.
func (u GenerationUsage) JSONBytes() int { return u.jsonBytes }

// ProofWorkUnits returns parse, application, and semantic reconstruction proof work.
func (u GenerationUsage) ProofWorkUnits() int { return u.proofWorkUnits }

// WorkUnits returns aggregate generation work.
func (u GenerationUsage) WorkUnits() int { return u.workUnits }

// newGenerationUsage constructs initialized immutable generation accounting.
func newGenerationUsage(inputBytes, inputItems, candidates, candidateKeyBytes, comparisons, generatedSteps, generatedLiterals, literalBytes, jsonBytes, proofWorkUnits, workUnits int) GenerationUsage {
	usage := GenerationUsage{
		inputBytes: inputBytes, inputItems: inputItems, candidates: candidates,
		candidateKeyBytes: candidateKeyBytes, comparisons: comparisons, generatedSteps: generatedSteps,
		generatedLiterals: generatedLiterals, literalBytes: literalBytes, jsonBytes: jsonBytes, proofWorkUnits: proofWorkUnits,
		workUnits: workUnits, initialized: true,
	}
	if !usage.Valid() {
		return GenerationUsage{}
	}
	return usage
}
