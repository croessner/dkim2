package recipe

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
)

const generationCounterWorkCase = "work"

// TestGenerateRejectsUniqueHeaderNameBombWithoutOutput proves the complete API fails before public serialization.
func TestGenerateRejectsUniqueHeaderNameBombWithoutOutput(t *testing.T) {
	var message strings.Builder
	for index := range 5 {
		fmt.Fprintf(&message, "X-Unique-%d: value\r\n", index)
	}
	message.WriteString("\r\nbody\r\n")
	previous := mustGenerationState(t, []byte(message.String()))
	current := mustGenerationState(t, []byte(message.String()))
	request, err := NewGenerationRequest(previous, current, RejectUnavailableBody, CopyOnly)
	if err != nil {
		t.Fatal("unique-header bomb request setup failed")
	}
	limits := DefaultGenerationLimits()
	limits.RecipeLimits.MaxHeaderNames = 4
	generator, err := NewGenerator(limits, canonical.NewHeaderRelevance())
	if err != nil {
		t.Fatal("unique-header bomb generator setup failed")
	}
	generation, usage, err := generator.Generate(request)
	var typed *Error
	if !errors.As(err, &typed) || typed.Code() != ErrorCodeLimitExceeded || typed.LimitName() != limitNameMaxHeaderNames || typed.Dimension() != DimensionHeader || generation.Valid() || usage.JSONBytes() != 0 {
		t.Fatal("unique-header bomb did not fail closed at the header-name bound")
	}
}

// TestGenerationCounterRejectsNegativeChargesTransactionally proves accounting can never move backwards.
func TestGenerationCounterRejectsNegativeChargesTransactionally(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*generationCounter)
		charge func(*generationCounter) error
	}{
		{name: "input-bytes", charge: func(c *generationCounter) error { return c.chargeInput(-1, 0, DimensionHeader) }},
		{name: "input-items", charge: func(c *generationCounter) error { return c.chargeInput(0, -1, DimensionHeader) }},
		{name: "candidate-key", charge: func(c *generationCounter) error { return c.chargeCandidate(-1, DimensionHeader) }},
		{name: "copy-ranges", charge: func(c *generationCounter) error { return c.chargeCopy(-1, 0, DimensionBody) }},
		{name: "copied-items", charge: func(c *generationCounter) error { return c.chargeCopy(0, -1, DimensionBody) }},
		{name: "literal-bytes", charge: func(c *generationCounter) error { return c.chargeLiteralString(-1, DimensionBody) }},
		{name: "json-preflight", charge: func(c *generationCounter) error { return c.checkJSONBytes(-1) }},
		{name: "json-bytes", charge: func(c *generationCounter) error { return c.commitJSONBytes(-1) }},
		{name: generationCounterWorkCase, charge: func(c *generationCounter) error { return c.chargeWork(-1, DimensionRecipe) }},
		{name: "semantic-proof", setup: prepareGenerationSemanticProofCounter, charge: func(c *generationCounter) error { return c.chargeReconstructionProofWork(-1, DimensionHeader) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			counter := newGenerationCounter(DefaultGenerationLimits())
			if test.setup != nil {
				test.setup(&counter)
			}
			before := counter
			if err := test.charge(&counter); err == nil || counter != before {
				t.Fatal("negative generation charge was accepted or mutated accounting")
			}
		})
	}
}

// TestGenerationCounterRejectsArithmeticOverflowTransactionally covers every mutable accounting family.
func TestGenerationCounterRejectsArithmeticOverflowTransactionally(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*generationCounter)
		charge func(*generationCounter) error
	}{
		{name: "input-bytes", setup: func(c *generationCounter) { c.inputBytes = math.MaxInt }, charge: func(c *generationCounter) error { return c.chargeInput(1, 0, DimensionHeader) }},
		{name: "input-items", setup: func(c *generationCounter) { c.inputItems = math.MaxInt }, charge: func(c *generationCounter) error { return c.chargeInput(0, 1, DimensionHeader) }},
		{name: "candidates", setup: func(c *generationCounter) { c.candidates = math.MaxInt }, charge: func(c *generationCounter) error { return c.chargeCandidate(0, DimensionHeader) }},
		{name: "candidate-key-bytes", setup: func(c *generationCounter) { c.candidateBytes = math.MaxInt }, charge: func(c *generationCounter) error { return c.chargeCandidate(1, DimensionHeader) }},
		{name: "comparisons", setup: func(c *generationCounter) { c.comparisons = math.MaxInt }, charge: func(c *generationCounter) error { return c.chargeComparison(DimensionHeader) }},
		{name: "steps", setup: func(c *generationCounter) { c.generatedSteps = math.MaxInt }, charge: func(c *generationCounter) error { return c.chargeStep(DimensionBody) }},
		{name: "copy-ranges", setup: func(c *generationCounter) { c.copyRanges = math.MaxInt }, charge: func(c *generationCounter) error { return c.chargeCopy(1, 0, DimensionBody) }},
		{name: "copied-items", setup: func(c *generationCounter) { c.copiedItems = math.MaxInt }, charge: func(c *generationCounter) error { return c.chargeCopy(0, 1, DimensionBody) }},
		{name: "literals", setup: func(c *generationCounter) { c.generatedLiterals = math.MaxInt }, charge: func(c *generationCounter) error { return c.chargeLiteralString(0, DimensionBody) }},
		{name: "literal-bytes", setup: func(c *generationCounter) { c.literalBytes = math.MaxInt }, charge: func(c *generationCounter) error { return c.chargeLiteralString(1, DimensionBody) }},
		{name: "json-preflight", setup: func(c *generationCounter) { c.jsonBytes = math.MaxInt }, charge: func(c *generationCounter) error { return c.checkJSONBytes(1) }},
		{name: "json-bytes", setup: func(c *generationCounter) { c.jsonBytes = math.MaxInt }, charge: func(c *generationCounter) error { return c.commitJSONBytes(1) }},
		{name: generationCounterWorkCase, setup: func(c *generationCounter) { c.workUnits = math.MaxInt }, charge: func(c *generationCounter) error { return c.chargeWork(1, DimensionRecipe) }},
		{name: "semantic-proof", setup: func(c *generationCounter) {
			prepareGenerationSemanticProofCounter(c)
			c.semanticProofWorkUnits = math.MaxInt
		}, charge: func(c *generationCounter) error { return c.chargeReconstructionProofWork(1, DimensionHeader) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			counter := newGenerationCounter(DefaultGenerationLimits())
			test.setup(&counter)
			before := counter
			if err := test.charge(&counter); err == nil || counter != before {
				t.Fatal("overflowing generation charge was accepted or mutated accounting")
			}
		})
	}
}

// prepareGenerationSemanticProofCounter establishes the immutable prerequisites for semantic-proof charging.
func prepareGenerationSemanticProofCounter(counter *generationCounter) {
	counter.proofReserved = true
	counter.parseProofRecorded = true
	counter.reconstructionProofRecorded = true
}
