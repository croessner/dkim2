package recipe_test

import (
	"bytes"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
)

// TestGeneratedRecipePreservesSection6KnownInputsAndHashes proves canonical equivalence without raw rewrite claims.
func TestGeneratedRecipePreservesSection6KnownInputsAndHashes(t *testing.T) {
	previous := mustExternalState(t, []byte("Beta: two\r\nSubject: previous\r\nAlpha: one\r\n\r\nold\r\n"))
	current := mustExternalState(t, []byte("Alpha: one\r\nSubject: current\r\nBeta: two\r\n\r\nnew\r\n"))
	generator := mustExternalGenerator(t)
	request, err := recipe.NewGenerationRequest(previous, current, recipe.RejectUnavailableBody, recipe.AllowLiterals)
	if err != nil {
		t.Fatal("generation request setup failed")
	}
	generation, _, err := generator.Generate(request)
	if err != nil || generation.Outcome() != recipe.GenerationOutcomeRecipe {
		t.Fatalf("Generate() outcome=%s", generation.Outcome())
	}
	parsed, _, err := mustExternalParser(t, generator.Limits().RecipeLimits).Parse(generation.DecodedJSON())
	if err != nil {
		t.Fatal("returned recipe parse failed")
	}
	reconstructed, _, err := mustExternalApplier(t, generator.Limits().RecipeLimits).Apply(current, parsed)
	if err != nil {
		t.Fatal("returned recipe apply failed")
	}
	previousMessage, err := previous.Materialize()
	if err != nil {
		t.Fatal("previous materialization failed")
	}
	reconstructedMessage, err := reconstructed.Materialize()
	if err != nil {
		t.Fatal("reconstructed materialization failed")
	}
	if bytes.Equal(previousMessage.Headers().OriginalBytes(), reconstructedMessage.Headers().OriginalBytes()) {
		t.Fatal("fixture did not exercise canonical-equivalent cross-name placement")
	}

	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatal("canonicalizer setup failed")
	}
	previousHeader, err := canonicalizer.HeaderHash(previousMessage.Headers())
	if err != nil {
		t.Fatal("previous header canonicalization failed")
	}
	reconstructedHeader, err := canonicalizer.HeaderHash(reconstructedMessage.Headers())
	if err != nil {
		t.Fatal("reconstructed header canonicalization failed")
	}
	assertCanonicalResultEqual(t, "header", previousHeader, reconstructedHeader)
	previousBody, err := canonicalizer.BodyHash(previousMessage.Body())
	if err != nil {
		t.Fatal("previous body canonicalization failed")
	}
	reconstructedBody, err := canonicalizer.BodyHash(reconstructedMessage.Body())
	if err != nil {
		t.Fatal("reconstructed body canonicalization failed")
	}
	assertCanonicalResultEqual(t, "body", previousBody, reconstructedBody)
}

// TestGeneratedUnavailableBodyProvesHeaderCanonicalizationOnly avoids body or whole-message equality claims for b:null.
func TestGeneratedUnavailableBodyProvesHeaderCanonicalizationOnly(t *testing.T) {
	previous := mustExternalState(t, []byte("Subject: previous\r\n"))
	current := mustExternalState(t, []byte("Subject: current\r\n\r\nbody\r\n"))
	generator := mustExternalGenerator(t)
	request, err := recipe.NewGenerationRequest(previous, current, recipe.AllowUnavailableBody, recipe.AllowLiterals)
	if err != nil {
		t.Fatal("generation request setup failed")
	}
	generation, _, err := generator.Generate(request)
	if err != nil || generation.BodyOutcome() != recipe.BodyGenerationUnavailable {
		t.Fatalf("Generate() body outcome=%s", generation.BodyOutcome())
	}
	parsed, _, err := mustExternalParser(t, generator.Limits().RecipeLimits).Parse(generation.DecodedJSON())
	if err != nil || parsed.BodyMode() != recipe.BodyModeUnavailable {
		t.Fatal("returned b:null parse failed")
	}
	reconstructed, _, err := mustExternalApplier(t, generator.Limits().RecipeLimits).Apply(current, parsed)
	if err != nil || reconstructed.BodyState() != recipe.BodyAvailabilityUnavailable {
		t.Fatalf("b:null state=%s", reconstructed.BodyState())
	}
	canonicalizer, _ := canonical.NewCanonicalizer()
	previousHeader, err := canonicalizer.HeaderHash(previous.Headers())
	if err != nil {
		t.Fatal("previous header canonicalization failed")
	}
	reconstructedHeader, err := canonicalizer.HeaderHash(reconstructed.Headers())
	if err != nil {
		t.Fatal("reconstructed header canonicalization failed")
	}
	assertCanonicalResultEqual(t, "header", previousHeader, reconstructedHeader)
	if _, known := reconstructed.Body(); known {
		t.Fatal("b:null exposed body bytes")
	}
}

// mustExternalState parses one strict message and constructs a recipe state.
func mustExternalState(t *testing.T, data []byte) recipe.State {
	t.Helper()
	message, err := rawmsg.Parse(data)
	if err != nil {
		t.Fatalf("raw message parse failed: %v", err)
	}
	state, err := recipe.NewState(message)
	if err != nil {
		t.Fatal("recipe state setup failed")
	}
	return state
}

// mustExternalGenerator constructs the production canonical-relevance generator.
func mustExternalGenerator(t *testing.T) recipe.Generator {
	t.Helper()
	generator, err := recipe.NewGenerator(recipe.GenerationLimits{}, canonical.NewHeaderRelevance())
	if err != nil {
		t.Fatal("generator setup failed")
	}
	return generator
}

// mustExternalParser constructs a strict parser under the exact generator limits.
func mustExternalParser(t *testing.T, limits recipe.Limits) recipe.Parser {
	t.Helper()
	parser, err := recipe.NewParser(limits)
	if err != nil {
		t.Fatal("parser setup failed")
	}
	return parser
}

// mustExternalApplier constructs an applier under the exact generator limits.
func mustExternalApplier(t *testing.T, limits recipe.Limits) recipe.Applier {
	t.Helper()
	applier, err := recipe.NewApplier(limits)
	if err != nil {
		t.Fatal("applier setup failed")
	}
	return applier
}

// assertCanonicalResultEqual compares exact Section 6 input bytes and SHA-256 output.
func assertCanonicalResultEqual(t *testing.T, dimension string, left, right canonical.Result) {
	t.Helper()
	if !bytes.Equal(left.CanonicalBytes().Bytes(), right.CanonicalBytes().Bytes()) {
		t.Fatalf("%s canonical input differs", dimension)
	}
	leftDigest, leftOK := left.Digest()
	rightDigest, rightOK := right.Digest()
	if !leftOK || !rightOK || !bytes.Equal(leftDigest.Bytes(), rightDigest.Bytes()) || leftDigest.Base64() != rightDigest.Base64() {
		t.Fatalf("%s canonical hash differs", dimension)
	}
}
