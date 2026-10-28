package recipe_test

import (
	"sync"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/recipe"
)

// TestCanonicalHeaderRelevanceAlignsWithDraft08 proves the production seam and complete exclusion surface.
func TestCanonicalHeaderRelevanceAlignsWithDraft08(t *testing.T) {
	relevance := canonical.NewHeaderRelevance()
	var contract recipe.HeaderRelevance = relevance
	if err := contract.Validate(); err != nil {
		t.Fatalf("Validate() failed: error=%t", err != nil)
	}

	for _, name := range []string{
		"received", "return-path", "delivered-to", "dkim-signature",
		"arc-seal", "arc-message-signature", "arc-authentication-results",
		"authentication-results", "x-local", "x-", "message-instance", "dkim2-signature",
		"received-spf", "apparently-to", "dl-expansion-history", "original-recipient",
		"sio-label-history", "x400-received", "x400-trace",
	} {
		relevant, err := contract.IsRelevantHeader(name)
		if err != nil || relevant {
			t.Fatalf("excluded Draft-08 classification: name=%s relevant=%t error=%t", name, relevant, err != nil)
		}
	}
	// Draft-08 Section 4 removed Auto-Submitted and VBR-Info from the unsigned
	// set, so recipes for both are legal and required when a hop changes them.
	for _, name := range []string{"from", "subject", "resent-from", "arcade", "x", "message-id", "auto-submitted", "vbr-info"} {
		relevant, err := contract.IsRelevantHeader(name)
		if err != nil || !relevant {
			t.Fatalf("signed Draft-08 classification: name=%s relevant=%t error=%t", name, relevant, err != nil)
		}
	}
	for _, name := range []string{"", "Subject", "bad name", "café"} {
		if _, err := contract.IsRelevantHeader(name); err == nil {
			t.Fatalf("out-of-domain name accepted: bytes=%d", len(name))
		}
	}
	if err := (canonical.HeaderRelevance{}).Validate(); err == nil {
		t.Fatal("zero canonical relevance unexpectedly valid")
	}
}

// TestCanonicalHeaderRelevanceIsConcurrentSafe verifies immutable production classification.
func TestCanonicalHeaderRelevanceIsConcurrentSafe(t *testing.T) {
	relevance := canonical.NewHeaderRelevance()
	var wait sync.WaitGroup
	for range 16 {
		wait.Go(func() {
			for range 100 {
				if relevant, err := relevance.IsRelevantHeader("subject"); err != nil || !relevant {
					t.Error("signed header classification changed")
					return
				}
				if relevant, err := relevance.IsRelevantHeader("received"); err != nil || relevant {
					t.Error("excluded header classification changed")
					return
				}
			}
		})
	}
	wait.Wait()
}

// TestProductionRelevanceRecipesCoverAutoSubmittedAndVBRInfo proves the
// Draft-08 Section 4 consequence for recipes: a hop that adds Auto-Submitted
// or VBR-Info changes the signed header hash, so the generator must describe
// both additions, the strict parser must accept that recipe, and applying it
// must restore the previous Section 6.2 header hash. A Draft-08 unsigned
// field added in the same hop stays outside the recipe.
func TestProductionRelevanceRecipesCoverAutoSubmittedAndVBRInfo(t *testing.T) {
	previous := mustExternalState(t, []byte("From: sender@example.test\r\nSubject: same\r\n\r\nbody\r\n"))
	current := mustExternalState(t, []byte(
		"X400-Trace: unsigned\r\n"+
			"Auto-Submitted: auto-forwarded\r\n"+
			"VBR-Info: md=example.test; mc=all; mv=vouch.example\r\n"+
			"From: sender@example.test\r\nSubject: same\r\n\r\nbody\r\n"))
	request, err := recipe.NewGenerationRequest(previous, current, recipe.RejectUnavailableBody, recipe.AllowLiterals)
	if err != nil {
		t.Fatal("generation request setup failed")
	}
	generator := mustExternalGenerator(t)
	generation, _, err := generator.Generate(request)
	if err != nil || !generation.Valid() || generation.Outcome() != recipe.GenerationOutcomeRecipe {
		t.Fatalf("Generate() valid=%t outcome=%q error=%t", generation.Valid(), generation.Outcome(), err != nil)
	}
	if got, want := string(generation.DecodedJSON()), `{"h":{"auto-submitted":[],"vbr-info":[]}}`; got != want {
		t.Fatalf("generated recipe = %s, want %s", got, want)
	}
	parsed, _, err := mustExternalParser(t, generator.Limits().RecipeLimits).Parse(generation.DecodedJSON())
	if err != nil {
		t.Fatal("generated recipe failed strict parse")
	}
	reconstructed, _, err := mustExternalApplier(t, generator.Limits().RecipeLimits).Apply(current, parsed)
	if err != nil {
		t.Fatal("generated recipe failed strict apply")
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatal("canonicalizer setup failed")
	}
	want, err := canonicalizer.HeaderHash(previous.Headers())
	if err != nil {
		t.Fatal("previous header hash failed")
	}
	got, err := canonicalizer.HeaderHash(reconstructed.Headers())
	if err != nil {
		t.Fatal("reconstructed header hash failed")
	}
	assertCanonicalResultEqual(t, "header", want, got)

	if _, _, err := mustExternalParser(t, recipe.Limits{}).Parse([]byte(`{"h":{"x400-trace":[]}}`)); !recipe.IsErrorCode(err, recipe.ErrorCodeUnsignedHeaderRecipe) {
		t.Fatal("recipe for a Draft-08 unsigned field was not rejected")
	}
}
