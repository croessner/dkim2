package verify

import (
	"context"
	"testing"
)

// TestRevisionProofRefusesNullBodyRecipeHistory reproduces Draft-08 Section
// 13: body hashes below a null Recipe cannot be checked, so a history with
// "b":null is never a Fully Verified DKIM2 Message. The all-hop proof reports
// body_history_unavailable and issues no proof, while the same history with
// a complete body Recipe stays verified.
func TestRevisionProofRefusesNullBodyRecipeHistory(t *testing.T) {
	complete := newCurrentHistoryVerificationFixture(t, `{"h":{"subject":[{"d":["previous"]}]},"b":[{"d":["previous"]}]}`)
	outcome, proof, err := mustVerifierForFixture(t, complete).VerifyRevisionProof(context.Background(), Request{Message: complete.message, Envelope: matchingEnvelope()})
	if err != nil || outcome != RevisionProofVerified || !proof.Valid() || proof.Facts().HistoryHasUnavailableBody() {
		t.Fatalf("complete history = %q/%t/%v", outcome, proof.Valid(), err)
	}
	null := newCurrentHistoryVerificationFixture(t, `{"h":{"subject":[{"d":["previous"]}]},"b":null}`)
	outcome, proof, err = mustVerifierForFixture(t, null).VerifyRevisionProof(context.Background(), Request{Message: null.message, Envelope: matchingEnvelope()})
	if err != nil || outcome != RevisionProofBodyHistoryUnavailable || proof.Valid() {
		t.Fatalf("null body history = %q/%t/%v", outcome, proof.Valid(), err)
	}
}

// TestRevisionProofSeparatesRecipeJSONFromInvalidRecipes reproduces the
// Draft-08 Section 14.2 distinction: text that is not a JSON object is
// invalid_recipe_json, while valid JSON with an invalid step, schema, or
// application is invalid_recipe.
func TestRevisionProofSeparatesRecipeJSONFromInvalidRecipes(t *testing.T) {
	tests := []struct {
		name   string
		recipe string
		want   RevisionProofOutcome
	}{
		{name: "malformed JSON", recipe: `{`, want: RevisionProofInvalidRecipeJSON},
		{name: "duplicate member", recipe: `{"b":null,"b":null}`, want: RevisionProofInvalidRecipeJSON},
		{name: "non-object root", recipe: `[]`, want: RevisionProofInvalidRecipeJSON},
		{name: "unknown step", recipe: `{"h":{"subject":[{"x":["previous"]}]},"b":[{"d":["previous"]}]}`, want: RevisionProofInvalidRecipe},
		{name: "missing dimension", recipe: `{}`, want: RevisionProofInvalidRecipe},
		{name: "copy range outside its source", recipe: `{"h":{"subject":[{"d":["previous"]}]},"b":[{"c":[1,99]}]}`, want: RevisionProofInvalidRecipe},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCurrentHistoryVerificationFixture(t, test.recipe)
			outcome, proof, err := mustVerifierForFixture(t, fixture).VerifyRevisionProof(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
			if err != nil || outcome != test.want || proof.Valid() {
				t.Fatalf("VerifyRevisionProof() = %q/%t/%v, want %q", outcome, proof.Valid(), err, test.want)
			}
		})
	}
}
