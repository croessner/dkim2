package dkim2

import (
	"context"
	"testing"
	"time"
)

// TestNullBodyHistoryIsNotFullyVerified reproduces Draft-08 Section 13
// through the public verifier: a history with a "b":null Recipe cannot have
// its body hashes checked, so the message is FAIL body_history_unavailable
// rather than a PASS with partial history, and strict policy rejects it.
func TestNullBodyHistoryIsNotFullyVerified(t *testing.T) {
	const timestamp = int64(1700000000)
	raw, key := signedPublicHistoriedMessageWithRecipe(t, timestamp, `{"b":null}`)
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return FoundRSAPublicKey(key), nil
	}), WithVerificationClock(func() time.Time { return time.Unix(timestamp, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil || result.State() != ResultStateFAIL || result.PrimaryReason() != ReasonBodyHistoryUnavailable ||
		result.Scope() != VerificationScopeCurrent || result.HistoricalContent() != HistoricalStateNotEvaluated || !result.Valid() {
		t.Fatalf("Verify() = %q/%q scope=%q content=%q valid=%t error=%v", result.State(), result.PrimaryReason(), result.Scope(), result.HistoricalContent(), result.Valid(), err)
	}
	if _, ok := result.VerifierProjection(); ok {
		t.Fatal("not Fully Verified result carried complete-chain evidence")
	}
	decision, err := EvaluatePolicy(result)
	if err != nil || decision.Verdict() != PolicyVerdictReject || decision.PrimaryReason() != PolicyReasonProtocolFail {
		t.Fatalf("EvaluatePolicy() = %q/%q error=%v", decision.Verdict(), decision.PrimaryReason(), err)
	}
}

// TestInvalidRecipeIsSeparateFromInvalidRecipeJSON reproduces the Draft-08
// Section 14.2 distinction through the public verifier: valid JSON with an
// invalid step or an inapplicable copy range is PERMERROR invalid_recipe,
// while text that is not a JSON object stays invalid_recipe_json.
func TestInvalidRecipeIsSeparateFromInvalidRecipeJSON(t *testing.T) {
	const timestamp = int64(1700000000)
	tests := []struct {
		name   string
		recipe string
		reason ReasonCode
	}{
		{name: "malformed JSON", recipe: `{`, reason: ReasonInvalidRecipeJSON},
		{name: "non-object root", recipe: `[]`, reason: ReasonInvalidRecipeJSON},
		{name: "unknown step", recipe: `{"b":[{"x":["body line"]}]}`, reason: ReasonInvalidRecipe},
		{name: "copy range outside its source", recipe: `{"b":[{"c":[1,99]}]}`, reason: ReasonInvalidRecipe},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, key := signedPublicHistoriedMessageWithRecipe(t, timestamp, test.recipe)
			verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
				return FoundRSAPublicKey(key), nil
			}), WithVerificationClock(func() time.Time { return time.Unix(timestamp, 0) }))
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}
			result, err := verifier.Verify(context.Background(), NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
			if err != nil || result.State() != ResultStatePERMERROR || result.PrimaryReason() != test.reason || !result.Valid() {
				t.Fatalf("Verify() = %q/%q valid=%t error=%v", result.State(), result.PrimaryReason(), result.Valid(), err)
			}
		})
	}
}

// TestTransitSigningRefusesNullBodyHistory reproduces Draft-08 Sections 12
// and 13 at the transit and revision signing gate: a hop may itself emit a
// null body Recipe (Section 12.1 MAY), but the resulting message is not a
// Fully Verified DKIM2 Message, so the next hop's VerifyForRevision issues
// no capability and SignExisting cannot be reached.
func TestTransitSigningRefusesNullBodyHistory(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	origin := fixture.signOrigin(t, []byte("From: alice@example.test\r\nSubject: header only\r\n"), RouteDisclosureSingle)
	_, capability, err := fixture.facade.VerifyForRevision(context.Background(), NewVerifyRequest(
		origin, []byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")},
	))
	if err != nil || !capability.Valid() {
		t.Fatalf("origin VerifyForRevision() capability=%t error=%v", capability.Valid(), err)
	}
	revised := append(append([]byte(nil), origin...), []byte("\r\nnew body\r\n")...)
	signed, recovery, err := fixture.facade.SignExisting(context.Background(), NewExistingSigningRequest(
		capability, revised, []byte("<relay@example.net>"), [][]byte{[]byte("<carol@next.test>")},
		fixture.existingTicket(t, capability, revised, RouteDisclosureSingle),
		fixture.existingProfile, SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
		AllowUnavailableBody, RecipeCopyOnly,
	))
	output, ok := signed.Unrestricted()
	if err != nil || recovery.Valid() || !ok || !output.Facts().BodyUnavailable() {
		t.Fatalf("null-body SignExisting() ok=%t recovery=%t error=%v", ok, recovery.Valid(), err)
	}
	verifier, err := NewVerifier(fixture.provider, WithVerificationClock(func() time.Time { return time.Unix(1_700_000_000, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(t.Context(), NewVerifyRequest(output.Bytes(), []byte("<relay@example.net>"), [][]byte{[]byte("<carol@next.test>")}))
	if err != nil || result.State() != ResultStateFAIL || result.PrimaryReason() != ReasonBodyHistoryUnavailable {
		t.Fatalf("next-hop Verify() = %q/%q error=%v", result.State(), result.PrimaryReason(), err)
	}
	outcome, next, err := fixture.facade.VerifyForRevision(context.Background(), NewVerifyRequest(
		output.Bytes(), []byte("<relay@example.net>"), [][]byte{[]byte("<carol@next.test>")},
	))
	if err != nil || outcome.Status() != RevisionVerificationProtocolRejected || next.Valid() {
		t.Fatalf("next-hop VerifyForRevision() = %q capability=%t error=%v", outcome.Status(), next.Valid(), err)
	}
}
