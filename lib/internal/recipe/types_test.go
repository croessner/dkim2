package recipe

import (
	"bytes"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// TestClosedEnumsRejectZeroAndFutureValues verifies all recipe vocabularies are closed.
func TestClosedEnumsRejectZeroAndFutureValues(t *testing.T) {
	for _, test := range []struct {
		name string
		ok   bool
	}{
		{"step zero", StepKind("").Known()}, {"step copy", StepKindCopy.Known()},
		{"step data", StepKindData.Known()}, {"step future", StepKind("future").Known()},
		{"body zero", BodyMode("").Known()}, {"body absent", BodyModeAbsent.Known()},
		{testBodyStepsLabel, BodyModeSteps.Known()}, {"body unavailable", BodyModeUnavailable.Known()},
		{"availability zero", BodyAvailability("").Known()}, {"availability known", BodyAvailabilityKnown.Known()},
		{"availability unavailable", BodyAvailabilityUnavailable.Known()},
	} {
		want := test.name == "step copy" || test.name == "step data" || test.name == "body absent" || test.name == testBodyStepsLabel || test.name == "body unavailable" || test.name == "availability known" || test.name == "availability unavailable"
		if test.ok != want {
			t.Fatalf("%s Known() = %t, want %t", test.name, test.ok, want)
		}
	}
}

// TestClosedModelConstructorsRejectInvalidRepresentations verifies parser callers cannot bypass invariants.
func TestClosedModelConstructorsRejectInvalidRepresentations(t *testing.T) {
	for _, literal := range [][]byte{[]byte("bad\rvalue"), []byte("bad\nvalue"), {0xff}} {
		if _, err := newDataStep([][]byte{literal}); !IsErrorCode(err, ErrorCodeInvalidLiteral) {
			t.Fatalf("newDataStep invalid literal mismatch: bytes=%d code=%s", len(literal), recipeTestErrorCode(err))
		}
	}
	copyOne, _ := newCopyStep(1, 1)
	for _, test := range []struct{ name, canonical string }{{"Bad Name", "bad name"}, {testRecipeHeaderName, "wrong"}, {"", ""}} {
		if _, err := newHeaderPlan(test.name, test.canonical, []step{copyOne}); !IsErrorCode(err, ErrorCodeInvalidHeaderName) {
			t.Fatalf("newHeaderPlan invalid name mismatch: name_bytes=%d canonical_bytes=%d code=%s", len(test.name), len(test.canonical), recipeTestErrorCode(err))
		}
	}
	first, _ := newHeaderPlan(testRecipeHeaderName, "subject", nil)
	second, _ := newHeaderPlan("subject", "subject", nil)
	if _, err := newRecipe([]headerPlan{first, second}, true, BodyModeAbsent, nil); !IsErrorCode(err, ErrorCodeHeaderNameCollision) {
		t.Fatalf("duplicate newRecipe error = %v", err)
	}
	overlap, _ := newCopyStep(1, 2)
	next, _ := newCopyStep(2, 3)
	if _, err := newHeaderPlan(testRecipeHeaderName, "subject", []step{overlap, next}); !IsErrorCode(err, ErrorCodeCopyRangeOrder) {
		t.Fatalf("overlapping header plan error = %v", err)
	}
}

// TestRecipeAndStepAccessorsAreImmutable verifies caller mutations cannot alter the closed model.
func TestRecipeAndStepAccessorsAreImmutable(t *testing.T) {
	literal := []byte("secret-marker")
	data, err := newDataStep([][]byte{literal})
	if err != nil {
		t.Fatalf("newDataStep() error = %v", err)
	}
	literal[0] = 'X'
	copyStep, err := newCopyStep(1, 2)
	if err != nil {
		t.Fatalf("newCopyStep() error = %v", err)
	}
	plan, err := newHeaderPlan(testRecipeHeaderName, "subject", []step{copyStep, data})
	if err != nil {
		t.Fatalf("newHeaderPlan() error = %v", err)
	}
	recipe, err := newRecipe([]headerPlan{plan}, true, BodyModeAbsent, nil)
	if err != nil {
		t.Fatalf("newRecipe() error = %v", err)
	}

	steps := recipe.headerPlans()[0].stepsCopy()
	values := steps[1].dataValues()
	values[0][0] = 'Y'
	if got := recipe.headerPlans()[0].stepsCopy()[1].dataValues()[0]; !bytes.Equal(got, []byte("secret-marker")) {
		t.Fatalf("stored literal mutated: bytes=%d", len(got))
	}
	names := recipe.HeaderNames()
	names[0] = "Changed"
	if got := recipe.HeaderNames()[0]; got != testRecipeHeaderName {
		t.Fatalf("stored name mutated: bytes=%d", len(got))
	}
	if !recipe.Valid() || !recipe.HasHeaderRecipe() || recipe.BodyMode() != BodyModeAbsent {
		t.Fatalf("recipe contract invalid: valid=%t headers=%d body_mode=%s", recipe.Valid(), len(recipe.HeaderNames()), recipe.BodyMode())
	}
}

// TestStateRejectsZeroAndClonesRawMessage verifies controlled state ownership.
func TestStateRejectsZeroAndClonesRawMessage(t *testing.T) {
	if (State{}).Valid() {
		t.Fatal("zero State unexpectedly valid")
	}
	message, err := rawmsg.Parse([]byte("Subject: value\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}
	state, err := NewState(message)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	if !state.Valid() || state.BodyState() != BodyAvailabilityKnown {
		t.Fatalf("state invalid: valid=%t body_state=%s", state.Valid(), state.BodyState())
	}
	body, ok := state.Body()
	if !ok {
		t.Fatal("Body() unavailable")
	}
	bytesView := body.Bytes()
	bytesView[0] = 'X'
	bodyAgain, _ := state.Body()
	if got := bodyAgain.Bytes(); !bytes.Equal(got, []byte("body\r\n")) {
		t.Fatalf("state body mutated: bytes=%d", len(got))
	}
	materialized, err := state.Materialize()
	if err != nil {
		t.Fatalf("Materialize() error = %v", err)
	}
	if got := materialized.RawBytes(); !bytes.Equal(got, message.RawBytes()) {
		t.Fatalf("Materialize bytes mismatch: got=%d want=%d", len(got), len(message.RawBytes()))
	}
}

// TestStatePreservesFramingAndUnavailableBody verifies identity and null-body contracts.
func TestStatePreservesFramingAndUnavailableBody(t *testing.T) {
	for _, raw := range [][]byte{[]byte("A: b\r\n"), []byte("A: b\r\n\r\n")} {
		message, err := rawmsg.Parse(raw)
		if err != nil {
			t.Fatalf("Parse error: input_bytes=%d", len(raw))
		}
		state, err := NewState(message)
		if err != nil {
			t.Fatalf("NewState() error = %v", err)
		}
		materialized, err := state.Materialize()
		if err != nil {
			t.Fatalf("Materialize() error = %v", err)
		}
		if !bytes.Equal(materialized.RawBytes(), raw) {
			t.Fatalf("framing mismatch: got_bytes=%d want_bytes=%d", len(materialized.RawBytes()), len(raw))
		}
	}
	message, _ := rawmsg.Parse([]byte("A: b\r\n\r\nbody"))
	unavailable, err := newUnavailableState(message.Headers())
	if err != nil {
		t.Fatalf("newUnavailableState() error = %v", err)
	}
	if !unavailable.Valid() || unavailable.BodyState() != BodyAvailabilityUnavailable {
		t.Fatalf("unavailable state invalid: valid=%t body_state=%s", unavailable.Valid(), unavailable.BodyState())
	}
	if _, ok := unavailable.Body(); ok {
		t.Fatal("unavailable Body() returned bytes")
	}
	if _, err := unavailable.Materialize(); !IsErrorCode(err, ErrorCodeInvalidState) {
		t.Fatalf("Materialize unavailable error = %v", err)
	}
	headers := unavailable.Headers().OriginalBytes()
	headers[0] = 'X'
	if got := unavailable.Headers().OriginalBytes(); !bytes.Equal(got, []byte("A: b\r\n")) {
		t.Fatalf("headers mutated: bytes=%d", len(got))
	}
}
