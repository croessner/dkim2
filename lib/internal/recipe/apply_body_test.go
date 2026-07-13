package recipe

import (
	"bytes"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// TestApplyBodyDistinguishesAbsentNullAndEmpty verifies the three body forms.
func TestApplyBodyDistinguishesAbsentNullAndEmpty(t *testing.T) {
	current := mustRecipeState(t, []byte("A:x\r\n\r\nbody\r\n"))
	absent, _, err := mustApplier(t, Limits{}).applyBody(current, mustParseRecipe(t, testHeaderRemovalRecipe))
	if err != nil || absent.BodyState() != BodyAvailabilityKnown || absent.framing != current.framing {
		t.Fatalf("absent mismatch: code=%s", recipeTestErrorCode(err))
	}
	body, ok := absent.Body()
	if !ok || !bytes.Equal(body.Bytes(), []byte("body\r\n")) {
		t.Fatal("absent body changed")
	}
	nullState, usage, err := mustApplier(t, Limits{}).applyBody(current, mustParseRecipe(t, testBodyNullRecipe))
	if err != nil || nullState.BodyState() != BodyAvailabilityUnavailable || nullState.framing != rawmsg.MessageFramingDelimited || usage.Items() != 0 {
		t.Fatalf("null mismatch: code=%s items=%d", recipeTestErrorCode(err), usage.Items())
	}
	empty, usage, err := mustApplier(t, Limits{}).applyBody(current, mustParseRecipe(t, testBodyEmptyRecipe))
	emptyBody, known := empty.Body()
	if err != nil || !known || emptyBody.Len() != 0 || empty.framing != rawmsg.MessageFramingDelimited || usage.Items() != 1 {
		t.Fatalf("empty mismatch: code=%s known=%t bytes=%d items=%d", recipeTestErrorCode(err), known, emptyBody.Len(), usage.Items())
	}
}

// TestApplyBodyCopiesTopDownAndMixesData verifies forward recipe emission order.
func TestApplyBodyCopiesTopDownAndMixesData(t *testing.T) {
	current := mustRecipeState(t, []byte("A:x\r\n\r\none\r\ntwo\r\nthree\r\n"))
	plan := mustParseRecipe(t, `{"b":[{"c":[2,2]},{"d":["x",""]},{"c":[3,3]}]}`)
	state, _, err := mustApplier(t, Limits{}).applyBody(current, plan)
	body, ok := state.Body()
	want := []byte("two\r\nx\r\n\r\nthree\r\n")
	if err != nil || !ok || !bytes.Equal(body.Bytes(), want) {
		t.Fatalf("mixed body mismatch: code=%s known=%t bytes=%d", recipeTestErrorCode(err), ok, body.Len())
	}
}

// TestApplyBodyPreservesCopiedTermination verifies final-only unterminated copies.
func TestApplyBodyPreservesCopiedTermination(t *testing.T) {
	current := mustRecipeState(t, []byte("A:x\r\n\r\none\r\ntwo"))
	state, _, err := mustApplier(t, Limits{}).applyBody(current, mustParseRecipe(t, `{"b":[{"c":[2,2]}]}`))
	body, ok := state.Body()
	if err != nil || !ok || !bytes.Equal(body.Bytes(), []byte("two")) {
		t.Fatalf("terminal copy mismatch: code=%s", recipeTestErrorCode(err))
	}
	for _, plan := range []string{
		`{"b":[{"c":[2,2]},{"d":["later"]}]}`,
	} {
		failed, usage, err := mustApplier(t, Limits{}).applyBody(current, mustParseRecipe(t, plan))
		if failed.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeInvalidState) {
			t.Fatalf("non-final unterminated accepted: code=%s", recipeTestErrorCode(err))
		}
		if usage.Items() != 3 || usage.WorkUnits() != 3 || usage.EmittedBytes() != 0 {
			t.Fatalf("termination preflight usage: items=%d work=%d emitted=%d", usage.Items(), usage.WorkUnits(), usage.EmittedBytes())
		}
	}
	complete, _, err := mustApplier(t, Limits{}).applyBody(current, mustParseRecipe(t, `{"b":[{"c":[1,2]}]}`))
	completeBody, known := complete.Body()
	if err != nil || !known || !bytes.Equal(completeBody.Bytes(), []byte("one\r\ntwo")) {
		t.Fatalf("final range rejected: code=%s", recipeTestErrorCode(err))
	}
}

// TestApplyBodyPreservesTrailingEmptyAndOpaqueBytes verifies line fidelity without text semantics.
func TestApplyBodyPreservesTrailingEmptyAndOpaqueBytes(t *testing.T) {
	current := mustRecipeState(t, append([]byte("A:x\r\n\r\nopaque:"), []byte{0xff, '\r', '\n', '\r', '\n'}...))
	state, _, err := mustApplier(t, Limits{}).applyBody(current, mustParseRecipe(t, `{"b":[{"c":[1,2]}]}`))
	body, ok := state.Body()
	want := append([]byte("opaque:"), []byte{0xff, '\r', '\n', '\r', '\n'}...)
	if err != nil || !ok || !bytes.Equal(body.Bytes(), want) {
		t.Fatalf("opaque copy mismatch: code=%s", recipeTestErrorCode(err))
	}
}

// TestApplyBodyUnavailableSourceAllowsOnlyData verifies structural source ownership.
func TestApplyBodyUnavailableSourceAllowsOnlyData(t *testing.T) {
	known := mustRecipeState(t, []byte("A:x\r\n\r\nbody"))
	unavailable, err := newUnavailableState(known.Headers())
	if err != nil {
		t.Fatal("unavailable setup failed")
	}
	failed, usage, err := mustApplier(t, Limits{}).applyBody(unavailable, mustParseRecipe(t, `{"b":[{"d":["first"]},{"c":[1,1]}]}`))
	if failed.Valid() || !usage.Valid() || usage.EmittedBytes() != 0 || !IsErrorCode(err, ErrorCodeSourceUnavailable) {
		t.Fatalf("unavailable copy mismatch: code=%s emitted=%d", recipeTestErrorCode(err), usage.EmittedBytes())
	}
	recovered, usage, err := mustApplier(t, Limits{}).applyBody(unavailable, mustParseRecipe(t, `{"b":[{"d":["restored",""]}]}`))
	body, ok := recovered.Body()
	if err != nil || !ok || !bytes.Equal(body.Bytes(), []byte("restored\r\n\r\n")) || usage.Items() != 2 {
		t.Fatalf("all-data recovery mismatch: code=%s items=%d", recipeTestErrorCode(err), usage.Items())
	}
}

// TestApplyBodyUnavailableAvailabilityMatrix verifies every source-independent form.
func TestApplyBodyUnavailableAvailabilityMatrix(t *testing.T) {
	known := mustRecipeState(t, []byte("A:x\r\n\r\nbody"))
	unavailable, err := newUnavailableState(known.Headers())
	if err != nil {
		t.Fatal("unavailable setup failed")
	}
	for _, encoded := range []string{testHeaderRemovalRecipe, testBodyNullRecipe} {
		state, _, err := mustApplier(t, Limits{}).applyBody(unavailable, mustParseRecipe(t, encoded))
		if err != nil || state.BodyState() != BodyAvailabilityUnavailable {
			t.Fatalf("unavailable propagation failed: code=%s", recipeTestErrorCode(err))
		}
	}
	state, _, err := mustApplier(t, Limits{}).applyBody(unavailable, mustParseRecipe(t, testBodyEmptyRecipe))
	body, recovered := state.Body()
	if err != nil || !recovered || body.Len() != 0 || state.framing != rawmsg.MessageFramingDelimited {
		t.Fatalf("empty recovery failed: code=%s", recipeTestErrorCode(err))
	}
}

// TestApplyBodyDistinguishesEmptySourceAndEmptyLine verifies raw line indexing boundaries.
func TestApplyBodyDistinguishesEmptySourceAndEmptyLine(t *testing.T) {
	empty := mustRecipeState(t, []byte("A:x\r\n\r\n"))
	failed, usage, err := mustApplier(t, Limits{}).applyBody(empty, mustParseRecipe(t, `{"b":[{"c":[1,1]}]}`))
	if failed.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeCopyRangeOutOfBounds) {
		t.Fatalf("empty source copy mismatch: code=%s", recipeTestErrorCode(err))
	}
	oneEmptyLine := mustRecipeState(t, []byte("A:x\r\n\r\n\r\n"))
	state, _, err := mustApplier(t, Limits{}).applyBody(oneEmptyLine, mustParseRecipe(t, `{"b":[{"c":[1,1]}]}`))
	body, known := state.Body()
	if err != nil || !known || !bytes.Equal(body.Bytes(), []byte("\r\n")) {
		t.Fatalf("empty line copy mismatch: code=%s", recipeTestErrorCode(err))
	}
}

// TestApplyBodyLiteralUTF8PreservesCodePoints verifies decoding without normalization.
func TestApplyBodyLiteralUTF8PreservesCodePoints(t *testing.T) {
	current := mustRecipeState(t, []byte("A:x\r\n\r\n"))
	escaped, _, err := mustApplier(t, Limits{}).applyBody(current, mustParseRecipe(t, `{"b":[{"d":["Gr\u00fc\u00dfe"]}]}`))
	if err != nil {
		t.Fatal(recipeTestErrorCode(err))
	}
	raw, _, err := mustApplier(t, Limits{}).applyBody(current, mustParseRecipe(t, `{"b":[{"d":["Grüße"]}]}`))
	if err != nil {
		t.Fatal(recipeTestErrorCode(err))
	}
	escapedBody, _ := escaped.Body()
	rawBody, _ := raw.Body()
	if !bytes.Equal(escapedBody.Bytes(), rawBody.Bytes()) {
		t.Fatal("escaped and raw UTF-8 differ")
	}
	composed, _, _ := mustApplier(t, Limits{}).applyBody(current, mustParseRecipe(t, `{"b":[{"d":["é"]}]}`))
	decomposed, _, _ := mustApplier(t, Limits{}).applyBody(current, mustParseRecipe(t, `{"b":[{"d":["é"]}]}`))
	composedBody, _ := composed.Body()
	decomposedBody, _ := decomposed.Body()
	if bytes.Equal(composedBody.Bytes(), decomposedBody.Bytes()) {
		t.Fatal("body literals were normalized")
	}
}

// TestApplyBodyUsageIsExact verifies examined, copied, emitted, and byte charging.
func TestApplyBodyUsageIsExact(t *testing.T) {
	current := mustRecipeState(t, []byte("A:x\r\n\r\none\r\ntwo\r\n"))
	_, usage, err := mustApplier(t, Limits{}).applyBody(current, mustParseRecipe(t, `{"b":[{"c":[1,1]}]}`))
	if err != nil || usage.Items() != 4 || usage.EmittedBytes() != 5 || usage.WorkUnits() != 9 {
		t.Fatalf("copy usage mismatch: items=%d emitted=%d work=%d code=%s", usage.Items(), usage.EmittedBytes(), usage.WorkUnits(), recipeTestErrorCode(err))
	}
	_, usage, err = mustApplier(t, Limits{}).applyBody(current, mustParseRecipe(t, testBodyDataXRecipe))
	if err != nil || usage.Items() != 3 || usage.EmittedBytes() != 3 || usage.WorkUnits() != 6 {
		t.Fatalf("data usage mismatch: items=%d emitted=%d work=%d", usage.Items(), usage.EmittedBytes(), usage.WorkUnits())
	}
}

// TestApplyBodyEnforcesLimitsIncrementally verifies exact and one-over body ceilings.
func TestApplyBodyEnforcesLimitsIncrementally(t *testing.T) {
	checks := []applyLimitCheck{
		{"source lines", []byte("A:x\r\n\r\na\r\nb\r\n"), testBodyEmptyRecipe, 2, limitNameMaxBodyLines, func(l *Limits, n int) { l.MaxBodyLines = n }},
		{"output lines", []byte("A:x\r\n\r\na\r\n"), `{"b":[{"d":["x","y"]}]}`, 2, limitNameMaxBodyLines, func(l *Limits, n int) { l.MaxBodyLines = n }},
		{"source line bytes", []byte("A:x\r\n\r\nxy\r\n"), testBodyEmptyRecipe, 2, limitNameMaxBodyLineBytes, func(l *Limits, n int) { l.MaxBodyLineBytes = n }},
		{"output line bytes", []byte("A:x\r\n\r\nx\r\n"), `{"b":[{"d":["xy"]}]}`, 2, limitNameMaxBodyLineBytes, func(l *Limits, n int) { l.MaxBodyLineBytes = n }},
		{testStateBytesLabel, []byte("A:x\r\n\r\na\r\n"), testBodyDataXRecipe, 10, limitNameMaxStateBytes, func(l *Limits, n int) { l.MaxStateBytes = n }},
		{"operation work", []byte("A:x\r\n\r\na\r\n"), testBodyDataXRecipe, 5, limitNameMaxOperationWorkUnits, func(l *Limits, n int) { l.MaxOperationWorkUnits = n }},
	}
	runApplyLimitChecks(t, checks, Applier.applyBody)
}

// TestApplyBodyStopsBeforeLaterOutput verifies output caps prevent later line charging.
func TestApplyBodyStopsBeforeLaterOutput(t *testing.T) {
	current := mustRecipeState(t, []byte("A:x\r\n\r\nsource\r\n"))
	limits := DefaultLimits()
	limits.MaxStateBytes = 10
	state, usage, err := mustApplier(t, limits).applyBody(current, mustParseRecipe(t, `{"b":[{"d":["x","later"]}]}`))
	if state.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != limitNameMaxStateBytes {
		t.Fatalf("early body cap mismatch: code=%s", recipeTestErrorCode(err))
	}
	if usage.Items() != 2 || usage.EmittedBytes() != 3 || usage.WorkUnits() != 5 {
		t.Fatalf("later body output charged: items=%d emitted=%d work=%d", usage.Items(), usage.EmittedBytes(), usage.WorkUnits())
	}
	if err.(*Error).Dimension() != DimensionBody {
		t.Fatalf("wrong limit dimension: %s", err.(*Error).Dimension())
	}
}

// TestApplyBodyRevalidatesStructuralPlanLimits verifies narrow Applier limits.
func TestApplyBodyRevalidatesStructuralPlanLimits(t *testing.T) {
	checks := []applyLimitCheck{
		{testBodyStepsLabel, []byte("A:x\r\n\r\na\r\n"), `{"b":[{"d":["x"]},{"d":["y"]}]}`, 2, limitNameMaxBodySteps, func(l *Limits, n int) { l.MaxBodySteps = n }},
		{"combined steps", []byte("A:x\r\n\r\na\r\n"), `{"h":{"A":[{"d":["x"]}]},"b":[{"d":["y"]}]}`, 2, limitNameMaxTotalSteps, func(l *Limits, n int) { l.MaxStepsPerHeader = n; l.MaxBodySteps = n; l.MaxTotalSteps = n }},
		{testCopyRangesLabel, []byte("A:x\r\n\r\na\r\nb\r\n"), `{"b":[{"c":[1,1]},{"c":[2,2]}]}`, 2, limitNameMaxCopyRanges, func(l *Limits, n int) { l.MaxCopyRanges = n }},
		{"copy per range", []byte("A:x\r\n\r\na\r\nb\r\n"), `{"b":[{"c":[1,2]}]}`, 2, limitNameMaxCopiedItemsPerRange, func(l *Limits, n int) { l.MaxCopiedItemsPerRange = n }},
		{"total copies", []byte("A:x\r\n\r\na\r\nb\r\n"), `{"b":[{"c":[1,1]},{"c":[2,2]}]}`, 2, limitNameMaxTotalCopiedItems, func(l *Limits, n int) { l.MaxCopiedItemsPerRange = n; l.MaxTotalCopiedItems = n }},
		{testDataStringsLabel, []byte("A:x\r\n\r\na\r\n"), `{"b":[{"d":["x","y"]}]}`, 2, limitNameMaxDataStrings, func(l *Limits, n int) { l.MaxDataStrings = n }},
		{testDataStringBytesLabel, []byte("A:x\r\n\r\na\r\n"), `{"b":[{"d":["xy"]}]}`, 2, limitNameMaxDataStringBytes, func(l *Limits, n int) { l.MaxDataStringBytes = n }},
		{testLiteralBytesLabel, []byte("A:x\r\n\r\na\r\n"), `{"b":[{"d":["xy","z"]}]}`, 3, limitNameMaxTotalLiteralBytes, func(l *Limits, n int) { l.MaxDataStringBytes = n; l.MaxTotalLiteralBytes = n }},
	}
	runApplyLimitChecks(t, checks, Applier.applyBody)
}

// TestApplyBodyHeaderOnlyBecomesDelimited verifies separator state accounting.
func TestApplyBodyHeaderOnlyBecomesDelimited(t *testing.T) {
	current := mustRecipeState(t, []byte("A:x\r\n"))
	plan := mustParseRecipe(t, testBodyDataXRecipe)
	exact := DefaultLimits()
	exact.MaxStateBytes = 10
	state, _, err := mustApplier(t, exact).applyBody(current, plan)
	message, materializeErr := state.Materialize()
	if err != nil || materializeErr != nil || !bytes.Equal(message.RawBytes(), []byte("A:x\r\n\r\nx\r\n")) {
		t.Fatalf("header-only transition mismatch: code=%s", recipeTestErrorCode(err))
	}
	over := DefaultLimits()
	over.MaxStateBytes = 9
	failed, usage, err := mustApplier(t, over).applyBody(current, plan)
	if failed.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != limitNameMaxStateBytes {
		t.Fatalf("separator limit mismatch: code=%s", recipeTestErrorCode(err))
	}
}

// TestApplyCombinesDimensionsUnderOneBudget verifies public orchestration and cumulative work.
func TestApplyCombinesDimensionsUnderOneBudget(t *testing.T) {
	current := mustRecipeState(t, []byte("B:y\r\nA:x\r\n\r\nold\r\n"))
	plan := mustParseRecipe(t, `{"h":{"A":[{"d":["new"]}]},"b":[{"d":["body"]}]}`)
	state, usage, err := mustApplier(t, Limits{}).Apply(current, plan)
	body, known := state.Body()
	if err != nil || !state.Valid() || !known || !bytes.Equal(body.Bytes(), []byte("body\r\n")) || !bytes.Contains(state.Headers().OriginalBytes(), []byte("A:new\r\n")) {
		t.Fatalf("combined apply mismatch: code=%s", recipeTestErrorCode(err))
	}
	if usage.Items() != 6 || usage.EmittedBytes() != 18 || usage.WorkUnits() != 25 {
		t.Fatalf("combined usage mismatch: items=%d emitted=%d work=%d", usage.Items(), usage.EmittedBytes(), usage.WorkUnits())
	}
	limits := DefaultLimits()
	limits.MaxOperationWorkUnits = usage.WorkUnits() - 1
	failed, failedUsage, err := mustApplier(t, limits).Apply(current, plan)
	if failed.Valid() || !failedUsage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != limitNameMaxOperationWorkUnits {
		t.Fatalf("combined budget mismatch: code=%s work=%d", recipeTestErrorCode(err), failedUsage.WorkUnits())
	}
}

// TestApplyUsesFinalCombinedStateForLimits verifies shrinking either dimension is allowed.
func TestApplyUsesFinalCombinedStateForLimits(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxStateBytes = 10
	applier := mustApplier(t, limits)
	largeBody := mustRecipeState(t, []byte("A:x\r\n\r\nthis body is deliberately large\r\n"))
	state, _, err := applier.Apply(largeBody, mustParseRecipe(t, `{"h":{"A":[{"d":["x"]}]},"b":[{"d":["y"]}]}`))
	if err != nil || !state.Valid() {
		t.Fatalf("body shrink rejected: code=%s", recipeTestErrorCode(err))
	}
	largeHeaders := mustRecipeState(t, []byte("A:x\r\nLarge: deliberately-long\r\n\r\nold\r\n"))
	state, _, err = applier.Apply(largeHeaders, mustParseRecipe(t, `{"h":{"Large":[]},"b":[{"d":["y"]}]}`))
	if err != nil || !state.Valid() {
		t.Fatalf("header shrink rejected: code=%s", recipeTestErrorCode(err))
	}
}

// TestApplyBodyRejectsInvalidContracts verifies zero-value failures are disjoint.
func TestApplyBodyRejectsInvalidContracts(t *testing.T) {
	current := mustRecipeState(t, []byte("A:x\r\n\r\nbody"))
	plan := mustParseRecipe(t, testBodyEmptyRecipe)
	valid := mustApplier(t, Limits{})
	for _, test := range []struct {
		name    string
		applier Applier
		state   State
		plan    Recipe
	}{{"applier", Applier{}, current, plan}, {"state", valid, State{}, plan}, {"recipe", valid, current, Recipe{}}} {
		t.Run(test.name, func(t *testing.T) {
			state, usage, err := test.applier.applyBody(test.state, test.plan)
			if state.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeInvalidState) {
				t.Fatalf("applyBody contract mismatch: code=%s", recipeTestErrorCode(err))
			}
			state, usage, err = test.applier.Apply(test.state, test.plan)
			if state.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeInvalidState) {
				t.Fatalf("Apply contract mismatch: code=%s", recipeTestErrorCode(err))
			}
		})
	}
}

// TestApplyRejectsUnavailableCopyBeforeHeaderWork verifies structural error precedence.
func TestApplyRejectsUnavailableCopyBeforeHeaderWork(t *testing.T) {
	known := mustRecipeState(t, []byte("A:x\r\n\r\nbody"))
	unavailable, _ := newUnavailableState(known.Headers())
	state, usage, err := mustApplier(t, Limits{}).Apply(unavailable, mustParseRecipe(t, `{"h":{"A":[{"d":["changed"]}]},"b":[{"c":[1,1]}]}`))
	if state.Valid() || usage.Items() != 0 || usage.EmittedBytes() != 0 || !IsErrorCode(err, ErrorCodeSourceUnavailable) {
		t.Fatalf("unavailable precedence mismatch: code=%s items=%d", recipeTestErrorCode(err), usage.Items())
	}
}

// TestApplyBodyPreflightWorkLimitPrecedesHeaderEmission verifies live shared accounting.
func TestApplyBodyPreflightWorkLimitPrecedesHeaderEmission(t *testing.T) {
	current := mustRecipeState(t, []byte("A:x\r\n\r\none\r\ntwo\r\n"))
	plan := mustParseRecipe(t, `{"h":{"A":[{"d":["changed"]}]},"b":[]}`)
	limits := DefaultLimits()
	limits.MaxOperationWorkUnits = 1
	state, usage, err := mustApplier(t, limits).Apply(current, plan)
	if state.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != limitNameMaxOperationWorkUnits {
		t.Fatalf("preflight work mismatch: code=%s", recipeTestErrorCode(err))
	}
	if usage.Items() != 1 || usage.WorkUnits() != 1 || usage.EmittedBytes() != 0 {
		t.Fatalf("header work preceded body preflight: items=%d work=%d emitted=%d", usage.Items(), usage.WorkUnits(), usage.EmittedBytes())
	}
}

// TestApplyBodyIsImmutableRepeatableAndPrivate verifies detached output and bounded failures.
func TestApplyBodyIsImmutableRepeatableAndPrivate(t *testing.T) {
	const marker = "TOXIC_BODY_MARKER"
	current := mustRecipeState(t, []byte("A:x\r\n\r\n"+marker+"\r\n"))
	plan := mustParseRecipe(t, `{"b":[{"c":[1,1]}]}`)
	applier := mustApplier(t, Limits{})
	first, _, err := applier.applyBody(current, plan)
	if err != nil {
		t.Fatal(recipeTestErrorCode(err))
	}
	second, _, err := applier.applyBody(current, plan)
	if err != nil {
		t.Fatal(recipeTestErrorCode(err))
	}
	body, _ := first.Body()
	exposed := body.Bytes()
	exposed[0] = 'X'
	firstBody, _ := first.Body()
	secondBody, _ := second.Body()
	if !bytes.Equal(firstBody.Bytes(), secondBody.Bytes()) {
		t.Fatal("body output aliases caller")
	}
	limits := DefaultLimits()
	limits.MaxBodyLineBytes = 1
	_, usage, err := mustApplier(t, limits).applyBody(current, plan)
	if err == nil || !usage.Valid() || strings.Contains(err.Error(), marker) {
		t.Fatalf("privacy mismatch: code=%s", recipeTestErrorCode(err))
	}
}
