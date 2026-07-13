package recipe

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
)

type applyLimitCheck struct {
	name      string
	current   []byte
	plan      string
	exact     int
	limitName string
	set       func(*Limits, int)
}

// TestApplyHeadersReconstructsBottomUpGroups verifies draft-04 copy, data, folding, and ordering.
func TestApplyHeadersReconstructsBottomUpGroups(t *testing.T) {
	current := mustRecipeState(t, []byte("Zed: z\r\nSubject: top\r\nSubject: folded\r\n value\r\nAlpha: a\r\n\r\nbody\r\n"))
	plan := mustParseRecipe(t, `{"h":{"Subject":[{"c":[1,1]},{"d":["restored"]}]}}`)
	state, usage, err := mustApplier(t, Limits{}).applyHeaders(current, plan)
	if err != nil || !state.Valid() || !usage.Valid() {
		t.Fatalf("apply invalid: state=%t usage=%t code=%s", state.Valid(), usage.Valid(), recipeTestErrorCode(err))
	}
	want := []byte("Alpha: a\r\nSubject:restored\r\nSubject: folded\r\n value\r\nZed: z\r\n")
	if got := state.Headers().OriginalBytes(); !bytes.Equal(got, want) {
		t.Fatalf("header mismatch: got_bytes=%d want_bytes=%d", len(got), len(want))
	}
	if body, ok := state.Body(); !ok || !bytes.Equal(body.Bytes(), []byte("body\r\n")) {
		t.Fatalf("body changed: known=%t bytes=%d", ok, body.Len())
	}
}

// TestApplyHeadersPreservesAbsentDimensionIdentity verifies exact known and unavailable state identity.
func TestApplyHeadersPreservesAbsentDimensionIdentity(t *testing.T) {
	for _, input := range [][]byte{[]byte("B: two\r\nA: one\r\n"), []byte("B: two\r\nA: one\r\n\r\nbody")} {
		current := mustRecipeState(t, input)
		state, _, err := mustApplier(t, Limits{}).applyHeaders(current, mustParseRecipe(t, `{"b":[]}`))
		if err != nil || !bytes.Equal(state.Headers().OriginalBytes(), current.Headers().OriginalBytes()) || state.BodyState() != current.BodyState() {
			t.Fatalf("known identity failed: bytes=%d code=%s", len(input), recipeTestErrorCode(err))
		}
		materialized, err := state.Materialize()
		if err != nil || !bytes.Equal(materialized.RawBytes(), input) || materialized.Framing() != current.framing {
			t.Fatalf("known framing changed: bytes=%d", len(input))
		}
	}
	known := mustRecipeState(t, []byte("A: one\r\n\r\nbody"))
	unavailable, err := newUnavailableState(known.Headers())
	if err != nil {
		t.Fatal("unavailable setup failed")
	}
	state, _, err := mustApplier(t, Limits{}).applyHeaders(unavailable, mustParseRecipe(t, `{"b":[]}`))
	if err != nil || state.BodyState() != BodyAvailabilityUnavailable || !bytes.Equal(state.Headers().OriginalBytes(), unavailable.Headers().OriginalBytes()) {
		t.Fatalf("unavailable identity failed: code=%s", recipeTestErrorCode(err))
	}
}

// TestApplyHeadersReversesEveryEmission verifies multi-copy, multi-data, and mixed-step ordering.
func TestApplyHeadersReversesEveryEmission(t *testing.T) {
	current := mustRecipeState(t, []byte("x-Mix: top\r\nX-MIX: folded\r\n value\r\nx-mix: bottom\r\n\r\n"))
	plan := mustParseRecipe(t, `{"h":{"X-Mix":[{"c":[1,2]},{"d":["","Grüße"]},{"c":[3,3]}]}}`)
	state, _, err := mustApplier(t, Limits{}).applyHeaders(current, plan)
	if err != nil {
		t.Fatalf("apply code=%s", recipeTestErrorCode(err))
	}
	want := []byte("x-Mix: top\r\nX-Mix:Grüße\r\nX-Mix:\r\nX-MIX: folded\r\n value\r\nx-mix: bottom\r\n")
	if !bytes.Equal(state.Headers().OriginalBytes(), want) {
		t.Fatalf("mixed ordering mismatch: got_bytes=%d want_bytes=%d", len(state.Headers().OriginalBytes()), len(want))
	}
}

// TestApplyHeadersHandlesMissingSourceGroup verifies data, removal, and copy semantics without source occurrences.
func TestApplyHeadersHandlesMissingSourceGroup(t *testing.T) {
	current := mustRecipeState(t, []byte("A: one\r\n\r\n"))
	dataState, _, err := mustApplier(t, Limits{}).applyHeaders(current, mustParseRecipe(t, `{"h":{"Missing":[{"d":["made"]}]}}`))
	if err != nil || !bytes.Contains(dataState.Headers().OriginalBytes(), []byte("Missing:made\r\n")) {
		t.Fatalf("missing data failed: code=%s", recipeTestErrorCode(err))
	}
	emptyState, _, err := mustApplier(t, Limits{}).applyHeaders(current, mustParseRecipe(t, `{"h":{"Missing":[]}}`))
	if err != nil || !bytes.Equal(emptyState.Headers().OriginalBytes(), []byte("A: one\r\n")) {
		t.Fatalf("missing removal failed: code=%s", recipeTestErrorCode(err))
	}
	failed, usage, err := mustApplier(t, Limits{}).applyHeaders(current, mustParseRecipe(t, `{"h":{"Missing":[{"c":[1,1]}]}}`))
	if failed.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeCopyRangeOutOfBounds) {
		t.Fatalf("missing copy mismatch: code=%s", recipeTestErrorCode(err))
	}
}

// TestApplyHeadersMechanicallyRestoresExcludedClass verifies recipe does not own canonical exclusions.
func TestApplyHeadersMechanicallyRestoresExcludedClass(t *testing.T) {
	current := mustRecipeState(t, []byte("Subject: one\r\n\r\n"))
	state, _, err := mustApplier(t, Limits{}).applyHeaders(current, mustParseRecipe(t, `{"h":{"Received":[{"d":["restored"]}]}}`))
	if err != nil || !bytes.Contains(state.Headers().OriginalBytes(), []byte("Received:restored\r\n")) {
		t.Fatalf("mechanical reconstruction failed: code=%s", recipeTestErrorCode(err))
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatal("canonicalizer setup failed")
	}
	input, err := canonicalizer.HeaderHashInput(state.Headers())
	if err != nil || input.Metadata().ExcludedHeaderCounts.Received != 1 {
		t.Fatal("canonical exclusion ownership changed")
	}
}

// TestApplyHeadersRemovesRetainsAndMatchesCaseInsensitively verifies named replacement semantics.
func TestApplyHeadersRemovesRetainsAndMatchesCaseInsensitively(t *testing.T) {
	current := mustRecipeState(t, []byte("Keep: one\r\nSubject: old\r\nRemove: gone\r\n\r\nbody"))
	plan := mustParseRecipe(t, `{"h":{"remove":[],"sUbJeCt":[{"d":["new"]}]}}`)
	state, _, err := mustApplier(t, Limits{}).applyHeaders(current, plan)
	if err != nil {
		t.Fatalf("apply code=%s", recipeTestErrorCode(err))
	}
	want := []byte("Keep: one\r\nsUbJeCt:new\r\n")
	if got := state.Headers().OriginalBytes(); !bytes.Equal(got, want) {
		t.Fatalf("replacement mismatch: got_bytes=%d want_bytes=%d", len(got), len(want))
	}
}

// TestApplyHeadersCanProduceInitializedEmptyBlock verifies removing every field is valid.
func TestApplyHeadersCanProduceInitializedEmptyBlock(t *testing.T) {
	current := mustRecipeState(t, []byte("Only: value\r\n\r\nbody"))
	state, usage, err := mustApplier(t, Limits{}).applyHeaders(current, mustParseRecipe(t, `{"h":{"Only":[]}}`))
	if err != nil || !state.Valid() || !state.Headers().Initialized() || state.Headers().Len() != 0 {
		t.Fatalf("empty result invalid: state=%t headers=%d code=%s", state.Valid(), state.Headers().Len(), recipeTestErrorCode(err))
	}
	if usage.Items() != 1 || usage.EmittedBytes() != 0 || usage.WorkUnits() != 1 {
		t.Fatalf("empty usage: items=%d emitted=%d work=%d", usage.Items(), usage.EmittedBytes(), usage.WorkUnits())
	}
}

// TestApplyHeadersUsageChargesEmissionExactly verifies one examined and one emitted field plus bytes.
func TestApplyHeadersUsageChargesEmissionExactly(t *testing.T) {
	current := mustRecipeState(t, []byte("A: old\r\n\r\n"))
	plan := mustParseRecipe(t, testHeaderDataXRecipe)
	_, usage, err := mustApplier(t, Limits{}).applyHeaders(current, plan)
	if err != nil {
		t.Fatalf("apply code=%s", recipeTestErrorCode(err))
	}
	if usage.DecodedBytes() != 0 || usage.EmittedBytes() != 5 || usage.Items() != 2 || usage.WorkUnits() != 7 {
		t.Fatalf("usage mismatch: decoded=%d emitted=%d items=%d work=%d", usage.DecodedBytes(), usage.EmittedBytes(), usage.Items(), usage.WorkUnits())
	}
}

// TestApplyHeadersRejectsOutOfBoundsWithoutPartialState verifies transactional range failure.
func TestApplyHeadersRejectsOutOfBoundsWithoutPartialState(t *testing.T) {
	current := mustRecipeState(t, []byte("A: one\r\n\r\nbody"))
	plan := mustParseRecipe(t, `{"h":{"A":[{"c":[2,2]}]}}`)
	state, usage, err := mustApplier(t, Limits{}).applyHeaders(current, plan)
	if state.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeCopyRangeOutOfBounds) {
		t.Fatalf("failure mismatch: state=%t usage=%t code=%s", state.Valid(), usage.Valid(), recipeTestErrorCode(err))
	}
	if usage.Items() != 1 || usage.WorkUnits() != 1 {
		t.Fatalf("failure usage: items=%d work=%d", usage.Items(), usage.WorkUnits())
	}
}

// TestApplyHeadersRejectsInvalidContracts verifies fail-closed zero-value behavior.
func TestApplyHeadersRejectsInvalidContracts(t *testing.T) {
	current := mustRecipeState(t, []byte("A: one\r\n\r\n"))
	plan := mustParseRecipe(t, testHeaderRemovalRecipe)
	valid := mustApplier(t, Limits{})
	for _, test := range []struct {
		name    string
		applier Applier
		state   State
		plan    Recipe
	}{{"applier", Applier{}, current, plan}, {"state", valid, State{}, plan}, {"recipe", valid, current, Recipe{}}} {
		t.Run(test.name, func(t *testing.T) {
			state, usage, err := test.applier.applyHeaders(test.state, test.plan)
			if state.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeInvalidState) {
				t.Fatalf("contract mismatch: state=%t usage=%t code=%s", state.Valid(), usage.Valid(), recipeTestErrorCode(err))
			}
		})
	}
}

// TestApplyHeadersEnforcesOutputAndWorkLimits verifies exact/over transactional ceilings.
func TestApplyHeadersEnforcesOutputAndWorkLimits(t *testing.T) {
	checks := []applyLimitCheck{
		{"source fields", []byte("A:x\r\nA:y\r\n\r\n"), testHeaderRemovalRecipe, 2, limitNameMaxHeaderFields, func(l *Limits, n int) { l.MaxHeaderFields = n }},
		{"output fields", []byte("A:x\r\n\r\n"), `{"h":{"A":[{"d":["x","y"]}]}}`, 2, limitNameMaxHeaderFields, func(l *Limits, n int) { l.MaxHeaderFields = n }},
		{"source names", []byte("A:x\r\nB:y\r\n\r\n"), testHeaderRemovalRecipe, 2, limitNameMaxHeaderNames, func(l *Limits, n int) { l.MaxHeaderNames = n }},
		{"output names", []byte("A:x\r\n\r\n"), `{"h":{"B":[{"d":["y"]}]}}`, 2, limitNameMaxHeaderNames, func(l *Limits, n int) { l.MaxHeaderNames = n }},
		{"source field bytes", []byte("A:x\r\n\r\n"), testHeaderRemovalRecipe, 5, limitNameMaxHeaderFieldBytes, func(l *Limits, n int) { l.MaxHeaderFieldBytes = n }},
		{"output field bytes", []byte("A:x\r\n\r\n"), testHeaderDataXYRecipe, 6, limitNameMaxHeaderFieldBytes, func(l *Limits, n int) { l.MaxHeaderFieldBytes = n }},
		{"source line bytes", []byte("A:x\r\n\r\n"), testHeaderRemovalRecipe, 3, limitNameMaxHeaderLineBytes, func(l *Limits, n int) { l.MaxHeaderLineBytes = n }},
		{"output line bytes", []byte("A:x\r\n\r\n"), testHeaderDataXYRecipe, 4, limitNameMaxHeaderLineBytes, func(l *Limits, n int) { l.MaxHeaderLineBytes = n }},
		{"source header bytes", []byte("A:x\r\nB:y\r\n\r\n"), testHeaderRemovalRecipe, 10, limitNameMaxHeaderBytes, func(l *Limits, n int) { l.MaxHeaderBytes = n }},
		{"output header bytes", []byte("A:x\r\n\r\n"), testHeaderDataXYRecipe, 6, limitNameMaxHeaderBytes, func(l *Limits, n int) { l.MaxHeaderBytes = n }},
		{testStateBytesLabel, []byte("A:x\r\n\r\nb\r\n"), testHeaderDataXRecipe, 10, limitNameMaxStateBytes, func(l *Limits, n int) { l.MaxStateBytes = n }},
		{"copy range", []byte("A:x\r\nA:y\r\n\r\n"), `{"h":{"A":[{"c":[1,2]}]}}`, 2, limitNameMaxCopiedItemsPerRange, func(l *Limits, n int) { l.MaxCopiedItemsPerRange = n }},
		{"total copies", []byte("A:x\r\nB:y\r\n\r\n"), `{"h":{"A":[{"c":[1,1]}],"B":[{"c":[1,1]}]}}`, 2, limitNameMaxTotalCopiedItems, func(l *Limits, n int) { l.MaxCopiedItemsPerRange = 1; l.MaxTotalCopiedItems = n }},
		{"operation work", []byte("A:x\r\n\r\n"), testHeaderDataXRecipe, 7, limitNameMaxOperationWorkUnits, func(l *Limits, n int) { l.MaxOperationWorkUnits = n }},
	}
	runApplyLimitChecks(t, checks, Applier.applyHeaders)
}

// TestApplyHeadersEnforcesNameBudgetsAcrossSourceAndPlan verifies distinct union accounting.
func TestApplyHeadersEnforcesNameBudgetsAcrossSourceAndPlan(t *testing.T) {
	checks := []applyLimitCheck{
		{"source name", []byte("Long:x\r\n\r\n"), testBodyEmptyRecipe, 4, limitNameMaxHeaderNameBytes, func(l *Limits, n int) { l.MaxHeaderNameBytes = n }},
		{"plan name", []byte("A:x\r\n\r\n"), `{"h":{"Long":[]}}`, 4, limitNameMaxHeaderNameBytes, func(l *Limits, n int) { l.MaxHeaderNameBytes = n }},
		{"source plan union", []byte("AA:x\r\n\r\n"), `{"h":{"BBB":[]}}`, 5, limitNameMaxTotalHeaderNameBytes, func(l *Limits, n int) { l.MaxTotalHeaderNameBytes = n }},
		{"case folded union", []byte("Name:x\r\n\r\n"), `{"h":{"nAmE":[]}}`, 4, limitNameMaxTotalHeaderNameBytes, func(l *Limits, n int) { l.MaxTotalHeaderNameBytes = n }},
	}
	runApplyLimitChecks(t, checks, Applier.applyHeaders)
}

// TestApplyHeadersRevalidatesParsedPlanBudgets verifies Parser and Applier limits cannot diverge.
func TestApplyHeadersRevalidatesParsedPlanBudgets(t *testing.T) {
	checks := []applyLimitCheck{
		{testStepsPerHeaderLabel, []byte("A:x\r\n\r\n"), `{"h":{"A":[{"d":["x"]},{"d":["y"]}]}}`, 2, limitNameMaxStepsPerHeader, func(l *Limits, n int) { l.MaxStepsPerHeader = n }},
		{testTotalStepsLabel, []byte("A:x\r\nB:y\r\n\r\n"), `{"h":{"A":[{"d":["x"]}],"B":[{"d":["y"]}]}}`, 2, limitNameMaxTotalSteps, func(l *Limits, n int) { l.MaxStepsPerHeader = n; l.MaxBodySteps = n; l.MaxTotalSteps = n }},
		{testCopyRangesLabel, []byte("A:x\r\nA:y\r\n\r\n"), `{"h":{"A":[{"c":[1,1]},{"c":[2,2]}]}}`, 2, limitNameMaxCopyRanges, func(l *Limits, n int) { l.MaxCopyRanges = n }},
		{testDataStringsLabel, []byte("A:x\r\n\r\n"), `{"h":{"A":[{"d":["x","y"]}]}}`, 2, limitNameMaxDataStrings, func(l *Limits, n int) { l.MaxDataStrings = n }},
		{testDataStringBytesLabel, []byte("A:x\r\n\r\n"), testHeaderDataXYRecipe, 2, limitNameMaxDataStringBytes, func(l *Limits, n int) { l.MaxDataStringBytes = n }},
		{testLiteralBytesLabel, []byte("A:x\r\n\r\n"), `{"h":{"A":[{"d":["xy","z"]}]}}`, 3, limitNameMaxTotalLiteralBytes, func(l *Limits, n int) { l.MaxDataStringBytes = n; l.MaxTotalLiteralBytes = n }},
	}
	runApplyLimitChecks(t, checks, Applier.applyHeaders)
}

// TestApplyHeadersChargesHeaderOnlyRemovalDelimiter verifies effective framing in state limits.
func TestApplyHeadersChargesHeaderOnlyRemovalDelimiter(t *testing.T) {
	current := mustRecipeState(t, []byte("A:x\r\n"))
	plan := mustParseRecipe(t, testHeaderRemovalRecipe)
	exact := DefaultLimits()
	exact.MaxStateBytes = 2
	state, _, err := mustApplier(t, exact).applyHeaders(current, plan)
	if err != nil || !state.Valid() {
		t.Fatalf("exact delimiter rejected: code=%s", recipeTestErrorCode(err))
	}
	message, err := state.Materialize()
	if err != nil || !bytes.Equal(message.RawBytes(), []byte("\r\n")) {
		t.Fatal("empty header-only output framing mismatch")
	}
	over := DefaultLimits()
	over.MaxStateBytes = 1
	failed, usage, err := mustApplier(t, over).applyHeaders(current, plan)
	if failed.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != limitNameMaxStateBytes {
		t.Fatalf("delimiter one-over mismatch: code=%s", recipeTestErrorCode(err))
	}
}

// TestApplyHeadersUsageIncludesCopyRetentionAndSorting verifies exact accounting policy.
func TestApplyHeadersUsageIncludesCopyRetentionAndSorting(t *testing.T) {
	current := mustRecipeState(t, []byte("B:y\r\nA:x\r\n\r\n"))
	state, usage, err := mustApplier(t, Limits{}).applyHeaders(current, mustParseRecipe(t, `{"h":{"A":[{"c":[1,1]}]}}`))
	if err != nil || !state.Valid() || usage.Items() != 5 || usage.EmittedBytes() != 10 || usage.WorkUnits() != 16 {
		t.Fatalf("sorted copy usage: items=%d emitted=%d work=%d code=%s", usage.Items(), usage.EmittedBytes(), usage.WorkUnits(), recipeTestErrorCode(err))
	}
	_, retained, err := mustApplier(t, Limits{}).applyHeaders(current, mustParseRecipe(t, `{"b":[]}`))
	if err != nil || retained.Items() != 4 || retained.EmittedBytes() != 10 || retained.WorkUnits() != 14 {
		t.Fatalf("retained usage: items=%d emitted=%d work=%d", retained.Items(), retained.EmittedBytes(), retained.WorkUnits())
	}
}

// TestApplyHeadersStopsBeforeLaterOutputExpansion verifies early caps prevent later emission work.
func TestApplyHeadersStopsBeforeLaterOutputExpansion(t *testing.T) {
	current := mustRecipeState(t, []byte("A:x\r\n\r\n"))
	plan := mustParseRecipe(t, `{"h":{"A":[{"d":["first","second"]}]}}`)
	limits := DefaultLimits()
	limits.MaxHeaderFields = 1
	state, usage, err := mustApplier(t, limits).applyHeaders(current, plan)
	if state.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != limitNameMaxHeaderFields {
		t.Fatalf("early cap mismatch: code=%s limit=%s", recipeTestErrorCode(err), recipeTestLimitName(err))
	}
	if usage.Items() != 2 || usage.EmittedBytes() != len("A:second\r\n") || usage.WorkUnits() != 2+len("A:second\r\n") {
		t.Fatalf("later emission was charged: items=%d emitted=%d work=%d", usage.Items(), usage.EmittedBytes(), usage.WorkUnits())
	}
}

// TestApplyHeadersErrorsDoNotExposeInput verifies toxic source and recipe bytes stay private.
func TestApplyHeadersErrorsDoNotExposeInput(t *testing.T) {
	const marker = "TOXIC_RECIPE_MARKER"
	current := mustRecipeState(t, []byte("A:"+marker+"\r\n\r\n"))
	limits := DefaultLimits()
	limits.MaxHeaderFieldBytes = 5
	_, usage, err := mustApplier(t, limits).applyHeaders(current, mustParseRecipe(t, testHeaderRemovalRecipe))
	if err == nil || !usage.Valid() || strings.Contains(err.Error(), marker) {
		t.Fatalf("private error mismatch: code=%s", recipeTestErrorCode(err))
	}
	_, _, parseErr := mustParser(t, Limits{}).Parse([]byte(`{"h":{"` + marker + ` bad":[]}}`))
	if parseErr == nil || strings.Contains(parseErr.Error(), marker) {
		t.Fatalf("private name error mismatch: code=%s", recipeTestErrorCode(parseErr))
	}
}

// TestApplyHeadersIsRepeatableAndImmutable verifies deterministic detached output.
func TestApplyHeadersIsRepeatableAndImmutable(t *testing.T) {
	current := mustRecipeState(t, []byte("B: two\r\nA: one\r\n\r\nbody"))
	plan := mustParseRecipe(t, `{"h":{"A":[{"c":[1,1]}]}}`)
	applier := mustApplier(t, Limits{})
	first, _, err := applier.applyHeaders(current, plan)
	if err != nil {
		t.Fatal(recipeTestErrorCode(err))
	}
	second, _, err := applier.applyHeaders(current, plan)
	if err != nil {
		t.Fatal(recipeTestErrorCode(err))
	}
	exposed := first.Headers().OriginalBytes()
	exposed[0] = 'X'
	if !bytes.Equal(first.Headers().OriginalBytes(), second.Headers().OriginalBytes()) || !bytes.Equal(current.Headers().OriginalBytes(), []byte("B: two\r\nA: one\r\n")) {
		t.Fatal("immutable repeatability failed")
	}
}

// mustRecipeState parses one synthetic state without exposing bytes on failure.
func mustRecipeState(t *testing.T, input []byte) State {
	t.Helper()
	message, err := rawmsg.Parse(input)
	if err != nil {
		t.Fatalf("raw state parse failed: bytes=%d", len(input))
	}
	state, err := NewState(message)
	if err != nil {
		t.Fatalf("NewState code=%s", recipeTestErrorCode(err))
	}
	return state
}

// mustParseRecipe parses one synthetic plan without exposing JSON on failure.
func mustParseRecipe(t *testing.T, input string) Recipe {
	t.Helper()
	plan, _, err := mustParser(t, Limits{}).Parse([]byte(input))
	if err != nil {
		t.Fatalf("recipe parse failed: bytes=%d code=%s", len(input), recipeTestErrorCode(err))
	}
	return plan
}

// mustApplier constructs one header applier.
func mustApplier(t *testing.T, limits Limits) Applier {
	t.Helper()
	applier, err := NewApplier(limits)
	if err != nil {
		t.Fatalf("NewApplier code=%s", recipeTestErrorCode(err))
	}
	return applier
}

// recipeTestLimitName returns bounded limit metadata for diagnostics.
func recipeTestLimitName(err error) string {
	var recipeErr *Error
	if errors.As(err, &recipeErr) {
		return recipeErr.LimitName()
	}
	return ""
}

// runApplyLimitChecks proves exact acceptance and one-over transactional rejection.
func runApplyLimitChecks(t *testing.T, checks []applyLimitCheck, apply func(Applier, State, Recipe) (State, Usage, error)) {
	t.Helper()
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			current := mustRecipeState(t, check.current)
			plan := mustParseRecipe(t, check.plan)
			exact := DefaultLimits()
			check.set(&exact, check.exact)
			if state, _, err := apply(mustApplier(t, exact), current, plan); err != nil || !state.Valid() {
				t.Fatalf("exact rejected: code=%s", recipeTestErrorCode(err))
			}
			over := DefaultLimits()
			check.set(&over, check.exact-1)
			state, usage, err := apply(mustApplier(t, over), current, plan)
			if state.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != check.limitName {
				t.Fatalf("one-over mismatch: code=%s limit=%s", recipeTestErrorCode(err), recipeTestLimitName(err))
			}
		})
	}
}
