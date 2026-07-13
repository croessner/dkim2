package recipe

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestPlanBodyUsesExactTopDownInverseSemantics verifies core body vectors.
func TestPlanBodyUsesExactTopDownInverseSemantics(t *testing.T) {
	tests := []struct {
		name        string
		previous    []byte
		current     []byte
		policy      LiteralDisclosurePolicy
		wantOutcome BodyGenerationOutcome
		wantKinds   []StepKind
		wantCopies  [][2]int
		wantData    []string
	}{
		{name: "unchanged", previous: []byte("A:x\r\n\r\na\r\n"), current: []byte("A:x\r\n\r\na\r\n"), policy: CopyOnly, wantOutcome: BodyGenerationUnchanged},
		{name: "unchanged header-only", previous: []byte("A:x\r\n"), current: []byte("A:x\r\n"), policy: CopyOnly, wantOutcome: BodyGenerationUnchanged},
		{name: "replace", previous: []byte("A:x\r\n\r\nold\r\n"), current: []byte("A:x\r\n\r\nnew\r\n"), policy: AllowLiterals, wantOutcome: BodyGenerationGenerated, wantKinds: []StepKind{StepKindData}, wantData: []string{"old"}},
		{name: "insert target", previous: []byte("A:x\r\n\r\na\r\nb\r\n"), current: []byte("A:x\r\n\r\na\r\n"), policy: AllowLiterals, wantOutcome: BodyGenerationGenerated, wantKinds: []StepKind{StepKindCopy, StepKindData}, wantCopies: [][2]int{{1, 1}}, wantData: []string{"b"}},
		{name: "delete source", previous: []byte("A:x\r\n\r\na\r\n"), current: []byte("A:x\r\n\r\na\r\nb\r\n"), policy: CopyOnly, wantOutcome: BodyGenerationGenerated, wantKinds: []StepKind{StepKindCopy}, wantCopies: [][2]int{{1, 1}}},
		{name: "empty crlf line", previous: []byte("A:x\r\n\r\n\r\n"), current: []byte("A:x\r\n\r\n"), policy: AllowLiterals, wantOutcome: BodyGenerationGenerated, wantKinds: []StepKind{StepKindData}, wantData: []string{""}},
		{name: "trailing empty line", previous: []byte("A:x\r\n\r\na\r\n\r\n"), current: []byte("A:x\r\n\r\na\r\n"), policy: AllowLiterals, wantOutcome: BodyGenerationGenerated, wantKinds: []StepKind{StepKindCopy, StepKindData}, wantCopies: [][2]int{{1, 1}}, wantData: []string{""}},
		{name: "duplicate monotone", previous: []byte("A:x\r\n\r\nd\r\nd\r\n"), current: []byte("A:x\r\n\r\nd\r\nm\r\nd\r\n"), policy: CopyOnly, wantOutcome: BodyGenerationGenerated, wantKinds: []StepKind{StepKindCopy, StepKindCopy}, wantCopies: [][2]int{{1, 1}, {3, 3}}},
		{name: "binary copy", previous: append([]byte("A:x\r\n\r\n"), 0xff, '\r', '\n'), current: append([]byte("A:x\r\n\r\nextra\r\n"), 0xff, '\r', '\n'), policy: CopyOnly, wantOutcome: BodyGenerationGenerated, wantKinds: []StepKind{StepKindCopy}, wantCopies: [][2]int{{2, 2}}},
		{name: "unterminated copy", previous: []byte("A:x\r\n\r\ntail"), current: []byte("A:x\r\n\r\nx\r\ntail"), policy: CopyOnly, wantOutcome: BodyGenerationGenerated, wantKinds: []StepKind{StepKindCopy}, wantCopies: [][2]int{{2, 2}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, _, err := mustPlanBody(t, test.previous, test.current, RejectUnavailableBody, test.policy, GenerationLimits{}, nil)
			if err != nil || !result.Valid() || result.Outcome() != test.wantOutcome {
				t.Fatalf("planBody result: valid=%t outcome=%s code=%s", result.Valid(), result.Outcome(), recipeTestErrorCode(err))
			}
			assertHeaderSteps(t, result.stepsCopy(), test.wantKinds, test.wantCopies, test.wantData)
		})
	}
}

// TestPlanBodyPinsFramingAsymmetry verifies header-only and delimited-empty distinctions.
func TestPlanBodyPinsFramingAsymmetry(t *testing.T) {
	generated, _, err := mustPlanBody(t, []byte("A:x\r\n\r\n"), []byte("A:x\r\n"), RejectUnavailableBody, CopyOnly, GenerationLimits{}, nil)
	if err != nil || generated.Outcome() != BodyGenerationGenerated || len(generated.stepsCopy()) != 0 {
		t.Fatalf("header-only to delimited-empty: outcome=%s steps=%d code=%s", generated.Outcome(), len(generated.stepsCopy()), recipeTestErrorCode(err))
	}
	failed, usage, err := mustPlanBody(t, []byte("A:x\r\n"), []byte("A:x\r\n\r\n"), RejectUnavailableBody, CopyOnly, GenerationLimits{}, nil)
	if failed.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeBodyUnrepresentable) {
		t.Fatalf("delimited to header-only rejection: valid=%t usage=%t code=%s", failed.Valid(), usage.Valid(), recipeTestErrorCode(err))
	}
	unavailable, _, err := mustPlanBody(t, []byte("A:x\r\n"), []byte("A:x\r\n\r\n"), AllowUnavailableBody, CopyOnly, GenerationLimits{}, nil)
	if err != nil || unavailable.Outcome() != BodyGenerationUnavailable || unavailable.UnavailableReason() != BodyUnavailableReasonUnrepresentable {
		t.Fatalf("authorized framing unavailable: outcome=%s reason=%s code=%s", unavailable.Outcome(), unavailable.UnavailableReason(), recipeTestErrorCode(err))
	}
}

// TestPlanBodySeparatesDisclosureAndUnavailablePolicies verifies fail-closed conversions.
func TestPlanBodySeparatesDisclosureAndUnavailablePolicies(t *testing.T) {
	previous := []byte("A:x\r\n\r\nprior\r\n")
	current := []byte("A:x\r\n\r\ncurrent\r\n")
	failed, _, err := mustPlanBody(t, previous, current, RejectUnavailableBody, CopyOnly, GenerationLimits{}, nil)
	if failed.Valid() || !IsErrorCode(err, ErrorCodeBodyUnrepresentable) {
		t.Fatalf("copy-only rejection: valid=%t code=%s", failed.Valid(), recipeTestErrorCode(err))
	}
	unavailable, _, err := mustPlanBody(t, previous, current, AllowUnavailableBody, CopyOnly, GenerationLimits{}, nil)
	if err != nil || unavailable.UnavailableReason() != BodyUnavailableReasonLiteralRequired {
		t.Fatalf("copy-only unavailable: reason=%s code=%s", unavailable.UnavailableReason(), recipeTestErrorCode(err))
	}
	for _, target := range [][]byte{
		append([]byte("A:x\r\n\r\n"), 0xff, '\r', '\n'),
		[]byte("A:x\r\n\r\ntail"),
	} {
		unavailable, _, err = mustPlanBody(t, target, current, AllowUnavailableBody, AllowLiterals, GenerationLimits{}, nil)
		if err != nil || unavailable.UnavailableReason() != BodyUnavailableReasonUnrepresentable {
			t.Fatalf("representation unavailable: reason=%s code=%s", unavailable.UnavailableReason(), recipeTestErrorCode(err))
		}
	}
}

// TestPlanBodyDistinguishesTerminatorsAndBackwardCandidates verifies exact keys and monotonicity.
func TestPlanBodyDistinguishesTerminatorsAndBackwardCandidates(t *testing.T) {
	terminatedTarget := []byte("A:x\r\n\r\nsame\r\nlater\r\n")
	unterminatedSource := []byte("A:x\r\n\r\nsame")
	result, _, err := mustPlanBody(t, terminatedTarget, unterminatedSource, RejectUnavailableBody, AllowLiterals, GenerationLimits{}, nil)
	if err != nil {
		t.Fatalf("terminator mismatch code=%s", recipeTestErrorCode(err))
	}
	assertHeaderSteps(t, result.stepsCopy(), []StepKind{StepKindData}, nil, []string{"same", "later"})
	failed, usage, err := mustPlanBody(t, terminatedTarget, unterminatedSource, RejectUnavailableBody, CopyOnly, GenerationLimits{}, nil)
	if failed.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeBodyUnrepresentable) {
		t.Fatalf("terminator copy-only: valid=%t usage=%t code=%s", failed.Valid(), usage.Valid(), recipeTestErrorCode(err))
	}

	backwardTarget := []byte("A:x\r\n\r\nz\r\ny\r\n")
	backwardSource := []byte("A:x\r\n\r\nx\r\ny\r\nz\r\n")
	result, _, err = mustPlanBody(t, backwardTarget, backwardSource, RejectUnavailableBody, AllowLiterals, GenerationLimits{}, nil)
	if err != nil {
		t.Fatalf("backward candidate code=%s", recipeTestErrorCode(err))
	}
	assertHeaderSteps(t, result.stepsCopy(), []StepKind{StepKindCopy, StepKindData}, [][2]int{{3, 3}}, []string{"y"})
}

// TestPlanBodyCoalescesAdjacentCopyAndData verifies deterministic step ownership.
func TestPlanBodyCoalescesAdjacentCopyAndData(t *testing.T) {
	copyResult, _, err := mustPlanBody(t,
		[]byte("A:x\r\n\r\nb\r\nc\r\n"), []byte("A:x\r\n\r\na\r\nb\r\nc\r\n"),
		RejectUnavailableBody, CopyOnly, GenerationLimits{}, nil)
	if err != nil {
		t.Fatalf("copy coalescing code=%s", recipeTestErrorCode(err))
	}
	assertHeaderSteps(t, copyResult.stepsCopy(), []StepKind{StepKindCopy}, [][2]int{{2, 3}}, nil)
	dataResult, _, err := mustPlanBody(t,
		[]byte("A:x\r\n\r\nb\r\nc\r\n"), []byte("A:x\r\n\r\na\r\n"),
		RejectUnavailableBody, AllowLiterals, GenerationLimits{}, nil)
	if err != nil {
		t.Fatalf("data coalescing code=%s", recipeTestErrorCode(err))
	}
	assertHeaderSteps(t, dataResult.stepsCopy(), []StepKind{StepKindData}, nil, []string{"b", "c"})
}

// TestPlanBodyBoundsAdversarialDuplicateInterleaving verifies near-linear cursor work.
func TestPlanBodyBoundsAdversarialDuplicateInterleaving(t *testing.T) {
	var previous, current strings.Builder
	previous.WriteString("A:x\r\n\r\n")
	current.WriteString("A:x\r\n\r\n")
	for range 200 {
		previous.WriteString("d\r\n")
		current.WriteString("d\r\nm\r\n")
	}
	result, usage, err := mustPlanBody(t, []byte(previous.String()), []byte(current.String()), RejectUnavailableBody, CopyOnly, GenerationLimits{}, nil)
	if err != nil || !result.Valid() || len(result.stepsCopy()) != 200 {
		t.Fatalf("duplicate bomb: valid=%t steps=%d code=%s", result.Valid(), len(result.stepsCopy()), recipeTestErrorCode(err))
	}
	if usage.Candidates() != 400 || usage.CandidateKeyBytes() != 6 || usage.Comparisons() > usage.InputItems() {
		t.Fatalf("duplicate usage: candidates=%d keys=%d comparisons=%d input=%d", usage.Candidates(), usage.CandidateKeyBytes(), usage.Comparisons(), usage.InputItems())
	}
}

// TestBodyPlanningResultRejectsIncoherentStates verifies its closed immutable vocabulary.
func TestBodyPlanningResultRejectsIncoherentStates(t *testing.T) {
	if (bodyPlanningResult{}).Valid() {
		t.Fatal("zero body result is valid")
	}
	for _, result := range []bodyPlanningResult{
		{outcome: BodyGenerationUnchanged, steps: []step{{kind: StepKindCopy, copyStart: 1, copyEnd: 1, initialized: true}}, initialized: true},
		{outcome: BodyGenerationUnavailable, initialized: true},
		{outcome: BodyGenerationGenerated, unavailable: BodyUnavailableReasonUnrepresentable, initialized: true},
	} {
		if result.Valid() {
			t.Fatalf("incoherent body result accepted: outcome=%s", result.outcome)
		}
	}
}

// TestResolveUnavailableBodyRejectsUnknownReasons verifies policy cannot mask invariants.
func TestResolveUnavailableBodyRejectsUnknownReasons(t *testing.T) {
	for _, policy := range []BodyUnavailablePolicy{RejectUnavailableBody, AllowUnavailableBody} {
		result, err := resolveUnavailableBody(policy, BodyUnavailableReason("future"))
		if result.Valid() || !IsErrorCode(err, ErrorCodeGeneratedOutputInvariant) || recipeTestErrorClass(err) != ErrorClassInvariant {
			t.Fatalf("unknown reason: policy=%d valid=%t code=%s class=%s", policy, result.Valid(), recipeTestErrorCode(err), recipeTestErrorClass(err))
		}
		var typed *Error
		if !errors.As(err, &typed) || typed.Dimension() != DimensionBody {
			t.Fatalf("unknown reason dimension: policy=%d code=%s", policy, recipeTestErrorCode(err))
		}
	}
}

// TestPlanBodyErrorsRemainSecretSafe verifies toxic body bytes never enter diagnostics.
func TestPlanBodyErrorsRemainSecretSafe(t *testing.T) {
	const protected = "protected-body-marker"
	failed, usage, err := mustPlanBody(t,
		[]byte("A:x\r\n\r\n"+protected), []byte("A:x\r\n\r\ncurrent\r\n"),
		RejectUnavailableBody, AllowLiterals, GenerationLimits{}, nil)
	if failed.Valid() || !usage.Valid() {
		t.Fatalf("privacy failure atomicity: valid=%t usage=%t", failed.Valid(), usage.Valid())
	}
	assertClosedSafeGenerationError(t, err, ErrorCodeBodyUnrepresentable, ErrorClassRepresentation, protected)
	failed, usage, err = mustPlanBody(t,
		append([]byte("A:x\r\n\r\n"), 0xff, '\r', '\n'), []byte("A:x\r\n\r\ncurrent\r\n"),
		RejectUnavailableBody, AllowLiterals, GenerationLimits{}, nil)
	if failed.Valid() || !usage.Valid() {
		t.Fatalf("binary privacy failure atomicity: valid=%t usage=%t", failed.Valid(), usage.Valid())
	}
	assertClosedSafeGenerationError(t, err, ErrorCodeBodyUnrepresentable, ErrorClassRepresentation, string([]byte{0xff}))
}

// TestPlanBodyNeverConvertsLimitsToUnavailable verifies the narrow b:null policy.
func TestPlanBodyNeverConvertsLimitsToUnavailable(t *testing.T) {
	limits := GenerationLimits{RecipeLimits: DefaultLimits()}
	limits.RecipeLimits.MaxDataStringBytes = 2
	limits.RecipeLimits.MaxTotalLiteralBytes = 2
	failed, usage, err := mustPlanBody(t, []byte("A:x\r\n\r\nlong\r\n"), []byte("A:x\r\n\r\nnew\r\n"), AllowUnavailableBody, AllowLiterals, limits, nil)
	if failed.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != limitNameMaxDataStringBytes {
		t.Fatalf("limit conversion: valid=%t usage=%t code=%s limit=%s", failed.Valid(), usage.Valid(), recipeTestErrorCode(err), recipeTestLimitName(err))
	}
}

// TestPlanBodySharesPreloadedOperationTotals verifies no shared counter resets.
func TestPlanBodySharesPreloadedOperationTotals(t *testing.T) {
	literalPrevious := []byte("A:x\r\n\r\nold\r\n")
	literalCurrent := []byte("A:x\r\n\r\nnew\r\n")
	copyPrevious := []byte("A:x\r\n\r\nb\r\nc\r\n")
	copyCurrent := []byte("A:x\r\n\r\na\r\nb\r\nc\r\n")
	tests := []struct {
		name      string
		previous  []byte
		current   []byte
		limitName string
		preload   func(*generationCounter, bool)
	}{
		{name: testTotalStepsLabel, previous: literalPrevious, current: literalCurrent, limitName: limitNameMaxTotalSteps, preload: func(c *generationCounter, exact bool) {
			c.generatedSteps = c.limits.RecipeLimits.MaxTotalSteps - 1
			if !exact {
				c.generatedSteps++
			}
		}},
		{name: testCopyRangesLabel, previous: copyPrevious, current: copyCurrent, limitName: limitNameMaxCopyRanges, preload: func(c *generationCounter, exact bool) {
			c.copyRanges = c.limits.RecipeLimits.MaxCopyRanges - 1
			if !exact {
				c.copyRanges++
			}
		}},
		{name: testTotalCopiedItemsLabel, previous: copyPrevious, current: copyCurrent, limitName: limitNameMaxTotalCopiedItems, preload: func(c *generationCounter, exact bool) {
			c.copiedItems = c.limits.RecipeLimits.MaxTotalCopiedItems - 2
			if !exact {
				c.copiedItems++
			}
		}},
		{name: testDataStringsLabel, previous: literalPrevious, current: literalCurrent, limitName: limitNameMaxDataStrings, preload: func(c *generationCounter, exact bool) {
			c.generatedLiterals = c.limits.RecipeLimits.MaxDataStrings - 1
			if !exact {
				c.generatedLiterals++
			}
		}},
		{name: testLiteralBytesLabel, previous: literalPrevious, current: literalCurrent, limitName: limitNameMaxTotalLiteralBytes, preload: func(c *generationCounter, exact bool) {
			c.literalBytes = c.limits.RecipeLimits.MaxTotalLiteralBytes - len("old")
			if !exact {
				c.literalBytes++
			}
		}},
		{name: testInputBytesLabel, previous: literalPrevious, current: literalCurrent, limitName: limitNameMaxInputBytes, preload: func(c *generationCounter, exact bool) {
			c.inputBytes = c.limits.MaxInputBytes - 14
			if !exact {
				c.inputBytes++
			}
		}},
		{name: testInputItemsLabel, previous: literalPrevious, current: literalCurrent, limitName: limitNameMaxInputItems, preload: func(c *generationCounter, exact bool) {
			c.inputItems = c.limits.MaxInputItems - 2
			if !exact {
				c.inputItems++
			}
		}},
		{name: "candidates", previous: literalPrevious, current: literalCurrent, limitName: limitNameMaxCandidateEntries, preload: func(c *generationCounter, exact bool) {
			c.candidates = c.limits.MaxCandidateEntries - 1
			if !exact {
				c.candidates++
			}
		}},
		{name: testCandidateKeyBytesLabel, previous: literalPrevious, current: literalCurrent, limitName: limitNameMaxCandidateKeyBytes, preload: func(c *generationCounter, exact bool) {
			c.candidateBytes = c.limits.MaxCandidateKeyBytes - len("new\r\n")
			if !exact {
				c.candidateBytes++
			}
		}},
		{name: testComparisonsLabel, previous: literalPrevious, current: literalCurrent, limitName: limitNameMaxComparisons, preload: func(c *generationCounter, exact bool) {
			c.comparisons = c.limits.MaxComparisons - 1
			if !exact {
				c.comparisons++
			}
		}},
		{name: generationCounterWorkCase, previous: literalPrevious, current: literalCurrent, limitName: limitNameMaxGenerationWorkUnits, preload: func(c *generationCounter, exact bool) {
			c.workUnits = c.limits.MaxGenerationWorkUnits - 99
			if !exact {
				c.workUnits++
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, _, err := mustPlanBody(t, test.previous, test.current, RejectUnavailableBody, AllowLiterals, GenerationLimits{}, func(c *generationCounter) { test.preload(c, true) })
			if err != nil || !result.Valid() {
				t.Fatalf("shared exact: valid=%t code=%s", result.Valid(), recipeTestErrorCode(err))
			}
			failed, usage, err := mustPlanBody(t, test.previous, test.current, RejectUnavailableBody, AllowLiterals, GenerationLimits{}, func(c *generationCounter) { test.preload(c, false) })
			if failed.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != test.limitName {
				t.Fatalf("shared total: valid=%t usage=%t code=%s limit=%s", failed.Valid(), usage.Valid(), recipeTestErrorCode(err), recipeTestLimitName(err))
			}
		})
	}
}

// TestPlanBodyReportsExactSuccessfulUsage locks the body accounting model.
func TestPlanBodyReportsExactSuccessfulUsage(t *testing.T) {
	result, usage, err := mustPlanBody(t,
		[]byte("A:x\r\n\r\nold\r\n"), []byte("A:x\r\n\r\nnew\r\n"),
		RejectUnavailableBody, AllowLiterals, GenerationLimits{}, nil)
	if err != nil || !result.Valid() {
		t.Fatalf("usage result: valid=%t code=%s", result.Valid(), recipeTestErrorCode(err))
	}
	if usage.InputBytes() != 14 || usage.InputItems() != 2 || usage.Candidates() != 1 ||
		usage.CandidateKeyBytes() != 5 || usage.Comparisons() != 1 || usage.GeneratedSteps() != 1 ||
		usage.GeneratedLiterals() != 1 || usage.LiteralBytes() != 3 || usage.WorkUnits() != 99 {
		t.Fatalf("body usage: input=%d/%d candidates=%d keys=%d comparisons=%d steps=%d literals=%d/%d work=%d",
			usage.InputBytes(), usage.InputItems(), usage.Candidates(), usage.CandidateKeyBytes(), usage.Comparisons(),
			usage.GeneratedSteps(), usage.GeneratedLiterals(), usage.LiteralBytes(), usage.WorkUnits())
	}
}

// TestPlanBodyEnforcesInheritedLimitsAtExactBoundaries verifies body plan ceilings.
func TestPlanBodyEnforcesInheritedLimitsAtExactBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		previous  []byte
		current   []byte
		exact     int
		limitName string
		configure func(*Limits, int)
	}{
		{name: testBodyStepsLabel, previous: []byte("A:x\r\n\r\nz\r\ny\r\n"), current: []byte("A:x\r\n\r\nx\r\ny\r\nz\r\n"), exact: 2, limitName: limitNameMaxBodySteps, configure: func(l *Limits, n int) { l.MaxBodySteps = n }},
		{name: testCopyRangesLabel, previous: []byte("A:x\r\n\r\nd\r\nd\r\n"), current: []byte("A:x\r\n\r\nd\r\nm\r\nd\r\n"), exact: 2, limitName: limitNameMaxCopyRanges, configure: func(l *Limits, n int) { l.MaxCopyRanges = n }},
		{name: testCopiedItemsPerRangeLabel, previous: []byte("A:x\r\n\r\nb\r\nc\r\n"), current: []byte("A:x\r\n\r\na\r\nb\r\nc\r\n"), exact: 2, limitName: limitNameMaxCopiedItemsPerRange, configure: func(l *Limits, n int) { l.MaxCopiedItemsPerRange = n }},
		{name: testTotalCopiedItemsLabel, previous: []byte("A:x\r\n\r\nd\r\nd\r\n"), current: []byte("A:x\r\n\r\nd\r\nm\r\nd\r\n"), exact: 2, limitName: limitNameMaxTotalCopiedItems, configure: func(l *Limits, n int) { l.MaxCopiedItemsPerRange, l.MaxTotalCopiedItems = 1, n }},
		{name: testDataStringsLabel, previous: []byte("A:x\r\n\r\nbb\r\nccc\r\n"), current: []byte("A:x\r\n\r\nx\r\n"), exact: 2, limitName: limitNameMaxDataStrings, configure: func(l *Limits, n int) { l.MaxDataStrings = n }},
		{name: testDataStringBytesLabel, previous: []byte("A:x\r\n\r\nold\r\n"), current: []byte("A:x\r\n\r\nnew\r\n"), exact: 3, limitName: limitNameMaxDataStringBytes, configure: func(l *Limits, n int) { l.MaxDataStringBytes = n }},
		{name: testLiteralBytesLabel, previous: []byte("A:x\r\n\r\nbb\r\nccc\r\n"), current: []byte("A:x\r\n\r\nx\r\n"), exact: 5, limitName: limitNameMaxTotalLiteralBytes, configure: func(l *Limits, n int) { l.MaxDataStringBytes, l.MaxTotalLiteralBytes = n, n }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, boundary := range []struct {
				name    string
				limit   int
				wantErr bool
			}{
				{name: testExactBoundaryLabel, limit: test.exact},
				{name: testOneUnderLabel, limit: test.exact - 1, wantErr: true},
			} {
				t.Run(boundary.name, func(t *testing.T) {
					limits := GenerationLimits{RecipeLimits: DefaultLimits()}
					test.configure(&limits.RecipeLimits, boundary.limit)
					result, usage, err := mustPlanBody(t, test.previous, test.current, RejectUnavailableBody, AllowLiterals, limits, nil)
					if boundary.wantErr {
						if result.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != test.limitName {
							t.Fatalf("one-under: valid=%t usage=%t code=%s limit=%s", result.Valid(), usage.Valid(), recipeTestErrorCode(err), recipeTestLimitName(err))
						}
						return
					}
					if err != nil || !result.Valid() {
						t.Fatalf("exact: valid=%t code=%s", result.Valid(), recipeTestErrorCode(err))
					}
				})
			}
		})
	}
}

// TestPlanBodyEnforcesInputIndexAndStateLimitsAtExactBoundaries verifies body accounting ceilings.
func TestPlanBodyEnforcesInputIndexAndStateLimitsAtExactBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		previous  []byte
		current   []byte
		exact     int
		limitName string
		configure func(*GenerationLimits, int)
	}{
		{name: "body lines", previous: []byte("A:x\r\n\r\na\r\nb\r\n"), current: []byte("A:x\r\n\r\nx\r\ny\r\n"), exact: 2, limitName: limitNameMaxBodyLines, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxBodyLines = n }},
		{name: "body line bytes", previous: []byte("A:x\r\n\r\nold\r\n"), current: []byte("A:x\r\n\r\nnew\r\n"), exact: 3, limitName: limitNameMaxBodyLineBytes, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxBodyLineBytes = n }},
		{name: testStateBytesLabel, previous: []byte("A:x\r\n\r\nold\r\n"), current: []byte("A:x\r\n\r\nnew\r\n"), exact: len("A:x\r\n\r\nold\r\n"), limitName: limitNameMaxStateBytes, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxStateBytes = n }},
		{name: testInputBytesLabel, previous: []byte("A:x\r\n\r\nold\r\n"), current: []byte("A:x\r\n\r\nnew\r\n"), exact: 14, limitName: limitNameMaxInputBytes, configure: func(l *GenerationLimits, n int) { l.MaxInputBytes = n }},
		{name: testInputItemsLabel, previous: []byte("A:x\r\n\r\nold\r\n"), current: []byte("A:x\r\n\r\nnew\r\n"), exact: 2, limitName: limitNameMaxInputItems, configure: func(l *GenerationLimits, n int) { l.MaxInputItems, l.MaxComparisons = n, n }},
		{name: "candidate entries", previous: []byte("A:x\r\n\r\na\r\nb\r\n"), current: []byte("A:x\r\n\r\nx\r\ny\r\n"), exact: 2, limitName: limitNameMaxCandidateEntries, configure: func(l *GenerationLimits, n int) { l.MaxCandidateEntries = n }},
		{name: testCandidateKeyBytesLabel, previous: []byte("A:x\r\n\r\na\r\nb\r\n"), current: []byte("A:x\r\n\r\nx\r\ny\r\n"), exact: 6, limitName: limitNameMaxCandidateKeyBytes, configure: func(l *GenerationLimits, n int) { l.MaxCandidateKeyBytes = n }},
		{name: testComparisonsLabel, previous: []byte("A:x\r\n\r\na\r\nb\r\n"), current: []byte("A:x\r\n\r\nx\r\ny\r\n"), exact: 2, limitName: limitNameMaxComparisons, configure: func(l *GenerationLimits, n int) { l.MaxComparisons = n }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exact := GenerationLimits{RecipeLimits: DefaultLimits()}
			test.configure(&exact, test.exact)
			if result, _, err := mustPlanBody(t, test.previous, test.current, RejectUnavailableBody, AllowLiterals, exact, nil); err != nil || !result.Valid() {
				t.Fatalf("exact: valid=%t code=%s", result.Valid(), recipeTestErrorCode(err))
			}
			over := GenerationLimits{RecipeLimits: DefaultLimits()}
			test.configure(&over, test.exact-1)
			failed, usage, err := mustPlanBody(t, test.previous, test.current, RejectUnavailableBody, AllowLiterals, over, nil)
			if failed.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != test.limitName {
				t.Fatalf("one-under: valid=%t usage=%t code=%s limit=%s", failed.Valid(), usage.Valid(), recipeTestErrorCode(err), recipeTestLimitName(err))
			}
		})
	}
}

// TestPlanBodyEnforcesExactWorkBoundary verifies all charged scans compose.
func TestPlanBodyEnforcesExactWorkBoundary(t *testing.T) {
	previous := []byte("A:x\r\n\r\nold\r\n")
	current := []byte("A:x\r\n\r\nnew\r\n")
	for _, boundary := range []struct {
		name    string
		limit   int
		wantErr bool
	}{
		{name: testExactBoundaryLabel, limit: 99},
		{name: testOneUnderLabel, limit: 98, wantErr: true},
	} {
		t.Run(boundary.name, func(t *testing.T) {
			result, usage, err := mustPlanBody(t, previous, current, RejectUnavailableBody, AllowLiterals, compactBodyWorkLimits(boundary.limit), nil)
			if boundary.wantErr {
				if result.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != limitNameMaxGenerationWorkUnits {
					t.Fatalf("one-under work: valid=%t usage=%t code=%s limit=%s", result.Valid(), usage.Valid(), recipeTestErrorCode(err), recipeTestLimitName(err))
				}
				return
			}
			if err != nil || !result.Valid() || usage.WorkUnits() != boundary.limit {
				t.Fatalf("exact work: valid=%t work=%d code=%s", result.Valid(), usage.WorkUnits(), recipeTestErrorCode(err))
			}
		})
	}
}

// compactBodyWorkLimits creates coherent narrow limits for the exact body vector.
func compactBodyWorkLimits(work int) GenerationLimits {
	recipeLimits := DefaultLimits()
	recipeLimits.MaxDecodedRecipeBytes = 3
	recipeLimits.MaxDataStringBytes = 3
	recipeLimits.MaxTotalLiteralBytes = 3
	recipeLimits.MaxOperationWorkUnits = 1
	return GenerationLimits{
		RecipeLimits: recipeLimits, MaxInputBytes: 14, MaxInputItems: 2,
		MaxCandidateEntries: 1, MaxCandidateKeyBytes: 5, MaxComparisons: 1,
		MaxGenerationWorkUnits: work,
	}
}

// TestHeaderAndBodyInputAccountingComposesFramingExactlyOnce verifies every framing matrix byte.
func TestHeaderAndBodyInputAccountingComposesFramingExactlyOnce(t *testing.T) {
	tests := []struct {
		name     string
		previous []byte
		current  []byte
		exact    int
	}{
		{name: "header-only header-only", previous: []byte("A:x\r\n"), current: []byte("A:x\r\n"), exact: 10},
		{name: "header-only delimited", previous: []byte("A:x\r\n"), current: []byte("A:x\r\n\r\n"), exact: 12},
		{name: "delimited header-only", previous: []byte("A:x\r\n\r\n"), current: []byte("A:x\r\n"), exact: 12},
		{name: "delimited delimited", previous: []byte("A:x\r\n\r\n"), current: []byte("A:x\r\n\r\n"), exact: 14},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, boundary := range []struct {
				name    string
				limit   int
				wantErr bool
			}{{name: testExactBoundaryLabel, limit: test.exact}, {name: testOneUnderLabel, limit: test.exact - 1, wantErr: true}} {
				t.Run(boundary.name, func(t *testing.T) {
					usage, err := planHeaderAndBodyForInputUsage(t, test.previous, test.current, boundary.limit)
					if boundary.wantErr {
						if !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != limitNameMaxInputBytes {
							t.Fatalf("one-under input: usage=%t code=%s limit=%s", usage.Valid(), recipeTestErrorCode(err), recipeTestLimitName(err))
						}
						return
					}
					if err != nil || usage.InputBytes() != test.exact {
						t.Fatalf("exact input: bytes=%d code=%s", usage.InputBytes(), recipeTestErrorCode(err))
					}
				})
			}
		})
	}
}

// planHeaderAndBodyForInputUsage composes both internal planners on one operation budget.
func planHeaderAndBodyForInputUsage(t *testing.T, previous, current []byte, maxInputBytes int) (GenerationUsage, error) {
	t.Helper()
	previousState := mustGenerationState(t, previous)
	currentState := mustGenerationState(t, current)
	request, err := NewGenerationRequest(previousState, currentState, AllowUnavailableBody, AllowLiterals)
	if err != nil {
		t.Fatalf("NewGenerationRequest() code=%s", recipeTestErrorCode(err))
	}
	limits := DefaultGenerationLimits()
	limits.MaxInputBytes = maxInputBytes
	generator, err := NewGenerator(limits, testHeaderRelevance{relevant: true})
	if err != nil {
		t.Fatalf("NewGenerator() code=%s", recipeTestErrorCode(err))
	}
	counter := newGenerationCounter(generator.limits)
	budget, err := newGenerationPlanBudget(&counter)
	if err != nil {
		t.Fatalf("newGenerationPlanBudget() code=%s", recipeTestErrorCode(err))
	}
	if _, err = generator.planHeaders(request, budget); err != nil {
		return counter.usage(), err
	}
	_, err = generator.planBody(request, budget)
	return counter.usage(), err
}

// TestPlanBodyDoesNotAliasInputOrOutput verifies immutable owned body plans.
func TestPlanBodyDoesNotAliasInputOrOutput(t *testing.T) {
	previous := []byte("A:x\r\n\r\nold\r\n")
	current := []byte("A:x\r\n\r\nnew\r\n")
	result, _, err := mustPlanBody(t, previous, current, RejectUnavailableBody, AllowLiterals, GenerationLimits{}, nil)
	if err != nil {
		t.Fatalf("planBody code=%s", recipeTestErrorCode(err))
	}
	previous[len(previous)-4] = 'X'
	steps := result.stepsCopy()
	data := steps[0].dataValues()
	data[0][0] = 'Y'
	if got := result.stepsCopy()[0].dataValues()[0]; !bytes.Equal(got, []byte("old")) {
		t.Fatalf("body literal mutated: bytes=%d", len(got))
	}
}

// mustPlanBody constructs one package-internal operation and optional shared preload.
func mustPlanBody(t *testing.T, previous, current []byte, bodyPolicy BodyUnavailablePolicy, literalPolicy LiteralDisclosurePolicy, limits GenerationLimits, preload func(*generationCounter)) (bodyPlanningResult, GenerationUsage, error) {
	t.Helper()
	previousState := mustGenerationState(t, previous)
	currentState := mustGenerationState(t, current)
	request, err := NewGenerationRequest(previousState, currentState, bodyPolicy, literalPolicy)
	if err != nil {
		t.Fatalf("NewGenerationRequest() code=%s", recipeTestErrorCode(err))
	}
	generator, err := NewGenerator(limits, testHeaderRelevance{relevant: true})
	if err != nil {
		t.Fatalf("NewGenerator() code=%s", recipeTestErrorCode(err))
	}
	counter := newGenerationCounter(generator.limits)
	if preload != nil {
		preload(&counter)
	}
	budget, err := newGenerationPlanBudget(&counter)
	if err != nil {
		t.Fatalf("newGenerationPlanBudget() code=%s", recipeTestErrorCode(err))
	}
	result, err := generator.planBody(request, budget)
	return result, counter.usage(), err
}
