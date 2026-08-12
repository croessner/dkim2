package recipe

import (
	"math"
	"reflect"
	"testing"
)

// TestDefaultGenerationLimitsMatchDurableContract locks exact defaults and hard maxima.
func TestDefaultGenerationLimitsMatchDurableContract(t *testing.T) {
	want := GenerationLimits{
		RecipeLimits: DefaultLimits(), MaxInputBytes: 67_108_864, MaxInputItems: 135_072,
		MaxCandidateEntries: 67_536, MaxCandidateKeyBytes: 33_554_432,
		MaxComparisons: 135_072, MaxGenerationWorkUnits: 268_435_456,
	}
	if got := DefaultGenerationLimits(); got != want {
		t.Fatalf("DefaultGenerationLimits() = %#v, want %#v", got, want)
	}
	if got, err := (GenerationLimits{}).normalized(); err != nil || got != want {
		t.Fatalf("zero normalization mismatch: code=%s equal=%t", recipeTestErrorCode(err), got == want)
	}
}

// TestEveryGenerationHardMaximumAcceptsExactAndRejectsOneOver locks every added ceiling.
func TestEveryGenerationHardMaximumAcceptsExactAndRejectsOneOver(t *testing.T) {
	exact := DefaultGenerationLimits()
	if err := exact.Validate(); err != nil {
		t.Fatalf("exact hard maxima code=%s", recipeTestErrorCode(err))
	}
	typeOfLimits := reflect.TypeFor[GenerationLimits]()
	for index := 1; index < typeOfLimits.NumField(); index++ {
		field := typeOfLimits.Field(index)
		t.Run(field.Name, func(t *testing.T) {
			over := DefaultGenerationLimits()
			value := reflect.ValueOf(&over).Elem().Field(index)
			value.SetInt(value.Int() + 1)
			if err := over.Validate(); !IsErrorCode(err, ErrorCodeInvalidOptions) {
				t.Fatalf("one-over hard maximum code=%s", recipeTestErrorCode(err))
			}
		})
	}
}

// TestEveryGenerationLimitRejectsNegative verifies each generation counter fails closed below zero.
func TestEveryGenerationLimitRejectsNegative(t *testing.T) {
	typeOfLimits := reflect.TypeOf(DefaultGenerationLimits())
	for index := 1; index < typeOfLimits.NumField(); index++ {
		field := typeOfLimits.Field(index)
		t.Run(field.Name, func(t *testing.T) {
			negative := DefaultGenerationLimits()
			reflect.ValueOf(&negative).Elem().Field(index).SetInt(-1)
			if err := negative.Validate(); !IsErrorCode(err, ErrorCodeInvalidOptions) {
				t.Fatalf("negative value code=%s", recipeTestErrorCode(err))
			}
		})
	}
}

// TestGenerationLimitsDeriveNarrowCoherentBounds verifies formula ownership and coherence.
func TestGenerationLimitsDeriveNarrowCoherentBounds(t *testing.T) {
	limits := GenerationLimits{RecipeLimits: DefaultLimits()}
	limits.RecipeLimits.MaxStateBytes = 100
	limits.RecipeLimits.MaxHeaderFields = 7
	limits.RecipeLimits.MaxBodyLines = 11
	limits.RecipeLimits.MaxDecodedRecipeBytes = 20
	limits.RecipeLimits.MaxTotalLiteralBytes = 20
	limits.RecipeLimits.MaxDataStringBytes = 20
	limits.RecipeLimits.MaxOperationWorkUnits = 30
	got, err := limits.normalized()
	if err != nil {
		t.Fatalf("normalized() code=%s", recipeTestErrorCode(err))
	}
	if got.MaxInputBytes != 200 || got.MaxInputItems != 36 || got.MaxCandidateEntries != 18 || got.MaxCandidateKeyBytes != 100 || got.MaxComparisons != 36 {
		t.Fatalf("derived bounds = %#v", got)
	}
	minimumWork := 200 + 100 + 36 + 2*20 + 2*30
	exactWork := limits
	exactWork.MaxGenerationWorkUnits = minimumWork
	if err := exactWork.Validate(); err != nil {
		t.Fatalf("exact aggregate work code=%s", recipeTestErrorCode(err))
	}
	oneUnderWork := exactWork
	oneUnderWork.MaxGenerationWorkUnits--
	if err := oneUnderWork.Validate(); !IsErrorCode(err, ErrorCodeInvalidOptions) {
		t.Fatalf("one-under aggregate work code=%s", recipeTestErrorCode(err))
	}

	tests := []struct {
		name string
		mut  func(*GenerationLimits)
	}{
		{name: "negative", mut: func(l *GenerationLimits) { l.MaxInputBytes = -1 }},
		{name: "input bytes incoherent", mut: func(l *GenerationLimits) { l.MaxInputBytes = 201 }},
		{name: "input items incoherent", mut: func(l *GenerationLimits) { l.MaxInputItems = 37 }},
		{name: "candidate entries incoherent", mut: func(l *GenerationLimits) { l.MaxCandidateEntries = 19 }},
		{name: "candidate bytes incoherent", mut: func(l *GenerationLimits) { l.MaxCandidateKeyBytes = 101 }},
		{name: "comparisons incoherent", mut: func(l *GenerationLimits) { l.MaxInputItems = 10; l.MaxComparisons = 11 }},
		{name: "derived comparisons incoherent", mut: func(l *GenerationLimits) { l.MaxInputItems = 10; l.MaxComparisons = 0 }},
		{name: "aggregate too small", mut: func(l *GenerationLimits) { l.MaxGenerationWorkUnits = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := limits
			test.mut(&candidate)
			if err := candidate.Validate(); !IsErrorCode(err, ErrorCodeInvalidOptions) {
				t.Fatalf("incoherent limits code=%s", recipeTestErrorCode(err))
			}
		})
	}
}

// TestGenerationCheckedArithmeticRejectsOverflow verifies formula arithmetic fails closed.
func TestGenerationCheckedArithmeticRejectsOverflow(t *testing.T) {
	if got, ok := checkedMultiply(math.MaxInt, 2); ok || got != math.MaxInt {
		t.Fatalf("checkedMultiply overflow = %d,%t", got, ok)
	}
	if got, ok := checkedMultiply(7, 3); !ok || got != 21 {
		t.Fatalf("checkedMultiply exact = %d,%t", got, ok)
	}
	if _, ok := checkedSum(math.MaxInt, 1); ok {
		t.Fatal("checkedSum accepted overflow")
	}
	if got, ok := checkedSum(1, 2, 3); !ok || got != 6 {
		t.Fatalf("checkedSum exact = %d,%t", got, ok)
	}
}
