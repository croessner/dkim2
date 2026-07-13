package recipe

import "math"

const (
	hardMaxGenerationInputBytes        = 67_108_864
	hardMaxGenerationInputItems        = 135_072
	hardMaxGenerationCandidateEntries  = 67_536
	hardMaxGenerationCandidateKeyBytes = 33_554_432
	hardMaxGenerationComparisons       = 135_072
	hardMaxGenerationWorkUnits         = 268_435_456
)

// GenerationLimits bounds one deterministic generation operation and its proof.
type GenerationLimits struct {
	// RecipeLimits bounds generated recipe syntax and internal parse/apply proof.
	RecipeLimits Limits
	// MaxInputBytes bounds previous and current state bytes examined.
	MaxInputBytes int
	// MaxInputItems bounds previous and current header fields and body lines examined.
	MaxInputItems int
	// MaxCandidateEntries bounds retained current-source occurrences.
	MaxCandidateEntries int
	// MaxCandidateKeyBytes bounds protected exact-match keys retained from the source.
	MaxCandidateKeyBytes int
	// MaxComparisons bounds target lookups and monotone candidate advances.
	MaxComparisons int
	// MaxGenerationWorkUnits bounds aggregate scans, plans, output, and proof work.
	MaxGenerationWorkUnits int
}

// DefaultGenerationLimits returns the exact closed generation hard ceilings.
func DefaultGenerationLimits() GenerationLimits {
	return GenerationLimits{
		RecipeLimits: DefaultLimits(), MaxInputBytes: hardMaxGenerationInputBytes,
		MaxInputItems: hardMaxGenerationInputItems, MaxCandidateEntries: hardMaxGenerationCandidateEntries,
		MaxCandidateKeyBytes: hardMaxGenerationCandidateKeyBytes, MaxComparisons: hardMaxGenerationComparisons,
		MaxGenerationWorkUnits: hardMaxGenerationWorkUnits,
	}
}

// Validate rejects negative, widening, overflowing, or incoherent generation limits.
func (l GenerationLimits) Validate() error {
	_, err := l.normalized()
	return err
}

// normalized resolves recipe limits before deriving and validating generation bounds.
func (l GenerationLimits) normalized() (GenerationLimits, error) {
	recipeLimits, err := l.RecipeLimits.normalized()
	if err != nil {
		return GenerationLimits{}, err
	}
	l.RecipeLimits = recipeLimits

	twoStateBytes, ok := checkedMultiply(recipeLimits.MaxStateBytes, 2)
	if !ok {
		return GenerationLimits{}, generationOptionsError(limitNameMaxInputBytes)
	}
	itemsPerState, ok := checkedSum(recipeLimits.MaxHeaderFields, recipeLimits.MaxBodyLines)
	if !ok {
		return GenerationLimits{}, generationOptionsError(limitNameMaxInputItems)
	}
	twoStateItems, ok := checkedMultiply(itemsPerState, 2)
	if !ok {
		return GenerationLimits{}, generationOptionsError(limitNameMaxInputItems)
	}

	if l.MaxInputBytes, err = resolveGenerationLimit(l.MaxInputBytes, twoStateBytes, hardMaxGenerationInputBytes, limitNameMaxInputBytes); err != nil {
		return GenerationLimits{}, err
	}
	if l.MaxInputItems, err = resolveGenerationLimit(l.MaxInputItems, twoStateItems, hardMaxGenerationInputItems, limitNameMaxInputItems); err != nil {
		return GenerationLimits{}, err
	}
	if l.MaxCandidateEntries, err = resolveGenerationLimit(l.MaxCandidateEntries, itemsPerState, hardMaxGenerationCandidateEntries, limitNameMaxCandidateEntries); err != nil {
		return GenerationLimits{}, err
	}
	if l.MaxCandidateKeyBytes, err = resolveGenerationLimit(l.MaxCandidateKeyBytes, recipeLimits.MaxStateBytes, hardMaxGenerationCandidateKeyBytes, limitNameMaxCandidateKeyBytes); err != nil {
		return GenerationLimits{}, err
	}
	if l.MaxComparisons, err = resolveGenerationLimit(l.MaxComparisons, twoStateItems, hardMaxGenerationComparisons, limitNameMaxComparisons); err != nil {
		return GenerationLimits{}, err
	}
	if l.MaxComparisons > l.MaxInputItems {
		return GenerationLimits{}, generationOptionsError(limitNameMaxComparisons)
	}
	if l.MaxGenerationWorkUnits < 0 || l.MaxGenerationWorkUnits > hardMaxGenerationWorkUnits {
		return GenerationLimits{}, generationOptionsError(limitNameMaxGenerationWorkUnits)
	}
	if l.MaxGenerationWorkUnits == 0 {
		l.MaxGenerationWorkUnits = hardMaxGenerationWorkUnits
	}

	twiceRecipeBytes, ok := checkedMultiply(recipeLimits.MaxDecodedRecipeBytes, 2)
	if !ok {
		return GenerationLimits{}, generationOptionsError(limitNameGenerationWorkCoherence)
	}
	twiceProofWork, ok := checkedMultiply(recipeLimits.MaxOperationWorkUnits, 2)
	if !ok {
		return GenerationLimits{}, generationOptionsError(limitNameGenerationWorkCoherence)
	}
	minimumWork, ok := checkedSum(l.MaxInputBytes, l.MaxCandidateKeyBytes, l.MaxComparisons, twiceRecipeBytes, twiceProofWork)
	if !ok || l.MaxGenerationWorkUnits < minimumWork {
		return GenerationLimits{}, generationOptionsError(limitNameGenerationWorkCoherence)
	}
	return l, nil
}

// resolveGenerationLimit derives zero or validates a nonzero narrowing bound.
func resolveGenerationLimit(value, derived, hardMaximum int, limitName string) (int, error) {
	if derived < 0 || derived > hardMaximum || value < 0 || value > hardMaximum || value > derived {
		return 0, generationOptionsError(limitName)
	}
	if value == 0 {
		return derived, nil
	}
	return value, nil
}

// checkedMultiply multiplies nonnegative counters without integer overflow.
func checkedMultiply(left, right int) (int, bool) {
	if left < 0 || right < 0 || left != 0 && right > math.MaxInt/left {
		return math.MaxInt, false
	}
	return left * right, true
}

// checkedSum adds nonnegative counters without integer overflow.
func checkedSum(values ...int) (int, bool) {
	total := 0
	for _, value := range values {
		var ok bool
		total, ok = checkedAdd(total, value)
		if !ok {
			return math.MaxInt, false
		}
	}
	return total, true
}

// generationOptionsError returns one closed generation configuration failure.
func generationOptionsError(limitName string) *Error {
	return newError(ErrorCodeInvalidOptions, ErrorLocation{}, ErrorDetails{Class: ErrorClassOptions, LimitName: limitName}, nil)
}
