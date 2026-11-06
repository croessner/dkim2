package recipe

// generationCounter owns checked operation-wide generation accounting across dimensions.
type generationCounter struct {
	limits                      GenerationLimits
	inputBytes, inputItems      int
	candidates, candidateBytes  int
	comparisons, generatedSteps int
	generatedLiterals           int
	copyRanges, copiedItems     int
	literalBytes, jsonBytes     int
	proofWorkUnits              int
	parseProofWorkUnits         int
	reconstructionProofUnits    int
	semanticProofWorkUnits      int
	proofReserved               bool
	parseProofRecorded          bool
	reconstructionProofRecorded bool
	workUnits                   int
}

// newGenerationCounter constructs an empty counter from normalized generator limits.
func newGenerationCounter(limits GenerationLimits) generationCounter {
	return generationCounter{limits: limits}
}

// usage snapshots numeric accounting without exposing protected operation data.
func (c *generationCounter) usage() GenerationUsage {
	if c == nil {
		return GenerationUsage{}
	}
	return newGenerationUsage(c.inputBytes, c.inputItems, c.candidates, c.candidateBytes,
		c.comparisons, c.generatedSteps, c.generatedLiterals, c.literalBytes, c.jsonBytes, c.proofWorkUnits, c.workUnits)
}

// failedUsage discards unexposed serialized-byte ownership before returning numeric failure accounting.
func (c *generationCounter) failedUsage() GenerationUsage {
	if c == nil {
		return GenerationUsage{}
	}
	c.jsonBytes = 0
	return c.usage()
}

// reserveProofBudgets atomically reserves full strict-parser and applier caps before parser allocation.
func (c *generationCounter) reserveProofBudgets() error {
	if c == nil || c.proofReserved {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	reservation, ok := checkedMultiply(c.limits.RecipeLimits.MaxOperationWorkUnits, 2)
	if !ok {
		return generationLimitError(limitNameMaxGenerationWorkUnits, c.limits.MaxGenerationWorkUnits, reservation, DimensionRecipe)
	}
	if err := c.chargeWork(reservation, DimensionRecipe); err != nil {
		return err
	}
	c.proofReserved = true
	return nil
}

// recordParseProofUsage stores bounded actual parser work under the first reserved proof cap.
func (c *generationCounter) recordParseProofUsage(usage Usage) error {
	if c == nil || !c.proofReserved || c.parseProofRecorded || !usage.Valid() || usage.WorkUnits() > c.limits.RecipeLimits.MaxOperationWorkUnits {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	c.parseProofWorkUnits = usage.WorkUnits()
	c.proofWorkUnits = usage.WorkUnits()
	c.parseProofRecorded = true
	return nil
}

// recordReconstructionProofUsage stores applier work under the second reserved proof cap.
func (c *generationCounter) recordReconstructionProofUsage(usage Usage) error {
	if c == nil || !c.proofReserved || !c.parseProofRecorded || c.reconstructionProofRecorded || !usage.Valid() || usage.WorkUnits() > c.limits.RecipeLimits.MaxOperationWorkUnits {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	c.reconstructionProofUnits = usage.WorkUnits()
	proof, ok := checkedAdd(c.parseProofWorkUnits, c.reconstructionProofUnits)
	if !ok {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	c.proofWorkUnits = proof
	c.reconstructionProofRecorded = true
	return nil
}

// chargeReconstructionProofWork transactionally precharges generation-specific semantic proof work.
func (c *generationCounter) chargeReconstructionProofWork(count int, dimension Dimension) error {
	if c == nil || !c.proofReserved || !c.parseProofRecorded || !c.reconstructionProofRecorded || count < 0 {
		return generationInvariantErrorForDimension(dimension)
	}
	semantic, ok := checkedAdd(c.semanticProofWorkUnits, count)
	if !ok {
		return generationLimitError(limitNameMaxGenerationWorkUnits, c.limits.MaxGenerationWorkUnits, semantic, dimension)
	}
	proof, ok := checkedSum(c.parseProofWorkUnits, c.reconstructionProofUnits, semantic)
	if !ok {
		return generationInvariantErrorForDimension(dimension)
	}
	work, err := c.checkedWork(count, dimension)
	if err != nil {
		return err
	}
	c.semanticProofWorkUnits = semantic
	c.proofWorkUnits = proof
	c.workUnits = work
	return nil
}

// checkJSONBytes validates decoded output ownership without mutating the counter.
func (c *generationCounter) checkJSONBytes(count int) error {
	bytes, ok := checkedAdd(c.jsonBytes, count)
	if !ok || bytes > c.limits.RecipeLimits.MaxDecodedRecipeBytes {
		return generationLimitError(limitNameMaxDecodedRecipeBytes, c.limits.RecipeLimits.MaxDecodedRecipeBytes, bytes, DimensionRecipe)
	}
	return nil
}

// commitJSONBytes records bytes only after the exact bounded write succeeds.
func (c *generationCounter) commitJSONBytes(count int) error {
	if err := c.checkJSONBytes(count); err != nil {
		return err
	}
	c.jsonBytes += count
	return nil
}

// chargeInput transactionally accounts for header bytes and occurrences scanned.
func (c *generationCounter) chargeInput(byteCount, itemCount int, dimension Dimension) error {
	bytes, ok := checkedAdd(c.inputBytes, byteCount)
	if !ok || bytes > c.limits.MaxInputBytes {
		return generationLimitError(limitNameMaxInputBytes, c.limits.MaxInputBytes, bytes, dimension)
	}
	items, ok := checkedAdd(c.inputItems, itemCount)
	if !ok || items > c.limits.MaxInputItems {
		return generationLimitError(limitNameMaxInputItems, c.limits.MaxInputItems, items, dimension)
	}
	workIncrement, ok := checkedSum(byteCount, itemCount)
	if !ok {
		return generationLimitError(limitNameMaxGenerationWorkUnits, c.limits.MaxGenerationWorkUnits, workIncrement, dimension)
	}
	work, err := c.checkedWork(workIncrement, dimension)
	if err != nil {
		return err
	}
	c.inputBytes, c.inputItems, c.workUnits = bytes, items, work
	return nil
}

// chargeCandidate transactionally accounts for one retained occurrence and optional unique key bytes.
func (c *generationCounter) chargeCandidate(keyBytes int, dimension Dimension) error {
	candidates, ok := checkedAdd(c.candidates, 1)
	if !ok || candidates > c.limits.MaxCandidateEntries {
		return generationLimitError(limitNameMaxCandidateEntries, c.limits.MaxCandidateEntries, candidates, dimension)
	}
	bytes, ok := checkedAdd(c.candidateBytes, keyBytes)
	if !ok || bytes > c.limits.MaxCandidateKeyBytes {
		return generationLimitError(limitNameMaxCandidateKeyBytes, c.limits.MaxCandidateKeyBytes, bytes, dimension)
	}
	workIncrement, ok := checkedAdd(1, keyBytes)
	if !ok {
		return generationLimitError(limitNameMaxGenerationWorkUnits, c.limits.MaxGenerationWorkUnits, workIncrement, dimension)
	}
	work, err := c.checkedWork(workIncrement, dimension)
	if err != nil {
		return err
	}
	c.candidates, c.candidateBytes, c.workUnits = candidates, bytes, work
	return nil
}

// chargeComparison accounts for one exact lookup or monotone candidate advance.
func (c *generationCounter) chargeComparison(dimension Dimension) error {
	comparisons, ok := checkedAdd(c.comparisons, 1)
	if !ok || comparisons > c.limits.MaxComparisons {
		return generationLimitError(limitNameMaxComparisons, c.limits.MaxComparisons, comparisons, dimension)
	}
	work, err := c.checkedWork(1, dimension)
	if err != nil {
		return err
	}
	c.comparisons, c.workUnits = comparisons, work
	return nil
}

// chargeStep accounts for one coalesced generated recipe operation.
func (c *generationCounter) chargeStep(dimension Dimension) error {
	steps, ok := checkedAdd(c.generatedSteps, 1)
	if !ok || steps > c.limits.RecipeLimits.MaxTotalSteps {
		return generationLimitError(limitNameMaxTotalSteps, c.limits.RecipeLimits.MaxTotalSteps, steps, dimension)
	}
	work, err := c.checkedWork(1, dimension)
	if err != nil {
		return err
	}
	c.generatedSteps, c.workUnits = steps, work
	return nil
}

// chargeCopy transactionally accounts for recipe-wide copy ranges and copied items.
func (c *generationCounter) chargeCopy(rangeCount, itemCount int, dimension Dimension) error {
	ranges, ok := checkedAdd(c.copyRanges, rangeCount)
	if !ok || ranges > c.limits.RecipeLimits.MaxCopyRanges {
		return generationLimitError(limitNameMaxCopyRanges, c.limits.RecipeLimits.MaxCopyRanges, ranges, dimension)
	}
	items, ok := checkedAdd(c.copiedItems, itemCount)
	if !ok || items > c.limits.RecipeLimits.MaxTotalCopiedItems {
		return generationLimitError(limitNameMaxTotalCopiedItems, c.limits.RecipeLimits.MaxTotalCopiedItems, items, dimension)
	}
	c.copyRanges, c.copiedItems = ranges, items
	return nil
}

// chargeLiteralString accounts for one generated data string before retaining it.
func (c *generationCounter) chargeLiteralString(byteCount int, dimension Dimension) error {
	literals, ok := checkedAdd(c.generatedLiterals, 1)
	if !ok || literals > c.limits.RecipeLimits.MaxDataStrings {
		return generationLimitError(limitNameMaxDataStrings, c.limits.RecipeLimits.MaxDataStrings, literals, dimension)
	}
	if byteCount < 0 || byteCount > c.limits.RecipeLimits.MaxDataStringBytes {
		return generationLimitError(limitNameMaxDataStringBytes, c.limits.RecipeLimits.MaxDataStringBytes, byteCount, dimension)
	}
	bytes, ok := checkedAdd(c.literalBytes, byteCount)
	if !ok || bytes > c.limits.RecipeLimits.MaxTotalLiteralBytes {
		return generationLimitError(limitNameMaxTotalLiteralBytes, c.limits.RecipeLimits.MaxTotalLiteralBytes, bytes, dimension)
	}
	work, err := c.checkedWork(byteCount, dimension)
	if err != nil {
		return err
	}
	c.generatedLiterals, c.literalBytes, c.workUnits = literals, bytes, work
	return nil
}

// chargeWork accounts for deterministic bounded work not represented by another counter.
func (c *generationCounter) chargeWork(count int, dimension Dimension) error {
	work, err := c.checkedWork(count, dimension)
	if err != nil {
		return err
	}
	c.workUnits = work
	return nil
}

// checkedWork projects aggregate work without mutating the counter.
func (c *generationCounter) checkedWork(count int, dimension Dimension) (int, error) {
	work, ok := checkedAdd(c.workUnits, count)
	if !ok || work > c.limits.MaxGenerationWorkUnits {
		return 0, generationLimitError(limitNameMaxGenerationWorkUnits, c.limits.MaxGenerationWorkUnits, work, dimension)
	}
	return work, nil
}

// generationLimitError constructs one closed dimension-aware generation limit failure.
func generationLimitError(name string, limit, actual int, dimension Dimension) *Error {
	return newError(ErrorCodeLimitExceeded, ErrorLocation{}, ErrorDetails{
		Class: ErrorClassLimit, LimitName: name, Expected: limit, Actual: actual, Dimension: dimension,
	}, nil)
}
