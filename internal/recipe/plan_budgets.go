package recipe

// planBudgetAccumulator owns shared recipe-step expansion counters.
type planBudgetAccumulator struct {
	steps        int
	ranges       int
	copied       int
	dataStrings  int
	literalBytes int
}

// addSteps revalidates one step sequence under shared Applier limits.
func (b *planBudgetAccumulator) addSteps(steps []step, limits Limits, dimension Dimension) error {
	var ok bool
	b.steps, ok = checkedAdd(b.steps, len(steps))
	if !ok || b.steps > limits.MaxTotalSteps {
		return applicationLimitError(dimension, limitNameMaxTotalSteps, limits.MaxTotalSteps, b.steps)
	}
	for _, instruction := range steps {
		if start, end, copyStep := instruction.copyRange(); copyStep {
			width := end - start + 1
			if width > limits.MaxCopiedItemsPerRange {
				return applicationLimitError(dimension, limitNameMaxCopiedItemsPerRange, limits.MaxCopiedItemsPerRange, width)
			}
			b.ranges, ok = checkedAdd(b.ranges, 1)
			if !ok || b.ranges > limits.MaxCopyRanges {
				return applicationLimitError(dimension, limitNameMaxCopyRanges, limits.MaxCopyRanges, b.ranges)
			}
			b.copied, ok = checkedAdd(b.copied, width)
			if !ok || b.copied > limits.MaxTotalCopiedItems {
				return applicationLimitError(dimension, limitNameMaxTotalCopiedItems, limits.MaxTotalCopiedItems, b.copied)
			}
			continue
		}
		for _, literal := range instruction.data {
			if len(literal) > limits.MaxDataStringBytes {
				return applicationLimitError(dimension, limitNameMaxDataStringBytes, limits.MaxDataStringBytes, len(literal))
			}
			b.dataStrings, ok = checkedAdd(b.dataStrings, 1)
			if !ok || b.dataStrings > limits.MaxDataStrings {
				return applicationLimitError(dimension, limitNameMaxDataStrings, limits.MaxDataStrings, b.dataStrings)
			}
			b.literalBytes, ok = checkedAdd(b.literalBytes, len(literal))
			if !ok || b.literalBytes > limits.MaxTotalLiteralBytes {
				return applicationLimitError(dimension, limitNameMaxTotalLiteralBytes, limits.MaxTotalLiteralBytes, b.literalBytes)
			}
		}
	}
	return nil
}

// validateAllPlanStepBudgets revalidates shared limits across both dimensions.
func validateAllPlanStepBudgets(recipe Recipe, limits Limits, dimension Dimension) error {
	budget := planBudgetAccumulator{}
	for _, plan := range recipe.headers {
		if err := budget.addSteps(plan.steps, limits, dimension); err != nil {
			return err
		}
	}
	return budget.addSteps(recipe.bodySteps, limits, dimension)
}
