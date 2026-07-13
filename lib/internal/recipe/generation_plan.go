package recipe

import (
	"bytes"
	"crypto/sha256"
)

// generationPlanBudget owns inherited recipe-wide counters across all planned dimensions.
type generationPlanBudget struct {
	limits  Limits
	counter *generationCounter
}

// exactCandidate owns one exact retained source key and its ascending occurrences.
type exactCandidate struct {
	key       []byte
	positions []int
	cursor    int
}

// exactCandidateIndex uses fixed-size digests for bounded lookup and exact collision checks.
type exactCandidateIndex struct {
	buckets map[[sha256.Size]byte][]*exactCandidate
}

// newExactCandidateIndex constructs one dimension-neutral exact source index.
func newExactCandidateIndex() exactCandidateIndex {
	return exactCandidateIndex{buckets: make(map[[sha256.Size]byte][]*exactCandidate)}
}

// add charges candidate ownership before retaining a new exact key or occurrence.
func (i *exactCandidateIndex) add(value []byte, occurrence int, counter *generationCounter, dimension Dimension) error {
	if err := counter.chargeWork(len(value), dimension); err != nil {
		return err
	}
	digest := sha256.Sum256(value)
	bucket := i.buckets[digest]
	for _, candidate := range bucket {
		if err := counter.chargeWork(len(value)+1, dimension); err != nil {
			return err
		}
		if bytes.Equal(candidate.key, value) {
			if err := counter.chargeCandidate(0, dimension); err != nil {
				return err
			}
			candidate.positions = append(candidate.positions, occurrence)
			return nil
		}
	}
	if err := counter.chargeCandidate(len(value), dimension); err != nil {
		return err
	}
	if err := counter.chargeWork(3, dimension); err != nil {
		return err
	}
	candidate := &exactCandidate{key: bytes.Clone(value), positions: []int{occurrence}}
	i.buckets[digest] = append(bucket, candidate)
	return nil
}

// lookup finds one exact key while preserving correctness across digest collisions.
func (i *exactCandidateIndex) lookup(value []byte, counter *generationCounter, dimension Dimension) (*exactCandidate, error) {
	if err := counter.chargeComparison(dimension); err != nil {
		return nil, err
	}
	if err := counter.chargeWork(len(value), dimension); err != nil {
		return nil, err
	}
	for _, candidate := range i.buckets[sha256.Sum256(value)] {
		if err := counter.chargeWork(len(value), dimension); err != nil {
			return nil, err
		}
		if bytes.Equal(candidate.key, value) {
			return candidate, nil
		}
		if err := counter.chargeComparison(dimension); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// newGenerationPlanBudget binds recipe-wide planning totals to one operation counter.
func newGenerationPlanBudget(counter *generationCounter) (*generationPlanBudget, error) {
	if counter == nil {
		return nil, generationInvariantError()
	}
	return &generationPlanBudget{limits: counter.limits.RecipeLimits, counter: counter}, nil
}

// appendCopy adds or extends one adjacent copy range under shared inherited limits.
func (b *generationPlanBudget) appendCopy(steps *[]step, occurrence int, dimension Dimension, maxSteps int, stepLimitName string) error {
	if len(*steps) > 0 {
		last := &(*steps)[len(*steps)-1]
		if start, end, copyStep := last.copyRange(); copyStep && occurrence == end+1 {
			width := occurrence - start + 1
			if width > b.limits.MaxCopiedItemsPerRange {
				return generationLimitError(limitNameMaxCopiedItemsPerRange, b.limits.MaxCopiedItemsPerRange, width, dimension)
			}
			if err := b.counter.chargeCopy(0, 1, dimension); err != nil {
				return err
			}
			if err := b.counter.chargeWork(1, dimension); err != nil {
				return err
			}
			last.copyEnd = occurrence
			return nil
		}
	}
	if err := b.counter.chargeCopy(1, 1, dimension); err != nil {
		return err
	}
	copyStep, err := newCopyStep(occurrence, occurrence)
	if err != nil {
		return generationInvariantErrorForDimension(dimension)
	}
	if err := b.appendStep(steps, copyStep, dimension, maxSteps, stepLimitName); err != nil {
		return err
	}
	return nil
}

// appendDataLiteral adds or extends one adjacent data step under shared limits.
func (b *generationPlanBudget) appendDataLiteral(steps *[]step, value []byte, dimension Dimension, maxSteps int, stepLimitName string) error {
	validationWork, ok := checkedMultiply(len(value), 2)
	if ok {
		validationWork, ok = checkedAdd(validationWork, 1)
	}
	if !ok {
		return generationLimitError(limitNameMaxGenerationWorkUnits, b.counter.limits.MaxGenerationWorkUnits, validationWork, dimension)
	}
	if err := b.counter.chargeWork(validationWork, dimension); err != nil {
		return err
	}
	if !validDataLiteral(value) {
		return generationInvariantErrorForDimension(dimension)
	}
	if len(value) > b.limits.MaxDataStringBytes {
		return generationLimitError(limitNameMaxDataStringBytes, b.limits.MaxDataStringBytes, len(value), dimension)
	}
	if err := b.counter.chargeLiteralString(len(value), dimension); err != nil {
		return err
	}
	if len(*steps) > 0 && (*steps)[len(*steps)-1].kind == StepKindData {
		if err := b.counter.chargeWork(1, dimension); err != nil {
			return err
		}
		last := &(*steps)[len(*steps)-1]
		last.data = append(last.data, bytes.Clone(value))
		return nil
	}
	if err := b.counter.chargeWork(1, dimension); err != nil {
		return err
	}
	dataStep := step{kind: StepKindData, data: [][]byte{bytes.Clone(value)}, initialized: true}
	if err := b.appendStep(steps, dataStep, dimension, maxSteps, stepLimitName); err != nil {
		return err
	}
	return nil
}

// appendStep enforces one dimension's step bound and the shared global bound.
func (b *generationPlanBudget) appendStep(steps *[]step, instruction step, dimension Dimension, maxSteps int, stepLimitName string) error {
	stepCount, ok := checkedAdd(len(*steps), 1)
	if !ok || stepCount > maxSteps {
		return generationLimitError(stepLimitName, maxSteps, stepCount, dimension)
	}
	if err := b.counter.chargeStep(dimension); err != nil {
		return err
	}
	*steps = append(*steps, instruction)
	return nil
}

// generationInvariantErrorForDimension returns one closed internal planning failure.
func generationInvariantErrorForDimension(dimension Dimension) *Error {
	return newError(ErrorCodeGeneratedOutputInvariant, ErrorLocation{}, ErrorDetails{Class: ErrorClassInvariant, Dimension: dimension}, nil)
}
