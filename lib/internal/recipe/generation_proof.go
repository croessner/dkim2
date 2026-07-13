package recipe

import (
	"bytes"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// generationProof is an unforgeable package-owned capability produced only by complete self-validation.
type generationProof struct {
	recipe      Recipe
	decodedJSON []byte
	bodyOutcome BodyGenerationOutcome
	unavailable BodyUnavailableReason
	validated   bool
}

// Valid reports whether the capability contains one coherent parsed recipe and exact JSON ownership.
func (p generationProof) Valid() bool {
	if !p.validated || !p.recipe.initialized || !p.recipe.bodyMode.Known() || len(p.decodedJSON) == 0 || !p.bodyOutcome.Known() {
		return false
	}
	if p.recipe.hasHeaderRecipe != (len(p.recipe.headers) > 0) || p.recipe.bodyMode != BodyModeSteps && len(p.recipe.bodySteps) != 0 {
		return false
	}
	if !p.recipe.hasHeaderRecipe && p.recipe.bodyMode == BodyModeAbsent {
		return false
	}
	switch p.bodyOutcome {
	case BodyGenerationUnchanged:
		return p.recipe.bodyMode == BodyModeAbsent && !p.unavailable.Known()
	case BodyGenerationGenerated:
		return p.recipe.bodyMode == BodyModeSteps && !p.unavailable.Known()
	case BodyGenerationUnavailable:
		return p.recipe.bodyMode == BodyModeUnavailable && p.unavailable.Known()
	default:
		return false
	}
}

// proveSerializedGeneration parses, applies, and semantically verifies the exact serializer-owned bytes.
func (g Generator) proveSerializedGeneration(request GenerationRequest, serialized serializedGenerationPlan, counter *generationCounter) (proof generationProof, proofErr error) {
	if counter != nil {
		defer func() {
			if proofErr != nil {
				counter.jsonBytes = 0
			}
		}()
	}
	if err := g.validateRequest(request); err != nil {
		return generationProof{}, err
	}
	if !serialized.Valid() || !serialized.classified || counter == nil || counter.limits != g.limits {
		return generationProof{}, generationInvariantErrorForDimension(DimensionRecipe)
	}
	if err := counter.reserveProofBudgets(); err != nil {
		return generationProof{}, err
	}

	parser, err := NewParser(g.limits.RecipeLimits)
	if err != nil {
		return generationProof{}, generationInvariantErrorForDimension(DimensionRecipe)
	}
	parsed, parseUsage, err := parser.Parse(serialized.decodedJSON)
	if usageErr := counter.recordParseProofUsage(parseUsage); usageErr != nil {
		return generationProof{}, usageErr
	}
	if err != nil || !parsed.initialized || !generationBodyModelMatches(serialized, parsed) {
		return generationProof{}, generationInvariantErrorForDimension(DimensionRecipe)
	}

	applier, err := NewApplier(g.limits.RecipeLimits)
	if err != nil {
		return generationProof{}, generationInvariantErrorForDimension(DimensionRecipe)
	}
	reconstructed, applyUsage, err := applier.Apply(request.Current(), parsed)
	if usageErr := counter.recordReconstructionProofUsage(applyUsage); usageErr != nil {
		return generationProof{}, usageErr
	}
	if err != nil || !reconstructed.Valid() {
		return generationProof{}, generationInvariantErrorForDimension(DimensionRecipe)
	}
	if err := g.proveReconstruction(request.Previous(), request.Current(), reconstructed, serialized.bodyOutcome, serialized.classifications, counter); err != nil {
		return generationProof{}, err
	}

	proof = generationProof{
		recipe: parsed, decodedJSON: serialized.decodedJSON, bodyOutcome: serialized.bodyOutcome,
		unavailable: serialized.unavailable, validated: true,
	}
	return proof, nil
}

// generationBodyModelMatches proves serializer metadata agrees with the strict parsed body model.
func generationBodyModelMatches(serialized serializedGenerationPlan, parsed Recipe) bool {
	if !serialized.Valid() || !parsed.initialized {
		return false
	}
	switch serialized.bodyOutcome {
	case BodyGenerationUnchanged:
		return parsed.bodyMode == BodyModeAbsent && !serialized.unavailable.Known()
	case BodyGenerationGenerated:
		return parsed.bodyMode == BodyModeSteps && !serialized.unavailable.Known()
	case BodyGenerationUnavailable:
		return parsed.bodyMode == BodyModeUnavailable && serialized.unavailable.Known()
	default:
		return false
	}
}

// proveReconstruction compares exact relevant header semantics and the permitted body dimension.
func (g Generator) proveReconstruction(previous, current, reconstructed State, bodyOutcome BodyGenerationOutcome, classifications []headerClassification, counter *generationCounter) error {
	if !knownGenerationState(previous) || !knownGenerationState(current) || !reconstructed.Valid() || counter == nil {
		return reconstructionMismatchError(DimensionRecipe)
	}
	if err := g.proveRelevantHeaderGroups(previous, current, reconstructed, classifications, counter); err != nil {
		return err
	}
	if bodyOutcome == BodyGenerationUnavailable {
		if reconstructed.BodyState() != BodyAvailabilityUnavailable {
			return reconstructionMismatchError(DimensionBody)
		}
		return nil
	}
	if reconstructed.BodyState() != BodyAvailabilityKnown {
		return reconstructionMismatchError(DimensionBody)
	}
	bodyWork, ok := checkedAdd(max(previous.body.Len(), reconstructed.body.Len()), 1)
	if !ok {
		return reconstructionMismatchError(DimensionBody)
	}
	if err := counter.chargeReconstructionProofWork(bodyWork, DimensionBody); err != nil {
		return err
	}
	if previous.framing != reconstructed.framing || !previous.body.Equal(reconstructed.body) {
		return reconstructionMismatchError(DimensionBody)
	}
	return nil
}

// proveRelevantHeaderGroups compares every relevant name's exact bottom-up unfolded values.
func (g Generator) proveRelevantHeaderGroups(previous, current, reconstructed State, classifications []headerClassification, counter *generationCounter) error {
	if !previous.Valid() || !current.Valid() || !reconstructed.Valid() || counter == nil || counter.limits != g.limits {
		return generationInvariantErrorForDimension(DimensionHeader)
	}
	var names map[string]struct{}
	nameBytes := 0
	previousGroups, err := collectProofHeaderGroups(previous.headers, &names, &nameBytes, g.limits.RecipeLimits, counter)
	if err != nil {
		return err
	}
	reconstructedGroups, err := collectProofHeaderGroups(reconstructed.headers, &names, &nameBytes, g.limits.RecipeLimits, counter)
	if err != nil {
		return err
	}
	var planningNames map[string]struct{}
	if err := collectProofHeaderNames(previous.headers, &planningNames, counter); err != nil {
		return err
	}
	if err := collectProofHeaderNames(current.headers, &planningNames, counter); err != nil {
		return err
	}
	if len(planningNames) != len(classifications) {
		return generationInvariantErrorForDimension(DimensionHeader)
	}
	previousName := ""
	for _, classification := range classifications {
		name := classification.name
		nameWork, ok := checkedNameScanWork(len(name), 10, 8)
		if !ok {
			return generationLimitError(limitNameMaxGenerationWorkUnits, counter.limits.MaxGenerationWorkUnits, nameWork, DimensionHeader)
		}
		if err := counter.chargeReconstructionProofWork(nameWork, DimensionHeader); err != nil {
			return err
		}
		if name == "" || previousName != "" && name <= previousName {
			return generationInvariantErrorForDimension(DimensionHeader)
		}
		previousName = name
		if _, exists := planningNames[name]; !exists {
			return generationInvariantErrorForDimension(DimensionHeader)
		}
		delete(planningNames, name)
		delete(names, name)
		relevant, err := g.classifyHeaderOnce(name)
		if err != nil {
			return err
		}
		if relevant != classification.relevant {
			return headerRelevanceInvariantError()
		}
		if !classification.relevant {
			continue
		}
		equal, err := equalProofHeaderValues(previousGroups[name].values, reconstructedGroups[name].values, counter)
		if err != nil {
			return err
		}
		if !equal {
			return reconstructionMismatchError(DimensionHeader)
		}
	}
	if len(names) != 0 || len(planningNames) != 0 {
		return reconstructionMismatchError(DimensionHeader)
	}
	return nil
}

// collectProofHeaderNames records the exact planning-state name union under semantic proof accounting.
func collectProofHeaderNames(headers rawmsg.HeaderBlock, names *map[string]struct{}, counter *generationCounter) error {
	return headers.VisitFieldsReverse(func(field rawmsg.HeaderFieldView) error {
		name := field.NameLower()
		work, ok := checkedNameScanWork(len(name), 3, 3)
		if !ok {
			return generationLimitError(limitNameMaxGenerationWorkUnits, counter.limits.MaxGenerationWorkUnits, work, DimensionHeader)
		}
		if err := counter.chargeReconstructionProofWork(work, DimensionHeader); err != nil {
			return err
		}
		if *names == nil {
			*names = make(map[string]struct{})
		}
		(*names)[name] = struct{}{}
		return nil
	})
}

// collectProofHeaderGroups builds bounded exact bottom-up groups under generation semantic proof accounting.
func collectProofHeaderGroups(headers rawmsg.HeaderBlock, names *map[string]struct{}, totalNameBytes *int, limits Limits, counter *generationCounter) (map[string]generationHeaderGroup, error) {
	var groups map[string]generationHeaderGroup
	err := headers.VisitFieldsReverse(func(field rawmsg.HeaderFieldView) error {
		name := field.NameLower()
		valueBytes := field.UnfoldedValueLen()
		nameWork, ok := checkedNameScanWork(len(name), 4, 0)
		if !ok {
			return generationLimitError(limitNameMaxGenerationWorkUnits, counter.limits.MaxGenerationWorkUnits, nameWork, DimensionHeader)
		}
		work, ok := checkedSum(nameWork, valueBytes, 6)
		if !ok {
			return generationLimitError(limitNameMaxGenerationWorkUnits, counter.limits.MaxGenerationWorkUnits, work, DimensionHeader)
		}
		if err := counter.chargeReconstructionProofWork(work, DimensionHeader); err != nil {
			return err
		}
		if _, exists := (*names)[name]; !exists {
			if len(*names)+1 > limits.MaxHeaderNames {
				return generationLimitError(limitNameMaxHeaderNames, limits.MaxHeaderNames, len(*names)+1, DimensionHeader)
			}
			if len(name) > limits.MaxHeaderNameBytes {
				return generationLimitError(limitNameMaxHeaderNameBytes, limits.MaxHeaderNameBytes, len(name), DimensionHeader)
			}
			nextNameBytes, added := checkedAdd(*totalNameBytes, len(name))
			if !added || nextNameBytes > limits.MaxTotalHeaderNameBytes {
				return generationLimitError(limitNameMaxTotalHeaderNameBytes, limits.MaxTotalHeaderNameBytes, nextNameBytes, DimensionHeader)
			}
			*totalNameBytes = nextNameBytes
			if *names == nil {
				*names = make(map[string]struct{})
			}
			(*names)[name] = struct{}{}
		}
		if groups == nil {
			groups = make(map[string]generationHeaderGroup)
		}
		group := groups[name]
		group.values = append(group.values, field.UnfoldedValueCopy())
		groups[name] = group
		return nil
	})
	if err != nil {
		return nil, err
	}
	return groups, nil
}

// equalProofHeaderValues compares exact unfolded sequences under reserved reconstruction work.
func equalProofHeaderValues(left, right [][]byte, counter *generationCounter) (bool, error) {
	if err := counter.chargeReconstructionProofWork(1, DimensionHeader); err != nil {
		return false, err
	}
	if len(left) != len(right) {
		return false, nil
	}
	for index := range left {
		if err := counter.chargeReconstructionProofWork(len(left[index])+1, DimensionHeader); err != nil {
			return false, err
		}
		if !bytes.Equal(left[index], right[index]) {
			return false, nil
		}
	}
	return true, nil
}

// reconstructionMismatchError returns one bounded semantic proof disagreement.
func reconstructionMismatchError(dimension Dimension) *Error {
	return newError(ErrorCodeReconstructionMismatch, ErrorLocation{}, ErrorDetails{Class: ErrorClassInvariant, Dimension: dimension}, nil)
}
