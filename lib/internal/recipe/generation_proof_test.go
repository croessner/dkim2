package recipe

import (
	"bytes"
	"sync"
	"testing"
)

const testProofSubjectName = "subject"

// TestGenerateProvesParsedRecipeRoundTrip verifies public recipe success only after strict parse and apply proof.
func TestGenerateProvesParsedRecipeRoundTrip(t *testing.T) {
	previous := mustGenerationState(t, []byte("Subject: previous\r\nX-Trace: keep\r\n\r\nold\r\n"))
	current := mustGenerationState(t, []byte("X-Trace: keep\r\nSubject: current\r\n\r\nnew\r\n"))
	request, err := NewGenerationRequest(previous, current, RejectUnavailableBody, AllowLiterals)
	if err != nil {
		t.Fatalf("NewGenerationRequest() code=%s", recipeTestErrorCode(err))
	}
	generator, err := NewGenerator(GenerationLimits{}, testHeaderRelevance{relevant: true})
	if err != nil {
		t.Fatalf("NewGenerator() code=%s", recipeTestErrorCode(err))
	}

	generation, usage, err := generator.Generate(request)
	if err != nil || !generation.Valid() || generation.Outcome() != GenerationOutcomeRecipe || !usage.Valid() {
		t.Fatalf("Generate() valid=%t usage=%t code=%s", generation.Valid(), usage.Valid(), recipeTestErrorCode(err))
	}
	if usage.ProofWorkUnits() <= 0 || usage.WorkUnits() < 2*generator.Limits().RecipeLimits.MaxOperationWorkUnits {
		t.Fatalf("proof accounting missing: proof=%d work=%d", usage.ProofWorkUnits(), usage.WorkUnits())
	}
	parsed, _, err := mustParser(t, generator.Limits().RecipeLimits).Parse(generation.DecodedJSON())
	if err != nil {
		t.Fatalf("returned JSON parse code=%s", recipeTestErrorCode(err))
	}
	returned, ok := generation.Recipe()
	if !ok || !recipesStructurallyEqual(returned, parsed) {
		t.Fatal("returned recipe differs from exact returned JSON model")
	}
	reconstructed, _, err := mustApplier(t, generator.Limits().RecipeLimits).Apply(current, returned)
	if err != nil || !reconstructed.Valid() || !reconstructed.body.Equal(previous.body) || reconstructed.framing != previous.framing {
		t.Fatalf("returned recipe does not reconstruct target: code=%s", recipeTestErrorCode(err))
	}
	assertConcreteHeaderGroupsEqual(t, previous, reconstructed, testProofSubjectName, "x-trace")

	jsonView := generation.DecodedJSON()
	jsonView[0] ^= 1
	recipeView, _ := generation.Recipe()
	recipeView.headers[0].steps[0].data[0][0] ^= 1
	recipeView.bodySteps[0].data[0][0] ^= 1
	if !bytes.HasPrefix(generation.DecodedJSON(), []byte("{")) {
		t.Fatal("generation JSON accessor aliases protected storage")
	}
	stable, _ := generation.Recipe()
	if recipesStructurallyEqual(recipeView, stable) {
		t.Fatal("generation recipe accessor aliases header or body literals")
	}
}

// TestGenerateRemovesCurrentOnlyRelevantGroup verifies an empty target group remains a valid proof relation.
func TestGenerateRemovesCurrentOnlyRelevantGroup(t *testing.T) {
	previous := mustGenerationState(t, []byte("Keep: value\r\n\r\nbody\r\n"))
	current := mustGenerationState(t, []byte("Subject: remove\r\nKeep: value\r\n\r\nbody\r\n"))
	request, _ := NewGenerationRequest(previous, current, RejectUnavailableBody, CopyOnly)
	generator, _ := NewGenerator(GenerationLimits{}, testHeaderRelevance{relevant: true})
	generation, _, err := generator.Generate(request)
	if err != nil || !generation.Valid() {
		t.Fatalf("Generate() valid=%t code=%s", generation.Valid(), recipeTestErrorCode(err))
	}
	recipe, _ := generation.Recipe()
	reconstructed, _, err := mustApplier(t, generator.Limits().RecipeLimits).Apply(current, recipe)
	if err != nil || len(reconstructed.Headers().FieldsByName(testProofSubjectName)) != 0 {
		t.Fatalf("current-only group retained: code=%s", recipeTestErrorCode(err))
	}
}

// TestGenerateUnavailableBodyProvesOnlyUnavailableState verifies b:null never claims known-body reconstruction.
func TestGenerateUnavailableBodyProvesOnlyUnavailableState(t *testing.T) {
	previous := mustGenerationState(t, []byte("Subject: previous\r\n"))
	current := mustGenerationState(t, []byte("Subject: current\r\n\r\nbody\r\n"))
	request, err := NewGenerationRequest(previous, current, AllowUnavailableBody, AllowLiterals)
	if err != nil {
		t.Fatal("request setup failed")
	}
	generator, err := NewGenerator(GenerationLimits{}, testHeaderRelevance{relevant: true})
	if err != nil {
		t.Fatal("generator setup failed")
	}
	generation, _, err := generator.Generate(request)
	if err != nil || generation.BodyOutcome() != BodyGenerationUnavailable {
		t.Fatalf("Generate() outcome=%s code=%s", generation.BodyOutcome(), recipeTestErrorCode(err))
	}
	recipe, ok := generation.Recipe()
	if !ok || recipe.BodyMode() != BodyModeUnavailable {
		t.Fatal("unavailable generation lost parsed b:null model")
	}
	reconstructed, _, err := mustApplier(t, generator.Limits().RecipeLimits).Apply(current, recipe)
	if err != nil || reconstructed.BodyState() != BodyAvailabilityUnavailable {
		t.Fatalf("b:null proof state=%s code=%s", reconstructed.BodyState(), recipeTestErrorCode(err))
	}
	assertConcreteHeaderGroupsEqual(t, previous, reconstructed, testProofSubjectName)
}

// TestGenerateUnchangedReturnsNoProofOutput verifies the closed identity path avoids self-proof reservation.
func TestGenerateUnchangedReturnsNoProofOutput(t *testing.T) {
	state := mustGenerationState(t, []byte("Subject: same\r\n\r\nbody\r\n"))
	request, _ := NewGenerationRequest(state, state, RejectUnavailableBody, CopyOnly)
	generator, _ := NewGenerator(GenerationLimits{}, testHeaderRelevance{relevant: true})
	generation, usage, err := generator.Generate(request)
	if err != nil || generation.Outcome() != GenerationOutcomeUnchanged || generation.DecodedJSON() != nil || usage.ProofWorkUnits() != 0 {
		t.Fatalf("unchanged outcome=%s json=%d proof=%d code=%s", generation.Outcome(), len(generation.DecodedJSON()), usage.ProofWorkUnits(), recipeTestErrorCode(err))
	}
	if _, ok := generation.Recipe(); ok {
		t.Fatal("unchanged generation exposed recipe")
	}
}

// TestPostProofTransferFailureClearsSerializedUsage verifies centralized failure cleanup after serialization.
func TestPostProofTransferFailureClearsSerializedUsage(t *testing.T) {
	counter := newGenerationCounter(DefaultGenerationLimits())
	counter.jsonBytes = 17
	generation, err := newProvenGeneration(generationProof{validated: true})
	usage := counter.failedUsage()
	if generation.Valid() || !IsErrorCode(err, ErrorCodeGeneratedOutputInvariant) || usage.JSONBytes() != 0 {
		t.Fatalf("transfer failure valid=%t json=%d code=%s", generation.Valid(), usage.JSONBytes(), recipeTestErrorCode(err))
	}
}

// TestProveReconstructionDetectsBodyBytesAndFraming verifies both known-body dimensions are exact.
func TestProveReconstructionDetectsBodyBytesAndFraming(t *testing.T) {
	generator, _ := NewGenerator(GenerationLimits{}, testHeaderRelevance{relevant: true})
	classifications := []headerClassification{{name: testProofSubjectName, relevant: true}}
	for _, test := range []struct {
		name          string
		previous      []byte
		reconstructed []byte
	}{
		{name: "bytes", previous: []byte("Subject: x\r\n\r\nold\r\n"), reconstructed: []byte("Subject: x\r\n\r\nnew\r\n")},
		{name: "framing", previous: []byte("Subject: x\r\n"), reconstructed: []byte("Subject: x\r\n\r\n")},
	} {
		t.Run(test.name, func(t *testing.T) {
			counter := newGenerationCounter(generator.limits)
			if err := counter.reserveProofBudgets(); err != nil {
				t.Fatal("proof reservation failed")
			}
			if err := counter.recordParseProofUsage(newUsage(0, 0, 0, 0)); err != nil {
				t.Fatal("parse proof setup failed")
			}
			if err := counter.recordReconstructionProofUsage(newUsage(0, 0, 0, 0)); err != nil {
				t.Fatal("apply proof setup failed")
			}
			previousState := mustGenerationState(t, test.previous)
			reconstructedState := mustGenerationState(t, test.reconstructed)
			err := generator.proveReconstruction(previousState, reconstructedState, reconstructedState, BodyGenerationGenerated, classifications, &counter)
			if !IsErrorCode(err, ErrorCodeReconstructionMismatch) {
				t.Fatalf("body disagreement code=%s", recipeTestErrorCode(err))
			}
		})
	}
}

// TestGenerationBodyMetadataMustMatchParsedModel verifies every body outcome disagreement fails closed.
func TestGenerationBodyMetadataMustMatchParsedModel(t *testing.T) {
	for _, test := range []struct {
		outcome BodyGenerationOutcome
		reason  BodyUnavailableReason
		json    string
	}{
		{outcome: BodyGenerationUnchanged, json: `{"b":[]}`},
		{outcome: BodyGenerationGenerated, json: `{"b":null}`},
		{outcome: BodyGenerationUnavailable, reason: BodyUnavailableReasonUnrepresentable, json: `{"h":{"subject":[]}}`},
	} {
		parsed := mustParseRecipe(t, test.json)
		serialized := serializedGenerationPlan{bodyOutcome: test.outcome, unavailable: test.reason, decodedJSON: []byte(test.json), validated: true, initialized: true}
		if generationBodyModelMatches(serialized, parsed) {
			t.Fatalf("metadata %s accepted model %s", test.outcome, parsed.BodyMode())
		}
	}
}

// TestProveSerializedGenerationFailsClosed verifies syntax, apply, and semantic disagreements expose no proof token.
func TestProveSerializedGenerationFailsClosed(t *testing.T) {
	previous := mustGenerationState(t, []byte("Subject: previous\r\n\r\nbody\r\n"))
	current := mustGenerationState(t, []byte("Subject: current\r\n\r\nbody\r\n"))
	request, err := NewGenerationRequest(previous, current, RejectUnavailableBody, AllowLiterals)
	if err != nil {
		t.Fatal("request setup failed")
	}
	generator, err := NewGenerator(GenerationLimits{}, testHeaderRelevance{relevant: true})
	if err != nil {
		t.Fatal("generator setup failed")
	}
	for _, test := range []struct {
		name string
		json string
		code ErrorCode
	}{
		{name: "parse", json: `{"h":`, code: ErrorCodeGeneratedOutputInvariant},
		{name: "apply", json: `{"h":{"subject":[{"c":[99,99]}]}}`, code: ErrorCodeGeneratedOutputInvariant},
		{name: "mismatch", json: `{"h":{"subject":[{"d":["wrong"]}]}}`, code: ErrorCodeReconstructionMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			counter := newGenerationCounter(generator.limits)
			counter.jsonBytes = len(test.json)
			serialized := serializedGenerationPlan{
				bodyOutcome: BodyGenerationUnchanged, decodedJSON: []byte(test.json),
				classifications: []headerClassification{{name: testProofSubjectName, relevant: true}}, classified: true,
				validated: true, initialized: true,
			}
			proof, err := generator.proveSerializedGeneration(request, serialized, &counter)
			if proof.Valid() || !IsErrorCode(err, test.code) || !counter.usage().Valid() || counter.usage().JSONBytes() != 0 {
				t.Fatalf("proof valid=%t json=%d code=%s", proof.Valid(), counter.usage().JSONBytes(), recipeTestErrorCode(err))
			}
		})
	}

	counter := newGenerationCounter(generator.limits)
	counter.jsonBytes = len(`{"b":null}`)
	serialized := serializedGenerationPlan{
		bodyOutcome: BodyGenerationGenerated, decodedJSON: []byte(`{"b":null}`),
		classifications: []headerClassification{{name: testProofSubjectName, relevant: true}}, classified: true,
		validated: true, initialized: true,
	}
	proof, err := generator.proveSerializedGeneration(request, serialized, &counter)
	if proof.Valid() || !IsErrorCode(err, ErrorCodeGeneratedOutputInvariant) || counter.usage().JSONBytes() != 0 {
		t.Fatalf("b:null metadata fallback: valid=%t json=%d code=%s", proof.Valid(), counter.usage().JSONBytes(), recipeTestErrorCode(err))
	}

	toxic := "PLANNING-LABEL-TOXIC-CONTENT"
	counter = newGenerationCounter(generator.limits)
	serialized = serializedGenerationPlan{
		bodyOutcome: BodyGenerationUnchanged, decodedJSON: []byte(`{"h":{"subject":[{"d":["` + toxic + `\r"]}]}}`),
		classifications: []headerClassification{{name: testProofSubjectName, relevant: true}}, classified: true,
		validated: true, initialized: true,
	}
	counter.jsonBytes = len(serialized.decodedJSON)
	_, err = generator.proveSerializedGeneration(request, serialized, &counter)
	if !IsErrorCode(err, ErrorCodeGeneratedOutputInvariant) || bytes.Contains([]byte(err.Error()), []byte(toxic)) {
		t.Fatalf("toxic proof error code=%s exposed=%t", recipeTestErrorCode(err), bytes.Contains([]byte(err.Error()), []byte(toxic)))
	}
}

// TestGenerationProofReservationIsAtomic verifies both M8 work caps are reserved before parser allocation.
func TestGenerationProofReservationIsAtomic(t *testing.T) {
	limits := DefaultGenerationLimits()
	reserve := 2 * limits.RecipeLimits.MaxOperationWorkUnits
	exact := newGenerationCounter(limits)
	exact.workUnits = limits.MaxGenerationWorkUnits - reserve
	if err := exact.reserveProofBudgets(); err != nil || exact.workUnits != limits.MaxGenerationWorkUnits {
		t.Fatalf("exact reservation work=%d code=%s", exact.workUnits, recipeTestErrorCode(err))
	}
	oneUnder := newGenerationCounter(limits)
	oneUnder.workUnits = limits.MaxGenerationWorkUnits - reserve + 1
	before := oneUnder.workUnits
	if err := oneUnder.reserveProofBudgets(); !IsErrorCode(err, ErrorCodeLimitExceeded) || oneUnder.workUnits != before {
		t.Fatalf("one-under reservation mutated=%t code=%s", oneUnder.workUnits != before, recipeTestErrorCode(err))
	}
}

// TestSemanticProofWorkIsTransactional verifies exact aggregate charging and one-over failure atomicity.
func TestSemanticProofWorkIsTransactional(t *testing.T) {
	limits := DefaultGenerationLimits()
	exact := newGenerationCounter(limits)
	if err := exact.reserveProofBudgets(); err != nil {
		t.Fatal("proof reservation failed")
	}
	if err := exact.recordParseProofUsage(newUsage(0, 0, 0, 3)); err != nil {
		t.Fatal("parse proof accounting failed")
	}
	if err := exact.recordReconstructionProofUsage(newUsage(0, 0, 0, limits.RecipeLimits.MaxOperationWorkUnits)); err != nil {
		t.Fatal("exact apply proof accounting failed")
	}
	exact.workUnits = limits.MaxGenerationWorkUnits - 5
	proofBefore := exact.proofWorkUnits
	if err := exact.chargeReconstructionProofWork(5, DimensionHeader); err != nil || exact.workUnits != limits.MaxGenerationWorkUnits || exact.proofWorkUnits != proofBefore+5 {
		t.Fatalf("exact semantic work=%d proof=%d code=%s", exact.workUnits, exact.proofWorkUnits, recipeTestErrorCode(err))
	}

	oneOver := newGenerationCounter(limits)
	if err := oneOver.reserveProofBudgets(); err != nil {
		t.Fatal("proof reservation failed")
	}
	if err := oneOver.recordParseProofUsage(newUsage(0, 0, 0, 3)); err != nil {
		t.Fatal("parse proof accounting failed")
	}
	if err := oneOver.recordReconstructionProofUsage(newUsage(0, 0, 0, limits.RecipeLimits.MaxOperationWorkUnits)); err != nil {
		t.Fatal("exact apply proof accounting failed")
	}
	oneOver.workUnits = limits.MaxGenerationWorkUnits - 4
	workBefore, semanticBefore, proofBefore := oneOver.workUnits, oneOver.semanticProofWorkUnits, oneOver.proofWorkUnits
	err := oneOver.chargeReconstructionProofWork(5, DimensionHeader)
	if !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != limitNameMaxGenerationWorkUnits || oneOver.workUnits != workBefore || oneOver.semanticProofWorkUnits != semanticBefore || oneOver.proofWorkUnits != proofBefore {
		t.Fatalf("one-over mutated work=%t semantic=%t proof=%t code=%s", oneOver.workUnits != workBefore, oneOver.semanticProofWorkUnits != semanticBefore, oneOver.proofWorkUnits != proofBefore, recipeTestErrorCode(err))
	}
}

// TestProofUsageRecordsZeroWorkOnlyOnce verifies initialized zero usage cannot bypass phase ownership.
func TestProofUsageRecordsZeroWorkOnlyOnce(t *testing.T) {
	counter := newGenerationCounter(DefaultGenerationLimits())
	if err := counter.reserveProofBudgets(); err != nil {
		t.Fatal("proof reservation failed")
	}
	zero := newUsage(0, 0, 0, 0)
	if err := counter.recordReconstructionProofUsage(zero); !IsErrorCode(err, ErrorCodeGeneratedOutputInvariant) {
		t.Fatalf("apply-before-parse code=%s", recipeTestErrorCode(err))
	}
	if err := counter.chargeReconstructionProofWork(0, DimensionHeader); !IsErrorCode(err, ErrorCodeGeneratedOutputInvariant) {
		t.Fatalf("semantic-before-parse code=%s", recipeTestErrorCode(err))
	}
	if err := counter.recordParseProofUsage(zero); err != nil {
		t.Fatal("first zero parse usage rejected")
	}
	if err := counter.recordParseProofUsage(zero); !IsErrorCode(err, ErrorCodeGeneratedOutputInvariant) {
		t.Fatalf("second zero parse usage code=%s", recipeTestErrorCode(err))
	}
	if err := counter.chargeReconstructionProofWork(0, DimensionHeader); !IsErrorCode(err, ErrorCodeGeneratedOutputInvariant) {
		t.Fatalf("semantic-before-apply code=%s", recipeTestErrorCode(err))
	}
	if err := counter.recordReconstructionProofUsage(zero); err != nil {
		t.Fatal("first zero apply usage rejected")
	}
	if err := counter.recordReconstructionProofUsage(zero); !IsErrorCode(err, ErrorCodeGeneratedOutputInvariant) {
		t.Fatalf("second zero apply usage code=%s", recipeTestErrorCode(err))
	}
}

// TestProofRejectsPhantomClassificationMetadata verifies retained decisions exactly match the planning-state union.
func TestProofRejectsPhantomClassificationMetadata(t *testing.T) {
	state := mustGenerationState(t, []byte("Subject: value\r\n\r\nbody\r\n"))
	generator, _ := NewGenerator(GenerationLimits{}, testHeaderRelevance{relevant: true})
	counter := newGenerationCounter(generator.limits)
	if err := counter.reserveProofBudgets(); err != nil {
		t.Fatal("proof reservation failed")
	}
	if err := counter.recordParseProofUsage(newUsage(0, 0, 0, 0)); err != nil {
		t.Fatal("parse proof setup failed")
	}
	if err := counter.recordReconstructionProofUsage(newUsage(0, 0, 0, 0)); err != nil {
		t.Fatal("apply proof setup failed")
	}
	classifications := []headerClassification{{name: "phantom", relevant: true}, {name: testProofSubjectName, relevant: true}}
	err := generator.proveRelevantHeaderGroups(state, state, state, classifications, &counter)
	if !IsErrorCode(err, ErrorCodeGeneratedOutputInvariant) {
		t.Fatalf("phantom classification code=%s", recipeTestErrorCode(err))
	}
}

// TestProveSerializedGenerationFailsSemanticLimitWithoutNullFallback verifies end-to-end proof-limit closure.
func TestProveSerializedGenerationFailsSemanticLimitWithoutNullFallback(t *testing.T) {
	previous := mustGenerationState(t, []byte("Subject: previous\r\n"))
	current := mustGenerationState(t, []byte("Subject: current\r\n\r\nbody\r\n"))
	request, _ := NewGenerationRequest(previous, current, AllowUnavailableBody, AllowLiterals)
	generator, _ := NewGenerator(GenerationLimits{}, testHeaderRelevance{relevant: true})
	jsonBytes := []byte(`{"h":{"subject":[{"d":["previous"]}]},"b":null}`)
	serialized := serializedGenerationPlan{
		bodyOutcome: BodyGenerationUnavailable, unavailable: BodyUnavailableReasonUnrepresentable,
		decodedJSON: jsonBytes, classifications: []headerClassification{{name: testProofSubjectName, relevant: true}},
		classified: true, validated: true, initialized: true,
	}
	counter := newGenerationCounter(generator.limits)
	reserve := 2 * generator.limits.RecipeLimits.MaxOperationWorkUnits
	counter.workUnits = generator.limits.MaxGenerationWorkUnits - reserve - 1
	counter.jsonBytes = len(jsonBytes)
	proof, err := generator.proveSerializedGeneration(request, serialized, &counter)
	if proof.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != limitNameMaxGenerationWorkUnits || counter.usage().JSONBytes() != 0 {
		t.Fatalf("semantic limit valid=%t json=%d limit=%s code=%s", proof.Valid(), counter.usage().JSONBytes(), recipeTestLimitName(err), recipeTestErrorCode(err))
	}
}

// TestGenerateRejectsFinalRelevanceFlip verifies proof decisions remain correlated with planning.
func TestGenerateRejectsFinalRelevanceFlip(t *testing.T) {
	previous := mustGenerationState(t, []byte("Subject: previous\r\n\r\nbody\r\n"))
	current := mustGenerationState(t, []byte("Subject: current\r\n\r\nbody\r\n"))
	request, _ := NewGenerationRequest(previous, current, RejectUnavailableBody, AllowLiterals)
	relevance := &flippingHeaderRelevance{flipAfter: 2}
	generator, err := NewGenerator(GenerationLimits{}, relevance)
	if err != nil {
		t.Fatal("generator setup failed")
	}
	generation, usage, err := generator.Generate(request)
	if generation.Valid() || !usage.Valid() || usage.JSONBytes() != 0 || !IsErrorCode(err, ErrorCodeHeaderRelevance) {
		t.Fatalf("relevance flip valid=%t json=%d code=%s", generation.Valid(), usage.JSONBytes(), recipeTestErrorCode(err))
	}
}

// TestGenerateUsesExactSameNarrowParserAndApplierLimits verifies output needs no proof relaxation.
func TestGenerateUsesExactSameNarrowParserAndApplierLimits(t *testing.T) {
	previous := mustGenerationState(t, []byte("Subject: previous\r\n\r\nold\r\n"))
	current := mustGenerationState(t, []byte("Subject: current\r\n\r\nnew\r\n"))
	request, _ := NewGenerationRequest(previous, current, RejectUnavailableBody, AllowLiterals)
	baseline, _ := NewGenerator(GenerationLimits{}, testHeaderRelevance{relevant: true})
	baselineGeneration, _, err := baseline.Generate(request)
	if err != nil {
		t.Fatal("baseline generation failed")
	}
	exactBytes := len(baselineGeneration.DecodedJSON())
	exactLimits := DefaultGenerationLimits()
	exactLimits.RecipeLimits.MaxDecodedRecipeBytes = exactBytes
	exactLimits.RecipeLimits.MaxTotalLiteralBytes = exactBytes
	exactLimits.RecipeLimits.MaxDataStringBytes = exactBytes
	exact, err := NewGenerator(exactLimits, testHeaderRelevance{relevant: true})
	if err != nil {
		t.Fatalf("exact generator setup code=%s", recipeTestErrorCode(err))
	}
	generation, usage, err := exact.Generate(request)
	if err != nil || !generation.Valid() || usage.JSONBytes() != exactBytes {
		t.Fatalf("exact Generate() valid=%t json=%d code=%s", generation.Valid(), usage.JSONBytes(), recipeTestErrorCode(err))
	}
	parsed, _, err := mustParser(t, exact.Limits().RecipeLimits).Parse(generation.DecodedJSON())
	if err != nil {
		t.Fatalf("exact parser code=%s", recipeTestErrorCode(err))
	}
	if reconstructed, _, applyErr := mustApplier(t, exact.Limits().RecipeLimits).Apply(current, parsed); applyErr != nil || !reconstructed.Valid() {
		t.Fatalf("exact applier valid=%t code=%s", reconstructed.Valid(), recipeTestErrorCode(applyErr))
	}

	oneUnderLimits := exactLimits
	oneUnderLimits.RecipeLimits.MaxDecodedRecipeBytes = exactBytes - 1
	oneUnderLimits.RecipeLimits.MaxTotalLiteralBytes = exactBytes - 1
	oneUnderLimits.RecipeLimits.MaxDataStringBytes = exactBytes - 1
	oneUnder, err := NewGenerator(oneUnderLimits, testHeaderRelevance{relevant: true})
	if err != nil {
		t.Fatalf("one-under generator setup code=%s", recipeTestErrorCode(err))
	}
	failed, failedUsage, err := oneUnder.Generate(request)
	if failed.Valid() || failedUsage.JSONBytes() != 0 || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != limitNameMaxDecodedRecipeBytes {
		t.Fatalf("one-under valid=%t json=%d limit=%s code=%s", failed.Valid(), failedUsage.JSONBytes(), recipeTestLimitName(err), recipeTestErrorCode(err))
	}
}

// TestGeneratorGenerateIsConcurrentSafe verifies immutable dependencies support parallel full proof operations.
func TestGeneratorGenerateIsConcurrentSafe(t *testing.T) {
	previous := mustGenerationState(t, []byte("Subject: previous\r\n\r\nold\r\n"))
	current := mustGenerationState(t, []byte("Subject: current\r\n\r\nnew\r\n"))
	request, _ := NewGenerationRequest(previous, current, RejectUnavailableBody, AllowLiterals)
	generator, _ := NewGenerator(GenerationLimits{}, testHeaderRelevance{relevant: true})
	baseline, baselineUsage, baselineErr := generator.Generate(request)
	if baselineErr != nil || !baseline.Valid() || !baselineUsage.Valid() || baseline.Outcome() != GenerationOutcomeRecipe {
		t.Fatal("concurrent generation baseline failed")
	}
	baselineJSON := baseline.DecodedJSON()
	if len(baselineJSON) == 0 {
		t.Fatal("concurrent generation baseline omitted recipe JSON")
	}
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 20 {
				generation, usage, err := generator.Generate(request)
				if err != nil || !generation.Valid() || !usage.Valid() || usage != baselineUsage ||
					generation.Outcome() != baseline.Outcome() || generation.BodyOutcome() != baseline.BodyOutcome() ||
					generation.BodyUnavailableReason() != baseline.BodyUnavailableReason() || !bytes.Equal(generation.DecodedJSON(), baselineJSON) {
					t.Errorf("Generate() valid=%t usage=%t code=%s", generation.Valid(), usage.Valid(), recipeTestErrorCode(err))
					return
				}
				view := generation.DecodedJSON()
				view[0] ^= 0xff
				if bytes.Equal(view, generation.DecodedJSON()) {
					t.Error("concurrent generation exposed mutable JSON storage")
					return
				}
			}
		}()
	}
	wait.Wait()
}

// recipesStructurallyEqual compares package-owned parsed recipe models without JSON reserialization.
func recipesStructurallyEqual(left, right Recipe) bool {
	if !left.Valid() || !right.Valid() || left.hasHeaderRecipe != right.hasHeaderRecipe || left.bodyMode != right.bodyMode || len(left.headers) != len(right.headers) || len(left.bodySteps) != len(right.bodySteps) {
		return false
	}
	for index := range left.headers {
		if left.headers[index].name != right.headers[index].name || !stepsStructurallyEqual(left.headers[index].steps, right.headers[index].steps) {
			return false
		}
	}
	return stepsStructurallyEqual(left.bodySteps, right.bodySteps)
}

// stepsStructurallyEqual compares exact parsed step structure and literal bytes.
func stepsStructurallyEqual(left, right []step) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].kind != right[index].kind || left[index].copyStart != right[index].copyStart || left[index].copyEnd != right[index].copyEnd || len(left[index].data) != len(right[index].data) {
			return false
		}
		for dataIndex := range left[index].data {
			if !bytes.Equal(left[index].data[dataIndex], right[index].data[dataIndex]) {
				return false
			}
		}
	}
	return true
}

// assertConcreteHeaderGroupsEqual independently compares exact unfolded occurrences for named groups.
func assertConcreteHeaderGroupsEqual(t *testing.T, previous, reconstructed State, names ...string) {
	t.Helper()
	for groupIndex, name := range names {
		left := previous.Headers().FieldsByName(name)
		right := reconstructed.Headers().FieldsByName(name)
		if len(left) != len(right) {
			t.Fatalf("header group %d count=%d want=%d", groupIndex, len(right), len(left))
		}
		for index := range left {
			if !bytes.Equal(left[index].UnfoldedValue(), right[index].UnfoldedValue()) {
				t.Fatalf("header group %d occurrence %d differs", groupIndex, index)
			}
		}
	}
}
