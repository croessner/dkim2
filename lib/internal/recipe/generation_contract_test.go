package recipe

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

type testHeaderRelevance struct {
	validateErr error
	relevant    bool
	classifyErr error
}

// Validate implements HeaderRelevance for contract tests.
func (r testHeaderRelevance) Validate() error { return r.validateErr }

// IsRelevantHeader implements HeaderRelevance for contract tests.
func (r testHeaderRelevance) IsRelevantHeader(string) (bool, error) {
	return r.relevant, r.classifyErr
}

type testPointerHeaderRelevance struct{}

// Validate implements HeaderRelevance for typed-nil tests.
func (*testPointerHeaderRelevance) Validate() error { return nil }

// IsRelevantHeader implements HeaderRelevance for typed-nil tests.
func (*testPointerHeaderRelevance) IsRelevantHeader(string) (bool, error) { return true, nil }

type alternatingHeaderRelevance struct {
	mu    sync.Mutex
	value bool
}

type mutableValidationHeaderRelevance struct {
	mu              sync.Mutex
	validateErr     error
	validationCalls int
	alternating     bool
}

// Validate returns mutable test state for fail-closed dependency validation tests.
func (r *mutableValidationHeaderRelevance) Validate() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.validationCalls++
	if r.alternating && r.validationCalls%2 == 0 {
		return errors.New("Subject: secret-marker")
	}
	return r.validateErr
}

// IsRelevantHeader implements HeaderRelevance for validation-boundary tests.
func (*mutableValidationHeaderRelevance) IsRelevantHeader(string) (bool, error) { return true, nil }

// setValidationError changes test validation state after generator construction.
func (r *mutableValidationHeaderRelevance) setValidationError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.validateErr = err
}

// Validate implements HeaderRelevance for nondeterminism tests.
func (*alternatingHeaderRelevance) Validate() error { return nil }

// IsRelevantHeader alternates its result to exercise fail-closed reclassification.
func (r *alternatingHeaderRelevance) IsRelevantHeader(string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.value = !r.value
	return r.value, nil
}

// TestGenerationPoliciesAreClosed verifies secure zero values and future-value rejection.
func TestGenerationPoliciesAreClosed(t *testing.T) {
	if !CopyOnly.Known() || !AllowLiterals.Known() || LiteralDisclosurePolicy(2).Known() {
		t.Fatal("literal disclosure policy vocabulary is not closed")
	}
	if !RejectUnavailableBody.Known() || !AllowUnavailableBody.Known() || BodyUnavailablePolicy(2).Known() {
		t.Fatal("body-unavailable policy vocabulary is not closed")
	}
	if GenerationOutcome("").Known() || !GenerationOutcomeUnchanged.Known() || !GenerationOutcomeRecipe.Known() {
		t.Fatal("generation outcome vocabulary is not closed")
	}
	if BodyGenerationOutcome("").Known() || !BodyGenerationUnchanged.Known() || !BodyGenerationGenerated.Known() || !BodyGenerationUnavailable.Known() {
		t.Fatal("body generation outcome vocabulary is not closed")
	}
	if BodyUnavailableReason("").Known() || !BodyUnavailableReasonUnrepresentable.Known() || !BodyUnavailableReasonLiteralRequired.Known() {
		t.Fatal("body-unavailable reason vocabulary is not closed")
	}
}

// TestGenerationRequestValidatesKnownInitializedStates verifies immutable request construction.
func TestGenerationRequestValidatesKnownInitializedStates(t *testing.T) {
	previous := mustGenerationState(t, []byte("Subject: previous\r\n\r\nbody\r\n"))
	current := mustGenerationState(t, []byte("Subject: current\r\n\r\nbody\r\n"))
	request, err := NewGenerationRequest(previous, current, RejectUnavailableBody, CopyOnly)
	if err != nil || !request.Valid() {
		t.Fatalf("NewGenerationRequest() valid=%t code=%s", request.Valid(), recipeTestErrorCode(err))
	}
	if !request.Previous().Valid() || !request.Current().Valid() || request.BodyUnavailablePolicy() != RejectUnavailableBody || request.LiteralPolicy() != CopyOnly {
		t.Fatal("request accessors lost validated values")
	}

	message, err := rawmsg.Parse([]byte("A: b\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatalf("rawmsg.Parse() failed: error=%t", err != nil)
	}
	unavailable, err := newUnavailableState(message.Headers())
	if err != nil {
		t.Fatalf("newUnavailableState() code=%s", recipeTestErrorCode(err))
	}
	for _, test := range []struct {
		name     string
		previous State
		current  State
		body     BodyUnavailablePolicy
		literal  LiteralDisclosurePolicy
	}{
		{name: "zero previous", current: current},
		{name: "zero current", previous: previous},
		{name: "unavailable previous", previous: unavailable, current: current},
		{name: "unavailable current", previous: previous, current: unavailable},
		{name: "invalid body policy", previous: previous, current: current, body: BodyUnavailablePolicy(2)},
		{name: "invalid literal policy", previous: previous, current: current, literal: LiteralDisclosurePolicy(2)},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := NewGenerationRequest(test.previous, test.current, test.body, test.literal)
			if request.Valid() || !IsErrorCode(err, ErrorCodeInvalidRequest) && !IsErrorCode(err, ErrorCodeInvalidPolicy) {
				t.Fatalf("invalid request accepted: valid=%t code=%s", request.Valid(), recipeTestErrorCode(err))
			}
		})
	}
}

// TestGeneratorRejectsInvalidRelevanceContracts verifies dependency failures remain opaque.
func TestGeneratorRejectsInvalidRelevanceContracts(t *testing.T) {
	var typedNil *testPointerHeaderRelevance
	toxic := errors.New("Subject: secret-marker")
	for _, test := range []struct {
		name      string
		relevance HeaderRelevance
	}{
		{name: "nil"},
		{name: "typed nil", relevance: typedNil},
		{name: "invalid", relevance: testHeaderRelevance{validateErr: toxic}},
	} {
		t.Run(test.name, func(t *testing.T) {
			generator, err := NewGenerator(GenerationLimits{}, test.relevance)
			if generator.Valid() {
				t.Fatal("invalid relevance produced a valid generator")
			}
			assertClosedSafeGenerationError(t, err, ErrorCodeInvalidGenerator, ErrorClassState, "secret-marker")
		})
	}

	generator, err := NewGenerator(GenerationLimits{}, testHeaderRelevance{relevant: true, classifyErr: toxic})
	if err != nil {
		t.Fatalf("NewGenerator() code=%s", recipeTestErrorCode(err))
	}
	_, err = generator.classifyStableHeader("subject")
	assertClosedSafeGenerationError(t, err, ErrorCodeHeaderRelevance, ErrorClassInvariant, "secret-marker")
	_, err = generator.classifyStableHeader("Subject")
	assertClosedSafeGenerationError(t, err, ErrorCodeHeaderRelevance, ErrorClassInvariant, "Subject")

	nondeterministic, err := NewGenerator(GenerationLimits{}, &alternatingHeaderRelevance{})
	if err != nil {
		t.Fatalf("NewGenerator() code=%s", recipeTestErrorCode(err))
	}
	_, err = nondeterministic.classifyStableHeader("subject")
	assertClosedSafeGenerationError(t, err, ErrorCodeHeaderRelevance, ErrorClassInvariant, "subject")
}

// TestGeneratorRevalidatesRelevanceAtEveryUseBoundary verifies mutable dependencies fail closed.
func TestGeneratorRevalidatesRelevanceAtEveryUseBoundary(t *testing.T) {
	relevance := &mutableValidationHeaderRelevance{}
	generator, err := NewGenerator(GenerationLimits{}, relevance)
	if err != nil {
		t.Fatalf("NewGenerator() code=%s", recipeTestErrorCode(err))
	}
	previous := mustGenerationState(t, []byte("A: previous\r\n\r\nbody\r\n"))
	current := mustGenerationState(t, []byte("A: current\r\n\r\nbody\r\n"))
	request, err := NewGenerationRequest(previous, current, RejectUnavailableBody, CopyOnly)
	if err != nil {
		t.Fatalf("NewGenerationRequest() code=%s", recipeTestErrorCode(err))
	}
	relevance.setValidationError(errors.New("Subject: secret-marker"))
	if generator.Valid() {
		t.Fatal("generator remained valid after relevance invalidation")
	}
	err = generator.validateRequest(request)
	assertClosedSafeGenerationError(t, err, ErrorCodeInvalidGenerator, ErrorClassState, "secret-marker")
	_, err = generator.classifyStableHeader("subject")
	assertClosedSafeGenerationError(t, err, ErrorCodeInvalidGenerator, ErrorClassState, "secret-marker")
	if generator.Limits() != (GenerationLimits{}) {
		t.Fatal("invalidated generator exposed normalized limits")
	}
}

// TestGeneratorRejectsNondeterministicValidation verifies constructor validation is stable.
func TestGeneratorRejectsNondeterministicValidation(t *testing.T) {
	relevance := &mutableValidationHeaderRelevance{alternating: true}
	generator, err := NewGenerator(GenerationLimits{}, relevance)
	if generator.Valid() {
		t.Fatal("nondeterministic validation produced a valid generator")
	}
	assertClosedSafeGenerationError(t, err, ErrorCodeInvalidGenerator, ErrorClassState, "secret-marker")
}

// TestGeneratorValidatesRequestsBeforeGenerationWork verifies zero and invalid contracts fail closed.
func TestGeneratorValidatesRequestsBeforeGenerationWork(t *testing.T) {
	previous := mustGenerationState(t, []byte("A: previous\r\n\r\nbody\r\n"))
	current := mustGenerationState(t, []byte("A: current\r\n\r\nbody\r\n"))
	request, err := NewGenerationRequest(previous, current, AllowUnavailableBody, AllowLiterals)
	if err != nil {
		t.Fatalf("NewGenerationRequest() code=%s", recipeTestErrorCode(err))
	}
	generator, err := NewGenerator(GenerationLimits{}, testHeaderRelevance{relevant: true})
	if err != nil {
		t.Fatalf("NewGenerator() code=%s", recipeTestErrorCode(err))
	}
	if err := generator.validateRequest(request); err != nil {
		t.Fatalf("valid request rejected: code=%s", recipeTestErrorCode(err))
	}
	if generator.Limits() != DefaultGenerationLimits() {
		t.Fatalf("normalized generator limits = %#v", generator.Limits())
	}
	if err := (Generator{}).validateRequest(request); !IsErrorCode(err, ErrorCodeInvalidGenerator) {
		t.Fatalf("zero generator code=%s", recipeTestErrorCode(err))
	}
	if err := generator.validateRequest(GenerationRequest{}); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("zero request code=%s", recipeTestErrorCode(err))
	}
}

// TestGenerationAndUsageAreImmutableConcurrentValues verifies cloned output and numeric-only usage.
func TestGenerationAndUsageAreImmutableConcurrentValues(t *testing.T) {
	recipe := mustParseRecipe(t, `{"b":null}`)
	jsonBytes := []byte(`{"b":null}`)
	generation, err := newProvenGeneration(generationProof{
		recipe: recipe, decodedJSON: jsonBytes, bodyOutcome: BodyGenerationUnavailable,
		unavailable: BodyUnavailableReasonUnrepresentable, validated: true,
	})
	if err != nil || !generation.Valid() || generation.Outcome() != GenerationOutcomeRecipe {
		t.Fatalf("newProvenGeneration() valid=%t code=%s", generation.Valid(), recipeTestErrorCode(err))
	}
	view := generation.DecodedJSON()
	view[0] = 'Y'
	if !bytes.Equal(generation.DecodedJSON(), []byte(`{"b":null}`)) {
		t.Fatal("generation JSON accessor aliases protected output")
	}
	if got, ok := generation.Recipe(); !ok || !got.Valid() || got.BodyMode() != BodyModeUnavailable {
		t.Fatal("generation recipe accessor lost closed model")
	}
	if generation.BodyOutcome() != BodyGenerationUnavailable || generation.BodyUnavailableReason() != BodyUnavailableReasonUnrepresentable {
		t.Fatal("generation body outcome mismatch")
	}
	unchanged := newUnchangedGeneration()
	if !unchanged.Valid() || unchanged.Outcome() != GenerationOutcomeUnchanged || unchanged.DecodedJSON() != nil {
		t.Fatal("unchanged generation contract mismatch")
	}
	if _, ok := unchanged.Recipe(); ok {
		t.Fatal("unchanged generation exposed a recipe")
	}
	if invalid, err := newProvenGeneration(generationProof{}); invalid.Valid() || !IsErrorCode(err, ErrorCodeGeneratedOutputInvariant) {
		t.Fatalf("unvalidated proof accepted: valid=%t code=%s", invalid.Valid(), recipeTestErrorCode(err))
	}
	if invalid, err := newProvenGeneration(generationProof{validated: true, decodedJSON: []byte(`{}`), bodyOutcome: BodyGenerationGenerated}); invalid.Valid() || !IsErrorCode(err, ErrorCodeGeneratedOutputInvariant) {
		t.Fatalf("incoherent proof accepted: valid=%t code=%s", invalid.Valid(), recipeTestErrorCode(err))
	}

	usage := newGenerationUsage(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
	if !usage.Valid() {
		t.Fatalf("generation usage invalid: %#v", usage)
	}
	gotUsage := [11]int{usage.InputBytes(), usage.InputItems(), usage.Candidates(), usage.CandidateKeyBytes(), usage.Comparisons(), usage.GeneratedSteps(), usage.GeneratedLiterals(), usage.LiteralBytes(), usage.JSONBytes(), usage.ProofWorkUnits(), usage.WorkUnits()}
	if gotUsage != [11]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11} {
		t.Fatalf("generation usage mismatch: %#v", usage)
	}

	var wait sync.WaitGroup
	for range 16 {
		wait.Go(func() {
			for range 100 {
				jsonCopy := generation.DecodedJSON()
				jsonCopy[0] ^= 1
				_, _ = generation.Recipe()
				_ = usage.WorkUnits()
			}
		})
	}
	wait.Wait()
}

// TestGeneratorAndImmutableRelevanceAreConcurrentSafe verifies reusable foundation values.
func TestGeneratorAndImmutableRelevanceAreConcurrentSafe(t *testing.T) {
	previous := mustGenerationState(t, []byte("A: previous\r\n\r\nbody\r\n"))
	current := mustGenerationState(t, []byte("A: current\r\n\r\nbody\r\n"))
	request, err := NewGenerationRequest(previous, current, RejectUnavailableBody, CopyOnly)
	if err != nil {
		t.Fatalf("NewGenerationRequest() code=%s", recipeTestErrorCode(err))
	}
	generator, err := NewGenerator(GenerationLimits{}, testHeaderRelevance{relevant: true})
	if err != nil {
		t.Fatalf("NewGenerator() code=%s", recipeTestErrorCode(err))
	}
	var wait sync.WaitGroup
	for range 16 {
		wait.Go(func() {
			for range 100 {
				if !generator.Valid() || generator.validateRequest(request) != nil {
					t.Error("concurrent generator contract changed")
					return
				}
				if relevant, err := generator.classifyStableHeader("subject"); err != nil || !relevant {
					t.Error("concurrent relevance classification changed")
					return
				}
				_ = generator.Limits()
			}
		})
	}
	wait.Wait()
}

// TestGenerationCounterPreservesFailureDimension verifies future shared-budget diagnostics.
func TestGenerationCounterPreservesFailureDimension(t *testing.T) {
	counter := newGenerationCounter(DefaultGenerationLimits())
	counter.workUnits = counter.limits.MaxGenerationWorkUnits
	err := counter.chargeWork(1, DimensionBody)
	var typed *Error
	if !errors.As(err, &typed) {
		t.Fatalf("body work failure type: code=%s", recipeTestErrorCode(err))
	}
	if typed.Code() != ErrorCodeLimitExceeded || typed.Dimension() != DimensionBody {
		t.Fatalf("body work failure: code=%s dimension=%s", typed.Code(), typed.Dimension())
	}
}

// mustGenerationState constructs one known generation state for tests.
func mustGenerationState(t *testing.T, input []byte) State {
	t.Helper()
	message, err := rawmsg.Parse(input)
	if err != nil {
		t.Fatalf("rawmsg.Parse() failed: error=%t", err != nil)
	}
	state, err := NewState(message)
	if err != nil {
		t.Fatalf("NewState() code=%s", recipeTestErrorCode(err))
	}
	return state
}

// assertClosedSafeGenerationError verifies error shape without emitting protected diagnostics.
func assertClosedSafeGenerationError(t *testing.T, err error, code ErrorCode, class ErrorClass, toxic string) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) {
		t.Fatal("generation error is not typed")
	}
	if typed.Code() != code || typed.Class() != class {
		t.Fatalf("generation error shape: code=%s class=%s", typed.Code(), typed.Class())
	}
	if bytes.Contains([]byte(typed.Error()), []byte(toxic)) {
		t.Fatal("generation error retained protected callback text")
	}
}
