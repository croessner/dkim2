package recipe

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"sync"
	"testing"
)

const recipeGenerationDraftBaseline = "draft-ietf-dkim-dkim2-spec-05"

type generationGoldenFile struct {
	Draft string                 `json:"draft"`
	Cases []generationGoldenCase `json:"cases"`
}

type generationGoldenCase struct {
	Name string `json:"name"`
	JSON string `json:"json"`
}

type generationSerializationMetrics struct {
	size, work                   int
	depth, members, tokens       int
	headerNames, headerNameBytes int
	maxHeaderNameBytes           int
	maxHeaderSteps, bodySteps    int
	totalSteps, copyRanges       int
	maxCopiedItems               int
	totalCopiedItems             int
	dataStrings, literalBytes    int
	maxLiteralBytes              int
	maxHeaderLineBytes           int
	maxHeaderFieldBytes          int
	maxBodyLineBytes             int
}

// TestSerializeGenerationPlanMatchesDraft05Goldens verifies exact versioned JSON bytes.
func TestSerializeGenerationPlanMatchesDraft05Goldens(t *testing.T) {
	fixture := loadGenerationGoldens(t)
	if fixture.Draft != recipeGenerationDraftBaseline {
		t.Fatal("fixture draft differs")
	}
	for _, golden := range fixture.Cases {
		t.Run(golden.Name, func(t *testing.T) {
			plan := generationGoldenPlan(t, golden.Name)
			result, usage, err := mustSerializeGenerationPlan(t, plan, GenerationLimits{})
			if err != nil || !result.Valid() {
				t.Fatalf("serialize: valid=%t code=%s", result.Valid(), recipeTestErrorCode(err))
			}
			if got := result.decodedJSON; !bytes.Equal(got, []byte(golden.JSON)) {
				t.Fatalf("golden mismatch: got_bytes=%d want_bytes=%d", len(got), len(golden.JSON))
			}
			if usage.JSONBytes() != len(golden.JSON) {
				t.Fatalf("json usage=%d want=%d", usage.JSONBytes(), len(golden.JSON))
			}
			metrics := mustPreflightGenerationPlan(t, plan, GenerationLimits{})
			if metrics.size != len(result.decodedJSON) || metrics.work != usage.WorkUnits() {
				t.Fatalf("preflight mismatch: size=%d/%d work=%d/%d", metrics.size, len(result.decodedJSON), metrics.work, usage.WorkUnits())
			}
		})
	}
}

// TestSerializeGenerationPlanEnforcesEveryOutputLimit verifies exact and one-under preflight ceilings.
func TestSerializeGenerationPlanEnforcesEveryOutputLimit(t *testing.T) {
	plan := generationGoldenPlan(t, "combined-order-and-escaping")
	metrics := mustPreflightGenerationPlan(t, plan, GenerationLimits{})
	tests := []struct {
		name      string
		exact     int
		limitName string
		configure func(*GenerationLimits, int)
	}{
		{name: "decoded bytes", exact: metrics.size, limitName: limitNameMaxDecodedRecipeBytes, configure: configureDecodedSerializerLimit},
		{name: "json depth", exact: metrics.depth, limitName: limitNameMaxJSONDepth, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxJSONDepth = n }},
		{name: "json members", exact: metrics.members, limitName: limitNameMaxJSONMembers, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxJSONMembers = n }},
		{name: "json tokens", exact: metrics.tokens, limitName: limitNameMaxJSONTokens, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxJSONTokens = n }},
		{name: testHeaderNamesLabel, exact: metrics.headerNames, limitName: limitNameMaxHeaderNames, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxHeaderNames = n }},
		{name: testHeaderNameBytesLabel, exact: metrics.maxHeaderNameBytes, limitName: limitNameMaxHeaderNameBytes, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxHeaderNameBytes = n }},
		{name: "total header name bytes", exact: metrics.headerNameBytes, limitName: limitNameMaxTotalHeaderNameBytes, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxTotalHeaderNameBytes = n }},
		{name: testStepsPerHeaderLabel, exact: metrics.maxHeaderSteps, limitName: limitNameMaxStepsPerHeader, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxStepsPerHeader = n }},
		{name: testBodyStepsLabel, exact: metrics.bodySteps, limitName: limitNameMaxBodySteps, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxBodySteps = n }},
		{name: testTotalStepsLabel, exact: metrics.totalSteps, limitName: limitNameMaxTotalSteps, configure: func(l *GenerationLimits, n int) {
			l.RecipeLimits.MaxStepsPerHeader, l.RecipeLimits.MaxBodySteps, l.RecipeLimits.MaxTotalSteps = min(l.RecipeLimits.MaxStepsPerHeader, n), min(l.RecipeLimits.MaxBodySteps, n), n
		}},
		{name: testCopyRangesLabel, exact: metrics.copyRanges, limitName: limitNameMaxCopyRanges, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxCopyRanges = n }},
		{name: testCopiedItemsPerRangeLabel, exact: metrics.maxCopiedItems, limitName: limitNameMaxCopiedItemsPerRange, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxCopiedItemsPerRange = n }},
		{name: testTotalCopiedItemsLabel, exact: metrics.totalCopiedItems, limitName: limitNameMaxTotalCopiedItems, configure: func(l *GenerationLimits, n int) {
			l.RecipeLimits.MaxCopiedItemsPerRange, l.RecipeLimits.MaxTotalCopiedItems = min(l.RecipeLimits.MaxCopiedItemsPerRange, n), n
		}},
		{name: testDataStringsLabel, exact: metrics.dataStrings, limitName: limitNameMaxDataStrings, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxDataStrings = n }},
		{name: testDataStringBytesLabel, exact: metrics.maxLiteralBytes, limitName: limitNameMaxDataStringBytes, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxDataStringBytes = n }},
		{name: testLiteralBytesLabel, exact: metrics.literalBytes, limitName: limitNameMaxTotalLiteralBytes, configure: func(l *GenerationLimits, n int) {
			l.RecipeLimits.MaxDataStringBytes, l.RecipeLimits.MaxTotalLiteralBytes = min(l.RecipeLimits.MaxDataStringBytes, n), n
		}},
		{name: "header line bytes", exact: metrics.maxHeaderLineBytes, limitName: limitNameMaxHeaderLineBytes, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxHeaderLineBytes = n }},
		{name: "header field bytes", exact: metrics.maxHeaderFieldBytes, limitName: limitNameMaxHeaderFieldBytes, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxHeaderFieldBytes = n }},
		{name: "body line bytes", exact: metrics.maxBodyLineBytes, limitName: limitNameMaxBodyLineBytes, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxBodyLineBytes = n }},
		{name: "serializer work", exact: metrics.work, limitName: limitNameMaxOperationWorkUnits, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxOperationWorkUnits = n }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, boundary := range []struct {
				name    string
				limit   int
				wantErr bool
			}{{name: testExactBoundaryLabel, limit: test.exact}, {name: testOneUnderLabel, limit: test.exact - 1, wantErr: true}} {
				t.Run(boundary.name, func(t *testing.T) {
					limits := DefaultGenerationLimits()
					test.configure(&limits, boundary.limit)
					result, usage, err := mustSerializeGenerationPlan(t, plan, limits)
					if boundary.wantErr {
						if result.Valid() || len(result.decodedJSON) != 0 || !usage.Valid() || usage.JSONBytes() != 0 || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != test.limitName {
							t.Fatalf("one-under: valid=%t bytes=%d json=%d code=%s limit=%s", result.Valid(), len(result.decodedJSON), usage.JSONBytes(), recipeTestErrorCode(err), recipeTestLimitName(err))
						}
						return
					}
					if err != nil || !result.Valid() || usage.JSONBytes() != metrics.size {
						t.Fatalf("exact: valid=%t json=%d code=%s", result.Valid(), usage.JSONBytes(), recipeTestErrorCode(err))
					}
				})
			}
		})
	}
}

// TestSerializeGenerationPlanPrechargesSharedWriterWork verifies failure occurs before output ownership.
func TestSerializeGenerationPlanPrechargesSharedWriterWork(t *testing.T) {
	plan := generationGoldenPlan(t, "combined-order-and-escaping")
	baseline, usage, err := serializeGenerationPlanWithPreload(plan, GenerationLimits{}, nil)
	if err != nil || !baseline.Valid() {
		t.Fatalf("baseline: valid=%t code=%s", baseline.Valid(), recipeTestErrorCode(err))
	}
	work := usage.WorkUnits()
	for _, boundary := range []struct {
		name    string
		offset  int
		wantErr bool
	}{{name: testExactBoundaryLabel}, {name: testOneUnderLabel, offset: 1, wantErr: true}} {
		t.Run(boundary.name, func(t *testing.T) {
			result, attempt, attemptErr := serializeGenerationPlanWithPreload(plan, GenerationLimits{}, func(counter *generationCounter) {
				counter.workUnits = counter.limits.MaxGenerationWorkUnits - work + boundary.offset
			})
			if boundary.wantErr {
				if result.Valid() || len(result.decodedJSON) != 0 || attempt.JSONBytes() != 0 || !IsErrorCode(attemptErr, ErrorCodeLimitExceeded) || recipeTestLimitName(attemptErr) != limitNameMaxGenerationWorkUnits {
					t.Fatalf("shared work failure: valid=%t bytes=%d json=%d code=%s limit=%s", result.Valid(), len(result.decodedJSON), attempt.JSONBytes(), recipeTestErrorCode(attemptErr), recipeTestLimitName(attemptErr))
				}
				return
			}
			if attemptErr != nil || !result.Valid() || attempt.WorkUnits() != DefaultGenerationLimits().MaxGenerationWorkUnits {
				t.Fatalf("shared work exact: valid=%t work=%d code=%s", result.Valid(), attempt.WorkUnits(), recipeTestErrorCode(attemptErr))
			}
		})
	}
}

// TestSerializeGenerationPlanPrechargesLargeProtectedScans verifies long-name and literal work.
func TestSerializeGenerationPlanPrechargesLargeProtectedScans(t *testing.T) {
	prefix := strings.Repeat("x", 900)
	first := mustGenerationHeaderPlan(t, prefix+"a", []step{mustGenerationDataStep(t, [][]byte{[]byte("")})})
	second := mustGenerationHeaderPlan(t, prefix+"b", nil)
	bodyLiteral := []byte(strings.Repeat("q", 900))
	plan := mustGenerationSerializationPlan(t, []headerPlan{first, second}, bodyPlanningResult{
		outcome:     BodyGenerationGenerated,
		steps:       []step{mustGenerationDataStep(t, [][]byte{bodyLiteral})},
		initialized: true,
	})
	metrics := mustPreflightGenerationPlan(t, plan, GenerationLimits{})
	for _, boundary := range []struct {
		name    string
		limit   int
		wantErr bool
	}{{name: testExactBoundaryLabel, limit: metrics.work}, {name: testOneUnderLabel, limit: metrics.work - 1, wantErr: true}} {
		t.Run(boundary.name, func(t *testing.T) {
			limits := DefaultGenerationLimits()
			limits.RecipeLimits.MaxOperationWorkUnits = boundary.limit
			result, usage, err := mustSerializeGenerationPlan(t, plan, limits)
			if boundary.wantErr {
				if result.Valid() || len(result.decodedJSON) != 0 || usage.JSONBytes() != 0 || recipeTestLimitName(err) != limitNameMaxOperationWorkUnits {
					t.Fatalf("large one-under: valid=%t bytes=%d json=%d limit=%s", result.Valid(), len(result.decodedJSON), usage.JSONBytes(), recipeTestLimitName(err))
				}
				return
			}
			if err != nil || !result.Valid() || len(result.decodedJSON) != metrics.size || usage.WorkUnits() != metrics.work {
				t.Fatalf("large exact: valid=%t bytes=%d work=%d code=%s", result.Valid(), len(result.decodedJSON), usage.WorkUnits(), recipeTestErrorCode(err))
			}
			plan.body.steps[0].data[0][0] = 'z'
			if bytes.Contains(result.decodedJSON, []byte("zqqq")) {
				t.Fatal("serialized output aliases the planning literal")
			}
		})
	}
}

// TestUnavailableSerializationFailureNeverReturnsNull verifies limits cannot become b:null.
func TestUnavailableSerializationFailureNeverReturnsNull(t *testing.T) {
	plan := generationGoldenPlan(t, "body-unavailable")
	metrics := mustPreflightGenerationPlan(t, plan, GenerationLimits{})
	limits := DefaultGenerationLimits()
	configureDecodedSerializerLimit(&limits, metrics.size-1)
	result, usage, err := mustSerializeGenerationPlan(t, plan, limits)
	if result.Valid() || len(result.decodedJSON) != 0 || usage.JSONBytes() != 0 || !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("unavailable limit: valid=%t bytes=%d json=%d code=%s", result.Valid(), len(result.decodedJSON), usage.JSONBytes(), recipeTestErrorCode(err))
	}
}

// TestSerializeGenerationPlanRejectsMalformedInternalSteps verifies full closed copy invariants.
func TestSerializeGenerationPlanRejectsMalformedInternalSteps(t *testing.T) {
	tests := []struct {
		name  string
		steps []step
	}{
		{name: "zero start", steps: []step{{kind: StepKindCopy, copyStart: 0, copyEnd: 1, initialized: true}}},
		{name: "negative start", steps: []step{{kind: StepKindCopy, copyStart: -1, copyEnd: 1, initialized: true}}},
		{name: "reversed", steps: []step{{kind: StepKindCopy, copyStart: 2, copyEnd: 1, initialized: true}}},
		{name: "copy payload", steps: []step{{kind: StepKindCopy, copyStart: 1, copyEnd: 1, data: [][]byte{[]byte("x")}, initialized: true}}},
		{name: "nonascending", steps: []step{mustGenerationCopyStep(t, 2, 2), mustGenerationCopyStep(t, 1, 1)}},
		{name: "arithmetic extremes", steps: []step{{kind: StepKindCopy, copyStart: math.MinInt, copyEnd: math.MaxInt, initialized: true}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := generationSerializationPlan{
				headers:     headerPlanningResult{initialized: true},
				body:        bodyPlanningResult{outcome: BodyGenerationGenerated, steps: test.steps, initialized: true},
				bodyOutcome: BodyGenerationGenerated, initialized: true,
			}
			result, usage, err := mustSerializeGenerationPlan(t, plan, GenerationLimits{})
			if result.Valid() || len(result.decodedJSON) != 0 || usage.JSONBytes() != 0 || !IsErrorCode(err, ErrorCodeGeneratedOutputInvariant) {
				t.Fatalf("malformed step: valid=%t bytes=%d json=%d code=%s", result.Valid(), len(result.decodedJSON), usage.JSONBytes(), recipeTestErrorCode(err))
			}
		})
	}
}

// TestSerializeGenerationPlanRejectsMalformedPlanVocabulary verifies ordering and body coherence.
func TestSerializeGenerationPlanRejectsMalformedPlanVocabulary(t *testing.T) {
	validStep := mustGenerationDataStep(t, [][]byte{[]byte("x")})
	first := mustGenerationHeaderPlan(t, "z", []step{validStep})
	second := mustGenerationHeaderPlan(t, "a", []step{validStep})
	tests := []struct {
		name string
		plan generationSerializationPlan
	}{
		{name: "unsorted headers", plan: generationSerializationPlan{headers: headerPlanningResult{plans: []headerPlan{first, second}, initialized: true}, body: newUnchangedBodyPlanningResult(), bodyOutcome: BodyGenerationUnchanged, initialized: true}},
		{name: "duplicate headers", plan: generationSerializationPlan{headers: headerPlanningResult{plans: []headerPlan{first, first}, initialized: true}, body: newUnchangedBodyPlanningResult(), bodyOutcome: BodyGenerationUnchanged, initialized: true}},
		{name: "generated with reason", plan: generationSerializationPlan{headers: headerPlanningResult{initialized: true}, body: bodyPlanningResult{outcome: BodyGenerationGenerated, unavailable: BodyUnavailableReasonUnrepresentable, initialized: true}, bodyOutcome: BodyGenerationGenerated, unavailable: BodyUnavailableReasonUnrepresentable, initialized: true}},
		{name: "unavailable with steps", plan: generationSerializationPlan{headers: headerPlanningResult{initialized: true}, body: bodyPlanningResult{outcome: BodyGenerationUnavailable, unavailable: BodyUnavailableReasonUnrepresentable, steps: []step{validStep}, initialized: true}, bodyOutcome: BodyGenerationUnavailable, unavailable: BodyUnavailableReasonUnrepresentable, initialized: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, usage, err := mustSerializeGenerationPlan(t, test.plan, GenerationLimits{})
			if result.Valid() || len(result.decodedJSON) != 0 || usage.JSONBytes() != 0 || !IsErrorCode(err, ErrorCodeGeneratedOutputInvariant) {
				t.Fatalf("malformed plan: valid=%t bytes=%d json=%d code=%s", result.Valid(), len(result.decodedJSON), usage.JSONBytes(), recipeTestErrorCode(err))
			}
		})
	}
}

// TestSerializeGenerationPlanRejectsCRLFAndArithmeticOverflow verifies protected preflight failures.
func TestSerializeGenerationPlanRejectsCRLFAndArithmeticOverflow(t *testing.T) {
	limits := DefaultGenerationLimits()
	for _, literal := range [][]byte{[]byte("bad\rvalue"), []byte("bad\nvalue")} {
		counter := newGenerationCounter(limits)
		preflight := newSerializationPreflight(limits.RecipeLimits, &counter)
		if err := preflight.validateLiteral(literal, DimensionBody, ""); !IsErrorCode(err, ErrorCodeSerializationFailure) || counter.jsonBytes != 0 {
			t.Fatalf("line break literal: json=%d code=%s", counter.jsonBytes, recipeTestErrorCode(err))
		}
	}
	counter := newGenerationCounter(limits)
	sizer := newRecipeJSONSizer(limits.RecipeLimits, &counter)
	sizer.size = math.MaxInt
	if err := sizer.appendByte('x'); !IsErrorCode(err, ErrorCodeLimitExceeded) || len(sizer.output) != 0 || counter.jsonBytes != 0 {
		t.Fatalf("size overflow: output=%d json=%d code=%s", len(sizer.output), counter.jsonBytes, recipeTestErrorCode(err))
	}
}

// TestSerializeGenerationPlanSupportsRetryAndIndependentOutputOwnership verifies failure isolation.
func TestSerializeGenerationPlanSupportsRetryAndIndependentOutputOwnership(t *testing.T) {
	plan := generationGoldenPlan(t, "header-only")
	metrics := mustPreflightGenerationPlan(t, plan, GenerationLimits{})
	failedLimits := DefaultGenerationLimits()
	configureDecodedSerializerLimit(&failedLimits, metrics.size-1)
	failed, _, err := mustSerializeGenerationPlan(t, plan, failedLimits)
	if failed.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("expected bounded failure: valid=%t code=%s", failed.Valid(), recipeTestErrorCode(err))
	}
	first, _, err := mustSerializeGenerationPlan(t, plan, GenerationLimits{})
	if err != nil || !first.Valid() {
		t.Fatalf("retry code=%s", recipeTestErrorCode(err))
	}
	second, _, err := mustSerializeGenerationPlan(t, plan, GenerationLimits{})
	if err != nil || !second.Valid() || len(first.decodedJSON) == 0 || &first.decodedJSON[0] == &second.decodedJSON[0] {
		t.Fatalf("independent output: first=%d second=%d code=%s", len(first.decodedJSON), len(second.decodedJSON), recipeTestErrorCode(err))
	}
}

// TestRecipeJSONEmitterRejectsZeroDependencies verifies closed internal writer seams.
func TestRecipeJSONEmitterRejectsZeroDependencies(t *testing.T) {
	var nilEmitter *recipeJSONEmitter
	if !IsErrorCode(nilEmitter.appendString("x"), ErrorCodeGeneratedOutputInvariant) {
		t.Fatal("nil emitter accepted")
	}
	zero := &recipeJSONEmitter{}
	if !IsErrorCode(zero.appendBytes([]byte("x")), ErrorCodeGeneratedOutputInvariant) {
		t.Fatal("zero emitter accepted")
	}
	if writer, err := newRecipeJSONWriter(nil, 1); writer != nil || !IsErrorCode(err, ErrorCodeGeneratedOutputInvariant) {
		t.Fatal("nil writer preflight accepted")
	}
	limits := DefaultGenerationLimits()
	counter := newGenerationCounter(limits)
	if writer, err := newRecipeJSONWriter(newSerializationPreflight(limits.RecipeLimits, &counter), 0); writer != nil || !IsErrorCode(err, ErrorCodeGeneratedOutputInvariant) {
		t.Fatal("zero writer size accepted")
	}
}

// TestSerializedGenerationPlanRejectsIncoherentMetadata verifies its closed zero-safe state.
func TestSerializedGenerationPlanRejectsIncoherentMetadata(t *testing.T) {
	for _, result := range []serializedGenerationPlan{
		{},
		{bodyOutcome: BodyGenerationGenerated, unavailable: BodyUnavailableReasonUnrepresentable, decodedJSON: []byte(`{"b":[]}`), initialized: true},
		{bodyOutcome: BodyGenerationUnavailable, decodedJSON: []byte(`{"b":null}`), initialized: true},
		{bodyOutcome: BodyGenerationOutcome("future"), decodedJSON: []byte(`{"b":[]}`), initialized: true},
	} {
		if result.Valid() {
			t.Fatalf("incoherent serialized result accepted: outcome=%s", result.bodyOutcome)
		}
	}
}

// TestSerializeGenerationPlanIsRepeatableAndConcurrent verifies immutable deterministic reuse.
func TestSerializeGenerationPlanIsRepeatableAndConcurrent(t *testing.T) {
	plan := generationGoldenPlan(t, "combined-order-and-escaping")
	want, _, err := mustSerializeGenerationPlan(t, plan, GenerationLimits{})
	if err != nil {
		t.Fatalf("baseline code=%s", recipeTestErrorCode(err))
	}
	wantJSON := bytes.Clone(want.decodedJSON)
	const workers = 32
	var wait sync.WaitGroup
	errorsSeen := make(chan error, workers)
	for range workers {
		wait.Go(func() {
			got, _, serializeErr := serializeGenerationPlanForTest(plan, GenerationLimits{})
			if serializeErr != nil {
				errorsSeen <- serializeErr
				return
			}
			if !bytes.Equal(got.decodedJSON, wantJSON) {
				errorsSeen <- errors.New("non-deterministic JSON")
			}
		})
	}
	wait.Wait()
	close(errorsSeen)
	for workerErr := range errorsSeen {
		t.Fatalf("concurrent serializer: %v", workerErr)
	}
}

// TestSerializeGenerationPlanRejectsInvalidUTF8BeforeOutput verifies no replacement or partial bytes.
func TestSerializeGenerationPlanRejectsInvalidUTF8BeforeOutput(t *testing.T) {
	limits := DefaultGenerationLimits()
	counter := newGenerationCounter(limits)
	sizer := newRecipeJSONSizer(limits.RecipeLimits, &counter)
	err := sizer.writeJSONStringBytes([]byte{0xff})
	if !IsErrorCode(err, ErrorCodeSerializationFailure) || sizer.size != 0 || counter.jsonBytes != 0 {
		t.Fatalf("invalid utf8: size=%d json=%d code=%s", sizer.size, counter.jsonBytes, recipeTestErrorCode(err))
	}
}

// TestSerializeGenerationPlanRejectsInvalidCombinedState verifies failure atomicity.
func TestSerializeGenerationPlanRejectsInvalidCombinedState(t *testing.T) {
	result, usage, err := mustSerializeGenerationPlan(t, generationSerializationPlan{}, GenerationLimits{})
	if result.Valid() || len(result.decodedJSON) != 0 || !usage.Valid() || !IsErrorCode(err, ErrorCodeGeneratedOutputInvariant) {
		t.Fatalf("invalid plan: valid=%t bytes=%d usage=%t code=%s", result.Valid(), len(result.decodedJSON), usage.Valid(), recipeTestErrorCode(err))
	}
}

// loadGenerationGoldens loads the retained draft-versioned serializer fixture.
func loadGenerationGoldens(t *testing.T) generationGoldenFile {
	t.Helper()
	data, err := os.ReadFile("testdata/golden/recipe-generation-draft-ietf-dkim-dkim2-spec-05.json")
	if err != nil {
		t.Fatalf("read generation golden: %v", err)
	}
	var fixture generationGoldenFile
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("decode generation golden: %v", err)
	}
	if err := validateGenerationGoldens(fixture); err != nil {
		t.Fatalf("validate generation golden: %v", err)
	}
	return fixture
}

// validateGenerationGoldens rejects missing, duplicate, unknown, or empty fixture cases.
func validateGenerationGoldens(fixture generationGoldenFile) error {
	if fixture.Draft != recipeGenerationDraftBaseline {
		return errors.New("unexpected draft baseline")
	}
	expected := map[string]bool{
		"combined-order-and-escaping":     false,
		"header-only":                     false,
		"body-empty":                      false,
		"body-unavailable":                false,
		"data-before-copy-and-multidigit": false,
	}
	for _, golden := range fixture.Cases {
		seen, known := expected[golden.Name]
		if !known || seen || golden.JSON == "" {
			return errors.New("invalid generation golden case")
		}
		expected[golden.Name] = true
	}
	for _, seen := range expected {
		if !seen {
			return errors.New("missing generation golden case")
		}
	}
	return nil
}

// TestGenerationGoldenFixtureValidationRejectsDrift verifies the versioned case inventory.
func TestGenerationGoldenFixtureValidationRejectsDrift(t *testing.T) {
	valid := loadGenerationGoldens(t)
	for _, mutate := range []func(*generationGoldenFile){
		func(f *generationGoldenFile) { f.Draft = "future" },
		func(f *generationGoldenFile) { f.Cases = f.Cases[:len(f.Cases)-1] },
		func(f *generationGoldenFile) { f.Cases = append(f.Cases, f.Cases[0]) },
		func(f *generationGoldenFile) { f.Cases[0].Name = "unknown" },
		func(f *generationGoldenFile) { f.Cases[0].JSON = "" },
	} {
		copyFixture := generationGoldenFile{Draft: valid.Draft, Cases: append([]generationGoldenCase(nil), valid.Cases...)}
		mutate(&copyFixture)
		if validateGenerationGoldens(copyFixture) == nil {
			t.Fatal("invalid fixture accepted")
		}
	}
}

// generationGoldenPlan constructs one closed fixture plan without public generation.
func generationGoldenPlan(t *testing.T, name string) generationSerializationPlan {
	t.Helper()
	switch name {
	case "combined-order-and-escaping":
		copyOne := mustGenerationCopyStep(t, 1, 2)
		data := mustGenerationDataStep(t, [][]byte{
			[]byte("quote\"slash\\"),
			{0x00, 0x08, 0x09, 0x0c, 0x1f},
			[]byte("Grüße/<>  &�"),
		})
		first := mustGenerationHeaderPlan(t, "a\"\\z", []step{copyOne, data})
		second := mustGenerationHeaderPlan(t, "z", nil)
		bodyCopy := mustGenerationCopyStep(t, 3, 4)
		bodyData := mustGenerationDataStep(t, [][]byte{[]byte("body")})
		return mustGenerationSerializationPlan(t, []headerPlan{first, second}, bodyPlanningResult{
			outcome: BodyGenerationGenerated, steps: []step{bodyCopy, bodyData}, initialized: true,
		})
	case "header-only":
		plan := mustGenerationHeaderPlan(t, "subject", []step{mustGenerationDataStep(t, [][]byte{[]byte("old")})})
		return mustGenerationSerializationPlan(t, []headerPlan{plan}, newUnchangedBodyPlanningResult())
	case "body-empty":
		return mustGenerationSerializationPlan(t, nil, bodyPlanningResult{outcome: BodyGenerationGenerated, initialized: true})
	case "body-unavailable":
		return mustGenerationSerializationPlan(t, nil, bodyPlanningResult{
			outcome: BodyGenerationUnavailable, unavailable: BodyUnavailableReasonUnrepresentable, initialized: true,
		})
	case "data-before-copy-and-multidigit":
		bodyData := mustGenerationDataStep(t, [][]byte{{0x01, 0x02}, []byte("direct/<> &")})
		bodyCopy := mustGenerationCopyStep(t, 123456789, 123456790)
		return mustGenerationSerializationPlan(t, nil, bodyPlanningResult{
			outcome: BodyGenerationGenerated, steps: []step{bodyData, bodyCopy}, initialized: true,
		})
	default:
		t.Fatal("unknown golden case")
		return generationSerializationPlan{}
	}
}

// mustGenerationSerializationPlan constructs one closed combined serializer input.
func mustGenerationSerializationPlan(t *testing.T, headers []headerPlan, body bodyPlanningResult) generationSerializationPlan {
	t.Helper()
	headerResult, err := newHeaderPlanningResult(headers)
	if err != nil {
		t.Fatalf("newHeaderPlanningResult() code=%s", recipeTestErrorCode(err))
	}
	plan, err := newGenerationSerializationPlan(headerResult, body)
	if err != nil {
		t.Fatalf("newGenerationSerializationPlan() code=%s", recipeTestErrorCode(err))
	}
	return plan
}

// mustGenerationHeaderPlan constructs one exact canonical test header plan.
func mustGenerationHeaderPlan(t *testing.T, name string, steps []step) headerPlan {
	t.Helper()
	plan, err := newHeaderPlan(name, name, steps)
	if err != nil {
		t.Fatalf("newHeaderPlan() code=%s", recipeTestErrorCode(err))
	}
	return plan
}

// mustGenerationCopyStep constructs one exact copy test step.
func mustGenerationCopyStep(t *testing.T, start, end int) step {
	t.Helper()
	instruction, err := newCopyStep(start, end)
	if err != nil {
		t.Fatalf("newCopyStep() code=%s", recipeTestErrorCode(err))
	}
	return instruction
}

// mustGenerationDataStep constructs one exact data test step.
func mustGenerationDataStep(t *testing.T, values [][]byte) step {
	t.Helper()
	instruction, err := newDataStep(values)
	if err != nil {
		t.Fatalf("newDataStep() code=%s", recipeTestErrorCode(err))
	}
	return instruction
}

// mustSerializeGenerationPlan serializes one internal plan under one operation budget.
func mustSerializeGenerationPlan(t *testing.T, plan generationSerializationPlan, limits GenerationLimits) (serializedGenerationPlan, GenerationUsage, error) {
	t.Helper()
	return serializeGenerationPlanForTest(plan, limits)
}

// serializeGenerationPlanForTest constructs fresh immutable serializer dependencies.
func serializeGenerationPlanForTest(plan generationSerializationPlan, limits GenerationLimits) (serializedGenerationPlan, GenerationUsage, error) {
	return serializeGenerationPlanWithPreload(plan, limits, nil)
}

// serializeGenerationPlanWithPreload runs one serializer with optional shared usage.
func serializeGenerationPlanWithPreload(plan generationSerializationPlan, limits GenerationLimits, preload func(*generationCounter)) (serializedGenerationPlan, GenerationUsage, error) {
	resolved, err := limits.normalized()
	if err != nil {
		return serializedGenerationPlan{}, GenerationUsage{}, err
	}
	counter := newGenerationCounter(resolved)
	if preload != nil {
		preload(&counter)
	}
	budget, err := newGenerationPlanBudget(&counter)
	if err != nil {
		return serializedGenerationPlan{}, counter.usage(), err
	}
	result, err := budget.serializeGenerationPlan(plan)
	return result, counter.usage(), err
}

// mustPreflightGenerationPlan returns exact internal sizing and semantic metrics.
func mustPreflightGenerationPlan(t *testing.T, plan generationSerializationPlan, limits GenerationLimits) generationSerializationMetrics {
	t.Helper()
	resolved, err := limits.normalized()
	if err != nil {
		t.Fatalf("normalize limits code=%s", recipeTestErrorCode(err))
	}
	counter := newGenerationCounter(resolved)
	sizer := newRecipeJSONSizer(resolved.RecipeLimits, &counter)
	if err := sizer.preflight.validatePlan(plan); err != nil {
		t.Fatalf("validate preflight code=%s limit=%s", recipeTestErrorCode(err), recipeTestLimitName(err))
	}
	if err := sizer.emitPlan(plan); err != nil {
		t.Fatalf("emit preflight code=%s limit=%s", recipeTestErrorCode(err), recipeTestLimitName(err))
	}
	metrics := generationSerializationMetrics{
		size: sizer.size, work: counter.workUnits, depth: sizer.preflight.maxDepth,
		members: sizer.preflight.members, tokens: sizer.preflight.tokens,
		headerNames: sizer.preflight.headerNames, headerNameBytes: sizer.preflight.headerNameBytes,
		totalSteps: sizer.preflight.totalSteps, copyRanges: sizer.preflight.copyRanges,
		totalCopiedItems: sizer.preflight.totalCopiedItems, dataStrings: sizer.preflight.dataStrings,
		literalBytes: sizer.preflight.literalBytes, bodySteps: len(plan.body.steps),
	}
	for _, header := range plan.headers.plans {
		metrics.maxHeaderNameBytes = max(metrics.maxHeaderNameBytes, len(header.name))
		metrics.maxHeaderSteps = max(metrics.maxHeaderSteps, len(header.steps))
		collectSerializationStepMetrics(&metrics, header.steps, DimensionHeader, header.name)
	}
	collectSerializationStepMetrics(&metrics, plan.body.steps, DimensionBody, "")
	return metrics
}

// collectSerializationStepMetrics derives maxima already validated by the preflight.
func collectSerializationStepMetrics(metrics *generationSerializationMetrics, steps []step, dimension Dimension, headerName string) {
	for _, instruction := range steps {
		if start, end, copyStep := instruction.copyRange(); copyStep {
			metrics.maxCopiedItems = max(metrics.maxCopiedItems, end-start+1)
			continue
		}
		for _, literal := range instruction.data {
			metrics.maxLiteralBytes = max(metrics.maxLiteralBytes, len(literal))
			if dimension == DimensionHeader {
				lineBytes := len(headerName) + 1 + len(literal)
				metrics.maxHeaderLineBytes = max(metrics.maxHeaderLineBytes, lineBytes)
				metrics.maxHeaderFieldBytes = max(metrics.maxHeaderFieldBytes, lineBytes+2)
			} else {
				metrics.maxBodyLineBytes = max(metrics.maxBodyLineBytes, len(literal))
			}
		}
	}
}

// configureDecodedSerializerLimit preserves literal coherence while narrowing output.
func configureDecodedSerializerLimit(limits *GenerationLimits, value int) {
	limits.RecipeLimits.MaxDecodedRecipeBytes = value
	limits.RecipeLimits.MaxTotalLiteralBytes = min(limits.RecipeLimits.MaxTotalLiteralBytes, value)
	limits.RecipeLimits.MaxDataStringBytes = min(limits.RecipeLimits.MaxDataStringBytes, limits.RecipeLimits.MaxTotalLiteralBytes)
}
