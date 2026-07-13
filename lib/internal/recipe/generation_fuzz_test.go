package recipe_test

import (
	"bytes"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
)

const generationFuzzToxicMarker = "TOXIC_GENERATION_MARKER"

type generationFuzzSeed struct {
	name              string
	previous, current []byte
	body, literal     byte
	limitProfile      byte
	wantCode          recipe.ErrorCode
	wantLimitName     string
	wantDimension     recipe.Dimension
	wantOutcome       recipe.GenerationOutcome
	wantBodyOutcome   recipe.BodyGenerationOutcome
	wantUnavailable   recipe.BodyUnavailableReason
	wantJSON          string
}

// FuzzGenerateRecipe exercises deterministic bounded generation over strict message pairs and both policies.
func FuzzGenerateRecipe(f *testing.F) {
	addGenerationFuzzSeeds(f)
	f.Fuzz(func(t *testing.T, previousBytes, currentBytes []byte, bodyPolicyByte, literalPolicyByte, limitProfile byte) {
		fuzzGenerationPair(t, previousBytes, currentBytes, bodyPolicyByte, literalPolicyByte, limitProfile, false)
	})
}

// FuzzGeneratedRecipeRoundTrip proves every recipe success remains parseable, applicable, and canonical-equivalent.
func FuzzGeneratedRecipeRoundTrip(f *testing.F) {
	addGenerationFuzzSeeds(f)
	f.Fuzz(func(t *testing.T, previousBytes, currentBytes []byte, bodyPolicyByte, literalPolicyByte, limitProfile byte) {
		fuzzGenerationPair(t, previousBytes, currentBytes, bodyPolicyByte, literalPolicyByte, limitProfile, true)
	})
}

// addGenerationFuzzSeeds retains normative framing, folding, binary, candidate, key, privacy, and policy vectors.
func addGenerationFuzzSeeds(f *testing.F) {
	f.Helper()
	for _, seed := range generationFuzzSeeds() {
		f.Add(seed.previous, seed.current, seed.body, seed.literal, seed.limitProfile)
	}
}

// generationFuzzSeeds returns named retained vectors for every required semantic lane.
func generationFuzzSeeds() []generationFuzzSeed {
	repeatedPrevious, repeatedCurrent := repeatedGenerationSeedMessages(24)
	return []generationFuzzSeed{
		{name: "unchanged-known", previous: []byte("Subject: same\r\n\r\nbody\r\n"), current: []byte("Subject: same\r\n\r\nbody\r\n"), wantOutcome: recipe.GenerationOutcomeUnchanged, wantBodyOutcome: recipe.BodyGenerationUnchanged},
		{name: "duplicate-case-folding-replace", previous: []byte("Subject: one  exact\r\nSubject: two\r\n three\r\n\r\nold\r\n"), current: []byte("subject: two three\r\nSUBJECT: changed\r\n\r\nnew\r\n"), literal: 1, wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationGenerated},
		{name: "header-only-target-unavailable", previous: []byte("Subject: prior\r\n"), current: []byte("Subject: current\r\n\r\nbody\r\n"), body: 1, literal: 1, wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationUnavailable, wantUnavailable: recipe.BodyUnavailableReasonUnrepresentable, wantJSON: "{\"h\":{\"subject\":[{\"d\":[\" prior\"]}]},\"b\":null}"},
		{name: "header-only-target-rejected", previous: []byte("Subject: prior\r\n"), current: []byte("Subject: current\r\n\r\nbody\r\n"), literal: 1, wantCode: recipe.ErrorCodeBodyUnrepresentable},
		{name: "delimited-empty-target", previous: []byte("A:x\r\n\r\n"), current: []byte("A:x\r\n"), wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationGenerated, wantJSON: "{\"b\":[]}"},
		{name: "binary-copy", previous: append([]byte("A:x\r\n\r\n"), 0xff, '\r', '\n'), current: append([]byte("A:x\r\n\r\nprefix\r\n"), 0xff, '\r', '\n'), wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationGenerated},
		{name: "unterminated-copy", previous: []byte("A:x\r\n\r\ntail"), current: []byte("A:x\r\n\r\nprefix\r\ntail"), wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationGenerated},
		{name: "json-sensitive-header", previous: []byte("a\"\\z: prior\r\n\r\nbody\r\n"), current: []byte("A\"\\Z: current\r\n\r\nbody\r\n"), literal: 1, wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationUnchanged},
		{name: "json-sensitive-body-literal", previous: append([]byte("A:x\r\n\r\n"), []byte("quote\"slash\\\x00\b\t\f\x1fGrüße\r\n")...), current: []byte("A:x\r\n\r\ncurrent\r\n"), literal: 1, wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationGenerated},
		{name: "body-copy-data-copy", previous: []byte("A:x\r\n\r\na\r\ninserted\r\nb\r\n"), current: []byte("A:x\r\n\r\na\r\nb\r\n"), literal: 1, wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationGenerated, wantJSON: "{\"b\":[{\"c\":[1,1]},{\"d\":[\"inserted\"]},{\"c\":[2,2]}]}"},
		{name: "one-empty-body-line", previous: []byte("A:x\r\n\r\n\r\n"), current: []byte("A:x\r\n\r\n"), literal: 1, wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationGenerated, wantJSON: "{\"b\":[{\"d\":[\"\"]}]}"},
		{name: "adjacent-copy-coalescing", previous: []byte("A:x\r\n\r\nb\r\nc\r\n"), current: []byte("A:x\r\n\r\na\r\nb\r\nc\r\n"), wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationGenerated, wantJSON: "{\"b\":[{\"c\":[2,3]}]}"},
		{name: "adjacent-data-coalescing", previous: []byte("A:x\r\n\r\nb\r\nc\r\n"), current: []byte("A:x\r\n\r\na\r\n"), literal: 1, wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationGenerated, wantJSON: "{\"b\":[{\"d\":[\"b\",\"c\"]}]}"},
		{name: "sorted-header-and-root-order", previous: []byte("Z: target-z\r\nA: target-a\r\n\r\nold\r\n"), current: []byte("a: current-a\r\nz: current-z\r\n\r\nnew\r\n"), literal: 1, wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationGenerated, wantJSON: "{\"h\":{\"a\":[{\"d\":[\" target-a\"]}],\"z\":[{\"d\":[\" target-z\"]}]},\"b\":[{\"d\":[\"old\"]}]}"},
		{name: "repeated-interleaved-candidates", previous: repeatedPrevious, current: repeatedCurrent, wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationGenerated},
		{name: "invalid-utf8-unavailable", previous: append([]byte("A:x\r\n\r\n"), 0xff), current: []byte("A:x\r\n\r\ntext"), body: 1, literal: 1, wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationUnavailable, wantUnavailable: recipe.BodyUnavailableReasonUnrepresentable},
		{name: "unmatched-unterminated-rejected", previous: []byte("A:x\r\n\r\ntail"), current: []byte("A:x\r\n\r\nother\r\n"), literal: 1, wantCode: recipe.ErrorCodeBodyUnrepresentable},
		{name: "unmatched-unterminated-unavailable", previous: []byte("A:x\r\n\r\ntail"), current: []byte("A:x\r\n\r\nother\r\n"), body: 1, literal: 1, wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationUnavailable, wantUnavailable: recipe.BodyUnavailableReasonUnrepresentable, wantJSON: "{\"b\":null}"},
		{name: "copy-only-literal-unavailable", previous: []byte("A:x\r\n\r\nprior\r\n"), current: []byte("A:x\r\n\r\ncurrent\r\n"), body: 1, wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationUnavailable, wantUnavailable: recipe.BodyUnavailableReasonLiteralRequired, wantJSON: "{\"b\":null}"},
		{name: "copy-only-literal-rejected", previous: []byte("A:x\r\n\r\nprior\r\n"), current: []byte("A:x\r\n\r\ncurrent\r\n"), wantCode: recipe.ErrorCodeBodyUnrepresentable},
		{name: "current-only-header-removal", previous: []byte("B: retained\r\n\r\nbody\r\n"), current: []byte("A: removed\r\nB: retained\r\n\r\nbody\r\n"), wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationUnchanged, wantJSON: "{\"h\":{\"a\":[]}}"},
		{name: "previous-only-header-add", previous: []byte("A: restored\r\nB: retained\r\n\r\nbody\r\n"), current: []byte("B: retained\r\n\r\nbody\r\n"), literal: 1, wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationUnchanged},
		{name: "excluded-only", previous: []byte("Received: old\r\nX-Trace: old\r\nSubject: same\r\n\r\nbody\r\n"), current: []byte("received: new\r\nx-trace: new\r\nSubject: same\r\n\r\nbody\r\n"), wantOutcome: recipe.GenerationOutcomeUnchanged, wantBodyOutcome: recipe.BodyGenerationUnchanged},
		{name: "trailing-empty-collapse", previous: []byte("A:x\r\n\r\nbody\r\n\r\n"), current: []byte("A:x\r\n\r\nbody\r\n"), literal: 1, wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationGenerated},
		{name: "privacy-marker-failure", previous: []byte("Subject: " + generationFuzzToxicMarker + "\r\n\r\nold\r\n"), current: []byte("Subject: current\r\n\r\nnew\r\n"), wantCode: recipe.ErrorCodeHeaderUnrepresentable},
		{name: "exact-input-limit", previous: []byte("Subject: prior\r\n\r\nold\r\n"), current: []byte("Subject: current\r\n\r\nnew\r\n"), literal: 1, limitProfile: 1, wantOutcome: recipe.GenerationOutcomeRecipe, wantBodyOutcome: recipe.BodyGenerationGenerated},
		{name: "one-over-input-limit", previous: []byte("Subject: prior\r\n\r\nold\r\n"), current: []byte("Subject: current\r\n\r\nnew\r\n"), literal: 1, limitProfile: 2, wantCode: recipe.ErrorCodeLimitExceeded, wantLimitName: "max_input_bytes", wantDimension: recipe.DimensionBody},
	}
}

// repeatedGenerationSeedMessages constructs a materially adversarial monotone candidate vector.
func repeatedGenerationSeedMessages(count int) ([]byte, []byte) {
	var previous, current strings.Builder
	previous.WriteString("A:x\r\n\r\n")
	current.WriteString("A:x\r\n\r\n")
	for range count {
		previous.WriteString("d\r\n")
		current.WriteString("d\r\nm\r\n")
	}
	return []byte(previous.String()), []byte(current.String())
}

// TestGenerationFuzzSeedsReachNamedLanes proves retained seeds cannot become vacuous typed failures.
func TestGenerationFuzzSeedsReachNamedLanes(t *testing.T) {
	for _, seed := range generationFuzzSeeds() {
		t.Run(seed.name, func(t *testing.T) {
			previousMessage, previousErr := rawmsg.Parse(seed.previous)
			currentMessage, currentErr := rawmsg.Parse(seed.current)
			if previousErr != nil || currentErr != nil {
				t.Fatal("retained seed is not a strict message pair")
			}
			previous, _ := recipe.NewState(previousMessage)
			current, _ := recipe.NewState(currentMessage)
			request, _ := recipe.NewGenerationRequest(previous, current, recipe.BodyUnavailablePolicy(seed.body%2), recipe.LiteralDisclosurePolicy(seed.literal%2))
			generator, err := recipe.NewGenerator(fuzzGenerationLimits(previous, current, seed.limitProfile), canonical.NewHeaderRelevance())
			if err != nil {
				t.Fatal("retained seed limits are incoherent")
			}
			generation, usage, err := generator.Generate(request)
			if seed.wantCode.Known() {
				if fuzzGenerationErrorCode(err) != seed.wantCode || generation.Valid() || usage.JSONBytes() != 0 {
					t.Fatal("retained failure seed did not reach expected closed lane")
				}
				var typed *recipe.Error
				if !errors.As(err, &typed) || seed.wantLimitName != "" && typed.LimitName() != seed.wantLimitName ||
					seed.wantDimension.Known() && typed.Dimension() != seed.wantDimension {
					t.Fatal("retained failure seed reached wrong bounded metadata lane")
				}
				return
			}
			if err != nil || generation.Outcome() != seed.wantOutcome || generation.BodyOutcome() != seed.wantBodyOutcome || generation.BodyUnavailableReason() != seed.wantUnavailable {
				t.Fatal("retained success seed did not reach expected closed lane")
			}
			if seed.wantJSON != "" && !bytes.Equal(generation.DecodedJSON(), []byte(seed.wantJSON)) {
				t.Fatal("retained success seed generated different normative JSON")
			}
			if generation.Outcome() == recipe.GenerationOutcomeRecipe {
				assertGeneratedRoundTrip(t, generator, previous, current, generation)
			}
		})
	}
}

// fuzzGenerationPair runs the common deterministic and immutable generation contract.
func fuzzGenerationPair(t *testing.T, previousBytes, currentBytes []byte, bodyPolicyByte, literalPolicyByte, limitProfile byte, roundTrip bool) {
	t.Helper()
	if len(previousBytes) > 8<<10 || len(currentBytes) > 8<<10 {
		t.Skip()
	}
	previousMessage, previousErr := rawmsg.Parse(previousBytes)
	currentMessage, currentErr := rawmsg.Parse(currentBytes)
	if previousErr != nil || currentErr != nil {
		return
	}
	previous, err := recipe.NewState(previousMessage)
	if err != nil {
		t.Fatal("validated previous message did not produce state")
	}
	current, err := recipe.NewState(currentMessage)
	if err != nil {
		t.Fatal("validated current message did not produce state")
	}
	bodyPolicy := recipe.BodyUnavailablePolicy(bodyPolicyByte % 2)
	literalPolicy := recipe.LiteralDisclosurePolicy(literalPolicyByte % 2)
	request, err := recipe.NewGenerationRequest(previous, current, bodyPolicy, literalPolicy)
	if err != nil {
		t.Fatal("valid fuzz states and policies did not produce request")
	}
	limits := fuzzGenerationLimits(previous, current, limitProfile)
	generator, err := recipe.NewGenerator(limits, canonical.NewHeaderRelevance())
	if err != nil {
		t.Fatal("production generator setup failed")
	}

	first, firstUsage, firstErr := generator.Generate(request)
	second, secondUsage, secondErr := generator.Generate(request)
	assertGenerationFuzzResult(t, generator, first, firstUsage, firstErr, previousBytes, currentBytes)
	assertGenerationFuzzResult(t, generator, second, secondUsage, secondErr, previousBytes, currentBytes)
	if fuzzGenerationErrorFingerprint(firstErr) != fuzzGenerationErrorFingerprint(secondErr) || firstUsage != secondUsage || first.Outcome() != second.Outcome() ||
		first.BodyOutcome() != second.BodyOutcome() || first.BodyUnavailableReason() != second.BodyUnavailableReason() || !bytes.Equal(first.DecodedJSON(), second.DecodedJSON()) {
		t.Fatal("generation is not deterministic")
	}
	if !roundTrip || firstErr != nil || first.Outcome() != recipe.GenerationOutcomeRecipe {
		assertStateStillMatchesInput(t, previous, previousBytes)
		assertStateStillMatchesInput(t, current, currentBytes)
		return
	}
	assertGeneratedRoundTrip(t, generator, previous, current, first)
	assertStateStillMatchesInput(t, previous, previousBytes)
	assertStateStillMatchesInput(t, current, currentBytes)
}

// fuzzGenerationLimits derives coherent default, exact-input, or one-over input profiles.
func fuzzGenerationLimits(previous, current recipe.State, profile byte) recipe.GenerationLimits {
	if profile%3 == 0 {
		return recipe.GenerationLimits{}
	}
	previousMessage, previousErr := previous.Materialize()
	currentMessage, currentErr := current.Materialize()
	if previousErr != nil || currentErr != nil {
		return recipe.GenerationLimits{}
	}
	exactBytes := len(previousMessage.RawBytes()) + len(currentMessage.RawBytes())
	limits := recipe.GenerationLimits{RecipeLimits: recipe.DefaultLimits()}
	limits.RecipeLimits.MaxStateBytes = max(len(previousMessage.RawBytes()), len(currentMessage.RawBytes()))
	limits.MaxInputBytes = exactBytes
	if profile%3 == 2 && exactBytes > 1 {
		limits.MaxInputBytes--
	}
	return limits
}

// assertGenerationFuzzResult verifies bounded zero-on-error and immutable success contracts.
func assertGenerationFuzzResult(t *testing.T, generator recipe.Generator, generation recipe.Generation, usage recipe.GenerationUsage, err error, previousBytes, currentBytes []byte) {
	t.Helper()
	if !usage.Valid() {
		t.Fatal("generation returned invalid usage")
	}
	assertGenerationUsageBounded(t, usage, generator.Limits())
	if err != nil {
		var typed *recipe.Error
		if generation.Valid() || usage.JSONBytes() != 0 || !errors.As(err, &typed) || !typed.Code().Known() || len(err.Error()) > 512 {
			t.Fatal("generation failure violated bounded zero-output contract")
		}
		if (bytes.Contains(previousBytes, []byte(generationFuzzToxicMarker)) || bytes.Contains(currentBytes, []byte(generationFuzzToxicMarker))) && bytes.Contains([]byte(err.Error()), []byte(generationFuzzToxicMarker)) {
			t.Fatal("generation failure exposed protected marker")
		}
		return
	}
	if !generation.Valid() || usage.JSONBytes() != len(generation.DecodedJSON()) || usage.JSONBytes() > generator.Limits().RecipeLimits.MaxDecodedRecipeBytes {
		t.Fatal("generation success violated bounded result contract")
	}
	jsonView := generation.DecodedJSON()
	if len(jsonView) > 0 {
		jsonView[0] ^= 0xff
		if bytes.Equal(jsonView, generation.DecodedJSON()) {
			t.Fatal("generation JSON accessor exposed owned storage")
		}
	}
	if parsed, ok := generation.Recipe(); ok {
		names := parsed.HeaderNames()
		if len(names) > 0 {
			names[0] = "mutated"
			if bytes.Equal([]byte(names[0]), []byte(parsed.HeaderNames()[0])) {
				t.Fatal("recipe header-name accessor exposed owned storage")
			}
		}
	}
}

// assertGeneratedRoundTrip proves strict same-limit apply and canonical equality for known dimensions.
func assertGeneratedRoundTrip(t *testing.T, generator recipe.Generator, previous, current recipe.State, generation recipe.Generation) {
	t.Helper()
	parser, err := recipe.NewParser(generator.Limits().RecipeLimits)
	if err != nil {
		t.Fatal("strict parser setup failed")
	}
	parsed, _, err := parser.Parse(generation.DecodedJSON())
	if err != nil {
		t.Fatal("generated JSON failed strict parser")
	}
	applier, err := recipe.NewApplier(generator.Limits().RecipeLimits)
	if err != nil {
		t.Fatal("strict applier setup failed")
	}
	reconstructed, _, err := applier.Apply(current, parsed)
	if err != nil || !reconstructed.Valid() {
		t.Fatal("generated recipe failed strict application")
	}
	assertExactRelevantHeaderGroups(t, previous.Headers(), reconstructed.Headers())
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatal("canonicalizer setup failed")
	}
	previousHeader, err := canonicalizer.HeaderHash(previous.Headers())
	if err != nil {
		t.Fatal("previous header canonicalization failed")
	}
	reconstructedHeader, err := canonicalizer.HeaderHash(reconstructed.Headers())
	if err != nil || !equalCanonicalResult(previousHeader, reconstructedHeader) {
		t.Fatal("reconstructed header canonical evidence differs")
	}
	if generation.BodyOutcome() == recipe.BodyGenerationUnavailable {
		if reconstructed.BodyState() != recipe.BodyAvailabilityUnavailable {
			t.Fatal("unavailable recipe reconstructed a known body")
		}
		return
	}
	previousBody, previousKnown := previous.Body()
	reconstructedBody, reconstructedKnown := reconstructed.Body()
	if !previousKnown || !reconstructedKnown || !previousBody.Equal(reconstructedBody) {
		t.Fatal("known-body generation lost body state")
	}
	previousMessage, previousErr := previous.Materialize()
	reconstructedMessage, reconstructedErr := reconstructed.Materialize()
	if previousErr != nil || reconstructedErr != nil || previousMessage.Framing() != reconstructedMessage.Framing() {
		t.Fatal("known-body generation changed message framing")
	}
	previousBodyResult, err := canonicalizer.BodyHash(previousBody)
	if err != nil {
		t.Fatal("previous body canonicalization failed")
	}
	reconstructedBodyResult, err := canonicalizer.BodyHash(reconstructedBody)
	if err != nil || !equalCanonicalResult(previousBodyResult, reconstructedBodyResult) {
		t.Fatal("reconstructed body canonical evidence differs")
	}
}

// assertExactRelevantHeaderGroups independently compares bottom-up unfolded values for production-relevant names.
func assertExactRelevantHeaderGroups(t *testing.T, previous, reconstructed rawmsg.HeaderBlock) {
	t.Helper()
	relevance := canonical.NewHeaderRelevance()
	names := make(map[string]struct{})
	for _, field := range previous.Fields() {
		names[field.NameLower()] = struct{}{}
	}
	for _, field := range reconstructed.Fields() {
		names[field.NameLower()] = struct{}{}
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	for _, name := range ordered {
		relevant, err := relevance.IsRelevantHeader(name)
		if err != nil {
			t.Fatal("production relevance rejected validated name")
		}
		if !relevant {
			continue
		}
		left := previous.FieldsByName(name)
		right := reconstructed.FieldsByName(name)
		if len(left) != len(right) {
			t.Fatal("relevant header occurrence count differs")
		}
		for index := range left {
			leftIndex := len(left) - 1 - index
			rightIndex := len(right) - 1 - index
			if !bytes.Equal(left[leftIndex].UnfoldedValue(), right[rightIndex].UnfoldedValue()) {
				t.Fatal("relevant bottom-up unfolded header value differs")
			}
		}
	}
}

// assertStateStillMatchesInput verifies generation and application did not mutate caller state.
func assertStateStillMatchesInput(t *testing.T, state recipe.State, input []byte) {
	t.Helper()
	message, err := state.Materialize()
	if err != nil || !bytes.Equal(message.RawBytes(), input) {
		t.Fatal("generation mutated an input state")
	}
}

// assertGenerationUsageBounded verifies every exposed counter stays within the active limits.
func assertGenerationUsageBounded(t *testing.T, usage recipe.GenerationUsage, limits recipe.GenerationLimits) {
	t.Helper()
	if usage.InputBytes() > limits.MaxInputBytes || usage.InputItems() > limits.MaxInputItems ||
		usage.Candidates() > limits.MaxCandidateEntries || usage.CandidateKeyBytes() > limits.MaxCandidateKeyBytes ||
		usage.Comparisons() > limits.MaxComparisons || usage.GeneratedSteps() > limits.RecipeLimits.MaxTotalSteps ||
		usage.GeneratedLiterals() > limits.RecipeLimits.MaxDataStrings || usage.LiteralBytes() > limits.RecipeLimits.MaxTotalLiteralBytes ||
		usage.JSONBytes() > limits.RecipeLimits.MaxDecodedRecipeBytes || usage.WorkUnits() > limits.MaxGenerationWorkUnits ||
		usage.ProofWorkUnits() > usage.WorkUnits() {
		t.Fatal("generation usage exceeded active limits")
	}
}

// equalCanonicalResult compares canonical bytes and digest without exposing either.
func equalCanonicalResult(left, right canonical.Result) bool {
	if !bytes.Equal(left.CanonicalBytes().Bytes(), right.CanonicalBytes().Bytes()) {
		return false
	}
	leftDigest, leftOK := left.Digest()
	rightDigest, rightOK := right.Digest()
	return leftOK && rightOK && bytes.Equal(leftDigest.Bytes(), rightDigest.Bytes())
}

// fuzzGenerationErrorCode returns the bounded closed code used for deterministic comparisons.
func fuzzGenerationErrorCode(err error) recipe.ErrorCode {
	var typed *recipe.Error
	if !errors.As(err, &typed) {
		return ""
	}
	return typed.Code()
}

// generationErrorFingerprint stores only closed non-sensitive error metadata.
type generationErrorFingerprint struct {
	code      recipe.ErrorCode
	class     recipe.ErrorClass
	dimension recipe.Dimension
	limitName string
}

// fuzzGenerationErrorFingerprint returns a closed safe fingerprint for deterministic failure comparisons.
func fuzzGenerationErrorFingerprint(err error) generationErrorFingerprint {
	var typed *recipe.Error
	if !errors.As(err, &typed) {
		return generationErrorFingerprint{}
	}
	return generationErrorFingerprint{code: typed.Code(), class: typed.Class(), dimension: typed.Dimension(), limitName: typed.LimitName()}
}
