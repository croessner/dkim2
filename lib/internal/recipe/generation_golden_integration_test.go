package recipe_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
)

const generationGoldenDraft04 = "draft-ietf-dkim-dkim2-spec-04"

type retainedGenerationFixture struct {
	Draft           string                   `json:"draft"`
	SerializerCases []retainedSerializerCase `json:"cases"`
	GenerationCases []retainedGenerationCase `json:"generation_cases"`
}

type retainedSerializerCase struct {
	Name string `json:"name"`
	JSON string `json:"json"`
}

type retainedGenerationCase struct {
	Name              string                        `json:"name"`
	PreviousBase64    string                        `json:"previous_base64"`
	CurrentBase64     string                        `json:"current_base64"`
	BodyPolicy        string                        `json:"body_policy"`
	LiteralPolicy     string                        `json:"literal_policy"`
	Outcome           recipe.GenerationOutcome      `json:"outcome"`
	BodyOutcome       recipe.BodyGenerationOutcome  `json:"body_outcome"`
	UnavailableReason recipe.BodyUnavailableReason  `json:"unavailable_reason"`
	JSON              string                        `json:"json"`
	Reconstructed     retainedReconstructedEvidence `json:"reconstructed"`
	Canonical         retainedCanonicalEvidence     `json:"canonical"`
}

type retainedReconstructedEvidence struct {
	Framing          *rawmsg.MessageFraming  `json:"framing"`
	BodyAvailability recipe.BodyAvailability `json:"body_availability"`
	BodyBase64       *string                 `json:"body_base64"`
	RelevantHeaders  []retainedHeaderGroup   `json:"relevant_headers"`
}

type retainedHeaderGroup struct {
	Name                 string   `json:"name"`
	ValuesBottomUpBase64 []string `json:"values_bottom_up_base64"`
}

type retainedCanonicalEvidence struct {
	HeaderInputBase64  string  `json:"header_input_base64"`
	HeaderSHA256Base64 string  `json:"header_sha256_base64"`
	BodyInputBase64    *string `json:"body_input_base64"`
	BodySHA256Base64   *string `json:"body_sha256_base64"`
}

// TestRetainedGenerationDraft04Evidence verifies reachable state, policy, outcome, reconstruction, and canonical fixtures.
func TestRetainedGenerationDraft04Evidence(t *testing.T) {
	fixture := loadRetainedGenerationFixture(t)
	if fixture.Draft != generationGoldenDraft04 || len(fixture.SerializerCases) == 0 || len(fixture.GenerationCases) == 0 {
		t.Fatal("retained fixture scope or draft is incomplete")
	}
	for _, test := range fixture.GenerationCases {
		t.Run(test.Name, func(t *testing.T) {
			previousBytes := decodeRetainedBase64(t, test.PreviousBase64)
			currentBytes := decodeRetainedBase64(t, test.CurrentBase64)
			previous := mustExternalState(t, previousBytes)
			current := mustExternalState(t, currentBytes)
			request, err := recipe.NewGenerationRequest(previous, current, retainedBodyPolicy(t, test.BodyPolicy), retainedLiteralPolicy(t, test.LiteralPolicy))
			if err != nil {
				t.Fatal("retained request construction failed")
			}
			generator := mustExternalGenerator(t)
			generation, usage, err := generator.Generate(request)
			if err != nil || !generation.Valid() || !usage.Valid() || generation.Outcome() != test.Outcome || generation.BodyOutcome() != test.BodyOutcome || generation.BodyUnavailableReason() != test.UnavailableReason {
				t.Fatal("retained generation outcome differs")
			}
			if !bytes.Equal(generation.DecodedJSON(), []byte(test.JSON)) {
				t.Fatal("retained generated JSON differs")
			}
			reconstructed := current
			if generation.Outcome() == recipe.GenerationOutcomeRecipe {
				parsed, _, parseErr := mustExternalParser(t, generator.Limits().RecipeLimits).Parse(generation.DecodedJSON())
				if parseErr != nil {
					t.Fatal("retained generated JSON failed strict parse")
				}
				reconstructed, _, err = mustExternalApplier(t, generator.Limits().RecipeLimits).Apply(current, parsed)
				if err != nil {
					t.Fatal("retained generated recipe failed strict apply")
				}
			}
			assertRetainedReconstruction(t, previous, current, reconstructed, test.Reconstructed)
			assertRetainedCanonicalEvidence(t, previous, reconstructed, test.Canonical)
		})
	}
}

// loadRetainedGenerationFixture reads the combined serializer-only and reachable generation fixture.
func loadRetainedGenerationFixture(t *testing.T) retainedGenerationFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/golden/recipe-generation-draft-ietf-dkim-dkim2-spec-04.json")
	if err != nil {
		t.Fatal("retained generation fixture read failed")
	}
	fixture, err := decodeRetainedGenerationFixture(data)
	if err != nil {
		t.Fatal("retained generation fixture is invalid")
	}
	return fixture
}

// decodeRetainedGenerationFixture strictly decodes one complete retained fixture document.
func decodeRetainedGenerationFixture(data []byte) (retainedGenerationFixture, error) {
	if err := rejectRetainedDuplicateJSONMembers(data); err != nil {
		return retainedGenerationFixture{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var fixture retainedGenerationFixture
	if err := decoder.Decode(&fixture); err != nil {
		return retainedGenerationFixture{}, fmt.Errorf("decode retained fixture: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return retainedGenerationFixture{}, fmt.Errorf("retained fixture has trailing JSON")
	}
	if err := validateRetainedGenerationFixture(fixture); err != nil {
		return retainedGenerationFixture{}, err
	}
	return fixture, nil
}

// rejectRetainedDuplicateJSONMembers rejects last-value-wins ambiguity at every object depth.
func rejectRetainedDuplicateJSONMembers(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := consumeRetainedJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("retained fixture has trailing JSON token")
	}
	return nil
}

// consumeRetainedJSONValue consumes one JSON value while rejecting duplicate object names.
func consumeRetainedJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("retained fixture token decode failed: %w", err)
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			nameToken, nameErr := decoder.Token()
			if nameErr != nil {
				return fmt.Errorf("retained fixture object name decode failed: %w", nameErr)
			}
			name, ok := nameToken.(string)
			if !ok {
				return fmt.Errorf("retained fixture object name is not a string")
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("retained fixture object contains duplicate member")
			}
			seen[name] = struct{}{}
			if err := consumeRetainedJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			return fmt.Errorf("retained fixture object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := consumeRetainedJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			return fmt.Errorf("retained fixture array is not closed")
		}
	default:
		return fmt.Errorf("retained fixture has unexpected delimiter")
	}
	return nil
}

// validateRetainedGenerationFixture enforces closed inventories and outcome-aware evidence presence.
func validateRetainedGenerationFixture(fixture retainedGenerationFixture) error {
	if fixture.Draft != generationGoldenDraft04 {
		return fmt.Errorf("retained fixture has wrong draft")
	}
	serializerInventory := map[string]struct{}{
		"combined-order-and-escaping": {}, "header-only": {}, "body-empty": {},
		"body-unavailable": {}, "data-before-copy-and-multidigit": {},
	}
	generationInventory := map[string]struct{}{
		"unchanged-known": {}, "replace-known": {}, "duplicate-copy": {},
		"header-only-unavailable": {}, "current-only-header-removal": {}, "binary-body-copy": {},
		"json-sensitive-header-key": {}, "delimited-empty-from-header-only": {}, "copy-only-literal-unavailable": {},
	}
	serializerNames := make([]string, 0, len(fixture.SerializerCases))
	for _, test := range fixture.SerializerCases {
		if test.JSON == "" {
			return fmt.Errorf("serializer fixture case is incomplete")
		}
		serializerNames = append(serializerNames, test.Name)
	}
	if err := validateRetainedCaseInventory(serializerNames, serializerInventory); err != nil {
		return err
	}
	generationNames := make([]string, 0, len(fixture.GenerationCases))
	for _, test := range fixture.GenerationCases {
		generationNames = append(generationNames, test.Name)
		if err := validateRetainedGenerationCase(test); err != nil {
			return err
		}
	}
	return validateRetainedCaseInventory(generationNames, generationInventory)
}

// validateRetainedCaseInventory rejects missing, duplicate, empty, and unknown fixture case names.
func validateRetainedCaseInventory(names []string, expected map[string]struct{}) error {
	if len(names) != len(expected) {
		return fmt.Errorf("retained fixture inventory size differs")
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if _, known := expected[name]; !known {
			return fmt.Errorf("retained fixture inventory contains unknown case")
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("retained fixture inventory contains duplicate case")
		}
		seen[name] = struct{}{}
	}
	return nil
}

// validateRetainedGenerationCase enforces the closed state, policy, outcome, and evidence schema.
func validateRetainedGenerationCase(test retainedGenerationCase) error {
	if test.PreviousBase64 == "" || test.CurrentBase64 == "" ||
		!retainedBodyPolicyKnown(test.BodyPolicy) || !retainedLiteralPolicyKnown(test.LiteralPolicy) ||
		!test.Outcome.Known() || !test.BodyOutcome.Known() ||
		test.Canonical.HeaderInputBase64 == "" || test.Canonical.HeaderSHA256Base64 == "" {
		return fmt.Errorf("retained generation case is incomplete")
	}
	if _, err := base64.StdEncoding.DecodeString(test.PreviousBase64); err != nil {
		return fmt.Errorf("retained previous state is not base64")
	}
	if _, err := base64.StdEncoding.DecodeString(test.CurrentBase64); err != nil {
		return fmt.Errorf("retained current state is not base64")
	}
	if err := validateRetainedGenerationOutcome(test); err != nil {
		return err
	}
	if err := validateRetainedBodyEvidence(test); err != nil {
		return err
	}
	return validateRetainedHeaderEvidence(test.Reconstructed.RelevantHeaders)
}

// validateRetainedGenerationOutcome enforces unchanged and recipe result ownership.
func validateRetainedGenerationOutcome(test retainedGenerationCase) error {
	if test.Outcome == recipe.GenerationOutcomeUnchanged {
		if test.JSON != "" || test.BodyOutcome != recipe.BodyGenerationUnchanged || test.UnavailableReason != "" {
			return fmt.Errorf("retained unchanged case is incoherent")
		}
		return nil
	}
	if test.JSON == "" {
		return fmt.Errorf("retained recipe case omits JSON")
	}
	return nil
}

// validateRetainedBodyEvidence enforces presence distinctions for known and unavailable bodies.
func validateRetainedBodyEvidence(test retainedGenerationCase) error {
	if test.BodyOutcome == recipe.BodyGenerationUnavailable {
		if !test.UnavailableReason.Known() || test.Reconstructed.BodyAvailability != recipe.BodyAvailabilityUnavailable ||
			test.Reconstructed.Framing != nil || test.Reconstructed.BodyBase64 != nil ||
			test.Canonical.BodyInputBase64 != nil || test.Canonical.BodySHA256Base64 != nil {
			return fmt.Errorf("retained unavailable case is incoherent")
		}
		return nil
	}
	if test.UnavailableReason != "" || test.Reconstructed.BodyAvailability != recipe.BodyAvailabilityKnown ||
		test.Reconstructed.Framing == nil || test.Reconstructed.BodyBase64 == nil ||
		test.Canonical.BodyInputBase64 == nil || test.Canonical.BodySHA256Base64 == nil {
		return fmt.Errorf("retained known-body case is incoherent")
	}
	return nil
}

// validateRetainedHeaderEvidence enforces unique named groups and valid protected encodings.
func validateRetainedHeaderEvidence(groups []retainedHeaderGroup) error {
	seenHeaders := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		if group.Name == "" {
			return fmt.Errorf("retained relevant header evidence has empty name")
		}
		if _, duplicate := seenHeaders[group.Name]; duplicate {
			return fmt.Errorf("retained relevant header evidence is duplicated")
		}
		seenHeaders[group.Name] = struct{}{}
		for _, value := range group.ValuesBottomUpBase64 {
			if _, err := base64.StdEncoding.DecodeString(value); err != nil {
				return fmt.Errorf("retained relevant header evidence is not base64")
			}
		}
	}
	return nil
}

// retainedBodyPolicyKnown reports whether a fixture body policy belongs to the closed vocabulary.
func retainedBodyPolicyKnown(value string) bool {
	return value == "reject" || value == "allow_unavailable"
}

// retainedLiteralPolicyKnown reports whether a fixture literal policy belongs to the closed vocabulary.
func retainedLiteralPolicyKnown(value string) bool {
	return value == "copy_only" || value == "allow_literals"
}

// TestRetainedGenerationFixtureRejectsSchemaDrift proves strict decoding and exact inventories are non-vacuous.
func TestRetainedGenerationFixtureRejectsSchemaDrift(t *testing.T) {
	data, err := os.ReadFile("testdata/golden/recipe-generation-draft-ietf-dkim-dkim2-spec-04.json")
	if err != nil {
		t.Fatal("retained generation fixture read failed")
	}
	unknownField := bytes.Replace(data, []byte("{\n  \"draft\":"), []byte("{\n  \"unknown_field\":true,\n  \"draft\":"), 1)
	if _, err := decodeRetainedGenerationFixture(unknownField); err == nil {
		t.Fatal("strict retained fixture decoder accepted an unknown field")
	}
	duplicateField := bytes.Replace(data, []byte("\"draft\": \"draft-ietf-dkim-dkim2-spec-04\","), []byte("\"draft\": \"draft-ietf-dkim-dkim2-spec-04\",\n  \"draft\": \"draft-ietf-dkim-dkim2-spec-04\","), 1)
	if _, err := decodeRetainedGenerationFixture(duplicateField); err == nil {
		t.Fatal("strict retained fixture decoder accepted a duplicate object member")
	}
	if _, err := decodeRetainedGenerationFixture(append(bytes.Clone(data), []byte("\n[]")...)); err == nil {
		t.Fatal("strict retained fixture decoder accepted trailing JSON")
	}
	mutations := []struct {
		name   string
		mutate func(*retainedGenerationFixture)
	}{
		{name: "missing-serializer", mutate: func(f *retainedGenerationFixture) { f.SerializerCases = f.SerializerCases[1:] }},
		{name: "duplicate-serializer", mutate: func(f *retainedGenerationFixture) { f.SerializerCases[0] = f.SerializerCases[1] }},
		{name: "unknown-serializer", mutate: func(f *retainedGenerationFixture) { f.SerializerCases[0].Name = "unknown" }},
		{name: "missing-generation", mutate: func(f *retainedGenerationFixture) { f.GenerationCases = f.GenerationCases[1:] }},
		{name: "duplicate-generation", mutate: func(f *retainedGenerationFixture) { f.GenerationCases[0] = f.GenerationCases[1] }},
		{name: "unknown-generation", mutate: func(f *retainedGenerationFixture) { f.GenerationCases[0].Name = "unknown" }},
		{name: "known-body-presence", mutate: func(f *retainedGenerationFixture) { f.GenerationCases[0].Reconstructed.BodyBase64 = nil }},
		{name: "unavailable-body-presence", mutate: func(f *retainedGenerationFixture) {
			value := ""
			f.GenerationCases[3].Reconstructed.BodyBase64 = &value
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			fixture, decodeErr := decodeRetainedGenerationFixture(data)
			if decodeErr != nil {
				t.Fatal("valid retained fixture failed setup decode")
			}
			mutation.mutate(&fixture)
			mutated, marshalErr := json.Marshal(fixture)
			if marshalErr != nil {
				t.Fatal("retained fixture mutation failed")
			}
			if _, decodeErr = decodeRetainedGenerationFixture(mutated); decodeErr == nil {
				t.Fatal("strict retained fixture validation accepted schema drift")
			}
		})
	}
}

// retainedBodyPolicy decodes the closed synthetic fixture vocabulary.
func retainedBodyPolicy(t *testing.T, value string) recipe.BodyUnavailablePolicy {
	t.Helper()
	switch value {
	case "reject":
		return recipe.RejectUnavailableBody
	case "allow_unavailable":
		return recipe.AllowUnavailableBody
	default:
		t.Fatal("retained body policy is unknown")
		return recipe.BodyUnavailablePolicy(255)
	}
}

// retainedLiteralPolicy decodes the closed synthetic fixture vocabulary.
func retainedLiteralPolicy(t *testing.T, value string) recipe.LiteralDisclosurePolicy {
	t.Helper()
	switch value {
	case "copy_only":
		return recipe.CopyOnly
	case "allow_literals":
		return recipe.AllowLiterals
	default:
		t.Fatal("retained literal policy is unknown")
		return recipe.LiteralDisclosurePolicy(255)
	}
}

// assertRetainedReconstruction verifies exact group, body, availability, and framing evidence.
func assertRetainedReconstruction(t *testing.T, previous, current, reconstructed recipe.State, evidence retainedReconstructedEvidence) {
	t.Helper()
	if !reconstructed.Valid() || reconstructed.BodyState() != evidence.BodyAvailability {
		t.Fatal("retained reconstructed state differs")
	}
	assertRetainedHeaderReconstruction(t, previous, current, reconstructed, evidence.RelevantHeaders)
	assertRetainedBodyReconstruction(t, previous, reconstructed, evidence)
}

// assertRetainedHeaderReconstruction compares both target and result to independent bottom-up evidence.
func assertRetainedHeaderReconstruction(t *testing.T, previous, current, reconstructed recipe.State, groups []retainedHeaderGroup) {
	t.Helper()
	expectedGroups := make(map[string]retainedHeaderGroup, len(groups))
	for _, group := range groups {
		if group.Name == "" {
			t.Fatal("retained relevant header evidence is incomplete")
		}
		if _, duplicate := expectedGroups[group.Name]; duplicate {
			t.Fatal("retained relevant header evidence is duplicated")
		}
		expectedGroups[group.Name] = group
	}
	nameUnion := make(map[string]struct{})
	for _, field := range previous.Headers().Fields() {
		nameUnion[field.NameLower()] = struct{}{}
	}
	for _, field := range current.Headers().Fields() {
		nameUnion[field.NameLower()] = struct{}{}
	}
	relevance := canonical.NewHeaderRelevance()
	relevantCount := 0
	for name := range nameUnion {
		relevant, err := relevance.IsRelevantHeader(name)
		if err != nil {
			t.Fatal("retained validated name failed relevance classification")
		}
		if !relevant {
			continue
		}
		relevantCount++
		group, present := expectedGroups[name]
		if !present {
			t.Fatal("retained relevant header evidence omitted a group")
		}
		previousFields := previous.Headers().FieldsByName(group.Name)
		reconstructedFields := reconstructed.Headers().FieldsByName(group.Name)
		if len(previousFields) != len(group.ValuesBottomUpBase64) || len(reconstructedFields) != len(group.ValuesBottomUpBase64) {
			t.Fatal("retained relevant header count differs")
		}
		for index, encoded := range group.ValuesBottomUpBase64 {
			previousIndex := len(previousFields) - 1 - index
			reconstructedIndex := len(reconstructedFields) - 1 - index
			expected := decodeRetainedBase64(t, encoded)
			if !bytes.Equal(previousFields[previousIndex].UnfoldedValue(), expected) || !bytes.Equal(reconstructedFields[reconstructedIndex].UnfoldedValue(), expected) {
				t.Fatal("retained relevant header value differs")
			}
		}
	}
	if relevantCount != len(expectedGroups) {
		t.Fatal("retained relevant header evidence added an unknown group")
	}
}

// assertRetainedBodyReconstruction compares known target and result bytes or unavailable field absence.
func assertRetainedBodyReconstruction(t *testing.T, previous, reconstructed recipe.State, evidence retainedReconstructedEvidence) {
	t.Helper()
	if evidence.BodyAvailability == recipe.BodyAvailabilityUnavailable {
		if _, known := reconstructed.Body(); known || evidence.BodyBase64 != nil || evidence.Framing != nil {
			t.Fatal("retained unavailable-body evidence is incoherent")
		}
		return
	}
	previousBody, previousKnown := previous.Body()
	reconstructedBody, reconstructedKnown := reconstructed.Body()
	previousMessage, previousErr := previous.Materialize()
	reconstructedMessage, reconstructedErr := reconstructed.Materialize()
	if evidence.BodyBase64 == nil || evidence.Framing == nil || !previousKnown || !reconstructedKnown || previousErr != nil || reconstructedErr != nil ||
		previousMessage.Framing() != *evidence.Framing || reconstructedMessage.Framing() != *evidence.Framing ||
		!bytes.Equal(previousBody.Bytes(), decodeRetainedBase64(t, *evidence.BodyBase64)) ||
		!bytes.Equal(reconstructedBody.Bytes(), decodeRetainedBase64(t, *evidence.BodyBase64)) {
		t.Fatal("retained known-body or framing evidence differs")
	}
}

// assertRetainedCanonicalEvidence verifies exact Section 6 inputs and SHA-256 evidence.
func assertRetainedCanonicalEvidence(t *testing.T, previous, reconstructed recipe.State, evidence retainedCanonicalEvidence) {
	t.Helper()
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatal("canonicalizer setup failed")
	}
	previousHeader, previousErr := canonicalizer.HeaderHash(previous.Headers())
	reconstructedHeader, reconstructedErr := canonicalizer.HeaderHash(reconstructed.Headers())
	if previousErr != nil || reconstructedErr != nil {
		t.Fatal("retained header canonicalization failed")
	}
	assertRetainedCanonicalResult(t, previousHeader, evidence.HeaderInputBase64, evidence.HeaderSHA256Base64)
	assertRetainedCanonicalResult(t, reconstructedHeader, evidence.HeaderInputBase64, evidence.HeaderSHA256Base64)
	if reconstructed.BodyState() == recipe.BodyAvailabilityUnavailable {
		if evidence.BodyInputBase64 != nil || evidence.BodySHA256Base64 != nil {
			t.Fatal("unavailable fixture claimed body canonical evidence")
		}
		return
	}
	previousBody, previousKnown := previous.Body()
	reconstructedBody, reconstructedKnown := reconstructed.Body()
	if evidence.BodyInputBase64 == nil || evidence.BodySHA256Base64 == nil || !previousKnown || !reconstructedKnown {
		t.Fatal("retained known-body canonical evidence is incomplete")
	}
	previousBodyResult, previousErr := canonicalizer.BodyHash(previousBody)
	reconstructedBodyResult, reconstructedErr := canonicalizer.BodyHash(reconstructedBody)
	if previousErr != nil || reconstructedErr != nil {
		t.Fatal("retained body canonicalization failed")
	}
	assertRetainedCanonicalResult(t, previousBodyResult, *evidence.BodyInputBase64, *evidence.BodySHA256Base64)
	assertRetainedCanonicalResult(t, reconstructedBodyResult, *evidence.BodyInputBase64, *evidence.BodySHA256Base64)
}

// assertRetainedCanonicalResult compares fixture bytes and padded digest text without logging payload.
func assertRetainedCanonicalResult(t *testing.T, result canonical.Result, inputBase64, digestBase64 string) {
	t.Helper()
	digest, ok := result.Digest()
	if !ok || !bytes.Equal(result.CanonicalBytes().Bytes(), decodeRetainedBase64(t, inputBase64)) || digest.Base64() != digestBase64 {
		t.Fatal("retained canonical evidence differs")
	}
}

// decodeRetainedBase64 decodes synthetic fixture bytes without echoing protected content on failure.
func decodeRetainedBase64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal("retained base64 evidence is invalid")
	}
	return decoded
}
