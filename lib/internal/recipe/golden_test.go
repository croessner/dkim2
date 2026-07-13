package recipe

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

const recipeApplicationDraftBaseline = "draft-ietf-dkim-dkim2-spec-04"

type recipeGoldenFixture struct {
	Draft string             `json:"draft"`
	Cases []recipeGoldenCase `json:"cases"`
}

type recipeGoldenCase struct {
	Name                  string `json:"name"`
	SourceMessageBase64   string `json:"source_message_base64"`
	RecipeJSON            string `json:"recipe_json"`
	ExpectedHeadersBase64 string `json:"expected_headers_base64"`
	ExpectedBodyState     string `json:"expected_body_state"`
	ExpectedBodyBase64    string `json:"expected_body_base64"`
}

// TestGoldenRecipeApplicationDraft04 verifies draft-versioned reconstruction examples.
func TestGoldenRecipeApplicationDraft04(t *testing.T) {
	fixture := loadRecipeGoldenFixture(t)
	if fixture.Draft != recipeApplicationDraftBaseline {
		t.Fatalf("fixture draft = %q, want %q", fixture.Draft, recipeApplicationDraftBaseline)
	}

	parser, err := NewParser(DefaultLimits())
	if err != nil {
		t.Fatalf("NewParser() error = %v", err)
	}
	applier, err := NewApplier(DefaultLimits())
	if err != nil {
		t.Fatalf("NewApplier() error = %v", err)
	}

	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			sourceBytes := decodeRecipeGoldenBase64(t, tc.SourceMessageBase64)
			source, parseErr := rawmsg.Parse(sourceBytes)
			if parseErr != nil {
				t.Fatalf("rawmsg.Parse() error = %v", parseErr)
			}
			state, stateErr := NewState(source)
			if stateErr != nil {
				t.Fatalf("NewState() error = %v", stateErr)
			}
			plan, _, recipeErr := parser.Parse([]byte(tc.RecipeJSON))
			if recipeErr != nil {
				t.Fatalf("Parser.Parse() error = %v", recipeErr)
			}
			got, _, applyErr := applier.Apply(state, plan)
			if applyErr != nil {
				t.Fatalf("Applier.Apply() error = %v", applyErr)
			}

			wantHeaders := decodeRecipeGoldenBase64(t, tc.ExpectedHeadersBase64)
			if !bytes.Equal(got.Headers().OriginalBytes(), wantHeaders) {
				t.Fatal("reconstructed header bytes differed from golden fixture")
			}
			assertRecipeGoldenBody(t, got, tc)
		})
	}
}

// loadRecipeGoldenFixture reads the synthetic draft-versioned fixture.
func loadRecipeGoldenFixture(t *testing.T) recipeGoldenFixture {
	t.Helper()

	const path = "testdata/golden/recipe-application-draft-ietf-dkim-dkim2-spec-04.json"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	if !bytes.Contains(data, []byte(recipeApplicationDraftBaseline)) {
		t.Fatalf("fixture %q does not identify %s", path, recipeApplicationDraftBaseline)
	}

	var fixture recipeGoldenFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("json.Unmarshal(%q) error = %v", path, err)
	}
	return fixture
}

// decodeRecipeGoldenBase64 decodes one byte-preserving fixture value.
func decodeRecipeGoldenBase64(t *testing.T, value string) []byte {
	t.Helper()

	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	return decoded
}

// assertRecipeGoldenBody verifies known and unavailable body outcomes.
func assertRecipeGoldenBody(t *testing.T, got State, tc recipeGoldenCase) {
	t.Helper()

	if string(got.BodyState()) != tc.ExpectedBodyState {
		t.Fatalf("BodyState() = %q, want %q", got.BodyState(), tc.ExpectedBodyState)
	}
	body, known := got.Body()
	if tc.ExpectedBodyState == string(BodyAvailabilityUnavailable) {
		if known {
			t.Fatal("unavailable golden body unexpectedly exposed bytes")
		}
		return
	}
	if tc.ExpectedBodyState != string(BodyAvailabilityKnown) || !known {
		t.Fatal("golden fixture has an invalid known-body expectation")
	}
	wantBody := decodeRecipeGoldenBase64(t, tc.ExpectedBodyBase64)
	if !bytes.Equal(body.Bytes(), wantBody) {
		t.Fatal("reconstructed body bytes differed from golden fixture")
	}
}
