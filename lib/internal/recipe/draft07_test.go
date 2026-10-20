package recipe

import (
	"bytes"
	"testing"
)

// TestParserAcceptsBinaryDataSteps reproduces the Draft-07 Section 5 "u" step:
// each string is canonical base64 of one line that need not be valid UTF-8.
func TestParserAcceptsBinaryDataSteps(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  [][]byte
	}{
		{"non utf8 byte", `{"b":[{"u":["/w=="]}]}`, [][]byte{{0xff}}},
		{"empty line", `{"b":[{"u":[""]}]}`, [][]byte{{}}},
		{"valid utf8 is not forbidden", `{"b":[{"u":["aGk="]}]}`, [][]byte{[]byte("hi")}},
		{"several lines", `{"b":[{"u":["gA==","YWJj"]}]}`, [][]byte{{0x80}, []byte("abc")}},
	}
	parser := mustParser(t, Limits{})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, _, err := parser.Parse([]byte(test.input))
			if err != nil || !plan.Valid() || len(plan.bodySteps) != 1 {
				t.Fatalf("Parse() valid=%t code=%s", plan.Valid(), recipeTestErrorCode(err))
			}
			got := plan.bodySteps[0]
			if got.kind != StepKindBinaryData || len(got.data) != len(test.want) {
				t.Fatalf("step kind=%s literals=%d", got.kind, len(got.data))
			}
			for index := range test.want {
				if !bytes.Equal(got.data[index], test.want[index]) {
					t.Fatalf("literal %d differs", index)
				}
			}
		})
	}
}

// TestParserRejectsMalformedBinaryDataSteps reproduces the Draft-07 Section 5
// base64-line pattern and the decoded CR/LF prohibition.
func TestParserRejectsMalformedBinaryDataSteps(t *testing.T) {
	for _, input := range []string{
		`{"b":[{"u":[]}]}`,
		`{"b":[{"u":"/w=="}]}`,
		`{"b":[{"u":[1]}]}`,
		`{"b":[{"u":["/w"]}]}`,
		`{"b":[{"u":["/x=="]}]}`,
		`{"b":[{"u":["/w= ="]}]}`,
		`{"b":[{"u":[" /w=="]}]}`,
		`{"b":[{"u":["/w==\n"]}]}`,
		`{"b":[{"u":["/w\r\n=="]}]}`,
		`{"b":[{"u":["_w=="]}]}`,
		`{"b":[{"u":["/w==="]}]}`,
		`{"b":[{"u":["DQ=="]}]}`,
		`{"b":[{"u":["Cg=="]}]}`,
		`{"b":[{"u":["YQ1i"]}]}`,
		`{"h":{"subject":[{"u":["YQpi"]}]}}`,
	} {
		plan, usage, err := mustParser(t, Limits{}).Parse([]byte(input))
		if plan.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeInvalidLiteral) {
			t.Fatalf("Parse(%s) valid=%t code=%s, want invalid literal", input, plan.Valid(), recipeTestErrorCode(err))
		}
	}
}

// TestApplyBinaryDataStepsEmitDecodedBytes proves that "u" steps reconstruct
// exactly the decoded bytes in both dimensions, like "d" steps.
func TestApplyBinaryDataStepsEmitDecodedBytes(t *testing.T) {
	current := mustRecipeState(t, []byte("Subject: now\r\n\r\nnew\r\n"))
	plan := mustParseRecipe(t, `{"h":{"subject":[{"u":["b2xk"]}]},"b":[{"u":["/w=="]},{"d":["x"]}]}`)
	previous, _, err := mustApplier(t, Limits{}).Apply(current, plan)
	if err != nil {
		t.Fatalf("Apply() code=%s", recipeTestErrorCode(err))
	}
	body, ok := previous.Body()
	if !ok || !bytes.Equal(body.Bytes(), []byte{0xff, '\r', '\n', 'x', '\r', '\n'}) {
		t.Fatalf("reconstructed body mismatch")
	}
	subjects := previous.Headers().FieldsByName(testRecipeHeaderName)
	if len(subjects) != 1 || !bytes.Equal(subjects[0].OriginalBytes(), []byte("subject:old\r\n")) {
		t.Fatalf("reconstructed header mismatch")
	}
}

// TestParserRejectsNonLowercaseJSONKeys reproduces the Draft-07 Section 5 rule
// that every JSON key is lowercase, including unknown top-level keys that are
// otherwise ignored for extensibility.
func TestParserRejectsNonLowercaseJSONKeys(t *testing.T) {
	parser := mustParser(t, Limits{})
	for _, input := range []string{
		`{"B":null}`,
		`{"H":{"subject":[]}}`,
		`{"b":null,"Future":1}`,
		`{"b":null,"future":{"Nested":1}}`,
		`{"b":[{"D":["x"]}]}`,
	} {
		plan, _, err := parser.Parse([]byte(input))
		if plan.Valid() || !IsErrorCode(err, ErrorCodeNonLowercaseKey) {
			t.Fatalf("Parse(%s) valid=%t code=%s, want non-lowercase key", input, plan.Valid(), recipeTestErrorCode(err))
		}
	}
	if plan, _, err := parser.Parse([]byte(`{"b":null,"future":{"nested":1}}`)); err != nil || !plan.Valid() {
		t.Fatalf("Parse(unknown lowercase extension) code=%s, want accepted", recipeTestErrorCode(err))
	}
}

// TestParserRejectsRecipesForUnsignedHeaders reproduces the Draft-07 Section
// 5.1 MUST NOT for recipes naming header fields that are not signed.
func TestParserRejectsRecipesForUnsignedHeaders(t *testing.T) {
	parser, err := NewParser(Limits{}, testHeaderRelevance{relevant: false})
	if err != nil {
		t.Fatalf("NewParser() code=%s", recipeTestErrorCode(err))
	}
	plan, _, err := parser.Parse([]byte(`{"h":{"received":[]}}`))
	if plan.Valid() || !IsErrorCode(err, ErrorCodeUnsignedHeaderRecipe) {
		t.Fatalf("Parse() valid=%t code=%s, want unsigned header recipe", plan.Valid(), recipeTestErrorCode(err))
	}
	if _, err := NewParser(Limits{}, nil); err == nil {
		t.Fatal("NewParser() accepted a nil header relevance classifier")
	}
}

// TestGenerateRoundTripsBinaryBodyLines proves that a generated recipe for a
// previous body line that is not valid UTF-8 serializes as a canonical "u"
// step and passes the generator's own parse, apply, and rehash proof.
func TestGenerateRoundTripsBinaryBodyLines(t *testing.T) {
	previous := mustGenerationState(t, append([]byte("Subject: same\r\n\r\n"), 0xff, 0xfe, '\r', '\n'))
	current := mustGenerationState(t, []byte("Subject: same\r\n\r\nnew\r\n"))
	request, err := NewGenerationRequest(previous, current, RejectUnavailableBody, AllowLiterals)
	if err != nil {
		t.Fatalf("NewGenerationRequest() code=%s", recipeTestErrorCode(err))
	}
	generator, err := NewGenerator(GenerationLimits{}, testHeaderRelevance{relevant: true})
	if err != nil {
		t.Fatalf("NewGenerator() code=%s", recipeTestErrorCode(err))
	}
	generation, _, err := generator.Generate(request)
	if err != nil || !generation.Valid() {
		t.Fatalf("Generate() valid=%t code=%s", generation.Valid(), recipeTestErrorCode(err))
	}
	if got := string(generation.DecodedJSON()); got != `{"b":[{"u":["//4="]}]}` {
		t.Fatalf("DecodedJSON() = %q", got)
	}
}

// TestApplyBinaryDataReconstructsNonUTF8HeaderBytes reproduces the Draft-07
// Section 5 "u" step for header fields: a previous header value that is not
// valid UTF-8 is reconstructed byte-exact.
func TestApplyBinaryDataReconstructsNonUTF8HeaderBytes(t *testing.T) {
	current := mustRecipeState(t, []byte("Subject: now\r\n\r\nbody\r\n"))
	plan := mustParseRecipe(t, `{"h":{"subject":[{"u":["/w=="]}]}}`)
	previous, _, err := mustApplier(t, Limits{}).Apply(current, plan)
	if err != nil || !previous.Valid() {
		t.Fatalf("Apply() valid=%t code=%s", previous.Valid(), recipeTestErrorCode(err))
	}
	subjects := previous.Headers().FieldsByName(testRecipeHeaderName)
	if len(subjects) != 1 || !bytes.Equal(subjects[0].OriginalBytes(), []byte("subject:\xff\r\n")) {
		t.Fatal("reconstructed non-UTF-8 header bytes mismatch")
	}
}

// TestGenerateRoundTripsBinaryHeaderValues proves that a previous header
// value that is not valid UTF-8 serializes as a "u" step and passes the
// generator's own parse, apply, and rehash proof.
func TestGenerateRoundTripsBinaryHeaderValues(t *testing.T) {
	previous := mustGenerationState(t, []byte("Subject: caf\xe9\r\n\r\nbody\r\n"))
	current := mustGenerationState(t, []byte("Subject: new\r\n\r\nbody\r\n"))
	request, err := NewGenerationRequest(previous, current, RejectUnavailableBody, AllowLiterals)
	if err != nil {
		t.Fatalf("NewGenerationRequest() code=%s", recipeTestErrorCode(err))
	}
	generator, err := NewGenerator(GenerationLimits{}, testHeaderRelevance{relevant: true})
	if err != nil {
		t.Fatalf("NewGenerator() code=%s", recipeTestErrorCode(err))
	}
	generation, _, err := generator.Generate(request)
	if err != nil || !generation.Valid() {
		t.Fatalf("Generate() valid=%t code=%s", generation.Valid(), recipeTestErrorCode(err))
	}
	if !bytes.Contains(generation.DecodedJSON(), []byte(`"u":[`)) {
		t.Fatalf("DecodedJSON() = %q, want a u step", generation.DecodedJSON())
	}
}
