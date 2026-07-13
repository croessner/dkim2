package recipe

import (
	"reflect"
	"strings"
	"testing"
)

// FuzzParseRecipe exercises bounded duplicate-aware parsing without accepting incoherent outputs.
func FuzzParseRecipe(f *testing.F) {
	dataBomb := `{"b":[{"d":[` + strings.Repeat(`"",`, 4096) + `""]}]}`
	deepIgnored := `{"ignored":` + strings.Repeat(`[`, 17) + `0` + strings.Repeat(`]`, 17) + `,"b":null}`
	for _, seed := range [][]byte{
		[]byte(testBodyNullRecipe), []byte(`{"h":{"Subject":[]}}`),
		[]byte(`{"b":[{"c":[1e0,2.0]},{"d":["line"]}]}`),
		[]byte(`{"x":{"x":1,"x":2},"b":null}`),
		[]byte(`{"h":{"Subject":[],"subject":[]}}`),
		[]byte(`{"b":[{"c":[1e999999999999,2]}]}`),
		[]byte(deepIgnored),
		[]byte(dataBomb),
		[]byte("{\"b\":[{\"d\":[\"line\\nmarker\"]}]}"),
		[]byte(`{"h":null}`), []byte(`{"b":[null]}`), []byte(`null`),
		[]byte(`{"b":[{"z":true}]}`),
		[]byte(`{"b":[{"c":[1,999999]}]}`),
		{0xff},
	} {
		f.Add(seed)
	}
	parser, err := NewParser(Limits{})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 16<<10 {
			t.Skip()
		}
		first, firstUsage, firstErr := parser.Parse(input)
		second, secondUsage, secondErr := parser.Parse(input)
		assertParserFuzzContract(t, first, firstUsage, firstErr)
		assertParserFuzzContract(t, second, secondUsage, secondErr)
		if recipeTestErrorCode(firstErr) != recipeTestErrorCode(secondErr) || firstUsage != secondUsage || !reflect.DeepEqual(first, second) {
			t.Fatal("recipe parsing is not deterministic")
		}
		snapshot := cloneRecipeForFuzz(first)
		for index := range input {
			input[index] ^= 0xff
		}
		if !reflect.DeepEqual(first, snapshot) {
			t.Fatal("parsed recipe retained caller storage")
		}
	})
}

// assertParserFuzzContract verifies deterministic typed and bounded parse outcomes.
func assertParserFuzzContract(t *testing.T, plan Recipe, usage Usage, err error) {
	t.Helper()
	if !usage.Valid() {
		t.Fatal("Parse returned invalid Usage")
	}
	if err != nil {
		if plan.Valid() || !recipeTestErrorCode(err).Known() || len(err.Error()) > 512 {
			t.Fatal("Parse returned an incoherent or unbounded failure")
		}
		return
	}
	if !plan.Valid() {
		t.Fatal("Parse returned invalid Recipe without error")
	}
}

// cloneRecipeForFuzz takes a semantic deep snapshot before caller-buffer mutation.
func cloneRecipeForFuzz(plan Recipe) Recipe {
	if !plan.Valid() {
		return Recipe{}
	}
	return Recipe{
		headers:         plan.headerPlans(),
		hasHeaderRecipe: plan.hasHeaderRecipe,
		bodyMode:        plan.bodyMode,
		bodySteps:       cloneSteps(plan.bodySteps),
		initialized:     true,
	}
}
