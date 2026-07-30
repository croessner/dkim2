package recipe

import (
	"bytes"
	"strings"
	"testing"
)

const (
	testRecipeHeaderName         = "Subject"
	testBodyNullRecipe           = `{"b":null}`
	testBodyEmptyRecipe          = `{"b":[]}`
	testBodyDataXRecipe          = `{"b":[{"d":["x"]}]}`
	testBodyStepsLabel           = "body steps"
	testLiteralBytesLabel        = "literal bytes"
	testHeaderNamesLabel         = "header names"
	testStateBytesLabel          = "state bytes"
	testTotalStepsLabel          = "total steps"
	testCopyRangesLabel          = "copy ranges"
	testDataStringsLabel         = "data strings"
	testDataStringBytesLabel     = "data string bytes"
	testCopiedItemsPerRangeLabel = "copied items per range"
	testHeaderNameBytesLabel     = "header name bytes"
	testStepsPerHeaderLabel      = "steps per header"
	testHeaderRemovalRecipe      = `{"h":{"A":[]}}`
	testHeaderDataXRecipe        = `{"h":{"A":[{"d":["x"]}]}}`
	testHeaderDataXYRecipe       = `{"h":{"A":[{"d":["xy"]}]}}`
	testTwoHeaderRecipe          = `{"h":{"A":[],"B":[]}}`
	testTwoRangesRecipe          = `{"b":[{"c":[1,1]},{"c":[2,2]}]}`
)

// TestParserAcceptsDraftRecipeForms verifies the complete draft recipe schema surface.
func TestParserAcceptsDraftRecipeForms(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		headers    []string
		body       BodyMode
		bodySteps  int
		headerStep int
	}{
		{"header empty", `{"h":{"Subject":[]}}`, []string{testRecipeHeaderName}, BodyModeAbsent, 0, 0},
		{"header copy data", `{"h":{"Subject":[{"c":[1,2]},{"d":["", "restored"]}]}}`, []string{testRecipeHeaderName}, BodyModeAbsent, 0, 2},
		{"body empty", testBodyEmptyRecipe, nil, BodyModeSteps, 0, 0},
		{"body null", testBodyNullRecipe, nil, BodyModeUnavailable, 0, 0},
		{"combined", `{"h":{"X-Test":[{"d":["value"]}]},"b":[{"c":[1.0,2e0]}]}`, []string{"X-Test"}, BodyModeSteps, 1, 1},
		{"unknown root", `{"future":{"nested":[1,true,{"x":"y"}]},"b":null}`, nil, BodyModeUnavailable, 0, 0},
		{"unicode literal", `{"b":[{"d":["Gr\u00fc\u00dfe","\ud83d\ude00"]}]}`, nil, BodyModeSteps, 1, 0},
	}
	parser := mustParser(t, Limits{})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recipe, usage, err := parser.Parse([]byte(test.input))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if !recipe.Valid() || !usage.Valid() || usage.DecodedBytes() != len(test.input) || usage.EmittedBytes() != 0 {
				t.Fatalf("result invalid: recipe_valid=%t usage_valid=%t decoded=%d work=%d", recipe.Valid(), usage.Valid(), usage.DecodedBytes(), usage.WorkUnits())
			}
			if got := recipe.HeaderNames(); !equalStrings(got, test.headers) {
				t.Fatalf("HeaderNames count = %d, want %d", len(got), len(test.headers))
			}
			if recipe.BodyMode() != test.body {
				t.Fatalf("BodyMode() = %q, want %q", recipe.BodyMode(), test.body)
			}
			if len(recipe.bodySteps) != test.bodySteps {
				t.Fatalf("body steps = %d", len(recipe.bodySteps))
			}
			if len(test.headers) > 0 && len(recipe.headers[0].steps) != test.headerStep {
				t.Fatalf("header steps = %d", len(recipe.headers[0].steps))
			}
		})
	}
}

// TestParserRejectsDuplicateAndCollidingMembers verifies duplicate detection precedes projection.
func TestParserRejectsDuplicateAndCollidingMembers(t *testing.T) {
	tests := []struct {
		name, input string
		code        ErrorCode
	}{
		{"root", `{"b":null,"b":[]}`, ErrorCodeDuplicateMember},
		{"escaped root", `{"b":null,"\u0062":[]}`, ErrorCodeDuplicateMember},
		{"unknown root", `{"x":1,"x":2,"b":null}`, ErrorCodeDuplicateMember},
		{"header exact", `{"h":{"Subject":[],"Subject":[]}}`, ErrorCodeDuplicateMember},
		{"header case fold", `{"h":{"Subject":[],"subject":[]}}`, ErrorCodeHeaderNameCollision},
		{"step", `{"b":[{"c":[1,1],"c":[2,2]}]}`, ErrorCodeDuplicateMember},
		{"unknown nested", `{"x":{"y":1,"y":2},"b":null}`, ErrorCodeDuplicateMember},
	}
	parser := mustParser(t, Limits{})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recipe, usage, err := parser.Parse([]byte(test.input))
			if recipe.Valid() || !usage.Valid() || !IsErrorCode(err, test.code) {
				t.Fatalf("Parse failure mismatch: recipe_valid=%t usage_valid=%t code=%s want=%s", recipe.Valid(), usage.Valid(), recipeTestErrorCode(err), test.code)
			}
		})
	}
}

// TestParserRejectsSchemaAndSyntaxFailures verifies malformed states fail closed.
func TestParserRejectsSchemaAndSyntaxFailures(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		code  ErrorCode
	}{
		{"empty", nil, ErrorCodeInvalidJSON}, {"array root", []byte(`[]`), ErrorCodeInvalidTopLevel},
		{"no dimension", []byte(`{"x":1}`), ErrorCodeMissingRecipeDimension},
		{"empty h", []byte(`{"h":{}}`), ErrorCodeInvalidHeaderRecipe}, {"h null", []byte(`{"h":null}`), ErrorCodeInvalidHeaderRecipe},
		{"body scalar", []byte(`{"b":1}`), ErrorCodeInvalidBodyRecipe}, {"null header plan", []byte(`{"h":{"A":null}}`), ErrorCodeInvalidHeaderRecipe},
		{"null step", []byte(`{"b":[null]}`), ErrorCodeInvalidStep}, {"unknown step", []byte(`{"b":[{"z":[]}]}`), ErrorCodeInvalidStep},
		{"extra step", []byte(`{"b":[{"c":[1,1],"x":1}]}`), ErrorCodeInvalidStep}, {"mixed step", []byte(`{"b":[{"c":[1,1],"d":["x"]}]}`), ErrorCodeInvalidStep},
		{"copy arity", []byte(`{"b":[{"c":[1]}]}`), ErrorCodeInvalidCopyRange}, {"copy type", []byte(`{"b":[{"c":[1,"2"]}]}`), ErrorCodeInvalidCopyRange},
		{"data empty", []byte(`{"b":[{"d":[]}]}`), ErrorCodeInvalidLiteral}, {"data type", []byte(`{"b":[{"d":[1]}]}`), ErrorCodeInvalidLiteral},
		{"literal cr", []byte(`{"b":[{"d":["bad\rline"]}]}`), ErrorCodeInvalidLiteral}, {"literal lf", []byte(`{"b":[{"d":["bad\nline"]}]}`), ErrorCodeInvalidLiteral},
		{"bad name", []byte(`{"h":{"Bad Name":[]}}`), ErrorCodeInvalidHeaderName}, {"nonascii name", []byte(`{"h":{"Sübject":[]}}`), ErrorCodeInvalidHeaderName},
		{"bom", append([]byte{0xef, 0xbb, 0xbf}, []byte(testBodyNullRecipe)...), ErrorCodeInvalidJSON},
		{"trailing", []byte(`{"b":null} true`), ErrorCodeInvalidJSON}, {"multiple", []byte(`{"b":null}{}`), ErrorCodeInvalidJSON},
		{"invalid utf8", []byte{'{', '"', 'b', '"', ':', '"', 0xff, '"', '}'}, ErrorCodeInvalidJSON},
		{"unpaired high", []byte(`{"x":"\ud800","b":null}`), ErrorCodeInvalidJSON}, {"unpaired low", []byte(`{"x":"\udc00","b":null}`), ErrorCodeInvalidJSON},
	}
	parser := mustParser(t, Limits{})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recipe, usage, err := parser.Parse(test.input)
			if recipe.Valid() || !usage.Valid() || !IsErrorCode(err, test.code) {
				t.Fatalf("Parse failure mismatch: recipe_valid=%t usage_valid=%t code=%s want=%s", recipe.Valid(), usage.Valid(), recipeTestErrorCode(err), test.code)
			}
		})
	}
}

// TestParserAcceptsExactMathematicalIntegers verifies decimal and exponent forms without float conversion.
func TestParserAcceptsExactMathematicalIntegers(t *testing.T) {
	for _, input := range []string{
		`{"b":[{"c":[1.0,2e0]}]}`, `{"b":[{"c":[10e-1,20e-1]}]}`,
		`{"b":[{"c":[100e-2,3.000]}]}`,
	} {
		recipe, _, err := mustParser(t, Limits{}).Parse([]byte(input))
		if err != nil || !recipe.Valid() {
			t.Fatalf("valid integer rejected: input_bytes=%d recipe_valid=%t code=%s", len(input), recipe.Valid(), recipeTestErrorCode(err))
		}
	}
}

// TestParserRejectsInvalidMathematicalIntegersAndRanges verifies exact positive bounded coordinates.
func TestParserRejectsInvalidMathematicalIntegersAndRanges(t *testing.T) {
	tests := []struct {
		value string
		code  ErrorCode
	}{
		{"0", ErrorCodeInvalidCopyRange}, {"-0", ErrorCodeInvalidCopyRange}, {"-1", ErrorCodeInvalidCopyRange},
		{"1.5", ErrorCodeInvalidCopyRange}, {"1e-1", ErrorCodeInvalidCopyRange}, {"1e999999999999", ErrorCodeInvalidCopyRange},
		{"999999999999999999999999999", ErrorCodeInvalidCopyRange},
	}
	parser := mustParser(t, Limits{})
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			input := `{"b":[{"c":[` + test.value + `,2]}]}`
			_, _, err := parser.Parse([]byte(input))
			if !IsErrorCode(err, test.code) {
				t.Fatalf("invalid integer result: input_bytes=%d code=%s want=%s", len(input), recipeTestErrorCode(err), test.code)
			}
		})
	}
	for name, input := range map[string]string{
		"reversed": `{"b":[{"c":[2,1]}]}`, "overlap": `{"b":[{"c":[1,2]},{"d":["x"]},{"c":[2,3]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := parser.Parse([]byte(input))
			if err == nil {
				t.Fatal("expected range error")
			}
		})
	}
}

// TestParserEnforcesRepresentativeLimits verifies recognized and ignored structures share budgets.
func TestParserEnforcesRepresentativeLimits(t *testing.T) {
	tests := []struct {
		name, input string
		mutate      func(*Limits)
		limit       string
	}{
		{"depth", `{"x":{"y":{"z":1}},"b":null}`, func(l *Limits) { l.MaxJSONDepth = 2 }, limitNameMaxJSONDepth},
		{"members", `{"x":1,"b":null}`, func(l *Limits) { l.MaxJSONMembers = 1 }, limitNameMaxJSONMembers},
		{"tokens", testBodyNullRecipe, func(l *Limits) { l.MaxJSONTokens = 4 }, limitNameMaxJSONTokens},
		{testHeaderNamesLabel, testTwoHeaderRecipe, func(l *Limits) { l.MaxHeaderNames = 1 }, limitNameMaxHeaderNames},
		{"steps", `{"b":[{"d":["a"]},{"d":["b"]}]}`, func(l *Limits) { l.MaxBodySteps = 1; l.MaxTotalSteps = 1; l.MaxStepsPerHeader = 1 }, limitNameMaxBodySteps},
		{"ranges", testTwoRangesRecipe, func(l *Limits) { l.MaxCopyRanges = 1 }, limitNameMaxCopyRanges},
		{"strings", `{"b":[{"d":["a","b"]}]}`, func(l *Limits) { l.MaxDataStrings = 1 }, limitNameMaxDataStrings},
		{testLiteralBytesLabel, `{"b":[{"d":["ab"]}]}`, func(l *Limits) { l.MaxDataStringBytes = 1; l.MaxTotalLiteralBytes = 1 }, limitNameMaxDataStringBytes},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := DefaultLimits()
			test.mutate(&limits)
			parser := mustParser(t, limits)
			_, usage, err := parser.Parse([]byte(test.input))
			if !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || err.(*Error).LimitName() != test.limit {
				t.Fatalf("limit result: usage_valid=%t decoded=%d work=%d code=%s", usage.Valid(), usage.DecodedBytes(), usage.WorkUnits(), recipeTestErrorCode(err))
			}
		})
	}
}

// TestParserUsageChargesSuccessAndFailureExactly locks operation accounting.
func TestParserUsageChargesSuccessAndFailureExactly(t *testing.T) {
	parser := mustParser(t, Limits{})
	recipe, usage, err := parser.Parse([]byte(testBodyNullRecipe))
	if err != nil || !recipe.Valid() {
		t.Fatalf("Parse success invalid: recipe_valid=%t code=%s", recipe.Valid(), recipeTestErrorCode(err))
	}
	if usage.DecodedBytes() != 10 || usage.Items() != 1 || usage.WorkUnits() != 16 || usage.EmittedBytes() != 0 {
		t.Fatalf("success usage mismatch: decoded=%d items=%d work=%d", usage.DecodedBytes(), usage.Items(), usage.WorkUnits())
	}
	zero, failed, err := parser.Parse([]byte(`{"b":null,"b":[]}`))
	if zero.Valid() || !IsErrorCode(err, ErrorCodeDuplicateMember) {
		t.Fatalf("duplicate mismatch: recipe_valid=%t code=%s", zero.Valid(), recipeTestErrorCode(err))
	}
	if failed.DecodedBytes() != 17 || failed.Items() != 2 || failed.WorkUnits() != 25 {
		t.Fatalf("failure usage mismatch: decoded=%d items=%d work=%d", failed.DecodedBytes(), failed.Items(), failed.WorkUnits())
	}
}

// TestParserPreservesImmutabilityAndDiagnosticPrivacy verifies toxic JSON cannot escape parser ownership.
func TestParserPreservesImmutabilityAndDiagnosticPrivacy(t *testing.T) {
	input := []byte(`{"h":{"Subject":[{"d":["secret_marker"]}]}}`)
	recipe, _, err := mustParser(t, Limits{}).Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'
	values := recipe.headers[0].steps[0].dataValues()
	values[0][0] = 'X'
	if got := recipe.headers[0].steps[0].dataValues()[0]; !bytes.Equal(got, []byte("secret_marker")) {
		t.Fatalf("literal mutated: bytes=%d equal_expected=%t", len(got), bytes.Equal(got, []byte("secret_marker")))
	}
	_, _, err = mustParser(t, Limits{}).Parse([]byte(`{"h":{"secret_marker":null}}`))
	if err == nil || strings.Contains(err.Error(), "secret_marker") {
		t.Fatalf("diagnostic leaked: %v", err)
	}
}

// mustParser constructs one parser or fails the test.
func mustParser(t *testing.T, limits Limits) Parser {
	t.Helper()
	parser, err := NewParser(limits)
	if err != nil {
		t.Fatal(err)
	}
	return parser
}

// equalStrings compares deterministic metadata slices.
func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// recipeTestErrorCode returns only the closed code for secret-safe test diagnostics.
func recipeTestErrorCode(err error) ErrorCode {
	if typed, ok := err.(*Error); ok {
		return typed.Code()
	}
	return ""
}
