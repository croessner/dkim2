package recipe

import (
	"math"
	"strconv"
	"strings"
	"testing"
)

// TestParserAdditionalDraftAndRFC8259Vectors locks whitespace, unicode, collision, and case rules.
func TestParserAdditionalDraftAndRFC8259Vectors(t *testing.T) {
	parser := mustParser(t, Limits{})
	valid := []string{
		" \t\r\n{\"b\":null}\n",
		`{"b":[{"d":["\ufffd\uffff\ufdd0","�","\ud83d\ude00"]}]}`,
		`{"b":[{"c":[1e000000000,1000e-000000003]}]}`,
		`{"b":[{"c":[` + strconv.Itoa(math.MaxInt) + `,` + strconv.Itoa(math.MaxInt) + `]}]}`,
	}
	for _, input := range valid {
		if recipe, usage, err := parser.Parse([]byte(input)); err != nil || !recipe.Valid() || !usage.Valid() {
			t.Fatalf("valid vector rejected: input_bytes=%d recipe_valid=%t usage_valid=%t code=%s", len(input), recipe.Valid(), usage.Valid(), recipeTestErrorCode(err))
		}
	}
	tests := []struct {
		name, input string
		code        ErrorCode
	}{
		{"uppercase dimensions", `{"H":{},"B":null}`, ErrorCodeMissingRecipeDimension},
		{"escaped header collision", `{"h":{"Subject":[],"\u0073ubject":[]}}`, ErrorCodeHeaderNameCollision},
		{"escaped step duplicate", `{"b":[{"c":[1,1],"\u0063":[2,2]}]}`, ErrorCodeDuplicateMember},
		{"escaped unknown duplicate", `{"x":{"y":1,"\u0079":2},"b":null}`, ErrorCodeDuplicateMember},
		{"recognized lone surrogate", `{"b":[{"d":["\ud800"]}]}`, ErrorCodeInvalidJSON},
		{"raw control", "{\"b\":[{\"d\":[\"bad\x01line\"]}]}", ErrorCodeInvalidJSON},
		{"data null", `{"b":[{"d":[null]}]}`, ErrorCodeInvalidLiteral},
		{"bom after whitespace", " \n\ufeff{\"b\":null}", ErrorCodeInvalidJSON},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recipe, usage, err := parser.Parse([]byte(test.input))
			if recipe.Valid() || !usage.Valid() || !IsErrorCode(err, test.code) {
				t.Fatalf("vector mismatch: recipe_valid=%t usage_valid=%t code=%s want=%s", recipe.Valid(), usage.Valid(), recipeTestErrorCode(err), test.code)
			}
		})
	}
}

// TestParserRejectsStrictNumberSyntaxAndMagnitude verifies bounded exact-number handling.
func TestParserRejectsStrictNumberSyntaxAndMagnitude(t *testing.T) {
	parser := mustParser(t, Limits{})
	for _, value := range []string{"01", "+1", ".1", "1.", "NaN", "Infinity"} {
		input := `{"b":[{"c":[` + value + `,2]}]}`
		if _, _, err := parser.Parse([]byte(input)); !IsErrorCode(err, ErrorCodeInvalidJSON) {
			t.Fatalf("number syntax mismatch: input_bytes=%d code=%s", len(input), recipeTestErrorCode(err))
		}
	}
	for _, value := range []string{"-0.0", "1e999999999999", "1e-999999999999", "9223372036854775808"} {
		input := `{"b":[{"c":[` + value + `,2]}]}`
		if _, _, err := parser.Parse([]byte(input)); !IsErrorCode(err, ErrorCodeInvalidCopyRange) {
			t.Fatalf("number magnitude mismatch: input_bytes=%d code=%s", len(input), recipeTestErrorCode(err))
		}
	}
}

// TestParserEveryOwnedLimitHasExactAndOneOverProof verifies independent parser budgets.
func TestParserEveryOwnedLimitHasExactAndOneOverProof(t *testing.T) {
	type limitCase struct {
		name, exact, over, limitName string
		configure                    func(*Limits)
	}
	cases := []limitCase{
		{"decoded", testBodyNullRecipe, testBodyNullRecipe + " ", limitNameMaxDecodedRecipeBytes, func(l *Limits) { l.MaxDecodedRecipeBytes = 10; l.MaxTotalLiteralBytes = 10; l.MaxDataStringBytes = 10 }},
		{"depth", `{"x":[],"b":null}`, `{"x":[[]],"b":null}`, limitNameMaxJSONDepth, func(l *Limits) { l.MaxJSONDepth = 2 }},
		{"members", `{"x":1,"b":null}`, `{"x":1,"y":2,"b":null}`, limitNameMaxJSONMembers, func(l *Limits) { l.MaxJSONMembers = 2 }},
		{testHeaderNamesLabel, testHeaderRemovalRecipe, testTwoHeaderRecipe, limitNameMaxHeaderNames, func(l *Limits) { l.MaxHeaderNames = 1 }},
		{testHeaderNameBytesLabel, testHeaderRemovalRecipe, `{"h":{"aa":[]}}`, limitNameMaxHeaderNameBytes, func(l *Limits) { l.MaxHeaderNameBytes = 1; l.MaxTotalHeaderNameBytes = 2 }},
		{"aggregate header names", testTwoHeaderRecipe, `{"h":{"a":[],"bb":[]}}`, limitNameMaxTotalHeaderNameBytes, func(l *Limits) { l.MaxHeaderNameBytes = 2; l.MaxTotalHeaderNameBytes = 2 }},
		{"header steps", testHeaderDataXRecipe, `{"h":{"a":[{"d":["x"]},{"d":["y"]}]}}`, limitNameMaxStepsPerHeader, func(l *Limits) { l.MaxStepsPerHeader = 1 }},
		{testBodyStepsLabel, testBodyDataXRecipe, `{"b":[{"d":["x"]},{"d":["y"]}]}`, limitNameMaxBodySteps, func(l *Limits) { l.MaxBodySteps = 1 }},
		{testTotalStepsLabel, `{"h":{"a":[{"d":["x"]}]},"b":[{"d":["y"]}]}`, `{"h":{"a":[{"d":["x"]},{"d":["z"]}]},"b":[{"d":["y"]}]}`, limitNameMaxTotalSteps, func(l *Limits) { l.MaxTotalSteps = 2; l.MaxStepsPerHeader = 2; l.MaxBodySteps = 2 }},
		{"ranges", `{"b":[{"c":[1,1]}]}`, testTwoRangesRecipe, limitNameMaxCopyRanges, func(l *Limits) { l.MaxCopyRanges = 1 }},
		{"range width", `{"b":[{"c":[1,2]}]}`, `{"b":[{"c":[1,3]}]}`, limitNameMaxCopiedItemsPerRange, func(l *Limits) { l.MaxCopiedItemsPerRange = 2; l.MaxTotalCopiedItems = 4 }},
		{"total copy width", testTwoRangesRecipe, `{"b":[{"c":[1,1]},{"c":[2,3]}]}`, limitNameMaxTotalCopiedItems, func(l *Limits) { l.MaxCopiedItemsPerRange = 2; l.MaxTotalCopiedItems = 2 }},
		{"strings", `{"b":[{"d":["a","b"]}]}`, `{"b":[{"d":["a","b","c"]}]}`, limitNameMaxDataStrings, func(l *Limits) { l.MaxDataStrings = 2 }},
		{"string bytes", `{"x":"ab","b":null}`, `{"x":"abc","b":null}`, limitNameMaxDataStringBytes, func(l *Limits) { l.MaxDataStringBytes = 2; l.MaxTotalLiteralBytes = 4 }},
		{testLiteralBytesLabel, `{"x":"a","y":"bc","b":null}`, `{"x":"ab","y":"bc","b":null}`, limitNameMaxTotalLiteralBytes, func(l *Limits) { l.MaxDataStringBytes = 2; l.MaxTotalLiteralBytes = 3 }},
		{"body line", `{"b":[{"d":["ab"]}]}`, `{"b":[{"d":["abc"]}]}`, limitNameMaxBodyLineBytes, func(l *Limits) { l.MaxBodyLineBytes = 2 }},
		{"header line", `{"h":{"a":[{"d":[""]}]}}`, `{"h":{"aa":[{"d":[""]}]}}`, limitNameMaxHeaderLineBytes, func(l *Limits) { l.MaxHeaderNameBytes = 2; l.MaxTotalHeaderNameBytes = 8; l.MaxHeaderLineBytes = 2 }},
		{"header field", `{"h":{"a":[{"d":[""]}]}}`, testHeaderDataXRecipe, limitNameMaxHeaderFieldBytes, func(l *Limits) { l.MaxHeaderFieldBytes = 4; l.MaxHeaderLineBytes = 8 }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			limits := DefaultLimits()
			test.configure(&limits)
			parser := mustParser(t, limits)
			if recipe, usage, err := parser.Parse([]byte(test.exact)); err != nil || !recipe.Valid() || !usage.Valid() {
				t.Fatalf("exact limit rejected: recipe_valid=%t usage_valid=%t code=%s", recipe.Valid(), usage.Valid(), recipeTestErrorCode(err))
			}
			_, usage, err := parser.Parse([]byte(test.over))
			if !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || err.(*Error).LimitName() != test.limitName {
				t.Fatalf("over limit mismatch: usage_valid=%t decoded=%d work=%d code=%s", usage.Valid(), usage.DecodedBytes(), usage.WorkUnits(), recipeTestErrorCode(err))
			}
		})
	}
	limits := DefaultLimits()
	limits.MaxJSONTokens = 5
	if _, _, err := mustParser(t, limits).Parse([]byte(testBodyNullRecipe)); err != nil {
		t.Fatalf("token exact=%v", err)
	}
	limits.MaxJSONTokens = 4
	if _, usage, err := mustParser(t, limits).Parse([]byte(testBodyNullRecipe)); !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || err.(*Error).LimitName() != limitNameMaxJSONTokens {
		t.Fatalf("token over mismatch: usage_valid=%t work=%d code=%s", usage.Valid(), usage.WorkUnits(), recipeTestErrorCode(err))
	}
	limits = DefaultLimits()
	limits.MaxOperationWorkUnits = 16
	if _, _, err := mustParser(t, limits).Parse([]byte(testBodyNullRecipe)); err != nil {
		t.Fatalf("work exact=%v", err)
	}
	limits.MaxOperationWorkUnits = 15
	if _, usage, err := mustParser(t, limits).Parse([]byte(testBodyNullRecipe)); !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || err.(*Error).LimitName() != limitNameMaxOperationWorkUnits {
		t.Fatalf("work over mismatch: usage_valid=%t work=%d code=%s", usage.Valid(), usage.WorkUnits(), recipeTestErrorCode(err))
	}
}

// TestParserFailureUsageCoversSyntaxSemanticAndLimitRejection verifies charged work survives failure.
func TestParserFailureUsageCoversSyntaxSemanticAndLimitRejection(t *testing.T) {
	parser := mustParser(t, Limits{})
	for _, input := range []string{"{", `{"b":[{"c":[0,1]}]}`, `{"b":[{"d":["secret_marker\n"]}]}`} {
		recipe, usage, err := parser.Parse([]byte(input))
		if recipe.Valid() || !usage.Valid() || err == nil || strings.Contains(err.Error(), "secret_marker") {
			t.Fatalf("failure accounting mismatch: input_bytes=%d recipe_valid=%t usage_valid=%t code=%s", len(input), recipe.Valid(), usage.Valid(), recipeTestErrorCode(err))
		}
	}
	limits := DefaultLimits()
	limits.MaxDecodedRecipeBytes = 9
	limits.MaxTotalLiteralBytes = 9
	limits.MaxDataStringBytes = 9
	recipe, usage, err := mustParser(t, limits).Parse([]byte(testBodyNullRecipe))
	if recipe.Valid() || !usage.Valid() || usage.DecodedBytes() != 0 || usage.WorkUnits() != 0 || !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("preflight mismatch: recipe_valid=%t usage_valid=%t decoded=%d work=%d code=%s", recipe.Valid(), usage.Valid(), usage.DecodedBytes(), usage.WorkUnits(), recipeTestErrorCode(err))
	}
}

// TestParserStringUsageCountsRecognizedAndIgnoredOnce locks the literal item category.
func TestParserStringUsageCountsRecognizedAndIgnoredOnce(t *testing.T) {
	parser := mustParser(t, Limits{})
	_, dataUsage, err := parser.Parse([]byte(`{"b":[{"d":["x"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	_, unknownUsage, err := parser.Parse([]byte(`{"x":"x","b":null}`))
	if err != nil {
		t.Fatal(err)
	}
	if dataUsage.Items() != 4 {
		t.Fatalf("data Items=%d, want members 2 + step 1 + literal 1", dataUsage.Items())
	}
	if unknownUsage.Items() != 3 {
		t.Fatalf("unknown Items=%d, want members 2 + literal 1", unknownUsage.Items())
	}
}

// TestParserChargesCanonicalHeaderPlanSorting verifies deterministic metadata and comparison work.
func TestParserChargesCanonicalHeaderPlanSorting(t *testing.T) {
	input := []byte(`{"h":{"c":[],"a":[],"b":[]}}`)
	recipe, usage, err := mustParser(t, Limits{}).Parse(input)
	if err != nil || !recipe.Valid() || !equalStrings(recipe.HeaderNames(), []string{"a", "b", "c"}) {
		t.Fatalf("sort result invalid: recipe_valid=%t names=%d code=%s", recipe.Valid(), len(recipe.HeaderNames()), recipeTestErrorCode(err))
	}
	limits := DefaultLimits()
	limits.MaxOperationWorkUnits = usage.WorkUnits()
	if _, _, err := mustParser(t, limits).Parse(input); err != nil {
		t.Fatalf("exact sort work rejected: code=%s", recipeTestErrorCode(err))
	}
	limits.MaxOperationWorkUnits--
	zero, failed, err := mustParser(t, limits).Parse(input)
	if zero.Valid() || !failed.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || err.(*Error).LimitName() != limitNameMaxOperationWorkUnits {
		t.Fatalf("sort work over mismatch: recipe_valid=%t usage_valid=%t work=%d code=%s", zero.Valid(), failed.Valid(), failed.WorkUnits(), recipeTestErrorCode(err))
	}
}

// TestParserRejectsStringAndHeaderNameBombsAtNarrowIncrementalLimits verifies pre-allocation ceilings.
func TestParserRejectsStringAndHeaderNameBombsAtNarrowIncrementalLimits(t *testing.T) {
	tests := []struct {
		name, input, limitName string
		configure              func(*Limits)
	}{
		{"ignored string", `{"x":"` + strings.Repeat("s", 4096) + `","b":null}`, limitNameMaxDataStringBytes, func(l *Limits) { l.MaxDataStringBytes = 8; l.MaxTotalLiteralBytes = 16 }},
		{"header name", `{"h":{"` + strings.Repeat("h", 4096) + `":[]}}`, limitNameMaxHeaderNameBytes, func(l *Limits) { l.MaxHeaderNameBytes = 8; l.MaxTotalHeaderNameBytes = 16 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := DefaultLimits()
			test.configure(&limits)
			zero, usage, err := mustParser(t, limits).Parse([]byte(test.input))
			if zero.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || err.(*Error).LimitName() != test.limitName {
				t.Fatalf("bomb mismatch: bytes=%d recipe_valid=%t usage_valid=%t code=%s", len(test.input), zero.Valid(), usage.Valid(), recipeTestErrorCode(err))
			}
		})
	}
}
