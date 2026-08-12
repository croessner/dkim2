package recipe

import (
	"bytes"
	"math"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// TestRecipeAbuseBombsFailBeforeProducingPartialState covers ignored, depth, range, and literal expansion attacks.
func TestRecipeAbuseBombsFailBeforeProducingPartialState(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		configure func(*Limits)
		limit     string
	}{
		{
			name:  "huge ignored extension",
			input: `{"ignored":["` + strings.Repeat("x", 4096) + `"],"b":null}`,
			configure: func(l *Limits) {
				l.MaxDataStringBytes = 32
				l.MaxTotalLiteralBytes = 64
			},
			limit: limitNameMaxDataStringBytes,
		},
		{
			name:  "deep ignored extension",
			input: `{"ignored":[[[[[]]]]],"b":null}`,
			configure: func(l *Limits) {
				l.MaxJSONDepth = 4
			},
			limit: limitNameMaxJSONDepth,
		},
		{
			name:  "many ignored members",
			input: `{"a":1,"b":null,"c":2,"d":3}`,
			configure: func(l *Limits) {
				l.MaxJSONMembers = 3
			},
			limit: limitNameMaxJSONMembers,
		},
		{
			name:  "copy expansion bomb",
			input: `{"b":[{"c":[1,5]}]}`,
			configure: func(l *Limits) {
				l.MaxCopiedItemsPerRange = 4
				l.MaxTotalCopiedItems = 4
			},
			limit: limitNameMaxCopiedItemsPerRange,
		},
		{
			name:  "literal item bomb",
			input: `{"b":[{"d":["a","b","c","d"]}]}`,
			configure: func(l *Limits) {
				l.MaxDataStrings = 3
			},
			limit: limitNameMaxDataStrings,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := DefaultLimits()
			test.configure(&limits)
			plan, usage, err := mustParser(t, limits).Parse([]byte(test.input))
			if plan.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != test.limit {
				t.Fatalf("bomb contract mismatch: code=%s limit=%s", recipeTestErrorCode(err), recipeTestLimitName(err))
			}
		})
	}
}

// TestRecipeArithmeticEdgesStayChecked verifies boundary helpers and maximal exact range arithmetic.
func TestRecipeArithmeticEdgesStayChecked(t *testing.T) {
	if value, ok := checkedAdd(math.MaxInt-1, 1); !ok || value != math.MaxInt {
		t.Fatal("exact checked addition failed")
	}
	if _, ok := checkedAdd(math.MaxInt, 1); ok {
		t.Fatal("overflowing checked addition succeeded")
	}
	if _, ok := checkedAdd(-1, 1); ok {
		t.Fatal("negative checked addition succeeded")
	}
	value, ok := exactPositiveInt("9223372036854775807")
	if strconv.IntSize == 64 && (!ok || value != math.MaxInt) {
		t.Fatal("maximal exact integer was not preserved")
	}
	if _, ok := exactPositiveInt("9223372036854775808"); ok {
		t.Fatal("overflowing integer was accepted")
	}
}

// TestConcurrentParserAndApplierReuseIsImmutable exercises shared value reuse under the race detector.
func TestConcurrentParserAndApplierReuseIsImmutable(t *testing.T) {
	const workers = 32
	input := []byte(`{"h":{"Subject":[{"c":[1,1]},{"d":["restored"]}]},"b":[{"d":["body"]}]}`)
	parser := mustParser(t, Limits{})
	plan, _, err := parser.Parse(input)
	if err != nil {
		t.Fatal("fixture parse failed")
	}
	current := mustRecipeState(t, []byte("Subject:current\r\n\r\ncurrent\r\n"))
	applier := mustApplier(t, Limits{})
	want, wantUsage, err := applier.Apply(current, plan)
	if err != nil {
		t.Fatal("fixture apply failed")
	}
	wantMessage, err := want.Materialize()
	if err != nil {
		t.Fatal("fixture materialization failed")
	}

	var wait sync.WaitGroup
	errors := make(chan string, workers)
	for range workers {
		wait.Go(func() {
			parsed, _, parseErr := parser.Parse(input)
			if parseErr != nil || !parsed.Valid() {
				errors <- "parse"
				return
			}
			state, usage, applyErr := applier.Apply(current, plan)
			if applyErr != nil || usage != wantUsage {
				errors <- "apply"
				return
			}
			message, materializeErr := state.Materialize()
			if materializeErr != nil || !bytes.Equal(message.RawBytes(), wantMessage.RawBytes()) {
				errors <- "result"
			}
		})
	}
	wait.Wait()
	close(errors)
	for failure := range errors {
		t.Fatalf("concurrent immutable reuse failed: %s", failure)
	}
}

// TestToxicRecipeMarkersStayOutOfAllFailureDiagnostics verifies parser and applier privacy together.
func TestToxicRecipeMarkersStayOutOfAllFailureDiagnostics(t *testing.T) {
	const marker = "TOXIC_RECIPE_SECRET_9f17"
	parser := mustParser(t, Limits{})
	for _, input := range []string{
		`{"` + marker + `":{"nested":"` + marker + `"}}`,
		`{"h":{"` + marker + ` bad":null}}`,
		`{"b":[{"d":["` + marker + `\n"]}]}`,
	} {
		_, _, err := parser.Parse([]byte(input))
		if err == nil || strings.Contains(err.Error(), marker) || len(err.Error()) > 512 {
			t.Fatalf("parser diagnostic privacy failed: code=%s", recipeTestErrorCode(err))
		}
	}
	current := mustRecipeState(t, []byte("A:"+marker+"\r\n\r\n"+marker+"\r\n"))
	plan := mustParseRecipe(t, `{"h":{"A":[{"c":[2,2]}]},"b":[{"c":[2,2]}]}`)
	_, usage, err := mustApplier(t, Limits{}).Apply(current, plan)
	if err == nil || !usage.Valid() || strings.Contains(err.Error(), marker) || len(err.Error()) > 512 {
		t.Fatalf("application diagnostic privacy failed: code=%s", recipeTestErrorCode(err))
	}
}
