package httpjson

import (
	"net/http"
	"testing"
)

// TestEvaluateStatusPreconditionsFreezesStrongWeakAndLazyOrder covers RFC evaluator order.
func TestEvaluateStatusPreconditionsFreezesStrongWeakAndLazyOrder(t *testing.T) {
	t.Parallel()
	const tag = `"0123456789abcdef"`
	cases := []struct {
		name    string
		match   []string
		none    []string
		outcome preconditionOutcome
	}{
		{name: transportTestAbsent, outcome: preconditionProceed},
		{name: "match star", match: []string{"*"}, outcome: preconditionProceed},
		{name: "match strong", match: []string{`"other", "0123456789abcdef"`}, outcome: preconditionProceed},
		{name: "match weak fails", match: []string{testWeakEntityTag}, outcome: preconditionFailed},
		{name: "match empty fails", match: []string{", ,"}, outcome: preconditionFailed},
		{name: "none strong", none: []string{tag}, outcome: preconditionNotModified},
		{name: "none weak", none: []string{testWeakEntityTag}, outcome: preconditionNotModified},
		{name: "none empty proceeds", none: []string{",,"}, outcome: preconditionProceed},
		{name: testMultipleFieldsName, none: []string{`"other"`, testWeakEntityTag}, outcome: preconditionNotModified},
		{name: "literal backslash", none: []string{`"literal\\tag"`}, outcome: preconditionProceed},
		{name: "comma in opaque", none: []string{`"a,b", "other"`}, outcome: preconditionProceed},
		{name: "empty opaque", none: []string{`""`}, outcome: preconditionProceed},
		{name: "asterisk in opaque none", none: []string{`"a*b"`}, outcome: preconditionProceed},
		{name: "asterisk in opaque match", match: []string{`"a*b"`}, outcome: preconditionFailed},
		{name: "mixed star", none: []string{`*, "other"`}, outcome: preconditionInvalid},
		{name: "leading empty star", none: []string{`, *`}, outcome: preconditionInvalid},
		{name: "trailing empty star", none: []string{`*,`}, outcome: preconditionInvalid},
		{name: "multiple field empty star", none: []string{`,`, `*`}, outcome: preconditionInvalid},
		{name: transportTestMalformed, none: []string{`W/"unterminated`}, outcome: preconditionInvalid},
		{name: "if-match precedence", match: []string{`"other"`}, none: []string{`W/"unterminated`}, outcome: preconditionFailed},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			header := make(http.Header)
			for _, value := range testCase.match {
				header.Add("If-Match", value)
			}
			for _, value := range testCase.none {
				header.Add("If-None-Match", value)
			}
			if result := evaluateStatusPreconditions(header, tag); result != testCase.outcome {
				t.Fatalf("evaluateStatusPreconditions() = %v, want %v", result, testCase.outcome)
			}
		})
	}
}

// TestMatchEntityTagListAcceptsObsTextAndRejectsControls covers byte-oriented opaque tags.
func TestMatchEntityTagListAcceptsObsTextAndRejectsControls(t *testing.T) {
	t.Parallel()
	selected := string([]byte{'"', 0x80, 0xff, '"'})
	if matched, valid := matchEntityTagList([]string{selected}, selected, false); !valid || !matched {
		t.Fatal("obs-text tag did not weakly match")
	}
	for _, value := range []string{"\"\x00\"", "\"\x1f\"", "\" \"", "\"\x7f\""} {
		if _, valid := matchEntityTagList([]string{value}, selected, false); valid {
			t.Fatalf("control-bearing entity tag %q was accepted", value)
		}
	}
}
