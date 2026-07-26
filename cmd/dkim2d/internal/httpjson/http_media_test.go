package httpjson

import "testing"

// TestValidJSONContentTypeFreezesSemanticMediaParsing covers the RFC-semantic matrix.
func TestValidJSONContentTypeFreezesSemanticMediaParsing(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		values []string
		valid  bool
	}{
		{name: testExactName, values: []string{testContentTypeJSON}, valid: true},
		{name: testCaseName, values: []string{"Application/JSON"}, valid: true},
		{name: "token charset", values: []string{"application/json ; charset=UTF-8"}, valid: true},
		{name: "quoted charset", values: []string{"application/json;charset=\"utf-8\""}, valid: true},
		{name: "quoted pair", values: []string{"application/json;charset=\"utf\\-8\""}, valid: true},
		{name: "quoted pair tab", values: []string{"application/json;charset=\"utf\\\t-8\""}},
		{name: "quoted pair space", values: []string{"application/json;charset=\"utf\\ -8\""}, valid: false},
		{name: testEmptyParametersName, values: []string{"application/json;;; charset=utf-8;;"}, valid: true},
		{name: transportTestAbsent},
		{name: transportTestEmpty, values: []string{""}},
		{name: "multiple", values: []string{testContentTypeJSON, testContentTypeJSON}},
		{name: testCommaName, values: []string{"application/json, application/json"}},
		{name: testWrongTypeName, values: []string{"text/json"}},
		{name: "wrong charset", values: []string{"application/json;charset=latin1"}},
		{name: "duplicate charset", values: []string{"application/json;charset=utf-8;charset=utf-8"}},
		{name: "space before equals", values: []string{"application/json;charset =utf-8"}},
		{name: "space after equals", values: []string{"application/json;charset= utf-8"}},
		{name: "extended", values: []string{"application/json;charset*=utf-8"}},
		{name: "continuation", values: []string{"application/json;charset*0=utf-8"}},
		{name: "extra", values: []string{"application/json;foo=bar"}},
		{name: "unterminated", values: []string{"application/json;charset=\"utf-8"}},
		{name: "dangling escape", values: []string{"application/json;charset=\"utf-8\\\""}},
		{name: "escaped nul", values: []string{"application/json;charset=\"utf\\\x00-8\""}},
		{name: "escaped control", values: []string{"application/json;charset=\"utf\\\x1f-8\""}},
		{name: "missing value", values: []string{"application/json;charset="}},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if result := validJSONContentType(testCase.values); result != testCase.valid {
				t.Fatalf("validJSONContentType() = %v, want %v", result, testCase.valid)
			}
		})
	}
}
