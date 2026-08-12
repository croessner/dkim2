package httpjson

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// TestJSONPreflightAcceptsExactRFC8259Text proves valid syntax and decoded constants.
func TestJSONPreflightAcceptsExactRFC8259Text(t *testing.T) {
	t.Parallel()

	input := []byte(" \r\n\t{" +
		`"api_\u0076ersion":"v\u0031",` +
		`"draft":"draft-ietf-dkim-dkim2-spec-04",` +
		`"unknown":[0,-0,1,-1,1.5,1e2,1E-2,true,false,null,"\uD834\uDD1E"]` +
		"} \t\r\n")
	constants, err := preflightJSON(input)
	if err != nil {
		t.Fatalf("preflightJSON() error = %v", err)
	}
	if constants.apiVersion != supportedAPIVersion || constants.draft != supportedDraftVersion {
		t.Fatalf("preflightJSON() constants = %#v", constants)
	}
}

// TestJSONPreflightRejectsMalformedTexts covers exact-one-text and scalar grammar.
func TestJSONPreflightRejectsMalformedTexts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: transportTestEmpty},
		{name: "whitespace", input: " \r\n\t"},
		{name: "two texts", input: validJSONPreflightDocument() + " null"},
		{name: "trailing byte", input: validJSONPreflightDocument() + " x"},
		{name: "unterminated object", input: `{"api_version":"v1"`},
		{name: "non-string name", input: `{1:"value"}`},
		{name: "raw control", input: "{\"api_version\":\"v1\",\"draft\":\"draft-ietf-dkim-dkim2-spec-04\",\"x\":\"\n\"}"},
		{name: "invalid escape", input: validJSONPreflightPrefix() + `"x":"\q"}`},
		{name: "leading zero", input: validJSONPreflightPrefix() + `"x":01}`},
		{name: "missing fraction", input: validJSONPreflightPrefix() + `"x":1.}`},
		{name: "missing exponent", input: validJSONPreflightPrefix() + `"x":1e}`},
		{name: "bare minus", input: validJSONPreflightPrefix() + `"x":-}`},
		{name: "trailing comma object", input: validJSONPreflightPrefix() + `"x":0,}`},
		{name: "trailing comma array", input: validJSONPreflightPrefix() + `"x":[0,]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertJSONPreflightCode(t, []byte(test.input), jsonPreflightInvalidJSON)
		})
	}
}

// TestJSONPreflightRejectsMalformedUTF8 proves replacement decoding is never used.
func TestJSONPreflightRejectsMalformedUTF8(t *testing.T) {
	t.Parallel()

	for _, input := range [][]byte{
		append([]byte(validJSONPreflightPrefix()+`"x":"`), 0xff, '"', '}'),
		append([]byte(validJSONPreflightPrefix()+`"`), 0xed, 0xa0, 0x80, '"', ':', '0', '}'),
	} {
		assertJSONPreflightCode(t, input, jsonPreflightInvalidJSON)
	}
}

// TestJSONPreflightValidatesSurrogatePairs covers scalar and member-name decoding.
func TestJSONPreflightValidatesSurrogatePairs(t *testing.T) {
	t.Parallel()

	valid := []string{
		validJSONPreflightPrefix() + `"x":"\uD834\uDD1E"}`,
		validJSONPreflightPrefix() + `"\uD83D\uDE00":0}`,
	}
	for _, input := range valid {
		if _, err := preflightJSON([]byte(input)); err != nil {
			t.Fatalf("valid surrogate input error = %v", err)
		}
	}

	invalid := []string{
		`\uD800`,
		`\uDC00`,
		`\uDC00\uD800`,
		`\uD800\uD800`,
		`\uD800\u0041`,
		`\uD800\u`,
		`\uD80G`,
	}
	for _, value := range invalid {
		input := validJSONPreflightPrefix() + `"x":"` + value + `"}`
		assertJSONPreflightCode(t, []byte(input), jsonPreflightInvalidJSON)
	}
}

// TestJSONPreflightRejectsDecodedDuplicateNames covers every object depth.
func TestJSONPreflightRejectsDecodedDuplicateNames(t *testing.T) {
	t.Parallel()

	tests := []string{
		`{"api_version":"v1","api_\u0076ersion":"v1","draft":"draft-ietf-dkim-dkim2-spec-04"}`,
		validJSONPreflightPrefix() + `"x":{"name":0,"na\u006de":1}}`,
		validJSONPreflightPrefix() + `"\uD83D\uDE00":0,"😀":1}`,
	}
	for _, input := range tests {
		assertJSONPreflightCode(t, []byte(input), jsonPreflightInvalidJSON)
	}
}

// TestJSONPreflightDepthBoundary proves root depth one and opening-container enforcement.
func TestJSONPreflightDepthBoundary(t *testing.T) {
	t.Parallel()

	exact := nestedJSONPreflightDocument(maxJSONDepth - 1)
	if _, err := preflightJSON([]byte(exact)); err != nil {
		t.Fatalf("depth %d error = %v", maxJSONDepth, err)
	}
	assertJSONPreflightCode(
		t,
		[]byte(nestedJSONPreflightDocument(maxJSONDepth)),
		jsonPreflightRequestTooLarge,
	)
}

// TestJSONPreflightTokenBoundary proves charge-before-accept at 8,192 tokens.
func TestJSONPreflightTokenBoundary(t *testing.T) {
	t.Parallel()

	exact := tokenBoundaryJSONPreflightDocument(false)
	if _, err := preflightJSON([]byte(exact)); err != nil {
		t.Fatalf("%d-token document error = %v", maxJSONTokens, err)
	}
	assertJSONPreflightCode(
		t,
		[]byte(tokenBoundaryJSONPreflightDocument(true)),
		jsonPreflightRequestTooLarge,
	)
}

// TestJSONPreflightMemberNameBoundary counts decoded UTF-8 bytes without normalization.
func TestJSONPreflightMemberNameBoundary(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		strings.Repeat("a", maxJSONMemberNameBytes),
		strings.Repeat("é", maxJSONMemberNameBytes/2),
	} {
		input := validJSONPreflightPrefix() + strconv.Quote(name) + `:0}`
		if _, err := preflightJSON([]byte(input)); err != nil {
			t.Fatalf("member name at %d decoded bytes error = %v", maxJSONMemberNameBytes, err)
		}
	}

	for _, name := range []string{
		strings.Repeat("a", maxJSONMemberNameBytes+1),
		strings.Repeat("é", maxJSONMemberNameBytes/2+1),
	} {
		input := validJSONPreflightPrefix() + strconv.Quote(name) + `:0}`
		assertJSONPreflightCode(t, []byte(input), jsonPreflightRequestTooLarge)
	}
}

// TestJSONPreflightConstantBoundaries proves resource caps precede comparisons.
func TestJSONPreflightConstantBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		api   string
		draft string
		code  jsonPreflightErrorCode
	}{
		{
			name:  "api exact wrong",
			api:   strings.Repeat("a", maxAPIVersionBytes),
			draft: supportedDraftVersion,
			code:  jsonPreflightUnsupportedVersion,
		},
		{
			name:  "api over",
			api:   strings.Repeat("a", maxAPIVersionBytes+1),
			draft: supportedDraftVersion,
			code:  jsonPreflightRequestTooLarge,
		},
		{
			name:  "draft exact wrong",
			api:   supportedAPIVersion,
			draft: strings.Repeat("d", maxDraftVersionBytes),
			code:  jsonPreflightUnsupportedDraft,
		},
		{
			name:  "draft over",
			api:   supportedAPIVersion,
			draft: strings.Repeat("d", maxDraftVersionBytes+1),
			code:  jsonPreflightRequestTooLarge,
		},
		{
			name:  "multibyte api over",
			api:   strings.Repeat("é", maxAPIVersionBytes/2+1),
			draft: supportedDraftVersion,
			code:  jsonPreflightRequestTooLarge,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := `{"api_version":` + strconv.Quote(test.api) +
				`,"draft":` + strconv.Quote(test.draft) + `}`
			assertJSONPreflightCode(t, []byte(input), test.code)
		})
	}
}

// TestJSONPreflightConstantClassification proves version-before-draft precedence.
func TestJSONPreflightConstantClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		code  jsonPreflightErrorCode
	}{
		{name: "root scalar", input: `null`, code: jsonPreflightInvalidContract},
		{name: "missing both", input: `{}`, code: jsonPreflightInvalidContract},
		{
			name:  "missing draft",
			input: `{"api_version":"v1"}`,
			code:  jsonPreflightInvalidContract,
		},
		{
			name:  "non-string api",
			input: `{"api_version":1,"draft":"draft-ietf-dkim-dkim2-spec-04"}`,
			code:  jsonPreflightInvalidContract,
		},
		{
			name:  "wrong api before missing draft",
			input: `{"api_version":"v2"}`,
			code:  jsonPreflightUnsupportedVersion,
		},
		{
			name:  "wrong api before wrong draft",
			input: `{"api_version":"v2","draft":"future"}`,
			code:  jsonPreflightUnsupportedVersion,
		},
		{
			name:  "wrong draft",
			input: `{"api_version":"v1","draft":"future"}`,
			code:  jsonPreflightUnsupportedDraft,
		},
		{
			name:  "non-string draft",
			input: `{"api_version":"v1","draft":false}`,
			code:  jsonPreflightInvalidContract,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertJSONPreflightCode(t, []byte(test.input), test.code)
		})
	}
}

// TestJSONPreflightVersionDominatesDraftLimitInEitherMemberOrder proves fixed extraction order.
func TestJSONPreflightVersionDominatesDraftLimitInEitherMemberOrder(t *testing.T) {
	t.Parallel()
	largeDraft := strconv.Quote(strings.Repeat("d", maxDraftVersionBytes+1))
	tests := []struct {
		name    string
		apiPart string
		code    jsonPreflightErrorCode
	}{
		{name: "wrong api", apiPart: `"api_version":"v2"`, code: jsonPreflightUnsupportedVersion},
		{name: "missing api", apiPart: `"other":0`, code: jsonPreflightInvalidContract},
		{name: "non-string api", apiPart: `"api_version":false`, code: jsonPreflightInvalidContract},
		{
			name:    "overlong api",
			apiPart: `"api_version":` + strconv.Quote(strings.Repeat("a", maxAPIVersionBytes+1)),
			code:    jsonPreflightRequestTooLarge,
		},
	}
	for _, test := range tests {
		for _, draftFirst := range []bool{false, true} {
			name := test.name + "/api_first"
			first, second := test.apiPart, `"draft":`+largeDraft
			if draftFirst {
				name = test.name + "/draft_first"
				first, second = second, first
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				assertJSONPreflightCode(t, []byte(`{`+first+`,`+second+`}`), test.code)
			})
		}
	}
}

// TestJSONPreflightExposesOnlyRawMessageTokenMetadata proves the bounded Base64 seam.
func TestJSONPreflightExposesOnlyRawMessageTokenMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		message     string
		wantRaw     string
		wantPresent bool
		wantString  bool
		wantEscaped bool
	}{
		{
			name:        "literal",
			message:     `{"raw_rfc5322_base64":"YQ=="}`,
			wantRaw:     "YQ==",
			wantPresent: true,
			wantString:  true,
		},
		{
			name:        "escaped spelling",
			message:     `{"raw_\u0072fc5322_base64":"YQ\u003d\u003d"}`,
			wantRaw:     `YQ\u003d\u003d`,
			wantPresent: true,
			wantString:  true,
			wantEscaped: true,
		},
		{
			name:        testWrongTypeName,
			message:     `{"raw_rfc5322_base64":null}`,
			wantPresent: true,
		},
		{
			name:    "nested lookalike ignored",
			message: `{"nested":{"raw_rfc5322_base64":"YQ=="}}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			input := []byte(validJSONPreflightPrefix() + `"message":` + test.message + `}`)
			constants, err := preflightJSON(input)
			if err != nil {
				t.Fatalf("preflightJSON() error = %v", err)
			}
			token := constants.rawMessage
			if token.present != test.wantPresent || token.stringValue != test.wantString ||
				token.escaped != test.wantEscaped {
				t.Fatalf("raw-message metadata = %#v", token)
			}
			if token.stringValue {
				if token.start < 0 || token.end < token.start || token.end > len(input) {
					t.Fatalf("raw-message bounds = [%d:%d]", token.start, token.end)
				}
				if got := string(input[token.start:token.end]); got != test.wantRaw {
					t.Fatalf("raw-message token = %q, want %q", got, test.wantRaw)
				}
			}
		})
	}
}

// TestJSONPreflightErrorsAreContentFree proves diagnostics retain no request spelling.
func TestJSONPreflightErrorsAreContentFree(t *testing.T) {
	t.Parallel()

	const marker = "DO-NOT-RETAIN-JSON-PREFLIGHT"
	input := []byte(`{"api_version":"` + marker + `"}`)
	_, err := preflightJSON(input)
	if err == nil {
		t.Fatal("preflightJSON() unexpectedly succeeded")
	}
	for index := range input {
		input[index] = 'x'
	}
	for _, output := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%#v", err)} {
		if strings.Contains(output, marker) {
			t.Fatal("error disclosed request-derived spelling")
		}
	}
}

// TestJSONPreflightUnknownEscapesDoNotAllocatePerEscape proves skipped values stay allocation-bounded.
func TestJSONPreflightUnknownEscapesDoNotAllocatePerEscape(t *testing.T) {
	small := []byte(validJSONPreflightPrefix() + `"x":"\u0061"}`)
	large := maximumEscapedUnknownJSONDocument()

	smallAllocations := testing.AllocsPerRun(1, func() {
		if _, err := preflightJSON(small); err != nil {
			panic(err)
		}
	})
	largeAllocations := testing.AllocsPerRun(1, func() {
		if _, err := preflightJSON(large); err != nil {
			panic(err)
		}
	})
	if largeAllocations > smallAllocations {
		t.Fatalf("unknown escape allocations grew from %.0f to %.0f", smallAllocations, largeAllocations)
	}
}

// FuzzJSONPreflight proves successful texts stay RFC 8259-valid with closed failures.
func FuzzJSONPreflight(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(validJSONPreflightDocument()),
		[]byte(validJSONPreflightPrefix() + `"x":"\uD834\uDD1E"}`),
		[]byte(`{"api_version":"v1","api_\u0076ersion":"v1"}`),
		{0xff},
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 64<<10 {
			return
		}
		constants, err := preflightJSON(input)
		if err == nil {
			if !json.Valid(input) || constants.apiVersion != supportedAPIVersion ||
				constants.draft != supportedDraftVersion {
				t.Fatal("successful preflight violated its lexical or constant invariant")
			}
			return
		}

		preflightErr, ok := err.(*jsonPreflightError)
		if !ok || preflightErr.Code() < jsonPreflightInvalidJSON ||
			preflightErr.Code() > jsonPreflightUnsupportedDraft {
			t.Fatalf("preflight returned an open failure: %#v", err)
		}
	})
}

// assertJSONPreflightCode requires one exact closed error classification.
func assertJSONPreflightCode(t testing.TB, input []byte, want jsonPreflightErrorCode) {
	t.Helper()

	_, err := preflightJSON(input)
	preflightErr, ok := err.(*jsonPreflightError)
	if !ok || preflightErr.Code() != want {
		t.Fatalf("preflightJSON() error = %#v, want code %d", err, want)
	}
}

// validJSONPreflightDocument returns one minimal supported root object.
func validJSONPreflightDocument() string {
	return `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04"}`
}

// validJSONPreflightPrefix returns supported constants followed by one member slot.
func validJSONPreflightPrefix() string {
	return `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04",`
}

// nestedJSONPreflightDocument builds a root object plus the requested array depth.
func nestedJSONPreflightDocument(arrayDepth int) string {
	var document strings.Builder
	document.WriteString(validJSONPreflightPrefix())
	document.WriteString(`"x":`)
	document.WriteString(strings.Repeat("[", arrayDepth))
	document.WriteString("null")
	document.WriteString(strings.Repeat("]", arrayDepth))
	document.WriteByte('}')

	return document.String()
}

// tokenBoundaryJSONPreflightDocument builds exactly 8,192 or 8,193 lexical tokens.
func tokenBoundaryJSONPreflightDocument(over bool) string {
	const zeroElements = 4_088

	var document strings.Builder
	document.WriteString(validJSONPreflightPrefix())
	document.WriteString(`"x":[[`)
	if over {
		document.WriteByte('0')
	}
	document.WriteByte(']')
	for range zeroElements {
		document.WriteString(",0")
	}
	document.WriteString("]}")

	return document.String()
}

// maximumEscapedUnknownJSONDocument fills the exact outer body cap with a skipped string.
func maximumEscapedUnknownJSONDocument() []byte {
	const maxProcessBodyBytes = 47_878_316

	prefix := validJSONPreflightPrefix() + `"x":"`
	const suffix = `"}`
	remaining := maxProcessBodyBytes - len(prefix) - len(suffix)

	var document strings.Builder
	document.Grow(maxProcessBodyBytes)
	document.WriteString(prefix)
	document.WriteString(strings.Repeat(`\u0061`, remaining/6))
	document.WriteString(strings.Repeat("a", remaining%6))
	document.WriteString(suffix)

	return []byte(document.String())
}
