package flatfile

import (
	"encoding/base64"
	"testing"

	"github.com/croessner/dkim2/internal/datasource"
)

// TestFlatFileNamedAbuseBombMatrixClosesEveryResourceAndReferenceClass
// records one explicit bounded oracle for each required abuse category.
func TestFlatFileNamedAbuseBombMatrixClosesEveryResourceAndReferenceClass(t *testing.T) {
	t.Parallel()

	validBytes := mustCompactFlatfileDocument(t)
	valid := string(validBytes)
	maxString, aggregate := flatfileStringAccounting(t, validBytes)
	const canonicalSPKI = "MCowBQYDK2VwAyEAIClZTFkgcVVuQpqSIcMJ98ohgPBzN3SrWTX3gbhSofw="
	tests := []struct {
		name      string
		document  []byte
		configure func(*datasource.Limits)
		code      datasource.ErrorCode
	}{
		{
			name: "file byte bomb", document: validBytes,
			configure: func(limits *datasource.Limits) {
				limits.MaxJSONFileBytes = len(validBytes) - 1
			},
			code: datasource.ErrorCodeLimitExceeded,
		},
		{
			name: "depth bomb", document: validBytes,
			configure: func(limits *datasource.Limits) { limits.MaxJSONDepth = 4 },
			code:      datasource.ErrorCodeLimitExceeded,
		},
		{
			name: "single string bomb", document: validBytes,
			configure: func(limits *datasource.Limits) {
				limits.MaxJSONStringBytes = maxString - 1
			},
			code: datasource.ErrorCodeLimitExceeded,
		},
		{
			name: "aggregate string bomb", document: validBytes,
			configure: func(limits *datasource.Limits) {
				limits.MaxDecodedStringBytes = aggregate - 1
			},
			code: datasource.ErrorCodeLimitExceeded,
		},
		{
			name: "record count bomb", document: validBytes,
			configure: func(limits *datasource.Limits) { limits.MaxRecords = 3 },
			code:      datasource.ErrorCodeLimitExceeded,
		},
		{
			name: "malformed base64",
			document: []byte(replaceFlatfileOnce(
				t,
				valid,
				canonicalSPKI,
				"***",
			)),
			code: datasource.ErrorCodeMalformedData,
		},
		{
			name: "malformed public SPKI",
			document: []byte(replaceFlatfileOnce(
				t,
				valid,
				canonicalSPKI,
				base64.StdEncoding.EncodeToString([]byte("not-spki")),
			)),
			code: datasource.ErrorCodeMalformedData,
		},
		{
			name: "duplicate decoded name",
			document: []byte(replaceFlatfileOnce(
				t,
				valid,
				`{"version":`,
				`{"version":"dkim2-datasource-v1","version":`,
			)),
			code: datasource.ErrorCodeMalformedData,
		},
		{
			name: "duplicate record identity",
			document: duplicateFlatfileCollectionEntry(
				t,
				validBytes,
				flatfileHandlesCollection,
			),
			code: datasource.ErrorCodeAmbiguous,
		},
		{
			name: "dangling handle binding",
			document: []byte(replaceFlatfileOnce(
				t,
				valid,
				`"handle_id":"key.example.ed25519"`,
				`"handle_id":"key.missing"`,
			)),
			code: datasource.ErrorCodeMalformedData,
		},
		{
			name: "incompatible key algorithm",
			document: []byte(replaceFlatfileOnce(
				t,
				valid,
				`"algorithm":"ed25519-sha256"`,
				`"algorithm":"rsa-sha256"`,
			)),
			code: datasource.ErrorCodeMalformedData,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := datasource.DefaultLimits()
			if test.configure != nil {
				test.configure(&limits)
			}
			assertFlatfileDecodeError(t, test.document, limits, test.code)
		})
	}

	for _, component := range []string{
		"",
		".",
		"..",
		"/rooted",
		"parent/child",
		`parent\child`,
		"nul\x00component",
	} {
		if datasource.ErrorCodeOf(validateFilename(component)) !=
			datasource.ErrorCodeInvalidRequest {
			t.Fatal("path component abuse did not fail closed")
		}
	}
}
