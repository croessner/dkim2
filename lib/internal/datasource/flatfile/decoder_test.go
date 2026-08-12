package flatfile

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/datasource"
	"github.com/croessner/dkim2/internal/datasource/memory"
)

const flatfileTestGeneration uint64 = 71

const (
	flatfileHandlesCollection  = "handles"
	flatfileProfilesCollection = "profiles"
	flatfilePoliciesCollection = "policies"
	flatfileWindowEnd          = "2026-07-23T13:00:00Z"
)

var flatfileTestTime = time.Date(2026, time.July, 23, 12, 30, 0, 0, time.UTC)

// TestDecodeAcceptsCompleteVersionedDocuments verifies the durable and minimal v1 shapes.
func TestDecodeAcceptsCompleteVersionedDocuments(t *testing.T) {
	t.Parallel()

	complete := mustFlatfileDocument(t)
	minimal := []byte(`{"version":"dkim2-datasource-v1","handles":[],"profiles":[],"policies":[]}`)
	for _, document := range [][]byte{complete, minimal} {
		snapshot := mustDecodeSnapshot(t, document, datasource.DefaultLimits())
		if !snapshot.Valid() {
			t.Fatal("Decode(valid) produced an invalid snapshot")
		}
	}

	snapshot := mustDecodeSnapshot(t, complete, datasource.DefaultLimits())
	profileRequest := mustFlatfileProfileRequest(t)
	profile, err := snapshot.ResolveProfile(context.Background(), profileRequest)
	if err != nil || !profile.Valid() || profile.Generation() != flatfileTestGeneration {
		t.Fatalf("ResolveProfile(valid) valid=%t generation=%d code=%s",
			profile.Valid(), profile.Generation(), datasource.ErrorCodeOf(err))
	}
	policyRequest := mustFlatfilePolicyRequest(t)
	policy, err := snapshot.ResolvePolicy(context.Background(), policyRequest)
	if err != nil || !policy.Valid() || policy.Generation() != flatfileTestGeneration ||
		policy.Profile().ID() != profile.ProfileID() {
		t.Fatalf("ResolvePolicy(valid) valid=%t generation=%d code=%s",
			policy.Valid(), policy.Generation(), datasource.ErrorCodeOf(err))
	}
}

// TestDecodeReaderMatchesByteDecode verifies equivalent pure reader and byte entry points.
func TestDecodeReaderMatchesByteDecode(t *testing.T) {
	t.Parallel()

	document := mustFlatfileDocument(t)
	fromBytes := mustDecodeSnapshot(t, document, datasource.DefaultLimits())
	fromReader, err := DecodeReader(
		flatfileTestGeneration, bytes.NewReader(document), datasource.DefaultLimits(),
	)
	if err != nil || fromReader == nil || !fromReader.Valid() {
		t.Fatalf("DecodeReader(valid) valid=%t code=%s",
			fromReader != nil && fromReader.Valid(), datasource.ErrorCodeOf(err))
	}
	bytesUsage, bytesErr := fromBytes.Usage()
	readerUsage, readerErr := fromReader.Usage()
	if bytesErr != nil || readerErr != nil || bytesUsage != readerUsage {
		t.Fatal("reader and byte decoder accounting differed")
	}

	bytesResult, bytesResolveErr := fromBytes.ResolvePolicy(
		context.Background(), mustFlatfilePolicyRequest(t),
	)
	readerResult, readerResolveErr := fromReader.ResolvePolicy(
		context.Background(), mustFlatfilePolicyRequest(t),
	)
	if bytesResolveErr != nil || readerResolveErr != nil ||
		bytesResult.Generation() != readerResult.Generation() ||
		bytesResult.Policy() != readerResult.Policy() ||
		bytesResult.Profile().ID() != readerResult.Profile().ID() {
		t.Fatal("reader and byte decoder results differed")
	}
}

// TestDecodeRejectsClosedSchemaViolations covers unknown, missing, null, and wrong-type facts.
func TestDecodeRejectsClosedSchemaViolations(t *testing.T) {
	t.Parallel()

	valid := string(mustCompactFlatfileDocument(t))
	tests := []struct {
		name     string
		document string
	}{
		{name: "root unknown", document: replaceFlatfileOnce(t, valid,
			`{"version":`, `{"unknown":"","version":`)},
		{name: "root missing version", document: replaceFlatfileOnce(t, valid,
			`"version":"dkim2-datasource-v1",`, ``)},
		{name: "root null handles", document: replaceFlatfileOnce(t, valid,
			`"handles":[`, `"handles":null,"discard":[`)},
		{name: "root wrong profiles type", document: replaceFlatfileOnce(t, valid,
			`"profiles":[`, `"profiles":{},"discard":[`)},
		{name: "handle unknown private key", document: replaceFlatfileOnce(t, valid,
			`{"id":"key.example.ed25519"}`, `{"id":"key.example.ed25519","private_key":"forbidden"}`)},
		{name: "handle missing id", document: replaceFlatfileOnce(t, valid,
			`{"id":"key.example.ed25519"}`, `{}`)},
		{name: "handle null id", document: replaceFlatfileOnce(t, valid,
			`"id":"key.example.ed25519"`, `"id":null`)},
		{name: "handle numeric id", document: replaceFlatfileOnce(t, valid,
			`"id":"key.example.ed25519"`, `"id":7`)},
		{name: "profile unknown", document: replaceFlatfileOnce(t, valid,
			`"status":"active","credentials"`, `"status":"active","key_path":"forbidden","credentials"`)},
		{name: "profile missing id", document: replaceFlatfileOnce(t, valid,
			`"id":"profile.example",`, ``)},
		{name: "profile null domain", document: replaceFlatfileOnce(t, valid,
			`"domain":"example.test","status"`, `"domain":null,"status"`)},
		{name: "profile wrong credentials type", document: replaceFlatfileOnce(t, valid,
			`"credentials":[{`, `"credentials":{"unexpected":`)},
		{name: "credential unknown", document: replaceFlatfileOnce(t, valid,
			`"handle_id":"key.example.ed25519"`, `"handle_id":"key.example.ed25519","password":"forbidden"`)},
		{name: "credential missing algorithm", document: replaceFlatfileOnce(t, valid,
			`"algorithm":"ed25519-sha256",`, ``)},
		{name: "credential null selector", document: replaceFlatfileOnce(t, valid,
			`"selector":"s1"`, `"selector":null`)},
		{name: "credential boolean public key", document: replaceFlatfileOnce(t, valid,
			`"public_key_spki":"MCowBQYDK2VwAyEAIClZTFkgcVVuQpqSIcMJ98ohgPBzN3SrWTX3gbhSofw="`,
			`"public_key_spki":true`)},
		{name: "policy unknown", document: replaceFlatfileOnce(t, valid,
			`"compatibility":"strict"`, `"compatibility":"strict","command":"forbidden"`)},
		{name: "policy missing tenant", document: replaceFlatfileOnce(t, valid,
			`"tenant_id":"tenant.example",`, ``)},
		{name: "policy null use", document: replaceFlatfileOnce(t, valid,
			`"use":"originator"`, `"use":null`)},
		{name: "policy numeric rollout", document: replaceFlatfileOnce(t, valid,
			`"rollout":"enforce"`, `"rollout":1`)},
		{name: "root array", document: `[]`},
		{name: "root string", document: `"dkim2-datasource-v1"`},
		{name: "trailing value", document: valid + `{}`},
		{name: "trailing comma", document: replaceFlatfileOnce(t, valid, `"policies":[`, `"policies":[,`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertFlatfileDecodeError(
				t, []byte(test.document), datasource.DefaultLimits(),
				datasource.ErrorCodeMalformedData,
			)
		})
	}
}

// TestDecodeRejectsDuplicateMembersAtEveryLevel verifies decoded-equivalent name uniqueness.
func TestDecodeRejectsDuplicateMembersAtEveryLevel(t *testing.T) {
	t.Parallel()

	valid := string(mustCompactFlatfileDocument(t))
	tests := []string{
		replaceFlatfileOnce(t, valid, `{"version":`,
			`{"version":"dkim2-datasource-v1","version":`),
		replaceFlatfileOnce(t, valid, `{"id":"key.example.ed25519"}`,
			`{"id":"key.example.ed25519","id":"key.example.ed25519"}`),
		replaceFlatfileOnce(t, valid, `"id":"profile.example","domain"`,
			`"id":"profile.example","id":"profile.example","domain"`),
		replaceFlatfileOnce(t, valid, `"algorithm":"ed25519-sha256","selector"`,
			`"algorithm":"ed25519-sha256","algorithm":"ed25519-sha256","selector"`),
		replaceFlatfileOnce(t, valid, `"tenant_id":"tenant.example","domain"`,
			`"tenant_id":"tenant.example","tenant_id":"tenant.example","domain"`),
		replaceFlatfileOnce(t, valid, `{"version":`,
			`{"version":"dkim2-datasource-v1","\\u0076ersion":`),
	}
	for _, document := range tests {
		assertFlatfileDecodeError(
			t, []byte(document), datasource.DefaultLimits(),
			datasource.ErrorCodeMalformedData,
		)
	}
}

// TestDecodeClassifiesDuplicateRecordsAsAmbiguous verifies identity and tuple collisions.
func TestDecodeClassifiesDuplicateRecordsAsAmbiguous(t *testing.T) {
	t.Parallel()

	for _, collection := range []string{
		flatfileHandlesCollection,
		flatfileProfilesCollection,
		flatfilePoliciesCollection,
	} {
		document := duplicateFlatfileCollectionEntry(t, mustFlatfileDocument(t), collection)
		assertFlatfileDecodeError(
			t, document, datasource.DefaultLimits(), datasource.ErrorCodeAmbiguous,
		)
	}
}

// TestDecodeRejectsDuplicateAndNoncanonicalCredentialOrder verifies profile-local collisions and ordering.
func TestDecodeRejectsDuplicateAndNoncanonicalCredentialOrder(t *testing.T) {
	t.Parallel()

	duplicate := flatfileDocumentWithSecondCredential(t, true, false)
	assertFlatfileDecodeError(
		t, duplicate, datasource.DefaultLimits(), datasource.ErrorCodeMalformedData,
	)
	reversed := flatfileDocumentWithSecondCredential(t, false, false)
	assertFlatfileDecodeError(
		t, reversed, datasource.DefaultLimits(), datasource.ErrorCodeMalformedData,
	)
	canonical := flatfileDocumentWithSecondCredential(t, false, true)
	canonicalText := string(canonical)
	for _, mutation := range [][2]string{
		{`"algorithm":"rsa-sha256"`, `"algorithm":"ed25519-sha256"`},
		{`"selector":"rsa1"`, `"selector":"s1"`},
		{`"handle_id":"key.example.rsa"`, `"handle_id":"key.example.ed25519"`},
	} {
		document := replaceFlatfileOnce(t, canonicalText, mutation[0], mutation[1])
		assertFlatfileDecodeError(
			t, []byte(document), datasource.DefaultLimits(),
			datasource.ErrorCodeMalformedData,
		)
	}
	snapshot := mustDecodeSnapshot(t, canonical, datasource.DefaultLimits())
	profile, err := snapshot.ResolveProfile(context.Background(), mustFlatfileProfileRequest(t))
	if err != nil || len(profile.Profile().Credentials()) != 2 ||
		profile.Profile().Credentials()[0].Algorithm() != datasource.AlgorithmRSASHA256 ||
		profile.Profile().Credentials()[1].Algorithm() != datasource.AlgorithmEd25519SHA256 {
		t.Fatalf("ResolveProfile(canonical dual) credentials=%d code=%s",
			len(profile.Profile().Credentials()), datasource.ErrorCodeOf(err))
	}
}

// TestDecodeRejectsMalformedEncodingAndSyntax covers UTF-8 and strict RFC 8259 failures.
func TestDecodeRejectsMalformedEncodingAndSyntax(t *testing.T) {
	t.Parallel()

	tests := [][]byte{
		nil,
		{},
		{0xff},
		append([]byte{0xef, 0xbb, 0xbf}, mustFlatfileDocument(t)...),
		[]byte(`{"version":"dkim2-datasource-v1","handles":[],"profiles":[],"policies":[]`),
		[]byte("{\"version\":\"dkim2-datasource-v1\",\"handles\":[],\"profiles\":[],\"policies\":[],\"x\":\"\xff\"}"),
		[]byte(`{"version":"dkim2-datasource-v1","handles":[],"profiles":[],"policies":[],"x":"\uD800"}`),
		[]byte(`{"version":"dkim2-datasource-v1","handles":[],"profiles":[],"policies":[],"x":"\uDC00"}`),
		[]byte(`{"version":"dkim2-datasource-v1","handles":[],"profiles":[],"policies":[],"x":"\uD800\u0041"}`),
	}
	for _, document := range tests {
		assertFlatfileDecodeError(
			t, document, datasource.DefaultLimits(), datasource.ErrorCodeMalformedData,
		)
	}
}

// TestScannerHandlesStrictUTF16Escapes proves paired escapes and decoded-name comparisons.
func TestScannerHandlesStrictUTF16Escapes(t *testing.T) {
	t.Parallel()

	limits := datasource.DefaultLimits()
	usage, err := scanDocument([]byte(`{"x":"\uD834\uDD1E"}`), limits)
	if err != nil || usage != len("x")+len("\U0001D11E") {
		t.Fatalf("scanDocument(valid pair) bytes=%d code=%s",
			usage, datasource.ErrorCodeOf(err))
	}
	for _, document := range [][]byte{
		[]byte(`{"x":"\uD834"}`),
		[]byte(`{"x":"\uDD1E"}`),
		[]byte(`{"x":"\uD834\u0041"}`),
		[]byte(`{"x":1,"\u0078":2}`),
	} {
		_, err := scanDocument(document, limits)
		if datasource.ErrorCodeOf(err) != datasource.ErrorCodeMalformedData {
			t.Fatalf("scanDocument(invalid escape) code=%s", datasource.ErrorCodeOf(err))
		}
	}
}

// TestScannerChargesArrayItemsBeforeSchemaDecode verifies local and aggregate array caps.
func TestScannerChargesArrayItemsBeforeSchemaDecode(t *testing.T) {
	t.Parallel()

	t.Run("aggregate scalar items", func(t *testing.T) {
		limits := datasource.DefaultLimits()
		limits.MaxRecords = 3
		if _, err := scanDocument([]byte(`[0,0,0]`), limits); err != nil {
			t.Fatalf("scanDocument(exact aggregate) code=%s", datasource.ErrorCodeOf(err))
		}
		if _, err := scanDocument([]byte(`[0,0,0,0]`), limits); datasource.ErrorCodeOf(err) != datasource.ErrorCodeLimitExceeded {
			t.Fatalf("scanDocument(aggregate one over) code=%s", datasource.ErrorCodeOf(err))
		}
	})

	t.Run("configured local array", func(t *testing.T) {
		limits := datasource.DefaultLimits()
		limits.MaxProfiles = 3
		limits.MaxCredentialsPerProfile = 1
		limits.MaxHandles = 3
		limits.MaxPolicies = 3
		limits.MaxRecords = 10
		if _, err := scanDocument([]byte(`[0,0,0]`), limits); err != nil {
			t.Fatalf("scanDocument(exact local) code=%s", datasource.ErrorCodeOf(err))
		}
		if _, err := scanDocument([]byte(`[0,0,0,0]`), limits); datasource.ErrorCodeOf(err) != datasource.ErrorCodeLimitExceeded {
			t.Fatalf("scanDocument(local one over) code=%s", datasource.ErrorCodeOf(err))
		}
	})

	t.Run("nested aggregate", func(t *testing.T) {
		limits := datasource.DefaultLimits()
		limits.MaxRecords = 5
		if _, err := scanDocument([]byte(`[[0,0],[0]]`), limits); err != nil {
			t.Fatalf("scanDocument(exact nested) code=%s", datasource.ErrorCodeOf(err))
		}
		limits.MaxRecords = 4
		if _, err := scanDocument([]byte(`[[0,0],[0]]`), limits); datasource.ErrorCodeOf(err) != datasource.ErrorCodeLimitExceeded {
			t.Fatalf("scanDocument(nested one over) code=%s", datasource.ErrorCodeOf(err))
		}
	})
}

// TestScannerEnforcesTheClosedObjectMemberCeiling verifies eight members are accepted and nine fail.
func TestScannerEnforcesTheClosedObjectMemberCeiling(t *testing.T) {
	t.Parallel()

	limits := datasource.DefaultLimits()
	if _, err := scanDocument([]byte(
		`{"a":0,"b":0,"c":0,"d":0,"e":0,"f":0,"g":0,"h":0}`,
	), limits); err != nil {
		t.Fatalf("scanDocument(eight members) code=%s", datasource.ErrorCodeOf(err))
	}
	if _, err := scanDocument([]byte(
		`{"a":0,"b":0,"c":0,"d":0,"e":0,"f":0,"g":0,"h":0,"i":0}`,
	), limits); datasource.ErrorCodeOf(err) != datasource.ErrorCodeMalformedData {
		t.Fatalf("scanDocument(nine members) code=%s", datasource.ErrorCodeOf(err))
	}
}

// TestDecodeAcceptsEscapedEquivalentSchemaNamesAndValues verifies semantic JSON string decoding.
func TestDecodeAcceptsEscapedEquivalentSchemaNamesAndValues(t *testing.T) {
	t.Parallel()

	document := string(mustCompactFlatfileDocument(t))
	document = replaceFlatfileOnce(t, document, `"version"`, `"\u0076ersion"`)
	document = replaceFlatfileOnce(t, document, `"profile.example"`, `"\u0070rofile.example"`)
	snapshot := mustDecodeSnapshot(t, []byte(document), datasource.DefaultLimits())
	if !snapshot.Valid() {
		t.Fatal("escaped-equivalent valid document produced an invalid snapshot")
	}
}

// TestDecodeRequiresCanonicalVersionEnumsAndIdentifiers verifies exact closed vocabularies.
func TestDecodeRequiresCanonicalVersionEnumsAndIdentifiers(t *testing.T) {
	t.Parallel()

	valid := string(mustCompactFlatfileDocument(t))
	replacements := [][2]string{
		{`dkim2-datasource-v1`, `DKIM2-datasource-v1`},
		{`ed25519-sha256`, `Ed25519-sha256`},
		{`"status":"active"`, `"status":"ACTIVE"`},
		{`originator`, `Originator`},
		{`enforce`, `ENFORCE`},
		{`strict`, `relaxed`},
		{`profile.example`, `Profile.example`},
		{`example.test`, `Example.test`},
		{`"selector":"s1"`, `"selector":"S1"`},
	}
	for _, replacement := range replacements {
		document := replaceFlatfileOnce(t, valid, replacement[0], replacement[1])
		assertFlatfileDecodeError(
			t, []byte(document), datasource.DefaultLimits(),
			datasource.ErrorCodeMalformedData,
		)
	}
}

// TestDecodeRequiresCanonicalPaddedSPKIBase64 verifies strict standard encoding and key semantics.
func TestDecodeRequiresCanonicalPaddedSPKIBase64(t *testing.T) {
	t.Parallel()

	const canonical = "MCowBQYDK2VwAyEAIClZTFkgcVVuQpqSIcMJ98ohgPBzN3SrWTX3gbhSofw="
	valid := string(mustCompactFlatfileDocument(t))
	der, err := base64.StdEncoding.DecodeString(canonical)
	if err != nil {
		t.Fatal("canonical public-key fixture could not be decoded")
	}
	tests := []string{
		strings.TrimSuffix(canonical, "="),
		canonical + "=",
		strings.Replace(canonical, "M", "_", 1),
		" " + canonical,
		canonical + "\n",
		base64.RawStdEncoding.EncodeToString(der),
		base64.StdEncoding.EncodeToString([]byte("not-spki")),
		strings.Replace(canonical, "M", `M\n`, 1),
		strings.Replace(canonical, "M", `M\r`, 1),
		canonical[:len(canonical)-2] + "x=",
		"",
	}
	for _, publicKey := range tests {
		document := replaceFlatfileOnce(t, valid, canonical, publicKey)
		assertFlatfileDecodeError(
			t, []byte(document), datasource.DefaultLimits(),
			datasource.ErrorCodeMalformedData,
		)
	}
	algorithmMismatch := replaceFlatfileOnce(t, valid, `"algorithm":"ed25519-sha256"`,
		`"algorithm":"rsa-sha256"`)
	assertFlatfileDecodeError(
		t, []byte(algorithmMismatch), datasource.DefaultLimits(),
		datasource.ErrorCodeMalformedData,
	)
}

// TestDecodeAcceptsOnlyValidOptionalFeedbackRouteIdentifiers verifies the optional policy reference.
func TestDecodeAcceptsOnlyValidOptionalFeedbackRouteIdentifiers(t *testing.T) {
	t.Parallel()

	valid := string(mustCompactFlatfileDocument(t))
	withFeedback := func(value string) string {
		t.Helper()
		return replaceFlatfileOnce(
			t, valid, `"compatibility":"strict"`,
			`"compatibility":"strict","feedback_route_id":"`+value+`"`,
		)
	}
	snapshot := mustDecodeSnapshot(
		t, []byte(withFeedback("feedback.example")), datasource.DefaultLimits(),
	)
	resolved, err := snapshot.ResolvePolicy(context.Background(), mustFlatfilePolicyRequest(t))
	feedback, present := resolved.Policy().FeedbackRouteID()
	if err != nil || !resolved.Valid() || !present || !feedback.Valid() {
		t.Fatalf("ResolvePolicy(feedback) valid=%t present=%t code=%s",
			resolved.Valid(), present, datasource.ErrorCodeOf(err))
	}
	for index, value := range []string{"", "Feedback.example", ".feedback"} {
		t.Run(fmt.Sprintf("invalid-%d", index), func(t *testing.T) {
			assertFlatfileDecodeError(
				t, []byte(withFeedback(value)), datasource.DefaultLimits(),
				datasource.ErrorCodeMalformedData,
			)
		})
	}
}

// TestDecodeRequiresCanonicalUTCValidityTimestamps verifies exact RFC3339Nano Z windows.
func TestDecodeRequiresCanonicalUTCValidityTimestamps(t *testing.T) {
	t.Parallel()

	valid := string(mustCompactFlatfileDocument(t))
	withWindow := func(notBefore, notAfter string) string {
		t.Helper()
		return replaceFlatfileOnce(
			t, valid, `"status":"active","credentials"`,
			`"status":"active","not_before":"`+notBefore+
				`","not_after":"`+notAfter+`","credentials"`,
		)
	}
	for _, pair := range [][2]string{
		{"2026-07-23T12:00:00Z", flatfileWindowEnd},
		{"2026-07-23T12:00:00.123456789Z", "2026-07-23T13:00:00.123456789Z"},
	} {
		mustDecodeSnapshot(t, []byte(withWindow(pair[0], pair[1])), datasource.DefaultLimits())
	}
	for _, pair := range [][2]string{
		{"2026-07-23T12:00:00+00:00", "2026-07-23T13:00:00+00:00"},
		{"2026-07-23T12:00:00.000Z", flatfileWindowEnd},
		{"2026-07-23t12:00:00Z", flatfileWindowEnd},
		{"2026-07-23T12:00:00z", flatfileWindowEnd},
		{"2026-07-23T13:00:00Z", "2026-07-23T12:00:00Z"},
		{"", flatfileWindowEnd},
	} {
		assertFlatfileDecodeError(
			t, []byte(withWindow(pair[0], pair[1])), datasource.DefaultLimits(),
			datasource.ErrorCodeMalformedData,
		)
	}
	onlyBefore := replaceFlatfileOnce(
		t, valid, `"status":"active","credentials"`,
		`"status":"active","not_before":"2026-07-23T12:00:00Z","credentials"`,
	)
	assertFlatfileDecodeError(
		t, []byte(onlyBefore), datasource.DefaultLimits(),
		datasource.ErrorCodeMalformedData,
	)
}

// TestDecodeRejectsDanglingAndInconsistentReferences verifies memory-provider validation reuse.
func TestDecodeRejectsDanglingAndInconsistentReferences(t *testing.T) {
	t.Parallel()

	valid := string(mustCompactFlatfileDocument(t))
	tests := []string{
		replaceFlatfileOnce(t, valid, `"handle_id":"key.example.ed25519"`,
			`"handle_id":"key.missing"`),
		replaceFlatfileOnce(t, valid, `"profile_id":"profile.example"`,
			`"profile_id":"profile.missing"`),
		replaceFlatfileOnce(t, valid, `"tenant_id":"tenant.example","domain":"example.test"`,
			`"tenant_id":"tenant.example","domain":"other.test"`),
	}
	for _, document := range tests {
		assertFlatfileDecodeError(
			t, []byte(document), datasource.DefaultLimits(),
			datasource.ErrorCodeMalformedData,
		)
	}
}

// TestDecodeEnforcesEveryStructuralAccountingCap verifies exact and one-over boundaries.
func TestDecodeEnforcesEveryStructuralAccountingCap(t *testing.T) {
	t.Parallel()

	document := mustFlatfileDocument(t)
	compact := mustCompactFlatfileDocument(t)
	decodedDER, err := base64.StdEncoding.DecodeString(
		"MCowBQYDK2VwAyEAIClZTFkgcVVuQpqSIcMJ98ohgPBzN3SrWTX3gbhSofw=",
	)
	if err != nil {
		t.Fatal("public-key fixture could not be decoded")
	}
	maxString, aggregate := flatfileStringAccounting(t, compact)
	exactCases := []func(*datasource.Limits){
		func(limits *datasource.Limits) { limits.MaxJSONFileBytes = len(document) },
		func(limits *datasource.Limits) { limits.MaxJSONDepth = 5 },
		func(limits *datasource.Limits) { limits.MaxJSONStringBytes = maxString },
		func(limits *datasource.Limits) { limits.MaxDecodedStringBytes = aggregate },
		func(limits *datasource.Limits) { limits.MaxDecodedPublicKeyBytes = len(decodedDER) },
		func(limits *datasource.Limits) { limits.MaxRecords = 4 },
	}
	for _, configure := range exactCases {
		limits := datasource.DefaultLimits()
		configure(&limits)
		mustDecodeSnapshot(t, document, limits)
	}

	oneOverCases := []struct {
		document  []byte
		configure func(*datasource.Limits)
	}{
		{document: append(bytes.Clone(document), ' '), configure: func(limits *datasource.Limits) {
			limits.MaxJSONFileBytes = len(document)
		}},
		{document: document, configure: func(limits *datasource.Limits) {
			limits.MaxJSONDepth = 4
		}},
		{document: document, configure: func(limits *datasource.Limits) {
			limits.MaxJSONStringBytes = maxString - 1
		}},
		{document: document, configure: func(limits *datasource.Limits) {
			limits.MaxDecodedStringBytes = aggregate - 1
		}},
		{document: document, configure: func(limits *datasource.Limits) {
			limits.MaxDecodedPublicKeyBytes = len(decodedDER) - 1
		}},
		{document: document, configure: func(limits *datasource.Limits) {
			limits.MaxRecords = 3
		}},
	}
	for _, test := range oneOverCases {
		limits := datasource.DefaultLimits()
		test.configure(&limits)
		assertFlatfileDecodeError(
			t, test.document, limits, datasource.ErrorCodeLimitExceeded,
		)
	}
}

// TestDecodeEnforcesSemanticCollectionCapsBeforePublication verifies exact and one-over arrays.
func TestDecodeEnforcesSemanticCollectionCapsBeforePublication(t *testing.T) {
	t.Parallel()

	valid := mustFlatfileDocument(t)
	exactCases := []func(*datasource.Limits){
		func(limits *datasource.Limits) { limits.MaxHandles = 1 },
		func(limits *datasource.Limits) { limits.MaxProfiles = 1 },
		func(limits *datasource.Limits) { limits.MaxPolicies = 1 },
		func(limits *datasource.Limits) { limits.MaxCredentialsPerProfile = 1 },
	}
	for _, configure := range exactCases {
		limits := datasource.DefaultLimits()
		configure(&limits)
		mustDecodeSnapshot(t, valid, limits)
	}

	for _, collection := range []string{
		flatfileHandlesCollection,
		flatfileProfilesCollection,
		flatfilePoliciesCollection,
	} {
		document := duplicateFlatfileCollectionEntry(t, valid, collection)
		limits := datasource.DefaultLimits()
		switch collection {
		case flatfileHandlesCollection:
			limits.MaxHandles = 1
		case flatfileProfilesCollection:
			limits.MaxProfiles = 1
		case flatfilePoliciesCollection:
			limits.MaxPolicies = 1
		}
		assertFlatfileDecodeError(
			t, document, limits, datasource.ErrorCodeLimitExceeded,
		)
	}
	credentialOneOver := flatfileDocumentWithSecondCredential(t, true, false)
	credentialLimits := datasource.DefaultLimits()
	credentialLimits.MaxCredentialsPerProfile = 1
	assertFlatfileDecodeError(
		t, credentialOneOver, credentialLimits, datasource.ErrorCodeLimitExceeded,
	)
}

// TestSnapshotUsageReportsExactIndependentParserAccounting verifies count and byte dimensions.
func TestSnapshotUsageReportsExactIndependentParserAccounting(t *testing.T) {
	t.Parallel()

	document := mustCompactFlatfileDocument(t)
	_, expectedBytes := flatfileStringAccounting(t, document)
	snapshot := mustDecodeSnapshot(t, document, datasource.DefaultLimits())
	usage, err := snapshot.Usage()
	if err != nil || usage.Profiles() != 1 || usage.Credentials() != 1 ||
		usage.Handles() != 1 || usage.Policies() != 1 || usage.Records() != 4 ||
		usage.Bytes() != expectedBytes || usage.Bytes() == usage.Records() {
		t.Fatalf("Usage() profiles=%d credentials=%d handles=%d policies=%d records=%d bytes=%d code=%s",
			usage.Profiles(), usage.Credentials(), usage.Handles(), usage.Policies(),
			usage.Records(), usage.Bytes(), datasource.ErrorCodeOf(err))
	}
}

// TestDecodeClassifiesInvalidConstructionInputs verifies caller input failures remain distinct.
func TestDecodeClassifiesInvalidConstructionInputs(t *testing.T) {
	t.Parallel()

	document := mustFlatfileDocument(t)
	invalidLimits := datasource.DefaultLimits()
	invalidLimits.MaxJSONDepth = 0
	for _, test := range []struct {
		generation uint64
		limits     datasource.Limits
	}{
		{generation: 0, limits: datasource.DefaultLimits()},
		{generation: flatfileTestGeneration, limits: invalidLimits},
	} {
		snapshot, err := Decode(test.generation, document, test.limits)
		if snapshot != nil || datasource.ErrorCodeOf(err) != datasource.ErrorCodeInvalidRequest {
			t.Fatalf("Decode(invalid construction) nonnil=%t code=%s",
				snapshot != nil, datasource.ErrorCodeOf(err))
		}
	}
}

// TestDecodeOwnsInputAndReturnsDeterministicDetachedResults proves immutable snapshot ownership.
func TestDecodeOwnsInputAndReturnsDeterministicDetachedResults(t *testing.T) {
	t.Parallel()

	document := mustFlatfileDocument(t)
	snapshot := mustDecodeSnapshot(t, document, datasource.DefaultLimits())
	for index := range document {
		document[index] = 0
	}
	request := mustFlatfileProfileRequest(t)
	first, firstErr := snapshot.ResolveProfile(context.Background(), request)
	if firstErr != nil {
		t.Fatalf("ResolveProfile(first) code=%s", datasource.ErrorCodeOf(firstErr))
	}
	firstDER := first.Profile().Credentials()[0].PublicKeySPKIDER()
	expected := bytes.Clone(firstDER)
	firstDER[0] ^= 0xff
	second, secondErr := snapshot.ResolveProfile(context.Background(), request)
	if secondErr != nil || !bytes.Equal(
		second.Profile().Credentials()[0].PublicKeySPKIDER(), expected,
	) || first.Generation() != second.Generation() {
		t.Fatalf("ResolveProfile(second) code=%s", datasource.ErrorCodeOf(secondErr))
	}
}

// TestDecodeReaderDefendsTheReaderBoundary verifies nil, partial-error, and panic handling.
func TestDecodeReaderDefendsTheReaderBoundary(t *testing.T) {
	t.Parallel()

	document := mustFlatfileDocument(t)
	var typedNil *flatfileNilReader
	tests := []struct {
		name   string
		reader io.Reader
		code   datasource.ErrorCode
	}{
		{name: "nil", reader: nil, code: datasource.ErrorCodeInvalidRequest},
		{name: "typed nil", reader: typedNil, code: datasource.ErrorCodeInvalidRequest},
		{name: "read failure", reader: &flatfileResultReader{err: io.ErrUnexpectedEOF},
			code: datasource.ErrorCodeUnavailable},
		{name: "bytes and failure", reader: &flatfileResultReader{data: document, err: io.ErrUnexpectedEOF},
			code: datasource.ErrorCodeUnavailable},
		{name: "panic", reader: flatfilePanicReader{}, code: datasource.ErrorCodeInternalInvariant},
		{name: "negative count", reader: flatfileInvalidCountReader{negative: true},
			code: datasource.ErrorCodeInternalInvariant},
		{name: "oversized count", reader: flatfileInvalidCountReader{},
			code: datasource.ErrorCodeInternalInvariant},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot, err := DecodeReader(flatfileTestGeneration, test.reader, datasource.DefaultLimits())
			if snapshot != nil || datasource.ErrorCodeOf(err) != test.code {
				t.Fatalf("DecodeReader(failure) nonnil=%t code=%s, want %s",
					snapshot != nil, datasource.ErrorCodeOf(err), test.code)
			}
		})
	}
	noProgress := &flatfileNoProgressReader{}
	snapshot, err := DecodeReader(
		flatfileTestGeneration, noProgress, datasource.DefaultLimits(),
	)
	if snapshot != nil || datasource.ErrorCodeOf(err) != datasource.ErrorCodeUnavailable ||
		noProgress.calls != maxConsecutiveEmptyReads {
		t.Fatalf("DecodeReader(no progress) nonnil=%t calls=%d code=%s",
			snapshot != nil, noProgress.calls, datasource.ErrorCodeOf(err))
	}
	delayed := &flatfileDelayedReader{emptyReads: maxConsecutiveEmptyReads - 1, data: document}
	snapshot, err = DecodeReader(
		flatfileTestGeneration, delayed, datasource.DefaultLimits(),
	)
	if err != nil || snapshot == nil || !snapshot.Valid() ||
		delayed.calls != maxConsecutiveEmptyReads {
		t.Fatalf("DecodeReader(delayed progress) valid=%t calls=%d code=%s",
			snapshot != nil && snapshot.Valid(), delayed.calls, datasource.ErrorCodeOf(err))
	}
	eofReader := &flatfileResultReader{data: document, err: io.EOF}
	snapshot, err = DecodeReader(flatfileTestGeneration, eofReader, datasource.DefaultLimits())
	if err != nil || snapshot == nil || !snapshot.Valid() {
		t.Fatalf("DecodeReader(bytes plus EOF) valid=%t code=%s",
			snapshot != nil && snapshot.Valid(), datasource.ErrorCodeOf(err))
	}
	limits := datasource.DefaultLimits()
	limits.MaxJSONFileBytes = len(document) - 1
	snapshot, err = DecodeReader(flatfileTestGeneration, bytes.NewReader(document), limits)
	if snapshot != nil || datasource.ErrorCodeOf(err) != datasource.ErrorCodeLimitExceeded {
		t.Fatalf("DecodeReader(file one over) nonnil=%t code=%s",
			snapshot != nil, datasource.ErrorCodeOf(err))
	}
}

// TestSnapshotZeroAndCorruptStateFailsClosed verifies wrapper invariants and context precedence.
func TestSnapshotZeroAndCorruptStateFailsClosed(t *testing.T) {
	t.Parallel()

	valid := mustDecodeSnapshot(t, mustFlatfileDocument(t), datasource.DefaultLimits())
	corrupt := []*Snapshot{nil, {}}
	incomplete := *valid
	incomplete.complete = false
	corrupt = append(corrupt, &incomplete)
	missingProvider := *valid
	missingProvider.provider = nil
	corrupt = append(corrupt, &missingProvider)
	wrongOwner := *valid
	wrongOwner.providerOwner = nil
	corrupt = append(corrupt, &wrongOwner)
	zeroUsage := *valid
	zeroUsage.usage = datasource.Usage{}
	corrupt = append(corrupt, &zeroUsage)
	zeroProviderUsage := *valid
	zeroProviderUsage.providerUsage = datasource.Usage{}
	corrupt = append(corrupt, &zeroProviderUsage)
	invalidLimits := *valid
	invalidLimits.limits = datasource.Limits{}
	corrupt = append(corrupt, &invalidLimits)
	wrongParserBytes := *valid
	wrongParserBytes.parserBytes++
	corrupt = append(corrupt, &wrongParserBytes)
	alteredUsage, alteredErr := datasource.NewUsage(
		valid.usage.Profiles(), valid.usage.Credentials(), valid.usage.Handles(),
		valid.usage.Policies(), valid.usage.Bytes()+1, valid.limits,
	)
	if alteredErr != nil {
		t.Fatal("corrupt parser-byte accounting fixture construction failed")
	}
	alteredAccounting := *valid
	alteredAccounting.usage = alteredUsage
	corrupt = append(corrupt, &alteredAccounting)
	emptyProvider, emptyErr := memory.New(
		flatfileTestGeneration, nil, nil, nil, datasource.DefaultLimits(),
	)
	if emptyErr != nil {
		t.Fatal("substituted provider fixture construction failed")
	}
	substituted := *valid
	substituted.provider = emptyProvider
	corrupt = append(corrupt, &substituted)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), flatfileTestTime.Add(-time.Hour))
	defer stop()
	var nilContext context.Context
	for _, snapshot := range corrupt {
		if snapshot != nil && snapshot.Valid() {
			t.Fatal("corrupt snapshot reported valid")
		}
		if usage, err := snapshot.Usage(); usage.Records() != 0 ||
			datasource.ErrorCodeOf(err) != datasource.ErrorCodeInternalInvariant {
			t.Fatalf("Usage(corrupt) records=%d code=%s",
				usage.Records(), datasource.ErrorCodeOf(err))
		}
		assertFlatfileProfileFailure(
			context.Background(), t, snapshot, datasource.ErrorCodeInternalInvariant,
		)
		assertFlatfilePolicyFailure(
			context.Background(), t, snapshot, datasource.ErrorCodeInternalInvariant,
		)
		assertFlatfileProfileFailure(nilContext, t, snapshot, datasource.ErrorCodeInvalidRequest)
		assertFlatfilePolicyFailure(nilContext, t, snapshot, datasource.ErrorCodeInvalidRequest)
		assertFlatfileProfileFailure(cancelled, t, snapshot, datasource.ErrorCodeCancelled)
		assertFlatfilePolicyFailure(cancelled, t, snapshot, datasource.ErrorCodeCancelled)
		assertFlatfileProfileFailure(expired, t, snapshot, datasource.ErrorCodeDeadlineExceeded)
		assertFlatfilePolicyFailure(expired, t, snapshot, datasource.ErrorCodeDeadlineExceeded)
	}
}

// TestSnapshotDefendsItsContextBoundary verifies nil, panic, and delegated cancellation handling.
func TestSnapshotDefendsItsContextBoundary(t *testing.T) {
	t.Parallel()

	snapshot := mustDecodeSnapshot(t, mustFlatfileDocument(t), datasource.DefaultLimits())
	var typedNil *flatfileNilContext
	assertFlatfileProfileFailure(typedNil, t, snapshot, datasource.ErrorCodeInvalidRequest)
	assertFlatfilePolicyFailure(typedNil, t, snapshot, datasource.ErrorCodeInvalidRequest)
	assertFlatfileProfileFailure(flatfilePanicContext{}, t, snapshot, datasource.ErrorCodeInternalInvariant)
	assertFlatfilePolicyFailure(flatfilePanicContext{}, t, snapshot, datasource.ErrorCodeInternalInvariant)

	for _, target := range []struct {
		err  error
		code datasource.ErrorCode
	}{
		{err: context.Canceled, code: datasource.ErrorCodeCancelled},
		{err: context.DeadlineExceeded, code: datasource.ErrorCodeDeadlineExceeded},
	} {
		profileContext := &flatfileTransitionContext{target: target.err}
		assertFlatfileProfileFailure(profileContext, t, snapshot, target.code)
		if profileContext.calls < 2 {
			t.Fatal("profile resolve did not recheck context at the delegated boundary")
		}
		policyContext := &flatfileTransitionContext{target: target.err}
		assertFlatfilePolicyFailure(policyContext, t, snapshot, target.code)
		if policyContext.calls < 2 {
			t.Fatal("policy resolve did not recheck context at the delegated boundary")
		}
	}
}

// TestSnapshotFormattingJSONAndErrorsRemainOpaque proves no decoded fact reaches diagnostics.
func TestSnapshotFormattingJSONAndErrorsRemainOpaque(t *testing.T) {
	t.Parallel()

	const marker = "flatfile-private-marker"
	document := bytes.ReplaceAll(mustFlatfileDocument(t), []byte("example"), []byte(marker))
	snapshot := mustDecodeSnapshot(t, document, datasource.DefaultLimits())
	for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
		rendered := fmt.Sprintf(format, snapshot)
		if strings.Contains(rendered, marker) || rendered != "flatfile.Snapshot{redacted}" {
			t.Fatal("snapshot formatting exposed a decoded fact")
		}
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || strings.Contains(string(encoded), marker) || string(encoded) != "{}" {
		t.Fatal("snapshot JSON exposed a decoded fact")
	}
	missingID, idErr := datasource.NewProfileID("profile.absent." + marker)
	if idErr != nil {
		t.Fatal("privacy test profile identifier construction failed")
	}
	request, requestErr := datasource.NewProfileRequest(
		missingID, datasource.ProfileUseOriginator, flatfileTestTime,
		datasource.DefaultLimits(),
	)
	if requestErr != nil {
		t.Fatal("privacy test profile request construction failed")
	}
	_, resolveErr := snapshot.ResolveProfile(context.Background(), request)
	if datasource.ErrorCodeOf(resolveErr) != datasource.ErrorCodeNotFound ||
		strings.Contains(resolveErr.Error(), marker) {
		t.Fatal("snapshot error exposed a decoded fact")
	}
}

// TestDurableFixtureContainsNoPrivateKeyShapedSchema verifies test data remains public-only.
func TestDurableFixtureContainsNoPrivateKeyShapedSchema(t *testing.T) {
	t.Parallel()

	document := strings.ToLower(string(mustFlatfileDocument(t)))
	for _, forbidden := range []string{
		"private_key", "private key", "password", "token", "callback",
		"key_path", "command", "begin private",
	} {
		if strings.Contains(document, forbidden) {
			t.Fatal("durable fixture contains a private-key-shaped field")
		}
	}
}

// mustFlatfileDocument reads a detached copy of the durable public-only fixture.
func mustFlatfileDocument(t *testing.T) []byte {
	t.Helper()
	document, err := os.ReadFile("testdata/valid-v1.json")
	if err != nil {
		t.Fatal("durable flat-file fixture could not be read")
	}
	return document
}

// mustCompactFlatfileDocument returns the durable fixture without insignificant whitespace.
func mustCompactFlatfileDocument(t *testing.T) []byte {
	t.Helper()
	var output bytes.Buffer
	if err := json.Compact(&output, mustFlatfileDocument(t)); err != nil {
		t.Fatal("durable flat-file fixture could not be compacted")
	}
	return output.Bytes()
}

// mustDecodeSnapshot decodes one document or fails without exposing document facts.
func mustDecodeSnapshot(
	t *testing.T,
	document []byte,
	limits datasource.Limits,
) *Snapshot {
	t.Helper()
	snapshot, err := Decode(flatfileTestGeneration, document, limits)
	if err != nil || snapshot == nil || !snapshot.Valid() {
		t.Fatalf("Decode(valid) nonnil=%t valid=%t code=%s",
			snapshot != nil, snapshot != nil && snapshot.Valid(), datasource.ErrorCodeOf(err))
	}
	return snapshot
}

// assertFlatfileDecodeError verifies one nil-snapshot typed decoder failure.
func assertFlatfileDecodeError(
	t *testing.T,
	document []byte,
	limits datasource.Limits,
	code datasource.ErrorCode,
) {
	t.Helper()
	snapshot, err := Decode(flatfileTestGeneration, document, limits)
	if snapshot != nil || datasource.ErrorCodeOf(err) != code {
		t.Fatalf("Decode(failure) nonnil=%t code=%s, want %s",
			snapshot != nil, datasource.ErrorCodeOf(err), code)
	}
}

// replaceFlatfileOnce applies one required deterministic fixture mutation.
func replaceFlatfileOnce(t *testing.T, input, old, replacement string) string {
	t.Helper()
	if !strings.Contains(input, old) {
		t.Fatal("flat-file fixture mutation target was absent")
	}
	return strings.Replace(input, old, replacement, 1)
}

// duplicateFlatfileCollectionEntry duplicates one valid record using test-only generic JSON.
func duplicateFlatfileCollectionEntry(t *testing.T, document []byte, collection string) []byte {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal(document, &root); err != nil {
		t.Fatal("flat-file fixture could not be decoded for a duplicate test")
	}
	records, ok := root[collection].([]any)
	if !ok || len(records) != 1 {
		t.Fatal("flat-file duplicate test collection was not singular")
	}
	root[collection] = append(records, records[0])
	output, err := json.Marshal(root)
	if err != nil {
		t.Fatal("flat-file duplicate test could not be encoded")
	}
	return output
}

// flatfileDocumentWithSecondCredential creates duplicate, reversed, or canonical dual-key input.
func flatfileDocumentWithSecondCredential(
	t *testing.T,
	duplicate bool,
	canonical bool,
) []byte {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal(mustFlatfileDocument(t), &root); err != nil {
		t.Fatal("dual-credential fixture could not be decoded")
	}
	handles := root[flatfileHandlesCollection].([]any)
	profiles := root[flatfileProfilesCollection].([]any)
	profile := profiles[0].(map[string]any)
	credentials := profile["credentials"].([]any)
	if duplicate {
		profile["credentials"] = append(credentials, credentials[0])
	} else {
		rsaCredential := map[string]any{
			"algorithm":       "rsa-sha256",
			"selector":        "rsa1",
			"public_key_spki": flatfileRSASPKI(t),
			"handle_id":       "key.example.rsa",
		}
		root[flatfileHandlesCollection] = append(handles, map[string]any{"id": "key.example.rsa"})
		if canonical {
			profile["credentials"] = []any{rsaCredential, credentials[0]}
		} else {
			profile["credentials"] = append(credentials, rsaCredential)
		}
	}
	output, err := json.Marshal(root)
	if err != nil {
		t.Fatal("dual-credential fixture could not be encoded")
	}
	return output
}

// flatfileRSASPKI returns deterministic canonical RSA public-key SPKI base64.
func flatfileRSASPKI(t *testing.T) string {
	t.Helper()
	modulus := new(big.Int).Lsh(big.NewInt(1), 2047)
	modulus.Add(modulus, big.NewInt(0x31))
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: modulus, E: 65537})
	if err != nil {
		t.Fatal("RSA public-key fixture could not be encoded")
	}
	return base64.StdEncoding.EncodeToString(der)
}

// flatfileStringAccounting measures decoded names and values in one valid JSON fixture.
func flatfileStringAccounting(t *testing.T, document []byte) (int, int) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(document))
	maximum := 0
	total := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal("flat-file fixture token accounting failed")
		}
		value, ok := token.(string)
		if !ok {
			continue
		}
		total += len(value)
		if len(value) > maximum {
			maximum = len(value)
		}
	}
	return maximum, total
}

// mustFlatfileProfileRequest constructs the durable fixture's exact profile request.
func mustFlatfileProfileRequest(t *testing.T) datasource.ProfileRequest {
	t.Helper()
	profileID, err := datasource.NewProfileID("profile.example")
	if err != nil {
		t.Fatal("profile request identifier construction failed")
	}
	request, err := datasource.NewProfileRequest(
		profileID, datasource.ProfileUseOriginator, flatfileTestTime,
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatal("profile request construction failed")
	}
	return request
}

// mustFlatfilePolicyRequest constructs the durable fixture's exact policy request.
func mustFlatfilePolicyRequest(t *testing.T) datasource.PolicyRequest {
	t.Helper()
	tenantID, err := datasource.NewTenantID("tenant.example")
	if err != nil {
		t.Fatal("policy request tenant construction failed")
	}
	request, err := datasource.NewPolicyRequest(
		tenantID, "example.test", datasource.ProfileUseOriginator,
		flatfileTestTime, datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatal("policy request construction failed")
	}
	return request
}

// assertFlatfileProfileFailure verifies one zero profile result plus the expected typed error.
func assertFlatfileProfileFailure(
	ctx context.Context,
	t *testing.T,
	snapshot *Snapshot,
	code datasource.ErrorCode,
) {
	t.Helper()
	result, err := snapshot.ResolveProfile(ctx, mustFlatfileProfileRequest(t))
	if result.Valid() || result.Generation() != 0 ||
		datasource.ErrorCodeOf(err) != code ||
		datasource.ValidateProfileOutcome(result, err) != nil {
		t.Fatalf("ResolveProfile(failure) valid=%t generation=%d code=%s, want %s",
			result.Valid(), result.Generation(), datasource.ErrorCodeOf(err), code)
	}
}

// assertFlatfilePolicyFailure verifies one zero policy result plus the expected typed error.
func assertFlatfilePolicyFailure(
	ctx context.Context,
	t *testing.T,
	snapshot *Snapshot,
	code datasource.ErrorCode,
) {
	t.Helper()
	result, err := snapshot.ResolvePolicy(ctx, mustFlatfilePolicyRequest(t))
	if result.Valid() || result.Generation() != 0 ||
		datasource.ErrorCodeOf(err) != code ||
		datasource.ValidatePolicyOutcome(result, err) != nil {
		t.Fatalf("ResolvePolicy(failure) valid=%t generation=%d code=%s, want %s",
			result.Valid(), result.Generation(), datasource.ErrorCodeOf(err), code)
	}
}

// flatfileNilReader is a typed-nil reader that must never be invoked.
type flatfileNilReader struct{}

// Read panics if typed-nil reader detection fails.
func (*flatfileNilReader) Read([]byte) (int, error) {
	panic("typed-nil reader invoked")
}

// flatfilePanicReader panics at the injected reader boundary.
type flatfilePanicReader struct{}

// Read provides the deliberate panic used to verify boundary recovery.
func (flatfilePanicReader) Read([]byte) (int, error) {
	panic("reader panic")
}

// flatfileResultReader returns one deterministic data/error pair.
type flatfileResultReader struct {
	data []byte
	err  error
	done bool
}

// Read returns its configured result once and EOF thereafter.
func (r *flatfileResultReader) Read(output []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	return copy(output, r.data), r.err
}

// flatfileNoProgressReader never makes progress and must be bounded by the decoder.
type flatfileNoProgressReader struct {
	calls int
}

// Read returns the hostile no-progress pair.
func (r *flatfileNoProgressReader) Read([]byte) (int, error) {
	r.calls++
	return 0, nil
}

// flatfileInvalidCountReader violates the io.Reader count contract.
type flatfileInvalidCountReader struct {
	negative bool
}

// Read returns a negative or out-of-range count without writing.
func (r flatfileInvalidCountReader) Read(output []byte) (int, error) {
	if r.negative {
		return -1, nil
	}
	return len(output) + 1, nil
}

// flatfileDelayedReader makes bounded empty progress before returning a complete document.
type flatfileDelayedReader struct {
	emptyReads int
	calls      int
	data       []byte
}

// Read returns configured empty reads followed by one complete EOF result.
func (r *flatfileDelayedReader) Read(output []byte) (int, error) {
	r.calls++
	if r.calls <= r.emptyReads {
		return 0, nil
	}
	return copy(output, r.data), io.EOF
}

// flatfileNilContext is a typed-nil context that must never be invoked.
type flatfileNilContext struct{}

// Deadline panics if typed-nil context detection fails.
func (*flatfileNilContext) Deadline() (time.Time, bool) {
	panic("typed-nil context invoked")
}

// Done panics if typed-nil context detection fails.
func (*flatfileNilContext) Done() <-chan struct{} {
	panic("typed-nil context invoked")
}

// Err panics if typed-nil context detection fails.
func (*flatfileNilContext) Err() error {
	panic("typed-nil context invoked")
}

// Value panics if typed-nil context detection fails.
func (*flatfileNilContext) Value(any) any {
	panic("typed-nil context invoked")
}

// flatfilePanicContext panics when its state is inspected.
type flatfilePanicContext struct{}

// Deadline reports no deadline without touching protected state.
func (flatfilePanicContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done reports no notification channel.
func (flatfilePanicContext) Done() <-chan struct{} { return nil }

// Err provides the hostile context panic.
func (flatfilePanicContext) Err() error { panic("context panic") }

// Value returns no associated value.
func (flatfilePanicContext) Value(any) any { return nil }

// flatfileTransitionContext changes from ready to one terminal error after its first check.
type flatfileTransitionContext struct {
	target error
	calls  int
}

// Deadline reports no static deadline because Err owns the deterministic transition.
func (*flatfileTransitionContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done reports no channel because Err owns the deterministic transition.
func (*flatfileTransitionContext) Done() <-chan struct{} { return nil }

// Err returns nil once and the configured terminal state thereafter.
func (c *flatfileTransitionContext) Err() error {
	c.calls++
	if c.calls == 1 {
		return nil
	}
	return c.target
}

// Value returns no associated value.
func (*flatfileTransitionContext) Value(any) any { return nil }
