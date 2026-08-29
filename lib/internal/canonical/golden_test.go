package canonical

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

type bodyGoldenFixture struct {
	Draft string           `json:"draft"`
	Cases []bodyGoldenCase `json:"cases"`
}

type bodyGoldenCase struct {
	Name               string `json:"name"`
	Draft              string `json:"draft"`
	BodyBase64         string `json:"body_base64"`
	CanonicalBase64    string `json:"canonical_base64"`
	SHA256Base64       string `json:"sha256_base64"`
	TrailingEmptyLines int    `json:"trailing_empty_lines"`
	TerminalAction     string `json:"terminal_action"`
}

type headerGoldenFixture struct {
	Draft           string               `json:"draft"`
	HeadersBase64   string               `json:"headers_base64"`
	CanonicalBase64 string               `json:"canonical_base64"`
	SHA256Base64    string               `json:"sha256_base64"`
	IncludedFields  int                  `json:"included_fields"`
	ExcludedFields  int                  `json:"excluded_fields"`
	ExcludedCounts  goldenExcludedCounts `json:"excluded_counts"`
}

type signatureGoldenFixture struct {
	Draft           string `json:"draft"`
	HeadersBase64   string `json:"headers_base64"`
	TargetSequence  uint64 `json:"target_sequence"`
	CanonicalBase64 string `json:"canonical_base64"`
	IncludedFields  int    `json:"included_fields"`
	ExcludedFields  int    `json:"excluded_fields"`
}

type goldenExcludedCounts struct {
	Received              int `json:"received"`
	ReturnPath            int `json:"return_path"`
	DeliveredTo           int `json:"delivered_to"`
	AuthenticationResults int `json:"authentication_results"`
	XHeader               int `json:"x_header"`
	DKIMSignature         int `json:"dkim_signature"`
	ExactUnsigned         int `json:"exact_unsigned"`
	ARC                   int `json:"arc"`
	MessageInstance       int `json:"message_instance"`
	DKIM2Signature        int `json:"dkim2_signature"`
}

// TestGoldenBodyCanonicalizationFixtures verifies draft-versioned Section 6.1 fixtures.
func TestGoldenBodyCanonicalizationFixtures(t *testing.T) {
	fixture := loadGoldenJSON[bodyGoldenFixture](t, "testdata/golden/body-canonicalization-draft-ietf-dkim-dkim2-spec-06.json")
	if fixture.Draft != DraftBaseline {
		t.Fatalf("fixture draft = %q, want %q", fixture.Draft, DraftBaseline)
	}

	canonicalizer := mustCanonicalizer(t)
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Draft != DraftBaseline {
				t.Fatalf("case draft = %q, want %q", tc.Draft, DraftBaseline)
			}

			body := decodeGoldenBase64(t, tc.BodyBase64)
			wantCanonical := decodeGoldenBase64(t, tc.CanonicalBase64)
			msg := mustParseBodyMessage(t, body)

			result, err := canonicalizer.BodyHash(msg.Body())
			if err != nil {
				t.Fatalf("BodyHash() error = %v", err)
			}
			gotCanonical := result.CanonicalBytes()
			if !bytes.Equal(gotCanonical.Bytes(), wantCanonical) {
				t.Fatalf("BodyHash() canonical bytes differed for %s", tc.Name)
			}

			metadata := gotCanonical.Metadata()
			assertGoldenMetadata(t, metadata, KindBodyHashInput, len(body), len(wantCanonical), 0, 0)
			if metadata.BodyTrailingEmptyLines != tc.TrailingEmptyLines {
				t.Fatalf("BodyTrailingEmptyLines = %d, want %d", metadata.BodyTrailingEmptyLines, tc.TrailingEmptyLines)
			}
			if metadata.BodyTerminalAction != BodyTerminalAction(tc.TerminalAction) {
				t.Fatalf("BodyTerminalAction = %q, want %q", metadata.BodyTerminalAction, tc.TerminalAction)
			}

			digest := mustResultDigest(t, result)
			if digest.Algorithm() != HashAlgorithmSHA256 {
				t.Fatalf("Digest().Algorithm() = %q, want %q", digest.Algorithm(), HashAlgorithmSHA256)
			}
			if digest.Base64() != tc.SHA256Base64 {
				t.Fatalf("Digest().Base64() = %q, want %q", digest.Base64(), tc.SHA256Base64)
			}
		})
	}
}

// TestGoldenHeaderCanonicalizationFixture verifies a draft-versioned Section 6.2 fixture.
func TestGoldenHeaderCanonicalizationFixture(t *testing.T) {
	fixture := loadGoldenJSON[headerGoldenFixture](t, "testdata/golden/header-canonicalization-draft-ietf-dkim-dkim2-spec-06.json")
	if fixture.Draft != DraftBaseline {
		t.Fatalf("fixture draft = %q, want %q", fixture.Draft, DraftBaseline)
	}

	headers := decodeGoldenBase64(t, fixture.HeadersBase64)
	wantCanonical := decodeGoldenBase64(t, fixture.CanonicalBase64)
	msg := mustParseHeaderMessage(t, headers)
	result, err := mustCanonicalizer(t).HeaderHashFromMessage(msg)
	if err != nil {
		t.Fatalf("HeaderHashFromMessage() error = %v", err)
	}

	gotCanonical := result.CanonicalBytes()
	if !bytes.Equal(gotCanonical.Bytes(), wantCanonical) {
		t.Fatalf("HeaderHashFromMessage() canonical bytes differed")
	}

	metadata := gotCanonical.Metadata()
	assertGoldenMetadata(t, metadata, KindHeaderHashInput, len(headers), len(wantCanonical), fixture.IncludedFields, fixture.ExcludedFields)
	assertGoldenExcludedCounts(t, metadata.ExcludedHeaderCounts, fixture.ExcludedCounts)

	digest := mustResultDigest(t, result)
	if digest.Algorithm() != HashAlgorithmSHA256 {
		t.Fatalf("Digest().Algorithm() = %q, want %q", digest.Algorithm(), HashAlgorithmSHA256)
	}
	if digest.Base64() != fixture.SHA256Base64 {
		t.Fatalf("Digest().Base64() = %q, want %q", digest.Base64(), fixture.SHA256Base64)
	}
}

// TestGoldenSignatureCanonicalizationFixture verifies a draft-versioned Section 9.6 fixture.
func TestGoldenSignatureCanonicalizationFixture(t *testing.T) {
	fixture := loadGoldenJSON[signatureGoldenFixture](t, "testdata/golden/signature-input-draft-ietf-dkim-dkim2-spec-06.json")
	if fixture.Draft != DraftBaseline {
		t.Fatalf("fixture draft = %q, want %q", fixture.Draft, DraftBaseline)
	}

	headers := decodeGoldenBase64(t, fixture.HeadersBase64)
	wantCanonical := decodeGoldenBase64(t, fixture.CanonicalBase64)
	msg := mustParseHeaderMessage(t, headers)
	got, err := mustCanonicalizer(t).SignatureInputFromMessage(msg, fixture.TargetSequence)
	if err != nil {
		t.Fatalf("SignatureInputFromMessage() error = %v", err)
	}
	if !bytes.Equal(got.Bytes(), wantCanonical) {
		t.Fatalf("SignatureInputFromMessage() canonical bytes differed")
	}

	metadata := got.Metadata()
	assertGoldenMetadata(t, metadata, KindSignatureInput, metadata.InputBytes, len(wantCanonical), fixture.IncludedFields, fixture.ExcludedFields)
	if metadata.InputBytes == 0 {
		t.Fatal("SignatureInput metadata InputBytes = 0, want selected protocol field length")
	}
}

// loadGoldenJSON reads and decodes one synthetic golden fixture.
func loadGoldenJSON[T any](t *testing.T, path string) T {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	if !bytes.Contains(data, []byte(DraftBaseline)) {
		t.Fatalf("fixture %q does not identify %s", path, DraftBaseline)
	}

	var fixture T
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("json.Unmarshal(%q) error = %v", path, err)
	}

	return fixture
}

// decodeGoldenBase64 decodes ASCII fixture payloads into expected bytes.
func decodeGoldenBase64(t *testing.T, value string) []byte {
	t.Helper()

	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString(%q) error = %v", value, err)
	}

	return decoded
}

// mustResultDigest extracts the SHA-256 digest from a golden result.
func mustResultDigest(t *testing.T, result Result) Digest {
	t.Helper()

	digest, ok := result.Digest()
	if !ok {
		t.Fatal("result did not include a digest")
	}

	return digest
}

// assertGoldenMetadata verifies bounded debug metadata common to golden outputs.
func assertGoldenMetadata(t *testing.T, metadata Metadata, kind Kind, inputBytes int, outputBytes int, includedFields int, excludedFields int) {
	t.Helper()

	if metadata.Kind != kind {
		t.Fatalf("Metadata().Kind = %q, want %q", metadata.Kind, kind)
	}
	if metadata.Draft != DraftBaseline {
		t.Fatalf("Metadata().Draft = %q, want %q", metadata.Draft, DraftBaseline)
	}
	if metadata.InputBytes != inputBytes {
		t.Fatalf("Metadata().InputBytes = %d, want %d", metadata.InputBytes, inputBytes)
	}
	if metadata.OutputBytes != outputBytes {
		t.Fatalf("Metadata().OutputBytes = %d, want %d", metadata.OutputBytes, outputBytes)
	}
	if metadata.IncludedFields != includedFields {
		t.Fatalf("Metadata().IncludedFields = %d, want %d", metadata.IncludedFields, includedFields)
	}
	if metadata.ExcludedFields != excludedFields {
		t.Fatalf("Metadata().ExcludedFields = %d, want %d", metadata.ExcludedFields, excludedFields)
	}
}

// assertGoldenExcludedCounts verifies allowlisted Section 6.2 exclusion counters.
func assertGoldenExcludedCounts(t *testing.T, got ExcludedHeaderCounts, want goldenExcludedCounts) {
	t.Helper()

	if got.Received != want.Received ||
		got.ReturnPath != want.ReturnPath ||
		got.DeliveredTo != want.DeliveredTo ||
		got.AuthenticationResults != want.AuthenticationResults ||
		got.XHeader != want.XHeader ||
		got.DKIMSignature != want.DKIMSignature ||
		got.ExactUnsigned != want.ExactUnsigned ||
		got.ARC != want.ARC ||
		got.MessageInstance != want.MessageInstance ||
		got.DKIM2Signature != want.DKIM2Signature {
		t.Fatalf("ExcludedHeaderCounts = %#v, want %#v", got, want)
	}
}
