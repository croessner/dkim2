package instance

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/tagvalue"
)

// TestParseAcceptsMessageInstance verifies the required and optional tags.
func TestParseAcceptsMessageInstance(t *testing.T) {
	field := messageInstanceField(t, 7, "m=2; h=sha256:"+base64OfByte(0x11, 32)+":"+base64OfByte(0x22, 32)+"; r="+base64.StdEncoding.EncodeToString([]byte(`{"op":[]}`))+"; x_ext=ignored")

	parsed, err := Parse(field)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.Number() != 2 {
		t.Fatalf("Number() = %d, want 2", parsed.Number())
	}
	if parsed.HeaderIndex() != 7 {
		t.Fatalf("HeaderIndex() = %d, want 7", parsed.HeaderIndex())
	}

	hashes := parsed.HashSets()
	if len(hashes) != 1 {
		t.Fatalf("HashSets() length = %d, want 1", len(hashes))
	}
	if hashes[0].Name() != HashAlgorithmSHA256 || !hashes[0].Known() {
		t.Fatalf("hash metadata = name %q known %v", hashes[0].Name(), hashes[0].Known())
	}
	if headerHash, ok := hashes[0].HeaderHash(); !ok || headerHash.DecodedLen() != 32 {
		t.Fatalf("HeaderHash() ok=%v decoded_len=%d, want known 32", ok, headerHash.DecodedLen())
	}
	if bodyHash, ok := hashes[0].BodyHash(); !ok || bodyHash.DecodedLen() != 32 {
		t.Fatalf("BodyHash() ok=%v decoded_len=%d, want known 32", ok, bodyHash.DecodedLen())
	}

	recipe, ok := parsed.Recipe()
	if !ok {
		t.Fatal("Recipe() missing")
	}
	if got := string(recipe.Decoded()); got != `{"op":[]}` {
		t.Fatalf("Recipe decoded = %q, want synthetic JSON bytes", got)
	}
}

// TestParseRejectsMissingFinalSemicolon reproduces the draft-04 Message-Instance terminator rule.
func TestParseRejectsMissingFinalSemicolon(t *testing.T) {
	value := "m=1; h=sha256:" + base64OfByte(1, 32) + ":" + base64OfByte(2, 32)
	if _, err := Parse(headerField(t, 0, "Message-Instance", value)); err == nil {
		t.Fatal("Parse() succeeded without the required final semicolon")
	}
}

// TestParseRejectsWrongHeaderKind verifies parser-boundary header matching.
func TestParseRejectsWrongHeaderKind(t *testing.T) {
	field := headerField(t, 0, "DKIM2-Signature", "m=1; h=value")
	_, err := Parse(field)
	if !IsErrorCode(err, ErrorCodeWrongHeaderField) {
		t.Fatalf("Parse() error = %v, want wrong header field", err)
	}
}

// TestParseRejectsMissingRequiredTags verifies fail-closed required tags.
func TestParseRejectsMissingRequiredTags(t *testing.T) {
	tests := []struct {
		name string
		in   string
		tag  string
	}{
		{name: "missing m", in: "h=sha256:" + base64OfByte(1, 32) + ":" + base64OfByte(2, 32), tag: "m"},
		{name: "missing h", in: "m=1", tag: "h"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(messageInstanceField(t, 0, tt.in))
			if !IsErrorCode(err, ErrorCodeMissingRequiredTag) {
				t.Fatalf("Parse() error = %v, want missing required tag", err)
			}

			var instanceErr *Error
			if !errors.As(err, &instanceErr) {
				t.Fatal("errors.As did not expose instance Error")
			}
			if instanceErr.TagName() != tt.tag {
				t.Fatalf("TagName() = %q, want %q", instanceErr.TagName(), tt.tag)
			}
		})
	}
}

// TestParseRejectsInvalidInstanceNumbers verifies strict m= decimal syntax.
func TestParseRejectsInvalidInstanceNumbers(t *testing.T) {
	tests := []string{"", "0", "-1", "+1", "1x", "0x10", "18446744073709551616"}
	for _, value := range tests {
		t.Run("m="+value, func(t *testing.T) {
			_, err := Parse(messageInstanceField(t, 0, "m="+value+"; h=sha256:"+base64OfByte(1, 32)+":"+base64OfByte(2, 32)))
			if !IsErrorCode(err, ErrorCodeInvalidNumber) {
				t.Fatalf("Parse() error = %v, want invalid number", err)
			}
		})
	}
}

// TestParseRejectsSharedTagSyntaxErrors verifies tagvalue remains authoritative.
func TestParseRejectsSharedTagSyntaxErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		code tagvalue.ErrorCode
	}{
		{name: "duplicate tag", in: "m=1; h=sha256:" + base64OfByte(1, 32) + ":" + base64OfByte(2, 32) + "; M=2", code: tagvalue.ErrorCodeDuplicateTag},
		{name: "empty interior tag", in: "m=1;; h=sha256:" + base64OfByte(1, 32) + ":" + base64OfByte(2, 32), code: tagvalue.ErrorCodeEmptyTagSpec},
		{name: "invalid extension tag", in: "m=1; h=sha256:" + base64OfByte(1, 32) + ":" + base64OfByte(2, 32) + "; x-bad=1", code: tagvalue.ErrorCodeInvalidTagName},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(messageInstanceField(t, 0, tt.in))
			if !tagvalue.IsErrorCode(err, tt.code) {
				t.Fatalf("Parse() error = %v, want tagvalue code %s", err, tt.code)
			}
		})
	}
}

// TestParseRejectsMalformedHashSets verifies h= tuple syntax.
func TestParseRejectsMalformedHashSets(t *testing.T) {
	tests := []string{
		"",
		"sha256",
		"sha256:" + base64OfByte(1, 32),
		"sha256:" + base64OfByte(1, 32) + ":" + base64OfByte(2, 32) + ":extra",
		":" + base64OfByte(1, 32) + ":" + base64OfByte(2, 32),
		"sha256::" + base64OfByte(2, 32),
		"sha256:" + base64OfByte(1, 32) + ":",
	}

	for _, value := range tests {
		t.Run("hash-set", func(t *testing.T) {
			_, err := Parse(messageInstanceField(t, 0, "m=1; h="+value))
			if !IsErrorCode(err, ErrorCodeMalformedHashSet) {
				t.Fatalf("Parse() error = %v, want malformed hash set", err)
			}
		})
	}
}

// TestParseRejectsDuplicateHashAlgorithms verifies h= ambiguity handling.
func TestParseRejectsDuplicateHashAlgorithms(t *testing.T) {
	value := "sha256:" + base64OfByte(1, 32) + ":" + base64OfByte(2, 32) +
		", SHA256:" + base64OfByte(3, 32) + ":" + base64OfByte(4, 32)
	_, err := Parse(messageInstanceField(t, 0, "m=1; h="+value))
	if !IsErrorCode(err, ErrorCodeDuplicateHashName) {
		t.Fatalf("Parse() error = %v, want duplicate hash name", err)
	}
}

// TestParseRejectsInvalidSHA256HashBase64 verifies known-hash base64 checks.
func TestParseRejectsInvalidSHA256HashBase64(t *testing.T) {
	tests := []struct {
		name string
		in   string
		code ErrorCode
	}{
		{name: "invalid alphabet", in: "sha256:not_base64:" + base64OfByte(2, 32), code: ErrorCodeInvalidHashBase64},
		{name: "wrong header length", in: "sha256:" + base64.StdEncoding.EncodeToString([]byte("short")) + ":" + base64OfByte(2, 32), code: ErrorCodeInvalidHashLength},
		{name: "wrong body length", in: "sha256:" + base64OfByte(1, 32) + ":" + base64.StdEncoding.EncodeToString([]byte("short")), code: ErrorCodeInvalidHashLength},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(messageInstanceField(t, 0, "m=1; h="+tt.in))
			if !IsErrorCode(err, tt.code) {
				t.Fatalf("Parse() error = %v, want %s", err, tt.code)
			}
		})
	}
}

// TestParsePreservesUnknownHashNames verifies strict base64 and non-success parser data.
func TestParsePreservesUnknownHashNames(t *testing.T) {
	unknownHeader := base64.StdEncoding.EncodeToString([]byte("future header hash"))
	unknownBody := base64.StdEncoding.EncodeToString([]byte("future body hash"))
	field := messageInstanceField(t, 0, "m=1; h=sha512:"+unknownHeader+":"+unknownBody+", sha256:"+base64OfByte(1, 32)+":"+base64OfByte(2, 32))
	parsed, err := Parse(field)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	hashes := parsed.HashSets()
	if len(hashes) != 2 {
		t.Fatalf("HashSets() length = %d, want 2", len(hashes))
	}
	if hashes[0].Name() != "sha512" || hashes[0].Known() {
		t.Fatalf("unknown hash metadata = name %q known %v", hashes[0].Name(), hashes[0].Known())
	}
	if _, ok := hashes[0].HeaderHash(); ok {
		t.Fatal("unknown hash returned a known header hash container")
	}
	if got := hashes[0].HeaderHashValue(); !bytes.Equal(got, []byte(unknownHeader)) {
		t.Fatalf("HeaderHashValue() = %q, want validated unknown base64 container", got)
	}
}

// TestParseRejectsInvalidUnknownHashBase64 verifies future algorithms retain base64string syntax.
func TestParseRejectsInvalidUnknownHashBase64(t *testing.T) {
	for _, value := range []string{
		"sha512:not-base64:" + base64OfByte(2, 64),
		"sha512:" + base64OfByte(1, 64) + ":also-not-base64",
	} {
		_, err := Parse(messageInstanceField(t, 0, "m=1; h="+value))
		if !IsErrorCode(err, ErrorCodeInvalidHashBase64) {
			t.Fatalf("Parse() error = %v, want invalid hash base64", err)
		}
	}
}

// TestParseRejectsInvalidRecipeBase64 verifies r= syntax without JSON parsing.
func TestParseRejectsInvalidRecipeBase64(t *testing.T) {
	_, err := Parse(messageInstanceField(t, 0, "m=1; h=sha256:"+base64OfByte(1, 32)+":"+base64OfByte(2, 32)+"; r=not_base64"))
	if !IsErrorCode(err, ErrorCodeInvalidRecipeBase64) {
		t.Fatalf("Parse() error = %v, want invalid recipe base64", err)
	}
}

// TestParserRejectsHashSetLimit verifies Message-Instance resource limits.
func TestParserRejectsHashSetLimit(t *testing.T) {
	parser, err := NewParser(Limits{MaxHashSets: 1})
	if err != nil {
		t.Fatalf("NewParser() error = %v", err)
	}
	value := "m=1; h=unknown:a:b, sha256:" + base64OfByte(1, 32) + ":" + base64OfByte(2, 32)
	_, err = parser.ParseField(messageInstanceField(t, 0, value))
	if !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("ParseField() error = %v, want limit exceeded", err)
	}
}

// TestInstanceErrorStringIsSecretSafe verifies diagnostics omit raw values.
func TestInstanceErrorStringIsSecretSafe(t *testing.T) {
	rawRecipe := "c2VjcmV0LXJlY2lwZQ"
	_, err := Parse(messageInstanceField(t, 0, "m=1; h=sha256:"+base64OfByte(1, 32)+":"+base64OfByte(2, 32)+"; r="+rawRecipe))
	if err == nil {
		t.Fatal("Parse() succeeded, want invalid recipe base64")
	}

	message := err.Error()
	for _, forbidden := range []string{rawRecipe, "secret-recipe", base64OfByte(1, 32)} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("error string leaked raw parser data %q in %q", forbidden, message)
		}
	}
}

// messageInstanceField constructs a synthetic Message-Instance header field.
func messageInstanceField(t *testing.T, index int, value string) rawmsg.HeaderField {
	t.Helper()
	if !strings.HasSuffix(strings.TrimRight(value, " \t"), ";") {
		value += ";"
	}

	return headerField(t, index, "Message-Instance", value)
}

// headerField constructs a synthetic rawmsg header field for parser tests.
func headerField(t *testing.T, index int, name string, value string) rawmsg.HeaderField {
	t.Helper()

	fieldValue := []byte(" " + value)
	field, err := rawmsg.NewHeaderField(index, []byte(name), fieldValue, fieldValue, []byte(name+": "+value+"\r\n"))
	if err != nil {
		t.Fatalf("NewHeaderField() error = %v", err)
	}

	return field
}

// base64OfByte returns a padded base64 string containing repeated byte data.
func base64OfByte(b byte, count int) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, count))
}

// TestParseAcceptsFoldedWhitespaceInHashBase64 verifies WSP inside hash base64 is ignored.
//
// Draft-04 Section 7.3 defines header-hash and body-hash as base64string, and
// Section 2 states that base64string admits FWS which "will be ignored when
// their value is being used". Unfolding a folded header leaves the fold's WSP in
// the value, so both SP and HTAB must be tolerated inside a hash component. The
// DKIM2-Signature s= path already accepts both.
func TestParseAcceptsFoldedWhitespaceInHashBase64(t *testing.T) {
	headerHash := base64OfByte(0x11, 32)
	bodyHash := base64OfByte(0x22, 32)
	for _, test := range []struct {
		name string
		wsp  string
	}{
		{name: "space", wsp: " "},
		{name: "htab", wsp: "\t"},
	} {
		t.Run(test.name, func(t *testing.T) {
			split := func(value string) string {
				return value[:8] + test.wsp + value[8:]
			}
			field := messageInstanceField(t, 1, "m=1; h=sha256:"+split(headerHash)+":"+split(bodyHash))
			parsed, err := Parse(field)
			if err != nil {
				t.Fatalf("Parse() error = %v, want folded hash acceptance", err)
			}
			hashes := parsed.HashSets()
			if len(hashes) != 1 || hashes[0].Name() != HashAlgorithmSHA256 {
				t.Fatalf("HashSets() = %#v, want one sha256 set", hashes)
			}
			decodedHeader, ok := hashes[0].HeaderHash()
			if !ok || decodedHeader.DecodedLen() != 32 {
				t.Fatalf("HeaderHash() ok=%v decoded_len=%d, want known 32", ok, decodedHeader.DecodedLen())
			}
			decodedBody, ok := hashes[0].BodyHash()
			if !ok || decodedBody.DecodedLen() != 32 {
				t.Fatalf("BodyHash() ok=%v decoded_len=%d, want known 32", ok, decodedBody.DecodedLen())
			}
			if string(decodedHeader.Encoded()) != headerHash || string(decodedBody.Encoded()) != bodyHash {
				t.Fatalf("canonical encodings = %q/%q, want the unfolded values %q/%q",
					decodedHeader.Encoded(), decodedBody.Encoded(), headerHash, bodyHash)
			}
		})
	}
}
