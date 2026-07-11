package tagvalue

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const (
	encodedMa  = "TWE="
	encodedMan = "TWFu"
)

// TestParseBase64StringAcceptsCanonicalValues verifies strict padded decoding.
func TestParseBase64StringAcceptsCanonicalValues(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		wantEncoded string
		wantDecoded []byte
	}{
		{name: "no padding needed", input: []byte(encodedMan), wantEncoded: encodedMan, wantDecoded: []byte("Man")},
		{name: "one padding byte", input: []byte(encodedMa), wantEncoded: encodedMa, wantDecoded: []byte("Ma")},
		{name: "two padding bytes", input: []byte("TQ=="), wantEncoded: "TQ==", wantDecoded: []byte("M")},
		{name: "space and tab stripped", input: []byte(" T\tW F\tu "), wantEncoded: encodedMan, wantDecoded: []byte("Man")},
		{name: "padding with fws", input: []byte("\tT W E = "), wantEncoded: encodedMa, wantDecoded: []byte("Ma")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := ParseBase64String(tt.input, Limits{})
			if err != nil {
				t.Fatalf("ParseBase64String() error = %v", err)
			}
			if got := value.EncodedString(); got != tt.wantEncoded {
				t.Fatalf("EncodedString() = %q, want %q", got, tt.wantEncoded)
			}
			if got := value.Encoded(); !bytes.Equal(got, []byte(tt.wantEncoded)) {
				t.Fatalf("Encoded() = %q, want %q", got, tt.wantEncoded)
			}
			if got := value.Decoded(); !bytes.Equal(got, tt.wantDecoded) {
				t.Fatalf("Decoded() = %q, want %q", got, tt.wantDecoded)
			}
			if got := value.Original(); !bytes.Equal(got, tt.input) {
				t.Fatalf("Original() = %q, want parser-owned input copy", got)
			}
		})
	}
}

// TestParseOptionalPaddingBase64StringAcceptsDNSValues verifies optional input and canonical output padding.
func TestParseOptionalPaddingBase64StringAcceptsDNSValues(t *testing.T) {
	for _, tt := range []struct {
		input, encoded, decoded string
	}{
		{input: "TWE", encoded: encodedMa, decoded: "Ma"},
		{input: "TQ", encoded: "TQ==", decoded: "M"},
		{input: " T\tW E ", encoded: encodedMa, decoded: "Ma"},
		{input: encodedMa, encoded: encodedMa, decoded: "Ma"},
	} {
		value, err := ParseOptionalPaddingBase64String([]byte(tt.input), Limits{})
		if err != nil || value.EncodedString() != tt.encoded || string(value.Decoded()) != tt.decoded {
			t.Fatalf("optional padding parse = %q/%q error=%v", value.EncodedString(), value.Decoded(), err)
		}
	}
	for _, input := range []string{"T", "TR", "TWF", "TQ=", "TWE==", "T=WE", "TWE===", "TW-F"} {
		if _, err := ParseOptionalPaddingBase64String([]byte(input), Limits{}); err == nil {
			t.Fatal("malformed optional-padding value accepted")
		}
	}
	if _, err := ParseOptionalPaddingBase64String([]byte("TWE"), Limits{MaxBase64DecodedBytes: 1}); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("unpadded decoded-limit error = %v, want limit exceeded", err)
	}
}

// TestParseBase64StringRejectsMalformedInput verifies fail-closed syntax.
func TestParseBase64StringRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name string
		in   string
		code ErrorCode
	}{
		{name: "empty", in: "", code: ErrorCodeInvalidBase64Length},
		{name: "only fws", in: " \t ", code: ErrorCodeInvalidBase64Length},
		{name: "missing padding one byte", in: "TWE", code: ErrorCodeInvalidBase64Length},
		{name: "missing padding two bytes", in: "TQ", code: ErrorCodeInvalidBase64Length},
		{name: "impossible length", in: "T", code: ErrorCodeInvalidBase64Length},
		{name: "excess padding", in: "TWFu====", code: ErrorCodeInvalidBase64Padding},
		{name: "interior padding", in: "TW=Fu", code: ErrorCodeInvalidBase64Padding},
		{name: "url safe dash", in: "TW-Fu==", code: ErrorCodeInvalidBase64Alphabet},
		{name: "url safe underscore", in: "TW_Fu==", code: ErrorCodeInvalidBase64Alphabet},
		{name: "non base64 byte", in: "TW*Fu==", code: ErrorCodeInvalidBase64Alphabet},
		{name: "cr not fws", in: "TW\rFu", code: ErrorCodeInvalidBase64Alphabet},
		{name: "lf not fws", in: "TW\nFu", code: ErrorCodeInvalidBase64Alphabet},
		{name: "non zero pad bits", in: "/x==", code: ErrorCodeInvalidBase64PadBits},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseBase64String([]byte(tt.in), Limits{})
			if !IsErrorCode(err, tt.code) {
				t.Fatalf("ParseBase64String() error = %v, want code %s", err, tt.code)
			}
		})
	}
}

// TestParseBase64StringRejectsDecodedLimit verifies decoded size limits.
func TestParseBase64StringRejectsDecodedLimit(t *testing.T) {
	_, err := ParseBase64String([]byte(encodedMan), Limits{MaxBase64DecodedBytes: 2})
	if !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("ParseBase64String() error = %v, want limit exceeded", err)
	}

	var tagErr *Error
	if !errors.As(err, &tagErr) {
		t.Fatal("errors.As did not expose tagvalue Error")
	}
	if tagErr.LimitName() != "max_base64_decoded_bytes" {
		t.Fatalf("LimitName() = %q, want max_base64_decoded_bytes", tagErr.LimitName())
	}
}

// TestParseBase64StringCopiesBoundaries verifies parser-owned immutability.
func TestParseBase64StringCopiesBoundaries(t *testing.T) {
	input := []byte(encodedMan)
	value, err := ParseBase64String(input, Limits{})
	if err != nil {
		t.Fatalf("ParseBase64String() error = %v", err)
	}

	input[0] = 'Q'
	original := value.Original()
	encoded := value.Encoded()
	decoded := value.Decoded()
	original[0] = 'Q'
	encoded[0] = 'Q'
	decoded[0] = 'X'

	if got := value.Original(); !bytes.Equal(got, []byte(encodedMan)) {
		t.Fatalf("Original() after mutation = %q, want %s", got, encodedMan)
	}
	if got := value.EncodedString(); got != encodedMan {
		t.Fatalf("EncodedString() after mutation = %q, want %s", got, encodedMan)
	}
	if got := value.Decoded(); !bytes.Equal(got, []byte("Man")) {
		t.Fatalf("Decoded() after mutation = %q, want Man", got)
	}
}

// TestBase64ErrorStringIsSecretSafe verifies diagnostics omit encoded bytes.
func TestBase64ErrorStringIsSecretSafe(t *testing.T) {
	raw := []byte("c2VjcmV0LXZhbHVl")
	_, err := ParseBase64String(raw, Limits{MaxBase64DecodedBytes: 1})
	if err == nil {
		t.Fatal("ParseBase64String() succeeded, want limit error")
	}

	message := err.Error()
	for _, forbidden := range []string{"c2VjcmV0", "secret", string(raw)} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("error string leaked base64 context %q in %q", forbidden, message)
		}
	}
}
