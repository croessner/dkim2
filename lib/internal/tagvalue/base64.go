package tagvalue

import "encoding/base64"

// Base64String stores immutable views of one canonical DKIM2 Base64 value.
type Base64String struct {
	original []byte
	encoded  []byte
	decoded  []byte
}

// ParseBase64String parses a padded RFC 4648 DKIM2 base64string value.
func ParseBase64String(input []byte, limits Limits) (Base64String, error) {
	return parseBase64String(input, limits, false)
}

// ParseOptionalPaddingBase64String parses RFC 4648 Base64 with optional terminal padding.
func ParseOptionalPaddingBase64String(input []byte, limits Limits) (Base64String, error) {
	return parseBase64String(input, limits, true)
}

// parseBase64String parses strict Base64 under the selected terminal-padding policy.
func parseBase64String(input []byte, limits Limits, optionalPadding bool) (Base64String, error) {
	limits = limits.normalize()
	if err := limits.Validate(); err != nil {
		return Base64String{}, err
	}
	if len(input) > limits.MaxTagValueBytes {
		return Base64String{}, limitExceededError("max_tag_value_bytes", limits.MaxTagValueBytes, len(input), ErrorLocation{})
	}

	encoded := stripBase64FWS(input)
	padCount, err := validateBase64AlphabetAndPadding(encoded)
	if err != nil {
		return Base64String{}, err
	}
	if len(encoded) == 0 {
		return Base64String{}, base64Error(ErrorCodeInvalidBase64Length, 0)
	}
	if remainder := len(encoded) % 4; remainder != 0 {
		if !optionalPadding || padCount != 0 || remainder == 1 {
			return Base64String{}, base64Error(ErrorCodeInvalidBase64Length, 0)
		}
		missingPadding := 4 - remainder
		encoded = append(encoded, bytesOf('=', missingPadding)...)
		padCount = missingPadding
	}

	decodedLen := decodedBase64Length(len(encoded), padCount)
	if decodedLen > limits.MaxBase64DecodedBytes {
		return Base64String{}, limitExceededError("max_base64_decoded_bytes", limits.MaxBase64DecodedBytes, decodedLen, ErrorLocation{})
	}
	original := copyBytes(input)

	decoded := make([]byte, decodedLen)
	written, decodeErr := base64.StdEncoding.Decode(decoded, encoded)
	if decodeErr != nil {
		return Base64String{}, base64Error(ErrorCodeInvalidBase64Padding, 0)
	}
	decoded = decoded[:written]
	if base64.StdEncoding.EncodeToString(decoded) != string(encoded) {
		return Base64String{}, base64Error(ErrorCodeInvalidBase64PadBits, 0)
	}

	return Base64String{
		original: original,
		encoded:  copyBytes(encoded),
		decoded:  copyBytes(decoded),
	}, nil
}

// bytesOf returns count copies of value for bounded canonical padding.
func bytesOf(value byte, count int) []byte {
	output := make([]byte, count)
	for index := range output {
		output[index] = value
	}
	return output
}

// Original returns the parser-owned encoded bytes before FWS stripping.
func (v Base64String) Original() []byte {
	return copyBytes(v.original)
}

// Encoded returns the canonical no-FWS padded base64 bytes.
func (v Base64String) Encoded() []byte {
	return copyBytes(v.encoded)
}

// EncodedString returns the canonical no-FWS padded base64 string.
func (v Base64String) EncodedString() string {
	return string(v.encoded)
}

// Decoded returns the decoded parser-owned bytes.
func (v Base64String) Decoded() []byte {
	return copyBytes(v.decoded)
}

// DecodedLen returns the decoded byte length without exposing decoded bytes.
func (v Base64String) DecodedLen() int {
	return len(v.decoded)
}

// stripBase64FWS removes only draft-allowed space and tab bytes.
func stripBase64FWS(input []byte) []byte {
	encoded := make([]byte, 0, len(input))
	for _, b := range input {
		if isWSP(b) {
			continue
		}
		encoded = append(encoded, b)
	}

	return encoded
}

// validateBase64AlphabetAndPadding enforces standard alphabet and padding shape.
func validateBase64AlphabetAndPadding(encoded []byte) (int, error) {
	padCount := 0
	seenPadding := false
	for i, b := range encoded {
		if b == '=' {
			seenPadding = true
			padCount++
			if padCount > 2 || i < len(encoded)-2 {
				return 0, base64Error(ErrorCodeInvalidBase64Padding, i)
			}
			continue
		}
		if seenPadding {
			return 0, base64Error(ErrorCodeInvalidBase64Padding, i)
		}
		if !isStandardBase64Alphabet(b) {
			return 0, base64Error(ErrorCodeInvalidBase64Alphabet, i)
		}
	}

	return padCount, nil
}

// decodedBase64Length calculates decoded bytes after validated padding.
func decodedBase64Length(encodedLen int, padCount int) int {
	return encodedLen/4*3 - padCount
}

// isStandardBase64Alphabet reports whether b belongs to RFC 4648 base64.
func isStandardBase64Alphabet(b byte) bool {
	return isASCIILetter(b) || isASCIIDigit(b) || b == '+' || b == '/'
}

// base64Error constructs a structured secret-safe base64 parser error.
func base64Error(code ErrorCode, offset int) *Error {
	return NewError(code, ErrorLocation{Offset: offset}, ErrorDetails{
		Class: ErrorClassMalformed,
	})
}

// copyBytes returns detached storage for immutable parser values.
func copyBytes(input []byte) []byte {
	if input == nil {
		return nil
	}

	output := make([]byte, len(input))
	copy(output, input)

	return output
}
