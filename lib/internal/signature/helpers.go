package signature

import "bytes"

// parseNonce validates n= as bounded printable ASCII excluding semicolon.
func parseNonce(value string, limits Limits, fieldIndex int) ([]byte, error) {
	if len(value) > limits.MaxNonceBytes {
		return nil, newError(ErrorCodeInvalidNonce, ErrorLocation{FieldIndex: fieldIndex}, ErrorDetails{
			TagName:   "n",
			LimitName: "max_nonce_bytes",
			Limit:     limits.MaxNonceBytes,
			Count:     len(value),
		}, nil)
	}
	if !ValidNonceSyntax([]byte(value)) {
		return nil, newError(ErrorCodeInvalidNonce, ErrorLocation{FieldIndex: fieldIndex}, ErrorDetails{
			TagName: "n",
		}, nil)
	}

	return []byte(value), nil
}

// ValidNonceSyntax reports whether bytes are printable ASCII excluding the tag terminator.
func ValidNonceSyntax(value []byte) bool {
	for _, b := range value {
		if b < 0x20 || b > 0x7e || b == ';' {
			return false
		}
	}
	return true
}

// splitCommaList splits a non-empty DKIM2 comma list without interpreting values.
func splitCommaList(input []byte) [][]byte {
	if len(input) == 0 {
		return nil
	}

	return bytes.Split(input, []byte{','})
}

// trimWSP removes DKIM2-permitted surrounding space and tab bytes.
func trimWSP(input []byte) ([]byte, int) {
	start := 0
	for start < len(input) && isWSP(input[start]) {
		start++
	}

	end := len(input)
	for end > start && isWSP(input[end-1]) {
		end--
	}

	return input[start:end], start
}

// isWSP reports whether b is RFC 5322 white space allowed around components.
func isWSP(b byte) bool {
	return b == ' ' || b == '\t'
}

// canonicalTokenName validates and lowercases an algorithm or flag token.
func canonicalTokenName(input []byte) (string, bool) {
	if len(input) == 0 {
		return "", false
	}

	output := make([]byte, len(input))
	for i, b := range input {
		if b >= 'A' && b <= 'Z' {
			output[i] = b + ('a' - 'A')
			continue
		}
		if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' || b == '-' {
			output[i] = b
			continue
		}

		return "", false
	}

	return string(output), true
}
