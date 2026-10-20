package tagvalue

// ParseTextstring validates one already-trimmed Draft-07 Section 2.14
// textstring value (1*ALPHADIGITD) and returns it unchanged. Textstring values
// such as hash algorithm, signature algorithm, and flag names are
// case-sensitive, so no case folding is applied: "SHA256" and "sha256" are
// different names.
func ParseTextstring(input []byte) (string, bool) {
	if len(input) == 0 {
		return "", false
	}
	for _, b := range input {
		if !isASCIILetter(b) && !isASCIIDigit(b) && b != '-' && b != '_' {
			return "", false
		}
	}

	return string(input), true
}
