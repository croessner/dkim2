package signature

import "bytes"

const maxDomainNameBytes = 253
const maxDomainLabelBytes = 63

// parseDomain validates and canonicalizes an ASCII d= or nd= domain.
func parseDomain(value string, fieldIndex int, tagName string) (string, error) {
	domain, ok := canonicalDNSName([]byte(value))
	if !ok {
		return "", newError(ErrorCodeInvalidDomain, ErrorLocation{FieldIndex: fieldIndex}, ErrorDetails{
			TagName: TagName(tagName),
		}, nil)
	}

	return domain, nil
}

// canonicalDNSName lowercases a parser-level DNS name after label validation.
func canonicalDNSName(input []byte) (string, bool) {
	if len(input) == 0 || len(input) > maxDomainNameBytes || input[0] == '.' || input[len(input)-1] == '.' {
		return "", false
	}

	output := bytes.Clone(input)
	labelStart := 0
	for i := 0; i <= len(input); i++ {
		if i != len(input) && input[i] != '.' {
			continue
		}
		if !validDNSLabel(output[labelStart:i]) {
			return "", false
		}
		labelStart = i + 1
	}

	return string(output), true
}

// validDNSLabel validates one ASCII DNS label and lowercases it in place.
func validDNSLabel(label []byte) bool {
	if len(label) == 0 || len(label) > maxDomainLabelBytes {
		return false
	}
	for i, b := range label {
		if b >= 'A' && b <= 'Z' {
			label[i] = b + ('a' - 'A')
			b = label[i]
		}
		if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') {
			continue
		}
		if b == '-' && i > 0 && i < len(label)-1 {
			continue
		}

		return false
	}

	return true
}
