package adapter

import (
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

const authenticationResultsName = "Authentication-Results"

// LocalAuthenticationResultOccurrences returns descending RFC 8601 removal
// occurrences for untrusted fields claiming the configured local authority.
func LocalAuthenticationResultOccurrences(headers [][]byte, authservID string) []uint16 {
	if authservID == "" || !validAuthservID(authservID) {
		return nil
	}
	occurrence := uint16(0)
	var matches []uint16
	for _, header := range headers {
		name, value, ok := splitHeader(header)
		if !ok || !strings.EqualFold(name, authenticationResultsName) {
			continue
		}
		occurrence++
		claimed, claimedOK := leadingAuthservID(unfoldHeaderValue(value))
		if claimedOK && equivalentAuthservID(claimed, authservID) {
			matches = append(matches, occurrence)
		}
	}
	for left, right := 0, len(matches)-1; left < right; left, right = left+1, right-1 {
		matches[left], matches[right] = matches[right], matches[left]
	}
	return matches
}

// splitHeader separates one already-admitted Exim LF header field.
func splitHeader(header []byte) (string, []byte, bool) {
	if len(header) < 3 || header[len(header)-1] != '\n' {
		return "", nil, false
	}
	separator := 0
	for separator < len(header)-1 && header[separator] != ':' {
		if header[separator] <= ' ' || header[separator] >= 127 {
			return "", nil, false
		}
		separator++
	}
	if separator == 0 || separator == len(header)-1 {
		return "", nil, false
	}
	return string(header[:separator]), header[separator+1 : len(header)-1], true
}

// unfoldHeaderValue removes only legal Exim LF folding delimiters.
func unfoldHeaderValue(value []byte) string {
	output := make([]byte, 0, len(value))
	for index := 0; index < len(value); index++ {
		if value[index] == '\n' && index+1 < len(value) &&
			(value[index+1] == ' ' || value[index+1] == '\t') {
			continue
		}
		output = append(output, value[index])
	}
	return string(output)
}

// equivalentAuthservID compares canonical A-label/U-label representations at
// the report trust boundary without changing SMTP envelope authority.
func equivalentAuthservID(claimed, local string) bool {
	if !utf8.ValidString(claimed) || !utf8.ValidString(local) {
		return false
	}
	profile := authservIDNAProfile()
	claimedASCII, claimedErr := profile.ToASCII(claimed)
	localASCII, localErr := profile.ToASCII(local)
	if claimedErr != nil || localErr != nil {
		return false
	}
	claimedUnicode, claimedErr := profile.ToUnicode(claimedASCII)
	localUnicode, localErr := profile.ToUnicode(localASCII)
	return claimedErr == nil && localErr == nil &&
		strings.EqualFold(claimedUnicode, localUnicode)
}

// leadingAuthservID extracts an RFC 8601 authserv-id after bounded CFWS.
func leadingAuthservID(value string) (string, bool) {
	index, ok := skipCFWS(value, 0)
	if !ok || index >= len(value) {
		return "", false
	}
	if value[index] == '"' {
		var output strings.Builder
		for index++; index < len(value); index++ {
			switch value[index] {
			case '\\':
				index++
				if index >= len(value) {
					return "", false
				}
				output.WriteByte(value[index])
			case '"':
				return output.String(), output.Len() != 0
			case '\r', '\n':
				return "", false
			default:
				output.WriteByte(value[index])
			}
		}
		return "", false
	}
	start := index
	for index < len(value) {
		current := value[index]
		if current == ' ' || current == '\t' || current == '(' || current == ';' {
			break
		}
		if current < 33 || current == 127 {
			return "", false
		}
		index++
	}
	claimed := value[start:index]
	return claimed, claimed != "" && utf8.ValidString(claimed)
}

// skipCFWS skips RFC 5322 whitespace and nested comments without retaining it.
func skipCFWS(value string, index int) (int, bool) {
	for index < len(value) {
		switch value[index] {
		case ' ', '\t':
			index++
		case '(':
			depth := 1
			index++
			for index < len(value) && depth > 0 {
				switch value[index] {
				case '\\':
					index += 2
				case '(':
					depth++
					index++
				case ')':
					depth--
					index++
				case '\r', '\n':
					return 0, false
				default:
					index++
				}
			}
			if depth != 0 {
				return 0, false
			}
		default:
			return index, true
		}
	}
	return index, true
}

// validAuthservID admits the canonical administrative domain configured locally.
func validAuthservID(value string) bool {
	if value == "" || value != strings.ToLower(value) || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

// authservIDNAProfile constructs the strict stateless RFC 5890 comparison profile.
func authservIDNAProfile() *idna.Profile {
	return idna.New(
		idna.ValidateForRegistration(), idna.BidiRule(), idna.CheckHyphens(true),
		idna.CheckJoiners(true), idna.StrictDomainName(true), idna.ValidateLabels(true),
		idna.VerifyDNSLength(true),
	)
}
