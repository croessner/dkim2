package keyresolver

// dkim1Version is the exact v= value of DNS key records (DNS-02) and Domain
// Policy Records (Draft-09 Section 3.8).
const dkim1Version = "DKIM1"

// leadingVersion reports the value of the first tag-spec of one TXT payload
// when that tag is v=, with surrounding WSP removed per Draft-09 Section 8.
// Only the first tag-spec is inspected, so malformed text after it cannot
// change the classification; a payload whose first tag is not v= (or whose
// first tag-spec has no "=") reports false.
func leadingVersion(payload []byte) (string, bool) {
	index := skipTXTWhitespace(payload, 0)
	if index >= len(payload) || payload[index] != 'v' {
		return "", false
	}
	index = skipTXTWhitespace(payload, index+1)
	if index >= len(payload) || payload[index] != '=' {
		return "", false
	}
	start := skipTXTWhitespace(payload, index+1)
	end := start
	for end < len(payload) && payload[end] != ';' {
		end++
	}
	for end > start && isTXTWhitespace(payload[end-1]) {
		end--
	}
	return string(payload[start:end]), true
}

// foreignVersionRecord reports whether a TXT payload begins with a v= tag
// whose value is not DKIM1. Draft-09 Sections 3.7 and 3.8 ignore such records
// before deciding that more than one record remains.
func foreignVersionRecord(payload []byte) bool {
	version, ok := leadingVersion(payload)
	return ok && version != dkim1Version
}

// skipTXTWhitespace advances over space and tab bytes from index.
func skipTXTWhitespace(payload []byte, index int) int {
	for index < len(payload) && isTXTWhitespace(payload[index]) {
		index++
	}
	return index
}

// isTXTWhitespace reports whether b is the WSP admitted around tag-list tokens.
func isTXTWhitespace(b byte) bool { return b == ' ' || b == '\t' }
