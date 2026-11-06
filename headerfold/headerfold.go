// Package headerfold restores the fold points of daemon-projected DKIM2 header
// field values for adapters that write header fields themselves.
//
// The dkim2d REST projection removes every CRLF of a library-rendered field
// but keeps the whitespace that followed it. The library's frozen field grammar
// emits a TAB only directly after such a CRLF, so every TAB after the first
// value octet marks one original fold point. The package lives in the library
// because the library is the only module both adapters share. Adapters that hand fields to an MTA must
// restore those line breaks: a DKIM2-Signature with a large RSA set or many
// recipients is several kilobytes long and would otherwise exceed the RFC 5322
// line limit.
package headerfold

import "strings"

// MaxLineOctets is the RFC 5322 physical line limit without the line ending.
const MaxLineOctets = 998

// Restore returns value with an LF line break before every TAB that follows
// other content, the LF-terminated folded form that Postfix Milter replies and
// Exim transport filters expect. A TAB at the very start is post-colon
// whitespace, not a fold point, and is kept byte-exact. Values without such a
// TAB are returned unchanged.
func Restore(value string) string {
	if value == "" {
		return value
	}
	return value[:1] + strings.ReplaceAll(value[1:], "\t", "\n\t")
}

// WithinLineLimit reports whether every physical line of a folded field,
// counting "name:" on the first line, fits the RFC 5322 line limit.
func WithinLineLimit(name, folded string) bool {
	first := true
	for line := range strings.SplitSeq(folded, "\n") {
		length := len(line)
		if first {
			length += len(name) + 1
			first = false
		}
		if length > MaxLineOctets {
			return false
		}
	}
	return true
}
