package signature

import (
	"bytes"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/croessner/dkim2/internal/domainname"
	"github.com/croessner/dkim2/internal/tagvalue"
)

// MaxEnvelopePathBytes is the RFC 5321 maximum path length including brackets.
const MaxEnvelopePathBytes = 256

// ValidEnvelopePath reports whether exact path bytes satisfy the shared SMTP path contract.
func ValidEnvelopePath(path []byte, allowNull bool) bool { return validEnvelopePath(path, allowNull) }

// CanonicalEnvelopePath validates and clones a path for comparison: every
// grammar-owned ASCII domain is case-folded and the mailbox domain is mapped
// from U-labels to lowercase A-labels (Draft-08 Section 18). Local parts are
// never changed.
func CanonicalEnvelopePath(path []byte, allowNull bool) ([]byte, bool) {
	return canonicalEnvelopePath(path, allowNull)
}

// RecordableEnvelopePath validates a caller-supplied SMTP path and returns the
// bytes a signer records in mf= or rt=. Draft-08 Section 18 requires U-label
// mailbox domains to be recorded as A-labels, so such a domain is replaced by
// its lowercase A-label form; every other path keeps its exact bytes.
func RecordableEnvelopePath(path []byte, allowNull bool) ([]byte, bool) {
	parts, valid := parseEnvelopeParts(path, allowNull)
	if !valid {
		return nil, false
	}
	if parts.null || parts.literal || domainname.IsASCII(path[parts.domainStart:parts.domainEnd]) {
		return bytes.Clone(path), true
	}
	return parts.render(path, false)
}

// CanonicalEnvelopeDomain returns the canonical DNS mailbox domain from one
// validated SMTP path. It rejects null paths and address literals because they
// do not provide a DNS identity suitable for domain-bound protocol checks.
func CanonicalEnvelopeDomain(path []byte, allowNull bool) (string, bool) {
	canonical, valid := canonicalEnvelopePath(path, allowNull)
	if !valid || len(canonical) < 4 {
		return "", false
	}
	mailbox := canonical[1 : len(canonical)-1]
	if len(mailbox) == 0 {
		return "", false
	}
	if mailbox[0] == '@' {
		separator := bytes.IndexByte(mailbox, ':')
		if separator <= 1 || separator == len(mailbox)-1 {
			return "", false
		}
		mailbox = mailbox[separator+1:]
	}
	domainStart, valid := smtpMailboxDomainStart(mailbox)
	if !valid || domainStart >= len(mailbox) {
		return "", false
	}
	return canonicalDNSName(mailbox[domainStart:])
}

// parseEnvelopePath decodes and checks one base64-wrapped SMTP path.
func parseEnvelopePath(value string, limits tagvalue.Limits, fieldIndex int, recipientIndex int, tagName string) (EnvelopePath, error) {
	parsed, err := tagvalue.ParseBase64String([]byte(value), limits)
	if err != nil {
		return EnvelopePath{}, newError(ErrorCodeInvalidEnvelopeBase64, ErrorLocation{FieldIndex: fieldIndex, RecipientIndex: recipientIndex}, ErrorDetails{
			TagName: TagName(tagName),
		}, err)
	}

	decoded := parsed.Decoded()
	if !validRecordedEnvelopePath(decoded, tagName == "mf") {
		return EnvelopePath{}, newError(ErrorCodeInvalidEnvelopePath, ErrorLocation{FieldIndex: fieldIndex, RecipientIndex: recipientIndex}, ErrorDetails{
			TagName: TagName(tagName),
		}, nil)
	}

	return EnvelopePath{
		value:     bytes.Clone(decoded),
		container: parsed,
	}, nil
}

// parseRecipientPaths parses comma-separated rt= base64-wrapped forward paths.
func parseRecipientPaths(value string, limits Limits, fieldIndex int) ([]EnvelopePath, error) {
	parts := splitCommaList([]byte(value))
	if len(parts) == 0 {
		return nil, malformedRecipientListError(fieldIndex)
	}
	if len(parts) > limits.MaxRecipients {
		return nil, newError(ErrorCodeLimitExceeded, ErrorLocation{FieldIndex: fieldIndex}, ErrorDetails{
			Class:     ErrorClassLimit,
			TagName:   "rt",
			LimitName: "max_recipients",
			Limit:     limits.MaxRecipients,
			Count:     len(parts),
		}, nil)
	}

	paths := make([]EnvelopePath, 0, len(parts))
	for i, part := range parts {
		trimmed, _ := trimWSP(part)
		if len(trimmed) == 0 {
			return nil, malformedRecipientListError(fieldIndex)
		}

		path, err := parseEnvelopePath(string(trimmed), limits.TagLimits, fieldIndex, i, "rt")
		if err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}

	return paths, nil
}

// validEnvelopePath checks RFC 5321 reverse-path or forward-path syntax with
// the RFC 6531 UTF-8 extensions for local parts and U-label domains.
func validEnvelopePath(path []byte, allowNull bool) bool {
	_, valid := parseEnvelopeParts(path, allowNull)
	return valid
}

// validRecordedEnvelopePath checks a path recorded in a DKIM2-Signature. Its
// mailbox domain must already be ASCII because Draft-08 Section 18 requires
// signers to record A-labels; recorded U-labels fail closed.
func validRecordedEnvelopePath(path []byte, allowNull bool) bool {
	parts, valid := parseEnvelopeParts(path, allowNull)
	return valid && (parts.null || domainname.IsASCII(path[parts.domainStart:parts.domainEnd]))
}

// canonicalEnvelopePath owns SMTP path parsing, case-insensitive Domain
// normalization, and U-label to A-label mapping for comparisons.
func canonicalEnvelopePath(path []byte, allowNull bool) ([]byte, bool) {
	parts, valid := parseEnvelopeParts(path, allowNull)
	if !valid {
		return nil, false
	}
	if parts.null {
		return bytes.Clone(path), true
	}
	return parts.render(path, true)
}

// envelopeParts records the validated grammar positions of one SMTP path.
type envelopeParts struct {
	null        bool
	literal     bool
	routeEnd    int
	domainStart int
	domainEnd   int
	asciiDomain string
}

// parseEnvelopeParts validates one bracketed path and locates its source
// route and mailbox domain. A non-literal mailbox domain is converted once to
// its lowercase A-label form.
func parseEnvelopeParts(path []byte, allowNull bool) (envelopeParts, bool) {
	if len(path) < 2 || len(path) > MaxEnvelopePathBytes || path[0] != '<' || path[len(path)-1] != '>' {
		return envelopeParts{}, false
	}
	inner := path[1 : len(path)-1]
	if len(inner) == 0 {
		return envelopeParts{null: true}, allowNull
	}
	mailboxOffset := 1
	routeEnd := 0
	if inner[0] == '@' {
		separator := bytes.IndexByte(inner, ':')
		if separator <= 1 || !validSourceRoute(inner[:separator]) {
			return envelopeParts{}, false
		}
		routeEnd = 1 + separator
		mailboxOffset += separator + 1
		inner = inner[separator+1:]
	}

	domainStart, valid := smtpMailboxDomainStart(inner)
	if !valid {
		return envelopeParts{}, false
	}
	parts := envelopeParts{
		routeEnd:    routeEnd,
		domainStart: mailboxOffset + domainStart,
		domainEnd:   len(path) - 1,
	}
	domain := path[parts.domainStart:parts.domainEnd]
	if domain[0] == '[' {
		parts.literal = true
		return parts, true
	}
	parts.asciiDomain, valid = domainname.ToASCII(domain)
	return parts, valid
}

// render rebuilds the path with the A-label mailbox domain. When foldRoute is
// true, the obsolete source route is case-folded as well, which is the
// comparison form; the recording form keeps route bytes unchanged.
func (p envelopeParts) render(path []byte, foldRoute bool) ([]byte, bool) {
	output := make([]byte, 0, len(path)+len(p.asciiDomain))
	output = append(output, path[:p.domainStart]...)
	if foldRoute && p.routeEnd > 1 {
		lowerASCIILetters(output[1:p.routeEnd])
	}
	if p.literal {
		literal := bytes.Clone(path[p.domainStart:p.domainEnd])
		lowerASCIILetters(literal)
		output = append(output, literal...)
	} else {
		output = append(output, p.asciiDomain...)
	}
	output = append(output, '>')
	if len(output) > MaxEnvelopePathBytes {
		return nil, false
	}
	return output, true
}

// validSourceRoute checks the obsolete A-d-l syntax that RFC 5321 requires
// receivers to accept. Source-route domains are deliberately ASCII-only: the
// route is never a DKIM2 identity, and Draft-08 Section 18 conversion applies
// only to the mailbox domain.
func validSourceRoute(route []byte) bool {
	parts := bytes.Split(route, []byte{','})
	for _, part := range parts {
		if len(part) < 2 || part[0] != '@' || !validSMTPDomain(part[1:]) {
			return false
		}
	}

	return len(parts) > 0
}

// smtpMailboxDomainStart validates one mailbox local part and address
// literal and locates its grammar-owned Domain. A DNS domain is validated
// once by the caller: parseEnvelopeParts converts it with domainname.ToASCII
// and CanonicalEnvelopeDomain re-checks the already canonical A-label form.
func smtpMailboxDomainStart(mailbox []byte) (int, bool) {
	localEnd, ok := smtpLocalPartEnd(mailbox)
	if !ok || localEnd >= len(mailbox) || mailbox[localEnd] != '@' {
		return 0, false
	}
	local := mailbox[:localEnd]
	domain := mailbox[localEnd+1:]
	if len(local) > 64 || len(domain) == 0 || len(domain) > 255 {
		return 0, false
	}
	if domain[0] == '[' {
		return localEnd + 1, validAddressLiteral(domain)
	}

	return localEnd + 1, utf8.Valid(local)
}

// smtpLocalPartEnd returns the byte immediately after an RFC 5321 Dot-string or Quoted-string.
func smtpLocalPartEnd(mailbox []byte) (int, bool) {
	if len(mailbox) == 0 {
		return 0, false
	}
	if mailbox[0] == '"' {
		for i := 1; i < len(mailbox); i++ {
			b := mailbox[i]
			if b == '"' {
				return i + 1, true
			}
			if b == '\\' {
				i++
				if i >= len(mailbox) || mailbox[i] < 32 || mailbox[i] > 126 {
					return 0, false
				}
				continue
			}
			if !isSMTPQuotedText(b) && b < utf8.RuneSelf {
				return 0, false
			}
		}

		return 0, false
	}

	separator := bytes.IndexByte(mailbox, '@')
	if separator <= 0 || !validDotString(mailbox[:separator]) {
		return 0, false
	}

	return separator, true
}

// validDotString checks one or more non-empty RFC 5321 Atom components.
func validDotString(local []byte) bool {
	for atom := range bytes.SplitSeq(local, []byte{'.'}) {
		if len(atom) == 0 {
			return false
		}
		for _, b := range atom {
			if !isSMTPAtext(b) {
				return false
			}
		}
	}

	return len(local) > 0
}

// isSMTPAtext reports whether b is an RFC 5322 atext byte imported by RFC
// 5321, extended by RFC 6531 with UTF-8 non-ASCII bytes whose sequence
// validity is checked for the whole local part.
func isSMTPAtext(b byte) bool {
	if b >= utf8.RuneSelf {
		return true
	}
	if isASCIILetter(b) || isASCIIDigit(b) {
		return true
	}

	return bytes.ContainsRune([]byte("!#$%&'*+-/=?^_`{|}~"), rune(b))
}

// isSMTPQuotedText reports whether b is unescaped RFC 5321 qtextSMTP.
func isSMTPQuotedText(b byte) bool {
	return b >= 32 && b <= 33 || b >= 35 && b <= 91 || b >= 93 && b <= 126
}

// validSMTPDomain checks RFC 5321 sub-domain syntax and DNS label bounds.
func validSMTPDomain(domain []byte) bool {
	if len(domain) == 0 || len(domain) > 255 {
		return false
	}
	for label := range bytes.SplitSeq(domain, []byte{'.'}) {
		if len(label) == 0 || len(label) > 63 || !isASCIILetterOrDigit(label[0]) || !isASCIILetterOrDigit(label[len(label)-1]) {
			return false
		}
		if len(label) > 2 {
			for _, b := range label[1 : len(label)-1] {
				if !isASCIILetterOrDigit(b) && b != '-' {
					return false
				}
			}
		}
	}

	return true
}

// validAddressLiteral checks IPv4, IPv6, and General-address-literal syntax.
func validAddressLiteral(domain []byte) bool {
	if len(domain) < 3 || domain[0] != '[' || domain[len(domain)-1] != ']' {
		return false
	}
	content := domain[1 : len(domain)-1]
	if validIPv4AddressLiteral(content) {
		return true
	}
	if len(content) > len("IPv6:") && strings.EqualFold(string(content[:len("IPv6:")]), "IPv6:") {
		address, err := netip.ParseAddr(string(content[len("IPv6:"):]))

		return err == nil && address.Is6()
	}

	separator := bytes.IndexByte(content, ':')
	return separator > 0 && validStandardizedTag(content[:separator]) && validGeneralAddressContent(content[separator+1:])
}

// validIPv4AddressLiteral checks four RFC 5321 Snum decimal components.
func validIPv4AddressLiteral(input []byte) bool {
	parts := bytes.Split(input, []byte{'.'})
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		value := 0
		for _, b := range part {
			if !isASCIIDigit(b) {
				return false
			}
			value = value*10 + int(b-'0')
		}
		if value > 255 {
			return false
		}
	}

	return true
}

// validStandardizedTag checks the RFC 5321 Ldh-str form used by general literals.
func validStandardizedTag(tag []byte) bool {
	if len(tag) == 0 || !isASCIILetterOrDigit(tag[len(tag)-1]) {
		return false
	}
	for _, b := range tag[:len(tag)-1] {
		if !isASCIILetterOrDigit(b) && b != '-' {
			return false
		}
	}

	return true
}

// validGeneralAddressContent checks one or more RFC 5321 dcontent bytes.
func validGeneralAddressContent(content []byte) bool {
	if len(content) == 0 {
		return false
	}
	for _, b := range content {
		if b < 33 || b > 90 && b < 94 || b > 126 {
			return false
		}
	}

	return true
}

// lowerASCIILetters folds only ASCII alphabetic bytes in one grammar-owned Domain span.
func lowerASCIILetters(value []byte) {
	for index, item := range value {
		if item >= 'A' && item <= 'Z' {
			value[index] = item + ('a' - 'A')
		}
	}
}

// isASCIILetterOrDigit reports whether b is an ASCII letter or digit.
func isASCIILetterOrDigit(b byte) bool {
	return isASCIILetter(b) || isASCIIDigit(b)
}

// isASCIILetter reports whether b is an ASCII alphabetic byte.
func isASCIILetter(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}

// isASCIIDigit reports whether b is an ASCII decimal digit.
func isASCIIDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// malformedRecipientListError constructs a bounded rt= syntax failure.
func malformedRecipientListError(fieldIndex int) *Error {
	return newError(ErrorCodeInvalidEnvelopePath, ErrorLocation{FieldIndex: fieldIndex}, ErrorDetails{
		TagName: "rt",
	}, nil)
}
