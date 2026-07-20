package signature

import (
	"bytes"
	"net/netip"
	"strings"

	"github.com/croessner/dkim2/internal/tagvalue"
)

// MaxEnvelopePathBytes is the RFC 5321 maximum path length including brackets.
const MaxEnvelopePathBytes = 256

// ValidEnvelopePath reports whether exact path bytes satisfy the shared SMTP path contract.
func ValidEnvelopePath(path []byte, allowNull bool) bool { return validEnvelopePath(path, allowNull) }

// parseEnvelopePath decodes and checks one base64-wrapped SMTP path.
func parseEnvelopePath(value string, limits tagvalue.Limits, fieldIndex int, recipientIndex int, tagName string) (EnvelopePath, error) {
	parsed, err := tagvalue.ParseBase64String([]byte(value), limits)
	if err != nil {
		return EnvelopePath{}, newError(ErrorCodeInvalidEnvelopeBase64, ErrorLocation{FieldIndex: fieldIndex, RecipientIndex: recipientIndex}, ErrorDetails{
			TagName: TagName(tagName),
		}, err)
	}

	decoded := parsed.Decoded()
	if !validEnvelopePath(decoded, tagName == "mf") {
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

// validEnvelopePath checks RFC 5321 reverse-path or forward-path syntax.
func validEnvelopePath(path []byte, allowNull bool) bool {
	if len(path) < 2 || len(path) > MaxEnvelopePathBytes || path[0] != '<' || path[len(path)-1] != '>' {
		return false
	}
	inner := path[1 : len(path)-1]
	if len(inner) == 0 {
		return allowNull
	}
	if inner[0] == '@' {
		separator := bytes.IndexByte(inner, ':')
		if separator <= 1 || !validSourceRoute(inner[:separator]) {
			return false
		}
		inner = inner[separator+1:]
	}

	return validSMTPMailbox(inner)
}

// validSourceRoute checks the obsolete A-d-l syntax that RFC 5321 requires receivers to accept.
func validSourceRoute(route []byte) bool {
	parts := bytes.Split(route, []byte{','})
	for _, part := range parts {
		if len(part) < 2 || part[0] != '@' || !validSMTPDomain(part[1:]) {
			return false
		}
	}

	return len(parts) > 0
}

// validSMTPMailbox checks Local-part followed by Domain or address-literal.
func validSMTPMailbox(mailbox []byte) bool {
	localEnd, ok := smtpLocalPartEnd(mailbox)
	if !ok || localEnd >= len(mailbox) || mailbox[localEnd] != '@' {
		return false
	}
	local := mailbox[:localEnd]
	domain := mailbox[localEnd+1:]
	if len(local) > 64 || len(domain) == 0 || len(domain) > 255 {
		return false
	}
	if domain[0] == '[' {
		return validAddressLiteral(domain)
	}

	return validSMTPDomain(domain)
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
			if !isSMTPQuotedText(b) {
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
	for _, atom := range bytes.Split(local, []byte{'.'}) {
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

// isSMTPAtext reports whether b is an ASCII RFC 5322 atext byte imported by RFC 5321.
func isSMTPAtext(b byte) bool {
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
	for _, label := range bytes.Split(domain, []byte{'.'}) {
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
