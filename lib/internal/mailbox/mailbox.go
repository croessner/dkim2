// Package mailbox owns bounded parsing of RFC 5322 author address lists for
// DKIM2 From authenticity (Draft-08 Section 11).
//
// The parser accepts the RFC 5322 address-list grammar with the RFC 6854 group
// update and the RFC 6532 UTF-8 extensions: display names, comments, folding
// white space, quoted local parts, obsolete dotted phrases and local parts, and
// groups. It does not decode encoded words, rewrite bytes, or normalize local
// parts. Obsolete route syntax inside angle addresses and empty list elements
// are rejected as unsupported. Callers receive the flattened mailbox count and,
// for exactly one mailbox, its local part and A-label domain.
package mailbox

import (
	"unicode/utf8"

	"github.com/croessner/dkim2/internal/domainname"
)

const (
	// MaxValueBytes bounds one unfolded author field value.
	MaxValueBytes = 16 * 1024
	maxMailboxes  = 128
	maxComments   = 32
)

// Status classifies one author field value.
type Status string

const (
	// StatusSingle reports exactly one mailbox with a DNS domain.
	StatusSingle Status = "single"
	// StatusMalformed reports syntax outside the supported grammar.
	StatusMalformed Status = "malformed"
	// StatusNoMailbox reports a syntactically valid value without any mailbox,
	// such as an empty group.
	StatusNoMailbox Status = "no_mailbox"
	// StatusMultiple reports more than one mailbox after flattening groups.
	StatusMultiple Status = "multiple"
	// StatusDomainLiteral reports a single mailbox whose domain is a literal.
	StatusDomainLiteral Status = "domain_literal"
	// StatusInvalidDomain reports a single mailbox whose domain is not a valid
	// IDNA2008 DNS name.
	StatusInvalidDomain Status = "invalid_domain"
)

// Author is the single parsed author mailbox.
type Author struct {
	localPart string
	domain    string
	inGroup   bool
	ascii     bool
}

// LocalPart returns the local part exactly as written, including quotes.
func (a Author) LocalPart() string { return a.localPart }

// Domain returns the lowercase A-label DNS domain.
func (a Author) Domain() string { return a.domain }

// InGroup reports whether the mailbox was written inside RFC 6854 group syntax.
func (a Author) InGroup() bool { return a.inGroup }

// ASCII reports whether the written local part and domain were pure ASCII.
func (a Author) ASCII() bool { return a.ascii }

// ParseAuthor parses one unfolded From field value and classifies it. Only
// StatusSingle returns a usable Author.
func ParseAuthor(value []byte) (Author, Status) {
	if len(value) == 0 || len(value) > MaxValueBytes || !utf8.Valid(value) {
		return Author{}, StatusMalformed
	}
	tokens, ok := tokenize(value)
	if !ok || len(tokens) == 0 {
		return Author{}, StatusMalformed
	}
	parser := listParser{tokens: tokens}
	mailboxes, ok := parser.addressList()
	if !ok {
		return Author{}, StatusMalformed
	}
	switch {
	case len(mailboxes) == 0:
		return Author{}, StatusNoMailbox
	case len(mailboxes) > 1:
		return Author{}, StatusMultiple
	}
	parsed := mailboxes[0]
	if parsed.literal {
		return Author{}, StatusDomainLiteral
	}
	domain, valid := domainname.ToASCII([]byte(parsed.domain))
	if !valid {
		return Author{}, StatusInvalidDomain
	}
	return Author{
		localPart: parsed.local,
		domain:    domain,
		inGroup:   parsed.inGroup,
		ascii:     asciiString(parsed.local) && asciiString(parsed.domain),
	}, StatusSingle
}

// tokenKind identifies one lexical element after CFWS removal.
type tokenKind uint8

const (
	tokenAtom tokenKind = iota + 1
	tokenQuoted
	tokenLiteral
	tokenSpecial
)

// token is one lexical element. text holds the exact source bytes for atoms,
// quoted strings (with quotes), and domain literals, or the special byte.
type token struct {
	kind tokenKind
	text string
}

// tokenize splits an unfolded value into atoms, quoted strings, domain
// literals, and specials while skipping white space and comments.
func tokenize(value []byte) ([]token, bool) {
	tokens := make([]token, 0, 16)
	comments := 0
	for index := 0; index < len(value); {
		b := value[index]
		switch {
		case b == ' ' || b == '\t':
			index++
		case b == '(':
			comments++
			end, ok := skipComment(value, index)
			if !ok || comments > maxComments {
				return nil, false
			}
			index = end
		case b == '"':
			end, ok := scanQuoted(value, index)
			if !ok {
				return nil, false
			}
			tokens = append(tokens, token{kind: tokenQuoted, text: string(value[index:end])})
			index = end
		case b == '[':
			end, ok := scanLiteral(value, index)
			if !ok {
				return nil, false
			}
			tokens = append(tokens, token{kind: tokenLiteral, text: string(value[index:end])})
			index = end
		case isSpecial(b):
			tokens = append(tokens, token{kind: tokenSpecial, text: string(b)})
			index++
		case isAtext(b):
			start := index
			for index < len(value) && isAtext(value[index]) {
				index++
			}
			tokens = append(tokens, token{kind: tokenAtom, text: string(value[start:index])})
		default:
			return nil, false
		}
	}
	return tokens, true
}

// skipComment returns the index after one possibly nested RFC 5322 comment.
func skipComment(value []byte, start int) (int, bool) {
	depth := 0
	for index := start; index < len(value); index++ {
		switch b := value[index]; {
		case b == '\\':
			index++
			if index >= len(value) || !quotedPairByte(value[index]) {
				return 0, false
			}
		case b == '(':
			depth++
			if depth > maxComments {
				return 0, false
			}
		case b == ')':
			depth--
			if depth == 0 {
				return index + 1, true
			}
		case b < 0x20 && b != '\t' || b == 0x7f:
			return 0, false
		}
	}
	return 0, false
}

// scanQuoted returns the index after one RFC 5322 quoted-string.
func scanQuoted(value []byte, start int) (int, bool) {
	for index := start + 1; index < len(value); index++ {
		switch b := value[index]; {
		case b == '\\':
			index++
			if index >= len(value) || !quotedPairByte(value[index]) {
				return 0, false
			}
		case b == '"':
			return index + 1, true
		case b < 0x20 && b != '\t' || b == 0x7f:
			return 0, false
		}
	}
	return 0, false
}

// scanLiteral returns the index after one RFC 5322 domain-literal.
func scanLiteral(value []byte, start int) (int, bool) {
	for index := start + 1; index < len(value); index++ {
		switch b := value[index]; {
		case b == ']':
			return index + 1, true
		case b == '[' || b == '\\' || b < 0x20 && b != '\t' || b == 0x7f:
			return 0, false
		}
	}
	return 0, false
}

// quotedPairByte reports whether b may follow a backslash (VCHAR or WSP).
func quotedPairByte(b byte) bool {
	return b == ' ' || b == '\t' || b >= 0x21 && b != 0x7f
}

// isSpecial reports whether b is an RFC 5322 special handled as a token.
func isSpecial(b byte) bool {
	switch b {
	case '<', '>', ':', ';', '@', ',', '.':
		return true
	default:
		return false
	}
}

// isAtext reports whether b is RFC 5322 atext or an RFC 6532 UTF-8 byte.
func isAtext(b byte) bool {
	if b >= utf8.RuneSelf {
		return true
	}
	if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
		return true
	}
	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~':
		return true
	default:
		return false
	}
}

// parsedMailbox is one mailbox found while parsing an address list.
type parsedMailbox struct {
	local   string
	domain  string
	literal bool
	inGroup bool
}

// listParser is a recursive-descent parser over the token sequence.
type listParser struct {
	tokens []token
	pos    int
}

// addressList parses address *("," address) and flattens groups.
func (p *listParser) addressList() ([]parsedMailbox, bool) {
	var mailboxes []parsedMailbox
	for {
		found, ok := p.address()
		if !ok {
			return nil, false
		}
		mailboxes = append(mailboxes, found...)
		if len(mailboxes) > maxMailboxes {
			return nil, false
		}
		if p.done() {
			return mailboxes, true
		}
		if !p.consumeSpecial(',') {
			return nil, false
		}
	}
}

// address parses one mailbox or one group.
func (p *listParser) address() ([]parsedMailbox, bool) {
	start := p.pos
	if p.phrase() && p.consumeSpecial(':') {
		mailboxes, ok := p.groupList()
		return mailboxes, ok
	}
	p.pos = start
	mailbox, ok := p.mailbox(false)
	if !ok {
		return nil, false
	}
	return []parsedMailbox{mailbox}, true
}

// groupList parses an optional mailbox-list followed by the closing ";".
func (p *listParser) groupList() ([]parsedMailbox, bool) {
	var mailboxes []parsedMailbox
	if p.consumeSpecial(';') {
		return mailboxes, true
	}
	for {
		mailbox, ok := p.mailbox(true)
		if !ok {
			return nil, false
		}
		mailboxes = append(mailboxes, mailbox)
		if len(mailboxes) > maxMailboxes {
			return nil, false
		}
		if p.consumeSpecial(';') {
			return mailboxes, true
		}
		if !p.consumeSpecial(',') {
			return nil, false
		}
	}
}

// mailbox parses name-addr or addr-spec.
func (p *listParser) mailbox(inGroup bool) (parsedMailbox, bool) {
	start := p.pos
	p.phrase()
	if p.consumeSpecial('<') {
		parsed, ok := p.addrSpec()
		if !ok || !p.consumeSpecial('>') {
			return parsedMailbox{}, false
		}
		parsed.inGroup = inGroup
		return parsed, true
	}
	p.pos = start
	parsed, ok := p.addrSpec()
	parsed.inGroup = inGroup
	return parsed, ok
}

// phrase consumes a display name: one or more words, with obsolete dots
// permitted after the first word. It reports whether any word was consumed.
func (p *listParser) phrase() bool {
	if !p.word() {
		return false
	}
	more := true
	for more {
		more = p.word() || p.consumeSpecial('.')
	}
	return true
}

// addrSpec parses local-part "@" domain.
func (p *listParser) addrSpec() (parsedMailbox, bool) {
	local, ok := p.localPart()
	if !ok || !p.consumeSpecial('@') {
		return parsedMailbox{}, false
	}
	if p.peekKind(tokenLiteral) {
		literal := p.tokens[p.pos].text
		p.pos++
		return parsedMailbox{local: local, domain: literal, literal: true}, true
	}
	domain, ok := p.dotAtoms()
	if !ok {
		return parsedMailbox{}, false
	}
	return parsedMailbox{local: local, domain: domain}, true
}

// localPart parses word *("." word), which covers dot-atom, quoted-string,
// and the obsolete mixed form.
func (p *listParser) localPart() (string, bool) {
	if !p.peekKind(tokenAtom) && !p.peekKind(tokenQuoted) {
		return "", false
	}
	local := p.tokens[p.pos].text
	p.pos++
	for p.peekSpecial('.') {
		p.pos++
		if !p.peekKind(tokenAtom) && !p.peekKind(tokenQuoted) {
			return "", false
		}
		local += "." + p.tokens[p.pos].text
		p.pos++
	}
	return local, true
}

// dotAtoms parses atom *("." atom) for a domain name.
func (p *listParser) dotAtoms() (string, bool) {
	if !p.peekKind(tokenAtom) {
		return "", false
	}
	domain := p.tokens[p.pos].text
	p.pos++
	for p.peekSpecial('.') {
		p.pos++
		if !p.peekKind(tokenAtom) {
			return "", false
		}
		domain += "." + p.tokens[p.pos].text
		p.pos++
	}
	return domain, true
}

// word consumes one atom or quoted string.
func (p *listParser) word() bool {
	if p.peekKind(tokenAtom) || p.peekKind(tokenQuoted) {
		p.pos++
		return true
	}
	return false
}

// consumeSpecial consumes one expected special token.
func (p *listParser) consumeSpecial(special byte) bool {
	if p.peekSpecial(special) {
		p.pos++
		return true
	}
	return false
}

// peekSpecial reports whether the next token is the given special.
func (p *listParser) peekSpecial(special byte) bool {
	return p.pos < len(p.tokens) && p.tokens[p.pos].kind == tokenSpecial && p.tokens[p.pos].text[0] == special
}

// peekKind reports whether the next token has the given kind.
func (p *listParser) peekKind(kind tokenKind) bool {
	return p.pos < len(p.tokens) && p.tokens[p.pos].kind == kind
}

// done reports whether every token was consumed.
func (p *listParser) done() bool { return p.pos == len(p.tokens) }

// asciiString reports whether value contains only ASCII bytes.
func asciiString(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
