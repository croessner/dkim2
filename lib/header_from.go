package dkim2

import (
	"bytes"
	"io"
	"mime"
	"net/mail"
	"strings"

	"github.com/croessner/dkim2/internal/keyresolver"
	"github.com/croessner/dkim2/internal/rawmsg"
)

// maxHeaderFromValueBytes bounds the single From field value that the
// null-sender identity derivation is willing to parse.
const maxHeaderFromValueBytes = 4096

// HeaderFromDomain derives the canonical DNS domain of the single RFC 5322
// author mailbox. It is the identity authority for originator signing of a
// null reverse path under an explicit header_from policy: draft-ietf-dkim-
// dkim2-spec Section 8.8 requires no d= match when mf= is "<>", so the
// signer binds d= to the message author instead of choosing it freely.
//
// The derivation succeeds only for exactly one From header field that holds
// exactly one mailbox, not a group, whose addr-spec is ASCII and whose domain
// is a DNS name accepted by the canonicalization used for delivery-status
// signing identities and d= values. Address literals, SMTPUTF8 mailboxes,
// groups, multiple mailboxes, missing or repeated From fields, and
// unparsable values report false.
func HeaderFromDomain(rawMessage []byte) (string, bool) {
	// Only the header section can hold From, so the body is never parsed or
	// copied; the header block keeps its final CRLF as a header-only message.
	if end := bytes.Index(rawMessage, []byte("\r\n\r\n")); end >= 0 {
		rawMessage = rawMessage[:end+2]
	}
	message, err := rawmsg.Parse(rawMessage)
	if err != nil {
		return "", false
	}
	fields := message.Headers().FieldsByName("from")
	if len(fields) != 1 {
		return "", false
	}
	return headerFromMailboxDomain(fields[0].UnfoldedValue())
}

// headerFromMailboxDomain parses one unfolded From value as exactly one
// mailbox and returns its canonical DNS domain.
func headerFromMailboxDomain(value []byte) (string, bool) {
	if len(value) == 0 || len(value) > maxHeaderFromValueBytes || !singleMailboxShape(value) {
		return "", false
	}
	parser := mail.AddressParser{WordDecoder: &mime.WordDecoder{
		// The display name never contributes to the identity, so an
		// unknown encoded-word charset must not refuse the mailbox.
		CharsetReader: func(_ string, input io.Reader) (io.Reader, error) { return input, nil },
	}}
	addresses, err := parser.ParseList(string(value))
	if err != nil || len(addresses) != 1 || addresses[0] == nil {
		return "", false
	}
	address := addresses[0].Address
	at := strings.LastIndexByte(address, '@')
	if at < 1 || at == len(address)-1 || !asciiPrintable(address) {
		return "", false
	}
	domain := address[at+1:]
	if domain[0] == '[' {
		return "", false
	}
	limits := keyresolver.DefaultLimits()
	canonical, err := keyresolver.CanonicalSigningDomain(domain, limits.MaxSigningDomainBytes, limits.MaxSigningDomainLabels)
	if err != nil {
		return "", false
	}
	return canonical, true
}

// singleMailboxShape rejects RFC 5322 group syntax and mailbox lists before
// address parsing. A top-level ':' or ';' marks a group and a top-level ','
// a list; quoted strings, comments, and angle-addr contents are skipped so
// that their literal punctuation does not count.
func singleMailboxShape(value []byte) bool {
	inQuote, angle, comment := false, 0, 0
	for index := 0; index < len(value); index++ {
		current := value[index]
		switch {
		case current == '\\' && (inQuote || comment > 0):
			index++
		case inQuote:
			inQuote = current != '"'
		case comment > 0:
			switch current {
			case '(':
				comment++
			case ')':
				comment--
			}
		case current == '"':
			inQuote = true
		case current == '(':
			comment++
		case current == '<':
			angle++
		case current == '>':
			if angle == 0 {
				return false
			}
			angle--
		case angle == 0 && bytes.IndexByte([]byte(":;,"), current) >= 0:
			return false
		}
	}
	return !inQuote && angle == 0 && comment == 0
}

// asciiPrintable reports whether value holds only visible ASCII and space.
func asciiPrintable(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}
