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

// HeaderFromNullSenderClass is the closed eligibility outcome of a message
// offered for originator signing with a null reverse path under the explicit
// header_from policy.
type HeaderFromNullSenderClass string

const (
	// HeaderFromNullSenderEligible marks an automatic reply or disposition
	// notification whose single From mailbox yields the signing domain.
	HeaderFromNullSenderEligible HeaderFromNullSenderClass = "eligible"
	// HeaderFromNullSenderProtocolFields marks a message that already carries
	// a DKIM2-Signature or Message-Instance header field. A new originator
	// instance would conflict with that history, and such null-sender mail is
	// a signed delivery-status notification that belongs on the Section 12
	// path.
	HeaderFromNullSenderProtocolFields HeaderFromNullSenderClass = "dkim2_protocol_fields"
	// HeaderFromNullSenderDeliveryStatus marks an RFC 3464 delivery-status
	// notification, a top-level multipart/report with report-type
	// delivery-status. DSNs are signed only through the Section 12 route,
	// never as originator mail.
	HeaderFromNullSenderDeliveryStatus HeaderFromNullSenderClass = "delivery_status_report"
	// HeaderFromNullSenderContentTypeAmbiguous marks a message whose
	// top-level Content-Type is repeated, overlong, or unparsable, so it
	// cannot be proven not to be a delivery-status notification.
	HeaderFromNullSenderContentTypeAmbiguous HeaderFromNullSenderClass = "content_type_ambiguous"
	// HeaderFromNullSenderAuthorUnusable marks a message whose header section
	// is unparsable or whose From does not yield one canonical DNS domain.
	HeaderFromNullSenderAuthorUnusable HeaderFromNullSenderClass = "author_unusable"
)

// maxContentTypeValueBytes bounds the top-level Content-Type value that the
// delivery-status classification is willing to parse.
const maxContentTypeValueBytes = 8192

// ClassifyHeaderFromNullSender decides whether a message with a null reverse
// path may be signed as originator mail under the header_from policy and, if
// so, returns the canonical From domain that binds d=. Draft-ietf-dkim-dkim2-
// spec Section 8.8 requires no d= match when mf= is "<>", so the signer binds
// d= to the message author instead of choosing it freely. Messages carrying
// DKIM2 protocol fields and RFC 3464 delivery-status notifications are never
// eligible; DSNs stay on the dedicated Section 12 route. Only the header
// section is parsed, so the body is never copied.
func ClassifyHeaderFromNullSender(rawMessage []byte) (string, HeaderFromNullSenderClass) {
	if end := bytes.Index(rawMessage, []byte("\r\n\r\n")); end >= 0 {
		rawMessage = rawMessage[:end+2]
	}
	message, err := rawmsg.Parse(rawMessage)
	if err != nil {
		return "", HeaderFromNullSenderAuthorUnusable
	}
	headers := message.Headers()
	if len(headers.FieldsByName("dkim2-signature")) != 0 ||
		len(headers.FieldsByName("message-instance")) != 0 {
		return "", HeaderFromNullSenderProtocolFields
	}
	contentTypes := headers.FieldsByName("content-type")
	if len(contentTypes) > 1 {
		return "", HeaderFromNullSenderContentTypeAmbiguous
	}
	if len(contentTypes) == 1 {
		report, known := deliveryStatusReport(contentTypes[0].UnfoldedValue())
		if !known {
			return "", HeaderFromNullSenderContentTypeAmbiguous
		}
		if report {
			return "", HeaderFromNullSenderDeliveryStatus
		}
	}
	authors := headers.FieldsByName("from")
	if len(authors) != 1 {
		return "", HeaderFromNullSenderAuthorUnusable
	}
	domain, ok := headerFromMailboxDomain(authors[0].UnfoldedValue())
	if !ok {
		return "", HeaderFromNullSenderAuthorUnusable
	}
	return domain, HeaderFromNullSenderEligible
}

// deliveryStatusReport reports whether one top-level Content-Type value is
// multipart/report with report-type delivery-status, comparing the media
// type and the parameter name and value case-insensitively. The second
// result is false when the value is overlong or unparsable.
func deliveryStatusReport(value []byte) (report bool, known bool) {
	if len(value) > maxContentTypeValueBytes {
		return false, false
	}
	mediaType, parameters, err := mime.ParseMediaType(string(value))
	if err != nil {
		return false, false
	}
	return mediaType == "multipart/report" &&
		strings.EqualFold(strings.TrimSpace(parameters["report-type"]), "delivery-status"), true
}

// HeaderFromDomain derives the canonical DNS domain of the single RFC 5322
// author mailbox of a message that is eligible for header_from null-sender
// originator signing; see ClassifyHeaderFromNullSender. The derivation
// succeeds only for exactly one From header field that holds exactly one
// mailbox, not a group, whose addr-spec is ASCII and whose domain is a DNS
// name accepted by the canonicalization used for delivery-status signing
// identities and d= values. Every other class reports false.
func HeaderFromDomain(rawMessage []byte) (string, bool) {
	domain, class := ClassifyHeaderFromNullSender(rawMessage)
	return domain, class == HeaderFromNullSenderEligible
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
