package dsn

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// propagationLanguage is the closed internal key selecting the fixed
// human-readable template of a propagated report. Only English is
// registered; a later revision may add languages without a facade change.
type propagationLanguage string

const (
	// propagationLanguageEnglish selects the fixed English template.
	propagationLanguageEnglish propagationLanguage = "en"
	// propagationSubject is the fixed outer Subject of a propagated report.
	propagationSubject = "Undelivered Mail Returned to Sender"
	// propagationFallbackStatus is used when the propagation group carries no 4.X.Y or 5.X.Y code.
	propagationFallbackStatus = "5.0.0"
	// propagationBoundaryPrefix starts every deterministic MIME boundary.
	propagationBoundaryPrefix = "=_dkim2-dsn-"
	// propagationBoundaryAttempts bounds boundary derivation against hostile part content.
	propagationBoundaryAttempts = 8
	// propagationMaxEnvelopeIDBytes is the RFC 3461 ENVID length ceiling.
	propagationMaxEnvelopeIDBytes = 100
	// propagationMinTokenBytes and propagationMaxTokenBytes bound the Message-ID token.
	propagationMinTokenBytes = 16
	propagationMaxTokenBytes = 64
	// propagationMaxOriginalRecipientBytes bounds the verbatim Original-Recipient
	// copy above the longest value that can decode to a valid envelope path,
	// "rfc822;" plus three xtext bytes per address byte; a longer value is
	// dropped like an invalid ENVID so the rendered line stays within the RFC
	// 5322 line limit and the fixed parts within PropagationFixedPartsBound.
	propagationMaxOriginalRecipientBytes = 800
	// PropagationFixedPartsBound is the ceiling of every rendered byte of a
	// propagated report outside the embedded original: the outer header block,
	// the human part, the machine part, the part headers, and the boundaries
	// with each bounded value at its maximum. A rebuilt report is never larger
	// than the received one plus this bound.
	PropagationFixedPartsBound = 4096
)

// Known reports whether the language key is registered.
func (l propagationLanguage) Known() bool { return l == propagationLanguageEnglish }

// propagationHumanText renders the fixed template for one registered
// language. The text names only the reporting MTA and never carries upstream
// diagnostics, addresses, hosts, or queue identifiers.
func propagationHumanText(reportingMTA string, language propagationLanguage) string {
	if !language.Known() {
		return ""
	}
	return "This is the mail system at host " + reportingMTA + ".\r\n" +
		"\r\n" +
		"A message that this system forwarded could not be delivered to its next\r\n" +
		"destination. The delivery status report received from that destination\r\n" +
		"was not forwarded.\r\n"
}

// propagationReportInput carries every value the report generator renders.
type propagationReportInput struct {
	reportingMTA        string
	timestamp           uint64
	token               []byte
	nextHop             []byte
	finalRecipient      []byte
	status              []byte
	envelopeID          []byte
	hasEnvelopeID       bool
	originalRecipient   []byte
	hasOriginal         bool
	originalContentType ContentType
	originalHeaders     []byte
	originalBody        []byte
}

// propagationTransportFacts records the transport extensions the rendered
// report needs: SMTPUTF8 when any header field of the report, including the
// embedded original's header block, carries a non-ASCII byte, and 8BITMIME
// when only the embedded original's body does.
type propagationTransportFacts struct {
	smtputf8     bool
	eightBitMIME bool
}

// renderedPropagationReport pairs the report bytes with their transport facts.
type renderedPropagationReport struct {
	raw       []byte
	transport propagationTransportFacts
}

// original returns the complete third-part body.
func (input propagationReportInput) original() []byte {
	return append(bytes.Clone(input.originalHeaders), input.originalBody...)
}

// renderPropagationReport assembles the deterministic RFC 6522 report: the
// fixed outer headers, the fixed English human part, the fresh
// message/delivery-status part, and the reconstructed third part. The
// result is re-parsed through the structural and strict RFC 3464 parsers so
// that this system never emits a report it would reject itself. The
// transport facts are derived from the assembled parts: every byte outside
// the embedded original's body decides SMTPUTF8, that body alone decides 8BITMIME.
func renderPropagationReport(input propagationReportInput) (renderedPropagationReport, error) {
	if !input.valid() {
		return renderedPropagationReport{}, newRebuildError(RebuildErrorInternal, nil)
	}
	human := "Content-Type: text/plain; charset=us-ascii\r\nContent-Language: en\r\n\r\n" + propagationHumanText(input.reportingMTA, propagationLanguageEnglish)
	machine := "Content-Type: message/delivery-status\r\n\r\n" + input.machinePart()
	thirdHeaders := "Content-Type: " + string(input.originalContentType) + "\r\n\r\n" + string(input.originalHeaders)
	third := thirdHeaders + string(input.originalBody)
	boundary, err := derivePropagationBoundary([]string{human, machine, third})
	if err != nil {
		return renderedPropagationReport{}, err
	}
	var outer bytes.Buffer
	outer.WriteString("From: Mail Delivery System <MAILER-DAEMON@" + input.reportingMTA + ">\r\n")
	outer.WriteString("To: " + string(input.nextHop) + "\r\n")
	outer.WriteString("Subject: " + propagationSubject + "\r\n")
	outer.WriteString("Date: " + time.Unix(int64(input.timestamp), 0).UTC().Format(time.RFC1123Z) + "\r\n")
	outer.WriteString("Message-ID: <" + string(input.token) + "@" + input.reportingMTA + ">\r\n")
	outer.WriteString("Auto-Submitted: auto-replied\r\n")
	outer.WriteString("MIME-Version: 1.0\r\n")
	outer.WriteString("Content-Type: multipart/report; report-type=delivery-status; boundary=\"" + boundary + "\"\r\n")
	var report bytes.Buffer
	report.Write(outer.Bytes())
	report.WriteString("\r\n")
	for _, part := range []string{human, machine, third} {
		report.WriteString("--" + boundary + "\r\n" + part + "\r\n")
	}
	report.WriteString("--" + boundary + "--\r\n")
	rendered := report.Bytes()
	if err := input.proveRendered(rendered); err != nil {
		return renderedPropagationReport{}, err
	}
	transport := propagationTransportFacts{
		smtputf8:     containsNonASCII(outer.Bytes()) || containsNonASCII([]byte(human)) || containsNonASCII([]byte(machine)) || containsNonASCII([]byte(thirdHeaders)),
		eightBitMIME: containsNonASCII(input.originalBody),
	}
	return renderedPropagationReport{raw: rendered, transport: transport}, nil
}

// containsNonASCII reports whether value carries any byte outside US-ASCII.
func containsNonASCII(value []byte) bool {
	for _, current := range value {
		if current >= 0x80 {
			return true
		}
	}
	return false
}

// machinePart renders the fresh message/delivery-status body with the
// per-message group first and exactly one per-recipient group.
func (input propagationReportInput) machinePart() string {
	var part bytes.Buffer
	if input.hasEnvelopeID {
		part.WriteString("Original-Envelope-Id: " + string(input.envelopeID) + "\r\n")
	}
	part.WriteString("Reporting-MTA: dns; " + input.reportingMTA + "\r\n\r\n")
	if input.hasOriginal {
		part.WriteString("Original-Recipient: " + string(input.originalRecipient) + "\r\n")
	}
	part.WriteString("Final-Recipient: rfc822; " + string(input.finalRecipient) + "\r\n")
	part.WriteString("Action: failed\r\n")
	part.WriteString("Status: " + string(input.status) + "\r\n")
	return part.String()
}

// valid reports whether every rendered value is present and well formed.
func (input propagationReportInput) valid() bool {
	if input.reportingMTA == "" || input.timestamp == 0 || input.timestamp > maxReferenceUnixSeconds ||
		!validPropagationToken(input.token) || len(input.nextHop) < 3 || len(input.finalRecipient) == 0 ||
		!validPropagationStatus(input.status) || len(input.originalHeaders) == 0 {
		return false
	}
	if envelopePathHasSourceRoute(input.nextHop) || input.finalRecipient[0] == '@' {
		return false
	}
	if input.originalContentType != ContentTypeRFC822 && input.originalContentType != ContentTypeRFC822Headers {
		return false
	}
	if input.hasEnvelopeID && !validPropagationEnvelopeID(input.envelopeID) {
		return false
	}
	if input.hasOriginal && (len(input.originalRecipient) > propagationMaxOriginalRecipientBytes || !validDeliveryStatusUnfoldedText(input.originalRecipient, false)) {
		return false
	}
	return !bytes.ContainsAny(input.finalRecipient, "\r\n") && !bytes.ContainsAny(input.nextHop, "\r\n")
}

// proveRendered re-parses the rendered report and requires the strict
// parsers to accept it and to read back exactly the third part that was written.
func (input propagationReportInput) proveRendered(rendered []byte) error {
	report, err := ParseWithOptions(rendered, DefaultOptions())
	if err != nil {
		return newRebuildError(RebuildErrorInternal, err)
	}
	if report.OriginalMessage().ContentType() != input.originalContentType || !bytes.Equal(report.OriginalMessage().BodyBytes(), input.original()) {
		return newRebuildError(RebuildErrorInternal, nil)
	}
	status, ok := parseDeliveryStatusBody(report.DeliveryStatus().BodyBytes(), deliveryStatusProfileStrictSequence)
	if !ok || len(status.recipients) != 1 || !status.recipients[0].failed() || status.hasEnvelopeID != input.hasEnvelopeID {
		return newRebuildError(RebuildErrorInternal, nil)
	}
	return nil
}

// derivePropagationBoundary derives a deterministic boundary from the part
// content and proves that no part contains it as a delimiter candidate.
func derivePropagationBoundary(parts []string) (string, error) {
	for attempt := 0; attempt < propagationBoundaryAttempts; attempt++ {
		digest := sha256.New()
		for _, part := range parts {
			digest.Write([]byte(part))
			digest.Write([]byte{0})
		}
		digest.Write([]byte(strconv.Itoa(attempt)))
		boundary := propagationBoundaryPrefix + hex.EncodeToString(digest.Sum(nil))[:24]
		collision := false
		for _, part := range parts {
			if bytes.Contains([]byte(part), []byte("--"+boundary)) {
				collision = true
				break
			}
		}
		if !collision {
			return boundary, nil
		}
	}
	return "", newRebuildError(RebuildErrorInternal, nil)
}

// validPropagationToken accepts a bounded alphanumeric Message-ID token.
func validPropagationToken(token []byte) bool {
	if len(token) < propagationMinTokenBytes || len(token) > propagationMaxTokenBytes {
		return false
	}
	for _, value := range token {
		if (value < '0' || value > '9') && (value < 'a' || value > 'z') && (value < 'A' || value > 'Z') {
			return false
		}
	}
	return true
}

// validPropagationStatus accepts only a syntactically valid 4.X.Y or 5.X.Y code.
func validPropagationStatus(status []byte) bool {
	return validDeliveryStatusCode(status) && (status[0] == '4' || status[0] == '5')
}

// propagationStatus copies a 4.X.Y or 5.X.Y code and falls back to 5.0.0 otherwise.
func propagationStatus(status []byte) []byte {
	if validPropagationStatus(status) {
		return bytes.Clone(status)
	}
	return []byte(propagationFallbackStatus)
}

// validPropagationEnvelopeID accepts a bounded RFC 3461 xtext ENVID.
func validPropagationEnvelopeID(value []byte) bool {
	if len(value) == 0 || len(value) > propagationMaxEnvelopeIDBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		current := value[index]
		switch {
		case current == '+':
			if index+2 >= len(value) || !upperHexByte(value[index+1]) || !upperHexByte(value[index+2]) {
				return false
			}
			index += 2
		case current < '!' || current > '~' || current == '=':
			return false
		}
	}
	return true
}
