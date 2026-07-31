package daemon

import (
	"bytes"
	"encoding/base64"
	"strings"
	"unicode/utf8"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/daemon/generated"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/daemon/wire"
)

const maxDaemonRawMessageBytes = 32 << 20

// MapProcessRequest projects exact local-scan evidence into generated REST DTOs.
func MapProcessRequest(
	input adapter.LocalScanRequest,
	authservID string,
) (generated.ProcessRequest, error) {
	message, err := mapLocalScanMessage(input)
	if err != nil {
		return generated.ProcessRequest{}, err
	}
	smtp, err := mapSMTP(input.MailFrom(), input.Recipients(), false)
	if err != nil {
		return generated.ProcessRequest{}, err
	}
	request := generated.ProcessRequest{
		ApiVersion: generated.V1,
		Draft:      generated.DraftIetfDkimDkim2Spec04,
		Message:    message,
		Smtp:       smtp,
	}
	if authservID != "" {
		if !validAdministrativeDomain(authservID) {
			return generated.ProcessRequest{}, contractError()
		}
		request.Reporting = &generated.ReportingContext{AuthservId: authservID}
	}
	return request, nil
}

// MapSignRequest projects one originator-filter request into generated REST DTOs.
func MapSignRequest(
	input adapter.FilterRequest,
	tenant string,
	domain string,
) (generated.SignRequest, error) {
	if input.Operation() != adapter.FilterSign || !validSigningContext(tenant, domain) {
		return generated.SignRequest{}, contractError()
	}
	outgoing := input.Outgoing()
	smtp, err := mapSMTP(
		outgoing.MailFrom(), [][]byte{outgoing.Recipient()}, true,
	)
	if err != nil {
		return generated.SignRequest{}, err
	}
	message, err := mapTransportFilterMessage(input.Message())
	if err != nil {
		return generated.SignRequest{}, err
	}
	return generated.SignRequest{
		ApiVersion: generated.V1,
		Context:    generated.SigningContext{Tenant: tenant, Domain: domain},
		Draft:      generated.DraftIetfDkimDkim2Spec04,
		Message:    message,
		Smtp:       smtp,
	}, nil
}

// MapReviseRequest projects distinct receive-time and transport-time evidence.
func MapReviseRequest(
	input adapter.FilterRequest,
	tenant string,
	domain string,
) (generated.ReviseRequest, error) {
	if input.Operation() != adapter.FilterRevise || !validSigningContext(tenant, domain) {
		return generated.ReviseRequest{}, contractError()
	}

	// Current transport authority is validated before inherited evidence is read.
	outgoing := input.Outgoing()
	currentSMTP, err := mapSMTP(
		outgoing.MailFrom(), [][]byte{outgoing.Recipient()}, true,
	)
	if err != nil {
		return generated.ReviseRequest{}, err
	}
	message, err := mapTransportFilterMessage(input.Message())
	if err != nil {
		return generated.ReviseRequest{}, err
	}
	incoming, ok := input.Incoming()
	if !ok {
		return generated.ReviseRequest{}, contractError()
	}
	incomingSMTP, err := mapSMTP(incoming.MailFrom(), incoming.Recipients(), false)
	if err != nil {
		return generated.ReviseRequest{}, err
	}
	return generated.ReviseRequest{
		ApiVersion:   generated.V1,
		Context:      generated.SigningContext{Tenant: tenant, Domain: domain},
		Draft:        generated.DraftIetfDkimDkim2Spec04,
		IncomingSmtp: incomingSMTP,
		Message:      message,
		Smtp:         currentSMTP,
	}, nil
}

// mapLocalScanMessage reconstructs the exact CRLF daemon representation.
func mapLocalScanMessage(input adapter.LocalScanRequest) (generated.MessageInput, error) {
	headers := input.Headers()
	body := input.Body()
	defer clearEvidence(headers, body)

	var converted bytes.Buffer
	defer func() { clear(converted.Bytes()) }()
	for _, header := range headers {
		if !appendCRLF(&converted, header) {
			return generated.MessageInput{}, adapter.NewError(adapter.FailureResource)
		}
	}
	if !appendCRLF(&converted, []byte{'\n'}) || !appendCRLF(&converted, body) {
		return generated.MessageInput{}, adapter.NewError(adapter.FailureResource)
	}
	return newMessageInput(converted.Bytes(), generated.EximLocalScanObservedCrlf)
}

// mapTransportFilterMessage creates the exact CRLF daemon representation.
func mapTransportFilterMessage(message []byte) (generated.MessageInput, error) {
	defer clear(message)
	var converted bytes.Buffer
	defer func() { clear(converted.Bytes()) }()
	if !appendCRLF(&converted, message) {
		return generated.MessageInput{}, adapter.NewError(adapter.FailureResource)
	}
	return newMessageInput(converted.Bytes(), generated.EximTransportFilterCrlf)
}

// newMessageInput base64-encodes one admitted raw message into a protected DTO.
func newMessageInput(
	raw []byte,
	fidelity generated.MessageInputFidelity,
) (generated.MessageInput, error) {
	if !fidelity.Valid() {
		return generated.MessageInput{}, contractError()
	}
	if len(raw) > maxDaemonRawMessageBytes {
		return generated.MessageInput{}, adapter.NewError(adapter.FailureResource)
	}
	protected, err := wire.NewProtectedString(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		return generated.MessageInput{}, contractError()
	}
	return generated.MessageInput{
		Fidelity: &fidelity, RawRfc5322Base64: protected,
	}, nil
}

// mapSMTP canonicalizes Exim address expansions into protected RFC 5321 paths.
func mapSMTP(
	mailFrom []byte,
	recipients [][]byte,
	asciiOnly bool,
) (generated.SMTPInput, error) {
	defer clearSMTP(mailFrom, recipients)
	canonicalMailFrom, err := adapter.CanonicalEximPath(mailFrom, true)
	if err != nil {
		return generated.SMTPInput{}, adapter.NewError(adapter.FailureFidelity)
	}
	canonicalRecipients := make([][]byte, len(recipients))
	defer clearSMTP(canonicalMailFrom, canonicalRecipients)
	if len(canonicalMailFrom) > 256 || len(recipients) == 0 || len(recipients) > 2_000 ||
		!validSMTPScalar(canonicalMailFrom, asciiOnly) {
		return generated.SMTPInput{}, adapter.NewError(adapter.FailureFidelity)
	}
	reverse, err := wire.NewProtectedString(string(canonicalMailFrom))
	if err != nil {
		return generated.SMTPInput{}, adapter.NewError(adapter.FailureFidelity)
	}
	forward := make([]wire.ProtectedString, len(recipients))
	for index, recipient := range recipients {
		canonicalRecipient, canonicalErr := adapter.CanonicalEximPath(recipient, false)
		if canonicalErr != nil || len(canonicalRecipient) > 256 ||
			!validSMTPScalar(canonicalRecipient, asciiOnly) {
			return generated.SMTPInput{}, adapter.NewError(adapter.FailureFidelity)
		}
		canonicalRecipients[index] = canonicalRecipient
		forward[index], err = wire.NewProtectedString(string(canonicalRecipient))
		if err != nil {
			return generated.SMTPInput{}, adapter.NewError(adapter.FailureFidelity)
		}
	}
	return generated.SMTPInput{MailFrom: reverse, RcptTo: forward}, nil
}

// validSMTPScalar enforces framing and optional signing ASCII constraints.
func validSMTPScalar(value []byte, asciiOnly bool) bool {
	if !utf8.Valid(value) {
		return false
	}
	for _, current := range value {
		if current == 0 || current == '\r' || current == '\n' ||
			asciiOnly && current > 0x7f {
			return false
		}
	}
	return true
}

// appendCRLF appends deterministic LF-to-CRLF conversion within the daemon cap.
func appendCRLF(output *bytes.Buffer, input []byte) bool {
	if output == nil {
		return false
	}
	previous := byte(0)
	for _, current := range input {
		if current == '\n' && previous != '\r' {
			if output.Len() >= maxDaemonRawMessageBytes {
				return false
			}
			output.WriteByte('\r')
		}
		if output.Len() >= maxDaemonRawMessageBytes {
			return false
		}
		output.WriteByte(current)
		previous = current
	}
	return true
}

// validSigningContext proves the generated signing-context patterns.
func validSigningContext(tenant string, domain string) bool {
	if tenant == "" || len(tenant) > 128 || !validAdministrativeDomain(domain) {
		return false
	}
	for index, current := range []byte(tenant) {
		letter := current >= 'a' && current <= 'z'
		digit := current >= '0' && current <= '9'
		punctuation := index > 0 && (current == '.' || current == '_' || current == '-')
		if !letter && !digit && !punctuation {
			return false
		}
	}
	return true
}

// validAdministrativeDomain proves the generated lower-case DNS-name pattern.
func validAdministrativeDomain(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 ||
			!asciiAlphanumeric(label[0]) ||
			!asciiAlphanumeric(label[len(label)-1]) {
			return false
		}
		for index := 1; index < len(label)-1; index++ {
			if !asciiAlphanumeric(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

// asciiAlphanumeric reports whether one byte is a lower-case DNS edge.
func asciiAlphanumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

// clearEvidence erases temporary local-scan message copies.
func clearEvidence(headers [][]byte, body []byte) {
	for index := range headers {
		clear(headers[index])
	}
	clear(body)
}

// clearSMTP erases temporary envelope copies after protected DTO construction.
func clearSMTP(mailFrom []byte, recipients [][]byte) {
	clear(mailFrom)
	for index := range recipients {
		clear(recipients[index])
	}
}
