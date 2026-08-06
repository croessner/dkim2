package milter

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
)

const (
	postfixDSNEnvelopeVersion       byte = 1
	maxPostfixDSNOriginalRecipients      = 256
	maxPostfixDSNEnvelopeBytes           = 47 << 10
)

// PostfixDSNEvidence is the non-persistent local proof that Postfix's
// bounce(8) path produced the outer DSN and retained its original envelope.
type PostfixDSNEvidence struct {
	originalQueueID []byte
	original        postfixDSNOriginalEnvelope
}

// OriginalQueueID returns an isolated original Postfix queue identifier.
func (e PostfixDSNEvidence) OriginalQueueID() []byte { return bytes.Clone(e.originalQueueID) }

// OriginalEnvelope returns isolated exact original SMTP envelope paths.
func (e PostfixDSNEvidence) OriginalEnvelope() ([]byte, [][]byte) {
	recipients := make([][]byte, len(e.original.recipients))
	for index := range e.original.recipients {
		recipients[index] = bytes.Clone(e.original.recipients[index])
	}
	return bytes.Clone(e.original.sender), recipients
}

// OriginalSigningDomain derives one canonical signing domain from the exact
// Postfix-owned original envelope. It applies the same ASCII envelope boundary
// as originator signing and never falls back to outer DSN message fields.
func (e PostfixDSNEvidence) OriginalSigningDomain() (string, bool) {
	if !asciiBytes(e.original.sender) || !validEnvelopePath(e.original.sender, true) ||
		len(e.original.sender) == 2 || len(e.original.recipients) == 0 {
		return "", false
	}
	for _, recipient := range e.original.recipients {
		if !asciiBytes(recipient) || !validEnvelopePath(recipient, false) {
			return "", false
		}
	}
	return canonicalASCIIEnvelopeDomain(e.original.sender, true)
}

// Clear erases one detached evidence copy after daemon request mapping.
func (e *PostfixDSNEvidence) Clear() { e.clear() }

// retainedBytes returns the exact evidence payload covered by EOM transport accounting.
func (e PostfixDSNEvidence) retainedBytes() int64 {
	total := int64(len(e.originalQueueID) + len(e.original.sender))
	for _, recipient := range e.original.recipients {
		total += int64(len(recipient))
	}
	return total
}

// clone creates an isolated copy without exposing the adapter-owned buffers.
func (e PostfixDSNEvidence) clone() PostfixDSNEvidence {
	sender, recipients := e.OriginalEnvelope()
	return PostfixDSNEvidence{
		originalQueueID: bytes.Clone(e.originalQueueID),
		original:        postfixDSNOriginalEnvelope{sender: sender, recipients: recipients},
	}
}

// clear erases adapter-owned DSN provenance after the synchronous handler call.
func (e *PostfixDSNEvidence) clear() {
	if e == nil {
		return
	}
	clear(e.originalQueueID)
	clear(e.original.sender)
	clearPostfixDSNRecipients(e.original.recipients)
	e.originalQueueID = nil
	e.original.sender = nil
	e.original.recipients = nil
}

// postfixDSNOriginalEnvelope holds an isolated exact original SMTP envelope
// reconstructed from the Postfix queue-address evidence record.
type postfixDSNOriginalEnvelope struct {
	sender     []byte
	recipients [][]byte
}

// decodePostfixDSNOriginalEnvelope accepts only the closed, unpadded base64url
// v1 representation. Postfix queue records omit the RFC 5321 path brackets;
// this boundary restores only that framing and otherwise preserves every
// address octet before returning detached copies to the adapter.
func decodePostfixDSNOriginalEnvelope(encoded []byte) (postfixDSNOriginalEnvelope, bool) {
	if len(encoded) == 0 || len(encoded) > base64.RawURLEncoding.EncodedLen(maxPostfixDSNEnvelopeBytes) ||
		!validRawBase64URL(encoded) {
		return postfixDSNOriginalEnvelope{}, false
	}
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(encoded)))
	length, err := base64.RawURLEncoding.Decode(decoded, encoded)
	if err != nil || length == 0 || length > maxPostfixDSNEnvelopeBytes {
		clear(decoded)
		return postfixDSNOriginalEnvelope{}, false
	}
	decoded = decoded[:length]
	defer clear(decoded)
	if decoded[0] != postfixDSNEnvelopeVersion {
		return postfixDSNOriginalEnvelope{}, false
	}
	position := 1
	queueSender, next, ok := postfixDSNEnvelopePath(decoded, position)
	if !ok {
		return postfixDSNOriginalEnvelope{}, false
	}
	sender, ok := postfixDSNSMTPPath(queueSender)
	clear(queueSender)
	if !ok {
		return postfixDSNOriginalEnvelope{}, false
	}
	position = next
	if len(decoded)-position < 2 {
		return postfixDSNOriginalEnvelope{}, false
	}
	count := int(binary.BigEndian.Uint16(decoded[position : position+2]))
	position += 2
	if count == 0 || count > maxPostfixDSNOriginalRecipients {
		return postfixDSNOriginalEnvelope{}, false
	}
	recipients := make([][]byte, 0, count)
	for range count {
		queueRecipient, next, ok := postfixDSNEnvelopePath(decoded, position)
		if !ok {
			clearPostfixDSNRecipients(recipients)
			return postfixDSNOriginalEnvelope{}, false
		}
		recipient, valid := postfixDSNSMTPPath(queueRecipient)
		clear(queueRecipient)
		if !valid {
			clearPostfixDSNRecipients(recipients)
			return postfixDSNOriginalEnvelope{}, false
		}
		recipients = append(recipients, recipient)
		position = next
	}
	if position != len(decoded) {
		clearPostfixDSNRecipients(recipients)
		return postfixDSNOriginalEnvelope{}, false
	}
	return postfixDSNOriginalEnvelope{sender: sender, recipients: recipients}, true
}

// postfixDSNSMTPPath restores the sole framing removed by Postfix queue
// records and then applies the adapter's strict SMTP path validation.
func postfixDSNSMTPPath(queueAddress []byte) ([]byte, bool) {
	if len(queueAddress) == 0 || len(queueAddress) > 254 {
		return nil, false
	}
	path := make([]byte, len(queueAddress)+2)
	path[0] = '<'
	copy(path[1:], queueAddress)
	path[len(path)-1] = '>'
	if !validEnvelopePath(path, false) {
		clear(path)
		return nil, false
	}
	return path, true
}

// postfixDSNEnvelopePath reads one length-prefixed SMTP path and returns a
// detached value so later decode-buffer clearing cannot alter the evidence.
func postfixDSNEnvelopePath(record []byte, position int) ([]byte, int, bool) {
	if position < 0 || len(record)-position < 2 {
		return nil, 0, false
	}
	length := int(binary.BigEndian.Uint16(record[position : position+2]))
	position += 2
	if length == 0 || len(record)-position < length {
		return nil, 0, false
	}
	path := bytes.Clone(record[position : position+length])
	return path, position + length, true
}

// validRawBase64URL excludes padding and every non-base64url octet before the
// decoder allocates or accepts a transport representation.
func validRawBase64URL(value []byte) bool {
	for _, current := range value {
		if current >= 'A' && current <= 'Z' || current >= 'a' && current <= 'z' ||
			current >= '0' && current <= '9' || current == '-' || current == '_' {
			continue
		}
		return false
	}
	return true
}

// clearPostfixDSNRecipients clears every temporary decoded recipient before a
// rejected record leaves the local parser boundary.
func clearPostfixDSNRecipients(recipients [][]byte) {
	for _, recipient := range recipients {
		clear(recipient)
	}
}
