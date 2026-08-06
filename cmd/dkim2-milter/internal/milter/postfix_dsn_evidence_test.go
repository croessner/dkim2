package milter

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"testing"
)

// TestDecodePostfixDSNOriginalEnvelope accepts the closed v1 binary envelope
// record and restores only the SMTP path brackets omitted by queue records.
func TestDecodePostfixDSNOriginalEnvelope(t *testing.T) {
	queueSender := []byte("sender@example.test")
	queueRecipients := [][]byte{
		[]byte("first@example.test"),
		[]byte("second@example.test"),
	}
	encoded := base64.RawURLEncoding.EncodeToString(postfixDSNEnvelopeRecord(queueSender, queueRecipients))
	evidence, ok := decodePostfixDSNOriginalEnvelope([]byte(encoded))
	if !ok {
		t.Fatal("decodePostfixDSNOriginalEnvelope() rejected valid evidence")
	}
	sender := []byte("<sender@example.test>")
	recipients := [][]byte{[]byte("<first@example.test>"), []byte("<second@example.test>")}
	if !bytes.Equal(evidence.sender, sender) || len(evidence.recipients) != len(recipients) {
		t.Fatalf("decoded evidence does not preserve the original envelope")
	}
	for index := range recipients {
		if !bytes.Equal(evidence.recipients[index], recipients[index]) {
			t.Fatalf("recipient %d was changed", index)
		}
	}

	detachedSender := evidence.sender
	detachedSender[1] = 'X'
	if bytes.Equal(evidence.sender, sender) {
		t.Fatal("decoded evidence aliases caller-owned path bytes")
	}
}

// TestPostfixDSNEvidenceDerivesOriginalSigningDomain proves dynamic DSN
// identity comes only from the complete trusted original SMTP envelope.
func TestPostfixDSNEvidenceDerivesOriginalSigningDomain(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		sender     []byte
		recipients [][]byte
		want       string
		ok         bool
	}{
		{
			name: "canonicalized domain", sender: []byte("<sender@Example.TEST>"),
			recipients: [][]byte{[]byte("<recipient@remote.example>")},
			want:       "example.test", ok: true,
		},
		{
			name: "null original sender", sender: []byte("<>"),
			recipients: [][]byte{[]byte("<recipient@example.test>")},
		},
		{
			name: "EAI recipient", sender: []byte("<sender@example.test>"),
			recipients: [][]byte{[]byte("<récipient@example.test>")},
		},
		{name: "missing recipient", sender: []byte("<sender@example.test>")},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			evidence := PostfixDSNEvidence{original: postfixDSNOriginalEnvelope{
				sender: testCase.sender, recipients: testCase.recipients,
			}}
			got, ok := evidence.OriginalSigningDomain()
			if got != testCase.want || ok != testCase.ok {
				t.Fatalf("OriginalSigningDomain()=(%q,%t), want (%q,%t)", got, ok, testCase.want, testCase.ok)
			}
		})
	}
}

// TestDecodePostfixDSNOriginalEnvelopeRejectsAmbiguity proves v1 has no
// permissive alternate encoding, null sender, partial record, or recipient
// count ambiguity.
func TestDecodePostfixDSNOriginalEnvelopeRejectsAmbiguity(t *testing.T) {
	valid := postfixDSNEnvelopeRecord(
		[]byte("sender@example.test"), [][]byte{[]byte("recipient@example.test")},
	)
	padded := postfixDSNEnvelopeRecord(
		[]byte("send@example.test"), [][]byte{[]byte("recipient@example.test")},
	)
	for _, testCase := range []struct {
		name  string
		value []byte
	}{
		{name: "padded base64", value: []byte(base64.URLEncoding.EncodeToString(padded))},
		{name: "wrong version", value: encodedPostfixDSNEnvelope(mutatedByte(valid, 0, 2))},
		{name: "truncated", value: encodedPostfixDSNEnvelope(valid[:len(valid)-1])},
		{name: "null sender", value: encodedPostfixDSNEnvelope(postfixDSNEnvelopeRecord(nil, [][]byte{[]byte("recipient@example.test")}))},
		{name: "already framed", value: encodedPostfixDSNEnvelope(postfixDSNEnvelopeRecord([]byte("<sender@example.test>"), [][]byte{[]byte("recipient@example.test")}))},
		{name: "no recipients", value: encodedPostfixDSNEnvelope(postfixDSNEnvelopeRecord([]byte("sender@example.test"), nil))},
		{name: "trailing octet", value: encodedPostfixDSNEnvelope(append(valid, 0))},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, ok := decodePostfixDSNOriginalEnvelope(testCase.value); ok {
				t.Fatal("ambiguous Postfix DSN envelope was accepted")
			}
		})
	}
}

// postfixDSNEnvelopeRecord builds the closed v1 record used exclusively by
// this package's evidence parser tests.
func postfixDSNEnvelopeRecord(sender []byte, recipients [][]byte) []byte {
	result := []byte{postfixDSNEnvelopeVersion}
	result = appendPostfixDSNPath(result, sender)
	count := make([]byte, 2)
	binary.BigEndian.PutUint16(count, uint16(len(recipients)))
	result = append(result, count...)
	for _, recipient := range recipients {
		result = appendPostfixDSNPath(result, recipient)
	}
	return result
}

// appendPostfixDSNPath appends one test-only length-prefixed SMTP path.
func appendPostfixDSNPath(result, path []byte) []byte {
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(path)))
	result = append(result, length...)
	return append(result, path...)
}

// encodedPostfixDSNEnvelope wraps test record bytes in the required unpadded
// base64url representation.
func encodedPostfixDSNEnvelope(record []byte) []byte {
	return []byte(base64.RawURLEncoding.EncodeToString(record))
}

// mutatedByte returns a detached test record with one deterministic mutation.
func mutatedByte(value []byte, index int, replacement byte) []byte {
	result := bytes.Clone(value)
	result[index] = replacement
	return result
}
