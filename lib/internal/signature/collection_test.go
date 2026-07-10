package signature

import (
	"errors"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
)

const syntheticBody = "body"

// TestExtractFindsSignaturesInHeaderOrder verifies rawmsg-backed extraction.
func TestExtractFindsSignaturesInHeaderOrder(t *testing.T) {
	msg := parseRawMessage(t, strings.Join([]string{
		"From: sender@example.test",
		dkim2SignatureHeader(signatureValueWith("i", "1")),
		"Subject: synthetic",
		dkim2SignatureHeader(signatureValueWith("i", "2")),
		"",
		syntheticBody,
	}, "\r\n"))

	signatures, err := Extract(msg)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if len(signatures) != 2 {
		t.Fatalf("Extract() length = %d, want 2", len(signatures))
	}
	if signatures[0].Sequence() != 1 || signatures[0].HeaderIndex() != 1 {
		t.Fatalf("first signature sequence/index = %d/%d, want 1/1", signatures[0].Sequence(), signatures[0].HeaderIndex())
	}
	if signatures[1].Sequence() != 2 || signatures[1].HeaderIndex() != 3 {
		t.Fatalf("second signature sequence/index = %d/%d, want 2/3", signatures[1].Sequence(), signatures[1].HeaderIndex())
	}
}

// TestValidateSequenceRejectsSignatureSequenceErrors verifies fail-closed collection rules.
func TestValidateSequenceRejectsSignatureSequenceErrors(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		code ErrorCode
	}{
		{
			name: "missing origin",
			raw:  signatureMessage(signatureValueWith("i", "2")),
			code: ErrorCodeMissingOrigin,
		},
		{
			name: "duplicate number",
			raw: strings.Join([]string{
				dkim2SignatureHeader(signatureValueWith("i", "1")),
				dkim2SignatureHeader(signatureValueWith("i", "1")),
				"",
				syntheticBody,
			}, "\r\n"),
			code: ErrorCodeDuplicateSequence,
		},
		{
			name: "gap",
			raw: strings.Join([]string{
				dkim2SignatureHeader(signatureValueWith("i", "1")),
				dkim2SignatureHeader(signatureValueWith("i", "3")),
				"",
				syntheticBody,
			}, "\r\n"),
			code: ErrorCodeSequenceGap,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Extract(parseRawMessage(t, tt.raw))
			if !IsErrorCode(err, tt.code) {
				t.Fatalf("Extract() error = %v, want %s", err, tt.code)
			}

			var signatureErr *Error
			if !errors.As(err, &signatureErr) {
				t.Fatal("errors.As did not expose signature Error")
			}
			if signatureErr.ExpectedNumber() == 0 || signatureErr.ObservedNumber() == 0 {
				t.Fatalf("sequence error missing bounded numbers: expected=%d observed=%d", signatureErr.ExpectedNumber(), signatureErr.ObservedNumber())
			}
			if strings.Contains(err.Error(), testSelector) || strings.Contains(err.Error(), baseValue("<user@example.net>")) {
				t.Fatalf("sequence error leaked parser data: %q", err.Error())
			}
		})
	}
}

// TestValidateInstanceReferencesReportsHigherInstances verifies the draft special case.
func TestValidateInstanceReferencesReportsHigherInstances(t *testing.T) {
	msg := parseRawMessage(t, strings.Join([]string{
		"Message-Instance: m=1; h=sha256:" + base64OfByte(0x11, 32) + ":" + base64OfByte(0x22, 32) + ";",
		"Message-Instance: m=2; h=sha256:" + base64OfByte(0x33, 32) + ":" + base64OfByte(0x44, 32) + ";",
		dkim2SignatureHeader(collectionSignatureValue("1", "1")),
		"",
		syntheticBody,
	}, "\r\n"))

	instances, err := instance.Extract(msg)
	if err != nil {
		t.Fatalf("instance.Extract() error = %v", err)
	}
	signatures, err := Extract(msg)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	err = ValidateInstanceReferences(instances, signatures)
	if !IsErrorCode(err, ErrorCodeUnreferencedInstance) {
		t.Fatalf("ValidateInstanceReferences() error = %v, want unreferenced instance", err)
	}

	var signatureErr *Error
	if !errors.As(err, &signatureErr) {
		t.Fatal("errors.As did not expose signature Error")
	}
	if signatureErr.Location().FieldIndex != 1 {
		t.Fatalf("Location().FieldIndex = %d, want higher Message-Instance index 1", signatureErr.Location().FieldIndex)
	}
	if signatureErr.ExpectedNumber() != 1 || signatureErr.ObservedNumber() != 2 {
		t.Fatalf("expected/observed = %d/%d, want 1/2", signatureErr.ExpectedNumber(), signatureErr.ObservedNumber())
	}
	if strings.Contains(err.Error(), base64OfByte(0x33, 32)) || strings.Contains(err.Error(), testSelector) {
		t.Fatalf("reference error leaked parser data: %q", err.Error())
	}
}

// TestValidateInstanceReferencesAcceptsCoveredInstances verifies max signature m= coverage.
func TestValidateInstanceReferencesAcceptsCoveredInstances(t *testing.T) {
	msg := parseRawMessage(t, strings.Join([]string{
		"Message-Instance: m=1; h=sha256:" + base64OfByte(0x11, 32) + ":" + base64OfByte(0x22, 32) + ";",
		"Message-Instance: m=2; h=sha256:" + base64OfByte(0x33, 32) + ":" + base64OfByte(0x44, 32) + ";",
		dkim2SignatureHeader(collectionSignatureValue("1", "1")),
		dkim2SignatureHeader(collectionSignatureValue("2", "2")),
		"",
		syntheticBody,
	}, "\r\n"))

	instances, err := instance.Extract(msg)
	if err != nil {
		t.Fatalf("instance.Extract() error = %v", err)
	}
	signatures, err := Extract(msg)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	if err := ValidateInstanceReferences(instances, signatures); err != nil {
		t.Fatalf("ValidateInstanceReferences() error = %v", err)
	}
}

// parseRawMessage parses a synthetic strict CRLF message.
func parseRawMessage(t *testing.T, raw string) rawmsg.Message {
	t.Helper()

	msg, err := rawmsg.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}

	return msg
}

// signatureMessage builds a one-field DKIM2-Signature test message.
func signatureMessage(value string) string {
	return strings.Join([]string{
		dkim2SignatureHeader(value),
		"",
		syntheticBody,
	}, "\r\n")
}

// dkim2SignatureHeader builds one synthetic DKIM2-Signature header line.
func dkim2SignatureHeader(value string) string {
	if !strings.HasSuffix(strings.TrimRight(value, " \t"), ";") {
		value += ";"
	}

	return "DKIM2-Signature: " + value
}

// collectionSignatureValue returns a valid signature with chosen i= and m= values.
func collectionSignatureValue(sequence string, instanceNumber string) string {
	value := signatureValueWith("i", sequence)

	return strings.Replace(value, "m=3", "m="+instanceNumber, 1)
}
