package instance

import (
	"errors"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

const syntheticBody = "body"

// TestExtractFindsMessageInstancesInHeaderOrder verifies rawmsg-backed extraction.
func TestExtractFindsMessageInstancesInHeaderOrder(t *testing.T) {
	msg := parseRawMessage(t, strings.Join([]string{
		"From: sender@example.test",
		"Message-Instance: m=1; h=sha256:" + base64OfByte(0x11, 32) + ":" + base64OfByte(0x22, 32) + ";",
		"Subject: synthetic",
		"Message-Instance: m=2; h=sha256:" + base64OfByte(0x33, 32) + ":" + base64OfByte(0x44, 32) + ";",
		"",
		syntheticBody,
	}, "\r\n"))

	instances, err := Extract(msg)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if len(instances) != 2 {
		t.Fatalf("Extract() length = %d, want 2", len(instances))
	}
	if instances[0].Number() != 1 || instances[0].HeaderIndex() != 1 {
		t.Fatalf("first instance number/index = %d/%d, want 1/1", instances[0].Number(), instances[0].HeaderIndex())
	}
	if instances[1].Number() != 2 || instances[1].HeaderIndex() != 3 {
		t.Fatalf("second instance number/index = %d/%d, want 2/3", instances[1].Number(), instances[1].HeaderIndex())
	}
}

// TestValidateSequenceRejectsMessageInstanceSequenceErrors verifies fail-closed collection rules.
func TestValidateSequenceRejectsMessageInstanceSequenceErrors(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		code ErrorCode
	}{
		{
			name: "missing origin",
			raw:  instanceMessage("m=2; h=sha256:" + base64OfByte(0x11, 32) + ":" + base64OfByte(0x22, 32)),
			code: ErrorCodeMissingOrigin,
		},
		{
			name: "duplicate number",
			raw: strings.Join([]string{
				instanceHeader("m=1; h=sha256:" + base64OfByte(0x11, 32) + ":" + base64OfByte(0x22, 32)),
				instanceHeader("m=1; h=sha256:" + base64OfByte(0x33, 32) + ":" + base64OfByte(0x44, 32)),
				"",
				syntheticBody,
			}, "\r\n"),
			code: ErrorCodeDuplicateNumber,
		},
		{
			name: "gap",
			raw: strings.Join([]string{
				instanceHeader("m=1; h=sha256:" + base64OfByte(0x11, 32) + ":" + base64OfByte(0x22, 32)),
				instanceHeader("m=3; h=sha256:" + base64OfByte(0x33, 32) + ":" + base64OfByte(0x44, 32)),
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

			var instanceErr *Error
			if !errors.As(err, &instanceErr) {
				t.Fatal("errors.As did not expose instance Error")
			}
			if instanceErr.ExpectedNumber() == 0 || instanceErr.ObservedNumber() == 0 {
				t.Fatalf("sequence error missing bounded numbers: expected=%d observed=%d", instanceErr.ExpectedNumber(), instanceErr.ObservedNumber())
			}
			if strings.Contains(err.Error(), base64OfByte(0x11, 32)) {
				t.Fatalf("sequence error leaked raw field data: %q", err.Error())
			}
		})
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

// instanceMessage builds a one-field Message-Instance test message.
func instanceMessage(value string) string {
	return strings.Join([]string{
		instanceHeader(value),
		"",
		syntheticBody,
	}, "\r\n")
}

// instanceHeader builds one synthetic Message-Instance header line.
func instanceHeader(value string) string {
	if !strings.HasSuffix(strings.TrimRight(value, " \t"), ";") {
		value += ";"
	}

	return "Message-Instance: " + value
}
