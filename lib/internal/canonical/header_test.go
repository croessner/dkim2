package canonical

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// TestHeaderHashInputExcludesDraftHeaderClasses verifies draft-04 Section 4 and Section 6.2 exclusions.
func TestHeaderHashInputExcludesDraftHeaderClasses(t *testing.T) {
	msg := mustParseHeaderMessage(t, []byte(
		"Received: by mx.example\r\n"+
			"RETURN-PATH: <sender@example.test>\r\n"+
			"Delivered-To: <recipient@example.test>\r\n"+
			"Authentication-Results: mx.example; pass\r\n"+
			"X-Trace: trace-secret\r\n"+
			"DKIM-Signature: v=1; secret\r\n"+
			"ARC-Seal: i=1; secret\r\n"+
			"Message-Instance: m=1; h=secret\r\n"+
			"DKIM2-Signature: i=1; s=secret\r\n"+
			"Subject: kept\r\n"+
			"From: sender@example.test\r\n"))
	canonicalizer := mustCanonicalizer(t)

	got, err := canonicalizer.HeaderHashInputFromMessage(msg)
	if err != nil {
		t.Fatalf("HeaderHashInputFromMessage() error = %v", err)
	}

	want := []byte("from:sender@example.test\r\nsubject:kept\r\n")
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("HeaderHashInputFromMessage() = %q, want %q", got.Bytes(), want)
	}

	metadata := got.Metadata()
	if metadata.IncludedFields != 2 {
		t.Fatalf("IncludedFields = %d, want 2", metadata.IncludedFields)
	}
	if metadata.ExcludedFields != 9 {
		t.Fatalf("ExcludedFields = %d, want 9", metadata.ExcludedFields)
	}
	counts := metadata.ExcludedHeaderCounts
	if counts.Received != 1 || counts.ReturnPath != 1 || counts.DeliveredTo != 1 || counts.AuthenticationResults != 1 ||
		counts.XHeader != 1 || counts.DKIMSignature != 1 || counts.ARC != 1 ||
		counts.MessageInstance != 1 || counts.DKIM2Signature != 1 {
		t.Fatalf("ExcludedHeaderCounts = %#v, want one per excluded class", counts)
	}
}

// TestHeaderHashInputCompressesWSPAndRetainsValueBytes verifies Section 6.2 value rules.
func TestHeaderHashInputCompressesWSPAndRetainsValueBytes(t *testing.T) {
	msg := mustParseHeaderMessage(t, []byte(
		"Subject:\t Alpha\r\n"+
			" \tBeta\t\t Gamma \t\r\n"+
			"Comment: \t=?UTF-8?Q?kept=5Fbytes?=\t value\t\r\n"+
			"Empty:\r\n"))
	canonicalizer := mustCanonicalizer(t)

	got, err := canonicalizer.HeaderHashInputFromMessage(msg)
	if err != nil {
		t.Fatalf("HeaderHashInputFromMessage() error = %v", err)
	}

	want := []byte(
		"comment:=?UTF-8?Q?kept=5Fbytes?= value\r\n" +
			"empty:\r\n" +
			"subject:Alpha Beta Gamma\r\n")
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("HeaderHashInputFromMessage() = %q, want %q", got.Bytes(), want)
	}
}

// TestHeaderHashInputSortsDuplicatesByReverseOccurrence verifies deterministic ordering.
func TestHeaderHashInputSortsDuplicatesByReverseOccurrence(t *testing.T) {
	msg := mustParseHeaderMessage(t, []byte(
		"Zed: tail\r\n"+
			"Subject: first\r\n"+
			"Alpha: one\r\n"+
			"subject: second\r\n"+
			"ALPHA: two\r\n"))
	canonicalizer := mustCanonicalizer(t)

	got, err := canonicalizer.HeaderHashInputFromMessage(msg)
	if err != nil {
		t.Fatalf("HeaderHashInputFromMessage() error = %v", err)
	}

	want := []byte(
		"alpha:two\r\n" +
			"alpha:one\r\n" +
			"subject:second\r\n" +
			"subject:first\r\n" +
			"zed:tail\r\n")
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("HeaderHashInputFromMessage() = %q, want %q", got.Bytes(), want)
	}
}

// TestHeaderHashInputBytesAreImmutable verifies callers cannot mutate canonical output.
func TestHeaderHashInputBytesAreImmutable(t *testing.T) {
	rawHeaders := []byte("Subject: immutable\r\nFrom: sender@example.test\r\n")
	msg := mustParseHeaderMessage(t, rawHeaders)
	canonicalizer := mustCanonicalizer(t)

	got, err := canonicalizer.HeaderHashInputFromMessage(msg)
	if err != nil {
		t.Fatalf("HeaderHashInputFromMessage() error = %v", err)
	}

	rawHeaders[0] = 'X'
	exposed := got.Bytes()
	exposed[0] = 'Y'
	if !bytes.Equal(got.Bytes(), []byte("from:sender@example.test\r\nsubject:immutable\r\n")) {
		t.Fatalf("canonical header bytes were mutated: %q", got.Bytes())
	}
	if !bytes.Equal(msg.Headers().OriginalBytes(), []byte("Subject: immutable\r\nFrom: sender@example.test\r\n")) {
		t.Fatalf("raw header bytes were mutated: %q", msg.Headers().OriginalBytes())
	}
}

// TestHeaderHashInputEnforcesLimitsWithoutLeakingValues verifies fail-closed limits.
func TestHeaderHashInputEnforcesLimitsWithoutLeakingValues(t *testing.T) {
	tests := []struct {
		name       string
		headers    []byte
		mutate     func(*Limits)
		limitName  string
		secretText string
	}{
		{
			name:    "field count",
			headers: []byte("Subject: secret-one\r\nFrom: secret-two\r\n"),
			mutate: func(limits *Limits) {
				limits.MaxFieldCount = 1
			},
			limitName:  "max_field_count",
			secretText: "secret-one",
		},
		{
			name:    "field bytes",
			headers: []byte("Subject: secret-value\r\n"),
			mutate: func(limits *Limits) {
				limits.MaxFieldBytes = len("subject:secret-value\r\n") - 1
			},
			limitName:  "max_field_bytes",
			secretText: "secret-value",
		},
		{
			name:    "header output bytes",
			headers: []byte("Subject: secret-output\r\n"),
			mutate: func(limits *Limits) {
				limits.MaxFieldBytes = 1024
				limits.MaxHeaderInputBytes = len("subject:secret-output\r\n") - 1
			},
			limitName:  "max_header_input_bytes",
			secretText: "secret-output",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limits := DefaultLimits()
			tt.mutate(&limits)
			canonicalizer, err := NewCanonicalizer(WithLimits(limits))
			if err != nil {
				t.Fatalf("NewCanonicalizer() error = %v", err)
			}

			_, err = canonicalizer.HeaderHashInputFromMessage(mustParseHeaderMessage(t, tt.headers))
			if !IsErrorCode(err, ErrorCodeLimitExceeded) {
				t.Fatalf("HeaderHashInputFromMessage() error = %v, want limit exceeded", err)
			}
			var canonicalErr *Error
			if !errors.As(err, &canonicalErr) {
				t.Fatalf("HeaderHashInputFromMessage() error = %T, want *Error", err)
			}
			if canonicalErr.LimitName() != tt.limitName {
				t.Fatalf("LimitName() = %q, want %q", canonicalErr.LimitName(), tt.limitName)
			}
			if strings.Contains(err.Error(), tt.secretText) {
				t.Fatalf("HeaderHashInputFromMessage() error leaked header value: %q", err.Error())
			}
		})
	}
}

// mustCanonicalizer constructs a default canonicalizer for header tests.
func mustCanonicalizer(t *testing.T) Canonicalizer {
	t.Helper()

	canonicalizer, err := NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}

	return canonicalizer
}

// mustParseHeaderMessage parses synthetic strict-CRLF header test messages.
func mustParseHeaderMessage(t *testing.T, headers []byte) rawmsg.Message {
	t.Helper()

	raw := make([]byte, 0, len(headers)+len("\r\nbody"))
	raw = append(raw, headers...)
	raw = append(raw, "\r\nbody"...)
	msg, err := rawmsg.Parse(raw)
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}

	return msg
}
