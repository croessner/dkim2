package dsn

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestParseAcceptsBoundedThreePartReport proves the structural RFC 6522 report boundary.
func TestParseAcceptsBoundedThreePartReport(t *testing.T) {
	report, err := Parse(validReport("message/rfc822", ""))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if got := string(report.DeliveryStatus().BodyBytes()); !strings.Contains(got, "Final-Recipient") {
		t.Fatalf("delivery-status body = %q, want recipient fields", got)
	}
	if got := string(report.OriginalMessage().BodyBytes()); !strings.Contains(got, "Subject: original") {
		t.Fatalf("original-message body = %q, want embedded message", got)
	}

	mutated := report.OriginalMessage().BodyBytes()
	mutated[0] = 'X'
	if got := report.OriginalMessage().BodyBytes()[0]; got != 'F' {
		t.Fatalf("original-message bytes were mutable: got %q", got)
	}
}

// TestParseAcceptsHeaderOnlyOriginalPart proves text/rfc822-headers is accepted without an invented body.
func TestParseAcceptsHeaderOnlyOriginalPart(t *testing.T) {
	report, err := Parse(validReport("text/rfc822-headers", ""))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if report.OriginalMessage().ContentType() != ContentTypeRFC822Headers {
		t.Fatalf("original content type = %q, want %q", report.OriginalMessage().ContentType(), ContentTypeRFC822Headers)
	}
}

// TestParseRejectsMalformedReportStructure proves the parser fails closed at each DSN-only boundary.
func TestParseRejectsMalformedReportStructure(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		code ErrorCode
	}{
		{
			name: "wrong report type",
			raw:  []byte(strings.Replace(string(validReport("message/rfc822", "")), "report-type=delivery-status", "report-type=disposition-notification", 1)),
			code: ErrorCodeInvalidReportType,
		},
		{
			name: "missing closing boundary",
			raw:  bytes.TrimSuffix(validReport("message/rfc822", ""), []byte("--dsn--\r\n")),
			code: ErrorCodeMalformedMultipart,
		},
		{
			name: "only two parts",
			raw:  twoPartReport(),
			code: ErrorCodeInvalidPartCount,
		},
		{
			name: "wrong second part",
			raw:  []byte(strings.Replace(string(validReport("message/rfc822", "")), "Content-Type: message/delivery-status", "Content-Type: text/plain", 1)),
			code: ErrorCodeInvalidPartContentType,
		},
		{
			name: "wrong third part",
			raw:  validReport("application/rfc822", ""),
			code: ErrorCodeInvalidPartContentType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.raw)
			if !IsErrorCode(err, tt.code) {
				t.Fatalf("Parse error = %v, want %s", err, tt.code)
			}
		})
	}
}

// TestParseIgnoresAllowedMultipartPreambleAndEpilogue proves that exact part counting does not reject RFC 2046 framing.
func TestParseIgnoresAllowedMultipartPreambleAndEpilogue(t *testing.T) {
	raw := validReport("message/rfc822", "epilogue\r\n")
	raw = bytes.Replace(raw, []byte("\r\n--dsn\r\n"), []byte("\r\npreamble\r\n--dsn\r\n"), 1)
	if _, err := Parse(raw); err != nil {
		t.Fatalf("Parse returned error for allowed multipart framing: %v", err)
	}
}

// TestParseRejectsResourceAndDiagnosticAbuse proves bounded opaque errors for hostile messages.
func TestParseRejectsResourceAndDiagnosticAbuse(t *testing.T) {
	const toxic = "must-not-appear-in-diagnostics"
	options := DefaultOptions()
	options.MaxPartBytes = 8
	_, err := ParseWithOptions(validReport("message/rfc822", ""), options)
	if !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("ParseWithOptions error = %v, want limit exceeded", err)
	}
	var dsnErr *Error
	if !errors.As(err, &dsnErr) || dsnErr.LimitName() != LimitNameMaxPartBytes {
		t.Fatalf("error = %#v, want max-part typed error", err)
	}

	_, err = Parse([]byte("From: " + toxic + "\r\nContent-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n--dsn\r\n"))
	if err == nil {
		t.Fatal("malformed report was accepted")
	}
	if strings.Contains(err.Error(), toxic) {
		t.Fatalf("error leaked input: %q", err)
	}
}

// FuzzParse rejects malformed inputs without panics or caller-byte mutation.
func FuzzParse(f *testing.F) {
	f.Add(validReport("message/rfc822", ""))
	f.Add([]byte("Content-Type: multipart/report; boundary=x\r\n\r\n--x--\r\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		before := bytes.Clone(input)
		_, _ = Parse(input)
		if !bytes.Equal(input, before) {
			t.Fatal("Parse mutated caller-owned bytes")
		}
	})
}

// validReport creates one three-part report and permits a controlled trailing suffix after its close delimiter.
func validReport(originalContentType string, suffix string) []byte {
	return []byte("From: postmaster@example.test\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n" +
		"\r\n" +
		"--dsn\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Human-readable status\r\n" +
		"--dsn\r\n" +
		"Content-Type: message/delivery-status\r\n" +
		"\r\n" +
		"Reporting-MTA: dns; mx.example.test\r\n" +
		"\r\n" +
		"Final-Recipient: rfc822; recipient@example.test\r\n" +
		"Action: failed\r\n" +
		"Status: 5.1.1\r\n" +
		"\r\n" +
		"--dsn\r\n" +
		"Content-Type: " + originalContentType + "\r\n" +
		"\r\n" +
		"From: sender@example.test\r\n" +
		"Subject: original\r\n" +
		"\r\n" +
		"body\r\n" +
		"--dsn--\r\n" + suffix)
}

// twoPartReport creates an otherwise valid report with one required part missing.
func twoPartReport() []byte {
	return []byte("From: postmaster@example.test\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n" +
		"\r\n" +
		"--dsn\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Human-readable status\r\n" +
		"--dsn\r\n" +
		"Content-Type: message/delivery-status\r\n" +
		"\r\n" +
		"Reporting-MTA: dns; mx.example.test\r\n" +
		"\r\n" +
		"Final-Recipient: rfc822; recipient@example.test\r\n" +
		"Action: failed\r\n" +
		"Status: 5.1.1\r\n" +
		"--dsn--\r\n")
}
