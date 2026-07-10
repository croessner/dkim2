package rawmsg

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestParseStrictCRLFMessagePreservesHeadersAndBody verifies strict happy-path parsing.
func TestParseStrictCRLFMessagePreservesHeadersAndBody(t *testing.T) {
	raw := []byte("From: sender@example.test\r\nSubject: folded\r\n continuation\r\n\tpart\r\nX-Test: one\r\nX-Test: two\r\n\r\nline one\r\nline two")

	msg, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if got := msg.RawBytes(); !bytes.Equal(got, raw) {
		t.Fatalf("RawBytes mismatch: %q", got)
	}
	if got := msg.Body().Bytes(); !bytes.Equal(got, []byte("line one\r\nline two")) {
		t.Fatalf("Body bytes mismatch: %q", got)
	}
	metadata := msg.Metadata()
	if metadata.LineEndingPolicy != LineEndingPolicyStrictCRLF || metadata.NormalizedInput {
		t.Fatalf("metadata policy=%q normalized=%v", metadata.LineEndingPolicy, metadata.NormalizedInput)
	}
	if metadata.HeaderFields != 4 || metadata.BodyBytes != len("line one\r\nline two") {
		t.Fatalf("metadata counts = %#v", metadata)
	}

	headers := msg.Headers()
	if headers.Len() != 4 {
		t.Fatalf("header count = %d, want 4", headers.Len())
	}
	if got := headers.OriginalBytes(); !bytes.Equal(got, []byte("From: sender@example.test\r\nSubject: folded\r\n continuation\r\n\tpart\r\nX-Test: one\r\nX-Test: two\r\n")) {
		t.Fatalf("header bytes mismatch: %q", got)
	}

	subject, ok := headers.Field(1)
	if !ok {
		t.Fatal("missing subject header")
	}
	if subject.Index() != 1 {
		t.Fatalf("subject index = %d, want 1", subject.Index())
	}
	if got := subject.RawName(); !bytes.Equal(got, []byte("Subject")) {
		t.Fatalf("subject raw name = %q", got)
	}
	if subject.NameLower() != "subject" {
		t.Fatalf("subject lower name = %q", subject.NameLower())
	}
	if got := subject.RawValue(); !bytes.Equal(got, []byte(" folded\r\n continuation\r\n\tpart")) {
		t.Fatalf("subject raw value = %q", got)
	}
	if got := subject.UnfoldedValue(); !bytes.Equal(got, []byte(" folded continuation\tpart")) {
		t.Fatalf("subject unfolded value = %q", got)
	}
	if got := subject.OriginalBytes(); !bytes.Equal(got, []byte("Subject: folded\r\n continuation\r\n\tpart\r\n")) {
		t.Fatalf("subject original bytes = %q", got)
	}
}

// TestParseSplitsAtFirstStrictDelimiter verifies body bytes may contain delimiters.
func TestParseSplitsAtFirstStrictDelimiter(t *testing.T) {
	raw := []byte("A: b\r\n\r\nbody\r\n\r\nstill body")

	msg, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if got := msg.Body().Bytes(); !bytes.Equal(got, []byte("body\r\n\r\nstill body")) {
		t.Fatalf("body split mismatch: %q", got)
	}
}

// TestCRLFStrictPolicyRejectsAmbiguousLineEndings verifies fail-closed line endings.
func TestCRLFStrictPolicyRejectsAmbiguousLineEndings(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		code ErrorCode
	}{
		{
			name: "bare lf only",
			raw:  []byte("From: a\n\nbody"),
			code: ErrorCodeBareLF,
		},
		{
			name: "bare cr only",
			raw:  []byte("From: a\r\rbody"),
			code: ErrorCodeBareCR,
		},
		{
			name: "mixed lf",
			raw:  []byte("From: a\r\nSubject: b\n\r\nbody"),
			code: ErrorCodeMixedLineEndings,
		},
		{
			name: "mixed cr",
			raw:  []byte("From: a\r\nSubject: b\r\r\nbody"),
			code: ErrorCodeMixedLineEndings,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.raw)
			if !IsParserErrorCode(err, tt.code) {
				t.Fatalf("Parse error = %v, want code %s", err, tt.code)
			}
		})
	}
}

// TestParseAcceptsConformantHeaderOnlyMessage verifies RFC 5322 optional-body syntax.
func TestParseAcceptsConformantHeaderOnlyMessage(t *testing.T) {
	raw := []byte("Date: 10 Jul 2026 12:00:00 +0200\r\nFrom: sender@example.test\r\n")

	message, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if got := message.RawBytes(); !bytes.Equal(got, raw) {
		t.Fatalf("RawBytes mismatch: %q", got)
	}
	if message.Body().Len() != 0 || message.Metadata().BodyBytes != 0 {
		t.Fatalf("header-only message has body metadata: %#v", message.Metadata())
	}
}

// TestParseRejectsUnterminatedHeaderSection verifies strict header framing.
func TestParseRejectsUnterminatedHeaderSection(t *testing.T) {
	_, err := Parse([]byte("From: sender@example.test"))
	if !IsParserErrorCode(err, ErrorCodeMissingDelimiter) {
		t.Fatalf("Parse error = %v, want missing delimiter or terminating CRLF", err)
	}
}

// TestParseRejectsMalformedHeaders verifies structured malformed header errors.
func TestParseRejectsMalformedHeaders(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "continuation before field", raw: []byte(" folded\r\nSubject: x\r\n\r\nbody")},
		{name: "line without colon", raw: []byte("Subject value\r\n\r\nbody")},
		{name: "empty name", raw: []byte(": value\r\n\r\nbody")},
		{name: "whitespace name", raw: []byte("Bad Name: value\r\n\r\nbody")},
		{name: "non ascii name", raw: []byte("Bad\xff: value\r\n\r\nbody")},
		{name: "control name", raw: []byte("Bad\x1f: value\r\n\r\nbody")},
		{name: "invalid utf8 value", raw: []byte("X-Bytes: \xff\xfe\r\n\r\nbody")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.raw)
			if !IsParserErrorCode(err, ErrorCodeMalformedHeader) {
				t.Fatalf("Parse error = %v, want malformed header", err)
			}
		})
	}
}

// TestParseRejectsHeaderResourceLimitViolations verifies bounded header limits.
func TestParseRejectsHeaderResourceLimitViolations(t *testing.T) {
	t.Run("header block", func(t *testing.T) {
		opts := DefaultParserOptions()
		opts.MaxHeaderBytes = len("A: b\r\n") - 1
		_, err := ParseWithOptions([]byte("A: b\r\n\r\nbody"), opts)
		if !IsParserErrorCode(err, ErrorCodeLimitExceeded) {
			t.Fatalf("Parse error = %v, want limit", err)
		}
	})

	t.Run("header fields", func(t *testing.T) {
		opts := DefaultParserOptions()
		opts.MaxHeaderFields = 1
		_, err := ParseWithOptions([]byte("A: b\r\nC: d\r\n\r\nbody"), opts)
		if !IsParserErrorCode(err, ErrorCodeLimitExceeded) {
			t.Fatalf("Parse error = %v, want limit", err)
		}
	})

	t.Run("single field", func(t *testing.T) {
		opts := DefaultParserOptions()
		opts.MaxHeaderFieldBytes = len("A: b\r\n") - 1
		_, err := ParseWithOptions([]byte("A: b\r\n\r\nbody"), opts)
		if !IsParserErrorCode(err, ErrorCodeLimitExceeded) {
			t.Fatalf("Parse error = %v, want limit", err)
		}
	})
}

// TestParseEnforcesRFC6532PhysicalLineLimit verifies the strict 998-octet boundary.
func TestParseEnforcesRFC6532PhysicalLineLimit(t *testing.T) {
	tests := []struct {
		name      string
		raw       []byte
		limitName string
	}{
		{
			name: "998 byte header line",
			raw:  []byte("X:" + strings.Repeat("h", 996) + "\r\n\r\nbody"),
		},
		{
			name:      "999 byte header line",
			raw:       []byte("X:" + strings.Repeat("h", 997) + "\r\n\r\nbody"),
			limitName: limitNameMaxHeaderLineBytes,
		},
		{
			name: "998 byte body line",
			raw:  []byte("X: value\r\n\r\n" + strings.Repeat("b", 998)),
		},
		{
			name:      "999 byte body line",
			raw:       []byte("X: value\r\n\r\n" + strings.Repeat("b", 999)),
			limitName: limitNameMaxBodyLineBytes,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message, err := Parse(test.raw)
			if test.limitName == "" {
				if err != nil {
					t.Fatalf("Parse returned error: %v", err)
				}
				if got := message.RawBytes(); !bytes.Equal(got, test.raw) {
					t.Fatalf("RawBytes length = %d, want %d", len(got), len(test.raw))
				}

				return
			}
			if !IsParserErrorCode(err, ErrorCodeLimitExceeded) {
				t.Fatalf("Parse error = %v, want limit exceeded", err)
			}
			var parserErr *ParserError
			if !errors.As(err, &parserErr) || parserErr.LimitName() != test.limitName {
				t.Fatalf("Parse error = %v, want limit %q", err, test.limitName)
			}
		})
	}
}

// TestParseNegativeChecklistExposesStructuredErrors verifies required malformed cases.
func TestParseNegativeChecklistExposesStructuredErrors(t *testing.T) {
	tests := []struct {
		name      string
		raw       []byte
		options   func(ParserOptions) ParserOptions
		code      ErrorCode
		reason    ErrorReasonClass
		limitName string
	}{
		{
			name:   "bare LF in strict mode",
			raw:    []byte("A: b\n\nbody"),
			code:   ErrorCodeBareLF,
			reason: ErrorReasonPolicy,
		},
		{
			name:   "bare CR in strict mode",
			raw:    []byte("A: b\r\rbody"),
			code:   ErrorCodeBareCR,
			reason: ErrorReasonPolicy,
		},
		{
			name:   "mixed line endings in strict mode",
			raw:    []byte("A: b\r\nB: c\n\r\nbody"),
			code:   ErrorCodeMixedLineEndings,
			reason: ErrorReasonPolicy,
		},
		{
			name:   "unterminated header section",
			raw:    []byte("A: b"),
			code:   ErrorCodeMissingDelimiter,
			reason: ErrorReasonPolicy,
		},
		{
			name:   "header continuation before field",
			raw:    []byte(" continuation\r\nA: b\r\n\r\nbody"),
			code:   ErrorCodeMalformedHeader,
			reason: ErrorReasonMalformed,
		},
		{
			name:   "header line without colon",
			raw:    []byte("A b\r\n\r\nbody"),
			code:   ErrorCodeMalformedHeader,
			reason: ErrorReasonMalformed,
		},
		{
			name:   "empty header field name",
			raw:    []byte(": b\r\n\r\nbody"),
			code:   ErrorCodeMalformedHeader,
			reason: ErrorReasonMalformed,
		},
		{
			name:   "header field name containing whitespace",
			raw:    []byte("Bad Name: b\r\n\r\nbody"),
			code:   ErrorCodeMalformedHeader,
			reason: ErrorReasonMalformed,
		},
		{
			name:   "header field name containing non ASCII",
			raw:    []byte("Bad\x80: b\r\n\r\nbody"),
			code:   ErrorCodeMalformedHeader,
			reason: ErrorReasonMalformed,
		},
		{
			name:   "header field name containing control byte",
			raw:    []byte("Bad\x1f: b\r\n\r\nbody"),
			code:   ErrorCodeMalformedHeader,
			reason: ErrorReasonMalformed,
		},
		{
			name: "header field exceeding configured field limit",
			raw:  []byte("A: b\r\n\r\nbody"),
			options: func(options ParserOptions) ParserOptions {
				options.MaxHeaderFieldBytes = len("A: b\r\n") - 1
				return options
			},
			code:      ErrorCodeLimitExceeded,
			reason:    ErrorReasonLimit,
			limitName: "max_header_field_bytes",
		},
		{
			name: "header block exceeding configured header limit",
			raw:  []byte("A: b\r\n\r\nbody"),
			options: func(options ParserOptions) ParserOptions {
				options.MaxHeaderBytes = len("A: b\r\n") - 1
				return options
			},
			code:      ErrorCodeLimitExceeded,
			reason:    ErrorReasonLimit,
			limitName: "max_header_bytes",
		},
		{
			name: "message exceeding configured message limit",
			raw:  []byte("A: b\r\n\r\nbody"),
			options: func(options ParserOptions) ParserOptions {
				options.MaxMessageBytes = len("A: b\r\n\r\nbody") - 1
				return options
			},
			code:      ErrorCodeLimitExceeded,
			reason:    ErrorReasonLimit,
			limitName: "max_message_bytes",
		},
		{
			name: "body line exceeding configured indexing limit",
			raw:  []byte("A: b\r\n\r\nbody\r\n"),
			options: func(options ParserOptions) ParserOptions {
				options.MaxBodyLineBytes = len("body") - 1
				return options
			},
			code:      ErrorCodeLimitExceeded,
			reason:    ErrorReasonLimit,
			limitName: limitNameMaxBodyLineBytes,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := DefaultParserOptions()
			if tt.options != nil {
				options = tt.options(options)
			}

			_, err := ParseWithOptions(tt.raw, options)
			if err == nil {
				t.Fatal("ParseWithOptions returned nil error")
			}
			var parserErr *ParserError
			if !errors.As(err, &parserErr) {
				t.Fatalf("ParseWithOptions error = %T, want ParserError", err)
			}
			if parserErr.Code() != tt.code {
				t.Fatalf("Code = %q, want %q", parserErr.Code(), tt.code)
			}
			if parserErr.ReasonClass() != tt.reason {
				t.Fatalf("ReasonClass = %q, want %q", parserErr.ReasonClass(), tt.reason)
			}
			if parserErr.LimitName() != tt.limitName {
				t.Fatalf("LimitName = %q, want %q", parserErr.LimitName(), tt.limitName)
			}
		})
	}
}

// TestParsePreservesValidUTF8HeaderAndArbitraryBodyBytes verifies byte-oriented storage.
func TestParsePreservesValidUTF8HeaderAndArbitraryBodyBytes(t *testing.T) {
	raw := []byte("Subject: caf\xc3\xa9\r\nX-Obs: \x00\x01\x7f\r\n\r\nbody:\x00\xff\r\n")

	msg, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if got := msg.RawBytes(); !bytes.Equal(got, raw) {
		t.Fatalf("RawBytes length = %d, want %d", len(got), len(raw))
	}
	subject, ok := msg.Headers().Field(0)
	if !ok {
		t.Fatal("missing subject field")
	}
	if got := subject.RawValue(); !bytes.Equal(got, []byte(" caf\xc3\xa9")) {
		t.Fatalf("subject raw value bytes = % x", got)
	}
	bytesField, ok := msg.Headers().Field(1)
	if !ok {
		t.Fatal("missing bytes field")
	}
	if got := bytesField.RawValue(); !bytes.Equal(got, []byte(" \x00\x01\x7f")) {
		t.Fatalf("bytes raw value = % x", got)
	}
	if got := msg.Body().Bytes(); !bytes.Equal(got, []byte("body:\x00\xff\r\n")) {
		t.Fatalf("body bytes = % x", got)
	}
}

// TestParseCopiesCallerOwnedInput verifies caller mutation cannot alter messages.
func TestParseCopiesCallerOwnedInput(t *testing.T) {
	raw := []byte("A: b\r\n\r\nbody\r\n")
	msg, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	for i := range raw {
		raw[i] = 'X'
	}

	if got := msg.RawBytes(); !bytes.Equal(got, []byte("A: b\r\n\r\nbody\r\n")) {
		t.Fatalf("RawBytes changed after caller mutation: %q", got)
	}
	if got := msg.Headers().OriginalBytes(); !bytes.Equal(got, []byte("A: b\r\n")) {
		t.Fatalf("Header bytes changed after caller mutation: %q", got)
	}
	if got := msg.Body().Bytes(); !bytes.Equal(got, []byte("body\r\n")) {
		t.Fatalf("Body bytes changed after caller mutation: %q", got)
	}
}

// TestParseErrorsDoNotLeakRawMessageContent verifies real parser errors are bounded.
func TestParseErrorsDoNotLeakRawMessageContent(t *testing.T) {
	rawHeaderValue := "synthetic-secret-header-value"
	rawBodyValue := "synthetic-secret-body-value"
	raw := []byte("X-Leak: " + rawHeaderValue + "\r\n\r\n" + rawBodyValue)
	options := DefaultParserOptions()
	options.MaxHeaderBytes = len("X-Leak: \r\n") - 1

	_, err := ParseWithOptions(raw, options)
	if err == nil {
		t.Fatal("ParseWithOptions returned nil error")
	}

	message := err.Error()
	for _, forbidden := range []string{rawHeaderValue, rawBodyValue, string(raw)} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("error string leaked raw input %q in %q", forbidden, message)
		}
	}
	if !IsParserErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("ParseWithOptions error = %v, want limit error", err)
	}
}
